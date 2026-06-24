/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free sovereign broker channel server.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_channel_internal.h"

#define SOVEREIGN_SERVER_RESULT_CHUNK_BYTES 3500U

static int hash_begin(
	const struct pqcp_sovereign_channel_begin *begin,
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	struct pqcp_sovereign_channel_frame frame;
	uint8_t encoded[PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES];
	size_t encoded_length = 0U;
	int ret;

	if (begin == NULL || transaction_id == NULL ||
	    request_id == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(&frame, 0, sizeof(frame));
	frame.schema_version =
		PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION;
	frame.type = PQCP_SOVEREIGN_CHANNEL_FRAME_BEGIN;
	frame.flags = PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST;
	memcpy(frame.transaction_id, transaction_id,
	       sizeof(frame.transaction_id));
	memcpy(frame.request_id, request_id,
	       sizeof(frame.request_id));
	frame.body.begin = *begin;
	frame.body.begin.has_resume_token = false;
	pqcp_runtime_secure_zero(
		frame.body.begin.resume_token,
		sizeof(frame.body.begin.resume_token));
	ret = pqcp_sovereign_channel_frame_encode(
		&frame, encoded, sizeof(encoded), &encoded_length);
	if (ret == 0) {
		ret = pqcp_runtime_internal_sha256(
			encoded, encoded_length, digest);
	}
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			digest,
			PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES);
	}
	return ret;
}

static bool server_state_valid(
	enum pqcp_sovereign_channel_server_state state)
{
	return state >= PQCP_SOVEREIGN_CHANNEL_SERVER_EMPTY &&
	       state <= PQCP_SOVEREIGN_CHANNEL_SERVER_FAILED;
}

static bool server_terminal_state(
	enum pqcp_sovereign_channel_server_state state)
{
	return state == PQCP_SOVEREIGN_CHANNEL_SERVER_COMPLETED ||
	       state == PQCP_SOVEREIGN_CHANNEL_SERVER_CANCELLED ||
	       state == PQCP_SOVEREIGN_CHANNEL_SERVER_FAILED;
}

static int lock_server(
	struct pqcp_sovereign_channel_server *server)
{
	if (server == NULL || !server->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&server->lock, K_FOREVER);
}

static void unlock_server(
	struct pqcp_sovereign_channel_server *server)
{
	(void)k_mutex_unlock(&server->lock);
}

static bool buffer_descriptor_valid(
	const struct pqcp_sovereign_channel_server_buffer *buffer)
{
	return buffer != NULL &&
	       buffer->input != NULL &&
	       buffer->input_capacity >=
		       PQCP_RUNTIME_MAX_INPUT_BYTES &&
	       buffer->aux_input != NULL &&
	       buffer->aux_input_capacity >=
		       PQCP_RUNTIME_MAX_INPUT_BYTES &&
	       buffer->context != NULL &&
	       buffer->context_capacity >=
		       PQCP_RUNTIME_MAX_CONTEXT_BYTES &&
	       buffer->output != NULL &&
	       buffer->output_capacity >=
		       PQCP_CRYPTO_BROKER_RESPONSE_MAX_BYTES &&
	       buffer->receipt != NULL &&
	       buffer->receipt_capacity >=
		       PQCP_SOVEREIGN_CHANNEL_RECEIPT_MAX_BYTES;
}

static int validate_server_configuration(
	const struct pqcp_sovereign_channel_server_config *config,
	const struct pqcp_sovereign_channel_server_storage *storage)
{
	if (config == NULL || storage == NULL ||
	    config->broker == NULL ||
	    !config->broker->initialized ||
	    config->multiplexer == NULL ||
	    !config->multiplexer->initialized ||
	    config->flow_controller == NULL ||
	    !config->flow_controller->initialized ||
	    config->resolve_identity == NULL ||
	    config->resume_secret == NULL ||
	    config->resume_secret_length < 16U ||
	    config->transaction_lifetime_ms == 0U ||
	    config->disconnected_retention_ms == 0U ||
	    config->disconnected_retention_ms >
		    config->transaction_lifetime_ms ||
	    config->stream_priority > 255U ||
	    storage->slots == NULL ||
	    storage->buffers == NULL ||
	    storage->capacity == 0U ||
	    config->multiplexer->channel == NULL ||
	    config->multiplexer->channel->config.role !=
		    PQCP_CHANNEL_ROLE_SERVER ||
	    config->multiplexer->channel->state !=
		    PQCP_CHANNEL_STATE_ESTABLISHED ||
	    !config->multiplexer->channel->established ||
	    !config->multiplexer->channel->peer_authenticated ||
	    (config->require_mutual_authentication &&
	     !config->multiplexer->channel->local_authenticated)) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < storage->capacity;
	     ++index) {
		if (!buffer_descriptor_valid(
			    &storage->buffers[index])) {
			return -ENOBUFS;
		}
	}
	return 0;
}

static struct pqcp_sovereign_channel_server_slot *slot_by_stream(
	struct pqcp_sovereign_channel_server *server,
	uint32_t stream_id)
{
	if (server == NULL || stream_id == 0U) {
		return NULL;
	}
	for (size_t index = 0U;
	     index < server->storage.capacity; ++index) {
		struct pqcp_sovereign_channel_server_slot *slot =
			&server->storage.slots[index];

		if (slot->occupied &&
		    slot->stream_id == stream_id &&
		    slot->state !=
			    PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED) {
			return slot;
		}
	}
	return NULL;
}

static struct pqcp_sovereign_channel_server_slot *slot_by_ids(
	struct pqcp_sovereign_channel_server *server,
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[
		PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES])
{
	if (server == NULL || transaction_id == NULL ||
	    request_id == NULL) {
		return NULL;
	}
	for (size_t index = 0U;
	     index < server->storage.capacity; ++index) {
		struct pqcp_sovereign_channel_server_slot *slot =
			&server->storage.slots[index];

		if (slot->occupied &&
		    pqcp_sovereign_channel_internal_equal(
			    slot->transaction_id, transaction_id,
			    sizeof(slot->transaction_id)) &&
		    pqcp_sovereign_channel_internal_equal(
			    slot->request_id, request_id,
			    sizeof(slot->request_id))) {
			return slot;
		}
	}
	return NULL;
}

static struct pqcp_sovereign_channel_server_slot *free_slot(
	struct pqcp_sovereign_channel_server *server,
	size_t *slot_index)
{
	if (server == NULL || slot_index == NULL) {
		return NULL;
	}
	for (size_t index = 0U;
	     index < server->storage.capacity; ++index) {
		if (!server->storage.slots[index].occupied) {
			*slot_index = index;
			return &server->storage.slots[index];
		}
	}
	return NULL;
}

static int secure_reset_slot(
	struct pqcp_sovereign_channel_server_slot *slot)
{
	if (slot == NULL) {
		return -EINVAL;
	}
	if (slot->buffers.input != NULL &&
	    slot->buffers.input_capacity != 0U) {
		pqcp_runtime_secure_zero(
			slot->buffers.input,
			slot->buffers.input_capacity);
	}
	if (slot->buffers.aux_input != NULL &&
	    slot->buffers.aux_input_capacity != 0U) {
		pqcp_runtime_secure_zero(
			slot->buffers.aux_input,
			slot->buffers.aux_input_capacity);
	}
	if (slot->buffers.context != NULL &&
	    slot->buffers.context_capacity != 0U) {
		pqcp_runtime_secure_zero(
			slot->buffers.context,
			slot->buffers.context_capacity);
	}
	if (slot->buffers.output != NULL &&
	    slot->buffers.output_capacity != 0U) {
		pqcp_runtime_secure_zero(
			slot->buffers.output,
			slot->buffers.output_capacity);
	}
	if (slot->buffers.receipt != NULL &&
	    slot->buffers.receipt_capacity != 0U) {
		pqcp_runtime_secure_zero(
			slot->buffers.receipt,
			slot->buffers.receipt_capacity);
	}
	pqcp_runtime_secure_zero(slot, sizeof(*slot));
	return 0;
}

static int digest_capability(
	const uint8_t capability[PQCP_CRYPTO_BROKER_TOKEN_BYTES],
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	if (capability == NULL || digest == NULL ||
	    pqcp_sovereign_channel_internal_all_zero(
		    capability, PQCP_CRYPTO_BROKER_TOKEN_BYTES)) {
		return -EINVAL;
	}
	return pqcp_runtime_internal_sha256(
		capability, PQCP_CRYPTO_BROKER_TOKEN_BYTES,
		digest);
}

static int resolve_and_bind_identity(
	struct pqcp_sovereign_channel_server *server,
	const struct pqcp_sovereign_channel_begin *begin,
	uint8_t identity_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	char principal_id[PQCP_CRYPTO_BROKER_ID_MAX_CHARS];
	char tenant_id[PQCP_CRYPTO_BROKER_TENANT_MAX_CHARS];
	int ret;

	if (server == NULL || begin == NULL ||
	    identity_digest == NULL) {
		return -EINVAL;
	}
	memset(principal_id, 0, sizeof(principal_id));
	memset(tenant_id, 0, sizeof(tenant_id));
	ret = pqcp_sovereign_channel_identity_digest(
		server->config.multiplexer->channel,
		identity_digest);
	if (ret == 0) {
		ret = server->config.resolve_identity(
			server->config.identity_context,
			identity_digest, principal_id, tenant_id);
	}
	if (ret == 0 &&
	    (principal_id[0] == '\0' ||
	     tenant_id[0] == '\0' ||
	     strnlen(principal_id, sizeof(principal_id)) >=
		     sizeof(principal_id) ||
	     strnlen(tenant_id, sizeof(tenant_id)) >=
		     sizeof(tenant_id))) {
		ret = -EACCES;
	}
	if (ret == 0 &&
	    (strcmp(principal_id, begin->principal_id) != 0 ||
	     strcmp(tenant_id, begin->tenant_id) != 0)) {
		ret = -EACCES;
	}
	if (ret == 0) {
		ret = pqcp_sovereign_channel_broker_bind_identity(
			server->config.broker, identity_digest,
			principal_id, tenant_id);
	}
	pqcp_runtime_secure_zero(
		principal_id, sizeof(principal_id));
	pqcp_runtime_secure_zero(tenant_id, sizeof(tenant_id));
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			identity_digest,
			PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES);
	}
	return ret;
}

static void initialize_frame(
	struct pqcp_sovereign_channel_frame *frame,
	enum pqcp_sovereign_channel_frame_type type,
	uint32_t flags,
	uint64_t sequence,
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[
		PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES])
{
	memset(frame, 0, sizeof(*frame));
	frame->schema_version =
		PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION;
	frame->type = type;
	frame->flags = flags;
	frame->sequence = sequence;
	memcpy(frame->transaction_id, transaction_id,
	       sizeof(frame->transaction_id));
	memcpy(frame->request_id, request_id,
	       sizeof(frame->request_id));
}

static int send_slot_frame(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	int ret;

	if (server == NULL || slot == NULL || frame == NULL ||
	    !slot->occupied || slot->stream_id == 0U ||
	    frame->sequence != slot->next_send_sequence) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_channel_internal_send_frame(
		&server->flow, slot->stream_id, frame, now_ms);
	if (ret == 0) {
		slot->next_send_sequence++;
		slot->last_activity_ms = now_ms;
	}
	return ret;
}

static int refresh_resume_token(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot)
{
	struct pqcp_sovereign_channel_resume_claim claim;
	int ret;

	if (server == NULL || slot == NULL) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_channel_resume_claim_from_slot(
		slot, &claim);
	if (ret == 0) {
		ret = pqcp_sovereign_channel_resume_token_issue(
			server->config.resume_secret,
			server->config.resume_secret_length,
			&claim, slot->resume_token);
	}
	pqcp_runtime_secure_zero(&claim, sizeof(claim));
	return ret;
}

static int send_checkpoint(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	enum pqcp_sovereign_channel_window_kind kind,
	uint64_t ack_offset,
	uint32_t flags,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	int ret;

	ret = refresh_resume_token(server, slot);
	if (ret != 0) {
		return ret;
	}
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW,
		flags, slot->next_send_sequence,
		slot->transaction_id, slot->request_id);
	frame.body.window.kind = kind;
	frame.body.window.ack_offset = ack_offset;
	frame.body.window.server_time_ms = now_ms;
	frame.body.window.expires_at_ms = slot->expires_at_ms;
	frame.body.window.has_resume_token = true;
	memcpy(frame.body.window.resume_token,
	       slot->resume_token,
	       sizeof(frame.body.window.resume_token));
	if (kind == PQCP_SOVEREIGN_CHANNEL_WINDOW_BEGIN_ACCEPTED ||
	    kind == PQCP_SOVEREIGN_CHANNEL_WINDOW_REQUEST_ACK ||
	    kind == PQCP_SOVEREIGN_CHANNEL_WINDOW_RESUME_ACCEPTED) {
		frame.body.window.has_rolling_digest = true;
		memcpy(frame.body.window.rolling_digest,
		       slot->assembler.rolling_digest,
		       sizeof(frame.body.window.rolling_digest));
	}
	ret = send_slot_frame(server, slot, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	return ret;
}

static int send_credit(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	const struct pqcp_sovereign_channel_window *credit,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	int ret;

	if (credit == NULL ||
	    (credit->connection_credit == 0U &&
	     credit->stream_credit == 0U)) {
		return 0;
	}
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW,
		0U, slot->next_send_sequence,
		slot->transaction_id, slot->request_id);
	frame.body.window = *credit;
	frame.body.window.server_time_ms = now_ms;
	frame.body.window.expires_at_ms = slot->expires_at_ms;
	ret = send_slot_frame(server, slot, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	return ret;
}

static int send_complete(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	uint64_t now_ms)
{
	int ret;

	ret = send_checkpoint(
		server, slot,
		PQCP_SOVEREIGN_CHANNEL_WINDOW_COMPLETE,
		slot->receipt_length != 0U ?
			slot->receipt_ack_offset :
			slot->result_ack_offset,
		PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL |
		PQCP_SOVEREIGN_CHANNEL_FLAG_ACK,
		now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_stream_close(
		server->config.multiplexer, slot->stream_id,
		PQCP_CHANNEL_STREAM_ERROR_NONE, now_ms);
	if (ret != 0 && ret != -EALREADY) {
		return ret;
	}
	slot->state =
		PQCP_SOVEREIGN_CHANNEL_SERVER_COMPLETED;
	server->completed_transactions++;
	return 0;
}

static int send_error_frame(
	struct pqcp_sovereign_channel_server *server,
	uint32_t stream_id,
	uint64_t sequence,
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[
		PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	int error,
	enum pqcp_sovereign_channel_error_stage stage,
	bool retryable,
	uint64_t retry_after_ms,
	const char *detail,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	size_t detail_length = 0U;
	int ret;

	if (server == NULL || stream_id == 0U ||
	    transaction_id == NULL || request_id == NULL ||
	    stage <= PQCP_SOVEREIGN_CHANNEL_STAGE_NONE ||
	    stage > PQCP_SOVEREIGN_CHANNEL_STAGE_RESUME) {
		return -EINVAL;
	}
	if (detail != NULL) {
		detail_length = strnlen(
			detail,
			PQCP_SOVEREIGN_CHANNEL_DETAIL_MAX_BYTES);
		if (detail_length ==
		    PQCP_SOVEREIGN_CHANNEL_DETAIL_MAX_BYTES) {
			detail_length--;
		}
	}
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_ERROR,
		PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL |
		(retryable ?
		 PQCP_SOVEREIGN_CHANNEL_FLAG_RETRYABLE : 0U),
		sequence, transaction_id, request_id);
	frame.body.error.error_code = error;
	frame.body.error.stage = stage;
	frame.body.error.retry_after_ms = retry_after_ms;
	if (detail_length != 0U) {
		memcpy(frame.body.error.detail, detail,
		       detail_length);
		frame.body.error.detail_length = detail_length;
	}
	ret = pqcp_sovereign_channel_internal_send_frame(
		&server->flow, stream_id, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	return ret;
}

static enum pqcp_sovereign_channel_server_state resumed_state(
	const struct pqcp_sovereign_channel_server_slot *slot)
{
	if (!slot->assembler.committed) {
		return PQCP_SOVEREIGN_CHANNEL_SERVER_RECEIVING;
	}
	if (!slot->broker_executed) {
		return PQCP_SOVEREIGN_CHANNEL_SERVER_READY;
	}
	if (slot->result_announced ||
	    slot->result_ack_offset <
		    slot->response.output_length) {
		return PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RESULT;
	}
	if (slot->receipt_length != 0U &&
	    (slot->receipt_announced ||
	     slot->receipt_ack_offset < slot->receipt_length)) {
		return PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RECEIPT;
	}
	return server_terminal_state(slot->state) ?
		slot->state :
		PQCP_SOVEREIGN_CHANNEL_SERVER_WAITING_ACK;
}

static int validate_begin_time(
	const struct pqcp_sovereign_channel_begin *begin,
	uint64_t now_ms)
{
	if (begin == NULL || now_ms == 0U ||
	    begin->submitted_at_ms == 0U ||
	    begin->deadline_ms < begin->submitted_at_ms) {
		return -EINVAL;
	}
	if (now_ms > begin->deadline_ms) {
		return -ETIMEDOUT;
	}
	return 0;
}

static int begin_new_transaction(
	struct pqcp_sovereign_channel_server *server,
	uint32_t stream_id,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_server_slot *slot;
	uint8_t identity_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t capability_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t request_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	size_t slot_index = 0U;
	uint64_t lifetime_end;
	int ret;

	if (frame->flags !=
		    PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST ||
	    frame->sequence != 0U ||
	    slot_by_ids(
		    server, frame->transaction_id,
		    frame->request_id) != NULL ||
	    slot_by_stream(server, stream_id) != NULL) {
		return -EALREADY;
	}
	ret = validate_begin_time(&frame->body.begin, now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = resolve_and_bind_identity(
		server, &frame->body.begin, identity_digest);
	if (ret == 0) {
		ret = digest_capability(
			frame->body.begin.capability,
			capability_digest);
	}
	if (ret == 0) {
		ret = hash_begin(
			&frame->body.begin,
			frame->transaction_id,
			frame->request_id, request_digest);
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			identity_digest, sizeof(identity_digest));
		pqcp_runtime_secure_zero(
			capability_digest,
			sizeof(capability_digest));
		pqcp_runtime_secure_zero(
			request_digest, sizeof(request_digest));
		return ret;
	}
	slot = free_slot(server, &slot_index);
	if (slot == NULL) {
		ret = -ENOSPC;
		goto out;
	}
	if (now_ms >
	    UINT64_MAX -
		    server->config.transaction_lifetime_ms) {
		ret = -EOVERFLOW;
		goto out;
	}
	lifetime_end =
		now_ms + server->config.transaction_lifetime_ms;
	memset(slot, 0, sizeof(*slot));
	slot->schema_version =
		PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION;
	slot->generation =
		pqcp_sovereign_channel_internal_next_generation(
			&server->next_generation);
	slot->state =
		PQCP_SOVEREIGN_CHANNEL_SERVER_RECEIVING;
	slot->stream_id = stream_id;
	slot->next_receive_sequence = 1U;
	slot->created_at_ms = now_ms;
	slot->last_activity_ms = now_ms;
	slot->expires_at_ms =
		frame->body.begin.deadline_ms < lifetime_end ?
			frame->body.begin.deadline_ms :
			lifetime_end;
	memcpy(slot->transaction_id, frame->transaction_id,
	       sizeof(slot->transaction_id));
	memcpy(slot->request_id, frame->request_id,
	       sizeof(slot->request_id));
	memcpy(slot->identity_digest, identity_digest,
	       sizeof(slot->identity_digest));
	memcpy(slot->capability_digest, capability_digest,
	       sizeof(slot->capability_digest));
	memcpy(slot->request_digest, request_digest,
	       sizeof(slot->request_digest));
	memcpy(slot->principal_id,
	       frame->body.begin.principal_id,
	       sizeof(slot->principal_id));
	memcpy(slot->tenant_id,
	       frame->body.begin.tenant_id,
	       sizeof(slot->tenant_id));
	slot->begin = frame->body.begin;
	slot->buffers = server->storage.buffers[slot_index];
	slot->response.output = slot->buffers.output;
	slot->response.output_capacity =
		slot->buffers.output_capacity;
	slot->occupied = true;
	ret = pqcp_sovereign_channel_request_assembler_init(
		&slot->assembler, &slot->begin,
		slot->transaction_id, slot->request_id,
		slot->buffers.input,
		slot->buffers.input_capacity,
		slot->buffers.aux_input,
		slot->buffers.aux_input_capacity,
		slot->buffers.context,
		slot->buffers.context_capacity);
	if (ret != 0) {
		(void)secure_reset_slot(slot);
		goto out;
	}
	ret = send_checkpoint(
		server, slot,
		PQCP_SOVEREIGN_CHANNEL_WINDOW_BEGIN_ACCEPTED,
		0U, PQCP_SOVEREIGN_CHANNEL_FLAG_ACCEPTED,
		now_ms);
	if (ret != 0) {
		(void)secure_reset_slot(slot);
		goto out;
	}
	server->accepted_transactions++;
out:
	pqcp_runtime_secure_zero(
		identity_digest, sizeof(identity_digest));
	pqcp_runtime_secure_zero(
		capability_digest, sizeof(capability_digest));
	pqcp_runtime_secure_zero(
		request_digest, sizeof(request_digest));
	return ret;
}

static int begin_resumed_transaction(
	struct pqcp_sovereign_channel_server *server,
	uint32_t stream_id,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_server_slot *slot;
	struct pqcp_sovereign_channel_resume_claim claim;
	uint8_t identity_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES] = {0};
	uint8_t capability_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES] = {0};
	uint8_t request_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES] = {0};
	enum pqcp_sovereign_channel_server_state state;
	uint32_t flags =
		PQCP_SOVEREIGN_CHANNEL_FLAG_ACCEPTED |
		PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME;
	int ret;

	if (frame->flags !=
		    (PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST |
		     PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME) ||
	    frame->sequence != 0U ||
	    !frame->body.begin.has_resume_token ||
	    slot_by_stream(server, stream_id) != NULL) {
		return -EPROTO;
	}
	slot = slot_by_ids(
		server, frame->transaction_id,
		frame->request_id);
	if (slot == NULL ||
	    slot->state !=
		    PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED ||
	    now_ms > slot->expires_at_ms ||
	    (slot->disconnected_at_ms != 0U &&
	     (now_ms < slot->disconnected_at_ms ||
	      now_ms - slot->disconnected_at_ms >
		      server->config.disconnected_retention_ms))) {
		return -ESTALE;
	}
	ret = validate_begin_time(&frame->body.begin, now_ms);
	if (ret == 0) {
		ret = resolve_and_bind_identity(
			server, &frame->body.begin,
			identity_digest);
	}
	if (ret == 0) {
		ret = digest_capability(
			frame->body.begin.capability,
			capability_digest);
	}
	if (ret == 0) {
		ret = hash_begin(
			&frame->body.begin,
			frame->transaction_id,
			frame->request_id, request_digest);
	}
	if (ret == 0 &&
	    (!pqcp_sovereign_channel_internal_equal(
		    identity_digest, slot->identity_digest,
		    sizeof(identity_digest)) ||
	     !pqcp_sovereign_channel_internal_equal(
		    capability_digest, slot->capability_digest,
		    sizeof(capability_digest)) ||
	     !pqcp_sovereign_channel_internal_equal(
		    request_digest, slot->request_digest,
		    sizeof(request_digest)))) {
		ret = -EKEYREJECTED;
	}
	if (ret == 0) {
		ret = pqcp_sovereign_channel_resume_claim_from_slot(
			slot, &claim);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_channel_resume_token_verify(
			server->config.resume_secret,
			server->config.resume_secret_length,
			&claim,
			frame->body.begin.resume_token, now_ms);
	}
	if (ret != 0) {
		goto out;
	}
	slot->result_send_offset = slot->result_ack_offset;
	slot->receipt_send_offset = slot->receipt_ack_offset;
	state = resumed_state(slot);
	slot->result_announced = false;
	slot->receipt_announced = false;
	slot->stream_id = stream_id;
	slot->next_receive_sequence = 1U;
	slot->next_send_sequence = 0U;
	slot->disconnected_at_ms = 0U;
	slot->last_activity_ms = now_ms;
	slot->state = state;
	if (slot->assembler.committed) {
		flags |= PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL;
	}
	ret = send_checkpoint(
		server, slot,
		PQCP_SOVEREIGN_CHANNEL_WINDOW_RESUME_ACCEPTED,
		slot->assembler.received_length, flags, now_ms);
	if (ret == 0) {
		server->resumed_transactions++;
	}
out:
	pqcp_runtime_secure_zero(&claim, sizeof(claim));
	pqcp_runtime_secure_zero(
		identity_digest, sizeof(identity_digest));
	pqcp_runtime_secure_zero(
		capability_digest, sizeof(capability_digest));
	pqcp_runtime_secure_zero(
		request_digest, sizeof(request_digest));
	return ret;
}

static int handle_begin(
	struct pqcp_sovereign_channel_server *server,
	uint32_t stream_id,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	if ((frame->flags &
	     PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME) != 0U) {
		return begin_resumed_transaction(
			server, stream_id, frame, now_ms);
	}
	return begin_new_transaction(
		server, stream_id, frame, now_ms);
}

static int handle_chunk(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	uint64_t next_offset;
	bool final;
	int ret;

	if (slot->state !=
		    PQCP_SOVEREIGN_CHANNEL_SERVER_RECEIVING ||
	    frame->flags &
		    ~PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL) {
		return -EPROTO;
	}
	next_offset = frame->body.chunk.offset +
		frame->body.chunk.data_length;
	final = (frame->flags &
		 PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL) != 0U;
	if (next_offset < frame->body.chunk.offset ||
	    final !=
		    (next_offset ==
		     slot->assembler.expected_total_length)) {
		return -EBADMSG;
	}
	ret = pqcp_sovereign_channel_request_assembler_append(
		&slot->assembler, &frame->body.chunk);
	if (ret != 0) {
		return ret;
	}
	return send_checkpoint(
		server, slot,
		PQCP_SOVEREIGN_CHANNEL_WINDOW_REQUEST_ACK,
		slot->assembler.received_length,
		PQCP_SOVEREIGN_CHANNEL_FLAG_ACK |
		(final ?
		 PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL : 0U),
		now_ms);
}

static int handle_commit(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	int ret;

	if (slot->state !=
		    PQCP_SOVEREIGN_CHANNEL_SERVER_RECEIVING ||
	    frame->flags !=
		    PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL) {
		return -EPROTO;
	}
	ret = pqcp_sovereign_channel_request_assembler_commit(
		&slot->assembler, &frame->body.commit);
	if (ret != 0) {
		return ret;
	}
	slot->state = PQCP_SOVEREIGN_CHANNEL_SERVER_READY;
	return send_checkpoint(
		server, slot,
		PQCP_SOVEREIGN_CHANNEL_WINDOW_REQUEST_ACK,
		slot->assembler.received_length,
		PQCP_SOVEREIGN_CHANNEL_FLAG_ACK |
		PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL,
		now_ms);
}

static int handle_cancel(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	int ret = 0;

	if (frame->flags !=
		    PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL ||
	    server_terminal_state(slot->state)) {
		return -EPROTO;
	}
	if (slot->broker_executed) {
		ret = pqcp_sovereign_channel_broker_cancel(
			server->config.broker,
			slot->principal_id, slot->request_id,
			now_ms);
		if (ret == -EALREADY || ret == -ENOENT) {
			ret = 0;
		}
	}
	if (ret != 0) {
		return ret;
	}
	slot->state =
		PQCP_SOVEREIGN_CHANNEL_SERVER_CANCELLED;
	slot->terminal_result =
		frame->body.cancel.error_code != 0 ?
			frame->body.cancel.error_code :
			-ECANCELED;
	server->cancelled_transactions++;
	ret = send_checkpoint(
		server, slot,
		PQCP_SOVEREIGN_CHANNEL_WINDOW_COMPLETE,
		slot->assembler.received_length,
		PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL |
		PQCP_SOVEREIGN_CHANNEL_FLAG_ACK,
		now_ms);
	if (ret == 0) {
		ret = pqcp_channel_stream_close(
			server->config.multiplexer,
			slot->stream_id,
			PQCP_CHANNEL_STREAM_ERROR_CANCELLED,
			now_ms);
		if (ret == -EALREADY) {
			ret = 0;
		}
	}
	return ret;
}

static int handle_result_ack(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	const struct pqcp_sovereign_channel_result *result =
		&frame->body.result;
	int ret;

	if (frame->flags !=
		    PQCP_SOVEREIGN_CHANNEL_FLAG_ACK ||
	    slot->state !=
		    PQCP_SOVEREIGN_CHANNEL_SERVER_WAITING_ACK ||
	    !slot->result_announced ||
	    result->ack_offset != slot->result_send_offset ||
	    result->ack_offset < slot->result_ack_offset ||
	    result->ack_offset >
		    slot->response.output_length ||
	    !pqcp_sovereign_channel_internal_equal(
		    result->content_digest, slot->result_digest,
		    sizeof(slot->result_digest))) {
		return -EBADMSG;
	}
	slot->result_ack_offset = result->ack_offset;
	slot->result_announced = false;
	ret = send_checkpoint(
		server, slot,
		PQCP_SOVEREIGN_CHANNEL_WINDOW_RESULT_ACK,
		slot->result_ack_offset,
		PQCP_SOVEREIGN_CHANNEL_FLAG_ACK,
		now_ms);
	if (ret != 0) {
		return ret;
	}
	if (slot->result_ack_offset <
	    slot->response.output_length) {
		slot->state =
			PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RESULT;
		return 0;
	}
	if (slot->receipt_length != 0U) {
		slot->state =
			PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RECEIPT;
		return 0;
	}
	return send_complete(server, slot, now_ms);
}

static int handle_receipt_ack(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	const struct pqcp_sovereign_channel_receipt_frame *receipt =
		&frame->body.receipt;
	int ret;

	if (frame->flags !=
		    PQCP_SOVEREIGN_CHANNEL_FLAG_ACK ||
	    slot->state !=
		    PQCP_SOVEREIGN_CHANNEL_SERVER_WAITING_ACK ||
	    !slot->receipt_announced ||
	    receipt->ack_offset != slot->receipt_send_offset ||
	    receipt->ack_offset < slot->receipt_ack_offset ||
	    receipt->ack_offset > slot->receipt_length ||
	    !pqcp_sovereign_channel_internal_equal(
		    receipt->content_digest,
		    slot->receipt_digest,
		    sizeof(slot->receipt_digest))) {
		return -EBADMSG;
	}
	slot->receipt_ack_offset = receipt->ack_offset;
	slot->receipt_announced = false;
	ret = send_checkpoint(
		server, slot,
		PQCP_SOVEREIGN_CHANNEL_WINDOW_RECEIPT_ACK,
		slot->receipt_ack_offset,
		PQCP_SOVEREIGN_CHANNEL_FLAG_ACK,
		now_ms);
	if (ret != 0) {
		return ret;
	}
	if (slot->receipt_ack_offset < slot->receipt_length) {
		slot->state =
			PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RECEIPT;
		return 0;
	}
	return send_complete(server, slot, now_ms);
}

static int handle_window(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	const struct pqcp_sovereign_channel_frame *frame)
{
	if (frame->flags != 0U ||
	    frame->body.window.kind !=
		    PQCP_SOVEREIGN_CHANNEL_WINDOW_CREDIT) {
		return -EPROTO;
	}
	return pqcp_sovereign_channel_flow_apply_window(
		&server->flow, slot->stream_id,
		&frame->body.window);
}

static int dispatch_slot_frame(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	switch (frame->type) {
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CHUNK:
		return handle_chunk(server, slot, frame, now_ms);
	case PQCP_SOVEREIGN_CHANNEL_FRAME_COMMIT:
		return handle_commit(server, slot, frame, now_ms);
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CANCEL:
		return handle_cancel(server, slot, frame, now_ms);
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RESULT:
		return handle_result_ack(server, slot, frame, now_ms);
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RECEIPT:
		return handle_receipt_ack(
			server, slot, frame, now_ms);
	case PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW:
		return handle_window(server, slot, frame);
	default:
		return -EPROTO;
	}
}

static int account_received_frame(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	const struct pqcp_channel_stream_header *stream_header,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_window credit;
	int ret;

	memset(&credit, 0, sizeof(credit));
	ret = pqcp_sovereign_channel_flow_receive_account(
		&server->flow, stream_header->stream_id,
		stream_header->payload_length, &credit);
	if (ret == 0 && slot != NULL &&
	    (credit.connection_credit != 0U ||
	     credit.stream_credit != 0U)) {
		ret = send_credit(
			server, slot, &credit, now_ms);
	}
	return ret;
}

static int receive_server_frame(
	struct pqcp_sovereign_channel_server *server,
	uint8_t encoded[PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES],
	size_t *encoded_length,
	struct pqcp_channel_stream_header *stream_header,
	struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	int ret;

	if (server == NULL || encoded == NULL ||
	    encoded_length == NULL || stream_header == NULL ||
	    frame == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	*encoded_length = 0U;
	ret = pqcp_channel_stream_receive(
		server->config.multiplexer, encoded,
		PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES,
		encoded_length, stream_header, now_ms);
	if (ret != 0) {
		return ret;
	}
	if (stream_header->type !=
		    PQCP_CHANNEL_STREAM_FRAME_DATA) {
		return -EAGAIN;
	}
	if (*encoded_length == 0U ||
	    *encoded_length != stream_header->payload_length) {
		return -EBADMSG;
	}
	return pqcp_sovereign_channel_frame_decode(
		encoded, *encoded_length, frame);
}

int pqcp_sovereign_channel_server_init(
	struct pqcp_sovereign_channel_server *server,
	const struct pqcp_sovereign_channel_server_config *config,
	const struct pqcp_sovereign_channel_server_storage *storage)
{
	int ret;

	if (server == NULL) {
		return -EINVAL;
	}
	ret = validate_server_configuration(config, storage);
	if (ret != 0) {
		return ret;
	}
	memset(server, 0, sizeof(*server));
	memset(storage->slots, 0,
	       storage->capacity * sizeof(*storage->slots));
	server->config = *config;
	server->storage = *storage;
	k_mutex_init(&server->lock);
	ret = pqcp_sovereign_channel_flow_init(
		&server->flow, config->multiplexer,
		config->flow_controller);
	if (ret != 0) {
		memset(server, 0, sizeof(*server));
		return ret;
	}
	server->initialized = true;
	return 0;
}

int pqcp_sovereign_channel_server_receive(
	struct pqcp_sovereign_channel_server *server,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES];
	struct pqcp_channel_stream_header stream_header;
	struct pqcp_sovereign_channel_frame frame;
	struct pqcp_sovereign_channel_server_slot *slot;
	size_t encoded_length = 0U;
	int ret;
	int account_ret;

	if (server == NULL || !server->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_server(server);
	if (ret != 0) {
		return ret;
	}
	memset(&stream_header, 0, sizeof(stream_header));
	memset(&frame, 0, sizeof(frame));
	ret = receive_server_frame(
		server, encoded, &encoded_length,
		&stream_header, &frame, now_ms);
	if (ret == -EAGAIN) {
		unlock_server(server);
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return 0;
	}
	if (ret != 0) {
		server->rejected_frames++;
		unlock_server(server);
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return ret;
	}
	slot = slot_by_stream(
		server, stream_header.stream_id);
	account_ret = account_received_frame(
		server, slot, &stream_header, now_ms);
	if (account_ret != 0) {
		server->rejected_frames++;
		unlock_server(server);
		pqcp_runtime_secure_zero(&frame, sizeof(frame));
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return account_ret;
	}
	if (frame.type == PQCP_SOVEREIGN_CHANNEL_FRAME_BEGIN) {
		ret = handle_begin(
			server, stream_header.stream_id,
			&frame, now_ms);
		if (ret != 0) {
			server->rejected_frames++;
			(void)send_error_frame(
				server, stream_header.stream_id, 0U,
				frame.transaction_id,
				frame.request_id, ret,
				(frame.flags &
				 PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME) !=
						0U ?
					PQCP_SOVEREIGN_CHANNEL_STAGE_RESUME :
					PQCP_SOVEREIGN_CHANNEL_STAGE_BEGIN,
				ret == -ENOSPC || ret == -EAGAIN,
				ret == -EAGAIN ? 10U : 0U,
				"begin rejected", now_ms);
		}
		unlock_server(server);
		pqcp_runtime_secure_zero(&frame, sizeof(frame));
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return ret;
	}
	if (slot == NULL ||
	    frame.sequence != slot->next_receive_sequence ||
	    !pqcp_sovereign_channel_internal_equal(
		    frame.transaction_id, slot->transaction_id,
		    sizeof(slot->transaction_id)) ||
	    !pqcp_sovereign_channel_internal_equal(
		    frame.request_id, slot->request_id,
		    sizeof(slot->request_id))) {
		server->rejected_frames++;
		unlock_server(server);
		pqcp_runtime_secure_zero(&frame, sizeof(frame));
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return slot == NULL ? -ENOENT : -EALREADY;
	}
	ret = dispatch_slot_frame(server, slot, &frame, now_ms);
	if (ret == 0) {
		slot->next_receive_sequence++;
		slot->last_activity_ms = now_ms;
	} else {
		enum pqcp_sovereign_channel_error_stage stage =
			frame.type ==
				PQCP_SOVEREIGN_CHANNEL_FRAME_CHUNK ?
				PQCP_SOVEREIGN_CHANNEL_STAGE_ASSEMBLY :
			frame.type ==
				PQCP_SOVEREIGN_CHANNEL_FRAME_COMMIT ?
				PQCP_SOVEREIGN_CHANNEL_STAGE_COMMIT :
			frame.type ==
				PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW ?
				PQCP_SOVEREIGN_CHANNEL_STAGE_FLOW :
				PQCP_SOVEREIGN_CHANNEL_STAGE_RESULT;

		server->rejected_frames++;
		slot->terminal_result = ret;
		slot->state =
			PQCP_SOVEREIGN_CHANNEL_SERVER_FAILED;
		server->failed_transactions++;
		(void)send_error_frame(
			server, slot->stream_id,
			slot->next_send_sequence,
			slot->transaction_id, slot->request_id,
			ret, stage, ret == -EAGAIN,
			ret == -EAGAIN ? 10U : 0U,
			"transaction frame rejected", now_ms);
	}
	unlock_server(server);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static int execute_slot(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot)
{
	int ret;
	int receipt_ret;

	slot->state =
		PQCP_SOVEREIGN_CHANNEL_SERVER_EXECUTING;
	slot->response.output = slot->buffers.output;
	slot->response.output_capacity =
		slot->buffers.output_capacity;
	ret = pqcp_sovereign_channel_broker_execute(
		server->config.broker, &slot->begin,
		&slot->assembler, &slot->response);
	slot->terminal_result = ret;
	slot->broker_executed = true;
	if (slot->response.output_length >
	    slot->buffers.output_capacity) {
		return -EOVERFLOW;
	}
	receipt_ret = 0;
	if (slot->response.receipt.sequence != 0U) {
		receipt_ret =
			pqcp_sovereign_channel_receipt_encode(
				&slot->response.receipt,
				slot->buffers.receipt,
				slot->buffers.receipt_capacity,
				&slot->receipt_length);
	}
	if (receipt_ret != 0) {
		return receipt_ret;
	}
	ret = pqcp_runtime_internal_sha256(
		slot->buffers.output,
		slot->response.output_length,
		slot->result_digest);
	if (ret != 0) {
		return ret;
	}
	if (slot->receipt_length != 0U) {
		ret = pqcp_sovereign_channel_internal_receipt_digest(
			slot->buffers.receipt,
			slot->receipt_length,
			slot->receipt_digest);
		if (ret != 0) {
			return ret;
		}
	}
	slot->state =
		PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RESULT;
	return 0;
}

static int send_result_chunk(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	size_t remaining;
	size_t chunk_length;
	bool first;
	bool final;
	int ret;

	if (slot->result_send_offset >
	    slot->response.output_length) {
		return -EOVERFLOW;
	}
	remaining = slot->response.output_length -
		slot->result_send_offset;
	chunk_length = remaining >
			SOVEREIGN_SERVER_RESULT_CHUNK_BYTES ?
		SOVEREIGN_SERVER_RESULT_CHUNK_BYTES :
		remaining;
	first = slot->result_send_offset == 0U;
	final = chunk_length == remaining;
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_RESULT,
		(first ? PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST : 0U) |
		(final ? PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL : 0U) |
		(slot->response.replayed ?
		 PQCP_SOVEREIGN_CHANNEL_FLAG_REPLAYED : 0U) |
		(slot->response.cancelled ?
		 PQCP_SOVEREIGN_CHANNEL_FLAG_CANCELLED : 0U),
		slot->next_send_sequence,
		slot->transaction_id, slot->request_id);
	frame.body.result.result_code =
		slot->response.result;
	frame.body.result.result_flags = 0U;
	frame.body.result.primary_key =
		slot->response.primary_key;
	frame.body.result.secondary_key =
		slot->response.secondary_key;
	frame.body.result.metadata =
		slot->response.metadata;
	frame.body.result.total_length =
		slot->response.output_length;
	frame.body.result.offset = slot->result_send_offset;
	frame.body.result.data =
		chunk_length != 0U ?
			slot->buffers.output +
				slot->result_send_offset :
			NULL;
	frame.body.result.data_length = chunk_length;
	memcpy(frame.body.result.content_digest,
	       slot->result_digest,
	       sizeof(frame.body.result.content_digest));
	ret = send_slot_frame(server, slot, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	if (ret != 0) {
		return ret;
	}
	slot->result_announced = true;
	slot->result_send_offset += chunk_length;
	slot->state =
		PQCP_SOVEREIGN_CHANNEL_SERVER_WAITING_ACK;
	return 0;
}

static int send_receipt_chunk(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	size_t remaining;
	size_t chunk_length;
	bool first;
	bool final;
	int ret;

	if (slot->receipt_length == 0U ||
	    slot->receipt_send_offset > slot->receipt_length) {
		return -EINVAL;
	}
	remaining =
		slot->receipt_length - slot->receipt_send_offset;
	chunk_length = remaining >
			SOVEREIGN_SERVER_RESULT_CHUNK_BYTES ?
		SOVEREIGN_SERVER_RESULT_CHUNK_BYTES :
		remaining;
	first = slot->receipt_send_offset == 0U;
	final = chunk_length == remaining;
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_RECEIPT,
		(first ? PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST : 0U) |
		(final ? PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL : 0U),
		slot->next_send_sequence,
		slot->transaction_id, slot->request_id);
	frame.body.receipt.total_length =
		slot->receipt_length;
	frame.body.receipt.offset =
		slot->receipt_send_offset;
	frame.body.receipt.data =
		slot->buffers.receipt +
		slot->receipt_send_offset;
	frame.body.receipt.data_length = chunk_length;
	memcpy(frame.body.receipt.content_digest,
	       slot->receipt_digest,
	       sizeof(frame.body.receipt.content_digest));
	frame.body.receipt.receipt_sequence =
		slot->response.receipt.sequence;
	memcpy(frame.body.receipt.receipt_digest,
	       slot->response.receipt.receipt_digest,
	       sizeof(frame.body.receipt.receipt_digest));
	ret = send_slot_frame(server, slot, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	if (ret != 0) {
		return ret;
	}
	slot->receipt_announced = true;
	slot->receipt_send_offset += chunk_length;
	slot->state =
		PQCP_SOVEREIGN_CHANNEL_SERVER_WAITING_ACK;
	return 0;
}

static int progress_slot(
	struct pqcp_sovereign_channel_server *server,
	struct pqcp_sovereign_channel_server_slot *slot,
	uint64_t now_ms)
{
	int ret;

	switch (slot->state) {
	case PQCP_SOVEREIGN_CHANNEL_SERVER_READY:
		ret = execute_slot(server, slot);
		if (ret != 0) {
			return ret;
		}
		return send_result_chunk(server, slot, now_ms);
	case PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RESULT:
		return send_result_chunk(server, slot, now_ms);
	case PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RECEIPT:
		return send_receipt_chunk(server, slot, now_ms);
	default:
		return 0;
	}
}

int pqcp_sovereign_channel_server_progress(
	struct pqcp_sovereign_channel_server *server,
	uint64_t now_ms)
{
	int ret;

	if (server == NULL || !server->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_server(server);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < server->storage.capacity; ++index) {
		struct pqcp_sovereign_channel_server_slot *slot =
			&server->storage.slots[index];

		if (!slot->occupied ||
		    slot->state ==
			    PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED ||
		    server_terminal_state(slot->state)) {
			continue;
		}
		if (now_ms > slot->expires_at_ms) {
			slot->terminal_result = -ETIMEDOUT;
			slot->state =
				PQCP_SOVEREIGN_CHANNEL_SERVER_FAILED;
			server->failed_transactions++;
			(void)send_error_frame(
				server, slot->stream_id,
				slot->next_send_sequence,
				slot->transaction_id,
				slot->request_id, -ETIMEDOUT,
				PQCP_SOVEREIGN_CHANNEL_STAGE_BROKER,
				false, 0U,
				"transaction expired", now_ms);
			continue;
		}
		ret = progress_slot(server, slot, now_ms);
		if (ret == -EAGAIN) {
			continue;
		}
		if (ret != 0) {
			slot->terminal_result = ret;
			slot->state =
				PQCP_SOVEREIGN_CHANNEL_SERVER_FAILED;
			server->failed_transactions++;
			(void)send_error_frame(
				server, slot->stream_id,
				slot->next_send_sequence,
				slot->transaction_id,
				slot->request_id, ret,
				PQCP_SOVEREIGN_CHANNEL_STAGE_RESULT,
				false, 0U,
				"server progress failed", now_ms);
			unlock_server(server);
			return ret;
		}
	}
	unlock_server(server);
	return 0;
}

int pqcp_sovereign_channel_server_disconnect(
	struct pqcp_sovereign_channel_server *server,
	uint32_t stream_id,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_server_slot *slot;
	int ret;

	if (server == NULL || !server->initialized ||
	    stream_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_server(server);
	if (ret != 0) {
		return ret;
	}
	slot = slot_by_stream(server, stream_id);
	if (slot == NULL) {
		unlock_server(server);
		return -ENOENT;
	}
	if (server_terminal_state(slot->state)) {
		unlock_server(server);
		return -EALREADY;
	}
	slot->state =
		PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED;
	slot->disconnected_at_ms = now_ms;
	slot->last_activity_ms = now_ms;
	ret = pqcp_channel_stream_close(
		server->config.multiplexer, stream_id,
		PQCP_CHANNEL_STREAM_ERROR_TIMEOUT, now_ms);
	if (ret == -EALREADY || ret == -ESHUTDOWN) {
		ret = 0;
	}
	unlock_server(server);
	return ret;
}

int pqcp_sovereign_channel_server_tick(
	struct pqcp_sovereign_channel_server *server,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret;

	if (server == NULL || !server->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = lock_server(server);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < server->storage.capacity; ++index) {
		struct pqcp_sovereign_channel_server_slot *slot =
			&server->storage.slots[index];
		bool disconnected_expired;

		if (!slot->occupied) {
			continue;
		}
		disconnected_expired =
			slot->state ==
				PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED &&
			slot->disconnected_at_ms != 0U &&
			now_ms >= slot->disconnected_at_ms &&
			now_ms - slot->disconnected_at_ms >
				server->config.disconnected_retention_ms;
		if (now_ms <= slot->expires_at_ms &&
		    !disconnected_expired) {
			continue;
		}
		if (!server_terminal_state(slot->state) &&
		    slot->broker_executed) {
			(void)pqcp_sovereign_channel_broker_cancel(
				server->config.broker,
				slot->principal_id,
				slot->request_id, now_ms);
		}
		if (slot->stream_id != 0U &&
		    slot->state !=
			    PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED) {
			(void)pqcp_channel_stream_close(
				server->config.multiplexer,
				slot->stream_id,
				PQCP_CHANNEL_STREAM_ERROR_TIMEOUT,
				now_ms);
		}
		(void)secure_reset_slot(slot);
		if (expired != UINT32_MAX) {
			expired++;
		}
	}
	*expired_count = expired;
	unlock_server(server);
	return 0;
}

static int audit_slot(
	const struct pqcp_sovereign_channel_server *server,
	const struct pqcp_sovereign_channel_server_slot *slot,
	size_t slot_index)
{
	if (!slot->occupied) {
		return slot->state ==
			       PQCP_SOVEREIGN_CHANNEL_SERVER_EMPTY ?
			0 : -EBADMSG;
	}
	if (slot->schema_version !=
		    PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION ||
	    slot->generation == 0U ||
	    !server_state_valid(slot->state) ||
	    slot->state ==
		    PQCP_SOVEREIGN_CHANNEL_SERVER_EMPTY ||
	    slot->created_at_ms == 0U ||
	    slot->last_activity_ms < slot->created_at_ms ||
	    slot->expires_at_ms < slot->created_at_ms ||
	    pqcp_sovereign_channel_internal_all_zero(
		    slot->transaction_id,
		    sizeof(slot->transaction_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    slot->request_id,
		    sizeof(slot->request_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    slot->identity_digest,
		    sizeof(slot->identity_digest)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    slot->capability_digest,
		    sizeof(slot->capability_digest)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    slot->request_digest,
		    sizeof(slot->request_digest)) ||
	    slot->principal_id[0] == '\0' ||
	    slot->tenant_id[0] == '\0' ||
	    memcmp(&slot->buffers,
		   &server->storage.buffers[slot_index],
		   sizeof(slot->buffers)) != 0 ||
	    slot->response.output != slot->buffers.output ||
	    slot->response.output_capacity !=
		    slot->buffers.output_capacity ||
	    slot->response.output_length >
		    slot->buffers.output_capacity ||
	    slot->result_ack_offset >
		    slot->result_send_offset ||
	    slot->result_send_offset >
		    slot->response.output_length ||
	    slot->receipt_ack_offset >
		    slot->receipt_send_offset ||
	    slot->receipt_send_offset >
		    slot->receipt_length ||
	    slot->receipt_length >
		    slot->buffers.receipt_capacity ||
	    (slot->state ==
		     PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED &&
	     slot->disconnected_at_ms == 0U) ||
	    (slot->state !=
		     PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED &&
	     slot->stream_id == 0U)) {
		return -EBADMSG;
	}
	if (pqcp_sovereign_channel_request_assembler_audit(
		    &slot->assembler) != 0) {
		return -EBADMSG;
	}
	if (slot->broker_executed &&
	    pqcp_sovereign_channel_internal_all_zero(
		    slot->result_digest,
		    sizeof(slot->result_digest))) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_sovereign_channel_server_audit(
	struct pqcp_sovereign_channel_server *server)
{
	int ret;

	if (server == NULL || !server->initialized) {
		return -EINVAL;
	}
	ret = lock_server(server);
	if (ret != 0) {
		return ret;
	}
	ret = validate_server_configuration(
		&server->config, &server->storage);
	for (size_t index = 0U;
	     ret == 0 && index < server->storage.capacity;
	     ++index) {
		ret = audit_slot(
			server, &server->storage.slots[index],
			index);
		for (size_t other = index + 1U;
		     ret == 0 &&
		     other < server->storage.capacity;
		     ++other) {
			const struct pqcp_sovereign_channel_server_slot
				*left =
					&server->storage.slots[index];
			const struct pqcp_sovereign_channel_server_slot
				*right =
					&server->storage.slots[other];

			if (!left->occupied || !right->occupied) {
				continue;
			}
			if (pqcp_sovereign_channel_internal_equal(
				    left->transaction_id,
				    right->transaction_id,
				    sizeof(left->transaction_id)) ||
			    (left->stream_id != 0U &&
			     left->stream_id == right->stream_id &&
			     left->state !=
				     PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED &&
			     right->state !=
				     PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED)) {
				ret = -EEXIST;
			}
		}
	}
	unlock_server(server);
	if (ret == 0) {
		ret = pqcp_sovereign_channel_flow_audit(
			&server->flow);
	}
	return ret;
}
