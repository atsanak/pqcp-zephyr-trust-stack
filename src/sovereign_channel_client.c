/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free sovereign broker channel client.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_channel_internal.h"

#define SOVEREIGN_CLIENT_REQUEST_CHUNK_BYTES 3800U

static bool client_state_valid(
	enum pqcp_sovereign_channel_client_state state)
{
	return state >= PQCP_SOVEREIGN_CHANNEL_CLIENT_EMPTY &&
	       state <= PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED;
}

static bool client_terminal_state(
	enum pqcp_sovereign_channel_client_state state)
{
	return state == PQCP_SOVEREIGN_CHANNEL_CLIENT_COMPLETED ||
	       state == PQCP_SOVEREIGN_CHANNEL_CLIENT_CANCELLED ||
	       state == PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED;
}

static int lock_client(
	struct pqcp_sovereign_channel_client *client)
{
	if (client == NULL || !client->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&client->lock, K_FOREVER);
}

static void unlock_client(
	struct pqcp_sovereign_channel_client *client)
{
	(void)k_mutex_unlock(&client->lock);
}

static int validate_client_configuration(
	const struct pqcp_sovereign_channel_client_config *config,
	const struct pqcp_sovereign_channel_client_storage *storage)
{
	if (config == NULL || storage == NULL ||
	    config->multiplexer == NULL ||
	    !config->multiplexer->initialized ||
	    config->flow_controller == NULL ||
	    !config->flow_controller->initialized ||
	    config->transaction_lifetime_ms == 0U ||
	    config->stream_priority > 255U ||
	    storage->transactions == NULL ||
	    storage->capacity == 0U ||
	    config->multiplexer->channel == NULL ||
	    config->multiplexer->channel->config.role !=
		    PQCP_CHANNEL_ROLE_CLIENT ||
	    config->multiplexer->channel->state !=
		    PQCP_CHANNEL_STATE_ESTABLISHED ||
	    !config->multiplexer->channel->established ||
	    !config->multiplexer->channel->peer_authenticated) {
		return -EINVAL;
	}
	return 0;
}

static struct pqcp_sovereign_channel_client_transaction *free_transaction(
	struct pqcp_sovereign_channel_client *client)
{
	struct pqcp_sovereign_channel_client_transaction *oldest =
		NULL;

	for (size_t index = 0U;
	     index < client->storage.capacity; ++index) {
		struct pqcp_sovereign_channel_client_transaction
			*transaction =
				&client->storage.transactions[index];

		if (!transaction->occupied) {
			return transaction;
		}
		if (client_terminal_state(transaction->state) &&
		    (oldest == NULL ||
		     transaction->last_activity_ms <
			     oldest->last_activity_ms)) {
			oldest = transaction;
		}
	}
	if (oldest != NULL) {
		if (oldest->result != NULL &&
		    oldest->result_capacity != 0U) {
			pqcp_runtime_secure_zero(
				oldest->result,
				oldest->result_capacity);
		}
		if (oldest->receipt != NULL &&
		    oldest->receipt_capacity != 0U) {
			pqcp_runtime_secure_zero(
				oldest->receipt,
				oldest->receipt_capacity);
		}
		pqcp_runtime_secure_zero(
			oldest, sizeof(*oldest));
	}
	return oldest;
}

static struct pqcp_sovereign_channel_client_transaction
	*transaction_by_stream(
		struct pqcp_sovereign_channel_client *client,
		uint32_t stream_id)
{
	if (client == NULL || stream_id == 0U) {
		return NULL;
	}
	for (size_t index = 0U;
	     index < client->storage.capacity; ++index) {
		struct pqcp_sovereign_channel_client_transaction
			*transaction =
				&client->storage.transactions[index];

		if (transaction->occupied &&
		    transaction->stream_id == stream_id) {
			return transaction;
		}
	}
	return NULL;
}

static bool transaction_belongs_to_client(
	const struct pqcp_sovereign_channel_client *client,
	const struct pqcp_sovereign_channel_client_transaction
		*transaction)
{
	if (client == NULL || transaction == NULL ||
	    client->storage.transactions == NULL) {
		return false;
	}
	for (size_t index = 0U;
	     index < client->storage.capacity; ++index) {
		if (&client->storage.transactions[index] ==
		    transaction) {
			return transaction->occupied;
		}
	}
	return false;
}

static uint64_t request_total(
	const struct pqcp_sovereign_channel_client_transaction
		*transaction)
{
	return (uint64_t)transaction->input_length +
	       (uint64_t)transaction->aux_input_length +
	       (uint64_t)transaction->context_length;
}

static int validate_begin_and_body(
	const struct pqcp_sovereign_channel_begin *begin,
	const uint8_t *input,
	size_t input_length,
	const uint8_t *aux_input,
	size_t aux_input_length,
	const uint8_t *context,
	size_t context_length,
	uint64_t now_ms)
{
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	int ret;

	if (begin == NULL || now_ms == 0U ||
	    begin->operation <=
		    PQCP_CRYPTO_BROKER_OPERATION_NONE ||
	    begin->operation >=
		    PQCP_CRYPTO_BROKER_OPERATION_COUNT ||
	    begin->submitted_at_ms == 0U ||
	    begin->deadline_ms < begin->submitted_at_ms ||
	    now_ms > begin->deadline_ms ||
	    begin->input_length != input_length ||
	    begin->aux_input_length != aux_input_length ||
	    begin->context_length != context_length ||
	    input_length > PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    aux_input_length > PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    context_length > PQCP_RUNTIME_MAX_CONTEXT_BYTES ||
	    (input == NULL && input_length != 0U) ||
	    (aux_input == NULL && aux_input_length != 0U) ||
	    (context == NULL && context_length != 0U) ||
	    strnlen(begin->principal_id,
		    sizeof(begin->principal_id)) == 0U ||
	    strnlen(begin->principal_id,
		    sizeof(begin->principal_id)) >=
		    sizeof(begin->principal_id) ||
	    strnlen(begin->tenant_id,
		    sizeof(begin->tenant_id)) == 0U ||
	    strnlen(begin->tenant_id,
		    sizeof(begin->tenant_id)) >=
		    sizeof(begin->tenant_id) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    begin->capability,
		    sizeof(begin->capability)) ||
	    begin->has_resume_token) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_channel_internal_hash_body(
		input, input_length, aux_input,
		aux_input_length, context, context_length,
		digest);
	if (ret == 0 &&
	    !pqcp_sovereign_channel_internal_equal(
		    digest, begin->content_digest,
		    sizeof(digest))) {
		ret = -EKEYREJECTED;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static void initialize_frame(
	struct pqcp_sovereign_channel_frame *frame,
	enum pqcp_sovereign_channel_frame_type type,
	uint32_t flags,
	uint64_t sequence,
	const struct pqcp_sovereign_channel_client_transaction
		*transaction)
{
	memset(frame, 0, sizeof(*frame));
	frame->schema_version =
		PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION;
	frame->type = type;
	frame->flags = flags;
	frame->sequence = sequence;
	memcpy(frame->transaction_id,
	       transaction->transaction_id,
	       sizeof(frame->transaction_id));
	memcpy(frame->request_id, transaction->request_id,
	       sizeof(frame->request_id));
}

static int send_transaction_frame(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	int ret;

	if (client == NULL || transaction == NULL ||
	    frame == NULL || transaction->stream_id == 0U ||
	    frame->sequence != transaction->next_send_sequence) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_channel_internal_send_frame(
		&client->flow, transaction->stream_id,
		frame, now_ms);
	if (ret == 0) {
		transaction->next_send_sequence++;
		transaction->last_activity_ms = now_ms;
	}
	return ret;
}

static int send_begin(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	bool resume,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	int ret;

	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_BEGIN,
		PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST |
		(resume ?
		 PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME : 0U),
		transaction->next_send_sequence, transaction);
	frame.body.begin = transaction->begin;
	frame.body.begin.has_resume_token = resume;
	if (resume) {
		memcpy(frame.body.begin.resume_token,
		       transaction->resume_token,
		       sizeof(frame.body.begin.resume_token));
	} else {
		pqcp_runtime_secure_zero(
			frame.body.begin.resume_token,
			sizeof(frame.body.begin.resume_token));
	}
	ret = send_transaction_frame(
		client, transaction, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	if (ret == 0) {
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_BEGIN_SENT;
	}
	return ret;
}

static int copy_request_slice(
	const struct pqcp_sovereign_channel_client_transaction
		*transaction,
	uint64_t offset,
	uint8_t *output,
	size_t output_length)
{
	uint64_t total;
	uint64_t cursor;
	size_t written = 0U;

	if (transaction == NULL || output == NULL ||
	    output_length == 0U) {
		return -EINVAL;
	}
	total = request_total(transaction);
	cursor = offset;
	if (offset > total || output_length > total - offset) {
		return -EINVAL;
	}
	while (written < output_length) {
		const uint8_t *source;
		uint64_t segment_start;
		size_t segment_length;
		size_t source_offset;
		size_t available;
		size_t take;

		if (cursor < transaction->input_length) {
			source = transaction->input;
			segment_start = 0U;
			segment_length = transaction->input_length;
		} else if (cursor <
			   (uint64_t)transaction->input_length +
			   transaction->aux_input_length) {
			source = transaction->aux_input;
			segment_start = transaction->input_length;
			segment_length =
				transaction->aux_input_length;
		} else {
			source = transaction->context;
			segment_start =
				(uint64_t)transaction->input_length +
				transaction->aux_input_length;
			segment_length =
				transaction->context_length;
		}
		if (source == NULL || cursor < segment_start ||
		    cursor - segment_start > segment_length) {
			return -EBADMSG;
		}
		source_offset =
			(size_t)(cursor - segment_start);
		available = segment_length - source_offset;
		take = output_length - written;
		if (take > available) {
			take = available;
		}
		if (take == 0U) {
			return -EBADMSG;
		}
		memcpy(output + written,
		       source + source_offset, take);
		written += take;
		cursor += take;
	}
	return 0;
}

static int send_request_chunk(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	uint64_t now_ms)
{
	uint8_t data[SOVEREIGN_CLIENT_REQUEST_CHUNK_BYTES];
	uint8_t next_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	struct pqcp_sovereign_channel_frame frame;
	uint64_t total = request_total(transaction);
	size_t remaining;
	size_t chunk_length;
	bool final;
	int ret;

	if (transaction->send_offset >= total) {
		return -EALREADY;
	}
	remaining = (size_t)(total - transaction->send_offset);
	chunk_length =
		remaining > sizeof(data) ? sizeof(data) : remaining;
	ret = copy_request_slice(
		transaction, transaction->send_offset,
		data, chunk_length);
	if (ret == 0) {
		ret = pqcp_sovereign_channel_internal_roll_digest(
			transaction->rolling_digest,
			transaction->send_offset,
			data, chunk_length, next_digest);
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(data, sizeof(data));
		pqcp_runtime_secure_zero(
			next_digest, sizeof(next_digest));
		return ret;
	}
	final = transaction->send_offset + chunk_length == total;
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_CHUNK,
		final ? PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL : 0U,
		transaction->next_send_sequence, transaction);
	frame.body.chunk.offset = transaction->send_offset;
	frame.body.chunk.data = data;
	frame.body.chunk.data_length = chunk_length;
	memcpy(frame.body.chunk.rolling_digest, next_digest,
	       sizeof(frame.body.chunk.rolling_digest));
	ret = send_transaction_frame(
		client, transaction, &frame, now_ms);
	if (ret == 0) {
		transaction->send_offset += chunk_length;
		memcpy(transaction->rolling_digest,
		       next_digest,
		       sizeof(transaction->rolling_digest));
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_BEGIN_SENT;
	}
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	pqcp_runtime_secure_zero(data, sizeof(data));
	pqcp_runtime_secure_zero(
		next_digest, sizeof(next_digest));
	return ret;
}

static int send_commit(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	int ret;

	if (transaction->send_offset !=
	    request_total(transaction)) {
		return -EINVAL;
	}
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_COMMIT,
		PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL,
		transaction->next_send_sequence, transaction);
	frame.body.commit.total_length =
		transaction->send_offset;
	memcpy(frame.body.commit.rolling_digest,
	       transaction->rolling_digest,
	       sizeof(frame.body.commit.rolling_digest));
	memcpy(frame.body.commit.content_digest,
	       transaction->begin.content_digest,
	       sizeof(frame.body.commit.content_digest));
	ret = send_transaction_frame(
		client, transaction, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	if (ret == 0) {
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_COMMIT_SENT;
	}
	return ret;
}

static int send_credit(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
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
		0U, transaction->next_send_sequence,
		transaction);
	frame.body.window = *credit;
	frame.body.window.server_time_ms = now_ms;
	frame.body.window.expires_at_ms =
		transaction->expires_at_ms;
	ret = send_transaction_frame(
		client, transaction, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	return ret;
}

static int send_result_ack(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	int ret;

	if (!transaction->result_assembler.initialized) {
		return -EINVAL;
	}
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_RESULT,
		PQCP_SOVEREIGN_CHANNEL_FLAG_ACK,
		transaction->next_send_sequence, transaction);
	frame.body.result.ack_offset =
		transaction->result_assembler.received_length;
	memcpy(frame.body.result.content_digest,
	       transaction->result_assembler.expected_digest,
	       sizeof(frame.body.result.content_digest));
	ret = send_transaction_frame(
		client, transaction, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	if (ret == 0) {
		transaction->result_ack_offset =
			transaction->result_assembler.received_length;
	}
	return ret;
}

static int send_receipt_ack(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	int ret;

	if (!transaction->receipt_assembler.initialized) {
		return -EINVAL;
	}
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_RECEIPT,
		PQCP_SOVEREIGN_CHANNEL_FLAG_ACK,
		transaction->next_send_sequence, transaction);
	frame.body.receipt.ack_offset =
		transaction->receipt_assembler.received_length;
	memcpy(frame.body.receipt.content_digest,
	       transaction->receipt_assembler.expected_digest,
	       sizeof(frame.body.receipt.content_digest));
	ret = send_transaction_frame(
		client, transaction, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	if (ret == 0) {
		transaction->receipt_ack_offset =
			transaction->receipt_assembler.received_length;
	}
	return ret;
}

static int receive_client_frame(
	struct pqcp_sovereign_channel_client *client,
	uint8_t encoded[PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES],
	size_t *encoded_length,
	struct pqcp_channel_stream_header *stream_header,
	struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	int ret;

	*encoded_length = 0U;
	ret = pqcp_channel_stream_receive(
		client->config.multiplexer, encoded,
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

static int account_received_frame(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	const struct pqcp_channel_stream_header *stream_header,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_window credit;
	int ret;

	memset(&credit, 0, sizeof(credit));
	ret = pqcp_sovereign_channel_flow_receive_account(
		&client->flow, stream_header->stream_id,
		stream_header->payload_length, &credit);
	if (ret == 0 &&
	    (credit.connection_credit != 0U ||
	     credit.stream_credit != 0U)) {
		ret = send_credit(
			client, transaction, &credit, now_ms);
	}
	return ret;
}

static int accept_resume_checkpoint(
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	const struct pqcp_sovereign_channel_frame *frame)
{
	const struct pqcp_sovereign_channel_window *window =
		&frame->body.window;
	uint64_t total = request_total(transaction);

	if ((frame->flags &
	     (PQCP_SOVEREIGN_CHANNEL_FLAG_ACCEPTED |
	      PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME)) !=
		    (PQCP_SOVEREIGN_CHANNEL_FLAG_ACCEPTED |
		     PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME) ||
	    !window->has_resume_token ||
	    !window->has_rolling_digest ||
	    window->ack_offset > total ||
	    window->expires_at_ms == 0U ||
	    window->expires_at_ms > transaction->expires_at_ms) {
		return -EBADMSG;
	}
	transaction->send_offset = window->ack_offset;
	memcpy(transaction->rolling_digest,
	       window->rolling_digest,
	       sizeof(transaction->rolling_digest));
	memcpy(transaction->resume_token,
	       window->resume_token,
	       sizeof(transaction->resume_token));
	transaction->has_resume_token = true;
	if (transaction->send_offset < total) {
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_SENDING;
	} else if ((frame->flags &
		    PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL) != 0U) {
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_WAITING_RESULT;
	} else {
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_SENDING;
	}
	return 0;
}

static int handle_checkpoint(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	const struct pqcp_sovereign_channel_frame *frame)
{
	const struct pqcp_sovereign_channel_window *window =
		&frame->body.window;
	uint64_t total = request_total(transaction);

	switch (window->kind) {
	case PQCP_SOVEREIGN_CHANNEL_WINDOW_CREDIT:
		if (frame->flags != 0U) {
			return -EPROTO;
		}
		return pqcp_sovereign_channel_flow_apply_window(
			&client->flow, transaction->stream_id,
			window);
	case PQCP_SOVEREIGN_CHANNEL_WINDOW_BEGIN_ACCEPTED:
		if (transaction->state !=
			    PQCP_SOVEREIGN_CHANNEL_CLIENT_BEGIN_SENT ||
		    frame->flags !=
			    PQCP_SOVEREIGN_CHANNEL_FLAG_ACCEPTED ||
		    window->ack_offset != 0U ||
		    !window->has_resume_token ||
		    !window->has_rolling_digest ||
		    !pqcp_sovereign_channel_internal_equal(
			    window->rolling_digest,
			    transaction->rolling_digest,
			    sizeof(transaction->rolling_digest))) {
			return -EBADMSG;
		}
		memcpy(transaction->resume_token,
		       window->resume_token,
		       sizeof(transaction->resume_token));
		transaction->has_resume_token = true;
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_SENDING;
		return 0;
	case PQCP_SOVEREIGN_CHANNEL_WINDOW_REQUEST_ACK:
		if (window->ack_offset !=
			    transaction->send_offset ||
		    !window->has_resume_token ||
		    !window->has_rolling_digest ||
		    !pqcp_sovereign_channel_internal_equal(
			    window->rolling_digest,
			    transaction->rolling_digest,
			    sizeof(transaction->rolling_digest)) ||
		    (frame->flags &
		     PQCP_SOVEREIGN_CHANNEL_FLAG_ACK) == 0U) {
			return -EBADMSG;
		}
		memcpy(transaction->resume_token,
		       window->resume_token,
		       sizeof(transaction->resume_token));
		transaction->has_resume_token = true;
		if ((frame->flags &
		     PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL) != 0U) {
			if (transaction->state !=
				    PQCP_SOVEREIGN_CHANNEL_CLIENT_COMMIT_SENT ||
			    transaction->send_offset != total) {
				return -EPROTO;
			}
			transaction->state =
				PQCP_SOVEREIGN_CHANNEL_CLIENT_WAITING_RESULT;
		} else {
			if (transaction->state !=
			    PQCP_SOVEREIGN_CHANNEL_CLIENT_BEGIN_SENT) {
				return -EPROTO;
			}
			transaction->state =
				PQCP_SOVEREIGN_CHANNEL_CLIENT_SENDING;
		}
		return 0;
	case PQCP_SOVEREIGN_CHANNEL_WINDOW_RESULT_ACK:
		if (frame->flags !=
			    PQCP_SOVEREIGN_CHANNEL_FLAG_ACK ||
		    window->ack_offset !=
			    transaction->result_ack_offset ||
		    !window->has_resume_token) {
			return -EBADMSG;
		}
		memcpy(transaction->resume_token,
		       window->resume_token,
		       sizeof(transaction->resume_token));
		transaction->has_resume_token = true;
		return 0;
	case PQCP_SOVEREIGN_CHANNEL_WINDOW_RECEIPT_ACK:
		if (frame->flags !=
			    PQCP_SOVEREIGN_CHANNEL_FLAG_ACK ||
		    window->ack_offset !=
			    transaction->receipt_ack_offset ||
		    !window->has_resume_token) {
			return -EBADMSG;
		}
		memcpy(transaction->resume_token,
		       window->resume_token,
		       sizeof(transaction->resume_token));
		transaction->has_resume_token = true;
		return 0;
	case PQCP_SOVEREIGN_CHANNEL_WINDOW_RESUME_ACCEPTED:
		return accept_resume_checkpoint(
			transaction, frame);
	case PQCP_SOVEREIGN_CHANNEL_WINDOW_COMPLETE:
		if ((frame->flags &
		     (PQCP_SOVEREIGN_CHANNEL_FLAG_ACK |
		      PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL)) !=
			    (PQCP_SOVEREIGN_CHANNEL_FLAG_ACK |
			     PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL) ||
		    !window->has_resume_token) {
			return -EBADMSG;
		}
		memcpy(transaction->resume_token,
		       window->resume_token,
		       sizeof(transaction->resume_token));
		transaction->has_resume_token = true;
		if (transaction->state !=
		    PQCP_SOVEREIGN_CHANNEL_CLIENT_CANCELLED) {
			transaction->state =
				PQCP_SOVEREIGN_CHANNEL_CLIENT_COMPLETED;
			client->completed_transactions++;
		}
		return 0;
	default:
		return -EPROTO;
	}
}

static bool result_header_matches(
	const struct pqcp_sovereign_channel_client_transaction
		*transaction,
	const struct pqcp_sovereign_channel_result *result)
{
	return transaction->response.result ==
		       result->result_code &&
	       memcmp(&transaction->response.primary_key,
		      &result->primary_key,
		      sizeof(result->primary_key)) == 0 &&
	       memcmp(&transaction->response.secondary_key,
		      &result->secondary_key,
		      sizeof(result->secondary_key)) == 0 &&
	       memcmp(&transaction->response.metadata,
		      &result->metadata,
		      sizeof(result->metadata)) == 0 &&
	       transaction->response.output_length ==
		       result->total_length &&
	       pqcp_sovereign_channel_internal_equal(
		       transaction->result_assembler.expected_digest,
		       result->content_digest,
		       PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES);
}

static int handle_result(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	const struct pqcp_sovereign_channel_result *result =
		&frame->body.result;
	bool first =
		(frame->flags &
		 PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST) != 0U;
	bool final =
		(frame->flags &
		 PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL) != 0U;
	int ret;

	if ((frame->flags &
	     PQCP_SOVEREIGN_CHANNEL_FLAG_ACK) != 0U ||
	    result->result_flags != 0U ||
	    result->total_length > transaction->result_capacity ||
	    result->offset > result->total_length ||
	    result->data_length >
		    result->total_length - result->offset) {
		return -EBADMSG;
	}
	if (!transaction->result_header_received) {
		if (!first || result->offset != 0U ||
		    transaction->state !=
			    PQCP_SOVEREIGN_CHANNEL_CLIENT_WAITING_RESULT) {
			return -EPROTO;
		}
		transaction->response.result =
			result->result_code;
		transaction->response.replayed =
			(frame->flags &
			 PQCP_SOVEREIGN_CHANNEL_FLAG_REPLAYED) != 0U;
		transaction->response.cancelled =
			(frame->flags &
			 PQCP_SOVEREIGN_CHANNEL_FLAG_CANCELLED) != 0U;
		transaction->response.primary_key =
			result->primary_key;
		transaction->response.secondary_key =
			result->secondary_key;
		transaction->response.metadata =
			result->metadata;
		transaction->response.output =
			transaction->result;
		transaction->response.output_capacity =
			transaction->result_capacity;
		transaction->response.output_length =
			result->total_length;
		ret = pqcp_sovereign_channel_blob_assembler_init(
			&transaction->result_assembler,
			transaction->result,
			transaction->result_capacity,
			result->total_length,
			result->content_digest);
		if (ret != 0) {
			return ret;
		}
		transaction->result_header_received = true;
	} else {
		if (first ||
		    !result_header_matches(transaction, result)) {
			return -EKEYREJECTED;
		}
	}
	if (result->data_length != 0U) {
		ret = pqcp_sovereign_channel_blob_assembler_append(
			&transaction->result_assembler,
			result->offset, result->data,
			result->data_length, final);
		if (ret != 0) {
			return ret;
		}
	} else if (!final ||
		   result->total_length != 0U ||
		   !transaction->result_assembler.completed) {
		return -EBADMSG;
	}
	transaction->state =
		PQCP_SOVEREIGN_CHANNEL_CLIENT_RECEIVING_RESULT;
	ret = send_result_ack(client, transaction, now_ms);
	if (ret != 0) {
		return ret;
	}
	if (final) {
		if (!transaction->result_assembler.completed) {
			return -EBADMSG;
		}
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_WAITING_RESULT;
	}
	return 0;
}

static int handle_receipt(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	const struct pqcp_sovereign_channel_receipt_frame *receipt =
		&frame->body.receipt;
	struct pqcp_crypto_broker_receipt decoded;
	bool first =
		(frame->flags &
		 PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST) != 0U;
	bool final =
		(frame->flags &
		 PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL) != 0U;
	int ret;

	if ((frame->flags &
	     PQCP_SOVEREIGN_CHANNEL_FLAG_ACK) != 0U ||
	    receipt->total_length > transaction->receipt_capacity ||
	    receipt->receipt_sequence == 0U) {
		return -EBADMSG;
	}
	if (!transaction->receipt_header_received) {
		if (!first || receipt->offset != 0U ||
		    transaction->state !=
			    PQCP_SOVEREIGN_CHANNEL_CLIENT_WAITING_RESULT) {
			return -EPROTO;
		}
		ret = pqcp_sovereign_channel_blob_assembler_init(
			&transaction->receipt_assembler,
			transaction->receipt,
			transaction->receipt_capacity,
			receipt->total_length,
			receipt->content_digest);
		if (ret != 0) {
			return ret;
		}
		transaction->response.receipt.sequence =
			receipt->receipt_sequence;
		memcpy(
			transaction->response.receipt.receipt_digest,
			receipt->receipt_digest,
			sizeof(receipt->receipt_digest));
		transaction->receipt_header_received = true;
	} else if (first ||
		   transaction->response.receipt.sequence !=
			   receipt->receipt_sequence ||
		   !pqcp_sovereign_channel_internal_equal(
			   transaction->receipt_assembler.
				   expected_digest,
			   receipt->content_digest,
			   sizeof(receipt->content_digest)) ||
		   !pqcp_sovereign_channel_internal_equal(
			   transaction->response.receipt.
				   receipt_digest,
			   receipt->receipt_digest,
			   sizeof(receipt->receipt_digest))) {
		return -EKEYREJECTED;
	}
	ret = pqcp_sovereign_channel_blob_assembler_append(
		&transaction->receipt_assembler,
		receipt->offset, receipt->data,
		receipt->data_length, final);
	if (ret != 0) {
		return ret;
	}
	transaction->state =
		PQCP_SOVEREIGN_CHANNEL_CLIENT_RECEIVING_RECEIPT;
	if (final) {
		if (!transaction->receipt_assembler.completed) {
			return -EBADMSG;
		}
		memset(&decoded, 0, sizeof(decoded));
		ret = pqcp_sovereign_channel_receipt_decode(
			transaction->receipt,
			(size_t)transaction->receipt_assembler.
				expected_length,
			&decoded);
		if (ret != 0 ||
		    decoded.sequence != receipt->receipt_sequence ||
		    !pqcp_sovereign_channel_internal_equal(
			    decoded.receipt_digest,
			    receipt->receipt_digest,
			    sizeof(decoded.receipt_digest))) {
			pqcp_runtime_secure_zero(
				&decoded, sizeof(decoded));
			return ret != 0 ? ret : -EKEYREJECTED;
		}
		transaction->response.receipt = decoded;
		pqcp_runtime_secure_zero(
			&decoded, sizeof(decoded));
	}
	ret = send_receipt_ack(client, transaction, now_ms);
	if (ret == 0 && final) {
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_WAITING_RESULT;
	}
	return ret;
}

static int handle_error(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	const struct pqcp_sovereign_channel_frame *frame)
{
	if (frame->flags &
	    ~(PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL |
	      PQCP_SOVEREIGN_CHANNEL_FLAG_RETRYABLE)) {
		return -EPROTO;
	}
	transaction->terminal_result =
		frame->body.error.error_code != 0 ?
			frame->body.error.error_code :
			-EPROTO;
	transaction->state =
		PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED;
	client->failed_transactions++;
	return transaction->terminal_result;
}

static int dispatch_frame(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	switch (frame->type) {
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RESULT:
		return handle_result(
			client, transaction, frame, now_ms);
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RECEIPT:
		return handle_receipt(
			client, transaction, frame, now_ms);
	case PQCP_SOVEREIGN_CHANNEL_FRAME_ERROR:
		return handle_error(client, transaction, frame);
	case PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW:
		return handle_checkpoint(
			client, transaction, frame);
	default:
		return -EPROTO;
	}
}

int pqcp_sovereign_channel_client_init(
	struct pqcp_sovereign_channel_client *client,
	const struct pqcp_sovereign_channel_client_config *config,
	const struct pqcp_sovereign_channel_client_storage *storage)
{
	int ret;

	if (client == NULL) {
		return -EINVAL;
	}
	ret = validate_client_configuration(config, storage);
	if (ret != 0) {
		return ret;
	}
	memset(client, 0, sizeof(*client));
	memset(storage->transactions, 0,
	       storage->capacity *
		       sizeof(*storage->transactions));
	client->config = *config;
	client->storage = *storage;
	k_mutex_init(&client->lock);
	ret = pqcp_sovereign_channel_flow_init(
		&client->flow, config->multiplexer,
		config->flow_controller);
	if (ret != 0) {
		memset(client, 0, sizeof(*client));
		return ret;
	}
	client->initialized = true;
	return 0;
}

int pqcp_sovereign_channel_client_start(
	struct pqcp_sovereign_channel_client *client,
	const struct pqcp_sovereign_channel_begin *begin,
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[
		PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	const uint8_t *input,
	size_t input_length,
	const uint8_t *aux_input,
	size_t aux_input_length,
	const uint8_t *context,
	size_t context_length,
	uint8_t *result,
	size_t result_capacity,
	uint8_t *receipt,
	size_t receipt_capacity,
	uint64_t now_ms,
	struct pqcp_sovereign_channel_client_transaction
		**transaction)
{
	struct pqcp_sovereign_channel_client_transaction *allocated;
	struct pqcp_channel_stream *stream;
	uint64_t lifetime_end;
	int ret;

	if (client == NULL || !client->initialized ||
	    transaction_id == NULL || request_id == NULL ||
	    result == NULL ||
	    result_capacity == 0U ||
	    receipt == NULL ||
	    receipt_capacity == 0U ||
	    transaction == NULL ||
	    pqcp_sovereign_channel_internal_all_zero(
		    transaction_id,
		    PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    request_id,
		    PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES)) {
		return -EINVAL;
	}
	ret = validate_begin_and_body(
		begin, input, input_length,
		aux_input, aux_input_length,
		context, context_length, now_ms);
	if (ret != 0) {
		return ret;
	}
	if (now_ms >
	    UINT64_MAX -
		    client->config.transaction_lifetime_ms) {
		return -EOVERFLOW;
	}
	ret = lock_client(client);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < client->storage.capacity; ++index) {
		struct pqcp_sovereign_channel_client_transaction
			*existing =
				&client->storage.transactions[index];

		if (existing->occupied &&
		    (pqcp_sovereign_channel_internal_equal(
			     existing->transaction_id,
			     transaction_id,
			     sizeof(existing->transaction_id)) ||
		     pqcp_sovereign_channel_internal_equal(
			     existing->request_id, request_id,
			     sizeof(existing->request_id)))) {
			unlock_client(client);
			return -EALREADY;
		}
	}
	allocated = free_transaction(client);
	if (allocated == NULL) {
		unlock_client(client);
		return -ENOSPC;
	}
	ret = pqcp_channel_stream_open(
		client->config.multiplexer,
		client->config.stream_priority, now_ms,
		&stream);
	if (ret != 0) {
		unlock_client(client);
		return ret;
	}
	memset(allocated, 0, sizeof(*allocated));
	allocated->schema_version =
		PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION;
	allocated->generation =
		pqcp_sovereign_channel_internal_next_generation(
			&client->next_generation);
	allocated->state =
		PQCP_SOVEREIGN_CHANNEL_CLIENT_EMPTY;
	allocated->stream_id = stream->stream_id;
	allocated->created_at_ms = now_ms;
	allocated->last_activity_ms = now_ms;
	lifetime_end =
		now_ms + client->config.transaction_lifetime_ms;
	allocated->expires_at_ms =
		begin->deadline_ms < lifetime_end ?
			begin->deadline_ms : lifetime_end;
	memcpy(allocated->transaction_id, transaction_id,
	       sizeof(allocated->transaction_id));
	memcpy(allocated->request_id, request_id,
	       sizeof(allocated->request_id));
	allocated->begin = *begin;
	allocated->input = input;
	allocated->input_length = input_length;
	allocated->aux_input = aux_input;
	allocated->aux_input_length = aux_input_length;
	allocated->context = context;
	allocated->context_length = context_length;
	allocated->result = result;
	allocated->result_capacity = result_capacity;
	allocated->receipt = receipt;
	allocated->receipt_capacity = receipt_capacity;
	allocated->response.output = result;
	allocated->response.output_capacity = result_capacity;
	allocated->occupied = true;
	memset(result, 0, result_capacity);
	memset(receipt, 0, receipt_capacity);
	ret = pqcp_sovereign_channel_internal_seed_digest(
		transaction_id, request_id,
		begin->input_length,
		begin->aux_input_length,
		begin->context_length,
		allocated->rolling_digest);
	if (ret == 0) {
		ret = send_begin(client, allocated, false, now_ms);
	}
	if (ret != 0) {
		(void)pqcp_channel_stream_close(
			client->config.multiplexer,
			allocated->stream_id,
			PQCP_CHANNEL_STREAM_ERROR_INTERNAL,
			now_ms);
		pqcp_runtime_secure_zero(
			allocated, sizeof(*allocated));
		unlock_client(client);
		return ret;
	}
	client->started_transactions++;
	*transaction = allocated;
	unlock_client(client);
	return 0;
}

int pqcp_sovereign_channel_client_send_next(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	uint64_t now_ms)
{
	int ret;

	if (client == NULL || !client->initialized ||
	    !transaction_belongs_to_client(client, transaction) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_client(client);
	if (ret != 0) {
		return ret;
	}
	if (now_ms > transaction->expires_at_ms) {
		transaction->terminal_result = -ETIMEDOUT;
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED;
		client->failed_transactions++;
		unlock_client(client);
		return -ETIMEDOUT;
	}
	switch (transaction->state) {
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_SENDING:
		if (transaction->send_offset <
		    request_total(transaction)) {
			ret = send_request_chunk(
				client, transaction, now_ms);
		} else {
			ret = send_commit(
				client, transaction, now_ms);
		}
		break;
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_BEGIN_SENT:
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_COMMIT_SENT:
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_WAITING_RESULT:
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_RECEIVING_RESULT:
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_RECEIVING_RECEIPT:
		ret = -EAGAIN;
		break;
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_DISCONNECTED:
		ret = -ENOTCONN;
		break;
	default:
		ret = client_terminal_state(transaction->state) ?
			-EALREADY : -EPROTO;
		break;
	}
	unlock_client(client);
	return ret;
}

int pqcp_sovereign_channel_client_receive(
	struct pqcp_sovereign_channel_client *client,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES];
	struct pqcp_channel_stream_header stream_header;
	struct pqcp_sovereign_channel_frame frame;
	struct pqcp_sovereign_channel_client_transaction *transaction;
	size_t encoded_length = 0U;
	int ret;

	if (client == NULL || !client->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_client(client);
	if (ret != 0) {
		return ret;
	}
	memset(&stream_header, 0, sizeof(stream_header));
	memset(&frame, 0, sizeof(frame));
	ret = receive_client_frame(
		client, encoded, &encoded_length,
		&stream_header, &frame, now_ms);
	if (ret == -EAGAIN) {
		unlock_client(client);
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return 0;
	}
	if (ret != 0) {
		client->rejected_frames++;
		unlock_client(client);
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return ret;
	}
	transaction = transaction_by_stream(
		client, stream_header.stream_id);
	if (transaction == NULL ||
	    transaction->state ==
		    PQCP_SOVEREIGN_CHANNEL_CLIENT_COMPLETED ||
	    transaction->state ==
		    PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED ||
	    frame.sequence != transaction->next_receive_sequence ||
	    !pqcp_sovereign_channel_internal_equal(
		    frame.transaction_id,
		    transaction->transaction_id,
		    sizeof(frame.transaction_id)) ||
	    !pqcp_sovereign_channel_internal_equal(
		    frame.request_id, transaction->request_id,
		    sizeof(frame.request_id))) {
		client->rejected_frames++;
		unlock_client(client);
		pqcp_runtime_secure_zero(&frame, sizeof(frame));
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return transaction == NULL ? -ENOENT : -EALREADY;
	}
	ret = account_received_frame(
		client, transaction, &stream_header, now_ms);
	if (ret == 0) {
		ret = dispatch_frame(
			client, transaction, &frame, now_ms);
	}
	if (ret == 0) {
		transaction->next_receive_sequence++;
		transaction->last_activity_ms = now_ms;
	} else if (transaction->state !=
		   PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED) {
		client->rejected_frames++;
		transaction->terminal_result = ret;
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED;
		client->failed_transactions++;
	}
	unlock_client(client);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

int pqcp_sovereign_channel_client_resume(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	uint64_t now_ms)
{
	struct pqcp_channel_stream *stream;
	int ret;

	if (client == NULL || !client->initialized ||
	    !transaction_belongs_to_client(client, transaction) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_client(client);
	if (ret != 0) {
		return ret;
	}
	if (transaction->state !=
		    PQCP_SOVEREIGN_CHANNEL_CLIENT_DISCONNECTED ||
	    !transaction->has_resume_token ||
	    pqcp_sovereign_channel_internal_all_zero(
		    transaction->resume_token,
		    sizeof(transaction->resume_token))) {
		unlock_client(client);
		return -EPERM;
	}
	if (now_ms > transaction->expires_at_ms) {
		transaction->terminal_result = -ESTALE;
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED;
		client->failed_transactions++;
		unlock_client(client);
		return -ESTALE;
	}
	ret = pqcp_channel_stream_open(
		client->config.multiplexer,
		client->config.stream_priority, now_ms,
		&stream);
	if (ret != 0) {
		unlock_client(client);
		return ret;
	}
	transaction->stream_id = stream->stream_id;
	transaction->next_send_sequence = 0U;
	transaction->next_receive_sequence = 0U;
	transaction->last_activity_ms = now_ms;
	ret = send_begin(client, transaction, true, now_ms);
	if (ret != 0) {
		(void)pqcp_channel_stream_close(
			client->config.multiplexer,
			transaction->stream_id,
			PQCP_CHANNEL_STREAM_ERROR_INTERNAL,
			now_ms);
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_DISCONNECTED;
		unlock_client(client);
		return ret;
	}
	client->resumed_transactions++;
	unlock_client(client);
	return 0;
}

int pqcp_sovereign_channel_client_cancel(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction
		*transaction,
	int reason,
	const uint8_t *detail,
	size_t detail_length,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_frame frame;
	int ret;

	if (client == NULL || !client->initialized ||
	    !transaction_belongs_to_client(client, transaction) ||
	    now_ms == 0U ||
	    (detail == NULL && detail_length != 0U) ||
	    detail_length >
		    PQCP_SOVEREIGN_CHANNEL_DETAIL_MAX_BYTES) {
		return -EINVAL;
	}
	ret = lock_client(client);
	if (ret != 0) {
		return ret;
	}
	if (client_terminal_state(transaction->state) ||
	    transaction->state ==
		    PQCP_SOVEREIGN_CHANNEL_CLIENT_DISCONNECTED) {
		unlock_client(client);
		return -EALREADY;
	}
	initialize_frame(
		&frame, PQCP_SOVEREIGN_CHANNEL_FRAME_CANCEL,
		PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL,
		transaction->next_send_sequence, transaction);
	frame.body.cancel.error_code =
		reason != 0 ? reason : -ECANCELED;
	if (detail_length != 0U) {
		memcpy(frame.body.cancel.detail, detail,
		       detail_length);
		frame.body.cancel.detail_length = detail_length;
	}
	ret = send_transaction_frame(
		client, transaction, &frame, now_ms);
	pqcp_runtime_secure_zero(&frame, sizeof(frame));
	if (ret == 0) {
		transaction->terminal_result =
			reason != 0 ? reason : -ECANCELED;
		transaction->state =
			PQCP_SOVEREIGN_CHANNEL_CLIENT_CANCELLED;
	}
	unlock_client(client);
	return ret;
}

int pqcp_sovereign_channel_client_disconnect(
	struct pqcp_sovereign_channel_client *client,
	uint32_t stream_id,
	uint64_t now_ms)
{
	struct pqcp_sovereign_channel_client_transaction *transaction;
	int ret;

	if (client == NULL || !client->initialized ||
	    stream_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_client(client);
	if (ret != 0) {
		return ret;
	}
	transaction = transaction_by_stream(client, stream_id);
	if (transaction == NULL) {
		unlock_client(client);
		return -ENOENT;
	}
	if (client_terminal_state(transaction->state)) {
		unlock_client(client);
		return -EALREADY;
	}
	transaction->state =
		PQCP_SOVEREIGN_CHANNEL_CLIENT_DISCONNECTED;
	transaction->last_activity_ms = now_ms;
	ret = pqcp_channel_stream_close(
		client->config.multiplexer, stream_id,
		PQCP_CHANNEL_STREAM_ERROR_TIMEOUT, now_ms);
	if (ret == -EALREADY || ret == -ESHUTDOWN) {
		ret = 0;
	}
	unlock_client(client);
	return ret;
}

static int audit_transaction(
	const struct pqcp_sovereign_channel_client_transaction
		*transaction)
{
	uint64_t total;

	if (!transaction->occupied) {
		return transaction->state ==
			       PQCP_SOVEREIGN_CHANNEL_CLIENT_EMPTY ?
			0 : -EBADMSG;
	}
	total = request_total(transaction);
	if (transaction->schema_version !=
		    PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION ||
	    transaction->generation == 0U ||
	    !client_state_valid(transaction->state) ||
	    transaction->state ==
		    PQCP_SOVEREIGN_CHANNEL_CLIENT_EMPTY ||
	    transaction->stream_id == 0U ||
	    transaction->created_at_ms == 0U ||
	    transaction->last_activity_ms <
		    transaction->created_at_ms ||
	    transaction->expires_at_ms <
		    transaction->created_at_ms ||
	    transaction->send_offset > total ||
	    transaction->input_length !=
		    transaction->begin.input_length ||
	    transaction->aux_input_length !=
		    transaction->begin.aux_input_length ||
	    transaction->context_length !=
		    transaction->begin.context_length ||
	    (transaction->input == NULL &&
	     transaction->input_length != 0U) ||
	    (transaction->aux_input == NULL &&
	     transaction->aux_input_length != 0U) ||
	    (transaction->context == NULL &&
	     transaction->context_length != 0U) ||
	    transaction->result == NULL ||
	    transaction->receipt == NULL ||
	    transaction->result_capacity == 0U ||
	    transaction->receipt_capacity == 0U ||
	    pqcp_sovereign_channel_internal_all_zero(
		    transaction->transaction_id,
		    sizeof(transaction->transaction_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    transaction->request_id,
		    sizeof(transaction->request_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    transaction->rolling_digest,
		    sizeof(transaction->rolling_digest)) ||
	    (transaction->has_resume_token &&
	     pqcp_sovereign_channel_internal_all_zero(
		     transaction->resume_token,
		     sizeof(transaction->resume_token))) ||
	    transaction->result_ack_offset >
		    transaction->result_capacity ||
	    transaction->receipt_ack_offset >
		    transaction->receipt_capacity) {
		return -EBADMSG;
	}
	if (transaction->result_header_received &&
	    pqcp_sovereign_channel_blob_assembler_audit(
		    &transaction->result_assembler) != 0) {
		return -EBADMSG;
	}
	if (transaction->receipt_header_received &&
	    pqcp_sovereign_channel_blob_assembler_audit(
		    &transaction->receipt_assembler) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_sovereign_channel_client_audit(
	struct pqcp_sovereign_channel_client *client)
{
	int ret;

	if (client == NULL || !client->initialized) {
		return -EINVAL;
	}
	ret = lock_client(client);
	if (ret != 0) {
		return ret;
	}
	ret = validate_client_configuration(
		&client->config, &client->storage);
	for (size_t index = 0U;
	     ret == 0 && index < client->storage.capacity;
	     ++index) {
		ret = audit_transaction(
			&client->storage.transactions[index]);
		for (size_t other = index + 1U;
		     ret == 0 &&
		     other < client->storage.capacity;
		     ++other) {
			const struct pqcp_sovereign_channel_client_transaction
				*left =
					&client->storage.transactions[index];
			const struct pqcp_sovereign_channel_client_transaction
				*right =
					&client->storage.transactions[other];

			if (!left->occupied || !right->occupied) {
				continue;
			}
			if (left->stream_id == right->stream_id ||
			    pqcp_sovereign_channel_internal_equal(
				    left->transaction_id,
				    right->transaction_id,
				    sizeof(left->transaction_id)) ||
			    pqcp_sovereign_channel_internal_equal(
				    left->request_id,
				    right->request_id,
				    sizeof(left->request_id))) {
				ret = -EEXIST;
			}
		}
	}
	unlock_client(client);
	if (ret == 0) {
		ret = pqcp_sovereign_channel_flow_audit(
			&client->flow);
	}
	return ret;
}
