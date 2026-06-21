/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Explicit protected-channel key epochs.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel_operations.h>

#include "runtime_internal.h"

#define REKEY_INFO_BYTES 192U
#define REKEY_MAC_INPUT_BYTES 96U

static int rekey_policy_validate(
	const struct pqcp_channel_rekey_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    policy->maximum_epoch_bytes == 0U ||
	    policy->maximum_epoch_ms == 0U ||
	    policy->minimum_interval_ms == 0U ||
	    policy->handshake_timeout_ms == 0U ||
	    policy->minimum_interval_ms >
		    policy->maximum_epoch_ms) {
		return -EINVAL;
	}
	return 0;
}

static void destroy_pending_keys(
	struct pqcp_channel_rekey_context *context)
{
	if (context->key_store != NULL &&
	    pqcp_runtime_key_handle_is_valid(
		    &context->pending_keys.client_write_key)) {
		(void)pqcp_runtime_key_store_destroy(
			context->key_store,
			&context->pending_keys.client_write_key);
	}
	if (context->key_store != NULL &&
	    pqcp_runtime_key_handle_is_valid(
		    &context->pending_keys.server_write_key)) {
		(void)pqcp_runtime_key_store_destroy(
			context->key_store,
			&context->pending_keys.server_write_key);
	}
	pqcp_runtime_secure_zero(
		&context->pending_keys,
		sizeof(context->pending_keys));
}

static int build_rekey_info(
	const struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_context *context,
	enum pqcp_channel_role direction,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES],
	uint8_t info[REKEY_INFO_BYTES],
	size_t *info_length)
{
	static const uint8_t label[] = "PQCP rekey traffic v2";
	size_t offset = 0U;

	memcpy(info + offset, label, sizeof(label) - 1U);
	offset += sizeof(label) - 1U;
	memcpy(info + offset, channel->keys.exporter,
	       sizeof(channel->keys.exporter));
	offset += sizeof(channel->keys.exporter);
	memcpy(info + offset, transcript_hash,
	       PQCP_CHANNEL_HASH_BYTES);
	offset += PQCP_CHANNEL_HASH_BYTES;
	pqcp_runtime_internal_write_u64(
		info + offset, channel->config.session_id);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		info + offset, context->current_epoch);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		info + offset, context->pending_epoch);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		info + offset, channel->config.mlkem_level);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		info + offset, channel->config.mldsa_level);
	offset += 4U;
	info[offset++] = (uint8_t)direction;
	*info_length = offset;
	return 0;
}

static int derive_rekey_handle(
	const struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	const struct pqcp_runtime_key_handle *source,
	enum pqcp_channel_role direction,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES],
	struct pqcp_runtime_key_handle *destination)
{
	struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_AEAD,
		.level = 256U,
		.usage = PQCP_RUNTIME_USAGE_ENCRYPT |
			 PQCP_RUNTIME_USAGE_DECRYPT |
			 PQCP_RUNTIME_USAGE_MAC |
			 PQCP_RUNTIME_USAGE_DERIVE |
			 PQCP_RUNTIME_USAGE_DESTROY,
		.owner = "channel",
		.persistent = false,
		.exportable_public = false,
	};
	uint8_t info[REKEY_INFO_BYTES];
	size_t info_length = 0U;
	int ret;

	request.now_ms = context->prepared_at_ms;
	request.expires_at_ms = 0U;
	request.label =
		direction == PQCP_CHANNEL_ROLE_CLIENT ?
			"client-rekey" : "server-rekey";
	ret = build_rekey_info(
		channel, context, direction, transcript_hash,
		info, &info_length);
	if (ret == 0) {
		ret = pqcp_runtime_key_store_derive(
			channel->key_store, source,
			context->salt, sizeof(context->salt),
			info, info_length, &request, destination);
	}
	pqcp_runtime_secure_zero(info, sizeof(info));
	return ret;
}

static int derive_rekey_nonce(
	const struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_context *context,
	const struct pqcp_runtime_key_handle *handle,
	enum pqcp_channel_role direction,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES],
	uint8_t nonce[PQCP_CHANNEL_AEAD_NONCE_BYTES])
{
	static const uint8_t label[] = "PQCP rekey nonce v2";
	uint8_t input[REKEY_MAC_INPUT_BYTES];
	uint8_t tag[PQCP_RUNTIME_DIGEST_BYTES];
	size_t tag_length = 0U;
	size_t offset = 0U;
	int ret;

	memcpy(input + offset, label, sizeof(label) - 1U);
	offset += sizeof(label) - 1U;
	memcpy(input + offset, transcript_hash,
	       PQCP_CHANNEL_HASH_BYTES);
	offset += PQCP_CHANNEL_HASH_BYTES;
	pqcp_runtime_internal_write_u64(
		input + offset, context->current_epoch);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		input + offset, context->pending_epoch);
	offset += 8U;
	input[offset++] = (uint8_t)direction;
	ret = pqcp_runtime_key_store_mac(
		channel->key_store, handle, input, offset,
		tag, sizeof(tag), &tag_length);
	if (ret == 0 && tag_length != sizeof(tag)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		memcpy(nonce, tag, PQCP_CHANNEL_AEAD_NONCE_BYTES);
	}
	pqcp_runtime_secure_zero(input, sizeof(input));
	pqcp_runtime_secure_zero(tag, sizeof(tag));
	return ret;
}

static int derive_confirmation(
	const struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES])
{
	static const uint8_t label[] = "PQCP rekey confirm v2";
	const struct pqcp_runtime_key_handle *key =
		context->initiator ?
			&context->pending_keys.client_write_key :
			&context->pending_keys.server_write_key;
	uint8_t input[REKEY_MAC_INPUT_BYTES];
	size_t tag_length = 0U;
	size_t offset = 0U;
	int ret;

	memcpy(input + offset, label, sizeof(label) - 1U);
	offset += sizeof(label) - 1U;
	memcpy(input + offset, transcript_hash,
	       PQCP_CHANNEL_HASH_BYTES);
	offset += PQCP_CHANNEL_HASH_BYTES;
	pqcp_runtime_internal_write_u64(
		input + offset, context->current_epoch);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		input + offset, context->pending_epoch);
	offset += 8U;
	input[offset++] = context->initiator ? 1U : 0U;
	ret = pqcp_runtime_key_store_mac(
		channel->key_store, key, input, offset,
		context->confirmation,
		sizeof(context->confirmation), &tag_length);
	pqcp_runtime_secure_zero(input, sizeof(input));
	return ret == 0 &&
	       tag_length != sizeof(context->confirmation) ?
		       -EBADMSG : ret;
}

static int derive_pending_keys(
	const struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context)
{
	uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES];
	int ret;

	ret = pqcp_channel_transcript_digest(
		&channel->transcript, transcript_hash);
	if (ret == 0) {
		ret = derive_rekey_handle(
			channel, context,
			&channel->keys.client_write_key,
			PQCP_CHANNEL_ROLE_CLIENT,
			transcript_hash,
			&context->pending_keys.client_write_key);
	}
	if (ret == 0) {
		ret = derive_rekey_handle(
			channel, context,
			&channel->keys.server_write_key,
			PQCP_CHANNEL_ROLE_SERVER,
			transcript_hash,
			&context->pending_keys.server_write_key);
	}
	if (ret == 0) {
		ret = derive_rekey_nonce(
			channel, context,
			&context->pending_keys.client_write_key,
			PQCP_CHANNEL_ROLE_CLIENT,
			transcript_hash,
			context->pending_keys.client_nonce_base);
	}
	if (ret == 0) {
		ret = derive_rekey_nonce(
			channel, context,
			&context->pending_keys.server_write_key,
			PQCP_CHANNEL_ROLE_SERVER,
			transcript_hash,
			context->pending_keys.server_nonce_base);
	}
	if (ret == 0) {
		memcpy(context->pending_keys.exporter,
		       channel->keys.exporter,
		       sizeof(context->pending_keys.exporter));
		context->pending_keys.exporter_ready = true;
		context->pending_keys.traffic_keys_ready = true;
		ret = derive_confirmation(
			channel, context, transcript_hash);
	}
	pqcp_runtime_secure_zero(
		transcript_hash, sizeof(transcript_hash));
	if (ret != 0) {
		destroy_pending_keys(context);
		pqcp_runtime_secure_zero(
			context->confirmation,
			sizeof(context->confirmation));
	}
	return ret;
}

int pqcp_channel_rekey_policy_default(
	struct pqcp_channel_rekey_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	policy->maximum_epoch_bytes =
		UINT64_C(1024) * 1024U * 1024U;
	policy->maximum_epoch_ms =
		UINT64_C(24) * 60U * 60U * 1000U;
	policy->minimum_interval_ms = 1000U;
	policy->handshake_timeout_ms = 30000U;
	policy->require_peer_confirmation = true;
	policy->close_on_failure = true;
	return 0;
}

bool pqcp_channel_rekey_due(
	const struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_policy *policy,
	uint64_t now_ms,
	uint64_t epoch_started_at_ms)
{
	uint64_t bytes;

	if (channel == NULL ||
	    rekey_policy_validate(policy) != 0 ||
	    !channel->established || now_ms == 0U ||
	    epoch_started_at_ms == 0U ||
	    now_ms < epoch_started_at_ms) {
		return false;
	}
	bytes = channel->application_bytes_sent +
		channel->application_bytes_received;
	return bytes >= policy->maximum_epoch_bytes ||
	       now_ms - epoch_started_at_ms >=
		       policy->maximum_epoch_ms;
}

int pqcp_channel_rekey_prepare(
	const struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_policy *policy,
	struct pqcp_channel_rekey_context *context,
	uint64_t now_ms,
	uint64_t next_epoch,
	const uint8_t salt[PQCP_CHANNEL_REKEY_SALT_BYTES],
	bool initiator)
{
	int ret;

	if (channel == NULL || !channel->established ||
	    channel->state !=
		    PQCP_CHANNEL_STATE_ESTABLISHED ||
	    !channel->keys.traffic_keys_ready ||
	    rekey_policy_validate(policy) != 0 ||
	    context == NULL || now_ms == 0U ||
	    next_epoch == 0U || salt == NULL) {
		return -EINVAL;
	}
	if (context->state != PQCP_CHANNEL_REKEY_IDLE &&
	    context->state != PQCP_CHANNEL_REKEY_COMMITTED &&
	    context->state != PQCP_CHANNEL_REKEY_ABORTED) {
		return -EBUSY;
	}
	if (next_epoch <= context->current_epoch) {
		return -EALREADY;
	}
	if (context->prepared_at_ms != 0U &&
	    now_ms - context->prepared_at_ms <
		    policy->minimum_interval_ms) {
		return -EAGAIN;
	}
	destroy_pending_keys(context);
	pqcp_runtime_secure_zero(context, sizeof(*context));
	context->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	context->state = PQCP_CHANNEL_REKEY_PREPARED;
	context->pending_epoch = next_epoch;
	context->prepared_at_ms = now_ms;
	context->expires_at_ms =
		now_ms + policy->handshake_timeout_ms;
	context->bytes_at_prepare =
		channel->application_bytes_sent +
		channel->application_bytes_received;
	context->key_store = channel->key_store;
	context->initiator = initiator;
	memcpy(context->salt, salt, sizeof(context->salt));
	ret = derive_pending_keys(channel, context);
	if (ret != 0) {
		context->state = PQCP_CHANNEL_REKEY_ABORTED;
	}
	return ret;
}

int pqcp_channel_rekey_accept(
	const struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	const uint8_t confirmation[PQCP_CHANNEL_FINISHED_BYTES],
	uint64_t now_ms)
{
	uint8_t difference = 0U;

	if (channel == NULL || !channel->established ||
	    context == NULL ||
	    context->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    context->state != PQCP_CHANNEL_REKEY_PREPARED ||
	    confirmation == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	if (now_ms > context->expires_at_ms) {
		(void)pqcp_channel_rekey_abort(context);
		return -ETIMEDOUT;
	}
	for (size_t index = 0U;
	     index < PQCP_CHANNEL_FINISHED_BYTES; ++index) {
		difference |=
			context->confirmation[index] ^
			confirmation[index];
	}
	if (difference != 0U) {
		(void)pqcp_channel_rekey_abort(context);
		return -EKEYREJECTED;
	}
	context->state = PQCP_CHANNEL_REKEY_ACCEPTED;
	return 0;
}

int pqcp_channel_rekey_commit(
	struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	uint64_t now_ms)
{
	int client_destroy;
	int server_destroy;

	if (channel == NULL || !channel->established ||
	    context == NULL ||
	    context->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    context->state != PQCP_CHANNEL_REKEY_ACCEPTED ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	if (now_ms > context->expires_at_ms) {
		(void)pqcp_channel_rekey_abort(context);
		return -ETIMEDOUT;
	}
	if (!context->pending_keys.traffic_keys_ready ||
	    !context->pending_keys.exporter_ready ||
	    !pqcp_runtime_key_handle_is_valid(
		    &context->pending_keys.client_write_key) ||
	    !pqcp_runtime_key_handle_is_valid(
		    &context->pending_keys.server_write_key)) {
		(void)pqcp_channel_rekey_abort(context);
		return -EBADMSG;
	}
	client_destroy = pqcp_runtime_key_store_destroy(
		channel->key_store,
		&channel->keys.client_write_key);
	server_destroy = pqcp_runtime_key_store_destroy(
		channel->key_store,
		&channel->keys.server_write_key);
	if (client_destroy != 0 || server_destroy != 0) {
		context->state = PQCP_CHANNEL_REKEY_ABORTED;
		destroy_pending_keys(context);
		pqcp_runtime_secure_zero(
			&channel->keys, sizeof(channel->keys));
		channel->state = PQCP_CHANNEL_STATE_FAILED;
		channel->established = false;
		return client_destroy != 0 ?
			client_destroy : server_destroy;
	}
	channel->keys = context->pending_keys;
	channel->send_sequence = 0U;
	channel->receive_sequence = 0U;
	pqcp_channel_replay_reset(&channel->inbound_replay);
	context->current_epoch = context->pending_epoch;
	context->pending_epoch = 0U;
	context->state = PQCP_CHANNEL_REKEY_COMMITTED;
	memset(&context->pending_keys, 0,
	       sizeof(context->pending_keys));
	context->key_store = channel->key_store;
	pqcp_runtime_secure_zero(
		context->salt, sizeof(context->salt));
	pqcp_runtime_secure_zero(
		context->confirmation,
		sizeof(context->confirmation));
	return 0;
}

int pqcp_channel_rekey_abort(
	struct pqcp_channel_rekey_context *context)
{
	uint64_t current_epoch;

	if (context == NULL ||
	    context->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION) {
		return -EINVAL;
	}
	current_epoch = context->current_epoch;
	destroy_pending_keys(context);
	pqcp_runtime_secure_zero(context, sizeof(*context));
	context->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	context->state = PQCP_CHANNEL_REKEY_ABORTED;
	context->current_epoch = current_epoch;
	return 0;
}

int pqcp_channel_rekey_audit(
	const struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_context *context)
{
	if (channel == NULL || context == NULL ||
	    context->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    context->state < PQCP_CHANNEL_REKEY_IDLE ||
	    context->state > PQCP_CHANNEL_REKEY_ABORTED ||
	    (context->pending_epoch != 0U &&
	     context->pending_epoch <=
		     context->current_epoch)) {
		return -EINVAL;
	}
	if ((context->state ==
		     PQCP_CHANNEL_REKEY_PREPARED ||
	     context->state ==
		     PQCP_CHANNEL_REKEY_ACCEPTED) &&
	    (!context->pending_keys.traffic_keys_ready ||
	     !pqcp_runtime_key_handle_is_valid(
		     &context->pending_keys.client_write_key) ||
	     !pqcp_runtime_key_handle_is_valid(
		     &context->pending_keys.server_write_key) ||
	     context->key_store == NULL ||
	     context->prepared_at_ms == 0U ||
	     context->expires_at_ms <=
		     context->prepared_at_ms)) {
		return -EBADMSG;
	}
	if (context->state ==
		    PQCP_CHANNEL_REKEY_COMMITTED &&
	    !channel->keys.traffic_keys_ready) {
		return -EBADMSG;
	}
	return 0;
}
