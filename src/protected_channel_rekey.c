/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Explicit protected-channel key epochs.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel_operations.h>

#include "runtime_internal.h"

#define REKEY_MATERIAL_BYTES \
	(PQCP_CHANNEL_FINISHED_BYTES * 2U + \
	 PQCP_CHANNEL_AEAD_KEY_BYTES * 2U + \
	 PQCP_CHANNEL_AEAD_NONCE_BYTES * 2U)

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

static int derive_pending_keys(
	const struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context)
{
	uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t input_key[
		PQCP_CHANNEL_EXPORTER_BYTES +
		PQCP_CHANNEL_AEAD_KEY_BYTES * 2U];
	uint8_t info[96];
	uint8_t material[REKEY_MATERIAL_BYTES];
	size_t offset = 0U;
	size_t info_length = 0U;
	int ret;

	ret = pqcp_channel_transcript_digest(
		&channel->transcript, transcript_hash);
	if (ret != 0) {
		return ret;
	}
	memcpy(input_key, channel->keys.exporter,
	       PQCP_CHANNEL_EXPORTER_BYTES);
	memcpy(input_key + PQCP_CHANNEL_EXPORTER_BYTES,
	       channel->keys.client_write_key,
	       PQCP_CHANNEL_AEAD_KEY_BYTES);
	memcpy(input_key + PQCP_CHANNEL_EXPORTER_BYTES +
		       PQCP_CHANNEL_AEAD_KEY_BYTES,
	       channel->keys.server_write_key,
	       PQCP_CHANNEL_AEAD_KEY_BYTES);
	memcpy(info + info_length, "PQCP rekey epoch v1", 19U);
	info_length += 19U;
	pqcp_runtime_internal_write_u64(
		info + info_length, channel->config.session_id);
	info_length += 8U;
	pqcp_runtime_internal_write_u64(
		info + info_length, context->current_epoch);
	info_length += 8U;
	pqcp_runtime_internal_write_u64(
		info + info_length, context->pending_epoch);
	info_length += 8U;
	pqcp_runtime_internal_write_u32(
		info + info_length, channel->config.mlkem_level);
	info_length += 4U;
	pqcp_runtime_internal_write_u32(
		info + info_length, channel->config.mldsa_level);
	info_length += 4U;
	ret = pqcp_runtime_internal_hkdf_sha256(
		context->salt, sizeof(context->salt),
		input_key, sizeof(input_key),
		info, info_length,
		material, sizeof(material));
	if (ret != 0) {
		goto cleanup;
	}
	memset(&context->pending_keys, 0,
	       sizeof(context->pending_keys));
	memcpy(context->pending_keys.exporter,
	       channel->keys.exporter,
	       sizeof(context->pending_keys.exporter));
	context->pending_keys.exporter_ready = true;
	memcpy(context->pending_keys.client_finished,
	       material + offset,
	       PQCP_CHANNEL_FINISHED_BYTES);
	offset += PQCP_CHANNEL_FINISHED_BYTES;
	memcpy(context->pending_keys.server_finished,
	       material + offset,
	       PQCP_CHANNEL_FINISHED_BYTES);
	offset += PQCP_CHANNEL_FINISHED_BYTES;
	memcpy(context->pending_keys.client_write_key,
	       material + offset,
	       PQCP_CHANNEL_AEAD_KEY_BYTES);
	offset += PQCP_CHANNEL_AEAD_KEY_BYTES;
	memcpy(context->pending_keys.server_write_key,
	       material + offset,
	       PQCP_CHANNEL_AEAD_KEY_BYTES);
	offset += PQCP_CHANNEL_AEAD_KEY_BYTES;
	memcpy(context->pending_keys.client_nonce_base,
	       material + offset,
	       PQCP_CHANNEL_AEAD_NONCE_BYTES);
	offset += PQCP_CHANNEL_AEAD_NONCE_BYTES;
	memcpy(context->pending_keys.server_nonce_base,
	       material + offset,
	       PQCP_CHANNEL_AEAD_NONCE_BYTES);
	context->pending_keys.traffic_keys_ready = true;
	{
		const uint8_t *confirmation_key =
			context->initiator ?
				context->pending_keys.
					client_finished :
				context->pending_keys.
					server_finished;
		uint8_t confirmation_input[
			PQCP_CHANNEL_HASH_BYTES + 16U];

		memcpy(confirmation_input, transcript_hash,
		       sizeof(transcript_hash));
		pqcp_runtime_internal_write_u64(
			confirmation_input +
				PQCP_CHANNEL_HASH_BYTES,
			context->current_epoch);
		pqcp_runtime_internal_write_u64(
			confirmation_input +
				PQCP_CHANNEL_HASH_BYTES + 8U,
			context->pending_epoch);
		ret = pqcp_runtime_internal_hmac_sha256(
			confirmation_key,
			PQCP_CHANNEL_FINISHED_BYTES,
			confirmation_input,
			sizeof(confirmation_input),
			context->confirmation);
		pqcp_runtime_secure_zero(
			confirmation_input,
			sizeof(confirmation_input));
	}

cleanup:
	pqcp_runtime_secure_zero(
		transcript_hash, sizeof(transcript_hash));
	pqcp_runtime_secure_zero(input_key, sizeof(input_key));
	pqcp_runtime_secure_zero(info, sizeof(info));
	pqcp_runtime_secure_zero(material, sizeof(material));
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			&context->pending_keys,
			sizeof(context->pending_keys));
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
		context->state = PQCP_CHANNEL_REKEY_ABORTED;
		return -ETIMEDOUT;
	}
	for (size_t index = 0U;
	     index < PQCP_CHANNEL_FINISHED_BYTES; ++index) {
		difference |=
			context->confirmation[index] ^
			confirmation[index];
	}
	if (difference != 0U) {
		context->state = PQCP_CHANNEL_REKEY_ABORTED;
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
	if (channel == NULL || !channel->established ||
	    context == NULL ||
	    context->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    context->state != PQCP_CHANNEL_REKEY_ACCEPTED ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	if (now_ms > context->expires_at_ms) {
		context->state = PQCP_CHANNEL_REKEY_ABORTED;
		return -ETIMEDOUT;
	}
	if (!context->pending_keys.traffic_keys_ready ||
	    !context->pending_keys.exporter_ready) {
		context->state = PQCP_CHANNEL_REKEY_ABORTED;
		return -EBADMSG;
	}
	pqcp_runtime_secure_zero(
		channel->keys.client_finished,
		sizeof(channel->keys.client_finished));
	pqcp_runtime_secure_zero(
		channel->keys.server_finished,
		sizeof(channel->keys.server_finished));
	pqcp_runtime_secure_zero(
		channel->keys.client_write_key,
		sizeof(channel->keys.client_write_key));
	pqcp_runtime_secure_zero(
		channel->keys.server_write_key,
		sizeof(channel->keys.server_write_key));
	pqcp_runtime_secure_zero(
		channel->keys.client_nonce_base,
		sizeof(channel->keys.client_nonce_base));
	pqcp_runtime_secure_zero(
		channel->keys.server_nonce_base,
		sizeof(channel->keys.server_nonce_base));
	channel->keys = context->pending_keys;
	channel->send_sequence = 0U;
	channel->receive_sequence = 0U;
	pqcp_channel_replay_reset(&channel->inbound_replay);
	context->current_epoch = context->pending_epoch;
	context->pending_epoch = 0U;
	context->state = PQCP_CHANNEL_REKEY_COMMITTED;
	pqcp_runtime_secure_zero(
		&context->pending_keys,
		sizeof(context->pending_keys));
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
