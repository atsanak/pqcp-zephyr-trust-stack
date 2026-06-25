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

static int safe_add_ms(
	uint64_t base,
	uint64_t delta,
	uint64_t *sum)
{
	if (sum == NULL || UINT64_MAX - base < delta) {
		return -EOVERFLOW;
	}
	*sum = base + delta;
	return 0;
}

static int destroy_pending_keys(
	struct pqcp_channel_rekey_context *context)
{
	int first_error = 0;
	int ret;

	if (context->key_store != NULL &&
	    pqcp_runtime_key_handle_is_valid(
		    &context->pending_keys.client_write_key)) {
		ret = pqcp_runtime_key_store_destroy(
			context->key_store,
			&context->pending_keys.client_write_key);
		if (ret == 0 || ret == -ENOENT) {
			memset(
				&context->pending_keys.client_write_key,
				0,
				sizeof(context->pending_keys.client_write_key));
		} else {
			first_error = ret;
		}
	}
	if (context->key_store != NULL &&
	    pqcp_runtime_key_handle_is_valid(
		    &context->pending_keys.server_write_key)) {
		ret = pqcp_runtime_key_store_destroy(
			context->key_store,
			&context->pending_keys.server_write_key);
		if (ret == 0 || ret == -ENOENT) {
			memset(
				&context->pending_keys.server_write_key,
				0,
				sizeof(context->pending_keys.server_write_key));
		} else if (first_error == 0) {
			first_error = ret;
		}
	}
	context->pending_cleanup =
		pqcp_runtime_key_handle_is_valid(
			&context->pending_keys.client_write_key) ||
		pqcp_runtime_key_handle_is_valid(
			&context->pending_keys.server_write_key);
	if (!context->pending_cleanup) {
		pqcp_runtime_secure_zero(
			&context->pending_keys,
			sizeof(context->pending_keys));
	}
	return first_error;
}

static enum pqcp_channel_role peer_role(
	enum pqcp_channel_role role)
{
	return role == PQCP_CHANNEL_ROLE_CLIENT ?
		PQCP_CHANNEL_ROLE_SERVER :
		PQCP_CHANNEL_ROLE_CLIENT;
}

static bool confirmation_equal(
	const uint8_t left[PQCP_CHANNEL_FINISHED_BYTES],
	const uint8_t right[PQCP_CHANNEL_FINISHED_BYTES])
{
	uint8_t difference = 0U;

	for (size_t index = 0U;
	     index < PQCP_CHANNEL_FINISHED_BYTES; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static struct pqcp_runtime_key_handle *direction_handle(
	struct pqcp_channel_keys *keys,
	enum pqcp_channel_role direction)
{
	return direction == PQCP_CHANNEL_ROLE_CLIENT ?
		&keys->client_write_key :
		&keys->server_write_key;
}

static const struct pqcp_runtime_key_handle *const_direction_handle(
	const struct pqcp_channel_keys *keys,
	enum pqcp_channel_role direction)
{
	return direction == PQCP_CHANNEL_ROLE_CLIENT ?
		&keys->client_write_key :
		&keys->server_write_key;
}

static bool direction_committed(
	const struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_context *context,
	enum pqcp_channel_role direction)
{
	return direction == channel->config.role ?
		context->local_direction_committed :
		context->peer_direction_committed;
}

static uint8_t *direction_nonce_base(
	struct pqcp_channel_keys *keys,
	enum pqcp_channel_role direction)
{
	return direction == PQCP_CHANNEL_ROLE_CLIENT ?
		keys->client_nonce_base :
		keys->server_nonce_base;
}

static void record_retired_direction(
	struct pqcp_channel_rekey_context *context,
	enum pqcp_channel_role direction,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t nonce[PQCP_CHANNEL_AEAD_NONCE_BYTES])
{
	struct pqcp_runtime_key_handle *retired =
		direction_handle(&context->retired_keys, direction);
	uint8_t *retired_nonce =
		direction_nonce_base(
			&context->retired_keys, direction);

	if (handle == NULL ||
	    !pqcp_runtime_key_handle_is_valid(handle) ||
	    nonce == NULL) {
		return;
	}
	*retired = *handle;
	memcpy(retired_nonce, nonce,
	       PQCP_CHANNEL_AEAD_NONCE_BYTES);
	context->retired_keys.traffic_keys_ready = true;
	context->cleanup_pending = true;
}

static void finalize_rekey(
	struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	uint64_t now_ms)
{
	memcpy(channel->keys.exporter,
	       context->pending_keys.exporter,
	       sizeof(channel->keys.exporter));
	channel->keys.exporter_ready =
		context->pending_keys.exporter_ready;
	channel->keys.traffic_keys_ready = true;
	pqcp_runtime_secure_zero(
		context->pending_keys.exporter,
		sizeof(context->pending_keys.exporter));
	context->pending_keys.exporter_ready = false;
	context->pending_keys.traffic_keys_ready = false;
	context->state = PQCP_CHANNEL_REKEY_COMMITTED;
	context->current_epoch = context->pending_epoch;
	context->pending_epoch = 0U;
	context->prepared_at_ms = now_ms;
	context->committed_at_ms = now_ms;
	context->bytes_at_prepare = 0U;
	context->local_direction_committed = false;
	context->peer_direction_committed = false;
	context->pending_peer_receive = false;
}

static int commit_direction(
	struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	enum pqcp_channel_role direction,
	uint64_t now_ms)
{
	struct pqcp_runtime_key_handle *active_handle;
	struct pqcp_runtime_key_handle *pending_handle;
	struct pqcp_runtime_key_handle old_handle;
	uint8_t old_nonce[PQCP_CHANNEL_AEAD_NONCE_BYTES];
	uint8_t *active_nonce;
	uint8_t *pending_nonce;
	bool local_direction;

	if (channel == NULL || context == NULL ||
	    context->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    context->state != PQCP_CHANNEL_REKEY_ACCEPTED ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	active_handle = direction_handle(
		&channel->keys, direction);
	pending_handle = direction_handle(
		&context->pending_keys, direction);
	active_nonce = direction_nonce_base(
		&channel->keys, direction);
	pending_nonce = direction_nonce_base(
		&context->pending_keys, direction);
	local_direction = direction == channel->config.role;
	if ((local_direction &&
	     context->local_direction_committed) ||
	    (!local_direction &&
	     context->peer_direction_committed)) {
		return 0;
	}
	if (!pqcp_runtime_key_handle_is_valid(
		    pending_handle)) {
		return -EBADMSG;
	}
	old_handle = *active_handle;
	memcpy(old_nonce, active_nonce, sizeof(old_nonce));
	*active_handle = *pending_handle;
	memcpy(active_nonce, pending_nonce,
	       PQCP_CHANNEL_AEAD_NONCE_BYTES);
	memset(pending_handle, 0, sizeof(*pending_handle));
	pqcp_runtime_secure_zero(
		pending_nonce, PQCP_CHANNEL_AEAD_NONCE_BYTES);
	record_retired_direction(
		context, direction, &old_handle, old_nonce);
	pqcp_runtime_secure_zero(
		old_nonce, sizeof(old_nonce));
	if (local_direction) {
		context->local_direction_committed = true;
	} else {
		context->peer_direction_committed = true;
		context->pending_peer_receive = false;
	}
	if (context->local_direction_committed &&
	    context->peer_direction_committed) {
		finalize_rekey(channel, context, now_ms);
	}
	return 0;
}

static void build_rekey_info(
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
	build_rekey_info(
		channel, context, direction, transcript_hash,
		info, &info_length);
	ret = pqcp_runtime_key_store_derive(
		channel->key_store, source,
		context->salt, sizeof(context->salt),
		info, info_length, &request, destination);
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

static int derive_role_confirmation(
	const struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES],
	enum pqcp_channel_role confirming_role,
	uint8_t confirmation[PQCP_CHANNEL_FINISHED_BYTES])
{
	static const uint8_t label[] = "PQCP rekey confirm v2";
	const struct pqcp_runtime_key_handle *key =
		confirming_role == PQCP_CHANNEL_ROLE_CLIENT ?
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
	input[offset++] = (uint8_t)context->initiator_role;
	input[offset++] = (uint8_t)confirming_role;
	input[offset++] =
		confirming_role == context->initiator_role ? 1U : 0U;
	ret = pqcp_runtime_key_store_mac(
		channel->key_store, key, input, offset,
		confirmation, PQCP_CHANNEL_FINISHED_BYTES,
		&tag_length);
	pqcp_runtime_secure_zero(input, sizeof(input));
	return ret == 0 &&
	       tag_length != PQCP_CHANNEL_FINISHED_BYTES ?
		       -EBADMSG : ret;
}

static int derive_confirmations(
	const struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES])
{
	const enum pqcp_channel_role local_role =
		channel->config.role;
	int ret;

	ret = derive_role_confirmation(
		channel, context, transcript_hash, local_role,
		context->confirmation);
	if (ret == 0) {
		ret = derive_role_confirmation(
			channel, context, transcript_hash,
			peer_role(local_role),
			context->expected_peer_confirmation);
	}
	return ret;
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
		ret = derive_confirmations(
			channel, context, transcript_hash);
	}
	pqcp_runtime_secure_zero(
		transcript_hash, sizeof(transcript_hash));
	if (ret != 0) {
		const int cleanup_ret =
			destroy_pending_keys(context);

		if (cleanup_ret != 0) {
			context->last_cleanup_error = cleanup_ret;
			context->cleanup_failures++;
		}
		pqcp_runtime_secure_zero(
			context->confirmation,
			sizeof(context->confirmation));
		pqcp_runtime_secure_zero(
			context->expected_peer_confirmation,
			sizeof(context->expected_peer_confirmation));
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
	uint64_t epoch_started_at_ms,
	uint64_t epoch_started_bytes)
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
	return bytes < epoch_started_bytes ||
	       bytes - epoch_started_bytes >=
		       policy->maximum_epoch_bytes ||
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
	uint64_t current_epoch;
	uint64_t expires_at_ms;
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
	if (context->schema_version == 0U) {
		if (context->state != PQCP_CHANNEL_REKEY_IDLE ||
		    context->current_epoch != 0U ||
		    context->pending_epoch != 0U ||
		    context->key_store != NULL ||
		    context->cleanup_pending ||
		    context->pending_cleanup) {
			return -EINVAL;
		}
		context->schema_version =
			PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	} else if (context->schema_version !=
			   PQCP_CHANNEL_OPERATION_SCHEMA_VERSION) {
		return -EINVAL;
	}
	if (context->cleanup_pending ||
	    context->pending_cleanup) {
		return -EBUSY;
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
	    now_ms < context->prepared_at_ms) {
		return -ERANGE;
	}
	if (context->prepared_at_ms != 0U &&
	    now_ms - context->prepared_at_ms <
		    policy->minimum_interval_ms) {
		return -EAGAIN;
	}
	ret = safe_add_ms(
		now_ms,
		(uint64_t)policy->handshake_timeout_ms,
		&expires_at_ms);
	if (ret != 0) {
		return ret;
	}
	current_epoch = context->current_epoch;
	ret = destroy_pending_keys(context);
	if (ret != 0) {
		context->last_cleanup_error = ret;
		context->cleanup_failures++;
		return ret;
	}
	pqcp_runtime_secure_zero(context, sizeof(*context));
	context->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	context->state = PQCP_CHANNEL_REKEY_PREPARED;
	context->current_epoch = current_epoch;
	context->pending_epoch = next_epoch;
	context->prepared_at_ms = now_ms;
	context->expires_at_ms = expires_at_ms;
	context->bytes_at_prepare =
		channel->application_bytes_sent +
		channel->application_bytes_received;
	context->key_store = channel->key_store;
	context->initiator = initiator;
	context->initiator_role = initiator ?
		channel->config.role :
		peer_role(channel->config.role);
	context->local_direction_committed = false;
	context->peer_direction_committed = false;
	context->pending_peer_receive = false;
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
	if (!confirmation_equal(
		    context->expected_peer_confirmation,
		    confirmation)) {
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
	int ret;

	ret = pqcp_channel_rekey_commit_local(
		channel, context, now_ms);
	if (ret == 0) {
		ret = pqcp_channel_rekey_commit_peer(
			channel, context, now_ms);
	}
	return ret;
}

int pqcp_channel_rekey_commit_local(
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
		return -ETIMEDOUT;
	}
	return commit_direction(
		channel, context, channel->config.role, now_ms);
}

int pqcp_channel_rekey_commit_peer(
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
		return -ETIMEDOUT;
	}
	return commit_direction(
		channel, context,
		peer_role(channel->config.role), now_ms);
}

int pqcp_channel_rekey_cleanup(
	struct pqcp_channel_rekey_context *context)
{
	int first_error = 0;
	int ret;

	if (context == NULL ||
	    context->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    context->key_store == NULL) {
		return -EINVAL;
	}
	if (!context->cleanup_pending &&
	    !context->pending_cleanup) {
		return 0;
	}
	if (context->pending_cleanup) {
		ret = destroy_pending_keys(context);
		if (ret != 0) {
			first_error = ret;
		}
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &context->retired_keys.client_write_key)) {
		ret = pqcp_runtime_key_store_destroy(
			context->key_store,
			&context->retired_keys.client_write_key);
		if (ret == 0 || ret == -ENOENT) {
			memset(
				&context->retired_keys.client_write_key,
				0,
				sizeof(context->retired_keys.client_write_key));
		} else {
			first_error = ret;
		}
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &context->retired_keys.server_write_key)) {
		ret = pqcp_runtime_key_store_destroy(
			context->key_store,
			&context->retired_keys.server_write_key);
		if (ret == 0 || ret == -ENOENT) {
			memset(
				&context->retired_keys.server_write_key,
				0,
				sizeof(context->retired_keys.server_write_key));
		} else if (first_error == 0) {
			first_error = ret;
		}
	}
	context->cleanup_pending =
		pqcp_runtime_key_handle_is_valid(
			&context->retired_keys.client_write_key) ||
		pqcp_runtime_key_handle_is_valid(
			&context->retired_keys.server_write_key);
	context->last_cleanup_error = first_error;
	if (first_error != 0) {
		context->cleanup_failures++;
		return first_error;
	}
	pqcp_runtime_secure_zero(
		&context->retired_keys,
		sizeof(context->retired_keys));
	return 0;
}

int pqcp_channel_rekey_abort(
	struct pqcp_channel_rekey_context *context)
{
	uint64_t current_epoch;
	struct pqcp_channel_keys pending_keys;
	struct pqcp_channel_keys retired_keys;
	struct pqcp_runtime_key_store *key_store;
	uint32_t cleanup_failures;
	int last_cleanup_error;
	bool cleanup_pending;
	bool pending_cleanup;
	int cleanup_ret;

	if (context == NULL ||
	    context->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION) {
		return -EINVAL;
	}
	current_epoch = context->current_epoch;
	retired_keys = context->retired_keys;
	key_store = context->key_store;
	cleanup_failures = context->cleanup_failures;
	last_cleanup_error = context->last_cleanup_error;
	cleanup_pending = context->cleanup_pending;
	cleanup_ret = destroy_pending_keys(context);
	if (cleanup_ret != 0) {
		cleanup_failures++;
		last_cleanup_error = cleanup_ret;
	}
	pending_keys = context->pending_keys;
	pending_cleanup = context->pending_cleanup;
	pqcp_runtime_secure_zero(context, sizeof(*context));
	context->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	context->state = PQCP_CHANNEL_REKEY_ABORTED;
	context->current_epoch = current_epoch;
	context->pending_keys = pending_keys;
	context->retired_keys = retired_keys;
	context->key_store = key_store;
	context->cleanup_failures = cleanup_failures;
	context->last_cleanup_error = last_cleanup_error;
	context->cleanup_pending = cleanup_pending;
	context->pending_cleanup = pending_cleanup;
	context->local_direction_committed = false;
	context->peer_direction_committed = false;
	context->pending_peer_receive = false;
	return cleanup_ret;
}

int pqcp_channel_rekey_audit(
	const struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_context *context)
{
	const bool active_exchange =
		context != NULL &&
		(context->state == PQCP_CHANNEL_REKEY_PREPARED ||
		 context->state == PQCP_CHANNEL_REKEY_ACCEPTED);

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
	if (active_exchange) {
		if (!context->pending_keys.traffic_keys_ready ||
		    context->key_store == NULL ||
		    context->prepared_at_ms == 0U ||
		    context->expires_at_ms <=
			    context->prepared_at_ms) {
			return -EBADMSG;
		}
		if ((!direction_committed(
			      channel, context,
			      PQCP_CHANNEL_ROLE_CLIENT) &&
		     !pqcp_runtime_key_handle_is_valid(
			     &context->pending_keys.client_write_key)) ||
		    (!direction_committed(
			      channel, context,
			      PQCP_CHANNEL_ROLE_SERVER) &&
		     !pqcp_runtime_key_handle_is_valid(
			     &context->pending_keys.server_write_key))) {
			return -EBADMSG;
		}
	}
	if ((context->local_direction_committed ||
	     context->peer_direction_committed) &&
	    context->state !=
		    PQCP_CHANNEL_REKEY_ACCEPTED) {
		return -EBADMSG;
	}
	if (context->state ==
		    PQCP_CHANNEL_REKEY_COMMITTED &&
	    (!channel->keys.traffic_keys_ready ||
	     context->committed_at_ms == 0U ||
	     context->expires_at_ms <
		     context->committed_at_ms)) {
		return -EBADMSG;
	}
	if (context->cleanup_pending &&
	    (context->key_store == NULL ||
	     !context->retired_keys.traffic_keys_ready ||
	     (!pqcp_runtime_key_handle_is_valid(
		      &context->retired_keys.client_write_key) &&
	      !pqcp_runtime_key_handle_is_valid(
		      &context->retired_keys.server_write_key)))) {
		return -EBADMSG;
	}
	if (context->pending_cleanup &&
		    (!pqcp_runtime_key_handle_is_valid(
		      &context->pending_keys.client_write_key) &&
	     !pqcp_runtime_key_handle_is_valid(
			      &context->pending_keys.server_write_key))) {
		return -EBADMSG;
	}
	if (context->pending_peer_receive &&
	    !pqcp_runtime_key_handle_is_valid(
		    const_direction_handle(
			    &context->pending_keys,
			    peer_role(channel->config.role)))) {
		return -EBADMSG;
	}
	return 0;
}
