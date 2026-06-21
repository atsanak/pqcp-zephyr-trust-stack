/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * TLS-exporter and ML-KEM bound key schedule.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel.h>

#include "protected_channel_internal.h"
#include "runtime_internal.h"

#define PQCP_CHANNEL_DERIVE_INFO_BYTES 160U
#define PQCP_CHANNEL_MAC_INPUT_BYTES 96U

static int build_export_context(
	const struct pqcp_channel *channel,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	const size_t profile_length = strnlen(
		channel->config.profile_id,
		sizeof(channel->config.profile_id));
	const size_t required =
		4U + 8U + 4U + 4U + 4U +
		PQCP_CHANNEL_NONCE_BYTES * 2U +
		1U + profile_length;
	const uint8_t *client_nonce;
	const uint8_t *server_nonce;

	if (output == NULL || output_length == NULL ||
	    required > output_capacity ||
	    profile_length > UINT8_MAX) {
		return -EINVAL;
	}
	if (channel->config.role == PQCP_CHANNEL_ROLE_CLIENT) {
		client_nonce = channel->local_nonce;
		server_nonce = channel->peer_nonce;
	} else {
		client_nonce = channel->peer_nonce;
		server_nonce = channel->local_nonce;
	}
	pqcp_runtime_internal_write_u32(
		output, PQCP_CHANNEL_SCHEMA_VERSION);
	pqcp_runtime_internal_write_u64(
		output + 4U, channel->config.session_id);
	pqcp_runtime_internal_write_u32(
		output + 12U, PQCP_CHANNEL_ROLE_CLIENT);
	pqcp_runtime_internal_write_u32(
		output + 16U, channel->config.mlkem_level);
	pqcp_runtime_internal_write_u32(
		output + 20U, channel->config.mldsa_level);
	memcpy(output + 24U, client_nonce,
	       PQCP_CHANNEL_NONCE_BYTES);
	memcpy(output + 24U + PQCP_CHANNEL_NONCE_BYTES,
	       server_nonce, PQCP_CHANNEL_NONCE_BYTES);
	output[24U + PQCP_CHANNEL_NONCE_BYTES * 2U] =
		(uint8_t)profile_length;
	memcpy(output + 25U + PQCP_CHANNEL_NONCE_BYTES * 2U,
	       channel->config.profile_id, profile_length);
	*output_length = required;
	return 0;
}

int pqcp_channel_internal_export(
	struct pqcp_channel *channel)
{
	size_t context_length = 0U;
	int ret;

	if (channel == NULL ||
	    channel->transport.export_keying_material == NULL) {
		return -EINVAL;
	}
	ret = build_export_context(
		channel, channel->work_buffer,
		sizeof(channel->work_buffer),
		&context_length);
	if (ret != 0) {
		return ret;
	}
	ret = channel->transport.export_keying_material(
		channel->transport.context,
		PQCP_CHANNEL_EXPORTER_LABEL,
		channel->work_buffer, context_length,
		channel->keys.exporter,
		sizeof(channel->keys.exporter));
	pqcp_runtime_secure_zero(
		channel->work_buffer, context_length);
	if (ret != 0) {
		return ret;
	}
	channel->keys.exporter_ready = true;
	return 0;
}

static uint64_t current_time_ms(void)
{
	const uint64_t now_ms = pqcp_runtime_internal_now_ms();

	return now_ms == 0U ? 1U : now_ms;
}

static int build_derive_info(
	const struct pqcp_channel *channel,
	enum pqcp_channel_role direction,
	uint8_t output[PQCP_CHANNEL_DERIVE_INFO_BYTES],
	size_t *output_length)
{
	static const uint8_t label[] = "PQCP traffic key v2";
	const size_t profile_length = strnlen(
		channel->config.profile_id,
		sizeof(channel->config.profile_id));
	size_t offset = 0U;

	if (output == NULL || output_length == NULL ||
	    profile_length > UINT8_MAX) {
		return -EINVAL;
	}
	memcpy(output + offset, label, sizeof(label) - 1U);
	offset += sizeof(label) - 1U;
	memcpy(output + offset, channel->keys.exporter,
	       sizeof(channel->keys.exporter));
	offset += sizeof(channel->keys.exporter);
	pqcp_runtime_internal_write_u64(
		output + offset, channel->config.session_id);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		output + offset, channel->config.mlkem_level);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		output + offset, channel->config.mldsa_level);
	offset += 4U;
	output[offset++] = (uint8_t)direction;
	output[offset++] = (uint8_t)profile_length;
	memcpy(output + offset, channel->config.profile_id,
	       profile_length);
	offset += profile_length;
	*output_length = offset;
	return 0;
}

static int derive_traffic_key(
	struct pqcp_channel *channel,
	enum pqcp_channel_role direction,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES],
	struct pqcp_runtime_key_handle *handle)
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
	uint8_t info[PQCP_CHANNEL_DERIVE_INFO_BYTES];
	size_t info_length = 0U;
	int ret;

	request.now_ms = current_time_ms();
	request.expires_at_ms = 0U;
	request.label =
		direction == PQCP_CHANNEL_ROLE_CLIENT ?
			"client-traffic" : "server-traffic";
	ret = build_derive_info(
		channel, direction, info, &info_length);
	if (ret == 0) {
		ret = pqcp_runtime_key_store_derive(
			channel->key_store,
			&channel->ephemeral_kem_key,
			transcript_hash, PQCP_CHANNEL_HASH_BYTES,
			info, info_length, &request, handle);
	}
	pqcp_runtime_secure_zero(info, sizeof(info));
	return ret;
}

static int derive_nonce_base(
	struct pqcp_channel *channel,
	const struct pqcp_runtime_key_handle *handle,
	enum pqcp_channel_role direction,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES],
	uint8_t nonce[PQCP_CHANNEL_AEAD_NONCE_BYTES])
{
	static const uint8_t label[] = "PQCP traffic nonce v2";
	uint8_t input[PQCP_CHANNEL_MAC_INPUT_BYTES];
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
		input + offset, channel->config.session_id);
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

int pqcp_channel_internal_derive_keys(
	struct pqcp_channel *channel)
{
	uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES];
	int ret;

	if (channel == NULL || !channel->keys.exporter_ready ||
	    !pqcp_runtime_key_handle_is_valid(
		    &channel->ephemeral_kem_key) ||
	    channel->ephemeral_kem_key.family !=
		    PQCP_RUNTIME_KEY_SHARED_SECRET) {
		return -EINVAL;
	}
	ret = pqcp_channel_transcript_digest(
		&channel->transcript, transcript_hash);
	if (ret == 0) {
		ret = derive_traffic_key(
			channel, PQCP_CHANNEL_ROLE_CLIENT,
			transcript_hash,
			&channel->keys.client_write_key);
	}
	if (ret == 0) {
		ret = derive_traffic_key(
			channel, PQCP_CHANNEL_ROLE_SERVER,
			transcript_hash,
			&channel->keys.server_write_key);
	}
	if (ret == 0) {
		ret = derive_nonce_base(
			channel, &channel->keys.client_write_key,
			PQCP_CHANNEL_ROLE_CLIENT,
			transcript_hash,
			channel->keys.client_nonce_base);
	}
	if (ret == 0) {
		ret = derive_nonce_base(
			channel, &channel->keys.server_write_key,
			PQCP_CHANNEL_ROLE_SERVER,
			transcript_hash,
			channel->keys.server_nonce_base);
	}
	if (ret == 0) {
		ret = pqcp_runtime_key_store_destroy(
			channel->key_store,
			&channel->ephemeral_kem_key);
	}
	if (ret == 0) {
		channel->keys.traffic_keys_ready = true;
		memset(&channel->ephemeral_kem_key, 0,
		       sizeof(channel->ephemeral_kem_key));
	} else {
		if (pqcp_runtime_key_handle_is_valid(
			    &channel->keys.client_write_key)) {
			(void)pqcp_runtime_key_store_destroy(
				channel->key_store,
				&channel->keys.client_write_key);
		}
		if (pqcp_runtime_key_handle_is_valid(
			    &channel->keys.server_write_key)) {
			(void)pqcp_runtime_key_store_destroy(
				channel->key_store,
				&channel->keys.server_write_key);
		}
		memset(&channel->keys.client_write_key, 0,
		       sizeof(channel->keys.client_write_key));
		memset(&channel->keys.server_write_key, 0,
		       sizeof(channel->keys.server_write_key));
	}
	pqcp_runtime_secure_zero(
		transcript_hash, sizeof(transcript_hash));
	return ret;
}

int pqcp_channel_internal_finished(
	const struct pqcp_channel *channel,
	enum pqcp_channel_role sender,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES],
	uint8_t output[PQCP_CHANNEL_FINISHED_BYTES])
{
	static const uint8_t label[] = "PQCP finished v2";
	const struct pqcp_runtime_key_handle *key;
	uint8_t input[PQCP_CHANNEL_MAC_INPUT_BYTES];
	size_t tag_length = 0U;
	size_t offset = 0U;
	int ret;

	if (channel == NULL || transcript_hash == NULL ||
	    output == NULL || !channel->keys.traffic_keys_ready) {
		return -EINVAL;
	}
	if (sender == PQCP_CHANNEL_ROLE_CLIENT) {
		key = &channel->keys.client_write_key;
	} else if (sender == PQCP_CHANNEL_ROLE_SERVER) {
		key = &channel->keys.server_write_key;
	} else {
		return -EINVAL;
	}
	memcpy(input + offset, label, sizeof(label) - 1U);
	offset += sizeof(label) - 1U;
	memcpy(input + offset, transcript_hash,
	       PQCP_CHANNEL_HASH_BYTES);
	offset += PQCP_CHANNEL_HASH_BYTES;
	pqcp_runtime_internal_write_u64(
		input + offset, channel->config.session_id);
	offset += 8U;
	input[offset++] = (uint8_t)sender;
	ret = pqcp_runtime_key_store_mac(
		channel->key_store, key, input, offset,
		output, PQCP_CHANNEL_FINISHED_BYTES,
		&tag_length);
	pqcp_runtime_secure_zero(input, sizeof(input));
	return ret == 0 &&
	       tag_length != PQCP_CHANNEL_FINISHED_BYTES ?
		       -EBADMSG : ret;
}
