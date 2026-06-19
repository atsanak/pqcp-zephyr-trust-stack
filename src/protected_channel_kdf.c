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

#define PQCP_CHANNEL_KEY_MATERIAL_BYTES \
	(PQCP_CHANNEL_FINISHED_BYTES * 2U + \
	 PQCP_CHANNEL_AEAD_KEY_BYTES * 2U + \
	 PQCP_CHANNEL_AEAD_NONCE_BYTES * 2U)

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

static int load_shared_secret(
	struct pqcp_channel *channel)
{
	const uint8_t *public_data = NULL;
	const uint8_t *secret_data = NULL;
	size_t public_length = 0U;
	size_t secret_length = 0U;
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(
		    &channel->ephemeral_kem_key)) {
		return -ENOENT;
	}
	/*
	 * During key exchange this handle is replaced with the derived shared
	 * secret handle once the ephemeral keypair is no longer needed.
	 */
	ret = pqcp_runtime_key_store_acquire(
		channel->key_store,
		&channel->ephemeral_kem_key,
		PQCP_RUNTIME_USAGE_DERIVE,
		pqcp_runtime_internal_now_ms(),
		&public_data, &public_length,
		&secret_data, &secret_length);
	if (ret != 0) {
		return ret;
	}
	if (secret_data == NULL ||
	    secret_length != PQCP_MLKEM_SS_SIZE) {
		(void)pqcp_runtime_key_store_release(
			channel->key_store,
			&channel->ephemeral_kem_key);
		return -EBADMSG;
	}
	memcpy(channel->keys.shared_secret,
	       secret_data, secret_length);
	(void)pqcp_runtime_key_store_release(
		channel->key_store,
		&channel->ephemeral_kem_key);
	channel->keys.shared_secret_ready = true;
	return 0;
}

int pqcp_channel_internal_derive_keys(
	struct pqcp_channel *channel)
{
	uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t input_key[PQCP_CHANNEL_EXPORTER_BYTES +
			  PQCP_MLKEM_SS_SIZE];
	uint8_t material[PQCP_CHANNEL_KEY_MATERIAL_BYTES];
	uint8_t info[128];
	size_t info_length;
	int ret;

	if (channel == NULL || !channel->keys.exporter_ready) {
		return -EINVAL;
	}
	if (!channel->keys.shared_secret_ready) {
		ret = load_shared_secret(channel);
		if (ret != 0) {
			return ret;
		}
	}
	ret = pqcp_channel_transcript_digest(
		&channel->transcript, transcript_hash);
	if (ret != 0) {
		return ret;
	}
	memcpy(input_key, channel->keys.exporter,
	       PQCP_CHANNEL_EXPORTER_BYTES);
	memcpy(input_key + PQCP_CHANNEL_EXPORTER_BYTES,
	       channel->keys.shared_secret,
	       PQCP_MLKEM_SS_SIZE);
	memset(info, 0, sizeof(info));
	info_length = 0U;
	memcpy(info + info_length, "PQCP traffic v1", 15U);
	info_length += 15U;
	pqcp_runtime_internal_write_u64(
		info + info_length, channel->config.session_id);
	info_length += 8U;
	pqcp_runtime_internal_write_u32(
		info + info_length, channel->config.mlkem_level);
	info_length += 4U;
	pqcp_runtime_internal_write_u32(
		info + info_length, channel->config.mldsa_level);
	info_length += 4U;
	const size_t profile_length = strnlen(
		channel->config.profile_id,
		sizeof(channel->config.profile_id));
	memcpy(info + info_length,
	       channel->config.profile_id, profile_length);
	info_length += profile_length;
	ret = pqcp_runtime_internal_hkdf_sha256(
		transcript_hash, sizeof(transcript_hash),
		input_key, sizeof(input_key),
		info, info_length,
		material, sizeof(material));
	if (ret != 0) {
		goto cleanup;
	}
	size_t offset = 0U;
	memcpy(channel->keys.client_finished,
	       material + offset,
	       PQCP_CHANNEL_FINISHED_BYTES);
	offset += PQCP_CHANNEL_FINISHED_BYTES;
	memcpy(channel->keys.server_finished,
	       material + offset,
	       PQCP_CHANNEL_FINISHED_BYTES);
	offset += PQCP_CHANNEL_FINISHED_BYTES;
	memcpy(channel->keys.client_write_key,
	       material + offset,
	       PQCP_CHANNEL_AEAD_KEY_BYTES);
	offset += PQCP_CHANNEL_AEAD_KEY_BYTES;
	memcpy(channel->keys.server_write_key,
	       material + offset,
	       PQCP_CHANNEL_AEAD_KEY_BYTES);
	offset += PQCP_CHANNEL_AEAD_KEY_BYTES;
	memcpy(channel->keys.client_nonce_base,
	       material + offset,
	       PQCP_CHANNEL_AEAD_NONCE_BYTES);
	offset += PQCP_CHANNEL_AEAD_NONCE_BYTES;
	memcpy(channel->keys.server_nonce_base,
	       material + offset,
	       PQCP_CHANNEL_AEAD_NONCE_BYTES);
	channel->keys.traffic_keys_ready = true;

cleanup:
	pqcp_runtime_secure_zero(
		transcript_hash, sizeof(transcript_hash));
	pqcp_runtime_secure_zero(input_key, sizeof(input_key));
	pqcp_runtime_secure_zero(material, sizeof(material));
	pqcp_runtime_secure_zero(info, sizeof(info));
	pqcp_runtime_secure_zero(
		channel->keys.shared_secret,
		sizeof(channel->keys.shared_secret));
	channel->keys.shared_secret_ready = false;
	return ret;
}

int pqcp_channel_internal_finished(
	const struct pqcp_channel *channel,
	enum pqcp_channel_role sender,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES],
	uint8_t output[PQCP_CHANNEL_FINISHED_BYTES])
{
	const uint8_t *key;

	if (channel == NULL || transcript_hash == NULL ||
	    output == NULL || !channel->keys.traffic_keys_ready) {
		return -EINVAL;
	}
	if (sender == PQCP_CHANNEL_ROLE_CLIENT) {
		key = channel->keys.client_finished;
	} else if (sender == PQCP_CHANNEL_ROLE_SERVER) {
		key = channel->keys.server_finished;
	} else {
		return -EINVAL;
	}
	return pqcp_runtime_internal_hmac_sha256(
		key, PQCP_CHANNEL_FINISHED_BYTES,
		transcript_hash, PQCP_CHANNEL_HASH_BYTES,
		output);
}
