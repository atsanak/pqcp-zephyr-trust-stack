/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Inner AES-256-GCM record protection derived from TLS exporter + ML-KEM.
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>

#include <pqcp_zephyr/protected_channel.h>

#include "protected_channel_internal.h"
#include "runtime_internal.h"

static const uint8_t *write_key(
	const struct pqcp_channel *channel)
{
	return channel->config.role == PQCP_CHANNEL_ROLE_CLIENT ?
		channel->keys.client_write_key :
		channel->keys.server_write_key;
}

static const uint8_t *read_key(
	const struct pqcp_channel *channel)
{
	return channel->config.role == PQCP_CHANNEL_ROLE_CLIENT ?
		channel->keys.server_write_key :
		channel->keys.client_write_key;
}

static const uint8_t *write_nonce_base(
	const struct pqcp_channel *channel)
{
	return channel->config.role == PQCP_CHANNEL_ROLE_CLIENT ?
		channel->keys.client_nonce_base :
		channel->keys.server_nonce_base;
}

static const uint8_t *read_nonce_base(
	const struct pqcp_channel *channel)
{
	return channel->config.role == PQCP_CHANNEL_ROLE_CLIENT ?
		channel->keys.server_nonce_base :
		channel->keys.client_nonce_base;
}

static void build_nonce(
	const uint8_t base[PQCP_CHANNEL_AEAD_NONCE_BYTES],
	uint64_t sequence,
	uint8_t nonce[PQCP_CHANNEL_AEAD_NONCE_BYTES])
{
	memcpy(nonce, base, PQCP_CHANNEL_AEAD_NONCE_BYTES);
	for (size_t index = 0U; index < 8U; ++index) {
		nonce[PQCP_CHANNEL_AEAD_NONCE_BYTES - 1U - index] ^=
			(uint8_t)(sequence >> (index * 8U));
	}
}

static void build_aad(
	const struct pqcp_channel *channel,
	uint64_t sequence,
	uint32_t plaintext_length,
	uint8_t aad[28])
{
	pqcp_runtime_internal_write_u32(
		aad, PQCP_CHANNEL_MAGIC);
	pqcp_runtime_internal_write_u32(
		aad + 4U, PQCP_CHANNEL_SCHEMA_VERSION);
	pqcp_runtime_internal_write_u64(
		aad + 8U, channel->config.session_id);
	pqcp_runtime_internal_write_u64(
		aad + 16U, sequence);
	pqcp_runtime_internal_write_u32(
		aad + 24U, plaintext_length);
}

static int import_aead_key(
	const uint8_t key[PQCP_CHANNEL_AEAD_KEY_BYTES],
	uint32_t usage,
	psa_key_id_t *key_id)
{
	psa_key_attributes_t attributes =
		PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(
		&attributes, PQCP_CHANNEL_AEAD_KEY_BYTES * 8U);
	psa_set_key_usage_flags(&attributes, usage);
	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
	status = psa_import_key(
		&attributes, key,
		PQCP_CHANNEL_AEAD_KEY_BYTES, key_id);
	psa_reset_key_attributes(&attributes);
	return status == PSA_SUCCESS ? 0 : -EIO;
}

int pqcp_channel_internal_encrypt_record(
	struct pqcp_channel *channel,
	const uint8_t *plaintext,
	size_t plaintext_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	uint8_t nonce[PQCP_CHANNEL_AEAD_NONCE_BYTES];
	uint8_t aad[28];
	psa_key_id_t key_id = 0U;
	size_t produced = 0U;
	psa_status_t status;
	int ret;

	if (channel == NULL ||
	    !channel->keys.traffic_keys_ready ||
	    (plaintext == NULL && plaintext_length != 0U) ||
	    output == NULL || output_length == NULL ||
	    plaintext_length >
		    channel->config.max_payload_bytes ||
	    output_capacity <
		    plaintext_length +
			    PQCP_CHANNEL_AEAD_TAG_BYTES) {
		return -EINVAL;
	}
	build_nonce(
		write_nonce_base(channel),
		channel->send_sequence, nonce);
	build_aad(
		channel, channel->send_sequence,
		(uint32_t)plaintext_length, aad);
	ret = import_aead_key(
		write_key(channel), PSA_KEY_USAGE_ENCRYPT,
		&key_id);
	if (ret != 0) {
		goto cleanup;
	}
	status = psa_aead_encrypt(
		key_id, PSA_ALG_GCM,
		nonce, sizeof(nonce),
		aad, sizeof(aad),
		plaintext, plaintext_length,
		output, output_capacity, &produced);
	ret = status == PSA_SUCCESS ? 0 : -EIO;
	if (ret == 0 &&
	    produced != plaintext_length +
			PQCP_CHANNEL_AEAD_TAG_BYTES) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		*output_length = produced;
	}

cleanup:
	if (key_id != 0U) {
		(void)psa_destroy_key(key_id);
	}
	pqcp_runtime_secure_zero(nonce, sizeof(nonce));
	pqcp_runtime_secure_zero(aad, sizeof(aad));
	if (ret != 0) {
		pqcp_runtime_secure_zero(output, output_capacity);
		*output_length = 0U;
	}
	return ret;
}

int pqcp_channel_internal_decrypt_record(
	struct pqcp_channel *channel,
	uint64_t sequence,
	const uint8_t *ciphertext,
	size_t ciphertext_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	uint8_t nonce[PQCP_CHANNEL_AEAD_NONCE_BYTES];
	uint8_t aad[28];
	psa_key_id_t key_id = 0U;
	size_t produced = 0U;
	size_t plaintext_length;
	psa_status_t status;
	int ret;

	if (channel == NULL ||
	    !channel->keys.traffic_keys_ready ||
	    ciphertext == NULL ||
	    ciphertext_length < PQCP_CHANNEL_AEAD_TAG_BYTES ||
	    output == NULL || output_length == NULL) {
		return -EINVAL;
	}
	plaintext_length =
		ciphertext_length - PQCP_CHANNEL_AEAD_TAG_BYTES;
	if (plaintext_length > output_capacity ||
	    plaintext_length >
		    channel->config.max_payload_bytes) {
		return -ENOSPC;
	}
	ret = pqcp_channel_replay_accept(
		&channel->inbound_replay, sequence);
	if (ret != 0) {
		return ret;
	}
	build_nonce(read_nonce_base(channel), sequence, nonce);
	build_aad(
		channel, sequence,
		(uint32_t)plaintext_length, aad);
	ret = import_aead_key(
		read_key(channel), PSA_KEY_USAGE_DECRYPT,
		&key_id);
	if (ret != 0) {
		goto cleanup;
	}
	status = psa_aead_decrypt(
		key_id, PSA_ALG_GCM,
		nonce, sizeof(nonce),
		aad, sizeof(aad),
		ciphertext, ciphertext_length,
		output, output_capacity, &produced);
	ret = status == PSA_SUCCESS ? 0 : -EBADMSG;
	if (ret == 0 && produced != plaintext_length) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		*output_length = produced;
	}

cleanup:
	if (key_id != 0U) {
		(void)psa_destroy_key(key_id);
	}
	pqcp_runtime_secure_zero(nonce, sizeof(nonce));
	pqcp_runtime_secure_zero(aad, sizeof(aad));
	if (ret != 0) {
		pqcp_runtime_secure_zero(output, output_capacity);
		*output_length = 0U;
	}
	return ret;
}
