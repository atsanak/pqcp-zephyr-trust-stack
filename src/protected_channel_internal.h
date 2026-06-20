/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#ifndef PQCP_PROTECTED_CHANNEL_INTERNAL_H_
#define PQCP_PROTECTED_CHANNEL_INTERNAL_H_

#include <pqcp_zephyr/protected_channel.h>

#define PQCP_CHANNEL_HELLO_BYTES \
	(16U + PQCP_CHANNEL_NONCE_BYTES + \
	 PQCP_RUNTIME_PROFILE_MAX_CHARS)
#define PQCP_CHANNEL_FLAG_MUTUAL_AUTH (1U << 0)
#define PQCP_CHANNEL_FLAG_SERVER_AUTH (1U << 1)

int pqcp_channel_internal_send_frame(
	struct pqcp_channel *channel,
	enum pqcp_channel_frame_type type,
	uint32_t flags,
	const uint8_t *payload,
	size_t payload_length,
	bool update_transcript);
int pqcp_channel_internal_receive_frame(
	struct pqcp_channel *channel,
	enum pqcp_channel_frame_type expected_type,
	struct pqcp_channel_frame_header *header,
	const uint8_t **payload,
	size_t *payload_length,
	bool update_transcript);
int pqcp_channel_internal_export(
	struct pqcp_channel *channel);
int pqcp_channel_internal_derive_keys(
	struct pqcp_channel *channel);
int pqcp_channel_internal_finished(
	const struct pqcp_channel *channel,
	enum pqcp_channel_role sender,
	const uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES],
	uint8_t output[PQCP_CHANNEL_FINISHED_BYTES]);
int pqcp_channel_internal_encrypt_record(
	const struct pqcp_channel *channel,
	const uint8_t *plaintext,
	size_t plaintext_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_channel_internal_decrypt_record(
	struct pqcp_channel *channel,
	uint64_t sequence,
	const uint8_t *ciphertext,
	size_t ciphertext_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_channel_internal_fail(
	struct pqcp_channel *channel,
	enum pqcp_channel_alert alert,
	int error);
int pqcp_channel_internal_encode_hello(
	const struct pqcp_channel *channel,
	const uint8_t nonce[PQCP_CHANNEL_NONCE_BYTES],
	uint8_t output[PQCP_CHANNEL_HELLO_BYTES]);
int pqcp_channel_internal_decode_hello(
	const uint8_t *input,
	size_t input_length,
	uint32_t *mlkem_level,
	uint32_t *mldsa_level,
	uint32_t *flags,
	uint8_t nonce[PQCP_CHANNEL_NONCE_BYTES],
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS]);
int pqcp_channel_internal_create_public_key(
	struct pqcp_channel *channel,
	enum pqcp_runtime_key_family family,
	uint32_t level,
	const uint8_t *public_key,
	size_t public_key_length,
	const char *label,
	struct pqcp_runtime_key_handle *handle);

#endif /* PQCP_PROTECTED_CHANNEL_INTERNAL_H_ */
