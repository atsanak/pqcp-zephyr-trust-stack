/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded binary frame and hello codecs.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel.h>

#include "protected_channel_internal.h"
#include "runtime_internal.h"

static bool frame_type_valid(uint16_t type)
{
	return type >= PQCP_CHANNEL_FRAME_CLIENT_HELLO &&
	       type <= PQCP_CHANNEL_FRAME_ALERT;
}

static bool header_valid(
	const struct pqcp_channel_frame_header *header)
{
	return header != NULL &&
	       header->magic == PQCP_CHANNEL_MAGIC &&
	       header->schema_version ==
		       PQCP_CHANNEL_SCHEMA_VERSION &&
	       frame_type_valid(header->type) &&
	       header->session_id != 0U &&
	       header->payload_length <=
		       PQCP_CHANNEL_MAX_PAYLOAD_BYTES &&
	       header->reserved == 0U;
}

int pqcp_channel_frame_encode(
	const struct pqcp_channel_frame_header *header,
	const uint8_t *payload,
	size_t payload_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	const size_t required =
		PQCP_CHANNEL_FRAME_HEADER_BYTES + payload_length;

	if (!header_valid(header) ||
	    header->payload_length != payload_length ||
	    (payload == NULL && payload_length != 0U) ||
	    output == NULL || output_length == NULL ||
	    required > output_capacity ||
	    required > PQCP_CHANNEL_MAX_FRAME_BYTES) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u32(
		output, header->magic);
	pqcp_runtime_internal_write_u16(
		output + 4U, header->schema_version);
	pqcp_runtime_internal_write_u16(
		output + 6U, header->type);
	pqcp_runtime_internal_write_u32(
		output + 8U, header->flags);
	pqcp_runtime_internal_write_u64(
		output + 12U, header->session_id);
	pqcp_runtime_internal_write_u64(
		output + 20U, header->sequence);
	pqcp_runtime_internal_write_u32(
		output + 28U, header->payload_length);
	pqcp_runtime_internal_write_u32(
		output + 32U, header->reserved);
	if (payload_length != 0U) {
		memcpy(output + PQCP_CHANNEL_FRAME_HEADER_BYTES,
		       payload, payload_length);
	}
	*output_length = required;
	return 0;
}

int pqcp_channel_frame_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_channel_frame_header *header,
	const uint8_t **payload,
	size_t *payload_length)
{
	size_t required;

	if (input == NULL || header == NULL ||
	    payload == NULL || payload_length == NULL ||
	    input_length < PQCP_CHANNEL_FRAME_HEADER_BYTES ||
	    input_length > PQCP_CHANNEL_MAX_FRAME_BYTES) {
		return -EINVAL;
	}
	memset(header, 0, sizeof(*header));
	header->magic =
		pqcp_runtime_internal_read_u32(input);
	header->schema_version =
		pqcp_runtime_internal_read_u16(input + 4U);
	header->type =
		pqcp_runtime_internal_read_u16(input + 6U);
	header->flags =
		pqcp_runtime_internal_read_u32(input + 8U);
	header->session_id =
		pqcp_runtime_internal_read_u64(input + 12U);
	header->sequence =
		pqcp_runtime_internal_read_u64(input + 20U);
	header->payload_length =
		pqcp_runtime_internal_read_u32(input + 28U);
	header->reserved =
		pqcp_runtime_internal_read_u32(input + 32U);
	if (!header_valid(header)) {
		return -EBADMSG;
	}
	required = PQCP_CHANNEL_FRAME_HEADER_BYTES +
		   header->payload_length;
	if (required != input_length) {
		return -EMSGSIZE;
	}
	*payload = header->payload_length != 0U ?
		input + PQCP_CHANNEL_FRAME_HEADER_BYTES : NULL;
	*payload_length = header->payload_length;
	return 0;
}

int pqcp_channel_internal_encode_hello(
	const struct pqcp_channel *channel,
	const uint8_t nonce[PQCP_CHANNEL_NONCE_BYTES],
	uint8_t output[PQCP_CHANNEL_HELLO_BYTES])
{
	uint32_t flags = PQCP_CHANNEL_FLAG_SERVER_AUTH;
	size_t profile_length;

	if (channel == NULL || nonce == NULL || output == NULL ||
	    !pqcp_runtime_internal_text_valid(
		    channel->config.profile_id,
		    sizeof(channel->config.profile_id))) {
		return -EINVAL;
	}
	if (channel->config.require_mutual_authentication) {
		flags |= PQCP_CHANNEL_FLAG_MUTUAL_AUTH;
	}
	memset(output, 0, PQCP_CHANNEL_HELLO_BYTES);
	pqcp_runtime_internal_write_u32(
		output, PQCP_CHANNEL_SCHEMA_VERSION);
	pqcp_runtime_internal_write_u32(
		output + 4U, channel->config.mlkem_level);
	pqcp_runtime_internal_write_u32(
		output + 8U, channel->config.mldsa_level);
	pqcp_runtime_internal_write_u32(
		output + 12U, flags);
	memcpy(output + 16U, nonce, PQCP_CHANNEL_NONCE_BYTES);
	profile_length = strnlen(
		channel->config.profile_id,
		sizeof(channel->config.profile_id));
	memcpy(output + 16U + PQCP_CHANNEL_NONCE_BYTES,
	       channel->config.profile_id, profile_length);
	return 0;
}

int pqcp_channel_internal_decode_hello(
	const uint8_t *input,
	size_t input_length,
	uint32_t *mlkem_level,
	uint32_t *mldsa_level,
	uint32_t *flags,
	uint8_t nonce[PQCP_CHANNEL_NONCE_BYTES],
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS])
{
	const uint32_t schema =
		input_length >= 4U ?
		pqcp_runtime_internal_read_u32(input) : 0U;

	if (input == NULL ||
	    input_length != PQCP_CHANNEL_HELLO_BYTES ||
	    mlkem_level == NULL || mldsa_level == NULL ||
	    flags == NULL || nonce == NULL ||
	    profile_id == NULL ||
	    schema != PQCP_CHANNEL_SCHEMA_VERSION) {
		return -EINVAL;
	}
	*mlkem_level =
		pqcp_runtime_internal_read_u32(input + 4U);
	*mldsa_level =
		pqcp_runtime_internal_read_u32(input + 8U);
	*flags =
		pqcp_runtime_internal_read_u32(input + 12U);
	if ((*flags &
	     ~(PQCP_CHANNEL_FLAG_MUTUAL_AUTH |
	       PQCP_CHANNEL_FLAG_SERVER_AUTH)) != 0U ||
	    (*flags & PQCP_CHANNEL_FLAG_SERVER_AUTH) == 0U) {
		return -EBADMSG;
	}
	memcpy(nonce, input + 16U, PQCP_CHANNEL_NONCE_BYTES);
	memcpy(profile_id,
	       input + 16U + PQCP_CHANNEL_NONCE_BYTES,
	       PQCP_RUNTIME_PROFILE_MAX_CHARS);
	profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS - 1U] = '\0';
	if (!pqcp_runtime_internal_text_valid(
		    profile_id, PQCP_RUNTIME_PROFILE_MAX_CHARS)) {
		return -EBADMSG;
	}
	return 0;
}

const char *pqcp_channel_frame_type_str(
	enum pqcp_channel_frame_type type)
{
	switch (type) {
	case PQCP_CHANNEL_FRAME_CLIENT_HELLO:
		return "client_hello";
	case PQCP_CHANNEL_FRAME_SERVER_HELLO:
		return "server_hello";
	case PQCP_CHANNEL_FRAME_KEM_PUBLIC_KEY:
		return "kem_public_key";
	case PQCP_CHANNEL_FRAME_KEM_CIPHERTEXT:
		return "kem_ciphertext";
	case PQCP_CHANNEL_FRAME_SERVER_AUTH:
		return "server_auth";
	case PQCP_CHANNEL_FRAME_CLIENT_AUTH:
		return "client_auth";
	case PQCP_CHANNEL_FRAME_FINISHED:
		return "finished";
	case PQCP_CHANNEL_FRAME_APPLICATION:
		return "application";
	case PQCP_CHANNEL_FRAME_CLOSE:
		return "close";
	case PQCP_CHANNEL_FRAME_ALERT:
		return "alert";
	default:
		return "unknown";
	}
}
