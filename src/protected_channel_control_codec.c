/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Canonical codec for protected-channel operational control messages.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel_operations.h>

#include "runtime_internal.h"

#define CONTROL_HEADER_BYTES 56U
#define CONTROL_DIGEST_BYTES 32U

static bool control_kind_valid(
	enum pqcp_channel_control_kind kind)
{
	return kind > PQCP_CHANNEL_CONTROL_NONE &&
	       kind < PQCP_CHANNEL_CONTROL_KIND_COUNT;
}

static int control_validate(
	const struct pqcp_channel_control_message *message)
{
	if (message == NULL ||
	    message->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    !control_kind_valid(message->kind) ||
	    message->message_id == 0U ||
	    message->timestamp_ms == 0U ||
	    message->payload_length >
		    sizeof(message->payload)) {
		return -EINVAL;
	}
	switch (message->kind) {
	case PQCP_CHANNEL_CONTROL_STREAM_OPEN:
	case PQCP_CHANNEL_CONTROL_STREAM_ACCEPT:
	case PQCP_CHANNEL_CONTROL_STREAM_REFUSE:
	case PQCP_CHANNEL_CONTROL_STREAM_CLOSE:
	case PQCP_CHANNEL_CONTROL_STREAM_RESET:
	case PQCP_CHANNEL_CONTROL_STREAM_WINDOW:
		if (message->stream_id == 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_CHANNEL_CONTROL_REKEY_PREPARE:
	case PQCP_CHANNEL_CONTROL_REKEY_ACCEPT:
	case PQCP_CHANNEL_CONTROL_REKEY_COMMIT:
	case PQCP_CHANNEL_CONTROL_REKEY_ABORT:
	case PQCP_CHANNEL_CONTROL_KEY_UPDATE_REQUEST:
	case PQCP_CHANNEL_CONTROL_KEY_UPDATE_ACK:
		if (message->epoch == 0U) {
			return -EINVAL;
		}
		break;
	default:
		break;
	}
	return 0;
}

static int control_digest(
	const uint8_t *header,
	const uint8_t *payload,
	size_t payload_length,
	uint8_t digest[CONTROL_DIGEST_BYTES])
{
	const uint8_t *parts[2] = {
		header,
		payload,
	};
	const size_t lengths[2] = {
		CONTROL_HEADER_BYTES,
		payload_length,
	};

	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, ARRAY_SIZE(parts), digest);
}

int pqcp_channel_control_encode(
	const struct pqcp_channel_control_message *message,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	uint8_t digest[CONTROL_DIGEST_BYTES];
	size_t required;
	int ret;

	ret = control_validate(message);
	if (ret != 0 || output == NULL ||
	    output_length == NULL) {
		return ret != 0 ? ret : -EINVAL;
	}
	required = CONTROL_HEADER_BYTES +
		message->payload_length +
		CONTROL_DIGEST_BYTES;
	if (required > output_capacity) {
		return -ENOSPC;
	}
	memset(output, 0, required);
	pqcp_runtime_internal_write_u32(
		output, message->schema_version);
	pqcp_runtime_internal_write_u32(
		output + 4U, (uint32_t)message->kind);
	pqcp_runtime_internal_write_u32(
		output + 8U, message->flags);
	pqcp_runtime_internal_write_u32(
		output + 12U, message->stream_id);
	pqcp_runtime_internal_write_u64(
		output + 16U, message->message_id);
	pqcp_runtime_internal_write_u64(
		output + 24U, message->timestamp_ms);
	pqcp_runtime_internal_write_u64(
		output + 32U, message->epoch);
	pqcp_runtime_internal_write_u32(
		output + 40U, message->value);
	pqcp_runtime_internal_write_u32(
		output + 44U, message->error);
	pqcp_runtime_internal_write_u32(
		output + 48U,
		(uint32_t)message->payload_length);
	pqcp_runtime_internal_write_u32(
		output + 52U, CONTROL_HEADER_BYTES);
	if (message->payload_length != 0U) {
		memcpy(output + CONTROL_HEADER_BYTES,
		       message->payload,
		       message->payload_length);
	}
	ret = control_digest(
		output, output + CONTROL_HEADER_BYTES,
		message->payload_length, digest);
	if (ret != 0) {
		pqcp_runtime_secure_zero(output, required);
		return ret;
	}
	memcpy(output + CONTROL_HEADER_BYTES +
		       message->payload_length,
	       digest, sizeof(digest));
	*output_length = required;
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return 0;
}

int pqcp_channel_control_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_channel_control_message *message)
{
	uint8_t digest[CONTROL_DIGEST_BYTES];
	uint32_t header_bytes;
	uint32_t payload_length;
	int ret;

	if (input == NULL ||
	    input_length <
		    CONTROL_HEADER_BYTES +
			    CONTROL_DIGEST_BYTES ||
	    message == NULL) {
		return -EINVAL;
	}
	header_bytes =
		pqcp_runtime_internal_read_u32(input + 52U);
	payload_length =
		pqcp_runtime_internal_read_u32(input + 48U);
	if (header_bytes != CONTROL_HEADER_BYTES ||
	    payload_length >
		    PQCP_CHANNEL_CONTROL_MAX_BYTES ||
	    input_length != CONTROL_HEADER_BYTES +
				    payload_length +
				    CONTROL_DIGEST_BYTES) {
		return -EBADMSG;
	}
	ret = control_digest(
		input, input + CONTROL_HEADER_BYTES,
		payload_length, digest);
	if (ret != 0) {
		return ret;
	}
	if (memcmp(
		    digest,
		    input + CONTROL_HEADER_BYTES +
			    payload_length,
		    sizeof(digest)) != 0) {
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return -EBADMSG;
	}
	memset(message, 0, sizeof(*message));
	message->schema_version =
		pqcp_runtime_internal_read_u32(input);
	message->kind =
		(enum pqcp_channel_control_kind)
			pqcp_runtime_internal_read_u32(input + 4U);
	message->flags =
		pqcp_runtime_internal_read_u32(input + 8U);
	message->stream_id =
		pqcp_runtime_internal_read_u32(input + 12U);
	message->message_id =
		pqcp_runtime_internal_read_u64(input + 16U);
	message->timestamp_ms =
		pqcp_runtime_internal_read_u64(input + 24U);
	message->epoch =
		pqcp_runtime_internal_read_u64(input + 32U);
	message->value =
		pqcp_runtime_internal_read_u32(input + 40U);
	message->error =
		pqcp_runtime_internal_read_u32(input + 44U);
	message->payload_length = payload_length;
	if (payload_length != 0U) {
		memcpy(message->payload,
		       input + CONTROL_HEADER_BYTES,
		       payload_length);
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	ret = control_validate(message);
	return ret == 0 ? 0 : -EBADMSG;
}
