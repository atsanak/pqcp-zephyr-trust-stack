/*
 * SPDX-License-Identifier: MIT
 *
 * Bounded fragmentation for application messages larger than one record.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel.h>

#include "runtime_internal.h"

#define PQCP_CHANNEL_FRAGMENT_HEADER_BYTES 20U
#define PQCP_CHANNEL_FRAGMENT_FLAG_FIRST (1U << 0)
#define PQCP_CHANNEL_FRAGMENT_FLAG_LAST (1U << 1)

static int encode_fragment_header(
	uint8_t output[PQCP_CHANNEL_FRAGMENT_HEADER_BYTES],
	uint32_t message_id,
	uint32_t total_length,
	uint32_t offset,
	uint32_t fragment_length,
	uint32_t flags)
{
	if (message_id == 0U || total_length == 0U ||
	    fragment_length == 0U ||
	    offset > total_length ||
	    fragment_length > total_length - offset ||
	    (flags & ~(PQCP_CHANNEL_FRAGMENT_FLAG_FIRST |
		       PQCP_CHANNEL_FRAGMENT_FLAG_LAST)) != 0U) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u32(output, message_id);
	pqcp_runtime_internal_write_u32(
		output + 4U, total_length);
	pqcp_runtime_internal_write_u32(
		output + 8U, offset);
	pqcp_runtime_internal_write_u32(
		output + 12U, fragment_length);
	pqcp_runtime_internal_write_u32(
		output + 16U, flags);
	return 0;
}

static int decode_fragment_header(
	const uint8_t input[PQCP_CHANNEL_FRAGMENT_HEADER_BYTES],
	uint32_t *message_id,
	uint32_t *total_length,
	uint32_t *offset,
	uint32_t *fragment_length,
	uint32_t *flags)
{
	*message_id = pqcp_runtime_internal_read_u32(input);
	*total_length =
		pqcp_runtime_internal_read_u32(input + 4U);
	*offset = pqcp_runtime_internal_read_u32(input + 8U);
	*fragment_length =
		pqcp_runtime_internal_read_u32(input + 12U);
	*flags = pqcp_runtime_internal_read_u32(input + 16U);
	if (*message_id == 0U || *total_length == 0U ||
	    *fragment_length == 0U ||
	    *offset > *total_length ||
	    *fragment_length > *total_length - *offset ||
	    (*flags & ~(PQCP_CHANNEL_FRAGMENT_FLAG_FIRST |
			PQCP_CHANNEL_FRAGMENT_FLAG_LAST)) != 0U) {
		return -EBADMSG;
	}
	if ((*offset == 0U) !=
	    ((*flags & PQCP_CHANNEL_FRAGMENT_FLAG_FIRST) != 0U) ||
	    (*offset + *fragment_length == *total_length) !=
	    ((*flags & PQCP_CHANNEL_FRAGMENT_FLAG_LAST) != 0U)) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_channel_send_message(
	struct pqcp_channel *channel,
	const uint8_t *message,
	size_t message_length,
	uint32_t message_id)
{
	const size_t maximum_fragment =
		channel != NULL &&
		channel->config.max_payload_bytes >
			PQCP_CHANNEL_FRAGMENT_HEADER_BYTES ?
		channel->config.max_payload_bytes -
			PQCP_CHANNEL_FRAGMENT_HEADER_BYTES : 0U;
	size_t offset = 0U;

	if (channel == NULL || !channel->established ||
	    message == NULL || message_length == 0U ||
	    message_length > UINT32_MAX || message_id == 0U ||
	    maximum_fragment == 0U) {
		return -EINVAL;
	}
	while (offset < message_length) {
		size_t fragment_length =
			message_length - offset;
		uint32_t flags = 0U;
		int ret;

		if (fragment_length > maximum_fragment) {
			fragment_length = maximum_fragment;
		}
		if (offset == 0U) {
			flags |= PQCP_CHANNEL_FRAGMENT_FLAG_FIRST;
		}
		if (offset + fragment_length == message_length) {
			flags |= PQCP_CHANNEL_FRAGMENT_FLAG_LAST;
		}
		ret = encode_fragment_header(
			channel->work_buffer, message_id,
			(uint32_t)message_length, (uint32_t)offset,
			(uint32_t)fragment_length, flags);
		if (ret != 0) {
			return ret;
		}
		memcpy(channel->work_buffer +
			       PQCP_CHANNEL_FRAGMENT_HEADER_BYTES,
		       message + offset, fragment_length);
		ret = pqcp_channel_send(
			channel, channel->work_buffer,
			PQCP_CHANNEL_FRAGMENT_HEADER_BYTES +
				fragment_length);
		pqcp_runtime_secure_zero(
			channel->work_buffer,
			PQCP_CHANNEL_FRAGMENT_HEADER_BYTES +
				fragment_length);
		if (ret != 0) {
			return ret;
		}
		offset += fragment_length;
	}
	return 0;
}

int pqcp_channel_receive_message(
	struct pqcp_channel *channel,
	uint8_t *message,
	size_t message_capacity,
	size_t *message_length,
	uint32_t *message_id)
{
	uint32_t expected_message_id = 0U;
	uint32_t expected_total = 0U;
	uint32_t expected_offset = 0U;

	if (channel == NULL || !channel->established ||
	    message == NULL || message_capacity == 0U ||
	    message_length == NULL || message_id == NULL) {
		return -EINVAL;
	}
	for (;;) {
		size_t record_length = 0U;
		uint32_t current_id;
		uint32_t total;
		uint32_t offset;
		uint32_t fragment_length;
		uint32_t flags;
		int ret = pqcp_channel_receive(
			channel, channel->work_buffer,
			sizeof(channel->work_buffer),
			&record_length);

		if (ret != 0) {
			return ret;
		}
		if (record_length <
		    PQCP_CHANNEL_FRAGMENT_HEADER_BYTES) {
			return -EBADMSG;
		}
		ret = decode_fragment_header(
			channel->work_buffer, &current_id,
			&total, &offset, &fragment_length, &flags);
		if (ret != 0 ||
		    record_length !=
			    PQCP_CHANNEL_FRAGMENT_HEADER_BYTES +
				    fragment_length ||
		    total > message_capacity) {
			pqcp_runtime_secure_zero(
				channel->work_buffer, record_length);
			return ret != 0 ? ret : -ENOSPC;
		}
		if (expected_message_id == 0U) {
			if ((flags &
			     PQCP_CHANNEL_FRAGMENT_FLAG_FIRST) == 0U) {
				return -EBADMSG;
			}
			expected_message_id = current_id;
			expected_total = total;
		}
		if (current_id != expected_message_id ||
		    total != expected_total ||
		    offset != expected_offset) {
			pqcp_runtime_secure_zero(
				channel->work_buffer, record_length);
			return -EPROTO;
		}
		memcpy(message + offset,
		       channel->work_buffer +
			       PQCP_CHANNEL_FRAGMENT_HEADER_BYTES,
		       fragment_length);
		pqcp_runtime_secure_zero(
			channel->work_buffer, record_length);
		expected_offset += fragment_length;
		if ((flags &
		     PQCP_CHANNEL_FRAGMENT_FLAG_LAST) != 0U) {
			if (expected_offset != expected_total) {
				pqcp_runtime_secure_zero(
					message, expected_offset);
				return -EBADMSG;
			}
			*message_id = expected_message_id;
			*message_length = expected_total;
			return 0;
		}
	}
}
