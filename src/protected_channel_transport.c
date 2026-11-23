/*
 * SPDX-License-Identifier: MIT
 *
 * Framed transport and failure handling.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel.h>
#include <pqcp_zephyr/protected_channel_operations.h>

#include "protected_channel_internal.h"
#include "runtime_internal.h"

static int receive_exact(
	struct pqcp_channel *channel,
	uint8_t *buffer,
	size_t length, int64_t deadline)
{
	size_t offset = 0U;

	while (offset < length) {
		size_t received = 0U;
		int64_t remaining = deadline - k_uptime_get();

		if (remaining <= 0) {
			return -ETIMEDOUT;
		}
		int ret = channel->transport.receive(
			channel->transport.context,
			buffer + offset, length - offset,
			&received, (uint32_t)remaining);

		if (ret != 0) {
			return ret;
		}
		if (k_uptime_get() >= deadline) {
			return -ETIMEDOUT;
		}
		if (received == 0U ||
		    received > length - offset) {
			return -ECONNRESET;
		}
		offset += received;
	}
	return 0;
}

int pqcp_channel_internal_send_frame(
	struct pqcp_channel *channel,
	enum pqcp_channel_frame_type type,
	uint32_t flags,
	const uint8_t *payload,
	size_t payload_length,
	bool update_transcript)
{
	struct pqcp_channel_frame_header header;
	size_t frame_length = 0U;
	int ret;

	if (channel == NULL ||
	    channel->transport.send == NULL ||
	    payload_length > channel->config.max_payload_bytes) {
		return -EINVAL;
	}
	if (channel->send_sequence == UINT64_MAX) {
		return -EOVERFLOW;
	}
	header = (struct pqcp_channel_frame_header) {
		.magic = PQCP_CHANNEL_MAGIC,
		.schema_version = PQCP_CHANNEL_SCHEMA_VERSION,
		.type = type,
		.flags = flags,
		.session_id = channel->config.session_id,
		.sequence = channel->send_sequence,
		.payload_length = payload_length,
		.reserved = 0U,
	};
	ret = pqcp_channel_frame_encode(
		&header, payload, payload_length,
		channel->tx_frame, sizeof(channel->tx_frame),
		&frame_length);
	if (ret != 0) {
		return ret;
	}
	ret = channel->transport.send(
		channel->transport.context,
		channel->tx_frame, frame_length,
		channel->config.timeout_ms);
	if (ret != 0) {
		return ret;
	}
	if (update_transcript) {
		ret = pqcp_channel_transcript_update(
			&channel->transcript,
			channel->tx_frame, frame_length);
		if (ret != 0) {
			return ret;
		}
	}
	channel->send_sequence++;
	channel->frames_sent++;
	return 0;
}

int pqcp_channel_internal_receive_frame(
	struct pqcp_channel *channel,
	enum pqcp_channel_frame_type expected_type,
	struct pqcp_channel_frame_header *header,
	const uint8_t **payload,
	size_t *payload_length,
	bool update_transcript)
{
	const uint8_t *decoded_payload = NULL;
	size_t decoded_length = 0U;
	size_t frame_length;
	int64_t deadline;
	int ret;

	if (channel == NULL || header == NULL ||
	    payload == NULL || payload_length == NULL ||
	    channel->transport.receive == NULL) {
		return -EINVAL;
	}
	if (channel->receive_sequence == UINT64_MAX) {
		return -EOVERFLOW;
	}
	deadline = k_uptime_get() + channel->config.timeout_ms;
	ret = receive_exact(
		channel, channel->rx_frame,
		PQCP_CHANNEL_FRAME_HEADER_BYTES, deadline);
	if (ret != 0) {
		return ret;
	}
	header->magic = pqcp_runtime_internal_read_u32(
		channel->rx_frame);
	header->schema_version =
		pqcp_runtime_internal_read_u16(
			channel->rx_frame + 4U);
	header->type = pqcp_runtime_internal_read_u16(
		channel->rx_frame + 6U);
	header->flags = pqcp_runtime_internal_read_u32(
		channel->rx_frame + 8U);
	header->session_id = pqcp_runtime_internal_read_u64(
		channel->rx_frame + 12U);
	header->sequence = pqcp_runtime_internal_read_u64(
		channel->rx_frame + 20U);
	header->payload_length =
		pqcp_runtime_internal_read_u32(
			channel->rx_frame + 28U);
	header->reserved = pqcp_runtime_internal_read_u32(
		channel->rx_frame + 32U);
	if (header->payload_length >
		    channel->config.max_payload_bytes ||
	    header->payload_length >
		    PQCP_CHANNEL_MAX_FRAME_BYTES -
			    PQCP_CHANNEL_FRAME_HEADER_BYTES) {
		return -EMSGSIZE;
	}
	frame_length = PQCP_CHANNEL_FRAME_HEADER_BYTES +
		       header->payload_length;
	if (header->payload_length != 0U) {
		ret = receive_exact(
			channel,
			channel->rx_frame +
				PQCP_CHANNEL_FRAME_HEADER_BYTES,
			header->payload_length, deadline);
		if (ret != 0) {
			return ret;
		}
	}
	ret = pqcp_channel_frame_decode(
		channel->rx_frame, frame_length, header,
		&decoded_payload, &decoded_length);
	if (ret != 0) {
		return ret;
	}
	if (header->session_id != channel->config.session_id) {
		return -EPROTO;
	}
	if (header->sequence != channel->receive_sequence) {
		return header->sequence < channel->receive_sequence ?
			-EALREADY : -ERANGE;
	}
	if (header->type == PQCP_CHANNEL_FRAME_ALERT) {
		if (decoded_length >= 4U) {
			channel->last_alert =
				pqcp_runtime_internal_read_u32(
					decoded_payload);
		}
		return -ECONNABORTED;
	}
	if (header->type != expected_type) {
		return -EPROTO;
	}
	if (update_transcript) {
		ret = pqcp_channel_transcript_update(
			&channel->transcript,
			channel->rx_frame, frame_length);
		if (ret != 0) {
			return ret;
		}
	}
	channel->receive_sequence++;
	channel->frames_received++;
	*payload = decoded_payload;
	*payload_length = decoded_length;
	return 0;
}

static int destroy_handle(struct pqcp_runtime_key_store *store,
	struct pqcp_runtime_key_handle *handle)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle)) {
		return 0;
	}
	ret = pqcp_runtime_key_store_destroy(store, handle);
	if (ret == 0 || ret == -ENOENT) {
		memset(handle, 0, sizeof(*handle));
		return 0;
	}
	return ret;
}

static void erase_material_keep_handles(struct pqcp_channel_keys *keys)
{
	struct pqcp_runtime_key_handle client = keys->client_write_key;
	struct pqcp_runtime_key_handle server = keys->server_write_key;

	pqcp_runtime_secure_zero(keys, sizeof(*keys));
	keys->client_write_key = client;
	keys->server_write_key = server;
}

int pqcp_channel_internal_discard_keys(struct pqcp_channel *channel)
{
	struct pqcp_runtime_key_handle client = channel->keys.client_write_key;
	struct pqcp_runtime_key_handle server = channel->keys.server_write_key;
	int first_error = 0;
	int ret;

	channel->established = false;
	channel->application_send_blocked = true;
	/* Erase material immediately, but retain failed handles for close retries. */
	pqcp_runtime_secure_zero(&channel->keys, sizeof(channel->keys));
	if (channel->rekey_context != NULL) {
		ret = pqcp_channel_rekey_abort(channel->rekey_context);
		if (ret != 0) {
			first_error = ret;
		}
		ret = pqcp_channel_rekey_cleanup(channel->rekey_context);
		if (first_error == 0 && ret != 0) {
			first_error = ret;
		}
		erase_material_keep_handles(&channel->rekey_context->pending_keys);
		erase_material_keep_handles(&channel->rekey_context->retired_keys);
	}
	ret = destroy_handle(channel->key_store, &client);
	if (first_error == 0 && ret != 0) {
		first_error = ret;
	}
	ret = destroy_handle(channel->key_store, &server);
	if (first_error == 0 && ret != 0) {
		first_error = ret;
	}
	ret = destroy_handle(channel->key_store, &channel->ephemeral_kem_key);
	if (first_error == 0 && ret != 0) {
		first_error = ret;
	}
	channel->keys.client_write_key = client;
	channel->keys.server_write_key = server;
	pqcp_runtime_secure_zero(channel->local_nonce, sizeof(channel->local_nonce));
	pqcp_runtime_secure_zero(channel->peer_nonce, sizeof(channel->peer_nonce));
	pqcp_runtime_secure_zero(channel->work_buffer, sizeof(channel->work_buffer));
	pqcp_runtime_secure_zero(channel->tx_frame, sizeof(channel->tx_frame));
	pqcp_runtime_secure_zero(channel->rx_frame, sizeof(channel->rx_frame));
	return first_error;
}

int pqcp_channel_internal_fail(
	struct pqcp_channel *channel,
	enum pqcp_channel_alert alert,
	int error)
{
	uint8_t payload[8];

	if (channel == NULL) {
		return error != 0 ? error : -EIO;
	}
	channel->state = PQCP_CHANNEL_STATE_FAILED;
	channel->last_alert = alert;
	channel->failure_count++;
	pqcp_runtime_internal_write_u32(payload, (uint32_t)alert);
	pqcp_runtime_internal_write_u32(
		payload + 4U, (uint32_t)(-error));
	if (channel->transport.send != NULL) {
		(void)pqcp_channel_internal_send_frame(
			channel, PQCP_CHANNEL_FRAME_ALERT,
			0U, payload, sizeof(payload), false);
	}
	(void)pqcp_channel_internal_discard_keys(channel);
	return error != 0 ? error : -EIO;
}
