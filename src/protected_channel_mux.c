/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Stream multiplexing carried inside protected-channel application records.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel_operations.h>

#include "runtime_internal.h"

static bool stream_frame_type_valid(
	enum pqcp_channel_stream_frame_type type)
{
	return type >= PQCP_CHANNEL_STREAM_FRAME_OPEN &&
	       type <= PQCP_CHANNEL_STREAM_FRAME_PONG;
}

static bool stream_state_valid(
	enum pqcp_channel_stream_state state)
{
	return state >= PQCP_CHANNEL_STREAM_IDLE &&
	       state <= PQCP_CHANNEL_STREAM_RESET;
}

static struct pqcp_channel_stream *stream_find(
	struct pqcp_channel_multiplexer *multiplexer,
	uint32_t stream_id)
{
	for (size_t index = 0U;
	     index < multiplexer->capacity; ++index) {
		struct pqcp_channel_stream *stream =
			&multiplexer->streams[index];

		if (stream->occupied &&
		    stream->stream_id == stream_id) {
			return stream;
		}
	}
	return NULL;
}

static struct pqcp_channel_stream *stream_allocate(
	struct pqcp_channel_multiplexer *multiplexer)
{
	for (size_t index = 0U;
	     index < multiplexer->capacity; ++index) {
		if (!multiplexer->streams[index].occupied) {
			return &multiplexer->streams[index];
		}
	}
	return NULL;
}

static bool locally_initiated_id(
	const struct pqcp_channel_multiplexer *multiplexer,
	uint32_t stream_id)
{
	const bool client =
		multiplexer->channel->config.role ==
		PQCP_CHANNEL_ROLE_CLIENT;

	return client ? (stream_id & 1U) != 0U :
			(stream_id & 1U) == 0U;
}

static bool remote_stream_id_valid(
	const struct pqcp_channel_multiplexer *multiplexer,
	uint32_t stream_id)
{
	return stream_id != 0U &&
	       !locally_initiated_id(multiplexer, stream_id);
}

static int stream_transition_receive(
	struct pqcp_channel_stream *stream,
	enum pqcp_channel_stream_frame_type type,
	uint32_t error)
{
	switch (type) {
	case PQCP_CHANNEL_STREAM_FRAME_OPEN:
		if (stream->state != PQCP_CHANNEL_STREAM_IDLE) {
			return -EALREADY;
		}
		stream->state = PQCP_CHANNEL_STREAM_OPEN;
		return 0;
	case PQCP_CHANNEL_STREAM_FRAME_DATA:
	case PQCP_CHANNEL_STREAM_FRAME_WINDOW_UPDATE:
	case PQCP_CHANNEL_STREAM_FRAME_PING:
	case PQCP_CHANNEL_STREAM_FRAME_PONG:
		return stream->state == PQCP_CHANNEL_STREAM_OPEN ||
			       stream->state ==
				       PQCP_CHANNEL_STREAM_HALF_CLOSED_LOCAL ?
			0 : -ESHUTDOWN;
	case PQCP_CHANNEL_STREAM_FRAME_CLOSE:
		if (stream->state == PQCP_CHANNEL_STREAM_OPEN) {
			stream->state =
				PQCP_CHANNEL_STREAM_HALF_CLOSED_REMOTE;
			return 0;
		}
		if (stream->state ==
		    PQCP_CHANNEL_STREAM_HALF_CLOSED_LOCAL) {
			stream->state =
				PQCP_CHANNEL_STREAM_CLOSED;
			return 0;
		}
		return -EALREADY;
	case PQCP_CHANNEL_STREAM_FRAME_RESET:
		stream->state = PQCP_CHANNEL_STREAM_RESET;
		stream->error =
			(enum pqcp_channel_stream_error)error;
		return 0;
	default:
		return -EPROTO;
	}
}

static int stream_transition_send(
	struct pqcp_channel_stream *stream,
	enum pqcp_channel_stream_frame_type type,
	enum pqcp_channel_stream_error error)
{
	switch (type) {
	case PQCP_CHANNEL_STREAM_FRAME_OPEN:
		if (stream->state != PQCP_CHANNEL_STREAM_IDLE) {
			return -EALREADY;
		}
		stream->state = PQCP_CHANNEL_STREAM_OPEN;
		return 0;
	case PQCP_CHANNEL_STREAM_FRAME_DATA:
	case PQCP_CHANNEL_STREAM_FRAME_WINDOW_UPDATE:
	case PQCP_CHANNEL_STREAM_FRAME_PING:
	case PQCP_CHANNEL_STREAM_FRAME_PONG:
		return stream->state == PQCP_CHANNEL_STREAM_OPEN ||
			       stream->state ==
				       PQCP_CHANNEL_STREAM_HALF_CLOSED_REMOTE ?
			0 : -ESHUTDOWN;
	case PQCP_CHANNEL_STREAM_FRAME_CLOSE:
		if (stream->state == PQCP_CHANNEL_STREAM_OPEN) {
			stream->state =
				PQCP_CHANNEL_STREAM_HALF_CLOSED_LOCAL;
			return 0;
		}
		if (stream->state ==
		    PQCP_CHANNEL_STREAM_HALF_CLOSED_REMOTE) {
			stream->state =
				PQCP_CHANNEL_STREAM_CLOSED;
			return 0;
		}
		return -EALREADY;
	case PQCP_CHANNEL_STREAM_FRAME_RESET:
		stream->state = PQCP_CHANNEL_STREAM_RESET;
		stream->error = error;
		return 0;
	default:
		return -EPROTO;
	}
}

int pqcp_channel_stream_header_encode(
	const struct pqcp_channel_stream_header *header,
	uint8_t output[PQCP_CHANNEL_STREAM_HEADER_BYTES])
{
	if (header == NULL || output == NULL ||
	    header->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    !stream_frame_type_valid(header->type) ||
	    header->stream_id == 0U ||
	    header->payload_length >
		    PQCP_CHANNEL_MAX_PAYLOAD_BYTES) {
		return -EINVAL;
	}
	memset(output, 0, PQCP_CHANNEL_STREAM_HEADER_BYTES);
	pqcp_runtime_internal_write_u32(
		output, header->schema_version);
	pqcp_runtime_internal_write_u32(
		output + 4U, (uint32_t)header->type);
	pqcp_runtime_internal_write_u32(
		output + 8U, header->flags);
	pqcp_runtime_internal_write_u32(
		output + 12U, header->stream_id);
	pqcp_runtime_internal_write_u64(
		output + 16U, header->sequence);
	pqcp_runtime_internal_write_u32(
		output + 24U, header->payload_length);
	pqcp_runtime_internal_write_u32(
		output + 28U,
		header->type ==
			PQCP_CHANNEL_STREAM_FRAME_WINDOW_UPDATE ?
			header->credit : header->error);
	return 0;
}

int pqcp_channel_stream_header_decode(
	const uint8_t input[PQCP_CHANNEL_STREAM_HEADER_BYTES],
	struct pqcp_channel_stream_header *header)
{
	uint32_t tail;

	if (input == NULL || header == NULL) {
		return -EINVAL;
	}
	memset(header, 0, sizeof(*header));
	header->schema_version =
		pqcp_runtime_internal_read_u32(input);
	header->type =
		(enum pqcp_channel_stream_frame_type)
			pqcp_runtime_internal_read_u32(input + 4U);
	header->flags =
		pqcp_runtime_internal_read_u32(input + 8U);
	header->stream_id =
		pqcp_runtime_internal_read_u32(input + 12U);
	header->sequence =
		pqcp_runtime_internal_read_u64(input + 16U);
	header->payload_length =
		pqcp_runtime_internal_read_u32(input + 24U);
	tail = pqcp_runtime_internal_read_u32(input + 28U);
	if (header->type ==
	    PQCP_CHANNEL_STREAM_FRAME_WINDOW_UPDATE) {
		header->credit = tail;
	} else {
		header->error = tail;
	}
	if (header->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    !stream_frame_type_valid(header->type) ||
	    header->stream_id == 0U ||
	    header->payload_length >
		    PQCP_CHANNEL_MAX_PAYLOAD_BYTES) {
		return -EBADMSG;
	}
	return 0;
}

static int send_stream_frame(
	struct pqcp_channel_multiplexer *multiplexer,
	struct pqcp_channel_stream *stream,
	enum pqcp_channel_stream_frame_type type,
	const uint8_t *payload,
	size_t payload_length,
	uint32_t flags,
	uint32_t value,
	uint64_t now_ms)
{
	uint8_t frame[
		PQCP_CHANNEL_STREAM_HEADER_BYTES +
		PQCP_CHANNEL_MAX_PAYLOAD_BYTES];
	struct pqcp_channel_stream_header header = {
		.schema_version =
			PQCP_CHANNEL_OPERATION_SCHEMA_VERSION,
		.type = type,
		.flags = flags,
		.stream_id = stream->stream_id,
		.sequence = stream->next_send_sequence,
		.payload_length = (uint32_t)payload_length,
	};
	int ret;

	if (payload_length > PQCP_CHANNEL_MAX_PAYLOAD_BYTES ||
	    (payload == NULL && payload_length != 0U)) {
		return -EMSGSIZE;
	}
	if (type == PQCP_CHANNEL_STREAM_FRAME_WINDOW_UPDATE) {
		header.credit = value;
	} else if (type == PQCP_CHANNEL_STREAM_FRAME_RESET) {
		header.error = value;
	}
	ret = stream_transition_send(
		stream, type,
		(enum pqcp_channel_stream_error)value);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_stream_header_encode(
		&header, frame);
	if (ret != 0) {
		return ret;
	}
	if (payload_length != 0U) {
		memcpy(frame + PQCP_CHANNEL_STREAM_HEADER_BYTES,
		       payload, payload_length);
	}
	ret = pqcp_channel_send(
		multiplexer->channel, frame,
		PQCP_CHANNEL_STREAM_HEADER_BYTES +
			payload_length);
	pqcp_runtime_secure_zero(frame, sizeof(frame));
	if (ret != 0) {
		return ret;
	}
	stream->next_send_sequence++;
	stream->last_activity_ms = now_ms;
	if (type == PQCP_CHANNEL_STREAM_FRAME_DATA) {
		stream->bytes_sent += payload_length;
		multiplexer->connection_remote_window -=
			(uint32_t)payload_length;
		stream->remote_window -=
			(uint32_t)payload_length;
	}
	multiplexer->frames_sent++;
	return 0;
}

int pqcp_channel_multiplexer_init(
	struct pqcp_channel_multiplexer *multiplexer,
	struct pqcp_channel *channel,
	struct pqcp_channel_stream *streams,
	size_t capacity,
	uint32_t initial_connection_window,
	uint32_t initial_stream_window)
{
	if (multiplexer == NULL || channel == NULL ||
	    channel->state != PQCP_CHANNEL_STATE_ESTABLISHED ||
	    streams == NULL || capacity == 0U ||
	    initial_connection_window == 0U ||
	    initial_stream_window == 0U) {
		return -EINVAL;
	}
	memset(streams, 0, capacity * sizeof(*streams));
	memset(multiplexer, 0, sizeof(*multiplexer));
	multiplexer->channel = channel;
	multiplexer->streams = streams;
	multiplexer->capacity = capacity;
	multiplexer->connection_local_window =
		initial_connection_window;
	multiplexer->connection_remote_window =
		initial_connection_window;
	multiplexer->initial_stream_window =
		initial_stream_window;
	multiplexer->next_local_stream_id =
		channel->config.role ==
			PQCP_CHANNEL_ROLE_CLIENT ?
			1U : 2U;
	k_mutex_init(&multiplexer->lock);
	multiplexer->initialized = true;
	return 0;
}

int pqcp_channel_stream_open(
	struct pqcp_channel_multiplexer *multiplexer,
	uint32_t priority,
	uint64_t now_ms,
	struct pqcp_channel_stream **stream)
{
	struct pqcp_channel_stream *allocated;
	int ret;

	if (multiplexer == NULL || !multiplexer->initialized ||
	    priority > 255U || now_ms == 0U || stream == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&multiplexer->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	allocated = stream_allocate(multiplexer);
	if (allocated == NULL ||
	    multiplexer->next_local_stream_id >
		    UINT32_MAX - 2U) {
		(void)k_mutex_unlock(&multiplexer->lock);
		return -ENOSPC;
	}
	memset(allocated, 0, sizeof(*allocated));
	allocated->stream_id =
		multiplexer->next_local_stream_id;
	multiplexer->next_local_stream_id += 2U;
	allocated->state = PQCP_CHANNEL_STREAM_IDLE;
	allocated->priority = priority;
	allocated->local_window =
		multiplexer->initial_stream_window;
	allocated->remote_window =
		multiplexer->initial_stream_window;
	allocated->opened_at_ms = now_ms;
	allocated->last_activity_ms = now_ms;
	allocated->locally_initiated = true;
	allocated->occupied = true;
	ret = send_stream_frame(
		multiplexer, allocated,
		PQCP_CHANNEL_STREAM_FRAME_OPEN,
		NULL, 0U, priority, 0U, now_ms);
	if (ret != 0) {
		memset(allocated, 0, sizeof(*allocated));
		(void)k_mutex_unlock(&multiplexer->lock);
		return ret;
	}
	multiplexer->count++;
	*stream = allocated;
	(void)k_mutex_unlock(&multiplexer->lock);
	return 0;
}

int pqcp_channel_stream_send(
	struct pqcp_channel_multiplexer *multiplexer,
	uint32_t stream_id,
	const uint8_t *payload,
	size_t payload_length,
	uint32_t flags,
	uint64_t now_ms)
{
	struct pqcp_channel_stream *stream;
	int ret;

	if (multiplexer == NULL || !multiplexer->initialized ||
	    stream_id == 0U || payload == NULL ||
	    payload_length == 0U ||
	    payload_length >
		    PQCP_CHANNEL_MAX_PAYLOAD_BYTES ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&multiplexer->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	stream = stream_find(multiplexer, stream_id);
	if (stream == NULL) {
		(void)k_mutex_unlock(&multiplexer->lock);
		return -ENOENT;
	}
	if (payload_length > stream->remote_window ||
	    payload_length >
		    multiplexer->connection_remote_window) {
		(void)k_mutex_unlock(&multiplexer->lock);
		return -EAGAIN;
	}
	ret = send_stream_frame(
		multiplexer, stream,
		PQCP_CHANNEL_STREAM_FRAME_DATA,
		payload, payload_length, flags, 0U, now_ms);
	(void)k_mutex_unlock(&multiplexer->lock);
	return ret;
}

static int receive_new_stream(
	struct pqcp_channel_multiplexer *multiplexer,
	const struct pqcp_channel_stream_header *header,
	uint64_t now_ms,
	struct pqcp_channel_stream **stream)
{
	struct pqcp_channel_stream *allocated;

	if (header->type != PQCP_CHANNEL_STREAM_FRAME_OPEN ||
	    !remote_stream_id_valid(
		    multiplexer, header->stream_id) ||
	    header->sequence != 0U) {
		return -EPROTO;
	}
	allocated = stream_allocate(multiplexer);
	if (allocated == NULL) {
		return -ENOSPC;
	}
	memset(allocated, 0, sizeof(*allocated));
	allocated->stream_id = header->stream_id;
	allocated->state = PQCP_CHANNEL_STREAM_IDLE;
	allocated->priority = header->flags & 0xffU;
	allocated->local_window =
		multiplexer->initial_stream_window;
	allocated->remote_window =
		multiplexer->initial_stream_window;
	allocated->opened_at_ms = now_ms;
	allocated->last_activity_ms = now_ms;
	allocated->locally_initiated = false;
	allocated->occupied = true;
	multiplexer->count++;
	*stream = allocated;
	return 0;
}

int pqcp_channel_stream_receive(
	struct pqcp_channel_multiplexer *multiplexer,
	uint8_t *payload,
	size_t payload_capacity,
	size_t *payload_length,
	struct pqcp_channel_stream_header *header,
	uint64_t now_ms)
{
	uint8_t frame[
		PQCP_CHANNEL_STREAM_HEADER_BYTES +
		PQCP_CHANNEL_MAX_PAYLOAD_BYTES];
	struct pqcp_channel_stream *stream;
	size_t frame_length = 0U;
	int ret;

	if (multiplexer == NULL || !multiplexer->initialized ||
	    payload == NULL || payload_length == NULL ||
	    header == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	*payload_length = 0U;
	ret = pqcp_channel_receive(
		multiplexer->channel, frame, sizeof(frame),
		&frame_length);
	if (ret != 0) {
		return ret;
	}
	if (frame_length < PQCP_CHANNEL_STREAM_HEADER_BYTES) {
		pqcp_runtime_secure_zero(frame, sizeof(frame));
		return -EBADMSG;
	}
	ret = pqcp_channel_stream_header_decode(frame, header);
	if (ret != 0 ||
	    frame_length !=
		    PQCP_CHANNEL_STREAM_HEADER_BYTES +
			    header->payload_length ||
	    header->payload_length > payload_capacity) {
		pqcp_runtime_secure_zero(frame, sizeof(frame));
		return ret != 0 ? ret : -EMSGSIZE;
	}
	ret = k_mutex_lock(&multiplexer->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(frame, sizeof(frame));
		return ret;
	}
	stream = stream_find(
		multiplexer, header->stream_id);
	if (stream == NULL) {
		ret = receive_new_stream(
			multiplexer, header, now_ms, &stream);
		if (ret != 0) {
			multiplexer->rejected_frames++;
			(void)k_mutex_unlock(
				&multiplexer->lock);
			pqcp_runtime_secure_zero(
				frame, sizeof(frame));
			return ret;
		}
	}
	if (header->sequence !=
	    stream->next_receive_sequence) {
		multiplexer->rejected_frames++;
		(void)k_mutex_unlock(&multiplexer->lock);
		pqcp_runtime_secure_zero(frame, sizeof(frame));
		return -EALREADY;
	}
	if (header->type ==
	    PQCP_CHANNEL_STREAM_FRAME_DATA) {
		if (header->payload_length >
			    stream->local_window ||
		    header->payload_length >
			    multiplexer->
				    connection_local_window) {
			stream->state =
				PQCP_CHANNEL_STREAM_RESET;
			stream->error =
				PQCP_CHANNEL_STREAM_ERROR_FLOW_CONTROL;
			multiplexer->rejected_frames++;
			(void)k_mutex_unlock(
				&multiplexer->lock);
			pqcp_runtime_secure_zero(
				frame, sizeof(frame));
			return -ENOBUFS;
		}
		stream->local_window -=
			header->payload_length;
		multiplexer->connection_local_window -=
			header->payload_length;
		stream->bytes_received +=
			header->payload_length;
	}
	ret = stream_transition_receive(
		stream, header->type, header->error);
	if (ret == 0) {
		stream->next_receive_sequence++;
		stream->last_activity_ms = now_ms;
		multiplexer->frames_received++;
		if (header->payload_length != 0U) {
			memcpy(
				payload,
				frame +
					PQCP_CHANNEL_STREAM_HEADER_BYTES,
				header->payload_length);
			*payload_length =
				header->payload_length;
		}
	} else {
		multiplexer->rejected_frames++;
	}
	(void)k_mutex_unlock(&multiplexer->lock);
	pqcp_runtime_secure_zero(frame, sizeof(frame));
	return ret;
}

int pqcp_channel_stream_close(
	struct pqcp_channel_multiplexer *multiplexer,
	uint32_t stream_id,
	enum pqcp_channel_stream_error error,
	uint64_t now_ms)
{
	struct pqcp_channel_stream *stream;
	enum pqcp_channel_stream_frame_type type;
	int ret;

	if (multiplexer == NULL || !multiplexer->initialized ||
	    stream_id == 0U || error >
		    PQCP_CHANNEL_STREAM_ERROR_INTERNAL ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&multiplexer->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	stream = stream_find(multiplexer, stream_id);
	if (stream == NULL) {
		(void)k_mutex_unlock(&multiplexer->lock);
		return -ENOENT;
	}
	type = error == PQCP_CHANNEL_STREAM_ERROR_NONE ?
		PQCP_CHANNEL_STREAM_FRAME_CLOSE :
		PQCP_CHANNEL_STREAM_FRAME_RESET;
	ret = send_stream_frame(
		multiplexer, stream, type, NULL, 0U, 0U,
		(uint32_t)error, now_ms);
	(void)k_mutex_unlock(&multiplexer->lock);
	return ret;
}

int pqcp_channel_multiplexer_audit(
	struct pqcp_channel_multiplexer *multiplexer)
{
	size_t occupied = 0U;
	int ret;

	if (multiplexer == NULL ||
	    !multiplexer->initialized ||
	    multiplexer->channel == NULL ||
	    multiplexer->streams == NULL ||
	    multiplexer->capacity == 0U ||
	    multiplexer->initial_stream_window == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&multiplexer->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t left = 0U;
	     left < multiplexer->capacity; ++left) {
		const struct pqcp_channel_stream *stream =
			&multiplexer->streams[left];

		if (!stream->occupied) {
			continue;
		}
		if (stream->stream_id == 0U ||
		    !stream_state_valid(stream->state) ||
		    (stream->next_receive_sequence == 0U &&
		     stream->state !=
			     PQCP_CHANNEL_STREAM_IDLE &&
		     stream->state !=
			     PQCP_CHANNEL_STREAM_OPEN)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t right = left + 1U;
		     right < multiplexer->capacity; ++right) {
			if (multiplexer->streams[right].occupied &&
			    multiplexer->streams[right].stream_id ==
				    stream->stream_id) {
				ret = -EBADMSG;
				break;
			}
		}
		if (ret != 0) {
			break;
		}
		occupied++;
	}
	if (ret == 0 && occupied != multiplexer->count) {
		ret = -EBADMSG;
	}
	(void)k_mutex_unlock(&multiplexer->lock);
	return ret;
}
