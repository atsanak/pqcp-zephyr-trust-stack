/*
 * SPDX-License-Identifier: MIT
 *
 * Flow-control adapter between sovereign frames and protected-channel streams.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_channel_internal.h"

struct pqcp_channel_stream *pqcp_sovereign_channel_internal_stream(
	struct pqcp_channel_multiplexer *multiplexer,
	uint32_t stream_id)
{
	if (multiplexer == NULL || !multiplexer->initialized ||
	    stream_id == 0U || multiplexer->streams == NULL) {
		return NULL;
	}
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

static int lock_adapter(
	struct pqcp_sovereign_channel_flow_adapter *adapter)
{
	if (adapter == NULL || !adapter->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&adapter->lock, K_FOREVER);
}

static void unlock_adapter(
	struct pqcp_sovereign_channel_flow_adapter *adapter)
{
	(void)k_mutex_unlock(&adapter->lock);
}

static bool stream_can_send(
	const struct pqcp_channel_stream *stream)
{
	return stream != NULL && stream->occupied &&
	       (stream->state == PQCP_CHANNEL_STREAM_OPEN ||
		stream->state ==
			PQCP_CHANNEL_STREAM_HALF_CLOSED_REMOTE);
}

static bool stream_can_receive(
	const struct pqcp_channel_stream *stream)
{
	return stream != NULL && stream->occupied &&
	       (stream->state == PQCP_CHANNEL_STREAM_OPEN ||
		stream->state ==
			PQCP_CHANNEL_STREAM_HALF_CLOSED_LOCAL);
}

int pqcp_sovereign_channel_flow_init(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	struct pqcp_channel_multiplexer *multiplexer,
	struct pqcp_channel_flow_controller *controller)
{
	if (adapter == NULL || multiplexer == NULL ||
	    !multiplexer->initialized || controller == NULL ||
	    !controller->initialized ||
	    controller->policy.maximum_frame_payload <
		    PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES ||
	    multiplexer->initial_stream_window <
		    PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES) {
		return -EINVAL;
	}
	memset(adapter, 0, sizeof(*adapter));
	adapter->multiplexer = multiplexer;
	adapter->controller = controller;
	adapter->maximum_frame_bytes =
		PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES;
	k_mutex_init(&adapter->lock);
	adapter->initialized = true;
	return 0;
}

static int reserve_controller_send(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	size_t frame_length)
{
	struct pqcp_channel_flow_controller *controller =
		adapter->controller;
	int ret;

	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (frame_length >
	    controller->remote_connection_window) {
		(void)k_mutex_unlock(&controller->lock);
		return -EAGAIN;
	}
	controller->remote_connection_window -=
		(uint32_t)frame_length;
	controller->consumed_remote += frame_length;
	(void)k_mutex_unlock(&controller->lock);
	return 0;
}

static void restore_controller_send(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	size_t frame_length)
{
	struct pqcp_channel_flow_controller *controller =
		adapter->controller;

	if (k_mutex_lock(&controller->lock, K_FOREVER) != 0) {
		return;
	}
	if (frame_length <=
	    controller->policy.maximum_connection_window -
		    controller->remote_connection_window) {
		controller->remote_connection_window +=
			(uint32_t)frame_length;
	}
	if (controller->consumed_remote >= frame_length) {
		controller->consumed_remote -= frame_length;
	}
	(void)k_mutex_unlock(&controller->lock);
}

int pqcp_sovereign_channel_flow_send(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	uint32_t stream_id,
	const uint8_t *frame,
	size_t frame_length,
	uint32_t flags,
	uint64_t now_ms)
{
	struct pqcp_channel_stream *stream;
	int ret;

	if (adapter == NULL || !adapter->initialized ||
	    stream_id == 0U || frame == NULL ||
	    frame_length <
		    PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES ||
	    frame_length > adapter->maximum_frame_bytes ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_adapter(adapter);
	if (ret != 0) {
		return ret;
	}
	stream = pqcp_sovereign_channel_internal_stream(
		adapter->multiplexer, stream_id);
	if (!stream_can_send(stream)) {
		unlock_adapter(adapter);
		return stream == NULL ? -ENOENT : -ESHUTDOWN;
	}
	if (frame_length > stream->remote_window ||
	    frame_length >
		    adapter->multiplexer->
			    connection_remote_window) {
		unlock_adapter(adapter);
		return -EAGAIN;
	}
	ret = reserve_controller_send(adapter, frame_length);
	if (ret != 0) {
		unlock_adapter(adapter);
		return ret;
	}
	ret = pqcp_channel_stream_send(
		adapter->multiplexer, stream_id,
		frame, frame_length, flags, now_ms);
	if (ret != 0) {
		restore_controller_send(adapter, frame_length);
		unlock_adapter(adapter);
		return ret;
	}
	adapter->frames_sent++;
	adapter->bytes_sent += frame_length;
	unlock_adapter(adapter);
	return 0;
}

static int replenish_mux_receive_window(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	struct pqcp_channel_stream *stream,
	uint32_t connection_credit,
	uint32_t stream_credit)
{
	struct pqcp_channel_multiplexer *multiplexer =
		adapter->multiplexer;
	int ret;

	ret = k_mutex_lock(&multiplexer->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (connection_credit >
		    UINT32_MAX -
			    multiplexer->connection_local_window ||
	    stream_credit > UINT32_MAX - stream->local_window) {
		(void)k_mutex_unlock(&multiplexer->lock);
		return -EOVERFLOW;
	}
	multiplexer->connection_local_window +=
		connection_credit;
	stream->local_window += stream_credit;
	(void)k_mutex_unlock(&multiplexer->lock);
	return 0;
}

int pqcp_sovereign_channel_flow_receive_account(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	uint32_t stream_id,
	size_t frame_length,
	struct pqcp_sovereign_channel_window *window)
{
	struct pqcp_channel_flow_controller *controller;
	struct pqcp_channel_stream *stream;
	uint32_t connection_credit = 0U;
	uint32_t stream_credit = 0U;
	int ret;

	if (adapter == NULL || !adapter->initialized ||
	    stream_id == 0U || frame_length == 0U ||
	    frame_length > adapter->maximum_frame_bytes ||
	    window == NULL) {
		return -EINVAL;
	}
	ret = lock_adapter(adapter);
	if (ret != 0) {
		return ret;
	}
	stream = pqcp_sovereign_channel_internal_stream(
		adapter->multiplexer, stream_id);
	if (!stream_can_receive(stream)) {
		unlock_adapter(adapter);
		return stream == NULL ? -ENOENT : -ESHUTDOWN;
	}
	controller = adapter->controller;
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		unlock_adapter(adapter);
		return ret;
	}
	if (frame_length >
	    controller->local_connection_window) {
		(void)k_mutex_unlock(&controller->lock);
		unlock_adapter(adapter);
		return -ENOBUFS;
	}
	controller->local_connection_window -=
		(uint32_t)frame_length;
	controller->consumed_local += frame_length;
	if (controller->policy.auto_update &&
	    controller->local_connection_window <=
		    controller->policy.update_threshold) {
		connection_credit =
			controller->policy.initial_connection_window -
			controller->local_connection_window;
		controller->local_connection_window +=
			connection_credit;
	}
	if (controller->policy.auto_update &&
	    stream->local_window <=
		    controller->policy.update_threshold) {
		stream_credit =
			controller->policy.initial_stream_window -
			stream->local_window;
	}
	if (connection_credit != 0U ||
	    stream_credit != 0U) {
		controller->updates_sent++;
	}
	(void)k_mutex_unlock(&controller->lock);
	if (connection_credit != 0U ||
	    stream_credit != 0U) {
		ret = replenish_mux_receive_window(
			adapter, stream,
			connection_credit, stream_credit);
		if (ret != 0) {
			unlock_adapter(adapter);
			return ret;
		}
	}
	memset(window, 0, sizeof(*window));
	window->kind =
		PQCP_SOVEREIGN_CHANNEL_WINDOW_CREDIT;
	window->connection_credit = connection_credit;
	window->stream_credit = stream_credit;
	adapter->frames_received++;
	adapter->bytes_received += frame_length;
	if (connection_credit != 0U ||
	    stream_credit != 0U) {
		adapter->updates_sent++;
	}
	unlock_adapter(adapter);
	return 0;
}

static int add_bounded_credit(
	uint32_t *value,
	uint32_t credit,
	uint32_t maximum,
	bool reject_overflow)
{
	if (value == NULL) {
		return -EINVAL;
	}
	if (credit == 0U) {
		return 0;
	}
	if (credit > maximum || *value > maximum - credit) {
		if (reject_overflow) {
			return -EOVERFLOW;
		}
		*value = maximum;
		return 0;
	}
	*value += credit;
	return 0;
}

static int apply_controller_credit(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	uint32_t connection_credit)
{
	struct pqcp_channel_flow_controller *controller =
		adapter->controller;
	int ret;

	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = add_bounded_credit(
		&controller->remote_connection_window,
		connection_credit,
		controller->policy.maximum_connection_window,
		controller->policy.reject_window_overflow);
	if (ret == 0 &&
	    connection_credit != 0U) {
		controller->updates_received++;
	}
	(void)k_mutex_unlock(&controller->lock);
	return ret;
}

static int apply_mux_credit(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	struct pqcp_channel_stream *stream,
	uint32_t connection_credit,
	uint32_t stream_credit)
{
	struct pqcp_channel_multiplexer *multiplexer =
		adapter->multiplexer;
	uint32_t original_connection;
	uint32_t original_stream;
	uint32_t connection_max =
		adapter->controller->policy.
			maximum_connection_window;
	uint32_t stream_max =
		adapter->controller->policy.maximum_stream_window;
	bool reject =
		adapter->controller->policy.reject_window_overflow;
	int ret;

	ret = k_mutex_lock(&multiplexer->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	original_connection =
		multiplexer->connection_remote_window;
	original_stream = stream->remote_window;
	ret = add_bounded_credit(
		&multiplexer->connection_remote_window,
		connection_credit, connection_max, reject);
	if (ret == 0) {
		ret = add_bounded_credit(
			&stream->remote_window,
			stream_credit, stream_max, reject);
	}
	if (ret != 0) {
		multiplexer->connection_remote_window =
			original_connection;
		stream->remote_window = original_stream;
	}
	(void)k_mutex_unlock(&multiplexer->lock);
	return ret;
}

int pqcp_sovereign_channel_flow_apply_window(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	uint32_t stream_id,
	const struct pqcp_sovereign_channel_window *window)
{
	struct pqcp_channel_stream *stream;
	int ret;

	if (adapter == NULL || !adapter->initialized ||
	    stream_id == 0U || window == NULL ||
	    window->kind !=
		    PQCP_SOVEREIGN_CHANNEL_WINDOW_CREDIT ||
	    (window->connection_credit == 0U &&
	     window->stream_credit == 0U)) {
		return -EINVAL;
	}
	ret = lock_adapter(adapter);
	if (ret != 0) {
		return ret;
	}
	stream = pqcp_sovereign_channel_internal_stream(
		adapter->multiplexer, stream_id);
	if (stream == NULL) {
		unlock_adapter(adapter);
		return -ENOENT;
	}
	ret = apply_controller_credit(
		adapter, window->connection_credit);
	if (ret == 0) {
		ret = apply_mux_credit(
			adapter, stream,
			window->connection_credit,
			window->stream_credit);
	}
	if (ret == 0) {
		adapter->updates_received++;
	}
	unlock_adapter(adapter);
	return ret;
}

int pqcp_sovereign_channel_flow_audit(
	struct pqcp_sovereign_channel_flow_adapter *adapter)
{
	int ret;

	if (adapter == NULL || !adapter->initialized ||
	    adapter->multiplexer == NULL ||
	    !adapter->multiplexer->initialized ||
	    adapter->controller == NULL ||
	    !adapter->controller->initialized ||
	    adapter->maximum_frame_bytes !=
		    PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES ||
	    adapter->controller->policy.maximum_frame_payload <
		    adapter->maximum_frame_bytes) {
		return -EINVAL;
	}
	ret = lock_adapter(adapter);
	if (ret != 0) {
		return ret;
	}
	if (adapter->frames_sent >
		    adapter->multiplexer->frames_sent ||
	    adapter->frames_received >
		    adapter->multiplexer->frames_received ||
	    adapter->updates_received >
		    adapter->controller->updates_received ||
	    adapter->updates_sent >
		    adapter->controller->updates_sent) {
		ret = -EBADMSG;
	} else {
		ret = 0;
	}
	unlock_adapter(adapter);
	if (ret == 0) {
		ret = pqcp_channel_flow_audit(adapter->controller);
	}
	if (ret == 0) {
		ret = pqcp_channel_multiplexer_audit(
			adapter->multiplexer);
	}
	return ret;
}

int pqcp_sovereign_channel_internal_send_frame(
	struct pqcp_sovereign_channel_flow_adapter *flow,
	uint32_t stream_id,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES];
	size_t encoded_length = 0U;
	int ret;

	if (flow == NULL || frame == NULL) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_channel_frame_encode(
		frame, encoded, sizeof(encoded),
		&encoded_length);
	if (ret == 0) {
		ret = pqcp_sovereign_channel_flow_send(
			flow, stream_id, encoded,
			encoded_length, 0U, now_ms);
	}
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

int pqcp_sovereign_channel_internal_receive_frame(
	struct pqcp_sovereign_channel_flow_adapter *flow,
	struct pqcp_channel_stream_header *stream_header,
	struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES];
	size_t encoded_length = 0U;
	int ret;

	if (flow == NULL || !flow->initialized ||
	    stream_header == NULL || frame == NULL ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_channel_stream_receive(
		flow->multiplexer, encoded, sizeof(encoded),
		&encoded_length, stream_header, now_ms);
	if (ret != 0) {
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return ret;
	}
	if (stream_header->type !=
		    PQCP_CHANNEL_STREAM_FRAME_DATA) {
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return -EAGAIN;
	}
	if (encoded_length == 0U ||
	    encoded_length != stream_header->payload_length) {
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return -EBADMSG;
	}
	ret = pqcp_sovereign_channel_frame_decode(
		encoded, encoded_length, frame);
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}
