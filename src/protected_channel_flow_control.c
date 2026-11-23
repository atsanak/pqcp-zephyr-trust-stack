/*
 * SPDX-License-Identifier: MIT
 *
 * Connection and per-stream credit accounting.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel_operations.h>

static int flow_policy_validate(
	const struct pqcp_channel_flow_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    policy->initial_connection_window == 0U ||
	    policy->initial_stream_window == 0U ||
	    policy->maximum_connection_window <
		    policy->initial_connection_window ||
	    policy->maximum_stream_window <
		    policy->initial_stream_window ||
	    policy->update_threshold == 0U ||
	    policy->update_threshold >
		    policy->initial_stream_window ||
	    policy->maximum_frame_payload == 0U ||
	    policy->maximum_frame_payload >
		    PQCP_CHANNEL_MAX_PAYLOAD_BYTES) {
		return -EINVAL;
	}
	return 0;
}

static int add_credit(
	uint32_t *window,
	uint32_t credit,
	uint32_t maximum,
	bool reject_overflow)
{
	if (credit == 0U) {
		return 0;
	}
	if (credit > maximum ||
	    *window > maximum - credit) {
		if (reject_overflow) {
			return -EOVERFLOW;
		}
		*window = maximum;
		return 0;
	}
	*window += credit;
	return 0;
}

int pqcp_channel_flow_policy_default(
	struct pqcp_channel_flow_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	policy->initial_connection_window = 65536U;
	policy->initial_stream_window = 16384U;
	policy->maximum_connection_window = 16U * 1024U * 1024U;
	policy->maximum_stream_window = 4U * 1024U * 1024U;
	policy->update_threshold = 4096U;
	policy->maximum_frame_payload =
		PQCP_CHANNEL_MAX_PAYLOAD_BYTES;
	policy->reject_window_overflow = true;
	policy->auto_update = true;
	return 0;
}

int pqcp_channel_flow_init(
	struct pqcp_channel_flow_controller *controller,
	const struct pqcp_channel_flow_policy *policy)
{
	if (controller == NULL ||
	    flow_policy_validate(policy) != 0) {
		return -EINVAL;
	}
	memset(controller, 0, sizeof(*controller));
	controller->policy = *policy;
	controller->local_connection_window =
		policy->initial_connection_window;
	controller->remote_connection_window =
		policy->initial_connection_window;
	k_mutex_init(&controller->lock);
	controller->initialized = true;
	return 0;
}

int pqcp_channel_flow_reserve_send(
	struct pqcp_channel_flow_controller *controller,
	struct pqcp_channel_stream *stream,
	size_t bytes)
{
	int ret;

	if (controller == NULL || !controller->initialized ||
	    stream == NULL || !stream->occupied ||
	    bytes == 0U ||
	    bytes > controller->policy.maximum_frame_payload ||
	    bytes > UINT32_MAX) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (bytes > controller->remote_connection_window ||
	    bytes > stream->remote_window) {
		(void)k_mutex_unlock(&controller->lock);
		return -EAGAIN;
	}
	controller->remote_connection_window -=
		(uint32_t)bytes;
	stream->remote_window -= (uint32_t)bytes;
	controller->consumed_remote += bytes;
	(void)k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_channel_flow_consume_receive(
	struct pqcp_channel_flow_controller *controller,
	struct pqcp_channel_stream *stream,
	size_t bytes,
	uint32_t *connection_credit,
	uint32_t *stream_credit)
{
	uint32_t connection_update = 0U;
	uint32_t stream_update = 0U;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    stream == NULL || !stream->occupied ||
	    bytes == 0U || bytes > UINT32_MAX ||
	    connection_credit == NULL ||
	    stream_credit == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (bytes > controller->local_connection_window ||
	    bytes > stream->local_window) {
		(void)k_mutex_unlock(&controller->lock);
		return -ENOBUFS;
	}
	controller->local_connection_window -=
		(uint32_t)bytes;
	stream->local_window -= (uint32_t)bytes;
	controller->consumed_local += bytes;
	if (controller->policy.auto_update &&
	    controller->local_connection_window <=
		    controller->policy.update_threshold) {
		connection_update =
			controller->policy.initial_connection_window -
			controller->local_connection_window;
		controller->local_connection_window +=
			connection_update;
	}
	if (controller->policy.auto_update &&
	    stream->local_window <=
		    controller->policy.update_threshold) {
		stream_update =
			controller->policy.initial_stream_window -
			stream->local_window;
		stream->local_window += stream_update;
	}
	if (connection_update != 0U ||
	    stream_update != 0U) {
		controller->updates_sent++;
	}
	*connection_credit = connection_update;
	*stream_credit = stream_update;
	(void)k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_channel_flow_apply_update(
	struct pqcp_channel_flow_controller *controller,
	struct pqcp_channel_stream *stream,
	uint32_t connection_credit,
	uint32_t stream_credit)
{
	uint32_t original_connection;
	uint32_t original_stream;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    stream == NULL || !stream->occupied ||
	    (connection_credit == 0U &&
	     stream_credit == 0U)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	original_connection =
		controller->remote_connection_window;
	original_stream = stream->remote_window;
	ret = add_credit(
		&controller->remote_connection_window,
		connection_credit,
		controller->policy.maximum_connection_window,
		controller->policy.reject_window_overflow);
	if (ret == 0) {
		ret = add_credit(
			&stream->remote_window,
			stream_credit,
			controller->policy.maximum_stream_window,
			controller->policy.reject_window_overflow);
	}
	if (ret != 0) {
		controller->remote_connection_window =
			original_connection;
		stream->remote_window = original_stream;
	} else {
		controller->updates_received++;
	}
	(void)k_mutex_unlock(&controller->lock);
	return ret;
}

int pqcp_channel_flow_audit(
	struct pqcp_channel_flow_controller *controller)
{
	int ret;

	if (controller == NULL || !controller->initialized ||
	    flow_policy_validate(&controller->policy) != 0) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = controller->local_connection_window <=
			      controller->policy.
				      maximum_connection_window &&
		      controller->remote_connection_window <=
			      controller->policy.
				      maximum_connection_window ?
		0 : -EBADMSG;
	(void)k_mutex_unlock(&controller->lock);
	return ret;
}
