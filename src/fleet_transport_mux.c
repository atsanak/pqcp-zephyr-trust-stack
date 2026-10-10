/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free fleet transport multiplexing, routing, and reassembly.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_transport_mux.h>

#include "runtime_internal.h"

#define TRANSPORT_BINDING_LABEL "PQCP-FLEET-TRANSPORT-BINDING-V1"
#define TRANSPORT_AUDIT_LABEL "PQCP-FLEET-TRANSPORT-AUDIT-V1"
#define TRANSPORT_SNAPSHOT_LABEL "PQCP-FLEET-TRANSPORT-SNAPSHOT-V1"
#define TRANSPORT_AUDIT_BODY_BYTES 160U
#define TRANSPORT_SNAPSHOT_BODY_BYTES 384U
#define TRANSPORT_ADAPTER_SNAPSHOT_BYTES 112U
#define TRANSPORT_BASE_ROUTE_SCORE 1000000000U

static bool priority_valid(enum pqcp_fleet_transport_priority priority)
{
	return priority >= PQCP_FLEET_TRANSPORT_PRIORITY_BACKGROUND &&
	       priority <= PQCP_FLEET_TRANSPORT_PRIORITY_CRITICAL;
}

static bool frame_type_valid(
	enum pqcp_fleet_transport_frame_type type)
{
	return type >= PQCP_FLEET_TRANSPORT_FRAME_DATA &&
	       type <= PQCP_FLEET_TRANSPORT_FRAME_RESET;
}

static bool link_state_valid(
	enum pqcp_fleet_transport_link_state state)
{
	return state >= PQCP_FLEET_TRANSPORT_LINK_UNUSED &&
	       state <= PQCP_FLEET_TRANSPORT_LINK_DISABLED;
}

static bool message_state_valid(
	enum pqcp_fleet_transport_message_state state)
{
	return state >= PQCP_FLEET_TRANSPORT_MESSAGE_FREE &&
	       state <= PQCP_FLEET_TRANSPORT_MESSAGE_FAILED;
}

static bool reassembly_state_valid(
	enum pqcp_fleet_transport_reassembly_state state)
{
	return state >= PQCP_FLEET_TRANSPORT_REASSEMBLY_FREE &&
	       state <= PQCP_FLEET_TRANSPORT_REASSEMBLY_COMPLETE;
}

static bool audit_event_valid(
	enum pqcp_fleet_transport_audit_event event)
{
	return event > PQCP_FLEET_TRANSPORT_AUDIT_NONE &&
	       event < PQCP_FLEET_TRANSPORT_AUDIT_EVENT_COUNT;
}

static bool digest_zero(const uint8_t *digest, size_t length)
{
	uint8_t aggregate = 0U;

	if (digest == NULL) {
		return true;
	}
	for (size_t index = 0U; index < length; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static bool digest_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if (left == NULL || right == NULL) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static int size_multiply(size_t left, size_t right, size_t *result)
{
	if (result == NULL) {
		return -EINVAL;
	}
	if (left != 0U && right > SIZE_MAX / left) {
		return -EOVERFLOW;
	}
	*result = left * right;
	return 0;
}

static int size_add(size_t left, size_t right, size_t *result)
{
	if (result == NULL) {
		return -EINVAL;
	}
	if (right > SIZE_MAX - left) {
		return -EOVERFLOW;
	}
	*result = left + right;
	return 0;
}

static uint64_t saturating_add_u64(uint64_t left, uint64_t right)
{
	if (right > UINT64_MAX - left) {
		return UINT64_MAX;
	}
	return left + right;
}

static uint32_t saturating_add_u32(uint32_t left, uint32_t right)
{
	if (right > UINT32_MAX - left) {
		return UINT32_MAX;
	}
	return left + right;
}

static uint64_t saturating_increment_u64(uint64_t value)
{
	return value == UINT64_MAX ? UINT64_MAX : value + 1U;
}

static uint32_t saturating_increment_u32(uint32_t value)
{
	return value == UINT32_MAX ? UINT32_MAX : value + 1U;
}

static uint64_t retry_delay(
	const struct pqcp_fleet_transport_policy *policy,
	uint32_t attempt,
	uint64_t sequence)
{
	uint64_t delay;
	uint32_t shift;
	uint64_t jitter;

	if (policy == NULL || policy->base_retry_ms == 0U) {
		return 0U;
	}
	shift = attempt > 1U ? attempt - 1U : 0U;
	if (shift > 31U ||
	    policy->base_retry_ms >
		    (UINT64_MAX >> shift)) {
		delay = UINT64_MAX;
	} else {
		delay = policy->base_retry_ms << shift;
	}
	if (delay > policy->maximum_retry_ms) {
		delay = policy->maximum_retry_ms;
	}
	if (delay == 0U) {
		return 0U;
	}
	jitter = (sequence ^ ((uint64_t)attempt << 32)) %
		 (delay / 8U + 1U);
	if (delay > policy->maximum_retry_ms - jitter) {
		return policy->maximum_retry_ms;
	}
	return delay + jitter;
}

static int policy_validate(
	const struct pqcp_fleet_transport_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_FLEET_TRANSPORT_SCHEMA_VERSION ||
	    (policy->required_capabilities &
	     ~PQCP_FLEET_TRANSPORT_CAP_KNOWN_MASK) != 0U ||
	    (policy->preferred_capabilities &
	     ~PQCP_FLEET_TRANSPORT_CAP_KNOWN_MASK) != 0U ||
	    (policy->forbidden_capabilities &
	     ~PQCP_FLEET_TRANSPORT_CAP_KNOWN_MASK) != 0U ||
	    (policy->required_capabilities &
	     policy->forbidden_capabilities) != 0U ||
	    policy->send_timeout_ms == 0U ||
	    policy->receive_timeout_ms == 0U ||
	    policy->initial_remote_window == 0U ||
	    policy->initial_local_window == 0U ||
	    policy->maximum_window <
		    policy->initial_remote_window ||
	    policy->maximum_window <
		    policy->initial_local_window ||
	    policy->window_update_threshold == 0U ||
	    policy->window_update_threshold >
		    policy->maximum_window ||
	    policy->maximum_attempts == 0U ||
	    policy->degrade_after_failures == 0U ||
	    policy->down_after_failures <
		    policy->degrade_after_failures ||
	    policy->recover_after_successes == 0U ||
	    policy->acknowledgement_timeout_ms == 0U ||
	    policy->base_retry_ms == 0U ||
	    policy->maximum_retry_ms <
		    policy->base_retry_ms ||
	    policy->adapter_backoff_ms == 0U ||
	    policy->probe_interval_ms == 0U ||
	    policy->probe_timeout_ms == 0U ||
	    policy->reassembly_timeout_ms == 0U) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_fleet_transport_policy_default(
	struct pqcp_fleet_transport_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version =
		PQCP_FLEET_TRANSPORT_SCHEMA_VERSION;
	policy->required_capabilities =
		PQCP_FLEET_TRANSPORT_CAP_AUTHENTICATED;
	policy->preferred_capabilities =
		PQCP_FLEET_TRANSPORT_CAP_RELIABLE |
		PQCP_FLEET_TRANSPORT_CAP_ORDERED |
		PQCP_FLEET_TRANSPORT_CAP_CONFIDENTIAL;
	policy->send_timeout_ms = 5000U;
	policy->receive_timeout_ms = 50U;
	policy->initial_remote_window = 32768U;
	policy->initial_local_window = 32768U;
	policy->maximum_window = 1048576U;
	policy->window_update_threshold = 8192U;
	policy->maximum_attempts = 6U;
	policy->degrade_after_failures = 2U;
	policy->down_after_failures = 5U;
	policy->recover_after_successes = 3U;
	policy->route_switch_hysteresis = 5000U;
	policy->latency_weight = 32U;
	policy->jitter_weight = 8U;
	policy->energy_weight = 64U;
	policy->monetary_weight = 64U;
	policy->failure_weight = 50000U;
	policy->priority_weight = 10000U;
	policy->acknowledgement_timeout_ms = 5000U;
	policy->base_retry_ms = 250U;
	policy->maximum_retry_ms = 30000U;
	policy->adapter_backoff_ms = 10000U;
	policy->probe_interval_ms = 15000U;
	policy->probe_timeout_ms = 5000U;
	policy->reassembly_timeout_ms = 30000U;
	policy->require_acknowledgements = true;
	policy->allow_fragmentation = true;
	policy->allow_metered_failover = true;
	policy->prefer_sticky_route = true;
	return 0;
}

static int metadata_validate(
	const struct pqcp_fleet_transport_metadata *metadata)
{
	if (metadata == NULL ||
	    metadata->schema_version !=
		    PQCP_FLEET_TRANSPORT_SCHEMA_VERSION ||
	    metadata->adapter_id == 0U ||
	    (metadata->capabilities &
	     ~PQCP_FLEET_TRANSPORT_CAP_KNOWN_MASK) != 0U ||
	    metadata->mtu < PQCP_FLEET_TRANSPORT_MIN_MTU ||
	    metadata->framing_overhead >= metadata->mtu ||
	    metadata->mtu - metadata->framing_overhead <
		    PQCP_FLEET_TRANSPORT_MIN_MTU ||
	    metadata->administrative_priority > 1000U) {
		return -EINVAL;
	}
	return 0;
}

static int ops_validate(
	const struct pqcp_fleet_transport_adapter_ops *ops)
{
	if (ops == NULL || ops->send == NULL ||
	    ops->receive == NULL) {
		return -EINVAL;
	}
	return 0;
}

static struct pqcp_fleet_transport_adapter *adapter_find_locked(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id)
{
	for (size_t index = 0U; index < mux->adapter_capacity;
	     ++index) {
		struct pqcp_fleet_transport_adapter *adapter =
			&mux->adapters[index];

		if (adapter->occupied &&
		    adapter->metadata.adapter_id == adapter_id) {
			return adapter;
		}
	}
	return NULL;
}

static const struct pqcp_fleet_transport_adapter *
adapter_find_const(
	const struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id)
{
	for (size_t index = 0U; index < mux->adapter_capacity;
	     ++index) {
		const struct pqcp_fleet_transport_adapter *adapter =
			&mux->adapters[index];

		if (adapter->occupied &&
		    adapter->metadata.adapter_id == adapter_id) {
			return adapter;
		}
	}
	return NULL;
}

static struct pqcp_fleet_transport_adapter *adapter_free_locked(
	struct pqcp_fleet_transport_mux *mux)
{
	for (size_t index = 0U; index < mux->adapter_capacity;
	     ++index) {
		if (!mux->adapters[index].occupied) {
			return &mux->adapters[index];
		}
	}
	return NULL;
}

static struct pqcp_fleet_transport_message *message_free_locked(
	struct pqcp_fleet_transport_mux *mux)
{
	for (size_t index = 0U; index < mux->message_capacity;
	     ++index) {
		if (!mux->messages[index].occupied) {
			return &mux->messages[index];
		}
	}
	return NULL;
}

static struct pqcp_fleet_transport_message *message_find_locked(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t message_id,
	uint64_t sequence)
{
	for (size_t index = 0U; index < mux->message_capacity;
	     ++index) {
		struct pqcp_fleet_transport_message *message =
			&mux->messages[index];

		if (message->occupied &&
		    message->message_id == message_id &&
		    message->sequence == sequence) {
			return message;
		}
	}
	return NULL;
}

static struct pqcp_fleet_transport_reassembly *
reassembly_free_locked(struct pqcp_fleet_transport_mux *mux)
{
	for (size_t index = 0U;
	     index < mux->reassembly_capacity; ++index) {
		if (!mux->reassemblies[index].occupied) {
			return &mux->reassemblies[index];
		}
	}
	return NULL;
}

static struct pqcp_fleet_transport_reassembly *
reassembly_find_locked(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t message_id,
	uint64_t sequence)
{
	for (size_t index = 0U;
	     index < mux->reassembly_capacity; ++index) {
		struct pqcp_fleet_transport_reassembly *reassembly =
			&mux->reassemblies[index];

		if (reassembly->occupied &&
		    reassembly->message_id == message_id &&
		    reassembly->sequence == sequence) {
			return reassembly;
		}
	}
	return NULL;
}

static size_t append_u32(
	uint8_t *output,
	size_t offset,
	uint32_t value)
{
	pqcp_runtime_internal_write_u32(output + offset, value);
	return offset + 4U;
}

static size_t append_i32(
	uint8_t *output,
	size_t offset,
	int32_t value)
{
	pqcp_runtime_internal_write_u32(
		output + offset, (uint32_t)value);
	return offset + 4U;
}

static size_t append_u64(
	uint8_t *output,
	size_t offset,
	uint64_t value)
{
	pqcp_runtime_internal_write_u64(output + offset, value);
	return offset + 8U;
}

static size_t audit_body(
	const struct pqcp_fleet_transport_audit_entry *entry,
	uint8_t output[TRANSPORT_AUDIT_BODY_BYTES])
{
	size_t offset = 0U;

	if (entry == NULL || output == NULL ||
	    entry->schema_version !=
		    PQCP_FLEET_TRANSPORT_SCHEMA_VERSION ||
	    entry->sequence == 0U ||
	    entry->timestamp_ms == 0U ||
	    !audit_event_valid(entry->event)) {
		return 0U;
	}
	memset(output, 0, TRANSPORT_AUDIT_BODY_BYTES);
	memcpy(output + offset, TRANSPORT_AUDIT_LABEL,
	       sizeof(TRANSPORT_AUDIT_LABEL) - 1U);
	offset += sizeof(TRANSPORT_AUDIT_LABEL) - 1U;
	offset = append_u32(
		output, offset, entry->schema_version);
	offset = append_u64(output, offset, entry->sequence);
	offset = append_u64(
		output, offset, entry->timestamp_ms);
	offset = append_u32(
		output, offset, (uint32_t)entry->event);
	offset = append_u64(output, offset, entry->channel_id);
	offset = append_u64(output, offset, entry->message_id);
	offset = append_u64(
		output, offset, entry->transport_sequence);
	offset = append_u32(output, offset, entry->adapter_id);
	offset = append_u32(output, offset, entry->detail);
	offset = append_i32(output, offset, entry->result);
	memcpy(output + offset, entry->previous_digest,
	       sizeof(entry->previous_digest));
	offset += sizeof(entry->previous_digest);
	return offset <= TRANSPORT_AUDIT_BODY_BYTES ?
		offset : 0U;
}

static int audit_digest(
	const struct pqcp_fleet_transport_audit_entry *entry,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[TRANSPORT_AUDIT_BODY_BYTES];
	size_t length;
	int ret;

	length = audit_body(entry, body);
	if (length == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_internal_sha256(body, length, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int audit_append_locked(
	struct pqcp_fleet_transport_mux *mux,
	enum pqcp_fleet_transport_audit_event event,
	uint64_t message_id,
	uint64_t sequence,
	uint32_t adapter_id,
	uint32_t detail,
	int result,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_audit_entry entry;
	int ret;

	if (mux->audit_entries == NULL ||
	    mux->audit_capacity == 0U) {
		return 0;
	}
	if (!audit_event_valid(event) || now_ms == 0U) {
		return -EINVAL;
	}
	memset(&entry, 0, sizeof(entry));
	entry.schema_version =
		PQCP_FLEET_TRANSPORT_SCHEMA_VERSION;
	entry.sequence = mux->next_audit_sequence;
	if (entry.sequence == 0U) {
		entry.sequence = 1U;
	}
	entry.timestamp_ms = now_ms;
	entry.event = event;
	entry.channel_id = mux->channel_id;
	entry.message_id = message_id;
	entry.transport_sequence = sequence;
	entry.adapter_id = adapter_id;
	entry.detail = detail;
	entry.result = result;
	memcpy(entry.previous_digest, mux->audit_chain_head,
	       sizeof(entry.previous_digest));
	entry.occupied = true;
	ret = audit_digest(&entry, entry.entry_digest);
	if (ret != 0) {
		pqcp_runtime_secure_zero(&entry, sizeof(entry));
		return ret;
	}
	mux->audit_entries[mux->audit_next] = entry;
	mux->audit_next =
		(mux->audit_next + 1U) % mux->audit_capacity;
	if (mux->audit_count < mux->audit_capacity) {
		mux->audit_count++;
	}
	memcpy(mux->audit_chain_head, entry.entry_digest,
	       sizeof(mux->audit_chain_head));
	mux->next_audit_sequence =
		saturating_increment_u64(entry.sequence);
	pqcp_runtime_secure_zero(&entry, sizeof(entry));
	return 0;
}

static void health_transition_locked(
	struct pqcp_fleet_transport_adapter *adapter,
	enum pqcp_fleet_transport_link_state state,
	uint64_t now_ms)
{
	if (adapter->health.state != state) {
		adapter->health.state = state;
		adapter->health.last_state_change_ms = now_ms;
	}
}

static void health_success_locked(
	struct pqcp_fleet_transport_mux *mux,
	struct pqcp_fleet_transport_adapter *adapter,
	bool receive,
	size_t bytes,
	uint64_t rtt_us,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_health *health =
		&adapter->health;

	health->consecutive_successes =
		saturating_increment_u32(
			health->consecutive_successes);
	health->consecutive_failures = 0U;
	health->last_success_ms = now_ms;
	health->last_error = 0;
	if (receive) {
		health->last_receive_ms = now_ms;
		health->frames_received =
			saturating_increment_u64(
				health->frames_received);
		health->bytes_received =
			saturating_add_u64(
				health->bytes_received, bytes);
	} else {
		health->last_send_ms = now_ms;
		health->frames_sent =
			saturating_increment_u64(
				health->frames_sent);
		health->bytes_sent =
			saturating_add_u64(
				health->bytes_sent, bytes);
	}
	if (rtt_us != 0U) {
		if (health->smoothed_rtt_us == 0U) {
			health->smoothed_rtt_us = rtt_us;
			health->rtt_variance_us = rtt_us / 2U;
		} else {
			uint64_t difference =
				health->smoothed_rtt_us > rtt_us ?
				health->smoothed_rtt_us - rtt_us :
				rtt_us - health->smoothed_rtt_us;

			health->rtt_variance_us =
				(health->rtt_variance_us * 3U +
				 difference) / 4U;
			health->smoothed_rtt_us =
				(health->smoothed_rtt_us * 7U +
				 rtt_us) / 8U;
		}
	}
	if ((health->state == PQCP_FLEET_TRANSPORT_LINK_PROBING ||
	     health->state == PQCP_FLEET_TRANSPORT_LINK_DEGRADED ||
	     health->state == PQCP_FLEET_TRANSPORT_LINK_BACKOFF ||
	     health->state == PQCP_FLEET_TRANSPORT_LINK_DOWN) &&
	    health->consecutive_successes >=
		    mux->policy.recover_after_successes) {
		health_transition_locked(
			adapter,
			PQCP_FLEET_TRANSPORT_LINK_HEALTHY,
			now_ms);
	}
}

static void health_failure_locked(
	struct pqcp_fleet_transport_mux *mux,
	struct pqcp_fleet_transport_adapter *adapter,
	bool receive,
	int error,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_health *health =
		&adapter->health;

	health->consecutive_failures =
		saturating_increment_u32(
			health->consecutive_failures);
	health->consecutive_successes = 0U;
	health->last_failure_ms = now_ms;
	health->last_error = error;
	if (receive) {
		health->receive_failures =
			saturating_increment_u64(
				health->receive_failures);
	} else {
		health->send_failures =
			saturating_increment_u64(
				health->send_failures);
	}
	if (health->consecutive_failures >=
	    mux->policy.down_after_failures) {
		health->backoff_until_ms =
			saturating_add_u64(
				now_ms,
				mux->policy.adapter_backoff_ms);
		health_transition_locked(
			adapter,
			PQCP_FLEET_TRANSPORT_LINK_BACKOFF,
			now_ms);
	} else if (health->consecutive_failures >=
		   mux->policy.degrade_after_failures) {
		health_transition_locked(
			adapter,
			PQCP_FLEET_TRANSPORT_LINK_DEGRADED,
			now_ms);
	}
}

static int frame_header_validate(
	const struct pqcp_fleet_transport_frame_header *header)
{
	enum pqcp_fleet_transport_frame_type type;

	if (header == NULL ||
	    header->magic != PQCP_FLEET_TRANSPORT_MAGIC ||
	    header->schema_version !=
		    PQCP_FLEET_TRANSPORT_SCHEMA_VERSION ||
	    header->header_bytes !=
		    PQCP_FLEET_TRANSPORT_HEADER_BYTES ||
	    header->channel_id == 0U ||
	    header->sequence == 0U ||
	    (header->flags &
	     ~PQCP_FLEET_TRANSPORT_FLAG_KNOWN_MASK) != 0U ||
	    !priority_valid(
		    (enum pqcp_fleet_transport_priority)
			    header->priority) ||
	    digest_zero(
		    header->channel_binding,
		    sizeof(header->channel_binding))) {
		return -EINVAL;
	}
	type = (enum pqcp_fleet_transport_frame_type)
		header->type;
	if (!frame_type_valid(type)) {
		return -EINVAL;
	}
	if (type == PQCP_FLEET_TRANSPORT_FRAME_DATA) {
		if (header->message_id == 0U ||
		    header->message_length == 0U ||
		    header->payload_length == 0U ||
		    header->fragment_offset >
			    header->message_length ||
		    header->payload_length >
			    header->message_length -
				    header->fragment_offset ||
		    ((header->fragment_offset == 0U) !=
		     ((header->flags &
		       PQCP_FLEET_TRANSPORT_FLAG_FIRST) != 0U)) ||
		    ((header->fragment_offset +
		       header->payload_length ==
		       header->message_length) !=
		     ((header->flags &
		       PQCP_FLEET_TRANSPORT_FLAG_LAST) != 0U))) {
			return -EINVAL;
		}
	} else {
		if (header->payload_length != 0U ||
		    header->fragment_offset != 0U ||
		    header->message_length != 0U ||
		    (header->flags &
		     (PQCP_FLEET_TRANSPORT_FLAG_FIRST |
		      PQCP_FLEET_TRANSPORT_FLAG_LAST |
		      PQCP_FLEET_TRANSPORT_FLAG_ACK_REQUIRED)) != 0U) {
			return -EINVAL;
		}
	}
	if (type == PQCP_FLEET_TRANSPORT_FRAME_ACK &&
	    (header->message_id == 0U ||
	     header->acknowledgement_sequence == 0U)) {
		return -EINVAL;
	}
	if (type == PQCP_FLEET_TRANSPORT_FRAME_WINDOW_UPDATE &&
	    header->window_credit == 0U) {
		return -EINVAL;
	}
	if ((type == PQCP_FLEET_TRANSPORT_FRAME_PROBE ||
	     type == PQCP_FLEET_TRANSPORT_FRAME_PROBE_ACK) &&
	    header->message_id == 0U) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_fleet_transport_frame_encode(
	const struct pqcp_fleet_transport_frame_header *header,
	const uint8_t *payload,
	size_t payload_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	uint8_t payload_digest[PQCP_FLEET_DIGEST_BYTES];
	size_t required;
	int ret;

	if (header == NULL ||
	    (payload == NULL && payload_length != 0U) ||
	    output == NULL || output_length == NULL ||
	    payload_length != header->payload_length) {
		return -EINVAL;
	}
	ret = frame_header_validate(header);
	if (ret != 0) {
		return ret;
	}
	ret = size_add(
		PQCP_FLEET_TRANSPORT_HEADER_BYTES,
		payload_length, &required);
	if (ret != 0 || required > output_capacity) {
		return ret != 0 ? ret : -ENOSPC;
	}
	ret = pqcp_runtime_internal_sha256(
		payload, payload_length, payload_digest);
	if (ret != 0) {
		return ret;
	}
	memset(output, 0, PQCP_FLEET_TRANSPORT_HEADER_BYTES);
	pqcp_runtime_internal_write_u32(output, header->magic);
	pqcp_runtime_internal_write_u16(
		output + 4U, header->schema_version);
	pqcp_runtime_internal_write_u16(
		output + 6U, header->type);
	pqcp_runtime_internal_write_u32(
		output + 8U, header->flags);
	pqcp_runtime_internal_write_u32(
		output + 12U, header->header_bytes);
	pqcp_runtime_internal_write_u64(
		output + 16U, header->channel_id);
	pqcp_runtime_internal_write_u64(
		output + 24U, header->message_id);
	pqcp_runtime_internal_write_u64(
		output + 32U, header->sequence);
	pqcp_runtime_internal_write_u64(
		output + 40U,
		header->acknowledgement_sequence);
	pqcp_runtime_internal_write_u32(
		output + 48U, header->fragment_offset);
	pqcp_runtime_internal_write_u32(
		output + 52U, header->message_length);
	pqcp_runtime_internal_write_u32(
		output + 56U, header->payload_length);
	pqcp_runtime_internal_write_u32(
		output + 60U, header->window_credit);
	pqcp_runtime_internal_write_u32(
		output + 64U, header->priority);
	pqcp_runtime_internal_write_u32(
		output + 68U, header->adapter_hint);
	memcpy(output + 72U, header->channel_binding,
	       PQCP_FLEET_TRANSPORT_BINDING_BYTES);
	memcpy(output + 104U, payload_digest,
	       sizeof(payload_digest));
	if (payload_length != 0U) {
		memcpy(
			output + PQCP_FLEET_TRANSPORT_HEADER_BYTES,
			payload, payload_length);
	}
	*output_length = required;
	pqcp_runtime_secure_zero(
		payload_digest, sizeof(payload_digest));
	return 0;
}

int pqcp_fleet_transport_frame_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_fleet_transport_frame_view *frame)
{
	uint8_t payload_digest[PQCP_FLEET_DIGEST_BYTES];
	size_t expected;
	int ret;

	if (input == NULL || frame == NULL ||
	    input_length < PQCP_FLEET_TRANSPORT_HEADER_BYTES) {
		return -EINVAL;
	}
	memset(frame, 0, sizeof(*frame));
	frame->header.magic =
		pqcp_runtime_internal_read_u32(input);
	frame->header.schema_version =
		pqcp_runtime_internal_read_u16(input + 4U);
	frame->header.type =
		pqcp_runtime_internal_read_u16(input + 6U);
	frame->header.flags =
		pqcp_runtime_internal_read_u32(input + 8U);
	frame->header.header_bytes =
		pqcp_runtime_internal_read_u32(input + 12U);
	frame->header.channel_id =
		pqcp_runtime_internal_read_u64(input + 16U);
	frame->header.message_id =
		pqcp_runtime_internal_read_u64(input + 24U);
	frame->header.sequence =
		pqcp_runtime_internal_read_u64(input + 32U);
	frame->header.acknowledgement_sequence =
		pqcp_runtime_internal_read_u64(input + 40U);
	frame->header.fragment_offset =
		pqcp_runtime_internal_read_u32(input + 48U);
	frame->header.message_length =
		pqcp_runtime_internal_read_u32(input + 52U);
	frame->header.payload_length =
		pqcp_runtime_internal_read_u32(input + 56U);
	frame->header.window_credit =
		pqcp_runtime_internal_read_u32(input + 60U);
	frame->header.priority =
		pqcp_runtime_internal_read_u32(input + 64U);
	frame->header.adapter_hint =
		pqcp_runtime_internal_read_u32(input + 68U);
	memcpy(frame->header.channel_binding, input + 72U,
	       sizeof(frame->header.channel_binding));
	memcpy(frame->header.payload_digest, input + 104U,
	       sizeof(frame->header.payload_digest));
	ret = frame_header_validate(&frame->header);
	if (ret != 0) {
		return -EBADMSG;
	}
	ret = size_add(
		PQCP_FLEET_TRANSPORT_HEADER_BYTES,
		frame->header.payload_length, &expected);
	if (ret != 0 || expected != input_length) {
		return -EBADMSG;
	}
	frame->payload =
		input + PQCP_FLEET_TRANSPORT_HEADER_BYTES;
	frame->payload_length = frame->header.payload_length;
	ret = pqcp_runtime_internal_sha256(
		frame->payload, frame->payload_length,
		payload_digest);
	if (ret == 0 &&
	    !digest_equal(
		    payload_digest,
		    frame->header.payload_digest,
		    sizeof(payload_digest))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(
		payload_digest, sizeof(payload_digest));
	return ret;
}

int pqcp_fleet_transport_mux_init(
	struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_policy *policy,
	struct pqcp_fleet_transport_adapter *adapters,
	size_t adapter_capacity,
	struct pqcp_fleet_transport_message *messages,
	size_t message_capacity,
	uint8_t *message_storage,
	size_t message_storage_bytes,
	size_t message_slot_bytes,
	struct pqcp_fleet_transport_reassembly *reassemblies,
	size_t reassembly_capacity,
	uint8_t *reassembly_storage,
	size_t reassembly_storage_bytes,
	size_t reassembly_slot_bytes,
	uint8_t *tx_scratch,
	size_t tx_scratch_capacity,
	uint8_t *rx_scratch,
	size_t rx_scratch_capacity,
	struct pqcp_fleet_transport_audit_entry *audit_entries,
	size_t audit_capacity)
{
	size_t required_message_storage;
	size_t required_reassembly_storage;
	int ret;

	if (mux == NULL || policy_validate(policy) != 0 ||
	    adapters == NULL || adapter_capacity == 0U ||
	    adapter_capacity >
		    PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS ||
	    messages == NULL || message_capacity == 0U ||
	    message_storage == NULL || message_slot_bytes == 0U ||
	    reassemblies == NULL || reassembly_capacity == 0U ||
	    reassembly_storage == NULL ||
	    reassembly_slot_bytes == 0U ||
	    tx_scratch == NULL ||
	    tx_scratch_capacity <
		    PQCP_FLEET_TRANSPORT_MIN_MTU ||
	    rx_scratch == NULL ||
	    rx_scratch_capacity <
		    PQCP_FLEET_TRANSPORT_MIN_MTU ||
	    (audit_entries == NULL && audit_capacity != 0U)) {
		return -EINVAL;
	}
	ret = size_multiply(
		message_capacity, message_slot_bytes,
		&required_message_storage);
	if (ret != 0 ||
	    required_message_storage > message_storage_bytes) {
		return ret != 0 ? ret : -ENOSPC;
	}
	ret = size_multiply(
		reassembly_capacity, reassembly_slot_bytes,
		&required_reassembly_storage);
	if (ret != 0 ||
	    required_reassembly_storage >
		    reassembly_storage_bytes) {
		return ret != 0 ? ret : -ENOSPC;
	}
	memset(mux, 0, sizeof(*mux));
	memset(adapters, 0,
	       adapter_capacity * sizeof(*adapters));
	memset(messages, 0,
	       message_capacity * sizeof(*messages));
	memset(reassemblies, 0,
	       reassembly_capacity * sizeof(*reassemblies));
	memset(message_storage, 0, required_message_storage);
	memset(reassembly_storage, 0,
	       required_reassembly_storage);
	if (audit_entries != NULL) {
		memset(audit_entries, 0,
		       audit_capacity * sizeof(*audit_entries));
	}
	for (size_t index = 0U; index < message_capacity;
	     ++index) {
		messages[index].storage =
			message_storage + index * message_slot_bytes;
		messages[index].storage_capacity =
			message_slot_bytes;
	}
	for (size_t index = 0U; index < reassembly_capacity;
	     ++index) {
		reassemblies[index].storage =
			reassembly_storage +
			index * reassembly_slot_bytes;
		reassemblies[index].storage_capacity =
			reassembly_slot_bytes;
	}
	mux->schema_version =
		PQCP_FLEET_TRANSPORT_SCHEMA_VERSION;
	mux->policy = *policy;
	mux->adapters = adapters;
	mux->adapter_capacity = adapter_capacity;
	mux->messages = messages;
	mux->message_capacity = message_capacity;
	mux->reassemblies = reassemblies;
	mux->reassembly_capacity = reassembly_capacity;
	mux->audit_entries = audit_entries;
	mux->audit_capacity = audit_capacity;
	mux->message_storage = message_storage;
	mux->message_storage_bytes = message_storage_bytes;
	mux->message_slot_bytes = message_slot_bytes;
	mux->reassembly_storage = reassembly_storage;
	mux->reassembly_storage_bytes =
		reassembly_storage_bytes;
	mux->reassembly_slot_bytes = reassembly_slot_bytes;
	mux->tx_scratch = tx_scratch;
	mux->tx_scratch_capacity = tx_scratch_capacity;
	mux->rx_scratch = rx_scratch;
	mux->rx_scratch_capacity = rx_scratch_capacity;
	mux->next_message_id = 1U;
	mux->next_send_sequence = 1U;
	mux->next_audit_sequence = 1U;
	mux->next_probe_id = 1U;
	mux->remote_window = policy->initial_remote_window;
	mux->local_window = policy->initial_local_window;
	k_mutex_init(&mux->lock);
	k_mutex_init(&mux->tx_lock);
	k_mutex_init(&mux->rx_lock);
	mux->initialized = true;
	return 0;
}

int pqcp_fleet_transport_adapter_register(
	struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_metadata *metadata,
	const struct pqcp_fleet_transport_adapter_ops *ops,
	void *context,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_adapter *adapter;
	uint32_t generation;
	int ret;

	if (mux == NULL || !mux->initialized ||
	    metadata_validate(metadata) != 0 ||
	    ops_validate(ops) != 0 || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (adapter_find_locked(mux, metadata->adapter_id) != NULL) {
		(void)k_mutex_unlock(&mux->lock);
		return -EEXIST;
	}
	adapter = adapter_free_locked(mux);
	if (adapter == NULL) {
		(void)k_mutex_unlock(&mux->lock);
		return -ENOSPC;
	}
	generation = adapter->generation == UINT32_MAX ?
		1U : adapter->generation + 1U;
	memset(adapter, 0, sizeof(*adapter));
	adapter->metadata = *metadata;
	adapter->ops = *ops;
	adapter->context = context;
	adapter->generation = generation;
	adapter->enabled = true;
	adapter->occupied = true;
	adapter->health.state =
		PQCP_FLEET_TRANSPORT_LINK_DOWN;
	adapter->health.last_state_change_ms = now_ms;
	mux->adapter_count++;
	ret = audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_ADAPTER_REGISTERED,
		0U, 0U, metadata->adapter_id,
		metadata->capabilities, 0, now_ms);
	(void)k_mutex_unlock(&mux->lock);
	return ret;
}

int pqcp_fleet_transport_adapter_unregister(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_adapter *adapter;
	uint32_t generation;
	bool opened;
	int (*close_fn)(void *);
	void *context;
	int ret;
	int close_ret = 0;

	if (mux == NULL || !mux->initialized ||
	    adapter_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->tx_lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&mux->rx_lock, K_FOREVER);
	if (ret != 0) {
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		(void)k_mutex_unlock(&mux->rx_lock);
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	adapter = adapter_find_locked(mux, adapter_id);
	if (adapter == NULL) {
		(void)k_mutex_unlock(&mux->lock);
		(void)k_mutex_unlock(&mux->rx_lock);
		(void)k_mutex_unlock(&mux->tx_lock);
		return -ENOENT;
	}
	for (size_t index = 0U; index < mux->message_capacity;
	     ++index) {
		if (mux->messages[index].occupied &&
		    mux->messages[index].active_adapter_id ==
			    adapter_id) {
			(void)k_mutex_unlock(&mux->lock);
			(void)k_mutex_unlock(&mux->rx_lock);
			(void)k_mutex_unlock(&mux->tx_lock);
			return -EBUSY;
		}
	}
	generation = adapter->generation;
	opened = adapter->opened;
	close_fn = adapter->ops.close;
	context = adapter->context;
	adapter->enabled = false;
	adapter->opened = false;
	health_transition_locked(
		adapter, PQCP_FLEET_TRANSPORT_LINK_DISABLED,
		now_ms);
	(void)k_mutex_unlock(&mux->lock);
	if (opened && close_fn != NULL) {
		close_ret = close_fn(context);
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret == 0) {
		adapter = adapter_find_locked(mux, adapter_id);
		if (adapter != NULL &&
		    adapter->generation == generation) {
			memset(adapter, 0, sizeof(*adapter));
			adapter->generation = generation;
			if (mux->adapter_count != 0U) {
				mux->adapter_count--;
			}
			if (mux->sticky_adapter_id == adapter_id) {
				mux->sticky_adapter_id = 0U;
			}
			(void)audit_append_locked(
				mux,
				PQCP_FLEET_TRANSPORT_AUDIT_ADAPTER_STATE,
				0U, 0U, adapter_id,
				PQCP_FLEET_TRANSPORT_LINK_UNUSED,
				close_ret, now_ms);
		}
		(void)k_mutex_unlock(&mux->lock);
	}
	(void)k_mutex_unlock(&mux->rx_lock);
	(void)k_mutex_unlock(&mux->tx_lock);
	return ret != 0 ? ret : close_ret;
}

int pqcp_fleet_transport_adapter_set_enabled(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	bool enabled,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_adapter *adapter;
	int ret;

	if (mux == NULL || !mux->initialized ||
	    adapter_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	adapter = adapter_find_locked(mux, adapter_id);
	if (adapter == NULL) {
		(void)k_mutex_unlock(&mux->lock);
		return -ENOENT;
	}
	adapter->enabled = enabled;
	if (!enabled) {
		health_transition_locked(
			adapter,
			PQCP_FLEET_TRANSPORT_LINK_DISABLED,
			now_ms);
		if (mux->sticky_adapter_id == adapter_id) {
			mux->sticky_adapter_id = 0U;
		}
	} else if (adapter->opened) {
		health_transition_locked(
			adapter,
			PQCP_FLEET_TRANSPORT_LINK_PROBING,
			now_ms);
	} else {
		health_transition_locked(
			adapter,
			PQCP_FLEET_TRANSPORT_LINK_DOWN,
			now_ms);
	}
	ret = audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_ADAPTER_STATE,
		0U, 0U, adapter_id,
		(uint32_t)adapter->health.state, 0, now_ms);
	(void)k_mutex_unlock(&mux->lock);
	return ret;
}

static int adapter_lifecycle(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	bool open,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_adapter *adapter;
	uint32_t generation;
	int (*operation)(void *);
	void *context;
	int ret;
	int operation_ret;

	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	adapter = adapter_find_locked(mux, adapter_id);
	if (adapter == NULL) {
		(void)k_mutex_unlock(&mux->lock);
		return -ENOENT;
	}
	if (open && !adapter->enabled) {
		(void)k_mutex_unlock(&mux->lock);
		return -EACCES;
	}
	if (adapter->opened == open) {
		(void)k_mutex_unlock(&mux->lock);
		return 0;
	}
	generation = adapter->generation;
	operation = open ? adapter->ops.open :
		adapter->ops.close;
	context = adapter->context;
	health_transition_locked(
		adapter,
		open ? PQCP_FLEET_TRANSPORT_LINK_PROBING :
		       PQCP_FLEET_TRANSPORT_LINK_DOWN,
		now_ms);
	(void)k_mutex_unlock(&mux->lock);
	operation_ret = operation != NULL ?
		operation(context) : 0;
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	adapter = adapter_find_locked(mux, adapter_id);
	if (adapter == NULL ||
	    adapter->generation != generation) {
		(void)k_mutex_unlock(&mux->lock);
		return -ESTALE;
	}
	if (operation_ret == 0) {
		adapter->opened = open;
		adapter->health.consecutive_failures = 0U;
		adapter->health.consecutive_successes = 0U;
		health_transition_locked(
			adapter,
			open ? PQCP_FLEET_TRANSPORT_LINK_PROBING :
			       PQCP_FLEET_TRANSPORT_LINK_DOWN,
			now_ms);
	} else {
		adapter->opened = false;
		health_failure_locked(
			mux, adapter, false,
			operation_ret, now_ms);
	}
	(void)audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_ADAPTER_STATE,
		0U, 0U, adapter_id,
		(uint32_t)adapter->health.state,
		operation_ret, now_ms);
	(void)k_mutex_unlock(&mux->lock);
	return operation_ret;
}

int pqcp_fleet_transport_adapter_open(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms)
{
	int ret;

	if (mux == NULL || !mux->initialized ||
	    adapter_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->tx_lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = adapter_lifecycle(
		mux, adapter_id, true, now_ms);
	(void)k_mutex_unlock(&mux->tx_lock);
	return ret;
}

int pqcp_fleet_transport_adapter_close(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms)
{
	int ret;

	if (mux == NULL || !mux->initialized ||
	    adapter_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->tx_lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = adapter_lifecycle(
		mux, adapter_id, false, now_ms);
	(void)k_mutex_unlock(&mux->tx_lock);
	return ret;
}

int pqcp_fleet_transport_bind_channel(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t channel_id,
	const uint8_t *exporter,
	size_t exporter_length,
	const uint8_t *transcript_digest,
	size_t transcript_digest_length,
	const uint8_t *peer_identity_digest,
	size_t peer_identity_digest_length,
	uint64_t now_ms)
{
	const uint8_t *parts[5];
	size_t lengths[5];
	uint8_t encoded_channel[8];
	uint8_t binding[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (mux == NULL || !mux->initialized ||
	    channel_id == 0U || exporter == NULL ||
	    exporter_length == 0U ||
	    transcript_digest == NULL ||
	    transcript_digest_length == 0U ||
	    peer_identity_digest == NULL ||
	    peer_identity_digest_length == 0U ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u64(
		encoded_channel, channel_id);
	parts[0] = (const uint8_t *)TRANSPORT_BINDING_LABEL;
	lengths[0] = sizeof(TRANSPORT_BINDING_LABEL) - 1U;
	parts[1] = encoded_channel;
	lengths[1] = sizeof(encoded_channel);
	parts[2] = exporter;
	lengths[2] = exporter_length;
	parts[3] = transcript_digest;
	lengths[3] = transcript_digest_length;
	parts[4] = peer_identity_digest;
	lengths[4] = peer_identity_digest_length;
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, 5U, binding);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		return ret;
	}
	if (mux->message_count != 0U ||
	    mux->reassembly_count != 0U) {
		(void)k_mutex_unlock(&mux->lock);
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		return -EBUSY;
	}
	mux->channel_id = channel_id;
	memcpy(mux->channel_binding, binding,
	       sizeof(mux->channel_binding));
	mux->next_message_id = 1U;
	mux->next_send_sequence = 1U;
	mux->inbound_replay =
		(struct pqcp_fleet_transport_replay_state){0};
	mux->channel_bound = true;
	ret = audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_CHANNEL_BOUND,
		0U, 0U, 0U, 0U, 0, now_ms);
	(void)k_mutex_unlock(&mux->lock);
	pqcp_runtime_secure_zero(binding, sizeof(binding));
	return ret;
}

static uint64_t route_penalty_product(
	uint64_t value,
	uint32_t weight)
{
	if (weight != 0U && value > UINT64_MAX / weight) {
		return UINT64_MAX;
	}
	return value * weight;
}

static uint64_t route_penalty_add(
	uint64_t current,
	uint64_t addition)
{
	if (addition > UINT64_MAX - current) {
		return UINT64_MAX;
	}
	return current + addition;
}

int pqcp_fleet_transport_route_score(
	const struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_adapter *adapter,
	uint32_t required_capabilities,
	size_t message_length,
	uint64_t now_ms,
	uint32_t *score)
{
	uint32_t required;
	uint32_t preferred_match;
	uint64_t penalty = 0U;
	uint64_t bonus = 0U;
	uint64_t latency;
	uint64_t jitter;
	size_t usable_mtu;

	if (mux == NULL || !mux->initialized ||
	    adapter == NULL || !adapter->occupied ||
	    score == NULL || now_ms == 0U ||
	    (required_capabilities &
	     ~PQCP_FLEET_TRANSPORT_CAP_KNOWN_MASK) != 0U ||
	    message_length == 0U) {
		return -EINVAL;
	}
	*score = 0U;
	required = mux->policy.required_capabilities |
		   required_capabilities;
	if (!adapter->enabled || !adapter->opened ||
	    adapter->health.state ==
		    PQCP_FLEET_TRANSPORT_LINK_UNUSED ||
	    adapter->health.state ==
		    PQCP_FLEET_TRANSPORT_LINK_DOWN ||
	    adapter->health.state ==
		    PQCP_FLEET_TRANSPORT_LINK_DISABLED ||
	    (adapter->health.state ==
		     PQCP_FLEET_TRANSPORT_LINK_BACKOFF &&
	     now_ms < adapter->health.backoff_until_ms) ||
	    (adapter->metadata.capabilities & required) !=
		    required ||
	    (adapter->metadata.capabilities &
	     mux->policy.forbidden_capabilities) != 0U) {
		return -ENETDOWN;
	}
	if (adapter->metadata.mtu <=
	    adapter->metadata.framing_overhead) {
		return -EMSGSIZE;
	}
	usable_mtu = adapter->metadata.mtu -
		     adapter->metadata.framing_overhead;
	if (usable_mtu <= PQCP_FLEET_TRANSPORT_HEADER_BYTES) {
		return -EMSGSIZE;
	}
	if (message_length >
		    usable_mtu -
			    PQCP_FLEET_TRANSPORT_HEADER_BYTES &&
	    (!mux->policy.allow_fragmentation ||
	     (adapter->metadata.capabilities &
	      PQCP_FLEET_TRANSPORT_CAP_FRAGMENTATION) == 0U)) {
		return -EMSGSIZE;
	}
	latency = adapter->health.smoothed_rtt_us != 0U ?
		adapter->health.smoothed_rtt_us / 1000U :
		adapter->metadata.nominal_latency_ms;
	jitter = adapter->health.rtt_variance_us != 0U ?
		adapter->health.rtt_variance_us / 1000U :
		adapter->metadata.nominal_jitter_ms;
	penalty = route_penalty_add(
		penalty,
		route_penalty_product(
			latency, mux->policy.latency_weight));
	penalty = route_penalty_add(
		penalty,
		route_penalty_product(
			jitter, mux->policy.jitter_weight));
	penalty = route_penalty_add(
		penalty,
		route_penalty_product(
			adapter->metadata.energy_cost,
			mux->policy.energy_weight));
	penalty = route_penalty_add(
		penalty,
		route_penalty_product(
			adapter->metadata.monetary_cost,
			mux->policy.monetary_weight));
	penalty = route_penalty_add(
		penalty,
		route_penalty_product(
			adapter->health.consecutive_failures,
			mux->policy.failure_weight));
	if (adapter->health.state ==
	    PQCP_FLEET_TRANSPORT_LINK_DEGRADED) {
		penalty = route_penalty_add(
			penalty,
			(uint64_t)mux->policy.failure_weight * 2U);
	}
	preferred_match =
		adapter->metadata.capabilities &
		mux->policy.preferred_capabilities;
	for (uint32_t mask = preferred_match;
	     mask != 0U; mask &= mask - 1U) {
		bonus = route_penalty_add(
			bonus, mux->policy.priority_weight);
	}
	bonus = route_penalty_add(
		bonus,
		route_penalty_product(
			adapter->metadata.administrative_priority,
			mux->policy.priority_weight));
	if (mux->policy.prefer_sticky_route &&
	    mux->sticky_adapter_id ==
		    adapter->metadata.adapter_id) {
		bonus = route_penalty_add(
			bonus,
			mux->policy.route_switch_hysteresis);
	}
	if (penalty >= TRANSPORT_BASE_ROUTE_SCORE) {
		*score = bonus >= UINT32_MAX ? UINT32_MAX : 1U;
	} else {
		uint64_t result =
			TRANSPORT_BASE_ROUTE_SCORE - penalty;

		result = route_penalty_add(result, bonus);
		*score = result > UINT32_MAX ?
			UINT32_MAX : (uint32_t)result;
	}
	return 0;
}

static int select_route_locked(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t required_capabilities,
	uint32_t preferred_adapter_id,
	uint32_t excluded_adapter_id,
	size_t message_length,
	bool failover,
	uint64_t now_ms,
	struct pqcp_fleet_transport_adapter **selected,
	uint32_t *selected_score)
{
	struct pqcp_fleet_transport_adapter *best = NULL;
	uint32_t best_score = 0U;
	bool found_unmetered = false;

	for (size_t index = 0U; index < mux->adapter_capacity;
	     ++index) {
		struct pqcp_fleet_transport_adapter *adapter =
			&mux->adapters[index];
		uint32_t score;
		int ret;

		if (!adapter->occupied ||
		    adapter->metadata.adapter_id ==
			    excluded_adapter_id) {
			continue;
		}
		if (failover &&
		    !mux->policy.allow_metered_failover &&
		    (adapter->metadata.capabilities &
		     PQCP_FLEET_TRANSPORT_CAP_METERED) != 0U) {
			continue;
		}
		ret = pqcp_fleet_transport_route_score(
			mux, adapter, required_capabilities,
			message_length, now_ms, &score);
		if (ret != 0) {
			continue;
		}
		if (adapter->metadata.adapter_id ==
		    preferred_adapter_id) {
			score = saturating_add_u32(
				score,
				mux->policy.route_switch_hysteresis +
				mux->policy.priority_weight);
		}
		if ((adapter->metadata.capabilities &
		     PQCP_FLEET_TRANSPORT_CAP_METERED) == 0U) {
			if (!found_unmetered) {
				best = NULL;
				best_score = 0U;
				found_unmetered = true;
			}
		} else if (found_unmetered) {
			continue;
		}
		if (best == NULL || score > best_score ||
		    (score == best_score &&
		     adapter->metadata.adapter_id <
			     best->metadata.adapter_id)) {
			best = adapter;
			best_score = score;
		}
	}
	if (best == NULL && excluded_adapter_id != 0U) {
		for (size_t index = 0U;
		     index < mux->adapter_capacity; ++index) {
			struct pqcp_fleet_transport_adapter *adapter =
				&mux->adapters[index];
			uint32_t score;

			if (!adapter->occupied ||
			    adapter->metadata.adapter_id !=
				    excluded_adapter_id ||
			    pqcp_fleet_transport_route_score(
				    mux, adapter,
				    required_capabilities,
				    message_length, now_ms,
				    &score) != 0) {
				continue;
			}
			best = adapter;
			best_score = score;
			break;
		}
	}
	if (best == NULL) {
		return -ENETUNREACH;
	}
	*selected = best;
	if (selected_score != NULL) {
		*selected_score = best_score;
	}
	return 0;
}

static void message_release_locked(
	struct pqcp_fleet_transport_mux *mux,
	struct pqcp_fleet_transport_message *message)
{
	uint8_t *storage;
	size_t capacity;

	if (message == NULL || !message->occupied) {
		return;
	}
	storage = message->storage;
	capacity = message->storage_capacity;
	if (storage != NULL && capacity != 0U) {
		pqcp_runtime_secure_zero(storage, capacity);
	}
	memset(message, 0, sizeof(*message));
	message->storage = storage;
	message->storage_capacity = capacity;
	if (mux->message_count != 0U) {
		mux->message_count--;
	}
}

static void reassembly_release_locked(
	struct pqcp_fleet_transport_mux *mux,
	struct pqcp_fleet_transport_reassembly *reassembly)
{
	uint8_t *storage;
	size_t capacity;

	if (reassembly == NULL || !reassembly->occupied) {
		return;
	}
	storage = reassembly->storage;
	capacity = reassembly->storage_capacity;
	if (storage != NULL && capacity != 0U) {
		pqcp_runtime_secure_zero(storage, capacity);
	}
	memset(reassembly, 0, sizeof(*reassembly));
	reassembly->storage = storage;
	reassembly->storage_capacity = capacity;
	if (mux->reassembly_count != 0U) {
		mux->reassembly_count--;
	}
}

int pqcp_fleet_transport_enqueue(
	struct pqcp_fleet_transport_mux *mux,
	const uint8_t *message,
	size_t message_length,
	enum pqcp_fleet_transport_priority priority,
	uint32_t required_capabilities,
	uint32_t preferred_adapter_id,
	bool acknowledgement_required,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t *message_id)
{
	struct pqcp_fleet_transport_message *slot;
	uint64_t assigned_message_id;
	uint64_t assigned_sequence;
	int ret;

	if (mux == NULL || !mux->initialized ||
	    !mux->channel_bound || message == NULL ||
	    message_length == 0U ||
	    message_length > mux->message_slot_bytes ||
	    message_length > UINT32_MAX ||
	    !priority_valid(priority) ||
	    (required_capabilities &
	     ~PQCP_FLEET_TRANSPORT_CAP_KNOWN_MASK) != 0U ||
	    now_ms == 0U || expires_at_ms <= now_ms ||
	    message_id == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	slot = message_free_locked(mux);
	if (slot == NULL) {
		(void)k_mutex_unlock(&mux->lock);
		return -ENOSPC;
	}
	if (mux->next_message_id == 0U ||
	    mux->next_send_sequence == 0U ||
	    mux->next_message_id == UINT64_MAX ||
	    mux->next_send_sequence == UINT64_MAX) {
		(void)k_mutex_unlock(&mux->lock);
		return -EOVERFLOW;
	}
	assigned_message_id = mux->next_message_id++;
	assigned_sequence = mux->next_send_sequence++;
	memcpy(slot->storage, message, message_length);
	slot->message_id = assigned_message_id;
	slot->sequence = assigned_sequence;
	slot->enqueued_at_ms = now_ms;
	slot->expires_at_ms = expires_at_ms;
	slot->next_attempt_ms = now_ms;
	slot->length = message_length;
	slot->required_capabilities = required_capabilities;
	slot->preferred_adapter_id = preferred_adapter_id;
	slot->priority = priority;
	slot->state = PQCP_FLEET_TRANSPORT_MESSAGE_QUEUED;
	slot->acknowledgement_required =
		acknowledgement_required ||
		mux->policy.require_acknowledgements;
	slot->occupied = true;
	mux->message_count++;
	*message_id = assigned_message_id;
	ret = audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_QUEUED,
		slot->message_id, slot->sequence, 0U,
		(uint32_t)message_length, 0, now_ms);
	(void)k_mutex_unlock(&mux->lock);
	return ret;
}

static struct pqcp_fleet_transport_message *
message_select_locked(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_message *selected = NULL;

	for (size_t index = 0U; index < mux->message_capacity;
	     ++index) {
		struct pqcp_fleet_transport_message *message =
			&mux->messages[index];
		bool eligible;

		if (!message->occupied) {
			continue;
		}
		eligible =
			message->state ==
				PQCP_FLEET_TRANSPORT_MESSAGE_QUEUED ||
			message->state ==
				PQCP_FLEET_TRANSPORT_MESSAGE_SENDING ||
			(message->state ==
				 PQCP_FLEET_TRANSPORT_MESSAGE_RETRY_WAIT &&
			 now_ms >= message->next_attempt_ms);
		if (!eligible) {
			continue;
		}
		if (selected == NULL ||
		    message->priority > selected->priority ||
		    (message->priority == selected->priority &&
		     message->enqueued_at_ms <
			     selected->enqueued_at_ms) ||
		    (message->priority == selected->priority &&
		     message->enqueued_at_ms ==
			     selected->enqueued_at_ms &&
		     message->sequence < selected->sequence)) {
			selected = message;
		}
	}
	return selected;
}

static size_t adapter_payload_capacity(
	const struct pqcp_fleet_transport_adapter *adapter)
{
	size_t available;

	if (adapter->metadata.mtu <=
	    adapter->metadata.framing_overhead) {
		return 0U;
	}
	available = adapter->metadata.mtu -
		    adapter->metadata.framing_overhead;
	if (available <= PQCP_FLEET_TRANSPORT_HEADER_BYTES) {
		return 0U;
	}
	return available -
	       PQCP_FLEET_TRANSPORT_HEADER_BYTES;
}

static int message_schedule_retry_locked(
	struct pqcp_fleet_transport_mux *mux,
	struct pqcp_fleet_transport_message *message,
	int error,
	uint64_t now_ms)
{
	uint64_t delay;

	message->attempts =
		saturating_increment_u32(message->attempts);
	message->route_failures =
		saturating_increment_u32(
			message->route_failures);
	message->last_error = error;
	message->previous_adapter_id =
		message->active_adapter_id;
	message->active_adapter_id = 0U;
	message->next_offset = 0U;
	message->acknowledgement_deadline_ms = 0U;
	if (message->attempts >= mux->policy.maximum_attempts) {
		message->state =
			PQCP_FLEET_TRANSPORT_MESSAGE_FAILED;
		(void)audit_append_locked(
			mux,
			PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_DROPPED,
			message->message_id, message->sequence,
			message->previous_adapter_id,
			message->attempts, error, now_ms);
		return -EHOSTUNREACH;
	}
	delay = retry_delay(
		&mux->policy, message->attempts,
		message->sequence);
	message->next_attempt_ms =
		saturating_add_u64(now_ms, delay);
	message->state =
		PQCP_FLEET_TRANSPORT_MESSAGE_RETRY_WAIT;
	mux->retry_count =
		saturating_increment_u64(mux->retry_count);
	(void)audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_RETRY_SCHEDULED,
		message->message_id, message->sequence,
		message->previous_adapter_id,
		message->attempts, error, now_ms);
	return 0;
}

static int message_prepare_frame_locked(
	struct pqcp_fleet_transport_mux *mux,
	struct pqcp_fleet_transport_message *message,
	struct pqcp_fleet_transport_adapter **adapter_out,
	uint32_t *adapter_generation,
	size_t *frame_length,
	size_t *fragment_length,
	uint32_t *route_score,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_adapter *adapter;
	struct pqcp_fleet_transport_frame_header header;
	size_t payload_capacity;
	size_t remaining;
	size_t fragment;
	uint32_t flags = 0U;
	bool failover;
	int ret;

	failover = message->previous_adapter_id != 0U;
	ret = select_route_locked(
		mux, message->required_capabilities,
		message->preferred_adapter_id,
		failover ? message->previous_adapter_id : 0U,
		message->length, failover, now_ms,
		&adapter, route_score);
	if (ret != 0) {
		return ret;
	}
	payload_capacity = adapter_payload_capacity(adapter);
	if (payload_capacity == 0U) {
		return -EMSGSIZE;
	}
	if (payload_capacity >
	    mux->tx_scratch_capacity -
		    PQCP_FLEET_TRANSPORT_HEADER_BYTES) {
		payload_capacity =
			mux->tx_scratch_capacity -
			PQCP_FLEET_TRANSPORT_HEADER_BYTES;
	}
	if (message->next_offset > message->length) {
		return -EBADMSG;
	}
	remaining = message->length - message->next_offset;
	fragment = remaining < payload_capacity ?
		remaining : payload_capacity;
	if (fragment > mux->remote_window) {
		fragment = mux->remote_window;
	}
	if (fragment == 0U) {
		return -EAGAIN;
	}
	if (fragment < remaining &&
	    (!mux->policy.allow_fragmentation ||
	     (adapter->metadata.capabilities &
	      PQCP_FLEET_TRANSPORT_CAP_FRAGMENTATION) == 0U)) {
		return -EMSGSIZE;
	}
	if (message->next_offset == 0U) {
		flags |= PQCP_FLEET_TRANSPORT_FLAG_FIRST;
	}
	if (message->next_offset + fragment ==
	    message->length) {
		flags |= PQCP_FLEET_TRANSPORT_FLAG_LAST;
	}
	if (message->acknowledgement_required) {
		flags |= PQCP_FLEET_TRANSPORT_FLAG_ACK_REQUIRED;
	}
	if (message->attempts != 0U) {
		flags |= PQCP_FLEET_TRANSPORT_FLAG_RETRANSMIT;
	}
	if (failover &&
	    adapter->metadata.adapter_id !=
		    message->previous_adapter_id) {
		flags |= PQCP_FLEET_TRANSPORT_FLAG_FAILOVER;
	}
	memset(&header, 0, sizeof(header));
	header.magic = PQCP_FLEET_TRANSPORT_MAGIC;
	header.schema_version =
		PQCP_FLEET_TRANSPORT_SCHEMA_VERSION;
	header.type = PQCP_FLEET_TRANSPORT_FRAME_DATA;
	header.flags = flags;
	header.header_bytes =
		PQCP_FLEET_TRANSPORT_HEADER_BYTES;
	header.channel_id = mux->channel_id;
	header.message_id = message->message_id;
	header.sequence = message->sequence;
	header.fragment_offset =
		(uint32_t)message->next_offset;
	header.message_length = (uint32_t)message->length;
	header.payload_length = (uint32_t)fragment;
	header.priority = (uint32_t)message->priority;
	header.adapter_hint = adapter->metadata.adapter_id;
	memcpy(header.channel_binding, mux->channel_binding,
	       sizeof(header.channel_binding));
	ret = pqcp_fleet_transport_frame_encode(
		&header,
		message->storage + message->next_offset,
		fragment, mux->tx_scratch,
		mux->tx_scratch_capacity, frame_length);
	if (ret != 0) {
		return ret;
	}
	message->state =
		PQCP_FLEET_TRANSPORT_MESSAGE_SENDING;
	message->active_adapter_id =
		adapter->metadata.adapter_id;
	if ((flags &
	     PQCP_FLEET_TRANSPORT_FLAG_FAILOVER) != 0U) {
		message->failover_used = true;
	}
	*adapter_out = adapter;
	*adapter_generation = adapter->generation;
	*fragment_length = fragment;
	return 0;
}

int pqcp_fleet_transport_service_tx(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t now_ms,
	uint64_t *message_id,
	bool *progressed)
{
	struct pqcp_fleet_transport_message *message;
	struct pqcp_fleet_transport_adapter *adapter;
	uint64_t selected_message_id;
	uint64_t selected_sequence;
	uint32_t adapter_id;
	uint32_t adapter_generation;
	uint32_t score = 0U;
	size_t frame_length = 0U;
	size_t fragment_length = 0U;
	int (*send_fn)(
		void *, const uint8_t *, size_t, uint32_t);
	void *context;
	int ret;
	int send_ret;

	if (mux == NULL || !mux->initialized ||
	    !mux->channel_bound || now_ms == 0U ||
	    progressed == NULL) {
		return -EINVAL;
	}
	*progressed = false;
	if (message_id != NULL) {
		*message_id = 0U;
	}
	ret = k_mutex_lock(&mux->tx_lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	message = message_select_locked(mux, now_ms);
	if (message == NULL) {
		(void)k_mutex_unlock(&mux->lock);
		(void)k_mutex_unlock(&mux->tx_lock);
		return -EAGAIN;
	}
	if (now_ms > message->expires_at_ms) {
		selected_message_id = message->message_id;
		mux->expired_messages =
			saturating_increment_u64(
				mux->expired_messages);
		(void)audit_append_locked(
			mux,
			PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_DROPPED,
			message->message_id, message->sequence,
			message->active_adapter_id, 0U,
			-ETIMEDOUT, now_ms);
		message_release_locked(mux, message);
		(void)k_mutex_unlock(&mux->lock);
		(void)k_mutex_unlock(&mux->tx_lock);
		if (message_id != NULL) {
			*message_id = selected_message_id;
		}
		*progressed = true;
		return -ETIMEDOUT;
	}
	ret = message_prepare_frame_locked(
		mux, message, &adapter,
		&adapter_generation, &frame_length,
		&fragment_length, &score, now_ms);
	if (ret != 0) {
		if (ret != -EAGAIN) {
			(void)message_schedule_retry_locked(
				mux, message, ret, now_ms);
		}
		(void)k_mutex_unlock(&mux->lock);
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	selected_message_id = message->message_id;
	selected_sequence = message->sequence;
	adapter_id = adapter->metadata.adapter_id;
	send_fn = adapter->ops.send;
	context = adapter->context;
	(void)audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_ROUTE_SELECTED,
		selected_message_id, selected_sequence,
		adapter_id, score, 0, now_ms);
	(void)k_mutex_unlock(&mux->lock);
	send_ret = send_fn(
		context, mux->tx_scratch, frame_length,
		mux->policy.send_timeout_ms);
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			mux->tx_scratch, frame_length);
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	message = message_find_locked(
		mux, selected_message_id, selected_sequence);
	adapter = adapter_find_locked(mux, adapter_id);
	if (message == NULL || adapter == NULL ||
	    adapter->generation != adapter_generation) {
		(void)k_mutex_unlock(&mux->lock);
		pqcp_runtime_secure_zero(
			mux->tx_scratch, frame_length);
		(void)k_mutex_unlock(&mux->tx_lock);
		return -ESTALE;
	}
	if (send_ret != 0) {
		health_failure_locked(
			mux, adapter, false, send_ret, now_ms);
		(void)message_schedule_retry_locked(
			mux, message, send_ret, now_ms);
		(void)audit_append_locked(
			mux,
			PQCP_FLEET_TRANSPORT_AUDIT_FRAME_SENT,
			selected_message_id, selected_sequence,
			adapter_id, (uint32_t)fragment_length,
			send_ret, now_ms);
		(void)k_mutex_unlock(&mux->lock);
		pqcp_runtime_secure_zero(
			mux->tx_scratch, frame_length);
		(void)k_mutex_unlock(&mux->tx_lock);
		return send_ret;
	}
	health_success_locked(
		mux, adapter, false, frame_length, 0U, now_ms);
	mux->total_frames_sent =
		saturating_increment_u64(mux->total_frames_sent);
	mux->total_bytes_sent =
		saturating_add_u64(
			mux->total_bytes_sent, frame_length);
	if (fragment_length > mux->remote_window) {
		ret = -EBADMSG;
	} else {
		mux->remote_window -= (uint32_t)fragment_length;
		message->next_offset += fragment_length;
		message->last_error = 0;
		mux->sticky_adapter_id = adapter_id;
		if (message->failover_used &&
		    message->previous_adapter_id != 0U &&
		    message->previous_adapter_id != adapter_id) {
			mux->failover_count =
				saturating_increment_u64(
					mux->failover_count);
			(void)audit_append_locked(
				mux,
				PQCP_FLEET_TRANSPORT_AUDIT_FAILOVER,
				message->message_id,
				message->sequence, adapter_id,
				message->previous_adapter_id,
				0, now_ms);
			message->previous_adapter_id = 0U;
		}
		if (message->next_offset == message->length) {
			if (message->acknowledgement_required) {
				message->state =
					PQCP_FLEET_TRANSPORT_MESSAGE_WAITING_ACK;
				message->acknowledgement_deadline_ms =
					saturating_add_u64(
						now_ms,
						mux->policy.
						acknowledgement_timeout_ms);
			} else {
				message->state =
					PQCP_FLEET_TRANSPORT_MESSAGE_DELIVERED;
			}
		} else {
			message->state =
				PQCP_FLEET_TRANSPORT_MESSAGE_SENDING;
		}
	}
	(void)audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_FRAME_SENT,
		selected_message_id, selected_sequence,
		adapter_id, (uint32_t)fragment_length,
		ret, now_ms);
	if (ret == 0 &&
	    message->state ==
		    PQCP_FLEET_TRANSPORT_MESSAGE_DELIVERED) {
		message_release_locked(mux, message);
	}
	(void)k_mutex_unlock(&mux->lock);
	pqcp_runtime_secure_zero(
		mux->tx_scratch, frame_length);
	(void)k_mutex_unlock(&mux->tx_lock);
	if (message_id != NULL) {
		*message_id = selected_message_id;
	}
	*progressed = true;
	return ret;
}

static int replay_status_locked(
	const struct pqcp_fleet_transport_replay_state *state,
	uint64_t sequence)
{
	uint64_t distance;
	uint64_t mask;

	if (sequence == 0U) {
		return -EINVAL;
	}
	if (!state->initialized ||
	    sequence > state->highest_sequence) {
		return 0;
	}
	distance = state->highest_sequence - sequence;
	if (distance >= PQCP_FLEET_TRANSPORT_REPLAY_WINDOW) {
		return -ERANGE;
	}
	mask = UINT64_C(1) << distance;
	return (state->bitmap & mask) != 0U ?
		-EALREADY : 0;
}

static int replay_accept_locked(
	struct pqcp_fleet_transport_replay_state *state,
	uint64_t sequence)
{
	uint64_t distance;
	int ret;

	ret = replay_status_locked(state, sequence);
	if (ret != 0) {
		return ret;
	}
	if (!state->initialized) {
		state->highest_sequence = sequence;
		state->bitmap = 1U;
		state->initialized = true;
		return 0;
	}
	if (sequence > state->highest_sequence) {
		distance = sequence - state->highest_sequence;
		if (distance >=
		    PQCP_FLEET_TRANSPORT_REPLAY_WINDOW) {
			state->bitmap = 1U;
		} else {
			state->bitmap =
				(state->bitmap << distance) | 1U;
		}
		state->highest_sequence = sequence;
		return 0;
	}
	distance = state->highest_sequence - sequence;
	state->bitmap |= UINT64_C(1) << distance;
	return 0;
}

static int send_control_frame(
	struct pqcp_fleet_transport_mux *mux,
	enum pqcp_fleet_transport_frame_type type,
	uint64_t message_id,
	uint64_t acknowledgement_sequence,
	uint32_t window_credit,
	uint32_t preferred_adapter_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_adapter *adapter;
	struct pqcp_fleet_transport_frame_header header;
	uint64_t sequence;
	uint32_t adapter_id;
	uint32_t adapter_generation;
	size_t frame_length = 0U;
	int (*send_fn)(
		void *, const uint8_t *, size_t, uint32_t);
	void *context;
	int ret;
	int send_ret;

	if (!frame_type_valid(type) ||
	    type == PQCP_FLEET_TRANSPORT_FRAME_DATA) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->tx_lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	if (!mux->channel_bound ||
	    mux->next_send_sequence == 0U ||
	    mux->next_send_sequence == UINT64_MAX) {
		(void)k_mutex_unlock(&mux->lock);
		(void)k_mutex_unlock(&mux->tx_lock);
		return -EOVERFLOW;
	}
	ret = select_route_locked(
		mux, 0U, preferred_adapter_id, 0U,
		1U, false, now_ms, &adapter, NULL);
	if (ret != 0) {
		(void)k_mutex_unlock(&mux->lock);
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	sequence = mux->next_send_sequence++;
	memset(&header, 0, sizeof(header));
	header.magic = PQCP_FLEET_TRANSPORT_MAGIC;
	header.schema_version =
		PQCP_FLEET_TRANSPORT_SCHEMA_VERSION;
	header.type = (uint16_t)type;
	header.flags =
		PQCP_FLEET_TRANSPORT_FLAG_CONTROL;
	header.header_bytes =
		PQCP_FLEET_TRANSPORT_HEADER_BYTES;
	header.channel_id = mux->channel_id;
	header.message_id = message_id;
	header.sequence = sequence;
	header.acknowledgement_sequence =
		acknowledgement_sequence;
	header.window_credit = window_credit;
	header.priority =
		PQCP_FLEET_TRANSPORT_PRIORITY_CRITICAL;
	header.adapter_hint = adapter->metadata.adapter_id;
	memcpy(header.channel_binding, mux->channel_binding,
	       sizeof(header.channel_binding));
	ret = pqcp_fleet_transport_frame_encode(
		&header, NULL, 0U, mux->tx_scratch,
		mux->tx_scratch_capacity, &frame_length);
	if (ret != 0) {
		(void)k_mutex_unlock(&mux->lock);
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	adapter_id = adapter->metadata.adapter_id;
	adapter_generation = adapter->generation;
	send_fn = adapter->ops.send;
	context = adapter->context;
	(void)k_mutex_unlock(&mux->lock);
	send_ret = send_fn(
		context, mux->tx_scratch, frame_length,
		mux->policy.send_timeout_ms);
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret == 0) {
		adapter = adapter_find_locked(mux, adapter_id);
		if (adapter == NULL ||
		    adapter->generation != adapter_generation) {
			ret = -ESTALE;
		} else if (send_ret != 0) {
			health_failure_locked(
				mux, adapter, false,
				send_ret, now_ms);
			ret = send_ret;
		} else {
			health_success_locked(
				mux, adapter, false,
				frame_length, 0U, now_ms);
			mux->total_frames_sent =
				saturating_increment_u64(
					mux->total_frames_sent);
			mux->total_bytes_sent =
				saturating_add_u64(
					mux->total_bytes_sent,
					frame_length);
			mux->sticky_adapter_id = adapter_id;
		}
		(void)audit_append_locked(
			mux,
			type == PQCP_FLEET_TRANSPORT_FRAME_PROBE ?
				PQCP_FLEET_TRANSPORT_AUDIT_PROBE_SENT :
				PQCP_FLEET_TRANSPORT_AUDIT_FRAME_SENT,
			message_id, sequence, adapter_id,
			(uint32_t)type,
			ret != 0 ? ret : send_ret, now_ms);
		(void)k_mutex_unlock(&mux->lock);
	}
	pqcp_runtime_secure_zero(
		mux->tx_scratch, frame_length);
	(void)k_mutex_unlock(&mux->tx_lock);
	return ret != 0 ? ret : send_ret;
}

static int ingest_ack_locked(
	struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_frame_header *header,
	uint32_t adapter_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_message *message;

	message = message_find_locked(
		mux, header->message_id,
		header->acknowledgement_sequence);
	if (message == NULL) {
		mux->duplicate_rejections =
			saturating_increment_u64(
				mux->duplicate_rejections);
		(void)audit_append_locked(
			mux,
			PQCP_FLEET_TRANSPORT_AUDIT_DUPLICATE_REJECTED,
			header->message_id,
			header->acknowledgement_sequence,
			adapter_id, 0U, -ENOENT, now_ms);
		return -ENOENT;
	}
	if (message->state !=
		    PQCP_FLEET_TRANSPORT_MESSAGE_WAITING_ACK ||
	    message->next_offset != message->length) {
		return -EPROTO;
	}
	mux->acknowledged_messages =
		saturating_increment_u64(
			mux->acknowledged_messages);
	(void)audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_ACKED,
		message->message_id, message->sequence,
		adapter_id, message->attempts, 0, now_ms);
	message_release_locked(mux, message);
	return 0;
}

static int ingest_window_locked(
	struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_frame_header *header,
	uint32_t adapter_id,
	uint64_t now_ms)
{
	uint32_t credit = header->window_credit;

	if (credit > mux->policy.maximum_window -
	    mux->remote_window) {
		return -EOVERFLOW;
	}
	mux->remote_window += credit;
	(void)audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_WINDOW_UPDATED,
		0U, header->sequence, adapter_id,
		credit, 0, now_ms);
	return 0;
}

static int ingest_probe_ack_locked(
	struct pqcp_fleet_transport_mux *mux,
	struct pqcp_fleet_transport_adapter *adapter,
	const struct pqcp_fleet_transport_frame_header *header,
	uint64_t now_ms)
{
	uint64_t elapsed_ms;
	uint64_t rtt_us;

	if (!adapter->health.probe_outstanding ||
	    adapter->health.last_probe_id !=
		    header->message_id ||
	    now_ms < adapter->health.probe_sent_at_ms) {
		return -ESTALE;
	}
	elapsed_ms = now_ms -
		     adapter->health.probe_sent_at_ms;
	if (elapsed_ms > UINT64_MAX / 1000U) {
		rtt_us = UINT64_MAX;
	} else {
		rtt_us = elapsed_ms * 1000U;
	}
	adapter->health.probe_outstanding = false;
	health_success_locked(
		mux, adapter, true, 0U, rtt_us, now_ms);
	(void)audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_PROBE_ACKED,
		header->message_id, header->sequence,
		adapter->metadata.adapter_id,
		rtt_us > UINT32_MAX ?
			UINT32_MAX : (uint32_t)rtt_us,
		0, now_ms);
	return 0;
}

static int ingest_reset_locked(
	struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_frame_header *header,
	uint32_t adapter_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_message *message;

	if (header->message_id == 0U ||
	    header->acknowledgement_sequence == 0U) {
		return -EBADMSG;
	}
	message = message_find_locked(
		mux, header->message_id,
		header->acknowledgement_sequence);
	if (message == NULL) {
		return -ENOENT;
	}
	message->active_adapter_id = adapter_id;
	return message_schedule_retry_locked(
		mux, message, -ECONNRESET, now_ms);
}

static int reassembly_initialize_locked(
	struct pqcp_fleet_transport_mux *mux,
	struct pqcp_fleet_transport_reassembly *reassembly,
	const struct pqcp_fleet_transport_frame_header *header,
	uint32_t adapter_id,
	uint64_t now_ms)
{
	uint8_t *storage = reassembly->storage;
	size_t capacity = reassembly->storage_capacity;

	if ((header->flags &
	     PQCP_FLEET_TRANSPORT_FLAG_FIRST) == 0U ||
	    header->fragment_offset != 0U ||
	    header->message_length > capacity) {
		return header->message_length > capacity ?
			-ENOSPC : -EPROTO;
	}
	memset(reassembly, 0, sizeof(*reassembly));
	reassembly->storage = storage;
	reassembly->storage_capacity = capacity;
	reassembly->message_id = header->message_id;
	reassembly->sequence = header->sequence;
	reassembly->started_at_ms = now_ms;
	reassembly->last_fragment_at_ms = now_ms;
	reassembly->total_length = header->message_length;
	reassembly->adapter_id = adapter_id;
	reassembly->priority =
		(enum pqcp_fleet_transport_priority)
			header->priority;
	reassembly->state =
		PQCP_FLEET_TRANSPORT_REASSEMBLY_RECEIVING;
	reassembly->occupied = true;
	mux->reassembly_count++;
	return 0;
}

static int ingest_data_locked(
	struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_frame_view *frame,
	uint32_t adapter_id,
	uint64_t now_ms,
	bool *send_ack)
{
	struct pqcp_fleet_transport_reassembly *reassembly;
	const struct pqcp_fleet_transport_frame_header *header =
		&frame->header;
	size_t end_offset;
	int replay_status;
	int ret;

	*send_ack = false;
	replay_status = replay_status_locked(
		&mux->inbound_replay, header->sequence);
	if (replay_status != 0) {
		if (replay_status == -EALREADY) {
			mux->duplicate_rejections =
				saturating_increment_u64(
					mux->duplicate_rejections);
			(void)audit_append_locked(
				mux,
				PQCP_FLEET_TRANSPORT_AUDIT_DUPLICATE_REJECTED,
				header->message_id, header->sequence,
				adapter_id, header->fragment_offset,
				replay_status, now_ms);
		} else {
			mux->replay_rejections =
				saturating_increment_u64(
					mux->replay_rejections);
			(void)audit_append_locked(
				mux,
				PQCP_FLEET_TRANSPORT_AUDIT_REPLAY_REJECTED,
				header->message_id, header->sequence,
				adapter_id, header->fragment_offset,
				replay_status, now_ms);
		}
		return replay_status;
	}
	reassembly = reassembly_find_locked(
		mux, header->message_id, header->sequence);
	if (reassembly == NULL) {
		reassembly = reassembly_free_locked(mux);
		if (reassembly == NULL) {
			return -ENOSPC;
		}
		ret = reassembly_initialize_locked(
			mux, reassembly, header,
			adapter_id, now_ms);
		if (ret != 0) {
			return ret;
		}
	}
	if (reassembly->total_length !=
		    header->message_length ||
	    reassembly->priority !=
		    (enum pqcp_fleet_transport_priority)
			    header->priority) {
		return -EPROTO;
	}
	ret = size_add(
		header->fragment_offset,
		header->payload_length, &end_offset);
	if (ret != 0 ||
	    end_offset > reassembly->total_length) {
		return -EOVERFLOW;
	}
	if (header->fragment_offset <
	    reassembly->received_length) {
		if (end_offset <= reassembly->received_length &&
		    memcmp(
			    reassembly->storage +
				    header->fragment_offset,
			    frame->payload,
			    frame->payload_length) == 0) {
			mux->duplicate_rejections =
				saturating_increment_u64(
					mux->duplicate_rejections);
			if (reassembly->state ==
			    PQCP_FLEET_TRANSPORT_REASSEMBLY_COMPLETE) {
				*send_ack =
					(header->flags &
					 PQCP_FLEET_TRANSPORT_FLAG_ACK_REQUIRED) !=
					0U;
			}
			return -EALREADY;
		}
		return -EBADMSG;
	}
	if (header->fragment_offset !=
	    reassembly->received_length) {
		return -ERANGE;
	}
	if (header->payload_length > mux->local_window) {
		return -ENOBUFS;
	}
	memcpy(
		reassembly->storage + header->fragment_offset,
		frame->payload, frame->payload_length);
	reassembly->received_length += frame->payload_length;
	reassembly->last_fragment_at_ms = now_ms;
	reassembly->adapter_id = adapter_id;
	mux->local_window -= header->payload_length;
	if ((header->flags &
	     PQCP_FLEET_TRANSPORT_FLAG_LAST) == 0U) {
		return 0;
	}
	if (reassembly->received_length !=
	    reassembly->total_length) {
		return -EBADMSG;
	}
	ret = pqcp_runtime_internal_sha256(
		reassembly->storage,
		reassembly->total_length,
		reassembly->message_digest);
	if (ret != 0) {
		return ret;
	}
	ret = replay_accept_locked(
		&mux->inbound_replay, header->sequence);
	if (ret != 0) {
		return ret;
	}
	reassembly->state =
		PQCP_FLEET_TRANSPORT_REASSEMBLY_COMPLETE;
	*send_ack =
		(header->flags &
		 PQCP_FLEET_TRANSPORT_FLAG_ACK_REQUIRED) != 0U;
	return 0;
}

int pqcp_fleet_transport_ingest(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	const uint8_t *frame,
	size_t frame_length,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_frame_view decoded;
	struct pqcp_fleet_transport_adapter *adapter;
	enum pqcp_fleet_transport_frame_type type;
	uint64_t control_message_id = 0U;
	uint64_t control_ack_sequence = 0U;
	uint32_t control_adapter_id = 0U;
	bool send_ack = false;
	bool send_probe_ack = false;
	int ret;
	int replay_ret;

	if (mux == NULL || !mux->initialized ||
	    adapter_id == 0U || frame == NULL ||
	    frame_length == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_fleet_transport_frame_decode(
		frame, frame_length, &decoded);
	if (ret != 0) {
		ret = k_mutex_lock(&mux->lock, K_FOREVER);
		if (ret == 0) {
			mux->malformed_rejections =
				saturating_increment_u64(
					mux->malformed_rejections);
			(void)audit_append_locked(
				mux,
				PQCP_FLEET_TRANSPORT_AUDIT_FRAME_REJECTED,
				0U, 0U, adapter_id,
				(uint32_t)(frame_length >
					UINT32_MAX ?
					UINT32_MAX : frame_length),
				-EBADMSG, now_ms);
			(void)k_mutex_unlock(&mux->lock);
		}
		return -EBADMSG;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	adapter = adapter_find_locked(mux, adapter_id);
	if (adapter == NULL || !adapter->enabled ||
	    !adapter->opened) {
		(void)k_mutex_unlock(&mux->lock);
		return adapter == NULL ? -ENOENT : -ENETDOWN;
	}
	if (!mux->channel_bound ||
	    decoded.header.channel_id != mux->channel_id ||
	    !digest_equal(
		    decoded.header.channel_binding,
		    mux->channel_binding,
		    sizeof(mux->channel_binding))) {
		mux->malformed_rejections =
			saturating_increment_u64(
				mux->malformed_rejections);
		health_failure_locked(
			mux, adapter, true, -EKEYREJECTED, now_ms);
		(void)audit_append_locked(
			mux,
			PQCP_FLEET_TRANSPORT_AUDIT_FRAME_REJECTED,
			decoded.header.message_id,
			decoded.header.sequence, adapter_id,
			decoded.header.type,
			-EKEYREJECTED, now_ms);
		(void)k_mutex_unlock(&mux->lock);
		return -EKEYREJECTED;
	}
	type = (enum pqcp_fleet_transport_frame_type)
		decoded.header.type;
	if (type != PQCP_FLEET_TRANSPORT_FRAME_DATA) {
		replay_ret = replay_accept_locked(
			&mux->inbound_replay,
			decoded.header.sequence);
		if (replay_ret != 0) {
			if (replay_ret == -EALREADY) {
				mux->duplicate_rejections =
					saturating_increment_u64(
						mux->duplicate_rejections);
			} else {
				mux->replay_rejections =
					saturating_increment_u64(
						mux->replay_rejections);
			}
			(void)k_mutex_unlock(&mux->lock);
			return replay_ret;
		}
	}
	switch (type) {
	case PQCP_FLEET_TRANSPORT_FRAME_DATA:
		ret = ingest_data_locked(
			mux, &decoded, adapter_id,
			now_ms, &send_ack);
		if (send_ack) {
			control_message_id =
				decoded.header.message_id;
			control_ack_sequence =
				decoded.header.sequence;
			control_adapter_id = adapter_id;
		}
		break;
	case PQCP_FLEET_TRANSPORT_FRAME_ACK:
		ret = ingest_ack_locked(
			mux, &decoded.header,
			adapter_id, now_ms);
		break;
	case PQCP_FLEET_TRANSPORT_FRAME_WINDOW_UPDATE:
		ret = ingest_window_locked(
			mux, &decoded.header,
			adapter_id, now_ms);
		break;
	case PQCP_FLEET_TRANSPORT_FRAME_PROBE:
		control_message_id =
			decoded.header.message_id;
		control_ack_sequence =
			decoded.header.sequence;
		control_adapter_id = adapter_id;
		send_probe_ack = true;
		ret = 0;
		break;
	case PQCP_FLEET_TRANSPORT_FRAME_PROBE_ACK:
		ret = ingest_probe_ack_locked(
			mux, adapter, &decoded.header, now_ms);
		break;
	case PQCP_FLEET_TRANSPORT_FRAME_RESET:
		ret = ingest_reset_locked(
			mux, &decoded.header,
			adapter_id, now_ms);
		break;
	default:
		ret = -EPROTO;
		break;
	}
	if (ret == 0 || ret == -EALREADY) {
		health_success_locked(
			mux, adapter, true,
			frame_length, 0U, now_ms);
		mux->total_frames_received =
			saturating_increment_u64(
				mux->total_frames_received);
		mux->total_bytes_received =
			saturating_add_u64(
				mux->total_bytes_received,
				frame_length);
		(void)audit_append_locked(
			mux,
			PQCP_FLEET_TRANSPORT_AUDIT_FRAME_RECEIVED,
			decoded.header.message_id,
			decoded.header.sequence, adapter_id,
			decoded.header.type, ret, now_ms);
	} else {
		mux->malformed_rejections =
			saturating_increment_u64(
				mux->malformed_rejections);
		health_failure_locked(
			mux, adapter, true, ret, now_ms);
		(void)audit_append_locked(
			mux,
			PQCP_FLEET_TRANSPORT_AUDIT_FRAME_REJECTED,
			decoded.header.message_id,
			decoded.header.sequence, adapter_id,
			decoded.header.type, ret, now_ms);
	}
	(void)k_mutex_unlock(&mux->lock);
	if (send_ack) {
		int ack_ret = send_control_frame(
			mux, PQCP_FLEET_TRANSPORT_FRAME_ACK,
			control_message_id,
			control_ack_sequence, 0U,
			control_adapter_id, now_ms);

		if (ret == 0 && ack_ret != 0) {
			ret = ack_ret;
		}
	}
	if (send_probe_ack) {
		int probe_ret = send_control_frame(
			mux,
			PQCP_FLEET_TRANSPORT_FRAME_PROBE_ACK,
			control_message_id,
			control_ack_sequence, 0U,
			control_adapter_id, now_ms);

		if (ret == 0 && probe_ret != 0) {
			ret = probe_ret;
		}
	}
	return ret;
}

int pqcp_fleet_transport_poll_adapter(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms,
	bool *progressed)
{
	struct pqcp_fleet_transport_adapter *adapter;
	uint32_t generation;
	size_t frame_capacity;
	size_t received = 0U;
	int (*receive_fn)(
		void *, uint8_t *, size_t, size_t *, uint32_t);
	void *context;
	int ret;
	int receive_ret;

	if (mux == NULL || !mux->initialized ||
	    adapter_id == 0U || now_ms == 0U ||
	    progressed == NULL) {
		return -EINVAL;
	}
	*progressed = false;
	ret = k_mutex_lock(&mux->rx_lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		(void)k_mutex_unlock(&mux->rx_lock);
		return ret;
	}
	adapter = adapter_find_locked(mux, adapter_id);
	if (adapter == NULL || !adapter->enabled ||
	    !adapter->opened) {
		(void)k_mutex_unlock(&mux->lock);
		(void)k_mutex_unlock(&mux->rx_lock);
		return adapter == NULL ? -ENOENT : -ENETDOWN;
	}
	generation = adapter->generation;
	receive_fn = adapter->ops.receive;
	context = adapter->context;
	frame_capacity = mux->rx_scratch_capacity;
	if (frame_capacity > adapter->metadata.mtu) {
		frame_capacity = adapter->metadata.mtu;
	}
	(void)k_mutex_unlock(&mux->lock);
	receive_ret = receive_fn(
		context, mux->rx_scratch, frame_capacity,
		&received, mux->policy.receive_timeout_ms);
	if (receive_ret != 0) {
		if (receive_ret != -EAGAIN &&
		    receive_ret != -ETIMEDOUT) {
			ret = k_mutex_lock(&mux->lock, K_FOREVER);
			if (ret == 0) {
				adapter = adapter_find_locked(
					mux, adapter_id);
				if (adapter != NULL &&
				    adapter->generation == generation) {
					health_failure_locked(
						mux, adapter, true,
						receive_ret, now_ms);
				}
				(void)k_mutex_unlock(&mux->lock);
			}
		}
		(void)k_mutex_unlock(&mux->rx_lock);
		return receive_ret;
	}
	if (received == 0U || received > frame_capacity) {
		(void)k_mutex_unlock(&mux->rx_lock);
		return -EBADMSG;
	}
	ret = pqcp_fleet_transport_ingest(
		mux, adapter_id, mux->rx_scratch,
		received, now_ms);
	pqcp_runtime_secure_zero(
		mux->rx_scratch, received);
	(void)k_mutex_unlock(&mux->rx_lock);
	*progressed = ret == 0 || ret == -EALREADY;
	return ret;
}

int pqcp_fleet_transport_poll(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t now_ms,
	uint32_t *frames_received)
{
	uint32_t adapter_ids[
		PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS];
	size_t count = 0U;
	uint32_t received_count = 0U;
	int first_error = 0;
	int ret;

	if (mux == NULL || !mux->initialized ||
	    now_ms == 0U || frames_received == NULL) {
		return -EINVAL;
	}
	*frames_received = 0U;
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < mux->adapter_capacity; ++index) {
		const struct pqcp_fleet_transport_adapter *adapter =
			&mux->adapters[index];

		if (adapter->occupied && adapter->enabled &&
		    adapter->opened &&
		    count <
			    PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS) {
			adapter_ids[count++] =
				adapter->metadata.adapter_id;
		}
	}
	(void)k_mutex_unlock(&mux->lock);
	for (size_t index = 0U; index < count; ++index) {
		bool progressed = false;

		ret = pqcp_fleet_transport_poll_adapter(
			mux, adapter_ids[index],
			now_ms, &progressed);
		if (progressed) {
			received_count =
				saturating_increment_u32(
					received_count);
		} else if (ret != 0 && ret != -EAGAIN &&
			   ret != -ETIMEDOUT &&
			   first_error == 0) {
			first_error = ret;
		}
	}
	*frames_received = received_count;
	if (received_count != 0U) {
		return 0;
	}
	return first_error != 0 ? first_error : -EAGAIN;
}

int pqcp_fleet_transport_receive(
	struct pqcp_fleet_transport_mux *mux,
	uint8_t *message,
	size_t message_capacity,
	size_t *message_length,
	uint64_t *message_id,
	enum pqcp_fleet_transport_priority *priority,
	uint32_t *adapter_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_reassembly *selected = NULL;
	uint32_t credit;
	uint32_t preferred_adapter;
	int ret;
	int window_ret = 0;

	if (mux == NULL || !mux->initialized ||
	    message == NULL || message_capacity == 0U ||
	    message_length == NULL || message_id == NULL ||
	    priority == NULL || adapter_id == NULL ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	*message_length = 0U;
	*message_id = 0U;
	*adapter_id = 0U;
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < mux->reassembly_capacity; ++index) {
		struct pqcp_fleet_transport_reassembly *candidate =
			&mux->reassemblies[index];

		if (!candidate->occupied ||
		    candidate->state !=
			    PQCP_FLEET_TRANSPORT_REASSEMBLY_COMPLETE) {
			continue;
		}
		if (selected == NULL ||
		    candidate->priority > selected->priority ||
		    (candidate->priority == selected->priority &&
		     candidate->started_at_ms <
			     selected->started_at_ms) ||
		    (candidate->priority == selected->priority &&
		     candidate->started_at_ms ==
			     selected->started_at_ms &&
		     candidate->sequence < selected->sequence)) {
			selected = candidate;
		}
	}
	if (selected == NULL) {
		(void)k_mutex_unlock(&mux->lock);
		return -EAGAIN;
	}
	if (selected->total_length > message_capacity) {
		(void)k_mutex_unlock(&mux->lock);
		return -ENOSPC;
	}
	memcpy(message, selected->storage,
	       selected->total_length);
	*message_length = selected->total_length;
	*message_id = selected->message_id;
	*priority = selected->priority;
	*adapter_id = selected->adapter_id;
	credit = selected->total_length > UINT32_MAX ?
		UINT32_MAX : (uint32_t)selected->total_length;
	preferred_adapter = selected->adapter_id;
	if (credit > mux->policy.maximum_window -
	    mux->local_window) {
		(void)k_mutex_unlock(&mux->lock);
		pqcp_runtime_secure_zero(
			message, selected->total_length);
		return -EOVERFLOW;
	}
	mux->local_window += credit;
	mux->pending_window_credit =
		saturating_add_u32(
			mux->pending_window_credit, credit);
	mux->delivered_messages =
		saturating_increment_u64(
			mux->delivered_messages);
	(void)audit_append_locked(
		mux,
		PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_DELIVERED,
		selected->message_id, selected->sequence,
		selected->adapter_id, credit, 0, now_ms);
	reassembly_release_locked(mux, selected);
	if (mux->pending_window_credit >=
	    mux->policy.window_update_threshold) {
		credit = mux->pending_window_credit;
		mux->pending_window_credit = 0U;
	} else {
		credit = 0U;
	}
	(void)k_mutex_unlock(&mux->lock);
	if (credit != 0U) {
		window_ret = send_control_frame(
			mux,
			PQCP_FLEET_TRANSPORT_FRAME_WINDOW_UPDATE,
			0U, 0U, credit, preferred_adapter, now_ms);
		if (window_ret != 0) {
			ret = k_mutex_lock(&mux->lock, K_FOREVER);
			if (ret == 0) {
				mux->pending_window_credit =
					saturating_add_u32(
						mux->pending_window_credit,
						credit);
				(void)k_mutex_unlock(&mux->lock);
			}
		}
	}
	return window_ret;
}

int pqcp_fleet_transport_probe(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_adapter *adapter;
	uint64_t probe_id;
	uint32_t generation;
	int (*probe_fn)(void *, uint64_t, uint32_t);
	void *context;
	int ret;
	int probe_ret;

	if (mux == NULL || !mux->initialized ||
	    adapter_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	adapter = adapter_find_locked(mux, adapter_id);
	if (adapter == NULL || !adapter->enabled ||
	    !adapter->opened) {
		(void)k_mutex_unlock(&mux->lock);
		return adapter == NULL ? -ENOENT : -ENETDOWN;
	}
	if (adapter->health.probe_outstanding) {
		(void)k_mutex_unlock(&mux->lock);
		return -EALREADY;
	}
	if (mux->next_probe_id == 0U ||
	    mux->next_probe_id == UINT64_MAX) {
		(void)k_mutex_unlock(&mux->lock);
		return -EOVERFLOW;
	}
	probe_id = mux->next_probe_id++;
	adapter->health.last_probe_id = probe_id;
	adapter->health.probe_sent_at_ms = now_ms;
	adapter->health.probe_outstanding = true;
	adapter->health.probe_count =
		saturating_increment_u64(
			adapter->health.probe_count);
	generation = adapter->generation;
	probe_fn = adapter->ops.probe;
	context = adapter->context;
	health_transition_locked(
		adapter,
		PQCP_FLEET_TRANSPORT_LINK_PROBING,
		now_ms);
	(void)k_mutex_unlock(&mux->lock);
	if (probe_fn == NULL) {
		probe_ret = send_control_frame(
			mux, PQCP_FLEET_TRANSPORT_FRAME_PROBE,
			probe_id, 0U, 0U, adapter_id, now_ms);
	} else {
		probe_ret = probe_fn(
			context, probe_id,
			mux->policy.send_timeout_ms);
	}
	if (probe_ret == 0) {
		return 0;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	adapter = adapter_find_locked(mux, adapter_id);
	if (adapter != NULL &&
	    adapter->generation == generation &&
	    adapter->health.last_probe_id == probe_id) {
		adapter->health.probe_outstanding = false;
		adapter->health.probe_failures =
			saturating_increment_u64(
				adapter->health.probe_failures);
		health_failure_locked(
			mux, adapter, false,
			probe_ret, now_ms);
	}
	(void)k_mutex_unlock(&mux->lock);
	return probe_ret;
}

int pqcp_fleet_transport_report_link_result(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	int result,
	uint64_t rtt_us,
	uint64_t now_ms)
{
	struct pqcp_fleet_transport_adapter *adapter;
	int ret;

	if (mux == NULL || !mux->initialized ||
	    adapter_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	adapter = adapter_find_locked(mux, adapter_id);
	if (adapter == NULL) {
		(void)k_mutex_unlock(&mux->lock);
		return -ENOENT;
	}
	adapter->health.probe_outstanding = false;
	if (result == 0) {
		health_success_locked(
			mux, adapter, true, 0U,
			rtt_us, now_ms);
		(void)audit_append_locked(
			mux,
			PQCP_FLEET_TRANSPORT_AUDIT_PROBE_ACKED,
			adapter->health.last_probe_id, 0U,
			adapter_id,
			rtt_us > UINT32_MAX ?
				UINT32_MAX : (uint32_t)rtt_us,
			0, now_ms);
	} else {
		adapter->health.probe_failures =
			saturating_increment_u64(
				adapter->health.probe_failures);
		health_failure_locked(
			mux, adapter, true,
			result, now_ms);
	}
	(void)k_mutex_unlock(&mux->lock);
	return 0;
}

int pqcp_fleet_transport_tick(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t now_ms,
	uint32_t *state_changes)
{
	uint32_t probe_ids[
		PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS];
	size_t probe_count = 0U;
	uint32_t changes = 0U;
	uint32_t window_credit = 0U;
	uint32_t window_adapter = 0U;
	int first_error = 0;
	int ret;

	if (mux == NULL || !mux->initialized ||
	    now_ms == 0U || state_changes == NULL) {
		return -EINVAL;
	}
	*state_changes = 0U;
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < mux->message_capacity;
	     ++index) {
		struct pqcp_fleet_transport_message *message =
			&mux->messages[index];

		if (!message->occupied) {
			continue;
		}
		if (now_ms > message->expires_at_ms) {
			mux->expired_messages =
				saturating_increment_u64(
					mux->expired_messages);
			(void)audit_append_locked(
				mux,
				PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_DROPPED,
				message->message_id, message->sequence,
				message->active_adapter_id, 0U,
				-ETIMEDOUT, now_ms);
			message_release_locked(mux, message);
			changes =
				saturating_increment_u32(changes);
			continue;
		}
		if (message->state ==
			    PQCP_FLEET_TRANSPORT_MESSAGE_WAITING_ACK &&
		    now_ms >
			    message->acknowledgement_deadline_ms) {
			(void)message_schedule_retry_locked(
				mux, message, -ETIMEDOUT, now_ms);
			changes =
				saturating_increment_u32(changes);
			continue;
		}
		if (message->state ==
			    PQCP_FLEET_TRANSPORT_MESSAGE_RETRY_WAIT &&
		    now_ms >= message->next_attempt_ms) {
			message->state =
				PQCP_FLEET_TRANSPORT_MESSAGE_QUEUED;
			changes =
				saturating_increment_u32(changes);
			continue;
		}
		if (message->state ==
		    PQCP_FLEET_TRANSPORT_MESSAGE_FAILED) {
			message_release_locked(mux, message);
			changes =
				saturating_increment_u32(changes);
		}
	}
	for (size_t index = 0U;
	     index < mux->reassembly_capacity; ++index) {
		struct pqcp_fleet_transport_reassembly *reassembly =
			&mux->reassemblies[index];

		if (!reassembly->occupied ||
		    reassembly->state !=
			    PQCP_FLEET_TRANSPORT_REASSEMBLY_RECEIVING ||
		    now_ms <= reassembly->last_fragment_at_ms ||
		    now_ms - reassembly->last_fragment_at_ms <=
			    mux->policy.reassembly_timeout_ms) {
			continue;
		}
		if (reassembly->received_length >
		    mux->policy.maximum_window -
			    mux->local_window) {
			first_error = first_error == 0 ?
				-EOVERFLOW : first_error;
		} else {
			uint32_t credit =
				(uint32_t)reassembly->received_length;

			mux->local_window += credit;
			mux->pending_window_credit =
				saturating_add_u32(
					mux->pending_window_credit,
					credit);
		}
		(void)audit_append_locked(
			mux,
			PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_DROPPED,
			reassembly->message_id,
			reassembly->sequence,
			reassembly->adapter_id,
			(uint32_t)reassembly->received_length,
			-ETIMEDOUT, now_ms);
		reassembly_release_locked(mux, reassembly);
		changes = saturating_increment_u32(changes);
	}
	for (size_t index = 0U;
	     index < mux->adapter_capacity; ++index) {
		struct pqcp_fleet_transport_adapter *adapter =
			&mux->adapters[index];
		bool probe_due = false;

		if (!adapter->occupied || !adapter->enabled ||
		    !adapter->opened) {
			continue;
		}
		if (adapter->health.state ==
			    PQCP_FLEET_TRANSPORT_LINK_BACKOFF &&
		    now_ms >= adapter->health.backoff_until_ms) {
			adapter->health.consecutive_failures = 0U;
			adapter->health.consecutive_successes = 0U;
			health_transition_locked(
				adapter,
				PQCP_FLEET_TRANSPORT_LINK_PROBING,
				now_ms);
			changes =
				saturating_increment_u32(changes);
		}
		if (adapter->health.probe_outstanding &&
		    now_ms >
			    adapter->health.probe_sent_at_ms &&
		    now_ms - adapter->health.probe_sent_at_ms >
			    mux->policy.probe_timeout_ms) {
			adapter->health.probe_outstanding = false;
			adapter->health.probe_failures =
				saturating_increment_u64(
					adapter->health.probe_failures);
			health_failure_locked(
				mux, adapter, true,
				-ETIMEDOUT, now_ms);
			changes =
				saturating_increment_u32(changes);
		}
		if (!adapter->health.probe_outstanding) {
			uint64_t last_activity =
				adapter->health.last_success_ms;

			if (last_activity == 0U) {
				last_activity =
					adapter->health.
					last_state_change_ms;
			}
			probe_due =
				now_ms > last_activity &&
				now_ms - last_activity >=
					mux->policy.probe_interval_ms;
		}
		if (probe_due &&
		    probe_count <
			    PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS) {
			probe_ids[probe_count++] =
				adapter->metadata.adapter_id;
		}
	}
	if (mux->pending_window_credit >=
	    mux->policy.window_update_threshold) {
		window_credit = mux->pending_window_credit;
		mux->pending_window_credit = 0U;
		window_adapter = mux->sticky_adapter_id;
	}
	(void)k_mutex_unlock(&mux->lock);
	if (window_credit != 0U) {
		ret = send_control_frame(
			mux,
			PQCP_FLEET_TRANSPORT_FRAME_WINDOW_UPDATE,
			0U, 0U, window_credit,
			window_adapter, now_ms);
		if (ret != 0) {
			int lock_ret =
				k_mutex_lock(&mux->lock, K_FOREVER);

			if (lock_ret == 0) {
				mux->pending_window_credit =
					saturating_add_u32(
						mux->pending_window_credit,
						window_credit);
				(void)k_mutex_unlock(&mux->lock);
			}
			if (first_error == 0) {
				first_error = ret;
			}
		}
	}
	for (size_t index = 0U; index < probe_count; ++index) {
		ret = pqcp_fleet_transport_probe(
			mux, probe_ids[index], now_ms);
		if (ret != 0 && ret != -EALREADY &&
		    first_error == 0) {
			first_error = ret;
		}
	}
	*state_changes = changes;
	return first_error;
}

static size_t adapter_snapshot_encode(
	const struct pqcp_fleet_transport_adapter_snapshot *snapshot,
	uint8_t output[TRANSPORT_ADAPTER_SNAPSHOT_BYTES])
{
	size_t offset = 0U;

	memset(output, 0, TRANSPORT_ADAPTER_SNAPSHOT_BYTES);
	offset = append_u32(output, offset, snapshot->adapter_id);
	offset = append_u32(output, offset, snapshot->generation);
	offset = append_u32(
		output, offset, snapshot->capabilities);
	offset = append_u32(output, offset, snapshot->mtu);
	offset = append_u32(output, offset, snapshot->route_score);
	offset = append_u32(
		output, offset, (uint32_t)snapshot->state);
	offset = append_u64(
		output, offset, snapshot->smoothed_rtt_us);
	offset = append_u64(
		output, offset, snapshot->bytes_sent);
	offset = append_u64(
		output, offset, snapshot->bytes_received);
	offset = append_u64(
		output, offset, snapshot->frames_sent);
	offset = append_u64(
		output, offset, snapshot->frames_received);
	offset = append_u64(
		output, offset, snapshot->send_failures);
	offset = append_u64(
		output, offset, snapshot->receive_failures);
	offset = append_u32(
		output, offset, snapshot->consecutive_failures);
	offset = append_i32(output, offset, snapshot->last_error);
	output[offset++] = snapshot->enabled ? 1U : 0U;
	output[offset++] = snapshot->opened ? 1U : 0U;
	return offset;
}

static size_t snapshot_body(
	const struct pqcp_fleet_transport_snapshot *snapshot,
	uint8_t output[TRANSPORT_SNAPSHOT_BODY_BYTES])
{
	size_t offset = 0U;

	if (snapshot == NULL || output == NULL ||
	    snapshot->schema_version !=
		    PQCP_FLEET_TRANSPORT_SCHEMA_VERSION ||
	    snapshot->captured_at_ms == 0U ||
	    snapshot->channel_id == 0U ||
	    snapshot->adapter_count >
		    PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS ||
	    digest_zero(
		    snapshot->channel_binding,
		    sizeof(snapshot->channel_binding))) {
		return 0U;
	}
	memset(output, 0, TRANSPORT_SNAPSHOT_BODY_BYTES);
	memcpy(output + offset, TRANSPORT_SNAPSHOT_LABEL,
	       sizeof(TRANSPORT_SNAPSHOT_LABEL) - 1U);
	offset += sizeof(TRANSPORT_SNAPSHOT_LABEL) - 1U;
	offset = append_u32(
		output, offset, snapshot->schema_version);
	offset = append_u64(
		output, offset, snapshot->captured_at_ms);
	offset = append_u64(output, offset, snapshot->channel_id);
	offset = append_u64(
		output, offset, snapshot->next_message_id);
	offset = append_u64(
		output, offset, snapshot->next_send_sequence);
	offset = append_u64(
		output, offset, snapshot->highest_receive_sequence);
	offset = append_u64(
		output, offset, snapshot->total_frames_sent);
	offset = append_u64(
		output, offset, snapshot->total_frames_received);
	offset = append_u64(
		output, offset, snapshot->total_bytes_sent);
	offset = append_u64(
		output, offset, snapshot->total_bytes_received);
	offset = append_u64(
		output, offset, snapshot->acknowledged_messages);
	offset = append_u64(
		output, offset, snapshot->delivered_messages);
	offset = append_u64(
		output, offset, snapshot->retry_count);
	offset = append_u64(
		output, offset, snapshot->failover_count);
	offset = append_u64(
		output, offset, snapshot->duplicate_rejections);
	offset = append_u64(
		output, offset, snapshot->replay_rejections);
	offset = append_u64(
		output, offset, snapshot->malformed_rejections);
	offset = append_u64(
		output, offset, snapshot->expired_messages);
	offset = append_u32(
		output, offset, snapshot->remote_window);
	offset = append_u32(
		output, offset, snapshot->local_window);
	for (size_t priority = 0U;
	     priority < PQCP_FLEET_TRANSPORT_PRIORITY_COUNT;
	     ++priority) {
		offset = append_u32(
			output, offset,
			snapshot->queued_by_priority[priority]);
	}
	offset = append_u64(
		output, offset, snapshot->adapter_count);
	offset = append_u64(
		output, offset, snapshot->reassembly_count);
	offset = append_u64(
		output, offset, snapshot->audit_count);
	memcpy(output + offset, snapshot->channel_binding,
	       sizeof(snapshot->channel_binding));
	offset += sizeof(snapshot->channel_binding);
	memcpy(output + offset, snapshot->audit_chain_head,
	       sizeof(snapshot->audit_chain_head));
	offset += sizeof(snapshot->audit_chain_head);
	return offset <= TRANSPORT_SNAPSHOT_BODY_BYTES ?
		offset : 0U;
}

static int snapshot_digest_calculate(
	const struct pqcp_fleet_transport_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	const uint8_t *parts[
		PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS + 1U];
	size_t lengths[
		PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS + 1U];
	uint8_t body[TRANSPORT_SNAPSHOT_BODY_BYTES];
	uint8_t adapters[
		PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS]
		[TRANSPORT_ADAPTER_SNAPSHOT_BYTES];
	size_t body_length;

	if (snapshot == NULL || digest == NULL ||
	    (snapshot->adapter_count != 0U &&
	     snapshot->adapters == NULL) ||
	    snapshot->adapter_count >
		    PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS) {
		return -EINVAL;
	}
	body_length = snapshot_body(snapshot, body);
	if (body_length == 0U) {
		return -EINVAL;
	}
	parts[0] = body;
	lengths[0] = body_length;
	for (size_t index = 0U;
	     index < snapshot->adapter_count; ++index) {
		size_t length = adapter_snapshot_encode(
			&snapshot->adapters[index],
			adapters[index]);

		parts[index + 1U] = adapters[index];
		lengths[index + 1U] = length;
	}
	int ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths,
		snapshot->adapter_count + 1U, digest);

	pqcp_runtime_secure_zero(body, sizeof(body));
	pqcp_runtime_secure_zero(adapters, sizeof(adapters));
	return ret;
}

int pqcp_fleet_transport_snapshot(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t now_ms,
	struct pqcp_fleet_transport_snapshot *snapshot)
{
	struct pqcp_fleet_transport_adapter_snapshot *adapters;
	size_t adapter_capacity;
	int ret;

	if (mux == NULL || !mux->initialized ||
	    now_ms == 0U || snapshot == NULL) {
		return -EINVAL;
	}
	adapters = snapshot->adapters;
	adapter_capacity = snapshot->adapter_capacity;
	if (adapters == NULL ||
	    adapter_capacity < mux->adapter_count ||
	    adapter_capacity >
		    PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS) {
		return -ENOSPC;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->adapters = adapters;
	snapshot->adapter_capacity = adapter_capacity;
	snapshot->schema_version =
		PQCP_FLEET_TRANSPORT_SCHEMA_VERSION;
	snapshot->captured_at_ms = now_ms;
	snapshot->channel_id = mux->channel_id;
	snapshot->next_message_id = mux->next_message_id;
	snapshot->next_send_sequence = mux->next_send_sequence;
	snapshot->highest_receive_sequence =
		mux->inbound_replay.highest_sequence;
	snapshot->total_frames_sent = mux->total_frames_sent;
	snapshot->total_frames_received =
		mux->total_frames_received;
	snapshot->total_bytes_sent = mux->total_bytes_sent;
	snapshot->total_bytes_received =
		mux->total_bytes_received;
	snapshot->acknowledged_messages =
		mux->acknowledged_messages;
	snapshot->delivered_messages = mux->delivered_messages;
	snapshot->retry_count = mux->retry_count;
	snapshot->failover_count = mux->failover_count;
	snapshot->duplicate_rejections =
		mux->duplicate_rejections;
	snapshot->replay_rejections = mux->replay_rejections;
	snapshot->malformed_rejections =
		mux->malformed_rejections;
	snapshot->expired_messages = mux->expired_messages;
	snapshot->remote_window = mux->remote_window;
	snapshot->local_window = mux->local_window;
	snapshot->reassembly_count = mux->reassembly_count;
	snapshot->audit_count = mux->audit_count;
	memcpy(snapshot->channel_binding, mux->channel_binding,
	       sizeof(snapshot->channel_binding));
	memcpy(snapshot->audit_chain_head, mux->audit_chain_head,
	       sizeof(snapshot->audit_chain_head));
	for (size_t index = 0U; index < mux->message_capacity;
	     ++index) {
		const struct pqcp_fleet_transport_message *message =
			&mux->messages[index];

		if (message->occupied &&
		    priority_valid(message->priority)) {
			snapshot->queued_by_priority[
				message->priority]++;
		}
	}
	for (size_t index = 0U;
	     index < mux->adapter_capacity; ++index) {
		const struct pqcp_fleet_transport_adapter *adapter =
			&mux->adapters[index];
		struct pqcp_fleet_transport_adapter_snapshot *item;
		uint32_t score = 0U;

		if (!adapter->occupied) {
			continue;
		}
		item = &snapshot->adapters[
			snapshot->adapter_count++];
		(void)pqcp_fleet_transport_route_score(
			mux, adapter, 0U, 1U, now_ms, &score);
		item->adapter_id = adapter->metadata.adapter_id;
		item->generation = adapter->generation;
		item->capabilities =
			adapter->metadata.capabilities;
		item->mtu = adapter->metadata.mtu;
		item->route_score = score;
		item->state = adapter->health.state;
		item->smoothed_rtt_us =
			adapter->health.smoothed_rtt_us;
		item->bytes_sent = adapter->health.bytes_sent;
		item->bytes_received =
			adapter->health.bytes_received;
		item->frames_sent = adapter->health.frames_sent;
		item->frames_received =
			adapter->health.frames_received;
		item->send_failures =
			adapter->health.send_failures;
		item->receive_failures =
			adapter->health.receive_failures;
		item->consecutive_failures =
			adapter->health.consecutive_failures;
		item->last_error = adapter->health.last_error;
		item->enabled = adapter->enabled;
		item->opened = adapter->opened;
	}
	(void)k_mutex_unlock(&mux->lock);
	return snapshot_digest_calculate(
		snapshot, snapshot->snapshot_digest);
}

int pqcp_fleet_transport_snapshot_verify(
	const struct pqcp_fleet_transport_snapshot *snapshot)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (snapshot == NULL ||
	    snapshot->schema_version !=
		    PQCP_FLEET_TRANSPORT_SCHEMA_VERSION ||
	    snapshot->captured_at_ms == 0U ||
	    snapshot->channel_id == 0U ||
	    snapshot->next_message_id == 0U ||
	    snapshot->next_send_sequence == 0U ||
	    snapshot->remote_window == 0U ||
	    snapshot->local_window == 0U ||
	    snapshot->adapter_count >
		    snapshot->adapter_capacity ||
	    snapshot->adapter_count >
		    PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS ||
	    (snapshot->adapter_count != 0U &&
	     snapshot->adapters == NULL) ||
	    digest_zero(
		    snapshot->snapshot_digest,
		    sizeof(snapshot->snapshot_digest))) {
		return -EINVAL;
	}
	for (size_t left = 0U;
	     left < snapshot->adapter_count; ++left) {
		const struct pqcp_fleet_transport_adapter_snapshot *item =
			&snapshot->adapters[left];

		if (item->adapter_id == 0U ||
		    item->mtu < PQCP_FLEET_TRANSPORT_MIN_MTU ||
		    !link_state_valid(item->state) ||
		    (item->capabilities &
		     ~PQCP_FLEET_TRANSPORT_CAP_KNOWN_MASK) != 0U) {
			return -EBADMSG;
		}
		for (size_t right = left + 1U;
		     right < snapshot->adapter_count; ++right) {
			if (snapshot->adapters[right].adapter_id ==
			    item->adapter_id) {
				return -EEXIST;
			}
		}
	}
	ret = snapshot_digest_calculate(snapshot, digest);
	if (ret == 0 &&
	    !digest_equal(
		    digest, snapshot->snapshot_digest,
		    sizeof(digest))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int adapter_audit(
	const struct pqcp_fleet_transport_adapter *adapter)
{
	if (!adapter->occupied) {
		return 0;
	}
	if (metadata_validate(&adapter->metadata) != 0 ||
	    ops_validate(&adapter->ops) != 0 ||
	    adapter->generation == 0U ||
	    !link_state_valid(adapter->health.state) ||
	    (adapter->enabled &&
	     adapter->health.state ==
		     PQCP_FLEET_TRANSPORT_LINK_DISABLED) ||
	    (!adapter->enabled &&
	     adapter->health.state !=
		     PQCP_FLEET_TRANSPORT_LINK_DISABLED) ||
	    (adapter->opened && !adapter->enabled) ||
	    (adapter->health.consecutive_failures != 0U &&
	     adapter->health.consecutive_successes != 0U) ||
	    (adapter->health.probe_outstanding &&
	     (adapter->health.last_probe_id == 0U ||
	      adapter->health.probe_sent_at_ms == 0U))) {
		return -EBADMSG;
	}
	return 0;
}

static int message_audit(
	const struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_message *message,
	size_t index)
{
	uint8_t *expected_storage =
		mux->message_storage +
		index * mux->message_slot_bytes;

	if (message->storage != expected_storage ||
	    message->storage_capacity !=
		    mux->message_slot_bytes) {
		return -EBADMSG;
	}
	if (!message->occupied) {
		if (message->state !=
		    PQCP_FLEET_TRANSPORT_MESSAGE_FREE) {
			return -EBADMSG;
		}
		return 0;
	}
	if (message->message_id == 0U ||
	    message->sequence == 0U ||
	    message->enqueued_at_ms == 0U ||
	    message->expires_at_ms <=
		    message->enqueued_at_ms ||
	    message->length == 0U ||
	    message->length > message->storage_capacity ||
	    message->next_offset > message->length ||
	    !priority_valid(message->priority) ||
	    !message_state_valid(message->state) ||
	    message->state ==
		    PQCP_FLEET_TRANSPORT_MESSAGE_FREE ||
	    (message->required_capabilities &
	     ~PQCP_FLEET_TRANSPORT_CAP_KNOWN_MASK) != 0U ||
	    message->attempts >
		    mux->policy.maximum_attempts) {
		return -EBADMSG;
	}
	if (message->state ==
		    PQCP_FLEET_TRANSPORT_MESSAGE_WAITING_ACK &&
	    (!message->acknowledgement_required ||
	     message->next_offset != message->length ||
	     message->acknowledgement_deadline_ms == 0U)) {
		return -EBADMSG;
	}
	if ((message->state ==
		     PQCP_FLEET_TRANSPORT_MESSAGE_QUEUED ||
	     message->state ==
		     PQCP_FLEET_TRANSPORT_MESSAGE_RETRY_WAIT) &&
	    message->next_offset != 0U) {
		return -EBADMSG;
	}
	return 0;
}

static int reassembly_audit(
	const struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_reassembly *reassembly,
	size_t index)
{
	uint8_t *expected_storage =
		mux->reassembly_storage +
		index * mux->reassembly_slot_bytes;

	if (reassembly->storage != expected_storage ||
	    reassembly->storage_capacity !=
		    mux->reassembly_slot_bytes) {
		return -EBADMSG;
	}
	if (!reassembly->occupied) {
		if (reassembly->state !=
		    PQCP_FLEET_TRANSPORT_REASSEMBLY_FREE) {
			return -EBADMSG;
		}
		return 0;
	}
	if (reassembly->message_id == 0U ||
	    reassembly->sequence == 0U ||
	    reassembly->started_at_ms == 0U ||
	    reassembly->last_fragment_at_ms <
		    reassembly->started_at_ms ||
	    reassembly->total_length == 0U ||
	    reassembly->total_length >
		    reassembly->storage_capacity ||
	    reassembly->received_length >
		    reassembly->total_length ||
	    reassembly->adapter_id == 0U ||
	    !priority_valid(reassembly->priority) ||
	    !reassembly_state_valid(reassembly->state) ||
	    reassembly->state ==
		    PQCP_FLEET_TRANSPORT_REASSEMBLY_FREE) {
		return -EBADMSG;
	}
	if (reassembly->state ==
		    PQCP_FLEET_TRANSPORT_REASSEMBLY_COMPLETE &&
	    (reassembly->received_length !=
		     reassembly->total_length ||
	     digest_zero(
		     reassembly->message_digest,
		     sizeof(reassembly->message_digest)))) {
		return -EBADMSG;
	}
	return 0;
}

static const struct pqcp_fleet_transport_audit_entry *
audit_entry_by_sequence(
	const struct pqcp_fleet_transport_mux *mux,
	uint64_t sequence)
{
	for (size_t index = 0U; index < mux->audit_capacity;
	     ++index) {
		if (mux->audit_entries[index].occupied &&
		    mux->audit_entries[index].sequence == sequence) {
			return &mux->audit_entries[index];
		}
	}
	return NULL;
}

static int audit_log_audit(
	const struct pqcp_fleet_transport_mux *mux)
{
	const struct pqcp_fleet_transport_audit_entry *latest = NULL;
	size_t occupied = 0U;

	if (mux->audit_capacity == 0U) {
		return mux->audit_count == 0U &&
		       mux->audit_next == 0U &&
		       digest_zero(
			       mux->audit_chain_head,
			       sizeof(mux->audit_chain_head)) ?
			0 : -EBADMSG;
	}
	if (mux->audit_entries == NULL ||
	    mux->audit_count > mux->audit_capacity ||
	    mux->audit_next >= mux->audit_capacity) {
		return -EBADMSG;
	}
	for (size_t index = 0U; index < mux->audit_capacity;
	     ++index) {
		const struct pqcp_fleet_transport_audit_entry *entry =
			&mux->audit_entries[index];
		uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
		int ret;

		if (!entry->occupied) {
			continue;
		}
		if (entry->schema_version !=
			    PQCP_FLEET_TRANSPORT_SCHEMA_VERSION ||
		    entry->sequence == 0U ||
		    entry->timestamp_ms == 0U ||
		    !audit_event_valid(entry->event)) {
			return -EBADMSG;
		}
		ret = audit_digest(entry, digest);
		if (ret != 0 ||
		    !digest_equal(
			    digest, entry->entry_digest,
			    sizeof(digest))) {
			pqcp_runtime_secure_zero(
				digest, sizeof(digest));
			return ret != 0 ? ret : -EBADMSG;
		}
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		for (size_t other = index + 1U;
		     other < mux->audit_capacity; ++other) {
			if (mux->audit_entries[other].occupied &&
			    mux->audit_entries[other].sequence ==
				    entry->sequence) {
				return -EEXIST;
			}
		}
		if (entry->sequence > 1U) {
			const struct pqcp_fleet_transport_audit_entry
				*previous = audit_entry_by_sequence(
					mux, entry->sequence - 1U);

			if (previous != NULL &&
			    !digest_equal(
				    entry->previous_digest,
				    previous->entry_digest,
				    sizeof(entry->previous_digest))) {
				return -EBADMSG;
			}
		}
		if (latest == NULL ||
		    entry->sequence > latest->sequence) {
			latest = entry;
		}
		occupied++;
	}
	if (occupied != mux->audit_count) {
		return -EBADMSG;
	}
	if (latest == NULL) {
		return digest_zero(
			       mux->audit_chain_head,
			       sizeof(mux->audit_chain_head)) ?
			0 : -EBADMSG;
	}
	if (!digest_equal(
		    latest->entry_digest, mux->audit_chain_head,
		    sizeof(mux->audit_chain_head)) ||
	    mux->next_audit_sequence <= latest->sequence) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_fleet_transport_audit(
	struct pqcp_fleet_transport_mux *mux)
{
	size_t adapters = 0U;
	size_t messages = 0U;
	size_t reassemblies = 0U;
	int ret;

	if (mux == NULL || !mux->initialized ||
	    mux->schema_version !=
		    PQCP_FLEET_TRANSPORT_SCHEMA_VERSION ||
	    policy_validate(&mux->policy) != 0 ||
	    mux->adapters == NULL ||
	    mux->adapter_capacity == 0U ||
	    mux->adapter_capacity >
		    PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS ||
	    mux->messages == NULL ||
	    mux->message_capacity == 0U ||
	    mux->message_storage == NULL ||
	    mux->message_slot_bytes == 0U ||
	    mux->reassemblies == NULL ||
	    mux->reassembly_capacity == 0U ||
	    mux->reassembly_storage == NULL ||
	    mux->reassembly_slot_bytes == 0U ||
	    mux->tx_scratch == NULL ||
	    mux->tx_scratch_capacity <
		    PQCP_FLEET_TRANSPORT_MIN_MTU ||
	    mux->rx_scratch == NULL ||
	    mux->rx_scratch_capacity <
		    PQCP_FLEET_TRANSPORT_MIN_MTU ||
	    mux->remote_window > mux->policy.maximum_window ||
	    mux->local_window > mux->policy.maximum_window ||
	    mux->next_message_id == 0U ||
	    mux->next_send_sequence == 0U ||
	    mux->next_probe_id == 0U) {
		return -EINVAL;
	}
	if (mux->channel_bound &&
	    (mux->channel_id == 0U ||
	     digest_zero(
		     mux->channel_binding,
		     sizeof(mux->channel_binding)))) {
		return -EBADMSG;
	}
	if (!mux->channel_bound &&
	    (mux->channel_id != 0U ||
	     !digest_zero(
		     mux->channel_binding,
		     sizeof(mux->channel_binding)) ||
	     mux->message_count != 0U ||
	     mux->reassembly_count != 0U)) {
		return -EBADMSG;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t left = 0U;
	     left < mux->adapter_capacity; ++left) {
		const struct pqcp_fleet_transport_adapter *adapter =
			&mux->adapters[left];

		ret = adapter_audit(adapter);
		if (ret != 0) {
			goto out;
		}
		if (!adapter->occupied) {
			continue;
		}
		for (size_t right = left + 1U;
		     right < mux->adapter_capacity; ++right) {
			if (mux->adapters[right].occupied &&
			    mux->adapters[right].metadata.adapter_id ==
				    adapter->metadata.adapter_id) {
				ret = -EEXIST;
				goto out;
			}
		}
		adapters++;
	}
	for (size_t left = 0U;
	     left < mux->message_capacity; ++left) {
		const struct pqcp_fleet_transport_message *message =
			&mux->messages[left];

		ret = message_audit(mux, message, left);
		if (ret != 0) {
			goto out;
		}
		if (!message->occupied) {
			continue;
		}
		for (size_t right = left + 1U;
		     right < mux->message_capacity; ++right) {
			if (mux->messages[right].occupied &&
			    (mux->messages[right].message_id ==
				     message->message_id ||
			     mux->messages[right].sequence ==
				     message->sequence)) {
				ret = -EEXIST;
				goto out;
			}
		}
		messages++;
	}
	for (size_t left = 0U;
	     left < mux->reassembly_capacity; ++left) {
		const struct pqcp_fleet_transport_reassembly *reassembly =
			&mux->reassemblies[left];

		ret = reassembly_audit(mux, reassembly, left);
		if (ret != 0) {
			goto out;
		}
		if (!reassembly->occupied) {
			continue;
		}
		for (size_t right = left + 1U;
		     right < mux->reassembly_capacity; ++right) {
			if (mux->reassemblies[right].occupied &&
			    (mux->reassemblies[right].message_id ==
				     reassembly->message_id ||
			     mux->reassemblies[right].sequence ==
				     reassembly->sequence)) {
				ret = -EEXIST;
				goto out;
			}
		}
		reassemblies++;
	}
	if (adapters != mux->adapter_count ||
	    messages != mux->message_count ||
	    reassemblies != mux->reassembly_count) {
		ret = -EBADMSG;
		goto out;
	}
	if (mux->sticky_adapter_id != 0U &&
	    adapter_find_const(
		    mux, mux->sticky_adapter_id) == NULL) {
		ret = -EBADMSG;
		goto out;
	}
	ret = audit_log_audit(mux);
out:
	(void)k_mutex_unlock(&mux->lock);
	return ret;
}

int pqcp_fleet_transport_reset(
	struct pqcp_fleet_transport_mux *mux,
	bool retain_adapters,
	uint64_t now_ms)
{
	int ret;

	if (mux == NULL || !mux->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&mux->tx_lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&mux->rx_lock, K_FOREVER);
	if (ret != 0) {
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	ret = k_mutex_lock(&mux->lock, K_FOREVER);
	if (ret != 0) {
		(void)k_mutex_unlock(&mux->rx_lock);
		(void)k_mutex_unlock(&mux->tx_lock);
		return ret;
	}
	for (size_t index = 0U; index < mux->message_capacity;
	     ++index) {
		if (mux->messages[index].occupied) {
			message_release_locked(
				mux, &mux->messages[index]);
		}
	}
	for (size_t index = 0U;
	     index < mux->reassembly_capacity; ++index) {
		if (mux->reassemblies[index].occupied) {
			reassembly_release_locked(
				mux, &mux->reassemblies[index]);
		}
	}
	if (!retain_adapters) {
		memset(mux->adapters, 0,
		       mux->adapter_capacity *
			       sizeof(*mux->adapters));
		mux->adapter_count = 0U;
		if (mux->audit_entries != NULL) {
			memset(mux->audit_entries, 0,
			       mux->audit_capacity *
				       sizeof(*mux->audit_entries));
		}
		mux->audit_count = 0U;
		mux->audit_next = 0U;
		mux->next_audit_sequence = 1U;
		memset(mux->audit_chain_head, 0,
		       sizeof(mux->audit_chain_head));
	} else {
		for (size_t index = 0U;
		     index < mux->adapter_capacity; ++index) {
			struct pqcp_fleet_transport_adapter *adapter =
				&mux->adapters[index];

			if (!adapter->occupied) {
				continue;
			}
			adapter->health.probe_outstanding = false;
			adapter->health.last_probe_id = 0U;
			adapter->health.probe_sent_at_ms = 0U;
			if (adapter->enabled && adapter->opened) {
				health_transition_locked(
					adapter,
					PQCP_FLEET_TRANSPORT_LINK_PROBING,
					now_ms);
			}
		}
	}
	mux->channel_id = 0U;
	mux->next_message_id = 1U;
	mux->next_send_sequence = 1U;
	mux->next_probe_id = 1U;
	mux->total_frames_sent = 0U;
	mux->total_frames_received = 0U;
	mux->total_bytes_sent = 0U;
	mux->total_bytes_received = 0U;
	mux->acknowledged_messages = 0U;
	mux->delivered_messages = 0U;
	mux->retry_count = 0U;
	mux->failover_count = 0U;
	mux->duplicate_rejections = 0U;
	mux->replay_rejections = 0U;
	mux->malformed_rejections = 0U;
	mux->expired_messages = 0U;
	mux->remote_window = mux->policy.initial_remote_window;
	mux->local_window = mux->policy.initial_local_window;
	mux->pending_window_credit = 0U;
	mux->sticky_adapter_id = 0U;
	mux->inbound_replay =
		(struct pqcp_fleet_transport_replay_state){0};
	pqcp_runtime_secure_zero(
		mux->channel_binding,
		sizeof(mux->channel_binding));
	pqcp_runtime_secure_zero(
		mux->tx_scratch, mux->tx_scratch_capacity);
	pqcp_runtime_secure_zero(
		mux->rx_scratch, mux->rx_scratch_capacity);
	mux->channel_bound = false;
	(void)k_mutex_unlock(&mux->lock);
	(void)k_mutex_unlock(&mux->rx_lock);
	(void)k_mutex_unlock(&mux->tx_lock);
	return 0;
}
