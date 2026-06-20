/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Hash-chained runtime event journal and bounded subscriptions.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/runtime_operations.h>

#include "runtime_internal.h"

static bool event_kind_valid(enum pqcp_runtime_event_kind kind)
{
	return kind > PQCP_RUNTIME_EVENT_NONE &&
	       kind < PQCP_RUNTIME_EVENT_KIND_COUNT;
}

static bool event_severity_valid(
	enum pqcp_runtime_event_severity severity)
{
	return severity >= PQCP_RUNTIME_EVENT_DEBUG &&
	       severity <= PQCP_RUNTIME_EVENT_CRITICAL;
}

static bool event_filter_valid(
	const struct pqcp_runtime_event_filter *filter)
{
	if (filter == NULL) {
		return true;
	}
	if ((filter->severity_mask & ~UINT32_C(0x3f)) != 0U) {
		return false;
	}
	if (filter->maximum_sequence != 0U &&
	    filter->maximum_sequence < filter->minimum_sequence) {
		return false;
	}
	return true;
}

static bool event_matches(
	const struct pqcp_runtime_event *event,
	const struct pqcp_runtime_event_filter *filter)
{
	uint32_t kind_bit = 0U;

	if (filter == NULL) {
		return true;
	}
	if (event->sequence < filter->minimum_sequence) {
		return false;
	}
	if (filter->maximum_sequence != 0U &&
	    event->sequence > filter->maximum_sequence) {
		return false;
	}
	if (filter->match_subject &&
	    event->subject_id != filter->subject_id) {
		return false;
	}
	if (!filter->include_debug &&
	    event->severity == PQCP_RUNTIME_EVENT_DEBUG) {
		return false;
	}
	if (filter->severity_mask != 0U &&
	    (filter->severity_mask &
	     BIT((uint32_t)event->severity)) == 0U) {
		return false;
	}
	if ((uint32_t)event->kind < 32U) {
		kind_bit = BIT((uint32_t)event->kind);
	}
	if (filter->kind_mask_low != 0U &&
	    (filter->kind_mask_low & kind_bit) == 0U) {
		return false;
	}
	return true;
}

static int event_digest(
	const struct pqcp_runtime_event *event,
	uint8_t digest[PQCP_RUNTIME_EVENT_CHAIN_BYTES])
{
	uint8_t header[48];
	const uint8_t *parts[4];
	size_t lengths[4];

	if (event == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(header, 0, sizeof(header));
	pqcp_runtime_internal_write_u32(
		header, event->schema_version);
	pqcp_runtime_internal_write_u64(
		header + 4U, event->sequence);
	pqcp_runtime_internal_write_u64(
		header + 12U, event->timestamp_ms);
	pqcp_runtime_internal_write_u32(
		header + 20U, (uint32_t)event->kind);
	pqcp_runtime_internal_write_u32(
		header + 24U, (uint32_t)event->severity);
	pqcp_runtime_internal_write_u64(
		header + 28U, event->subject_id);
	pqcp_runtime_internal_write_u32(
		header + 36U, (uint32_t)event->result);
	pqcp_runtime_internal_write_u32(
		header + 40U, event->reason_mask);
	pqcp_runtime_internal_write_u32(
		header + 44U, (uint32_t)event->value);
	parts[0] = event->previous_digest;
	lengths[0] = sizeof(event->previous_digest);
	parts[1] = header;
	lengths[1] = sizeof(header);
	parts[2] = (const uint8_t *)event->profile_id;
	lengths[2] = strnlen(
		event->profile_id, sizeof(event->profile_id));
	parts[3] = (const uint8_t *)event->detail;
	lengths[3] = strnlen(
		event->detail, sizeof(event->detail));
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, ARRAY_SIZE(parts), digest);
}

static int event_validate(
	const struct pqcp_runtime_event *event)
{
	if (event == NULL ||
	    event->schema_version !=
		    PQCP_RUNTIME_OPERATION_SCHEMA_VERSION ||
	    event->sequence == 0U ||
	    event->timestamp_ms == 0U ||
	    !event_kind_valid(event->kind) ||
	    !event_severity_valid(event->severity) ||
	    !pqcp_runtime_internal_text_valid(
		    event->profile_id,
		    sizeof(event->profile_id)) ||
	    !pqcp_runtime_internal_text_valid(
		    event->detail, sizeof(event->detail))) {
		return -EINVAL;
	}
	return 0;
}

static size_t oldest_index(
	const struct pqcp_runtime_event_bus *bus)
{
	if (bus->count < bus->capacity) {
		return 0U;
	}
	return bus->next_index;
}

static struct pqcp_runtime_event *event_at_offset(
	struct pqcp_runtime_event_bus *bus,
	size_t offset)
{
	const size_t index =
		(oldest_index(bus) + offset) % bus->capacity;

	return &bus->entries[index];
}

int pqcp_runtime_event_bus_init(
	struct pqcp_runtime_event_bus *bus,
	struct pqcp_runtime_event *entries,
	size_t capacity,
	struct pqcp_runtime_event_subscription *subscriptions,
	size_t subscription_capacity)
{
	if (bus == NULL || entries == NULL || capacity == 0U ||
	    (subscriptions == NULL &&
	     subscription_capacity != 0U)) {
		return -EINVAL;
	}
	memset(entries, 0, capacity * sizeof(*entries));
	if (subscriptions != NULL) {
		memset(subscriptions, 0,
		       subscription_capacity *
			       sizeof(*subscriptions));
	}
	memset(bus, 0, sizeof(*bus));
	bus->entries = entries;
	bus->capacity = capacity;
	bus->subscriptions = subscriptions;
	bus->subscription_capacity = subscription_capacity;
	bus->next_sequence = 1U;
	k_mutex_init(&bus->lock);
	bus->initialized = true;
	return 0;
}

int pqcp_runtime_event_append(
	struct pqcp_runtime_event_bus *bus,
	const struct pqcp_runtime_event *event,
	uint64_t *sequence)
{
	struct pqcp_runtime_event prepared;
	size_t index;
	int ret;

	if (bus == NULL || !bus->initialized || event == NULL) {
		return -EINVAL;
	}
	prepared = *event;
	prepared.schema_version =
		PQCP_RUNTIME_OPERATION_SCHEMA_VERSION;
	if (prepared.timestamp_ms == 0U) {
		prepared.timestamp_ms =
			pqcp_runtime_internal_now_ms();
	}
	if (!event_kind_valid(prepared.kind) ||
	    !event_severity_valid(prepared.severity) ||
	    !pqcp_runtime_internal_text_valid(
		    prepared.profile_id,
		    sizeof(prepared.profile_id)) ||
	    !pqcp_runtime_internal_text_valid(
		    prepared.detail, sizeof(prepared.detail))) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&bus->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	prepared.sequence = bus->next_sequence++;
	memcpy(prepared.previous_digest, bus->chain_head,
	       sizeof(prepared.previous_digest));
	ret = event_digest(&prepared, prepared.digest);
	if (ret != 0) {
		(void)k_mutex_unlock(&bus->lock);
		return ret;
	}
	index = bus->next_index;
	bus->entries[index] = prepared;
	bus->next_index = (index + 1U) % bus->capacity;
	if (bus->count < bus->capacity) {
		bus->count++;
	} else {
		bus->dropped_events++;
	}
	memcpy(bus->chain_head, prepared.digest,
	       sizeof(bus->chain_head));
	if (sequence != NULL) {
		*sequence = prepared.sequence;
	}
	for (size_t subscription = 0U;
	     subscription < bus->subscription_capacity;
	     ++subscription) {
		struct pqcp_runtime_event_subscription *entry =
			&bus->subscriptions[subscription];

		if (!entry->active || entry->callback == NULL ||
		    !event_matches(&prepared, &entry->filter)) {
			continue;
		}
		entry->callback(&prepared, entry->user_data);
	}
	(void)k_mutex_unlock(&bus->lock);
	return 0;
}

int pqcp_runtime_event_read(
	struct pqcp_runtime_event_bus *bus,
	uint64_t sequence,
	struct pqcp_runtime_event *event)
{
	int ret;

	if (bus == NULL || !bus->initialized ||
	    sequence == 0U || event == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&bus->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t offset = 0U; offset < bus->count; ++offset) {
		const struct pqcp_runtime_event *entry =
			event_at_offset(bus, offset);

		if (entry->sequence == sequence) {
			*event = *entry;
			(void)k_mutex_unlock(&bus->lock);
			return 0;
		}
	}
	(void)k_mutex_unlock(&bus->lock);
	return -ENOENT;
}

int pqcp_runtime_event_subscribe(
	struct pqcp_runtime_event_bus *bus,
	const struct pqcp_runtime_event_filter *filter,
	pqcp_runtime_event_callback callback,
	void *user_data,
	size_t *subscription_id)
{
	int ret;

	if (bus == NULL || !bus->initialized ||
	    callback == NULL || subscription_id == NULL ||
	    !event_filter_valid(filter)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&bus->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < bus->subscription_capacity; ++index) {
		struct pqcp_runtime_event_subscription *entry =
			&bus->subscriptions[index];

		if (entry->active) {
			continue;
		}
		memset(entry, 0, sizeof(*entry));
		entry->callback = callback;
		entry->user_data = user_data;
		if (filter != NULL) {
			entry->filter = *filter;
		}
		entry->active = true;
		*subscription_id = index;
		(void)k_mutex_unlock(&bus->lock);
		return 0;
	}
	(void)k_mutex_unlock(&bus->lock);
	return -ENOSPC;
}

int pqcp_runtime_event_unsubscribe(
	struct pqcp_runtime_event_bus *bus,
	size_t subscription_id)
{
	int ret;

	if (bus == NULL || !bus->initialized ||
	    subscription_id >= bus->subscription_capacity) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&bus->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (!bus->subscriptions[subscription_id].active) {
		(void)k_mutex_unlock(&bus->lock);
		return -ENOENT;
	}
	memset(&bus->subscriptions[subscription_id], 0,
	       sizeof(bus->subscriptions[subscription_id]));
	(void)k_mutex_unlock(&bus->lock);
	return 0;
}

int pqcp_runtime_event_bus_verify(
	struct pqcp_runtime_event_bus *bus)
{
	uint8_t previous[PQCP_RUNTIME_EVENT_CHAIN_BYTES];
	uint64_t last_sequence = 0U;
	int ret;

	if (bus == NULL || !bus->initialized) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&bus->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(previous, 0, sizeof(previous));
	for (size_t offset = 0U; offset < bus->count; ++offset) {
		const struct pqcp_runtime_event *entry =
			event_at_offset(bus, offset);
		uint8_t digest[PQCP_RUNTIME_EVENT_CHAIN_BYTES];

		ret = event_validate(entry);
		if (ret != 0) {
			break;
		}
		if (last_sequence != 0U &&
		    entry->sequence != last_sequence + 1U) {
			ret = -EBADMSG;
			break;
		}
		if (offset != 0U &&
		    memcmp(entry->previous_digest, previous,
			   sizeof(previous)) != 0) {
			ret = -EBADMSG;
			break;
		}
		ret = event_digest(entry, digest);
		if (ret != 0 ||
		    memcmp(digest, entry->digest,
			   sizeof(digest)) != 0) {
			ret = -EBADMSG;
			break;
		}
		memcpy(previous, entry->digest, sizeof(previous));
		last_sequence = entry->sequence;
	}
	if (ret == 0 && bus->count != 0U &&
	    memcmp(previous, bus->chain_head,
		   sizeof(previous)) != 0) {
		ret = -EBADMSG;
	}
	(void)k_mutex_unlock(&bus->lock);
	return ret;
}

int pqcp_runtime_event_emit(
	const struct pqcp_runtime_event *event)
{
	char digest_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];
	int ret;

	ret = event_validate(event);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_internal_hex(
		event->digest, sizeof(event->digest),
		digest_hex, sizeof(digest_hex));
	if (ret != 0) {
		return ret;
	}
	printk("PQCP_RUNTIME_EVENT schema=%u sequence=%llu timestamp_ms=%llu kind=%s severity=%u subject=%llu result=%d reasons=0x%08x value=%llu profile=%s detail=%s digest=%s\n",
	       event->schema_version,
	       event->sequence,
	       event->timestamp_ms,
	       pqcp_runtime_event_kind_str(event->kind),
	       (unsigned int)event->severity,
	       event->subject_id,
	       event->result,
	       event->reason_mask,
	       event->value,
	       event->profile_id,
	       event->detail,
	       digest_hex);
	return 0;
}

const char *pqcp_runtime_event_kind_str(
	enum pqcp_runtime_event_kind kind)
{
	switch (kind) {
	case PQCP_RUNTIME_EVENT_NONE:
		return "none";
	case PQCP_RUNTIME_EVENT_SERVICE_INITIALIZED:
		return "service-initialized";
	case PQCP_RUNTIME_EVENT_SERVICE_STARTED:
		return "service-started";
	case PQCP_RUNTIME_EVENT_SERVICE_STOPPED:
		return "service-stopped";
	case PQCP_RUNTIME_EVENT_SERVICE_TICK:
		return "service-tick";
	case PQCP_RUNTIME_EVENT_JOB_ADMITTED:
		return "job-admitted";
	case PQCP_RUNTIME_EVENT_JOB_QUEUED:
		return "job-queued";
	case PQCP_RUNTIME_EVENT_JOB_STARTED:
		return "job-started";
	case PQCP_RUNTIME_EVENT_JOB_COMPLETED:
		return "job-completed";
	case PQCP_RUNTIME_EVENT_JOB_FAILED:
		return "job-failed";
	case PQCP_RUNTIME_EVENT_JOB_CANCELLED:
		return "job-cancelled";
	case PQCP_RUNTIME_EVENT_SESSION_OPENED:
		return "session-opened";
	case PQCP_RUNTIME_EVENT_SESSION_DRAINING:
		return "session-draining";
	case PQCP_RUNTIME_EVENT_SESSION_CLOSED:
		return "session-closed";
	case PQCP_RUNTIME_EVENT_KEY_CREATED:
		return "key-created";
	case PQCP_RUNTIME_EVENT_KEY_ROTATED:
		return "key-rotated";
	case PQCP_RUNTIME_EVENT_KEY_EXPIRED:
		return "key-expired";
	case PQCP_RUNTIME_EVENT_KEY_DESTROYED:
		return "key-destroyed";
	case PQCP_RUNTIME_EVENT_IDENTITY_CREATED:
		return "identity-created";
	case PQCP_RUNTIME_EVENT_IDENTITY_ROTATED:
		return "identity-rotated";
	case PQCP_RUNTIME_EVENT_PROFILE_OBSERVED:
		return "profile-observed";
	case PQCP_RUNTIME_EVENT_PROFILE_TRANSITIONED:
		return "profile-transitioned";
	case PQCP_RUNTIME_EVENT_HEALTH_DEGRADED:
		return "health-degraded";
	case PQCP_RUNTIME_EVENT_HEALTH_RECOVERED:
		return "health-recovered";
	case PQCP_RUNTIME_EVENT_CIRCUIT_OPENED:
		return "circuit-opened";
	case PQCP_RUNTIME_EVENT_CIRCUIT_CLOSED:
		return "circuit-closed";
	case PQCP_RUNTIME_EVENT_CHECKPOINT_WRITTEN:
		return "checkpoint-written";
	case PQCP_RUNTIME_EVENT_CHECKPOINT_RESTORED:
		return "checkpoint-restored";
	case PQCP_RUNTIME_EVENT_COMMAND_ACCEPTED:
		return "command-accepted";
	case PQCP_RUNTIME_EVENT_COMMAND_REJECTED:
		return "command-rejected";
	case PQCP_RUNTIME_EVENT_COMMAND_COMPLETED:
		return "command-completed";
	case PQCP_RUNTIME_EVENT_AUDIT_FAILURE:
		return "audit-failure";
	default:
		return "unknown";
	}
}
