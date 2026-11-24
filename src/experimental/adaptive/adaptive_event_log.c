/*
 * SPDX-License-Identifier: MIT
 *
 * Digest-chained runtime event journal for adaptive PQC decisions.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_EVENT_ROOT_DOMAIN UINT64_C(0x4144504556524f4f)

static bool event_type_valid(enum pqcp_adaptive_event_type type)
{
	return type >= PQCP_ADAPTIVE_EVENT_BOOT &&
	       type <= PQCP_ADAPTIVE_EVENT_FAULT;
}

static uint32_t physical_index(
	const struct pqcp_adaptive_event_log *log,
	uint32_t logical_index)
{
	uint32_t oldest;

	if (log->count < PQCP_ADAPTIVE_MAX_EVENTS) {
		return logical_index;
	}
	oldest = log->head;
	return (oldest + logical_index) % PQCP_ADAPTIVE_MAX_EVENTS;
}

static int root_digest(
	const struct pqcp_adaptive_event_log *log,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (log == NULL || output == NULL ||
	    log->count > PQCP_ADAPTIVE_MAX_EVENTS ||
	    log->head >= PQCP_ADAPTIVE_MAX_EVENTS) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_EVENT_ROOT_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, log->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, log->count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, log->next_sequence);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, log->dropped_events);
	for (uint32_t index = 0U; index < log->count; ++index) {
		const struct pqcp_adaptive_event *event =
			pqcp_adaptive_event_log_get(log, index);

		if (event == NULL) {
			return -EBADMSG;
		}
		pqcp_deployment_evidence_digest_update_u32(
			&digest, event->sequence);
		pqcp_deployment_evidence_digest_update_text(
			&digest, event->event_digest_hex);
	}
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

static const char *previous_digest(
	const struct pqcp_adaptive_event_log *log)
{
	const struct pqcp_adaptive_event *last;

	if (log->count == 0U) {
		return "genesis";
	}
	last = pqcp_adaptive_event_log_get(log, log->count - 1U);
	return last != NULL ? last->event_digest_hex : "invalid";
}

static bool event_identifiers_valid(
	const char *profile_id, const char *related_id)
{
	return pqcp_adaptive_internal_id_valid(profile_id) &&
	       pqcp_adaptive_internal_id_valid(related_id);
}

int pqcp_adaptive_event_log_init(struct pqcp_adaptive_event_log *log)
{
	if (log == NULL) {
		return -EINVAL;
	}
	memset(log, 0, sizeof(*log));
	log->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	log->next_sequence = 1U;
	return root_digest(log, log->root_digest_hex);
}

int pqcp_adaptive_event_log_append(
	struct pqcp_adaptive_event_log *log,
	enum pqcp_adaptive_event_type type,
	enum pqcp_adaptive_status status,
	uint64_t timestamp_ms,
	uint32_t reason_mask,
	uint32_t blocker_mask,
	uint32_t warning_mask,
	uint32_t score,
	const char *profile_id,
	const char *related_id)
{
	struct pqcp_adaptive_event event;
	uint32_t slot;
	int ret;

	if (log == NULL ||
	    log->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    log->count > PQCP_ADAPTIVE_MAX_EVENTS ||
	    log->head >= PQCP_ADAPTIVE_MAX_EVENTS ||
	    !event_type_valid(type) ||
	    !pqcp_adaptive_internal_status_valid(status) ||
	    !event_identifiers_valid(profile_id, related_id) ||
	    (blocker_mask & ~PQCP_ADAPTIVE_BLOCK_KNOWN_MASK) != 0U ||
	    (warning_mask & ~PQCP_ADAPTIVE_WARNING_KNOWN_MASK) != 0U ||
	    score > PQCP_ADAPTIVE_SCORE_MAX) {
		return -EINVAL;
	}
	memset(&event, 0, sizeof(event));
	event.schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	event.sequence = log->next_sequence;
	event.type = type;
	event.status = status;
	event.timestamp_ms = timestamp_ms;
	event.reason_mask = reason_mask;
	event.blocker_mask = blocker_mask;
	event.warning_mask = warning_mask;
	event.score = score;
	pqcp_adaptive_internal_set_text(
		event.profile_id, sizeof(event.profile_id), profile_id);
	pqcp_adaptive_internal_set_text(
		event.related_id, sizeof(event.related_id), related_id);
	pqcp_adaptive_internal_set_text(
		event.previous_digest_hex,
		sizeof(event.previous_digest_hex),
		previous_digest(log));
	ret = pqcp_adaptive_internal_digest_event(
		&event, event.event_digest_hex);
	if (ret != 0) {
		return ret;
	}
	slot = log->head;
	log->events[slot] = event;
	log->head = (log->head + 1U) % PQCP_ADAPTIVE_MAX_EVENTS;
	if (log->count < PQCP_ADAPTIVE_MAX_EVENTS) {
		log->count++;
	} else {
		log->dropped_events++;
	}
	if (log->next_sequence != UINT32_MAX) {
		log->next_sequence++;
	}
	return root_digest(log, log->root_digest_hex);
}

const struct pqcp_adaptive_event *pqcp_adaptive_event_log_get(
	const struct pqcp_adaptive_event_log *log,
	uint32_t logical_index)
{
	if (log == NULL || logical_index >= log->count ||
	    log->count > PQCP_ADAPTIVE_MAX_EVENTS ||
	    log->head >= PQCP_ADAPTIVE_MAX_EVENTS) {
		return NULL;
	}
	return &log->events[physical_index(log, logical_index)];
}

static int verify_event(
	const struct pqcp_adaptive_event *event,
	const char *expected_previous,
	uint32_t expected_sequence)
{
	char expected[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];

	if (event == NULL ||
	    event->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    event->sequence != expected_sequence ||
	    !event_type_valid(event->type) ||
	    !pqcp_adaptive_internal_status_valid(event->status) ||
	    !event_identifiers_valid(
		    event->profile_id, event->related_id) ||
	    strcmp(event->previous_digest_hex,
		   expected_previous) != 0 ||
	    pqcp_adaptive_internal_digest_event(
		    event, expected) != 0 ||
	    strcmp(event->event_digest_hex, expected) != 0) {
		return -EBADMSG;
	}
	return 0;
}
int pqcp_adaptive_event_log_verify(
	const struct pqcp_adaptive_event_log *log)
{
	char expected_root[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
	const char *previous = "genesis";
	uint32_t expected_sequence;

	if (log == NULL ||
	    log->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    log->count > PQCP_ADAPTIVE_MAX_EVENTS ||
	    log->head >= PQCP_ADAPTIVE_MAX_EVENTS ||
	    log->next_sequence == 0U) {
		return -EINVAL;
	}
	expected_sequence =
		log->next_sequence > log->count ?
		log->next_sequence - log->count : 1U;
	for (uint32_t index = 0U; index < log->count; ++index) {
		const struct pqcp_adaptive_event *event =
			pqcp_adaptive_event_log_get(log, index);

		if (index == 0U && log->dropped_events != 0U) {
			/*
			 * A bounded ring cannot retain the dropped predecessor.
			 * The first retained event anchors the remaining chain.
			 */
			previous = event->previous_digest_hex;
		}
		if (verify_event(event, previous, expected_sequence) != 0) {
			return -EBADMSG;
		}
		previous = event->event_digest_hex;
		expected_sequence++;
	}
	if (root_digest(log, expected_root) != 0 ||
	    strcmp(expected_root, log->root_digest_hex) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_adaptive_event_log_reseal(
	struct pqcp_adaptive_event_log *log)
{
	const char *previous = "genesis";
	uint32_t expected_sequence;

	if (log == NULL ||
	    log->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    log->count > PQCP_ADAPTIVE_MAX_EVENTS ||
	    log->head >= PQCP_ADAPTIVE_MAX_EVENTS ||
	    log->next_sequence == 0U) {
		return -EINVAL;
	}
	expected_sequence =
		log->next_sequence > log->count ?
		log->next_sequence - log->count : 1U;
	for (uint32_t index = 0U; index < log->count; ++index) {
		const struct pqcp_adaptive_event *event =
			pqcp_adaptive_event_log_get(log, index);

		if (event == NULL) {
			return -EBADMSG;
		}
		if (index == 0U && log->dropped_events != 0U) {
			previous = event->previous_digest_hex;
		}
		if (verify_event(
			    event, previous,
			    expected_sequence) != 0) {
			return -EBADMSG;
		}
		previous = event->event_digest_hex;
		expected_sequence++;
	}
	return root_digest(log, log->root_digest_hex);
}

int pqcp_adaptive_event_log_emit(
	const struct pqcp_adaptive_event_log *log)
{
	int ret = pqcp_adaptive_event_log_verify(log);

	if (ret != 0) {
		return ret;
	}
	for (uint32_t index = 0U; index < log->count; ++index) {
		const struct pqcp_adaptive_event *event =
			pqcp_adaptive_event_log_get(log, index);

		printk("PQCP_ADAPTIVE_EVENT schema=%u sequence=%u type=%s status=%s timestamp_ms=%llu reasons=0x%08x blockers=0x%08x warnings=0x%08x score=%u profile=%s related=%s previous=%s digest=%s\n",
		       event->schema_version,
		       event->sequence,
		       pqcp_adaptive_event_type_str(event->type),
		       pqcp_adaptive_status_str(event->status),
		       (unsigned long long)event->timestamp_ms,
		       event->reason_mask,
		       event->blocker_mask,
		       event->warning_mask,
		       event->score,
		       event->profile_id,
		       event->related_id,
		       event->previous_digest_hex,
		       event->event_digest_hex);
	}
	printk("PQCP_ADAPTIVE_EVENT_LOG schema=%u count=%u next_sequence=%u dropped=%u digest=%s\n",
	       log->schema_version,
	       log->count,
	       log->next_sequence,
	       log->dropped_events,
	       log->root_digest_hex);
	return 0;
}
