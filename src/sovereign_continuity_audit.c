/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tamper-evident bounded audit log for sovereign continuity actions.
 */

#include "sovereign_continuity_internal.h"

static bool event_type_valid(
	enum pqcp_sovereign_continuity_event_type type)
{
	return type >=
		       PQCP_SOVEREIGN_CONTINUITY_EVENT_OBJECTIVE_REGISTERED &&
	       type <= PQCP_SOVEREIGN_CONTINUITY_EVENT_EDGE_ADAPTER;
}

static bool event_outcome_valid(
	enum pqcp_sovereign_continuity_event_outcome outcome)
{
	return outcome >= PQCP_SOVEREIGN_EVENT_OUTCOME_ALLOWED &&
	       outcome <= PQCP_SOVEREIGN_EVENT_OUTCOME_EXPIRED;
}

static size_t physical_index(
	const struct pqcp_sovereign_continuity_audit_log *log,
	size_t logical_index)
{
	return (log->head + logical_index) % log->capacity;
}

static int record_validate(
	const struct pqcp_sovereign_continuity_audit_record *record)
{
	if (record == NULL ||
	    !pqcp_sovereign_continuity_text_valid(record->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(record->subject_id) ||
	    !event_type_valid(record->type) ||
	    !event_outcome_valid(record->outcome) ||
	    record->occurred_at_ms == 0U ||
	    record->policy_epoch == 0U ||
	    record->revocation_epoch == 0U) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_sovereign_continuity_audit_log_init(
	struct pqcp_sovereign_continuity_audit_log *log,
	struct pqcp_sovereign_continuity_event *events,
	size_t capacity)
{
	if (log == NULL || events == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(log, 0, sizeof(*log));
	memset(events, 0, capacity * sizeof(events[0]));
	log->schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	log->events = events;
	log->capacity = capacity;
	log->next_sequence = 1U;
	k_mutex_init(&log->lock);
	log->initialized = true;
	return 0;
}

int pqcp_sovereign_continuity_audit_append(
	struct pqcp_sovereign_continuity_audit_log *log,
	const struct pqcp_sovereign_continuity_audit_record *record,
	struct pqcp_sovereign_continuity_event *event)
{
	struct pqcp_sovereign_continuity_event candidate;
	size_t index;
	int ret;

	if (log == NULL || !log->initialized ||
	    record_validate(record) != 0) {
		return -EINVAL;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	candidate.occurred_at_ms = record->occurred_at_ms;
	candidate.type = record->type;
	candidate.outcome = record->outcome;
	candidate.object_id = record->object_id;
	candidate.policy_epoch = record->policy_epoch;
	candidate.revocation_epoch = record->revocation_epoch;
	candidate.fencing_epoch = record->fencing_epoch;
	candidate.result = record->result;
	candidate.occupied = true;
	ret = pqcp_sovereign_continuity_copy_id(
		candidate.tenant_id, record->tenant_id);
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			candidate.subject_id, record->subject_id);
	}
	if (ret != 0) {
		return ret;
	}
	memcpy(candidate.evidence_digest, record->evidence_digest,
	       sizeof(candidate.evidence_digest));

	k_mutex_lock(&log->lock, K_FOREVER);
	candidate.sequence = log->next_sequence++;
	if (log->next_sequence == 0U) {
		log->next_sequence = 1U;
	}
	memcpy(candidate.previous_digest, log->tail_digest,
	       sizeof(candidate.previous_digest));
	ret = pqcp_sovereign_continuity_digest_event(
		&candidate, candidate.event_digest);
	if (ret != 0) {
		k_mutex_unlock(&log->lock);
		return ret;
	}
	if (log->count < log->capacity) {
		index = physical_index(log, log->count);
		log->count++;
	} else {
		index = log->head;
		memcpy(log->anchor_digest,
		       log->events[index].event_digest,
		       sizeof(log->anchor_digest));
		log->head = (log->head + 1U) % log->capacity;
		log->eviction_count =
			pqcp_sovereign_continuity_add_u64(
				log->eviction_count, 1U);
	}
	log->events[index] = candidate;
	memcpy(log->tail_digest, candidate.event_digest,
	       sizeof(log->tail_digest));
	if (event != NULL) {
		*event = candidate;
	}
	k_mutex_unlock(&log->lock);
	return 0;
}

int pqcp_sovereign_continuity_audit_read(
	struct pqcp_sovereign_continuity_audit_log *log,
	uint64_t sequence,
	struct pqcp_sovereign_continuity_event *event)
{
	int ret = -ENOENT;

	if (log == NULL || !log->initialized ||
	    sequence == 0U || event == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&log->lock, K_FOREVER);
	for (size_t logical = 0U; logical < log->count; ++logical) {
		const struct pqcp_sovereign_continuity_event *candidate =
			&log->events[physical_index(log, logical)];

		if (candidate->occupied &&
		    candidate->sequence == sequence) {
			*event = *candidate;
			ret = 0;
			break;
		}
	}
	k_mutex_unlock(&log->lock);
	return ret;
}

int pqcp_sovereign_continuity_audit_bounds(
	struct pqcp_sovereign_continuity_audit_log *log,
	uint64_t *first_sequence,
	uint64_t *last_sequence,
	uint8_t anchor_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint8_t tail_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	if (log == NULL || !log->initialized ||
	    first_sequence == NULL || last_sequence == NULL ||
	    anchor_digest == NULL || tail_digest == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&log->lock, K_FOREVER);
	if (log->count == 0U) {
		*first_sequence = 0U;
		*last_sequence = 0U;
	} else {
		*first_sequence =
			log->events[log->head].sequence;
		*last_sequence =
			log->events[
				physical_index(log, log->count - 1U)].
				sequence;
	}
	memcpy(anchor_digest, log->anchor_digest,
	       PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES);
	memcpy(tail_digest, log->tail_digest,
	       PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES);
	k_mutex_unlock(&log->lock);
	return 0;
}

int pqcp_sovereign_continuity_audit_verify(
	struct pqcp_sovereign_continuity_audit_log *log)
{
	uint8_t previous[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint64_t expected_sequence = 0U;
	int ret = 0;

	if (log == NULL || !log->initialized ||
	    log->schema_version !=
		    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
	    log->events == NULL || log->capacity == 0U ||
	    log->count > log->capacity || log->head >= log->capacity ||
	    log->next_sequence == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&log->lock, K_FOREVER);
	memcpy(previous, log->anchor_digest, sizeof(previous));
	for (size_t logical = 0U;
	     logical < log->count && ret == 0; ++logical) {
		const struct pqcp_sovereign_continuity_event *event =
			&log->events[physical_index(log, logical)];

		if (!event->occupied ||
		    event->schema_version !=
			    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
		    !event_type_valid(event->type) ||
		    !event_outcome_valid(event->outcome) ||
		    !pqcp_sovereign_continuity_text_valid(
			    event->tenant_id) ||
		    !pqcp_sovereign_continuity_text_valid(
			    event->subject_id) ||
		    !pqcp_sovereign_continuity_digest_equal(
			    previous, event->previous_digest)) {
			ret = -EBADMSG;
			break;
		}
		if (logical != 0U &&
		    event->sequence != expected_sequence) {
			ret = -EILSEQ;
			break;
		}
		ret = pqcp_sovereign_continuity_digest_event(
			event, digest);
		if (ret == 0 &&
		    !pqcp_sovereign_continuity_digest_equal(
			    digest, event->event_digest)) {
			ret = -EBADMSG;
		}
		memcpy(previous, event->event_digest, sizeof(previous));
		expected_sequence = event->sequence + 1U;
	}
	if (ret == 0 &&
	    !pqcp_sovereign_continuity_digest_equal(
		    previous, log->tail_digest)) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&log->lock);
	return ret;
}
