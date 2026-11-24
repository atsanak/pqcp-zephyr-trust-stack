/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free, hash-chained forensic timeline.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"
#include "sovereign_artifact_internal.h"

#define FORENSIC_EVENT_DOMAIN "pqcp-sovereign-forensic-event-v1"
#define FORENSIC_CANONICAL_BYTES 512U
#define FORENSIC_CONFIDENCE_MAX 10000U
#define FORENSIC_SEVERITY_MAX 5U

static int timeline_lock(struct pqcp_sovereign_forensic_timeline *timeline)
{
	if (timeline == NULL || !timeline->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&timeline->lock, K_FOREVER);
}

static void timeline_unlock(
	struct pqcp_sovereign_forensic_timeline *timeline)
{
	(void)k_mutex_unlock(&timeline->lock);
}

static bool digest_zero(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	return digest == NULL ||
	       pqcp_sovereign_internal_all_zero(
		       digest, PQCP_SOVEREIGN_DIGEST_BYTES);
}

static size_t encode_u32(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	uint32_t value)
{
	if (output == NULL || offset > capacity ||
	    capacity - offset < sizeof(value)) {
		return 0U;
	}
	pqcp_runtime_internal_write_u32(&output[offset], value);
	return offset + sizeof(value);
}

static size_t encode_u64(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	uint64_t value)
{
	if (output == NULL || offset > capacity ||
	    capacity - offset < sizeof(value)) {
		return 0U;
	}
	pqcp_runtime_internal_write_u64(&output[offset], value);
	return offset + sizeof(value);
}

static size_t encode_bytes(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	const uint8_t *value,
	size_t value_length)
{
	size_t next;

	if (output == NULL ||
	    (value == NULL && value_length != 0U) ||
	    value_length > UINT32_MAX) {
		return 0U;
	}
	next = encode_u32(
		output, capacity, offset, (uint32_t)value_length);
	if (next == 0U || next > capacity ||
	    capacity - next < value_length) {
		return 0U;
	}
	if (value_length != 0U) {
		memcpy(&output[next], value, value_length);
	}
	return next + value_length;
}

static size_t encode_text(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	const char *text,
	size_t maximum)
{
	size_t length;

	if (!pqcp_sovereign_internal_text_valid(text, maximum)) {
		return 0U;
	}
	length = strnlen(text, maximum);
	return encode_bytes(
		output, capacity, offset,
		(const uint8_t *)text, length);
}

static int forensic_event_digest(
	const struct pqcp_sovereign_forensic_event *event,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[FORENSIC_CANONICAL_BYTES];
	size_t offset = 0U;
	int ret;

	if (event == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	offset = encode_text(
		body, sizeof(body), offset, FORENSIC_EVENT_DOMAIN,
		sizeof(FORENSIC_EVENT_DOMAIN));
	offset = encode_u32(
		body, sizeof(body), offset, event->schema_version);
	offset = encode_u64(
		body, sizeof(body), offset, event->sequence);
	offset = encode_text(
		body, sizeof(body), offset, event->case_id,
		sizeof(event->case_id));
	offset = encode_text(
		body, sizeof(body), offset, event->subject_id,
		sizeof(event->subject_id));
	offset = encode_text(
		body, sizeof(body), offset, event->actor_id,
		sizeof(event->actor_id));
	offset = encode_text(
		body, sizeof(body), offset, event->event_type,
		sizeof(event->event_type));
	offset = encode_u64(
		body, sizeof(body), offset, event->observed_at_ms);
	offset = encode_u64(
		body, sizeof(body), offset, event->ingested_at_ms);
	offset = encode_u64(
		body, sizeof(body), offset, event->policy_epoch);
	offset = encode_u32(
		body, sizeof(body), offset,
		event->confidence_basis_points);
	offset = encode_u32(
		body, sizeof(body), offset, event->severity);
	offset = encode_bytes(
		body, sizeof(body), offset, event->evidence_digest,
		sizeof(event->evidence_digest));
	offset = encode_bytes(
		body, sizeof(body), offset, event->previous_digest,
		sizeof(event->previous_digest));
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static bool event_shape_valid(
	const struct pqcp_sovereign_forensic_event *event)
{
	return event != NULL &&
	       event->occupied &&
	       event->schema_version == PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       event->sequence != 0U &&
	       pqcp_sovereign_internal_text_valid(
		       event->case_id, sizeof(event->case_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       event->subject_id, sizeof(event->subject_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       event->actor_id, sizeof(event->actor_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       event->event_type, sizeof(event->event_type)) &&
	       event->observed_at_ms != 0U &&
	       event->ingested_at_ms >= event->observed_at_ms &&
	       event->policy_epoch != 0U &&
	       event->confidence_basis_points <=
		       FORENSIC_CONFIDENCE_MAX &&
	       event->severity <= FORENSIC_SEVERITY_MAX &&
	       !digest_zero(event->evidence_digest) &&
	       !digest_zero(event->event_digest);
}

static size_t oldest_index_locked(
	const struct pqcp_sovereign_forensic_timeline *timeline)
{
	if (timeline->count == 0U) {
		return timeline->next_index;
	}
	if (timeline->count < timeline->capacity) {
		return 0U;
	}
	return timeline->next_index;
}

static size_t chronological_index_locked(
	const struct pqcp_sovereign_forensic_timeline *timeline,
	size_t ordinal)
{
	return (oldest_index_locked(timeline) + ordinal) %
	       timeline->capacity;
}

static int sequence_index_locked(
	const struct pqcp_sovereign_forensic_timeline *timeline,
	uint64_t sequence)
{
	size_t ordinal;

	for (ordinal = 0U; ordinal < timeline->count; ++ordinal) {
		size_t index =
			chronological_index_locked(timeline, ordinal);

		if (timeline->events[index].occupied &&
		    timeline->events[index].sequence == sequence) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static const struct pqcp_sovereign_forensic_event *
newest_event_locked(
	const struct pqcp_sovereign_forensic_timeline *timeline)
{
	size_t index;

	if (timeline->count == 0U) {
		return NULL;
	}
	index = chronological_index_locked(
		timeline, timeline->count - 1U);
	return &timeline->events[index];
}

int pqcp_sovereign_forensic_timeline_init(
	struct pqcp_sovereign_forensic_timeline *timeline,
	struct pqcp_sovereign_forensic_event *events,
	size_t capacity)
{
	if (timeline == NULL || events == NULL ||
	    capacity == 0U || capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(timeline, 0, sizeof(*timeline));
	memset(events, 0, capacity * sizeof(*events));
	timeline->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	timeline->events = events;
	timeline->capacity = capacity;
	timeline->next_sequence = 1U;
	k_mutex_init(&timeline->lock);
	timeline->initialized = true;
	return 0;
}

int pqcp_sovereign_forensic_append(
	struct pqcp_sovereign_forensic_timeline *timeline,
	const char *case_id,
	const char *subject_id,
	const char *actor_id,
	const char *event_type,
	uint64_t observed_at_ms,
	uint64_t ingested_at_ms,
	uint64_t policy_epoch,
	uint32_t confidence_basis_points,
	uint32_t severity,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	struct pqcp_sovereign_forensic_event *event)
{
	struct pqcp_sovereign_forensic_event staged;
	const struct pqcp_sovereign_forensic_event *newest;
	int ret;

	if (!pqcp_sovereign_internal_text_valid(
		    case_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    actor_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    event_type, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    observed_at_ms == 0U ||
	    ingested_at_ms < observed_at_ms ||
	    policy_epoch == 0U ||
	    confidence_basis_points > FORENSIC_CONFIDENCE_MAX ||
	    severity > FORENSIC_SEVERITY_MAX ||
	    digest_zero(evidence_digest)) {
		return -EINVAL;
	}
	ret = timeline_lock(timeline);
	if (ret != 0) {
		return ret;
	}
	if (timeline->next_sequence == 0U ||
	    timeline->next_sequence == UINT64_MAX ||
	    timeline->next_index >= timeline->capacity ||
	    timeline->count > timeline->capacity) {
		timeline_unlock(timeline);
		return -EOVERFLOW;
	}
	newest = newest_event_locked(timeline);
	if (newest != NULL &&
	    (ingested_at_ms < newest->ingested_at_ms ||
	     policy_epoch < newest->policy_epoch)) {
		timeline_unlock(timeline);
		return -ESTALE;
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.sequence = timeline->next_sequence;
	ret = pqcp_sovereign_internal_copy_text(
		staged.case_id, sizeof(staged.case_id), case_id);
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			staged.subject_id, sizeof(staged.subject_id),
			subject_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			staged.actor_id, sizeof(staged.actor_id),
			actor_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			staged.event_type, sizeof(staged.event_type),
			event_type);
	}
	if (ret != 0) {
		timeline_unlock(timeline);
		return ret;
	}
	staged.observed_at_ms = observed_at_ms;
	staged.ingested_at_ms = ingested_at_ms;
	staged.policy_epoch = policy_epoch;
	staged.confidence_basis_points = confidence_basis_points;
	staged.severity = severity;
	memcpy(staged.evidence_digest, evidence_digest,
	       sizeof(staged.evidence_digest));
	memcpy(staged.previous_digest, timeline->chain_head,
	       sizeof(staged.previous_digest));
	staged.occupied = true;
	ret = forensic_event_digest(
		&staged, staged.event_digest);
	if (ret != 0) {
		timeline_unlock(timeline);
		return ret;
	}
	if (timeline->count == timeline->capacity) {
		if (timeline->dropped_count == UINT64_MAX) {
			timeline_unlock(timeline);
			return -EOVERFLOW;
		}
		timeline->dropped_count++;
	} else {
		timeline->count++;
	}
	timeline->events[timeline->next_index] = staged;
	timeline->next_index =
		(timeline->next_index + 1U) % timeline->capacity;
	timeline->next_sequence++;
	memcpy(timeline->chain_head, staged.event_digest,
	       sizeof(timeline->chain_head));
	if (event != NULL) {
		*event = staged;
	}
	timeline_unlock(timeline);
	return 0;
}

int pqcp_sovereign_forensic_find(
	struct pqcp_sovereign_forensic_timeline *timeline,
	uint64_t sequence,
	struct pqcp_sovereign_forensic_event *event)
{
	int index;
	int ret;

	if (sequence == 0U || event == NULL) {
		return -EINVAL;
	}
	memset(event, 0, sizeof(*event));
	ret = timeline_lock(timeline);
	if (ret != 0) {
		return ret;
	}
	index = sequence_index_locked(timeline, sequence);
	if (index < 0) {
		timeline_unlock(timeline);
		return index;
	}
	*event = timeline->events[index];
	timeline_unlock(timeline);
	return 0;
}

int pqcp_sovereign_forensic_case_bounds(
	struct pqcp_sovereign_forensic_timeline *timeline,
	const char *case_id,
	uint64_t *first_sequence,
	uint64_t *last_sequence,
	uint32_t *event_count)
{
	uint64_t first = 0U;
	uint64_t last = 0U;
	uint32_t count = 0U;
	size_t ordinal;
	int ret;

	if (!pqcp_sovereign_internal_text_valid(
		    case_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    first_sequence == NULL || last_sequence == NULL ||
	    event_count == NULL) {
		return -EINVAL;
	}
	*first_sequence = 0U;
	*last_sequence = 0U;
	*event_count = 0U;
	ret = timeline_lock(timeline);
	if (ret != 0) {
		return ret;
	}
	for (ordinal = 0U; ordinal < timeline->count; ++ordinal) {
		const struct pqcp_sovereign_forensic_event *candidate =
			&timeline->events[
				chronological_index_locked(
					timeline, ordinal)];

		if (!candidate->occupied ||
		    strcmp(candidate->case_id, case_id) != 0) {
			continue;
		}
		if (count == 0U) {
			first = candidate->sequence;
		}
		last = candidate->sequence;
		if (count == UINT32_MAX) {
			timeline_unlock(timeline);
			return -EOVERFLOW;
		}
		count++;
	}
	if (count == 0U) {
		timeline_unlock(timeline);
		return -ENOENT;
	}
	*first_sequence = first;
	*last_sequence = last;
	*event_count = count;
	timeline_unlock(timeline);
	return 0;
}

static int verify_chain_locked(
	const struct pqcp_sovereign_forensic_timeline *timeline)
{
	uint8_t previous[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t expected[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint64_t sequence;
	uint64_t previous_ingested = 0U;
	uint64_t previous_policy_epoch = 0U;
	size_t ordinal;
	int ret = 0;

	memset(previous, 0, sizeof(previous));
	memset(expected, 0, sizeof(expected));
	if (timeline->count != 0U) {
		const struct pqcp_sovereign_forensic_event *first =
			&timeline->events[
				chronological_index_locked(
					timeline, 0U)];

		if (timeline->dropped_count == 0U &&
		    !digest_zero(first->previous_digest)) {
			return -EBADMSG;
		}
		memcpy(previous, first->previous_digest,
		       sizeof(previous));
		sequence = first->sequence;
	} else {
		sequence = 1U;
	}
	for (ordinal = 0U; ordinal < timeline->count; ++ordinal) {
		const struct pqcp_sovereign_forensic_event *entry =
			&timeline->events[
				chronological_index_locked(
					timeline, ordinal)];

		if (!event_shape_valid(entry) ||
		    entry->sequence != sequence ||
		    !pqcp_sovereign_internal_equal(
			    entry->previous_digest, previous,
			    sizeof(previous)) ||
		    (ordinal != 0U &&
		     (entry->ingested_at_ms < previous_ingested ||
		      entry->policy_epoch < previous_policy_epoch))) {
			ret = -EBADMSG;
			break;
		}
		ret = forensic_event_digest(entry, expected);
		if (ret != 0 ||
		    !pqcp_sovereign_internal_equal(
			    expected, entry->event_digest,
			    sizeof(expected))) {
			ret = ret != 0 ? ret : -EBADMSG;
			break;
		}
		memcpy(previous, entry->event_digest,
		       sizeof(previous));
		previous_ingested = entry->ingested_at_ms;
		previous_policy_epoch = entry->policy_epoch;
		if (sequence == UINT64_MAX) {
			ret = -EOVERFLOW;
			break;
		}
		sequence++;
	}
	if (ret == 0 &&
	    !pqcp_sovereign_internal_equal(
		    previous, timeline->chain_head,
		    sizeof(previous))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(previous, sizeof(previous));
	pqcp_runtime_secure_zero(expected, sizeof(expected));
	return ret;
}

int pqcp_sovereign_forensic_verify(
	struct pqcp_sovereign_forensic_timeline *timeline)
{
	size_t occupied = 0U;
	size_t index;
	int ret;

	ret = timeline_lock(timeline);
	if (ret != 0) {
		return ret;
	}
	if (timeline->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    timeline->events == NULL ||
	    timeline->capacity == 0U ||
	    timeline->next_index >= timeline->capacity ||
	    timeline->count > timeline->capacity ||
	    timeline->next_sequence == 0U) {
		timeline_unlock(timeline);
		return -EBADMSG;
	}
	for (index = 0U; index < timeline->capacity; ++index) {
		if (timeline->events[index].occupied) {
			occupied++;
		}
	}
	if (occupied != timeline->count) {
		timeline_unlock(timeline);
		return -EBADMSG;
	}
	if (timeline->count == 0U) {
		if (timeline->next_index != 0U ||
		    timeline->next_sequence != 1U ||
		    timeline->dropped_count != 0U ||
		    !digest_zero(timeline->chain_head)) {
			timeline_unlock(timeline);
			return -EBADMSG;
		}
		timeline_unlock(timeline);
		return 0;
	}
	if (timeline->dropped_count >
		    UINT64_MAX - (uint64_t)timeline->count ||
	    timeline->next_sequence - 1U !=
		    timeline->dropped_count +
			    (uint64_t)timeline->count ||
	    (timeline->count < timeline->capacity &&
	     timeline->next_index != timeline->count) ||
	    (timeline->count == timeline->capacity &&
	     timeline->next_index !=
		     timeline->dropped_count % timeline->capacity)) {
		timeline_unlock(timeline);
		return -EBADMSG;
	}
	ret = verify_chain_locked(timeline);
	timeline_unlock(timeline);
	return ret;
}
