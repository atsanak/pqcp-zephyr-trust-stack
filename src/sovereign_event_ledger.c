/*
 * SPDX-License-Identifier: MIT
 *
 * Hash-chained sovereign event ring with eviction anchoring.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_audit_internal.h"

#define LEDGER_SNAPSHOT_NUMERIC_BYTES 88U
#define LEDGER_SNAPSHOT_PARTS 4U

size_t pqcp_sovereign_audit_internal_physical_index(
	const struct pqcp_sovereign_event_ledger *ledger,
	size_t logical_index)
{
	if (ledger == NULL || ledger->capacity == 0U) {
		return 0U;
	}
	return (ledger->head + logical_index) %
	       ledger->capacity;
}

const struct pqcp_sovereign_event *
pqcp_sovereign_audit_internal_logical_event(
	const struct pqcp_sovereign_event_ledger *ledger,
	size_t logical_index)
{
	if (ledger == NULL || ledger->events == NULL ||
	    logical_index >= ledger->count ||
	    ledger->capacity == 0U) {
		return NULL;
	}
	return &ledger->events[
		pqcp_sovereign_audit_internal_physical_index(
			ledger, logical_index)];
}

int pqcp_sovereign_audit_internal_find_sequence(
	const struct pqcp_sovereign_event_ledger *ledger,
	uint64_t sequence,
	size_t *logical_index)
{
	uint64_t first;
	uint64_t distance;

	if (ledger == NULL || logical_index == NULL ||
	    sequence == 0U || ledger->count == 0U) {
		return -EINVAL;
	}
	first = pqcp_sovereign_audit_internal_logical_event(
		ledger, 0U)->sequence;
	if (sequence < first) {
		return -ESTALE;
	}
	distance = sequence - first;
	if (distance >= ledger->count) {
		return -ENOENT;
	}
	if (distance > SIZE_MAX) {
		return -EOVERFLOW;
	}
	*logical_index = (size_t)distance;
	if (pqcp_sovereign_audit_internal_logical_event(
		    ledger, *logical_index)->sequence != sequence) {
		return -EBADMSG;
	}
	return 0;
}

static int ledger_lock(
	struct pqcp_sovereign_event_ledger *ledger)
{
	int ret;

	if (ledger == NULL || !ledger->initialized) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&ledger->lock, K_FOREVER);
	return ret == 0 ? 0 : -EDEADLK;
}

static void ledger_unlock(
	struct pqcp_sovereign_event_ledger *ledger)
{
	if (ledger != NULL) {
		(void)k_mutex_unlock(&ledger->lock);
	}
}

static bool anchor_valid(
	const uint8_t anchor[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES])
{
	return anchor != NULL;
}

int pqcp_sovereign_event_ledger_init(
	struct pqcp_sovereign_event_ledger *ledger,
	struct pqcp_sovereign_event *events,
	size_t capacity,
	uint64_t first_sequence,
	const uint8_t anchor_digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES])
{
	if (ledger == NULL || events == NULL ||
	    capacity == 0U || first_sequence == 0U ||
	    !anchor_valid(anchor_digest)) {
		return -EINVAL;
	}
	memset(ledger, 0, sizeof(*ledger));
	memset(events, 0, capacity * sizeof(*events));
	ledger->schema_version =
		PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION;
	ledger->events = events;
	ledger->capacity = capacity;
	ledger->generation = 1U;
	ledger->next_sequence = first_sequence;
	memcpy(ledger->anchor_digest, anchor_digest,
	       sizeof(ledger->anchor_digest));
	memcpy(ledger->chain_head, anchor_digest,
	       sizeof(ledger->chain_head));
	k_mutex_init(&ledger->lock);
	ledger->initialized = true;
	return 0;
}

static int staged_event_prepare(
	const struct pqcp_sovereign_event *source,
	uint64_t sequence,
	const uint8_t previous_digest[
		PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES],
	struct pqcp_sovereign_event *staged)
{
	uint8_t expected_scope[
		PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	int ret;

	if (source == NULL || staged == NULL ||
	    previous_digest == NULL || sequence == 0U ||
	    source->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    source->generation == 0U ||
	    source->sequence != 0U || source->occupied ||
	    source->observed_at_ms == 0U ||
	    source->ingested_at_ms < source->observed_at_ms ||
	    source->tenant.policy_epoch !=
		    source->policy_epoch ||
	    source->tenant.revocation_epoch !=
		    source->revocation_epoch ||
	    pqcp_sovereign_audit_internal_all_zero(
		    source->event_id, sizeof(source->event_id))) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_audit_internal_scope_digest(
		&source->tenant, expected_scope);
	if (ret == 0 &&
	    !pqcp_sovereign_audit_internal_equal(
		    expected_scope, source->tenant.scope_digest,
		    sizeof(expected_scope))) {
		ret = -EBADMSG;
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			expected_scope, sizeof(expected_scope));
		return ret;
	}
	*staged = *source;
	staged->sequence = sequence;
	memcpy(staged->previous_digest, previous_digest,
	       sizeof(staged->previous_digest));
	memset(staged->event_digest, 0,
	       sizeof(staged->event_digest));
	staged->occupied = true;
	ret = pqcp_sovereign_event_digest(
		staged, staged->event_digest);
	if (ret == 0) {
		ret = pqcp_sovereign_event_verify(staged);
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(staged, sizeof(*staged));
	}
	pqcp_runtime_secure_zero(
		expected_scope, sizeof(expected_scope));
	return ret;
}

static uint64_t next_sequence_value(uint64_t current)
{
	return current == UINT64_MAX ? 0U : current + 1U;
}

int pqcp_sovereign_event_ledger_append(
	struct pqcp_sovereign_event_ledger *ledger,
	const struct pqcp_sovereign_event *event,
	struct pqcp_sovereign_event *committed)
{
	struct pqcp_sovereign_event staged;
	size_t write_index;
	uint64_t next_sequence;
	int ret;

	if (ledger == NULL || !ledger->initialized ||
	    event == NULL ||
	    ledger->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    ledger->events == NULL || ledger->capacity == 0U) {
		return -EINVAL;
	}
	ret = ledger_lock(ledger);
	if (ret != 0) {
		return ret;
	}
	if (ledger->next_sequence == 0U ||
	    ledger->next_sequence == UINT64_MAX) {
		ledger->rejected_count =
			pqcp_sovereign_audit_internal_add_u64(
				ledger->rejected_count, 1U);
		ledger_unlock(ledger);
		return -EOVERFLOW;
	}
	ret = staged_event_prepare(
		event, ledger->next_sequence,
		ledger->chain_head, &staged);
	if (ret != 0) {
		ledger->rejected_count =
			pqcp_sovereign_audit_internal_add_u64(
				ledger->rejected_count, 1U);
		ledger_unlock(ledger);
		return ret;
	}
	next_sequence = next_sequence_value(
		ledger->next_sequence);
	if (next_sequence == 0U) {
		ledger->rejected_count =
			pqcp_sovereign_audit_internal_add_u64(
				ledger->rejected_count, 1U);
		pqcp_runtime_secure_zero(
			&staged, sizeof(staged));
		ledger_unlock(ledger);
		return -EOVERFLOW;
	}
	if (ledger->count == ledger->capacity) {
		const struct pqcp_sovereign_event *evicted =
			&ledger->events[ledger->head];

		if (!evicted->occupied ||
		    pqcp_sovereign_event_verify(evicted) != 0) {
			ledger->rejected_count =
				pqcp_sovereign_audit_internal_add_u64(
					ledger->rejected_count, 1U);
			pqcp_runtime_secure_zero(
				&staged, sizeof(staged));
			ledger_unlock(ledger);
			return -EBADMSG;
		}
		write_index = ledger->head;
		memcpy(ledger->anchor_digest,
		       evicted->event_digest,
		       sizeof(ledger->anchor_digest));
		ledger->head =
			(ledger->head + 1U) % ledger->capacity;
		ledger->evicted_count =
			pqcp_sovereign_audit_internal_add_u64(
				ledger->evicted_count, 1U);
	} else {
		write_index =
			pqcp_sovereign_audit_internal_physical_index(
				ledger, ledger->count);
		ledger->count++;
	}
	ledger->events[write_index] = staged;
	memcpy(ledger->chain_head, staged.event_digest,
	       sizeof(ledger->chain_head));
	ledger->next_sequence = next_sequence;
	ledger->appended_count =
		pqcp_sovereign_audit_internal_add_u64(
			ledger->appended_count, 1U);
	ledger->generation =
		pqcp_sovereign_audit_internal_add_u64(
			ledger->generation, 1U);
	if (committed != NULL) {
		*committed = staged;
	}
	pqcp_runtime_secure_zero(&staged, sizeof(staged));
	ledger_unlock(ledger);
	return 0;
}

int pqcp_sovereign_event_ledger_get(
	struct pqcp_sovereign_event_ledger *ledger,
	uint64_t sequence,
	struct pqcp_sovereign_event *event)
{
	size_t logical_index;
	int ret;

	if (ledger == NULL || !ledger->initialized ||
	    sequence == 0U || event == NULL) {
		return -EINVAL;
	}
	ret = ledger_lock(ledger);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_audit_internal_find_sequence(
		ledger, sequence, &logical_index);
	if (ret == 0) {
		const struct pqcp_sovereign_event *found =
			pqcp_sovereign_audit_internal_logical_event(
				ledger, logical_index);

		if (found == NULL || !found->occupied) {
			ret = -EBADMSG;
		} else {
			*event = *found;
		}
	}
	ledger_unlock(ledger);
	return ret;
}

int pqcp_sovereign_event_ledger_bounds(
	struct pqcp_sovereign_event_ledger *ledger,
	uint64_t *first_sequence,
	uint64_t *last_sequence)
{
	int ret;

	if (ledger == NULL || !ledger->initialized ||
	    first_sequence == NULL || last_sequence == NULL) {
		return -EINVAL;
	}
	ret = ledger_lock(ledger);
	if (ret != 0) {
		return ret;
	}
	if (ledger->count == 0U) {
		*first_sequence = ledger->next_sequence;
		*last_sequence = 0U;
	} else {
		const struct pqcp_sovereign_event *first =
			pqcp_sovereign_audit_internal_logical_event(
				ledger, 0U);
		const struct pqcp_sovereign_event *last =
			pqcp_sovereign_audit_internal_logical_event(
				ledger, ledger->count - 1U);

		if (first == NULL || last == NULL) {
			ret = -EBADMSG;
		} else {
			*first_sequence = first->sequence;
			*last_sequence = last->sequence;
		}
	}
	ledger_unlock(ledger);
	return ret;
}

static int snapshot_digest(
	const struct pqcp_sovereign_event_ledger_snapshot *snapshot,
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES])
{
	uint8_t numeric[LEDGER_SNAPSHOT_NUMERIC_BYTES];
	const uint8_t *parts[LEDGER_SNAPSHOT_PARTS];
	size_t lengths[LEDGER_SNAPSHOT_PARTS];
	size_t offset = 0U;

	if (snapshot == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(numeric, 0, sizeof(numeric));
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, snapshot->schema_version);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, snapshot->generation);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, snapshot->first_sequence);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, snapshot->last_sequence);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, snapshot->next_sequence);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, snapshot->appended_count);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, snapshot->evicted_count);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, snapshot->rejected_count);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, snapshot->count);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, snapshot->capacity);
	offset += 8U;
	parts[0] = (const uint8_t *)
		PQCP_SOVEREIGN_AUDIT_LEDGER_SNAPSHOT_DOMAIN;
	lengths[0] = sizeof(
		PQCP_SOVEREIGN_AUDIT_LEDGER_SNAPSHOT_DOMAIN) - 1U;
	parts[1] = numeric;
	lengths[1] = offset;
	parts[2] = snapshot->anchor_digest;
	lengths[2] = sizeof(snapshot->anchor_digest);
	parts[3] = snapshot->chain_head;
	lengths[3] = sizeof(snapshot->chain_head);
	return pqcp_sovereign_audit_internal_sha256_parts(
		parts, lengths, LEDGER_SNAPSHOT_PARTS, digest);
}

static int snapshot_locked(
	const struct pqcp_sovereign_event_ledger *ledger,
	struct pqcp_sovereign_event_ledger_snapshot *snapshot)
{
	const struct pqcp_sovereign_event *first = NULL;
	const struct pqcp_sovereign_event *last = NULL;
	int ret;

	if (ledger == NULL || snapshot == NULL) {
		return -EINVAL;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->schema_version =
		PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION;
	snapshot->generation = ledger->generation;
	snapshot->next_sequence = ledger->next_sequence;
	snapshot->appended_count = ledger->appended_count;
	snapshot->evicted_count = ledger->evicted_count;
	snapshot->rejected_count = ledger->rejected_count;
	snapshot->count = ledger->count;
	snapshot->capacity = ledger->capacity;
	memcpy(snapshot->anchor_digest,
	       ledger->anchor_digest,
	       sizeof(snapshot->anchor_digest));
	memcpy(snapshot->chain_head,
	       ledger->chain_head,
	       sizeof(snapshot->chain_head));
	if (ledger->count != 0U) {
		first = pqcp_sovereign_audit_internal_logical_event(
			ledger, 0U);
		last = pqcp_sovereign_audit_internal_logical_event(
			ledger, ledger->count - 1U);
		if (first == NULL || last == NULL) {
			return -EBADMSG;
		}
		snapshot->first_sequence = first->sequence;
		snapshot->last_sequence = last->sequence;
	}
	ret = snapshot_digest(
		snapshot, snapshot->snapshot_digest);
	return ret;
}

int pqcp_sovereign_event_ledger_snapshot(
	struct pqcp_sovereign_event_ledger *ledger,
	struct pqcp_sovereign_event_ledger_snapshot *snapshot)
{
	int ret;

	if (ledger == NULL || !ledger->initialized ||
	    snapshot == NULL) {
		return -EINVAL;
	}
	ret = ledger_lock(ledger);
	if (ret != 0) {
		return ret;
	}
	ret = snapshot_locked(ledger, snapshot);
	ledger_unlock(ledger);
	return ret;
}

static int verify_locked(
	const struct pqcp_sovereign_event_ledger *ledger)
{
	uint8_t previous[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint64_t expected_sequence = 0U;

	if (ledger == NULL || !ledger->initialized ||
	    ledger->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    ledger->events == NULL || ledger->capacity == 0U ||
	    ledger->count > ledger->capacity ||
	    ledger->head >= ledger->capacity ||
	    ledger->next_sequence == 0U ||
	    ledger->generation == 0U ||
	    ledger->appended_count < ledger->count ||
	    ledger->appended_count <
		    ledger->evicted_count) {
		return -EINVAL;
	}
	memcpy(previous, ledger->anchor_digest,
	       sizeof(previous));
	for (size_t index = 0U; index < ledger->count;
	     ++index) {
		const struct pqcp_sovereign_event *event =
			pqcp_sovereign_audit_internal_logical_event(
				ledger, index);
		int ret;

		if (event == NULL || !event->occupied) {
			return -EBADMSG;
		}
		if (index == 0U) {
			expected_sequence = event->sequence;
		} else {
			expected_sequence++;
		}
		if (event->sequence != expected_sequence ||
		    !pqcp_sovereign_audit_internal_equal(
			    event->previous_digest, previous,
			    sizeof(previous))) {
			return -EBADMSG;
		}
		ret = pqcp_sovereign_event_verify(event);
		if (ret != 0) {
			return ret;
		}
		memcpy(previous, event->event_digest,
		       sizeof(previous));
	}
	if (ledger->count == 0U) {
		if (!pqcp_sovereign_audit_internal_equal(
			    ledger->chain_head,
			    ledger->anchor_digest,
			    sizeof(ledger->chain_head))) {
			return -EBADMSG;
		}
	} else {
		const struct pqcp_sovereign_event *last =
			pqcp_sovereign_audit_internal_logical_event(
				ledger, ledger->count - 1U);

		if (last == NULL ||
		    !pqcp_sovereign_audit_internal_equal(
			    ledger->chain_head,
			    last->event_digest,
			    sizeof(ledger->chain_head)) ||
		    ledger->next_sequence !=
			    last->sequence + 1U) {
			return -EBADMSG;
		}
	}
	return 0;
}

int pqcp_sovereign_event_ledger_verify(
	struct pqcp_sovereign_event_ledger *ledger)
{
	int ret;

	if (ledger == NULL || !ledger->initialized) {
		return -EINVAL;
	}
	ret = ledger_lock(ledger);
	if (ret != 0) {
		return ret;
	}
	ret = verify_locked(ledger);
	ledger_unlock(ledger);
	return ret;
}
