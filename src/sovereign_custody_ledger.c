/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Hash-chained, allocation-free custody transcript.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"
#include "sovereign_ceremony_internal.h"

#define CUSTODY_EVENT_DOMAIN "pqcp-sovereign-custody-event-v1"

static int lock_ledger(struct pqcp_sovereign_custody_ledger *ledger)
{
	if (ledger == NULL || !ledger->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&ledger->lock, K_FOREVER);
}

static void unlock_ledger(
	struct pqcp_sovereign_custody_ledger *ledger)
{
	(void)k_mutex_unlock(&ledger->lock);
}

static bool custody_action_valid(const char *action)
{
	static const char *const actions[] = {
		"ceremony-opened",
		"approval-accepted",
		"contribution-accepted",
		"key-generated",
		"key-rotated",
		"key-retired",
		"key-destroyed",
		"key-recovered",
		"secret-granted",
		"secret-used",
		"secret-revoked",
		"ceremony-aborted",
	};
	size_t index;

	if (!pqcp_sovereign_ceremony_text_valid(
		    action, PQCP_SOVEREIGN_LABEL_MAX_CHARS)) {
		return false;
	}
	for (index = 0U; index < ARRAY_SIZE(actions); ++index) {
		if (strcmp(actions[index], action) == 0) {
			return true;
		}
	}
	return false;
}

static int custody_event_digest(
	const struct pqcp_sovereign_custody_event *event,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_CUSTODY_BYTES];
	size_t offset = 0U;
	int ret;

	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, CUSTODY_EVENT_DOMAIN,
		sizeof(CUSTODY_EVENT_DOMAIN));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, event->schema_version);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, event->sequence);
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, event->key_id,
		sizeof(event->key_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, event->custodian_id,
		sizeof(event->custodian_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, event->action,
		sizeof(event->action));
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, event->key_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, event->timestamp_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, event->policy_epoch);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, event->evidence_digest,
		sizeof(event->evidence_digest));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, event->previous_digest,
		sizeof(event->previous_digest));
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_sovereign_ceremony_hash(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static bool custody_event_shape_valid(
	const struct pqcp_sovereign_custody_event *event)
{
	uint8_t expected[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool valid;

	if (event == NULL || !event->occupied ||
	    event->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    event->sequence == 0U ||
	    !pqcp_sovereign_ceremony_text_valid(
		    event->key_id, sizeof(event->key_id)) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    event->custodian_id, sizeof(event->custodian_id)) ||
	    !custody_action_valid(event->action) ||
	    event->key_epoch == 0U ||
	    event->timestamp_ms == 0U ||
	    event->policy_epoch == 0U ||
	    pqcp_sovereign_ceremony_digest_zero(
		    event->evidence_digest) ||
	    pqcp_sovereign_ceremony_digest_zero(
		    event->event_digest)) {
		return false;
	}
	if (custody_event_digest(event, expected) != 0) {
		return false;
	}
	valid = pqcp_sovereign_ceremony_digest_equal(
		expected, event->event_digest);
	pqcp_runtime_secure_zero(expected, sizeof(expected));
	return valid;
}

static size_t oldest_index_locked(
	const struct pqcp_sovereign_custody_ledger *ledger)
{
	if (ledger->count == 0U) {
		return ledger->next_index;
	}
	if (ledger->count < ledger->capacity) {
		return 0U;
	}
	return ledger->next_index;
}

static size_t chronological_index_locked(
	const struct pqcp_sovereign_custody_ledger *ledger,
	size_t ordinal)
{
	const size_t oldest = oldest_index_locked(ledger);

	return (oldest + ordinal) % ledger->capacity;
}

static int event_index_by_sequence_locked(
	const struct pqcp_sovereign_custody_ledger *ledger,
	uint64_t sequence)
{
	size_t ordinal;

	for (ordinal = 0U; ordinal < ledger->count; ++ordinal) {
		const size_t index =
			chronological_index_locked(ledger, ordinal);

		if (ledger->events[index].occupied &&
		    ledger->events[index].sequence == sequence) {
			return (int)index;
		}
	}
	return -ENOENT;
}

int pqcp_sovereign_custody_ledger_init(
	struct pqcp_sovereign_custody_ledger *ledger,
	struct pqcp_sovereign_custody_event *events,
	size_t capacity)
{
	if (ledger == NULL || events == NULL || capacity == 0U ||
	    capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(ledger, 0, sizeof(*ledger));
	memset(events, 0, capacity * sizeof(*events));
	ledger->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	ledger->events = events;
	ledger->capacity = capacity;
	ledger->next_sequence = 1U;
	k_mutex_init(&ledger->lock);
	ledger->initialized = true;
	return 0;
}

int pqcp_sovereign_custody_append(
	struct pqcp_sovereign_custody_ledger *ledger,
	const char *key_id,
	const char *custodian_id,
	const char *action,
	uint64_t key_epoch,
	uint64_t policy_epoch,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_sovereign_custody_event *event)
{
	struct pqcp_sovereign_custody_event staged;
	int ret;

	if (!pqcp_sovereign_ceremony_text_valid(
		    key_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    custodian_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !custody_action_valid(action) ||
	    key_epoch == 0U || policy_epoch == 0U ||
	    evidence_digest == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(
		    evidence_digest) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_ledger(ledger);
	if (ret != 0) {
		return ret;
	}
	if (ledger->next_sequence == 0U ||
	    ledger->next_sequence == UINT64_MAX ||
	    ledger->next_index >= ledger->capacity ||
	    ledger->count > ledger->capacity) {
		unlock_ledger(ledger);
		return -EOVERFLOW;
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.sequence = ledger->next_sequence;
	ret = pqcp_sovereign_ceremony_copy_text(
		staged.key_id, sizeof(staged.key_id), key_id);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.custodian_id,
			sizeof(staged.custodian_id), custodian_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.action, sizeof(staged.action), action);
	}
	if (ret != 0) {
		unlock_ledger(ledger);
		return ret;
	}
	staged.key_epoch = key_epoch;
	staged.timestamp_ms = now_ms;
	staged.policy_epoch = policy_epoch;
	memcpy(staged.evidence_digest, evidence_digest,
	       sizeof(staged.evidence_digest));
	memcpy(staged.previous_digest, ledger->chain_head,
	       sizeof(staged.previous_digest));
	staged.occupied = true;
	ret = custody_event_digest(
		&staged, staged.event_digest);
	if (ret != 0) {
		unlock_ledger(ledger);
		return ret;
	}
	if (ledger->count == ledger->capacity) {
		if (ledger->dropped_count != UINT64_MAX) {
			ledger->dropped_count++;
		}
	} else {
		ledger->count++;
	}
	ledger->events[ledger->next_index] = staged;
	ledger->next_index =
		(ledger->next_index + 1U) % ledger->capacity;
	ledger->next_sequence++;
	memcpy(ledger->chain_head, staged.event_digest,
	       sizeof(ledger->chain_head));
	if (event != NULL) {
		*event = staged;
	}
	unlock_ledger(ledger);
	return 0;
}

int pqcp_sovereign_custody_find(
	struct pqcp_sovereign_custody_ledger *ledger,
	uint64_t sequence,
	struct pqcp_sovereign_custody_event *event)
{
	int index;
	int ret;

	if (sequence == 0U || event == NULL) {
		return -EINVAL;
	}
	ret = lock_ledger(ledger);
	if (ret != 0) {
		return ret;
	}
	index = event_index_by_sequence_locked(ledger, sequence);
	if (index < 0) {
		unlock_ledger(ledger);
		return index;
	}
	*event = ledger->events[index];
	unlock_ledger(ledger);
	return 0;
}

static int verify_chain_locked(
	const struct pqcp_sovereign_custody_ledger *ledger)
{
	uint8_t previous[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t expected[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint64_t expected_sequence = 0U;
	size_t ordinal;
	int ret = 0;

	memset(previous, 0, sizeof(previous));
	memset(expected, 0, sizeof(expected));
	if (ledger->count != 0U) {
		const size_t first =
			chronological_index_locked(ledger, 0U);

		memcpy(previous,
		       ledger->events[first].previous_digest,
		       sizeof(previous));
		expected_sequence =
			ledger->events[first].sequence;
	}
	for (ordinal = 0U; ordinal < ledger->count; ++ordinal) {
		const size_t index =
			chronological_index_locked(ledger, ordinal);
		const struct pqcp_sovereign_custody_event *entry =
			&ledger->events[index];

		if (!custody_event_shape_valid(entry) ||
		    entry->sequence != expected_sequence ||
		    !pqcp_sovereign_ceremony_digest_equal(
			    previous, entry->previous_digest)) {
			ret = -EBADMSG;
			break;
		}
		ret = custody_event_digest(entry, expected);
		if (ret != 0 ||
		    !pqcp_sovereign_ceremony_digest_equal(
			    expected, entry->event_digest)) {
			ret = ret != 0 ? ret : -EBADMSG;
			break;
		}
		memcpy(previous, entry->event_digest,
		       sizeof(previous));
		if (expected_sequence == UINT64_MAX) {
			ret = -EOVERFLOW;
			break;
		}
		expected_sequence++;
	}
	if (ret == 0 &&
	    !pqcp_sovereign_ceremony_digest_equal(
		    previous, ledger->chain_head)) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(previous, sizeof(previous));
	pqcp_runtime_secure_zero(expected, sizeof(expected));
	return ret;
}

int pqcp_sovereign_custody_verify(
	struct pqcp_sovereign_custody_ledger *ledger)
{
	size_t index;
	size_t occupied = 0U;
	int ret;

	ret = lock_ledger(ledger);
	if (ret != 0) {
		return ret;
	}
	if (ledger->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    ledger->events == NULL ||
	    ledger->capacity == 0U ||
	    ledger->next_index >= ledger->capacity ||
	    ledger->count > ledger->capacity ||
	    ledger->next_sequence == 0U) {
		unlock_ledger(ledger);
		return -EBADMSG;
	}
	for (index = 0U; index < ledger->capacity; ++index) {
		if (ledger->events[index].occupied) {
			occupied++;
		}
	}
	if (occupied != ledger->count) {
		unlock_ledger(ledger);
		return -EBADMSG;
	}
	if (ledger->count == 0U) {
		if (!pqcp_sovereign_ceremony_digest_zero(
			    ledger->chain_head) ||
		    ledger->next_sequence != 1U ||
		    ledger->dropped_count != 0U) {
			unlock_ledger(ledger);
			return -EBADMSG;
		}
		unlock_ledger(ledger);
		return 0;
	}
	if (ledger->next_sequence <= ledger->count ||
	    ledger->next_sequence - 1U <
		    ledger->dropped_count) {
		unlock_ledger(ledger);
		return -EBADMSG;
	}
	ret = verify_chain_locked(ledger);
	unlock_ledger(ledger);
	return ret;
}
