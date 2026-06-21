/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tamper-evident vault access journal.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool event_valid(
	enum pqcp_edge_vault_journal_event event)
{
	return event >= PQCP_EDGE_VAULT_JOURNAL_CREATE &&
	       event <=
		       PQCP_EDGE_VAULT_JOURNAL_INTEGRITY_FAILURE;
}

static int entry_digest(
	const struct pqcp_edge_vault_journal_entry *entry,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[32];
	const uint8_t *parts[5];
	size_t lengths[5];
	size_t offset = 0U;

	pqcp_edge_internal_write_u32(
		numeric + offset, entry->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, entry->sequence);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, entry->timestamp_ms);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, entry->event);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, (uint32_t)entry->result);
	offset += 4U;
	parts[0] = numeric;
	lengths[0] = offset;
	parts[1] = (const uint8_t *)entry->object_id;
	lengths[1] = strlen(entry->object_id);
	parts[2] = (const uint8_t *)entry->actor_id;
	lengths[2] = strlen(entry->actor_id);
	parts[3] = entry->payload_digest;
	lengths[3] = sizeof(entry->payload_digest);
	parts[4] = entry->previous_digest;
	lengths[4] = sizeof(entry->previous_digest);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 5U, output);
}

static int physical_index_for_sequence(
	const struct pqcp_edge_vault_journal *journal,
	uint64_t sequence)
{
	for (size_t index = 0U;
	     index < journal->capacity; ++index) {
		if (journal->entries[index].occupied &&
		    journal->entries[index].sequence == sequence) {
			return (int)index;
		}
	}
	return -ENOENT;
}

int pqcp_edge_vault_journal_init(
	struct pqcp_edge_vault_journal *journal,
	struct pqcp_edge_vault_journal_entry *entries,
	size_t capacity)
{
	if (journal == NULL || entries == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(journal, 0, sizeof(*journal));
	memset(entries, 0, capacity * sizeof(*entries));
	journal->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	journal->entries = entries;
	journal->capacity = capacity;
	journal->next_sequence = 1U;
	k_mutex_init(&journal->lock);
	journal->initialized = true;
	return 0;
}

int pqcp_edge_vault_journal_append(
	struct pqcp_edge_vault_journal *journal,
	enum pqcp_edge_vault_journal_event event,
	const char *object_id,
	const char *actor_id,
	int result,
	const uint8_t *payload,
	size_t payload_length,
	uint64_t now_ms)
{
	struct pqcp_edge_vault_journal_entry candidate;
	size_t index;
	int ret;

	if (journal == NULL || !journal->initialized ||
	    !event_valid(event) ||
	    !pqcp_edge_internal_text_valid(
		    object_id, PQCP_EDGE_OBJECT_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    actor_id, PQCP_EDGE_ACTOR_MAX_CHARS) ||
	    (payload == NULL && payload_length != 0U)) {
		return -EINVAL;
	}
	k_mutex_lock(&journal->lock, K_FOREVER);
	index = journal->next_index;
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.sequence =
		pqcp_edge_internal_next_identifier(
			&journal->next_sequence);
	candidate.timestamp_ms = now_ms;
	candidate.event = event;
	candidate.result = result;
	ret = pqcp_edge_internal_copy_text(
		candidate.object_id,
		sizeof(candidate.object_id), object_id);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.actor_id,
			sizeof(candidate.actor_id), actor_id);
	}
	if (ret == 0) {
		ret = pqcp_edge_internal_sha256(
			payload, payload_length,
			candidate.payload_digest);
	}
	if (ret == 0) {
		memcpy(candidate.previous_digest,
		       journal->chain_head,
		       sizeof(candidate.previous_digest));
		ret = entry_digest(
			&candidate, candidate.entry_digest);
	}
	if (ret == 0) {
		candidate.occupied = true;
		if (journal->entries[index].occupied) {
			++journal->dropped_count;
		} else if (journal->count <
			   journal->capacity) {
			++journal->count;
		}
		journal->entries[index] = candidate;
		memcpy(journal->chain_head,
		       candidate.entry_digest,
		       sizeof(journal->chain_head));
		journal->next_index =
			(index + 1U) % journal->capacity;
	}
	k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_edge_vault_journal_find(
	struct pqcp_edge_vault_journal *journal,
	uint64_t sequence,
	struct pqcp_edge_vault_journal_entry *entry)
{
	int index;
	int ret = 0;

	if (journal == NULL || !journal->initialized ||
	    sequence == 0U || entry == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&journal->lock, K_FOREVER);
	index = physical_index_for_sequence(
		journal, sequence);
	if (index < 0) {
		ret = index;
	} else {
		*entry = journal->entries[index];
	}
	k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_edge_vault_journal_verify(
	struct pqcp_edge_vault_journal *journal)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t previous[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	uint64_t minimum_sequence = UINT64_MAX;
	uint64_t maximum_sequence = 0U;
	size_t occupied = 0U;
	int ret = 0;

	if (journal == NULL || !journal->initialized ||
	    journal->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    journal->entries == NULL ||
	    journal->capacity == 0U ||
	    journal->count > journal->capacity ||
	    journal->next_index >= journal->capacity) {
		return -EINVAL;
	}
	k_mutex_lock(&journal->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < journal->capacity; ++index) {
		if (!journal->entries[index].occupied) {
			continue;
		}
		++occupied;
		if (journal->entries[index].sequence <
		    minimum_sequence) {
			minimum_sequence =
				journal->entries[index].sequence;
		}
		if (journal->entries[index].sequence >
		    maximum_sequence) {
			maximum_sequence =
				journal->entries[index].sequence;
		}
	}
	if (occupied != journal->count) {
		ret = -EBADMSG;
		goto out;
	}
	if (occupied == 0U) {
		if (!pqcp_edge_internal_all_zero(
			    journal->chain_head,
			    sizeof(journal->chain_head))) {
			ret = -EBADMSG;
		}
		goto out;
	}
	for (uint64_t sequence = minimum_sequence;
	     sequence <= maximum_sequence; ++sequence) {
		int index = physical_index_for_sequence(
			journal, sequence);
		const struct pqcp_edge_vault_journal_entry *entry;

		if (index < 0) {
			ret = -EBADMSG;
			break;
		}
		entry = &journal->entries[index];
		if (entry->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    !event_valid(entry->event) ||
		    !pqcp_edge_internal_text_valid(
			    entry->object_id,
			    sizeof(entry->object_id)) ||
		    !pqcp_edge_internal_text_valid(
			    entry->actor_id,
			    sizeof(entry->actor_id)) ||
		    entry_digest(entry, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    digest, entry->entry_digest,
			    sizeof(digest))) {
			ret = -EBADMSG;
			break;
		}
		if (sequence != minimum_sequence &&
		    !pqcp_edge_internal_equal(
			    entry->previous_digest, previous,
			    sizeof(previous))) {
			ret = -EBADMSG;
			break;
		}
		memcpy(previous, entry->entry_digest,
		       sizeof(previous));
		if (sequence == UINT64_MAX) {
			break;
		}
	}
	if (ret == 0 &&
	    !pqcp_edge_internal_equal(
		    previous, journal->chain_head,
		    sizeof(previous))) {
		ret = -EBADMSG;
	}
out:
	k_mutex_unlock(&journal->lock);
	return ret;
}
