/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Resumable audit export cursors for intermittent uplinks.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int cursor_index(
	const struct pqcp_edge_audit_exporter *exporter,
	uint64_t cursor_id)
{
	for (size_t index = 0U;
	     index < exporter->capacity; ++index) {
		if (exporter->cursors[index].occupied &&
		    exporter->cursors[index].cursor_id ==
			    cursor_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_cursor_index(
	const struct pqcp_edge_audit_exporter *exporter)
{
	for (size_t index = 0U;
	     index < exporter->capacity; ++index) {
		if (!exporter->cursors[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int journal_entry_index(
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

int pqcp_edge_audit_exporter_init(
	struct pqcp_edge_audit_exporter *exporter,
	struct pqcp_edge_export_cursor *cursors,
	size_t capacity)
{
	if (exporter == NULL || cursors == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(exporter, 0, sizeof(*exporter));
	memset(cursors, 0, capacity * sizeof(*cursors));
	exporter->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	exporter->cursors = cursors;
	exporter->capacity = capacity;
	exporter->next_cursor_id = 1U;
	k_mutex_init(&exporter->lock);
	exporter->initialized = true;
	return 0;
}

int pqcp_edge_audit_export_open(
	struct pqcp_edge_audit_exporter *exporter,
	const char *consumer_id,
	uint64_t first_sequence,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	struct pqcp_edge_export_cursor **cursor)
{
	struct pqcp_edge_export_cursor candidate;
	int index;
	int ret;

	if (exporter == NULL || !exporter->initialized ||
	    !pqcp_edge_internal_text_valid(
		    consumer_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    first_sequence == 0U || lifetime_ms == 0U ||
	    cursor == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&exporter->lock, K_FOREVER);
	index = free_cursor_index(exporter);
	if (index < 0) {
		*cursor = NULL;
		k_mutex_unlock(&exporter->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.cursor_id =
		pqcp_edge_internal_next_identifier(
			&exporter->next_cursor_id);
	candidate.next_sequence = first_sequence;
	candidate.acknowledged_sequence =
		first_sequence - 1U;
	candidate.expires_at_ms =
		pqcp_edge_internal_saturating_add_u64(
			now_ms, lifetime_ms);
	ret = pqcp_edge_internal_copy_text(
		candidate.consumer_id,
		sizeof(candidate.consumer_id), consumer_id);
	candidate.occupied = true;
	if (ret == 0) {
		exporter->cursors[index] = candidate;
		*cursor = &exporter->cursors[index];
	} else {
		*cursor = NULL;
	}
	k_mutex_unlock(&exporter->lock);
	return ret;
}

int pqcp_edge_audit_export_batch(
	struct pqcp_edge_audit_exporter *exporter,
	struct pqcp_edge_vault_journal *journal,
	uint64_t cursor_id,
	uint32_t maximum_records,
	uint64_t now_ms,
	struct pqcp_edge_export_batch *batch)
{
	struct pqcp_edge_export_cursor *cursor;
	uint8_t aggregate[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	uint8_t next[PQCP_EDGE_DIGEST_BYTES];
	const uint8_t *parts[2];
	size_t lengths[2];
	uint64_t sequence;
	uint32_t count = 0U;
	int cursor_slot;
	int ret = 0;

	if (exporter == NULL || !exporter->initialized ||
	    journal == NULL || !journal->initialized ||
	    cursor_id == 0U || maximum_records == 0U ||
	    batch == NULL) {
		return -EINVAL;
	}
	memset(batch, 0, sizeof(*batch));
	k_mutex_lock(&exporter->lock, K_FOREVER);
	cursor_slot = cursor_index(exporter, cursor_id);
	if (cursor_slot < 0) {
		ret = cursor_slot;
		goto exporter_out;
	}
	cursor = &exporter->cursors[cursor_slot];
	if (cursor->expires_at_ms <= now_ms) {
		ret = -ETIMEDOUT;
		goto exporter_out;
	}
	k_mutex_lock(&journal->lock, K_FOREVER);
	sequence = cursor->next_sequence;
	while (count < maximum_records) {
		int index = journal_entry_index(
			journal, sequence);

		if (index < 0) {
			break;
		}
		parts[0] = aggregate;
		lengths[0] = sizeof(aggregate);
		parts[1] =
			journal->entries[index].entry_digest;
		lengths[1] =
			sizeof(journal->entries[index].entry_digest);
		ret = pqcp_edge_internal_sha256_parts(
			parts, lengths, 2U, next);
		if (ret != 0) {
			break;
		}
		memcpy(aggregate, next, sizeof(aggregate));
		++count;
		if (sequence == UINT64_MAX) {
			break;
		}
		++sequence;
	}
	k_mutex_unlock(&journal->lock);
	if (ret == 0 && count == 0U) {
		ret = -EAGAIN;
		goto exporter_out;
	}
	if (ret == 0) {
		batch->cursor_id = cursor_id;
		batch->first_sequence = cursor->next_sequence;
		batch->last_sequence =
			cursor->next_sequence + count - 1U;
		batch->record_count = count;
		memcpy(batch->batch_digest, aggregate,
		       sizeof(batch->batch_digest));
		exporter->exported_records =
			pqcp_edge_internal_saturating_add_u64(
				exporter->exported_records, count);
	}
exporter_out:
	k_mutex_unlock(&exporter->lock);
	return ret;
}

int pqcp_edge_audit_export_acknowledge(
	struct pqcp_edge_audit_exporter *exporter,
	uint64_t cursor_id,
	uint64_t sequence)
{
	struct pqcp_edge_export_cursor *cursor;
	int index;
	int ret = 0;

	if (exporter == NULL || !exporter->initialized ||
	    cursor_id == 0U || sequence == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&exporter->lock, K_FOREVER);
	index = cursor_index(exporter, cursor_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	cursor = &exporter->cursors[index];
	if (sequence < cursor->next_sequence ||
	    sequence <= cursor->acknowledged_sequence) {
		ret = -ESTALE;
	} else {
		cursor->acknowledged_sequence = sequence;
		cursor->next_sequence =
			sequence == UINT64_MAX ?
				UINT64_MAX : sequence + 1U;
	}
out:
	k_mutex_unlock(&exporter->lock);
	return ret;
}

int pqcp_edge_audit_export_expire(
	struct pqcp_edge_audit_exporter *exporter,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (exporter == NULL || !exporter->initialized ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&exporter->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < exporter->capacity; ++index) {
		if (exporter->cursors[index].occupied &&
		    exporter->cursors[index].expires_at_ms <=
			    now_ms) {
			memset(&exporter->cursors[index], 0,
			       sizeof(exporter->cursors[index]));
			++expired;
		}
	}
	k_mutex_unlock(&exporter->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_audit_exporter_audit(
	struct pqcp_edge_audit_exporter *exporter)
{
	int ret = 0;

	if (exporter == NULL || !exporter->initialized ||
	    exporter->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    exporter->cursors == NULL ||
	    exporter->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&exporter->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < exporter->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_export_cursor *cursor =
			&exporter->cursors[index];

		if (!cursor->occupied) {
			continue;
		}
		if (cursor->cursor_id == 0U ||
		    cursor->next_sequence == 0U ||
		    !pqcp_edge_internal_text_valid(
			    cursor->consumer_id,
			    sizeof(cursor->consumer_id)) ||
		    cursor->acknowledged_sequence >=
			    cursor->next_sequence) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&exporter->lock);
	return ret;
}
