/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Durable bounded revocation index with monotonic epoch application.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>

#include "runtime_internal.h"

static bool kind_valid(enum pqcp_fleet_revocation_kind kind)
{
	return kind >= PQCP_FLEET_REVOKE_CREDENTIAL &&
	       kind <= PQCP_FLEET_REVOKE_DOMAIN;
}

static int record_index(
	const struct pqcp_fleet_revocation_index *index,
	enum pqcp_fleet_revocation_kind kind,
	const char *subject_id)
{
	for (size_t slot = 0U; slot < index->capacity; ++slot) {
		const struct pqcp_fleet_revocation_record *record =
			&index->records[slot];

		if (record->occupied && record->kind == kind &&
		    strcmp(record->subject_id, subject_id) == 0) {
			return (int)slot;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_revocation_index *index)
{
	for (size_t slot = 0U; slot < index->capacity; ++slot) {
		if (!index->records[slot].occupied) {
			return (int)slot;
		}
	}
	return -1;
}

static int subject_digest(
	enum pqcp_fleet_revocation_kind kind,
	const char *subject_id,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[
		PQCP_FLEET_REVOCATION_SUBJECT_MAX_CHARS + 4U];
	const size_t length = strnlen(
		subject_id,
		PQCP_FLEET_REVOCATION_SUBJECT_MAX_CHARS);

	if (!kind_valid(kind) || length == 0U ||
	    length >= PQCP_FLEET_REVOCATION_SUBJECT_MAX_CHARS) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u32(
		encoded, (uint32_t)kind);
	memcpy(encoded + 4U, subject_id, length);
	int ret = pqcp_runtime_internal_sha256(
		encoded, length + 4U, digest);

	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static int record_validate(
	const struct pqcp_fleet_revocation_record *record)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (!record->occupied) {
		return 0;
	}
	if (record->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    !kind_valid(record->kind) ||
	    !pqcp_runtime_internal_text_valid(
		    record->subject_id,
		    sizeof(record->subject_id)) ||
	    record->effective_at_ms == 0U ||
	    record->expires_at_ms <= record->effective_at_ms ||
	    record->epoch == 0U) {
		return -EBADMSG;
	}
	ret = subject_digest(
		record->kind, record->subject_id, digest);
	if (ret == 0 &&
	    memcmp(digest, record->subject_digest,
		   sizeof(digest)) != 0) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_fleet_revocation_index_init(
	struct pqcp_fleet_revocation_index *index,
	struct pqcp_fleet_revocation_record *records,
	size_t capacity)
{
	if (index == NULL || records == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(index, 0, sizeof(*index));
	memset(records, 0, sizeof(*records) * capacity);
	index->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	index->records = records;
	index->capacity = capacity;
	k_mutex_init(&index->lock);
	index->initialized = true;
	return 0;
}

static int update_validate(
	const struct pqcp_fleet_revocation_update *update,
	uint64_t current_epoch,
	uint64_t now_ms)
{
	if (update == NULL ||
	    update->envelope.type !=
		    PQCP_FLEET_MESSAGE_REVOCATION_UPDATE ||
	    update->envelope.issued_at_ms > now_ms ||
	    update->envelope.expires_at_ms <= now_ms ||
	    update->previous_epoch != current_epoch ||
	    update->envelope.revocation_epoch <= current_epoch ||
	    update->next_refresh_ms <= now_ms ||
	    update->entry_count > PQCP_FLEET_MAX_REVOCATIONS) {
		return -EINVAL;
	}
	for (size_t entry = 0U;
	     entry < update->entry_count; ++entry) {
		const struct pqcp_fleet_revocation_entry *item =
			&update->entries[entry];

		if (!kind_valid(item->kind) ||
		    !pqcp_runtime_internal_text_valid(
			    item->subject_id,
			    sizeof(item->subject_id)) ||
		    item->effective_at_ms == 0U) {
			return -EINVAL;
		}
		for (size_t other = entry + 1U;
		     other < update->entry_count; ++other) {
			if (update->entries[other].kind == item->kind &&
			    strcmp(update->entries[other].subject_id,
				   item->subject_id) == 0) {
				return -EEXIST;
			}
		}
	}
	return 0;
}

static size_t required_free_slots(
	const struct pqcp_fleet_revocation_index *index,
	const struct pqcp_fleet_revocation_update *update)
{
	size_t required = 0U;

	for (size_t entry = 0U;
	     entry < update->entry_count; ++entry) {
		if (record_index(
			    index, update->entries[entry].kind,
			    update->entries[entry].subject_id) < 0) {
			required++;
		}
	}
	return required;
}

static size_t available_slots(
	const struct pqcp_fleet_revocation_index *index)
{
	size_t available = 0U;

	for (size_t slot = 0U; slot < index->capacity; ++slot) {
		if (!index->records[slot].occupied) {
			available++;
		}
	}
	return available;
}

int pqcp_fleet_revocation_index_apply(
	struct pqcp_fleet_revocation_index *index,
	const struct pqcp_fleet_revocation_update *update,
	uint64_t now_ms)
{
	uint64_t expires_at_ms;
	int ret;

	if (index == NULL || !index->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&index->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = update_validate(update, index->current_epoch, now_ms);
	if (ret != 0) {
		index->rejected_updates++;
		(void)k_mutex_unlock(&index->lock);
		return ret;
	}
	if (required_free_slots(index, update) >
	    available_slots(index)) {
		index->rejected_updates++;
		(void)k_mutex_unlock(&index->lock);
		return -ENOSPC;
	}
	if (UINT64_MAX - update->next_refresh_ms <
	    update->offline_grace_ms) {
		index->rejected_updates++;
		(void)k_mutex_unlock(&index->lock);
		return -EOVERFLOW;
	}
	expires_at_ms =
		update->next_refresh_ms + update->offline_grace_ms;
	for (size_t entry = 0U;
	     entry < update->entry_count; ++entry) {
		const struct pqcp_fleet_revocation_entry *item =
			&update->entries[entry];
		struct pqcp_fleet_revocation_record *record;
		int slot = record_index(
			index, item->kind, item->subject_id);

		if (slot < 0) {
			slot = free_index(index);
		}
		record = &index->records[slot];
		memset(record, 0, sizeof(*record));
		record->schema_version =
			PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
		record->kind = item->kind;
		ret = pqcp_runtime_internal_copy_text(
			record->subject_id,
			sizeof(record->subject_id),
			item->subject_id);
		if (ret == 0) {
			ret = subject_digest(
				record->kind, record->subject_id,
				record->subject_digest);
		}
		if (ret != 0) {
			/*
			 * Inputs were prevalidated, so this indicates an
			 * internal invariant failure. Leave the slot empty.
			 */
			memset(record, 0, sizeof(*record));
			index->rejected_updates++;
			(void)k_mutex_unlock(&index->lock);
			return ret;
		}
		record->effective_at_ms = item->effective_at_ms;
		record->expires_at_ms = expires_at_ms;
		record->epoch =
			update->envelope.revocation_epoch;
		record->reason = item->reason;
		record->occupied = true;
	}
	index->current_epoch =
		update->envelope.revocation_epoch;
	index->refresh_due_ms = update->next_refresh_ms;
	index->offline_grace_ms = update->offline_grace_ms;
	index->applied_updates++;
	(void)k_mutex_unlock(&index->lock);
	return 0;
}

int pqcp_fleet_revocation_index_query(
	struct pqcp_fleet_revocation_index *index,
	enum pqcp_fleet_revocation_kind kind,
	const char *subject_id,
	uint64_t now_ms,
	struct pqcp_fleet_revocation_record *record)
{
	int slot;
	int ret;

	if (index == NULL || !index->initialized ||
	    !kind_valid(kind) || subject_id == NULL ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&index->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	slot = record_index(index, kind, subject_id);
	if (slot < 0) {
		(void)k_mutex_unlock(&index->lock);
		return -ENOENT;
	}
	const struct pqcp_fleet_revocation_record *found =
		&index->records[slot];

	if (now_ms < found->effective_at_ms) {
		(void)k_mutex_unlock(&index->lock);
		return -EAGAIN;
	}
	if (now_ms >= found->expires_at_ms) {
		(void)k_mutex_unlock(&index->lock);
		return -ESTALE;
	}
	if (record != NULL) {
		*record = *found;
	}
	(void)k_mutex_unlock(&index->lock);
	return 0;
}

int pqcp_fleet_revocation_index_expire(
	struct pqcp_fleet_revocation_index *index,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret;

	if (index == NULL || !index->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&index->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t slot = 0U; slot < index->capacity; ++slot) {
		struct pqcp_fleet_revocation_record *record =
			&index->records[slot];

		if (record->occupied &&
		    now_ms >= record->expires_at_ms) {
			pqcp_runtime_secure_zero(
				record, sizeof(*record));
			expired++;
		}
	}
	(void)k_mutex_unlock(&index->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_fleet_revocation_index_audit(
	struct pqcp_fleet_revocation_index *index)
{
	int ret;

	if (index == NULL || !index->initialized ||
	    index->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    index->records == NULL || index->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&index->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t slot = 0U; slot < index->capacity; ++slot) {
		const struct pqcp_fleet_revocation_record *record =
			&index->records[slot];

		if (record_validate(record) != 0 ||
		    (record->occupied &&
		     record->epoch > index->current_epoch)) {
			(void)k_mutex_unlock(&index->lock);
			return -EBADMSG;
		}
		if (!record->occupied) {
			continue;
		}
		for (size_t other = slot + 1U;
		     other < index->capacity; ++other) {
			if (index->records[other].occupied &&
			    index->records[other].kind ==
				    record->kind &&
			    strcmp(
				    index->records[other].subject_id,
				    record->subject_id) == 0) {
				(void)k_mutex_unlock(&index->lock);
				return -EEXIST;
			}
		}
	}
	if (index->current_epoch != 0U &&
	    (index->refresh_due_ms == 0U ||
	     UINT64_MAX - index->refresh_due_ms <
		     index->offline_grace_ms)) {
		(void)k_mutex_unlock(&index->lock);
		return -EBADMSG;
	}
	(void)k_mutex_unlock(&index->lock);
	return 0;
}
