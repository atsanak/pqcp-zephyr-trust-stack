/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded tamper-evident runtime audit chain.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_control.h>

#include "runtime_internal.h"

static bool event_valid(enum pqcp_runtime_audit_event event)
{
	return event >= PQCP_RUNTIME_AUDIT_BOOT &&
	       event <= PQCP_RUNTIME_AUDIT_FAULT;
}

static int digest_entry(
	const struct pqcp_runtime_audit_entry *entry,
	uint8_t output[PQCP_RUNTIME_AUDIT_DIGEST_BYTES])
{
	uint8_t fixed[48];
	const uint8_t *parts[4];
	size_t lengths[4];

	memset(fixed, 0, sizeof(fixed));
	pqcp_runtime_internal_write_u32(
		fixed, entry->schema_version);
	pqcp_runtime_internal_write_u64(
		fixed + 4U, entry->sequence);
	pqcp_runtime_internal_write_u64(
		fixed + 12U, entry->timestamp_ms);
	pqcp_runtime_internal_write_u32(
		fixed + 20U, (uint32_t)entry->event);
	pqcp_runtime_internal_write_u32(
		fixed + 24U, (uint32_t)entry->result);
	pqcp_runtime_internal_write_u64(
		fixed + 28U, entry->object_id);
	pqcp_runtime_internal_write_u32(
		fixed + 36U, entry->reason_mask);
	parts[0] = entry->previous_digest;
	lengths[0] = sizeof(entry->previous_digest);
	parts[1] = fixed;
	lengths[1] = sizeof(fixed);
	parts[2] = (const uint8_t *)entry->profile_id;
	lengths[2] = strnlen(
		entry->profile_id, sizeof(entry->profile_id));
	parts[3] = (const uint8_t *)entry->detail;
	lengths[3] = strnlen(
		entry->detail, sizeof(entry->detail));
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, 4U, output);
}

static size_t physical_index(
	const struct pqcp_runtime_audit_log *log,
	size_t logical_index)
{
	if (log->count < log->capacity) {
		return logical_index;
	}
	return (log->head + logical_index) % log->capacity;
}

int pqcp_runtime_audit_init(
	struct pqcp_runtime_audit_log *log,
	struct pqcp_runtime_audit_entry *entries,
	size_t capacity)
{
	if (log == NULL || entries == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(log, 0, sizeof(*log));
	memset(entries, 0, sizeof(*entries) * capacity);
	log->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	log->entries = entries;
	log->capacity = capacity;
	log->next_sequence = 1U;
	k_mutex_init(&log->lock);
	return 0;
}

int pqcp_runtime_audit_append(
	struct pqcp_runtime_audit_log *log,
	enum pqcp_runtime_audit_event event,
	uint64_t timestamp_ms,
	uint64_t object_id,
	int result,
	uint32_t reason_mask,
	const char *profile_id,
	const char *detail)
{
	struct pqcp_runtime_audit_entry *entry;
	size_t index;
	int ret;

	if (log == NULL ||
	    log->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    !event_valid(event) || timestamp_ms == 0U ||
	    profile_id == NULL || detail == NULL ||
	    !pqcp_runtime_internal_text_valid(
		    profile_id, PQCP_RUNTIME_PROFILE_MAX_CHARS) ||
	    !pqcp_runtime_internal_text_valid(
		    detail, PQCP_RUNTIME_AUDIT_MAX_DETAIL_CHARS)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&log->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = log->head;
	entry = &log->entries[index];
	memset(entry, 0, sizeof(*entry));
	entry->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	entry->sequence = log->next_sequence++;
	entry->timestamp_ms = timestamp_ms;
	entry->event = event;
	entry->result = result;
	entry->object_id = object_id;
	entry->reason_mask = reason_mask;
	memcpy(entry->previous_digest, log->root_digest,
	       sizeof(entry->previous_digest));
	(void)pqcp_runtime_internal_copy_text(
		entry->profile_id, sizeof(entry->profile_id),
		profile_id);
	(void)pqcp_runtime_internal_copy_text(
		entry->detail, sizeof(entry->detail), detail);
	ret = digest_entry(entry, entry->digest);
	if (ret == 0) {
		memcpy(log->root_digest, entry->digest,
		       sizeof(log->root_digest));
		log->head = (log->head + 1U) % log->capacity;
		if (log->count < log->capacity) {
			log->count++;
		} else {
			log->overwritten_count++;
		}
	}
	(void)k_mutex_unlock(&log->lock);
	return ret;
}

const struct pqcp_runtime_audit_entry *pqcp_runtime_audit_get(
	const struct pqcp_runtime_audit_log *log,
	size_t logical_index)
{
	if (log == NULL || logical_index >= log->count) {
		return NULL;
	}
	return &log->entries[
		physical_index(log, logical_index)];
}

int pqcp_runtime_audit_verify(
	struct pqcp_runtime_audit_log *log)
{
	uint8_t previous[PQCP_RUNTIME_AUDIT_DIGEST_BYTES];
	uint8_t expected[PQCP_RUNTIME_AUDIT_DIGEST_BYTES];
	uint64_t previous_sequence = 0U;
	int ret;

	if (log == NULL ||
	    log->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    log->entries == NULL || log->capacity == 0U ||
	    log->count > log->capacity ||
	    log->head >= log->capacity) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&log->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(previous, 0, sizeof(previous));
	for (size_t logical = 0U; logical < log->count; ++logical) {
		const struct pqcp_runtime_audit_entry *entry =
			&log->entries[physical_index(log, logical)];

		if (entry->schema_version !=
			    PQCP_RUNTIME_SCHEMA_VERSION ||
		    !event_valid(entry->event) ||
		    entry->sequence == 0U ||
		    (previous_sequence != 0U &&
		     entry->sequence != previous_sequence + 1U) ||
		    !pqcp_runtime_internal_text_valid(
			    entry->profile_id,
			    sizeof(entry->profile_id)) ||
		    !pqcp_runtime_internal_text_valid(
			    entry->detail,
			    sizeof(entry->detail)) ||
		    digest_entry(entry, expected) != 0 ||
		    memcmp(expected, entry->digest,
			   sizeof(expected)) != 0) {
			(void)k_mutex_unlock(&log->lock);
			return -EBADMSG;
		}
		/*
		 * Once the ring overwrites old entries, the first retained entry
		 * legitimately references a digest outside the retained window.
		 */
		if (logical != 0U &&
		    memcmp(entry->previous_digest, previous,
			   sizeof(previous)) != 0) {
			(void)k_mutex_unlock(&log->lock);
			return -EBADMSG;
		}
		memcpy(previous, entry->digest, sizeof(previous));
		previous_sequence = entry->sequence;
	}
	if (log->count != 0U &&
	    memcmp(previous, log->root_digest,
		   sizeof(previous)) != 0) {
		(void)k_mutex_unlock(&log->lock);
		return -EBADMSG;
	}
	(void)k_mutex_unlock(&log->lock);
	return 0;
}
