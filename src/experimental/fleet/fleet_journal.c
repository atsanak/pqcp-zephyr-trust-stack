/*
 * SPDX-License-Identifier: MIT
 *
 * Bounded hash-chained operational journal for disconnected fleet devices.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_journal.h>

#include "fleet_internal.h"

#define JOURNAL_HASH_DOMAIN "PQCP-FLEET-JOURNAL-V1"
#define JOURNAL_SNAPSHOT_DOMAIN "PQCP-FLEET-JOURNAL-SNAPSHOT-V1"
#define JOURNAL_ENTRY_HASH_BYTES \
	(24U + 8U * 6U + 4U * 7U + \
	 PQCP_FLEET_JOURNAL_SUBJECT_MAX_CHARS + \
	 PQCP_FLEET_JOURNAL_COMPONENT_MAX_CHARS + \
	 PQCP_FLEET_JOURNAL_DETAIL_MAX_BYTES + \
	 PQCP_FLEET_DIGEST_BYTES)
#define JOURNAL_SNAPSHOT_HASH_BYTES \
	(32U + 8U * 8U + 4U * 3U + \
	 PQCP_FLEET_DIGEST_BYTES * 2U)

static bool text_character_valid(char value)
{
	return (value >= 'a' && value <= 'z') ||
	       (value >= 'A' && value <= 'Z') ||
	       (value >= '0' && value <= '9') ||
	       value == '-' || value == '_' || value == '.' ||
	       value == ':' || value == '/' || value == '@';
}

static bool text_valid(const char *text, size_t capacity)
{
	size_t length;

	if (text == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(text, capacity);
	if (length == 0U || length >= capacity) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		if (!text_character_valid(text[index])) {
			return false;
		}
	}
	return true;
}

static int copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	size_t length;

	if (destination == NULL || capacity == 0U ||
	    !text_valid(source, capacity)) {
		return -EINVAL;
	}
	length = strnlen(source, capacity);
	memset(destination, 0, capacity);
	memcpy(destination, source, length);
	return 0;
}

static bool kind_valid(enum pqcp_fleet_journal_kind kind)
{
	return kind > PQCP_FLEET_JOURNAL_NONE &&
	       kind < PQCP_FLEET_JOURNAL_KIND_COUNT;
}

static bool severity_valid(
	enum pqcp_fleet_journal_severity severity)
{
	return severity >= PQCP_FLEET_JOURNAL_DEBUG &&
	       severity <= PQCP_FLEET_JOURNAL_CRITICAL;
}

static uint32_t known_flags(void)
{
	return PQCP_FLEET_JOURNAL_FLAG_SECURITY_RELEVANT |
	       PQCP_FLEET_JOURNAL_FLAG_REQUIRES_UPLOAD |
	       PQCP_FLEET_JOURNAL_FLAG_OPERATOR_VISIBLE |
	       PQCP_FLEET_JOURNAL_FLAG_RECOVERY_RELEVANT |
	       PQCP_FLEET_JOURNAL_FLAG_PRIVACY_REDACTED |
	       PQCP_FLEET_JOURNAL_FLAG_ACKNOWLEDGED |
	       PQCP_FLEET_JOURNAL_FLAG_CHECKPOINT;
}

static void write_u32(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)(value >> 24U);
	output[1] = (uint8_t)(value >> 16U);
	output[2] = (uint8_t)(value >> 8U);
	output[3] = (uint8_t)value;
}

static void write_u64(uint8_t *output, uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[index] =
			(uint8_t)(value >> (56U - index * 8U));
	}
}

static void write_i32(uint8_t *output, int32_t value)
{
	write_u32(output, (uint32_t)value);
}

static int entry_digest(
	const struct pqcp_fleet_journal_entry *entry,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[JOURNAL_ENTRY_HASH_BYTES];
	size_t offset = 0U;

	if (entry == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(encoded, 0, sizeof(encoded));
	memcpy(encoded + offset, JOURNAL_HASH_DOMAIN,
	       sizeof(JOURNAL_HASH_DOMAIN) - 1U);
	offset += sizeof(JOURNAL_HASH_DOMAIN) - 1U;
	write_u32(encoded + offset, entry->schema_version);
	offset += 4U;
	write_u64(encoded + offset, entry->sequence);
	offset += 8U;
	write_u64(encoded + offset, entry->timestamp_ms);
	offset += 8U;
	write_u64(encoded + offset, entry->correlation_id);
	offset += 8U;
	write_u64(encoded + offset, entry->policy_epoch);
	offset += 8U;
	write_u64(encoded + offset, entry->revocation_epoch);
	offset += 8U;
	write_u32(encoded + offset, (uint32_t)entry->kind);
	offset += 4U;
	write_u32(encoded + offset, (uint32_t)entry->severity);
	offset += 4U;
	write_i32(encoded + offset, entry->result);
	offset += 4U;
	write_u32(encoded + offset, entry->reason);
	offset += 4U;
	write_u32(
		encoded + offset,
		entry->flags &
			~PQCP_FLEET_JOURNAL_FLAG_ACKNOWLEDGED);
	offset += 4U;
	write_u32(encoded + offset, entry->detail_length);
	offset += 4U;
	memcpy(encoded + offset, entry->subject,
	       sizeof(entry->subject));
	offset += sizeof(entry->subject);
	memcpy(encoded + offset, entry->component,
	       sizeof(entry->component));
	offset += sizeof(entry->component);
	memcpy(encoded + offset, entry->detail,
	       sizeof(entry->detail));
	offset += sizeof(entry->detail);
	memcpy(encoded + offset, entry->previous_digest,
	       sizeof(entry->previous_digest));
	offset += sizeof(entry->previous_digest);
	if (offset > sizeof(encoded)) {
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return -EOVERFLOW;
	}
	int ret = pqcp_fleet_sha256(encoded, offset, digest);

	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static int snapshot_digest(
	const struct pqcp_fleet_journal_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[JOURNAL_SNAPSHOT_HASH_BYTES];
	size_t offset = 0U;

	if (snapshot == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(encoded, 0, sizeof(encoded));
	memcpy(encoded + offset, JOURNAL_SNAPSHOT_DOMAIN,
	       sizeof(JOURNAL_SNAPSHOT_DOMAIN) - 1U);
	offset += sizeof(JOURNAL_SNAPSHOT_DOMAIN) - 1U;
	write_u32(encoded + offset, snapshot->schema_version);
	offset += 4U;
	write_u64(encoded + offset, snapshot->generation);
	offset += 8U;
	write_u64(encoded + offset, snapshot->oldest_sequence);
	offset += 8U;
	write_u64(encoded + offset, snapshot->newest_sequence);
	offset += 8U;
	write_u64(encoded + offset, snapshot->acknowledged_through);
	offset += 8U;
	write_u64(encoded + offset, snapshot->dropped_entries);
	offset += 8U;
	write_u64(encoded + offset, snapshot->security_entries);
	offset += 8U;
	write_u64(
		encoded + offset,
		snapshot->pending_upload_entries);
	offset += 8U;
	write_u64(encoded + offset, snapshot->count);
	offset += 8U;
	write_u32(encoded + offset, (uint32_t)snapshot->capacity);
	offset += 4U;
	memcpy(encoded + offset, snapshot->anchor_digest,
	       sizeof(snapshot->anchor_digest));
	offset += sizeof(snapshot->anchor_digest);
	memcpy(encoded + offset, snapshot->tail_digest,
	       sizeof(snapshot->tail_digest));
	offset += sizeof(snapshot->tail_digest);
	int ret = pqcp_fleet_sha256(encoded, offset, digest);

	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static size_t physical_index(
	const struct pqcp_fleet_journal *journal,
	size_t logical_index)
{
	return (journal->head + logical_index) %
	       journal->capacity;
}

static struct pqcp_fleet_journal_entry *logical_entry(
	struct pqcp_fleet_journal *journal,
	size_t logical_index)
{
	if (journal == NULL || logical_index >= journal->count) {
		return NULL;
	}
	return &journal->entries[
		physical_index(journal, logical_index)];
}

static const struct pqcp_fleet_journal_entry *
logical_entry_const(
	const struct pqcp_fleet_journal *journal,
	size_t logical_index)
{
	if (journal == NULL || logical_index >= journal->count) {
		return NULL;
	}
	return &journal->entries[
		physical_index(journal, logical_index)];
}

static int find_sequence(
	const struct pqcp_fleet_journal *journal,
	uint64_t sequence,
	size_t *logical_index)
{
	if (journal == NULL || logical_index == NULL ||
	    sequence == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < journal->count; ++index) {
		const struct pqcp_fleet_journal_entry *entry =
			logical_entry_const(journal, index);

		if (entry != NULL && entry->occupied &&
		    entry->sequence == sequence) {
			*logical_index = index;
			return 0;
		}
		if (entry != NULL && entry->sequence > sequence) {
			break;
		}
	}
	return -ENOENT;
}

static bool filter_text_matches(
	const char *filter,
	const char *value,
	size_t capacity)
{
	if (filter == NULL || filter[0] == '\0') {
		return true;
	}
	if (!text_valid(filter, capacity)) {
		return false;
	}
	return strncmp(filter, value, capacity) == 0;
}

static bool entry_matches(
	const struct pqcp_fleet_journal_entry *entry,
	const struct pqcp_fleet_journal_filter *filter)
{
	if (entry == NULL || !entry->occupied) {
		return false;
	}
	if (filter == NULL) {
		return true;
	}
	if (filter->sequence_after != 0U &&
	    entry->sequence <= filter->sequence_after) {
		return false;
	}
	if (filter->sequence_before != 0U &&
	    entry->sequence >= filter->sequence_before) {
		return false;
	}
	if (filter->timestamp_after_ms != 0U &&
	    entry->timestamp_ms <= filter->timestamp_after_ms) {
		return false;
	}
	if (filter->timestamp_before_ms != 0U &&
	    entry->timestamp_ms >= filter->timestamp_before_ms) {
		return false;
	}
	if (filter->correlation_id != 0U &&
	    entry->correlation_id != filter->correlation_id) {
		return false;
	}
	if ((entry->flags & filter->required_flags) !=
	    filter->required_flags) {
		return false;
	}
	if ((entry->flags & filter->forbidden_flags) != 0U) {
		return false;
	}
	if (filter->kind != PQCP_FLEET_JOURNAL_NONE &&
	    entry->kind != filter->kind) {
		return false;
	}
	if (entry->severity < filter->minimum_severity) {
		return false;
	}
	if (!filter_text_matches(
		    filter->subject, entry->subject,
		    sizeof(entry->subject))) {
		return false;
	}
	return filter_text_matches(
		filter->component, entry->component,
		sizeof(entry->component));
}

static bool append_valid(
	const struct pqcp_fleet_journal_append *append)
{
	return append != NULL &&
	       append->timestamp_ms != 0U &&
	       kind_valid(append->kind) &&
	       severity_valid(append->severity) &&
	       (append->flags & ~known_flags()) == 0U &&
	       (append->flags &
		PQCP_FLEET_JOURNAL_FLAG_ACKNOWLEDGED) == 0U &&
	       text_valid(
		       append->subject,
		       PQCP_FLEET_JOURNAL_SUBJECT_MAX_CHARS) &&
	       text_valid(
		       append->component,
		       PQCP_FLEET_JOURNAL_COMPONENT_MAX_CHARS) &&
	       append->detail_length <=
		       PQCP_FLEET_JOURNAL_DETAIL_MAX_BYTES &&
	       (append->detail != NULL ||
		append->detail_length == 0U);
}

static bool journal_ready(
	const struct pqcp_fleet_journal *journal)
{
	return journal != NULL && journal->initialized &&
	       journal->entries != NULL &&
	       journal->capacity != 0U &&
	       journal->count <= journal->capacity &&
	       journal->head < journal->capacity &&
	       journal->next_sequence != 0U &&
	       journal->generation != 0U;
}

static int make_room(
	struct pqcp_fleet_journal *journal)
{
	struct pqcp_fleet_journal_entry *oldest;

	if (journal->count < journal->capacity) {
		return 0;
	}
	oldest = logical_entry(journal, 0U);
	if (oldest == NULL || !oldest->occupied) {
		return -EBADMSG;
	}
	if ((oldest->flags &
	     PQCP_FLEET_JOURNAL_FLAG_ACKNOWLEDGED) == 0U) {
		return -ENOSPC;
	}
	memcpy(journal->anchor_digest, oldest->digest,
	       sizeof(journal->anchor_digest));
	if ((oldest->flags &
	     PQCP_FLEET_JOURNAL_FLAG_SECURITY_RELEVANT) != 0U &&
	    journal->security_entries != 0U) {
		journal->security_entries--;
	}
	if ((oldest->flags &
	     PQCP_FLEET_JOURNAL_FLAG_REQUIRES_UPLOAD) != 0U &&
	    journal->pending_upload_entries != 0U) {
		journal->pending_upload_entries--;
	}
	pqcp_runtime_secure_zero(oldest, sizeof(*oldest));
	journal->head =
		(journal->head + 1U) % journal->capacity;
	journal->count--;
	journal->dropped_entries++;
	return 0;
}

static int append_locked(
	struct pqcp_fleet_journal *journal,
	const struct pqcp_fleet_journal_append *append,
	struct pqcp_fleet_journal_entry *committed)
{
	struct pqcp_fleet_journal_entry candidate;
	size_t index;
	int ret;

	ret = make_room(journal);
	if (ret != 0) {
		journal->rejected_entries++;
		return ret;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_FLEET_JOURNAL_SCHEMA_VERSION;
	candidate.sequence = journal->next_sequence;
	candidate.timestamp_ms = append->timestamp_ms;
	candidate.correlation_id = append->correlation_id;
	candidate.policy_epoch = append->policy_epoch;
	candidate.revocation_epoch = append->revocation_epoch;
	candidate.kind = append->kind;
	candidate.severity = append->severity;
	candidate.result = append->result;
	candidate.reason = append->reason;
	candidate.flags = append->flags;
	candidate.detail_length =
		(uint32_t)append->detail_length;
	ret = copy_text(
		candidate.subject, sizeof(candidate.subject),
		append->subject);
	if (ret == 0) {
		ret = copy_text(
			candidate.component,
			sizeof(candidate.component),
			append->component);
	}
	if (ret != 0) {
		journal->rejected_entries++;
		return ret;
	}
	if (append->detail_length != 0U) {
		memcpy(candidate.detail, append->detail,
		       append->detail_length);
	}
	memcpy(candidate.previous_digest,
	       journal->tail_digest,
	       sizeof(candidate.previous_digest));
	candidate.occupied = true;
	ret = entry_digest(&candidate, candidate.digest);
	if (ret != 0) {
		journal->rejected_entries++;
		return ret;
	}
	index = physical_index(journal, journal->count);
	journal->entries[index] = candidate;
	journal->count++;
	journal->next_sequence++;
	if (journal->next_sequence == 0U) {
		journal->next_sequence = 1U;
	}
	journal->generation++;
	memcpy(journal->tail_digest, candidate.digest,
	       sizeof(journal->tail_digest));
	if ((candidate.flags &
	     PQCP_FLEET_JOURNAL_FLAG_SECURITY_RELEVANT) != 0U) {
		journal->security_entries++;
	}
	if ((candidate.flags &
	     PQCP_FLEET_JOURNAL_FLAG_REQUIRES_UPLOAD) != 0U) {
		journal->pending_upload_entries++;
	}
	if (committed != NULL) {
		*committed = candidate;
	}
	return 0;
}

int pqcp_fleet_journal_init(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_entry *entries,
	size_t capacity,
	uint64_t first_sequence,
	const uint8_t anchor_digest[PQCP_FLEET_DIGEST_BYTES])
{
	if (journal == NULL || entries == NULL ||
	    capacity == 0U || first_sequence == 0U) {
		return -EINVAL;
	}
	memset(entries, 0, capacity * sizeof(*entries));
	memset(journal, 0, sizeof(*journal));
	journal->entries = entries;
	journal->capacity = capacity;
	journal->next_sequence = first_sequence;
	journal->generation = 1U;
	if (anchor_digest != NULL) {
		memcpy(journal->anchor_digest, anchor_digest,
		       sizeof(journal->anchor_digest));
		memcpy(journal->tail_digest, anchor_digest,
		       sizeof(journal->tail_digest));
	}
	k_mutex_init(&journal->lock);
	journal->initialized = true;
	return 0;
}

int pqcp_fleet_journal_append(
	struct pqcp_fleet_journal *journal,
	const struct pqcp_fleet_journal_append *append,
	struct pqcp_fleet_journal_entry *committed)
{
	int ret;

	if (!journal_ready(journal) || !append_valid(append)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = append_locked(journal, append, committed);
	(void)k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_fleet_journal_get(
	struct pqcp_fleet_journal *journal,
	uint64_t sequence,
	struct pqcp_fleet_journal_entry *entry)
{
	size_t logical_index;
	int ret;

	if (!journal_ready(journal) || sequence == 0U ||
	    entry == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = find_sequence(journal, sequence, &logical_index);
	if (ret == 0) {
		*entry = *logical_entry(journal, logical_index);
	}
	(void)k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_fleet_journal_latest(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_entry *entry)
{
	int ret;

	if (!journal_ready(journal) || entry == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (journal->count == 0U) {
		ret = -ENOENT;
	} else {
		*entry = *logical_entry(
			journal, journal->count - 1U);
		ret = 0;
	}
	(void)k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_fleet_journal_cursor_init(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_cursor *cursor,
	uint64_t sequence_after)
{
	int ret;

	if (!journal_ready(journal) || cursor == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(cursor, 0, sizeof(*cursor));
	cursor->next_sequence =
		sequence_after == UINT64_MAX ?
			UINT64_MAX : sequence_after + 1U;
	if (cursor->next_sequence == 0U) {
		cursor->next_sequence =
			journal->count != 0U ?
				logical_entry(
					journal, 0U)->sequence :
				journal->next_sequence;
	}
	cursor->observed_generation = journal->generation;
	cursor->initialized = true;
	(void)k_mutex_unlock(&journal->lock);
	return 0;
}

int pqcp_fleet_journal_cursor_next(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_cursor *cursor,
	const struct pqcp_fleet_journal_filter *filter,
	struct pqcp_fleet_journal_entry *entry)
{
	int ret;

	if (!journal_ready(journal) || cursor == NULL ||
	    !cursor->initialized || entry == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = -ENOENT;
	for (size_t index = 0U; index < journal->count; ++index) {
		const struct pqcp_fleet_journal_entry *candidate =
			logical_entry_const(journal, index);

		if (candidate->sequence < cursor->next_sequence) {
			continue;
		}
		cursor->next_sequence =
			candidate->sequence == UINT64_MAX ?
				UINT64_MAX :
				candidate->sequence + 1U;
		if (entry_matches(candidate, filter)) {
			*entry = *candidate;
			ret = 0;
			break;
		}
	}
	cursor->observed_generation = journal->generation;
	(void)k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_fleet_journal_query(
	struct pqcp_fleet_journal *journal,
	const struct pqcp_fleet_journal_filter *filter,
	struct pqcp_fleet_journal_entry *output,
	size_t output_capacity,
	size_t *output_count)
{
	size_t count = 0U;
	int ret;

	if (!journal_ready(journal) || output_count == NULL ||
	    (output == NULL && output_capacity != 0U)) {
		return -EINVAL;
	}
	*output_count = 0U;
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < journal->count && count < output_capacity;
	     ++index) {
		const struct pqcp_fleet_journal_entry *entry =
			logical_entry_const(journal, index);

		if (entry_matches(entry, filter)) {
			output[count++] = *entry;
		}
	}
	*output_count = count;
	(void)k_mutex_unlock(&journal->lock);
	return 0;
}

int pqcp_fleet_journal_export_batch(
	struct pqcp_fleet_journal *journal,
	uint64_t sequence_after,
	size_t maximum_entries,
	bool upload_required_only,
	struct pqcp_fleet_journal_batch *batch)
{
	int ret;

	if (!journal_ready(journal) || batch == NULL ||
	    maximum_entries == 0U ||
	    maximum_entries >
		    PQCP_FLEET_JOURNAL_BATCH_MAX_ENTRIES) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(batch, 0, sizeof(*batch));
	for (size_t index = 0U;
	     index < journal->count &&
	     batch->count < maximum_entries;
	     ++index) {
		const struct pqcp_fleet_journal_entry *entry =
			logical_entry_const(journal, index);

		if (entry->sequence <= sequence_after ||
		    (upload_required_only &&
		     (entry->flags &
		      PQCP_FLEET_JOURNAL_FLAG_REQUIRES_UPLOAD) ==
			     0U)) {
			continue;
		}
		if (batch->count == 0U) {
			batch->first_sequence = entry->sequence;
			memcpy(batch->first_previous_digest,
			       entry->previous_digest,
			       sizeof(batch->first_previous_digest));
		}
		batch->entries[batch->count++] = *entry;
		batch->last_sequence = entry->sequence;
		memcpy(batch->last_digest, entry->digest,
		       sizeof(batch->last_digest));
	}
	if (batch->count != 0U) {
		const struct pqcp_fleet_journal_entry *newest =
			logical_entry_const(
				journal, journal->count - 1U);

		batch->complete =
			batch->last_sequence == newest->sequence;
	}
	(void)k_mutex_unlock(&journal->lock);
	return 0;
}

int pqcp_fleet_journal_acknowledge(
	struct pqcp_fleet_journal *journal,
	uint64_t sequence,
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t *acknowledged_count)
{
	size_t logical_index;
	uint64_t count = 0U;
	int ret;

	if (!journal_ready(journal) || sequence == 0U ||
	    digest == NULL || acknowledged_count == NULL) {
		return -EINVAL;
	}
	*acknowledged_count = 0U;
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = find_sequence(journal, sequence, &logical_index);
	if (ret == 0 &&
	    memcmp(logical_entry(journal, logical_index)->digest,
		   digest, PQCP_FLEET_DIGEST_BYTES) != 0) {
		ret = -EKEYREJECTED;
	}
	if (ret == 0) {
		for (size_t index = 0U;
		     index <= logical_index; ++index) {
			struct pqcp_fleet_journal_entry *entry =
				logical_entry(journal, index);

			if ((entry->flags &
			     PQCP_FLEET_JOURNAL_FLAG_ACKNOWLEDGED) !=
			    0U) {
				continue;
			}
			entry->flags |=
				PQCP_FLEET_JOURNAL_FLAG_ACKNOWLEDGED;
			if ((entry->flags &
			     PQCP_FLEET_JOURNAL_FLAG_REQUIRES_UPLOAD) !=
			    0U &&
			    journal->pending_upload_entries != 0U) {
				journal->pending_upload_entries--;
			}
			count++;
		}
		if (sequence > journal->acknowledged_through) {
			journal->acknowledged_through = sequence;
		}
		journal->generation++;
		*acknowledged_count = count;
	}
	(void)k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_fleet_journal_prune(
	struct pqcp_fleet_journal *journal,
	size_t maximum_to_prune,
	uint64_t *pruned_count)
{
	uint64_t count = 0U;
	int ret;

	if (!journal_ready(journal) ||
	    maximum_to_prune == 0U || pruned_count == NULL) {
		return -EINVAL;
	}
	*pruned_count = 0U;
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	while (journal->count != 0U &&
	       count < maximum_to_prune) {
		struct pqcp_fleet_journal_entry *entry =
			logical_entry(journal, 0U);

		if ((entry->flags &
		     PQCP_FLEET_JOURNAL_FLAG_ACKNOWLEDGED) == 0U) {
			break;
		}
		memcpy(journal->anchor_digest, entry->digest,
		       sizeof(journal->anchor_digest));
		if ((entry->flags &
		     PQCP_FLEET_JOURNAL_FLAG_SECURITY_RELEVANT) != 0U &&
		    journal->security_entries != 0U) {
			journal->security_entries--;
		}
		pqcp_runtime_secure_zero(entry, sizeof(*entry));
		journal->head =
			(journal->head + 1U) %
			journal->capacity;
		journal->count--;
		journal->dropped_entries++;
		count++;
	}
	if (count != 0U) {
		journal->generation++;
		if (journal->count == 0U) {
			memcpy(journal->tail_digest,
			       journal->anchor_digest,
			       sizeof(journal->tail_digest));
		}
	}
	*pruned_count = count;
	(void)k_mutex_unlock(&journal->lock);
	return 0;
}

int pqcp_fleet_journal_checkpoint(
	struct pqcp_fleet_journal *journal,
	uint64_t timestamp_ms,
	const char *component,
	struct pqcp_fleet_journal_entry *entry)
{
	struct pqcp_fleet_journal_snapshot snapshot;
	struct pqcp_fleet_journal_append append;
	int ret;

	if (!journal_ready(journal) || timestamp_ms == 0U ||
	    !text_valid(
		    component,
		    PQCP_FLEET_JOURNAL_COMPONENT_MAX_CHARS)) {
		return -EINVAL;
	}
	ret = pqcp_fleet_journal_snapshot(journal, &snapshot);
	if (ret != 0) {
		return ret;
	}
	memset(&append, 0, sizeof(append));
	append.timestamp_ms = timestamp_ms;
	append.correlation_id = snapshot.generation;
	append.kind = PQCP_FLEET_JOURNAL_PEER_SYNCHRONIZED;
	append.severity = PQCP_FLEET_JOURNAL_NOTICE;
	append.flags =
		PQCP_FLEET_JOURNAL_FLAG_CHECKPOINT |
		PQCP_FLEET_JOURNAL_FLAG_SECURITY_RELEVANT |
		PQCP_FLEET_JOURNAL_FLAG_REQUIRES_UPLOAD;
	append.subject = "journal";
	append.component = component;
	append.detail = snapshot.digest;
	append.detail_length = sizeof(snapshot.digest);
	ret = pqcp_fleet_journal_append(
		journal, &append, entry);
	pqcp_runtime_secure_zero(
		&snapshot, sizeof(snapshot));
	return ret;
}

int pqcp_fleet_journal_snapshot(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_snapshot *snapshot)
{
	int ret;

	if (!journal_ready(journal) || snapshot == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->schema_version =
		PQCP_FLEET_JOURNAL_SCHEMA_VERSION;
	snapshot->generation = journal->generation;
	snapshot->acknowledged_through =
		journal->acknowledged_through;
	snapshot->dropped_entries =
		journal->dropped_entries;
	snapshot->security_entries =
		journal->security_entries;
	snapshot->pending_upload_entries =
		journal->pending_upload_entries;
	snapshot->count = journal->count;
	snapshot->capacity = journal->capacity;
	memcpy(snapshot->anchor_digest,
	       journal->anchor_digest,
	       sizeof(snapshot->anchor_digest));
	memcpy(snapshot->tail_digest,
	       journal->tail_digest,
	       sizeof(snapshot->tail_digest));
	if (journal->count != 0U) {
		snapshot->oldest_sequence =
			logical_entry_const(
				journal, 0U)->sequence;
		snapshot->newest_sequence =
			logical_entry_const(
				journal,
				journal->count - 1U)->sequence;
	}
	ret = snapshot_digest(snapshot, snapshot->digest);
	(void)k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_fleet_journal_entry_verify(
	const struct pqcp_fleet_journal_entry *entry)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (entry == NULL || !entry->occupied ||
	    entry->schema_version !=
		    PQCP_FLEET_JOURNAL_SCHEMA_VERSION ||
	    entry->sequence == 0U ||
	    entry->timestamp_ms == 0U ||
	    !kind_valid(entry->kind) ||
	    !severity_valid(entry->severity) ||
	    (entry->flags & ~known_flags()) != 0U ||
	    !text_valid(entry->subject,
			sizeof(entry->subject)) ||
	    !text_valid(entry->component,
			sizeof(entry->component)) ||
	    entry->detail_length >
		    sizeof(entry->detail)) {
		return -EINVAL;
	}
	ret = entry_digest(entry, digest);
	if (ret == 0 &&
	    memcmp(digest, entry->digest,
		   sizeof(digest)) != 0) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_fleet_journal_verify(
	struct pqcp_fleet_journal *journal)
{
	uint8_t previous[PQCP_FLEET_DIGEST_BYTES];
	uint64_t expected_sequence = 0U;
	uint64_t security_entries = 0U;
	uint64_t pending_upload_entries = 0U;
	int ret;

	if (!journal_ready(journal)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memcpy(previous, journal->anchor_digest,
	       sizeof(previous));
	ret = 0;
	for (size_t index = 0U; index < journal->count;
	     ++index) {
		const struct pqcp_fleet_journal_entry *entry =
			logical_entry_const(journal, index);

		if (pqcp_fleet_journal_entry_verify(entry) != 0 ||
		    memcmp(entry->previous_digest, previous,
			   sizeof(previous)) != 0 ||
		    (expected_sequence != 0U &&
		     entry->sequence != expected_sequence)) {
			ret = -EBADMSG;
			break;
		}
		expected_sequence =
			entry->sequence == UINT64_MAX ?
				UINT64_MAX :
				entry->sequence + 1U;
		memcpy(previous, entry->digest,
		       sizeof(previous));
		if ((entry->flags &
		     PQCP_FLEET_JOURNAL_FLAG_SECURITY_RELEVANT) != 0U) {
			security_entries++;
		}
		if ((entry->flags &
		     PQCP_FLEET_JOURNAL_FLAG_REQUIRES_UPLOAD) != 0U &&
		    (entry->flags &
		     PQCP_FLEET_JOURNAL_FLAG_ACKNOWLEDGED) == 0U) {
			pending_upload_entries++;
		}
	}
	if (ret == 0 &&
	    (memcmp(previous, journal->tail_digest,
		    sizeof(previous)) != 0 ||
	     security_entries != journal->security_entries ||
	     pending_upload_entries !=
		     journal->pending_upload_entries ||
	     (journal->count != 0U &&
	      expected_sequence != journal->next_sequence))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(previous, sizeof(previous));
	(void)k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_fleet_journal_batch_verify(
	const struct pqcp_fleet_journal_batch *batch)
{
	uint8_t previous[PQCP_FLEET_DIGEST_BYTES];

	if (batch == NULL ||
	    batch->count >
		    PQCP_FLEET_JOURNAL_BATCH_MAX_ENTRIES ||
	    (batch->count == 0U &&
	     (batch->first_sequence != 0U ||
	      batch->last_sequence != 0U))) {
		return -EINVAL;
	}
	if (batch->count == 0U) {
		return 0;
	}
	memcpy(previous, batch->first_previous_digest,
	       sizeof(previous));
	for (size_t index = 0U; index < batch->count;
	     ++index) {
		const struct pqcp_fleet_journal_entry *entry =
			&batch->entries[index];

		if (pqcp_fleet_journal_entry_verify(entry) != 0 ||
		    memcmp(entry->previous_digest, previous,
			   sizeof(previous)) != 0 ||
		    (index != 0U &&
		     entry->sequence !=
			     batch->entries[index - 1U].
				     sequence + 1U)) {
			pqcp_runtime_secure_zero(
				previous, sizeof(previous));
			return -EBADMSG;
		}
		memcpy(previous, entry->digest,
		       sizeof(previous));
	}
	const bool valid =
		batch->first_sequence ==
			batch->entries[0].sequence &&
		batch->last_sequence ==
			batch->entries[batch->count - 1U].
				sequence &&
		memcmp(batch->last_digest, previous,
		       sizeof(previous)) == 0;

	pqcp_runtime_secure_zero(previous, sizeof(previous));
	return valid ? 0 : -EBADMSG;
}

const char *pqcp_fleet_journal_kind_str(
	enum pqcp_fleet_journal_kind kind)
{
	switch (kind) {
	case PQCP_FLEET_JOURNAL_NONE:
		return "none";
	case PQCP_FLEET_JOURNAL_BOOT:
		return "boot";
	case PQCP_FLEET_JOURNAL_ENROLLMENT_STARTED:
		return "enrollment_started";
	case PQCP_FLEET_JOURNAL_ENROLLMENT_COMPLETED:
		return "enrollment_completed";
	case PQCP_FLEET_JOURNAL_POLICY_RECEIVED:
		return "policy_received";
	case PQCP_FLEET_JOURNAL_POLICY_APPLIED:
		return "policy_applied";
	case PQCP_FLEET_JOURNAL_POLICY_REJECTED:
		return "policy_rejected";
	case PQCP_FLEET_JOURNAL_CREDENTIAL_ROTATION_STARTED:
		return "credential_rotation_started";
	case PQCP_FLEET_JOURNAL_CREDENTIAL_ROTATION_COMMITTED:
		return "credential_rotation_committed";
	case PQCP_FLEET_JOURNAL_CREDENTIAL_ROTATION_ABORTED:
		return "credential_rotation_aborted";
	case PQCP_FLEET_JOURNAL_UPDATE_AUTHORIZED:
		return "update_authorized";
	case PQCP_FLEET_JOURNAL_UPDATE_STAGED:
		return "update_staged";
	case PQCP_FLEET_JOURNAL_UPDATE_COMMITTED:
		return "update_committed";
	case PQCP_FLEET_JOURNAL_UPDATE_ROLLED_BACK:
		return "update_rolled_back";
	case PQCP_FLEET_JOURNAL_REVOCATION_APPLIED:
		return "revocation_applied";
	case PQCP_FLEET_JOURNAL_ATTESTATION_EMITTED:
		return "attestation_emitted";
	case PQCP_FLEET_JOURNAL_ATTESTATION_REJECTED:
		return "attestation_rejected";
	case PQCP_FLEET_JOURNAL_COMMAND_ACCEPTED:
		return "command_accepted";
	case PQCP_FLEET_JOURNAL_COMMAND_APPLIED:
		return "command_applied";
	case PQCP_FLEET_JOURNAL_COMMAND_REJECTED:
		return "command_rejected";
	case PQCP_FLEET_JOURNAL_RECOVERY_ENTERED:
		return "recovery_entered";
	case PQCP_FLEET_JOURNAL_RECOVERY_COMPLETED:
		return "recovery_completed";
	case PQCP_FLEET_JOURNAL_QUARANTINE_ENTERED:
		return "quarantine_entered";
	case PQCP_FLEET_JOURNAL_QUARANTINE_RELEASED:
		return "quarantine_released";
	case PQCP_FLEET_JOURNAL_CHANNEL_ESTABLISHED:
		return "channel_established";
	case PQCP_FLEET_JOURNAL_CHANNEL_CLOSED:
		return "channel_closed";
	case PQCP_FLEET_JOURNAL_PEER_SYNCHRONIZED:
		return "peer_synchronized";
	case PQCP_FLEET_JOURNAL_DECOMMISSIONED:
		return "decommissioned";
	default:
		return "invalid";
	}
}

const char *pqcp_fleet_journal_severity_str(
	enum pqcp_fleet_journal_severity severity)
{
	switch (severity) {
	case PQCP_FLEET_JOURNAL_DEBUG:
		return "debug";
	case PQCP_FLEET_JOURNAL_INFO:
		return "info";
	case PQCP_FLEET_JOURNAL_NOTICE:
		return "notice";
	case PQCP_FLEET_JOURNAL_WARNING:
		return "warning";
	case PQCP_FLEET_JOURNAL_ERROR:
		return "error";
	case PQCP_FLEET_JOURNAL_CRITICAL:
		return "critical";
	default:
		return "invalid";
	}
}
