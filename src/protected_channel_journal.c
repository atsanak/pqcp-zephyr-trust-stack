/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Fixed-capacity chained journal for protected-channel security events.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/protected_channel_journal.h>

#include "runtime_internal.h"

#define JOURNAL_ENTRY_DOMAIN UINT64_C(0x505143504a454e31)
#define JOURNAL_SNAPSHOT_DOMAIN UINT64_C(0x505143504a534e31)

static bool event_valid(enum pqcp_channel_journal_event event)
{
	return event >= PQCP_CHANNEL_JOURNAL_TLS_READY &&
	       event <= PQCP_CHANNEL_JOURNAL_FAULT;
}

static bool state_valid(enum pqcp_channel_state state)
{
	return state >= PQCP_CHANNEL_STATE_IDLE &&
	       state <= PQCP_CHANNEL_STATE_FAILED;
}

static bool frame_type_valid_or_none(
	enum pqcp_channel_frame_type type)
{
	return type == 0 ||
	       (type >= PQCP_CHANNEL_FRAME_CLIENT_HELLO &&
		type <= PQCP_CHANNEL_FRAME_ALERT);
}

static bool alert_valid(enum pqcp_channel_alert alert)
{
	return alert >= PQCP_CHANNEL_ALERT_NONE &&
	       alert <= PQCP_CHANNEL_ALERT_TIMEOUT;
}

static size_t entry_physical_index(
	const struct pqcp_channel_journal *journal,
	size_t logical_index)
{
	if (journal->count < journal->capacity) {
		return logical_index;
	}
	return (journal->head + logical_index) % journal->capacity;
}

const struct pqcp_channel_journal_entry *pqcp_channel_journal_get(
	const struct pqcp_channel_journal *journal,
	size_t logical_index)
{
	if (journal == NULL || logical_index >= journal->count ||
	    journal->entries == NULL || journal->capacity == 0U) {
		return NULL;
	}
	return &journal->entries[
		entry_physical_index(journal, logical_index)];
}

static int hash_entry(
	const struct pqcp_channel_journal_entry *entry,
	uint8_t output[PQCP_CHANNEL_HASH_BYTES])
{
	uint8_t buffer[256];
	size_t offset = 0U;
	size_t profile_length;
	size_t detail_length;

	if (entry == NULL || output == NULL) {
		return -EINVAL;
	}
	profile_length = strnlen(
		entry->profile_id, sizeof(entry->profile_id));
	detail_length = strnlen(
		entry->detail, sizeof(entry->detail));
	memset(buffer, 0, sizeof(buffer));
	pqcp_runtime_internal_write_u64(
		buffer + offset, JOURNAL_ENTRY_DOMAIN);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, entry->sequence);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, entry->timestamp_ms);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, entry->session_id);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, (uint32_t)entry->event);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, (uint32_t)entry->state);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, (uint32_t)entry->frame_type);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, (uint32_t)entry->alert);
	offset += 4U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, entry->frame_sequence);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, entry->payload_bytes);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, (uint32_t)entry->result);
	offset += 4U;
	memcpy(buffer + offset, entry->transcript_hash,
	       sizeof(entry->transcript_hash));
	offset += sizeof(entry->transcript_hash);
	memcpy(buffer + offset, entry->previous_digest,
	       sizeof(entry->previous_digest));
	offset += sizeof(entry->previous_digest);
	memcpy(buffer + offset, entry->profile_id, profile_length);
	offset += profile_length;
	buffer[offset++] = 0U;
	memcpy(buffer + offset, entry->detail, detail_length);
	offset += detail_length;
	return pqcp_runtime_internal_sha256(buffer, offset, output);
}

static int snapshot_hash(
	const struct pqcp_channel_journal_snapshot *snapshot,
	uint8_t output[PQCP_CHANNEL_HASH_BYTES])
{
	uint8_t buffer[128];
	size_t offset = 0U;

	memset(buffer, 0, sizeof(buffer));
	pqcp_runtime_internal_write_u64(
		buffer + offset, JOURNAL_SNAPSHOT_DOMAIN);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, snapshot->session_id);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, snapshot->first_sequence);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, snapshot->last_sequence);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, snapshot->total_entries);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, snapshot->overwritten_entries);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, snapshot->retained_entries);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, snapshot->alerts);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, snapshot->faults);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, snapshot->replay_rejections);
	offset += 4U;
	memcpy(buffer + offset, snapshot->root_digest,
	       sizeof(snapshot->root_digest));
	offset += sizeof(snapshot->root_digest);
	return pqcp_runtime_internal_sha256(buffer, offset, output);
}

int pqcp_channel_journal_init(
	struct pqcp_channel_journal *journal,
	uint64_t session_id,
	struct pqcp_channel_journal_entry *entries,
	size_t capacity)
{
	if (journal == NULL || entries == NULL ||
	    capacity < 4U || session_id == 0U) {
		return -EINVAL;
	}
	memset(journal, 0, sizeof(*journal));
	memset(entries, 0, sizeof(*entries) * capacity);
	journal->schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	journal->session_id = session_id;
	journal->entries = entries;
	journal->capacity = capacity;
	journal->next_sequence = 1U;
	k_mutex_init(&journal->lock);
	return 0;
}

static int copy_entry_text(
	struct pqcp_channel_journal_entry *entry,
	const struct pqcp_channel *channel,
	const char *detail)
{
	int ret = pqcp_runtime_internal_copy_text(
		entry->profile_id, sizeof(entry->profile_id),
		channel != NULL ?
			channel->config.profile_id : "unknown");

	if (ret != 0) {
		return ret;
	}
	return pqcp_runtime_internal_copy_text(
		entry->detail, sizeof(entry->detail),
		detail != NULL ? detail : "none");
}

static void update_counters(
	struct pqcp_channel_journal *journal,
	enum pqcp_channel_journal_event event)
{
	if (event == PQCP_CHANNEL_JOURNAL_ALERT) {
		journal->alert_count++;
	} else if (event == PQCP_CHANNEL_JOURNAL_FAULT) {
		journal->fault_count++;
	} else if (event ==
		   PQCP_CHANNEL_JOURNAL_REPLAY_REJECTED) {
		journal->replay_rejection_count++;
	}
}

int pqcp_channel_journal_append(
	struct pqcp_channel_journal *journal,
	const struct pqcp_channel *channel,
	enum pqcp_channel_journal_event event,
	enum pqcp_channel_frame_type frame_type,
	uint64_t frame_sequence,
	uint32_t payload_bytes,
	int result,
	const char *detail,
	uint64_t timestamp_ms)
{
	struct pqcp_channel_journal_entry entry;
	size_t index;
	int ret;

	if (journal == NULL || channel == NULL ||
	    journal->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION ||
	    channel->config.session_id != journal->session_id ||
	    !event_valid(event) ||
	    !frame_type_valid_or_none(frame_type) ||
	    timestamp_ms == 0U) {
		return -EINVAL;
	}
	memset(&entry, 0, sizeof(entry));
	entry.schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	entry.sequence = journal->next_sequence;
	entry.timestamp_ms = timestamp_ms;
	entry.session_id = journal->session_id;
	entry.event = event;
	entry.state = channel->state;
	entry.frame_type = frame_type;
	entry.alert = channel->last_alert;
	entry.frame_sequence = frame_sequence;
	entry.payload_bytes = payload_bytes;
	entry.result = result;
	ret = copy_entry_text(&entry, channel, detail);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_transcript_digest(
		&channel->transcript, entry.transcript_hash);
	if (ret != 0 && channel->transcript.initialized) {
		return ret;
	}
	memcpy(entry.previous_digest, journal->root_digest,
	       sizeof(entry.previous_digest));
	ret = hash_entry(&entry, entry.digest);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = journal->head;
	journal->entries[index] = entry;
	journal->head = (journal->head + 1U) % journal->capacity;
	if (journal->count < journal->capacity) {
		journal->count++;
	} else {
		journal->overwritten_entries++;
	}
	journal->next_sequence++;
	memcpy(journal->root_digest, entry.digest,
	       sizeof(journal->root_digest));
	update_counters(journal, event);
	(void)k_mutex_unlock(&journal->lock);
	return 0;
}

static int verify_entry_fields(
	const struct pqcp_channel_journal *journal,
	const struct pqcp_channel_journal_entry *entry)
{
	if (entry == NULL ||
	    entry->schema_version != PQCP_CHANNEL_SCHEMA_VERSION ||
	    entry->session_id != journal->session_id ||
	    entry->sequence == 0U ||
	    entry->timestamp_ms == 0U ||
	    !event_valid(entry->event) ||
	    !state_valid(entry->state) ||
	    !frame_type_valid_or_none(entry->frame_type) ||
	    !alert_valid(entry->alert) ||
	    !pqcp_runtime_internal_text_valid(
		    entry->profile_id,
		    sizeof(entry->profile_id)) ||
	    !pqcp_runtime_internal_text_valid(
		    entry->detail, sizeof(entry->detail))) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_channel_journal_verify(
	struct pqcp_channel_journal *journal)
{
	uint8_t previous[PQCP_CHANNEL_HASH_BYTES] = { 0 };
	uint8_t expected[PQCP_CHANNEL_HASH_BYTES];
	uint64_t previous_sequence = 0U;
	int ret;

	if (journal == NULL ||
	    journal->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION ||
	    journal->session_id == 0U ||
	    journal->entries == NULL ||
	    journal->capacity < 4U ||
	    journal->count > journal->capacity ||
	    journal->head >= journal->capacity ||
	    journal->next_sequence == 0U) {
		return -EBADMSG;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (journal->count > 0U) {
		const struct pqcp_channel_journal_entry *first =
			pqcp_channel_journal_get(journal, 0U);

		memcpy(previous, first->previous_digest,
		       sizeof(previous));
	}
	for (size_t logical = 0U;
	     logical < journal->count; ++logical) {
		const struct pqcp_channel_journal_entry *entry =
			pqcp_channel_journal_get(journal, logical);

		if (verify_entry_fields(journal, entry) != 0 ||
		    (previous_sequence != 0U &&
		     entry->sequence != previous_sequence + 1U) ||
		    memcmp(entry->previous_digest, previous,
			   sizeof(previous)) != 0 ||
		    hash_entry(entry, expected) != 0 ||
		    memcmp(entry->digest, expected,
			   sizeof(expected)) != 0) {
			(void)k_mutex_unlock(&journal->lock);
			return -EBADMSG;
		}
		previous_sequence = entry->sequence;
		memcpy(previous, entry->digest, sizeof(previous));
	}
	if (journal->count != 0U &&
	    memcmp(previous, journal->root_digest,
		   sizeof(previous)) != 0) {
		(void)k_mutex_unlock(&journal->lock);
		return -EBADMSG;
	}
	(void)k_mutex_unlock(&journal->lock);
	return 0;
}

int pqcp_channel_journal_snapshot(
	struct pqcp_channel_journal *journal,
	struct pqcp_channel_journal_snapshot *snapshot)
{
	const struct pqcp_channel_journal_entry *first;
	const struct pqcp_channel_journal_entry *last;
	int ret;

	if (journal == NULL || snapshot == NULL) {
		return -EINVAL;
	}
	ret = pqcp_channel_journal_verify(journal);
	if (ret != 0) {
		return ret;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	snapshot->session_id = journal->session_id;
	snapshot->retained_entries = (uint32_t)journal->count;
	snapshot->overwritten_entries =
		journal->overwritten_entries;
	snapshot->total_entries =
		journal->overwritten_entries + journal->count;
	snapshot->alerts = journal->alert_count;
	snapshot->faults = journal->fault_count;
	snapshot->replay_rejections =
		journal->replay_rejection_count;
	if (journal->count != 0U) {
		first = pqcp_channel_journal_get(journal, 0U);
		last = pqcp_channel_journal_get(
			journal, journal->count - 1U);
		snapshot->first_sequence = first->sequence;
		snapshot->last_sequence = last->sequence;
	}
	memcpy(snapshot->root_digest, journal->root_digest,
	       sizeof(snapshot->root_digest));
	return snapshot_hash(
		snapshot, snapshot->snapshot_digest);
}

int pqcp_channel_journal_snapshot_verify(
	const struct pqcp_channel_journal_snapshot *snapshot)
{
	uint8_t expected[PQCP_CHANNEL_HASH_BYTES];

	if (snapshot == NULL ||
	    snapshot->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION ||
	    snapshot->session_id == 0U ||
	    snapshot->retained_entries >
		    snapshot->total_entries ||
	    snapshot->overwritten_entries >
		    snapshot->total_entries ||
	    (snapshot->retained_entries == 0U &&
	     (snapshot->first_sequence != 0U ||
	      snapshot->last_sequence != 0U)) ||
	    (snapshot->retained_entries != 0U &&
	     snapshot->last_sequence < snapshot->first_sequence) ||
	    snapshot_hash(snapshot, expected) != 0 ||
	    memcmp(expected, snapshot->snapshot_digest,
		   sizeof(expected)) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_channel_journal_emit(
	const struct pqcp_channel_journal_snapshot *snapshot)
{
	char root_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];
	char snapshot_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];

	if (pqcp_channel_journal_snapshot_verify(snapshot) != 0 ||
	    pqcp_runtime_internal_hex(
		    snapshot->root_digest,
		    sizeof(snapshot->root_digest),
		    root_hex, sizeof(root_hex)) != 0 ||
	    pqcp_runtime_internal_hex(
		    snapshot->snapshot_digest,
		    sizeof(snapshot->snapshot_digest),
		    snapshot_hex, sizeof(snapshot_hex)) != 0) {
		return -EBADMSG;
	}
	printk("PQCP_CHANNEL_JOURNAL session=%llu retained=%u total=%llu overwritten=%llu first=%llu last=%llu alerts=%u faults=%u replay_rejections=%u root=%s snapshot=%s\n",
	       (unsigned long long)snapshot->session_id,
	       snapshot->retained_entries,
	       (unsigned long long)snapshot->total_entries,
	       (unsigned long long)snapshot->overwritten_entries,
	       (unsigned long long)snapshot->first_sequence,
	       (unsigned long long)snapshot->last_sequence,
	       snapshot->alerts, snapshot->faults,
	       snapshot->replay_rejections,
	       root_hex, snapshot_hex);
	return 0;
}
