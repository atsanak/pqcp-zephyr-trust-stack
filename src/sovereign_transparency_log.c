/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded hash-chained transparency log with portable witnesses.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_artifact_internal.h"

#define TRANSPARENCY_CHECKPOINT_BYTES 160U

struct transparency_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

static void transparency_write_bytes(
	struct transparency_writer *writer,
	const void *value,
	size_t length)
{
	if (writer == NULL || writer->error != 0) {
		return;
	}
	if ((value == NULL && length != 0U) ||
	    length > writer->capacity - writer->offset) {
		writer->error = -EOVERFLOW;
		return;
	}
	if (length != 0U) {
		memcpy(writer->buffer + writer->offset,
		       value, length);
	}
	writer->offset += length;
}

static void transparency_write_u16(
	struct transparency_writer *writer,
	uint16_t value)
{
	uint8_t encoded[2];

	pqcp_runtime_internal_write_u16(encoded, value);
	transparency_write_bytes(writer, encoded,
				 sizeof(encoded));
}

static void transparency_write_u32(
	struct transparency_writer *writer,
	uint32_t value)
{
	uint8_t encoded[4];

	pqcp_runtime_internal_write_u32(encoded, value);
	transparency_write_bytes(writer, encoded,
				 sizeof(encoded));
}

static void transparency_write_u64(
	struct transparency_writer *writer,
	uint64_t value)
{
	uint8_t encoded[8];

	pqcp_runtime_internal_write_u64(encoded, value);
	transparency_write_bytes(writer, encoded,
				 sizeof(encoded));
}

static void transparency_write_text(
	struct transparency_writer *writer,
	const char *value,
	size_t capacity)
{
	size_t length;

	if (!pqcp_sovereign_internal_text_valid(
		    value, capacity)) {
		if (writer != NULL) {
			writer->error = -EINVAL;
		}
		return;
	}
	length = strnlen(value, capacity);
	if (length > UINT16_MAX) {
		writer->error = -EOVERFLOW;
		return;
	}
	transparency_write_u16(writer, (uint16_t)length);
	transparency_write_bytes(writer, value, length);
}

static bool entry_text_valid(
	const struct pqcp_sovereign_transparency_entry *entry)
{
	return entry != NULL &&
	       pqcp_sovereign_internal_text_valid(
		       entry->subject_id,
		       sizeof(entry->subject_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       entry->event_type,
		       sizeof(entry->event_type)) &&
	       pqcp_sovereign_internal_text_valid(
		       entry->actor_id,
		       sizeof(entry->actor_id));
}

static bool entry_shape_valid(
	const struct pqcp_sovereign_transparency_entry *entry)
{
	return entry != NULL &&
	       entry->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       entry->sequence != 0U &&
	       entry_text_valid(entry) &&
	       entry->timestamp_ms != 0U &&
	       entry->policy_epoch != 0U &&
	       !pqcp_sovereign_internal_all_zero(
		       entry->subject_digest,
		       sizeof(entry->subject_digest)) &&
	       !pqcp_sovereign_internal_all_zero(
		       entry->entry_digest,
		       sizeof(entry->entry_digest)) &&
	       entry->occupied;
}

int pqcp_sovereign_transparency_entry_digest(
	const struct pqcp_sovereign_transparency_entry *entry,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t canonical[
		PQCP_SOVEREIGN_TRANSPARENCY_CANONICAL_BYTES];
	struct transparency_writer writer = {
		.buffer = canonical,
		.capacity = sizeof(canonical),
	};
	int ret;

	if (entry == NULL || output == NULL ||
	    entry->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    entry->sequence == 0U || !entry_text_valid(entry) ||
	    entry->timestamp_ms == 0U ||
	    entry->policy_epoch == 0U ||
	    pqcp_sovereign_internal_all_zero(
		    entry->subject_digest,
		    sizeof(entry->subject_digest))) {
		return -EINVAL;
	}
	memset(canonical, 0, sizeof(canonical));
	transparency_write_bytes(
		&writer, "PQCP-SOVEREIGN-TRANSPARENCY-V1", 30U);
	transparency_write_u32(
		&writer, entry->schema_version);
	transparency_write_u64(&writer, entry->sequence);
	transparency_write_text(
		&writer, entry->subject_id,
		sizeof(entry->subject_id));
	transparency_write_text(
		&writer, entry->event_type,
		sizeof(entry->event_type));
	transparency_write_text(
		&writer, entry->actor_id,
		sizeof(entry->actor_id));
	transparency_write_u64(
		&writer, entry->timestamp_ms);
	transparency_write_u64(
		&writer, entry->policy_epoch);
	transparency_write_bytes(
		&writer, entry->subject_digest,
		sizeof(entry->subject_digest));
	transparency_write_bytes(
		&writer, entry->previous_digest,
		sizeof(entry->previous_digest));
	if (writer.error != 0) {
		pqcp_runtime_secure_zero(
			canonical, sizeof(canonical));
		return writer.error;
	}
	ret = pqcp_runtime_internal_sha256(
		canonical, writer.offset, output);
	pqcp_runtime_secure_zero(canonical, sizeof(canonical));
	return ret;
}

static size_t oldest_index_unlocked(
	const struct pqcp_sovereign_transparency_log *log)
{
	if (log->count == 0U) {
		return log->next_index;
	}
	if (log->count < log->capacity) {
		return 0U;
	}
	return log->next_index;
}

static uint64_t oldest_sequence_unlocked(
	const struct pqcp_sovereign_transparency_log *log)
{
	if (log->count == 0U) {
		return log->next_sequence;
	}
	return log->next_sequence - (uint64_t)log->count;
}

static int sequence_index_unlocked(
	const struct pqcp_sovereign_transparency_log *log,
	uint64_t sequence)
{
	uint64_t oldest_sequence;
	uint64_t offset;
	size_t oldest_index;

	if (log->count == 0U || sequence == 0U) {
		return -ENOENT;
	}
	oldest_sequence = oldest_sequence_unlocked(log);
	if (sequence < oldest_sequence ||
	    sequence >= log->next_sequence) {
		return -ENOENT;
	}
	offset = sequence - oldest_sequence;
	if (offset >= log->count) {
		return -ENOENT;
	}
	oldest_index = oldest_index_unlocked(log);
	return (int)((oldest_index + (size_t)offset) %
		     log->capacity);
}

static int entry_verify(
	const struct pqcp_sovereign_transparency_entry *entry)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int ret;

	if (!entry_shape_valid(entry)) {
		return -EBADMSG;
	}
	ret = pqcp_sovereign_transparency_entry_digest(
		entry, digest);
	if (ret == 0 &&
	    !pqcp_sovereign_internal_equal(
		    digest, entry->entry_digest,
		    sizeof(digest))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int checkpoint_digest(
	const struct pqcp_sovereign_transparency_checkpoint *checkpoint,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t canonical[TRANSPARENCY_CHECKPOINT_BYTES];
	struct transparency_writer writer = {
		.buffer = canonical,
		.capacity = sizeof(canonical),
	};
	int ret;

	if (checkpoint == NULL || output == NULL ||
	    checkpoint->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    checkpoint->sequence == 0U ||
	    checkpoint->policy_epoch == 0U ||
	    pqcp_sovereign_internal_all_zero(
		    checkpoint->chain_head,
		    sizeof(checkpoint->chain_head))) {
		return -EINVAL;
	}
	memset(canonical, 0, sizeof(canonical));
	transparency_write_bytes(
		&writer, "PQCP-SOVEREIGN-CHECKPOINT-V1", 28U);
	transparency_write_u32(
		&writer, checkpoint->schema_version);
	transparency_write_u64(
		&writer, checkpoint->sequence);
	transparency_write_u64(
		&writer, checkpoint->dropped_count);
	transparency_write_u64(
		&writer, checkpoint->policy_epoch);
	transparency_write_bytes(
		&writer, checkpoint->chain_head,
		sizeof(checkpoint->chain_head));
	if (writer.error != 0) {
		return writer.error;
	}
	ret = pqcp_runtime_internal_sha256(
		canonical, writer.offset, output);
	pqcp_runtime_secure_zero(canonical, sizeof(canonical));
	return ret;
}

static int checkpoint_verify(
	const struct pqcp_sovereign_transparency_checkpoint *checkpoint)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int ret;

	if (checkpoint == NULL ||
	    pqcp_sovereign_internal_all_zero(
		    checkpoint->checkpoint_digest,
		    sizeof(checkpoint->checkpoint_digest))) {
		return -EINVAL;
	}
	ret = checkpoint_digest(checkpoint, digest);
	if (ret == 0 &&
	    !pqcp_sovereign_internal_equal(
		    digest, checkpoint->checkpoint_digest,
		    sizeof(digest))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_sovereign_transparency_log_init(
	struct pqcp_sovereign_transparency_log *log,
	struct pqcp_sovereign_transparency_entry *entries,
	size_t capacity)
{
	if (log == NULL || entries == NULL ||
	    capacity == 0U || capacity > INT_MAX) {
		return -EINVAL;
	}
	memset(log, 0, sizeof(*log));
	memset(entries, 0, sizeof(*entries) * capacity);
	log->schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	log->entries = entries;
	log->capacity = capacity;
	log->next_sequence = 1U;
	k_mutex_init(&log->lock);
	log->initialized = true;
	return 0;
}

int pqcp_sovereign_transparency_append(
	struct pqcp_sovereign_transparency_log *log,
	const char *subject_id,
	const char *event_type,
	const char *actor_id,
	uint64_t policy_epoch,
	const uint8_t subject_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_sovereign_transparency_entry *entry)
{
	struct pqcp_sovereign_transparency_entry staged;
	int ret;

	if (log == NULL || !log->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    event_type, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    actor_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    policy_epoch == 0U || subject_digest == NULL ||
	    pqcp_sovereign_internal_all_zero(
		    subject_digest, PQCP_SOVEREIGN_DIGEST_BYTES) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.timestamp_ms = now_ms;
	staged.policy_epoch = policy_epoch;
	staged.occupied = true;
	ret = pqcp_sovereign_internal_copy_text(
		staged.subject_id, sizeof(staged.subject_id),
		subject_id);
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			staged.event_type,
			sizeof(staged.event_type), event_type);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			staged.actor_id, sizeof(staged.actor_id),
			actor_id);
	}
	if (ret != 0) {
		return ret;
	}
	memcpy(staged.subject_digest, subject_digest,
	       sizeof(staged.subject_digest));
	ret = k_mutex_lock(&log->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	staged.sequence = log->next_sequence;
	if (staged.sequence == 0U ||
	    staged.sequence == UINT64_MAX) {
		(void)k_mutex_unlock(&log->lock);
		return -EOVERFLOW;
	}
	memcpy(staged.previous_digest, log->chain_head,
	       sizeof(staged.previous_digest));
	ret = pqcp_sovereign_transparency_entry_digest(
		&staged, staged.entry_digest);
	if (ret != 0) {
		(void)k_mutex_unlock(&log->lock);
		return ret;
	}
	if (log->count == log->capacity) {
		log->dropped_count++;
	} else {
		log->count++;
	}
	log->entries[log->next_index] = staged;
	log->next_index =
		(log->next_index + 1U) % log->capacity;
	log->next_sequence++;
	memcpy(log->chain_head, staged.entry_digest,
	       sizeof(log->chain_head));
	if (entry != NULL) {
		*entry = staged;
	}
	(void)k_mutex_unlock(&log->lock);
	return 0;
}

int pqcp_sovereign_transparency_find(
	struct pqcp_sovereign_transparency_log *log,
	uint64_t sequence,
	struct pqcp_sovereign_transparency_entry *entry)
{
	int index;
	int ret;

	if (log == NULL || !log->initialized ||
	    sequence == 0U || entry == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&log->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = sequence_index_unlocked(log, sequence);
	if (index >= 0) {
		*entry = log->entries[index];
	}
	(void)k_mutex_unlock(&log->lock);
	return index >= 0 ? 0 : index;
}

int pqcp_sovereign_transparency_subject_latest(
	struct pqcp_sovereign_transparency_log *log,
	const char *subject_id,
	struct pqcp_sovereign_transparency_entry *entry)
{
	uint64_t sequence;
	int ret;

	if (log == NULL || !log->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    entry == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&log->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (log->count == 0U) {
		(void)k_mutex_unlock(&log->lock);
		return -ENOENT;
	}
	sequence = log->next_sequence - 1U;
	for (size_t offset = 0U; offset < log->count;
	     ++offset, --sequence) {
		int index = sequence_index_unlocked(log, sequence);

		if (index >= 0 &&
		    strncmp(log->entries[index].subject_id,
			    subject_id,
			    sizeof(log->entries[index].
				   subject_id)) == 0) {
			*entry = log->entries[index];
			(void)k_mutex_unlock(&log->lock);
			return 0;
		}
	}
	(void)k_mutex_unlock(&log->lock);
	return -ENOENT;
}

static int verify_chain_unlocked(
	const struct pqcp_sovereign_transparency_log *log)
{
	uint64_t sequence;
	uint8_t previous[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool first = true;

	if (log->count == 0U) {
		return log->next_sequence == 1U &&
			       log->dropped_count == 0U &&
			       pqcp_sovereign_internal_all_zero(
				       log->chain_head,
				       sizeof(log->chain_head)) ?
			       0 : -EBADMSG;
	}
	sequence = oldest_sequence_unlocked(log);
	memset(previous, 0, sizeof(previous));
	for (size_t offset = 0U; offset < log->count;
	     ++offset, ++sequence) {
		int index = sequence_index_unlocked(log, sequence);
		const struct pqcp_sovereign_transparency_entry *entry;
		int ret;

		if (index < 0) {
			return -EBADMSG;
		}
		entry = &log->entries[index];
		if (entry->sequence != sequence) {
			return -EBADMSG;
		}
		ret = entry_verify(entry);
		if (ret != 0) {
			return ret;
		}
		if (!first &&
		    !pqcp_sovereign_internal_equal(
			    entry->previous_digest, previous,
			    sizeof(previous))) {
			return -EBADMSG;
		}
		if (first && log->dropped_count == 0U &&
		    !pqcp_sovereign_internal_all_zero(
			    entry->previous_digest,
			    sizeof(entry->previous_digest))) {
			return -EBADMSG;
		}
		if (first && log->dropped_count != 0U &&
		    pqcp_sovereign_internal_all_zero(
			    entry->previous_digest,
			    sizeof(entry->previous_digest))) {
			return -EBADMSG;
		}
		memcpy(previous, entry->entry_digest,
		       sizeof(previous));
		first = false;
	}
	if (!pqcp_sovereign_internal_equal(
		    previous, log->chain_head,
		    sizeof(previous))) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_sovereign_transparency_verify(
	struct pqcp_sovereign_transparency_log *log)
{
	int ret;

	if (log == NULL || !log->initialized ||
	    log->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    log->entries == NULL || log->capacity == 0U ||
	    log->next_index >= log->capacity ||
	    log->count > log->capacity ||
	    log->next_sequence == 0U ||
	    log->dropped_count >
		    log->next_sequence - 1U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&log->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = verify_chain_unlocked(log);
	(void)k_mutex_unlock(&log->lock);
	return ret;
}

int pqcp_sovereign_transparency_checkpoint(
	struct pqcp_sovereign_transparency_log *log,
	uint64_t policy_epoch,
	struct pqcp_sovereign_transparency_checkpoint *checkpoint)
{
	int ret;

	if (log == NULL || !log->initialized ||
	    policy_epoch == 0U || checkpoint == NULL) {
		return -EINVAL;
	}
	memset(checkpoint, 0, sizeof(*checkpoint));
	ret = k_mutex_lock(&log->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = verify_chain_unlocked(log);
	if (ret != 0) {
		(void)k_mutex_unlock(&log->lock);
		return ret;
	}
	if (log->count == 0U) {
		(void)k_mutex_unlock(&log->lock);
		return -ENODATA;
	}
	checkpoint->schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	checkpoint->sequence = log->next_sequence - 1U;
	checkpoint->dropped_count = log->dropped_count;
	checkpoint->policy_epoch = policy_epoch;
	memcpy(checkpoint->chain_head, log->chain_head,
	       sizeof(checkpoint->chain_head));
	ret = checkpoint_digest(
		checkpoint, checkpoint->checkpoint_digest);
	(void)k_mutex_unlock(&log->lock);
	return ret;
}

static int copy_sequence_range_unlocked(
	const struct pqcp_sovereign_transparency_log *log,
	uint64_t first,
	uint64_t last,
	struct pqcp_sovereign_transparency_entry *entries,
	size_t capacity,
	size_t *count)
{
	uint64_t range;

	if (first == 0U || last < first ||
	    entries == NULL || count == NULL) {
		return -EINVAL;
	}
	range = last - first + 1U;
	if (range > capacity || range > SIZE_MAX) {
		return -ENOSPC;
	}
	for (uint64_t sequence = first;
	     sequence <= last; ++sequence) {
		int index = sequence_index_unlocked(log, sequence);

		if (index < 0) {
			return -ENOENT;
		}
		entries[(size_t)(sequence - first)] =
			log->entries[index];
	}
	*count = (size_t)range;
	return 0;
}

int pqcp_sovereign_transparency_inclusion_prove(
	struct pqcp_sovereign_transparency_log *log,
	uint64_t subject_sequence,
	uint64_t checkpoint_sequence,
	struct pqcp_sovereign_transparency_inclusion_witness *witness)
{
	struct pqcp_sovereign_transparency_checkpoint checkpoint;
	int subject_index;
	int checkpoint_index;
	int ret;

	if (log == NULL || !log->initialized ||
	    subject_sequence == 0U ||
	    checkpoint_sequence < subject_sequence ||
	    witness == NULL) {
		return -EINVAL;
	}
	memset(witness, 0, sizeof(*witness));
	ret = k_mutex_lock(&log->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = verify_chain_unlocked(log);
	if (ret != 0) {
		(void)k_mutex_unlock(&log->lock);
		return ret;
	}
	subject_index =
		sequence_index_unlocked(log, subject_sequence);
	checkpoint_index =
		sequence_index_unlocked(log, checkpoint_sequence);
	if (subject_index < 0 || checkpoint_index < 0) {
		(void)k_mutex_unlock(&log->lock);
		return -ENOENT;
	}
	ret = copy_sequence_range_unlocked(
		log, subject_sequence, checkpoint_sequence,
		witness->entries,
		PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES,
		&witness->entry_count);
	if (ret != 0) {
		(void)k_mutex_unlock(&log->lock);
		return ret;
	}
	memset(&checkpoint, 0, sizeof(checkpoint));
	checkpoint.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	checkpoint.sequence = checkpoint_sequence;
	checkpoint.dropped_count = log->dropped_count;
	checkpoint.policy_epoch =
		log->entries[checkpoint_index].policy_epoch;
	memcpy(checkpoint.chain_head,
	       log->entries[checkpoint_index].entry_digest,
	       sizeof(checkpoint.chain_head));
	ret = checkpoint_digest(
		&checkpoint, checkpoint.checkpoint_digest);
	if (ret == 0) {
		witness->schema_version =
			PQCP_SOVEREIGN_SCHEMA_VERSION;
		witness->subject_sequence = subject_sequence;
		witness->checkpoint_sequence =
			checkpoint_sequence;
		memcpy(witness->subject_digest,
		       log->entries[subject_index].subject_digest,
		       sizeof(witness->subject_digest));
		memcpy(witness->checkpoint_digest,
		       checkpoint.checkpoint_digest,
		       sizeof(witness->checkpoint_digest));
	}
	(void)k_mutex_unlock(&log->lock);
	return ret;
}

int pqcp_sovereign_transparency_inclusion_verify(
	const struct pqcp_sovereign_transparency_inclusion_witness *witness,
	const struct pqcp_sovereign_transparency_checkpoint *checkpoint)
{
	uint8_t previous[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint64_t expected_sequence;
	int ret;

	if (witness == NULL || checkpoint == NULL ||
	    witness->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    witness->subject_sequence == 0U ||
	    witness->checkpoint_sequence <
		    witness->subject_sequence ||
	    witness->entry_count == 0U ||
	    witness->entry_count >
		    PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES ||
	    witness->entry_count !=
		    (size_t)(witness->checkpoint_sequence -
			     witness->subject_sequence + 1U) ||
	    checkpoint_verify(checkpoint) != 0 ||
	    checkpoint->sequence !=
		    witness->checkpoint_sequence ||
	    !pqcp_sovereign_internal_equal(
		    witness->checkpoint_digest,
		    checkpoint->checkpoint_digest,
		    sizeof(witness->checkpoint_digest))) {
		return -EINVAL;
	}
	memset(previous, 0, sizeof(previous));
	expected_sequence = witness->subject_sequence;
	for (size_t index = 0U;
	     index < witness->entry_count; ++index) {
		const struct pqcp_sovereign_transparency_entry *entry =
			&witness->entries[index];

		if (entry->sequence != expected_sequence) {
			return -EBADMSG;
		}
		ret = entry_verify(entry);
		if (ret != 0) {
			return ret;
		}
		if (index == 0U) {
			if (!pqcp_sovereign_internal_equal(
				    entry->subject_digest,
				    witness->subject_digest,
				    sizeof(witness->
					   subject_digest))) {
				return -EBADMSG;
			}
		} else if (!pqcp_sovereign_internal_equal(
				   entry->previous_digest,
				   previous,
				   sizeof(previous))) {
			return -EBADMSG;
		}
		memcpy(previous, entry->entry_digest,
		       sizeof(previous));
		expected_sequence++;
	}
	if (!pqcp_sovereign_internal_equal(
		    previous, checkpoint->chain_head,
		    sizeof(previous))) {
		return -EBADMSG;
	}
	return 0;
}

static int consistency_witness_digest(
	const struct pqcp_sovereign_transparency_consistency_witness
		*witness,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t prefix[96];
	const uint8_t
		*parts[PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES +
		       1U];
	size_t
		lengths[PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES +
			1U];
	struct transparency_writer writer = {
		.buffer = prefix,
		.capacity = sizeof(prefix),
	};

	if (witness == NULL || output == NULL ||
	    witness->entry_count == 0U ||
	    witness->entry_count >
		    PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES) {
		return -EINVAL;
	}
	memset(prefix, 0, sizeof(prefix));
	transparency_write_bytes(
		&writer, "PQCP-SOVEREIGN-CONSISTENCY-V1", 29U);
	transparency_write_u32(
		&writer, witness->schema_version);
	transparency_write_u64(
		&writer, witness->previous_sequence);
	transparency_write_u64(
		&writer, witness->current_sequence);
	transparency_write_bytes(
		&writer, witness->previous_head,
		sizeof(witness->previous_head));
	transparency_write_bytes(
		&writer, witness->current_head,
		sizeof(witness->current_head));
	if (writer.error != 0) {
		return writer.error;
	}
	parts[0] = prefix;
	lengths[0] = writer.offset;
	for (size_t index = 0U;
	     index < witness->entry_count; ++index) {
		parts[index + 1U] =
			witness->entries[index].entry_digest;
		lengths[index + 1U] =
			PQCP_SOVEREIGN_DIGEST_BYTES;
	}
	return pqcp_sovereign_internal_hash_parts(
		parts, lengths, witness->entry_count + 1U,
		output);
}

int pqcp_sovereign_transparency_consistency_prove(
	struct pqcp_sovereign_transparency_log *log,
	const struct pqcp_sovereign_transparency_checkpoint *previous,
	const struct pqcp_sovereign_transparency_checkpoint *current,
	struct pqcp_sovereign_transparency_consistency_witness *witness)
{
	int previous_index;
	int current_index;
	int ret;

	if (log == NULL || !log->initialized ||
	    checkpoint_verify(previous) != 0 ||
	    checkpoint_verify(current) != 0 ||
	    previous->sequence >= current->sequence ||
	    current->policy_epoch < previous->policy_epoch ||
	    witness == NULL) {
		return -EINVAL;
	}
	memset(witness, 0, sizeof(*witness));
	ret = k_mutex_lock(&log->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = verify_chain_unlocked(log);
	if (ret != 0) {
		(void)k_mutex_unlock(&log->lock);
		return ret;
	}
	previous_index = sequence_index_unlocked(
		log, previous->sequence);
	current_index = sequence_index_unlocked(
		log, current->sequence);
	if (previous_index < 0 || current_index < 0 ||
	    !pqcp_sovereign_internal_equal(
		    log->entries[previous_index].entry_digest,
		    previous->chain_head,
		    PQCP_SOVEREIGN_DIGEST_BYTES) ||
	    !pqcp_sovereign_internal_equal(
		    log->entries[current_index].entry_digest,
		    current->chain_head,
		    PQCP_SOVEREIGN_DIGEST_BYTES)) {
		(void)k_mutex_unlock(&log->lock);
		return -ESTALE;
	}
	ret = copy_sequence_range_unlocked(
		log, previous->sequence + 1U,
		current->sequence, witness->entries,
		PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES,
		&witness->entry_count);
	if (ret == 0) {
		witness->schema_version =
			PQCP_SOVEREIGN_SCHEMA_VERSION;
		witness->previous_sequence =
			previous->sequence;
		witness->current_sequence = current->sequence;
		memcpy(witness->previous_head,
		       previous->chain_head,
		       sizeof(witness->previous_head));
		memcpy(witness->current_head,
		       current->chain_head,
		       sizeof(witness->current_head));
		ret = consistency_witness_digest(
			witness, witness->witness_digest);
	}
	(void)k_mutex_unlock(&log->lock);
	return ret;
}

int pqcp_sovereign_transparency_consistency_verify(
	const struct pqcp_sovereign_transparency_consistency_witness *witness,
	const struct pqcp_sovereign_transparency_checkpoint *previous,
	const struct pqcp_sovereign_transparency_checkpoint *current)
{
	uint8_t previous_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t computed[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint64_t expected_sequence;
	int ret;

	if (witness == NULL ||
	    checkpoint_verify(previous) != 0 ||
	    checkpoint_verify(current) != 0 ||
	    witness->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    witness->previous_sequence != previous->sequence ||
	    witness->current_sequence != current->sequence ||
	    witness->entry_count == 0U ||
	    witness->entry_count !=
		    (size_t)(current->sequence -
			     previous->sequence) ||
	    witness->entry_count >
		    PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES ||
	    !pqcp_sovereign_internal_equal(
		    witness->previous_head, previous->chain_head,
		    sizeof(witness->previous_head)) ||
	    !pqcp_sovereign_internal_equal(
		    witness->current_head, current->chain_head,
		    sizeof(witness->current_head))) {
		return -EINVAL;
	}
	memcpy(previous_digest, previous->chain_head,
	       sizeof(previous_digest));
	expected_sequence = previous->sequence + 1U;
	for (size_t index = 0U;
	     index < witness->entry_count; ++index) {
		const struct pqcp_sovereign_transparency_entry *entry =
			&witness->entries[index];

		if (entry->sequence != expected_sequence ||
		    !pqcp_sovereign_internal_equal(
			    entry->previous_digest,
			    previous_digest,
			    sizeof(previous_digest))) {
			return -EBADMSG;
		}
		ret = entry_verify(entry);
		if (ret != 0) {
			return ret;
		}
		memcpy(previous_digest, entry->entry_digest,
		       sizeof(previous_digest));
		expected_sequence++;
	}
	if (!pqcp_sovereign_internal_equal(
		    previous_digest, current->chain_head,
		    sizeof(previous_digest))) {
		return -EBADMSG;
	}
	ret = consistency_witness_digest(witness, computed);
	if (ret == 0 &&
	    !pqcp_sovereign_internal_equal(
		    computed, witness->witness_digest,
		    sizeof(computed))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(computed, sizeof(computed));
	pqcp_runtime_secure_zero(
		previous_digest, sizeof(previous_digest));
	return ret;
}
