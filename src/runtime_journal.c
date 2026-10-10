/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */
#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_journal.h>
#include "runtime_internal.h"

#define JOURNAL_MAGIC 0x504a5254U
#define JOURNAL_SCHEMA 1U
#define HEADER_HASH_OFFSET 96U

static size_t payload_aligned(const struct pqcp_runtime_journal *journal, size_t size)
{
	return (size + journal->io.write_bytes - 1U) /
		journal->io.write_bytes * journal->io.write_bytes;
}

static void commit_encode(uint8_t bytes[PQCP_RUNTIME_JOURNAL_COMMIT_BYTES],
	const uint8_t header[PQCP_RUNTIME_JOURNAL_HEADER_BYTES])
{
	memcpy(bytes, "PQJCOM01", 8U);
	memcpy(bytes + 8U, header + 8U, 8U);
	memcpy(bytes + 16U, header + HEADER_HASH_OFFSET, 16U);
}

static bool erased(const uint8_t *bytes, size_t size)
{
	for (size_t i = 0U; i < size; ++i) {
		if (bytes[i] != 0xffU) {
			return false;
		}
	}
	return true;
}

/* Always reload payload from storage, never trust the cached scratch bytes. */
static int inspect_slot(struct pqcp_runtime_journal *journal, unsigned int slot,
	bool committed, uint64_t *generation, size_t *length)
{
	uint8_t header[PQCP_RUNTIME_JOURNAL_HEADER_BYTES];
	uint8_t actual[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t marker[PQCP_RUNTIME_JOURNAL_COMMIT_BYTES];
	uint8_t expected[PQCP_RUNTIME_JOURNAL_COMMIT_BYTES];
	const size_t base = slot * journal->slot_bytes;
	int ret = journal->io.read(journal->io.context, base, header, sizeof(header));

	if (ret != 0) {
		return ret;
	}
	if (erased(header, sizeof(header))) {
		return -ENODATA;
	}
	if (pqcp_runtime_internal_read_u32(header) != JOURNAL_MAGIC ||
	    pqcp_runtime_internal_read_u32(header + 4U) != JOURNAL_SCHEMA) {
		return -EBADMSG;
	}
	ret = pqcp_runtime_internal_sha256(header, HEADER_HASH_OFFSET, actual);
	if (ret != 0) {
		return ret;
	}
	if (memcmp(actual, header + HEADER_HASH_OFFSET, sizeof(actual)) != 0) {
		return -EBADMSG;
	}
	if (memcmp(header + 24U, journal->binding, sizeof(journal->binding)) != 0) {
		return -EXDEV;
	}
	*generation = pqcp_runtime_internal_read_u64(header + 8U);
	*length = pqcp_runtime_internal_read_u32(header + 16U);
	if (*generation == 0U || *length == 0U ||
	    *length > journal->scratch_capacity ||
	    *length > journal->slot_bytes - sizeof(header) - sizeof(marker)) {
		return -EBADMSG;
	}
	if (*generation < journal->minimum_generation) {
		return -ESTALE;
	}
	if (committed) {
		ret = journal->io.read(journal->io.context,
			base + journal->slot_bytes - sizeof(marker), marker, sizeof(marker));
		if (ret != 0) {
			return ret;
		}
		commit_encode(expected, header);
		if (memcmp(marker, expected, sizeof(marker)) != 0) {
			return -EBADMSG;
		}
	}
	ret = journal->io.read(journal->io.context, base + sizeof(header),
		journal->scratch, *length);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_internal_sha256(journal->scratch, *length, actual);
	if (ret != 0) {
		return ret;
	}
	return memcmp(actual, header + 56U, sizeof(actual)) == 0 ? 0 : -EBADMSG;
}

int pqcp_runtime_journal_open(struct pqcp_runtime_journal *journal,
	const struct pqcp_runtime_journal_io *io, size_t slot_bytes,
	const uint8_t binding[PQCP_RUNTIME_DIGEST_BYTES],
	uint64_t minimum_generation, uint8_t *scratch, size_t scratch_capacity)
{
	unsigned int invalid = 0U;
	int invalid_reason = -EBADMSG;

	if (journal == NULL || io == NULL || binding == NULL || scratch == NULL ||
	    io->read == NULL || io->write == NULL || io->erase == NULL || io->sync == NULL ||
	    io->write_bytes == 0U || io->write_bytes > PQCP_RUNTIME_JOURNAL_MAX_ALIGNMENT ||
	    PQCP_RUNTIME_JOURNAL_COMMIT_BYTES % io->write_bytes != 0U ||
	    io->erase_bytes == 0U || slot_bytes % io->erase_bytes != 0U ||
	    slot_bytes <= PQCP_RUNTIME_JOURNAL_HEADER_BYTES + PQCP_RUNTIME_JOURNAL_COMMIT_BYTES ||
	    slot_bytes > io->region_bytes / 2U || slot_bytes % io->write_bytes != 0U ||
	    scratch_capacity < PQCP_RUNTIME_JOURNAL_MAX_ALIGNMENT ||
	    scratch_capacity > UINT32_MAX - PQCP_RUNTIME_JOURNAL_MAX_ALIGNMENT) {
		return -EINVAL;
	}
	memset(journal, 0, sizeof(*journal));
	journal->io = *io;
	journal->scratch = scratch;
	journal->scratch_capacity = scratch_capacity;
	journal->slot_bytes = slot_bytes;
	journal->minimum_generation = minimum_generation;
	memcpy(journal->binding, binding, sizeof(journal->binding));
	k_mutex_init(&journal->lock);
	for (unsigned int slot = 0U; slot < 2U; ++slot) {
		uint64_t generation;
		size_t length;
		int ret = inspect_slot(journal, slot, true, &generation, &length);

		if (ret == -ENODATA) {
			continue;
		}
		if (ret == -EBADMSG || ret == -EXDEV || ret == -ESTALE) {
			invalid++;
			invalid_reason = ret;
			continue;
		}
		if (ret != 0) {
			return ret;
		}
		if (journal->has_snapshot && generation == journal->generation) {
			return -EBADMSG;
		}
		if (!journal->has_snapshot || generation > journal->generation) {
			journal->active_slot = slot;
			journal->generation = generation;
			journal->snapshot_bytes = length;
			journal->has_snapshot = true;
		}
	}
	if (!journal->has_snapshot && invalid != 0U) {
		return invalid_reason;
	}
	journal->ready = true;
	return 0;
}

int pqcp_runtime_journal_save(struct pqcp_runtime_journal *journal,
	const struct pqcp_runtime_session *sessions, size_t session_capacity,
	const struct pqcp_runtime_profile_state *profiles, size_t profile_capacity)
{
	struct pqcp_runtime_snapshot_info info;
	uint8_t header[PQCP_RUNTIME_JOURNAL_HEADER_BYTES] = {0};
	uint8_t marker[PQCP_RUNTIME_JOURNAL_COMMIT_BYTES];
	uint64_t generation;
	size_t length;
	size_t padded;
	size_t base;
	unsigned int target;
	int ret;

	if (journal == NULL || !journal->ready) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (!journal->ready || journal->generation == UINT64_MAX) {
		ret = journal->ready ? -EOVERFLOW : -EIO;
		goto out;
	}
	ret = pqcp_runtime_snapshot_write(sessions, session_capacity, profiles,
		profile_capacity, journal->scratch, journal->scratch_capacity, &info);
	if (ret != 0) {
		goto out;
	}
	length = info.bytes_written;
	padded = payload_aligned(journal, length);
	if (padded > journal->scratch_capacity || padded > journal->slot_bytes -
	    sizeof(header) - sizeof(marker)) {
		ret = -ENOSPC;
		goto out;
	}
	generation = journal->generation + 1U;
	if (generation < journal->minimum_generation) {
		generation = journal->minimum_generation;
	}
	target = journal->has_snapshot ? 1U - journal->active_slot : 0U;
	base = target * journal->slot_bytes;
	pqcp_runtime_internal_write_u32(header, JOURNAL_MAGIC);
	pqcp_runtime_internal_write_u32(header + 4U, JOURNAL_SCHEMA);
	pqcp_runtime_internal_write_u64(header + 8U, generation);
	pqcp_runtime_internal_write_u32(header + 16U, (uint32_t)length);
	memcpy(header + 24U, journal->binding, sizeof(journal->binding));
	ret = pqcp_runtime_internal_sha256(journal->scratch, length, header + 56U);
	if (ret == 0) {
		ret = pqcp_runtime_internal_sha256(header, HEADER_HASH_OFFSET,
			header + HEADER_HASH_OFFSET);
	}
	if (ret != 0) {
		goto out;
	}
	memset(journal->scratch + length, 0, padded - length);
	/* An interrupted erase/write never targets the last committed slot. */
	ret = journal->io.erase(journal->io.context, base, journal->slot_bytes);
	if (ret == 0) {
		ret = journal->io.write(journal->io.context, base, header, sizeof(header));
	}
	if (ret == 0) {
		ret = journal->io.write(journal->io.context, base + sizeof(header),
			journal->scratch, padded);
	}
	if (ret == 0) {
		ret = journal->io.sync(journal->io.context);
	}
	if (ret == 0) {
		ret = inspect_slot(journal, target, false, &generation, &length);
	}
	if (ret == 0) {
		commit_encode(marker, header);
		ret = journal->io.write(journal->io.context,
			base + journal->slot_bytes - sizeof(marker), marker, sizeof(marker));
	}
	if (ret == 0) {
		ret = journal->io.sync(journal->io.context);
	}
	if (ret == 0) {
		ret = inspect_slot(journal, target, true, &generation, &length);
	}
	if (ret == 0) {
		journal->active_slot = target;
		journal->generation = generation;
		journal->snapshot_bytes = length;
		journal->has_snapshot = true;
	} else {
		journal->ready = false;
	}
out:
	(void)k_mutex_unlock(&journal->lock);
	return ret;
}

int pqcp_runtime_journal_restore(struct pqcp_runtime_journal *journal,
	struct pqcp_runtime_controller *controller,
	struct pqcp_runtime_snapshot_info *info, uint64_t now_ms)
{
	uint64_t generation;
	size_t length;
	int ret;

	if (journal == NULL || !journal->ready || controller == NULL ||
	    !controller->initialized || !journal->has_snapshot ||
	    controller->sessions == NULL || controller->executor == NULL || info == NULL) {
		return -EINVAL;
	}
	if (controller->executor->worker_started) {
		return -EBUSY;
	}
	ret = k_mutex_lock(&journal->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = journal->ready ? inspect_slot(journal, journal->active_slot,
		true, &generation, &length) : -EIO;
	if (ret == 0 && (generation != journal->generation || length != journal->snapshot_bytes)) {
		ret = -ESTALE;
	}
	if (ret == 0) {
		ret = pqcp_runtime_recovery_restore(controller, journal->scratch, length,
			controller->sessions->sessions, controller->sessions->capacity,
			controller->executor->profile_states, controller->executor->profile_state_capacity,
			info, now_ms);
	}
	(void)k_mutex_unlock(&journal->lock);
	return ret;
}
