/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <string.h>
#include <psa/crypto.h>
#include <zephyr/ztest.h>
#include <pqcp_zephyr/runtime_journal.h>
#include <pqcp_zephyr/runtime_operations.h>

#define SLOT_BYTES 2048U
static uint8_t storage[2U * SLOT_BYTES];
static uint8_t scratch[1024];
static const uint8_t build_binding[32] = {0x42U, 0x17U};
static struct pqcp_runtime_journal journal;
static struct pqcp_runtime_session sessions[1];
static struct pqcp_runtime_profile_state profiles[1];
static unsigned int calls;
static unsigned int fail_at;
static bool partial;

static int read_bytes(void *context, size_t offset, void *buffer, size_t length)
{
	ARG_UNUSED(context);
	if (offset > sizeof(storage) || length > sizeof(storage) - offset) {
		return -EINVAL;
	}
	memcpy(buffer, storage + offset, length);
	return 0;
}

static int write_bytes(void *context, size_t offset, const void *buffer, size_t length)
{
	const uint8_t *bytes = buffer;
	ARG_UNUSED(context);
	bool fail = ++calls == fail_at;

	if (offset > sizeof(storage) || length > sizeof(storage) - offset ||
	    offset % 4U != 0U || length % 4U != 0U) {
		return -EINVAL;
	}
	if (!fail || partial) {
		size_t written = fail ? length / 2U : length;

		for (size_t i = 0U; i < written; ++i) {
			if ((storage[offset + i] & bytes[i]) != bytes[i]) {
				return -EIO;
			}
			storage[offset + i] &= bytes[i];
		}
	}
	return fail ? -EIO : 0;
}

static int erase_bytes(void *context, size_t offset, size_t length)
{
	ARG_UNUSED(context);
	bool fail = ++calls == fail_at;

	if (offset > sizeof(storage) || length > sizeof(storage) - offset) {
		return -EINVAL;
	}
	if (!fail || partial) {
		memset(storage + offset, 0xff, fail ? length / 2U : length);
	}
	return fail ? -EIO : 0;
}

static int sync_bytes(void *context)
{
	ARG_UNUSED(context);
	return ++calls == fail_at ? -EIO : 0;
}

static struct pqcp_runtime_journal_io io = {
	.read = read_bytes, .write = write_bytes, .erase = erase_bytes,
	.sync = sync_bytes, .region_bytes = sizeof(storage),
	.erase_bytes = SLOT_BYTES, .write_bytes = 4U,
};

static void reset_fixture(void)
{
	zassert_equal(psa_crypto_init(), PSA_SUCCESS);
	memset(storage, 0xff, sizeof(storage));
	memset(sessions, 0, sizeof(sessions));
	memset(profiles, 0, sizeof(profiles));
	sessions[0].schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	sessions[0].session_id = 7U;
	sessions[0].active = true;
	sessions[0].mlkem_level = 768U;
	sessions[0].mldsa_level = 65U;
	strcpy(sessions[0].profile_id, "hybrid768-65-runtime");
	profiles[0].schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	strcpy(profiles[0].profile_id, "hybrid768-65-runtime");
	calls = 0U;
	fail_at = 0U;
	partial = false;
	zassert_ok(pqcp_runtime_journal_open(&journal, &io, SLOT_BYTES,
		build_binding, 0U, scratch, sizeof(scratch)));
}

ZTEST(pqcp_recovery, test_reopen_committed_and_reject_wrong_build)
{
	struct pqcp_runtime_journal reopened;
	uint8_t wrong[32] = {1U};

	reset_fixture();
	zassert_false(journal.has_snapshot);
	zassert_ok(pqcp_runtime_journal_save(&journal, sessions, 1U, profiles, 1U));
	zassert_ok(pqcp_runtime_journal_open(&reopened, &io, SLOT_BYTES,
		build_binding, 0U, scratch, sizeof(scratch)));
	zassert_equal(reopened.generation, 1U);
	zassert_true(reopened.has_snapshot);
	zassert_equal(pqcp_runtime_journal_open(&reopened, &io, SLOT_BYTES,
		wrong, 0U, scratch, sizeof(scratch)), -EXDEV);
	zassert_false(reopened.ready);
	zassert_equal(pqcp_runtime_journal_open(&reopened, &io, SLOT_BYTES,
		build_binding, 2U, scratch, sizeof(scratch)), -ESTALE);
}

ZTEST(pqcp_recovery, test_power_cut_at_every_persistence_phase)
{
	/* erase, header, payload, sync, commit, final sync; include torn writes. */
	for (unsigned int torn = 0U; torn < 2U; ++torn) {
		for (unsigned int phase = 1U; phase <= 6U; ++phase) {
			struct pqcp_runtime_journal reopened;

			reset_fixture();
			zassert_ok(pqcp_runtime_journal_save(&journal, sessions, 1U, profiles, 1U));
			calls = 0U;
			fail_at = phase;
			partial = torn != 0U;
			zassert_equal(pqcp_runtime_journal_save(&journal, sessions, 1U, profiles, 1U), -EIO);
			zassert_false(journal.ready);
			fail_at = 0U;
			memset(&journal, 0, sizeof(journal));
			zassert_ok(pqcp_runtime_journal_open(&reopened, &io, SLOT_BYTES,
				build_binding, 0U, scratch, sizeof(scratch)));
			zassert_equal(reopened.generation, phase == 6U ? 2U : 1U,
				"phase=%u torn=%u", phase, torn);
		}
	}
}

ZTEST(pqcp_recovery, test_corrupted_newest_falls_back_and_all_corrupt_fail)
{
	reset_fixture();
	zassert_ok(pqcp_runtime_journal_save(&journal, sessions, 1U, profiles, 1U));
	zassert_ok(pqcp_runtime_journal_save(&journal, sessions, 1U, profiles, 1U));
	storage[SLOT_BYTES + PQCP_RUNTIME_JOURNAL_HEADER_BYTES + 20U] ^= 1U;
	zassert_ok(pqcp_runtime_journal_open(&journal, &io, SLOT_BYTES,
		build_binding, 0U, scratch, sizeof(scratch)));
	zassert_equal(journal.generation, 1U);
	storage[PQCP_RUNTIME_JOURNAL_HEADER_BYTES + 20U] ^= 1U;
	zassert_equal(pqcp_runtime_journal_open(&journal, &io, SLOT_BYTES,
		build_binding, 0U, scratch, sizeof(scratch)), -EBADMSG);
}

ZTEST(pqcp_recovery, test_capacity_alignment_and_generation_exhaustion)
{
	struct pqcp_runtime_journal_io bad = io;

	reset_fixture();
	bad.write_bytes = 3U;
	zassert_equal(pqcp_runtime_journal_open(&journal, &bad, SLOT_BYTES,
		build_binding, 0U, scratch, sizeof(scratch)), -EINVAL);
	journal.generation = UINT64_MAX;
	zassert_equal(pqcp_runtime_journal_save(&journal, sessions, 1U, profiles, 1U), -EOVERFLOW);
	zassert_equal(calls, 0U);
}

ZTEST(pqcp_recovery, test_flash_partition_survives_runtime_reinitialization)
{
	const struct flash_area *area;
	struct pqcp_runtime_journal_flash flash;
	struct pqcp_runtime_journal_io flash_io;
	struct pqcp_runtime_journal rebooted;

	reset_fixture();
	zassert_ok(flash_area_open(PARTITION_ID(storage_partition), &area));
	zassert_ok(pqcp_runtime_journal_flash_io(&flash, area, &flash_io));
	zassert_ok(flash_area_erase(area, 0, 2U * SLOT_BYTES));
	zassert_ok(pqcp_runtime_journal_open(&journal, &flash_io, SLOT_BYTES,
		build_binding, 0U, scratch, sizeof(scratch)));
	zassert_ok(pqcp_runtime_journal_save(&journal, sessions, 1U, profiles, 1U));
	memset(&journal, 0, sizeof(journal));
	memset(scratch, 0xa5, sizeof(scratch));
	zassert_ok(pqcp_runtime_journal_open(&rebooted, &flash_io, SLOT_BYTES,
		build_binding, 0U, scratch, sizeof(scratch)));
	zassert_equal(rebooted.generation, 1U);
	zassert_true(rebooted.has_snapshot);
	flash_area_close(area);
}

ZTEST(pqcp_recovery, test_restore_missing_key_requires_fresh_session)
{
	static struct pqcp_runtime_volatile_slot key_slots[2];
	static struct pqcp_runtime_key_store keys;
	static struct pqcp_runtime_volatile_context key_context;
	static struct pqcp_runtime_session restored[1];
	static struct pqcp_runtime_profile_state restored_profiles[1];
	struct pqcp_runtime_executor executor = {
		.profile_states = restored_profiles, .profile_state_capacity = 1U,
	};
	struct pqcp_runtime_session_manager manager = {
		.sessions = restored, .capacity = 1U,
	};
	struct pqcp_runtime_controller controller = {
		.initialized = true, .executor = &executor, .sessions = &manager,
		.key_store = &keys, .accepting_sessions = true,
	};
	struct pqcp_runtime_snapshot_info info;

	reset_fixture();
	memset(restored, 0, sizeof(restored));
	memset(restored_profiles, 0, sizeof(restored_profiles));
	zassert_ok(pqcp_runtime_volatile_store_init(&keys, &key_context,
		key_slots, ARRAY_SIZE(key_slots)));
	sessions[0].kem_key = (struct pqcp_runtime_key_handle) {
		.slot = 0U, .generation = 1U, .family = PQCP_RUNTIME_KEY_MLKEM_KEYPAIR,
		.level = 768U, .backend = PQCP_RUNTIME_KEY_BACKEND_VOLATILE,
	};
	zassert_ok(pqcp_runtime_journal_save(&journal, sessions, 1U, profiles, 1U));
	zassert_equal(pqcp_runtime_journal_restore(&journal, &controller, &info, 100U), -ENOENT);
	zassert_false(controller.accepting_sessions);
	zassert_true(restored[0].draining);
	zassert_false(pqcp_runtime_key_handle_is_valid(&restored[0].kem_key));
	zassert_equal(manager.active_count, 1U);
	manager.active_count = 0U;
	sessions[0].expires_at_ms = 50U;
	zassert_ok(pqcp_runtime_journal_save(&journal, sessions, 1U, profiles, 1U));
	zassert_ok(pqcp_runtime_journal_restore(&journal, &controller, &info, 100U));
	zassert_equal(manager.active_count, 0U);
	zassert_false(restored[0].active);
	memset(restored, 0xa5, sizeof(restored));
	storage[journal.active_slot * SLOT_BYTES + PQCP_RUNTIME_JOURNAL_HEADER_BYTES] ^= 1U;
	zassert_equal(pqcp_runtime_journal_restore(&journal, &controller, &info, 100U), -EBADMSG);
	zassert_equal(((uint8_t *)restored)[0], 0xa5U);
}

ZTEST(pqcp_recovery, test_checkpoint_store_reopen_preserves_buffers)
{
	static uint8_t buffers[2][1024];
	struct pqcp_runtime_checkpoint_slot slots[2] = {
		{.buffer = buffers[0], .capacity = sizeof(buffers[0])},
		{.buffer = buffers[1], .capacity = sizeof(buffers[1])},
	};
	struct pqcp_runtime_checkpoint_store store;
	struct pqcp_runtime_service service = {.initialized = true};
	struct pqcp_runtime_checkpoint_header header;

	reset_fixture();
	zassert_ok(pqcp_runtime_checkpoint_store_init(&store, slots, 2U));
	zassert_ok(pqcp_runtime_checkpoint_write(&store, &service, 1U, 1U, 0U, &header));
	zassert_ok(pqcp_runtime_checkpoint_write(&store, &service, 2U, 1U, 0U, &header));
	zassert_ok(pqcp_runtime_checkpoint_store_reopen(&store, slots, 2U));
	zassert_equal(store.next_generation, 3U);
	zassert_ok(pqcp_runtime_checkpoint_store_audit(&store));
	buffers[store.active_slot][PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES] ^= 1U;
	zassert_ok(pqcp_runtime_checkpoint_store_reopen(&store, slots, 2U));
	zassert_equal(store.next_generation, 2U);
	zassert_ok(pqcp_runtime_checkpoint_store_audit(&store));
}

ZTEST_SUITE(pqcp_recovery, NULL, NULL, NULL, NULL, NULL);
