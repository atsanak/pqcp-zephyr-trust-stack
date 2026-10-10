/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */

#include <errno.h>
#include <string.h>
#include <psa/crypto.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>
#include <pqcp_zephyr/runtime.h>

#define HEADER_BYTES 32U
#define RECORD_BYTES 160U
#define SNAPSHOT_BYTES (HEADER_BYTES + 3U * RECORD_BYTES + PQCP_RUNTIME_DIGEST_BYTES)

struct restore_state {
	struct pqcp_runtime_session sessions[2];
	struct pqcp_runtime_profile_state profiles[1];
	struct pqcp_runtime_snapshot_info info;
};

static void make_snapshot(uint8_t *snapshot)
{
	struct restore_state source = {0};

	for (size_t i = 0U; i < ARRAY_SIZE(source.sessions); ++i) {
		source.sessions[i].schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
		source.sessions[i].session_id = i + 1U;
		source.sessions[i].active = true;
		source.sessions[i].mlkem_level = 768U;
		source.sessions[i].mldsa_level = 65U;
		strcpy(source.sessions[i].profile_id, "hybrid768-65-runtime");
	}
	source.sessions[0].kem_key = (struct pqcp_runtime_key_handle) {
		.slot = 0U,
		.generation = 7U,
		.backend = PQCP_RUNTIME_KEY_BACKEND_VOLATILE,
		.family = PQCP_RUNTIME_KEY_MLKEM_KEYPAIR,
		.level = 768U,
	};
	zassert_ok(pqcp_runtime_profile_state_init(&source.profiles[0],
						 "hybrid768-65-runtime"));
	zassert_ok(pqcp_runtime_snapshot_write(source.sessions,
		ARRAY_SIZE(source.sessions), source.profiles,
		ARRAY_SIZE(source.profiles), snapshot, SNAPSHOT_BYTES, &source.info));
	zassert_equal(source.info.bytes_written, SNAPSHOT_BYTES);
}

static void rehash(uint8_t *snapshot)
{
	size_t hash_length;

	zassert_equal(psa_hash_compute(PSA_ALG_SHA_256, snapshot,
		SNAPSHOT_BYTES - PQCP_RUNTIME_DIGEST_BYTES,
		snapshot + SNAPSHOT_BYTES - PQCP_RUNTIME_DIGEST_BYTES,
		PQCP_RUNTIME_DIGEST_BYTES, &hash_length), PSA_SUCCESS);
	zassert_equal(hash_length, PQCP_RUNTIME_DIGEST_BYTES);
}

static void assert_restore_unchanged(const uint8_t *snapshot, size_t length,
				     int expected)
{
	struct restore_state restored;
	struct restore_state before;

	memset(&restored, 0xa5, sizeof(restored));
	memcpy(&before, &restored, sizeof(before));
	zassert_equal(pqcp_runtime_snapshot_read(snapshot, length,
		restored.sessions, ARRAY_SIZE(restored.sessions), restored.profiles,
		ARRAY_SIZE(restored.profiles), &restored.info), expected);
	zassert_mem_equal(&restored, &before, sizeof(before),
			  "a rejected snapshot changed live restore state");
}

ZTEST(pqcp_runtime, test_snapshot_roundtrip)
{
	uint8_t snapshot[SNAPSHOT_BYTES];
	struct restore_state restored = {0};

	make_snapshot(snapshot);
	zassert_ok(pqcp_runtime_snapshot_read(snapshot, sizeof(snapshot),
		restored.sessions, ARRAY_SIZE(restored.sessions), restored.profiles,
		ARRAY_SIZE(restored.profiles), &restored.info));
	zassert_equal(restored.sessions[0].session_id, 1U);
	zassert_equal(restored.sessions[1].session_id, 2U);
	zassert_true(restored.sessions[1].active);
	zassert_str_equal(restored.profiles[0].profile_id, "hybrid768-65-runtime");
	zassert_equal(restored.info.session_count, 2U);
	zassert_equal(restored.info.profile_count, 1U);
	zassert_equal(restored.info.key_reference_count, 1U);
	zassert_equal(restored.sessions[0].kem_key.generation, 7U);
}

ZTEST(pqcp_runtime, test_snapshot_write_rejects_null_and_overflow_before_scan)
{
	struct restore_state source = {0};
	uint8_t snapshot[SNAPSHOT_BYTES];
	uint8_t before[SNAPSHOT_BYTES];

	memset(snapshot, 0x5a, sizeof(snapshot));
	memcpy(before, snapshot, sizeof(before));
	zassert_equal(pqcp_runtime_snapshot_write(NULL, 1U, source.profiles, 1U,
		snapshot, sizeof(snapshot), &source.info), -EINVAL);
	zassert_equal(pqcp_runtime_snapshot_write(source.sessions, 1U, NULL, 1U,
		snapshot, sizeof(snapshot), &source.info), -EINVAL);
	zassert_equal(pqcp_runtime_snapshot_write(source.sessions, SIZE_MAX,
		source.profiles, 1U, snapshot, sizeof(snapshot), &source.info), -EINVAL);
	zassert_equal(pqcp_runtime_snapshot_write(source.sessions, 1U,
		source.profiles, SIZE_MAX, snapshot, sizeof(snapshot), &source.info), -EINVAL);
	zassert_equal(pqcp_runtime_snapshot_write(source.sessions, 1U,
		source.profiles, 1U, snapshot, 1U, &source.info), -EINVAL);
	zassert_mem_equal(snapshot, before, sizeof(before));
}

ZTEST(pqcp_runtime, test_snapshot_read_rejects_null_and_short_inputs)
{
	uint8_t snapshot[SNAPSHOT_BYTES];

	make_snapshot(snapshot);
	assert_restore_unchanged(NULL, sizeof(snapshot), -EINVAL);
	for (size_t length = 0U; length < HEADER_BYTES + PQCP_RUNTIME_DIGEST_BYTES;
	     ++length) {
		assert_restore_unchanged(snapshot, length, -EINVAL);
	}
}

ZTEST(pqcp_runtime, test_snapshot_late_record_failure_is_atomic)
{
	uint8_t snapshot[SNAPSHOT_BYTES];

	make_snapshot(snapshot);
	/* The first session is valid, but the second session's schema is not. */
	sys_put_be32(UINT32_MAX, snapshot + HEADER_BYTES + RECORD_BYTES);
	rehash(snapshot);
	assert_restore_unchanged(snapshot, sizeof(snapshot), -EBADMSG);
}

ZTEST(pqcp_runtime, test_snapshot_rejects_rehashed_invalid_metadata)
{
	uint8_t snapshot[SNAPSHOT_BYTES];
	const size_t profile_offset = HEADER_BYTES + 2U * RECORD_BYTES;

	make_snapshot(snapshot);
	sys_put_be32(0U, snapshot + 20U);
	rehash(snapshot);
	assert_restore_unchanged(snapshot, sizeof(snapshot), -EBADMSG);

	make_snapshot(snapshot);
	sys_put_be32(UINT32_MAX, snapshot + profile_offset + 4U);
	rehash(snapshot);
	assert_restore_unchanged(snapshot, sizeof(snapshot), -EBADMSG);

	make_snapshot(snapshot);
	sys_put_be32(UINT32_MAX, snapshot + profile_offset + 24U);
	sys_put_be32(1U, snapshot + profile_offset + 28U);
	rehash(snapshot);
	assert_restore_unchanged(snapshot, sizeof(snapshot), -EBADMSG);

	make_snapshot(snapshot);
	snapshot[HEADER_BYTES + 61U] = 2U;
	rehash(snapshot);
	assert_restore_unchanged(snapshot, sizeof(snapshot), -EBADMSG);

	make_snapshot(snapshot);
	memset(snapshot + profile_offset + 72U, 'x', PQCP_RUNTIME_PROFILE_MAX_CHARS);
	rehash(snapshot);
	assert_restore_unchanged(snapshot, sizeof(snapshot), -EBADMSG);
}

ZTEST(pqcp_runtime, test_snapshot_rejects_hash_and_size_corruption)
{
	uint8_t snapshot[SNAPSHOT_BYTES];

	make_snapshot(snapshot);
	snapshot[sizeof(snapshot) - 1U] ^= 1U;
	assert_restore_unchanged(snapshot, sizeof(snapshot), -EBADMSG);
	make_snapshot(snapshot);
	sys_put_be32(UINT32_MAX, snapshot + 12U);
	sys_put_be32(UINT32_MAX, snapshot + 16U);
	assert_restore_unchanged(snapshot, sizeof(snapshot), -EINVAL);
}

ZTEST(pqcp_runtime, test_snapshot_rejects_insufficient_restore_capacity)
{
	uint8_t snapshot[SNAPSHOT_BYTES];
	struct restore_state restored;
	struct restore_state before;

	make_snapshot(snapshot);
	memset(&restored, 0xa5, sizeof(restored));
	memcpy(&before, &restored, sizeof(before));
	zassert_equal(pqcp_runtime_snapshot_read(snapshot, sizeof(snapshot),
		restored.sessions, 1U, restored.profiles, 1U, &restored.info), -EINVAL);
	zassert_mem_equal(&restored, &before, sizeof(before));
}

ZTEST(pqcp_runtime, test_snapshot_rejects_input_output_alias)
{
	union {
		uint8_t snapshot[SNAPSHOT_BYTES];
		struct pqcp_runtime_session alignment;
	} buffer;
	uint8_t before[SNAPSHOT_BYTES];
	struct restore_state restored = {0};

	make_snapshot(buffer.snapshot);
	memcpy(before, buffer.snapshot, sizeof(before));
	zassert_equal(pqcp_runtime_snapshot_read(buffer.snapshot, sizeof(buffer.snapshot),
		&buffer.alignment, 2U, restored.profiles, 1U, &restored.info), -EINVAL);
	zassert_mem_equal(buffer.snapshot, before, sizeof(before));
}
