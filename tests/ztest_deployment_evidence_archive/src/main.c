/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for end-to-end deployment evidence archive capture.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_archive.h>

#include "deployment_evidence_archive_fixture.h"

#define CAPSULE_CAPACITY 8192U

static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char nonce_b[] = "ffeeddccbbaa99887766554433221100";

struct archive_fixture {
	struct pqcp_archive_test_fixture passport_fixture;
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_archive_workspace workspace;
	struct pqcp_deployment_evidence_archive_result result;
	uint8_t capsule[CAPSULE_CAPACITY];
};

static void build_passport(
	struct archive_fixture *fixture,
	const char *top_candidate,
	const char *nonce,
	bool production_allowed)
{
	memset(fixture, 0, sizeof(*fixture));
	zassert_equal(pqcp_archive_test_build_passport(
			      &fixture->passport_fixture, "qemu_x86_64",
			      top_candidate, nonce, production_allowed),
		      0);
}

static int capture(
	struct archive_fixture *fixture,
	const char *device_id,
	uint64_t boot_counter,
	uint64_t capture_time_ms)
{
	return pqcp_deployment_evidence_archive_capture(
		&fixture->passport_fixture.passport,
		&fixture->passport_fixture.passport_replay,
		NULL, device_id, boot_counter, capture_time_ms,
		fixture->capsule, sizeof(fixture->capsule),
		&fixture->journal, &fixture->workspace,
		&fixture->result);
}

ZTEST(pqcp_deployment_evidence_archive, test_status_tokens)
{
	zassert_str_equal(
		pqcp_deployment_evidence_archive_status_str(
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_evidence_archive_status_str(
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_evidence_archive_status_str(
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_FAIL),
		"FAIL");
}

ZTEST(pqcp_deployment_evidence_archive, test_unsigned_capture_warns)
{
	struct archive_fixture fixture;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(capture(&fixture, "device-001", 1U, 1000U), 0);
	zassert_equal(fixture.result.status,
		      PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARN);
	zassert_equal(fixture.result.error_mask, 0U);
	zassert_not_equal(
		fixture.result.warning_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_UNSIGNED,
		0U);
	zassert_true(fixture.result.capsule_built);
	zassert_true(fixture.result.capsule_replayed);
	zassert_true(fixture.result.journal_appended);
	zassert_true(fixture.result.journal_finalized);
	zassert_true(fixture.result.journal_replayed);
	zassert_true(fixture.result.capsule_digest_bound);
	zassert_true(fixture.result.passport_digest_bound);
	zassert_true(fixture.result.production_allowed);
	zassert_false(fixture.result.signature_verified);
	zassert_equal(fixture.result.journal_entries, 1U);
	zassert_str_equal(fixture.result.device_id, "device-001");
	zassert_str_equal(fixture.result.board, "qemu_x86_64");
	zassert_str_equal(fixture.result.top_candidate_id,
			  "hybrid768_65_campaign");
	zassert_true(pqcp_deployment_evidence_codec_is_lower_hex(
		fixture.result.archive_digest_hex, 64U));
	zassert_equal(
		pqcp_deployment_evidence_archive_emit(&fixture.result), 0);
}

ZTEST(pqcp_deployment_evidence_archive, test_nonproduction_warns)
{
	struct archive_fixture fixture;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, false);
	zassert_equal(capture(&fixture, "device-001", 1U, 1000U), 0);
	zassert_equal(fixture.result.status,
		      PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARN);
	zassert_false(fixture.result.production_allowed);
	zassert_not_equal(
		fixture.result.warning_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_NON_PRODUCTION,
		0U);
}

ZTEST(pqcp_deployment_evidence_archive, test_journal_initializes_automatically)
{
	struct archive_fixture fixture;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(fixture.journal.schema_version, 0U);
	zassert_equal(capture(&fixture, "device-auto", 7U, 9000U), 0);
	zassert_equal(fixture.journal.schema_version,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION);
	zassert_equal(fixture.journal.status,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_OPEN);
	zassert_equal(fixture.journal.entry_count, 1U);
	zassert_str_equal(fixture.journal.device_id, "device-auto");
	zassert_equal(fixture.result.boot_counter, 7U);
	zassert_equal(fixture.result.capture_time_ms, 9000U);
}

ZTEST(pqcp_deployment_evidence_archive, test_multiple_unique_captures_append)
{
	struct archive_fixture fixture;
	struct pqcp_archive_test_fixture second_passport;
	char first_archive_digest[65];

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(capture(&fixture, "device-001", 1U, 1000U), 0);
	strcpy(first_archive_digest, fixture.result.archive_digest_hex);
	zassert_equal(pqcp_archive_test_build_passport(
			      &second_passport, "qemu_x86_64",
			      "hybrid1024_87_campaign", nonce_b, true),
		      0);
	memcpy(&fixture.passport_fixture, &second_passport,
	       sizeof(second_passport));
	zassert_equal(capture(&fixture, "device-001", 2U, 2000U), 0);
	zassert_equal(fixture.journal.entry_count, 2U);
	zassert_equal(fixture.result.journal_entries, 2U);
	zassert_str_equal(fixture.result.top_candidate_id,
			  "hybrid1024_87_campaign");
	zassert_not_equal(strcmp(
		first_archive_digest, fixture.result.archive_digest_hex), 0);
}

ZTEST(pqcp_deployment_evidence_archive, test_duplicate_capture_rejected)
{
	struct archive_fixture fixture;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(capture(&fixture, "device-001", 1U, 1000U), 0);
	zassert_equal(capture(&fixture, "device-001", 2U, 2000U),
		      -EEXIST);
	zassert_not_equal(
		fixture.result.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_APPEND,
		0U);
	zassert_equal(fixture.journal.entry_count, 1U);
}

ZTEST(pqcp_deployment_evidence_archive, test_device_mismatch_rejected)
{
	struct archive_fixture fixture;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(capture(&fixture, "device-001", 1U, 1000U), 0);
	zassert_equal(capture(&fixture, "device-002", 2U, 2000U),
		      -EINVAL);
	zassert_not_equal(
		fixture.result.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_INIT,
		0U);
}

ZTEST(pqcp_deployment_evidence_archive, test_boot_rollback_rejected)
{
	struct archive_fixture fixture;
	struct pqcp_archive_test_fixture second_passport;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(capture(&fixture, "device-001", 2U, 1000U), 0);
	zassert_equal(pqcp_archive_test_build_passport(
			      &second_passport, "qemu_x86_64",
			      "hybrid1024_87_campaign", nonce_b, true),
		      0);
	memcpy(&fixture.passport_fixture, &second_passport,
	       sizeof(second_passport));
	zassert_equal(capture(&fixture, "device-001", 1U, 2000U),
		      -ERANGE);
	zassert_not_equal(
		fixture.result.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_APPEND,
		0U);
}

ZTEST(pqcp_deployment_evidence_archive, test_time_rollback_rejected)
{
	struct archive_fixture fixture;
	struct pqcp_archive_test_fixture second_passport;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(capture(&fixture, "device-001", 1U, 2000U), 0);
	zassert_equal(pqcp_archive_test_build_passport(
			      &second_passport, "qemu_x86_64",
			      "hybrid1024_87_campaign", nonce_b, true),
		      0);
	memcpy(&fixture.passport_fixture, &second_passport,
	       sizeof(second_passport));
	zassert_equal(capture(&fixture, "device-001", 2U, 1000U),
		      -ERANGE);
	zassert_not_equal(
		fixture.result.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_APPEND,
		0U);
}

ZTEST(pqcp_deployment_evidence_archive, test_small_capsule_buffer_fails)
{
	struct archive_fixture fixture;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(pqcp_deployment_evidence_archive_capture(
			      &fixture.passport_fixture.passport,
			      &fixture.passport_fixture.passport_replay,
			      NULL, "device-001", 1U, 1000U,
			      fixture.capsule, 32U, &fixture.journal,
			      &fixture.workspace, &fixture.result),
		      -ENOSPC);
	zassert_not_equal(
		fixture.result.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_CAPSULE_BUILD,
		0U);
	zassert_false(fixture.result.capsule_built);
}

ZTEST(pqcp_deployment_evidence_archive, test_bad_passport_replay_fails)
{
	struct archive_fixture fixture;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	fixture.passport_fixture.passport_replay.passed = false;
	zassert_equal(capture(&fixture, "device-001", 1U, 1000U),
		      -EBADMSG);
	zassert_not_equal(
		fixture.result.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_CAPSULE_BUILD,
		0U);
}

ZTEST(pqcp_deployment_evidence_archive, test_passport_digest_tamper_fails)
{
	struct archive_fixture fixture;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	fixture.passport_fixture.passport.passport_digest_hex[0] =
		fixture.passport_fixture.passport.passport_digest_hex[0] == '0' ?
			'1' : '0';
	zassert_equal(capture(&fixture, "device-001", 1U, 1000U),
		      -EBADMSG);
	zassert_not_equal(
		fixture.result.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_CAPSULE_BUILD,
		0U);
}

ZTEST(pqcp_deployment_evidence_archive, test_null_inputs_fail)
{
	struct archive_fixture fixture;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(pqcp_deployment_evidence_archive_capture(
			      NULL,
			      &fixture.passport_fixture.passport_replay,
			      NULL, "device-001", 1U, 1000U,
			      fixture.capsule, sizeof(fixture.capsule),
			      &fixture.journal, &fixture.workspace,
			      &fixture.result),
		      -EINVAL);
	zassert_not_equal(
		fixture.result.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_INVALID_INPUT,
		0U);
	zassert_equal(pqcp_deployment_evidence_archive_capture(
			      &fixture.passport_fixture.passport,
			      &fixture.passport_fixture.passport_replay,
			      NULL, NULL, 1U, 1000U, fixture.capsule,
			      sizeof(fixture.capsule), &fixture.journal,
			      &fixture.workspace, &fixture.result),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_archive_capture(
			      &fixture.passport_fixture.passport,
			      &fixture.passport_fixture.passport_replay,
			      NULL, "device-001", 1U, 1000U,
			      fixture.capsule, sizeof(fixture.capsule),
			      &fixture.journal, &fixture.workspace, NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_archive, test_archive_digest_is_stable)
{
	struct archive_fixture first;
	struct archive_fixture second;

	build_passport(
		&first, "hybrid768_65_campaign", nonce_a, true);
	build_passport(
		&second, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(capture(&first, "device-001", 1U, 1000U), 0);
	zassert_equal(capture(&second, "device-001", 1U, 1000U), 0);
	zassert_str_equal(first.result.archive_digest_hex,
			  second.result.archive_digest_hex);
	zassert_str_equal(first.result.capsule_digest_hex,
			  second.result.capsule_digest_hex);
	zassert_str_equal(first.result.journal_digest_hex,
			  second.result.journal_digest_hex);
}

ZTEST(pqcp_deployment_evidence_archive, test_result_bindings_match_workspace)
{
	struct archive_fixture fixture;
	const struct pqcp_deployment_evidence_journal_entry *entry;

	build_passport(
		&fixture, "hybrid768_65_campaign", nonce_a, true);
	zassert_equal(capture(&fixture, "device-001", 1U, 1000U), 0);
	entry = &fixture.workspace.finalized_snapshot.entries[0];
	zassert_str_equal(entry->capsule_digest_hex,
			  fixture.result.capsule_digest_hex);
	zassert_str_equal(entry->passport_digest_hex,
			  fixture.result.passport_digest_hex);
	zassert_str_equal(
		fixture.workspace.journal_replay.latest_capsule_digest_hex,
		fixture.result.capsule_digest_hex);
	zassert_str_equal(
		fixture.workspace.journal_replay.computed_journal_digest_hex,
		fixture.result.journal_digest_hex);
}

ZTEST(pqcp_deployment_evidence_archive, test_emit_rejects_bad_masks)
{
	struct pqcp_deployment_evidence_archive_result result = {
		.schema_version =
			PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_SCHEMA_VERSION,
		.error_mask = 1U << 31,
	};

	zassert_equal(
		pqcp_deployment_evidence_archive_emit(&result), -EINVAL);
	result.error_mask = 0U;
	result.warning_mask = 1U << 31;
	zassert_equal(
		pqcp_deployment_evidence_archive_emit(&result), -EINVAL);
	zassert_equal(
		pqcp_deployment_evidence_archive_emit(NULL), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_archive, NULL, NULL, NULL, NULL, NULL);
