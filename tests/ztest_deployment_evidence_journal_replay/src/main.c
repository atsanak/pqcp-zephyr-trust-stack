/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for deployment evidence journal replay verification.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_journal_replay.h>

#include "deployment_evidence_archive_fixture.h"

static const char nonce[] = "00112233445566778899aabbccddeeff";
static const char passport_digest[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct replay_fixture {
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_journal_replay_result result;
};

static void make_capsule(
	struct pqcp_deployment_evidence_capsule_replay_result *capsule,
	uint32_t sequence,
	uint32_t score)
{
	char capsule_digest[
		PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];

	pqcp_archive_test_increment_digest(capsule_digest, sequence);
	pqcp_archive_test_fill_capsule_replay(
		capsule, "qemu_x86_64", "hybrid768_65_campaign",
		nonce, passport_digest, capsule_digest,
		score, true, true);
}

static void build_journal(struct replay_fixture *fixture, uint32_t entries)
{
	struct pqcp_deployment_evidence_capsule_replay_result capsule;

	memset(fixture, 0, sizeof(*fixture));
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &fixture->journal, "device-001"),
		      0);
	for (uint32_t index = 1U; index <= entries; ++index) {
		make_capsule(&capsule, index, 80U + index);
		zassert_equal(pqcp_deployment_evidence_journal_append(
				      &fixture->journal, &capsule, index,
				      1000U + index * 100U),
			      0);
	}
	zassert_equal(pqcp_deployment_evidence_journal_finalize(
			      &fixture->journal),
		      0);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_error_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_evidence_journal_replay_error_str(
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NONE),
		"none");
	zassert_str_equal(
		pqcp_deployment_evidence_journal_replay_error_str(
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ENTRY_DIGEST),
		"entry_digest");
	zassert_str_equal(
		pqcp_deployment_evidence_journal_replay_error_str(
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ROOT_DIGEST),
		"root_digest");
	zassert_str_equal(
		pqcp_deployment_evidence_journal_replay_error_str(99),
		"unknown");
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_valid_journal_replays)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 4U);
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      0);
	zassert_true(fixture.result.passed);
	zassert_equal(fixture.result.entries_checked, 4U);
	zassert_equal(fixture.result.pass_count, 4U);
	zassert_equal(fixture.result.signed_count, 4U);
	zassert_equal(fixture.result.production_count, 4U);
	zassert_true(fixture.result.sequence_valid);
	zassert_true(fixture.result.boot_counters_valid);
	zassert_true(fixture.result.capture_times_valid);
	zassert_true(fixture.result.device_stable);
	zassert_true(fixture.result.board_stable);
	zassert_true(fixture.result.capsules_unique);
	zassert_true(fixture.result.entry_chain_valid);
	zassert_true(fixture.result.summary_valid);
	zassert_true(fixture.result.root_digest_valid);
	zassert_equal(fixture.result.latest_passport_score, 84U);
	zassert_true(fixture.result.latest_signature_verified);
	zassert_true(fixture.result.latest_production_allowed);
	zassert_str_equal(fixture.result.latest_top_candidate_id,
			  "hybrid768_65_campaign");
	zassert_equal(
		pqcp_deployment_evidence_journal_replay_emit(
			&fixture.result),
		0);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_null_journal_fails)
{
	struct pqcp_deployment_evidence_journal_replay_result result;

	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      NULL, &result),
		      -EINVAL);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_INVALID_ARGUMENT);
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      NULL, NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_bad_schema_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 2U);
	fixture.journal.schema_version = 99U;
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EPROTONOSUPPORT);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BAD_SCHEMA);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_open_journal_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 2U);
	fixture.journal.status =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_OPEN;
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EPERM);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NOT_FINALIZED);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_sequence_tamper_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	fixture.journal.entries[1].sequence = 9U;
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_SEQUENCE);
	zassert_equal(fixture.result.first_error_entry, 2U);
	zassert_false(fixture.result.sequence_valid);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_boot_rollback_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	fixture.journal.entries[1].boot_counter =
		fixture.journal.entries[0].boot_counter;
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BOOT_COUNTER);
	zassert_false(fixture.result.boot_counters_valid);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_time_rollback_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	fixture.journal.entries[1].capture_time_ms =
		fixture.journal.entries[0].capture_time_ms - 1U;
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_TIME_ORDER);
	zassert_false(fixture.result.capture_times_valid);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_device_drift_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	strcpy(fixture.journal.entries[1].device_id, "other-device");
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_DEVICE_DRIFT);
	zassert_false(fixture.result.device_stable);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_board_drift_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	strcpy(fixture.journal.entries[1].board, "nucleo_h743zi");
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BOARD_DRIFT);
	zassert_false(fixture.result.board_stable);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_duplicate_capsule_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	strcpy(fixture.journal.entries[1].capsule_digest_hex,
	       fixture.journal.entries[0].capsule_digest_hex);
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_DUPLICATE_CAPSULE);
	zassert_false(fixture.result.capsules_unique);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_previous_digest_tamper_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	fixture.journal.entries[1].previous_entry_digest_hex[0] =
		fixture.journal.entries[1].previous_entry_digest_hex[0] == '0' ?
			'1' : '0';
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_PREVIOUS_DIGEST);
	zassert_false(fixture.result.entry_chain_valid);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_entry_digest_tamper_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	fixture.journal.entries[1].entry_digest_hex[0] =
		fixture.journal.entries[1].entry_digest_hex[0] == '0' ?
			'1' : '0';
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ENTRY_DIGEST);
	zassert_false(fixture.result.entry_chain_valid);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_summary_count_tamper_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	fixture.journal.pass_count--;
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_SUMMARY);
	zassert_false(fixture.result.summary_valid);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_root_digest_tamper_fails)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 3U);
	fixture.journal.journal_digest_hex[0] =
		fixture.journal.journal_digest_hex[0] == '0' ? '1' : '0';
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ROOT_DIGEST);
	zassert_false(fixture.result.root_digest_valid);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_latest_fields_follow_last_entry)
{
	struct replay_fixture fixture;

	build_journal(&fixture, 4U);
	zassert_equal(pqcp_deployment_evidence_journal_replay_verify(
			      &fixture.journal, &fixture.result),
		      0);
	zassert_equal(fixture.result.latest_passport_status,
		      fixture.journal.entries[3].passport_status);
	zassert_equal(fixture.result.latest_profile,
		      fixture.journal.entries[3].profile);
	zassert_equal(fixture.result.latest_passport_score,
		      fixture.journal.entries[3].passport_score);
	zassert_str_equal(fixture.result.latest_capsule_digest_hex,
			  fixture.journal.entries[3].capsule_digest_hex);
}

ZTEST(pqcp_deployment_evidence_journal_replay, test_emit_rejects_bad_result)
{
	struct pqcp_deployment_evidence_journal_replay_result result = {
		.schema_version =
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_SCHEMA_VERSION,
		.entries_checked =
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES + 1U,
	};

	zassert_equal(
		pqcp_deployment_evidence_journal_replay_emit(&result),
		-EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_journal_replay, NULL, NULL, NULL, NULL,
	    NULL);
