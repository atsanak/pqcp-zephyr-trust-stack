/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for the append-only deployment evidence journal.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_journal.h>

#include "deployment_evidence_archive_fixture.h"

static const char nonce[] = "00112233445566778899aabbccddeeff";
static const char passport_digest[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static void make_capsule(
	struct pqcp_deployment_evidence_capsule_replay_result *capsule,
	uint32_t sequence,
	uint32_t score,
	bool signed_verified,
	bool production_allowed)
{
	char capsule_digest[
		PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];

	pqcp_archive_test_increment_digest(capsule_digest, sequence);
	pqcp_archive_test_fill_capsule_replay(
		capsule, "qemu_x86_64", "hybrid768_65_campaign",
		nonce, passport_digest, capsule_digest, score,
		signed_verified, production_allowed);
}

ZTEST(pqcp_deployment_evidence_journal, test_status_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_journal_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_EMPTY),
			  "EMPTY");
	zassert_str_equal(pqcp_deployment_evidence_journal_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_OPEN),
			  "OPEN");
	zassert_str_equal(pqcp_deployment_evidence_journal_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FINALIZED),
			  "FINALIZED");
	zassert_str_equal(pqcp_deployment_evidence_journal_status_str(99),
			  "FAILED");
}

ZTEST(pqcp_deployment_evidence_journal, test_error_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_journal_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_NONE),
			  "none");
	zassert_str_equal(pqcp_deployment_evidence_journal_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DUPLICATE),
			  "duplicate");
	zassert_str_equal(pqcp_deployment_evidence_journal_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DIGEST),
			  "digest");
	zassert_str_equal(
		pqcp_deployment_evidence_journal_error_str(99), "unknown");
}

ZTEST(pqcp_deployment_evidence_journal, test_init_creates_empty_journal)
{
	struct pqcp_deployment_evidence_journal journal;

	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_equal(journal.schema_version,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION);
	zassert_equal(journal.status,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_EMPTY);
	zassert_equal(journal.entry_count, 0U);
	zassert_true(journal.monotonic_boot_counters);
	zassert_true(journal.monotonic_capture_times);
	zassert_true(journal.unique_capsules);
	zassert_str_equal(journal.device_id, "device-001");
}

ZTEST(pqcp_deployment_evidence_journal, test_invalid_device_id_fails)
{
	struct pqcp_deployment_evidence_journal journal;
	char long_id[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DEVICE_ID_MAX_CHARS + 1U];

	memset(long_id, 'x', sizeof(long_id));
	long_id[sizeof(long_id) - 1U] = '\0';
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, ""),
		      -EINVAL);
	zassert_equal(journal.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BAD_DEVICE_ID);
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, long_id),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_journal, test_append_one_capsule)
{
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_capsule_replay_result capsule;
	const struct pqcp_deployment_evidence_journal_entry *entry;

	make_capsule(&capsule, 1U, 90U, true, true);
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &capsule, 1U, 1000U),
		      0);
	zassert_equal(journal.status,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_OPEN);
	zassert_equal(journal.entry_count, 1U);
	zassert_equal(journal.pass_count, 1U);
	zassert_equal(journal.signed_count, 1U);
	zassert_equal(journal.production_count, 1U);
	zassert_str_equal(journal.board, "qemu_x86_64");
	entry = pqcp_deployment_evidence_journal_entry_at(
		&journal, 0U);
	zassert_not_null(entry);
	zassert_equal(entry->sequence, 1U);
	zassert_equal(entry->boot_counter, 1U);
	zassert_equal(entry->capture_time_ms, 1000U);
	zassert_str_equal(entry->previous_entry_digest_hex,
			  "0000000000000000000000000000000000000000000000000000000000000000");
	zassert_true(pqcp_deployment_evidence_codec_is_lower_hex(
		entry->entry_digest_hex,
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS));
}

ZTEST(pqcp_deployment_evidence_journal, test_append_multiple_capsules_chains)
{
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_capsule_replay_result capsule;

	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	for (uint32_t index = 1U; index <= 4U; ++index) {
		make_capsule(&capsule, index, 80U + index, true, true);
		zassert_equal(pqcp_deployment_evidence_journal_append(
				      &journal, &capsule, index,
				      1000U + index * 100U),
			      0);
	}
	zassert_equal(journal.entry_count, 4U);
	for (size_t index = 1U; index < journal.entry_count; ++index) {
		zassert_str_equal(
			journal.entries[index].previous_entry_digest_hex,
			journal.entries[index - 1U].entry_digest_hex);
		zassert_not_equal(
			strcmp(journal.entries[index].entry_digest_hex,
			       journal.entries[index - 1U].entry_digest_hex),
			0);
	}
}

ZTEST(pqcp_deployment_evidence_journal, test_duplicate_capsule_fails)
{
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_capsule_replay_result capsule;

	make_capsule(&capsule, 1U, 90U, true, true);
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &capsule, 1U, 1000U),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &capsule, 2U, 1100U),
		      -EEXIST);
	zassert_equal(journal.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DUPLICATE);
	zassert_equal(journal.status,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FAILED);
}

ZTEST(pqcp_deployment_evidence_journal, test_boot_counter_rollback_fails)
{
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_capsule_replay_result first;
	struct pqcp_deployment_evidence_capsule_replay_result second;

	make_capsule(&first, 1U, 90U, true, true);
	make_capsule(&second, 2U, 90U, true, true);
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &first, 5U, 1000U),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &second, 5U, 1100U),
		      -ERANGE);
	zassert_equal(journal.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BOOT_COUNTER);
}

ZTEST(pqcp_deployment_evidence_journal, test_time_rollback_fails)
{
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_capsule_replay_result first;
	struct pqcp_deployment_evidence_capsule_replay_result second;

	make_capsule(&first, 1U, 90U, true, true);
	make_capsule(&second, 2U, 90U, true, true);
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &first, 1U, 2000U),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &second, 2U, 1999U),
		      -ERANGE);
	zassert_equal(journal.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_TIME_ORDER);
}

ZTEST(pqcp_deployment_evidence_journal, test_bad_capsule_fails)
{
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_capsule_replay_result capsule;

	make_capsule(&capsule, 1U, 90U, true, true);
	capsule.passed = false;
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &capsule, 1U, 1000U),
		      -EBADMSG);
	zassert_equal(journal.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BAD_CAPSULE);
}

ZTEST(pqcp_deployment_evidence_journal, test_full_journal_fails)
{
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_capsule_replay_result capsule;

	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	for (uint32_t index = 1U;
	     index <= PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES;
	     ++index) {
		make_capsule(&capsule, index, 90U, true, true);
		zassert_equal(pqcp_deployment_evidence_journal_append(
				      &journal, &capsule, index,
				      1000U + index),
			      0);
	}
	make_capsule(&capsule, 31U, 90U, true, true);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &capsule, 31U, 3000U),
		      -ENOSPC);
	zassert_equal(journal.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_FULL);
}

ZTEST(pqcp_deployment_evidence_journal, test_empty_finalize_fails)
{
	struct pqcp_deployment_evidence_journal journal;

	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_finalize(
			      &journal),
		      -ENODATA);
	zassert_equal(journal.status,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FAILED);
}

ZTEST(pqcp_deployment_evidence_journal, test_finalize_produces_root)
{
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_capsule_replay_result capsule;

	make_capsule(&capsule, 1U, 90U, true, true);
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &capsule, 1U, 1000U),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_finalize(
			      &journal),
		      0);
	zassert_equal(journal.status,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FINALIZED);
	zassert_true(pqcp_deployment_evidence_codec_is_lower_hex(
		journal.journal_digest_hex,
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS));
	zassert_equal(
		pqcp_deployment_evidence_journal_emit(&journal), 0);
	zassert_equal(
		pqcp_deployment_evidence_journal_finalize(&journal), 0);
}

ZTEST(pqcp_deployment_evidence_journal, test_append_after_finalize_fails)
{
	struct pqcp_deployment_evidence_journal journal;
	struct pqcp_deployment_evidence_capsule_replay_result first;
	struct pqcp_deployment_evidence_capsule_replay_result second;

	make_capsule(&first, 1U, 90U, true, true);
	make_capsule(&second, 2U, 90U, true, true);
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &first, 1U, 1000U),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_finalize(
			      &journal),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &journal, &second, 2U, 1100U),
		      -EPERM);
	zassert_equal(journal.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_FINALIZED);
}

ZTEST(pqcp_deployment_evidence_journal, test_journal_digest_is_stable)
{
	struct pqcp_deployment_evidence_journal first;
	struct pqcp_deployment_evidence_journal second;
	struct pqcp_deployment_evidence_capsule_replay_result capsule;

	make_capsule(&capsule, 1U, 90U, true, true);
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &first, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &second, "device-001"),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &first, &capsule, 1U, 1000U),
		      0);
	zassert_equal(pqcp_deployment_evidence_journal_append(
			      &second, &capsule, 1U, 1000U),
		      0);
	zassert_equal(
		pqcp_deployment_evidence_journal_finalize(&first), 0);
	zassert_equal(
		pqcp_deployment_evidence_journal_finalize(&second), 0);
	zassert_str_equal(first.journal_digest_hex,
			  second.journal_digest_hex);
}

ZTEST(pqcp_deployment_evidence_journal, test_entry_at_bounds)
{
	struct pqcp_deployment_evidence_journal journal;

	zassert_equal(pqcp_deployment_evidence_journal_init(
			      &journal, "device-001"),
		      0);
	zassert_is_null(pqcp_deployment_evidence_journal_entry_at(
		&journal, 0U));
	zassert_is_null(pqcp_deployment_evidence_journal_entry_at(
		NULL, 0U));
}

ZTEST_SUITE(pqcp_deployment_evidence_journal, NULL, NULL, NULL, NULL, NULL);
