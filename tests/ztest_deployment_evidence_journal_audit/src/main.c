/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for cross-snapshot deployment evidence journal audit.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_journal_audit.h>

#include "deployment_evidence_archive_fixture.h"

#define SNAPSHOT_COUNT 3U

struct audit_fixture {
	struct pqcp_deployment_evidence_journal_replay_result
		snapshots[SNAPSHOT_COUNT];
	struct pqcp_deployment_evidence_journal_audit_policy policy;
	struct pqcp_deployment_evidence_journal_audit_report report;
	char roots[SNAPSHOT_COUNT]
		  [PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	char capsules[SNAPSHOT_COUNT]
		     [PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
};

static void build_snapshots(struct audit_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	zassert_equal(
		pqcp_deployment_evidence_journal_audit_default_policy(
			&fixture->policy),
		0);
	for (uint32_t index = 0U; index < SNAPSHOT_COUNT; ++index) {
		pqcp_archive_test_increment_digest(
			fixture->roots[index], 100U + index);
		pqcp_archive_test_increment_digest(
			fixture->capsules[index], 200U + index);
		pqcp_archive_test_fill_journal_replay(
			&fixture->snapshots[index], "device-001",
			"qemu_x86_64", "hybrid768_65_campaign",
			fixture->roots[index], fixture->capsules[index],
			index + 1U, 90U, true, true);
		fixture->snapshots[index].first_boot_counter = 1U;
		fixture->snapshots[index].last_boot_counter =
			index + 1U;
		fixture->snapshots[index].first_capture_time_ms = 1000U;
		fixture->snapshots[index].last_capture_time_ms =
			1000U + (uint64_t)index * 100U;
	}
}

static int run_audit(struct audit_fixture *fixture)
{
	return pqcp_deployment_evidence_journal_audit_run(
		fixture->snapshots, SNAPSHOT_COUNT, &fixture->policy,
		&fixture->report);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_default_policy)
{
	struct pqcp_deployment_evidence_journal_audit_policy policy;

	zassert_equal(
		pqcp_deployment_evidence_journal_audit_default_policy(&policy),
		0);
	zassert_equal(policy.min_snapshots, 2U);
	zassert_equal(policy.min_entries, 1U);
	zassert_equal(policy.min_signed_percent, 50U);
	zassert_equal(policy.min_production_percent, 50U);
	zassert_equal(policy.min_average_score, 70U);
	zassert_true(policy.require_all_replays);
	zassert_true(policy.require_stable_identity);
	zassert_true(policy.require_monotonic_growth);
	zassert_true(policy.require_unique_roots);
	zassert_equal(
		pqcp_deployment_evidence_journal_audit_default_policy(NULL),
		-EINVAL);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_status_tokens)
{
	zassert_str_equal(
		pqcp_deployment_evidence_journal_audit_status_str(
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_evidence_journal_audit_status_str(
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_evidence_journal_audit_status_str(
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL),
		"FAIL");
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_valid_history_passes)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	zassert_equal(run_audit(&fixture), 0);
	zassert_equal(fixture.report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_PASS);
	zassert_equal(fixture.report.snapshot_count, SNAPSHOT_COUNT);
	zassert_equal(fixture.report.replay_pass_count, SNAPSHOT_COUNT);
	zassert_equal(fixture.report.total_entries, 6U);
	zassert_equal(fixture.report.min_entries, 1U);
	zassert_equal(fixture.report.max_entries, 3U);
	zassert_equal(fixture.report.average_score, 100U);
	zassert_equal(fixture.report.distinct_root_count, SNAPSHOT_COUNT);
	zassert_true(fixture.report.stable_device_id);
	zassert_true(fixture.report.stable_board);
	zassert_true(fixture.report.monotonic_entry_growth);
	zassert_true(fixture.report.monotonic_boot_counter);
	zassert_true(fixture.report.monotonic_capture_time);
	zassert_true(fixture.report.unique_roots);
	zassert_true(fixture.report.signature_non_regression);
	zassert_true(fixture.report.production_non_regression);
	zassert_true(pqcp_deployment_evidence_codec_is_lower_hex(
		fixture.report.audit_digest_hex, 64U));
	zassert_equal(
		pqcp_deployment_evidence_journal_audit_emit(
			&fixture.report),
		0);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_low_sample_warns)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	fixture.policy.min_snapshots = 4U;
	zassert_equal(run_audit(&fixture), 0);
	zassert_equal(fixture.report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARN);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_LOW_SAMPLES,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_replay_failure_blocks)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	fixture.snapshots[1].passed = false;
	fixture.snapshots[1].fail_count = 1U;
	fixture.snapshots[1].pass_count = 1U;
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_REPLAY_FAILURE,
		0U);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_FAILURE_HISTORY,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_device_drift_blocks)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	strcpy(fixture.snapshots[2].device_id, "device-002");
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_false(fixture.report.stable_device_id);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_DEVICE_DRIFT,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_board_drift_blocks)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	strcpy(fixture.snapshots[2].board, "nucleo_h743zi");
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_false(fixture.report.stable_board);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_BOARD_DRIFT,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_entry_rollback_blocks)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	fixture.snapshots[2].entries_checked = 1U;
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_false(fixture.report.monotonic_entry_growth);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_ENTRY_ROLLBACK,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_boot_rollback_blocks)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	fixture.snapshots[2].last_boot_counter = 1U;
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_false(fixture.report.monotonic_boot_counter);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_BOOT_ROLLBACK,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_time_rollback_blocks)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	fixture.snapshots[2].last_capture_time_ms = 900U;
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_false(fixture.report.monotonic_capture_time);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_TIME_ROLLBACK,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_root_reuse_blocks)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	strcpy(fixture.snapshots[2].computed_journal_digest_hex,
	       fixture.snapshots[1].computed_journal_digest_hex);
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_false(fixture.report.unique_roots);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_ROOT_REUSE,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_signature_regression_blocks)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	fixture.snapshots[2].signed_count = 0U;
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_false(fixture.report.signature_non_regression);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_SIGNATURE_REGRESSION,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_production_regression_blocks)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	fixture.snapshots[2].production_count = 0U;
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_false(fixture.report.production_non_regression);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_PRODUCTION_REGRESSION,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_unsigned_history_warns)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	for (size_t index = 0U; index < SNAPSHOT_COUNT; ++index) {
		fixture.snapshots[index].signed_count = 0U;
	}
	fixture.policy.require_no_signature_regression = false;
	zassert_equal(run_audit(&fixture), 0);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_UNSIGNED,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_nonproduction_warns)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	for (size_t index = 0U; index < SNAPSHOT_COUNT; ++index) {
		fixture.snapshots[index].production_count = 0U;
	}
	fixture.policy.require_no_production_regression = false;
	zassert_equal(run_audit(&fixture), 0);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_NON_PRODUCTION,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_score_floor_warns)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	for (size_t index = 0U; index < SNAPSHOT_COUNT; ++index) {
		fixture.snapshots[index].pass_count = 0U;
		fixture.snapshots[index].warn_count =
			fixture.snapshots[index].entries_checked;
	}
	zassert_equal(run_audit(&fixture), 0);
	zassert_equal(fixture.report.average_score, 60U);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_SCORE_FLOOR,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_score_floor_can_block)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	for (size_t index = 0U; index < SNAPSHOT_COUNT; ++index) {
		fixture.snapshots[index].pass_count = 0U;
		fixture.snapshots[index].warn_count =
			fixture.snapshots[index].entries_checked;
	}
	fixture.policy.score_floor_blocks = true;
	zassert_equal(run_audit(&fixture), -EBADMSG);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_SCORE_FLOOR,
		0U);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_digest_is_stable)
{
	struct audit_fixture first;
	struct audit_fixture second;

	build_snapshots(&first);
	build_snapshots(&second);
	zassert_equal(run_audit(&first), 0);
	zassert_equal(run_audit(&second), 0);
	zassert_str_equal(first.report.audit_digest_hex,
			  second.report.audit_digest_hex);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_invalid_inputs)
{
	struct audit_fixture fixture;

	build_snapshots(&fixture);
	zassert_equal(pqcp_deployment_evidence_journal_audit_run(
			      NULL, SNAPSHOT_COUNT, &fixture.policy,
			      &fixture.report),
		      -EINVAL);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_INVALID_INPUT,
		0U);
	zassert_equal(pqcp_deployment_evidence_journal_audit_run(
			      fixture.snapshots, 0U, &fixture.policy,
			      &fixture.report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_journal_audit_run(
			      fixture.snapshots, SNAPSHOT_COUNT, NULL,
			      &fixture.report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_journal_audit_run(
			      fixture.snapshots, SNAPSHOT_COUNT,
			      &fixture.policy, NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_journal_audit, test_emit_rejects_bad_masks)
{
	struct pqcp_deployment_evidence_journal_audit_report report = {
		.schema_version =
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_SCHEMA_VERSION,
		.error_mask = 1U << 31,
	};

	zassert_equal(
		pqcp_deployment_evidence_journal_audit_emit(&report),
		-EINVAL);
	report.error_mask = 0U;
	report.warning_mask = 1U << 31;
	zassert_equal(
		pqcp_deployment_evidence_journal_audit_emit(&report),
		-EINVAL);
	zassert_equal(
		pqcp_deployment_evidence_journal_audit_emit(NULL),
		-EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_journal_audit, NULL, NULL, NULL, NULL,
	    NULL);
