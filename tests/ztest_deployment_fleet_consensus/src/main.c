/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for fleet deployment evidence consensus.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_fleet_consensus.h>

#include "deployment_evidence_archive_fixture.h"

#define DEVICE_COUNT 3U

struct fleet_fixture {
	struct pqcp_deployment_evidence_journal_replay_result
		journals[DEVICE_COUNT];
	struct pqcp_deployment_evidence_journal_audit_report
		audits[DEVICE_COUNT];
	struct pqcp_deployment_fleet_consensus_policy policy;
	struct pqcp_deployment_fleet_consensus_report report;
	char roots[DEVICE_COUNT]
		  [PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	char capsules[DEVICE_COUNT]
		     [PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	char audit_digests[DEVICE_COUNT]
			 [PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
};

static const char *device_ids[DEVICE_COUNT] = {
	"device-001", "device-002", "device-003",
};

static void build_fleet(struct fleet_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	zassert_equal(
		pqcp_deployment_fleet_consensus_default_policy(
			&fixture->policy),
		0);
	for (uint32_t index = 0U; index < DEVICE_COUNT; ++index) {
		pqcp_archive_test_increment_digest(
			fixture->roots[index], 300U + index);
		pqcp_archive_test_increment_digest(
			fixture->capsules[index], 400U + index);
		pqcp_archive_test_increment_digest(
			fixture->audit_digests[index], 500U + index);
		pqcp_archive_test_fill_journal_replay(
			&fixture->journals[index], device_ids[index],
			"qemu_x86_64", "hybrid768_65_campaign",
			fixture->roots[index], fixture->capsules[index],
			4U, 90U + index, true, true);
		pqcp_archive_test_fill_journal_audit(
			&fixture->audits[index], device_ids[index],
			"qemu_x86_64", fixture->roots[index],
			fixture->roots[index],
			fixture->audit_digests[index], 2U, 4U,
			90U + index,
			PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_PASS);
	}
}

static int run_fleet(struct fleet_fixture *fixture)
{
	return pqcp_deployment_fleet_consensus_run(
		fixture->journals, fixture->audits, DEVICE_COUNT,
		&fixture->policy, &fixture->report);
}

ZTEST(pqcp_deployment_fleet_consensus, test_default_policy)
{
	struct pqcp_deployment_fleet_consensus_policy policy;

	zassert_equal(
		pqcp_deployment_fleet_consensus_default_policy(&policy), 0);
	zassert_equal(policy.min_devices, 3U);
	zassert_equal(policy.min_quorum_percent, 67U);
	zassert_equal(policy.min_signature_percent, 67U);
	zassert_equal(policy.min_production_percent, 67U);
	zassert_true(policy.require_all_replays);
	zassert_true(policy.require_all_audits);
	zassert_true(policy.require_candidate_consensus);
	zassert_false(policy.require_board_consensus);
	zassert_equal(
		pqcp_deployment_fleet_consensus_default_policy(NULL),
		-EINVAL);
}

ZTEST(pqcp_deployment_fleet_consensus, test_status_tokens)
{
	zassert_str_equal(
		pqcp_deployment_fleet_consensus_status_str(
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_fleet_consensus_status_str(
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_fleet_consensus_status_str(
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_FAIL),
		"FAIL");
}

ZTEST(pqcp_deployment_fleet_consensus, test_uniform_fleet_passes)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	zassert_equal(run_fleet(&fixture), 0);
	zassert_equal(fixture.report.status,
		      PQCP_DEPLOYMENT_FLEET_CONSENSUS_PASS);
	zassert_equal(fixture.report.device_count, DEVICE_COUNT);
	zassert_equal(fixture.report.accepted_count, DEVICE_COUNT);
	zassert_equal(fixture.report.rejected_count, 0U);
	zassert_equal(fixture.report.candidate_quorum_percent, 100U);
	zassert_equal(fixture.report.board_quorum_percent, 100U);
	zassert_equal(fixture.report.profile_quorum_percent, 100U);
	zassert_equal(fixture.report.distinct_profiles, 1U);
	zassert_equal(fixture.report.signature_count, DEVICE_COUNT);
	zassert_equal(fixture.report.production_count, DEVICE_COUNT);
	zassert_equal(fixture.report.average_score, 91U);
	zassert_str_equal(fixture.report.consensus_candidate_id,
			  "hybrid768_65_campaign");
	zassert_str_equal(fixture.report.consensus_board, "qemu_x86_64");
	zassert_true(pqcp_deployment_evidence_codec_is_lower_hex(
		fixture.report.fleet_digest_hex, 64U));
	zassert_equal(
		pqcp_deployment_fleet_consensus_emit(&fixture.report), 0);
}

ZTEST(pqcp_deployment_fleet_consensus, test_candidate_quorum_two_of_three)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	strcpy(fixture.journals[2].latest_top_candidate_id,
	       "mlkem1024_mldsa87");
	zassert_equal(run_fleet(&fixture), -EBADMSG);
	zassert_equal(fixture.report.candidate_quorum_percent, 66U);
	zassert_equal(fixture.report.status,
		      PQCP_DEPLOYMENT_FLEET_CONSENSUS_FAIL);
}

ZTEST(pqcp_deployment_fleet_consensus, test_candidate_warning_mode)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	strcpy(fixture.journals[2].latest_top_candidate_id,
	       "mlkem1024_mldsa87");
	fixture.policy.require_candidate_consensus = false;
	zassert_equal(run_fleet(&fixture), 0);
	zassert_equal(fixture.report.status,
		      PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARN);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_CANDIDATE_DRIFT,
		0U);
	zassert_equal(fixture.report.outlier_count, 1U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_duplicate_device_fails)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	strcpy(fixture.journals[2].device_id,
	       fixture.journals[1].device_id);
	zassert_equal(run_fleet(&fixture), -EBADMSG);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_DUPLICATE_DEVICE,
		0U);
	zassert_equal(fixture.report.rejected_count, 1U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_replay_failure_fails)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	fixture.journals[1].passed = false;
	zassert_equal(run_fleet(&fixture), -EBADMSG);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_REPLAY_FAILURE,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_audit_failure_fails)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	fixture.audits[1].status =
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL;
	zassert_equal(run_fleet(&fixture), -EBADMSG);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_AUDIT_FAILURE,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_identity_mismatch_fails)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	strcpy(fixture.audits[1].device_id, "wrong-device");
	zassert_equal(run_fleet(&fixture), -EBADMSG);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_IDENTITY_MISMATCH,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_unsigned_fleet_warns)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	fixture.journals[1].latest_signature_verified = false;
	fixture.journals[2].latest_signature_verified = false;
	zassert_equal(run_fleet(&fixture), 0);
	zassert_equal(fixture.report.status,
		      PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARN);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_UNSIGNED,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_signature_floor_can_block)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	fixture.journals[1].latest_signature_verified = false;
	fixture.journals[2].latest_signature_verified = false;
	fixture.policy.signature_floor_blocks = true;
	zassert_equal(run_fleet(&fixture), -EBADMSG);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_SIGNATURE_COVERAGE,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_nonproduction_warns)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	fixture.journals[1].latest_production_allowed = false;
	fixture.journals[2].latest_production_allowed = false;
	zassert_equal(run_fleet(&fixture), 0);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_NON_PRODUCTION,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_low_score_warns)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	for (size_t index = 0U; index < DEVICE_COUNT; ++index) {
		fixture.journals[index].latest_passport_score = 60U;
	}
	zassert_equal(run_fleet(&fixture), 0);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_LOW_SCORE,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_board_drift_warns)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	strcpy(fixture.journals[2].board, "nucleo_h743zi");
	strcpy(fixture.audits[2].board, "nucleo_h743zi");
	zassert_equal(run_fleet(&fixture), 0);
	zassert_equal(fixture.report.status,
		      PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARN);
	zassert_equal(fixture.report.distinct_boards, 2U);
	zassert_equal(fixture.report.outlier_count, 1U);
	zassert_not_equal(
		fixture.report.warning_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_BOARD_DRIFT,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_board_drift_can_block)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	strcpy(fixture.journals[2].board, "nucleo_h743zi");
	strcpy(fixture.audits[2].board, "nucleo_h743zi");
	fixture.policy.require_board_consensus = true;
	zassert_equal(run_fleet(&fixture), -EBADMSG);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_BOARD_DRIFT,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_profile_drift_blocks)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	fixture.journals[2].latest_profile =
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	zassert_equal(run_fleet(&fixture), -EBADMSG);
	zassert_not_equal(
		fixture.report.error_mask &
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_PROFILE_DRIFT,
		0U);
}

ZTEST(pqcp_deployment_fleet_consensus, test_digest_is_stable)
{
	struct fleet_fixture first;
	struct fleet_fixture second;

	build_fleet(&first);
	build_fleet(&second);
	zassert_equal(run_fleet(&first), 0);
	zassert_equal(run_fleet(&second), 0);
	zassert_str_equal(first.report.fleet_digest_hex,
			  second.report.fleet_digest_hex);
}

ZTEST(pqcp_deployment_fleet_consensus, test_invalid_inputs)
{
	struct fleet_fixture fixture;

	build_fleet(&fixture);
	zassert_equal(pqcp_deployment_fleet_consensus_run(
			      NULL, fixture.audits, DEVICE_COUNT,
			      &fixture.policy, &fixture.report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_fleet_consensus_run(
			      fixture.journals, NULL, DEVICE_COUNT,
			      &fixture.policy, &fixture.report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_fleet_consensus_run(
			      fixture.journals, fixture.audits, 0U,
			      &fixture.policy, &fixture.report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_fleet_consensus_run(
			      fixture.journals, fixture.audits,
			      DEVICE_COUNT, NULL, &fixture.report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_fleet_consensus_run(
			      fixture.journals, fixture.audits,
			      DEVICE_COUNT, &fixture.policy, NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_fleet_consensus, test_emit_rejects_bad_report)
{
	struct pqcp_deployment_fleet_consensus_report report = {
		.schema_version =
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_SCHEMA_VERSION,
		.device_count =
			PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_DEVICES + 1U,
	};

	zassert_equal(
		pqcp_deployment_fleet_consensus_emit(&report), -EINVAL);
	report.device_count = 1U;
	report.error_mask = 1U << 31;
	zassert_equal(
		pqcp_deployment_fleet_consensus_emit(&report), -EINVAL);
	zassert_equal(
		pqcp_deployment_fleet_consensus_emit(NULL), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_fleet_consensus, NULL, NULL, NULL, NULL, NULL);
