/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for fleet deployment policy appraisal.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_fleet_policy.h>

#include "deployment_evidence_archive_fixture.h"

static void fill_consensus(
	struct pqcp_deployment_fleet_consensus_report *report,
	uint32_t devices)
{
	char digest[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];

	memset(report, 0, sizeof(*report));
	pqcp_archive_test_increment_digest(digest, 600U);
	report->schema_version =
		PQCP_DEPLOYMENT_FLEET_CONSENSUS_SCHEMA_VERSION;
	report->status = PQCP_DEPLOYMENT_FLEET_CONSENSUS_PASS;
	report->device_count = devices;
	report->accepted_count = devices;
	report->replay_pass_count = devices;
	report->audit_pass_count = devices;
	report->signature_count = devices;
	report->production_count = devices;
	report->passport_pass_count = devices;
	report->min_score = 90U;
	report->max_score = 94U;
	report->average_score = 92U;
	report->candidate_quorum_percent = 100U;
	report->board_quorum_percent = 100U;
	report->profile_quorum_percent = 100U;
	report->distinct_candidates = 1U;
	report->distinct_boards = 1U;
	report->distinct_profiles = 1U;
	report->consensus_profile =
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	strcpy(report->consensus_candidate_id, "hybrid768_65_campaign");
	strcpy(report->consensus_board, "qemu_x86_64");
	strcpy(report->fleet_digest_hex, digest);
}

static int evaluate(
	const struct pqcp_deployment_fleet_consensus_report *consensus,
	enum pqcp_deployment_fleet_policy_profile profile,
	struct pqcp_deployment_fleet_policy *policy,
	struct pqcp_deployment_fleet_policy_result *result)
{
	int ret = pqcp_deployment_fleet_policy_default(profile, policy);

	if (ret != 0) {
		return ret;
	}
	return pqcp_deployment_fleet_policy_evaluate(
		consensus, policy, result);
}

ZTEST(pqcp_deployment_fleet_policy, test_profile_tokens)
{
	zassert_str_equal(
		pqcp_deployment_fleet_policy_profile_str(
			PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE),
		"prototype");
	zassert_str_equal(
		pqcp_deployment_fleet_policy_profile_str(
			PQCP_DEPLOYMENT_FLEET_POLICY_PAPER),
		"paper");
	zassert_str_equal(
		pqcp_deployment_fleet_policy_profile_str(
			PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT),
		"product");
	zassert_str_equal(
		pqcp_deployment_fleet_policy_profile_str(
			PQCP_DEPLOYMENT_FLEET_POLICY_PARTNER),
		"partner");
	zassert_str_equal(
		pqcp_deployment_fleet_policy_profile_str(
			PQCP_DEPLOYMENT_FLEET_POLICY_HARDWARE),
		"hardware");
	zassert_str_equal(
		pqcp_deployment_fleet_policy_profile_str(99), "unknown");
}

ZTEST(pqcp_deployment_fleet_policy, test_status_tokens)
{
	zassert_str_equal(
		pqcp_deployment_fleet_policy_status_str(
			PQCP_DEPLOYMENT_FLEET_POLICY_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_fleet_policy_status_str(
			PQCP_DEPLOYMENT_FLEET_POLICY_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_fleet_policy_status_str(
			PQCP_DEPLOYMENT_FLEET_POLICY_FAIL),
		"FAIL");
}

ZTEST(pqcp_deployment_fleet_policy, test_default_profiles_are_ordered)
{
	struct pqcp_deployment_fleet_policy prototype;
	struct pqcp_deployment_fleet_policy paper;
	struct pqcp_deployment_fleet_policy product;
	struct pqcp_deployment_fleet_policy partner;
	struct pqcp_deployment_fleet_policy hardware;

	zassert_equal(pqcp_deployment_fleet_policy_default(
			      PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE,
			      &prototype),
		      0);
	zassert_equal(pqcp_deployment_fleet_policy_default(
			      PQCP_DEPLOYMENT_FLEET_POLICY_PAPER, &paper),
		      0);
	zassert_equal(pqcp_deployment_fleet_policy_default(
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT, &product),
		      0);
	zassert_equal(pqcp_deployment_fleet_policy_default(
			      PQCP_DEPLOYMENT_FLEET_POLICY_PARTNER, &partner),
		      0);
	zassert_equal(pqcp_deployment_fleet_policy_default(
			      PQCP_DEPLOYMENT_FLEET_POLICY_HARDWARE,
			      &hardware),
		      0);
	zassert_true(prototype.min_devices < paper.min_devices);
	zassert_true(paper.min_devices <= product.min_devices);
	zassert_true(product.min_signature_percent >=
		     paper.min_signature_percent);
	zassert_true(partner.signature_floor_blocks);
	zassert_true(hardware.min_board_quorum_percent == 100U);
	zassert_equal(
		pqcp_deployment_fleet_policy_default(
			PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE, NULL),
		-EINVAL);
	zassert_equal(
		pqcp_deployment_fleet_policy_default(99, &prototype),
		-EINVAL);
}

ZTEST(pqcp_deployment_fleet_policy, test_prototype_single_device_passes)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 1U);
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE,
			      &policy, &result),
		      0);
	zassert_equal(result.status, PQCP_DEPLOYMENT_FLEET_POLICY_PASS);
	zassert_equal(result.blocker_mask, 0U);
	zassert_equal(result.warning_mask, 0U);
	zassert_equal(result.readiness_score, 96U);
	zassert_equal(result.reviewer_risk_score, 4U);
	zassert_equal(result.evidence_grade, 4U);
	zassert_true(result.consensus_digest_bound);
	zassert_str_equal(result.candidate_id, "hybrid768_65_campaign");
	zassert_equal(pqcp_deployment_fleet_policy_emit(&result), 0);
}

ZTEST(pqcp_deployment_fleet_policy, test_product_requires_five_devices)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 3U);
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &policy, &result),
		      -EBADMSG);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_DEVICE_COUNT,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_ADD_DEVICES,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_product_requires_production)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 5U);
	consensus.production_count = 2U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &policy, &result),
		      -EBADMSG);
	zassert_equal(result.production_percent, 40U);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_PRODUCTION_COVERAGE,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_PROMOTE_PRODUCTION,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_partner_requires_signatures)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 3U);
	consensus.signature_count = 1U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PARTNER,
			      &policy, &result),
		      -EBADMSG);
	zassert_equal(result.signature_percent, 33U);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_SIGNATURE_COVERAGE,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_SIGN_PASSPORTS,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_paper_warns_on_unsigned)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 3U);
	consensus.signature_count = 0U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PAPER,
			      &policy, &result),
		      0);
	zassert_equal(result.status, PQCP_DEPLOYMENT_FLEET_POLICY_PASS);
}

ZTEST(pqcp_deployment_fleet_policy, test_quorum_drift_generates_actions)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 5U);
	consensus.candidate_quorum_percent = 60U;
	consensus.profile_quorum_percent = 60U;
	consensus.board_quorum_percent = 40U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &policy, &result),
		      -EBADMSG);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_CANDIDATE_QUORUM,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_RESOLVE_CANDIDATE_DRIFT,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_RESOLVE_PROFILE_DRIFT,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_RESOLVE_BOARD_DRIFT,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_consensus_warn_blocks_product)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 5U);
	consensus.status = PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARN;
	consensus.warning_mask =
		PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_OUTLIERS;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &policy, &result),
		      -EBADMSG);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_CONSENSUS_FAIL,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_failure_history_blocks_product)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 5U);
	consensus.passport_fail_count = 1U;
	consensus.passport_pass_count = 4U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &policy, &result),
		      -EBADMSG);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_PASSPORT_FAILURES,
		0U);
	zassert_not_equal(
		result.warning_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_FAILURE_HISTORY,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_audit_failure_generates_reaudit)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 5U);
	consensus.audit_fail_count = 1U;
	consensus.audit_pass_count = 4U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &policy, &result),
		      -EBADMSG);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_AUDIT_FAILURES,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_REAUDIT_DEVICE,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_replay_failure_generates_replay_action)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 5U);
	consensus.replay_pass_count = 4U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &policy, &result),
		      -EBADMSG);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_REPLAY_FAILURES,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_REPLAY_FAILED_DEVICE,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_low_score_blocks_product)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 5U);
	consensus.average_score = 60U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &policy, &result),
		      -EBADMSG);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_SCORE_FLOOR,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_REPEAT_BENCHMARKS,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_outliers_block_partner)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 4U);
	consensus.outlier_count = 2U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PARTNER,
			      &policy, &result),
		      -EBADMSG);
	zassert_equal(result.outlier_percent, 50U);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_OUTLIERS,
		0U);
	zassert_not_equal(
		result.action_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_INVESTIGATE_OUTLIERS,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_heterogeneous_board_warns)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 3U);
	consensus.distinct_boards = 2U;
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PAPER,
			      &policy, &result),
		      0);
	zassert_equal(result.status, PQCP_DEPLOYMENT_FLEET_POLICY_WARN);
	zassert_not_equal(
		result.warning_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_HETEROGENEOUS_BOARD,
		0U);
}

ZTEST(pqcp_deployment_fleet_policy, test_digest_is_stable)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy first_policy;
	struct pqcp_deployment_fleet_policy second_policy;
	struct pqcp_deployment_fleet_policy_result first;
	struct pqcp_deployment_fleet_policy_result second;

	fill_consensus(&consensus, 5U);
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &first_policy, &first),
		      0);
	zassert_equal(evaluate(
			      &consensus,
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &second_policy, &second),
		      0);
	zassert_str_equal(first.policy_digest_hex,
			  second.policy_digest_hex);
}

ZTEST(pqcp_deployment_fleet_policy, test_invalid_inputs)
{
	struct pqcp_deployment_fleet_consensus_report consensus;
	struct pqcp_deployment_fleet_policy policy;
	struct pqcp_deployment_fleet_policy_result result;

	fill_consensus(&consensus, 5U);
	zassert_equal(pqcp_deployment_fleet_policy_default(
			      PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
			      &policy),
		      0);
	zassert_equal(pqcp_deployment_fleet_policy_evaluate(
			      NULL, &policy, &result),
		      -EINVAL);
	zassert_not_equal(
		result.blocker_mask &
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_INVALID_INPUT,
		0U);
	zassert_equal(pqcp_deployment_fleet_policy_evaluate(
			      &consensus, NULL, &result),
		      -EINVAL);
	zassert_equal(pqcp_deployment_fleet_policy_evaluate(
			      &consensus, &policy, NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_fleet_policy, test_emit_rejects_bad_result)
{
	struct pqcp_deployment_fleet_policy_result result = {
		.schema_version = PQCP_DEPLOYMENT_FLEET_POLICY_SCHEMA_VERSION,
		.profile = PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
		.blocker_mask = 1U << 31,
	};

	zassert_equal(pqcp_deployment_fleet_policy_emit(&result), -EINVAL);
	result.blocker_mask = 0U;
	result.action_mask = 1U << 31;
	zassert_equal(pqcp_deployment_fleet_policy_emit(&result), -EINVAL);
	zassert_equal(pqcp_deployment_fleet_policy_emit(NULL), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_fleet_policy, NULL, NULL, NULL, NULL, NULL);
