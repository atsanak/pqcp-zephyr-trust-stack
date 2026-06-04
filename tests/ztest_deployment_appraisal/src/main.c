/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deployment evidence appraisal tests.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_appraisal.h>

#define BASE_MARKERS \
	(PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_SCENARIO | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CANDIDATE | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_DECISION)
#define ROBUSTNESS_MARKERS \
	(PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUST_CANDIDATE | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUSTNESS)
#define CAMPAIGN_MARKERS \
	(PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN_METRIC)
#define FULL_MARKERS (BASE_MARKERS | ROBUSTNESS_MARKERS | CAMPAIGN_MARKERS)

static struct pqcp_deployment_transcript_result replay_full(void)
{
	return (struct pqcp_deployment_transcript_result) {
		.schema_version = PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION,
		.lines_seen = 18U,
		.marker_mask = FULL_MARKERS,
		.candidate_count = 3U,
		.accepted_count = 2U,
		.conditional_count = 0U,
		.rejected_count = 1U,
		.feasible_count = 2U,
		.robustness_candidate_count = 3U,
		.pareto_frontier_count = 1U,
		.campaign_metric_count = 7U,
		.campaign_observations = 5U,
		.campaign_quality_mask = 0U,
		.gap_count = 0U,
		.first_error_line = 0U,
		.first_error = PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE,
		.passed = true,
	};
}

static struct pqcp_deployment_transcript_result replay_lab_minimal(void)
{
	return (struct pqcp_deployment_transcript_result) {
		.schema_version = PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION,
		.lines_seen = 6U,
		.marker_mask = BASE_MARKERS,
		.candidate_count = 1U,
		.accepted_count = 0U,
		.conditional_count = 1U,
		.rejected_count = 0U,
		.feasible_count = 1U,
		.first_error_line = 0U,
		.first_error = PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE,
		.passed = true,
	};
}

static int evaluate_default(
	enum pqcp_deployment_appraisal_profile profile,
	const struct pqcp_deployment_transcript_result *replay,
	struct pqcp_deployment_appraisal *appraisal)
{
	struct pqcp_deployment_appraisal_policy policy;

	zassert_equal(pqcp_deployment_appraisal_default_policy(
			      profile, &policy),
		      0);
	return pqcp_deployment_appraisal_evaluate(
		replay, &policy, appraisal);
}

ZTEST(pqcp_deployment_appraisal, test_profile_tokens_are_stable)
{
	zassert_true(strcmp(pqcp_deployment_appraisal_profile_str(
				    PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB),
			    "lab") == 0);
	zassert_true(strcmp(pqcp_deployment_appraisal_profile_str(
				    PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW),
			    "partner_review") == 0);
	zassert_true(strcmp(pqcp_deployment_appraisal_profile_str(
				    (enum pqcp_deployment_appraisal_profile)99),
			    "unknown") == 0);
}

ZTEST(pqcp_deployment_appraisal, test_default_policies_are_distinct)
{
	struct pqcp_deployment_appraisal_policy lab;
	struct pqcp_deployment_appraisal_policy paper;
	struct pqcp_deployment_appraisal_policy partner;

	zassert_equal(pqcp_deployment_appraisal_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB, &lab),
		      0);
	zassert_equal(pqcp_deployment_appraisal_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PAPER, &paper),
		      0);
	zassert_equal(pqcp_deployment_appraisal_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW,
			      &partner),
		      0);
	zassert_false(lab.require_campaign);
	zassert_true(paper.require_campaign);
	zassert_true(partner.require_clean_campaign);
	zassert_false(partner.allow_conditional);
	zassert_equal(partner.max_gap_count, 0U);
	zassert_equal(pqcp_deployment_appraisal_default_policy(
			      (enum pqcp_deployment_appraisal_profile)99, &lab),
		      -EINVAL);
}

ZTEST(pqcp_deployment_appraisal, test_lab_minimal_passes_with_warnings)
{
	struct pqcp_deployment_transcript_result replay = replay_lab_minimal();
	struct pqcp_deployment_appraisal appraisal;

	zassert_equal(evaluate_default(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB,
			      &replay,
			      &appraisal),
		      0);
	zassert_true(appraisal.passed);
	zassert_equal(appraisal.blocker_mask, 0U);
	zassert_true((appraisal.warning_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_WARNING_CONDITIONAL) != 0U);
	zassert_true((appraisal.warning_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_WARNING_NO_CAMPAIGN) != 0U);
	zassert_true((appraisal.warning_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_WARNING_NO_ROBUSTNESS) != 0U);
	zassert_true(appraisal.readiness_score < 100U);
	zassert_equal(pqcp_deployment_appraisal_emit(&appraisal), 0);
}

ZTEST(pqcp_deployment_appraisal, test_full_partner_review_passes)
{
	struct pqcp_deployment_transcript_result replay = replay_full();
	struct pqcp_deployment_appraisal appraisal;

	zassert_equal(evaluate_default(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW,
			      &replay,
			      &appraisal),
		      0);
	zassert_true(appraisal.passed);
	zassert_equal(appraisal.blocker_mask, 0U);
	zassert_true((appraisal.warning_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_WARNING_REJECTED) != 0U);
	zassert_equal(appraisal.candidate_count, 3U);
	zassert_equal(appraisal.accepted_count, 2U);
	zassert_equal(appraisal.campaign_observations, 5U);
	zassert_equal(pqcp_deployment_appraisal_emit(&appraisal), 0);
}

ZTEST(pqcp_deployment_appraisal, test_paper_blocks_missing_campaign)
{
	struct pqcp_deployment_transcript_result replay = replay_lab_minimal();
	struct pqcp_deployment_appraisal appraisal;

	zassert_equal(evaluate_default(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PAPER,
			      &replay,
			      &appraisal),
		      0);
	zassert_false(appraisal.passed);
	zassert_true((appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_MISSING_MARKERS) !=
		     0U);
	zassert_true((appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_REQUIRED) !=
		     0U);
	zassert_true((appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_ROBUSTNESS_REQUIRED) !=
		     0U);
	zassert_equal(pqcp_deployment_appraisal_emit(&appraisal), -EPERM);
}

ZTEST(pqcp_deployment_appraisal, test_product_blocks_bad_campaign_quality)
{
	struct pqcp_deployment_transcript_result replay = replay_full();
	struct pqcp_deployment_appraisal appraisal;

	replay.campaign_quality_mask =
		PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_HIGH_VARIANCE;
	zassert_equal(evaluate_default(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
			      &replay,
			      &appraisal),
		      0);
	zassert_false(appraisal.passed);
	zassert_true((appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_QUALITY) !=
		     0U);
}

ZTEST(pqcp_deployment_appraisal, test_partner_blocks_gaps_and_conditionals)
{
	struct pqcp_deployment_transcript_result replay = replay_full();
	struct pqcp_deployment_appraisal appraisal;

	replay.conditional_count = 1U;
	replay.feasible_count = 3U;
	replay.gap_count = 1U;
	zassert_equal(evaluate_default(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW,
			      &replay,
			      &appraisal),
		      0);
	zassert_false(appraisal.passed);
	zassert_true((appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_OPEN_GAPS) != 0U);
	zassert_true((appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CONDITIONAL) != 0U);
	zassert_true((appraisal.warning_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_WARNING_OPEN_GAPS) != 0U);
}

ZTEST(pqcp_deployment_appraisal, test_hardware_review_requires_more_candidates)
{
	struct pqcp_deployment_transcript_result replay = replay_full();
	struct pqcp_deployment_appraisal appraisal;

	replay.candidate_count = 2U;
	zassert_equal(evaluate_default(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW,
			      &replay,
			      &appraisal),
		      0);
	zassert_false(appraisal.passed);
	zassert_true((appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CANDIDATE_COUNT) !=
		     0U);
}

ZTEST(pqcp_deployment_appraisal, test_failed_replay_blocks_all_profiles)
{
	struct pqcp_deployment_transcript_result replay = replay_full();
	struct pqcp_deployment_appraisal appraisal;

	replay.passed = false;
	replay.first_error = PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_TOP_MISMATCH;
	zassert_equal(evaluate_default(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB,
			      &replay,
			      &appraisal),
		      0);
	zassert_false(appraisal.passed);
	zassert_true((appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_REPLAY_FAILED) != 0U);
}

ZTEST(pqcp_deployment_appraisal, test_custom_policy_controls_thresholds)
{
	struct pqcp_deployment_transcript_result replay = replay_full();
	struct pqcp_deployment_appraisal appraisal;
	struct pqcp_deployment_appraisal_policy policy;

	zassert_equal(pqcp_deployment_appraisal_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
			      &policy),
		      0);
	policy.min_campaign_observations = 6U;
	zassert_equal(pqcp_deployment_appraisal_evaluate(
			      &replay, &policy, &appraisal),
		      0);
	zassert_false(appraisal.passed);
	zassert_true((appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_SAMPLES) !=
		     0U);
}

ZTEST(pqcp_deployment_appraisal, test_invalid_arguments_and_masks_fail)
{
	struct pqcp_deployment_transcript_result replay = replay_full();
	struct pqcp_deployment_appraisal appraisal;
	struct pqcp_deployment_appraisal_policy policy;

	zassert_equal(pqcp_deployment_appraisal_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB, &policy),
		      0);
	zassert_equal(pqcp_deployment_appraisal_evaluate(
			      NULL, &policy, &appraisal),
		      -EINVAL);
	zassert_equal(pqcp_deployment_appraisal_evaluate(
			      &replay, NULL, &appraisal),
		      -EINVAL);
	zassert_equal(pqcp_deployment_appraisal_evaluate(
			      &replay, &policy, NULL),
		      -EINVAL);

	policy.required_markers = 0x80000000U;
	zassert_equal(pqcp_deployment_appraisal_evaluate(
			      &replay, &policy, &appraisal),
		      -EINVAL);

	appraisal = (struct pqcp_deployment_appraisal) {
		.schema_version = PQCP_DEPLOYMENT_APPRAISAL_SCHEMA_VERSION,
		.profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB,
		.blocker_mask = 0x80000000U,
		.warning_mask = 0U,
		.marker_mask = BASE_MARKERS,
		.readiness_score = 100U,
		.passed = true,
	};
	zassert_equal(pqcp_deployment_appraisal_emit(NULL), -EINVAL);
	zassert_equal(pqcp_deployment_appraisal_emit(&appraisal), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_appraisal, NULL, NULL, NULL, NULL, NULL);
