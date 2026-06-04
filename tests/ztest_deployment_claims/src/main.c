/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deployment claim support matrix tests.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_claims.h>

#define BASE_MARKERS \
	(PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_SCENARIO | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CANDIDATE | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_DECISION)
#define CAMPAIGN_MARKERS \
	(PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN_METRIC)
#define ROBUSTNESS_MARKERS \
	(PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUST_CANDIDATE | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUSTNESS)
#define FULL_MARKERS (BASE_MARKERS | CAMPAIGN_MARKERS | ROBUSTNESS_MARKERS)

static struct pqcp_deployment_report advisor_ready(void)
{
	return (struct pqcp_deployment_report) {
		.schema_version = PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION,
		.scenario_id = "claim_case",
		.candidate_count = 3U,
		.feasible_count = 2U,
		.accepted_count = 2U,
		.conditional_count = 0U,
		.rejected_count = 1U,
		.top_result_index = 0U,
		.recommendation_ready = true,
	};
}

static struct pqcp_deployment_robustness_report robustness_ready(void)
{
	return (struct pqcp_deployment_robustness_report) {
		.schema_version = PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION,
		.scenario_id = "claim_case",
		.candidate_count = 3U,
		.feasible_count = 2U,
		.pareto_frontier_count = 1U,
		.top_candidate_index = 0U,
		.top_robustness_score = 96U,
		.top_preference_win_count = 4U,
		.recommendation_stable = true,
		.recommendation_robust = true,
	};
}

static struct pqcp_deployment_transcript_result transcript_ready(void)
{
	return (struct pqcp_deployment_transcript_result) {
		.schema_version = PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION,
		.lines_seen = 24U,
		.marker_mask = FULL_MARKERS,
		.candidate_count = 3U,
		.accepted_count = 2U,
		.conditional_count = 0U,
		.rejected_count = 1U,
		.feasible_count = 2U,
		.robustness_candidate_count = 3U,
		.pareto_frontier_count = 1U,
		.campaign_metric_count = 7U,
		.campaign_observations =
			PQCP_DEPLOYMENT_CAMPAIGN_DEFAULT_MIN_SAMPLES,
		.campaign_quality_mask = 0U,
		.gap_count = 0U,
		.first_error_line = 0U,
		.first_error = PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE,
		.passed = true,
	};
}

static struct pqcp_deployment_appraisal appraisal_ready(void)
{
	return (struct pqcp_deployment_appraisal) {
		.schema_version = PQCP_DEPLOYMENT_APPRAISAL_SCHEMA_VERSION,
		.profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW,
		.blocker_mask = 0U,
		.warning_mask = 0U,
		.marker_mask = FULL_MARKERS,
		.candidate_count = 3U,
		.feasible_count = 2U,
		.accepted_count = 2U,
		.conditional_count = 0U,
		.gap_count = 0U,
		.campaign_observations =
			PQCP_DEPLOYMENT_CAMPAIGN_DEFAULT_MIN_SAMPLES,
		.readiness_score = 96U,
		.passed = true,
	};
}

static struct pqcp_deployment_claim_inputs inputs_from(
	const struct pqcp_deployment_report *advisor,
	const struct pqcp_deployment_robustness_report *robustness,
	const struct pqcp_deployment_transcript_result *transcript,
	const struct pqcp_deployment_appraisal *appraisal)
{
	return (struct pqcp_deployment_claim_inputs) {
		.advisor_report = advisor,
		.robustness_report = robustness,
		.transcript_result = transcript,
		.appraisal = appraisal,
	};
}

static int evaluate(
	const struct pqcp_deployment_claim_inputs *inputs,
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS],
	struct pqcp_deployment_claim_matrix *matrix)
{
	return pqcp_deployment_claims_evaluate(
		inputs, rows, PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS, matrix);
}

static const struct pqcp_deployment_claim_row *find_row(
	const struct pqcp_deployment_claim_row *rows,
	enum pqcp_deployment_claim_id claim_id)
{
	for (size_t i = 0U; i < PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS; ++i) {
		if (rows[i].claim_id == claim_id) {
			return &rows[i];
		}
	}

	return NULL;
}

ZTEST(pqcp_deployment_claims, test_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_claim_id_str(
			PQCP_DEPLOYMENT_CLAIM_FEASIBLE_RECOMMENDATION),
		"claim.deployment.feasible_recommendation");
	zassert_str_equal(
		pqcp_deployment_claim_id_str(
			PQCP_DEPLOYMENT_CLAIM_GAP_FREE_REVIEW),
		"claim.deployment.gap_free_review");
	zassert_str_equal(
		pqcp_deployment_claim_id_str(
			(enum pqcp_deployment_claim_id)99),
		"claim.deployment.unknown");
	zassert_str_equal(
		pqcp_deployment_claim_support_str(
			PQCP_DEPLOYMENT_CLAIM_SUPPORTED),
		"SUPPORTED");
	zassert_str_equal(
		pqcp_deployment_claim_support_str(
			PQCP_DEPLOYMENT_CLAIM_PARTIAL),
		"PARTIAL");
	zassert_str_equal(
		pqcp_deployment_claim_risk_str(
			PQCP_DEPLOYMENT_CLAIM_RISK_HIGH),
		"HIGH");
}

ZTEST(pqcp_deployment_claims, test_full_evidence_supports_all_claims)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;

	zassert_equal(evaluate(&inputs, rows, &matrix), 0);
	zassert_true(matrix.passed);
	zassert_equal(matrix.claim_count, PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS);
	zassert_equal(matrix.supported_count, PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS);
	zassert_equal(matrix.partial_count, 0U);
	zassert_equal(matrix.unsupported_count, 0U);
	zassert_equal(matrix.high_risk_count, 0U);
	zassert_true(matrix.average_score >= 95U);
	zassert_equal(pqcp_deployment_claim_matrix_emit(&matrix), 0);
	for (size_t i = 0U; i < PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS; ++i) {
		zassert_equal(rows[i].support,
			      PQCP_DEPLOYMENT_CLAIM_SUPPORTED);
		zassert_equal(rows[i].risk, PQCP_DEPLOYMENT_CLAIM_RISK_LOW);
		zassert_equal(pqcp_deployment_claim_row_emit(&rows[i]), 0);
	}
}

ZTEST(pqcp_deployment_claims, test_conditional_candidate_makes_feasibility_partial)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;
	const struct pqcp_deployment_claim_row *row;

	advisor.conditional_count = 1U;
	zassert_equal(evaluate(&inputs, rows, &matrix), 0);
	row = find_row(rows, PQCP_DEPLOYMENT_CLAIM_FEASIBLE_RECOMMENDATION);
	zassert_not_null(row);
	zassert_equal(row->support, PQCP_DEPLOYMENT_CLAIM_PARTIAL);
	zassert_equal(row->risk, PQCP_DEPLOYMENT_CLAIM_RISK_MEDIUM);
	zassert_true(matrix.passed);
	zassert_equal(matrix.partial_count, 1U);
}

ZTEST(pqcp_deployment_claims, test_failed_transcript_blocks_replay_claim)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;
	const struct pqcp_deployment_claim_row *row;

	transcript.passed = false;
	transcript.first_error =
		PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_TOP_MISMATCH;
	zassert_equal(evaluate(&inputs, rows, &matrix), 0);
	row = find_row(rows, PQCP_DEPLOYMENT_CLAIM_REPLAYABLE_EVIDENCE);
	zassert_not_null(row);
	zassert_equal(row->support, PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED);
	zassert_true((row->blocker_mask &
		      PQCP_DEPLOYMENT_CLAIM_BLOCKER_REPLAY_FAILED) != 0U);
	zassert_false(matrix.passed);
	zassert_equal(pqcp_deployment_claim_row_emit(row), -ENODATA);
}

ZTEST(pqcp_deployment_claims, test_bad_campaign_quality_is_partial)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;
	const struct pqcp_deployment_claim_row *row;

	transcript.campaign_quality_mask =
		PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_HIGH_VARIANCE;
	zassert_equal(evaluate(&inputs, rows, &matrix), 0);
	row = find_row(rows, PQCP_DEPLOYMENT_CLAIM_REPRODUCIBLE_CAMPAIGN);
	zassert_not_null(row);
	zassert_equal(row->support, PQCP_DEPLOYMENT_CLAIM_PARTIAL);
	zassert_true((row->warning_mask &
		      PQCP_DEPLOYMENT_CLAIM_BLOCKER_CAMPAIGN_QUALITY) != 0U);
	zassert_true(matrix.passed);
}

ZTEST(pqcp_deployment_claims, test_missing_campaign_is_unsupported)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;
	const struct pqcp_deployment_claim_row *row;

	transcript.marker_mask &= ~CAMPAIGN_MARKERS;
	transcript.campaign_observations = 0U;
	zassert_equal(evaluate(&inputs, rows, &matrix), 0);
	row = find_row(rows, PQCP_DEPLOYMENT_CLAIM_REPRODUCIBLE_CAMPAIGN);
	zassert_not_null(row);
	zassert_equal(row->support, PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED);
	zassert_true((row->blocker_mask &
		      PQCP_DEPLOYMENT_CLAIM_BLOCKER_CAMPAIGN_MISSING) != 0U);
	zassert_false(matrix.passed);
}

ZTEST(pqcp_deployment_claims, test_non_robust_recommendation_is_unsupported)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;
	const struct pqcp_deployment_claim_row *row;

	robustness.recommendation_robust = false;
	robustness.recommendation_stable = false;
	zassert_equal(evaluate(&inputs, rows, &matrix), 0);
	row = find_row(rows, PQCP_DEPLOYMENT_CLAIM_ROBUST_RECOMMENDATION);
	zassert_not_null(row);
	zassert_equal(row->support, PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED);
	zassert_true((row->blocker_mask &
		      PQCP_DEPLOYMENT_CLAIM_BLOCKER_NOT_ROBUST) != 0U);
	zassert_false(matrix.passed);
}

ZTEST(pqcp_deployment_claims, test_open_gaps_block_gap_free_review)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;
	const struct pqcp_deployment_claim_row *row;

	appraisal.gap_count = 1U;
	zassert_equal(evaluate(&inputs, rows, &matrix), 0);
	row = find_row(rows, PQCP_DEPLOYMENT_CLAIM_GAP_FREE_REVIEW);
	zassert_not_null(row);
	zassert_equal(row->support, PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED);
	zassert_true((row->blocker_mask &
		      PQCP_DEPLOYMENT_CLAIM_BLOCKER_OPEN_GAPS) != 0U);
	zassert_false(matrix.passed);
}

ZTEST(pqcp_deployment_claims, test_lower_profile_gap_free_review_is_partial)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;
	const struct pqcp_deployment_claim_row *row;

	appraisal.profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT;
	zassert_equal(evaluate(&inputs, rows, &matrix), 0);
	row = find_row(rows, PQCP_DEPLOYMENT_CLAIM_GAP_FREE_REVIEW);
	zassert_not_null(row);
	zassert_equal(row->support, PQCP_DEPLOYMENT_CLAIM_PARTIAL);
	zassert_true(matrix.passed);
}

ZTEST(pqcp_deployment_claims, test_invalid_arguments_fail)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;

	zassert_equal(pqcp_deployment_claims_evaluate(
			      NULL, rows, ARRAY_SIZE(rows), &matrix),
		      -EINVAL);
	zassert_equal(pqcp_deployment_claims_evaluate(
			      &inputs, NULL, ARRAY_SIZE(rows), &matrix),
		      -EINVAL);
	zassert_equal(pqcp_deployment_claims_evaluate(
			      &inputs, rows, 1U, &matrix),
		      -ENOSPC);
	zassert_equal(pqcp_deployment_claims_evaluate(
			      &inputs, rows, ARRAY_SIZE(rows), NULL),
		      -EINVAL);

	transcript.schema_version = 99U;
	zassert_equal(evaluate(&inputs, rows, &matrix), -EINVAL);
	zassert_equal(pqcp_deployment_claim_row_emit(NULL), -EINVAL);
	zassert_equal(pqcp_deployment_claim_matrix_emit(NULL), -EINVAL);
}

ZTEST(pqcp_deployment_claims, test_emit_rejects_corrupted_row_and_matrix)
{
	struct pqcp_deployment_report advisor = advisor_ready();
	struct pqcp_deployment_robustness_report robustness = robustness_ready();
	struct pqcp_deployment_transcript_result transcript = transcript_ready();
	struct pqcp_deployment_appraisal appraisal = appraisal_ready();
	struct pqcp_deployment_claim_inputs inputs =
		inputs_from(&advisor, &robustness, &transcript, &appraisal);
	struct pqcp_deployment_claim_row rows[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	struct pqcp_deployment_claim_matrix matrix;

	zassert_equal(evaluate(&inputs, rows, &matrix), 0);
	rows[0].score = 101U;
	zassert_equal(pqcp_deployment_claim_row_emit(&rows[0]), -EINVAL);
	matrix.average_score = 101U;
	zassert_equal(pqcp_deployment_claim_matrix_emit(&matrix), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_claims, NULL, NULL, NULL, NULL, NULL);
