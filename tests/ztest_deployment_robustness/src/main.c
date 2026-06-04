/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deployment Pareto and sensitivity analysis tests.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_robustness.h>

static struct pqcp_deployment_scenario scenario_base(void)
{
	return (struct pqcp_deployment_scenario) {
		.scenario_id = "robustness_case",
		.operation = PQCP_DEPLOYMENT_OPERATION_KEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.minimum_security_level = 3U,
		.latency_budget_us = 10000U,
		.ram_budget_bytes = 40000U,
		.stack_budget_bytes = 10000U,
		.heap_budget_bytes = 5000U,
		.flash_budget_bytes = 200000U,
		.energy_budget_uj = 2000U,
		.preference = PQCP_DEPLOYMENT_PREFERENCE_BALANCED,
		.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT,
		.require_native_provider = true,
		.require_hardware_evidence = true,
	};
}

static struct pqcp_deployment_candidate candidate_base(void)
{
	return (struct pqcp_deployment_candidate) {
		.candidate_id = "mlkem768_robust",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
		.security_level = 3U,
		.mlkem_level = 768U,
		.latency_us = 2000U,
		.cycles = 800000U,
		.ram_bytes = 10000U,
		.stack_bytes = 2500U,
		.heap_bytes = 1000U,
		.flash_bytes = 50000U,
		.energy_uj = 500U,
		.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	};
}

static int analyze(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	size_t candidate_count,
	struct pqcp_deployment_candidate_result *evaluations,
	struct pqcp_deployment_candidate_robustness *robustness,
	struct pqcp_deployment_report *advisor_report,
	struct pqcp_deployment_robustness_report *robustness_report)
{
	return pqcp_deployment_robustness_analyze(
		scenario, candidates, candidate_count, evaluations, robustness,
		advisor_report, robustness_report);
}

ZTEST(pqcp_deployment_robustness, test_tokens_are_stable)
{
	zassert_true(strcmp(pqcp_deployment_robustness_status_str(
				    PQCP_DEPLOYMENT_ROBUSTNESS_ROBUST),
			    "ROBUST") == 0);
	zassert_true(strcmp(pqcp_deployment_robustness_status_str(
				    (enum pqcp_deployment_robustness_status)99),
			    "UNKNOWN") == 0);
	zassert_true(strcmp(pqcp_deployment_metric_str(
				    PQCP_DEPLOYMENT_METRIC_LATENCY),
			    "latency") == 0);
	zassert_true(strcmp(pqcp_deployment_metric_str(
				    PQCP_DEPLOYMENT_METRIC_ENERGY),
			    "energy") == 0);
	zassert_true(strcmp(pqcp_deployment_metric_str(0x80000000U),
			    "none") == 0);
}

ZTEST(pqcp_deployment_robustness, test_single_complete_candidate_is_robust)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidate = candidate_base();
	struct pqcp_deployment_candidate_result evaluation;
	struct pqcp_deployment_candidate_robustness robustness;
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	zassert_equal(analyze(
			      &scenario, &candidate, 1U, &evaluation, &robustness,
			      &advisor_report, &report),
		      0);
	zassert_equal(evaluation.status,
		      PQCP_DEPLOYMENT_RECOMMENDATION_ACCEPTED);
	zassert_equal(robustness.status, PQCP_DEPLOYMENT_ROBUSTNESS_ROBUST);
	zassert_true(robustness.pareto_frontier);
	zassert_true(robustness.measurements_complete);
	zassert_equal(robustness.configured_metric_mask,
		      PQCP_DEPLOYMENT_METRIC_KNOWN_MASK);
	zassert_equal(robustness.measured_metric_mask,
		      PQCP_DEPLOYMENT_METRIC_KNOWN_MASK);
	zassert_equal(robustness.missing_metric_mask, 0U);
	zassert_equal(robustness.binding_metric,
		      PQCP_DEPLOYMENT_METRIC_RAM);
	zassert_equal(robustness.minimum_headroom_permille, 750);
	zassert_equal(robustness.maximum_uniform_budget_reduction_percent, 75U);
	zassert_equal(robustness.preference_win_mask,
		      PQCP_DEPLOYMENT_PREFERENCE_WIN_KNOWN_MASK);
	zassert_equal(robustness.preference_win_count, 4U);
	zassert_equal(robustness.stress_pass_mask,
		      PQCP_DEPLOYMENT_STRESS_PASS_KNOWN_MASK);
	zassert_true(report.recommendation_stable);
	zassert_true(report.recommendation_robust);
	zassert_equal(report.pareto_frontier_count, 1U);
}

ZTEST(pqcp_deployment_robustness, test_headroom_and_binding_constraint)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidate = candidate_base();
	struct pqcp_deployment_candidate_result evaluation;
	struct pqcp_deployment_candidate_robustness robustness;
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	candidate.latency_us = 9000U;
	zassert_equal(analyze(
			      &scenario, &candidate, 1U, &evaluation, &robustness,
			      &advisor_report, &report),
		      0);
	zassert_equal(robustness.latency_headroom_permille, 100);
	zassert_equal(robustness.binding_metric,
		      PQCP_DEPLOYMENT_METRIC_LATENCY);
	zassert_equal(robustness.minimum_headroom_permille, 100);
	zassert_equal(robustness.maximum_uniform_budget_reduction_percent, 10U);
	zassert_true((robustness.stress_pass_mask &
		      PQCP_DEPLOYMENT_STRESS_PASS_5_PERCENT) != 0U);
	zassert_true((robustness.stress_pass_mask &
		      PQCP_DEPLOYMENT_STRESS_PASS_10_PERCENT) != 0U);
	zassert_false((robustness.stress_pass_mask &
		       PQCP_DEPLOYMENT_STRESS_PASS_20_PERCENT) != 0U);
	zassert_equal(robustness.status, PQCP_DEPLOYMENT_ROBUSTNESS_ADEQUATE);
}

ZTEST(pqcp_deployment_robustness, test_missing_measurement_is_fragile)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidate = candidate_base();
	struct pqcp_deployment_candidate_result evaluation;
	struct pqcp_deployment_candidate_robustness robustness;
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	candidate.energy_uj = 0U;
	zassert_equal(analyze(
			      &scenario, &candidate, 1U, &evaluation, &robustness,
			      &advisor_report, &report),
		      0);
	zassert_equal(evaluation.status,
		      PQCP_DEPLOYMENT_RECOMMENDATION_CONDITIONAL);
	zassert_equal(robustness.status, PQCP_DEPLOYMENT_ROBUSTNESS_FRAGILE);
	zassert_false(robustness.measurements_complete);
	zassert_true((robustness.missing_metric_mask &
		      PQCP_DEPLOYMENT_METRIC_ENERGY) != 0U);
	zassert_equal(robustness.energy_headroom_permille,
		      PQCP_DEPLOYMENT_HEADROOM_UNKNOWN);
	zassert_equal(robustness.stress_pass_mask, 0U);
	zassert_false(report.recommendation_robust);
}

ZTEST(pqcp_deployment_robustness, test_exceeded_budget_is_rejected)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidate = candidate_base();
	struct pqcp_deployment_candidate_result evaluation;
	struct pqcp_deployment_candidate_robustness robustness;
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	candidate.latency_us = 12000U;
	zassert_equal(analyze(
			      &scenario, &candidate, 1U, &evaluation, &robustness,
			      &advisor_report, &report),
		      0);
	zassert_equal(evaluation.status,
		      PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED);
	zassert_equal(robustness.status, PQCP_DEPLOYMENT_ROBUSTNESS_REJECTED);
	zassert_equal(robustness.latency_headroom_permille, -200);
	zassert_equal(robustness.robustness_score, 0U);
	zassert_false(robustness.pareto_frontier);
	zassert_equal(report.top_candidate_index, UINT32_MAX);
}

ZTEST(pqcp_deployment_robustness, test_dominated_candidate_is_not_frontier)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidates[] = {
		candidate_base(),
		candidate_base(),
	};
	struct pqcp_deployment_candidate_result evaluations[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_candidate_robustness robustness[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	candidates[0].candidate_id = "dominant";
	candidates[1].candidate_id = "dominated";
	candidates[1].latency_us += 1000U;
	candidates[1].ram_bytes += 1000U;
	candidates[1].stack_bytes += 100U;
	candidates[1].heap_bytes += 100U;
	candidates[1].flash_bytes += 1000U;
	candidates[1].energy_uj += 100U;

	zassert_equal(analyze(
			      &scenario, candidates, ARRAY_SIZE(candidates),
			      evaluations, robustness, &advisor_report, &report),
		      0);
	zassert_equal(robustness[0].dominates_count, 1U);
	zassert_equal(robustness[0].dominated_by_count, 0U);
	zassert_true(robustness[0].pareto_frontier);
	zassert_equal(robustness[1].dominates_count, 0U);
	zassert_equal(robustness[1].dominated_by_count, 1U);
	zassert_false(robustness[1].pareto_frontier);
	zassert_equal(report.pareto_frontier_count, 1U);
}

ZTEST(pqcp_deployment_robustness, test_tradeoff_candidates_share_frontier)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidates[] = {
		candidate_base(),
		candidate_base(),
	};
	struct pqcp_deployment_candidate_result evaluations[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_candidate_robustness robustness[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	candidates[0].candidate_id = "fast_large";
	candidates[0].latency_us = 1000U;
	candidates[0].ram_bytes = 35000U;
	candidates[0].stack_bytes = 9000U;
	candidates[0].heap_bytes = 4500U;
	candidates[0].flash_bytes = 190000U;
	candidates[0].energy_uj = 1500U;
	candidates[1].candidate_id = "slow_small";
	candidates[1].latency_us = 9000U;
	candidates[1].ram_bytes = 5000U;
	candidates[1].stack_bytes = 1000U;
	candidates[1].heap_bytes = 500U;
	candidates[1].flash_bytes = 25000U;
	candidates[1].energy_uj = 200U;

	zassert_equal(analyze(
			      &scenario, candidates, ARRAY_SIZE(candidates),
			      evaluations, robustness, &advisor_report, &report),
		      0);
	zassert_true(robustness[0].pareto_frontier);
	zassert_true(robustness[1].pareto_frontier);
	zassert_equal(report.pareto_frontier_count, 2U);
	zassert_false(report.recommendation_stable);
	zassert_true(robustness[0].preference_win_count > 0U);
	zassert_true(robustness[1].preference_win_count > 0U);
}

ZTEST(pqcp_deployment_robustness, test_unconfigured_metrics_are_not_missing)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidate = candidate_base();
	struct pqcp_deployment_candidate_result evaluation;
	struct pqcp_deployment_candidate_robustness robustness;
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	scenario.heap_budget_bytes = 0U;
	scenario.energy_budget_uj = 0U;
	candidate.heap_bytes = 0U;
	candidate.energy_uj = 0U;
	zassert_equal(analyze(
			      &scenario, &candidate, 1U, &evaluation, &robustness,
			      &advisor_report, &report),
		      0);
	zassert_false((robustness.configured_metric_mask &
		       PQCP_DEPLOYMENT_METRIC_HEAP) != 0U);
	zassert_false((robustness.configured_metric_mask &
		       PQCP_DEPLOYMENT_METRIC_ENERGY) != 0U);
	zassert_equal(robustness.missing_metric_mask, 0U);
	zassert_true(robustness.measurements_complete);
}

ZTEST(pqcp_deployment_robustness, test_large_budgets_do_not_overflow)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidate = candidate_base();
	struct pqcp_deployment_candidate_result evaluation;
	struct pqcp_deployment_candidate_robustness robustness;
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	scenario.latency_budget_us = UINT64_MAX;
	candidate.latency_us = UINT64_MAX / 2U;
	zassert_equal(analyze(
			      &scenario, &candidate, 1U, &evaluation, &robustness,
			      &advisor_report, &report),
		      0);
	zassert_true(robustness.latency_headroom_permille >= 499);
	zassert_true(robustness.latency_headroom_permille <= 501);
}

ZTEST(pqcp_deployment_robustness, test_emitters_accept_valid_results)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidate = candidate_base();
	struct pqcp_deployment_candidate_result evaluation;
	struct pqcp_deployment_candidate_robustness robustness;
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	zassert_equal(analyze(
			      &scenario, &candidate, 1U, &evaluation, &robustness,
			      &advisor_report, &report),
		      0);
	zassert_equal(pqcp_deployment_candidate_robustness_emit(&robustness), 0);
	zassert_equal(pqcp_deployment_robustness_report_emit(
			      &report, &robustness),
		      0);

	robustness.preference_win_count = 3U;
	zassert_equal(pqcp_deployment_candidate_robustness_emit(&robustness),
		      -EINVAL);
}

ZTEST(pqcp_deployment_robustness, test_no_feasible_candidate_report)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidate = candidate_base();
	struct pqcp_deployment_candidate_result evaluation;
	struct pqcp_deployment_candidate_robustness robustness;
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	candidate.security_level = 1U;
	zassert_equal(analyze(
			      &scenario, &candidate, 1U, &evaluation, &robustness,
			      &advisor_report, &report),
		      0);
	zassert_equal(report.top_candidate_index, UINT32_MAX);
	zassert_equal(report.feasible_count, 0U);
	zassert_equal(report.pareto_frontier_count, 0U);
	zassert_false(report.recommendation_stable);
	zassert_false(report.recommendation_robust);
	zassert_equal(pqcp_deployment_robustness_report_emit(
			      &report, &robustness),
		      -ENODATA);
}

ZTEST(pqcp_deployment_robustness, test_invalid_arguments_and_limits)
{
	struct pqcp_deployment_scenario scenario = scenario_base();
	struct pqcp_deployment_candidate candidates[
		PQCP_DEPLOYMENT_MAX_CANDIDATES + 1U];
	struct pqcp_deployment_candidate_result evaluations[
		PQCP_DEPLOYMENT_MAX_CANDIDATES + 1U];
	struct pqcp_deployment_candidate_robustness robustness[
		PQCP_DEPLOYMENT_MAX_CANDIDATES + 1U];
	struct pqcp_deployment_report advisor_report;
	struct pqcp_deployment_robustness_report report;

	for (size_t i = 0U; i < ARRAY_SIZE(candidates); ++i) {
		candidates[i] = candidate_base();
	}
	zassert_equal(analyze(
			      NULL, candidates, 1U, evaluations, robustness,
			      &advisor_report, &report),
		      -EINVAL);
	zassert_equal(analyze(
			      &scenario, candidates, 0U, evaluations, robustness,
			      &advisor_report, &report),
		      -EINVAL);
	zassert_equal(analyze(
			      &scenario, candidates, ARRAY_SIZE(candidates),
			      evaluations, robustness, &advisor_report, &report),
		      -E2BIG);
	zassert_equal(pqcp_deployment_candidate_robustness_emit(NULL), -EINVAL);
	zassert_equal(pqcp_deployment_robustness_report_emit(NULL, robustness),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_robustness, NULL, NULL, NULL, NULL, NULL);
