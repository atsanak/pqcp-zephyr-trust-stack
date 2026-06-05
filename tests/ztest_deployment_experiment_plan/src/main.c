/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deployment next-experiment planner tests.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_experiment_plan.h>

#define PRODUCT_EVIDENCE \
	(PQCP_DEPLOYMENT_EVIDENCE_KAT | \
	 PQCP_DEPLOYMENT_EVIDENCE_ACVP | \
	 PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE | \
	 PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE | \
	 PQCP_DEPLOYMENT_EVIDENCE_HARDWARE | \
	 PQCP_DEPLOYMENT_EVIDENCE_POLICY | \
	 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT | \
	 PQCP_DEPLOYMENT_EVIDENCE_RESOURCE | \
	 PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE | \
	 PQCP_DEPLOYMENT_EVIDENCE_BASELINE)

static const struct pqcp_deployment_scenario product_scenario = {
	.scenario_id = "experiment_product_m7",
	.operation = PQCP_DEPLOYMENT_OPERATION_KEM,
	.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
	.minimum_security_level = 3U,
	.latency_budget_us = 10000U,
	.ram_budget_bytes = 65536U,
	.stack_budget_bytes = 16384U,
	.heap_budget_bytes = 4096U,
	.flash_budget_bytes = 262144U,
	.preference = PQCP_DEPLOYMENT_PREFERENCE_BALANCED,
	.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT,
	.require_native_provider = true,
};

static const struct pqcp_deployment_scenario hardware_scenario = {
	.scenario_id = "experiment_hardware_m7",
	.operation = PQCP_DEPLOYMENT_OPERATION_KEM,
	.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
	.minimum_security_level = 3U,
	.latency_budget_us = 10000U,
	.ram_budget_bytes = 65536U,
	.stack_budget_bytes = 16384U,
	.heap_budget_bytes = 4096U,
	.flash_budget_bytes = 262144U,
	.preference = PQCP_DEPLOYMENT_PREFERENCE_BALANCED,
	.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE,
	.require_native_provider = true,
	.require_hardware_evidence = true,
};

static const struct pqcp_deployment_candidate product_candidates[] = {
	{
		.candidate_id = "mlkem768_m7",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
		.security_level = 5U,
		.mlkem_level = 768U,
		.latency_us = 5000U,
		.cycles = 2000000U,
		.ram_bytes = 20000U,
		.stack_bytes = 4000U,
		.heap_bytes = 1000U,
		.flash_bytes = 100000U,
		.evidence_mask = PRODUCT_EVIDENCE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
	{
		.candidate_id = "mlkem1024_m7",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
		.security_level = 5U,
		.mlkem_level = 1024U,
		.latency_us = 9000U,
		.cycles = 3600000U,
		.ram_bytes = 50000U,
		.stack_bytes = 12000U,
		.heap_bytes = 3000U,
		.flash_bytes = 230000U,
		.evidence_mask = PRODUCT_EVIDENCE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
};

static const struct pqcp_deployment_candidate no_hardware_candidate[] = {
	{
		.candidate_id = "mlkem768_no_hardware",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
		.security_level = 5U,
		.mlkem_level = 768U,
		.latency_us = 5100U,
		.cycles = 2040000U,
		.ram_bytes = 22000U,
		.stack_bytes = 4200U,
		.heap_bytes = 1100U,
		.flash_bytes = 104000U,
		.evidence_mask = PRODUCT_EVIDENCE &
				 ~PQCP_DEPLOYMENT_EVIDENCE_HARDWARE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
};

static const struct pqcp_deployment_candidate missing_measurement_candidate[] = {
	{
		.candidate_id = "mlkem768_missing_measurement",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
		.security_level = 5U,
		.mlkem_level = 768U,
		.latency_us = 5100U,
		.cycles = 2040000U,
		.ram_bytes = 22000U,
		.stack_bytes = 4200U,
		.heap_bytes = 0U,
		.flash_bytes = 104000U,
		.evidence_mask = PRODUCT_EVIDENCE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
};

static const struct pqcp_deployment_campaign_observation stable_observations[] = {
	{
		.passed = true,
		.latency_us = 6100U,
		.cycles = 2440000U,
		.ram_bytes = 30000U,
		.stack_bytes = 6200U,
		.heap_bytes = 1100U,
		.flash_bytes = 144000U,
	},
	{
		.passed = true,
		.latency_us = 6150U,
		.cycles = 2460000U,
		.ram_bytes = 30000U,
		.stack_bytes = 6200U,
		.heap_bytes = 1100U,
		.flash_bytes = 144000U,
	},
	{
		.passed = true,
		.latency_us = 6125U,
		.cycles = 2450000U,
		.ram_bytes = 30000U,
		.stack_bytes = 6200U,
		.heap_bytes = 1100U,
		.flash_bytes = 144000U,
	},
	{
		.passed = true,
		.latency_us = 6180U,
		.cycles = 2472000U,
		.ram_bytes = 30000U,
		.stack_bytes = 6200U,
		.heap_bytes = 1100U,
		.flash_bytes = 144000U,
	},
	{
		.passed = true,
		.latency_us = 6110U,
		.cycles = 2444000U,
		.ram_bytes = 30000U,
		.stack_bytes = 6200U,
		.heap_bytes = 1100U,
		.flash_bytes = 144000U,
	},
};

static struct pqcp_deployment_pipeline_workspace workspace;
static struct pqcp_deployment_pipeline_result pipeline;
static struct pqcp_deployment_budget_candidate budget_rows[
	PQCP_DEPLOYMENT_MAX_CANDIDATES];
static struct pqcp_deployment_budget_report budget_report;
static struct pqcp_deployment_experiment_row experiment_rows[
	PQCP_DEPLOYMENT_EXPERIMENT_PLAN_MAX_ROWS];
static struct pqcp_deployment_experiment_plan plan;
static char trace_buffer[12288];

static struct pqcp_deployment_candidate campaign_template(void)
{
	return (struct pqcp_deployment_candidate) {
		.candidate_id = "mlkem768_campaign",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
		.security_level = 3U,
		.mlkem_level = 768U,
		.evidence_mask = PRODUCT_EVIDENCE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	};
}

static struct pqcp_deployment_pipeline_campaign campaign(void)
{
	return (struct pqcp_deployment_pipeline_campaign) {
		.campaign_id = "experiment_campaign",
		.candidate_template = campaign_template(),
		.observations = stable_observations,
		.observation_count = ARRAY_SIZE(stable_observations),
		.projection = PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90,
		.min_samples = ARRAY_SIZE(stable_observations),
		.cv_warn_bps = 1000U,
		.static_drift_warn_permille = 10U,
	};
}

static int run_all(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	size_t candidate_count,
	const struct pqcp_deployment_pipeline_campaign *campaign_input,
	enum pqcp_deployment_appraisal_profile profile,
	uint32_t min_headroom)
{
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = scenario,
		.candidates = candidates,
		.candidate_count = candidate_count,
		.campaign = campaign_input,
		.appraisal_profile = profile,
	};
	struct pqcp_deployment_budget_policy policy;
	int ret;

	ret = pqcp_deployment_pipeline_run(
		&config, &workspace, trace_buffer, sizeof(trace_buffer),
		&pipeline);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_deployment_budget_default_policy(profile, &policy);
	if (ret != 0) {
		return ret;
	}
	policy.min_headroom_permille = min_headroom;
	ret = pqcp_deployment_budget_evaluate(
		&config, &workspace, &pipeline, &policy, budget_rows,
		ARRAY_SIZE(budget_rows), &budget_report);
	if (ret != 0) {
		return ret;
	}

	return pqcp_deployment_experiment_plan_generate(
		&config, &workspace, &pipeline, budget_rows, &budget_report,
		experiment_rows, ARRAY_SIZE(experiment_rows), &plan);
}

static bool plan_has_kind(enum pqcp_deployment_experiment_kind kind)
{
	for (size_t i = 0U; i < plan.row_count; ++i) {
		if (experiment_rows[i].kind == kind) {
			return true;
		}
	}

	return false;
}

static bool plan_has_evidence(uint32_t evidence)
{
	for (size_t i = 0U; i < plan.row_count; ++i) {
		if ((experiment_rows[i].evidence_mask & evidence) != 0U) {
			return true;
		}
	}

	return false;
}

static bool plan_has_metric(uint32_t metric)
{
	for (size_t i = 0U; i < plan.row_count; ++i) {
		if ((experiment_rows[i].metric_mask & metric) != 0U) {
			return true;
		}
	}

	return false;
}

ZTEST(pqcp_deployment_experiment_plan, test_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_experiment_kind_str(
			PQCP_DEPLOYMENT_EXPERIMENT_HARDWARE_PROMOTION),
		"hardware_promotion");
	zassert_str_equal(
		pqcp_deployment_experiment_maturity_str(
			PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PRODUCT),
		"product");
	zassert_str_equal(
		pqcp_deployment_experiment_plan_status_str(
			PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL),
		"FAIL");
}

ZTEST(pqcp_deployment_experiment_plan, test_clean_product_pipeline_has_empty_plan)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();

	zassert_equal(run_all(&product_scenario, product_candidates,
			      ARRAY_SIZE(product_candidates), &campaign_input,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT, 100U), 0);
	zassert_true(pipeline.passed);
	zassert_equal(budget_report.status, PQCP_DEPLOYMENT_BUDGET_STATUS_PASS);
	zassert_equal(plan.status, PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS);
	zassert_equal(plan.row_count, 0U);
	zassert_equal(plan.blocking_count, 0U);
	zassert_equal(pqcp_deployment_experiment_plan_emit(&plan), 0);
}

ZTEST(pqcp_deployment_experiment_plan, test_hardware_gap_generates_blocking_plan)
{
	zassert_equal(run_all(&hardware_scenario, no_hardware_candidate,
			      ARRAY_SIZE(no_hardware_candidate), NULL,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB, 0U), 0);
	zassert_equal(plan.status, PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL);
	zassert_true(plan.blocking_count > 0U);
	zassert_true(plan_has_kind(
		PQCP_DEPLOYMENT_EXPERIMENT_HARDWARE_PROMOTION));
	zassert_true(plan_has_evidence(PQCP_DEPLOYMENT_EVIDENCE_HARDWARE));
	zassert_equal(pqcp_deployment_experiment_row_emit(&experiment_rows[0]),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_experiment_plan, test_missing_measurement_generates_metric_plan)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();

	zassert_equal(run_all(&product_scenario, missing_measurement_candidate,
			      ARRAY_SIZE(missing_measurement_candidate),
			      &campaign_input,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT, 100U), 0);
	zassert_equal(plan.status, PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL);
	zassert_true(plan_has_metric(PQCP_DEPLOYMENT_METRIC_HEAP));
	zassert_true(plan_has_kind(
		PQCP_DEPLOYMENT_EXPERIMENT_STACK_HEAP_AUDIT));
}

ZTEST(pqcp_deployment_experiment_plan, test_low_margin_generates_warning_plan)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();

	zassert_equal(run_all(&product_scenario, product_candidates,
			      ARRAY_SIZE(product_candidates), &campaign_input,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT, 200U), 0);
	zassert_equal(budget_report.status, PQCP_DEPLOYMENT_BUDGET_STATUS_WARN);
	zassert_equal(plan.status, PQCP_DEPLOYMENT_EXPERIMENT_PLAN_WARN);
	zassert_equal(plan.blocking_count, 0U);
	zassert_true(plan_has_metric(PQCP_DEPLOYMENT_METRIC_FLASH));
}

ZTEST(pqcp_deployment_experiment_plan, test_pipeline_gap_rows_are_preserved)
{
	zassert_equal(run_all(&product_scenario, product_candidates,
			      ARRAY_SIZE(product_candidates), NULL,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT, 100U), 0);
	zassert_false(pipeline.passed);
	zassert_true(pipeline.gap_count > 0U ||
		     !pipeline.claims_passed);
	zassert_equal(plan.status, PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL);
	zassert_true(plan_has_kind(PQCP_DEPLOYMENT_EXPERIMENT_CLAIM_REVIEW));
}

ZTEST(pqcp_deployment_experiment_plan, test_capacity_failure)
{
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = &hardware_scenario,
		.candidates = no_hardware_candidate,
		.candidate_count = ARRAY_SIZE(no_hardware_candidate),
		.appraisal_profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB,
	};
	struct pqcp_deployment_budget_policy policy;

	zassert_equal(pqcp_deployment_pipeline_run(
			      &config, &workspace, trace_buffer,
			      sizeof(trace_buffer), &pipeline), 0);
	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB, &policy), 0);
	zassert_equal(pqcp_deployment_budget_evaluate(
			      &config, &workspace, &pipeline, &policy,
			      budget_rows, ARRAY_SIZE(budget_rows),
			      &budget_report),
		      0);
	zassert_equal(pqcp_deployment_experiment_plan_generate(
			      &config, &workspace, &pipeline, budget_rows,
			      &budget_report, experiment_rows, 1U, &plan),
		      -ENOSPC);
}

ZTEST_SUITE(pqcp_deployment_experiment_plan, NULL, NULL, NULL, NULL, NULL);
