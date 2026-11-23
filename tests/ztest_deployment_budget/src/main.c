/*
 * SPDX-License-Identifier: MIT
 *
 * Deployment budget verdict tests.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_budget.h>

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
	.scenario_id = "budget_product_m7",
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

static const struct pqcp_deployment_scenario impossible_scenario = {
	.scenario_id = "budget_impossible_m7",
	.operation = PQCP_DEPLOYMENT_OPERATION_KEM,
	.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
	.minimum_security_level = 5U,
	.latency_budget_us = 1000U,
	.ram_budget_bytes = 4096U,
	.stack_budget_bytes = 1024U,
	.heap_budget_bytes = 512U,
	.flash_budget_bytes = 8192U,
	.preference = PQCP_DEPLOYMENT_PREFERENCE_LOW_LATENCY,
	.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT,
	.require_native_provider = true,
	.require_hardware_evidence = true,
};

static const struct pqcp_deployment_scenario hardware_required_scenario = {
	.scenario_id = "budget_hardware_required",
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

static const struct pqcp_deployment_candidate weak_candidate[] = {
	{
		.candidate_id = "mlkem512_qemu",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_QEMU,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
		.security_level = 1U,
		.mlkem_level = 512U,
		.latency_us = 700U,
		.ram_bytes = 7000U,
		.stack_bytes = 1800U,
		.flash_bytes = 42000U,
		.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KAT |
				 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER,
		.policy_allowed = true,
		.native_provider = true,
	},
};

static const struct pqcp_deployment_candidate missing_evidence_candidate[] = {
	{
		.candidate_id = "mlkem768_missing_evidence",
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
		.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KAT |
				 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER,
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
static struct pqcp_deployment_budget_candidate rows[
	PQCP_DEPLOYMENT_MAX_CANDIDATES];
static struct pqcp_deployment_budget_report report;
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
		.campaign_id = "budget_campaign",
		.candidate_template = campaign_template(),
		.observations = stable_observations,
		.observation_count = ARRAY_SIZE(stable_observations),
		.projection = PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90,
		.min_samples = ARRAY_SIZE(stable_observations),
		.cv_warn_bps = 1000U,
		.static_drift_warn_permille = 10U,
	};
}

static int run_pipeline(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	size_t candidate_count,
	const struct pqcp_deployment_pipeline_campaign *campaign_input,
	enum pqcp_deployment_appraisal_profile profile)
{
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = scenario,
		.candidates = candidates,
		.candidate_count = candidate_count,
		.campaign = campaign_input,
		.appraisal_profile = profile,
	};

	return pqcp_deployment_pipeline_run(
		&config, &workspace, trace_buffer, sizeof(trace_buffer),
		&pipeline);
}

static int evaluate_budget(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	size_t candidate_count,
	const struct pqcp_deployment_pipeline_campaign *campaign_input,
	struct pqcp_deployment_budget_policy *policy)
{
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = scenario,
		.candidates = candidates,
		.candidate_count = candidate_count,
		.campaign = campaign_input,
		.appraisal_profile = policy->profile,
	};

	return pqcp_deployment_budget_evaluate(
		&config, &workspace, &pipeline, policy, rows, ARRAY_SIZE(rows),
		&report);
}

ZTEST(pqcp_deployment_budget, test_default_policy_profiles_are_stable)
{
	struct pqcp_deployment_budget_policy lab;
	struct pqcp_deployment_budget_policy product;
	struct pqcp_deployment_budget_policy hardware;

	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB, &lab), 0);
	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
			      &product), 0);
	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW,
			      &hardware), 0);
	zassert_false(lab.require_pipeline_pass);
	zassert_true(product.require_pipeline_pass);
	zassert_true(hardware.require_hardware_evidence);
	zassert_true(hardware.require_independent_evidence);
	zassert_true((hardware.required_evidence_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_HARDWARE) != 0U);
}

ZTEST(pqcp_deployment_budget, test_product_budget_passes)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();
	struct pqcp_deployment_budget_policy policy;

	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
			      &policy), 0);
	zassert_equal(run_pipeline(&product_scenario, product_candidates,
				   ARRAY_SIZE(product_candidates),
				   &campaign_input,
				   PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	zassert_true(pipeline.passed);
	zassert_equal(evaluate_budget(&product_scenario, product_candidates,
				      ARRAY_SIZE(product_candidates),
				      &campaign_input, &policy), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_BUDGET_STATUS_PASS,
		      "status=%s blockers=0x%08x warnings=0x%08x pass=%u warn=%u fail=%u top=%s top_status=%s",
		      pqcp_deployment_budget_status_str(report.status),
		      report.blocker_mask, report.warning_mask, report.pass_count,
		      report.warn_count, report.fail_count,
		      report.top_candidate_id,
		      pqcp_deployment_budget_status_str(report.top_status));
	zassert_equal(report.pass_count, report.candidate_count);
	zassert_equal(report.fail_count, 0U);
	zassert_true(strcmp(report.top_candidate_id, "mlkem768_m7") == 0);
	zassert_equal(report.top_status, PQCP_DEPLOYMENT_BUDGET_STATUS_PASS);
	zassert_equal(pqcp_deployment_budget_report_emit(&report), 0);
}

ZTEST(pqcp_deployment_budget, test_low_margin_warns_without_failing)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();
	struct pqcp_deployment_budget_policy policy;

	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
			      &policy), 0);
	policy.min_headroom_permille = 200U;
	zassert_equal(run_pipeline(&product_scenario, product_candidates,
				   ARRAY_SIZE(product_candidates),
				   &campaign_input,
				   PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	zassert_equal(evaluate_budget(&product_scenario, product_candidates,
				      ARRAY_SIZE(product_candidates),
				      &campaign_input, &policy), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_BUDGET_STATUS_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_BUDGET_WARNING_LOW_MARGIN) != 0U);
	zassert_equal(report.fail_count, 0U);
}

ZTEST(pqcp_deployment_budget, test_rejected_candidate_fails_budget)
{
	struct pqcp_deployment_budget_policy policy;

	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB, &policy), 0);
	zassert_equal(run_pipeline(&impossible_scenario, weak_candidate,
				   ARRAY_SIZE(weak_candidate), NULL,
				   PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB), 0);
	zassert_equal(evaluate_budget(&impossible_scenario, weak_candidate,
				      ARRAY_SIZE(weak_candidate), NULL,
				      &policy), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL);
	zassert_true((rows[0].blocker_mask &
		      PQCP_DEPLOYMENT_BUDGET_BLOCKER_ADVISOR_REJECTED) != 0U);
	zassert_equal(pqcp_deployment_budget_candidate_emit(&rows[0]),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_budget, test_missing_required_evidence_fails)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();
	struct pqcp_deployment_budget_policy policy;

	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
			      &policy), 0);
	policy.require_pipeline_pass = false;
	zassert_equal(run_pipeline(&product_scenario, missing_evidence_candidate,
				   ARRAY_SIZE(missing_evidence_candidate),
				   &campaign_input,
				   PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	zassert_equal(evaluate_budget(&product_scenario,
				      missing_evidence_candidate,
				      ARRAY_SIZE(missing_evidence_candidate),
				      &campaign_input, &policy), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL);
	zassert_true((rows[0].blocker_mask &
		      PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_EVIDENCE) != 0U);
	zassert_true(rows[0].evidence_missing_mask != 0U);
}

ZTEST(pqcp_deployment_budget, test_scenario_hardware_requirement_is_blocking)
{
	struct pqcp_deployment_budget_policy policy;

	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB, &policy), 0);
	zassert_equal(run_pipeline(&hardware_required_scenario,
				   no_hardware_candidate,
				   ARRAY_SIZE(no_hardware_candidate), NULL,
				   PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB), 0);
	zassert_equal(evaluate_budget(&hardware_required_scenario,
				      no_hardware_candidate,
				      ARRAY_SIZE(no_hardware_candidate), NULL,
				      &policy), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL);
	zassert_true((rows[0].evidence_missing_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_HARDWARE) != 0U);
	zassert_true((rows[0].blocker_mask &
		      PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_EVIDENCE) != 0U);
}

ZTEST(pqcp_deployment_budget, test_pipeline_failure_can_be_blocking)
{
	struct pqcp_deployment_budget_policy policy;

	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
			      &policy), 0);
	zassert_equal(run_pipeline(&product_scenario, product_candidates,
				   ARRAY_SIZE(product_candidates), NULL,
				   PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	zassert_false(pipeline.passed);
	zassert_equal(evaluate_budget(&product_scenario, product_candidates,
				      ARRAY_SIZE(product_candidates), NULL,
				      &policy), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL);
	zassert_true((report.blocker_mask &
		      PQCP_DEPLOYMENT_BUDGET_BLOCKER_PIPELINE_FAILED) != 0U);
}

ZTEST(pqcp_deployment_budget, test_capacity_failure_is_reported)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();
	struct pqcp_deployment_budget_policy policy;
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = &product_scenario,
		.candidates = product_candidates,
		.candidate_count = ARRAY_SIZE(product_candidates),
		.campaign = &campaign_input,
		.appraisal_profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
	};

	zassert_equal(pqcp_deployment_budget_default_policy(
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
			      &policy), 0);
	zassert_equal(pqcp_deployment_pipeline_run(
			      &config, &workspace, trace_buffer,
			      sizeof(trace_buffer), &pipeline), 0);
	zassert_equal(pqcp_deployment_budget_evaluate(
			      &config, &workspace, &pipeline, &policy, rows, 1U,
			      &report),
		      -ENOSPC);
	zassert_equal(report.status, PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL);
	zassert_true((report.blocker_mask &
		      PQCP_DEPLOYMENT_BUDGET_BLOCKER_INVALID_INPUT) != 0U);
}

ZTEST_SUITE(pqcp_deployment_budget, NULL, NULL, NULL, NULL, NULL);
