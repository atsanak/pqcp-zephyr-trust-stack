/*
 * SPDX-License-Identifier: MIT
 *
 * Deployment evidence pipeline tests.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_pipeline.h>

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
	 PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE)

static const struct pqcp_deployment_scenario product_scenario = {
	.scenario_id = "product_kem_m7",
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
	.scenario_id = "impossible_kem_m7",
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

static const struct pqcp_deployment_scenario lab_scenario = {
	.scenario_id = "lab_kem_m7",
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
		.evidence_mask = PRODUCT_EVIDENCE |
				 PQCP_DEPLOYMENT_EVIDENCE_BASELINE,
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
		.evidence_mask = PRODUCT_EVIDENCE |
				 PQCP_DEPLOYMENT_EVIDENCE_BASELINE,
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
				 PQCP_DEPLOYMENT_EVIDENCE_POLICY |
				 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER,
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

static const struct pqcp_deployment_campaign_observation sparse_observations[] = {
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
		.latency_us = 9000U,
		.cycles = 3600000U,
		.ram_bytes = 30000U,
		.stack_bytes = 6200U,
		.heap_bytes = 1100U,
		.flash_bytes = 144000U,
	},
};

static struct pqcp_deployment_pipeline_workspace workspace;
static struct pqcp_deployment_pipeline_result result;
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
		.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KAT |
				 PQCP_DEPLOYMENT_EVIDENCE_ACVP |
				 PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
				 PQCP_DEPLOYMENT_EVIDENCE_HARDWARE |
				 PQCP_DEPLOYMENT_EVIDENCE_POLICY |
				 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
				 PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
				 PQCP_DEPLOYMENT_EVIDENCE_BASELINE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	};
}

static struct pqcp_deployment_pipeline_campaign campaign_with(
	const struct pqcp_deployment_campaign_observation *observations,
	size_t observation_count,
	uint32_t min_samples)
{
	return (struct pqcp_deployment_pipeline_campaign) {
		.campaign_id = "m7_campaign",
		.candidate_template = campaign_template(),
		.observations = observations,
		.observation_count = observation_count,
		.projection = PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90,
		.min_samples = min_samples,
		.cv_warn_bps = 1000U,
		.static_drift_warn_permille = 10U,
	};
}

static int run_config(const struct pqcp_deployment_scenario *scenario,
		      const struct pqcp_deployment_candidate *candidates,
		      size_t candidate_count,
		      const struct pqcp_deployment_pipeline_campaign *campaign,
		      enum pqcp_deployment_appraisal_profile profile,
		      size_t buffer_size)
{
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = scenario,
		.candidates = candidates,
		.candidate_count = candidate_count,
		.campaign = campaign,
		.appraisal_profile = profile,
	};

	return pqcp_deployment_pipeline_run(
		&config, &workspace, trace_buffer, buffer_size, &result);
}

ZTEST(pqcp_deployment_pipeline, test_full_pipeline_passes)
{
	struct pqcp_deployment_pipeline_campaign campaign =
		campaign_with(stable_observations,
			      ARRAY_SIZE(stable_observations), 5U);

	zassert_equal(run_config(&product_scenario, product_candidates,
				 ARRAY_SIZE(product_candidates), &campaign,
				 PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
				 sizeof(trace_buffer)), 0);
	zassert_true(result.passed,
		     "errors=0x%08x replay=%u appraisal=%u claims=%u gaps=%u "
		     "quality=0x%08x top=%s readiness=%u claim_score=%u",
		     result.error_mask, result.replay_passed ? 1U : 0U,
		     result.appraisal_passed ? 1U : 0U,
		     result.claims_passed ? 1U : 0U, result.gap_count,
		     result.campaign_summary.quality_mask,
		     result.top_candidate_id, result.appraisal.readiness_score,
		     result.claim_matrix.average_score);
	zassert_true(result.replay_passed);
	zassert_true(result.appraisal_passed);
	zassert_true(result.claims_passed);
	zassert_equal(result.gap_count, 0U);
	zassert_equal(result.candidate_count, 3U);
	zassert_true(strcmp(result.top_candidate_id, "mlkem768_m7") == 0);
	zassert_equal(pqcp_deployment_pipeline_result_emit(&result), 0);
}

ZTEST(pqcp_deployment_pipeline, test_no_accepted_candidate_records_failure)
{
	zassert_equal(run_config(&impossible_scenario, weak_candidate,
				 ARRAY_SIZE(weak_candidate), NULL,
				 PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB,
				 sizeof(trace_buffer)), 0);
	zassert_false(result.passed);
	zassert_false(result.recommendation_ready);
	zassert_false(result.replay_passed);
	zassert_true((result.error_mask &
		      PQCP_DEPLOYMENT_PIPELINE_ERROR_TRACE) != 0U);
	zassert_true((result.error_mask &
		      PQCP_DEPLOYMENT_PIPELINE_ERROR_CLAIMS) != 0U);
}

ZTEST(pqcp_deployment_pipeline, test_campaign_quality_warning_is_blocking)
{
	struct pqcp_deployment_pipeline_campaign campaign =
		campaign_with(sparse_observations,
			      ARRAY_SIZE(sparse_observations), 2U);

	zassert_equal(run_config(&product_scenario, product_candidates,
				 ARRAY_SIZE(product_candidates), &campaign,
				 PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
				 sizeof(trace_buffer)), 0);
	zassert_false(result.passed);
	zassert_false(result.replay_passed);
	zassert_not_equal(result.campaign_summary.quality_mask, 0U);
	zassert_true((result.error_mask &
		      PQCP_DEPLOYMENT_PIPELINE_ERROR_TRACE) != 0U);
}

ZTEST(pqcp_deployment_pipeline, test_appraisal_failure_path)
{
	zassert_equal(run_config(&product_scenario, product_candidates,
				 ARRAY_SIZE(product_candidates), NULL,
				 PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
				 sizeof(trace_buffer)), 0);
	zassert_false(result.passed);
	zassert_true(result.replay_passed);
	zassert_false(result.appraisal_passed);
	zassert_true((result.appraisal.blocker_mask &
		      PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_REQUIRED) != 0U);
}

ZTEST(pqcp_deployment_pipeline, test_claim_matrix_failure_path)
{
	zassert_equal(run_config(&lab_scenario, product_candidates,
				 ARRAY_SIZE(product_candidates), NULL,
				 PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB,
				 sizeof(trace_buffer)), 0);
	zassert_false(result.passed);
	zassert_true(result.replay_passed);
	zassert_true(result.appraisal_passed);
	zassert_false(result.claims_passed);
	zassert_true((result.error_mask &
		      PQCP_DEPLOYMENT_PIPELINE_ERROR_CLAIMS) != 0U);
}

ZTEST(pqcp_deployment_pipeline, test_buffer_too_small_path)
{
	struct pqcp_deployment_pipeline_campaign campaign =
		campaign_with(stable_observations,
			      ARRAY_SIZE(stable_observations), 5U);

	zassert_equal(run_config(&product_scenario, product_candidates,
				 ARRAY_SIZE(product_candidates), &campaign,
				 PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
				 128U), -ENOSPC);
	zassert_false(result.passed);
	zassert_true((result.error_mask &
		      PQCP_DEPLOYMENT_PIPELINE_ERROR_TRACE) != 0U);
}

ZTEST_SUITE(pqcp_deployment_pipeline, NULL, NULL, NULL, NULL, NULL);
