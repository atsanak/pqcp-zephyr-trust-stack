/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deployment review packet tests.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_review_packet.h>

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
	.scenario_id = "review_product_m7",
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
static struct pqcp_deployment_experiment_plan experiment_plan;
static struct pqcp_deployment_review_packet packet;
static char trace_buffer[12288];
static char review_buffer[3072];

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
		.campaign_id = "review_campaign",
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
	enum pqcp_deployment_appraisal_profile profile)
{
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = scenario,
		.candidates = candidates,
		.candidate_count = candidate_count,
		.campaign = campaign_input,
		.appraisal_profile = profile,
	};
	struct pqcp_deployment_budget_policy budget_policy;
	int ret;

	ret = pqcp_deployment_pipeline_run(
		&config, &workspace, trace_buffer, sizeof(trace_buffer),
		&pipeline);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_deployment_budget_default_policy(profile, &budget_policy);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_deployment_budget_evaluate(
		&config, &workspace, &pipeline, &budget_policy, budget_rows,
		ARRAY_SIZE(budget_rows), &budget_report);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_deployment_experiment_plan_generate(
		&config, &workspace, &pipeline, budget_rows, &budget_report,
		experiment_rows, ARRAY_SIZE(experiment_rows), &experiment_plan);
	if (ret != 0) {
		return ret;
	}

	return pqcp_deployment_review_packet_build(
		&config, &pipeline, &budget_report, &experiment_plan,
		review_buffer, sizeof(review_buffer), &packet);
}

ZTEST(pqcp_deployment_review_packet, test_status_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_review_packet_status_str(
			PQCP_DEPLOYMENT_REVIEW_PACKET_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_review_packet_status_str(
			PQCP_DEPLOYMENT_REVIEW_PACKET_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_review_packet_status_str(
			PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL),
		"FAIL");
}

ZTEST(pqcp_deployment_review_packet, test_clean_packet_passes_and_emits)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();

	zassert_equal(run_all(&product_scenario, product_candidates,
			      ARRAY_SIZE(product_candidates), &campaign_input,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	zassert_equal(packet.status, PQCP_DEPLOYMENT_REVIEW_PACKET_PASS);
	zassert_equal(packet.error_mask, 0U);
	zassert_equal(packet.warning_mask, 0U);
	zassert_equal(packet.line_count, 4U);
	zassert_true(packet.byte_count > 0U);
	zassert_true(strcmp(packet.top_candidate_id, "mlkem768_m7") == 0);
	zassert_true(strcmp(packet.trace_digest_hex,
			    pipeline.trace_digest.digest_hex) == 0);
	zassert_equal(pqcp_deployment_review_packet_emit_facts(
			      review_buffer, &packet), 0);
	zassert_equal(pqcp_deployment_review_packet_emit(&packet), 0);
}

ZTEST(pqcp_deployment_review_packet, test_failure_packet_is_digest_bound)
{
	zassert_equal(run_all(&product_scenario, no_hardware_candidate,
			      ARRAY_SIZE(no_hardware_candidate), NULL,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	zassert_equal(packet.status, PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL);
	zassert_true(packet.blocking_experiment_count > 0U);
	zassert_false(packet.pipeline_passed);
	zassert_false(packet.budget_passed);
	zassert_false(packet.experiment_plan_passed);
	zassert_true(packet.packet_digest_hex[0] != '\0');
	zassert_equal(pqcp_deployment_review_packet_emit(&packet), -EBADMSG);
}

ZTEST(pqcp_deployment_review_packet, test_digest_is_stable)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();
	struct pqcp_deployment_review_packet first;
	char first_digest[PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];

	zassert_equal(run_all(&product_scenario, product_candidates,
			      ARRAY_SIZE(product_candidates), &campaign_input,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	first = packet;
	memcpy(first_digest, packet.packet_digest_hex, sizeof(first_digest));
	zassert_equal(run_all(&product_scenario, product_candidates,
			      ARRAY_SIZE(product_candidates), &campaign_input,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	zassert_true(strcmp(first_digest, packet.packet_digest_hex) == 0);
	zassert_equal(first.line_count, packet.line_count);
	zassert_equal(first.byte_count, packet.byte_count);
}

ZTEST(pqcp_deployment_review_packet, test_top_mismatch_fails)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = &product_scenario,
		.candidates = product_candidates,
		.candidate_count = ARRAY_SIZE(product_candidates),
		.campaign = &campaign_input,
		.appraisal_profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
	};

	zassert_equal(run_all(&product_scenario, product_candidates,
			      ARRAY_SIZE(product_candidates), &campaign_input,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	experiment_plan.top_candidate_id = "different_top";
	zassert_equal(pqcp_deployment_review_packet_build(
			      &config, &pipeline, &budget_report,
			      &experiment_plan, review_buffer,
			      sizeof(review_buffer), &packet),
		      -EBADMSG);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_TOP_MISMATCH) != 0U);
}

ZTEST(pqcp_deployment_review_packet, test_small_buffer_overflow_fails)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = &product_scenario,
		.candidates = product_candidates,
		.candidate_count = ARRAY_SIZE(product_candidates),
		.campaign = &campaign_input,
		.appraisal_profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
	};
	char small_buffer[64];

	zassert_equal(run_all(&product_scenario, product_candidates,
			      ARRAY_SIZE(product_candidates), &campaign_input,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	zassert_equal(pqcp_deployment_review_packet_build(
			      &config, &pipeline, &budget_report,
			      &experiment_plan, small_buffer,
			      sizeof(small_buffer), &packet),
		      -ENOSPC);
	zassert_true((packet.error_mask &
		      PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_OVERFLOW) != 0U);
}

ZTEST(pqcp_deployment_review_packet, test_fact_emit_detects_tamper)
{
	struct pqcp_deployment_pipeline_campaign campaign_input = campaign();

	zassert_equal(run_all(&product_scenario, product_candidates,
			      ARRAY_SIZE(product_candidates), &campaign_input,
			      PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT), 0);
	review_buffer[0] = '\0';
	zassert_equal(pqcp_deployment_review_packet_emit_facts(
			      review_buffer, &packet), -EBADMSG);
}

ZTEST_SUITE(pqcp_deployment_review_packet, NULL, NULL, NULL, NULL, NULL);
