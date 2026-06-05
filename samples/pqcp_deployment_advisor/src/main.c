/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Demonstrates an allocation-free deployment evidence pipeline.
 */

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <errno.h>

#include <pqcp_zephyr/capability_descriptor.h>
#include <pqcp_zephyr/deployment_device_token.h>
#include <pqcp_zephyr/deployment_release_gate.h>
#include <pqcp_zephyr/deployment_review_audit.h>
#include <pqcp_zephyr/deployment_review_packet.h>
#include <pqcp_zephyr/deployment_review_verifier.h>

#define DEMO_REVIEW_NONCE "00112233445566778899aabbccddeeff"

#define PRODUCT_EVIDENCE \
	(PQCP_DEPLOYMENT_EVIDENCE_KAT | \
	 PQCP_DEPLOYMENT_EVIDENCE_ACVP | \
	 PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE | \
	 PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE | \
	 PQCP_DEPLOYMENT_EVIDENCE_POLICY | \
	 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT | \
	 PQCP_DEPLOYMENT_EVIDENCE_RESOURCE | \
	 PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE)

static const struct pqcp_deployment_scenario scenario = {
	.scenario_id = "m7_device_onboarding",
	.operation = PQCP_DEPLOYMENT_OPERATION_ONBOARDING,
	.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
	.minimum_security_level = 3U,
	.latency_budget_us = 10000U,
	.ram_budget_bytes = 65536U,
	.stack_budget_bytes = 16384U,
	.heap_budget_bytes = 8192U,
	.flash_budget_bytes = 262144U,
	.energy_budget_uj = 2500U,
	.preference = PQCP_DEPLOYMENT_PREFERENCE_BALANCED,
	.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT,
	.require_native_provider = true,
	.require_hardware_evidence = true,
};

static const struct pqcp_deployment_candidate candidates[] = {
	{
		.candidate_id = "mlkem512_qemu",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_QEMU,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM |
				  PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING,
		.security_level = 1U,
		.mlkem_level = 512U,
		.latency_us = 700U,
		.ram_bytes = 7000U,
		.stack_bytes = 1800U,
		.flash_bytes = 42000U,
		.evidence_mask = PRODUCT_EVIDENCE |
				 PQCP_DEPLOYMENT_EVIDENCE_SIMULATION,
		.policy_allowed = true,
		.native_provider = true,
	},
	{
		.candidate_id = "hybrid768_65_m7",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
				  PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING,
		.security_level = 3U,
		.mlkem_level = 768U,
		.mldsa_level = 65U,
		.latency_us = 7600U,
		.cycles = 3040000U,
		.ram_bytes = 43000U,
		.stack_bytes = 9200U,
		.heap_bytes = 3800U,
		.flash_bytes = 210000U,
		.energy_uj = 1800U,
		.evidence_mask = PRODUCT_EVIDENCE |
				 PQCP_DEPLOYMENT_EVIDENCE_HARDWARE |
				 PQCP_DEPLOYMENT_EVIDENCE_BASELINE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
	{
		.candidate_id = "hybrid1024_87_m7",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
				  PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING,
		.security_level = 5U,
		.mlkem_level = 1024U,
		.mldsa_level = 87U,
		.latency_us = 13000U,
		.cycles = 5200000U,
		.ram_bytes = 61000U,
		.stack_bytes = 14000U,
		.heap_bytes = 6000U,
		.flash_bytes = 300000U,
		.energy_uj = 2700U,
		.evidence_mask = PRODUCT_EVIDENCE |
				 PQCP_DEPLOYMENT_EVIDENCE_HARDWARE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
	{
		.candidate_id = "hybrid768_65_missing_hw",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
				  PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING,
		.security_level = 3U,
		.mlkem_level = 768U,
		.mldsa_level = 65U,
		.latency_us = 6800U,
		.cycles = 2720000U,
		.ram_bytes = 39000U,
		.stack_bytes = 8500U,
		.heap_bytes = 3400U,
		.flash_bytes = 205000U,
		.evidence_mask = PRODUCT_EVIDENCE |
				 PQCP_DEPLOYMENT_EVIDENCE_SIMULATION,
		.policy_allowed = true,
		.native_provider = true,
	},
};

static const struct pqcp_deployment_campaign_observation campaign_observations[] = {
	{
		.passed = true,
		.latency_us = 7200U,
		.cycles = 2880000U,
		.ram_bytes = 41000U,
		.stack_bytes = 9000U,
		.heap_bytes = 3600U,
		.flash_bytes = 207000U,
		.energy_uj = 1720U,
	},
	{
		.passed = true,
		.latency_us = 7350U,
		.cycles = 2940000U,
		.ram_bytes = 41000U,
		.stack_bytes = 9000U,
		.heap_bytes = 3600U,
		.flash_bytes = 207000U,
		.energy_uj = 1760U,
	},
	{
		.passed = true,
		.latency_us = 7300U,
		.cycles = 2920000U,
		.ram_bytes = 41000U,
		.stack_bytes = 9000U,
		.heap_bytes = 3600U,
		.flash_bytes = 207000U,
		.energy_uj = 1750U,
	},
	{
		.passed = true,
		.latency_us = 7425U,
		.cycles = 2970000U,
		.ram_bytes = 41000U,
		.stack_bytes = 9000U,
		.heap_bytes = 3600U,
		.flash_bytes = 207000U,
		.energy_uj = 1780U,
	},
	{
		.passed = true,
		.latency_us = 7280U,
		.cycles = 2912000U,
		.ram_bytes = 41000U,
		.stack_bytes = 9000U,
		.heap_bytes = 3600U,
		.flash_bytes = 207000U,
		.energy_uj = 1745U,
	},
};

static struct pqcp_deployment_pipeline_workspace workspace;
static struct pqcp_deployment_pipeline_result result;
static struct pqcp_deployment_budget_candidate budget_rows[
	PQCP_DEPLOYMENT_MAX_CANDIDATES];
static struct pqcp_deployment_budget_report budget_report;
static struct pqcp_deployment_experiment_row experiment_rows[
	PQCP_DEPLOYMENT_EXPERIMENT_PLAN_MAX_ROWS];
static struct pqcp_deployment_experiment_plan experiment_plan;
static struct pqcp_deployment_review_packet review_packet;
static struct pqcp_deployment_review_verifier_result review_replay;
static struct pqcp_deployment_review_audit_policy review_audit_policy;
static struct pqcp_deployment_review_audit_report review_audit;
static struct pqcp_deployment_release_gate_policy release_gate_policy;
static struct pqcp_deployment_release_gate_report release_gate;
static struct pqcp_capability_descriptor capability_descriptor;
static struct pqcp_deployment_device_token_policy device_token_policy;
static struct pqcp_deployment_device_token device_token;
static struct pqcp_deployment_device_token_verification device_token_verify;
static char trace_buffer[12288];
static char review_buffer[3072];

static struct pqcp_deployment_candidate campaign_template(void)
{
	return (struct pqcp_deployment_candidate) {
		.candidate_id = "hybrid768_65_campaign",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
				  PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING,
		.security_level = 3U,
		.mlkem_level = 768U,
		.mldsa_level = 65U,
		.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KAT |
				 PQCP_DEPLOYMENT_EVIDENCE_ACVP |
				 PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
				 PQCP_DEPLOYMENT_EVIDENCE_POLICY |
				 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
				 PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
				 PQCP_DEPLOYMENT_EVIDENCE_HARDWARE |
				 PQCP_DEPLOYMENT_EVIDENCE_BASELINE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	};
}

int main(void)
{
	struct pqcp_deployment_budget_policy budget_policy;
	const struct pqcp_deployment_pipeline_campaign campaign = {
		.campaign_id = "m7_onboarding_campaign",
		.candidate_template = campaign_template(),
		.observations = campaign_observations,
		.observation_count = ARRAY_SIZE(campaign_observations),
		.projection = PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90,
		.min_samples = ARRAY_SIZE(campaign_observations),
		.cv_warn_bps = 1000U,
		.static_drift_warn_permille = 10U,
	};
	const struct pqcp_deployment_pipeline_config config = {
		.scenario = &scenario,
		.candidates = candidates,
		.candidate_count = ARRAY_SIZE(candidates),
		.campaign = &campaign,
		.appraisal_profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
		.emit_markers = true,
	};
	int ret = pqcp_deployment_pipeline_run(
		&config, &workspace, trace_buffer, sizeof(trace_buffer), &result);

	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_budget_default_policy(
		config.appraisal_profile, &budget_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_budget_evaluate(
		&config, &workspace, &result, &budget_policy, budget_rows,
		ARRAY_SIZE(budget_rows), &budget_report);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	for (size_t i = 0U; i < budget_report.candidate_count; ++i) {
		(void)pqcp_deployment_budget_candidate_emit(&budget_rows[i]);
	}
	(void)pqcp_deployment_budget_report_emit(&budget_report);
	ret = pqcp_deployment_experiment_plan_generate(
		&config, &workspace, &result, budget_rows, &budget_report,
		experiment_rows, ARRAY_SIZE(experiment_rows), &experiment_plan);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	for (size_t i = 0U; i < experiment_plan.row_count; ++i) {
		(void)pqcp_deployment_experiment_row_emit(&experiment_rows[i]);
	}
	(void)pqcp_deployment_experiment_plan_emit(&experiment_plan);
	ret = pqcp_deployment_review_packet_build(
		&config, &result, &budget_report, &experiment_plan,
		review_buffer, sizeof(review_buffer), &review_packet);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_review_packet_emit_facts(
		review_buffer, &review_packet);
	(void)pqcp_deployment_review_packet_emit(&review_packet);
	ret = pqcp_deployment_review_verifier_verify_packet(
		review_buffer, &review_packet, &review_replay);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_review_verifier_emit_result(&review_replay);
	ret = pqcp_deployment_review_audit_default_policy(
		&review_audit_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_review_audit_run(
		&review_replay, 1U, &review_audit_policy, &review_audit);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_review_audit_emit(&review_audit);
	ret = pqcp_deployment_release_gate_default_policy(
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
		&release_gate_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_release_gate_evaluate(
		&result, &budget_report, &experiment_plan, &review_packet,
		&review_replay, &review_audit, &release_gate_policy,
		&release_gate);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_release_gate_emit(&release_gate);
	ret = pqcp_capability_descriptor_current(&capability_descriptor);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_device_token_default_policy(
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
		&device_token_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_device_token_build(
		&capability_descriptor, &release_gate, DEMO_REVIEW_NONCE,
		&device_token_policy, &device_token);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_device_token_emit(&device_token);
	ret = pqcp_deployment_device_token_verify(
		&device_token, &capability_descriptor, &release_gate,
		DEMO_REVIEW_NONCE, &device_token_policy, &device_token_verify);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_device_token_verification_emit(
		&device_token_verify);

	printk("PROJECT EXECUTION SUCCESSFUL\n");
	return 0;
}
