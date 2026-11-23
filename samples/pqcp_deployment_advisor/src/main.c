/*
 * SPDX-License-Identifier: MIT
 *
 * Demonstrates an allocation-free deployment evidence pipeline.
 */

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <pqcp_zephyr/capability_descriptor.h>
#include <pqcp_zephyr/capability_extension.h>
#include <pqcp_zephyr/deployment_device_gate.h>
#include <pqcp_zephyr/deployment_evidence_trail.h>
#include <pqcp_zephyr/deployment_evidence_trail_audit.h>
#include <pqcp_zephyr/deployment_evidence_trail_replay.h>
#include <pqcp_zephyr/deployment_tamper_matrix.h>
#include <pqcp_zephyr/deployment_tamper_matrix_audit.h>
#include <pqcp_zephyr/deployment_tamper_matrix_replay.h>
#include <pqcp_zephyr/deployment_device_packet.h>
#include <pqcp_zephyr/deployment_device_packet_audit.h>
#include <pqcp_zephyr/deployment_device_packet_replay.h>
#include <pqcp_zephyr/deployment_device_token.h>
#include <pqcp_zephyr/deployment_device_token_audit.h>
#include <pqcp_zephyr/deployment_device_token_replay.h>
#include <pqcp_zephyr/deployment_evidence_verdict.h>
#include <pqcp_zephyr/deployment_evidence_verdict_audit.h>
#include <pqcp_zephyr/deployment_assurance_passport.h>
#include <pqcp_zephyr/deployment_assurance_passport_replay.h>
#include <pqcp_zephyr/deployment_evidence_seal.h>
#include <pqcp_zephyr/deployment_evidence_seal_audit.h>
#include <pqcp_zephyr/deployment_evidence_seal_replay.h>
#include <pqcp_zephyr/deployment_evidence_verdict_replay.h>
#ifdef CONFIG_PQCP_DEPLOYMENT_PASSPORT_SIGNATURE
#include <pqcp_zephyr/deployment_passport_signature.h>
#include <pqcp_zephyr/rng.h>
#endif
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
static struct pqcp_deployment_device_token_replay_result device_token_replay;
static struct pqcp_deployment_device_token_audit_policy device_token_audit_policy;
static struct pqcp_deployment_device_token_audit_report device_token_audit;
static struct pqcp_deployment_device_gate_policy device_gate_policy;
static struct pqcp_deployment_device_gate_report device_gate;
static struct pqcp_deployment_device_packet device_packet;
static struct pqcp_deployment_device_packet_replay_result device_packet_replay;
static struct pqcp_deployment_device_packet_audit_policy device_packet_audit_policy;
static struct pqcp_deployment_device_packet_audit_report device_packet_audit;
static struct pqcp_deployment_evidence_verdict_policy evidence_verdict_policy;
static struct pqcp_deployment_evidence_verdict evidence_verdict;
static struct pqcp_deployment_evidence_verdict_replay_result evidence_verdict_replay;
static struct pqcp_deployment_evidence_verdict_audit_policy evidence_verdict_audit_policy;
static struct pqcp_deployment_evidence_verdict_audit_report evidence_verdict_audit;
static struct pqcp_deployment_evidence_seal_policy evidence_seal_policy;
static struct pqcp_deployment_evidence_seal evidence_seal;
static struct pqcp_deployment_evidence_seal_replay_result evidence_seal_replay;
static struct pqcp_deployment_evidence_seal_audit_policy evidence_seal_audit_policy;
static struct pqcp_deployment_evidence_seal_audit_report evidence_seal_audit;
static struct pqcp_deployment_assurance_passport_policy assurance_passport_policy;
static struct pqcp_deployment_assurance_passport assurance_passport;
static struct pqcp_deployment_assurance_passport_replay_result assurance_passport_replay;
static struct pqcp_capability_extension capability_extension;
static struct pqcp_deployment_tamper_matrix_policy tamper_matrix_policy;
static struct pqcp_deployment_tamper_matrix_workspace tamper_matrix_workspace;
static struct pqcp_deployment_tamper_cell tamper_cells[
	PQCP_DEPLOYMENT_TAMPER_MATRIX_MAX_CELLS];
static struct pqcp_deployment_tamper_matrix_report tamper_matrix;
static struct pqcp_deployment_tamper_matrix_replay_result tamper_matrix_replay;
static struct pqcp_deployment_tamper_matrix_audit_policy tamper_matrix_audit_policy;
static struct pqcp_deployment_tamper_matrix_audit_report tamper_matrix_audit;
static struct pqcp_deployment_evidence_trail evidence_trail;
static struct pqcp_deployment_evidence_trail_entry evidence_trail_entries[
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES];
static struct pqcp_deployment_evidence_trail_policy evidence_trail_policy;
static struct pqcp_deployment_evidence_trail_replay_result evidence_trail_replay;
static struct pqcp_deployment_evidence_trail_audit_policy evidence_trail_audit_policy;
static struct pqcp_deployment_evidence_trail_audit_report evidence_trail_audit;
#ifdef CONFIG_PQCP_DEPLOYMENT_PASSPORT_SIGNATURE
static struct pqcp_deployment_passport_signing_state passport_signing_state;
static struct pqcp_deployment_passport_signature passport_signature;
#endif
static char trace_buffer[12288];
static char review_buffer[3072];
static char device_token_replay_buffer[4096];
static char device_packet_buffer[4096];

static int append_replay_line(char *buffer, size_t buffer_size,
			      size_t *offset, const char *fmt, ...)
{
	va_list args;
	int written;

	if (buffer == NULL || offset == NULL || fmt == NULL ||
	    *offset >= buffer_size) {
		return -EINVAL;
	}

	va_start(args, fmt);
	written = vsnprintk(&buffer[*offset], buffer_size - *offset, fmt,
			    args);
	va_end(args);
	if (written < 0 || (size_t)written >= buffer_size - *offset) {
		return -ENOSPC;
	}
	*offset += (size_t)written;
	return 0;
}

static int build_device_token_replay_transcript(char *buffer,
						size_t buffer_size)
{
	size_t offset = 0U;
	int ret;

	if (buffer == NULL || buffer_size == 0U) {
		return -EINVAL;
	}
	memset(buffer, 0, buffer_size);

	ret = append_replay_line(
		buffer, buffer_size, &offset,
		"PQCP_CAPABILITY_DESCRIPTOR schema=%u profile=%s status=%s production_allowed=%u provider=%s backend=%s mlkem_levels=0x%08x mldsa_levels=0x%08x rng=%s evidence=0x%08x blockers=0x%08x readiness=%u\n",
		capability_descriptor.schema_version,
		pqcp_firmware_policy_profile_str(capability_descriptor.profile),
		capability_descriptor.policy_passed ? "PASS" : "FAIL",
		capability_descriptor.production_allowed ? 1U : 0U,
		pqcp_capability_provider_summary_str(
			capability_descriptor.provider_summary),
		capability_descriptor.backend_selector,
		capability_descriptor.mlkem_level_mask,
		capability_descriptor.mldsa_level_mask,
		capability_descriptor.rng_mode,
		capability_descriptor.evidence_capabilities,
		capability_descriptor.policy_blockers,
		capability_descriptor.evidence_readiness_score);
	if (ret != 0) {
		return ret;
	}
	ret = append_replay_line(
		buffer, buffer_size, &offset,
		"PQCP_DEPLOYMENT_RELEASE_GATE schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x candidates=%u gaps=%u experiments=%u blocking=%u readiness=%u claim_score=%u review_score=%u gate_score=%u top_consistent=%u digest_bound=%u pipeline=%s budget=%s experiment_plan=%s packet=%s replay=%s audit=%s top=%s trace_digest=%s packet_digest=%s\n",
		release_gate.schema_version,
		pqcp_deployment_release_gate_profile_str(release_gate.profile),
		pqcp_deployment_release_gate_status_str(release_gate.status),
		release_gate.error_mask,
		release_gate.warning_mask,
		release_gate.candidate_count,
		release_gate.gap_count,
		release_gate.experiment_count,
		release_gate.blocking_experiment_count,
		release_gate.readiness_score,
		release_gate.claim_score,
		release_gate.review_score,
		release_gate.gate_score,
		release_gate.top_consistent ? 1U : 0U,
		release_gate.digest_bound ? 1U : 0U,
		release_gate.pipeline_passed ? "PASS" : "FAIL",
		release_gate.budget_passed ? "PASS" : "FAIL",
		release_gate.experiment_plan_passed ? "PASS" : "FAIL",
		release_gate.packet_passed ? "PASS" : "FAIL",
		release_gate.replay_passed ? "PASS" : "FAIL",
		release_gate.audit_passed ? "PASS" : "FAIL",
		release_gate.top_candidate_id,
		release_gate.trace_digest_hex,
		release_gate.packet_digest_hex);
	if (ret != 0) {
		return ret;
	}
	ret = append_replay_line(
		buffer, buffer_size, &offset,
		"PQCP_DEPLOYMENT_DEVICE_TOKEN schema=%u profile=%s status=%s nonce=%s errors=0x%08x warnings=0x%08x evidence=0x%08x cap_readiness=%u gate_score=%u gate_status=%s capability_policy=%u production_allowed=%u native_provider=%u gate_digest_bound=%u top=%s trace_digest=%s packet_digest=%s token_digest=%s\n",
		device_token.schema_version,
		pqcp_deployment_release_gate_profile_str(device_token.profile),
		pqcp_deployment_device_token_status_str(device_token.status),
		device_token.nonce_hex,
		device_token.error_mask,
		device_token.warning_mask,
		device_token.evidence_capabilities,
		device_token.capability_readiness_score,
		device_token.gate_score,
		pqcp_deployment_release_gate_status_str(
			device_token.gate_status),
		device_token.capability_policy_passed ? 1U : 0U,
		device_token.production_allowed ? 1U : 0U,
		device_token.native_provider ? 1U : 0U,
		device_token.gate_digest_bound ? 1U : 0U,
		device_token.top_candidate_id,
		device_token.trace_digest_hex,
		device_token.packet_digest_hex,
		device_token.token_digest_hex);
	if (ret != 0) {
		return ret;
	}
	return append_replay_line(
		buffer, buffer_size, &offset,
		"PQCP_DEPLOYMENT_DEVICE_TOKEN_VERIFY schema=%u status=%s errors=0x%08x expected_status=%s observed_status=%s expected_digest=%s observed_digest=%s\n",
		device_token_verify.schema_version,
		device_token_verify.passed ? "PASS" : "FAIL",
		device_token_verify.error_mask,
		pqcp_deployment_device_token_status_str(
			device_token_verify.expected_status),
		pqcp_deployment_device_token_status_str(
			device_token_verify.observed_status),
		device_token_verify.expected_digest_hex,
		device_token_verify.observed_digest_hex);
}

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
	(void)pqcp_capability_descriptor_emit(&capability_descriptor);
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
	ret = build_device_token_replay_transcript(
		device_token_replay_buffer, sizeof(device_token_replay_buffer));
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_device_token_replay_verify_transcript(
		device_token_replay_buffer, DEMO_REVIEW_NONCE,
		&device_token_replay);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_device_token_replay_emit_result(
		&device_token_replay);
	ret = pqcp_deployment_device_token_audit_default_policy(
		&device_token_audit_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_device_token_audit_run(
		&device_token_replay, 1U, &device_token_audit_policy,
		&device_token_audit);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_device_token_audit_emit(&device_token_audit);
	ret = pqcp_deployment_device_gate_default_policy(
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
		&device_gate_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_device_gate_evaluate(
		&capability_descriptor, &release_gate, &device_token,
		&device_token_verify, &device_token_replay, &device_token_audit,
		&device_gate_policy, &device_gate);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_device_gate_emit(&device_gate);
	ret = pqcp_deployment_device_packet_build(
		&capability_descriptor, &release_gate, &device_token,
		&device_token_verify, &device_token_replay, &device_token_audit,
		&device_gate, device_packet_buffer,
		sizeof(device_packet_buffer), &device_packet);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_device_packet_emit_facts(
		device_packet_buffer, &device_packet);
	(void)pqcp_deployment_device_packet_emit(&device_packet);
	ret = pqcp_deployment_device_packet_replay_verify_packet(
		device_packet_buffer, &device_packet, &device_packet_replay);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_device_packet_replay_emit_result(
		&device_packet_replay);
	ret = pqcp_deployment_device_packet_audit_default_policy(
		&device_packet_audit_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_device_packet_audit_run(
		&device_packet_replay, 1U, &device_packet_audit_policy,
		&device_packet_audit);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_device_packet_audit_emit(&device_packet_audit);
	ret = pqcp_deployment_evidence_verdict_default_policy(
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
		&evidence_verdict_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_evidence_verdict_evaluate(
		&capability_descriptor, &result, &budget_report,
		&experiment_plan, &review_packet, &review_replay,
		&review_audit, &release_gate, &device_token,
		&device_token_verify, &device_token_replay,
		&device_token_audit, &device_gate, &device_packet,
		&device_packet_replay, &device_packet_audit,
		&evidence_verdict_policy, &evidence_verdict);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_evidence_verdict_emit(&evidence_verdict);
	ret = pqcp_deployment_evidence_verdict_replay_verify(
		&evidence_verdict, &evidence_verdict_replay);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_evidence_verdict_replay_emit_result(
		&evidence_verdict_replay);
	ret = pqcp_deployment_evidence_verdict_audit_default_policy(
		&evidence_verdict_audit_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_evidence_verdict_audit_run(
		&evidence_verdict_replay, 1U, &evidence_verdict_audit_policy,
		&evidence_verdict_audit);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_evidence_verdict_audit_emit(
		&evidence_verdict_audit);
	ret = pqcp_deployment_evidence_seal_default_policy(
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
		&evidence_seal_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_evidence_seal_run(
		&evidence_verdict, &evidence_verdict_replay,
		&evidence_verdict_audit, &evidence_seal_policy,
		&evidence_seal);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_evidence_seal_emit(&evidence_seal);
	ret = pqcp_deployment_evidence_seal_replay_verify(
		&evidence_seal, &evidence_seal_replay);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_evidence_seal_replay_emit_result(
		&evidence_seal_replay);
	ret = pqcp_deployment_evidence_seal_audit_default_policy(
		&evidence_seal_audit_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_evidence_seal_audit_run(
		&evidence_seal_replay, 1U, &evidence_seal_audit_policy,
		&evidence_seal_audit);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_evidence_seal_audit_emit(&evidence_seal_audit);
	ret = pqcp_deployment_assurance_passport_default_policy(
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
		&assurance_passport_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_assurance_passport_run(
		&capability_descriptor, &evidence_seal,
		&evidence_seal_replay, &evidence_seal_audit,
		&assurance_passport_policy, &assurance_passport);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_assurance_passport_emit(&assurance_passport);
	ret = pqcp_deployment_assurance_passport_replay_verify(
		&assurance_passport, &assurance_passport_replay);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_assurance_passport_replay_emit_result(
		&assurance_passport_replay);

	ret = pqcp_capability_extension_current(&capability_extension);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_capability_extension_emit(&capability_extension);

	/* Adversarial self-validation: attack the three terminal markers
	 * in-image and require the unmodified replay verifiers to reject
	 * every forged variant while accepting the genuine controls.
	 */
	ret = pqcp_deployment_tamper_matrix_default_policy(
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
		&tamper_matrix_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_tamper_matrix_run(
		&evidence_verdict, &evidence_seal, &assurance_passport,
		&tamper_matrix_policy, &tamper_matrix_workspace,
		tamper_cells, ARRAY_SIZE(tamper_cells), &tamper_matrix);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	for (size_t i = 0U; i < tamper_matrix.cell_count; ++i) {
		(void)pqcp_deployment_tamper_cell_emit(&tamper_cells[i]);
	}
	(void)pqcp_deployment_tamper_matrix_emit(&tamper_matrix);
	ret = pqcp_deployment_tamper_matrix_replay_verify(
		&tamper_matrix, &tamper_matrix_replay);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_tamper_matrix_replay_emit_result(
		&tamper_matrix_replay);
	ret = pqcp_deployment_tamper_matrix_audit_default_policy(
		&tamper_matrix_audit_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_tamper_matrix_audit_run(
		&tamper_matrix_replay, 1U, &tamper_matrix_audit_policy,
		&tamper_matrix_audit);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_tamper_matrix_audit_emit(&tamper_matrix_audit);

	/* Hash-chained commitment over the terminal stage digests: removing,
	 * reordering, or splicing any terminal artifact breaks the head.
	 */
	ret = pqcp_deployment_evidence_trail_init(
		&evidence_trail, PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
		evidence_verdict.top_candidate_id, evidence_verdict.nonce_hex);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	if (pqcp_deployment_evidence_trail_append(
		    &evidence_trail, evidence_trail_entries,
		    ARRAY_SIZE(evidence_trail_entries),
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT,
		    evidence_verdict.verdict_digest_hex) != 0 ||
	    pqcp_deployment_evidence_trail_append(
		    &evidence_trail, evidence_trail_entries,
		    ARRAY_SIZE(evidence_trail_entries),
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL,
		    evidence_seal.seal_digest_hex) != 0 ||
	    pqcp_deployment_evidence_trail_append(
		    &evidence_trail, evidence_trail_entries,
		    ARRAY_SIZE(evidence_trail_entries),
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL_AUDIT,
		    evidence_seal_audit.audit_digest_hex) != 0 ||
	    pqcp_deployment_evidence_trail_append(
		    &evidence_trail, evidence_trail_entries,
		    ARRAY_SIZE(evidence_trail_entries),
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_PASSPORT,
		    assurance_passport.passport_digest_hex) != 0 ||
	    pqcp_deployment_evidence_trail_append(
		    &evidence_trail, evidence_trail_entries,
		    ARRAY_SIZE(evidence_trail_entries),
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_TAMPER_MATRIX,
		    tamper_matrix.matrix_digest_hex) != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_evidence_trail_default_policy(
		&evidence_trail_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_evidence_trail_finish(&evidence_trail,
						    &evidence_trail_policy);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	for (size_t i = 0U; i < evidence_trail.entry_count; ++i) {
		(void)pqcp_deployment_evidence_trail_entry_emit(
			&evidence_trail_entries[i]);
	}
	(void)pqcp_deployment_evidence_trail_emit(&evidence_trail);
	ret = pqcp_deployment_evidence_trail_replay_verify(
		&evidence_trail, evidence_trail_entries,
		evidence_trail.entry_count, &evidence_trail_replay);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_evidence_trail_replay_emit_result(
		&evidence_trail_replay);
	ret = pqcp_deployment_evidence_trail_audit_default_policy(
		&evidence_trail_audit_policy);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	ret = pqcp_deployment_evidence_trail_audit_run(
		&evidence_trail_replay, 1U, &evidence_trail_audit_policy,
		&evidence_trail_audit);
	if (ret != 0 && ret != -EBADMSG) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	(void)pqcp_deployment_evidence_trail_audit_emit(&evidence_trail_audit);

#ifdef CONFIG_PQCP_DEPLOYMENT_PASSPORT_SIGNATURE
	{
		/* Demo custody profile (docs/passport-signing-custody.md):
		 * deterministic test RNG, boot-ephemeral single-use key.
		 */
		static const uint8_t demo_seed[32] = {
			0x50, 0x51, 0x43, 0x50, 0x2d, 0x53, 0x49, 0x47,
			0x4e, 0x45, 0x44, 0x2d, 0x50, 0x41, 0x53, 0x53,
			0x50, 0x4f, 0x52, 0x54, 0x2d, 0x44, 0x45, 0x4d,
			0x4f, 0x2d, 0x53, 0x45, 0x45, 0x44, 0x30, 0x31,
		};

		ret = pqcp_rng_deterministic_seed(demo_seed,
						  sizeof(demo_seed));
		if (ret != PQCP_RNG_SUCCESS) {
			printk("PROJECT EXECUTION FAILED\n");
			return 1;
		}
		ret = pqcp_deployment_passport_signature_create(
			&assurance_passport, &passport_signing_state,
			&passport_signature);
		if (ret != 0) {
			printk("PROJECT EXECUTION FAILED\n");
			return 1;
		}
		ret = pqcp_deployment_passport_signature_verify(
			&assurance_passport, &passport_signature);
		if (ret != 0) {
			printk("PROJECT EXECUTION FAILED\n");
			return 1;
		}
		(void)pqcp_deployment_passport_signature_emit(
			&passport_signature);
	}
#endif

	printk("PROJECT EXECUTION SUCCESSFUL\n");
	return 0;
}
