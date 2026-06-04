/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Demonstrates an allocation-free constrained-device deployment decision.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/deployment_advisor.h>
#include <pqcp_zephyr/deployment_campaign.h>
#include <pqcp_zephyr/deployment_robustness.h>

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
		.independent_evidence = false,
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
		.energy_uj = 0U,
		.evidence_mask = PRODUCT_EVIDENCE |
				 PQCP_DEPLOYMENT_EVIDENCE_SIMULATION,
		.independent_evidence = false,
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

static struct pqcp_deployment_candidate
	working_candidates[ARRAY_SIZE(candidates) + 1U];
static struct pqcp_deployment_candidate_result
	results[ARRAY_SIZE(working_candidates)];
static struct pqcp_deployment_candidate_robustness
	robustness[ARRAY_SIZE(working_candidates)];
static struct pqcp_deployment_gap_plan_entry
	gaps[PQCP_DEPLOYMENT_MAX_GAPS];
static struct pqcp_deployment_report report;
static struct pqcp_deployment_robustness_report robustness_report;

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

static int build_campaign_candidate(
	struct pqcp_deployment_candidate *candidate)
{
	struct pqcp_deployment_campaign_observation
		storage[ARRAY_SIZE(campaign_observations)];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_config config = {
		.campaign_id = "m7_onboarding_campaign",
		.candidate_template = campaign_template(),
		.projection = PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90,
		.min_samples = ARRAY_SIZE(campaign_observations),
		.cv_warn_bps = 1000U,
		.static_drift_warn_permille = 10U,
	};
	int ret;

	if (candidate == NULL) {
		return -EINVAL;
	}
	ret = pqcp_deployment_campaign_init(
		&state, &config, storage, ARRAY_SIZE(storage));
	if (ret != 0) {
		return ret;
	}
	for (size_t i = 0U; i < ARRAY_SIZE(campaign_observations); ++i) {
		ret = pqcp_deployment_campaign_add(
			&state, &campaign_observations[i]);
		if (ret != 0) {
			return ret;
		}
	}
	ret = pqcp_deployment_campaign_summarize(&state, &summary);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_deployment_campaign_summary_emit(&summary);
	if (ret != 0 || !summary.projected_candidate_valid) {
		return ret != 0 ? ret : -ENODATA;
	}

	*candidate = summary.projected_candidate;
	return 0;
}

int main(void)
{
	size_t gap_count = 0U;
	int ret;

	memcpy(working_candidates, candidates, sizeof(candidates));
	ret = build_campaign_candidate(&working_candidates[ARRAY_SIZE(candidates)]);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	ret = pqcp_deployment_robustness_analyze(
		&scenario, working_candidates, ARRAY_SIZE(working_candidates), results,
		robustness, &report, &robustness_report);
	if (ret != 0 || pqcp_deployment_scenario_emit(&scenario) != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	for (size_t i = 0U; i < ARRAY_SIZE(working_candidates); ++i) {
		if (pqcp_deployment_candidate_result_emit(
			    &scenario, &working_candidates[i], &results[i]) != 0) {
			printk("PROJECT EXECUTION FAILED\n");
			return 1;
		}
		if (pqcp_deployment_candidate_robustness_emit(
			    &robustness[i]) != 0) {
			printk("PROJECT EXECUTION FAILED\n");
			return 1;
		}
	}

	ret = pqcp_deployment_report_emit(&report, results);
	if (ret != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	if (pqcp_deployment_robustness_report_emit(
	    &robustness_report, robustness) != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	ret = pqcp_deployment_plan_gaps(
		&scenario, working_candidates, results, ARRAY_SIZE(working_candidates),
		gaps, ARRAY_SIZE(gaps), &gap_count);
	if (ret != 0 && ret != -ENOSPC) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	for (size_t i = 0U; i < gap_count; ++i) {
		if (pqcp_deployment_gap_plan_entry_emit(&gaps[i]) != 0) {
			printk("PROJECT EXECUTION FAILED\n");
			return 1;
		}
	}

	printk("PROJECT EXECUTION SUCCESSFUL\n");
	return 0;
}
