/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware-native deployment next-experiment planner.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_experiment_plan.h>

struct metric_plan {
	uint32_t metric;
	enum pqcp_deployment_experiment_kind kind;
	const char *artifact;
	const char *claim;
};

struct evidence_plan {
	uint32_t evidence;
	enum pqcp_deployment_experiment_kind kind;
	const char *artifact;
	const char *claim;
	uint32_t reason;
};

struct gap_plan {
	uint32_t gap;
	enum pqcp_deployment_experiment_kind kind;
	const char *artifact;
	const char *claim;
};

static const struct metric_plan metric_plans[] = {
	{
		.metric = PQCP_DEPLOYMENT_METRIC_LATENCY,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_LATENCY_BENCHMARK,
		.artifact = "benchmark_latency_transcript",
		.claim = "claim.performance_latency_budget",
	},
	{
		.metric = PQCP_DEPLOYMENT_METRIC_RAM,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_RESOURCE_MEASUREMENT,
		.artifact = "resource_ram_report",
		.claim = "claim.resource_ram_budget",
	},
	{
		.metric = PQCP_DEPLOYMENT_METRIC_STACK,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_STACK_HEAP_AUDIT,
		.artifact = "resource_stack_report",
		.claim = "claim.resource_stack_budget",
	},
	{
		.metric = PQCP_DEPLOYMENT_METRIC_HEAP,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_STACK_HEAP_AUDIT,
		.artifact = "resource_heap_report",
		.claim = "claim.resource_heap_budget",
	},
	{
		.metric = PQCP_DEPLOYMENT_METRIC_FLASH,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_RESOURCE_MEASUREMENT,
		.artifact = "resource_flash_report",
		.claim = "claim.resource_flash_budget",
	},
	{
		.metric = PQCP_DEPLOYMENT_METRIC_ENERGY,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_ENERGY_MEASUREMENT,
		.artifact = "hardware_energy_report",
		.claim = "claim.performance_energy_budget",
	},
};

static const struct evidence_plan evidence_plans[] = {
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_KAT,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_KAT_ACVP_VALIDATION,
		.artifact = "kat_transcript",
		.claim = "claim.correctness_known_answer",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_ACVP,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_KAT_ACVP_VALIDATION,
		.artifact = "acvp_transcript",
		.claim = "claim.interface_acvp_behavior",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_CT_SMOKE_REPLAY,
		.artifact = "ct_smoke_transcript",
		.claim = "claim.security_timing_regression",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_REPRODUCIBILITY_RUN,
		.artifact = "reproducibility_report",
		.claim = "claim.measurement_reproducibility",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_BASELINE,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_BASELINE_COMPARISON,
		.artifact = "baseline_comparison_report",
		.claim = "claim.performance_comparison",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_BASELINE_REQUIRED,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_HARDWARE,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_HARDWARE_PROMOTION,
		.artifact = "hardware_benchmark_transcript",
		.claim = "claim.deployment_physical_target",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_HARDWARE_REQUIRED,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_SIMULATION,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_REPRODUCIBILITY_RUN,
		.artifact = "qemu_benchmark_transcript",
		.claim = "claim.deployment_simulation_regression",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_POLICY,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_POLICY_PROVIDER_REPLAY,
		.artifact = "firmware_policy_marker",
		.claim = "claim.policy_profile_acceptance",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_PROVIDER,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_POLICY_PROVIDER_REPLAY,
		.artifact = "provider_contract_marker",
		.claim = "claim.provider_native_binding",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_TRANSCRIPT_REPLAY,
		.artifact = "evidence_transcript_manifest",
		.claim = "claim.evidence_hash_binding",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_RESOURCE,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_RESOURCE_MEASUREMENT,
		.artifact = "resource_budget_report",
		.claim = "claim.resource_budget_binding",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
	{
		.evidence = PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_LATENCY_BENCHMARK,
		.artifact = "benchmark_campaign_result",
		.claim = "claim.performance_measurement_binding",
		.reason = PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE,
	},
};

static const struct gap_plan gap_plans[] = {
	{
		.gap = PQCP_DEPLOYMENT_GAP_LATENCY,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_LATENCY_BENCHMARK,
		.artifact = "benchmark_latency_transcript",
		.claim = "claim.performance_latency_budget",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_RAM,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_RESOURCE_MEASUREMENT,
		.artifact = "resource_ram_report",
		.claim = "claim.resource_ram_budget",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_STACK,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_STACK_HEAP_AUDIT,
		.artifact = "resource_stack_report",
		.claim = "claim.resource_stack_budget",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_HEAP,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_STACK_HEAP_AUDIT,
		.artifact = "resource_heap_report",
		.claim = "claim.resource_heap_budget",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_FLASH,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_RESOURCE_MEASUREMENT,
		.artifact = "resource_flash_report",
		.claim = "claim.resource_flash_budget",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_ENERGY,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_ENERGY_MEASUREMENT,
		.artifact = "hardware_energy_report",
		.claim = "claim.performance_energy_budget",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_KAT,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_KAT_ACVP_VALIDATION,
		.artifact = "kat_transcript",
		.claim = "claim.correctness_known_answer",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_ACVP,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_KAT_ACVP_VALIDATION,
		.artifact = "acvp_transcript",
		.claim = "claim.interface_acvp_behavior",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_CT_SMOKE,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_CT_SMOKE_REPLAY,
		.artifact = "ct_smoke_transcript",
		.claim = "claim.security_timing_regression",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_REPRODUCIBILITY,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_REPRODUCIBILITY_RUN,
		.artifact = "reproducibility_report",
		.claim = "claim.measurement_reproducibility",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_BASELINE,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_BASELINE_COMPARISON,
		.artifact = "baseline_comparison_report",
		.claim = "claim.performance_comparison",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_HARDWARE,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_HARDWARE_PROMOTION,
		.artifact = "hardware_benchmark_transcript",
		.claim = "claim.deployment_physical_target",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_SIMULATION,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_REPRODUCIBILITY_RUN,
		.artifact = "qemu_benchmark_transcript",
		.claim = "claim.deployment_simulation_regression",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_POLICY,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_POLICY_PROVIDER_REPLAY,
		.artifact = "firmware_policy_marker",
		.claim = "claim.policy_profile_acceptance",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_PROVIDER,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_POLICY_PROVIDER_REPLAY,
		.artifact = "provider_contract_marker",
		.claim = "claim.provider_native_binding",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_TRANSCRIPT,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_TRANSCRIPT_REPLAY,
		.artifact = "evidence_transcript_manifest",
		.claim = "claim.evidence_hash_binding",
	},
	{
		.gap = PQCP_DEPLOYMENT_GAP_INDEPENDENT,
		.kind = PQCP_DEPLOYMENT_EXPERIMENT_BASELINE_COMPARISON,
		.artifact = "independent_framework_comparison",
		.claim = "claim.evidence_independent_baseline",
	},
};

static bool kind_valid(enum pqcp_deployment_experiment_kind kind)
{
	return kind >= PQCP_DEPLOYMENT_EXPERIMENT_LATENCY_BENCHMARK &&
	       kind <= PQCP_DEPLOYMENT_EXPERIMENT_CLAIM_REVIEW;
}

static bool maturity_valid(enum pqcp_deployment_experiment_maturity maturity)
{
	return maturity >= PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PROTOTYPE &&
	       maturity <= PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PARTNER;
}

static bool status_valid(enum pqcp_deployment_experiment_plan_status status)
{
	return status >= PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS &&
	       status <= PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL;
}

const char *pqcp_deployment_experiment_kind_str(
	enum pqcp_deployment_experiment_kind kind)
{
	switch (kind) {
	case PQCP_DEPLOYMENT_EXPERIMENT_LATENCY_BENCHMARK:
		return "latency_benchmark";
	case PQCP_DEPLOYMENT_EXPERIMENT_RESOURCE_MEASUREMENT:
		return "resource_measurement";
	case PQCP_DEPLOYMENT_EXPERIMENT_STACK_HEAP_AUDIT:
		return "stack_heap_audit";
	case PQCP_DEPLOYMENT_EXPERIMENT_ENERGY_MEASUREMENT:
		return "energy_measurement";
	case PQCP_DEPLOYMENT_EXPERIMENT_HARDWARE_PROMOTION:
		return "hardware_promotion";
	case PQCP_DEPLOYMENT_EXPERIMENT_KAT_ACVP_VALIDATION:
		return "kat_acvp_validation";
	case PQCP_DEPLOYMENT_EXPERIMENT_CT_SMOKE_REPLAY:
		return "ct_smoke_replay";
	case PQCP_DEPLOYMENT_EXPERIMENT_REPRODUCIBILITY_RUN:
		return "reproducibility_run";
	case PQCP_DEPLOYMENT_EXPERIMENT_BASELINE_COMPARISON:
		return "baseline_comparison";
	case PQCP_DEPLOYMENT_EXPERIMENT_POLICY_PROVIDER_REPLAY:
		return "policy_provider_replay";
	case PQCP_DEPLOYMENT_EXPERIMENT_TRANSCRIPT_REPLAY:
		return "transcript_replay";
	case PQCP_DEPLOYMENT_EXPERIMENT_CLAIM_REVIEW:
		return "claim_review";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_experiment_maturity_str(
	enum pqcp_deployment_experiment_maturity maturity)
{
	switch (maturity) {
	case PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PROTOTYPE:
		return "prototype";
	case PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PAPER:
		return "paper";
	case PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PRODUCT:
		return "product";
	case PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PARTNER:
		return "partner";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_experiment_plan_status_str(
	enum pqcp_deployment_experiment_plan_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EXPERIMENT_PLAN_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

static enum pqcp_deployment_experiment_maturity maturity_from_profile(
	enum pqcp_deployment_appraisal_profile profile)
{
	switch (profile) {
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB:
		return PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PROTOTYPE;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PAPER:
		return PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PAPER;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT:
		return PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PRODUCT;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW:
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW:
	default:
		return PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PARTNER;
	}
}

static enum pqcp_deployment_experiment_maturity maturity_from_gap(
	enum pqcp_deployment_evidence_level level)
{
	switch (level) {
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE:
		return PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PROTOTYPE;
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PAPER:
		return PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PAPER;
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PRODUCT:
		return PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PRODUCT;
	case PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PARTNER_DEMO:
	default:
		return PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PARTNER;
	}
}

static uint64_t acceptance_for_metric(
	const struct pqcp_deployment_scenario *scenario,
	uint32_t metric)
{
	switch (metric) {
	case PQCP_DEPLOYMENT_METRIC_LATENCY:
		return scenario->latency_budget_us;
	case PQCP_DEPLOYMENT_METRIC_RAM:
		return scenario->ram_budget_bytes;
	case PQCP_DEPLOYMENT_METRIC_STACK:
		return scenario->stack_budget_bytes;
	case PQCP_DEPLOYMENT_METRIC_HEAP:
		return scenario->heap_budget_bytes;
	case PQCP_DEPLOYMENT_METRIC_FLASH:
		return scenario->flash_budget_bytes;
	case PQCP_DEPLOYMENT_METRIC_ENERGY:
		return scenario->energy_budget_uj;
	default:
		return 0U;
	}
}

static const struct metric_plan *find_metric_plan(uint32_t metric)
{
	for (size_t i = 0U; i < sizeof(metric_plans) / sizeof(metric_plans[0]);
	     ++i) {
		if (metric_plans[i].metric == metric) {
			return &metric_plans[i];
		}
	}

	return NULL;
}

static const struct gap_plan *find_gap_plan(uint32_t gap)
{
	for (size_t i = 0U; i < sizeof(gap_plans) / sizeof(gap_plans[0]); ++i) {
		if (gap_plans[i].gap == gap) {
			return &gap_plans[i];
		}
	}

	return NULL;
}

static bool same_experiment(
	const struct pqcp_deployment_experiment_row *row,
	uint32_t candidate_index,
	const char *candidate_id,
	enum pqcp_deployment_experiment_kind kind,
	uint32_t metric,
	uint32_t evidence,
	uint32_t gap)
{
	return row->candidate_index == candidate_index &&
	       row->candidate_id != NULL &&
	       candidate_id != NULL &&
	       strcmp(row->candidate_id, candidate_id) == 0 &&
	       row->kind == kind &&
	       row->metric_mask == metric &&
	       row->evidence_mask == evidence &&
	       row->gap_mask == gap;
}

static int append_row(
	struct pqcp_deployment_experiment_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_experiment_plan *plan,
	const struct pqcp_deployment_experiment_row *candidate)
{
	if (candidate == NULL || candidate->candidate_id == NULL ||
	    !kind_valid(candidate->kind) ||
	    !maturity_valid(candidate->maturity) ||
	    candidate->expected_artifact == NULL ||
	    candidate->claim_token == NULL ||
	    (candidate->reason_mask &
	     ~PQCP_DEPLOYMENT_EXPERIMENT_REASON_KNOWN_MASK) != 0U ||
	    (candidate->metric_mask & ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) != 0U ||
	    (candidate->evidence_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK) != 0U ||
	    (candidate->gap_mask & ~PQCP_DEPLOYMENT_GAP_KNOWN_MASK) != 0U ||
	    (candidate->budget_blocker_mask &
	     ~PQCP_DEPLOYMENT_BUDGET_BLOCKER_KNOWN_MASK) != 0U ||
	    (candidate->budget_warning_mask &
	     ~PQCP_DEPLOYMENT_BUDGET_WARNING_KNOWN_MASK) != 0U) {
		return -EINVAL;
	}

	for (size_t i = 0U; i < plan->row_count; ++i) {
		if (same_experiment(&rows[i], candidate->candidate_index,
				    candidate->candidate_id, candidate->kind,
				    candidate->metric_mask,
				    candidate->evidence_mask,
				    candidate->gap_mask)) {
			rows[i].reason_mask |= candidate->reason_mask;
			rows[i].budget_blocker_mask |=
				candidate->budget_blocker_mask;
			rows[i].budget_warning_mask |=
				candidate->budget_warning_mask;
			if (!rows[i].blocking && candidate->blocking) {
				rows[i].blocking = true;
				plan->blocking_count++;
				if (plan->recommended_count != 0U) {
					plan->recommended_count--;
				}
			}
			return 0;
		}
	}

	if (plan->row_count >= row_capacity ||
	    plan->row_count >= PQCP_DEPLOYMENT_EXPERIMENT_PLAN_MAX_ROWS) {
		return -ENOSPC;
	}

	rows[plan->row_count] = *candidate;
	rows[plan->row_count].schema_version =
		PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION;
	rows[plan->row_count].priority = plan->row_count + 1U;
	if (candidate->blocking) {
		plan->blocking_count++;
	} else {
		plan->recommended_count++;
	}
	plan->row_count++;
	plan->highest_priority = plan->row_count == 0U ? 0U : 1U;

	return 0;
}

static int append_metric_rows(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_budget_candidate *budget,
	struct pqcp_deployment_experiment_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_experiment_plan *plan)
{
	static const uint32_t metrics[] = {
		PQCP_DEPLOYMENT_METRIC_LATENCY,
		PQCP_DEPLOYMENT_METRIC_RAM,
		PQCP_DEPLOYMENT_METRIC_STACK,
		PQCP_DEPLOYMENT_METRIC_HEAP,
		PQCP_DEPLOYMENT_METRIC_FLASH,
		PQCP_DEPLOYMENT_METRIC_ENERGY,
	};

	for (size_t i = 0U; i < sizeof(metrics) / sizeof(metrics[0]); ++i) {
		const struct metric_plan *meta;
		struct pqcp_deployment_experiment_row row;
		uint32_t metric = metrics[i];
		bool fail = (budget->metric_fail_mask & metric) != 0U;
		bool missing = (budget->metric_missing_mask & metric) != 0U;
		bool warn = (budget->metric_warn_mask & metric) != 0U;

		if (!fail && !missing && !warn) {
			continue;
		}
		meta = find_metric_plan(metric);
		if (meta == NULL) {
			return -EINVAL;
		}

		memset(&row, 0, sizeof(row));
		row.candidate_index = budget->candidate_index;
		row.candidate_id = budget->candidate_id;
		row.kind = meta->kind;
		row.maturity = PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PRODUCT;
		row.metric_mask = metric;
		row.budget_blocker_mask = budget->blocker_mask;
		row.budget_warning_mask = budget->warning_mask;
		row.expected_artifact = meta->artifact;
		row.claim_token = meta->claim;
		row.acceptance_max = acceptance_for_metric(scenario, metric);
		row.blocking = fail || missing;
		if (fail) {
			row.reason_mask |=
				PQCP_DEPLOYMENT_EXPERIMENT_REASON_BLOCKER;
		}
		if (missing) {
			row.reason_mask |=
				PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_MEASUREMENT;
		}
		if (warn) {
			row.reason_mask |=
				PQCP_DEPLOYMENT_EXPERIMENT_REASON_LOW_MARGIN;
		}

		int ret = append_row(rows, row_capacity, plan, &row);

		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

static int append_evidence_rows(
	const struct pqcp_deployment_budget_candidate *budget,
	struct pqcp_deployment_experiment_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_experiment_plan *plan)
{
	for (size_t i = 0U;
	     i < sizeof(evidence_plans) / sizeof(evidence_plans[0]); ++i) {
		const struct evidence_plan *meta = &evidence_plans[i];
		struct pqcp_deployment_experiment_row row;

		if ((budget->evidence_missing_mask & meta->evidence) == 0U) {
			continue;
		}

		memset(&row, 0, sizeof(row));
		row.candidate_index = budget->candidate_index;
		row.candidate_id = budget->candidate_id;
		row.kind = meta->kind;
		row.maturity = PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PRODUCT;
		row.reason_mask = meta->reason;
		row.evidence_mask = meta->evidence;
		row.budget_blocker_mask = budget->blocker_mask;
		row.budget_warning_mask = budget->warning_mask;
		row.expected_artifact = meta->artifact;
		row.claim_token = meta->claim;
		row.blocking =
			(budget->blocker_mask &
			 PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_EVIDENCE) != 0U;

		int ret = append_row(rows, row_capacity, plan, &row);

		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

static int append_advisor_blocker_row(
	const struct pqcp_deployment_budget_candidate *budget,
	struct pqcp_deployment_experiment_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_experiment_plan *plan)
{
	struct pqcp_deployment_experiment_row row;

	if ((budget->blocker_mask &
	     PQCP_DEPLOYMENT_BUDGET_BLOCKER_ADVISOR_REJECTED) == 0U) {
		return 0;
	}

	memset(&row, 0, sizeof(row));
	row.candidate_index = budget->candidate_index;
	row.candidate_id = budget->candidate_id;
	row.kind = PQCP_DEPLOYMENT_EXPERIMENT_CLAIM_REVIEW;
	row.maturity = PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PRODUCT;
	row.reason_mask = PQCP_DEPLOYMENT_EXPERIMENT_REASON_BLOCKER;
	row.budget_blocker_mask = budget->blocker_mask;
	row.budget_warning_mask = budget->warning_mask;
	row.expected_artifact = "deployment_advisor_replay";
	row.claim_token = "claim.deployment.feasible_recommendation";
	row.blocking = true;

	return append_row(rows, row_capacity, plan, &row);
}

static int append_gap_rows(
	const struct pqcp_deployment_pipeline_workspace *workspace,
	const struct pqcp_deployment_pipeline_result *pipeline,
	struct pqcp_deployment_experiment_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_experiment_plan *plan)
{
	for (size_t i = 0U; i < pipeline->gap_count; ++i) {
		const struct pqcp_deployment_gap_plan_entry *gap =
			&workspace->gaps[i];
		const struct gap_plan *meta = find_gap_plan(gap->gap);
		struct pqcp_deployment_experiment_row row;

		if (meta == NULL) {
			return -EINVAL;
		}
		memset(&row, 0, sizeof(row));
		row.candidate_index = UINT32_MAX;
		row.candidate_id = gap->candidate_id != NULL ?
			gap->candidate_id : "report";
		row.kind = meta->kind;
		row.maturity = maturity_from_gap(gap->maturity);
		row.reason_mask =
			PQCP_DEPLOYMENT_EXPERIMENT_REASON_PIPELINE_GAP;
		row.gap_mask = gap->gap;
		row.expected_artifact = gap->expected_artifact != NULL ?
			gap->expected_artifact : meta->artifact;
		row.claim_token = gap->claim_token != NULL ?
			gap->claim_token : meta->claim;
		row.acceptance_max = gap->acceptance_max;
		row.blocking = true;

		int ret = append_row(rows, row_capacity, plan, &row);

		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

static int append_report_row(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget_report,
	struct pqcp_deployment_experiment_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_experiment_plan *plan)
{
	struct pqcp_deployment_experiment_row row;

	if (pipeline->passed && budget_report->status ==
	    PQCP_DEPLOYMENT_BUDGET_STATUS_PASS) {
		return 0;
	}

	memset(&row, 0, sizeof(row));
	row.candidate_index = UINT32_MAX;
	row.candidate_id = budget_report->top_candidate_id != NULL ?
		budget_report->top_candidate_id : "report";
	row.kind = PQCP_DEPLOYMENT_EXPERIMENT_CLAIM_REVIEW;
	row.maturity = maturity_from_profile(budget_report->profile);
	row.reason_mask = PQCP_DEPLOYMENT_EXPERIMENT_REASON_PIPELINE_GAP;
	row.budget_blocker_mask = budget_report->blocker_mask;
	row.budget_warning_mask = budget_report->warning_mask;
	row.expected_artifact = "deployment_claim_matrix_replay";
	row.claim_token = "claim.deployment.gap_free_review";
	row.blocking = !pipeline->passed ||
		       budget_report->status ==
			       PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL;

	return append_row(rows, row_capacity, plan, &row);
}

static int validate_inputs(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_workspace *workspace,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_candidate *budget_rows,
	const struct pqcp_deployment_budget_report *budget_report,
	const struct pqcp_deployment_experiment_row *rows,
	size_t row_capacity,
	const struct pqcp_deployment_experiment_plan *plan)
{
	if (config == NULL || workspace == NULL || pipeline == NULL ||
	    budget_rows == NULL || budget_report == NULL || rows == NULL ||
	    plan == NULL ||
	    pqcp_deployment_scenario_validate(config->scenario) != 0 ||
	    pipeline->schema_version != PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION ||
	    budget_report->schema_version !=
		    PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION ||
	    pipeline->candidate_count == 0U ||
	    pipeline->candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES ||
	    budget_report->candidate_count != pipeline->candidate_count ||
	    row_capacity == 0U ||
	    row_capacity > PQCP_DEPLOYMENT_EXPERIMENT_PLAN_MAX_ROWS) {
		return -EINVAL;
	}

	for (size_t i = 0U; i < pipeline->candidate_count; ++i) {
		if (budget_rows[i].schema_version !=
			    PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION ||
		    budget_rows[i].candidate_id == NULL ||
		    budget_rows[i].candidate_index != i) {
			return -EINVAL;
		}
	}

	return 0;
}

static void finalize_plan(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget_report,
	struct pqcp_deployment_experiment_plan *plan)
{
	plan->pipeline_passed = pipeline->passed;
	plan->replay_passed = pipeline->replay_passed;
	plan->appraisal_passed = pipeline->appraisal_passed;
	plan->claims_passed = pipeline->claims_passed;
	plan->budget_status = budget_report->status;
	plan->top_candidate_id = budget_report->top_candidate_id != NULL ?
		budget_report->top_candidate_id : "none";

	if (plan->blocking_count != 0U ||
	    budget_report->status == PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL ||
	    !pipeline->passed) {
		plan->status = PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL;
	} else if (plan->row_count != 0U ||
		   budget_report->status == PQCP_DEPLOYMENT_BUDGET_STATUS_WARN) {
		plan->status = PQCP_DEPLOYMENT_EXPERIMENT_PLAN_WARN;
	} else {
		plan->status = PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS;
	}
}

int pqcp_deployment_experiment_plan_generate(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_workspace *workspace,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_candidate *budget_rows,
	const struct pqcp_deployment_budget_report *budget_report,
	struct pqcp_deployment_experiment_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_experiment_plan *plan)
{
	int ret = validate_inputs(config, workspace, pipeline, budget_rows,
				  budget_report, rows, row_capacity, plan);

	if (ret != 0) {
		if (plan != NULL) {
			memset(plan, 0, sizeof(*plan));
			plan->schema_version =
				PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION;
			plan->status = PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL;
			plan->top_candidate_id = "none";
		}
		return ret;
	}

	memset(rows, 0, sizeof(rows[0]) * row_capacity);
	memset(plan, 0, sizeof(*plan));
	plan->schema_version = PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION;
	plan->top_candidate_id = "none";

	for (size_t i = 0U; i < pipeline->candidate_count; ++i) {
		ret = append_advisor_blocker_row(&budget_rows[i], rows,
						 row_capacity, plan);
		if (ret != 0) {
			return ret;
		}
		ret = append_metric_rows(config->scenario, &budget_rows[i], rows,
					 row_capacity, plan);
		if (ret != 0) {
			return ret;
		}
		ret = append_evidence_rows(&budget_rows[i], rows, row_capacity,
					   plan);
		if (ret != 0) {
			return ret;
		}
	}

	ret = append_gap_rows(workspace, pipeline, rows, row_capacity, plan);
	if (ret != 0) {
		return ret;
	}
	ret = append_report_row(pipeline, budget_report, rows, row_capacity,
				plan);
	if (ret != 0) {
		return ret;
	}

	finalize_plan(pipeline, budget_report, plan);
	return 0;
}

static bool row_valid(const struct pqcp_deployment_experiment_row *row)
{
	return row != NULL &&
	       row->schema_version ==
		       PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION &&
	       row->priority != 0U &&
	       row->candidate_id != NULL &&
	       kind_valid(row->kind) &&
	       maturity_valid(row->maturity) &&
	       row->expected_artifact != NULL &&
	       row->claim_token != NULL &&
	       (row->reason_mask &
		~PQCP_DEPLOYMENT_EXPERIMENT_REASON_KNOWN_MASK) == 0U &&
	       (row->metric_mask & ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) == 0U &&
	       (row->evidence_mask &
		~PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK) == 0U &&
	       (row->gap_mask & ~PQCP_DEPLOYMENT_GAP_KNOWN_MASK) == 0U &&
	       (row->budget_blocker_mask &
		~PQCP_DEPLOYMENT_BUDGET_BLOCKER_KNOWN_MASK) == 0U &&
	       (row->budget_warning_mask &
		~PQCP_DEPLOYMENT_BUDGET_WARNING_KNOWN_MASK) == 0U;
}

int pqcp_deployment_experiment_row_emit(
	const struct pqcp_deployment_experiment_row *row)
{
	if (!row_valid(row)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EXPERIMENT schema=%u priority=%u candidate=%s kind=%s maturity=%s reason=0x%08x metric=0x%08x evidence=0x%08x gap=0x%08x budget_blockers=0x%08x budget_warnings=0x%08x acceptance_max=%llu expected=%s claim=%s blocking=%u\n",
	       row->schema_version,
	       row->priority,
	       row->candidate_id,
	       pqcp_deployment_experiment_kind_str(row->kind),
	       pqcp_deployment_experiment_maturity_str(row->maturity),
	       row->reason_mask,
	       row->metric_mask,
	       row->evidence_mask,
	       row->gap_mask,
	       row->budget_blocker_mask,
	       row->budget_warning_mask,
	       (unsigned long long)row->acceptance_max,
	       row->expected_artifact,
	       row->claim_token,
	       row->blocking ? 1U : 0U);

	return row->blocking ? -EBADMSG : 0;
}

static bool plan_valid(const struct pqcp_deployment_experiment_plan *plan)
{
	return plan != NULL &&
	       plan->schema_version ==
		       PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION &&
	       status_valid(plan->status) &&
	       plan->row_count <= PQCP_DEPLOYMENT_EXPERIMENT_PLAN_MAX_ROWS &&
	       plan->blocking_count <= plan->row_count &&
	       plan->recommended_count <= plan->row_count &&
	       plan->blocking_count + plan->recommended_count ==
		       plan->row_count &&
	       plan->top_candidate_id != NULL;
}

int pqcp_deployment_experiment_plan_emit(
	const struct pqcp_deployment_experiment_plan *plan)
{
	if (!plan_valid(plan)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EXPERIMENT_PLAN schema=%u status=%s rows=%u blocking=%u recommended=%u top=%s budget=%s pipeline=%s replay=%s appraisal=%s claims=%s\n",
	       plan->schema_version,
	       pqcp_deployment_experiment_plan_status_str(plan->status),
	       plan->row_count,
	       plan->blocking_count,
	       plan->recommended_count,
	       plan->top_candidate_id,
	       pqcp_deployment_budget_status_str(plan->budget_status),
	       plan->pipeline_passed ? "PASS" : "FAIL",
	       plan->replay_passed ? "PASS" : "FAIL",
	       plan->appraisal_passed ? "PASS" : "FAIL",
	       plan->claims_passed ? "PASS" : "FAIL");

	return plan->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL ?
		-EBADMSG : 0;
}
