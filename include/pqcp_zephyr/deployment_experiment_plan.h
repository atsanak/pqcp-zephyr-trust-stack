/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment experiment planning evidence
 *
 * Stability: experimental evidence API. The planner converts firmware
 * pipeline, budget, and gap-plan results into deterministic next-experiment
 * rows for partner review. It does not execute experiments or change crypto
 * APIs, ACVP wire formats, or benchmark marker formats.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EXPERIMENT_PLAN_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EXPERIMENT_PLAN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_budget.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment experiment-plan structures and markers. */
#define PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION 1U

/** Maximum experiment rows emitted by one planner call. */
#define PQCP_DEPLOYMENT_EXPERIMENT_PLAN_MAX_ROWS 32U

/** Experiment planner input was malformed. */
#define PQCP_DEPLOYMENT_EXPERIMENT_REASON_INVALID_INPUT     (1U << 0)
/** Candidate violated a hard budget or advisor constraint. */
#define PQCP_DEPLOYMENT_EXPERIMENT_REASON_BLOCKER           (1U << 1)
/** Candidate has a low resource/performance margin. */
#define PQCP_DEPLOYMENT_EXPERIMENT_REASON_LOW_MARGIN        (1U << 2)
/** Candidate is missing required measurement data. */
#define PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_MEASUREMENT (1U << 3)
/** Candidate is missing required evidence. */
#define PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE  (1U << 4)
/** Pipeline replay/appraisal/claims exposed open review gaps. */
#define PQCP_DEPLOYMENT_EXPERIMENT_REASON_PIPELINE_GAP      (1U << 5)
/** Scenario explicitly requires hardware promotion evidence. */
#define PQCP_DEPLOYMENT_EXPERIMENT_REASON_HARDWARE_REQUIRED (1U << 6)
/** Independent baseline or cross-framework evidence is missing. */
#define PQCP_DEPLOYMENT_EXPERIMENT_REASON_BASELINE_REQUIRED (1U << 7)

/** All experiment reason bits known by this API version. */
#define PQCP_DEPLOYMENT_EXPERIMENT_REASON_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EXPERIMENT_REASON_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_EXPERIMENT_REASON_BLOCKER | \
	 PQCP_DEPLOYMENT_EXPERIMENT_REASON_LOW_MARGIN | \
	 PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_MEASUREMENT | \
	 PQCP_DEPLOYMENT_EXPERIMENT_REASON_MISSING_EVIDENCE | \
	 PQCP_DEPLOYMENT_EXPERIMENT_REASON_PIPELINE_GAP | \
	 PQCP_DEPLOYMENT_EXPERIMENT_REASON_HARDWARE_REQUIRED | \
	 PQCP_DEPLOYMENT_EXPERIMENT_REASON_BASELINE_REQUIRED)

/** Type of experiment proposed by the firmware planner. */
enum pqcp_deployment_experiment_kind {
	PQCP_DEPLOYMENT_EXPERIMENT_LATENCY_BENCHMARK = 0,
	PQCP_DEPLOYMENT_EXPERIMENT_RESOURCE_MEASUREMENT,
	PQCP_DEPLOYMENT_EXPERIMENT_STACK_HEAP_AUDIT,
	PQCP_DEPLOYMENT_EXPERIMENT_ENERGY_MEASUREMENT,
	PQCP_DEPLOYMENT_EXPERIMENT_HARDWARE_PROMOTION,
	PQCP_DEPLOYMENT_EXPERIMENT_KAT_ACVP_VALIDATION,
	PQCP_DEPLOYMENT_EXPERIMENT_CT_SMOKE_REPLAY,
	PQCP_DEPLOYMENT_EXPERIMENT_REPRODUCIBILITY_RUN,
	PQCP_DEPLOYMENT_EXPERIMENT_BASELINE_COMPARISON,
	PQCP_DEPLOYMENT_EXPERIMENT_POLICY_PROVIDER_REPLAY,
	PQCP_DEPLOYMENT_EXPERIMENT_TRANSCRIPT_REPLAY,
	PQCP_DEPLOYMENT_EXPERIMENT_CLAIM_REVIEW,
};

/** Required maturity of a proposed experiment. */
enum pqcp_deployment_experiment_maturity {
	PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PROTOTYPE = 0,
	PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PAPER,
	PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PRODUCT,
	PQCP_DEPLOYMENT_EXPERIMENT_MATURITY_PARTNER,
};

/** Overall experiment-plan status. */
enum pqcp_deployment_experiment_plan_status {
	PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS = 0,
	PQCP_DEPLOYMENT_EXPERIMENT_PLAN_WARN,
	PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL,
};

/** One prioritized next experiment proposed by firmware evidence. */
struct pqcp_deployment_experiment_row {
	/** Row schema version. */
	uint32_t schema_version;
	/** One-based priority. Lower values should run first. */
	uint32_t priority;
	/** Candidate index, or UINT32_MAX when report-level. */
	uint32_t candidate_index;
	/** Stable candidate identifier, or "report". */
	const char *candidate_id;
	/** Experiment kind. */
	enum pqcp_deployment_experiment_kind kind;
	/** Required maturity. */
	enum pqcp_deployment_experiment_maturity maturity;
	/** Reason bit mask. */
	uint32_t reason_mask;
	/** Related PQCP_DEPLOYMENT_METRIC_* bits. */
	uint32_t metric_mask;
	/** Related PQCP_DEPLOYMENT_EVIDENCE_* bits. */
	uint32_t evidence_mask;
	/** Related PQCP_DEPLOYMENT_GAP_* bits. */
	uint32_t gap_mask;
	/** Related budget blocker bits. */
	uint32_t budget_blocker_mask;
	/** Related budget warning bits. */
	uint32_t budget_warning_mask;
	/** Stable artifact token expected from this experiment. */
	const char *expected_artifact;
	/** Stable claim token this experiment supports. */
	const char *claim_token;
	/** Acceptance upper bound for a metric, or zero when not metric-bound. */
	uint64_t acceptance_max;
	/** True when the row blocks the selected profile/product claim. */
	bool blocking;
};

/** Complete firmware experiment plan. */
struct pqcp_deployment_experiment_plan {
	/** Plan schema version. */
	uint32_t schema_version;
	/** Overall plan status. */
	enum pqcp_deployment_experiment_plan_status status;
	/** Rows generated. */
	uint32_t row_count;
	/** Blocking rows generated. */
	uint32_t blocking_count;
	/** Non-blocking recommended rows generated. */
	uint32_t recommended_count;
	/** Lowest priority value generated, or zero when empty. */
	uint32_t highest_priority;
	/** Stable top candidate identifier from the budget report. */
	const char *top_candidate_id;
	/** Budget report status. */
	enum pqcp_deployment_budget_status budget_status;
	/** Pipeline passed flag copied for review. */
	bool pipeline_passed;
	/** Replay passed flag copied for review. */
	bool replay_passed;
	/** Appraisal passed flag copied for review. */
	bool appraisal_passed;
	/** Claim matrix passed flag copied for review. */
	bool claims_passed;
};

/** Convert an experiment kind to a stable marker token. */
const char *pqcp_deployment_experiment_kind_str(
	enum pqcp_deployment_experiment_kind kind);

/** Convert an experiment maturity to a stable marker token. */
const char *pqcp_deployment_experiment_maturity_str(
	enum pqcp_deployment_experiment_maturity maturity);

/** Convert an experiment-plan status to a stable marker token. */
const char *pqcp_deployment_experiment_plan_status_str(
	enum pqcp_deployment_experiment_plan_status status);

/** Generate next-experiment rows from pipeline and budget evidence. */
int pqcp_deployment_experiment_plan_generate(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_workspace *workspace,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_candidate *budget_rows,
	const struct pqcp_deployment_budget_report *budget_report,
	struct pqcp_deployment_experiment_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_experiment_plan *plan);

/** Emit one stable deployment experiment row marker. */
int pqcp_deployment_experiment_row_emit(
	const struct pqcp_deployment_experiment_row *row);

/** Emit a stable deployment experiment plan summary marker. */
int pqcp_deployment_experiment_plan_emit(
	const struct pqcp_deployment_experiment_plan *plan);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EXPERIMENT_PLAN_H_ */
