/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment budget evidence verdicts
 *
 * Stability: experimental evidence API. The budget layer converts an already
 * executed deployment pipeline into deterministic resource, performance, and
 * evidence-readiness verdicts. It does not run cryptography, select providers,
 * or change deployment marker formats emitted by lower layers.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_BUDGET_H_
#define PQCP_ZEPHYR_DEPLOYMENT_BUDGET_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_pipeline.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment budget result structures and markers. */
#define PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION 1U

/** Budget evaluator input was malformed. */
#define PQCP_DEPLOYMENT_BUDGET_BLOCKER_INVALID_INPUT       (1U << 0)
/** Candidate was rejected by the advisor. */
#define PQCP_DEPLOYMENT_BUDGET_BLOCKER_ADVISOR_REJECTED    (1U << 1)
/** One or more configured metrics exceed scenario budgets. */
#define PQCP_DEPLOYMENT_BUDGET_BLOCKER_OVER_BUDGET         (1U << 2)
/** Required measurement evidence is missing. */
#define PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_MEASUREMENT (1U << 3)
/** Required evidence flags are missing. */
#define PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_EVIDENCE    (1U << 4)
/** Pipeline-level replay/appraisal/claim result was not acceptable. */
#define PQCP_DEPLOYMENT_BUDGET_BLOCKER_PIPELINE_FAILED     (1U << 5)
/** Candidate confidence is below policy. */
#define PQCP_DEPLOYMENT_BUDGET_BLOCKER_CONFIDENCE          (1U << 6)
/** Candidate score is below policy. */
#define PQCP_DEPLOYMENT_BUDGET_BLOCKER_SCORE               (1U << 7)

/** All deployment budget blocker bits known by this API version. */
#define PQCP_DEPLOYMENT_BUDGET_BLOCKER_KNOWN_MASK \
	(PQCP_DEPLOYMENT_BUDGET_BLOCKER_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_BUDGET_BLOCKER_ADVISOR_REJECTED | \
	 PQCP_DEPLOYMENT_BUDGET_BLOCKER_OVER_BUDGET | \
	 PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_MEASUREMENT | \
	 PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_EVIDENCE | \
	 PQCP_DEPLOYMENT_BUDGET_BLOCKER_PIPELINE_FAILED | \
	 PQCP_DEPLOYMENT_BUDGET_BLOCKER_CONFIDENCE | \
	 PQCP_DEPLOYMENT_BUDGET_BLOCKER_SCORE)

/** Candidate has a known metric close to its configured budget. */
#define PQCP_DEPLOYMENT_BUDGET_WARNING_LOW_MARGIN       (1U << 0)
/** Candidate has optional metrics that were not measured. */
#define PQCP_DEPLOYMENT_BUDGET_WARNING_PARTIAL_METRICS  (1U << 1)
/** Candidate has optional evidence gaps visible to reviewers. */
#define PQCP_DEPLOYMENT_BUDGET_WARNING_PARTIAL_EVIDENCE (1U << 2)
/** Recommendation is conditional even though hard constraints passed. */
#define PQCP_DEPLOYMENT_BUDGET_WARNING_CONDITIONAL      (1U << 3)
/** Pipeline completed but exposed warnings or open gaps. */
#define PQCP_DEPLOYMENT_BUDGET_WARNING_PIPELINE_GAPS    (1U << 4)

/** All deployment budget warning bits known by this API version. */
#define PQCP_DEPLOYMENT_BUDGET_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_BUDGET_WARNING_LOW_MARGIN | \
	 PQCP_DEPLOYMENT_BUDGET_WARNING_PARTIAL_METRICS | \
	 PQCP_DEPLOYMENT_BUDGET_WARNING_PARTIAL_EVIDENCE | \
	 PQCP_DEPLOYMENT_BUDGET_WARNING_CONDITIONAL | \
	 PQCP_DEPLOYMENT_BUDGET_WARNING_PIPELINE_GAPS)

/** Deployment budget verdict for one candidate or report. */
enum pqcp_deployment_budget_status {
	PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL = 0,
	PQCP_DEPLOYMENT_BUDGET_STATUS_WARN,
	PQCP_DEPLOYMENT_BUDGET_STATUS_PASS,
};

/**
 * @brief Profile-specific budget and evidence policy.
 *
 * A zero threshold means that field is not enforced. Required evidence is
 * checked against candidate evidence masks; missing evidence is a blocker when
 * require_required_evidence is true and a warning otherwise.
 */
struct pqcp_deployment_budget_policy {
	/** Appraisal profile this policy was derived from. */
	enum pqcp_deployment_appraisal_profile profile;
	/** Required minimum known metric headroom in permille. */
	uint32_t min_headroom_permille;
	/** Candidate confidence threshold from 0 to 100. */
	uint32_t min_confidence;
	/** Candidate score threshold from 0 to 100. */
	uint32_t min_score;
	/** Evidence bits required by this budget policy. */
	uint32_t required_evidence_mask;
	/** True when every configured scenario metric must be measured. */
	bool require_complete_measurements;
	/** True when required evidence gaps are blockers. */
	bool require_required_evidence;
	/** True when the pipeline result must pass completely. */
	bool require_pipeline_pass;
	/** True when hardware evidence is mandatory. */
	bool require_hardware_evidence;
	/** True when independent evidence is mandatory. */
	bool require_independent_evidence;
};

/** Budget verdict for one deployment candidate. */
struct pqcp_deployment_budget_candidate {
	/** Result schema version. */
	uint32_t schema_version;
	/** Index of the candidate in the pipeline workspace. */
	uint32_t candidate_index;
	/** Stable candidate identifier. */
	const char *candidate_id;
	/** Verdict status. */
	enum pqcp_deployment_budget_status status;
	/** Blocking issue bit mask. */
	uint32_t blocker_mask;
	/** Non-blocking warning bit mask. */
	uint32_t warning_mask;
	/** Configured metrics that passed required headroom. */
	uint32_t metric_pass_mask;
	/** Configured metrics that passed budget but are below margin. */
	uint32_t metric_warn_mask;
	/** Configured metrics that exceed budget. */
	uint32_t metric_fail_mask;
	/** Configured metrics without concrete measurements. */
	uint32_t metric_missing_mask;
	/** Required evidence bits missing from candidate evidence. */
	uint32_t evidence_missing_mask;
	/** Lowest known metric headroom in permille. */
	int32_t minimum_headroom_permille;
	/** Mean known metric headroom in permille. */
	int32_t average_headroom_permille;
	/** Deterministic 0-100 margin score. */
	uint32_t margin_score;
	/** Advisor score copied for review. */
	uint32_t advisor_score;
	/** Advisor confidence copied for review. */
	uint32_t advisor_confidence;
	/** True when this row is the pipeline top candidate. */
	bool top_candidate;
};

/** Complete deployment budget report. */
struct pqcp_deployment_budget_report {
	/** Result schema version. */
	uint32_t schema_version;
	/** Evaluated policy profile. */
	enum pqcp_deployment_appraisal_profile profile;
	/** Overall verdict status. */
	enum pqcp_deployment_budget_status status;
	/** Candidate rows evaluated. */
	uint32_t candidate_count;
	/** Candidate rows with PASS status. */
	uint32_t pass_count;
	/** Candidate rows with WARN status. */
	uint32_t warn_count;
	/** Candidate rows with FAIL status. */
	uint32_t fail_count;
	/** Aggregated blocker bits. */
	uint32_t blocker_mask;
	/** Aggregated warning bits. */
	uint32_t warning_mask;
	/** Required metric headroom threshold in permille. */
	uint32_t required_margin_permille;
	/** Stable top candidate identifier, or "none". */
	const char *top_candidate_id;
	/** Top candidate status. */
	enum pqcp_deployment_budget_status top_status;
	/** Top candidate minimum headroom in permille. */
	int32_t top_minimum_headroom_permille;
	/** Top candidate margin score. */
	uint32_t top_margin_score;
	/** Pipeline readiness score copied from appraisal. */
	uint32_t pipeline_readiness_score;
	/** Claim matrix score copied from pipeline. */
	uint32_t claim_score;
	/** True when the pipeline result passed. */
	bool pipeline_passed;
	/** True when replay passed. */
	bool replay_passed;
	/** True when appraisal passed. */
	bool appraisal_passed;
	/** True when claim matrix passed. */
	bool claims_passed;
};

/** Convert a deployment budget status to a stable marker token. */
const char *pqcp_deployment_budget_status_str(
	enum pqcp_deployment_budget_status status);

/** Build the default budget policy for one appraisal profile. */
int pqcp_deployment_budget_default_policy(
	enum pqcp_deployment_appraisal_profile profile,
	struct pqcp_deployment_budget_policy *policy);

/** Evaluate budget/evidence verdicts from an executed deployment pipeline. */
int pqcp_deployment_budget_evaluate(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_workspace *workspace,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_policy *policy,
	struct pqcp_deployment_budget_candidate *rows,
	size_t row_capacity,
	struct pqcp_deployment_budget_report *report);

/** Emit one stable deployment budget candidate marker. */
int pqcp_deployment_budget_candidate_emit(
	const struct pqcp_deployment_budget_candidate *row);

/** Emit one stable deployment budget report marker. */
int pqcp_deployment_budget_report_emit(
	const struct pqcp_deployment_budget_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_BUDGET_H_ */
