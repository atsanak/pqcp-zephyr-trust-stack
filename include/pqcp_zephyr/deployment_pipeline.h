/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - End-to-end deployment evidence pipeline
 *
 * Stability: experimental evidence API. The pipeline composes campaign,
 * advisor, robustness, transcript replay, appraisal, and claim support without
 * dynamic allocation or changes to cryptographic APIs.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_PIPELINE_H_
#define PQCP_ZEPHYR_DEPLOYMENT_PIPELINE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_trace_builder.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for pipeline result structures and markers. */
#define PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION 1U

/** Pipeline input or workspace was invalid. */
#define PQCP_DEPLOYMENT_PIPELINE_ERROR_INVALID_INPUT   (1U << 0)
/** Candidate workspace capacity was insufficient. */
#define PQCP_DEPLOYMENT_PIPELINE_ERROR_CANDIDATE_SPACE (1U << 1)
/** Campaign projection failed. */
#define PQCP_DEPLOYMENT_PIPELINE_ERROR_CAMPAIGN        (1U << 2)
/** Advisor/robustness analysis failed. */
#define PQCP_DEPLOYMENT_PIPELINE_ERROR_ANALYSIS        (1U << 3)
/** Trace building or transcript replay failed. */
#define PQCP_DEPLOYMENT_PIPELINE_ERROR_TRACE           (1U << 4)
/** Appraisal evaluation failed. */
#define PQCP_DEPLOYMENT_PIPELINE_ERROR_APPRAISAL       (1U << 5)
/** Claim matrix evaluation failed. */
#define PQCP_DEPLOYMENT_PIPELINE_ERROR_CLAIMS          (1U << 6)

/** All pipeline error bits known by this API version. */
#define PQCP_DEPLOYMENT_PIPELINE_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_PIPELINE_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_PIPELINE_ERROR_CANDIDATE_SPACE | \
	 PQCP_DEPLOYMENT_PIPELINE_ERROR_CAMPAIGN | \
	 PQCP_DEPLOYMENT_PIPELINE_ERROR_ANALYSIS | \
	 PQCP_DEPLOYMENT_PIPELINE_ERROR_TRACE | \
	 PQCP_DEPLOYMENT_PIPELINE_ERROR_APPRAISAL | \
	 PQCP_DEPLOYMENT_PIPELINE_ERROR_CLAIMS)

/** Optional repeated-measurement campaign input. */
struct pqcp_deployment_pipeline_campaign {
	/** Stable campaign identifier. */
	const char *campaign_id;
	/** Candidate template for projected observations. */
	struct pqcp_deployment_candidate candidate_template;
	/** Observation array, or NULL when no campaign is provided. */
	const struct pqcp_deployment_campaign_observation *observations;
	/** Number of observations. */
	size_t observation_count;
	/** Projection policy for variable metrics. */
	enum pqcp_deployment_campaign_projection projection;
	/** Minimum successful observations required. Zero selects default. */
	uint32_t min_samples;
	/** CV warning threshold in basis points. Zero selects default. */
	uint32_t cv_warn_bps;
	/** Static resource drift threshold in permille. Zero selects default. */
	uint32_t static_drift_warn_permille;
};

/** Pipeline caller configuration. */
struct pqcp_deployment_pipeline_config {
	/** Deployment scenario. */
	const struct pqcp_deployment_scenario *scenario;
	/** Base candidate array. */
	const struct pqcp_deployment_candidate *candidates;
	/** Number of base candidates. */
	size_t candidate_count;
	/** Optional campaign input. */
	const struct pqcp_deployment_pipeline_campaign *campaign;
	/** Appraisal profile to apply to replayed evidence. */
	enum pqcp_deployment_appraisal_profile appraisal_profile;
	/** True when generated markers should be printed. */
	bool emit_markers;
};

/** Caller-owned pipeline workspace. */
struct pqcp_deployment_pipeline_workspace {
	/** Candidate storage, including optional campaign-projected candidate. */
	struct pqcp_deployment_candidate candidates[PQCP_DEPLOYMENT_MAX_CANDIDATES];
	/** Advisor result storage. */
	struct pqcp_deployment_candidate_result results[PQCP_DEPLOYMENT_MAX_CANDIDATES];
	/** Robustness result storage. */
	struct pqcp_deployment_candidate_robustness robustness[PQCP_DEPLOYMENT_MAX_CANDIDATES];
	/** Gap-plan storage. */
	struct pqcp_deployment_gap_plan_entry gaps[PQCP_DEPLOYMENT_MAX_GAPS];
	/** Claim row storage. */
	struct pqcp_deployment_claim_row claims[PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS];
	/** Campaign observation copy storage. */
	struct pqcp_deployment_campaign_observation campaign_observations[
		PQCP_DEPLOYMENT_CAMPAIGN_MAX_OBSERVATIONS];
};

/** End-to-end pipeline result. */
struct pqcp_deployment_pipeline_result {
	/** Pipeline schema version. */
	uint32_t schema_version;
	/** Pipeline error bit mask. */
	uint32_t error_mask;
	/** Number of candidates analyzed after optional campaign projection. */
	uint32_t candidate_count;
	/** Number of gap rows generated. */
	uint32_t gap_count;
	/** Stable identifier for the top-ranked candidate, or "none". */
	const char *top_candidate_id;
	/** Top-ranked candidate score, or zero when no candidate was ranked. */
	uint32_t top_candidate_score;
	/** True when the advisor has at least one accepted recommendation. */
	bool recommendation_ready;
	/** True when the generated deployment trace replayed successfully. */
	bool replay_passed;
	/** True when profile-specific appraisal passed. */
	bool appraisal_passed;
	/** True when the claim matrix passed. */
	bool claims_passed;
	/** Advisor report. */
	struct pqcp_deployment_report advisor_report;
	/** Robustness report. */
	struct pqcp_deployment_robustness_report robustness_report;
	/** Optional campaign summary. */
	struct pqcp_deployment_campaign_summary campaign_summary;
	/** Trace digest and replay result. */
	struct pqcp_deployment_trace_digest trace_digest;
	/** Deployment appraisal result. */
	struct pqcp_deployment_appraisal appraisal;
	/** Deployment claim matrix. */
	struct pqcp_deployment_claim_matrix claim_matrix;
	/** True when all blocking pipeline stages passed. */
	bool passed;
};

/** Run the end-to-end deployment evidence pipeline. */
int pqcp_deployment_pipeline_run(
	const struct pqcp_deployment_pipeline_config *config,
	struct pqcp_deployment_pipeline_workspace *workspace,
	char *trace_buffer,
	size_t trace_buffer_size,
	struct pqcp_deployment_pipeline_result *result);

/** Emit a stable pipeline summary marker. */
int pqcp_deployment_pipeline_result_emit(
	const struct pqcp_deployment_pipeline_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_PIPELINE_H_ */
