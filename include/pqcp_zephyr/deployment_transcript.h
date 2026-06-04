/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment evidence transcript replay
 *
 * Stability: experimental evidence API. This verifier replays the stable
 * PQCP_DEPLOYMENT_* marker grammar emitted by the deployment advisor,
 * campaign accumulator, and robustness analyzer.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_TRANSCRIPT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_TRANSCRIPT_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_campaign.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment transcript replay results. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION 1U

/** Deployment scenario marker was observed. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_SCENARIO       (1U << 0)
/** Deployment campaign summary marker was observed. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN       (1U << 1)
/** One or more deployment campaign metric markers were observed. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN_METRIC (1U << 2)
/** One or more deployment candidate markers were observed. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CANDIDATE      (1U << 3)
/** Deployment decision marker was observed. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_DECISION       (1U << 4)
/** One or more deployment robustness candidate markers were observed. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUST_CANDIDATE (1U << 5)
/** Deployment robustness summary marker was observed. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUSTNESS     (1U << 6)
/** One or more deployment evidence-gap markers were observed. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_GAP            (1U << 7)

/** All deployment marker bits known by this API version. */
#define PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_KNOWN_MASK \
	(PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_SCENARIO | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN_METRIC | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CANDIDATE | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_DECISION | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUST_CANDIDATE | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUSTNESS | \
	 PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_GAP)

/** Replay error reason for deployment evidence transcripts. */
enum pqcp_deployment_transcript_error {
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_BAD_SEQUENCE,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_DUPLICATE_SUMMARY,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_STATUS_FAIL,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_COUNT_MISMATCH,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_TOP_MISMATCH,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_CAMPAIGN_MISMATCH,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_ROBUSTNESS_MISMATCH,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MISSING_REQUIRED,
	PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_UNKNOWN_STATUS,
};

/** Caller-owned deployment transcript replay state. */
struct pqcp_deployment_transcript_state {
	/** Replay schema version. */
	uint32_t schema_version;
	/** Transcript lines consumed. */
	uint32_t lines_seen;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_transcript_error first_error;
	/** Observed PQCP_DEPLOYMENT_* marker bits. */
	uint32_t marker_mask;
	/** Candidate rows observed. */
	uint32_t candidate_count;
	/** Candidate rows with status=ACCEPTED. */
	uint32_t accepted_count;
	/** Candidate rows with status=CONDITIONAL. */
	uint32_t conditional_count;
	/** Candidate rows with status=REJECTED. */
	uint32_t rejected_count;
	/** Robustness candidate rows observed. */
	uint32_t robustness_candidate_count;
	/** Robustness candidates on the Pareto frontier. */
	uint32_t pareto_frontier_count;
	/** Campaign metric rows observed. */
	uint32_t campaign_metric_count;
	/** Distinct campaign metric names observed. */
	uint32_t campaign_metric_mask;
	/** Evidence-gap rows observed. */
	uint32_t gap_count;
	/** Candidate count declared by the decision marker. */
	uint32_t decision_candidate_count;
	/** Feasible count declared by the decision marker. */
	uint32_t decision_feasible_count;
	/** Accepted count declared by the decision marker. */
	uint32_t decision_accepted_count;
	/** Conditional count declared by the decision marker. */
	uint32_t decision_conditional_count;
	/** Rejected count declared by the decision marker. */
	uint32_t decision_rejected_count;
	/** Candidate count declared by the robustness marker. */
	uint32_t robustness_candidate_total;
	/** Feasible count declared by the robustness marker. */
	uint32_t robustness_feasible_count;
	/** Frontier count declared by the robustness marker. */
	uint32_t robustness_frontier_count;
	/** Campaign observations declared by the campaign summary. */
	uint32_t campaign_observations;
	/** Campaign successful observations. */
	uint32_t campaign_successful;
	/** Campaign failed observations. */
	uint32_t campaign_failed;
	/** Campaign quality mask. */
	uint32_t campaign_quality_mask;
	/** True when campaign summary projected a candidate. */
	bool campaign_projected;
	/** True when a deployment scenario marker was observed. */
	bool scenario_seen;
	/** True when a deployment decision marker was observed. */
	bool decision_seen;
	/** True when a robustness summary marker was observed. */
	bool robustness_seen;
	/** True when a campaign summary marker was observed. */
	bool campaign_seen;
	/** True when the decision top candidate appeared in candidate rows. */
	bool decision_top_seen;
	/** True when the robustness top candidate appeared in robustness rows. */
	bool robustness_top_seen;
	/** True when the campaign projected candidate appeared in candidates. */
	bool campaign_candidate_seen;
	/** Top candidate id from decision marker. */
	char decision_top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Top candidate id from robustness marker. */
	char robustness_top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Projected candidate id from campaign summary. */
	char campaign_candidate[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Candidate id observed with rank=1. */
	char rank_one_candidate[PQCP_DEPLOYMENT_ID_MAX_CHARS];
};

/** Final replay result. */
struct pqcp_deployment_transcript_result {
	/** Replay schema version. */
	uint32_t schema_version;
	/** Transcript lines consumed. */
	uint32_t lines_seen;
	/** Observed marker bit mask. */
	uint32_t marker_mask;
	/** Candidate row count. */
	uint32_t candidate_count;
	/** Robustness candidate row count. */
	uint32_t robustness_candidate_count;
	/** Campaign metric row count. */
	uint32_t campaign_metric_count;
	/** Evidence-gap row count. */
	uint32_t gap_count;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_transcript_error first_error;
	/** True when all required deployment markers are internally consistent. */
	bool passed;
};

/** Convert a replay error to a stable diagnostic token. */
const char *pqcp_deployment_transcript_error_str(
	enum pqcp_deployment_transcript_error error);

/** Initialize a deployment transcript replay state. */
int pqcp_deployment_transcript_init(
	struct pqcp_deployment_transcript_state *state);

/** Feed one transcript line into the deployment replay verifier. */
int pqcp_deployment_transcript_ingest_line(
	struct pqcp_deployment_transcript_state *state,
	const char *line);

/** Finish replay and verify cross-marker consistency. */
int pqcp_deployment_transcript_finish(
	struct pqcp_deployment_transcript_state *state,
	struct pqcp_deployment_transcript_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_TRANSCRIPT_H_ */
