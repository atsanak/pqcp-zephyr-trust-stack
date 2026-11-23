/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment claim support matrix
 *
 * Stability: experimental evidence API. The claim matrix turns firmware-side
 * deployment evidence into explicit supported/partial/unsupported claim rows.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_CLAIMS_H_
#define PQCP_ZEPHYR_DEPLOYMENT_CLAIMS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_appraisal.h>
#include <pqcp_zephyr/deployment_robustness.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment claim matrix result structures and markers. */
#define PQCP_DEPLOYMENT_CLAIMS_SCHEMA_VERSION 1U

/** Maximum claim rows emitted by this API version. */
#define PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS 6U

/** Advisor report evidence was present. */
#define PQCP_DEPLOYMENT_CLAIM_EVIDENCE_ADVISOR    (1U << 0)
/** Robustness report evidence was present. */
#define PQCP_DEPLOYMENT_CLAIM_EVIDENCE_ROBUSTNESS (1U << 1)
/** Transcript replay evidence was present. */
#define PQCP_DEPLOYMENT_CLAIM_EVIDENCE_TRANSCRIPT (1U << 2)
/** Appraisal scorecard evidence was present. */
#define PQCP_DEPLOYMENT_CLAIM_EVIDENCE_APPRAISAL  (1U << 3)
/** Repeated-measurement campaign evidence was present. */
#define PQCP_DEPLOYMENT_CLAIM_EVIDENCE_CAMPAIGN   (1U << 4)

/** All claim evidence bits known by this API version. */
#define PQCP_DEPLOYMENT_CLAIM_EVIDENCE_KNOWN_MASK \
	(PQCP_DEPLOYMENT_CLAIM_EVIDENCE_ADVISOR | \
	 PQCP_DEPLOYMENT_CLAIM_EVIDENCE_ROBUSTNESS | \
	 PQCP_DEPLOYMENT_CLAIM_EVIDENCE_TRANSCRIPT | \
	 PQCP_DEPLOYMENT_CLAIM_EVIDENCE_APPRAISAL | \
	 PQCP_DEPLOYMENT_CLAIM_EVIDENCE_CAMPAIGN)

/** Required source evidence is missing. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_MISSING_INPUT     (1U << 0)
/** Advisor found no feasible candidate. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_NO_FEASIBLE       (1U << 1)
/** Advisor found no accepted candidate. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_NO_ACCEPTED       (1U << 2)
/** Transcript replay failed or was internally inconsistent. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_REPLAY_FAILED     (1U << 3)
/** Required transcript marker class was not observed. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_MARKER_MISSING    (1U << 4)
/** Campaign evidence is missing or too small. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_CAMPAIGN_MISSING  (1U << 5)
/** Campaign evidence has quality warnings. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_CAMPAIGN_QUALITY  (1U << 6)
/** Robustness analysis did not produce a robust recommendation. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_NOT_ROBUST        (1U << 7)
/** Appraisal scorecard failed for the selected profile. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_APPRAISAL_FAILED  (1U << 8)
/** Open evidence gaps remain. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_OPEN_GAPS         (1U << 9)
/** Conditional recommendations remain. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_CONDITIONAL       (1U << 10)

/** All claim blocker bits known by this API version. */
#define PQCP_DEPLOYMENT_CLAIM_BLOCKER_KNOWN_MASK \
	(PQCP_DEPLOYMENT_CLAIM_BLOCKER_MISSING_INPUT | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_NO_FEASIBLE | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_NO_ACCEPTED | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_REPLAY_FAILED | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_MARKER_MISSING | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_CAMPAIGN_MISSING | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_CAMPAIGN_QUALITY | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_NOT_ROBUST | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_APPRAISAL_FAILED | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_OPEN_GAPS | \
	 PQCP_DEPLOYMENT_CLAIM_BLOCKER_CONDITIONAL)

/** Claim is supported by replayed firmware evidence. */
enum pqcp_deployment_claim_support {
	PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED = 0,
	PQCP_DEPLOYMENT_CLAIM_PARTIAL,
	PQCP_DEPLOYMENT_CLAIM_SUPPORTED,
};

/** Reviewer/product risk for one claim row. */
enum pqcp_deployment_claim_risk {
	PQCP_DEPLOYMENT_CLAIM_RISK_HIGH = 0,
	PQCP_DEPLOYMENT_CLAIM_RISK_MEDIUM,
	PQCP_DEPLOYMENT_CLAIM_RISK_LOW,
};

/** Deployment claim identifiers emitted in a stable order. */
enum pqcp_deployment_claim_id {
	PQCP_DEPLOYMENT_CLAIM_FEASIBLE_RECOMMENDATION = 0,
	PQCP_DEPLOYMENT_CLAIM_REPLAYABLE_EVIDENCE,
	PQCP_DEPLOYMENT_CLAIM_REPRODUCIBLE_CAMPAIGN,
	PQCP_DEPLOYMENT_CLAIM_ROBUST_RECOMMENDATION,
	PQCP_DEPLOYMENT_CLAIM_PROFILE_APPRAISAL,
	PQCP_DEPLOYMENT_CLAIM_GAP_FREE_REVIEW,
};

/** Inputs for one deployment claim matrix evaluation. */
struct pqcp_deployment_claim_inputs {
	/** Evaluated advisor report. */
	const struct pqcp_deployment_report *advisor_report;
	/** Evaluated robustness report. */
	const struct pqcp_deployment_robustness_report *robustness_report;
	/** Replayed deployment transcript result. */
	const struct pqcp_deployment_transcript_result *transcript_result;
	/** Profile-specific deployment appraisal result. */
	const struct pqcp_deployment_appraisal *appraisal;
};

/** One claim-support row. */
struct pqcp_deployment_claim_row {
	/** Row schema version. */
	uint32_t schema_version;
	/** Stable claim identifier. */
	enum pqcp_deployment_claim_id claim_id;
	/** Stable claim token. */
	const char *claim_token;
	/** Supported/partial/unsupported status. */
	enum pqcp_deployment_claim_support support;
	/** Reviewer/product risk. */
	enum pqcp_deployment_claim_risk risk;
	/** Source evidence bit mask. */
	uint32_t evidence_mask;
	/** Blocking issue bit mask. */
	uint32_t blocker_mask;
	/** Non-blocking issue bit mask. */
	uint32_t warning_mask;
	/** Deterministic claim score from 0 to 100. */
	uint32_t score;
};

/** Summary for a complete claim matrix. */
struct pqcp_deployment_claim_matrix {
	/** Matrix schema version. */
	uint32_t schema_version;
	/** Number of rows evaluated. */
	uint32_t claim_count;
	/** Fully supported rows. */
	uint32_t supported_count;
	/** Partially supported rows. */
	uint32_t partial_count;
	/** Unsupported rows. */
	uint32_t unsupported_count;
	/** High-risk rows. */
	uint32_t high_risk_count;
	/** Medium-risk rows. */
	uint32_t medium_risk_count;
	/** Average deterministic score from 0 to 100. */
	uint32_t average_score;
	/** True when no unsupported or high-risk rows remain. */
	bool passed;
};

/** Convert a claim id to a stable token. */
const char *pqcp_deployment_claim_id_str(
	enum pqcp_deployment_claim_id claim_id);

/** Convert a support state to a stable token. */
const char *pqcp_deployment_claim_support_str(
	enum pqcp_deployment_claim_support support);

/** Convert a claim risk state to a stable token. */
const char *pqcp_deployment_claim_risk_str(
	enum pqcp_deployment_claim_risk risk);

/** Evaluate deployment evidence into a claim support matrix. */
int pqcp_deployment_claims_evaluate(
	const struct pqcp_deployment_claim_inputs *inputs,
	struct pqcp_deployment_claim_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_claim_matrix *matrix);

/** Emit one stable deployment claim marker. */
int pqcp_deployment_claim_row_emit(
	const struct pqcp_deployment_claim_row *row);

/** Emit one stable deployment claim matrix summary marker. */
int pqcp_deployment_claim_matrix_emit(
	const struct pqcp_deployment_claim_matrix *matrix);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_CLAIMS_H_ */
