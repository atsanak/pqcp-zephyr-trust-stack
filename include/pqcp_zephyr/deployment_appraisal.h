/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment evidence appraisal
 *
 * Stability: experimental evidence API. The appraisal layer converts a
 * replayed deployment transcript into a profile-specific readiness marker.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_APPRAISAL_H_
#define PQCP_ZEPHYR_DEPLOYMENT_APPRAISAL_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_transcript.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment appraisal result structures and markers. */
#define PQCP_DEPLOYMENT_APPRAISAL_SCHEMA_VERSION 1U

/** Replay result did not pass. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_REPLAY_FAILED (1U << 0)
/** Required deployment marker class is missing. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_MISSING_MARKERS (1U << 1)
/** Too few deployment candidates were replayed. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CANDIDATE_COUNT (1U << 2)
/** Too few feasible deployment candidates were replayed. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_FEASIBLE_COUNT (1U << 3)
/** Too few accepted deployment candidates were replayed. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_ACCEPTED_COUNT (1U << 4)
/** Repeated-measurement campaign evidence is required but missing. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_REQUIRED (1U << 5)
/** Campaign sample count is below the profile requirement. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_SAMPLES (1U << 6)
/** Campaign quality mask is nonzero where clean campaign evidence is required. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_QUALITY (1U << 7)
/** Robustness replay evidence is required but missing. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_ROBUSTNESS_REQUIRED (1U << 8)
/** Open evidence gaps exceed the profile allowance. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_OPEN_GAPS (1U << 9)
/** Conditional recommendations are forbidden by this profile. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CONDITIONAL (1U << 10)

/** All deployment appraisal blocker bits known by this API version. */
#define PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_KNOWN_MASK \
	(PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_REPLAY_FAILED | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_MISSING_MARKERS | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CANDIDATE_COUNT | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_FEASIBLE_COUNT | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_ACCEPTED_COUNT | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_REQUIRED | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_SAMPLES | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_QUALITY | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_ROBUSTNESS_REQUIRED | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_OPEN_GAPS | \
	 PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CONDITIONAL)

/** Transcript contains conditional recommendations. */
#define PQCP_DEPLOYMENT_APPRAISAL_WARNING_CONDITIONAL (1U << 0)
/** Transcript contains rejected candidates. */
#define PQCP_DEPLOYMENT_APPRAISAL_WARNING_REJECTED (1U << 1)
/** Transcript contains open evidence-gap rows. */
#define PQCP_DEPLOYMENT_APPRAISAL_WARNING_OPEN_GAPS (1U << 2)
/** Campaign evidence is absent but not blocking for this profile. */
#define PQCP_DEPLOYMENT_APPRAISAL_WARNING_NO_CAMPAIGN (1U << 3)
/** Robustness evidence is absent but not blocking for this profile. */
#define PQCP_DEPLOYMENT_APPRAISAL_WARNING_NO_ROBUSTNESS (1U << 4)
/** Only one feasible recommendation path was replayed. */
#define PQCP_DEPLOYMENT_APPRAISAL_WARNING_SINGLE_FEASIBLE (1U << 5)

/** All deployment appraisal warning bits known by this API version. */
#define PQCP_DEPLOYMENT_APPRAISAL_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_APPRAISAL_WARNING_CONDITIONAL | \
	 PQCP_DEPLOYMENT_APPRAISAL_WARNING_REJECTED | \
	 PQCP_DEPLOYMENT_APPRAISAL_WARNING_OPEN_GAPS | \
	 PQCP_DEPLOYMENT_APPRAISAL_WARNING_NO_CAMPAIGN | \
	 PQCP_DEPLOYMENT_APPRAISAL_WARNING_NO_ROBUSTNESS | \
	 PQCP_DEPLOYMENT_APPRAISAL_WARNING_SINGLE_FEASIBLE)

/** Deployment evidence maturity profile. */
enum pqcp_deployment_appraisal_profile {
	PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB = 0,
	PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PAPER,
	PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT,
	PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW,
	PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW,
};

/** Profile-specific deployment evidence policy. */
struct pqcp_deployment_appraisal_policy {
	/** Policy profile token. */
	enum pqcp_deployment_appraisal_profile profile;
	/** Required deployment transcript marker bits. */
	uint32_t required_markers;
	/** Minimum candidate rows. */
	uint32_t min_candidates;
	/** Minimum feasible candidates. */
	uint32_t min_feasible;
	/** Minimum accepted candidates. */
	uint32_t min_accepted;
	/** Minimum campaign observations when campaign evidence is required. */
	uint32_t min_campaign_observations;
	/** Maximum allowed open evidence-gap rows. UINT32_MAX means unlimited. */
	uint32_t max_gap_count;
	/** True when campaign evidence is mandatory. */
	bool require_campaign;
	/** True when campaign quality mask must be zero. */
	bool require_clean_campaign;
	/** True when robustness summary and per-candidate rows are mandatory. */
	bool require_robustness;
	/** True when conditional recommendations are accepted. */
	bool allow_conditional;
};

/** Deployment evidence appraisal result. */
struct pqcp_deployment_appraisal {
	/** Result schema version. */
	uint32_t schema_version;
	/** Evaluated profile. */
	enum pqcp_deployment_appraisal_profile profile;
	/** Blocking issue bit mask. */
	uint32_t blocker_mask;
	/** Non-blocking concern bit mask. */
	uint32_t warning_mask;
	/** Replayed marker bits. */
	uint32_t marker_mask;
	/** Candidate rows replayed. */
	uint32_t candidate_count;
	/** Feasible candidates replayed. */
	uint32_t feasible_count;
	/** Accepted candidates replayed. */
	uint32_t accepted_count;
	/** Conditional candidates replayed. */
	uint32_t conditional_count;
	/** Open evidence-gap rows replayed. */
	uint32_t gap_count;
	/** Campaign observations replayed. */
	uint32_t campaign_observations;
	/** Deterministic readiness score from 0 to 100. */
	uint32_t readiness_score;
	/** True when blocker_mask is zero. */
	bool passed;
};

/** Convert a deployment appraisal profile to a stable token. */
const char *pqcp_deployment_appraisal_profile_str(
	enum pqcp_deployment_appraisal_profile profile);

/** Return the default appraisal policy for one profile. */
int pqcp_deployment_appraisal_default_policy(
	enum pqcp_deployment_appraisal_profile profile,
	struct pqcp_deployment_appraisal_policy *policy);

/** Evaluate a replay result against a deployment evidence policy. */
int pqcp_deployment_appraisal_evaluate(
	const struct pqcp_deployment_transcript_result *replay,
	const struct pqcp_deployment_appraisal_policy *policy,
	struct pqcp_deployment_appraisal *appraisal);

/** Emit a stable deployment appraisal marker. */
int pqcp_deployment_appraisal_emit(
	const struct pqcp_deployment_appraisal *appraisal);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_APPRAISAL_H_ */
