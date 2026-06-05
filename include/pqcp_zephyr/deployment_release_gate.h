/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment release gate evidence
 *
 * Stability: experimental evidence API. This module applies an explicit
 * firmware-side policy to the deployment pipeline, budget verdict,
 * experiment plan, review packet, replay verifier, and review audit outputs.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_RELEASE_GATE_H_
#define PQCP_ZEPHYR_DEPLOYMENT_RELEASE_GATE_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_review_audit.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment release gate reports and markers. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION 1U

/** Release gate input was malformed. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_INVALID_INPUT       (1U << 0)
/** Evidence summaries disagree on top candidate identity. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_TOP_MISMATCH        (1U << 1)
/** Pipeline result failed a required policy condition. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_PIPELINE            (1U << 2)
/** Budget result failed a required policy condition. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_BUDGET              (1U << 3)
/** Experiment plan exceeds allowed blocking or open rows. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_EXPERIMENTS         (1U << 4)
/** Review packet status failed a required policy condition. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_PACKET              (1U << 5)
/** Review replay failed a required policy condition. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_REPLAY              (1U << 6)
/** Review audit failed a required policy condition. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_AUDIT               (1U << 7)
/** Required score floor was not met. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_SCORE_FLOOR         (1U << 8)
/** Digest binding between packet, replay, and audit disagrees. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_DIGEST_MISMATCH     (1U << 9)

/** All deployment release gate error bits known by this API version. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_TOP_MISMATCH | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_PIPELINE | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_BUDGET | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_EXPERIMENTS | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_PACKET | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_REPLAY | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_AUDIT | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_SCORE_FLOOR | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_DIGEST_MISMATCH)

/** Pipeline has warnings/open gaps but was not a hard blocker. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_PIPELINE_GAPS     (1U << 0)
/** Budget has warnings/failures but was not a hard blocker. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_BUDGET            (1U << 1)
/** Experiment plan has open rows but was not a hard blocker. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_EXPERIMENTS       (1U << 2)
/** Packet is WARN/FAIL but packet pass was not required. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_PACKET            (1U << 3)
/** Audit is WARN but audit pass was not required. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_AUDIT             (1U << 4)
/** Score is below warning floor but not hard-blocking. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_SCORE_FLOOR       (1U << 5)
/** Review remains local/simulation oriented according to upstream audit. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_REVIEW_LIMITED    (1U << 6)

/** All deployment release gate warning bits known by this API version. */
#define PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_PIPELINE_GAPS | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_BUDGET | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_EXPERIMENTS | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_PACKET | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_AUDIT | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_SCORE_FLOOR | \
	 PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_REVIEW_LIMITED)

/** Release gate policy profile. */
enum pqcp_deployment_release_gate_profile {
	PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE = 0,
	PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER,
	PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
	PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER,
};

/** Overall release gate status. */
enum pqcp_deployment_release_gate_status {
	PQCP_DEPLOYMENT_RELEASE_GATE_FAIL = 0,
	PQCP_DEPLOYMENT_RELEASE_GATE_WARN,
	PQCP_DEPLOYMENT_RELEASE_GATE_PASS,
};

/** Firmware-side policy for one deployment release gate profile. */
struct pqcp_deployment_release_gate_policy {
	/** Profile represented by this policy. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Minimum readiness score. */
	uint32_t min_readiness_score;
	/** Minimum claim matrix score. */
	uint32_t min_claim_score;
	/** Minimum review packet score. */
	uint32_t min_review_score;
	/** Maximum blocking experiment rows allowed. */
	uint32_t max_blocking_experiments;
	/** Maximum total open experiment rows allowed. */
	uint32_t max_total_experiments;
	/** Treat score floor misses as hard blockers. */
	bool score_floor_blocks;
	/** Require pipeline result to pass. */
	bool require_pipeline_pass;
	/** Require budget report to pass. */
	bool require_budget_pass;
	/** Require experiment plan to pass. */
	bool require_experiment_plan_pass;
	/** Require review packet status to pass. */
	bool require_packet_pass;
	/** Require replay verifier to pass. */
	bool require_replay_pass;
	/** Require review audit status to pass. */
	bool require_audit_pass;
	/** Require packet/replay/audit packet digests to agree. */
	bool require_digest_binding;
};

/** Complete firmware-side deployment release gate report. */
struct pqcp_deployment_release_gate_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Policy profile evaluated. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Overall gate status. */
	enum pqcp_deployment_release_gate_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Candidate count from the pipeline. */
	uint32_t candidate_count;
	/** Open gap count from the pipeline. */
	uint32_t gap_count;
	/** Blocking experiment row count. */
	uint32_t blocking_experiment_count;
	/** Total experiment row count. */
	uint32_t experiment_count;
	/** Readiness score used for gating. */
	uint32_t readiness_score;
	/** Claim score used for gating. */
	uint32_t claim_score;
	/** Review score used for gating. */
	uint32_t review_score;
	/** Deterministic gate score from 0 to 100. */
	uint32_t gate_score;
	/** True when top candidate matched across summaries. */
	bool top_consistent;
	/** True when packet/replay/audit digest binding matched. */
	bool digest_bound;
	/** True when pipeline passed. */
	bool pipeline_passed;
	/** True when budget passed. */
	bool budget_passed;
	/** True when experiment plan passed. */
	bool experiment_plan_passed;
	/** True when review packet passed. */
	bool packet_passed;
	/** True when replay verifier passed. */
	bool replay_passed;
	/** True when review audit passed. */
	bool audit_passed;
	/** Stable top candidate identifier, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Trace digest copied from the pipeline/review chain. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Packet digest copied from the review chain. */
	char packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
};

/** Convert release gate status to a stable marker token. */
const char *pqcp_deployment_release_gate_status_str(
	enum pqcp_deployment_release_gate_status status);

/** Convert release gate profile to a stable marker token. */
const char *pqcp_deployment_release_gate_profile_str(
	enum pqcp_deployment_release_gate_profile profile);

/** Build a default policy for one release gate profile. */
int pqcp_deployment_release_gate_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_release_gate_policy *policy);

/** Evaluate a deployment release gate from already-built evidence summaries. */
int pqcp_deployment_release_gate_evaluate(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const struct pqcp_deployment_review_packet *packet,
	const struct pqcp_deployment_review_verifier_result *replay,
	const struct pqcp_deployment_review_audit_report *audit,
	const struct pqcp_deployment_release_gate_policy *policy,
	struct pqcp_deployment_release_gate_report *report);

/** Emit one stable deployment release gate marker. */
int pqcp_deployment_release_gate_emit(
	const struct pqcp_deployment_release_gate_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_RELEASE_GATE_H_ */
