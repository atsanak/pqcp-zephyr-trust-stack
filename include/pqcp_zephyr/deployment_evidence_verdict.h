/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment evidence verdict
 *
 * Stability: experimental evidence API. This module consumes the already-built
 * firmware deployment evidence chain and emits one deterministic verdict over
 * pipeline, review, release, device, packet, replay, audit, and capability
 * summaries. It performs no cryptographic operation and uses no dynamic
 * allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_VERDICT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_VERDICT_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_device_packet_audit.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment evidence verdict reports and markers. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_SCHEMA_VERSION 1U

/** Hex characters in a deployment evidence verdict digest. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS 64U

/** Required pointer, schema, or policy input was invalid. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_INVALID_INPUT       (1U << 0)
/** Capability descriptor failed policy or did not advertise required evidence. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_CAPABILITY          (1U << 1)
/** Deployment pipeline failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_PIPELINE            (1U << 2)
/** Budget report failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_BUDGET              (1U << 3)
/** Experiment plan failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_EXPERIMENTS         (1U << 4)
/** Review packet failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_PACKET       (1U << 5)
/** Review replay failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_REPLAY       (1U << 6)
/** Review audit failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_AUDIT        (1U << 7)
/** Release gate failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_RELEASE_GATE        (1U << 8)
/** Device token failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_TOKEN        (1U << 9)
/** Device token replay/audit failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOKEN_REPLAY_AUDIT  (1U << 10)
/** Device gate failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_GATE         (1U << 11)
/** Device packet failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_PACKET       (1U << 12)
/** Device packet replay/audit failed required evidence policy. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_PACKET_REPLAY_AUDIT (1U << 13)
/** Top candidate IDs disagreed across the evidence chain. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOP_MISMATCH        (1U << 14)
/** Nonce values disagreed across the device-bound evidence chain. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_NONCE_MISMATCH      (1U << 15)
/** Trace digest values disagreed across the review/release/device chain. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TRACE_DIGEST        (1U << 16)
/** Review-packet digest values disagreed across release/device evidence. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_DIGEST       (1U << 17)
/** Device-packet digest values disagreed across packet replay/audit evidence. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_DIGEST       (1U << 18)
/** Device-token digest values disagreed across token/replay/audit evidence. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOKEN_DIGEST        (1U << 19)
/** Evidence capability masks disagreed or required bits were absent. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_CAPABILITY_MISMATCH (1U << 20)
/** Required score floor was not met. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_SCORE_FLOOR         (1U << 21)

/** All deployment evidence verdict error bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_CAPABILITY | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_PIPELINE | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_BUDGET | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_EXPERIMENTS | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_PACKET | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_REPLAY | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_AUDIT | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_RELEASE_GATE | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_TOKEN | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOKEN_REPLAY_AUDIT | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_GATE | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_PACKET | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_PACKET_REPLAY_AUDIT | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOP_MISMATCH | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_NONCE_MISMATCH | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TRACE_DIGEST | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_DIGEST | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_DIGEST | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOKEN_DIGEST | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_CAPABILITY_MISMATCH | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_SCORE_FLOOR)

/** One or more upstream evidence summaries produced review-visible warnings. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_UPSTREAM_WARNINGS (1U << 0)
/** Chain is internally replayable but not all product gates passed. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_NOT_PRODUCT_PASS  (1U << 1)
/** Score is below warning floor but not hard-blocking. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_SCORE_FLOOR       (1U << 2)
/** Review evidence remains local/simulation oriented. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_LOCAL_ONLY        (1U << 3)
/** Device packet status is WARN/FAIL but packet pass was not required. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_DEVICE_PACKET     (1U << 4)
/** Packet audit status is WARN but audit pass was not required. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_PACKET_AUDIT      (1U << 5)

/** All deployment evidence verdict warning bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_UPSTREAM_WARNINGS | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_NOT_PRODUCT_PASS | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_SCORE_FLOOR | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_LOCAL_ONLY | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_DEVICE_PACKET | \
	 PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_PACKET_AUDIT)

/** Overall deployment evidence verdict status. */
enum pqcp_deployment_evidence_verdict_status {
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL = 0,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS,
};

/** Policy controlling final deployment evidence verdict generation. */
struct pqcp_deployment_evidence_verdict_policy {
	/** Policy profile represented by the verdict. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Minimum final score accepted before warning or failure. */
	uint32_t min_verdict_score;
	/** Minimum release gate score accepted before warning or failure. */
	uint32_t min_release_gate_score;
	/** Minimum review packet score accepted before warning or failure. */
	uint32_t min_review_score;
	/** Minimum capability readiness accepted before warning or failure. */
	uint32_t min_capability_readiness_score;
	/** Treat score floor misses as hard blockers. */
	bool score_floor_blocks;
	/** Require all upstream status fields to be PASS. */
	bool require_all_pass;
	/** Require the pipeline stage to pass. */
	bool require_pipeline_pass;
	/** Require budget and experiment-plan stages to pass. */
	bool require_planning_pass;
	/** Require review packet, replay, and audit stages to pass. */
	bool require_review_pass;
	/** Require release gate status PASS. */
	bool require_release_gate_pass;
	/** Require device token, replay, and token audit PASS. */
	bool require_device_token_pass;
	/** Require device gate status PASS. */
	bool require_device_gate_pass;
	/** Require device packet status PASS. */
	bool require_device_packet_pass;
	/** Require device packet replay and packet audit PASS. */
	bool require_device_packet_audit_pass;
	/** Require cross-chain digest and identity consistency. */
	bool require_digest_consistency;
	/** Require final verdict capability bit to be visible. */
	bool require_verdict_capability;
};

/** Final firmware-side verdict over the complete deployment evidence chain. */
struct pqcp_deployment_evidence_verdict {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall verdict status. */
	enum pqcp_deployment_evidence_verdict_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Policy profile evaluated. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Final deterministic verdict score from 0 to 100. */
	uint32_t verdict_score;
	/** Lowest upstream score used by the verdict. */
	uint32_t min_chain_score;
	/** Number of upstream stages represented by this verdict. */
	uint32_t stage_count;
	/** Number of upstream stages with PASS status. */
	uint32_t pass_count;
	/** Number of upstream stages with WARN status. */
	uint32_t warn_count;
	/** Number of upstream stages with FAIL status. */
	uint32_t fail_count;
	/** Number of cross-chain consistency checks performed. */
	uint32_t consistency_checks;
	/** Number of cross-chain consistency checks that passed. */
	uint32_t consistency_pass_count;
	/** Capability evidence bits present in every relevant evidence summary. */
	uint32_t evidence_capabilities_all;
	/** Capability evidence bits present in at least one evidence summary. */
	uint32_t evidence_capabilities_any;
	/** True when all top-candidate IDs matched. */
	bool top_consistent;
	/** True when all device nonces matched. */
	bool nonce_consistent;
	/** True when trace digests matched across review/release/device evidence. */
	bool trace_digest_consistent;
	/** True when review packet digests matched across release/device evidence. */
	bool review_packet_digest_consistent;
	/** True when device packet digests matched across replay/audit evidence. */
	bool device_packet_digest_consistent;
	/** True when token digests matched across token/replay/audit evidence. */
	bool token_digest_consistent;
	/** Stable top candidate identifier, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce, or all-zero nonce when no device token is present. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Stable trace digest. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Stable review packet digest. */
	char review_packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Stable device packet digest. */
	char device_packet_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Stable token digest. */
	char token_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	/** Stable packet-audit digest. */
	char packet_audit_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_DIGEST_HEX_CHARS + 1U];
	/** Stable digest over the final verdict summary. */
	char verdict_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U];
};

/** Convert deployment evidence verdict status to a stable marker token. */
const char *pqcp_deployment_evidence_verdict_status_str(
	enum pqcp_deployment_evidence_verdict_status status);

/** Populate a default deployment evidence verdict policy for one profile. */
int pqcp_deployment_evidence_verdict_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_evidence_verdict_policy *policy);

/** Evaluate the final firmware-native deployment evidence verdict. */
int pqcp_deployment_evidence_verdict_evaluate(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const struct pqcp_deployment_review_packet *review_packet,
	const struct pqcp_deployment_review_verifier_result *review_replay,
	const struct pqcp_deployment_review_audit_report *review_audit,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *device_token,
	const struct pqcp_deployment_device_token_verification *token_verify,
	const struct pqcp_deployment_device_token_replay_result *token_replay,
	const struct pqcp_deployment_device_token_audit_report *token_audit,
	const struct pqcp_deployment_device_gate_report *device_gate,
	const struct pqcp_deployment_device_packet *device_packet,
	const struct pqcp_deployment_device_packet_replay_result *packet_replay,
	const struct pqcp_deployment_device_packet_audit_report *packet_audit,
	const struct pqcp_deployment_evidence_verdict_policy *policy,
	struct pqcp_deployment_evidence_verdict *verdict);

/** Emit one stable deployment evidence verdict marker. */
int pqcp_deployment_evidence_verdict_emit(
	const struct pqcp_deployment_evidence_verdict *verdict);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_VERDICT_H_ */
