/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment evidence seal replay audit
 *
 * Stability: experimental evidence API. This module aggregates one or more
 * replayed deployment evidence seals, detects replay failure, seal status
 * weakness, top/nonce/digest drift, capability drift, profile drift, and
 * score-floor weakness, then emits a compact firmware-native audit marker.
 * It performs no cryptographic operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_seal_replay.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment evidence seal audit reports and markers. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_SCHEMA_VERSION 1U

/** Maximum replay results accepted by the seal audit API. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_MAX_RESULTS 16U

/** Hex characters in a deployment evidence seal audit digest. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_DIGEST_HEX_CHARS 64U

/** Audit input pointer, count, or policy was invalid. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_INVALID_INPUT (1U << 0)
/** No replay results were supplied. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_NO_RESULTS    (1U << 1)
/** At least one seal replay result failed. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_REPLAY_FAILED (1U << 2)
/** Seal status was below the policy requirement. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_SEAL_STATUS   (1U << 3)
/** Replay top candidate changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_TOP_DRIFT     (1U << 4)
/** Replay nonce changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_NONCE_DRIFT   (1U << 5)
/** Recomputed seal digest changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_DIGEST_DRIFT  (1U << 6)
/** Evidence capability mask changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_CAPABILITY_DRIFT (1U << 7)
/** Seal status changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_STATUS_DRIFT  (1U << 8)
/** Release profile changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_PROFILE_DRIFT (1U << 9)
/** A score field was outside the stable 0-100 range. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_SCORE_RANGE   (1U << 10)
/** Replay result schema, marker set, or mandatory fields were malformed. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_MALFORMED_RESULT (1U << 11)
/** Required terminal-chain capability evidence was not present. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_MISSING_CAPABILITY (1U << 12)

/** All deployment evidence seal audit error bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_NO_RESULTS | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_REPLAY_FAILED | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_SEAL_STATUS | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_TOP_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_NONCE_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_DIGEST_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_CAPABILITY_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_STATUS_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_PROFILE_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_SCORE_RANGE | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_MALFORMED_RESULT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_ERROR_MISSING_CAPABILITY)

/** Fewer replay samples than the requested audit depth were supplied. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_LOW_SAMPLE_COUNT (1U << 0)
/** Seal status is WARN/FAIL but policy only required replay integrity. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_SEAL_NOT_PASS (1U << 1)
/** Seal score is below the configured warning threshold. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_LOW_SEAL_SCORE (1U << 2)
/** Terminal score is below the configured warning threshold. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_LOW_TERMINAL_SCORE (1U << 3)
/** Seal digests differ but digest stability was not a hard requirement. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_DIGEST_DIVERSITY (1U << 4)
/** Capability masks differ but capability stability was not a hard requirement. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_CAPABILITY_DIVERSITY (1U << 5)

/** All deployment evidence seal audit warning bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_LOW_SAMPLE_COUNT | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_SEAL_NOT_PASS | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_LOW_SEAL_SCORE | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_LOW_TERMINAL_SCORE | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_DIGEST_DIVERSITY | \
	 PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARNING_CAPABILITY_DIVERSITY)

/** Overall deployment evidence seal audit status. */
enum pqcp_deployment_evidence_seal_audit_status {
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_FAIL = 0,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARN,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS,
};

/** Policy controlling seal replay aggregation. */
struct pqcp_deployment_evidence_seal_audit_policy {
	/** Minimum replay results desired for the audit. */
	uint32_t minimum_results;
	/** Minimum accepted seal score before warning. */
	uint32_t seal_score_warn_floor;
	/** Minimum accepted terminal score before warning. */
	uint32_t terminal_score_warn_floor;
	/** Require every seal replay result to pass. */
	bool require_replay_pass;
	/** Require every seal status to be PASS. */
	bool require_seal_pass;
	/** Require every replay result to use the same top candidate. */
	bool require_stable_top;
	/** Require every replay result to use the same nonce. */
	bool require_stable_nonce;
	/** Require every replay result to use the same seal digest. */
	bool require_stable_digest;
	/** Require every replay result to use the same capability mask. */
	bool require_stable_capabilities;
	/** Require every replay result to use the same seal status. */
	bool require_stable_seal_status;
	/** Require every replay result to use the same release profile. */
	bool require_stable_profile;
	/** Require verdict, verdict-replay, and verdict-audit capability bits. */
	bool require_chain_capability;
};

/** Firmware-side aggregate report over replayed evidence seals. */
struct pqcp_deployment_evidence_seal_audit_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall audit status. */
	enum pqcp_deployment_evidence_seal_audit_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Representative release profile. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Number of replay results audited. */
	uint32_t result_count;
	/** Number of replay results that passed. */
	uint32_t replay_pass_count;
	/** Number of replay results that failed. */
	uint32_t replay_fail_count;
	/** Number of seals with status PASS. */
	uint32_t seal_pass_count;
	/** Number of seals with status WARN. */
	uint32_t seal_warn_count;
	/** Number of seals with status FAIL. */
	uint32_t seal_fail_count;
	/** Number of distinct recomputed seal digests. */
	uint32_t unique_seal_digest_count;
	/** Minimum seal score observed. */
	uint32_t min_seal_score;
	/** Maximum seal score observed. */
	uint32_t max_seal_score;
	/** Integer average seal score observed. */
	uint32_t avg_seal_score;
	/** Minimum terminal score observed. */
	uint32_t min_terminal_score;
	/** Maximum terminal score observed. */
	uint32_t max_terminal_score;
	/** Integer average terminal score observed. */
	uint32_t avg_terminal_score;
	/** Bitwise AND of evidence capability masks across all results. */
	uint32_t evidence_capabilities_all;
	/** Bitwise OR of evidence capability masks across all results. */
	uint32_t evidence_capabilities_any;
	/** True when every result used the same top candidate. */
	bool stable_top_candidate;
	/** True when every result used the same nonce. */
	bool stable_nonce;
	/** True when every result used the same recomputed seal digest. */
	bool stable_seal_digest;
	/** True when every result used the same capability mask. */
	bool stable_capabilities;
	/** True when every result used the same seal status. */
	bool stable_seal_status;
	/** True when every result used the same release profile. */
	bool stable_profile;
	/** Representative top candidate, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Representative nonce. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Representative recomputed seal digest. */
	char seal_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U];
	/** Stable digest over the audited replay result summaries. */
	char audit_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_DIGEST_HEX_CHARS + 1U];
};

/** Convert deployment evidence seal audit status to a stable marker token. */
const char *pqcp_deployment_evidence_seal_audit_status_str(
	enum pqcp_deployment_evidence_seal_audit_status status);

/** Populate a conservative default seal audit policy. */
int pqcp_deployment_evidence_seal_audit_default_policy(
	struct pqcp_deployment_evidence_seal_audit_policy *policy);

/** Run a firmware-side audit over one or more replayed seal results. */
int pqcp_deployment_evidence_seal_audit_run(
	const struct pqcp_deployment_evidence_seal_replay_result *results,
	size_t result_count,
	const struct pqcp_deployment_evidence_seal_audit_policy *policy,
	struct pqcp_deployment_evidence_seal_audit_report *report);

/** Emit a stable deployment evidence seal audit marker. */
int pqcp_deployment_evidence_seal_audit_emit(
	const struct pqcp_deployment_evidence_seal_audit_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_H_ */
