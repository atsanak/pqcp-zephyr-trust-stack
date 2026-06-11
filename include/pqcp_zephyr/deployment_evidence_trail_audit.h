/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment evidence trail replay audit
 *
 * Stability: experimental evidence API. This module aggregates one or more
 * replayed deployment evidence trails, detects replay failure, trail status
 * weakness, head digest drift, entry count drift, stage drift, and identity
 * drift, then emits a compact firmware-native audit marker. It performs no
 * cryptographic operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_trail_replay.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for evidence trail audit reports and markers. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_SCHEMA_VERSION 1U

/** Maximum replay results accepted by the trail audit API. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_MAX_RESULTS 16U

/** Hex characters in an evidence trail audit digest. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_DIGEST_HEX_CHARS 64U

/** Audit input pointer, count, or policy was invalid. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_INVALID_INPUT (1U << 0)
/** No replay results were supplied. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_NO_RESULTS    (1U << 1)
/** At least one trail replay result failed. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_REPLAY_FAILED (1U << 2)
/** Trail status was below the policy requirement. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_TRAIL_STATUS  (1U << 3)
/** Recomputed head digest changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_HEAD_DRIFT    (1U << 4)
/** Entry count changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_COUNT_DRIFT   (1U << 5)
/** Stage mask changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_STAGE_DRIFT   (1U << 6)
/** Release profile changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_PROFILE_DRIFT (1U << 7)
/** Replay top candidate changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_TOP_DRIFT     (1U << 8)
/** Replay nonce changed across audited results. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_NONCE_DRIFT   (1U << 9)
/** Replay result schema, marker set, or mandatory fields were malformed. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_MALFORMED_RESULT (1U << 10)

/** All evidence trail audit error bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_NO_RESULTS | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_REPLAY_FAILED | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_TRAIL_STATUS | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_HEAD_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_COUNT_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_STAGE_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_PROFILE_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_TOP_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_NONCE_DRIFT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_MALFORMED_RESULT)

/** Fewer replay samples than the requested audit depth were supplied. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARNING_LOW_SAMPLE_COUNT (1U << 0)
/** Trail status is WARN but policy only required replay integrity. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARNING_TRAIL_NOT_PASS  (1U << 1)

/** All evidence trail audit warning bits known by this API version. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARNING_LOW_SAMPLE_COUNT | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARNING_TRAIL_NOT_PASS)

/** Overall evidence trail audit status. */
enum pqcp_deployment_evidence_trail_audit_status {
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_FAIL = 0,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARN,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_PASS,
};

/** Policy controlling evidence trail replay aggregation. */
struct pqcp_deployment_evidence_trail_audit_policy {
	/** Minimum replay results desired for the audit. */
	uint32_t minimum_results;
	/** Require every trail replay result to pass. */
	bool require_replay_pass;
	/** Require every trail status to be PASS. */
	bool require_trail_pass;
	/** Require every result to share one recomputed head digest. */
	bool require_stable_head;
	/** Require every result to share one entry count. */
	bool require_stable_count;
	/** Require every result to share one stage mask. */
	bool require_stable_stages;
	/** Require every result to share one release profile. */
	bool require_stable_profile;
	/** Require every result to share one top candidate. */
	bool require_stable_top;
	/** Require every result to share one nonce. */
	bool require_stable_nonce;
};

/** Firmware-side aggregate report over replayed evidence trails. */
struct pqcp_deployment_evidence_trail_audit_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall audit status. */
	enum pqcp_deployment_evidence_trail_audit_status status;
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
	/** Number of trails with status PASS. */
	uint32_t trail_pass_count;
	/** Number of trails with status WARN. */
	uint32_t trail_warn_count;
	/** Number of trails with status FAIL. */
	uint32_t trail_fail_count;
	/** Representative entry count. */
	uint32_t entry_count;
	/** Representative observed stage mask. */
	uint32_t observed_stage_mask;
	/** True when every result used the same recomputed head digest. */
	bool stable_head_digest;
	/** True when every result used the same entry count. */
	bool stable_entry_count;
	/** True when every result used the same stage mask. */
	bool stable_stages;
	/** True when every result used the same release profile. */
	bool stable_profile;
	/** True when every result used the same top candidate. */
	bool stable_top_candidate;
	/** True when every result used the same nonce. */
	bool stable_nonce;
	/** Representative top candidate, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Representative nonce. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Representative recomputed head digest. */
	char head_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];
	/** Stable digest over the audited replay result summaries. */
	char audit_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_DIGEST_HEX_CHARS + 1U];
};

/** Convert evidence trail audit status to a stable marker token. */
const char *pqcp_deployment_evidence_trail_audit_status_str(
	enum pqcp_deployment_evidence_trail_audit_status status);

/** Populate a conservative default evidence trail audit policy. */
int pqcp_deployment_evidence_trail_audit_default_policy(
	struct pqcp_deployment_evidence_trail_audit_policy *policy);

/** Run a firmware-side audit over one or more replayed evidence trails. */
int pqcp_deployment_evidence_trail_audit_run(
	const struct pqcp_deployment_evidence_trail_replay_result *results,
	size_t result_count,
	const struct pqcp_deployment_evidence_trail_audit_policy *policy,
	struct pqcp_deployment_evidence_trail_audit_report *report);

/** Emit a stable evidence trail audit marker. */
int pqcp_deployment_evidence_trail_audit_emit(
	const struct pqcp_deployment_evidence_trail_audit_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_H_ */
