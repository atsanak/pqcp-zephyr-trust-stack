/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment device-token replay audit
 *
 * Stability: experimental evidence API. This module aggregates one or more
 * replayed deployment device-token transcripts and detects replay failure,
 * nonce drift, top-candidate drift, token-digest drift, status drift, and
 * score-floor weakness without dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_DEVICE_TOKEN_AUDIT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_DEVICE_TOKEN_AUDIT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_device_token_replay.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment device-token audit reports and markers. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_SCHEMA_VERSION 1U

/** Maximum replay results accepted by the device-token audit API. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_MAX_RESULTS 16U

/** Audit input pointer, count, or policy was invalid. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_INVALID_INPUT (1U << 0)
/** No replay results were supplied. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_NO_RESULTS    (1U << 1)
/** At least one replay result failed. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_REPLAY_FAILED (1U << 2)
/** Replay nonce changed across audited results. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_NONCE_DRIFT   (1U << 3)
/** Top candidate changed across audited results. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOP_DRIFT     (1U << 4)
/** Token digest changed across audited results. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOKEN_DIGEST_DRIFT (1U << 5)
/** Gate status changed across audited results. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_GATE_STATUS_DRIFT (1U << 6)
/** Token status was below the policy requirement. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOKEN_STATUS  (1U << 7)
/** Gate status was below the policy requirement. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_GATE_STATUS   (1U << 8)
/** A score field was outside the stable 0-100 range. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_SCORE_RANGE   (1U << 9)
/** Replay result schema, marker set, or mandatory fields were malformed. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_MALFORMED_RESULT (1U << 10)

/** All deployment device-token audit error bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_NO_RESULTS | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_REPLAY_FAILED | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_NONCE_DRIFT | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOP_DRIFT | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOKEN_DIGEST_DRIFT | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_GATE_STATUS_DRIFT | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOKEN_STATUS | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_GATE_STATUS | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_SCORE_RANGE | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_MALFORMED_RESULT)

/** Fewer replay samples than the requested audit depth were supplied. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_SAMPLE_COUNT (1U << 0)
/** Token status is WARN/FAIL but policy only required replay integrity. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_TOKEN_NOT_PASS   (1U << 1)
/** Gate status is WARN/FAIL but policy only required replay integrity. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_GATE_NOT_PASS    (1U << 2)
/** Capability readiness score is below the configured warning threshold. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_CAPABILITY_SCORE (1U << 3)
/** Release gate score is below the configured warning threshold. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_GATE_SCORE   (1U << 4)
/** Token digests differ but digest stability was not a hard requirement. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_TOKEN_DIVERSITY  (1U << 5)

/** All deployment device-token audit warning bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_SAMPLE_COUNT | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_TOKEN_NOT_PASS | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_GATE_NOT_PASS | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_CAPABILITY_SCORE | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_GATE_SCORE | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_TOKEN_DIVERSITY)

/** Overall deployment device-token audit status. */
enum pqcp_deployment_device_token_audit_status {
	PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL = 0,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS,
};

/** Policy controlling device-token replay aggregation. */
struct pqcp_deployment_device_token_audit_policy {
	/** Minimum replay results desired for the audit. */
	uint32_t minimum_results;
	/** Minimum accepted capability readiness before warning. */
	uint32_t capability_score_warn_floor;
	/** Minimum accepted release-gate score before warning. */
	uint32_t gate_score_warn_floor;
	/** Require every replay result to pass. */
	bool require_replay_pass;
	/** Require every token status to be PASS. */
	bool require_token_pass;
	/** Require every release gate status to be PASS. */
	bool require_gate_pass;
	/** Require every replay result to use the same nonce. */
	bool require_stable_nonce;
	/** Require every replay result to use the same top candidate. */
	bool require_stable_top;
	/** Require every replay result to use the same token digest. */
	bool require_stable_token_digest;
	/** Require every replay result to use the same gate status. */
	bool require_stable_gate_status;
};

/** Firmware-side aggregate report over replayed device-token evidence. */
struct pqcp_deployment_device_token_audit_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall audit status. */
	enum pqcp_deployment_device_token_audit_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Number of replay results audited. */
	uint32_t result_count;
	/** Number of replay results that passed. */
	uint32_t replay_pass_count;
	/** Number of replay results that failed. */
	uint32_t replay_fail_count;
	/** Number of tokens with status PASS. */
	uint32_t token_pass_count;
	/** Number of tokens with status WARN. */
	uint32_t token_warn_count;
	/** Number of tokens with status FAIL. */
	uint32_t token_fail_count;
	/** Number of release gates with status PASS. */
	uint32_t gate_pass_count;
	/** Number of release gates with status WARN. */
	uint32_t gate_warn_count;
	/** Number of release gates with status FAIL. */
	uint32_t gate_fail_count;
	/** Number of distinct token digests, saturated at result_count. */
	uint32_t unique_token_digest_count;
	/** Minimum capability readiness score observed. */
	uint32_t min_capability_readiness_score;
	/** Minimum release gate score observed. */
	uint32_t min_gate_score;
	/** Maximum release gate score observed. */
	uint32_t max_gate_score;
	/** Integer average release gate score observed. */
	uint32_t avg_gate_score;
	/** True when every result used the same nonce. */
	bool stable_nonce;
	/** True when every result used the same top candidate. */
	bool stable_top_candidate;
	/** True when every result used the same token digest. */
	bool stable_token_digest;
	/** True when every result used the same gate status. */
	bool stable_gate_status;
	/** Representative nonce. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Representative top candidate, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Representative token digest. */
	char token_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
};

/** Convert deployment device-token audit status to a stable marker token. */
const char *pqcp_deployment_device_token_audit_status_str(
	enum pqcp_deployment_device_token_audit_status status);

/** Populate a conservative default device-token audit policy. */
int pqcp_deployment_device_token_audit_default_policy(
	struct pqcp_deployment_device_token_audit_policy *policy);

/** Run a firmware-side audit over one or more replayed device-token results. */
int pqcp_deployment_device_token_audit_run(
	const struct pqcp_deployment_device_token_replay_result *results,
	size_t result_count,
	const struct pqcp_deployment_device_token_audit_policy *policy,
	struct pqcp_deployment_device_token_audit_report *report);

/** Emit a stable deployment device-token audit marker. */
int pqcp_deployment_device_token_audit_emit(
	const struct pqcp_deployment_device_token_audit_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_DEVICE_TOKEN_AUDIT_H_ */
