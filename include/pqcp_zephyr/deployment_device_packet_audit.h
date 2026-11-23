/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment device-packet replay audit
 *
 * Stability: experimental evidence API. This module aggregates one or more
 * replayed deployment device packets, detects replay failure, packet status
 * weakness, top/nonce/digest drift, capability drift, and score-floor weakness,
 * then emits a compact firmware-native audit marker.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_DEVICE_PACKET_AUDIT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_DEVICE_PACKET_AUDIT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_device_packet_replay.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment device-packet audit reports and markers. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_SCHEMA_VERSION 1U

/** Maximum replay results accepted by the device-packet audit API. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_MAX_RESULTS 16U

/** Hex characters in a deployment device-packet audit digest. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_DIGEST_HEX_CHARS 64U

/** Audit input pointer, count, or policy was invalid. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_INVALID_INPUT (1U << 0)
/** No replay results were supplied. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_NO_RESULTS    (1U << 1)
/** At least one device-packet replay result failed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_REPLAY_FAILED (1U << 2)
/** Packet status was below the policy requirement. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_PACKET_STATUS (1U << 3)
/** Replay top candidate changed across audited results. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_TOP_DRIFT     (1U << 4)
/** Replay nonce changed across audited results. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_NONCE_DRIFT   (1U << 5)
/** Recomputed packet digest changed across audited results. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_DIGEST_DRIFT  (1U << 6)
/** Evidence capability mask changed across audited results. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_CAPABILITY_DRIFT (1U << 7)
/** Packet status changed across audited results. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_STATUS_DRIFT  (1U << 8)
/** A score field was outside the stable 0-100 range. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_SCORE_RANGE   (1U << 9)
/** Replay result schema, marker set, or mandatory fields were malformed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_MALFORMED_RESULT (1U << 10)
/** Required device-packet replay capability evidence was not present. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_MISSING_CAPABILITY (1U << 11)

/** All deployment device-packet audit error bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_NO_RESULTS | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_REPLAY_FAILED | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_PACKET_STATUS | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_TOP_DRIFT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_NONCE_DRIFT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_DIGEST_DRIFT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_CAPABILITY_DRIFT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_STATUS_DRIFT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_SCORE_RANGE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_MALFORMED_RESULT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_MISSING_CAPABILITY)

/** Fewer replay samples than the requested audit depth were supplied. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_SAMPLE_COUNT (1U << 0)
/** Packet status is WARN/FAIL but policy only required replay integrity. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_PACKET_NOT_PASS (1U << 1)
/** Capability readiness score is below the configured warning threshold. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_CAPABILITY_SCORE (1U << 2)
/** Release-gate score is below the configured warning threshold. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_RELEASE_SCORE (1U << 3)
/** Device-token audit gate score is below the configured warning threshold. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_AUDIT_SCORE (1U << 4)
/** Packet digests differ but digest stability was not a hard requirement. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_DIGEST_DIVERSITY (1U << 5)
/** Capability masks differ but capability stability was not a hard requirement. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_CAPABILITY_DIVERSITY (1U << 6)

/** All deployment device-packet audit warning bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_SAMPLE_COUNT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_PACKET_NOT_PASS | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_CAPABILITY_SCORE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_RELEASE_SCORE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_AUDIT_SCORE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_DIGEST_DIVERSITY | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_CAPABILITY_DIVERSITY)

/** Overall deployment device-packet audit status. */
enum pqcp_deployment_device_packet_audit_status {
	PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL = 0,
	PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN,
	PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS,
};

/** Policy controlling device-packet replay aggregation. */
struct pqcp_deployment_device_packet_audit_policy {
	/** Minimum replay results desired for the audit. */
	uint32_t minimum_results;
	/** Minimum accepted capability readiness before warning. */
	uint32_t capability_score_warn_floor;
	/** Minimum accepted release-gate score before warning. */
	uint32_t release_score_warn_floor;
	/** Minimum accepted token-audit gate score before warning. */
	uint32_t audit_score_warn_floor;
	/** Require every packet replay result to pass. */
	bool require_replay_pass;
	/** Require every packet status to be PASS. */
	bool require_packet_pass;
	/** Require every replay result to use the same top candidate. */
	bool require_stable_top;
	/** Require every replay result to use the same nonce. */
	bool require_stable_nonce;
	/** Require every replay result to use the same packet digest. */
	bool require_stable_digest;
	/** Require every replay result to use the same capability mask. */
	bool require_stable_capabilities;
	/** Require every replay result to use the same packet status. */
	bool require_stable_packet_status;
	/** Require the packet replay capability bit in evidence masks. */
	bool require_replay_capability;
};

/** Firmware-side aggregate report over replayed device-packet evidence. */
struct pqcp_deployment_device_packet_audit_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall audit status. */
	enum pqcp_deployment_device_packet_audit_status status;
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
	/** Number of packets with status PASS. */
	uint32_t packet_pass_count;
	/** Number of packets with status WARN. */
	uint32_t packet_warn_count;
	/** Number of packets with status FAIL. */
	uint32_t packet_fail_count;
	/** Number of distinct recomputed packet digests. */
	uint32_t unique_packet_digest_count;
	/** Minimum capability readiness score observed. */
	uint32_t min_capability_readiness_score;
	/** Minimum release gate score observed. */
	uint32_t min_release_gate_score;
	/** Maximum release gate score observed. */
	uint32_t max_release_gate_score;
	/** Integer average release gate score observed. */
	uint32_t avg_release_gate_score;
	/** Minimum token-audit gate score observed. */
	uint32_t min_audit_gate_score;
	/** Maximum token-audit gate score observed. */
	uint32_t max_audit_gate_score;
	/** Integer average token-audit gate score observed. */
	uint32_t avg_audit_gate_score;
	/** Bitwise AND of evidence capability masks across all results. */
	uint32_t evidence_capabilities_all;
	/** Bitwise OR of evidence capability masks across all results. */
	uint32_t evidence_capabilities_any;
	/** True when every result used the same top candidate. */
	bool stable_top_candidate;
	/** True when every result used the same nonce. */
	bool stable_nonce;
	/** True when every result used the same recomputed packet digest. */
	bool stable_packet_digest;
	/** True when every result used the same capability mask. */
	bool stable_capabilities;
	/** True when every result used the same packet status. */
	bool stable_packet_status;
	/** Representative top candidate, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Representative nonce. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Representative recomputed packet digest. */
	char packet_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Stable digest over the audited replay result summaries. */
	char audit_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_DIGEST_HEX_CHARS + 1U];
};

/** Convert deployment device-packet audit status to a stable marker token. */
const char *pqcp_deployment_device_packet_audit_status_str(
	enum pqcp_deployment_device_packet_audit_status status);

/** Populate a conservative default device-packet audit policy. */
int pqcp_deployment_device_packet_audit_default_policy(
	struct pqcp_deployment_device_packet_audit_policy *policy);

/** Run a firmware-side audit over one or more replayed device-packet results. */
int pqcp_deployment_device_packet_audit_run(
	const struct pqcp_deployment_device_packet_replay_result *results,
	size_t result_count,
	const struct pqcp_deployment_device_packet_audit_policy *policy,
	struct pqcp_deployment_device_packet_audit_report *report);

/** Emit a stable deployment device-packet audit marker. */
int pqcp_deployment_device_packet_audit_emit(
	const struct pqcp_deployment_device_packet_audit_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_DEVICE_PACKET_AUDIT_H_ */
