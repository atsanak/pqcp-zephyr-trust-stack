/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment device evidence gate
 *
 * Stability: experimental evidence API. This module appraises the complete
 * device-bound deployment evidence chain in firmware: capability descriptor,
 * release gate, nonce-bound device token, token verification, transcript
 * replay, and replay audit. It performs deterministic consistency checks and
 * emits one final PQCP_DEPLOYMENT_DEVICE_GATE marker without dynamic
 * allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_DEVICE_GATE_H_
#define PQCP_ZEPHYR_DEPLOYMENT_DEVICE_GATE_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/capability_descriptor.h>
#include <pqcp_zephyr/deployment_device_token_audit.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment device-gate reports and markers. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_SCHEMA_VERSION 1U

/** Required pointer, profile, or policy input was invalid. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_INVALID_INPUT      (1U << 0)
/** Capability descriptor failed validation or firmware policy. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_CAPABILITY         (1U << 1)
/** Required evidence capability bit was not present. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_MISSING_CAPABILITY (1U << 2)
/** Capability descriptor was not production-allowed when required. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PRODUCTION         (1U << 3)
/** Capability provider summary was not PQCP native when required. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PROVIDER           (1U << 4)
/** Release gate status was below the policy requirement. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_RELEASE_GATE       (1U << 5)
/** Device token status was below the policy requirement. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOKEN              (1U << 6)
/** Device token verification failed. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_VERIFY             (1U << 7)
/** Device token replay failed. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_REPLAY             (1U << 8)
/** Device token replay audit status was below the policy requirement. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_AUDIT              (1U << 9)
/** Evidence profiles disagreed. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PROFILE_MISMATCH   (1U << 10)
/** Top candidate identifiers disagreed across the evidence chain. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOP_MISMATCH       (1U << 11)
/** Nonce values disagreed across token, replay, and audit evidence. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_NONCE_MISMATCH     (1U << 12)
/** Token digest values disagreed across token, verification, replay, or audit. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOKEN_DIGEST       (1U << 13)
/** Trace or packet digest values disagreed across token and release gate. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_RELEASE_DIGEST     (1U << 14)
/** Score floor required by policy was not met. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_SCORE_FLOOR        (1U << 15)

/** All deployment device-gate error bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_CAPABILITY | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_MISSING_CAPABILITY | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PRODUCTION | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PROVIDER | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_RELEASE_GATE | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOKEN | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_VERIFY | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_REPLAY | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_AUDIT | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PROFILE_MISMATCH | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOP_MISMATCH | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_NONCE_MISMATCH | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOKEN_DIGEST | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_RELEASE_DIGEST | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_SCORE_FLOOR)

/** Capability descriptor is not production-allowed but policy permits review. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_NOT_PRODUCTION    (1U << 0)
/** Provider summary is not PQCP native but policy permits review. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_NON_NATIVE        (1U << 1)
/** Release gate status is WARN/FAIL but policy permits review. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_RELEASE_GATE      (1U << 2)
/** Token status is WARN/FAIL but policy permits review. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_TOKEN             (1U << 3)
/** Replay audit is WARN/FAIL but policy permits review. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_AUDIT             (1U << 4)
/** Capability readiness score is below warning floor. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_CAPABILITY_SCORE  (1U << 5)
/** Release gate score is below warning floor. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_GATE_SCORE        (1U << 6)
/** Replay audit gate score is below warning floor. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_AUDIT_SCORE       (1U << 7)

/** All deployment device-gate warning bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_NOT_PRODUCTION | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_NON_NATIVE | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_RELEASE_GATE | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_TOKEN | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_AUDIT | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_CAPABILITY_SCORE | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_GATE_SCORE | \
	 PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_AUDIT_SCORE)

/** Overall deployment device-gate status. */
enum pqcp_deployment_device_gate_status {
	PQCP_DEPLOYMENT_DEVICE_GATE_FAIL = 0,
	PQCP_DEPLOYMENT_DEVICE_GATE_WARN,
	PQCP_DEPLOYMENT_DEVICE_GATE_PASS,
};

/** Policy controlling complete device-evidence acceptance. */
struct pqcp_deployment_device_gate_policy {
	/** Release-gate profile this policy appraises. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Minimum capability readiness before warning or failure. */
	uint32_t min_capability_readiness_score;
	/** Minimum release gate score before warning or failure. */
	uint32_t min_release_gate_score;
	/** Minimum audit gate score before warning or failure. */
	uint32_t min_audit_gate_score;
	/** Treat score-floor misses as hard blockers. */
	bool score_floor_blocks;
	/** Require descriptor firmware policy to pass. */
	bool require_capability_policy_pass;
	/** Require descriptor production_allowed. */
	bool require_production_allowed;
	/** Require PQCP-native provider summary. */
	bool require_native_provider;
	/** Require the device-token audit capability bit. */
	bool require_device_token_audit_capability;
	/** Require release gate status PASS. */
	bool require_release_gate_pass;
	/** Require device token status PASS. */
	bool require_token_pass;
	/** Require device token verification PASS. */
	bool require_verification_pass;
	/** Require token replay PASS. */
	bool require_replay_pass;
	/** Require token audit PASS. */
	bool require_audit_pass;
	/** Require cross-evidence top candidate consistency. */
	bool require_top_consistency;
	/** Require cross-evidence nonce consistency. */
	bool require_nonce_consistency;
	/** Require cross-evidence token digest consistency. */
	bool require_token_digest_consistency;
	/** Require release gate trace/packet digests to match the token. */
	bool require_release_digest_consistency;
};

/** Complete firmware-side report over the device-bound evidence chain. */
struct pqcp_deployment_device_gate_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Policy profile evaluated. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Overall gate status. */
	enum pqcp_deployment_device_gate_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Capability evidence mask copied from descriptor. */
	uint32_t evidence_capabilities;
	/** Capability readiness score copied from descriptor. */
	uint32_t capability_readiness_score;
	/** Release gate score copied from release gate. */
	uint32_t release_gate_score;
	/** Minimum gate score copied from token audit. */
	uint32_t audit_min_gate_score;
	/** Release gate status. */
	enum pqcp_deployment_release_gate_status release_gate_status;
	/** Device token status. */
	enum pqcp_deployment_device_token_status token_status;
	/** Device token audit status. */
	enum pqcp_deployment_device_token_audit_status audit_status;
	/** True when descriptor firmware policy passed. */
	bool capability_policy_passed;
	/** True when descriptor allows production interpretation. */
	bool production_allowed;
	/** True when provider summary is PQCP native. */
	bool native_provider;
	/** True when device token verification passed. */
	bool verification_passed;
	/** True when token transcript replay passed. */
	bool replay_passed;
	/** True when top candidate IDs matched. */
	bool top_consistent;
	/** True when nonces matched. */
	bool nonce_consistent;
	/** True when token digests matched. */
	bool token_digest_consistent;
	/** True when release trace/packet digest binding matched. */
	bool release_digest_consistent;
	/** Stable top candidate identifier, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Trace digest copied from release gate. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Packet digest copied from release gate. */
	char packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Device token digest. */
	char token_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
};

/** Convert deployment device-gate status to a stable marker token. */
const char *pqcp_deployment_device_gate_status_str(
	enum pqcp_deployment_device_gate_status status);

/** Populate a default device-gate policy for one profile. */
int pqcp_deployment_device_gate_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_device_gate_policy *policy);

/** Evaluate complete device-bound deployment evidence under one policy. */
int pqcp_deployment_device_gate_evaluate(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_policy *policy,
	struct pqcp_deployment_device_gate_report *report);

/** Emit one stable deployment device-gate marker. */
int pqcp_deployment_device_gate_emit(
	const struct pqcp_deployment_device_gate_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_DEVICE_GATE_H_ */
