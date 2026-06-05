/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment device evidence token
 *
 * Stability: experimental evidence API. This module binds the firmware
 * capability descriptor and deployment release gate into a compact,
 * nonce-bound token that can be captured from QEMU/UART transcripts and
 * replay-checked without dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_DEVICE_TOKEN_H_
#define PQCP_ZEPHYR_DEPLOYMENT_DEVICE_TOKEN_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/capability_descriptor.h>
#include <pqcp_zephyr/deployment_release_gate.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment device token structures and markers. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION 1U

/** 128-bit nonce hex length excluding NUL. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS 32U

/** Token digest hex length excluding NUL. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS 64U

/** Device token input pointer, policy, or schema was malformed. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_INVALID_INPUT       (1U << 0)
/** Nonce was missing or was not a 128-bit hex string. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_BAD_NONCE           (1U << 1)
/** Capability descriptor failed validation. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_CAPABILITY          (1U << 2)
/** Release gate report failed validation. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_RELEASE_GATE        (1U << 3)
/** Capability descriptor does not advertise release-gate evidence support. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_MISSING_GATE_CAP    (1U << 4)
/** Capability descriptor does not advertise device-token evidence support. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_MISSING_TOKEN_CAP   (1U << 5)
/** Firmware policy was required to pass but did not. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_POLICY              (1U << 6)
/** Production interpretation was required but not allowed. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_PRODUCTION          (1U << 7)
/** PQ Code Package native provider was required but not observed. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_PROVIDER            (1U << 8)
/** Release gate was required to pass but did not. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_GATE_STATUS         (1U << 9)
/** Release gate digest binding was required but absent. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_GATE_DIGEST         (1U << 10)
/** Capability or gate score floor was not met. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_SCORE_FLOOR         (1U << 11)
/** Observed token does not match recomputed token fields. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_TOKEN_MISMATCH      (1U << 12)

/** All deployment device token error bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_BAD_NONCE | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_CAPABILITY | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_RELEASE_GATE | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_MISSING_GATE_CAP | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_MISSING_TOKEN_CAP | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_POLICY | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_PRODUCTION | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_PROVIDER | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_GATE_STATUS | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_GATE_DIGEST | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_SCORE_FLOOR | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_TOKEN_MISMATCH)

/** Release gate is WARN and policy accepts a warning token. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_GATE_WARN         (1U << 0)
/** Release gate failed but policy records it as review-visible warning. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_GATE_FAIL         (1U << 1)
/** Capability descriptor is not production-interpretable. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_NOT_PRODUCTION    (1U << 2)
/** Capability descriptor does not use the PQCP native provider family. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_NON_NATIVE        (1U << 3)
/** Score is below warning floor but not hard-blocking. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_SCORE_FLOOR       (1U << 4)

/** All deployment device token warning bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_GATE_WARN | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_GATE_FAIL | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_NOT_PRODUCTION | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_NON_NATIVE | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_SCORE_FLOOR)

/** Overall deployment device token status. */
enum pqcp_deployment_device_token_status {
	PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL = 0,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS,
};

/** Firmware-side policy for device token generation and replay. */
struct pqcp_deployment_device_token_policy {
	/** Release-gate profile this token is expected to represent. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Minimum capability descriptor readiness score. */
	uint32_t min_capability_readiness_score;
	/** Minimum deployment release gate score. */
	uint32_t min_gate_score;
	/** Treat score floor misses as hard blockers. */
	bool score_floor_blocks;
	/** Require firmware policy to pass. */
	bool require_capability_policy_pass;
	/** Require production interpretation to be allowed. */
	bool require_production_allowed;
	/** Require PQ Code Package native provider summary. */
	bool require_native_provider;
	/** Require release-gate capability bit in descriptor. */
	bool require_release_gate_capability;
	/** Require device-token capability bit in descriptor. */
	bool require_device_token_capability;
	/** Require release gate status PASS. */
	bool require_gate_pass;
	/** Require release gate digest binding. */
	bool require_gate_digest_binding;
};

/** Compact device evidence token derived from capability and release gate. */
struct pqcp_deployment_device_token {
	/** Token schema version. */
	uint32_t schema_version;
	/** Overall token status. */
	enum pqcp_deployment_device_token_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Policy profile represented by the token. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Caller-supplied 128-bit nonce. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Capability descriptor evidence bit mask. */
	uint32_t evidence_capabilities;
	/** Capability descriptor readiness score. */
	uint32_t capability_readiness_score;
	/** Release gate score. */
	uint32_t gate_score;
	/** Release gate status copied into the token. */
	enum pqcp_deployment_release_gate_status gate_status;
	/** True when descriptor policy passed. */
	bool capability_policy_passed;
	/** True when descriptor allows production interpretation. */
	bool production_allowed;
	/** True when descriptor provider summary is PQCP native. */
	bool native_provider;
	/** True when release gate reported digest binding. */
	bool gate_digest_bound;
	/** Stable top candidate identifier, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Trace digest copied from the release gate. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Packet digest copied from the release gate. */
	char packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Digest over canonical token fields. */
	char token_digest_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
};

/** Result of replay-checking an observed deployment device token. */
struct pqcp_deployment_device_token_verification {
	/** Verification schema version. */
	uint32_t schema_version;
	/** True when the observed token exactly matches recomputed evidence. */
	bool passed;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Expected status from recomputed evidence. */
	enum pqcp_deployment_device_token_status expected_status;
	/** Observed token status. */
	enum pqcp_deployment_device_token_status observed_status;
	/** Expected digest from recomputed evidence. */
	char expected_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	/** Observed digest from the token under verification. */
	char observed_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
};

/** Convert a deployment device token status to a stable marker token. */
const char *pqcp_deployment_device_token_status_str(
	enum pqcp_deployment_device_token_status status);

/** Populate a default device token policy for a release-gate profile. */
int pqcp_deployment_device_token_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_device_token_policy *policy);

/** Build a nonce-bound device token from capability and release-gate evidence. */
int pqcp_deployment_device_token_build(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const char *nonce_hex,
	const struct pqcp_deployment_device_token_policy *policy,
	struct pqcp_deployment_device_token *token);

/** Verify an observed token by recomputing it from current evidence inputs. */
int pqcp_deployment_device_token_verify(
	const struct pqcp_deployment_device_token *observed,
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const char *nonce_hex,
	const struct pqcp_deployment_device_token_policy *policy,
	struct pqcp_deployment_device_token_verification *verification);

/** Emit one stable deployment device token marker. */
int pqcp_deployment_device_token_emit(
	const struct pqcp_deployment_device_token *token);

/** Emit one stable deployment device token verification marker. */
int pqcp_deployment_device_token_verification_emit(
	const struct pqcp_deployment_device_token_verification *verification);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_DEVICE_TOKEN_H_ */
