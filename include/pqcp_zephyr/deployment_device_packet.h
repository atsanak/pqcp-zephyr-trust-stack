/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment device evidence packet
 *
 * Stability: experimental evidence API. This module serializes the final
 * device-bound deployment evidence chain into canonical caller-owned fact
 * lines, hashes those lines, and emits one stable device packet marker.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_DEVICE_PACKET_H_
#define PQCP_ZEPHYR_DEPLOYMENT_DEVICE_PACKET_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_device_gate.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment device-packet structures and markers. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION 1U

/** Device packet digest hex length excluding NUL. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS 64U

/** One formatted device fact line, including terminating NUL. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_LINE_MAX 640U

/** Device packet input pointer, schema, or mandatory text field was invalid. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_INVALID_INPUT      (1U << 0)
/** Caller-owned output buffer overflowed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_OVERFLOW           (1U << 1)
/** Evidence status fields contradicted each other. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_STATUS_MISMATCH    (1U << 2)
/** Evidence profile values disagreed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_PROFILE_MISMATCH   (1U << 3)
/** Top candidate identifiers disagreed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_TOP_MISMATCH       (1U << 4)
/** Nonce values disagreed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_NONCE_MISMATCH     (1U << 5)
/** Token digest values disagreed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_TOKEN_DIGEST       (1U << 6)
/** Release trace or packet digest values disagreed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_RELEASE_DIGEST     (1U << 7)
/** A score field was outside the stable 0-100 range. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_SCORE_RANGE        (1U << 8)
/** Required device-packet capability bit was not present. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_MISSING_CAPABILITY (1U << 9)
/** Device gate reported a hard failure. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_DEVICE_GATE        (1U << 10)
/** Token verification or token transcript replay failed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_REPLAY             (1U << 11)

/** All deployment device-packet error bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_OVERFLOW | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_STATUS_MISMATCH | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_PROFILE_MISMATCH | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_TOP_MISMATCH | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_NONCE_MISMATCH | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_TOKEN_DIGEST | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_RELEASE_DIGEST | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_SCORE_RANGE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_MISSING_CAPABILITY | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_DEVICE_GATE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_REPLAY)

/** Device gate is WARN and represented as review-visible evidence. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_DEVICE_GATE      (1U << 0)
/** Release gate is WARN or FAIL and represented as review-visible evidence. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_RELEASE_GATE     (1U << 1)
/** Device token is WARN or FAIL and represented as review-visible evidence. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_TOKEN            (1U << 2)
/** Device-token audit is WARN or FAIL and represented as review evidence. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_AUDIT            (1U << 3)
/** Capability descriptor is not production-interpretable. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_NOT_PRODUCTION   (1U << 4)
/** Provider summary is not PQCP native. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_NON_NATIVE       (1U << 5)
/** One or more readiness/gate scores are below 80. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_LOW_SCORE        (1U << 6)

/** All deployment device-packet warning bits known by this API version. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_DEVICE_GATE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_RELEASE_GATE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_TOKEN | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_AUDIT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_NOT_PRODUCTION | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_NON_NATIVE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_LOW_SCORE)

/** Overall deployment device-packet status. */
enum pqcp_deployment_device_packet_status {
	PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL = 0,
	PQCP_DEPLOYMENT_DEVICE_PACKET_WARN,
	PQCP_DEPLOYMENT_DEVICE_PACKET_PASS,
};

/** Deterministic summary over the final device-bound evidence chain. */
struct pqcp_deployment_device_packet {
	/** Packet schema version. */
	uint32_t schema_version;
	/** Overall packet status. */
	enum pqcp_deployment_device_packet_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Canonical device fact lines included in the digest. */
	uint32_t line_count;
	/** Canonical device fact bytes included in the digest. */
	uint32_t byte_count;
	/** Capability evidence mask copied from descriptor. */
	uint32_t evidence_capabilities;
	/** Capability readiness score copied from descriptor. */
	uint32_t capability_readiness_score;
	/** Release gate score copied from release gate. */
	uint32_t release_gate_score;
	/** Device-token audit minimum gate score. */
	uint32_t audit_min_gate_score;
	/** Policy profile evaluated. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Release gate status. */
	enum pqcp_deployment_release_gate_status release_gate_status;
	/** Device token status. */
	enum pqcp_deployment_device_token_status token_status;
	/** Device-token audit status. */
	enum pqcp_deployment_device_token_audit_status audit_status;
	/** Final device-gate status. */
	enum pqcp_deployment_device_gate_status device_gate_status;
	/** True when firmware policy passed. */
	bool capability_policy_passed;
	/** True when descriptor allows production interpretation. */
	bool production_allowed;
	/** True when provider summary is PQCP native. */
	bool native_provider;
	/** True when token verification passed. */
	bool verification_passed;
	/** True when token replay passed. */
	bool replay_passed;
	/** True when top candidate values matched. */
	bool top_consistent;
	/** True when nonce values matched. */
	bool nonce_consistent;
	/** True when token digest values matched. */
	bool token_digest_consistent;
	/** True when release trace/packet digest values matched. */
	bool release_digest_consistent;
	/** Stable top candidate identifier, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Trace digest copied from release gate. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Review packet digest copied from release gate. */
	char packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Device token digest copied from token evidence. */
	char token_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	/** Digest over canonical device fact lines. */
	char device_packet_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS + 1U];
};

/** Convert deployment device-packet status to a stable marker token. */
const char *pqcp_deployment_device_packet_status_str(
	enum pqcp_deployment_device_packet_status status);

/**
 * @brief Build a deterministic deployment device evidence packet.
 *
 * The output buffer receives canonical `PQCP_DEPLOYMENT_DEVICE_FACT` lines.
 * The final packet marker is emitted separately by
 * pqcp_deployment_device_packet_emit().
 */
int pqcp_deployment_device_packet_build(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_report *device_gate,
	char *buffer,
	size_t buffer_size,
	struct pqcp_deployment_device_packet *packet);

/** Emit canonical device fact lines from the caller-owned buffer. */
int pqcp_deployment_device_packet_emit_facts(
	const char *buffer,
	const struct pqcp_deployment_device_packet *packet);

/** Emit one stable final deployment device-packet marker. */
int pqcp_deployment_device_packet_emit(
	const struct pqcp_deployment_device_packet *packet);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_DEVICE_PACKET_H_ */
