/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment device-packet replay verifier
 *
 * Stability: experimental evidence API. This verifier consumes captured
 * PQCP_DEPLOYMENT_DEVICE_FACT and PQCP_DEPLOYMENT_DEVICE_PACKET markers,
 * recomputes the canonical packet digest, and rejects missing, duplicate,
 * malformed, or internally inconsistent device evidence.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_DEVICE_PACKET_REPLAY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_DEVICE_PACKET_REPLAY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_device_packet.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment device-packet replay reports. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_SCHEMA_VERSION 1U

/** Capability fact marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_CAPABILITY (1U << 0)
/** Release-gate fact marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_RELEASE    (1U << 1)
/** Device-token fact marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_TOKEN      (1U << 2)
/** Device-token replay fact marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_REPLAY     (1U << 3)
/** Device-token audit fact marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_AUDIT      (1U << 4)
/** Device-gate fact marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_DEVICE_GATE (1U << 5)
/** Final device-packet marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_PACKET     (1U << 6)

/** All required deployment device-packet replay marker bits. */
#define PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_REQUIRED_MASK \
	(PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_CAPABILITY | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_RELEASE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_TOKEN | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_REPLAY | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_AUDIT | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_DEVICE_GATE | \
	 PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_PACKET)

/** Replay error reason for deployment device-packet transcripts. */
enum pqcp_deployment_device_packet_replay_error {
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_DUPLICATE_MARKER,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MISSING_REQUIRED,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_UNKNOWN_MARKER,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_BYTE_COUNT_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_LINE_COUNT_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_PROFILE_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOP_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONCE_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_RELEASE_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_CAPABILITY_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH,
};

/** Caller-owned deployment device-packet replay state. */
struct pqcp_deployment_device_packet_replay_state {
	/** Replay schema version. */
	uint32_t schema_version;
	/** Lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Canonical device fact lines hashed into the packet digest. */
	uint32_t fact_lines;
	/** Canonical device fact bytes hashed into the packet digest. */
	uint32_t fact_bytes;
	/** Observed device-packet marker bits. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_device_packet_replay_error first_error;
	/** Packet status parsed from the final marker. */
	enum pqcp_deployment_device_packet_status packet_status;
	/** Packet error mask parsed from the final marker. */
	uint32_t packet_error_mask;
	/** Packet warning mask parsed from the final marker. */
	uint32_t packet_warning_mask;
	/** Line count parsed from the final packet marker. */
	uint32_t packet_line_count;
	/** Byte count parsed from the final packet marker. */
	uint32_t packet_byte_count;
	/** Capability evidence mask parsed from facts/final marker. */
	uint32_t evidence_capabilities;
	/** Capability readiness score parsed from facts/final marker. */
	uint32_t capability_readiness_score;
	/** Release gate score parsed from facts/final marker. */
	uint32_t release_gate_score;
	/** Device-token audit gate score parsed from facts/final marker. */
	uint32_t audit_gate_score;
	/** Release profile parsed from release/device facts/final marker. */
	enum pqcp_deployment_release_gate_profile profile;
	/** True once a release profile has been observed. */
	bool profile_seen;
	/** Release gate status parsed from facts/final marker. */
	enum pqcp_deployment_release_gate_status release_status;
	/** Device token status parsed from facts/final marker. */
	enum pqcp_deployment_device_token_status token_status;
	/** Device-token audit status parsed from facts/final marker. */
	enum pqcp_deployment_device_token_audit_status audit_status;
	/** Device gate status parsed from facts/final marker. */
	enum pqcp_deployment_device_gate_status device_gate_status;
	/** True once evidence capability mask has been observed. */
	bool evidence_seen;
	/** True once capability readiness score has been observed. */
	bool capability_score_seen;
	/** True once release gate score has been observed. */
	bool release_score_seen;
	/** True once audit gate score has been observed. */
	bool audit_score_seen;
	/** True once release status has been observed. */
	bool release_status_seen;
	/** True once token status has been observed. */
	bool token_status_seen;
	/** True once audit status has been observed. */
	bool audit_status_seen;
	/** True once device-gate status has been observed. */
	bool device_gate_status_seen;
	/** True once token verification status has been observed. */
	bool verification_seen;
	/** True once token replay status has been observed. */
	bool replay_seen;
	/** True once capability policy status has been observed. */
	bool capability_policy_seen;
	/** True once production-allowed status has been observed. */
	bool production_allowed_seen;
	/** True when token verification parsed as PASS. */
	bool verification_passed;
	/** True when token replay parsed as PASS. */
	bool replay_passed;
	/** True when capability policy parsed as PASS. */
	bool capability_policy_passed;
	/** Production-allowed flag parsed from capability fact. */
	uint32_t production_allowed;
	/** Stable top candidate parsed from facts/final marker. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce parsed from facts/final marker. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Trace digest parsed from release/final marker. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Review packet digest parsed from release/final marker. */
	char packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Device token digest parsed from facts/final marker. */
	char token_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	/** Device packet digest recomputed from canonical fact lines. */
	char computed_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Device packet digest parsed from the final marker. */
	char packet_digest_observed_hex[
		PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Private digest state. */
	uint64_t digest_state[4];
};

/** Final deployment device-packet replay result. */
struct pqcp_deployment_device_packet_replay_result {
	/** Result schema version. */
	uint32_t schema_version;
	/** Lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed device-packet marker bit mask. */
	uint32_t marker_mask;
	/** Canonical fact line count. */
	uint32_t fact_lines;
	/** Canonical fact byte count. */
	uint32_t fact_bytes;
	/** Capability evidence mask. */
	uint32_t evidence_capabilities;
	/** Capability readiness score. */
	uint32_t capability_readiness_score;
	/** Release gate score. */
	uint32_t release_gate_score;
	/** Audit gate score. */
	uint32_t audit_gate_score;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_device_packet_replay_error first_error;
	/** Packet status from the final marker. */
	enum pqcp_deployment_device_packet_status packet_status;
	/** True when all facts and final marker replayed consistently. */
	bool passed;
	/** Stable top candidate from the packet. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce from the packet. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Recomputed device packet digest. */
	char computed_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS + 1U];
};

/** Convert a device-packet replay error to a stable diagnostic token. */
const char *pqcp_deployment_device_packet_replay_error_str(
	enum pqcp_deployment_device_packet_replay_error error);

/** Initialize a deployment device-packet replay state. */
int pqcp_deployment_device_packet_replay_init(
	struct pqcp_deployment_device_packet_replay_state *state);

/** Feed one device fact or final device packet marker into the verifier. */
int pqcp_deployment_device_packet_replay_ingest_line(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line);

/** Finish device-packet replay and verify cross-marker consistency. */
int pqcp_deployment_device_packet_replay_finish(
	struct pqcp_deployment_device_packet_replay_state *state,
	struct pqcp_deployment_device_packet_replay_result *result);

/** Verify caller-owned fact buffer against an already-built packet struct. */
int pqcp_deployment_device_packet_replay_verify_packet(
	const char *fact_buffer,
	const struct pqcp_deployment_device_packet *packet,
	struct pqcp_deployment_device_packet_replay_result *result);

/** Emit a stable deployment device-packet replay marker. */
int pqcp_deployment_device_packet_replay_emit_result(
	const struct pqcp_deployment_device_packet_replay_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_DEVICE_PACKET_REPLAY_H_ */
