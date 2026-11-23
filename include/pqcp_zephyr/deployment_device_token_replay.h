/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment device-token transcript replay
 *
 * Stability: experimental evidence API. This verifier consumes captured
 * PQCP_CAPABILITY_DESCRIPTOR, PQCP_DEPLOYMENT_RELEASE_GATE,
 * PQCP_DEPLOYMENT_DEVICE_TOKEN, and PQCP_DEPLOYMENT_DEVICE_TOKEN_VERIFY
 * transcript lines and checks that they describe one internally consistent,
 * nonce-bound deployment evidence token.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_DEVICE_TOKEN_REPLAY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_DEVICE_TOKEN_REPLAY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_device_token.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment device-token replay reports. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION 1U

/** Capability descriptor marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_CAPABILITY (1U << 0)
/** Deployment release-gate marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_RELEASE_GATE (1U << 1)
/** Deployment device-token marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_TOKEN (1U << 2)
/** Deployment device-token verification marker was observed. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_VERIFY (1U << 3)

/** All required markers for a complete device-token transcript. */
#define PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK \
	(PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_CAPABILITY | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_RELEASE_GATE | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_TOKEN | \
	 PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_VERIFY)

/** Replay error reason for deployment device-token transcripts. */
enum pqcp_deployment_device_token_replay_error {
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_DUPLICATE_MARKER,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MISSING_REQUIRED,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_UNKNOWN_MARKER,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONCE_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_CAPABILITY_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_RELEASE_GATE_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_VERIFY_MISMATCH,
};

/** Caller-owned replay state for one device-token transcript. */
struct pqcp_deployment_device_token_replay_state {
	/** Replay schema version. */
	uint32_t schema_version;
	/** Lines consumed by the replay verifier. */
	uint32_t lines_seen;
	/** Marker bits observed so far. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_device_token_replay_error first_error;
	/** Parsed capability descriptor readiness score. */
	uint32_t capability_readiness_score;
	/** Parsed capability descriptor evidence bit mask. */
	uint32_t evidence_capabilities;
	/** True when capability descriptor status is PASS. */
	bool capability_policy_passed;
	/** True when capability descriptor production_allowed is 1. */
	bool production_allowed;
	/** True when provider summary is pqcp_native. */
	bool native_provider;
	/** Release gate score. */
	uint32_t gate_score;
	/** Release gate profile. */
	enum pqcp_deployment_release_gate_profile gate_profile;
	/** Release gate status. */
	enum pqcp_deployment_release_gate_status gate_status;
	/** True when release gate digest_bound is 1. */
	bool gate_digest_bound;
	/** Stable top candidate parsed from release gate marker. */
	char gate_top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Trace digest parsed from release gate marker. */
	char gate_trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Packet digest parsed from release gate marker. */
	char gate_packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Token parsed from the device-token marker. */
	struct pqcp_deployment_device_token token;
	/** True when token verify marker status is PASS. */
	bool verify_passed;
	/** Token verification marker error mask. */
	uint32_t verify_error_mask;
	/** Expected status parsed from verification marker. */
	enum pqcp_deployment_device_token_status verify_expected_status;
	/** Observed status parsed from verification marker. */
	enum pqcp_deployment_device_token_status verify_observed_status;
	/** Expected digest parsed from verification marker. */
	char verify_expected_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	/** Observed digest parsed from verification marker. */
	char verify_observed_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
};

/** Final replay result for one device-token transcript. */
struct pqcp_deployment_device_token_replay_result {
	/** Result schema version. */
	uint32_t schema_version;
	/** True when required markers and cross-checks passed. */
	bool passed;
	/** Lines consumed by the replay verifier. */
	uint32_t lines_seen;
	/** Marker bits observed. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_device_token_replay_error first_error;
	/** Token status parsed from transcript. */
	enum pqcp_deployment_device_token_status token_status;
	/** Release gate status parsed from transcript. */
	enum pqcp_deployment_release_gate_status gate_status;
	/** Capability descriptor readiness score parsed from transcript. */
	uint32_t capability_readiness_score;
	/** Release gate score parsed from transcript. */
	uint32_t gate_score;
	/** Stable top candidate parsed from transcript. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Nonce parsed from transcript. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Token digest parsed from transcript. */
	char token_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	/** Token digest recomputed during replay. */
	char computed_digest_hex[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
};

/** Convert replay error to a stable marker token. */
const char *pqcp_deployment_device_token_replay_error_str(
	enum pqcp_deployment_device_token_replay_error error);

/** Initialize a deployment device-token replay state. */
int pqcp_deployment_device_token_replay_init(
	struct pqcp_deployment_device_token_replay_state *state);

/** Feed one captured transcript line into the replay verifier. */
int pqcp_deployment_device_token_replay_ingest_line(
	struct pqcp_deployment_device_token_replay_state *state,
	const char *line);

/** Finish replay and verify cross-marker consistency. */
int pqcp_deployment_device_token_replay_finish(
	struct pqcp_deployment_device_token_replay_state *state,
	const char *expected_nonce_hex,
	struct pqcp_deployment_device_token_replay_result *result);

/** Verify a newline-delimited transcript buffer. */
int pqcp_deployment_device_token_replay_verify_transcript(
	const char *transcript,
	const char *expected_nonce_hex,
	struct pqcp_deployment_device_token_replay_result *result);

/** Emit one stable device-token replay marker. */
int pqcp_deployment_device_token_replay_emit_result(
	const struct pqcp_deployment_device_token_replay_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_DEVICE_TOKEN_REPLAY_H_ */
