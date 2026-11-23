/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment evidence seal replay verifier
 *
 * Stability: experimental evidence API. This verifier consumes a captured
 * PQCP_DEPLOYMENT_EVIDENCE_SEAL marker (or an already-built seal struct),
 * recomputes the canonical seal digest with the identical algorithm used by
 * the seal generator, and rejects missing, duplicate, malformed, or
 * internally inconsistent seal evidence. It performs no cryptographic
 * operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_seal.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment evidence seal replay reports. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_SCHEMA_VERSION 1U

/** Final deployment evidence seal marker was observed. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_MARKER_SEAL (1U << 0)

/** All required deployment evidence seal replay marker bits. */
#define PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_REQUIRED_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_MARKER_SEAL)

/** Replay error reason for deployment evidence seal transcripts. */
enum pqcp_deployment_evidence_seal_replay_error {
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MALFORMED_FIELD,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DUPLICATE_MARKER,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MISSING_REQUIRED,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_UNKNOWN_MARKER,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_STATUS_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_PROFILE_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MASK_RANGE,
	PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_SCORE_RANGE,
};

/** Caller-owned deployment evidence seal replay state. */
struct pqcp_deployment_evidence_seal_replay_state {
	/** Replay schema version. */
	uint32_t schema_version;
	/** Lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed seal marker bits. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_evidence_seal_replay_error first_error;
	/** Seal reconstructed from the parsed marker. */
	struct pqcp_deployment_evidence_seal seal;
	/** Seal digest parsed from the final marker. */
	char seal_digest_observed_hex[
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U];
};

/** Final deployment evidence seal replay result. */
struct pqcp_deployment_evidence_seal_replay_result {
	/** Result schema version. */
	uint32_t schema_version;
	/** Lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed seal marker bit mask. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_evidence_seal_replay_error first_error;
	/** Seal status parsed from the marker. */
	enum pqcp_deployment_evidence_seal_status seal_status;
	/** Seal error mask parsed from the marker. */
	uint32_t seal_error_mask;
	/** Seal warning mask parsed from the marker. */
	uint32_t seal_warning_mask;
	/** Release profile parsed from the marker. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Final seal score parsed from the marker. */
	uint32_t seal_score;
	/** Lowest terminal score parsed from the marker. */
	uint32_t min_terminal_score;
	/** Sealed verdict status parsed from the marker. */
	enum pqcp_deployment_evidence_verdict_status verdict_status;
	/** Sealed verdict audit status parsed from the marker. */
	enum pqcp_deployment_evidence_verdict_audit_status audit_status;
	/** Sealed verdict replay pass flag parsed from the marker. */
	bool sealed_replay_passed;
	/** Audited replay sample count parsed from the marker. */
	uint32_t audited_result_count;
	/** Chain stage count parsed from the marker. */
	uint32_t chain_stage_count;
	/** Chain consistency check count parsed from the marker. */
	uint32_t chain_consistency_checks;
	/** Capability evidence intersection parsed from the marker. */
	uint32_t evidence_capabilities_all;
	/** Capability evidence union parsed from the marker. */
	uint32_t evidence_capabilities_any;
	/** True when the seal marker replayed consistently. */
	bool passed;
	/** Stable top candidate from the seal. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce from the seal. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Sealed verdict digest from the marker. */
	char verdict_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U];
	/** Sealed audit digest from the marker. */
	char audit_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_DIGEST_HEX_CHARS + 1U];
	/** Recomputed seal digest. */
	char computed_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U];
};

/** Convert a seal replay error to a stable diagnostic token. */
const char *pqcp_deployment_evidence_seal_replay_error_str(
	enum pqcp_deployment_evidence_seal_replay_error error);

/** Initialize a deployment evidence seal replay state. */
int pqcp_deployment_evidence_seal_replay_init(
	struct pqcp_deployment_evidence_seal_replay_state *state);

/** Feed one final deployment evidence seal marker into the verifier. */
int pqcp_deployment_evidence_seal_replay_ingest_line(
	struct pqcp_deployment_evidence_seal_replay_state *state,
	const char *line);

/** Finish seal replay and verify cross-field consistency. */
int pqcp_deployment_evidence_seal_replay_finish(
	struct pqcp_deployment_evidence_seal_replay_state *state,
	struct pqcp_deployment_evidence_seal_replay_result *result);

/** Verify an already-built seal struct by recomputing its digest. */
int pqcp_deployment_evidence_seal_replay_verify(
	const struct pqcp_deployment_evidence_seal *seal,
	struct pqcp_deployment_evidence_seal_replay_result *result);

/** Emit a stable deployment evidence seal replay marker. */
int pqcp_deployment_evidence_seal_replay_emit_result(
	const struct pqcp_deployment_evidence_seal_replay_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_H_ */
