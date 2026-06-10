/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment evidence verdict replay verifier
 *
 * Stability: experimental evidence API. This verifier consumes a captured
 * PQCP_DEPLOYMENT_EVIDENCE_VERDICT marker (or an already-built verdict
 * struct), recomputes the canonical verdict digest with the identical
 * algorithm used by the verdict evaluator, and rejects missing, duplicate,
 * malformed, or internally inconsistent verdict evidence. It performs no
 * cryptographic operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_verdict.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment evidence verdict replay reports. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_SCHEMA_VERSION 1U

/** Final deployment evidence verdict marker was observed. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_MARKER_VERDICT (1U << 0)

/** All required deployment evidence verdict replay marker bits. */
#define PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_REQUIRED_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_MARKER_VERDICT)

/** Replay error reason for deployment evidence verdict transcripts. */
enum pqcp_deployment_evidence_verdict_replay_error {
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MALFORMED_FIELD,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_DUPLICATE_MARKER,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MISSING_REQUIRED,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_UNKNOWN_MARKER,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_STATUS_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_PROFILE_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MASK_RANGE,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_SCORE_RANGE,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_STAGE_COUNT_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_CONSISTENCY_MISMATCH,
};

/** Caller-owned deployment evidence verdict replay state. */
struct pqcp_deployment_evidence_verdict_replay_state {
	/** Replay schema version. */
	uint32_t schema_version;
	/** Lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed verdict marker bits. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_evidence_verdict_replay_error first_error;
	/** Verdict reconstructed from the parsed marker. */
	struct pqcp_deployment_evidence_verdict verdict;
	/** Verdict digest parsed from the final marker. */
	char verdict_digest_observed_hex[
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U];
};

/** Final deployment evidence verdict replay result. */
struct pqcp_deployment_evidence_verdict_replay_result {
	/** Result schema version. */
	uint32_t schema_version;
	/** Lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed verdict marker bit mask. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_evidence_verdict_replay_error first_error;
	/** Verdict status parsed from the marker. */
	enum pqcp_deployment_evidence_verdict_status verdict_status;
	/** Verdict error mask parsed from the marker. */
	uint32_t verdict_error_mask;
	/** Verdict warning mask parsed from the marker. */
	uint32_t verdict_warning_mask;
	/** Release profile parsed from the marker. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Final verdict score parsed from the marker. */
	uint32_t verdict_score;
	/** Lowest upstream score parsed from the marker. */
	uint32_t min_chain_score;
	/** Number of upstream stages parsed from the marker. */
	uint32_t stage_count;
	/** Cross-chain consistency checks parsed from the marker. */
	uint32_t consistency_checks;
	/** Cross-chain consistency passes parsed from the marker. */
	uint32_t consistency_pass_count;
	/** Capability evidence intersection parsed from the marker. */
	uint32_t evidence_capabilities_all;
	/** Capability evidence union parsed from the marker. */
	uint32_t evidence_capabilities_any;
	/** True when all facts and final marker replayed consistently. */
	bool passed;
	/** Stable top candidate from the verdict. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce from the verdict. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Recomputed verdict digest. */
	char computed_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U];
};

/** Convert a verdict replay error to a stable diagnostic token. */
const char *pqcp_deployment_evidence_verdict_replay_error_str(
	enum pqcp_deployment_evidence_verdict_replay_error error);

/** Initialize a deployment evidence verdict replay state. */
int pqcp_deployment_evidence_verdict_replay_init(
	struct pqcp_deployment_evidence_verdict_replay_state *state);

/** Feed one final deployment evidence verdict marker into the verifier. */
int pqcp_deployment_evidence_verdict_replay_ingest_line(
	struct pqcp_deployment_evidence_verdict_replay_state *state,
	const char *line);

/** Finish verdict replay and verify cross-field consistency. */
int pqcp_deployment_evidence_verdict_replay_finish(
	struct pqcp_deployment_evidence_verdict_replay_state *state,
	struct pqcp_deployment_evidence_verdict_replay_result *result);

/** Verify an already-built verdict struct by recomputing its digest. */
int pqcp_deployment_evidence_verdict_replay_verify(
	const struct pqcp_deployment_evidence_verdict *verdict,
	struct pqcp_deployment_evidence_verdict_replay_result *result);

/** Emit a stable deployment evidence verdict replay marker. */
int pqcp_deployment_evidence_verdict_replay_emit_result(
	const struct pqcp_deployment_evidence_verdict_replay_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_H_ */
