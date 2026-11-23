/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Tamper matrix replay verifier
 *
 * Stability: experimental evidence API. This verifier consumes a captured
 * PQCP_DEPLOYMENT_TAMPER_MATRIX marker (or an already-built matrix report),
 * recomputes the canonical matrix digest with the identical algorithm used
 * by the matrix generator, re-derives the count and coverage invariants, and
 * rejects missing, duplicate, malformed, or internally inconsistent
 * adversarial detection evidence. It performs no cryptographic operation and
 * uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_TAMPER_MATRIX_REPLAY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_TAMPER_MATRIX_REPLAY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_tamper_matrix.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for tamper matrix replay reports. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_SCHEMA_VERSION 1U

/** Tamper matrix summary marker was observed. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_MARKER_MATRIX (1U << 0)

/** All required tamper matrix replay marker bits. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_REQUIRED_MASK \
	(PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_MARKER_MATRIX)

/** Replay error reason for tamper matrix evidence. */
enum pqcp_deployment_tamper_matrix_replay_error {
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MALFORMED_FIELD,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DUPLICATE_MARKER,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MISSING_REQUIRED,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_STATUS_MISMATCH,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_PROFILE_MISMATCH,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MASK_RANGE,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_COUNT_MISMATCH,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_COVERAGE_MISMATCH,
};

/** Caller-owned tamper matrix replay state. */
struct pqcp_deployment_tamper_matrix_replay_state {
	/** Replay schema version. */
	uint32_t schema_version;
	/** Matrix marker lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed matrix marker bits. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_tamper_matrix_replay_error first_error;
	/** Matrix report reconstructed from the parsed marker. */
	struct pqcp_deployment_tamper_matrix_report report;
	/** Matrix digest parsed from the marker. */
	char matrix_digest_observed_hex[
		PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U];
};

/** Final tamper matrix replay result. */
struct pqcp_deployment_tamper_matrix_replay_result {
	/** Result schema version. */
	uint32_t schema_version;
	/** Matrix marker lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed matrix marker bit mask. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_tamper_matrix_replay_error first_error;
	/** Matrix status verified by this replay. */
	enum pqcp_deployment_tamper_matrix_status matrix_status;
	/** Matrix error mask verified by this replay. */
	uint32_t matrix_error_mask;
	/** Matrix warning mask verified by this replay. */
	uint32_t matrix_warning_mask;
	/** Release profile verified by this replay. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Stage mask verified by this replay. */
	uint32_t stage_mask;
	/** Total cells verified by this replay. */
	uint32_t cell_count;
	/** Attack cells verified by this replay. */
	uint32_t attack_count;
	/** Detected attack cells verified by this replay. */
	uint32_t detected_count;
	/** Missed attack cells verified by this replay. */
	uint32_t missed_count;
	/** Control cells that passed, verified by this replay. */
	uint32_t control_pass_count;
	/** Detection coverage in permille verified by this replay. */
	uint32_t coverage_permille;
	/** True when the matrix marker replayed consistently. */
	bool passed;
	/** Stable top candidate from the matrix. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce from the matrix. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Passport digest binding carried by the matrix. */
	char passport_digest_hex[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
	/** Recomputed matrix digest. */
	char computed_digest_hex[
		PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U];
};

/** Convert a tamper matrix replay error to a stable diagnostic token. */
const char *pqcp_deployment_tamper_matrix_replay_error_str(
	enum pqcp_deployment_tamper_matrix_replay_error error);

/** Initialize a tamper matrix replay state. */
int pqcp_deployment_tamper_matrix_replay_init(
	struct pqcp_deployment_tamper_matrix_replay_state *state);

/** Feed one tamper matrix summary marker into the verifier. */
int pqcp_deployment_tamper_matrix_replay_ingest_line(
	struct pqcp_deployment_tamper_matrix_replay_state *state,
	const char *line);

/** Finish tamper matrix replay and verify cross-field consistency. */
int pqcp_deployment_tamper_matrix_replay_finish(
	struct pqcp_deployment_tamper_matrix_replay_state *state,
	struct pqcp_deployment_tamper_matrix_replay_result *result);

/** Verify an already-built matrix report by recomputing its digest. */
int pqcp_deployment_tamper_matrix_replay_verify(
	const struct pqcp_deployment_tamper_matrix_report *report,
	struct pqcp_deployment_tamper_matrix_replay_result *result);

/** Emit a stable tamper matrix replay marker. */
int pqcp_deployment_tamper_matrix_replay_emit_result(
	const struct pqcp_deployment_tamper_matrix_replay_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_TAMPER_MATRIX_REPLAY_H_ */
