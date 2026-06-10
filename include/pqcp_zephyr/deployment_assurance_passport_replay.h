/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment assurance passport replay verifier
 *
 * Stability: experimental evidence API. This verifier consumes an
 * already-built deployment assurance passport, recomputes the canonical
 * passport digest with the identical algorithm used by the passport
 * generator, and rejects malformed or internally inconsistent passport
 * evidence. It performs no cryptographic operation and uses no dynamic
 * allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_assurance_passport.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment assurance passport replay reports. */
#define PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_SCHEMA_VERSION 1U

/** Replay error reason for deployment assurance passport evidence. */
enum pqcp_deployment_assurance_passport_replay_error {
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MALFORMED_FIELD,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_STATUS_MISMATCH,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_PROFILE_MISMATCH,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MASK_RANGE,
	PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_SCORE_RANGE,
};

/** Final deployment assurance passport replay result. */
struct pqcp_deployment_assurance_passport_replay_result {
	/** Result schema version. */
	uint32_t schema_version;
	/** First replay error. */
	enum pqcp_deployment_assurance_passport_replay_error first_error;
	/** Passport status verified by this replay. */
	enum pqcp_deployment_assurance_passport_status passport_status;
	/** Passport error mask verified by this replay. */
	uint32_t passport_error_mask;
	/** Passport warning mask verified by this replay. */
	uint32_t passport_warning_mask;
	/** Release profile verified by this replay. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Passport score verified by this replay. */
	uint32_t passport_score;
	/** Lowest terminal score verified by this replay. */
	uint32_t min_terminal_score;
	/** Capability evidence intersection verified by this replay. */
	uint32_t evidence_capabilities_all;
	/** Capability evidence union verified by this replay. */
	uint32_t evidence_capabilities_any;
	/** True when the passport replayed consistently. */
	bool passed;
	/** Board identity verified by this replay. */
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	/** Stable top candidate from the passport. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce from the passport. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Recomputed passport digest. */
	char computed_digest_hex[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
};

/** Convert a passport replay error to a stable diagnostic token. */
const char *pqcp_deployment_assurance_passport_replay_error_str(
	enum pqcp_deployment_assurance_passport_replay_error error);

/** Verify an already-built passport by recomputing its digest. */
int pqcp_deployment_assurance_passport_replay_verify(
	const struct pqcp_deployment_assurance_passport *passport,
	struct pqcp_deployment_assurance_passport_replay_result *result);

/** Emit a stable deployment assurance passport replay marker. */
int pqcp_deployment_assurance_passport_replay_emit_result(
	const struct pqcp_deployment_assurance_passport_replay_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_H_ */
