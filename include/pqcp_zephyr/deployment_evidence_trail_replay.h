/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment evidence trail replay verifier
 *
 * Stability: experimental evidence API. This verifier consumes captured
 * PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ENTRY and PQCP_DEPLOYMENT_EVIDENCE_TRAIL
 * markers (or an already-built trail plus its entries), recomputes the
 * genesis link and every chained link digest with the identical algorithm
 * used by the trail generator, and rejects sequence gaps, reordering,
 * splicing, entry tampering, head tampering, and count drift. It performs
 * no cryptographic operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_trail.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment evidence trail replay reports. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_SCHEMA_VERSION 1U

/** Evidence trail head marker was observed. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_MARKER_HEAD  (1U << 0)
/** At least one evidence trail entry marker was observed. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_MARKER_ENTRY (1U << 1)

/** All required deployment evidence trail replay marker bits. */
#define PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_REQUIRED_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_MARKER_HEAD | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_MARKER_ENTRY)

/** Replay error reason for deployment evidence trail transcripts. */
enum pqcp_deployment_evidence_trail_replay_error {
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_DUPLICATE_MARKER,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MISSING_REQUIRED,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_SEQUENCE_GAP,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_ENTRY_OVERFLOW,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_ENTRY_AFTER_HEAD,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_LINK_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_HEAD_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_COUNT_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_STAGE_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_STATUS_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MASK_RANGE,
};

/** Caller-owned deployment evidence trail replay state. */
struct pqcp_deployment_evidence_trail_replay_state {
	/** Replay schema version. */
	uint32_t schema_version;
	/** Trail marker lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed trail marker bits. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_evidence_trail_replay_error first_error;
	/** Entries reconstructed from parsed entry markers. */
	struct pqcp_deployment_evidence_trail_entry entries[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES];
	/** Number of entries parsed so far. */
	uint32_t entries_seen;
	/** Trail head reconstructed from the parsed head marker. */
	struct pqcp_deployment_evidence_trail trail;
};

/** Final deployment evidence trail replay result. */
struct pqcp_deployment_evidence_trail_replay_result {
	/** Result schema version. */
	uint32_t schema_version;
	/** Trail marker lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed trail marker bit mask. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_evidence_trail_replay_error first_error;
	/** Trail status verified by this replay. */
	enum pqcp_deployment_evidence_trail_status trail_status;
	/** Trail error mask verified by this replay. */
	uint32_t trail_error_mask;
	/** Trail warning mask verified by this replay. */
	uint32_t trail_warning_mask;
	/** Release profile verified by this replay. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Entries verified by this replay. */
	uint32_t entry_count;
	/** Stage occurrence bits verified by this replay. */
	uint32_t observed_stage_mask;
	/** True when every link and the head replayed consistently. */
	bool passed;
	/** Stable top candidate from the trail. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Stable nonce from the trail. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Recomputed head digest. */
	char computed_head_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];
};

/** Convert a trail replay error to a stable diagnostic token. */
const char *pqcp_deployment_evidence_trail_replay_error_str(
	enum pqcp_deployment_evidence_trail_replay_error error);

/** Initialize a deployment evidence trail replay state. */
int pqcp_deployment_evidence_trail_replay_init(
	struct pqcp_deployment_evidence_trail_replay_state *state);

/** Feed one evidence trail entry or head marker into the verifier. */
int pqcp_deployment_evidence_trail_replay_ingest_line(
	struct pqcp_deployment_evidence_trail_replay_state *state,
	const char *line);

/** Finish trail replay and verify the full link chain. */
int pqcp_deployment_evidence_trail_replay_finish(
	struct pqcp_deployment_evidence_trail_replay_state *state,
	struct pqcp_deployment_evidence_trail_replay_result *result);

/** Verify an already-built trail and its entries by recomputing links. */
int pqcp_deployment_evidence_trail_replay_verify(
	const struct pqcp_deployment_evidence_trail *trail,
	const struct pqcp_deployment_evidence_trail_entry *entries,
	size_t entry_count,
	struct pqcp_deployment_evidence_trail_replay_result *result);

/** Emit a stable deployment evidence trail replay marker. */
int pqcp_deployment_evidence_trail_replay_emit_result(
	const struct pqcp_deployment_evidence_trail_replay_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_H_ */
