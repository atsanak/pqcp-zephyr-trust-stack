/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment review packet verifier
 *
 * Stability: experimental evidence API. This verifier replays the stable
 * review packet fact and digest markers emitted by the deployment pipeline.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_REVIEW_VERIFIER_H_
#define PQCP_ZEPHYR_DEPLOYMENT_REVIEW_VERIFIER_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_review_packet.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment review verifier reports. */
#define PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION 1U

/** Review scenario fact marker was observed. */
#define PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_SCENARIO    (1U << 0)
/** Review pipeline fact marker was observed. */
#define PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_PIPELINE    (1U << 1)
/** Review budget fact marker was observed. */
#define PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_BUDGET      (1U << 2)
/** Review experiment-plan fact marker was observed. */
#define PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_EXPERIMENTS (1U << 3)
/** Final review packet marker was observed. */
#define PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_PACKET      (1U << 4)

/** All required deployment review verifier marker bits. */
#define PQCP_DEPLOYMENT_REVIEW_VERIFIER_REQUIRED_MASK \
	(PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_SCENARIO | \
	 PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_PIPELINE | \
	 PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_BUDGET | \
	 PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_EXPERIMENTS | \
	 PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_PACKET)

/** Replay error reason for deployment review packets. */
enum pqcp_deployment_review_verifier_error {
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DUPLICATE_MARKER,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MISSING_REQUIRED,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_BYTE_COUNT_MISMATCH,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_LINE_COUNT_MISMATCH,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_TOP_MISMATCH,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_STATUS_MISMATCH,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_COUNT_MISMATCH,
	PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_UNKNOWN_MARKER,
};

/** Caller-owned deployment review verifier replay state. */
struct pqcp_deployment_review_verifier_state {
	/** Replay schema version. */
	uint32_t schema_version;
	/** Lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Canonical fact lines hashed into the packet digest. */
	uint32_t fact_lines;
	/** Canonical fact bytes hashed into the packet digest. */
	uint32_t fact_bytes;
	/** Observed review marker bits. */
	uint32_t marker_mask;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_review_verifier_error first_error;
	/** Packet status parsed from the final marker. */
	enum pqcp_deployment_review_packet_status packet_status;
	/** Packet error mask parsed from the final marker. */
	uint32_t packet_error_mask;
	/** Packet warning mask parsed from the final marker. */
	uint32_t packet_warning_mask;
	/** Line count parsed from the final packet marker. */
	uint32_t packet_line_count;
	/** Byte count parsed from the final packet marker. */
	uint32_t packet_byte_count;
	/** Candidate count from pipeline/final packet. */
	uint32_t candidate_count;
	/** Experiment count from experiments/final packet. */
	uint32_t experiment_count;
	/** Blocking experiment count from experiments/final packet. */
	uint32_t blocking_count;
	/** Readiness score from pipeline/final packet. */
	uint32_t readiness_score;
	/** Claim score from pipeline/final packet. */
	uint32_t claim_score;
	/** Review score from the final packet. */
	uint32_t review_score;
	/** True when pipeline status parsed as PASS. */
	bool pipeline_passed;
	/** True when transcript replay status parsed as PASS. */
	bool replay_passed;
	/** True when budget status parsed as PASS. */
	bool budget_passed;
	/** True when experiment-plan status parsed as PASS. */
	bool experiment_plan_passed;
	/** Top candidate parsed from pipeline/final packet. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Trace digest parsed from pipeline/final packet. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Packet digest recomputed from canonical fact lines. */
	char computed_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	/** Packet digest parsed from the final marker. */
	char packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	uint64_t digest_state[4];
};

/** Final deployment review replay result. */
struct pqcp_deployment_review_verifier_result {
	/** Result schema version. */
	uint32_t schema_version;
	/** Lines consumed by the verifier. */
	uint32_t lines_seen;
	/** Observed review marker bit mask. */
	uint32_t marker_mask;
	/** Canonical fact line count. */
	uint32_t fact_lines;
	/** Canonical fact byte count. */
	uint32_t fact_bytes;
	/** Candidate count from the packet. */
	uint32_t candidate_count;
	/** Experiment count from the packet. */
	uint32_t experiment_count;
	/** Blocking experiment count from the packet. */
	uint32_t blocking_count;
	/** Readiness score from the packet. */
	uint32_t readiness_score;
	/** Claim score from the packet. */
	uint32_t claim_score;
	/** Review score from the packet. */
	uint32_t review_score;
	/** First failing line, or zero. */
	uint32_t first_error_line;
	/** First replay error. */
	enum pqcp_deployment_review_verifier_error first_error;
	/** Packet status from the final marker. */
	enum pqcp_deployment_review_packet_status packet_status;
	/** True when all review facts and packet marker replayed consistently. */
	bool passed;
	/** Top candidate from the packet. */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Trace digest from the packet. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Recomputed packet digest. */
	char computed_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
};

/** Convert a review verifier error to a stable diagnostic token. */
const char *pqcp_deployment_review_verifier_error_str(
	enum pqcp_deployment_review_verifier_error error);

/** Initialize a deployment review verifier state. */
int pqcp_deployment_review_verifier_init(
	struct pqcp_deployment_review_verifier_state *state);

/** Feed one review fact or final review packet marker into the verifier. */
int pqcp_deployment_review_verifier_ingest_line(
	struct pqcp_deployment_review_verifier_state *state,
	const char *line);

/** Finish review-packet replay and verify cross-marker consistency. */
int pqcp_deployment_review_verifier_finish(
	struct pqcp_deployment_review_verifier_state *state,
	struct pqcp_deployment_review_verifier_result *result);

/** Verify caller-owned fact buffer against an already-built packet struct. */
int pqcp_deployment_review_verifier_verify_packet(
	const char *fact_buffer,
	const struct pqcp_deployment_review_packet *packet,
	struct pqcp_deployment_review_verifier_result *result);

/** Emit a stable deployment review replay marker. */
int pqcp_deployment_review_verifier_emit_result(
	const struct pqcp_deployment_review_verifier_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_REVIEW_VERIFIER_H_ */
