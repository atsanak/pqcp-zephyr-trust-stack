/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment evidence trace builder
 *
 * Stability: experimental evidence API. The builder formats stable
 * PQCP_DEPLOYMENT_* markers into caller-owned memory, updates a lightweight
 * replay digest, and feeds replayable lines into the deployment transcript
 * verifier.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_TRACE_BUILDER_H_
#define PQCP_ZEPHYR_DEPLOYMENT_TRACE_BUILDER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_claims.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment trace digest result structures and markers. */
#define PQCP_DEPLOYMENT_TRACE_BUILDER_SCHEMA_VERSION 1U

/** Maximum formatted deployment marker line, including terminating NUL. */
#define PQCP_DEPLOYMENT_TRACE_LINE_MAX 768U

/** Digest hex length excluding NUL. */
#define PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS 64U

/** Trace builder is not initialized. */
#define PQCP_DEPLOYMENT_TRACE_ERROR_NOT_INITIALIZED (1U << 0)
/** Caller-owned trace buffer overflowed. */
#define PQCP_DEPLOYMENT_TRACE_ERROR_OVERFLOW        (1U << 1)
/** One marker could not be formatted into the fixed line buffer. */
#define PQCP_DEPLOYMENT_TRACE_ERROR_LINE_TOO_LONG   (1U << 2)
/** A deployment marker failed transcript replay during append. */
#define PQCP_DEPLOYMENT_TRACE_ERROR_REPLAY_APPEND   (1U << 3)
/** Final transcript replay failed. */
#define PQCP_DEPLOYMENT_TRACE_ERROR_REPLAY_FINISH   (1U << 4)
/** A supplied deployment evidence object was invalid. */
#define PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT  (1U << 5)

/** All trace builder error bits known by this API version. */
#define PQCP_DEPLOYMENT_TRACE_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_TRACE_ERROR_NOT_INITIALIZED | \
	 PQCP_DEPLOYMENT_TRACE_ERROR_OVERFLOW | \
	 PQCP_DEPLOYMENT_TRACE_ERROR_LINE_TOO_LONG | \
	 PQCP_DEPLOYMENT_TRACE_ERROR_REPLAY_APPEND | \
	 PQCP_DEPLOYMENT_TRACE_ERROR_REPLAY_FINISH | \
	 PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT)

/** Caller-owned deployment trace builder state. */
struct pqcp_deployment_trace_builder {
	/** Builder schema version. */
	uint32_t schema_version;
	/** Caller-owned output buffer. */
	char *buffer;
	/** Output buffer capacity. */
	size_t capacity;
	/** Bytes written, excluding final NUL. */
	size_t length;
	/** Number of marker lines appended. */
	uint32_t line_count;
	/** First error bit, or zero. */
	uint32_t first_error;
	/** Accumulated error bit mask. */
	uint32_t error_mask;
	/** Lightweight rolling digest state. */
	uint64_t digest_words[4];
	/** Replay verifier state for replayable deployment markers. */
	struct pqcp_deployment_transcript_state replay_state;
	/** True after finish has been called. */
	bool finished;
};

/** Final deployment trace digest and replay result. */
struct pqcp_deployment_trace_digest {
	/** Digest schema version. */
	uint32_t schema_version;
	/** Number of lines included in the digest. */
	uint32_t line_count;
	/** Number of bytes included in the digest. */
	uint32_t byte_count;
	/** Error bit mask. Zero means no trace-builder error. */
	uint32_t error_mask;
	/** Hex-encoded rolling digest. */
	char digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Replay result for replayable deployment markers. */
	struct pqcp_deployment_transcript_result replay_result;
	/** True when trace-builder and transcript replay both passed. */
	bool passed;
};

/** Initialize a caller-owned trace builder and output buffer. */
int pqcp_deployment_trace_builder_init(
	struct pqcp_deployment_trace_builder *builder,
	char *buffer,
	size_t capacity);

/** Append an already formatted line; useful for replay/tamper tests. */
int pqcp_deployment_trace_builder_append_line(
	struct pqcp_deployment_trace_builder *builder,
	const char *line);

/** Append a deployment campaign summary and metric rows. */
int pqcp_deployment_trace_builder_append_campaign(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_campaign_summary *summary);

/** Append one deployment scenario marker. */
int pqcp_deployment_trace_builder_append_scenario(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_scenario *scenario);

/** Append one deployment candidate marker. */
int pqcp_deployment_trace_builder_append_candidate(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	const struct pqcp_deployment_candidate_result *result);

/** Append one deployment robustness candidate marker. */
int pqcp_deployment_trace_builder_append_robust_candidate(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_candidate_robustness *robustness);

/** Append one deployment decision marker. */
int pqcp_deployment_trace_builder_append_decision(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_report *report,
	const struct pqcp_deployment_candidate_result *results);

/** Append one deployment robustness summary marker. */
int pqcp_deployment_trace_builder_append_robustness(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_robustness_report *report,
	const struct pqcp_deployment_candidate_robustness *results);

/** Append one deployment evidence-gap marker. */
int pqcp_deployment_trace_builder_append_gap(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_gap_plan_entry *entry);

/** Finish trace building and transcript replay. */
int pqcp_deployment_trace_builder_finish(
	struct pqcp_deployment_trace_builder *builder,
	struct pqcp_deployment_trace_digest *digest);

/** Emit one stable trace digest marker. */
int pqcp_deployment_trace_digest_emit(
	const struct pqcp_deployment_trace_digest *digest);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_TRACE_BUILDER_H_ */
