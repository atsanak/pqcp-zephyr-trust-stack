/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Deployment review packet evidence
 *
 * Stability: experimental evidence API. The review packet binds deployment
 * pipeline, budget, and next-experiment planning summaries into a compact,
 * deterministic firmware marker for partner review transcripts.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_REVIEW_PACKET_H_
#define PQCP_ZEPHYR_DEPLOYMENT_REVIEW_PACKET_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_experiment_plan.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment review packet structures and markers. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION 1U

/** Digest hex length excluding NUL. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS 64U

/** One formatted review fact line, including terminating NUL. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_LINE_MAX 512U

/** Review packet input was malformed. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_INVALID_INPUT (1U << 0)
/** Caller-owned output buffer overflowed. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_OVERFLOW      (1U << 1)
/** Review summaries disagree on top candidate identity. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_TOP_MISMATCH  (1U << 2)
/** Summary status fields contradict each other. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_STATUS_MISMATCH (1U << 3)

/** All deployment review packet error bits known by this API version. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_OVERFLOW | \
	 PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_TOP_MISMATCH | \
	 PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_STATUS_MISMATCH)

/** Review packet has non-blocking open experiment rows. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_OPEN_EXPERIMENTS (1U << 0)
/** Review packet has low readiness or claim score but no hard failure. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_LOW_SCORE        (1U << 1)
/** Review packet represents simulation/local evidence only. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_LOCAL_ONLY       (1U << 2)

/** All deployment review packet warning bits known by this API version. */
#define PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_OPEN_EXPERIMENTS | \
	 PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_LOW_SCORE | \
	 PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_LOCAL_ONLY)

/** Overall review packet status. */
enum pqcp_deployment_review_packet_status {
	PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL = 0,
	PQCP_DEPLOYMENT_REVIEW_PACKET_WARN,
	PQCP_DEPLOYMENT_REVIEW_PACKET_PASS,
};

/** Deterministic summary of deployment evidence ready for review. */
struct pqcp_deployment_review_packet {
	/** Packet schema version. */
	uint32_t schema_version;
	/** Overall packet status. */
	enum pqcp_deployment_review_packet_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Canonical fact lines included in the packet digest. */
	uint32_t line_count;
	/** Canonical fact bytes included in the packet digest. */
	uint32_t byte_count;
	/** Candidate rows represented by the pipeline. */
	uint32_t candidate_count;
	/** Open experiment rows represented by the plan. */
	uint32_t experiment_count;
	/** Blocking experiment rows represented by the plan. */
	uint32_t blocking_experiment_count;
	/** Stable top candidate identifier, or "none". */
	const char *top_candidate_id;
	/** Pipeline readiness score copied for review. */
	uint32_t readiness_score;
	/** Claim matrix score copied for review. */
	uint32_t claim_score;
	/** Packet-level score from 0 to 100. */
	uint32_t review_score;
	/** True when pipeline passed. */
	bool pipeline_passed;
	/** True when replay passed. */
	bool replay_passed;
	/** True when budget passed. */
	bool budget_passed;
	/** True when experiment plan passed. */
	bool experiment_plan_passed;
	/** Trace digest copied from the pipeline result. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Digest over canonical review fact lines. */
	char packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
};

/** Convert a review packet status to a stable marker token. */
const char *pqcp_deployment_review_packet_status_str(
	enum pqcp_deployment_review_packet_status status);

/**
 * @brief Build a deterministic deployment review packet.
 *
 * The output buffer receives canonical `PQCP_DEPLOYMENT_REVIEW_FACT` lines.
 * The final packet marker is emitted separately by
 * pqcp_deployment_review_packet_emit().
 */
int pqcp_deployment_review_packet_build(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	char *buffer,
	size_t buffer_size,
	struct pqcp_deployment_review_packet *packet);

/** Emit canonical review fact lines from the caller-owned buffer. */
int pqcp_deployment_review_packet_emit_facts(
	const char *buffer,
	const struct pqcp_deployment_review_packet *packet);

/** Emit one stable final deployment review packet marker. */
int pqcp_deployment_review_packet_emit(
	const struct pqcp_deployment_review_packet *packet);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_REVIEW_PACKET_H_ */
