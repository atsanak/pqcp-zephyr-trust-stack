/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment review audit evidence
 *
 * Stability: experimental evidence API. This module summarizes one or more
 * replayed deployment review packets into a deterministic firmware-side audit
 * marker that catches replay failure, status drift, top-candidate drift, and
 * digest instability without dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_REVIEW_AUDIT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_REVIEW_AUDIT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_review_verifier.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for deployment review audit reports and markers. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_SCHEMA_VERSION 1U

/** Maximum verifier results accepted by the audit API. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_MAX_RESULTS 16U

/** Audit input pointer, count, or policy was invalid. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_INVALID_INPUT      (1U << 0)
/** No replay results were supplied. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_NO_RESULTS         (1U << 1)
/** At least one replay result failed. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_REPLAY_FAILED      (1U << 2)
/** Top candidate changed across replayed packets. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_TOP_DRIFT          (1U << 3)
/** Trace digest changed across replayed packets. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_TRACE_DIGEST_DRIFT (1U << 4)
/** Packet digest changed when stability was required. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_PACKET_DIGEST_DRIFT (1U << 5)
/** Packet status was below the policy requirement. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_PACKET_STATUS      (1U << 6)
/** A score field was outside its stable 0-100 range. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_SCORE_RANGE        (1U << 7)

/** All deployment review audit error bits known by this API version. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_NO_RESULTS | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_REPLAY_FAILED | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_TOP_DRIFT | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_TRACE_DIGEST_DRIFT | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_PACKET_DIGEST_DRIFT | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_PACKET_STATUS | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_SCORE_RANGE)

/** Fewer replay samples than the requested audit depth were supplied. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_SAMPLE_COUNT (1U << 0)
/** Packet status is FAIL/WARN but policy only required replay integrity. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_NOT_PASS  (1U << 1)
/** Review score is below the configured warning threshold. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_REVIEW_SCORE (1U << 2)
/** Packet digests differ but digest stability was not a hard requirement. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_DIVERSITY (1U << 3)
/** Claim score is below the configured warning threshold. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_CLAIM_SCORE  (1U << 4)

/** All deployment review audit warning bits known by this API version. */
#define PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_SAMPLE_COUNT | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_NOT_PASS | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_REVIEW_SCORE | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_DIVERSITY | \
	 PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_CLAIM_SCORE)

/** Overall deployment review audit status. */
enum pqcp_deployment_review_audit_status {
	PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL = 0,
	PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN,
	PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS,
};

/** Policy controlling review-result aggregation. */
struct pqcp_deployment_review_audit_policy {
	/** Minimum replay results desired for the audit. */
	uint32_t minimum_results;
	/** Minimum accepted review score before a warning is raised. */
	uint32_t review_score_warn_floor;
	/** Minimum accepted claim score before a warning is raised. */
	uint32_t claim_score_warn_floor;
	/** Require every replay result to pass. */
	bool require_replay_pass;
	/** Require every packet status to be PASS. */
	bool require_packet_pass;
	/** Require all replay results to report the same top candidate. */
	bool require_stable_top;
	/** Require all replay results to report the same trace digest. */
	bool require_stable_trace_digest;
	/** Require all replay results to report the same packet digest. */
	bool require_stable_packet_digest;
};

/** Firmware-side aggregate report over replayed review packet evidence. */
struct pqcp_deployment_review_audit_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall audit status. */
	enum pqcp_deployment_review_audit_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Number of replay results audited. */
	uint32_t result_count;
	/** Number of replay results whose verifier passed. */
	uint32_t replay_pass_count;
	/** Number of replay results whose verifier failed. */
	uint32_t replay_fail_count;
	/** Number of final packets with status PASS. */
	uint32_t packet_pass_count;
	/** Number of final packets with status WARN. */
	uint32_t packet_warn_count;
	/** Number of final packets with status FAIL. */
	uint32_t packet_fail_count;
	/** Number of distinct packet digests, saturated at result_count. */
	uint32_t unique_packet_digest_count;
	/** Minimum readiness score observed. */
	uint32_t min_readiness_score;
	/** Minimum claim score observed. */
	uint32_t min_claim_score;
	/** Minimum review score observed. */
	uint32_t min_review_score;
	/** Maximum review score observed. */
	uint32_t max_review_score;
	/** Integer average review score observed. */
	uint32_t avg_review_score;
	/** True when every replay result used the same top candidate. */
	bool stable_top_candidate;
	/** True when every replay result used the same trace digest. */
	bool stable_trace_digest;
	/** True when every replay result used the same packet digest. */
	bool stable_packet_digest;
	/** Representative top candidate, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Representative trace digest. */
	char trace_digest_hex[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	/** Representative packet digest. */
	char packet_digest_hex[
		PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
};

/** Convert a deployment review audit status to a stable marker token. */
const char *pqcp_deployment_review_audit_status_str(
	enum pqcp_deployment_review_audit_status status);

/** Populate a conservative default review-audit policy. */
int pqcp_deployment_review_audit_default_policy(
	struct pqcp_deployment_review_audit_policy *policy);

/** Run a firmware-side audit over one or more replayed review packets. */
int pqcp_deployment_review_audit_run(
	const struct pqcp_deployment_review_verifier_result *results,
	size_t result_count,
	const struct pqcp_deployment_review_audit_policy *policy,
	struct pqcp_deployment_review_audit_report *report);

/** Emit a stable deployment review audit marker. */
int pqcp_deployment_review_audit_emit(
	const struct pqcp_deployment_review_audit_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_REVIEW_AUDIT_H_ */
