/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Tamper matrix replay audit
 *
 * Stability: experimental evidence API. This module aggregates one or more
 * replayed tamper matrix results, detects replay failure, detection
 * weakness, coverage drift, digest drift, stage drift, and profile drift,
 * then emits a compact firmware-native audit marker. It performs no
 * cryptographic operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_TAMPER_MATRIX_AUDIT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_TAMPER_MATRIX_AUDIT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_tamper_matrix_replay.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for tamper matrix audit reports and markers. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_SCHEMA_VERSION 1U

/** Maximum replay results accepted by the tamper matrix audit API. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_MAX_RESULTS 16U

/** Hex characters in a tamper matrix audit digest. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_DIGEST_HEX_CHARS 64U

/** Audit input pointer, count, or policy was invalid. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_INVALID_INPUT (1U << 0)
/** No replay results were supplied. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_NO_RESULTS    (1U << 1)
/** At least one tamper matrix replay result failed. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_REPLAY_FAILED (1U << 2)
/** Matrix status was below the policy requirement. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_MATRIX_STATUS (1U << 3)
/** Detection coverage fell below the policy floor. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_COVERAGE_FLOOR (1U << 4)
/** Recomputed matrix digest changed across audited results. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_DIGEST_DRIFT  (1U << 5)
/** Coverage changed across audited results. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_COVERAGE_DRIFT (1U << 6)
/** Stage mask changed across audited results. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_STAGE_DRIFT   (1U << 7)
/** Release profile changed across audited results. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_PROFILE_DRIFT (1U << 8)
/** Replay top candidate changed across audited results. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_TOP_DRIFT     (1U << 9)
/** Replay nonce changed across audited results. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_NONCE_DRIFT   (1U << 10)
/** Replay result schema, marker set, or mandatory fields were malformed. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_MALFORMED_RESULT (1U << 11)

/** All tamper matrix audit error bits known by this API version. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_KNOWN_MASK \
	(PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_INVALID_INPUT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_NO_RESULTS | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_REPLAY_FAILED | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_MATRIX_STATUS | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_COVERAGE_FLOOR | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_DIGEST_DRIFT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_COVERAGE_DRIFT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_STAGE_DRIFT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_PROFILE_DRIFT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_TOP_DRIFT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_NONCE_DRIFT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_MALFORMED_RESULT)

/** Fewer replay samples than the requested audit depth were supplied. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARNING_LOW_SAMPLE_COUNT (1U << 0)
/** Matrix status is WARN but policy only required replay integrity. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARNING_MATRIX_NOT_PASS (1U << 1)
/** Coverage is below the warning floor but not hard-blocking. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARNING_LOW_COVERAGE    (1U << 2)

/** All tamper matrix audit warning bits known by this API version. */
#define PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARNING_KNOWN_MASK \
	(PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARNING_LOW_SAMPLE_COUNT | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARNING_MATRIX_NOT_PASS | \
	 PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARNING_LOW_COVERAGE)

/** Overall tamper matrix audit status. */
enum pqcp_deployment_tamper_matrix_audit_status {
	PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_FAIL = 0,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARN,
	PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_PASS,
};

/** Policy controlling tamper matrix replay aggregation. */
struct pqcp_deployment_tamper_matrix_audit_policy {
	/** Minimum replay results desired for the audit. */
	uint32_t minimum_results;
	/** Minimum accepted coverage in permille before warning. */
	uint32_t coverage_warn_floor_permille;
	/** Minimum accepted coverage in permille before failure. */
	uint32_t coverage_fail_floor_permille;
	/** Require every tamper matrix replay result to pass. */
	bool require_replay_pass;
	/** Require every matrix status to be PASS. */
	bool require_matrix_pass;
	/** Require every result to share one recomputed matrix digest. */
	bool require_stable_digest;
	/** Require every result to share one coverage value. */
	bool require_stable_coverage;
	/** Require every result to share one stage mask. */
	bool require_stable_stages;
	/** Require every result to share one release profile. */
	bool require_stable_profile;
	/** Require every result to share one top candidate. */
	bool require_stable_top;
	/** Require every result to share one nonce. */
	bool require_stable_nonce;
};

/** Firmware-side aggregate report over replayed tamper matrices. */
struct pqcp_deployment_tamper_matrix_audit_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Overall audit status. */
	enum pqcp_deployment_tamper_matrix_audit_status status;
	/** Error bit mask. */
	uint32_t error_mask;
	/** Warning bit mask. */
	uint32_t warning_mask;
	/** Representative release profile. */
	enum pqcp_deployment_release_gate_profile profile;
	/** Number of replay results audited. */
	uint32_t result_count;
	/** Number of replay results that passed. */
	uint32_t replay_pass_count;
	/** Number of replay results that failed. */
	uint32_t replay_fail_count;
	/** Number of matrices with status PASS. */
	uint32_t matrix_pass_count;
	/** Number of matrices with status WARN. */
	uint32_t matrix_warn_count;
	/** Number of matrices with status FAIL. */
	uint32_t matrix_fail_count;
	/** Number of distinct recomputed matrix digests. */
	uint32_t unique_matrix_digest_count;
	/** Minimum coverage observed, in permille. */
	uint32_t min_coverage_permille;
	/** Maximum coverage observed, in permille. */
	uint32_t max_coverage_permille;
	/** Integer average coverage observed, in permille. */
	uint32_t avg_coverage_permille;
	/** Total attack cells across audited results. */
	uint32_t total_attack_count;
	/** Total detected attack cells across audited results. */
	uint32_t total_detected_count;
	/** Total missed attack cells across audited results. */
	uint32_t total_missed_count;
	/** True when every result used the same matrix digest. */
	bool stable_matrix_digest;
	/** True when every result used the same coverage value. */
	bool stable_coverage;
	/** True when every result used the same stage mask. */
	bool stable_stages;
	/** True when every result used the same release profile. */
	bool stable_profile;
	/** True when every result used the same top candidate. */
	bool stable_top_candidate;
	/** True when every result used the same nonce. */
	bool stable_nonce;
	/** Representative stage mask. */
	uint32_t stage_mask;
	/** Representative top candidate, or "none". */
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	/** Representative nonce. */
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	/** Representative recomputed matrix digest. */
	char matrix_digest_hex[
		PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U];
	/** Stable digest over the audited replay result summaries. */
	char audit_digest_hex[
		PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_DIGEST_HEX_CHARS + 1U];
};

/** Convert tamper matrix audit status to a stable marker token. */
const char *pqcp_deployment_tamper_matrix_audit_status_str(
	enum pqcp_deployment_tamper_matrix_audit_status status);

/** Populate a conservative default tamper matrix audit policy. */
int pqcp_deployment_tamper_matrix_audit_default_policy(
	struct pqcp_deployment_tamper_matrix_audit_policy *policy);

/** Run a firmware-side audit over one or more replayed tamper matrices. */
int pqcp_deployment_tamper_matrix_audit_run(
	const struct pqcp_deployment_tamper_matrix_replay_result *results,
	size_t result_count,
	const struct pqcp_deployment_tamper_matrix_audit_policy *policy,
	struct pqcp_deployment_tamper_matrix_audit_report *report);

/** Emit a stable tamper matrix audit marker. */
int pqcp_deployment_tamper_matrix_audit_emit(
	const struct pqcp_deployment_tamper_matrix_audit_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_TAMPER_MATRIX_AUDIT_H_ */
