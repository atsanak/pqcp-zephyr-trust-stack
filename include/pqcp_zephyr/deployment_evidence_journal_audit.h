/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment evidence journal audit
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_journal_replay.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_SCHEMA_VERSION 1U
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_MAX_SNAPSHOTS 16U
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_DIGEST_HEX_CHARS 64U

#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_INVALID_INPUT \
	(1U << 0)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_REPLAY_FAILURE \
	(1U << 1)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_DEVICE_DRIFT \
	(1U << 2)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_BOARD_DRIFT \
	(1U << 3)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_ENTRY_ROLLBACK \
	(1U << 4)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_BOOT_ROLLBACK \
	(1U << 5)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_TIME_ROLLBACK \
	(1U << 6)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_ROOT_REUSE \
	(1U << 7)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_SIGNATURE_REGRESSION \
	(1U << 8)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_PRODUCTION_REGRESSION \
	(1U << 9)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_SCORE_FLOOR \
	(1U << 10)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_ERROR_KNOWN_MASK \
	((1U << 11) - 1U)

#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_LOW_SAMPLES \
	(1U << 0)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_UNSIGNED \
	(1U << 1)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_NON_PRODUCTION \
	(1U << 2)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_FAILURE_HISTORY \
	(1U << 3)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_SCORE_FLOOR \
	(1U << 4)
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARNING_KNOWN_MASK \
	((1U << 5) - 1U)

enum pqcp_deployment_evidence_journal_audit_status {
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_FAIL = 0,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_WARN,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_PASS,
};

struct pqcp_deployment_evidence_journal_audit_policy {
	uint32_t min_snapshots;
	uint32_t min_entries;
	uint32_t min_signed_percent;
	uint32_t min_production_percent;
	uint32_t min_average_score;
	bool require_all_replays;
	bool require_stable_identity;
	bool require_monotonic_growth;
	bool require_unique_roots;
	bool require_no_signature_regression;
	bool require_no_production_regression;
	bool score_floor_blocks;
};

struct pqcp_deployment_evidence_journal_audit_report {
	uint32_t schema_version;
	enum pqcp_deployment_evidence_journal_audit_status status;
	uint32_t error_mask;
	uint32_t warning_mask;
	uint32_t snapshot_count;
	uint32_t replay_pass_count;
	uint32_t replay_fail_count;
	uint32_t min_entries;
	uint32_t max_entries;
	uint32_t total_entries;
	uint32_t min_score;
	uint32_t max_score;
	uint32_t average_score;
	uint32_t signed_entries;
	uint32_t production_entries;
	uint32_t failed_passports;
	uint32_t distinct_root_count;
	uint64_t first_boot_counter;
	uint64_t last_boot_counter;
	uint64_t first_capture_time_ms;
	uint64_t last_capture_time_ms;
	bool stable_device_id;
	bool stable_board;
	bool monotonic_entry_growth;
	bool monotonic_boot_counter;
	bool monotonic_capture_time;
	bool unique_roots;
	bool signature_non_regression;
	bool production_non_regression;
	char device_id[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DEVICE_ID_MAX_CHARS];
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	char first_root_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	char last_root_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	char audit_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_DIGEST_HEX_CHARS + 1U];
};

const char *pqcp_deployment_evidence_journal_audit_status_str(
	enum pqcp_deployment_evidence_journal_audit_status status);

int pqcp_deployment_evidence_journal_audit_default_policy(
	struct pqcp_deployment_evidence_journal_audit_policy *policy);

int pqcp_deployment_evidence_journal_audit_run(
	const struct pqcp_deployment_evidence_journal_replay_result *snapshots,
	size_t snapshot_count,
	const struct pqcp_deployment_evidence_journal_audit_policy *policy,
	struct pqcp_deployment_evidence_journal_audit_report *report);

int pqcp_deployment_evidence_journal_audit_emit(
	const struct pqcp_deployment_evidence_journal_audit_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_H_ */
