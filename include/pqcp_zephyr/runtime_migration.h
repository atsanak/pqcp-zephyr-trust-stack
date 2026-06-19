/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Measured profile migration and canary control.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_MIGRATION_H_
#define PQCP_ZEPHYR_RUNTIME_MIGRATION_H_

#include <pqcp_zephyr/runtime_governance.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_MIGRATION_MAX_CANARIES 8U

enum pqcp_runtime_migration_state {
	PQCP_RUNTIME_MIGRATION_IDLE = 0,
	PQCP_RUNTIME_MIGRATION_ASSESSING,
	PQCP_RUNTIME_MIGRATION_CANARY,
	PQCP_RUNTIME_MIGRATION_DRAINING,
	PQCP_RUNTIME_MIGRATION_PROMOTED,
	PQCP_RUNTIME_MIGRATION_ROLLING_BACK,
	PQCP_RUNTIME_MIGRATION_ROLLED_BACK,
	PQCP_RUNTIME_MIGRATION_BLOCKED,
};

enum pqcp_runtime_migration_reason {
	PQCP_RUNTIME_MIGRATION_REASON_NONE = 0U,
	PQCP_RUNTIME_MIGRATION_REASON_TARGET_MISSING = (1U << 0),
	PQCP_RUNTIME_MIGRATION_REASON_TARGET_DISABLED = (1U << 1),
	PQCP_RUNTIME_MIGRATION_REASON_SECURITY_DOWNGRADE = (1U << 2),
	PQCP_RUNTIME_MIGRATION_REASON_EVIDENCE_REGRESSION = (1U << 3),
	PQCP_RUNTIME_MIGRATION_REASON_LATENCY_REGRESSION = (1U << 4),
	PQCP_RUNTIME_MIGRATION_REASON_MEMORY_REGRESSION = (1U << 5),
	PQCP_RUNTIME_MIGRATION_REASON_CANARY_FAILURE = (1U << 6),
	PQCP_RUNTIME_MIGRATION_REASON_ACTIVE_SESSIONS = (1U << 7),
	PQCP_RUNTIME_MIGRATION_REASON_DEADLINE = (1U << 8),
	PQCP_RUNTIME_MIGRATION_REASON_AUDIT = (1U << 9),
};

struct pqcp_runtime_migration_policy {
	uint32_t schema_version;
	uint32_t minimum_security_level;
	uint32_t minimum_evidence_score;
	uint32_t required_canary_successes;
	uint32_t maximum_canary_failures;
	uint32_t maximum_latency_regression_permille;
	uint32_t maximum_memory_regression_permille;
	uint64_t drain_timeout_ms;
	uint64_t canary_timeout_ms;
	bool require_measured_target;
	bool forbid_security_downgrade;
	bool drain_old_sessions;
	bool rollback_on_canary_failure;
};

struct pqcp_runtime_migration_canary {
	uint32_t schema_version;
	uint64_t canary_id;
	uint64_t session_id;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	uint64_t latency_us;
	uint64_t cycles;
	uint64_t stack_bytes;
	int result;
	bool completed;
	bool successful;
};

struct pqcp_runtime_migration_report {
	uint32_t schema_version;
	uint64_t migration_id;
	enum pqcp_runtime_migration_state state;
	uint32_t reason_mask;
	uint32_t old_security_level;
	uint32_t new_security_level;
	uint32_t old_evidence_score;
	uint32_t new_evidence_score;
	uint32_t canaries_started;
	uint32_t canaries_succeeded;
	uint32_t canaries_failed;
	uint32_t sessions_draining;
	uint32_t sessions_remaining;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	char from_profile[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	char to_profile[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
};

struct pqcp_runtime_migration {
	uint32_t schema_version;
	uint64_t migration_id;
	enum pqcp_runtime_migration_state state;
	struct pqcp_runtime_controller *controller;
	struct pqcp_runtime_migration_policy policy;
	struct pqcp_runtime_migration_canary
		canaries[PQCP_RUNTIME_MIGRATION_MAX_CANARIES];
	size_t canary_count;
	uint32_t reason_mask;
	uint64_t started_at_ms;
	uint64_t deadline_ms;
	char from_profile[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	char to_profile[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	bool target_enabled_before;
	bool source_enabled_before;
	struct k_mutex lock;
};

int pqcp_runtime_migration_policy_default(
	struct pqcp_runtime_migration_policy *policy);
int pqcp_runtime_migration_begin(
	struct pqcp_runtime_migration *migration,
	uint64_t migration_id,
	const char *from_profile,
	const char *to_profile,
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_migration_policy *policy,
	uint64_t now_ms,
	struct pqcp_runtime_migration_report *report);
int pqcp_runtime_migration_start_canary(
	struct pqcp_runtime_migration *migration,
	uint64_t canary_id,
	uint64_t session_id,
	uint64_t now_ms);
int pqcp_runtime_migration_complete_canary(
	struct pqcp_runtime_migration *migration,
	uint64_t canary_id,
	const struct pqcp_runtime_measurement *measurement,
	uint64_t now_ms);
int pqcp_runtime_migration_promote(
	struct pqcp_runtime_migration *migration,
	uint64_t now_ms,
	struct pqcp_runtime_migration_report *report);
int pqcp_runtime_migration_rollback(
	struct pqcp_runtime_migration *migration,
	uint64_t now_ms,
	struct pqcp_runtime_migration_report *report);
int pqcp_runtime_migration_tick(
	struct pqcp_runtime_migration *migration,
	uint64_t now_ms,
	struct pqcp_runtime_migration_report *report);
int pqcp_runtime_migration_audit(
	const struct pqcp_runtime_migration *migration);
int pqcp_runtime_migration_report_verify(
	const struct pqcp_runtime_migration_report *report);
int pqcp_runtime_migration_emit(
	const struct pqcp_runtime_migration_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_MIGRATION_H_ */
