/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Operational control, policy, audit, health, and recovery for the PQCP
 * executable runtime.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_CONTROL_H_
#define PQCP_ZEPHYR_RUNTIME_CONTROL_H_

#include <pqcp_zephyr/runtime_session.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_AUDIT_MAX_DETAIL_CHARS 48U
#define PQCP_RUNTIME_AUDIT_DIGEST_BYTES 32U

enum pqcp_runtime_audit_event {
	PQCP_RUNTIME_AUDIT_BOOT = 1,
	PQCP_RUNTIME_AUDIT_KEY_CREATE,
	PQCP_RUNTIME_AUDIT_KEY_ROTATE,
	PQCP_RUNTIME_AUDIT_KEY_DESTROY,
	PQCP_RUNTIME_AUDIT_JOB_SUBMIT,
	PQCP_RUNTIME_AUDIT_JOB_COMPLETE,
	PQCP_RUNTIME_AUDIT_SESSION_OPEN,
	PQCP_RUNTIME_AUDIT_SESSION_DRAIN,
	PQCP_RUNTIME_AUDIT_SESSION_CLOSE,
	PQCP_RUNTIME_AUDIT_PROFILE_TRANSITION,
	PQCP_RUNTIME_AUDIT_SNAPSHOT,
	PQCP_RUNTIME_AUDIT_RESTORE,
	PQCP_RUNTIME_AUDIT_FAULT,
};

enum pqcp_runtime_health_status {
	PQCP_RUNTIME_HEALTH_HEALTHY = 0,
	PQCP_RUNTIME_HEALTH_DEGRADED,
	PQCP_RUNTIME_HEALTH_RECOVERY,
	PQCP_RUNTIME_HEALTH_LOCKDOWN,
};

struct pqcp_runtime_key_policy {
	uint32_t schema_version;
	uint64_t maximum_volatile_lifetime_ms;
	uint64_t maximum_persistent_lifetime_ms;
	uint32_t maximum_uses;
	uint32_t allowed_family_mask;
	uint32_t allowed_usage_mask;
	uint32_t minimum_security_level;
	bool allow_persistent;
	bool require_expiry;
	bool require_owner;
	bool allow_public_export;
};

struct pqcp_runtime_audit_entry {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t timestamp_ms;
	enum pqcp_runtime_audit_event event;
	int result;
	uint64_t object_id;
	uint32_t reason_mask;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	char detail[PQCP_RUNTIME_AUDIT_MAX_DETAIL_CHARS];
	uint8_t previous_digest[PQCP_RUNTIME_AUDIT_DIGEST_BYTES];
	uint8_t digest[PQCP_RUNTIME_AUDIT_DIGEST_BYTES];
};

struct pqcp_runtime_audit_log {
	uint32_t schema_version;
	struct pqcp_runtime_audit_entry *entries;
	size_t capacity;
	size_t count;
	size_t head;
	uint64_t next_sequence;
	uint64_t overwritten_count;
	uint8_t root_digest[PQCP_RUNTIME_AUDIT_DIGEST_BYTES];
	struct k_mutex lock;
};

struct pqcp_runtime_health_policy {
	uint32_t schema_version;
	uint32_t maximum_consecutive_failures;
	uint32_t maximum_queue_depth;
	uint32_t minimum_success_permille;
	uint64_t maximum_latency_us;
	uint64_t maximum_stack_bytes;
	uint64_t maximum_workspace_bytes;
	bool lockdown_on_audit_failure;
	bool lockdown_on_key_store_failure;
	bool recovery_on_profile_failure;
};

struct pqcp_runtime_health_report {
	uint32_t schema_version;
	enum pqcp_runtime_health_status status;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	uint32_t success_permille;
	uint32_t queue_depth;
	uint32_t consecutive_failures;
	uint64_t maximum_latency_us;
	uint64_t maximum_stack_bytes;
	uint64_t maximum_workspace_bytes;
	uint64_t jobs_observed;
	uint64_t jobs_failed;
	bool key_store_valid;
	bool executor_valid;
	bool session_table_valid;
	bool audit_valid;
};

struct pqcp_runtime_controller {
	uint32_t schema_version;
	struct pqcp_runtime_key_store *key_store;
	struct pqcp_runtime_executor *executor;
	struct pqcp_runtime_session_manager *sessions;
	struct pqcp_runtime_audit_log *audit;
	struct pqcp_runtime_key_policy key_policy;
	struct pqcp_runtime_health_policy health_policy;
	struct pqcp_runtime_health_report health;
	uint64_t last_tick_ms;
	uint32_t consecutive_failures;
	bool initialized;
	bool accepting_sessions;
	bool lockdown;
};

int pqcp_runtime_key_policy_default(
	struct pqcp_runtime_key_policy *policy);
int pqcp_runtime_key_policy_validate(
	const struct pqcp_runtime_key_policy *policy);
int pqcp_runtime_key_policy_check(
	const struct pqcp_runtime_key_policy *policy,
	const struct pqcp_runtime_key_request *request,
	uint32_t *reason_mask);

int pqcp_runtime_audit_init(
	struct pqcp_runtime_audit_log *log,
	struct pqcp_runtime_audit_entry *entries,
	size_t capacity);
int pqcp_runtime_audit_append(
	struct pqcp_runtime_audit_log *log,
	enum pqcp_runtime_audit_event event,
	uint64_t timestamp_ms,
	uint64_t object_id,
	int result,
	uint32_t reason_mask,
	const char *profile_id,
	const char *detail);
int pqcp_runtime_audit_verify(
	struct pqcp_runtime_audit_log *log);
const struct pqcp_runtime_audit_entry *pqcp_runtime_audit_get(
	const struct pqcp_runtime_audit_log *log,
	size_t logical_index);

int pqcp_runtime_health_policy_default(
	struct pqcp_runtime_health_policy *policy);
int pqcp_runtime_health_evaluate(
	struct pqcp_runtime_controller *controller,
	struct pqcp_runtime_health_report *report);

int pqcp_runtime_controller_init(
	struct pqcp_runtime_controller *controller,
	struct pqcp_runtime_key_store *key_store,
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_session_manager *sessions,
	struct pqcp_runtime_audit_log *audit,
	uint64_t now_ms);
int pqcp_runtime_controller_open_session(
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_session_request *request,
	struct pqcp_runtime_session **session);
int pqcp_runtime_controller_submit(
	struct pqcp_runtime_controller *controller,
	uint64_t session_id,
	struct pqcp_runtime_job *job);
int pqcp_runtime_controller_close_session(
	struct pqcp_runtime_controller *controller,
	uint64_t session_id);
int pqcp_runtime_controller_transition_profile(
	struct pqcp_runtime_controller *controller,
	const char *from_profile,
	const char *to_profile,
	uint64_t now_ms);
int pqcp_runtime_controller_tick(
	struct pqcp_runtime_controller *controller,
	uint64_t now_ms);
int pqcp_runtime_controller_lockdown(
	struct pqcp_runtime_controller *controller,
	uint32_t reason_mask,
	uint64_t now_ms);
int pqcp_runtime_controller_recover(
	struct pqcp_runtime_controller *controller,
	uint64_t now_ms);
int pqcp_runtime_controller_audit(
	struct pqcp_runtime_controller *controller);

int pqcp_runtime_recovery_restore(
	struct pqcp_runtime_controller *controller,
	const uint8_t *snapshot,
	size_t snapshot_length,
	struct pqcp_runtime_session *session_storage,
	size_t session_capacity,
	struct pqcp_runtime_profile_state *profile_storage,
	size_t profile_capacity,
	struct pqcp_runtime_snapshot_info *info,
	uint64_t now_ms);
int pqcp_runtime_recovery_validate_key_references(
	struct pqcp_runtime_controller *controller);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_CONTROL_H_ */
