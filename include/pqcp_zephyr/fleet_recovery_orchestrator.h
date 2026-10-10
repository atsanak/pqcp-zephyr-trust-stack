/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Typed, checkpointed fleet recovery playbook orchestration.
 *
 * This layer complements pqcp_fleet_recovery_manager by binding an authorized
 * recovery session to an acyclic playbook, invoking platform-owned recovery
 * operations, recording an evidence chain, and applying compensating actions.
 * It performs no allocation; all step, checkpoint, evidence, and audit storage
 * is supplied by the caller.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_RECOVERY_ORCHESTRATOR_H_
#define PQCP_ZEPHYR_FLEET_RECOVERY_ORCHESTRATOR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_resilience.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_RECOVERY_ORCHESTRATOR_SCHEMA_VERSION 1U
#define PQCP_FLEET_RECOVERY_MAX_STEPS 32U
#define PQCP_FLEET_RECOVERY_CHALLENGE_BYTES 32U
#define PQCP_FLEET_RECOVERY_BINDING_BYTES PQCP_FLEET_DIGEST_BYTES
#define PQCP_FLEET_RECOVERY_EVIDENCE_DIGEST_BYTES \
	PQCP_FLEET_DIGEST_BYTES
#define PQCP_FLEET_RECOVERY_COMPONENT_MAX_CHARS 48U
#define PQCP_FLEET_RECOVERY_CREDENTIAL_MAX_CHARS 48U
#define PQCP_FLEET_RECOVERY_SESSION_LABEL_MAX_CHARS 32U

enum pqcp_fleet_recovery_step_type {
	PQCP_FLEET_RECOVERY_STEP_NONE = 0,
	PQCP_FLEET_RECOVERY_STEP_TRUST_ANCHOR_RENEWAL,
	PQCP_FLEET_RECOVERY_STEP_REVOCATION_POLICY_SNAPSHOT,
	PQCP_FLEET_RECOVERY_STEP_CREDENTIAL_REPLACEMENT,
	PQCP_FLEET_RECOVERY_STEP_UPDATE_ROLLBACK,
	PQCP_FLEET_RECOVERY_STEP_SECURE_TIME_RESTORE,
	PQCP_FLEET_RECOVERY_STEP_SESSION_REOPEN,
	PQCP_FLEET_RECOVERY_STEP_TYPE_COUNT,
};

enum pqcp_fleet_recovery_step_state {
	PQCP_FLEET_RECOVERY_STEP_PENDING = 0,
	PQCP_FLEET_RECOVERY_STEP_READY,
	PQCP_FLEET_RECOVERY_STEP_RUNNING,
	PQCP_FLEET_RECOVERY_STEP_RETRY_WAIT,
	PQCP_FLEET_RECOVERY_STEP_SUCCEEDED,
	PQCP_FLEET_RECOVERY_STEP_FAILED,
	PQCP_FLEET_RECOVERY_STEP_COMPENSATING,
	PQCP_FLEET_RECOVERY_STEP_COMPENSATED,
	PQCP_FLEET_RECOVERY_STEP_SKIPPED,
};

enum pqcp_fleet_recovery_orchestrator_state {
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_EMPTY = 0,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOADED,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_AUTHORIZED,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_RUNNING,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_PAUSED,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPENSATING,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_VALIDATING,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_COMPLETE,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_ABORTED,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_FAILED,
	PQCP_FLEET_RECOVERY_ORCHESTRATOR_LOCKED,
};

enum pqcp_fleet_recovery_compensation {
	PQCP_FLEET_RECOVERY_COMPENSATE_NONE = 0,
	PQCP_FLEET_RECOVERY_COMPENSATE_RESTORE_TRUST_ANCHOR,
	PQCP_FLEET_RECOVERY_COMPENSATE_RESTORE_SECURITY_SNAPSHOT,
	PQCP_FLEET_RECOVERY_COMPENSATE_REVOKE_REPLACEMENT,
	PQCP_FLEET_RECOVERY_COMPENSATE_REACTIVATE_UPDATE,
	PQCP_FLEET_RECOVERY_COMPENSATE_INVALIDATE_TIME_ANCHOR,
	PQCP_FLEET_RECOVERY_COMPENSATE_CLOSE_REOPENED_SESSIONS,
};

enum pqcp_fleet_recovery_audit_event {
	PQCP_FLEET_RECOVERY_AUDIT_NONE = 0,
	PQCP_FLEET_RECOVERY_AUDIT_PLAYBOOK_LOADED,
	PQCP_FLEET_RECOVERY_AUDIT_AUTHORIZED,
	PQCP_FLEET_RECOVERY_AUDIT_STARTED,
	PQCP_FLEET_RECOVERY_AUDIT_STEP_READY,
	PQCP_FLEET_RECOVERY_AUDIT_STEP_STARTED,
	PQCP_FLEET_RECOVERY_AUDIT_STEP_RETRY,
	PQCP_FLEET_RECOVERY_AUDIT_STEP_SUCCEEDED,
	PQCP_FLEET_RECOVERY_AUDIT_STEP_FAILED,
	PQCP_FLEET_RECOVERY_AUDIT_CHECKPOINT,
	PQCP_FLEET_RECOVERY_AUDIT_PAUSED,
	PQCP_FLEET_RECOVERY_AUDIT_RESUMED,
	PQCP_FLEET_RECOVERY_AUDIT_ABORT_REQUESTED,
	PQCP_FLEET_RECOVERY_AUDIT_COMPENSATION_STARTED,
	PQCP_FLEET_RECOVERY_AUDIT_COMPENSATION_SUCCEEDED,
	PQCP_FLEET_RECOVERY_AUDIT_COMPENSATION_FAILED,
	PQCP_FLEET_RECOVERY_AUDIT_VALIDATED,
	PQCP_FLEET_RECOVERY_AUDIT_COMPLETED,
	PQCP_FLEET_RECOVERY_AUDIT_LOCKED,
	PQCP_FLEET_RECOVERY_AUDIT_RESTORED,
	PQCP_FLEET_RECOVERY_AUDIT_EVENT_COUNT,
};

struct pqcp_fleet_recovery_trust_anchor_step {
	uint64_t current_epoch;
	uint64_t replacement_epoch;
	uint8_t current_anchor_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t replacement_anchor_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t authorization_key_digest[PQCP_FLEET_DIGEST_BYTES];
	bool require_cross_signature;
};

struct pqcp_fleet_recovery_security_snapshot_step {
	uint64_t current_policy_epoch;
	uint64_t target_policy_epoch;
	uint64_t current_revocation_epoch;
	uint64_t target_revocation_epoch;
	uint8_t policy_snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t revocation_snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
	bool allow_equal_policy_epoch;
	bool require_complete_revocation_set;
};

struct pqcp_fleet_recovery_credential_step {
	char current_credential_id[
		PQCP_FLEET_RECOVERY_CREDENTIAL_MAX_CHARS];
	char replacement_credential_id[
		PQCP_FLEET_RECOVERY_CREDENTIAL_MAX_CHARS];
	uint64_t current_credential_epoch;
	uint64_t replacement_credential_epoch;
	uint64_t overlap_until_ms;
	uint8_t current_key_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t replacement_key_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t replacement_credential_digest[PQCP_FLEET_DIGEST_BYTES];
	bool destroy_old_key_after_commit;
};

struct pqcp_fleet_recovery_update_rollback_step {
	char component_id[PQCP_FLEET_RECOVERY_COMPONENT_MAX_CHARS];
	uint64_t failed_version;
	uint64_t rollback_version;
	uint64_t rollback_deadline_ms;
	uint8_t failed_image_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t rollback_image_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t boot_measurement_digest[PQCP_FLEET_DIGEST_BYTES];
	bool require_health_validation;
};

struct pqcp_fleet_recovery_secure_time_step {
	enum pqcp_fleet_time_source source;
	enum pqcp_fleet_time_quality minimum_quality;
	uint64_t minimum_reference_time_ms;
	uint64_t maximum_uncertainty_ms;
	uint64_t valid_until_monotonic_ms;
	uint32_t maximum_drift_ppm;
	uint8_t source_digest[PQCP_FLEET_DIGEST_BYTES];
	bool require_attested_source;
};

struct pqcp_fleet_recovery_session_step {
	char session_label[
		PQCP_FLEET_RECOVERY_SESSION_LABEL_MAX_CHARS];
	uint64_t previous_session_id;
	uint32_t required_capabilities;
	uint32_t minimum_session_count;
	uint32_t maximum_session_count;
	uint8_t peer_identity_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t expected_channel_binding[PQCP_FLEET_DIGEST_BYTES];
	bool require_fresh_handshake;
};

union pqcp_fleet_recovery_step_parameters {
	struct pqcp_fleet_recovery_trust_anchor_step trust_anchor;
	struct pqcp_fleet_recovery_security_snapshot_step security_snapshot;
	struct pqcp_fleet_recovery_credential_step credential;
	struct pqcp_fleet_recovery_update_rollback_step update_rollback;
	struct pqcp_fleet_recovery_secure_time_step secure_time;
	struct pqcp_fleet_recovery_session_step session;
};

struct pqcp_fleet_recovery_step_definition {
	uint32_t schema_version;
	uint32_t step_id;
	enum pqcp_fleet_recovery_step_type type;
	uint32_t dependency_mask;
	uint32_t manager_step_bit;
	uint32_t priority;
	uint32_t maximum_attempts;
	uint64_t timeout_ms;
	uint64_t base_retry_ms;
	uint64_t maximum_retry_ms;
	enum pqcp_fleet_recovery_compensation compensation;
	union pqcp_fleet_recovery_step_parameters parameters;
	bool required;
};

struct pqcp_fleet_recovery_step_runtime {
	struct pqcp_fleet_recovery_step_definition definition;
	enum pqcp_fleet_recovery_step_state state;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	uint64_t next_attempt_ms;
	uint64_t completion_ordinal;
	uint32_t attempt_count;
	int result;
	uint8_t *evidence;
	size_t evidence_capacity;
	size_t evidence_length;
	uint8_t evidence_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_FLEET_DIGEST_BYTES];
	bool restored;
	bool occupied;
};

struct pqcp_fleet_recovery_authorization {
	uint32_t schema_version;
	uint64_t session_id;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	enum pqcp_fleet_recovery_reason reason;
	uint32_t authorized_step_mask;
	uint8_t challenge[PQCP_FLEET_RECOVERY_CHALLENGE_BYTES];
	uint8_t authority_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t scope_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t playbook_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t binding_digest[PQCP_FLEET_RECOVERY_BINDING_BYTES];
};

struct pqcp_fleet_recovery_checkpoint {
	uint32_t schema_version;
	uint64_t checkpoint_sequence;
	uint64_t session_id;
	uint64_t timestamp_ms;
	uint32_t step_id;
	enum pqcp_fleet_recovery_step_type step_type;
	enum pqcp_fleet_recovery_step_state step_state;
	uint32_t attempt_count;
	int result;
	uint8_t authorization_binding[PQCP_FLEET_RECOVERY_BINDING_BYTES];
	uint8_t evidence_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_FLEET_DIGEST_BYTES];
	bool compensation;
	bool occupied;
};

struct pqcp_fleet_recovery_audit_entry {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t timestamp_ms;
	uint64_t session_id;
	enum pqcp_fleet_recovery_audit_event event;
	enum pqcp_fleet_recovery_orchestrator_state orchestrator_state;
	uint32_t step_id;
	uint32_t detail;
	int result;
	uint8_t previous_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t entry_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_recovery_policy {
	uint32_t schema_version;
	uint32_t maximum_playbook_attempts;
	uint32_t lockout_after_failures;
	uint32_t maximum_authorization_failures;
	uint64_t default_step_timeout_ms;
	uint64_t default_base_retry_ms;
	uint64_t default_maximum_retry_ms;
	uint64_t lockout_ms;
	uint64_t completion_cooldown_ms;
	bool auto_compensate;
	bool compensate_optional_steps;
	bool lock_on_compensation_failure;
	bool require_checkpoint_persistence;
	bool require_all_steps_authorized;
};

struct pqcp_fleet_recovery_step_result {
	uint32_t step_id;
	enum pqcp_fleet_recovery_step_type type;
	enum pqcp_fleet_recovery_step_state state;
	uint32_t attempt_count;
	int result;
	uint8_t evidence_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_recovery_progress {
	enum pqcp_fleet_recovery_orchestrator_state state;
	uint32_t total_steps;
	uint32_t succeeded_steps;
	uint32_t failed_steps;
	uint32_t compensated_steps;
	uint32_t pending_steps;
	uint32_t active_step_id;
	bool progressed;
	bool terminal;
	int result;
};

struct pqcp_fleet_recovery_snapshot {
	uint32_t schema_version;
	uint64_t captured_at_ms;
	uint64_t session_id;
	enum pqcp_fleet_recovery_orchestrator_state state;
	enum pqcp_fleet_recovery_reason reason;
	uint32_t authorized_step_mask;
	uint32_t completed_step_mask;
	uint32_t failed_step_mask;
	uint32_t compensated_step_mask;
	uint32_t playbook_attempts;
	uint32_t authorization_failures;
	uint32_t terminal_failures;
	uint64_t lockout_until_ms;
	uint64_t checkpoint_count;
	uint64_t audit_count;
	size_t step_count;
	struct pqcp_fleet_recovery_step_result *steps;
	size_t step_capacity;
	uint8_t playbook_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t authorization_binding[PQCP_FLEET_DIGEST_BYTES];
	uint8_t evidence_chain_head[PQCP_FLEET_DIGEST_BYTES];
	uint8_t audit_chain_head[PQCP_FLEET_DIGEST_BYTES];
	uint8_t snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_recovery_executor {
	void *context;
	int (*renew_trust_anchor)(
		void *context,
		const struct pqcp_fleet_recovery_trust_anchor_step *step,
		const uint8_t authorization_binding[
			PQCP_FLEET_RECOVERY_BINDING_BYTES],
		uint8_t *evidence,
		size_t evidence_capacity,
		size_t *evidence_length,
		uint64_t now_ms);
	int (*install_security_snapshot)(
		void *context,
		const struct pqcp_fleet_recovery_security_snapshot_step *step,
		const uint8_t authorization_binding[
			PQCP_FLEET_RECOVERY_BINDING_BYTES],
		uint8_t *evidence,
		size_t evidence_capacity,
		size_t *evidence_length,
		uint64_t now_ms);
	int (*replace_credential)(
		void *context,
		const struct pqcp_fleet_recovery_credential_step *step,
		const uint8_t authorization_binding[
			PQCP_FLEET_RECOVERY_BINDING_BYTES],
		uint8_t *evidence,
		size_t evidence_capacity,
		size_t *evidence_length,
		uint64_t now_ms);
	int (*rollback_update)(
		void *context,
		const struct pqcp_fleet_recovery_update_rollback_step *step,
		const uint8_t authorization_binding[
			PQCP_FLEET_RECOVERY_BINDING_BYTES],
		uint8_t *evidence,
		size_t evidence_capacity,
		size_t *evidence_length,
		uint64_t now_ms);
	int (*restore_secure_time)(
		void *context,
		const struct pqcp_fleet_recovery_secure_time_step *step,
		const uint8_t authorization_binding[
			PQCP_FLEET_RECOVERY_BINDING_BYTES],
		uint8_t *evidence,
		size_t evidence_capacity,
		size_t *evidence_length,
		uint64_t now_ms);
	int (*reopen_sessions)(
		void *context,
		const struct pqcp_fleet_recovery_session_step *step,
		const uint8_t authorization_binding[
			PQCP_FLEET_RECOVERY_BINDING_BYTES],
		uint8_t *evidence,
		size_t evidence_capacity,
		size_t *evidence_length,
		uint64_t now_ms);
	int (*verify_evidence)(
		void *context,
		const struct pqcp_fleet_recovery_step_definition *step,
		const uint8_t *evidence,
		size_t evidence_length,
		uint64_t now_ms);
	int (*compensate)(
		void *context,
		enum pqcp_fleet_recovery_compensation action,
		const struct pqcp_fleet_recovery_step_definition *step,
		const struct pqcp_fleet_recovery_checkpoint *checkpoint,
		const uint8_t authorization_binding[
			PQCP_FLEET_RECOVERY_BINDING_BYTES],
		uint8_t *evidence,
		size_t evidence_capacity,
		size_t *evidence_length,
		uint64_t now_ms);
	int (*persist_checkpoint)(
		void *context,
		const struct pqcp_fleet_recovery_checkpoint *checkpoint);
	int (*notify_lockout)(
		void *context,
		uint64_t session_id,
		uint64_t lockout_until_ms,
		int reason);
};

struct pqcp_fleet_recovery_orchestrator {
	uint32_t schema_version;
	struct pqcp_fleet_recovery_policy policy;
	struct pqcp_fleet_recovery_manager *manager;
	struct pqcp_fleet_recovery_executor executor;
	struct pqcp_fleet_recovery_step_runtime *steps;
	size_t step_capacity;
	size_t step_count;
	struct pqcp_fleet_recovery_checkpoint *checkpoints;
	size_t checkpoint_capacity;
	size_t checkpoint_count;
	struct pqcp_fleet_recovery_audit_entry *audit_entries;
	size_t audit_capacity;
	size_t audit_count;
	size_t audit_next;
	uint8_t *evidence_storage;
	size_t evidence_storage_bytes;
	size_t evidence_slot_bytes;
	enum pqcp_fleet_recovery_orchestrator_state state;
	struct pqcp_fleet_recovery_authorization authorization;
	uint64_t playbook_id;
	uint64_t loaded_at_ms;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	uint64_t next_checkpoint_sequence;
	uint64_t next_audit_sequence;
	uint64_t completion_counter;
	uint64_t lockout_until_ms;
	uint32_t authorized_step_mask;
	uint32_t completed_step_mask;
	uint32_t failed_step_mask;
	uint32_t compensated_step_mask;
	uint32_t playbook_attempts;
	uint32_t authorization_failures;
	uint32_t terminal_failures;
	uint32_t active_step_index;
	int terminal_result;
	uint8_t playbook_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t evidence_chain_head[PQCP_FLEET_DIGEST_BYTES];
	uint8_t audit_chain_head[PQCP_FLEET_DIGEST_BYTES];
	struct k_mutex lock;
	bool pause_requested;
	bool abort_requested;
	bool executor_busy;
	bool initialized;
};

int pqcp_fleet_recovery_policy_default(
	struct pqcp_fleet_recovery_policy *policy);

int pqcp_fleet_recovery_orchestrator_init(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const struct pqcp_fleet_recovery_policy *policy,
	struct pqcp_fleet_recovery_manager *manager,
	const struct pqcp_fleet_recovery_executor *executor,
	struct pqcp_fleet_recovery_step_runtime *steps,
	size_t step_capacity,
	struct pqcp_fleet_recovery_checkpoint *checkpoints,
	size_t checkpoint_capacity,
	uint8_t *evidence_storage,
	size_t evidence_storage_bytes,
	size_t evidence_slot_bytes,
	struct pqcp_fleet_recovery_audit_entry *audit_entries,
	size_t audit_capacity);

int pqcp_fleet_recovery_playbook_load(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t playbook_id,
	const struct pqcp_fleet_recovery_step_definition *steps,
	size_t step_count,
	uint64_t now_ms);

int pqcp_fleet_recovery_playbook_digest(
	const struct pqcp_fleet_recovery_step_definition *steps,
	size_t step_count,
	uint64_t playbook_id,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES]);

int pqcp_fleet_recovery_authorization_bind(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const struct pqcp_fleet_recovery_authorization *authorization,
	uint64_t now_ms);

int pqcp_fleet_recovery_orchestrator_start(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms);

int pqcp_fleet_recovery_orchestrator_advance(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms,
	struct pqcp_fleet_recovery_progress *progress);

int pqcp_fleet_recovery_orchestrator_pause(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms);

int pqcp_fleet_recovery_orchestrator_resume(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms);

int pqcp_fleet_recovery_orchestrator_abort(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	int reason,
	uint64_t now_ms);

int pqcp_fleet_recovery_orchestrator_finish(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms);

int pqcp_fleet_recovery_orchestrator_unlock(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const uint8_t authority_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms);

int pqcp_fleet_recovery_checkpoint_import(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	const struct pqcp_fleet_recovery_checkpoint *checkpoints,
	size_t checkpoint_count,
	uint64_t now_ms);

int pqcp_fleet_recovery_snapshot(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	uint64_t now_ms,
	struct pqcp_fleet_recovery_snapshot *snapshot);

int pqcp_fleet_recovery_snapshot_verify(
	const struct pqcp_fleet_recovery_snapshot *snapshot);

int pqcp_fleet_recovery_orchestrator_audit(
	struct pqcp_fleet_recovery_orchestrator *orchestrator);

int pqcp_fleet_recovery_orchestrator_reset(
	struct pqcp_fleet_recovery_orchestrator *orchestrator,
	bool retain_playbook,
	uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_RECOVERY_ORCHESTRATOR_H_ */
