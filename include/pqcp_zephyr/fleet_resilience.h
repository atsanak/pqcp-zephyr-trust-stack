/*
 * SPDX-License-Identifier: MIT
 *
 * Fleet resilience services for disconnected and failure-prone devices.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_RESILIENCE_H_
#define PQCP_ZEPHYR_FLEET_RESILIENCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_operations.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_RESILIENCE_SCHEMA_VERSION 1U
#define PQCP_FLEET_TIME_MAX_SOURCES 8U
#define PQCP_FLEET_REVOCATION_SUBJECT_MAX_CHARS 48U
#define PQCP_FLEET_ROLLOUT_SEED_BYTES 32U
#define PQCP_FLEET_HEALTH_DETAIL_MAX_CHARS 48U
#define PQCP_FLEET_RECOVERY_AUTH_BYTES 32U

enum pqcp_fleet_time_source {
	PQCP_FLEET_TIME_SOURCE_NONE = 0,
	PQCP_FLEET_TIME_SOURCE_MONOTONIC,
	PQCP_FLEET_TIME_SOURCE_RTC,
	PQCP_FLEET_TIME_SOURCE_NETWORK,
	PQCP_FLEET_TIME_SOURCE_REGISTRAR,
	PQCP_FLEET_TIME_SOURCE_SECURE_ELEMENT,
};

enum pqcp_fleet_time_quality {
	PQCP_FLEET_TIME_UNTRUSTED = 0,
	PQCP_FLEET_TIME_HOLDOVER,
	PQCP_FLEET_TIME_SYNCHRONIZED,
	PQCP_FLEET_TIME_ATTESTED,
};

struct pqcp_fleet_time_anchor {
	uint32_t schema_version;
	enum pqcp_fleet_time_source source;
	enum pqcp_fleet_time_quality quality;
	uint64_t local_monotonic_ms;
	uint64_t reference_time_ms;
	uint64_t uncertainty_ms;
	uint64_t valid_until_monotonic_ms;
	uint32_t maximum_drift_ppm;
	uint32_t priority;
	uint8_t source_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_secure_time {
	uint32_t schema_version;
	struct pqcp_fleet_time_anchor *anchors;
	size_t capacity;
	uint64_t last_returned_ms;
	uint64_t rollback_tolerance_ms;
	uint64_t maximum_uncertainty_ms;
	uint64_t update_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_fleet_time_reading {
	uint64_t time_ms;
	uint64_t uncertainty_ms;
	enum pqcp_fleet_time_source source;
	enum pqcp_fleet_time_quality quality;
	bool holdover;
};

struct pqcp_fleet_revocation_record {
	uint32_t schema_version;
	enum pqcp_fleet_revocation_kind kind;
	char subject_id[PQCP_FLEET_REVOCATION_SUBJECT_MAX_CHARS];
	uint64_t effective_at_ms;
	uint64_t expires_at_ms;
	uint64_t epoch;
	uint32_t reason;
	uint8_t subject_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_revocation_index {
	uint32_t schema_version;
	struct pqcp_fleet_revocation_record *records;
	size_t capacity;
	uint64_t current_epoch;
	uint64_t refresh_due_ms;
	uint64_t offline_grace_ms;
	uint64_t applied_updates;
	uint64_t rejected_updates;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_fleet_rollout_state {
	PQCP_FLEET_ROLLOUT_EMPTY = 0,
	PQCP_FLEET_ROLLOUT_PLANNED,
	PQCP_FLEET_ROLLOUT_ACTIVE,
	PQCP_FLEET_ROLLOUT_PAUSED,
	PQCP_FLEET_ROLLOUT_PROMOTED,
	PQCP_FLEET_ROLLOUT_DRAINING,
	PQCP_FLEET_ROLLOUT_COMPLETED,
	PQCP_FLEET_ROLLOUT_ABORTED,
};

struct pqcp_fleet_rollout_campaign {
	uint32_t schema_version;
	uint64_t campaign_id;
	char component_id[PQCP_FLEET_COMPONENT_MAX_CHARS];
	uint64_t target_version;
	uint32_t cohort_percent_basis_points;
	uint32_t minimum_success_basis_points;
	uint32_t maximum_failure_basis_points;
	uint32_t assigned_devices;
	uint32_t successful_devices;
	uint32_t failed_devices;
	uint32_t pending_devices;
	uint64_t starts_at_ms;
	uint64_t promotion_not_before_ms;
	uint64_t deadline_ms;
	uint8_t cohort_seed[PQCP_FLEET_ROLLOUT_SEED_BYTES];
	enum pqcp_fleet_rollout_state state;
	bool occupied;
};

struct pqcp_fleet_rollout_manager {
	uint32_t schema_version;
	struct pqcp_fleet_rollout_campaign *campaigns;
	size_t capacity;
	uint64_t decision_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_fleet_health_probe {
	PQCP_FLEET_HEALTH_CRYPTO = 0,
	PQCP_FLEET_HEALTH_CHANNEL,
	PQCP_FLEET_HEALTH_STORAGE,
	PQCP_FLEET_HEALTH_TIME,
	PQCP_FLEET_HEALTH_POLICY,
	PQCP_FLEET_HEALTH_UPDATE,
	PQCP_FLEET_HEALTH_ENTROPY,
	PQCP_FLEET_HEALTH_MEMORY,
	PQCP_FLEET_HEALTH_PROBE_COUNT,
};

enum pqcp_fleet_health_state {
	PQCP_FLEET_HEALTH_UNKNOWN = 0,
	PQCP_FLEET_HEALTH_HEALTHY,
	PQCP_FLEET_HEALTH_DEGRADED,
	PQCP_FLEET_HEALTH_FAILED,
	PQCP_FLEET_HEALTH_ISOLATED,
};

enum pqcp_fleet_health_action {
	PQCP_FLEET_HEALTH_ACTION_NONE = 0,
	PQCP_FLEET_HEALTH_ACTION_RETRY,
	PQCP_FLEET_HEALTH_ACTION_REKEY,
	PQCP_FLEET_HEALTH_ACTION_RECONNECT,
	PQCP_FLEET_HEALTH_ACTION_ROLLBACK,
	PQCP_FLEET_HEALTH_ACTION_RECOVERY,
	PQCP_FLEET_HEALTH_ACTION_QUARANTINE,
};

struct pqcp_fleet_health_record {
	uint32_t schema_version;
	enum pqcp_fleet_health_probe probe;
	enum pqcp_fleet_health_state state;
	uint64_t last_checked_ms;
	uint64_t last_success_ms;
	uint64_t last_failure_ms;
	uint64_t retry_after_ms;
	uint32_t consecutive_successes;
	uint32_t consecutive_failures;
	uint32_t total_failures;
	int last_result;
	char detail[PQCP_FLEET_HEALTH_DETAIL_MAX_CHARS];
};

struct pqcp_fleet_health_policy {
	uint32_t degrade_after_failures;
	uint32_t fail_after_failures;
	uint32_t recover_after_successes;
	uint64_t base_retry_ms;
	uint64_t maximum_retry_ms;
	uint32_t critical_probe_mask;
};

struct pqcp_fleet_health_monitor {
	uint32_t schema_version;
	struct pqcp_fleet_health_record
		records[PQCP_FLEET_HEALTH_PROBE_COUNT];
	struct pqcp_fleet_health_policy policy;
	uint64_t transition_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_fleet_offline_lease {
	uint32_t schema_version;
	uint64_t lease_id;
	uint64_t issued_at_ms;
	uint64_t valid_from_ms;
	uint64_t expires_at_ms;
	uint64_t maximum_offline_ms;
	uint64_t operation_limit;
	uint64_t operation_count;
	uint32_t capability_mask;
	uint32_t operation_mask;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint8_t lease_digest[PQCP_FLEET_DIGEST_BYTES];
	bool active;
	bool revoked;
};

struct pqcp_fleet_lease_manager {
	uint32_t schema_version;
	struct pqcp_fleet_offline_lease *leases;
	size_t capacity;
	uint64_t latest_policy_epoch;
	uint64_t latest_revocation_epoch;
	uint64_t accepted_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_fleet_recovery_state {
	PQCP_FLEET_RECOVERY_IDLE = 0,
	PQCP_FLEET_RECOVERY_AUTHORIZED,
	PQCP_FLEET_RECOVERY_ENTERING,
	PQCP_FLEET_RECOVERY_ACTIVE,
	PQCP_FLEET_RECOVERY_VALIDATING,
	PQCP_FLEET_RECOVERY_EXITING,
	PQCP_FLEET_RECOVERY_COMPLETE,
	PQCP_FLEET_RECOVERY_LOCKED,
};

enum pqcp_fleet_recovery_reason {
	PQCP_FLEET_RECOVERY_REASON_NONE = 0,
	PQCP_FLEET_RECOVERY_CREDENTIAL_EXPIRED,
	PQCP_FLEET_RECOVERY_KEY_COMPROMISE,
	PQCP_FLEET_RECOVERY_POLICY_FAILURE,
	PQCP_FLEET_RECOVERY_UPDATE_FAILURE,
	PQCP_FLEET_RECOVERY_TIME_FAILURE,
	PQCP_FLEET_RECOVERY_OPERATOR_REQUEST,
};

struct pqcp_fleet_recovery_manager {
	uint32_t schema_version;
	enum pqcp_fleet_recovery_state state;
	enum pqcp_fleet_recovery_reason reason;
	uint64_t session_id;
	uint64_t authorized_at_ms;
	uint64_t expires_at_ms;
	uint64_t cooldown_until_ms;
	uint32_t attempt_count;
	uint32_t maximum_attempts;
	uint32_t completed_steps;
	uint32_t required_steps;
	uint8_t authorization_digest[PQCP_FLEET_RECOVERY_AUTH_BYTES];
	uint8_t evidence_digest[PQCP_FLEET_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_fleet_peer_state {
	PQCP_FLEET_PEER_EMPTY = 0,
	PQCP_FLEET_PEER_ACTIVE,
	PQCP_FLEET_PEER_DEGRADED,
	PQCP_FLEET_PEER_QUARANTINED,
	PQCP_FLEET_PEER_REVOKED,
};

struct pqcp_fleet_peer_record {
	uint32_t schema_version;
	uint32_t generation;
	char device_id[PQCP_FLEET_ID_MAX_CHARS];
	char domain_id[PQCP_FLEET_ID_MAX_CHARS];
	char product_class[PQCP_FLEET_PRODUCT_MAX_CHARS];
	uint8_t credential_fingerprint[PQCP_FLEET_DIGEST_BYTES];
	uint64_t credential_epoch;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t first_seen_ms;
	uint64_t last_seen_ms;
	uint64_t quarantine_until_ms;
	uint32_t capabilities;
	uint32_t active_sessions;
	uint32_t maximum_sessions;
	uint32_t consecutive_failures;
	uint32_t trust_score;
	enum pqcp_fleet_peer_state state;
};

struct pqcp_fleet_peer_registry {
	uint32_t schema_version;
	struct pqcp_fleet_peer_record *peers;
	size_t capacity;
	uint32_t next_generation;
	uint64_t admission_count;
	uint64_t rejection_count;
	uint64_t quarantine_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_fleet_admission_policy {
	uint64_t bucket_capacity;
	uint64_t refill_tokens;
	uint64_t refill_interval_ms;
	uint64_t maximum_cost_per_request;
	uint64_t maximum_bytes_per_window;
	uint32_t maximum_concurrent;
	uint32_t failure_penalty;
	uint32_t recovery_credit;
};

struct pqcp_fleet_admission_subject {
	uint32_t schema_version;
	char subject_id[PQCP_FLEET_ID_MAX_CHARS];
	uint64_t tokens;
	uint64_t last_refill_ms;
	uint64_t window_started_ms;
	uint64_t bytes_in_window;
	uint64_t accepted;
	uint64_t rejected;
	uint32_t concurrent;
	uint32_t failure_score;
	uint64_t blocked_until_ms;
	bool occupied;
};

struct pqcp_fleet_admission_controller {
	uint32_t schema_version;
	struct pqcp_fleet_admission_policy policy;
	struct pqcp_fleet_admission_subject *subjects;
	size_t capacity;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_fleet_risk_signal {
	PQCP_FLEET_RISK_AUTH_FAILURE = 0,
	PQCP_FLEET_RISK_REPLAY,
	PQCP_FLEET_RISK_POLICY_REJECT,
	PQCP_FLEET_RISK_CLOCK_ROLLBACK,
	PQCP_FLEET_RISK_STORAGE_TAMPER,
	PQCP_FLEET_RISK_UPDATE_FAILURE,
	PQCP_FLEET_RISK_CRYPTO_FAILURE,
	PQCP_FLEET_RISK_CHANNEL_FAILURE,
	PQCP_FLEET_RISK_RESOURCE_PRESSURE,
	PQCP_FLEET_RISK_OPERATOR_ALERT,
	PQCP_FLEET_RISK_SIGNAL_COUNT,
};

enum pqcp_fleet_risk_action {
	PQCP_FLEET_RISK_ACTION_NONE = 0,
	PQCP_FLEET_RISK_ACTION_OBSERVE,
	PQCP_FLEET_RISK_ACTION_THROTTLE,
	PQCP_FLEET_RISK_ACTION_REAUTHENTICATE,
	PQCP_FLEET_RISK_ACTION_RECOVERY,
	PQCP_FLEET_RISK_ACTION_QUARANTINE,
};

struct pqcp_fleet_risk_policy {
	uint32_t signal_weight[PQCP_FLEET_RISK_SIGNAL_COUNT];
	uint32_t observe_threshold;
	uint32_t throttle_threshold;
	uint32_t reauthenticate_threshold;
	uint32_t recovery_threshold;
	uint32_t quarantine_threshold;
	uint32_t maximum_score;
	uint32_t decay_points;
	uint64_t decay_interval_ms;
	uint64_t correlation_window_ms;
};

struct pqcp_fleet_risk_signal_state {
	uint64_t last_seen_ms;
	uint64_t window_started_ms;
	uint32_t occurrences;
	uint32_t consecutive;
	uint32_t peak_consecutive;
};

struct pqcp_fleet_risk_engine {
	uint32_t schema_version;
	struct pqcp_fleet_risk_policy policy;
	struct pqcp_fleet_risk_signal_state
		signals[PQCP_FLEET_RISK_SIGNAL_COUNT];
	uint32_t score;
	uint32_t peak_score;
	uint64_t last_decay_ms;
	uint64_t event_count;
	enum pqcp_fleet_risk_action action;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_fleet_maintenance_type {
	PQCP_FLEET_MAINTENANCE_NONE = 0,
	PQCP_FLEET_MAINTENANCE_REKEY,
	PQCP_FLEET_MAINTENANCE_ROTATE_IDENTITY,
	PQCP_FLEET_MAINTENANCE_APPLY_POLICY,
	PQCP_FLEET_MAINTENANCE_UPDATE_FIRMWARE,
	PQCP_FLEET_MAINTENANCE_COMPACT_STORAGE,
	PQCP_FLEET_MAINTENANCE_ATTEST,
	PQCP_FLEET_MAINTENANCE_TYPE_COUNT,
};

enum pqcp_fleet_maintenance_state {
	PQCP_FLEET_MAINTENANCE_EMPTY = 0,
	PQCP_FLEET_MAINTENANCE_SCHEDULED,
	PQCP_FLEET_MAINTENANCE_RUNNING,
	PQCP_FLEET_MAINTENANCE_COMPLETED,
	PQCP_FLEET_MAINTENANCE_CANCELLED,
	PQCP_FLEET_MAINTENANCE_EXPIRED,
};

struct pqcp_fleet_maintenance_job {
	uint32_t schema_version;
	uint64_t job_id;
	enum pqcp_fleet_maintenance_type type;
	enum pqcp_fleet_maintenance_state state;
	uint64_t earliest_start_ms;
	uint64_t latest_finish_ms;
	uint64_t expected_duration_ms;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	uint32_t priority;
	uint32_t resource_mask;
	uint32_t attempt_count;
	uint32_t maximum_attempts;
	int result;
	bool disruptive;
};

struct pqcp_fleet_maintenance_scheduler {
	uint32_t schema_version;
	struct pqcp_fleet_maintenance_job *jobs;
	size_t capacity;
	uint32_t active_resource_mask;
	uint64_t completed_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

int pqcp_fleet_secure_time_init(
	struct pqcp_fleet_secure_time *time,
	struct pqcp_fleet_time_anchor *anchors,
	size_t capacity,
	uint64_t rollback_tolerance_ms,
	uint64_t maximum_uncertainty_ms);
int pqcp_fleet_secure_time_update(
	struct pqcp_fleet_secure_time *time,
	const struct pqcp_fleet_time_anchor *anchor);
int pqcp_fleet_secure_time_now(
	struct pqcp_fleet_secure_time *time,
	uint64_t local_monotonic_ms,
	struct pqcp_fleet_time_reading *reading);
int pqcp_fleet_secure_time_expire(
	struct pqcp_fleet_secure_time *time,
	uint64_t local_monotonic_ms,
	uint32_t *expired_count);
int pqcp_fleet_secure_time_audit(
	struct pqcp_fleet_secure_time *time);

int pqcp_fleet_revocation_index_init(
	struct pqcp_fleet_revocation_index *index,
	struct pqcp_fleet_revocation_record *records,
	size_t capacity);
int pqcp_fleet_revocation_index_apply(
	struct pqcp_fleet_revocation_index *index,
	const struct pqcp_fleet_revocation_update *update,
	uint64_t now_ms);
int pqcp_fleet_revocation_index_query(
	struct pqcp_fleet_revocation_index *index,
	enum pqcp_fleet_revocation_kind kind,
	const char *subject_id,
	uint64_t now_ms,
	struct pqcp_fleet_revocation_record *record);
int pqcp_fleet_revocation_index_expire(
	struct pqcp_fleet_revocation_index *index,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_fleet_revocation_index_audit(
	struct pqcp_fleet_revocation_index *index);

int pqcp_fleet_rollout_manager_init(
	struct pqcp_fleet_rollout_manager *manager,
	struct pqcp_fleet_rollout_campaign *campaigns,
	size_t capacity);
int pqcp_fleet_rollout_create(
	struct pqcp_fleet_rollout_manager *manager,
	const struct pqcp_fleet_rollout_campaign *campaign);
int pqcp_fleet_rollout_assign(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id,
	const char *device_id,
	bool *assigned,
	uint32_t *cohort_value);
int pqcp_fleet_rollout_record(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id,
	bool success);
int pqcp_fleet_rollout_tick(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_fleet_rollout_pause(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id);
int pqcp_fleet_rollout_resume(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id);
int pqcp_fleet_rollout_audit(
	struct pqcp_fleet_rollout_manager *manager);

int pqcp_fleet_health_monitor_init(
	struct pqcp_fleet_health_monitor *monitor,
	const struct pqcp_fleet_health_policy *policy);
int pqcp_fleet_health_report(
	struct pqcp_fleet_health_monitor *monitor,
	enum pqcp_fleet_health_probe probe,
	int result,
	const char *detail,
	uint64_t now_ms);
int pqcp_fleet_health_evaluate(
	struct pqcp_fleet_health_monitor *monitor,
	uint64_t now_ms,
	enum pqcp_fleet_health_state *state,
	enum pqcp_fleet_health_action *action);
int pqcp_fleet_health_due(
	struct pqcp_fleet_health_monitor *monitor,
	enum pqcp_fleet_health_probe probe,
	uint64_t now_ms,
	bool *due);
int pqcp_fleet_health_audit(
	struct pqcp_fleet_health_monitor *monitor);

int pqcp_fleet_lease_manager_init(
	struct pqcp_fleet_lease_manager *manager,
	struct pqcp_fleet_offline_lease *leases,
	size_t capacity);
int pqcp_fleet_lease_install(
	struct pqcp_fleet_lease_manager *manager,
	const struct pqcp_fleet_offline_lease *lease,
	uint64_t now_ms);
int pqcp_fleet_lease_authorize(
	struct pqcp_fleet_lease_manager *manager,
	uint64_t lease_id,
	enum pqcp_fleet_operation_type operation,
	uint32_t required_capabilities,
	uint64_t now_ms);
int pqcp_fleet_lease_revoke(
	struct pqcp_fleet_lease_manager *manager,
	uint64_t lease_id);
int pqcp_fleet_lease_advance_epochs(
	struct pqcp_fleet_lease_manager *manager,
	uint64_t policy_epoch,
	uint64_t revocation_epoch);
int pqcp_fleet_lease_expire(
	struct pqcp_fleet_lease_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_fleet_lease_manager_audit(
	struct pqcp_fleet_lease_manager *manager);

int pqcp_fleet_recovery_manager_init(
	struct pqcp_fleet_recovery_manager *manager,
	uint32_t maximum_attempts,
	uint32_t required_steps);
int pqcp_fleet_recovery_authorize(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t session_id,
	enum pqcp_fleet_recovery_reason reason,
	const uint8_t authorization_digest[
		PQCP_FLEET_RECOVERY_AUTH_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms);
int pqcp_fleet_recovery_enter(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t now_ms);
int pqcp_fleet_recovery_step(
	struct pqcp_fleet_recovery_manager *manager,
	uint32_t step,
	const uint8_t *evidence,
	size_t evidence_length,
	uint64_t now_ms);
int pqcp_fleet_recovery_validate(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t now_ms);
int pqcp_fleet_recovery_complete(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t now_ms,
	uint64_t cooldown_ms);
int pqcp_fleet_recovery_abort(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t now_ms,
	uint64_t cooldown_ms);
int pqcp_fleet_recovery_audit(
	struct pqcp_fleet_recovery_manager *manager);

int pqcp_fleet_peer_registry_init(
	struct pqcp_fleet_peer_registry *registry,
	struct pqcp_fleet_peer_record *peers,
	size_t capacity);
int pqcp_fleet_peer_upsert(
	struct pqcp_fleet_peer_registry *registry,
	const struct pqcp_fleet_peer_record *peer,
	uint64_t now_ms);
int pqcp_fleet_peer_observe(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	bool success,
	uint64_t now_ms);
int pqcp_fleet_peer_open_session(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	uint64_t now_ms);
int pqcp_fleet_peer_close_session(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id);
int pqcp_fleet_peer_quarantine(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	uint64_t until_ms);
int pqcp_fleet_peer_release(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	uint64_t now_ms);
int pqcp_fleet_peer_find(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	struct pqcp_fleet_peer_record *peer);
int pqcp_fleet_peer_registry_audit(
	struct pqcp_fleet_peer_registry *registry);

int pqcp_fleet_admission_controller_init(
	struct pqcp_fleet_admission_controller *controller,
	const struct pqcp_fleet_admission_policy *policy,
	struct pqcp_fleet_admission_subject *subjects,
	size_t capacity,
	uint64_t now_ms);
int pqcp_fleet_admission_authorize(
	struct pqcp_fleet_admission_controller *controller,
	const char *subject_id,
	uint64_t cost,
	uint64_t bytes,
	uint64_t now_ms);
int pqcp_fleet_admission_complete(
	struct pqcp_fleet_admission_controller *controller,
	const char *subject_id,
	bool success,
	uint64_t now_ms);
int pqcp_fleet_admission_block(
	struct pqcp_fleet_admission_controller *controller,
	const char *subject_id,
	uint64_t until_ms);
int pqcp_fleet_admission_reset(
	struct pqcp_fleet_admission_controller *controller,
	const char *subject_id,
	uint64_t now_ms);
int pqcp_fleet_admission_tick(
	struct pqcp_fleet_admission_controller *controller,
	uint64_t now_ms,
	uint32_t *refilled_count);
int pqcp_fleet_admission_audit(
	struct pqcp_fleet_admission_controller *controller);

int pqcp_fleet_risk_engine_init(
	struct pqcp_fleet_risk_engine *engine,
	const struct pqcp_fleet_risk_policy *policy,
	uint64_t now_ms);
int pqcp_fleet_risk_report(
	struct pqcp_fleet_risk_engine *engine,
	enum pqcp_fleet_risk_signal signal,
	uint32_t magnitude,
	uint64_t now_ms,
	uint32_t *score,
	enum pqcp_fleet_risk_action *action);
int pqcp_fleet_risk_success(
	struct pqcp_fleet_risk_engine *engine,
	enum pqcp_fleet_risk_signal signal,
	uint64_t now_ms);
int pqcp_fleet_risk_tick(
	struct pqcp_fleet_risk_engine *engine,
	uint64_t now_ms,
	uint32_t *score,
	enum pqcp_fleet_risk_action *action);
int pqcp_fleet_risk_reset(
	struct pqcp_fleet_risk_engine *engine,
	uint64_t now_ms);
int pqcp_fleet_risk_audit(
	struct pqcp_fleet_risk_engine *engine);

int pqcp_fleet_maintenance_scheduler_init(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	struct pqcp_fleet_maintenance_job *jobs,
	size_t capacity);
int pqcp_fleet_maintenance_schedule(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	const struct pqcp_fleet_maintenance_job *job);
int pqcp_fleet_maintenance_next(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t now_ms,
	bool disruption_allowed,
	struct pqcp_fleet_maintenance_job **job);
int pqcp_fleet_maintenance_complete(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t job_id,
	int result,
	uint64_t now_ms);
int pqcp_fleet_maintenance_retry(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t job_id,
	uint64_t earliest_start_ms);
int pqcp_fleet_maintenance_cancel(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t job_id);
int pqcp_fleet_maintenance_tick(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_fleet_maintenance_audit(
	struct pqcp_fleet_maintenance_scheduler *scheduler);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_RESILIENCE_H_ */
