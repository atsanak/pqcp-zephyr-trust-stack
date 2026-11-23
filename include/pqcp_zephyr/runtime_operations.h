/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free operational services for the executable PQC runtime.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_OPERATIONS_H_
#define PQCP_ZEPHYR_RUNTIME_OPERATIONS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/runtime_service.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_OPERATION_SCHEMA_VERSION 1U
#define PQCP_RUNTIME_EVENT_DETAIL_MAX_CHARS 64U
#define PQCP_RUNTIME_EVENT_CHAIN_BYTES PQCP_RUNTIME_DIGEST_BYTES
#define PQCP_RUNTIME_CHECKPOINT_MAGIC 0x50515243U
#define PQCP_RUNTIME_CHECKPOINT_FORMAT_VERSION 1U
#define PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES 128U
#define PQCP_RUNTIME_COMMAND_TOKEN_BYTES 32U
#define PQCP_RUNTIME_COMMAND_RESULT_MAX_BYTES 256U
#define PQCP_RUNTIME_POLICY_STATE_COUNT 16U
#define PQCP_RUNTIME_POLICY_COMMAND_COUNT 32U

enum pqcp_runtime_event_kind {
	PQCP_RUNTIME_EVENT_NONE = 0,
	PQCP_RUNTIME_EVENT_SERVICE_INITIALIZED,
	PQCP_RUNTIME_EVENT_SERVICE_STARTED,
	PQCP_RUNTIME_EVENT_SERVICE_STOPPED,
	PQCP_RUNTIME_EVENT_SERVICE_TICK,
	PQCP_RUNTIME_EVENT_JOB_ADMITTED,
	PQCP_RUNTIME_EVENT_JOB_QUEUED,
	PQCP_RUNTIME_EVENT_JOB_STARTED,
	PQCP_RUNTIME_EVENT_JOB_COMPLETED,
	PQCP_RUNTIME_EVENT_JOB_FAILED,
	PQCP_RUNTIME_EVENT_JOB_CANCELLED,
	PQCP_RUNTIME_EVENT_SESSION_OPENED,
	PQCP_RUNTIME_EVENT_SESSION_DRAINING,
	PQCP_RUNTIME_EVENT_SESSION_CLOSED,
	PQCP_RUNTIME_EVENT_KEY_CREATED,
	PQCP_RUNTIME_EVENT_KEY_ROTATED,
	PQCP_RUNTIME_EVENT_KEY_EXPIRED,
	PQCP_RUNTIME_EVENT_KEY_DESTROYED,
	PQCP_RUNTIME_EVENT_IDENTITY_CREATED,
	PQCP_RUNTIME_EVENT_IDENTITY_ROTATED,
	PQCP_RUNTIME_EVENT_PROFILE_OBSERVED,
	PQCP_RUNTIME_EVENT_PROFILE_TRANSITIONED,
	PQCP_RUNTIME_EVENT_HEALTH_DEGRADED,
	PQCP_RUNTIME_EVENT_HEALTH_RECOVERED,
	PQCP_RUNTIME_EVENT_CIRCUIT_OPENED,
	PQCP_RUNTIME_EVENT_CIRCUIT_CLOSED,
	PQCP_RUNTIME_EVENT_CHECKPOINT_WRITTEN,
	PQCP_RUNTIME_EVENT_CHECKPOINT_RESTORED,
	PQCP_RUNTIME_EVENT_COMMAND_ACCEPTED,
	PQCP_RUNTIME_EVENT_COMMAND_REJECTED,
	PQCP_RUNTIME_EVENT_COMMAND_COMPLETED,
	PQCP_RUNTIME_EVENT_AUDIT_FAILURE,
	PQCP_RUNTIME_EVENT_KIND_COUNT,
};

enum pqcp_runtime_event_severity {
	PQCP_RUNTIME_EVENT_DEBUG = 0,
	PQCP_RUNTIME_EVENT_INFO,
	PQCP_RUNTIME_EVENT_NOTICE,
	PQCP_RUNTIME_EVENT_WARNING,
	PQCP_RUNTIME_EVENT_ERROR,
	PQCP_RUNTIME_EVENT_CRITICAL,
};

enum pqcp_runtime_scheduler_class {
	PQCP_RUNTIME_SCHEDULER_CONTROL = 0,
	PQCP_RUNTIME_SCHEDULER_INTERACTIVE,
	PQCP_RUNTIME_SCHEDULER_DEFAULT,
	PQCP_RUNTIME_SCHEDULER_BULK,
	PQCP_RUNTIME_SCHEDULER_MAINTENANCE,
	PQCP_RUNTIME_SCHEDULER_CLASS_COUNT,
};

enum pqcp_runtime_scheduler_reason {
	PQCP_RUNTIME_SCHEDULER_REASON_NONE = 0,
	PQCP_RUNTIME_SCHEDULER_REASON_SELECTED,
	PQCP_RUNTIME_SCHEDULER_REASON_EMPTY,
	PQCP_RUNTIME_SCHEDULER_REASON_NOT_BEFORE,
	PQCP_RUNTIME_SCHEDULER_REASON_DEADLINE,
	PQCP_RUNTIME_SCHEDULER_REASON_QUOTA,
	PQCP_RUNTIME_SCHEDULER_REASON_CIRCUIT,
	PQCP_RUNTIME_SCHEDULER_REASON_BACKPRESSURE,
	PQCP_RUNTIME_SCHEDULER_REASON_CANCELLED,
};

enum pqcp_runtime_command_kind {
	PQCP_RUNTIME_COMMAND_NONE = 0,
	PQCP_RUNTIME_COMMAND_START,
	PQCP_RUNTIME_COMMAND_STOP,
	PQCP_RUNTIME_COMMAND_TICK,
	PQCP_RUNTIME_COMMAND_SELFTEST,
	PQCP_RUNTIME_COMMAND_AUDIT,
	PQCP_RUNTIME_COMMAND_LOCKDOWN,
	PQCP_RUNTIME_COMMAND_RECOVER,
	PQCP_RUNTIME_COMMAND_OPEN_SESSION,
	PQCP_RUNTIME_COMMAND_CLOSE_SESSION,
	PQCP_RUNTIME_COMMAND_DRAIN_SESSION,
	PQCP_RUNTIME_COMMAND_SUBMIT_JOB,
	PQCP_RUNTIME_COMMAND_CANCEL_JOB,
	PQCP_RUNTIME_COMMAND_ROTATE_KEYS,
	PQCP_RUNTIME_COMMAND_EXPIRE_KEYS,
	PQCP_RUNTIME_COMMAND_ROTATE_IDENTITIES,
	PQCP_RUNTIME_COMMAND_TRANSITION_PROFILE,
	PQCP_RUNTIME_COMMAND_WRITE_CHECKPOINT,
	PQCP_RUNTIME_COMMAND_RESTORE_CHECKPOINT,
	PQCP_RUNTIME_COMMAND_BEGIN_TRANSACTION,
	PQCP_RUNTIME_COMMAND_COMMIT_TRANSACTION,
	PQCP_RUNTIME_COMMAND_ROLLBACK_TRANSACTION,
	PQCP_RUNTIME_COMMAND_BEGIN_MIGRATION,
	PQCP_RUNTIME_COMMAND_PROMOTE_MIGRATION,
	PQCP_RUNTIME_COMMAND_ROLLBACK_MIGRATION,
	PQCP_RUNTIME_COMMAND_ISSUE_LEASE,
	PQCP_RUNTIME_COMMAND_REVOKE_LEASE,
	PQCP_RUNTIME_COMMAND_RECONCILE_LEASES,
	PQCP_RUNTIME_COMMAND_RUN_CAMPAIGN,
	PQCP_RUNTIME_COMMAND_BUILD_EVIDENCE,
	PQCP_RUNTIME_COMMAND_READ_HEALTH,
	PQCP_RUNTIME_COMMAND_READ_SNAPSHOT,
	PQCP_RUNTIME_COMMAND_KIND_COUNT,
};

enum pqcp_runtime_policy_state {
	PQCP_RUNTIME_POLICY_UNINITIALIZED = 0,
	PQCP_RUNTIME_POLICY_INITIALIZED,
	PQCP_RUNTIME_POLICY_STARTING,
	PQCP_RUNTIME_POLICY_RUNNING,
	PQCP_RUNTIME_POLICY_DEGRADED,
	PQCP_RUNTIME_POLICY_DRAINING,
	PQCP_RUNTIME_POLICY_STOPPING,
	PQCP_RUNTIME_POLICY_STOPPED,
	PQCP_RUNTIME_POLICY_LOCKDOWN,
	PQCP_RUNTIME_POLICY_RECOVERING,
	PQCP_RUNTIME_POLICY_MIGRATING,
	PQCP_RUNTIME_POLICY_CHECKPOINTING,
	PQCP_RUNTIME_POLICY_RESTORING,
	PQCP_RUNTIME_POLICY_MAINTENANCE,
	PQCP_RUNTIME_POLICY_FAILED,
	PQCP_RUNTIME_POLICY_TERMINATED,
};

enum pqcp_runtime_policy_action {
	PQCP_RUNTIME_POLICY_DENY = 0,
	PQCP_RUNTIME_POLICY_ALLOW,
	PQCP_RUNTIME_POLICY_ALLOW_IDEMPOTENT,
	PQCP_RUNTIME_POLICY_ALLOW_READ_ONLY,
	PQCP_RUNTIME_POLICY_REQUIRE_DRAIN,
	PQCP_RUNTIME_POLICY_REQUIRE_MAINTENANCE,
	PQCP_RUNTIME_POLICY_REQUIRE_RECOVERY,
};

enum pqcp_runtime_metric_kind {
	PQCP_RUNTIME_METRIC_QUEUE_WAIT_US = 0,
	PQCP_RUNTIME_METRIC_EXECUTION_US,
	PQCP_RUNTIME_METRIC_END_TO_END_US,
	PQCP_RUNTIME_METRIC_CYCLES,
	PQCP_RUNTIME_METRIC_STACK_BYTES,
	PQCP_RUNTIME_METRIC_WORKSPACE_BYTES,
	PQCP_RUNTIME_METRIC_QUEUE_DEPTH,
	PQCP_RUNTIME_METRIC_FAILURES,
	PQCP_RUNTIME_METRIC_KIND_COUNT,
};

enum pqcp_runtime_slo_status {
	PQCP_RUNTIME_SLO_UNKNOWN = 0,
	PQCP_RUNTIME_SLO_PASS,
	PQCP_RUNTIME_SLO_WARNING,
	PQCP_RUNTIME_SLO_FAIL,
};

enum pqcp_runtime_pressure_level {
	PQCP_RUNTIME_PRESSURE_NORMAL = 0,
	PQCP_RUNTIME_PRESSURE_ELEVATED,
	PQCP_RUNTIME_PRESSURE_HIGH,
	PQCP_RUNTIME_PRESSURE_CRITICAL,
};

enum pqcp_runtime_resource_condition {
	PQCP_RUNTIME_RESOURCE_AVAILABLE = 0,
	PQCP_RUNTIME_RESOURCE_JOBS_ELEVATED,
	PQCP_RUNTIME_RESOURCE_KEYS_ELEVATED,
	PQCP_RUNTIME_RESOURCE_SESSIONS_ELEVATED,
	PQCP_RUNTIME_RESOURCE_WORKSPACES_ELEVATED,
	PQCP_RUNTIME_RESOURCE_MEMORY_ELEVATED,
	PQCP_RUNTIME_RESOURCE_HIGH,
	PQCP_RUNTIME_RESOURCE_CRITICAL,
	PQCP_RUNTIME_RESOURCE_JOBS_EXHAUSTED,
	PQCP_RUNTIME_RESOURCE_KEYS_EXHAUSTED,
	PQCP_RUNTIME_RESOURCE_SESSIONS_EXHAUSTED,
	PQCP_RUNTIME_RESOURCE_WORKSPACES_EXHAUSTED,
	PQCP_RUNTIME_RESOURCE_MEMORY_EXHAUSTED,
	PQCP_RUNTIME_RESOURCE_QUARANTINED,
	PQCP_RUNTIME_RESOURCE_RECLAIMING,
	PQCP_RUNTIME_RESOURCE_FAILED,
	PQCP_RUNTIME_RESOURCE_CONDITION_COUNT,
};

enum pqcp_runtime_resource_disposition {
	PQCP_RUNTIME_RESOURCE_DENY = 0,
	PQCP_RUNTIME_RESOURCE_ALLOW,
	PQCP_RUNTIME_RESOURCE_ALLOW_THROTTLED,
	PQCP_RUNTIME_RESOURCE_ALLOW_RECLAIM,
	PQCP_RUNTIME_RESOURCE_REQUIRE_CHECKPOINT,
	PQCP_RUNTIME_RESOURCE_REQUIRE_RECOVERY,
};

enum pqcp_runtime_recovery_condition {
	PQCP_RUNTIME_RECOVERY_HEALTHY = 0,
	PQCP_RUNTIME_RECOVERY_TRANSIENT_IO,
	PQCP_RUNTIME_RECOVERY_TRANSIENT_CRYPTO,
	PQCP_RUNTIME_RECOVERY_QUEUE_STALL,
	PQCP_RUNTIME_RECOVERY_DEADLINE_MISS,
	PQCP_RUNTIME_RECOVERY_RESOURCE_PRESSURE,
	PQCP_RUNTIME_RECOVERY_KEY_STORE_INVALID,
	PQCP_RUNTIME_RECOVERY_SESSION_INVALID,
	PQCP_RUNTIME_RECOVERY_EXECUTOR_INVALID,
	PQCP_RUNTIME_RECOVERY_AUDIT_INVALID,
	PQCP_RUNTIME_RECOVERY_CHECKPOINT_INVALID,
	PQCP_RUNTIME_RECOVERY_IDENTITY_INVALID,
	PQCP_RUNTIME_RECOVERY_POLICY_VIOLATION,
	PQCP_RUNTIME_RECOVERY_REPEATED_FAILURE,
	PQCP_RUNTIME_RECOVERY_LOCKDOWN,
	PQCP_RUNTIME_RECOVERY_UNRECOVERABLE,
	PQCP_RUNTIME_RECOVERY_CONDITION_COUNT,
};

enum pqcp_runtime_recovery_directive {
	PQCP_RUNTIME_RECOVERY_IGNORE = 0,
	PQCP_RUNTIME_RECOVERY_OBSERVE,
	PQCP_RUNTIME_RECOVERY_RETRY,
	PQCP_RUNTIME_RECOVERY_BACKOFF,
	PQCP_RUNTIME_RECOVERY_DRAIN,
	PQCP_RUNTIME_RECOVERY_CHECKPOINT,
	PQCP_RUNTIME_RECOVERY_ROLLBACK,
	PQCP_RUNTIME_RECOVERY_ROTATE_KEYS,
	PQCP_RUNTIME_RECOVERY_LOCK_DOWN,
	PQCP_RUNTIME_RECOVERY_RESTART,
	PQCP_RUNTIME_RECOVERY_TERMINATE,
};

struct pqcp_runtime_event {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t timestamp_ms;
	enum pqcp_runtime_event_kind kind;
	enum pqcp_runtime_event_severity severity;
	uint64_t subject_id;
	int32_t result;
	uint32_t reason_mask;
	uint64_t value;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	char detail[PQCP_RUNTIME_EVENT_DETAIL_MAX_CHARS];
	uint8_t previous_digest[PQCP_RUNTIME_EVENT_CHAIN_BYTES];
	uint8_t digest[PQCP_RUNTIME_EVENT_CHAIN_BYTES];
};

struct pqcp_runtime_event_filter {
	uint64_t minimum_sequence;
	uint64_t maximum_sequence;
	uint64_t subject_id;
	uint32_t kind_mask_low;
	uint32_t severity_mask;
	bool match_subject;
	bool include_debug;
};

typedef void (*pqcp_runtime_event_callback)(
	const struct pqcp_runtime_event *event,
	void *user_data);

struct pqcp_runtime_event_subscription {
	pqcp_runtime_event_callback callback;
	void *user_data;
	struct pqcp_runtime_event_filter filter;
	bool active;
};

struct pqcp_runtime_event_bus {
	struct pqcp_runtime_event *entries;
	size_t capacity;
	size_t count;
	size_t next_index;
	uint64_t next_sequence;
	uint64_t dropped_events;
	struct pqcp_runtime_event_subscription *subscriptions;
	size_t subscription_capacity;
	uint8_t chain_head[PQCP_RUNTIME_EVENT_CHAIN_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_runtime_scheduler_policy {
	uint32_t schema_version;
	uint32_t class_weights[PQCP_RUNTIME_SCHEDULER_CLASS_COUNT];
	uint32_t class_burst[PQCP_RUNTIME_SCHEDULER_CLASS_COUNT];
	uint32_t tenant_quantum;
	uint32_t maximum_consecutive_dispatches;
	uint32_t deadline_guard_ms;
	uint32_t retry_base_ms;
	uint32_t retry_max_ms;
	bool expire_missed_deadlines;
	bool enforce_owner_fairness;
};

struct pqcp_runtime_scheduler_entry {
	struct pqcp_runtime_job *job;
	enum pqcp_runtime_scheduler_class scheduler_class;
	uint64_t enqueued_at_ms;
	uint64_t not_before_ms;
	uint64_t deadline_ms;
	uint64_t dispatch_sequence;
	uint32_t tenant_id;
	uint32_t cost;
	uint32_t retry_count;
	bool occupied;
	bool cancelled;
};

struct pqcp_runtime_scheduler_tenant {
	uint32_t tenant_id;
	uint32_t weight;
	uint32_t deficit;
	uint32_t queued;
	uint32_t in_flight;
	uint64_t dispatched;
	uint64_t completed;
	uint64_t failed;
	bool enabled;
};

struct pqcp_runtime_scheduler_decision {
	struct pqcp_runtime_job *job;
	enum pqcp_runtime_scheduler_reason reason;
	uint64_t selected_at_ms;
	uint64_t waited_ms;
	uint32_t tenant_id;
	uint32_t cost;
	size_t slot;
};

struct pqcp_runtime_scheduler {
	struct pqcp_runtime_scheduler_policy policy;
	struct pqcp_runtime_scheduler_entry *entries;
	size_t capacity;
	size_t count;
	struct pqcp_runtime_scheduler_tenant *tenants;
	size_t tenant_capacity;
	uint64_t next_dispatch_sequence;
	uint64_t dispatched;
	uint64_t expired;
	uint64_t cancelled;
	uint64_t rejected;
	uint32_t last_tenant_id;
	uint32_t consecutive_dispatches;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_runtime_checkpoint_header {
	uint32_t magic;
	uint16_t format_version;
	uint16_t header_bytes;
	uint32_t payload_bytes;
	uint32_t flags;
	uint64_t generation;
	uint64_t created_at_ms;
	uint64_t runtime_epoch;
	uint32_t session_count;
	uint32_t profile_count;
	uint32_t key_reference_count;
	uint32_t identity_count;
	uint8_t previous_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t payload_digest[PQCP_RUNTIME_DIGEST_BYTES];
};

struct pqcp_runtime_checkpoint_slot {
	uint8_t *buffer;
	size_t capacity;
	size_t length;
	uint64_t generation;
	bool valid;
};

struct pqcp_runtime_checkpoint_store {
	struct pqcp_runtime_checkpoint_slot *slots;
	size_t slot_count;
	size_t active_slot;
	uint64_t next_generation;
	uint8_t chain_head[PQCP_RUNTIME_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_runtime_command {
	uint32_t schema_version;
	uint64_t command_id;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	enum pqcp_runtime_command_kind kind;
	uint32_t flags;
	uint64_t subject_id;
	uint64_t argument_u64[4];
	uint32_t argument_u32[4];
	char owner[PQCP_RUNTIME_OWNER_MAX_CHARS];
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	uint8_t authorization_token[PQCP_RUNTIME_COMMAND_TOKEN_BYTES];
	const void *payload;
	size_t payload_length;
};

struct pqcp_runtime_command_result {
	uint32_t schema_version;
	uint64_t command_id;
	uint64_t completed_at_ms;
	enum pqcp_runtime_command_kind kind;
	int result;
	uint32_t reason_mask;
	uint64_t output_u64[4];
	uint32_t output_u32[4];
	uint8_t output[PQCP_RUNTIME_COMMAND_RESULT_MAX_BYTES];
	size_t output_length;
	bool replayed;
};

struct pqcp_runtime_command_cache_entry {
	uint64_t command_id;
	struct pqcp_runtime_command_result result;
	bool occupied;
};

typedef int (*pqcp_runtime_command_authorize_fn)(
	const struct pqcp_runtime_command *command,
	void *user_data);

typedef int (*pqcp_runtime_command_handler_fn)(
	struct pqcp_runtime_service *service,
	const struct pqcp_runtime_command *command,
	struct pqcp_runtime_command_result *result,
	void *user_data);

struct pqcp_runtime_command_handler {
	enum pqcp_runtime_command_kind kind;
	pqcp_runtime_command_handler_fn callback;
	void *user_data;
	bool registered;
};

struct pqcp_runtime_command_router {
	struct pqcp_runtime_service *service;
	struct pqcp_runtime_event_bus *events;
	struct pqcp_runtime_command_handler *handlers;
	size_t handler_capacity;
	struct pqcp_runtime_command_cache_entry *cache;
	size_t cache_capacity;
	size_t next_cache_slot;
	pqcp_runtime_command_authorize_fn authorize;
	void *authorize_user_data;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_runtime_policy_decision {
	enum pqcp_runtime_policy_state state;
	enum pqcp_runtime_command_kind command;
	enum pqcp_runtime_policy_action action;
	enum pqcp_runtime_policy_state next_state;
	int error;
	uint32_t flags;
};

struct pqcp_runtime_metric_sample {
	uint32_t schema_version;
	enum pqcp_runtime_metric_kind kind;
	uint64_t timestamp_ms;
	uint64_t value;
	uint64_t subject_id;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	bool success;
};

struct pqcp_runtime_metric_aggregate {
	uint32_t schema_version;
	enum pqcp_runtime_metric_kind kind;
	uint64_t count;
	uint64_t success_count;
	uint64_t failure_count;
	uint64_t minimum;
	uint64_t maximum;
	uint64_t sum;
	uint64_t ewma;
	uint64_t buckets[16];
	uint64_t last_updated_ms;
};

struct pqcp_runtime_slo_policy {
	uint32_t schema_version;
	uint64_t warning_threshold[PQCP_RUNTIME_METRIC_KIND_COUNT];
	uint64_t failure_threshold[PQCP_RUNTIME_METRIC_KIND_COUNT];
	uint32_t minimum_samples;
	uint32_t maximum_failure_bps;
};

struct pqcp_runtime_slo_report {
	uint32_t schema_version;
	enum pqcp_runtime_slo_status status;
	uint32_t warning_mask;
	uint32_t failure_mask;
	uint32_t evaluated_metrics;
	uint64_t evaluated_at_ms;
	uint64_t total_samples;
	uint64_t total_failures;
};

struct pqcp_runtime_metrics {
	struct pqcp_runtime_metric_aggregate
		aggregates[PQCP_RUNTIME_METRIC_KIND_COUNT];
	struct pqcp_runtime_slo_policy policy;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_runtime_orchestrator {
	struct pqcp_runtime_service *service;
	struct pqcp_runtime_event_bus *events;
	struct pqcp_runtime_scheduler *scheduler;
	struct pqcp_runtime_checkpoint_store *checkpoints;
	struct pqcp_runtime_command_router *commands;
	struct pqcp_runtime_metrics *metrics;
	enum pqcp_runtime_policy_state state;
	uint64_t epoch;
	uint64_t started_at_ms;
	uint64_t last_tick_ms;
	uint64_t ticks;
	uint64_t failures;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_runtime_resource_budget {
	uint32_t schema_version;
	uint32_t maximum_jobs;
	uint32_t maximum_keys;
	uint32_t maximum_sessions;
	uint32_t maximum_workspaces;
	uint64_t maximum_workspace_bytes;
	uint32_t elevated_threshold_bps;
	uint32_t high_threshold_bps;
	uint32_t critical_threshold_bps;
};

struct pqcp_runtime_resource_usage {
	uint32_t jobs;
	uint32_t keys;
	uint32_t sessions;
	uint32_t workspaces;
	uint64_t workspace_bytes;
};

struct pqcp_runtime_resource_reservation {
	uint64_t reservation_id;
	uint32_t tenant_id;
	struct pqcp_runtime_resource_usage usage;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	bool committed;
	bool occupied;
};

struct pqcp_runtime_resource_governor {
	struct pqcp_runtime_resource_budget budget;
	struct pqcp_runtime_resource_usage committed;
	struct pqcp_runtime_resource_usage reserved;
	struct pqcp_runtime_resource_reservation *reservations;
	size_t capacity;
	uint64_t next_reservation_id;
	uint64_t accepted;
	uint64_t rejected;
	uint64_t expired;
	enum pqcp_runtime_pressure_level pressure;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_runtime_resource_policy_decision {
	enum pqcp_runtime_resource_condition condition;
	enum pqcp_runtime_command_kind command;
	enum pqcp_runtime_resource_disposition disposition;
	uint32_t maximum_concurrency;
	uint32_t reservation_ttl_ms;
	uint32_t priority_penalty;
	uint32_t reason_mask;
	int error;
};

struct pqcp_runtime_recovery_policy_decision {
	enum pqcp_runtime_recovery_condition condition;
	enum pqcp_runtime_command_kind command;
	enum pqcp_runtime_recovery_directive directive;
	enum pqcp_runtime_policy_state next_state;
	uint32_t maximum_attempts;
	uint32_t delay_ms;
	uint32_t reason_mask;
	int error;
};

int pqcp_runtime_event_bus_init(
	struct pqcp_runtime_event_bus *bus,
	struct pqcp_runtime_event *entries,
	size_t capacity,
	struct pqcp_runtime_event_subscription *subscriptions,
	size_t subscription_capacity);
int pqcp_runtime_event_append(
	struct pqcp_runtime_event_bus *bus,
	const struct pqcp_runtime_event *event,
	uint64_t *sequence);
int pqcp_runtime_event_read(
	struct pqcp_runtime_event_bus *bus,
	uint64_t sequence,
	struct pqcp_runtime_event *event);
int pqcp_runtime_event_subscribe(
	struct pqcp_runtime_event_bus *bus,
	const struct pqcp_runtime_event_filter *filter,
	pqcp_runtime_event_callback callback,
	void *user_data,
	size_t *subscription_id);
int pqcp_runtime_event_unsubscribe(
	struct pqcp_runtime_event_bus *bus,
	size_t subscription_id);
int pqcp_runtime_event_bus_verify(
	struct pqcp_runtime_event_bus *bus);
int pqcp_runtime_event_emit(
	const struct pqcp_runtime_event *event);

int pqcp_runtime_scheduler_policy_default(
	struct pqcp_runtime_scheduler_policy *policy);
int pqcp_runtime_scheduler_init(
	struct pqcp_runtime_scheduler *scheduler,
	const struct pqcp_runtime_scheduler_policy *policy,
	struct pqcp_runtime_scheduler_entry *entries,
	size_t capacity,
	struct pqcp_runtime_scheduler_tenant *tenants,
	size_t tenant_capacity);
int pqcp_runtime_scheduler_configure_tenant(
	struct pqcp_runtime_scheduler *scheduler,
	uint32_t tenant_id,
	uint32_t weight,
	bool enabled);
int pqcp_runtime_scheduler_submit(
	struct pqcp_runtime_scheduler *scheduler,
	struct pqcp_runtime_job *job,
	enum pqcp_runtime_scheduler_class scheduler_class,
	uint32_t tenant_id,
	uint32_t cost,
	uint64_t not_before_ms);
int pqcp_runtime_scheduler_select(
	struct pqcp_runtime_scheduler *scheduler,
	uint64_t now_ms,
	struct pqcp_runtime_scheduler_decision *decision);
int pqcp_runtime_scheduler_complete(
	struct pqcp_runtime_scheduler *scheduler,
	const struct pqcp_runtime_scheduler_decision *decision,
	int result,
	uint64_t now_ms);
int pqcp_runtime_scheduler_cancel(
	struct pqcp_runtime_scheduler *scheduler,
	uint64_t job_id);
int pqcp_runtime_scheduler_audit(
	struct pqcp_runtime_scheduler *scheduler);

int pqcp_runtime_checkpoint_store_init(
	struct pqcp_runtime_checkpoint_store *store,
	struct pqcp_runtime_checkpoint_slot *slots,
	size_t slot_count);
/* Reconstruct slot metadata from retained buffers without erasing them.
 * A corrupt newest slot is ignored if an older verified slot survives.
 * Call only while the store is offline and its buffers are exclusively owned.
 */
int pqcp_runtime_checkpoint_store_reopen(
	struct pqcp_runtime_checkpoint_store *store,
	struct pqcp_runtime_checkpoint_slot *slots, size_t slot_count);
int pqcp_runtime_checkpoint_write(
	struct pqcp_runtime_checkpoint_store *store,
	const struct pqcp_runtime_service *service,
	uint64_t now_ms,
	uint64_t runtime_epoch,
	uint32_t flags,
	struct pqcp_runtime_checkpoint_header *header);
int pqcp_runtime_checkpoint_read(
	struct pqcp_runtime_checkpoint_store *store,
	uint64_t generation,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	struct pqcp_runtime_checkpoint_header *header);
int pqcp_runtime_checkpoint_verify(
	const uint8_t *checkpoint,
	size_t checkpoint_length,
	struct pqcp_runtime_checkpoint_header *header);
int pqcp_runtime_checkpoint_store_audit(
	struct pqcp_runtime_checkpoint_store *store);

int pqcp_runtime_command_router_init(
	struct pqcp_runtime_command_router *router,
	struct pqcp_runtime_service *service,
	struct pqcp_runtime_event_bus *events,
	struct pqcp_runtime_command_handler *handlers,
	size_t handler_capacity,
	struct pqcp_runtime_command_cache_entry *cache,
	size_t cache_capacity,
	pqcp_runtime_command_authorize_fn authorize,
	void *authorize_user_data);
int pqcp_runtime_command_register(
	struct pqcp_runtime_command_router *router,
	enum pqcp_runtime_command_kind kind,
	pqcp_runtime_command_handler_fn callback,
	void *user_data);
int pqcp_runtime_command_execute(
	struct pqcp_runtime_command_router *router,
	const struct pqcp_runtime_command *command,
	struct pqcp_runtime_command_result *result);
int pqcp_runtime_command_router_audit(
	struct pqcp_runtime_command_router *router);

int pqcp_runtime_slo_policy_default(
	struct pqcp_runtime_slo_policy *policy);
int pqcp_runtime_metrics_init(
	struct pqcp_runtime_metrics *metrics,
	const struct pqcp_runtime_slo_policy *policy);
int pqcp_runtime_metrics_observe(
	struct pqcp_runtime_metrics *metrics,
	const struct pqcp_runtime_metric_sample *sample);
int pqcp_runtime_metrics_observe_job(
	struct pqcp_runtime_metrics *metrics,
	const struct pqcp_runtime_job *job,
	uint64_t queue_wait_us,
	uint64_t end_to_end_us);
int pqcp_runtime_metrics_report(
	struct pqcp_runtime_metrics *metrics,
	uint64_t now_ms,
	struct pqcp_runtime_slo_report *report);
int pqcp_runtime_metrics_audit(
	struct pqcp_runtime_metrics *metrics);

int pqcp_runtime_orchestrator_init(
	struct pqcp_runtime_orchestrator *orchestrator,
	struct pqcp_runtime_service *service,
	struct pqcp_runtime_event_bus *events,
	struct pqcp_runtime_scheduler *scheduler,
	struct pqcp_runtime_checkpoint_store *checkpoints,
	struct pqcp_runtime_command_router *commands,
	struct pqcp_runtime_metrics *metrics,
	uint64_t now_ms);
int pqcp_runtime_orchestrator_start(
	struct pqcp_runtime_orchestrator *orchestrator,
	uint64_t now_ms);
int pqcp_runtime_orchestrator_tick(
	struct pqcp_runtime_orchestrator *orchestrator,
	uint64_t now_ms,
	uint32_t dispatch_budget);
int pqcp_runtime_orchestrator_stop(
	struct pqcp_runtime_orchestrator *orchestrator,
	uint64_t now_ms);
int pqcp_runtime_orchestrator_checkpoint(
	struct pqcp_runtime_orchestrator *orchestrator,
	uint64_t now_ms,
	uint32_t flags,
	struct pqcp_runtime_checkpoint_header *header);
int pqcp_runtime_orchestrator_audit(
	struct pqcp_runtime_orchestrator *orchestrator);

int pqcp_runtime_resource_budget_default(
	struct pqcp_runtime_resource_budget *budget);
int pqcp_runtime_resource_governor_init(
	struct pqcp_runtime_resource_governor *governor,
	const struct pqcp_runtime_resource_budget *budget,
	struct pqcp_runtime_resource_reservation *reservations,
	size_t capacity);
int pqcp_runtime_resource_reserve(
	struct pqcp_runtime_resource_governor *governor,
	uint32_t tenant_id,
	const struct pqcp_runtime_resource_usage *usage,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t *reservation_id);
int pqcp_runtime_resource_commit(
	struct pqcp_runtime_resource_governor *governor,
	uint64_t reservation_id);
int pqcp_runtime_resource_release(
	struct pqcp_runtime_resource_governor *governor,
	uint64_t reservation_id);
int pqcp_runtime_resource_tick(
	struct pqcp_runtime_resource_governor *governor,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_runtime_resource_governor_audit(
	struct pqcp_runtime_resource_governor *governor);

int pqcp_runtime_resource_policy_lookup(
	enum pqcp_runtime_resource_condition condition,
	enum pqcp_runtime_command_kind command,
	struct pqcp_runtime_resource_policy_decision *decision);
int pqcp_runtime_resource_policy_catalog_audit(void);
int pqcp_runtime_recovery_policy_lookup(
	enum pqcp_runtime_recovery_condition condition,
	enum pqcp_runtime_command_kind command,
	struct pqcp_runtime_recovery_policy_decision *decision);
int pqcp_runtime_recovery_policy_catalog_audit(void);

int pqcp_runtime_policy_lookup(
	enum pqcp_runtime_policy_state state,
	enum pqcp_runtime_command_kind command,
	struct pqcp_runtime_policy_decision *decision);
int pqcp_runtime_policy_catalog_audit(void);
const char *pqcp_runtime_event_kind_str(
	enum pqcp_runtime_event_kind kind);
const char *pqcp_runtime_command_kind_str(
	enum pqcp_runtime_command_kind kind);
const char *pqcp_runtime_policy_state_str(
	enum pqcp_runtime_policy_state state);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_OPERATIONS_H_ */
