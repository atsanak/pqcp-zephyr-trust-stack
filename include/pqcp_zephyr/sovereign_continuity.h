/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free sovereign continuity and fenced recovery orchestration.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_SOVEREIGN_CONTINUITY_H_
#define PQCP_ZEPHYR_SOVEREIGN_CONTINUITY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/edge_security.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION 1U
#define PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES PQCP_EDGE_DIGEST_BYTES
#define PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS PQCP_EDGE_ID_MAX_CHARS
#define PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS 32U
#define PQCP_SOVEREIGN_CONTINUITY_MAX_DEPENDENCIES 32U

#define PQCP_SOVEREIGN_RECOVERY_OP_CHECKPOINT (1U << 0)
#define PQCP_SOVEREIGN_RECOVERY_OP_ISOLATE (1U << 1)
#define PQCP_SOVEREIGN_RECOVERY_OP_RESTORE (1U << 2)
#define PQCP_SOVEREIGN_RECOVERY_OP_VALIDATE (1U << 3)
#define PQCP_SOVEREIGN_RECOVERY_OP_REJOIN (1U << 4)
#define PQCP_SOVEREIGN_RECOVERY_OP_ROLLBACK (1U << 5)
#define PQCP_SOVEREIGN_RECOVERY_OP_FAILOVER (1U << 6)
#define PQCP_SOVEREIGN_RECOVERY_OP_DISASTER_RECOVERY (1U << 7)
#define PQCP_SOVEREIGN_RECOVERY_OP_FENCE (1U << 8)
#define PQCP_SOVEREIGN_RECOVERY_OP_ALL \
	(PQCP_SOVEREIGN_RECOVERY_OP_CHECKPOINT | \
	 PQCP_SOVEREIGN_RECOVERY_OP_ISOLATE | \
	 PQCP_SOVEREIGN_RECOVERY_OP_RESTORE | \
	 PQCP_SOVEREIGN_RECOVERY_OP_VALIDATE | \
	 PQCP_SOVEREIGN_RECOVERY_OP_REJOIN | \
	 PQCP_SOVEREIGN_RECOVERY_OP_ROLLBACK | \
	 PQCP_SOVEREIGN_RECOVERY_OP_FAILOVER | \
	 PQCP_SOVEREIGN_RECOVERY_OP_DISASTER_RECOVERY | \
	 PQCP_SOVEREIGN_RECOVERY_OP_FENCE)

enum pqcp_sovereign_objective_tier {
	PQCP_SOVEREIGN_OBJECTIVE_TIER_UNSPECIFIED = 0,
	PQCP_SOVEREIGN_OBJECTIVE_TIER_STANDARD,
	PQCP_SOVEREIGN_OBJECTIVE_TIER_IMPORTANT,
	PQCP_SOVEREIGN_OBJECTIVE_TIER_CRITICAL,
	PQCP_SOVEREIGN_OBJECTIVE_TIER_SAFETY,
};

enum pqcp_sovereign_objective_status {
	PQCP_SOVEREIGN_OBJECTIVE_STATUS_EMPTY = 0,
	PQCP_SOVEREIGN_OBJECTIVE_STATUS_COMPLIANT,
	PQCP_SOVEREIGN_OBJECTIVE_STATUS_RPO_AT_RISK,
	PQCP_SOVEREIGN_OBJECTIVE_STATUS_RTO_AT_RISK,
	PQCP_SOVEREIGN_OBJECTIVE_STATUS_BREACHED,
	PQCP_SOVEREIGN_OBJECTIVE_STATUS_SUSPENDED,
};

enum pqcp_sovereign_recovery_mode {
	PQCP_SOVEREIGN_RECOVERY_MODE_NONE = 0,
	PQCP_SOVEREIGN_RECOVERY_MODE_FAILOVER,
	PQCP_SOVEREIGN_RECOVERY_MODE_REJOIN,
	PQCP_SOVEREIGN_RECOVERY_MODE_ROLLBACK,
	PQCP_SOVEREIGN_RECOVERY_MODE_DISASTER_RECOVERY,
};

enum pqcp_sovereign_recovery_step_kind {
	PQCP_SOVEREIGN_STEP_NONE = 0,
	PQCP_SOVEREIGN_STEP_CHECKPOINT,
	PQCP_SOVEREIGN_STEP_FENCE,
	PQCP_SOVEREIGN_STEP_ISOLATE,
	PQCP_SOVEREIGN_STEP_SELECT_POINT,
	PQCP_SOVEREIGN_STEP_RESTORE,
	PQCP_SOVEREIGN_STEP_VALIDATE,
	PQCP_SOVEREIGN_STEP_PROMOTE,
	PQCP_SOVEREIGN_STEP_REJOIN,
	PQCP_SOVEREIGN_STEP_ROLLBACK,
	PQCP_SOVEREIGN_STEP_RELEASE_FENCE,
	PQCP_SOVEREIGN_STEP_COMPLETE,
};

enum pqcp_sovereign_recovery_run_state {
	PQCP_SOVEREIGN_RUN_EMPTY = 0,
	PQCP_SOVEREIGN_RUN_AUTHORIZED,
	PQCP_SOVEREIGN_RUN_FENCING,
	PQCP_SOVEREIGN_RUN_CHECKPOINTING,
	PQCP_SOVEREIGN_RUN_ISOLATING,
	PQCP_SOVEREIGN_RUN_RESTORING,
	PQCP_SOVEREIGN_RUN_VALIDATING,
	PQCP_SOVEREIGN_RUN_PROMOTING,
	PQCP_SOVEREIGN_RUN_REJOINING,
	PQCP_SOVEREIGN_RUN_ROLLING_BACK,
	PQCP_SOVEREIGN_RUN_COMPLETED,
	PQCP_SOVEREIGN_RUN_FAILED,
	PQCP_SOVEREIGN_RUN_CANCELLED,
	PQCP_SOVEREIGN_RUN_EXPIRED,
};

enum pqcp_sovereign_recovery_point_state {
	PQCP_SOVEREIGN_POINT_EMPTY = 0,
	PQCP_SOVEREIGN_POINT_CANDIDATE,
	PQCP_SOVEREIGN_POINT_VERIFIED,
	PQCP_SOVEREIGN_POINT_SELECTED,
	PQCP_SOVEREIGN_POINT_CONSUMED,
	PQCP_SOVEREIGN_POINT_QUARANTINED,
	PQCP_SOVEREIGN_POINT_EXPIRED,
};

enum pqcp_sovereign_lease_state {
	PQCP_SOVEREIGN_LEASE_EMPTY = 0,
	PQCP_SOVEREIGN_LEASE_PENDING,
	PQCP_SOVEREIGN_LEASE_ACTIVE,
	PQCP_SOVEREIGN_LEASE_EXHAUSTED,
	PQCP_SOVEREIGN_LEASE_EXPIRED,
	PQCP_SOVEREIGN_LEASE_REVOKED,
	PQCP_SOVEREIGN_LEASE_STALE,
};

enum pqcp_sovereign_fence_state {
	PQCP_SOVEREIGN_FENCE_EMPTY = 0,
	PQCP_SOVEREIGN_FENCE_HELD,
	PQCP_SOVEREIGN_FENCE_RELEASED,
	PQCP_SOVEREIGN_FENCE_EXPIRED,
	PQCP_SOVEREIGN_FENCE_SUPERSEDED,
};

enum pqcp_sovereign_continuity_event_type {
	PQCP_SOVEREIGN_CONTINUITY_EVENT_NONE = 0,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_OBJECTIVE_REGISTERED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_OBJECTIVE_EVALUATED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_POINT_REGISTERED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_POINT_SELECTED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_POINT_QUARANTINED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_LEASE_ISSUED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_LEASE_CONSUMED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_LEASE_REVOKED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_FENCE_ACQUIRED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_FENCE_ADVANCED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_FENCE_RELEASED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_PLAN_REGISTERED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_RUN_STARTED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_RUN_TRANSITIONED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_STEP_RECORDED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_RUN_COMPLETED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_RUN_FAILED,
	PQCP_SOVEREIGN_CONTINUITY_EVENT_EDGE_ADAPTER,
};

enum pqcp_sovereign_continuity_event_outcome {
	PQCP_SOVEREIGN_EVENT_OUTCOME_UNKNOWN = 0,
	PQCP_SOVEREIGN_EVENT_OUTCOME_ALLOWED,
	PQCP_SOVEREIGN_EVENT_OUTCOME_DENIED,
	PQCP_SOVEREIGN_EVENT_OUTCOME_SUCCEEDED,
	PQCP_SOVEREIGN_EVENT_OUTCOME_FAILED,
	PQCP_SOVEREIGN_EVENT_OUTCOME_EXPIRED,
};

struct pqcp_sovereign_continuity_objective {
	uint32_t schema_version;
	uint32_t generation;
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char objective_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char service_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	enum pqcp_sovereign_objective_tier tier;
	enum pqcp_sovereign_objective_status status;
	uint64_t created_at_ms;
	uint64_t updated_at_ms;
	uint64_t expires_at_ms;
	uint64_t recovery_point_objective_ms;
	uint64_t recovery_time_objective_ms;
	uint64_t maximum_data_loss_bytes;
	uint64_t latest_protected_at_ms;
	uint64_t outage_started_at_ms;
	uint64_t last_evaluated_at_ms;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint32_t minimum_replicas;
	uint32_t available_replicas;
	uint32_t priority;
	uint32_t breach_count;
	uint64_t dependency_mask;
	uint64_t satisfied_dependency_mask;
	uint8_t policy_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t objective_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	bool suspended;
	bool occupied;
};

struct pqcp_sovereign_continuity_observation {
	uint64_t observed_at_ms;
	uint64_t latest_protected_at_ms;
	uint64_t outage_started_at_ms;
	uint64_t unprotected_bytes;
	uint64_t satisfied_dependency_mask;
	uint32_t available_replicas;
	bool service_available;
};

struct pqcp_sovereign_objective_evaluation {
	enum pqcp_sovereign_objective_status status;
	uint64_t data_age_ms;
	uint64_t outage_duration_ms;
	uint64_t rpo_remaining_ms;
	uint64_t rto_remaining_ms;
	uint64_t unsatisfied_dependency_mask;
	uint32_t missing_replicas;
	bool rpo_met;
	bool rto_met;
	bool dependencies_met;
	bool replicas_met;
};

struct pqcp_sovereign_objective_registry {
	uint32_t schema_version;
	struct pqcp_sovereign_continuity_objective *objectives;
	size_t capacity;
	uint32_t next_generation;
	uint64_t evaluation_count;
	uint64_t breach_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_recovery_point {
	uint32_t schema_version;
	uint32_t generation;
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char objective_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char point_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char source_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	enum pqcp_sovereign_recovery_point_state state;
	uint64_t created_at_ms;
	uint64_t protected_at_ms;
	uint64_t verified_at_ms;
	uint64_t expires_at_ms;
	uint64_t sequence;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t fencing_epoch;
	uint64_t logical_bytes;
	uint32_t replica_count;
	uint32_t verification_flags;
	uint8_t content_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t manifest_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t parent_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t point_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	bool complete;
	bool immutable;
	bool occupied;
};

struct pqcp_sovereign_recovery_point_query {
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char objective_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	uint64_t now_ms;
	uint64_t maximum_age_ms;
	uint64_t minimum_sequence;
	uint64_t minimum_policy_epoch;
	uint64_t minimum_revocation_epoch;
	uint64_t maximum_fencing_epoch;
	uint64_t maximum_logical_bytes;
	uint32_t minimum_replicas;
	uint32_t required_verification_flags;
	bool require_immutable;
	bool require_parent_binding;
};

struct pqcp_sovereign_recovery_point_selection {
	uint32_t generation;
	char point_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	uint64_t selected_at_ms;
	uint64_t age_ms;
	uint64_t sequence;
	uint64_t fencing_epoch;
	uint8_t point_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t selection_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
};

struct pqcp_sovereign_recovery_point_catalog {
	uint32_t schema_version;
	struct pqcp_sovereign_recovery_point *points;
	size_t capacity;
	uint32_t next_generation;
	uint64_t selection_count;
	uint64_t rejection_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_authority_lease {
	uint32_t schema_version;
	uint32_t generation;
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char principal_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char lease_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	enum pqcp_sovereign_lease_state state;
	uint64_t issued_at_ms;
	uint64_t valid_from_ms;
	uint64_t expires_at_ms;
	uint64_t maximum_offline_ms;
	uint64_t last_used_at_ms;
	uint64_t operation_limit;
	uint64_t operation_count;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t fencing_epoch;
	uint32_t operation_mask;
	uint32_t required_approval_count;
	uint8_t plan_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t quorum_authorization_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t previous_lease_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t lease_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	bool offline_permitted;
	bool occupied;
};

struct pqcp_sovereign_lease_use {
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char principal_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char lease_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	uint64_t now_ms;
	uint64_t disconnected_since_ms;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t fencing_epoch;
	uint32_t operation;
	uint8_t plan_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t authorization_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
};

struct pqcp_sovereign_authority_lease_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_authority_lease *leases;
	size_t capacity;
	uint32_t next_generation;
	uint64_t current_policy_epoch;
	uint64_t current_revocation_epoch;
	uint64_t current_fencing_epoch;
	uint64_t accepted_count;
	uint64_t rejected_count;
	uint64_t exhausted_count;
	uint8_t tail_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_fence {
	uint32_t schema_version;
	uint32_t generation;
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char resource_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char holder_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char lease_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	enum pqcp_sovereign_fence_state state;
	uint64_t epoch;
	uint64_t acquired_at_ms;
	uint64_t renewed_at_ms;
	uint64_t expires_at_ms;
	uint64_t released_at_ms;
	uint8_t holder_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t authorization_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t previous_fence_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t fence_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_fence_claim {
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char resource_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char holder_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char lease_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	uint64_t requested_epoch;
	uint64_t now_ms;
	uint64_t expires_at_ms;
	uint8_t holder_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t authorization_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
};

struct pqcp_sovereign_fence_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_fence *fences;
	size_t capacity;
	uint32_t next_generation;
	uint64_t highest_epoch;
	uint64_t acquisition_count;
	uint64_t rejection_count;
	uint8_t tail_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_recovery_step {
	uint32_t step_id;
	enum pqcp_sovereign_recovery_step_kind kind;
	char service_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	uint32_t dependency_mask;
	uint32_t required_operation;
	uint32_t maximum_attempts;
	uint64_t timeout_ms;
	uint64_t minimum_stable_ms;
	uint8_t expected_evidence_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	bool point_required;
	bool fence_required;
	bool evidence_required;
	bool critical;
};

struct pqcp_sovereign_recovery_plan {
	uint32_t schema_version;
	uint32_t generation;
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char plan_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char objective_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char resource_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	enum pqcp_sovereign_recovery_mode mode;
	uint64_t created_at_ms;
	uint64_t updated_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t maximum_duration_ms;
	uint64_t point_maximum_age_ms;
	uint32_t step_count;
	uint32_t required_approval_count;
	uint32_t required_operation_mask;
	struct pqcp_sovereign_recovery_step
		steps[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS];
	uint8_t topological_order[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS];
	uint8_t policy_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t plan_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	bool active;
	bool occupied;
};

struct pqcp_sovereign_recovery_plan_registry {
	uint32_t schema_version;
	struct pqcp_sovereign_recovery_plan *plans;
	size_t capacity;
	uint32_t next_generation;
	uint64_t registration_count;
	uint64_t rejection_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_recovery_run {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t run_id;
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char plan_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char objective_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char resource_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char principal_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char lease_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char selected_point_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	enum pqcp_sovereign_recovery_mode mode;
	enum pqcp_sovereign_recovery_run_state state;
	uint64_t authorized_at_ms;
	uint64_t started_at_ms;
	uint64_t updated_at_ms;
	uint64_t deadline_ms;
	uint64_t completed_at_ms;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t fencing_epoch;
	uint64_t edge_recovery_id;
	uint32_t selected_point_generation;
	uint32_t fence_generation;
	uint32_t current_order_index;
	uint32_t completed_step_mask;
	uint32_t failed_step_mask;
	uint32_t attempt_mask;
	uint32_t failure_count;
	uint8_t step_attempts[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS];
	uint8_t plan_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t quorum_authorization_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t selected_point_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t run_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	bool fence_held;
	bool edge_authorized;
	bool occupied;
};

struct pqcp_sovereign_recovery_start {
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char plan_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char principal_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char lease_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	uint64_t incident_id;
	uint64_t now_ms;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t fencing_epoch;
	uint32_t approval_count;
	uint8_t plan_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t quorum_authorization_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
};

struct pqcp_sovereign_recovery_step_result {
	uint64_t run_id;
	uint32_t step_id;
	uint64_t now_ms;
	int result;
	uint8_t evidence_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
};

struct pqcp_sovereign_edge_adapters {
	struct pqcp_edge_continuity_manager *continuity;
	struct pqcp_edge_recovery_coordinator *recovery;
};

struct pqcp_sovereign_recovery_orchestrator {
	uint32_t schema_version;
	struct pqcp_sovereign_recovery_run *runs;
	size_t capacity;
	uint32_t next_generation;
	uint64_t next_run_id;
	struct pqcp_sovereign_objective_registry *objectives;
	struct pqcp_sovereign_recovery_point_catalog *points;
	struct pqcp_sovereign_authority_lease_manager *leases;
	struct pqcp_sovereign_fence_manager *fences;
	struct pqcp_sovereign_recovery_plan_registry *plans;
	struct pqcp_sovereign_edge_adapters edge;
	uint64_t completed_count;
	uint64_t failed_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_continuity_event {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t occurred_at_ms;
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char subject_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	enum pqcp_sovereign_continuity_event_type type;
	enum pqcp_sovereign_continuity_event_outcome outcome;
	uint64_t object_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t fencing_epoch;
	int result;
	uint8_t evidence_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t event_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_continuity_audit_log {
	uint32_t schema_version;
	struct pqcp_sovereign_continuity_event *events;
	size_t capacity;
	size_t head;
	size_t count;
	uint64_t next_sequence;
	uint64_t eviction_count;
	uint8_t anchor_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t tail_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_continuity_audit_record {
	char tenant_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	char subject_id[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS];
	enum pqcp_sovereign_continuity_event_type type;
	enum pqcp_sovereign_continuity_event_outcome outcome;
	uint64_t occurred_at_ms;
	uint64_t object_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t fencing_epoch;
	int result;
	uint8_t evidence_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
};

int pqcp_sovereign_objective_registry_init(
	struct pqcp_sovereign_objective_registry *registry,
	struct pqcp_sovereign_continuity_objective *objectives,
	size_t capacity);
int pqcp_sovereign_objective_put(
	struct pqcp_sovereign_objective_registry *registry,
	const struct pqcp_sovereign_continuity_objective *objective);
int pqcp_sovereign_objective_remove(
	struct pqcp_sovereign_objective_registry *registry,
	const char *tenant_id,
	const char *objective_id,
	uint32_t generation);
int pqcp_sovereign_objective_get(
	struct pqcp_sovereign_objective_registry *registry,
	const char *tenant_id,
	const char *objective_id,
	struct pqcp_sovereign_continuity_objective *objective);
int pqcp_sovereign_objective_observe(
	struct pqcp_sovereign_objective_registry *registry,
	const char *tenant_id,
	const char *objective_id,
	const struct pqcp_sovereign_continuity_observation *observation,
	struct pqcp_sovereign_objective_evaluation *evaluation);
int pqcp_sovereign_objective_evaluate(
	const struct pqcp_sovereign_continuity_objective *objective,
	const struct pqcp_sovereign_continuity_observation *observation,
	struct pqcp_sovereign_objective_evaluation *evaluation);
int pqcp_sovereign_objective_sync_edge(
	struct pqcp_sovereign_objective_registry *registry,
	const char *tenant_id,
	const char *objective_id,
	struct pqcp_edge_continuity_manager *manager);
int pqcp_sovereign_objective_registry_audit(
	struct pqcp_sovereign_objective_registry *registry);

int pqcp_sovereign_recovery_point_catalog_init(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	struct pqcp_sovereign_recovery_point *points,
	size_t capacity);
int pqcp_sovereign_recovery_point_put(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const struct pqcp_sovereign_recovery_point *point);
int pqcp_sovereign_recovery_point_verify(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const char *tenant_id,
	const char *point_id,
	uint32_t generation,
	uint32_t verification_flags,
	const uint8_t evidence_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_recovery_point_quarantine(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const char *tenant_id,
	const char *point_id,
	uint32_t generation,
	const uint8_t evidence_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_recovery_point_select(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const struct pqcp_sovereign_recovery_point_query *query,
	struct pqcp_sovereign_recovery_point_selection *selection);
int pqcp_sovereign_recovery_point_consume(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const char *tenant_id,
	const char *point_id,
	uint32_t generation,
	uint64_t now_ms);
int pqcp_sovereign_recovery_point_catalog_expire(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_recovery_point_catalog_audit(
	struct pqcp_sovereign_recovery_point_catalog *catalog);

int pqcp_sovereign_authority_lease_manager_init(
	struct pqcp_sovereign_authority_lease_manager *manager,
	struct pqcp_sovereign_authority_lease *leases,
	size_t capacity,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t fencing_epoch);
int pqcp_sovereign_authority_lease_issue(
	struct pqcp_sovereign_authority_lease_manager *manager,
	const struct pqcp_sovereign_authority_lease *lease);
int pqcp_sovereign_authority_lease_activate(
	struct pqcp_sovereign_authority_lease_manager *manager,
	const char *tenant_id,
	const char *lease_id,
	uint32_t generation,
	uint64_t now_ms);
int pqcp_sovereign_authority_lease_use(
	struct pqcp_sovereign_authority_lease_manager *manager,
	const struct pqcp_sovereign_lease_use *use);
int pqcp_sovereign_authority_lease_revoke(
	struct pqcp_sovereign_authority_lease_manager *manager,
	const char *tenant_id,
	const char *lease_id,
	uint32_t generation,
	uint64_t now_ms);
int pqcp_sovereign_authority_lease_update_epochs(
	struct pqcp_sovereign_authority_lease_manager *manager,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t fencing_epoch);
int pqcp_sovereign_authority_lease_expire(
	struct pqcp_sovereign_authority_lease_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_authority_lease_manager_audit(
	struct pqcp_sovereign_authority_lease_manager *manager);

int pqcp_sovereign_fence_manager_init(
	struct pqcp_sovereign_fence_manager *manager,
	struct pqcp_sovereign_fence *fences,
	size_t capacity,
	uint64_t initial_epoch);
int pqcp_sovereign_fence_acquire(
	struct pqcp_sovereign_fence_manager *manager,
	const struct pqcp_sovereign_fence_claim *claim,
	struct pqcp_sovereign_fence *fence);
int pqcp_sovereign_fence_renew(
	struct pqcp_sovereign_fence_manager *manager,
	const struct pqcp_sovereign_fence_claim *claim,
	uint32_t generation,
	struct pqcp_sovereign_fence *fence);
int pqcp_sovereign_fence_advance(
	struct pqcp_sovereign_fence_manager *manager,
	const char *tenant_id,
	const char *resource_id,
	uint64_t minimum_epoch,
	const uint8_t authorization_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t *new_epoch);
int pqcp_sovereign_fence_release(
	struct pqcp_sovereign_fence_manager *manager,
	const char *tenant_id,
	const char *resource_id,
	const char *holder_id,
	uint32_t generation,
	uint64_t epoch,
	uint64_t now_ms);
int pqcp_sovereign_fence_check(
	struct pqcp_sovereign_fence_manager *manager,
	const char *tenant_id,
	const char *resource_id,
	const char *holder_id,
	uint64_t epoch,
	uint64_t now_ms);
int pqcp_sovereign_fence_expire(
	struct pqcp_sovereign_fence_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_fence_manager_audit(
	struct pqcp_sovereign_fence_manager *manager);

int pqcp_sovereign_recovery_plan_registry_init(
	struct pqcp_sovereign_recovery_plan_registry *registry,
	struct pqcp_sovereign_recovery_plan *plans,
	size_t capacity);
int pqcp_sovereign_recovery_plan_put(
	struct pqcp_sovereign_recovery_plan_registry *registry,
	const struct pqcp_sovereign_recovery_plan *plan);
int pqcp_sovereign_recovery_plan_get(
	struct pqcp_sovereign_recovery_plan_registry *registry,
	const char *tenant_id,
	const char *plan_id,
	struct pqcp_sovereign_recovery_plan *plan);
int pqcp_sovereign_recovery_plan_remove(
	struct pqcp_sovereign_recovery_plan_registry *registry,
	const char *tenant_id,
	const char *plan_id,
	uint32_t generation);
int pqcp_sovereign_recovery_plan_order(
	const struct pqcp_sovereign_recovery_plan *plan,
	uint8_t order[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS]);
int pqcp_sovereign_recovery_plan_registry_audit(
	struct pqcp_sovereign_recovery_plan_registry *registry);

int pqcp_sovereign_recovery_orchestrator_init(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *runs,
	size_t capacity,
	struct pqcp_sovereign_objective_registry *objectives,
	struct pqcp_sovereign_recovery_point_catalog *points,
	struct pqcp_sovereign_authority_lease_manager *leases,
	struct pqcp_sovereign_fence_manager *fences,
	struct pqcp_sovereign_recovery_plan_registry *plans,
	const struct pqcp_sovereign_edge_adapters *edge);
int pqcp_sovereign_recovery_start(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_start *start,
	struct pqcp_sovereign_recovery_run *run);
int pqcp_sovereign_recovery_current_step(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	uint64_t run_id,
	struct pqcp_sovereign_recovery_step *step);
int pqcp_sovereign_recovery_record(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_step_result *result,
	struct pqcp_sovereign_recovery_run *run);
int pqcp_sovereign_recovery_cancel(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	uint64_t run_id,
	const uint8_t authorization_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_recovery_tick(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_recovery_orchestrator_audit(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator);

int pqcp_sovereign_continuity_audit_log_init(
	struct pqcp_sovereign_continuity_audit_log *log,
	struct pqcp_sovereign_continuity_event *events,
	size_t capacity);
int pqcp_sovereign_continuity_audit_append(
	struct pqcp_sovereign_continuity_audit_log *log,
	const struct pqcp_sovereign_continuity_audit_record *record,
	struct pqcp_sovereign_continuity_event *event);
int pqcp_sovereign_continuity_audit_read(
	struct pqcp_sovereign_continuity_audit_log *log,
	uint64_t sequence,
	struct pqcp_sovereign_continuity_event *event);
int pqcp_sovereign_continuity_audit_bounds(
	struct pqcp_sovereign_continuity_audit_log *log,
	uint64_t *first_sequence,
	uint64_t *last_sequence,
	uint8_t anchor_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint8_t tail_digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
int pqcp_sovereign_continuity_audit_verify(
	struct pqcp_sovereign_continuity_audit_log *log);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_SOVEREIGN_CONTINUITY_H_ */
