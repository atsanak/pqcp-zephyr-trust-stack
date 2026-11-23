/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free dependency-aware fleet convergence orchestration.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_CONVERGENCE_H_
#define PQCP_ZEPHYR_FLEET_CONVERGENCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_desired_state.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION 1U
#define PQCP_FLEET_PLAN_LEASE_OWNER_MAX_CHARS 32U

enum pqcp_fleet_convergence_action {
	PQCP_FLEET_CONVERGENCE_ACTION_NONE = 0,
	PQCP_FLEET_CONVERGENCE_INSTALL_IDENTITY,
	PQCP_FLEET_CONVERGENCE_ROTATE_IDENTITY,
	PQCP_FLEET_CONVERGENCE_RESTRICT_IDENTITY,
	PQCP_FLEET_CONVERGENCE_APPLY_REVOCATION,
	PQCP_FLEET_CONVERGENCE_QUARANTINE,
	PQCP_FLEET_CONVERGENCE_DECOMMISSION,
	PQCP_FLEET_CONVERGENCE_APPLY_POLICY,
	PQCP_FLEET_CONVERGENCE_RESTRICT_POLICY,
	PQCP_FLEET_CONVERGENCE_STAGE_FIRMWARE,
	PQCP_FLEET_CONVERGENCE_ACTIVATE_FIRMWARE,
	PQCP_FLEET_CONVERGENCE_ROLLBACK_FIRMWARE,
	PQCP_FLEET_CONVERGENCE_VERIFY_FIRMWARE,
	PQCP_FLEET_CONVERGENCE_ESTABLISH_CHANNEL,
	PQCP_FLEET_CONVERGENCE_REKEY_CHANNEL,
	PQCP_FLEET_CONVERGENCE_CLOSE_CHANNEL,
	PQCP_FLEET_CONVERGENCE_ENTER_RECOVERY,
	PQCP_FLEET_CONVERGENCE_ADVANCE_RECOVERY,
	PQCP_FLEET_CONVERGENCE_EXIT_RECOVERY,
	PQCP_FLEET_CONVERGENCE_WAIT_BARRIER,
	PQCP_FLEET_CONVERGENCE_VERIFY_STATE,
	PQCP_FLEET_CONVERGENCE_ACTION_COUNT,
};

enum pqcp_fleet_plan_state {
	PQCP_FLEET_PLAN_EMPTY = 0,
	PQCP_FLEET_PLAN_BUILDING,
	PQCP_FLEET_PLAN_READY,
	PQCP_FLEET_PLAN_RUNNING,
	PQCP_FLEET_PLAN_BLOCKED,
	PQCP_FLEET_PLAN_ROLLING_BACK,
	PQCP_FLEET_PLAN_SUCCEEDED,
	PQCP_FLEET_PLAN_FAILED,
	PQCP_FLEET_PLAN_SUPERSEDED,
	PQCP_FLEET_PLAN_CANCELLED,
};

enum pqcp_fleet_step_state {
	PQCP_FLEET_STEP_EMPTY = 0,
	PQCP_FLEET_STEP_PENDING,
	PQCP_FLEET_STEP_READY,
	PQCP_FLEET_STEP_LEASED,
	PQCP_FLEET_STEP_APPLYING,
	PQCP_FLEET_STEP_AWAITING_ACK,
	PQCP_FLEET_STEP_RETRY_WAIT,
	PQCP_FLEET_STEP_SUCCEEDED,
	PQCP_FLEET_STEP_FAILED,
	PQCP_FLEET_STEP_BLOCKED,
	PQCP_FLEET_STEP_SUPERSEDED,
	PQCP_FLEET_STEP_ROLLBACK_PENDING,
	PQCP_FLEET_STEP_ROLLED_BACK,
	PQCP_FLEET_STEP_CANCELLED,
};

enum pqcp_fleet_dependency_kind {
	PQCP_FLEET_DEPENDENCY_HARD = 0,
	PQCP_FLEET_DEPENDENCY_SECURITY,
	PQCP_FLEET_DEPENDENCY_ROLLBACK_BARRIER,
	PQCP_FLEET_DEPENDENCY_WAVE_GATE,
};

enum pqcp_fleet_step_flag {
	PQCP_FLEET_STEP_SECURITY_CRITICAL = (1U << 0),
	PQCP_FLEET_STEP_IRREVERSIBLE = (1U << 1),
	PQCP_FLEET_STEP_REQUIRE_ACK = (1U << 2),
	PQCP_FLEET_STEP_ALLOW_RETRY = (1U << 3),
	PQCP_FLEET_STEP_ALLOW_ROLLBACK = (1U << 4),
	PQCP_FLEET_STEP_BATCHABLE = (1U << 5),
	PQCP_FLEET_STEP_DISRUPTIVE = (1U << 6),
	PQCP_FLEET_STEP_OFFLINE_SAFE = (1U << 7),
	PQCP_FLEET_STEP_BARRIER = (1U << 8),
};

enum pqcp_fleet_plan_flag {
	PQCP_FLEET_PLAN_SECURITY_FIRST = (1U << 0),
	PQCP_FLEET_PLAN_STOP_ON_FAILURE = (1U << 1),
	PQCP_FLEET_PLAN_AUTO_ROLLBACK = (1U << 2),
	PQCP_FLEET_PLAN_REQUIRE_LEASE = (1U << 3),
	PQCP_FLEET_PLAN_ALLOW_PARALLEL = (1U << 4),
	PQCP_FLEET_PLAN_BLOCK_ON_CONFLICT = (1U << 5),
};

enum pqcp_fleet_failure_disposition {
	PQCP_FLEET_FAILURE_TERMINAL = 0,
	PQCP_FLEET_FAILURE_RETRY,
	PQCP_FLEET_FAILURE_ROLLBACK,
	PQCP_FLEET_FAILURE_BLOCK,
	PQCP_FLEET_FAILURE_SUPERSEDE,
};

struct pqcp_fleet_retry_policy {
	uint32_t maximum_attempts;
	uint64_t initial_backoff_ms;
	uint64_t maximum_backoff_ms;
	uint32_t multiplier_numerator;
	uint32_t multiplier_denominator;
	uint32_t jitter_basis_points;
};

struct pqcp_fleet_convergence_policy {
	uint32_t schema_version;
	uint32_t plan_flags;
	uint32_t maximum_parallel_steps;
	uint32_t maximum_wave_size;
	uint64_t plan_lease_ms;
	uint64_t step_lease_ms;
	uint64_t acknowledgement_timeout_ms;
	uint64_t plan_deadline_ms;
	struct pqcp_fleet_retry_policy default_retry;
	struct pqcp_fleet_retry_policy security_retry;
};

struct pqcp_fleet_plan_dependency {
	uint32_t predecessor_step_id;
	uint32_t successor_step_id;
	enum pqcp_fleet_dependency_kind kind;
	bool satisfied;
};

struct pqcp_fleet_plan_step {
	uint32_t schema_version;
	uint32_t step_id;
	struct pqcp_fleet_resource_key key;
	enum pqcp_fleet_convergence_action action;
	enum pqcp_fleet_step_state state;
	enum pqcp_fleet_drift_class drift_class;
	uint32_t drift_reason_mask;
	uint32_t flags;
	uint32_t priority;
	uint32_t wave;
	uint32_t attempts;
	uint32_t maximum_attempts;
	uint64_t desired_generation;
	uint64_t desired_epoch;
	uint64_t plan_generation;
	uint64_t leased_at_ms;
	uint64_t lease_expires_at_ms;
	uint64_t started_at_ms;
	uint64_t acknowledgement_deadline_ms;
	uint64_t next_retry_ms;
	uint64_t completed_at_ms;
	uint64_t rollback_barrier_generation;
	int result;
	uint8_t desired_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t observed_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t acknowledgement_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_plan_wave {
	uint32_t wave;
	uint32_t total_steps;
	uint32_t ready_steps;
	uint32_t active_steps;
	uint32_t succeeded_steps;
	uint32_t failed_steps;
	uint32_t blocked_steps;
	bool released;
	bool complete;
};

struct pqcp_fleet_plan_lease {
	uint64_t lease_id;
	uint64_t plan_id;
	uint64_t plan_generation;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t renewal_count;
	char owner[PQCP_FLEET_PLAN_LEASE_OWNER_MAX_CHARS];
	uint8_t token[PQCP_FLEET_DIGEST_BYTES];
	bool active;
	bool revoked;
};

struct pqcp_fleet_convergence_plan {
	uint32_t schema_version;
	uint64_t plan_id;
	uint64_t generation;
	uint64_t desired_generation;
	uint64_t observed_generation;
	uint64_t created_at_ms;
	uint64_t deadline_ms;
	uint64_t superseded_by_generation;
	enum pqcp_fleet_plan_state state;
	uint32_t flags;
	struct pqcp_fleet_plan_step *steps;
	size_t step_capacity;
	size_t step_count;
	struct pqcp_fleet_plan_dependency *dependencies;
	size_t dependency_capacity;
	size_t dependency_count;
	struct pqcp_fleet_plan_wave *waves;
	size_t wave_capacity;
	size_t wave_count;
	uint32_t succeeded_steps;
	uint32_t failed_steps;
	uint32_t blocked_steps;
	uint32_t superseded_steps;
	uint32_t rollback_steps;
	int result;
	uint8_t desired_snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t observed_snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_convergence_storage {
	struct pqcp_fleet_drift *drift;
	size_t drift_capacity;
	struct pqcp_fleet_plan_step *steps;
	size_t step_capacity;
	struct pqcp_fleet_plan_dependency *dependencies;
	size_t dependency_capacity;
	struct pqcp_fleet_plan_wave *waves;
	size_t wave_capacity;
	struct pqcp_fleet_resource_state *desired_snapshot;
	size_t desired_snapshot_capacity;
	struct pqcp_fleet_resource_state *observed_snapshot;
	size_t observed_snapshot_capacity;
};

struct pqcp_fleet_step_claim {
	uint64_t plan_id;
	uint64_t plan_generation;
	uint64_t lease_id;
	uint32_t step_id;
	uint32_t wave;
	enum pqcp_fleet_convergence_action action;
	struct pqcp_fleet_resource_key key;
	uint64_t desired_generation;
	uint64_t desired_epoch;
	uint64_t lease_expires_at_ms;
	uint8_t desired_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_convergence_snapshot {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t captured_at_ms;
	uint64_t plan_id;
	uint64_t plan_generation;
	uint64_t desired_generation;
	uint64_t observed_generation;
	enum pqcp_fleet_plan_state plan_state;
	uint32_t total_steps;
	uint32_t pending_steps;
	uint32_t ready_steps;
	uint32_t active_steps;
	uint32_t retry_steps;
	uint32_t succeeded_steps;
	uint32_t failed_steps;
	uint32_t blocked_steps;
	uint32_t superseded_steps;
	uint32_t rollback_steps;
	uint32_t current_wave;
	uint64_t lease_id;
	uint64_t lease_expires_at_ms;
	uint8_t plan_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_convergence {
	uint32_t schema_version;
	struct pqcp_fleet_desired_state *model;
	struct pqcp_fleet_convergence_policy policy;
	struct pqcp_fleet_convergence_plan plan;
	struct pqcp_fleet_plan_lease lease;
	struct pqcp_fleet_drift *drift;
	size_t drift_capacity;
	size_t drift_count;
	struct pqcp_fleet_resource_state *desired_resources;
	size_t desired_resource_capacity;
	struct pqcp_fleet_resource_state *observed_resources;
	size_t observed_resource_capacity;
	uint64_t next_plan_id;
	uint64_t next_lease_id;
	uint64_t snapshot_sequence;
	uint64_t plan_count;
	uint64_t supersession_count;
	uint64_t transition_count;
	uint64_t retry_count;
	struct k_mutex lock;
	bool initialized;
};

int pqcp_fleet_convergence_policy_default(
	struct pqcp_fleet_convergence_policy *policy);

int pqcp_fleet_convergence_init(
	struct pqcp_fleet_convergence *convergence,
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_convergence_storage *storage,
	const struct pqcp_fleet_convergence_policy *policy);

int pqcp_fleet_convergence_build_plan(
	struct pqcp_fleet_convergence *convergence,
	uint64_t now_ms,
	struct pqcp_fleet_convergence_plan **plan);

int pqcp_fleet_convergence_plan_digest(
	const struct pqcp_fleet_convergence_plan *plan,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES]);

int pqcp_fleet_convergence_plan_verify(
	const struct pqcp_fleet_convergence_plan *plan);

int pqcp_fleet_convergence_acquire(
	struct pqcp_fleet_convergence *convergence,
	const char *owner,
	uint64_t now_ms,
	uint64_t requested_duration_ms,
	struct pqcp_fleet_plan_lease *lease);

int pqcp_fleet_convergence_renew(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t requested_duration_ms,
	struct pqcp_fleet_plan_lease *lease);

int pqcp_fleet_convergence_release(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms);

int pqcp_fleet_convergence_next(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_fleet_step_claim *claim);

int pqcp_fleet_convergence_begin_apply(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t step_id,
	uint64_t now_ms);

int pqcp_fleet_convergence_applied(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t step_id,
	const uint8_t result_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms);

int pqcp_fleet_convergence_acknowledge(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t step_id,
	uint64_t observed_generation,
	uint64_t observed_epoch,
	const uint8_t observed_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms);

int pqcp_fleet_convergence_fail(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t step_id,
	int result,
	enum pqcp_fleet_failure_disposition disposition,
	uint64_t now_ms);

int pqcp_fleet_convergence_request_rollback(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t failed_step_id,
	uint64_t now_ms);

int pqcp_fleet_convergence_supersede(
	struct pqcp_fleet_convergence *convergence,
	uint64_t desired_generation,
	uint64_t now_ms);

int pqcp_fleet_convergence_tick(
	struct pqcp_fleet_convergence *convergence,
	uint64_t now_ms);

int pqcp_fleet_convergence_wave(
	struct pqcp_fleet_convergence *convergence,
	uint32_t wave,
	struct pqcp_fleet_plan_wave *summary);

int pqcp_fleet_convergence_snapshot(
	struct pqcp_fleet_convergence *convergence,
	uint64_t now_ms,
	struct pqcp_fleet_convergence_snapshot *snapshot);

int pqcp_fleet_convergence_snapshot_verify(
	const struct pqcp_fleet_convergence_snapshot *snapshot);

int pqcp_fleet_convergence_reconcile_compat(
	const struct pqcp_fleet_state_snapshot *desired,
	const struct pqcp_fleet_state_snapshot *observed,
	struct pqcp_fleet_reconcile_result *result);

int pqcp_fleet_convergence_audit(
	struct pqcp_fleet_convergence *convergence);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_CONVERGENCE_H_ */
