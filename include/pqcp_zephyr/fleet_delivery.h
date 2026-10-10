/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free bounded fleet artifact delivery scheduler.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_DELIVERY_H_
#define PQCP_ZEPHYR_FLEET_DELIVERY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_DELIVERY_SCHEMA_VERSION 1U
#define PQCP_FLEET_DELIVERY_PRIORITY_MAX 255U
#define PQCP_FLEET_DELIVERY_DEFAULT_AGING_MS 30000U
#define PQCP_FLEET_DELIVERY_DEFAULT_LEASE_MS 30000U
#define PQCP_FLEET_DELIVERY_DEFAULT_MAX_LEASE_MS 300000U
#define PQCP_FLEET_DELIVERY_DEFAULT_BACKOFF_MS 1000U
#define PQCP_FLEET_DELIVERY_DEFAULT_MAX_BACKOFF_MS 300000U
#define PQCP_FLEET_DELIVERY_MAX_JITTER_BASIS_POINTS 10000U
#define PQCP_FLEET_DELIVERY_NO_DEPENDENCY 0U

enum pqcp_fleet_delivery_state {
	PQCP_FLEET_DELIVERY_EMPTY = 0,
	PQCP_FLEET_DELIVERY_WAITING_DEPENDENCY,
	PQCP_FLEET_DELIVERY_READY,
	PQCP_FLEET_DELIVERY_LEASED,
	PQCP_FLEET_DELIVERY_RETRY_WAIT,
	PQCP_FLEET_DELIVERY_DELIVERED,
	PQCP_FLEET_DELIVERY_FAILED,
	PQCP_FLEET_DELIVERY_CANCELLED,
	PQCP_FLEET_DELIVERY_EXPIRED,
	PQCP_FLEET_DELIVERY_DEPENDENCY_FAILED,
	PQCP_FLEET_DELIVERY_CONFLICT,
	PQCP_FLEET_DELIVERY_STATE_COUNT,
};

enum pqcp_fleet_delivery_terminal_reason {
	PQCP_FLEET_DELIVERY_REASON_NONE = 0,
	PQCP_FLEET_DELIVERY_REASON_COMPLETED,
	PQCP_FLEET_DELIVERY_REASON_CANCELLED_BY_CALLER,
	PQCP_FLEET_DELIVERY_REASON_EXPIRED,
	PQCP_FLEET_DELIVERY_REASON_ATTEMPTS_EXHAUSTED,
	PQCP_FLEET_DELIVERY_REASON_PERMANENT_FAILURE,
	PQCP_FLEET_DELIVERY_REASON_DEPENDENCY_TERMINAL,
	PQCP_FLEET_DELIVERY_REASON_EPOCH_STALE,
	PQCP_FLEET_DELIVERY_REASON_DIGEST_CONFLICT,
	PQCP_FLEET_DELIVERY_REASON_INVARIANT_FAILURE,
	PQCP_FLEET_DELIVERY_REASON_REMOVED,
	PQCP_FLEET_DELIVERY_REASON_COUNT,
};

enum pqcp_fleet_delivery_flag {
	PQCP_FLEET_DELIVERY_FLAG_IDEMPOTENT = (1U << 0),
	PQCP_FLEET_DELIVERY_FLAG_REQUIRE_POLICY_EPOCH = (1U << 1),
	PQCP_FLEET_DELIVERY_FLAG_REQUIRE_REVOCATION_EPOCH = (1U << 2),
	PQCP_FLEET_DELIVERY_FLAG_CANCEL_DEPENDENTS = (1U << 3),
	PQCP_FLEET_DELIVERY_FLAG_RETAIN_PROGRESS_ON_RETRY = (1U << 4),
	PQCP_FLEET_DELIVERY_FLAG_REQUIRE_FINAL_DIGEST = (1U << 5),
	PQCP_FLEET_DELIVERY_FLAG_ALLOW_ZERO_LENGTH = (1U << 6),
	PQCP_FLEET_DELIVERY_FLAG_HIGH_INTEGRITY = (1U << 7),
};

enum pqcp_fleet_delivery_audit_flag {
	PQCP_FLEET_DELIVERY_AUDIT_NONE = 0U,
	PQCP_FLEET_DELIVERY_AUDIT_MANAGER = (1U << 0),
	PQCP_FLEET_DELIVERY_AUDIT_STORAGE = (1U << 1),
	PQCP_FLEET_DELIVERY_AUDIT_SCHEMA = (1U << 2),
	PQCP_FLEET_DELIVERY_AUDIT_STATE = (1U << 3),
	PQCP_FLEET_DELIVERY_AUDIT_IDENTITY = (1U << 4),
	PQCP_FLEET_DELIVERY_AUDIT_DIGEST = (1U << 5),
	PQCP_FLEET_DELIVERY_AUDIT_TIME = (1U << 6),
	PQCP_FLEET_DELIVERY_AUDIT_CHUNK = (1U << 7),
	PQCP_FLEET_DELIVERY_AUDIT_LEASE = (1U << 8),
	PQCP_FLEET_DELIVERY_AUDIT_RETRY = (1U << 9),
	PQCP_FLEET_DELIVERY_AUDIT_DEPENDENCY = (1U << 10),
	PQCP_FLEET_DELIVERY_AUDIT_DUPLICATE = (1U << 11),
	PQCP_FLEET_DELIVERY_AUDIT_COUNTER = (1U << 12),
	PQCP_FLEET_DELIVERY_AUDIT_RECORD_HASH = (1U << 13),
	PQCP_FLEET_DELIVERY_AUDIT_TERMINAL = (1U << 14),
	PQCP_FLEET_DELIVERY_AUDIT_OVERFLOW = (1U << 15),
};

struct pqcp_fleet_delivery_config {
	uint64_t default_lease_ms;
	uint64_t maximum_lease_ms;
	uint64_t priority_aging_ms;
	uint64_t default_backoff_ms;
	uint64_t maximum_backoff_ms;
	uint32_t default_maximum_attempts;
	uint32_t default_jitter_basis_points;
	bool expire_stale_epochs;
};

struct pqcp_fleet_delivery_request {
	uint64_t artifact_id;
	uint64_t message_id;
	uint64_t correlation_id;
	uint64_t dependency_artifact_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t created_at_ms;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint64_t artifact_size;
	uint64_t lease_duration_ms;
	uint64_t base_backoff_ms;
	uint64_t maximum_backoff_ms;
	uint32_t chunk_size;
	uint32_t maximum_attempts;
	uint32_t jitter_basis_points;
	uint16_t priority;
	uint32_t flags;
	uint8_t idempotency_key[PQCP_FLEET_DIGEST_BYTES];
	uint8_t artifact_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_delivery_handle {
	uint64_t artifact_id;
	uint32_t generation;
};

struct pqcp_fleet_delivery_lease {
	struct pqcp_fleet_delivery_handle handle;
	uint64_t worker_id;
	uint64_t token;
	uint64_t acquired_at_ms;
	uint64_t expires_at_ms;
	uint32_t attempt;
	uint32_t next_chunk;
};

struct pqcp_fleet_delivery_chunk {
	struct pqcp_fleet_delivery_handle handle;
	uint64_t lease_token;
	uint64_t offset;
	uint64_t length;
	uint32_t index;
	uint32_t count;
	bool final_chunk;
};

struct pqcp_fleet_delivery_record {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t enqueue_sequence;
	uint64_t artifact_id;
	uint64_t message_id;
	uint64_t correlation_id;
	uint64_t dependency_artifact_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t created_at_ms;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint64_t lease_duration_ms;
	uint64_t base_backoff_ms;
	uint64_t maximum_backoff_ms;
	uint64_t next_attempt_ms;
	uint64_t lease_acquired_at_ms;
	uint64_t lease_expires_at_ms;
	uint64_t last_progress_at_ms;
	uint64_t terminal_at_ms;
	uint64_t artifact_size;
	uint64_t committed_bytes;
	uint64_t worker_id;
	uint64_t lease_token;
	uint32_t chunk_size;
	uint32_t chunk_count;
	uint32_t next_chunk;
	uint32_t attempts;
	uint32_t maximum_attempts;
	uint32_t jitter_basis_points;
	uint16_t priority;
	uint32_t flags;
	enum pqcp_fleet_delivery_state state;
	enum pqcp_fleet_delivery_terminal_reason terminal_reason;
	int32_t last_error;
	uint8_t idempotency_key[PQCP_FLEET_DIGEST_BYTES];
	uint8_t artifact_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t progress_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t record_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_delivery_snapshot {
	uint32_t schema_version;
	uint64_t generation;
	uint64_t latest_policy_epoch;
	uint64_t latest_revocation_epoch;
	uint64_t enqueued_count;
	uint64_t replayed_count;
	uint64_t conflict_count;
	uint64_t lease_count;
	uint64_t retry_count;
	uint64_t delivered_count;
	uint64_t failed_count;
	uint64_t cancelled_count;
	uint64_t expired_count;
	uint64_t removed_count;
	uint64_t committed_bytes;
	uint64_t pending_bytes;
	uint64_t earliest_expiry_ms;
	uint64_t next_wakeup_ms;
	size_t capacity;
	size_t occupied_count;
	size_t waiting_count;
	size_t ready_count;
	size_t leased_count;
	size_t retry_wait_count;
	size_t terminal_count;
	uint8_t aggregate_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_delivery_audit {
	uint32_t schema_version;
	uint32_t violation_mask;
	size_t inspected_records;
	size_t occupied_records;
	size_t terminal_records;
	size_t first_bad_index;
	uint64_t first_bad_artifact_id;
	uint64_t duplicate_artifact_id;
	uint64_t duplicate_message_id;
	uint64_t dependency_cycle_artifact_id;
	uint64_t recomputed_committed_bytes;
	uint64_t recomputed_delivered_count;
	uint64_t recomputed_failed_count;
	uint64_t recomputed_cancelled_count;
	uint64_t recomputed_expired_count;
	uint8_t aggregate_digest[PQCP_FLEET_DIGEST_BYTES];
	bool consistent;
};

struct pqcp_fleet_delivery_scheduler {
	uint32_t schema_version;
	struct pqcp_fleet_delivery_record *records;
	size_t capacity;
	size_t occupied_count;
	uint32_t next_generation;
	uint64_t next_enqueue_sequence;
	uint64_t next_lease_nonce;
	uint64_t generation;
	uint64_t latest_policy_epoch;
	uint64_t latest_revocation_epoch;
	uint64_t default_lease_ms;
	uint64_t maximum_lease_ms;
	uint64_t priority_aging_ms;
	uint64_t default_backoff_ms;
	uint64_t maximum_backoff_ms;
	uint32_t default_maximum_attempts;
	uint32_t default_jitter_basis_points;
	uint64_t enqueued_count;
	uint64_t replayed_count;
	uint64_t conflict_count;
	uint64_t lease_count;
	uint64_t retry_count;
	uint64_t delivered_count;
	uint64_t failed_count;
	uint64_t cancelled_count;
	uint64_t expired_count;
	uint64_t dependency_failed_count;
	uint64_t stale_epoch_count;
	uint64_t lease_timeout_count;
	uint64_t removed_count;
	uint64_t committed_bytes;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool expire_stale_epochs;
	bool initialized;
};

int pqcp_fleet_delivery_init(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_record *records,
	size_t capacity,
	const struct pqcp_fleet_delivery_config *config);
int pqcp_fleet_delivery_enqueue(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_request *request,
	struct pqcp_fleet_delivery_handle *handle,
	bool *replayed);
int pqcp_fleet_delivery_acquire(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t worker_id,
	uint64_t now_ms,
	struct pqcp_fleet_delivery_lease *lease);
int pqcp_fleet_delivery_next_chunk(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	uint64_t now_ms,
	struct pqcp_fleet_delivery_chunk *chunk);
int pqcp_fleet_delivery_commit_chunk(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	const struct pqcp_fleet_delivery_chunk *chunk,
	const uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_fleet_delivery_renew(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	uint64_t extension_ms,
	uint64_t now_ms,
	struct pqcp_fleet_delivery_lease *renewed);
int pqcp_fleet_delivery_complete(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	const uint8_t artifact_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_fleet_delivery_fail(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	int error,
	bool retryable,
	uint64_t now_ms);
int pqcp_fleet_delivery_release(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	uint64_t now_ms);
int pqcp_fleet_delivery_cancel(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle,
	int reason,
	uint64_t now_ms);
int pqcp_fleet_delivery_reprioritize(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle,
	uint16_t priority);
int pqcp_fleet_delivery_reschedule(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle,
	uint64_t not_before_ms,
	uint64_t expires_at_ms);
int pqcp_fleet_delivery_advance_epochs(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_fleet_delivery_tick(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_fleet_delivery_get(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle,
	struct pqcp_fleet_delivery_record *record);
int pqcp_fleet_delivery_find(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t artifact_id,
	struct pqcp_fleet_delivery_record *record);
int pqcp_fleet_delivery_remove(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle);
int pqcp_fleet_delivery_snapshot(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t now_ms,
	struct pqcp_fleet_delivery_snapshot *snapshot);
int pqcp_fleet_delivery_audit(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_audit *audit);
int pqcp_fleet_delivery_record_verify(
	const struct pqcp_fleet_delivery_record *record);
bool pqcp_fleet_delivery_state_terminal(
	enum pqcp_fleet_delivery_state state);
const char *pqcp_fleet_delivery_state_str(
	enum pqcp_fleet_delivery_state state);
const char *pqcp_fleet_delivery_reason_str(
	enum pqcp_fleet_delivery_terminal_reason reason);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_DELIVERY_H_ */
