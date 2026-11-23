/*
 * SPDX-License-Identifier: MIT
 *
 * Single-entry executable runtime service bootstrap.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_SERVICE_H_
#define PQCP_ZEPHYR_RUNTIME_SERVICE_H_

#include <pqcp_zephyr/runtime_governance.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pqcp_runtime_service_storage {
	struct pqcp_runtime_volatile_slot *key_slots;
	size_t key_slot_count;
	struct pqcp_runtime_workspace_slot *workspace_slots;
	uint8_t *workspace_bytes;
	size_t workspace_slot_count;
	size_t workspace_bytes_per_slot;
	struct pqcp_runtime_queue_entry *queue;
	size_t queue_capacity;
	struct pqcp_runtime_session *sessions;
	size_t session_capacity;
	struct pqcp_runtime_profile_state *profile_states;
	size_t profile_state_capacity;
	struct pqcp_runtime_audit_entry *audit_entries;
	size_t audit_capacity;
	struct pqcp_runtime_identity *identities;
	size_t identity_capacity;
	struct pqcp_runtime_admission_quota *quotas;
	size_t quota_capacity;
};

struct pqcp_runtime_service {
	uint32_t schema_version;
	struct pqcp_runtime_key_store key_store;
	struct pqcp_runtime_volatile_context volatile_context;
	struct pqcp_runtime_workspace_pool workspace_pool;
	struct pqcp_runtime_executor executor;
	struct pqcp_runtime_session_manager sessions;
	struct pqcp_runtime_audit_log audit;
	struct pqcp_runtime_identity_store identities;
	struct pqcp_runtime_admission admission;
	struct pqcp_runtime_controller controller;
	struct pqcp_adaptive_calibration_table calibration;
	struct k_thread worker_thread;
	k_thread_stack_t *worker_stack;
	size_t worker_stack_size;
	bool initialized;
	bool started;
};

int pqcp_runtime_service_init(
	struct pqcp_runtime_service *service,
	const struct pqcp_runtime_service_storage *storage,
	struct pqcp_adaptive_control_plane *adaptive_control,
	uint64_t now_ms);
int pqcp_runtime_service_start(
	struct pqcp_runtime_service *service,
	k_thread_stack_t *worker_stack,
	size_t worker_stack_size,
	int priority);
int pqcp_runtime_service_stop(
	struct pqcp_runtime_service *service,
	k_timeout_t timeout);
int pqcp_runtime_service_tick(
	struct pqcp_runtime_service *service,
	uint64_t now_ms);
int pqcp_runtime_service_selftest(
	struct pqcp_runtime_service *service,
	uint32_t mlkem_level,
	uint32_t mldsa_level,
	uint64_t now_ms);
int pqcp_runtime_service_audit(
	struct pqcp_runtime_service *service);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_SERVICE_H_ */
