/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free PQCP job scheduler and primitive executor.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_EXECUTOR_H_
#define PQCP_ZEPHYR_RUNTIME_EXECUTOR_H_

#include <zephyr/kernel.h>

#include <pqcp_zephyr/runtime.h>
#include <pqcp_zephyr/runtime_key_store.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS (1U << 0)
#define PQCP_RUNTIME_JOB_FLAG_ZERO_OUTPUT_ON_FAILURE (1U << 1)
#define PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION (1U << 2)
#define PQCP_RUNTIME_JOB_FLAG_ALLOW_EXPIRED_DEADLINE (1U << 3)

struct pqcp_runtime_workspace_slot {
	uint8_t *buffer;
	size_t capacity;
	size_t used;
	uint64_t owner_job_id;
	uint32_t generation;
	bool allocated;
};

struct pqcp_runtime_workspace_pool {
	uint32_t schema_version;
	struct pqcp_runtime_workspace_slot *slots;
	size_t slot_count;
	uint32_t allocated_count;
	uint32_t high_watermark;
	struct k_mutex lock;
};

struct pqcp_runtime_queue_entry {
	struct pqcp_runtime_job *job;
	uint64_t sequence;
	bool occupied;
};

struct pqcp_runtime_executor {
	uint32_t schema_version;
	struct pqcp_runtime_key_store *key_store;
	struct pqcp_runtime_workspace_pool *workspace_pool;
	struct pqcp_runtime_queue_entry *queue;
	size_t queue_capacity;
	size_t queue_count;
	uint64_t next_sequence;
	uint64_t submitted_count;
	uint64_t completed_count;
	uint64_t failed_count;
	uint64_t cancelled_count;
	uint64_t expired_count;
	struct k_mutex lock;
	struct k_sem pending;
	struct k_thread *worker_thread;
	k_thread_stack_t *worker_stack;
	size_t worker_stack_size;
	int worker_priority;
	bool worker_started;
	bool stop_requested;
	struct pqcp_adaptive_control_plane *adaptive_control;
	struct pqcp_adaptive_calibration_table *calibration;
	struct pqcp_runtime_profile_state *profile_states;
	size_t profile_state_capacity;
};

int pqcp_runtime_workspace_pool_init(
	struct pqcp_runtime_workspace_pool *pool,
	struct pqcp_runtime_workspace_slot *slots,
	uint8_t *storage,
	size_t slot_count,
	size_t bytes_per_slot);
int pqcp_runtime_workspace_acquire(
	struct pqcp_runtime_workspace_pool *pool,
	uint64_t job_id,
	size_t required_bytes,
	uint8_t **workspace,
	size_t *workspace_capacity,
	uint32_t *generation);
int pqcp_runtime_workspace_release(
	struct pqcp_runtime_workspace_pool *pool,
	uint64_t job_id,
	uint32_t generation);
int pqcp_runtime_workspace_audit(
	struct pqcp_runtime_workspace_pool *pool);

int pqcp_runtime_executor_init(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_key_store *key_store,
	struct pqcp_runtime_workspace_pool *workspace_pool,
	struct pqcp_runtime_queue_entry *queue,
	size_t queue_capacity);
int pqcp_runtime_executor_bind_adaptive(
	struct pqcp_runtime_executor *executor,
	struct pqcp_adaptive_control_plane *control,
	struct pqcp_adaptive_calibration_table *calibration,
	struct pqcp_runtime_profile_state *profile_states,
	size_t profile_state_capacity);
int pqcp_runtime_executor_start(
	struct pqcp_runtime_executor *executor,
	struct k_thread *thread,
	k_thread_stack_t *stack,
	size_t stack_size,
	int priority);
int pqcp_runtime_executor_stop(
	struct pqcp_runtime_executor *executor,
	k_timeout_t timeout);
int pqcp_runtime_executor_submit(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job);
int pqcp_runtime_executor_execute(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job);
int pqcp_runtime_executor_cancel(
	struct pqcp_runtime_executor *executor,
	uint64_t job_id);
int pqcp_runtime_executor_drain(
	const struct pqcp_runtime_executor *executor,
	k_timeout_t timeout);
int pqcp_runtime_executor_audit(
	struct pqcp_runtime_executor *executor);

int pqcp_runtime_execute_mlkem_keygen(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity);
int pqcp_runtime_execute_mlkem_encapsulate(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity);
int pqcp_runtime_execute_mlkem_decapsulate(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity);
int pqcp_runtime_execute_mldsa_keygen(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity);
int pqcp_runtime_execute_mldsa_sign(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity);
int pqcp_runtime_execute_mldsa_verify(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity);
int pqcp_runtime_execute_hkdf_derive(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity);
int pqcp_runtime_execute_aead_encrypt(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity);
int pqcp_runtime_execute_aead_decrypt(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_EXECUTOR_H_ */
