/*
 * SPDX-License-Identifier: MIT
 *
 * Atomic multi-operation transactions for the executable PQCP runtime.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_TRANSACTION_H_
#define PQCP_ZEPHYR_RUNTIME_TRANSACTION_H_

#include <pqcp_zephyr/runtime_control.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_TRANSACTION_MAX_STEPS 16U
#define PQCP_RUNTIME_TRANSACTION_MAX_KEYS 16U

enum pqcp_runtime_transaction_state {
	PQCP_RUNTIME_TRANSACTION_EMPTY = 0,
	PQCP_RUNTIME_TRANSACTION_OPEN,
	PQCP_RUNTIME_TRANSACTION_RUNNING,
	PQCP_RUNTIME_TRANSACTION_COMMITTED,
	PQCP_RUNTIME_TRANSACTION_ROLLING_BACK,
	PQCP_RUNTIME_TRANSACTION_ROLLED_BACK,
	PQCP_RUNTIME_TRANSACTION_FAILED,
};

enum pqcp_runtime_transaction_step_state {
	PQCP_RUNTIME_TRANSACTION_STEP_EMPTY = 0,
	PQCP_RUNTIME_TRANSACTION_STEP_STAGED,
	PQCP_RUNTIME_TRANSACTION_STEP_RUNNING,
	PQCP_RUNTIME_TRANSACTION_STEP_COMPLETED,
	PQCP_RUNTIME_TRANSACTION_STEP_SKIPPED,
	PQCP_RUNTIME_TRANSACTION_STEP_ROLLED_BACK,
	PQCP_RUNTIME_TRANSACTION_STEP_FAILED,
};

struct pqcp_runtime_transaction_step {
	uint32_t schema_version;
	uint32_t step_id;
	uint32_t dependency_mask;
	enum pqcp_runtime_transaction_step_state state;
	struct pqcp_runtime_job *job;
	struct pqcp_runtime_key_handle produced_primary;
	struct pqcp_runtime_key_handle produced_secondary;
	int result;
	bool rollback_primary;
	bool rollback_secondary;
};

struct pqcp_runtime_transaction_policy {
	uint32_t schema_version;
	uint32_t maximum_steps;
	uint64_t maximum_duration_ms;
	bool stop_on_failure;
	bool rollback_generated_keys;
	bool require_synchronous_jobs;
	bool reject_external_dependencies;
};

struct pqcp_runtime_transaction_result {
	uint32_t schema_version;
	uint64_t transaction_id;
	enum pqcp_runtime_transaction_state state;
	uint32_t staged_steps;
	uint32_t completed_steps;
	uint32_t failed_steps;
	uint32_t skipped_steps;
	uint32_t rolled_back_steps;
	uint32_t destroyed_keys;
	uint32_t rollback_failures;
	uint32_t failure_step_id;
	int result;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
};

struct pqcp_runtime_transaction {
	uint32_t schema_version;
	uint64_t transaction_id;
	uint64_t session_id;
	enum pqcp_runtime_transaction_state state;
	struct pqcp_runtime_controller *controller;
	struct pqcp_runtime_transaction_policy policy;
	struct pqcp_runtime_transaction_step
		steps[PQCP_RUNTIME_TRANSACTION_MAX_STEPS];
	size_t step_count;
	struct pqcp_runtime_key_handle
		rollback_keys[PQCP_RUNTIME_TRANSACTION_MAX_KEYS];
	size_t rollback_key_count;
	uint64_t opened_at_ms;
	uint64_t deadline_ms;
	uint32_t mutation_sequence;
	int terminal_result;
	struct k_mutex lock;
};

int pqcp_runtime_transaction_policy_default(
	struct pqcp_runtime_transaction_policy *policy);
int pqcp_runtime_transaction_init(
	struct pqcp_runtime_transaction *transaction,
	uint64_t transaction_id,
	uint64_t session_id,
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_transaction_policy *policy,
	uint64_t now_ms);
int pqcp_runtime_transaction_stage(
	struct pqcp_runtime_transaction *transaction,
	uint32_t step_id,
	uint32_t dependency_mask,
	struct pqcp_runtime_job *job,
	bool rollback_primary,
	bool rollback_secondary);
int pqcp_runtime_transaction_execute(
	struct pqcp_runtime_transaction *transaction,
	uint64_t now_ms,
	struct pqcp_runtime_transaction_result *result);
int pqcp_runtime_transaction_rollback(
	struct pqcp_runtime_transaction *transaction,
	uint64_t now_ms,
	struct pqcp_runtime_transaction_result *result);
int pqcp_runtime_transaction_cancel(
	struct pqcp_runtime_transaction *transaction,
	uint64_t now_ms,
	struct pqcp_runtime_transaction_result *result);
int pqcp_runtime_transaction_audit(
	const struct pqcp_runtime_transaction *transaction);
int pqcp_runtime_transaction_result_verify(
	const struct pqcp_runtime_transaction_result *result);
int pqcp_runtime_transaction_emit(
	const struct pqcp_runtime_transaction_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_TRANSACTION_H_ */
