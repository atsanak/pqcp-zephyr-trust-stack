/*
 * SPDX-License-Identifier: MIT
 *
 * Atomic multi-operation transaction execution and key rollback.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/runtime_transaction.h>

#include "runtime_internal.h"

#define TRANSACTION_DOMAIN UINT64_C(0x5051435054524e31)

static bool transaction_state_terminal(
	enum pqcp_runtime_transaction_state state)
{
	return state == PQCP_RUNTIME_TRANSACTION_COMMITTED ||
	       state == PQCP_RUNTIME_TRANSACTION_ROLLED_BACK ||
	       state == PQCP_RUNTIME_TRANSACTION_FAILED;
}

static bool step_state_valid(
	enum pqcp_runtime_transaction_step_state state)
{
	return state >= PQCP_RUNTIME_TRANSACTION_STEP_EMPTY &&
	       state <= PQCP_RUNTIME_TRANSACTION_STEP_FAILED;
}

static bool transaction_policy_valid(
	const struct pqcp_runtime_transaction_policy *policy)
{
	return policy != NULL &&
	       policy->schema_version == PQCP_RUNTIME_SCHEMA_VERSION &&
	       policy->maximum_steps != 0U &&
	       policy->maximum_steps <= PQCP_RUNTIME_TRANSACTION_MAX_STEPS &&
	       policy->maximum_duration_ms != 0U;
}

int pqcp_runtime_transaction_policy_default(
	struct pqcp_runtime_transaction_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	*policy = (struct pqcp_runtime_transaction_policy) {
		.schema_version = PQCP_RUNTIME_SCHEMA_VERSION,
		.maximum_steps = PQCP_RUNTIME_TRANSACTION_MAX_STEPS,
		.maximum_duration_ms = 30000U,
		.stop_on_failure = true,
		.rollback_generated_keys = true,
		.require_synchronous_jobs = true,
		.reject_external_dependencies = true,
	};
	return 0;
}

int pqcp_runtime_transaction_init(
	struct pqcp_runtime_transaction *transaction,
	uint64_t transaction_id,
	uint64_t session_id,
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_transaction_policy *policy,
	uint64_t now_ms)
{
	struct pqcp_runtime_transaction_policy effective;

	if (transaction == NULL || controller == NULL ||
	    !controller->initialized || transaction_id == 0U ||
	    session_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	if (policy == NULL) {
		if (pqcp_runtime_transaction_policy_default(
			    &effective) != 0) {
			return -EINVAL;
		}
		policy = &effective;
	}
	if (!transaction_policy_valid(policy) ||
	    pqcp_runtime_session_find(
		    controller->sessions, session_id) == NULL) {
		return -EINVAL;
	}
	memset(transaction, 0, sizeof(*transaction));
	transaction->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	transaction->transaction_id = transaction_id;
	transaction->session_id = session_id;
	transaction->controller = controller;
	transaction->policy = *policy;
	transaction->state = PQCP_RUNTIME_TRANSACTION_OPEN;
	transaction->opened_at_ms = now_ms;
	transaction->deadline_ms =
		now_ms + policy->maximum_duration_ms;
	k_mutex_init(&transaction->lock);
	return 0;
}

static int step_index_by_id(
	const struct pqcp_runtime_transaction *transaction,
	uint32_t step_id)
{
	for (size_t index = 0U;
	     index < transaction->step_count; ++index) {
		if (transaction->steps[index].step_id == step_id) {
			return (int)index;
		}
	}
	return -1;
}

static bool dependency_mask_valid(
	const struct pqcp_runtime_transaction *transaction,
	uint32_t dependency_mask)
{
	uint32_t valid_mask;

	if (transaction->step_count == 0U) {
		return dependency_mask == 0U;
	}
	valid_mask = transaction->step_count >= 32U ?
		UINT32_MAX :
		((UINT32_C(1) << transaction->step_count) - 1U);
	return (dependency_mask & ~valid_mask) == 0U;
}

static bool dependency_cycle_from(
	const struct pqcp_runtime_transaction *transaction,
	size_t start,
	size_t current,
	uint32_t visited)
{
	const uint32_t current_bit = UINT32_C(1) << current;
	uint32_t dependencies;

	if ((visited & current_bit) != 0U) {
		return current == start;
	}
	visited |= current_bit;
	dependencies =
		transaction->steps[current].dependency_mask;
	for (size_t index = 0U;
	     index < transaction->step_count; ++index) {
		if ((dependencies & (UINT32_C(1) << index)) == 0U) {
			continue;
		}
		if (dependency_cycle_from(
			    transaction, start, index, visited)) {
			return true;
		}
	}
	return false;
}

static bool dependency_graph_acyclic(
	const struct pqcp_runtime_transaction *transaction)
{
	for (size_t index = 0U;
	     index < transaction->step_count; ++index) {
		if (dependency_cycle_from(
			    transaction, index, index, 0U)) {
			return false;
		}
	}
	return true;
}

int pqcp_runtime_transaction_stage(
	struct pqcp_runtime_transaction *transaction,
	uint32_t step_id,
	uint32_t dependency_mask,
	struct pqcp_runtime_job *job,
	bool rollback_primary,
	bool rollback_secondary)
{
	struct pqcp_runtime_transaction_step *step;
	int ret;

	if (transaction == NULL || job == NULL ||
	    step_id == 0U ||
	    transaction->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&transaction->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (transaction->state != PQCP_RUNTIME_TRANSACTION_OPEN ||
	    transaction->step_count >=
		    transaction->policy.maximum_steps ||
	    step_index_by_id(transaction, step_id) >= 0 ||
	    !dependency_mask_valid(transaction, dependency_mask) ||
	    (transaction->policy.require_synchronous_jobs &&
	     (job->flags &
	      PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS) == 0U)) {
		(void)k_mutex_unlock(&transaction->lock);
		return -EINVAL;
	}
	step = &transaction->steps[transaction->step_count];
	memset(step, 0, sizeof(*step));
	step->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	step->step_id = step_id;
	step->dependency_mask = dependency_mask;
	step->state = PQCP_RUNTIME_TRANSACTION_STEP_STAGED;
	step->job = job;
	step->rollback_primary = rollback_primary;
	step->rollback_secondary = rollback_secondary;
	transaction->step_count++;
	transaction->mutation_sequence++;
	if (!dependency_graph_acyclic(transaction)) {
		transaction->step_count--;
		memset(step, 0, sizeof(*step));
		(void)k_mutex_unlock(&transaction->lock);
		return -ELOOP;
	}
	(void)k_mutex_unlock(&transaction->lock);
	return 0;
}

static bool dependencies_completed(
	const struct pqcp_runtime_transaction *transaction,
	const struct pqcp_runtime_transaction_step *step)
{
	for (size_t index = 0U;
	     index < transaction->step_count; ++index) {
		if ((step->dependency_mask &
		     (UINT32_C(1) << index)) == 0U) {
			continue;
		}
		if (transaction->steps[index].state !=
		    PQCP_RUNTIME_TRANSACTION_STEP_COMPLETED) {
			return false;
		}
	}
	return true;
}

static int remember_rollback_key(
	struct pqcp_runtime_transaction *transaction,
	const struct pqcp_runtime_key_handle *handle)
{
	if (!pqcp_runtime_key_handle_is_valid(handle)) {
		return 0;
	}
	for (size_t index = 0U;
	     index < transaction->rollback_key_count; ++index) {
		if (pqcp_runtime_key_handle_equal(
			    &transaction->rollback_keys[index],
			    handle)) {
			return 0;
		}
	}
	if (transaction->rollback_key_count >=
	    PQCP_RUNTIME_TRANSACTION_MAX_KEYS) {
		return -ENOSPC;
	}
	transaction->rollback_keys[
		transaction->rollback_key_count++] = *handle;
	return 0;
}

static int capture_step_outputs(
	struct pqcp_runtime_transaction *transaction,
	struct pqcp_runtime_transaction_step *step)
{
	int ret = 0;

	step->produced_primary = step->job->primary_key;
	step->produced_secondary = step->job->secondary_key;
	if (!transaction->policy.rollback_generated_keys) {
		return 0;
	}
	if (step->rollback_primary) {
		ret = remember_rollback_key(
			transaction, &step->produced_primary);
	}
	if (ret == 0 && step->rollback_secondary) {
		ret = remember_rollback_key(
			transaction, &step->produced_secondary);
	}
	return ret;
}

static int execute_step(
	struct pqcp_runtime_transaction *transaction,
	struct pqcp_runtime_transaction_step *step)
{
	int ret;

	step->state = PQCP_RUNTIME_TRANSACTION_STEP_RUNNING;
	ret = pqcp_runtime_controller_submit(
		transaction->controller,
		transaction->session_id, step->job);
	step->result = ret;
	if (ret != 0) {
		step->state = PQCP_RUNTIME_TRANSACTION_STEP_FAILED;
		return ret;
	}
	ret = capture_step_outputs(transaction, step);
	if (ret != 0) {
		step->result = ret;
		step->state = PQCP_RUNTIME_TRANSACTION_STEP_FAILED;
		return ret;
	}
	step->state = PQCP_RUNTIME_TRANSACTION_STEP_COMPLETED;
	return 0;
}

static void count_result(
	const struct pqcp_runtime_transaction *transaction,
	struct pqcp_runtime_transaction_result *result)
{
	for (size_t index = 0U;
	     index < transaction->step_count; ++index) {
		switch (transaction->steps[index].state) {
		case PQCP_RUNTIME_TRANSACTION_STEP_COMPLETED:
			result->completed_steps++;
			break;
		case PQCP_RUNTIME_TRANSACTION_STEP_FAILED:
			result->failed_steps++;
			if (result->failure_step_id == 0U) {
				result->failure_step_id =
					transaction->steps[index].step_id;
			}
			break;
		case PQCP_RUNTIME_TRANSACTION_STEP_SKIPPED:
			result->skipped_steps++;
			break;
		case PQCP_RUNTIME_TRANSACTION_STEP_ROLLED_BACK:
			result->rolled_back_steps++;
			break;
		default:
			break;
		}
	}
}

static int transaction_digest(
	const struct pqcp_runtime_transaction *transaction,
	struct pqcp_runtime_transaction_result *result)
{
	uint8_t buffer[32U +
		       PQCP_RUNTIME_TRANSACTION_MAX_STEPS * 24U];
	size_t offset = 0U;

	memset(buffer, 0, sizeof(buffer));
	pqcp_runtime_internal_write_u64(
		buffer + offset, TRANSACTION_DOMAIN);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, transaction->transaction_id);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, transaction->session_id);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, (uint32_t)transaction->state);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, (uint32_t)transaction->step_count);
	offset += 4U;
	for (size_t index = 0U;
	     index < transaction->step_count; ++index) {
		const struct pqcp_runtime_transaction_step *step =
			&transaction->steps[index];

		pqcp_runtime_internal_write_u32(
			buffer + offset, step->step_id);
		offset += 4U;
		pqcp_runtime_internal_write_u32(
			buffer + offset, step->dependency_mask);
		offset += 4U;
		pqcp_runtime_internal_write_u32(
			buffer + offset, (uint32_t)step->state);
		offset += 4U;
		pqcp_runtime_internal_write_u32(
			buffer + offset, (uint32_t)step->result);
		offset += 4U;
		pqcp_runtime_internal_write_u64(
			buffer + offset, step->job != NULL ?
				step->job->job_id : 0U);
		offset += 8U;
	}
	return pqcp_runtime_internal_sha256(
		buffer, offset, result->digest);
}

static int fill_result(
	const struct pqcp_runtime_transaction *transaction,
	uint64_t completed_at_ms,
	uint32_t destroyed_keys,
	uint32_t rollback_failures,
	struct pqcp_runtime_transaction_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	result->transaction_id = transaction->transaction_id;
	result->state = transaction->state;
	result->staged_steps = (uint32_t)transaction->step_count;
	result->destroyed_keys = destroyed_keys;
	result->rollback_failures = rollback_failures;
	result->result = transaction->terminal_result;
	result->started_at_ms = transaction->opened_at_ms;
	result->completed_at_ms = completed_at_ms;
	count_result(transaction, result);
	return transaction_digest(transaction, result);
}

int pqcp_runtime_transaction_rollback(
	struct pqcp_runtime_transaction *transaction,
	uint64_t now_ms,
	struct pqcp_runtime_transaction_result *result)
{
	uint32_t destroyed = 0U;
	uint32_t failures = 0U;
	int terminal = 0;

	if (transaction == NULL || result == NULL ||
	    now_ms == 0U ||
	    transaction->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
		return -EINVAL;
	}
	transaction->state =
		PQCP_RUNTIME_TRANSACTION_ROLLING_BACK;
	for (size_t reverse = transaction->rollback_key_count;
	     reverse > 0U; --reverse) {
		const size_t index = reverse - 1U;
		int ret = pqcp_runtime_key_store_destroy(
			transaction->controller->key_store,
			&transaction->rollback_keys[index]);

		if (ret == 0 || ret == -ESTALE || ret == -ENOENT) {
			destroyed++;
		} else {
			failures++;
			terminal = ret;
		}
		memset(&transaction->rollback_keys[index], 0,
		       sizeof(transaction->rollback_keys[index]));
	}
	transaction->rollback_key_count = 0U;
	for (size_t index = 0U;
	     index < transaction->step_count; ++index) {
		struct pqcp_runtime_transaction_step *step =
			&transaction->steps[index];

		if (step->state ==
		    PQCP_RUNTIME_TRANSACTION_STEP_COMPLETED) {
			step->state =
				PQCP_RUNTIME_TRANSACTION_STEP_ROLLED_BACK;
		} else if (step->state ==
			   PQCP_RUNTIME_TRANSACTION_STEP_STAGED) {
			step->state =
				PQCP_RUNTIME_TRANSACTION_STEP_SKIPPED;
		}
	}
	transaction->state = failures == 0U ?
		PQCP_RUNTIME_TRANSACTION_ROLLED_BACK :
		PQCP_RUNTIME_TRANSACTION_FAILED;
	if (terminal != 0) {
		transaction->terminal_result = terminal;
	}
	(void)fill_result(
		transaction, now_ms, destroyed, failures, result);
	return failures == 0U ? 0 : terminal;
}

int pqcp_runtime_transaction_execute(
	struct pqcp_runtime_transaction *transaction,
	uint64_t now_ms,
	struct pqcp_runtime_transaction_result *result)
{
	int terminal = 0;

	if (transaction == NULL || result == NULL ||
	    now_ms == 0U ||
	    transaction->state !=
		    PQCP_RUNTIME_TRANSACTION_OPEN ||
	    transaction->step_count == 0U ||
	    !dependency_graph_acyclic(transaction)) {
		return -EINVAL;
	}
	if (now_ms > transaction->deadline_ms) {
		transaction->terminal_result = -ETIMEDOUT;
		transaction->state = PQCP_RUNTIME_TRANSACTION_FAILED;
		(void)fill_result(transaction, now_ms, 0U, 0U, result);
		return -ETIMEDOUT;
	}
	transaction->state = PQCP_RUNTIME_TRANSACTION_RUNNING;
	do {
		size_t completed_before = 0U;

		for (size_t index = 0U;
		     index < transaction->step_count; ++index) {
			struct pqcp_runtime_transaction_step *step =
				&transaction->steps[index];

			if (step->state ==
			    PQCP_RUNTIME_TRANSACTION_STEP_COMPLETED) {
				completed_before++;
				continue;
			}
			if (step->state !=
				    PQCP_RUNTIME_TRANSACTION_STEP_STAGED ||
			    !dependencies_completed(transaction, step)) {
				continue;
			}
			terminal = execute_step(transaction, step);
			if (terminal != 0 &&
			    transaction->policy.stop_on_failure) {
				break;
			}
		}
		if (terminal != 0 &&
		    transaction->policy.stop_on_failure) {
			break;
		}
		size_t completed_after = 0U;

		for (size_t index = 0U;
		     index < transaction->step_count; ++index) {
			if (transaction->steps[index].state ==
			    PQCP_RUNTIME_TRANSACTION_STEP_COMPLETED) {
				completed_after++;
			}
		}
		if (completed_after == transaction->step_count) {
			break;
		}
		if (completed_after == completed_before) {
			terminal = -EDEADLK;
			break;
		}
	} while (pqcp_runtime_internal_now_ms() <=
		 transaction->deadline_ms);

	if (terminal == 0 &&
	    pqcp_runtime_internal_now_ms() >
		    transaction->deadline_ms) {
		terminal = -ETIMEDOUT;
	}
	if (terminal != 0) {
		transaction->terminal_result = terminal;
		if (transaction->policy.rollback_generated_keys) {
			return pqcp_runtime_transaction_rollback(
				transaction,
				pqcp_runtime_internal_now_ms(), result);
		}
		transaction->state = PQCP_RUNTIME_TRANSACTION_FAILED;
		(void)fill_result(
			transaction, pqcp_runtime_internal_now_ms(),
			0U, 0U, result);
		return terminal;
	}
	transaction->terminal_result = 0;
	transaction->state = PQCP_RUNTIME_TRANSACTION_COMMITTED;
	return fill_result(
		transaction, pqcp_runtime_internal_now_ms(),
		0U, 0U, result);
}

int pqcp_runtime_transaction_cancel(
	struct pqcp_runtime_transaction *transaction,
	uint64_t now_ms,
	struct pqcp_runtime_transaction_result *result)
{
	if (transaction == NULL || result == NULL ||
	    now_ms == 0U ||
	    transaction_state_terminal(transaction->state)) {
		return -EINVAL;
	}
	transaction->terminal_result = -ECANCELED;
	return pqcp_runtime_transaction_rollback(
		transaction, now_ms, result);
}

int pqcp_runtime_transaction_audit(
	const struct pqcp_runtime_transaction *transaction)
{
	if (transaction == NULL ||
	    transaction->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    transaction->transaction_id == 0U ||
	    transaction->session_id == 0U ||
	    transaction->controller == NULL ||
	    !transaction_policy_valid(&transaction->policy) ||
	    transaction->step_count >
		    transaction->policy.maximum_steps ||
	    transaction->rollback_key_count >
		    PQCP_RUNTIME_TRANSACTION_MAX_KEYS ||
	    !dependency_graph_acyclic(transaction)) {
		return -EBADMSG;
	}
	for (size_t index = 0U;
	     index < transaction->step_count; ++index) {
		const struct pqcp_runtime_transaction_step *step =
			&transaction->steps[index];

		if (step->schema_version !=
			    PQCP_RUNTIME_SCHEMA_VERSION ||
		    step->step_id == 0U || step->job == NULL ||
		    !step_state_valid(step->state) ||
		    !dependency_mask_valid(transaction,
					   step->dependency_mask)) {
			return -EBADMSG;
		}
	}
	return 0;
}

int pqcp_runtime_transaction_result_verify(
	const struct pqcp_runtime_transaction_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    result->transaction_id == 0U ||
	    !transaction_state_terminal(result->state) ||
	    result->completed_at_ms < result->started_at_ms ||
	    result->completed_steps + result->failed_steps +
			    result->skipped_steps +
			    result->rolled_back_steps >
		    result->staged_steps) {
		return -EBADMSG;
	}
	if (result->state == PQCP_RUNTIME_TRANSACTION_COMMITTED &&
	    (result->result != 0 || result->failed_steps != 0U ||
	     result->completed_steps != result->staged_steps)) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_transaction_emit(
	const struct pqcp_runtime_transaction_result *result)
{
	char digest_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];

	if (pqcp_runtime_transaction_result_verify(result) != 0 ||
	    pqcp_runtime_internal_hex(
		    result->digest, sizeof(result->digest),
		    digest_hex, sizeof(digest_hex)) != 0) {
		return -EBADMSG;
	}
	printk("PQCP_RUNTIME_TRANSACTION id=%llu state=%u steps=%u completed=%u failed=%u skipped=%u rolled_back=%u destroyed_keys=%u rollback_failures=%u failure_step=%u result=%d digest=%s\n",
	       (unsigned long long)result->transaction_id,
	       (unsigned int)result->state,
	       result->staged_steps, result->completed_steps,
	       result->failed_steps, result->skipped_steps,
	       result->rolled_back_steps, result->destroyed_keys,
	       result->rollback_failures, result->failure_step_id,
	       result->result, digest_hex);
	return 0;
}
