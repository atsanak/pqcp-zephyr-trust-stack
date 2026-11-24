/*
 * SPDX-License-Identifier: MIT
 *
 * Priority/deadline scheduler for native PQCP operations.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/runtime_executor.h>

#include "runtime_internal.h"

void pqcp_runtime_measurement_begin(
	struct pqcp_runtime_job *job,
	uint64_t *start_cycles);
void pqcp_runtime_measurement_finish(
	struct pqcp_runtime_job *job,
	uint64_t start_cycles,
	size_t workspace_bytes,
	int result);
int pqcp_runtime_measurement_publish(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job);

static bool executor_valid(
	const struct pqcp_runtime_executor *executor)
{
	return executor != NULL &&
	       executor->schema_version ==
		       PQCP_RUNTIME_SCHEMA_VERSION &&
	       executor->key_store != NULL &&
	       executor->workspace_pool != NULL &&
	       executor->queue != NULL &&
	       executor->queue_capacity != 0U &&
	       executor->queue_count <=
		       executor->queue_capacity;
}

static bool job_buffers_valid(
	const struct pqcp_runtime_job *job)
{
	if ((job->input == NULL && job->input_length != 0U) ||
	    (job->aux_input == NULL &&
	     job->aux_input_length != 0U) ||
	    (job->context == NULL &&
	     job->context_length != 0U) ||
	    (job->output == NULL &&
	     job->output_capacity != 0U) ||
	    (job->aux_output == NULL &&
	     job->aux_output_capacity != 0U) ||
	    job->input_length > PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    job->aux_input_length >
		    PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    job->context_length >
		    PQCP_RUNTIME_MAX_CONTEXT_BYTES ||
	    job->output_capacity >
		    PQCP_RUNTIME_MAX_OUTPUT_BYTES ||
	    job->aux_output_capacity >
		    PQCP_RUNTIME_MAX_OUTPUT_BYTES) {
		return false;
	}
	return true;
}

static bool job_valid(const struct pqcp_runtime_job *job)
{
	return job != NULL &&
	       job->schema_version ==
		       PQCP_RUNTIME_SCHEMA_VERSION &&
	       job->job_id != 0U &&
	       pqcp_runtime_internal_job_type_valid(job->type) &&
	       pqcp_runtime_internal_priority_valid(job->priority) &&
	       job_buffers_valid(job);
}

static size_t workspace_requirement(
	const struct pqcp_runtime_job *job)
{
	switch (job->type) {
	case PQCP_RUNTIME_JOB_MLKEM_KEYGEN:
		return PQCP_MLKEM_PK_SIZE_MAX +
		       PQCP_MLKEM_SK_SIZE_MAX;
	case PQCP_RUNTIME_JOB_MLKEM_ENCAPSULATE:
		return PQCP_MLKEM_CT_SIZE_MAX;
	case PQCP_RUNTIME_JOB_MLKEM_DECAPSULATE:
		return 256U;
	case PQCP_RUNTIME_JOB_MLDSA_KEYGEN:
		return PQCP_MLDSA_PK_SIZE_MAX +
		       PQCP_MLDSA_SK_SIZE_MAX;
	case PQCP_RUNTIME_JOB_MLDSA_SIGN:
		return PQCP_MLDSA_SIG_SIZE_MAX;
	case PQCP_RUNTIME_JOB_MLDSA_VERIFY:
		return 256U;
	case PQCP_RUNTIME_JOB_HKDF_DERIVE:
		return 256U;
	case PQCP_RUNTIME_JOB_AEAD_ENCRYPT:
	case PQCP_RUNTIME_JOB_AEAD_DECRYPT:
		return PQCP_RUNTIME_MAX_OUTPUT_BYTES;
	default:
		return 0U;
	}
}

static int execute_primitive(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	switch (job->type) {
	case PQCP_RUNTIME_JOB_MLKEM_KEYGEN:
		return pqcp_runtime_execute_mlkem_keygen(
			executor, job, workspace,
			workspace_capacity);
	case PQCP_RUNTIME_JOB_MLKEM_ENCAPSULATE:
		return pqcp_runtime_execute_mlkem_encapsulate(
			executor, job, workspace,
			workspace_capacity);
	case PQCP_RUNTIME_JOB_MLKEM_DECAPSULATE:
		return pqcp_runtime_execute_mlkem_decapsulate(
			executor, job, workspace,
			workspace_capacity);
	case PQCP_RUNTIME_JOB_MLDSA_KEYGEN:
		return pqcp_runtime_execute_mldsa_keygen(
			executor, job, workspace,
			workspace_capacity);
	case PQCP_RUNTIME_JOB_MLDSA_SIGN:
		return pqcp_runtime_execute_mldsa_sign(
			executor, job, workspace,
			workspace_capacity);
	case PQCP_RUNTIME_JOB_MLDSA_VERIFY:
		return pqcp_runtime_execute_mldsa_verify(
			executor, job, workspace,
			workspace_capacity);
	case PQCP_RUNTIME_JOB_HKDF_DERIVE:
		return pqcp_runtime_execute_hkdf_derive(
			executor, job, workspace,
			workspace_capacity);
	case PQCP_RUNTIME_JOB_AEAD_ENCRYPT:
		return pqcp_runtime_execute_aead_encrypt(
			executor, job, workspace,
			workspace_capacity);
	case PQCP_RUNTIME_JOB_AEAD_DECRYPT:
		return pqcp_runtime_execute_aead_decrypt(
			executor, job, workspace,
			workspace_capacity);
	default:
		return -ENOTSUP;
	}
}

int pqcp_runtime_executor_init(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_key_store *key_store,
	struct pqcp_runtime_workspace_pool *workspace_pool,
	struct pqcp_runtime_queue_entry *queue,
	size_t queue_capacity)
{
	if (executor == NULL || key_store == NULL ||
	    workspace_pool == NULL || queue == NULL ||
	    queue_capacity == 0U ||
	    pqcp_runtime_key_store_validate(key_store) != 0 ||
	    pqcp_runtime_workspace_audit(workspace_pool) != 0) {
		return -EINVAL;
	}
	memset(executor, 0, sizeof(*executor));
	memset(queue, 0, sizeof(*queue) * queue_capacity);
	executor->schema_version =
		PQCP_RUNTIME_SCHEMA_VERSION;
	executor->key_store = key_store;
	executor->workspace_pool = workspace_pool;
	executor->queue = queue;
	executor->queue_capacity = queue_capacity;
	executor->next_sequence = 1U;
	k_mutex_init(&executor->lock);
	k_sem_init(
		&executor->pending, 0U,
		(uint32_t)queue_capacity);
	return 0;
}

int pqcp_runtime_executor_bind_adaptive(
	struct pqcp_runtime_executor *executor,
	struct pqcp_adaptive_control_plane *control,
	struct pqcp_adaptive_calibration_table *calibration,
	struct pqcp_runtime_profile_state *profile_states,
	size_t profile_state_capacity)
{
	if (!executor_valid(executor) || control == NULL ||
	    calibration == NULL || profile_states == NULL ||
	    profile_state_capacity == 0U) {
		return -EINVAL;
	}
	executor->adaptive_control = control;
	executor->calibration = calibration;
	executor->profile_states = profile_states;
	executor->profile_state_capacity =
		profile_state_capacity;
	memset(profile_states, 0,
	       sizeof(*profile_states) * profile_state_capacity);
	return 0;
}

static bool deadline_expired(
	const struct pqcp_runtime_job *job,
	uint64_t now_ms)
{
	return job->deadline_ms != 0U &&
	       now_ms > job->deadline_ms &&
	       (job->flags &
		PQCP_RUNTIME_JOB_FLAG_ALLOW_EXPIRED_DEADLINE) == 0U;
}

int pqcp_runtime_executor_execute(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job)
{
	uint8_t *workspace = NULL;
	size_t workspace_capacity = 0U;
	const size_t required =
		workspace_requirement(job);
	uint32_t generation = 0U;
	uint64_t start_cycles = 0U;
	int ret;

	if (!executor_valid(executor) || !job_valid(job) ||
	    required == 0U) {
		return -EINVAL;
	}
	if (deadline_expired(
		    job, pqcp_runtime_internal_now_ms())) {
		job->status = PQCP_RUNTIME_STATUS_EXPIRED;
		job->result = -ETIMEDOUT;
		executor->expired_count++;
		return -ETIMEDOUT;
	}
	ret = pqcp_runtime_workspace_acquire(
		executor->workspace_pool, job->job_id,
		required, &workspace, &workspace_capacity,
		&generation);
	if (ret != 0) {
		job->status = PQCP_RUNTIME_STATUS_FAILED;
		job->result = ret;
		executor->failed_count++;
		return ret;
	}
	job->status = PQCP_RUNTIME_STATUS_RUNNING;
	pqcp_runtime_measurement_begin(job, &start_cycles);
	ret = execute_primitive(
		executor, job, workspace, workspace_capacity);
	pqcp_runtime_measurement_finish(
		job, start_cycles, required, ret);
	(void)pqcp_runtime_workspace_release(
		executor->workspace_pool, job->job_id,
		generation);
	if (ret == 0) {
		executor->completed_count++;
	} else {
		executor->failed_count++;
		if ((job->flags &
		     PQCP_RUNTIME_JOB_FLAG_ZERO_OUTPUT_ON_FAILURE) != 0U) {
			pqcp_runtime_secure_zero(
				job->output, job->output_capacity);
			pqcp_runtime_secure_zero(
				job->aux_output,
				job->aux_output_capacity);
			job->output_length = 0U;
			job->aux_output_length = 0U;
		}
	}
	if ((job->flags &
	     PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION) != 0U) {
		(void)pqcp_runtime_measurement_publish(executor, job);
	}
	if (job->completion != NULL) {
		job->completion(job, job->completion_user);
	}
	return ret;
}

static int free_queue_index(
	const struct pqcp_runtime_executor *executor)
{
	for (size_t index = 0U;
	     index < executor->queue_capacity; ++index) {
		if (!executor->queue[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_runtime_executor_submit(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job)
{
	int index;
	int ret;

	if (!executor_valid(executor) || !job_valid(job) ||
	    job->status != PQCP_RUNTIME_STATUS_IDLE) {
		return -EINVAL;
	}
	if ((job->flags &
	     PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS) != 0U) {
		job->submitted_at_ms =
			pqcp_runtime_internal_now_ms();
		executor->submitted_count++;
		return pqcp_runtime_executor_execute(
			executor, job);
	}
	ret = k_mutex_lock(&executor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = free_queue_index(executor);
	if (index < 0) {
		(void)k_mutex_unlock(&executor->lock);
		return -ENOSPC;
	}
	job->submitted_at_ms =
		pqcp_runtime_internal_now_ms();
	job->status = PQCP_RUNTIME_STATUS_QUEUED;
	executor->queue[index].job = job;
	executor->queue[index].sequence =
		executor->next_sequence++;
	executor->queue[index].occupied = true;
	executor->queue_count++;
	executor->submitted_count++;
	(void)k_mutex_unlock(&executor->lock);
	k_sem_give(&executor->pending);
	return 0;
}

static int next_job_index(
	const struct pqcp_runtime_executor *executor)
{
	int selected = -1;

	for (size_t index = 0U;
	     index < executor->queue_capacity; ++index) {
		const struct pqcp_runtime_queue_entry *entry =
			&executor->queue[index];

		if (!entry->occupied || entry->job == NULL) {
			continue;
		}
		if (selected < 0 ||
		    entry->job->priority >
			    executor->queue[selected].job->priority ||
		    (entry->job->priority ==
			     executor->queue[selected].job->priority &&
		     entry->sequence <
			     executor->queue[selected].sequence)) {
			selected = (int)index;
		}
	}
	return selected;
}

static struct pqcp_runtime_job *dequeue_job(
	struct pqcp_runtime_executor *executor)
{
	struct pqcp_runtime_job *job = NULL;
	int index;

	if (k_mutex_lock(&executor->lock, K_FOREVER) != 0) {
		return NULL;
	}
	index = next_job_index(executor);
	if (index >= 0) {
		job = executor->queue[index].job;
		memset(&executor->queue[index], 0,
		       sizeof(executor->queue[index]));
		if (executor->queue_count != 0U) {
			executor->queue_count--;
		}
	}
	(void)k_mutex_unlock(&executor->lock);
	return job;
}

static void executor_worker(void *first, void *second, void *third)
{
	struct pqcp_runtime_executor *executor = first;

	ARG_UNUSED(second);
	ARG_UNUSED(third);
	while (!executor->stop_requested) {
		if (k_sem_take(
			    &executor->pending,
			    K_MSEC(100)) != 0) {
			continue;
		}
		struct pqcp_runtime_job *job =
			dequeue_job(executor);

		if (job != NULL &&
		    job->status ==
			    PQCP_RUNTIME_STATUS_QUEUED) {
			(void)pqcp_runtime_executor_execute(
				executor, job);
		}
	}
}

int pqcp_runtime_executor_start(
	struct pqcp_runtime_executor *executor,
	struct k_thread *thread,
	k_thread_stack_t *stack,
	size_t stack_size,
	int priority)
{
	if (!executor_valid(executor) || thread == NULL ||
	    stack == NULL || stack_size == 0U ||
	    executor->worker_started) {
		return -EINVAL;
	}
	executor->worker_thread = thread;
	executor->worker_stack = stack;
	executor->worker_stack_size = stack_size;
	executor->worker_priority = priority;
	executor->stop_requested = false;
	k_thread_create(
		thread, stack, stack_size,
		executor_worker, executor, NULL, NULL,
		priority, 0U, K_NO_WAIT);
	executor->worker_started = true;
	return 0;
}

int pqcp_runtime_executor_stop(
	struct pqcp_runtime_executor *executor,
	k_timeout_t timeout)
{
	int ret;

	if (!executor_valid(executor) ||
	    !executor->worker_started) {
		return -EINVAL;
	}
	executor->stop_requested = true;
	k_sem_give(&executor->pending);
	ret = k_thread_join(
		executor->worker_thread, timeout);
	if (ret != 0) {
		return ret;
	}
	executor->worker_started = false;
	return 0;
}

int pqcp_runtime_executor_cancel(
	struct pqcp_runtime_executor *executor,
	uint64_t job_id)
{
	int ret;

	if (!executor_valid(executor) || job_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&executor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < executor->queue_capacity; ++index) {
		struct pqcp_runtime_queue_entry *entry =
			&executor->queue[index];

		if (!entry->occupied || entry->job == NULL ||
		    entry->job->job_id != job_id) {
			continue;
		}
		entry->job->status =
			PQCP_RUNTIME_STATUS_CANCELLED;
		entry->job->result = -ECANCELED;
		if (entry->job->completion != NULL) {
			entry->job->completion(
				entry->job,
				entry->job->completion_user);
		}
		memset(entry, 0, sizeof(*entry));
		if (executor->queue_count != 0U) {
			executor->queue_count--;
		}
		executor->cancelled_count++;
		(void)k_mutex_unlock(&executor->lock);
		return 0;
	}
	(void)k_mutex_unlock(&executor->lock);
	return -ENOENT;
}

int pqcp_runtime_executor_drain(
	const struct pqcp_runtime_executor *executor,
	k_timeout_t timeout)
{
	const bool wait_forever = K_TIMEOUT_EQ(timeout, K_FOREVER);
	const int64_t timeout_ms = wait_forever ?
		INT64_MAX : k_ticks_to_ms_ceil64(timeout.ticks);
	const int64_t deadline = wait_forever ?
		INT64_MAX : k_uptime_get() + timeout_ms;

	if (!executor_valid(executor)) {
		return -EINVAL;
	}
	while (executor->queue_count != 0U) {
		if (!wait_forever && k_uptime_get() >= deadline) {
			return -ETIMEDOUT;
		}
		k_sleep(K_MSEC(1));
	}
	return 0;
}

int pqcp_runtime_executor_audit(
	struct pqcp_runtime_executor *executor)
{
	uint32_t occupied = 0U;
	int ret;

	if (!executor_valid(executor)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&executor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < executor->queue_capacity; ++index) {
		const struct pqcp_runtime_queue_entry *entry =
			&executor->queue[index];

		if (!entry->occupied) {
			if (entry->job != NULL ||
			    entry->sequence != 0U) {
				(void)k_mutex_unlock(
					&executor->lock);
				return -EBADMSG;
			}
			continue;
		}
		occupied++;
		if (entry->job == NULL ||
		    entry->sequence == 0U ||
		    entry->job->status !=
			    PQCP_RUNTIME_STATUS_QUEUED ||
		    !job_valid(entry->job)) {
			(void)k_mutex_unlock(&executor->lock);
			return -EBADMSG;
		}
	}
	ret = occupied == executor->queue_count ?
		0 : -EBADMSG;
	(void)k_mutex_unlock(&executor->lock);
	if (ret != 0) {
		return ret;
	}
	if (pqcp_runtime_key_store_audit(
		    executor->key_store) != 0 ||
	    pqcp_runtime_workspace_audit(
		    executor->workspace_pool) != 0) {
		return -EBADMSG;
	}
	return 0;
}
