/*
 * SPDX-License-Identifier: MIT
 *
 * Bounded deadline-aware workload scheduler.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "edge_security_internal.h"

static bool terminal_state(
	enum pqcp_edge_job_state state)
{
	return state == PQCP_EDGE_JOB_COMPLETED ||
	       state == PQCP_EDGE_JOB_FAILED ||
	       state == PQCP_EDGE_JOB_CANCELLED;
}

static bool active_state(
	enum pqcp_edge_job_state state)
{
	return state == PQCP_EDGE_JOB_QUEUED ||
	       state == PQCP_EDGE_JOB_RESERVED ||
	       state == PQCP_EDGE_JOB_RUNNING ||
	       state == PQCP_EDGE_JOB_RETRY_WAIT;
}

static bool job_shape_valid(
	const struct pqcp_edge_workload_job *job)
{
	return job != NULL &&
	       pqcp_edge_internal_text_valid(
		       job->principal_id,
		       sizeof(job->principal_id)) &&
	       pqcp_edge_internal_text_valid(
		       job->service_id,
		       sizeof(job->service_id)) &&
	       job->deadline_ms > job->earliest_start_ms &&
	       job->estimated_cost != 0U &&
	       job->priority != 0U &&
	       job->required_resource_mask != 0U &&
	       job->maximum_attempts != 0U &&
	       job->attempts <= job->maximum_attempts;
}

static int job_index(
	const struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t job_id)
{
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		if (scheduler->jobs[index].occupied &&
		    scheduler->jobs[index].job_id == job_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_job_index(
	const struct pqcp_edge_workload_scheduler *scheduler)
{
	int terminal = -1;
	uint64_t oldest_completion = UINT64_MAX;

	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		const struct pqcp_edge_workload_job *job =
			&scheduler->jobs[index];

		if (!job->occupied) {
			return (int)index;
		}
		if (terminal_state(job->state) &&
		    job->deadline_ms < oldest_completion) {
			oldest_completion = job->deadline_ms;
			terminal = (int)index;
		}
	}
	return terminal >= 0 ? terminal : -ENOSPC;
}

static bool conflicts_with_active_job(
	const struct pqcp_edge_workload_scheduler *scheduler,
	const struct pqcp_edge_workload_job *candidate)
{
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		const struct pqcp_edge_workload_job *existing =
			&scheduler->jobs[index];

		if (!existing->occupied ||
		    !active_state(existing->state)) {
			continue;
		}
		if (candidate->job_id != 0U &&
		    existing->job_id == candidate->job_id) {
			return true;
		}
	}
	return false;
}

static bool runnable(
	const struct pqcp_edge_workload_job *job,
	uint64_t now_ms,
	uint32_t available_resource_mask)
{
	if (!job->occupied ||
	    job->state != PQCP_EDGE_JOB_QUEUED ||
	    job->earliest_start_ms > now_ms ||
	    job->deadline_ms <= now_ms) {
		return false;
	}
	return (available_resource_mask &
		job->required_resource_mask) ==
	       job->required_resource_mask;
}

static bool better_candidate(
	const struct pqcp_edge_workload_job *candidate,
	const struct pqcp_edge_workload_job *selected)
{
	if (selected == NULL) {
		return true;
	}
	if (candidate->priority != selected->priority) {
		return candidate->priority >
		       selected->priority;
	}
	if (candidate->deadline_ms !=
	    selected->deadline_ms) {
		return candidate->deadline_ms <
		       selected->deadline_ms;
	}
	if (candidate->estimated_cost !=
	    selected->estimated_cost) {
		return candidate->estimated_cost <
		       selected->estimated_cost;
	}
	if (candidate->submitted_at_ms !=
	    selected->submitted_at_ms) {
		return candidate->submitted_at_ms <
		       selected->submitted_at_ms;
	}
	return candidate->job_id < selected->job_id;
}

static void fail_job(
	struct pqcp_edge_workload_scheduler *scheduler,
	struct pqcp_edge_workload_job *job,
	int result)
{
	if (job->state == PQCP_EDGE_JOB_RESERVED ||
	    job->state == PQCP_EDGE_JOB_RUNNING) {
		scheduler->reserved_resource_mask &=
			~job->required_resource_mask;
	}
	job->state = PQCP_EDGE_JOB_FAILED;
	job->result = result;
	++scheduler->failed_count;
}

int pqcp_edge_workload_scheduler_init(
	struct pqcp_edge_workload_scheduler *scheduler,
	struct pqcp_edge_workload_job *jobs,
	size_t capacity)
{
	if (scheduler == NULL || jobs == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(scheduler, 0, sizeof(*scheduler));
	memset(jobs, 0, capacity * sizeof(*jobs));
	scheduler->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	scheduler->jobs = jobs;
	scheduler->capacity = capacity;
	scheduler->next_job_id = 1U;
	k_mutex_init(&scheduler->lock);
	scheduler->initialized = true;
	return 0;
}

int pqcp_edge_workload_submit(
	struct pqcp_edge_workload_scheduler *scheduler,
	const struct pqcp_edge_workload_job *job,
	uint64_t now_ms,
	struct pqcp_edge_workload_job **accepted)
{
	struct pqcp_edge_workload_job candidate;
	int index;

	if (scheduler == NULL ||
	    !scheduler->initialized ||
	    !job_shape_valid(job) ||
	    job->deadline_ms <= now_ms ||
	    job->earliest_start_ms <
		    job->submitted_at_ms ||
	    job->submitted_at_ms > now_ms) {
		return -EINVAL;
	}
	candidate = *job;
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.submitted_at_ms = now_ms;
	candidate.state = PQCP_EDGE_JOB_QUEUED;
	candidate.result = 0;
	candidate.occupied = true;
	k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (conflicts_with_active_job(
		    scheduler, &candidate)) {
		k_mutex_unlock(&scheduler->lock);
		return -EEXIST;
	}
	index = free_job_index(scheduler);
	if (index < 0) {
		k_mutex_unlock(&scheduler->lock);
		return index;
	}
	if (candidate.job_id == 0U) {
		candidate.job_id =
			pqcp_edge_internal_next_identifier(
				&scheduler->next_job_id);
	} else if (candidate.job_id >=
		   scheduler->next_job_id) {
		scheduler->next_job_id =
			candidate.job_id == UINT64_MAX ?
				1U :
				candidate.job_id + 1U;
	}
	scheduler->jobs[index] = candidate;
	if (accepted != NULL) {
		*accepted = &scheduler->jobs[index];
	}
	k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_edge_workload_next(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t now_ms,
	uint32_t available_resource_mask,
	struct pqcp_edge_workload_job **job)
{
	struct pqcp_edge_workload_job *selected = NULL;

	if (scheduler == NULL ||
	    !scheduler->initialized ||
	    available_resource_mask == 0U ||
	    job == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&scheduler->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		struct pqcp_edge_workload_job *candidate =
			&scheduler->jobs[index];

		if (candidate->occupied &&
		    active_state(candidate->state) &&
		    candidate->deadline_ms <= now_ms) {
			fail_job(scheduler, candidate,
				 -ETIMEDOUT);
			continue;
		}
		if (!runnable(candidate, now_ms,
			      available_resource_mask)) {
			continue;
		}
		if ((scheduler->reserved_resource_mask &
		     candidate->required_resource_mask) != 0U) {
			continue;
		}
		if (better_candidate(candidate, selected)) {
			selected = candidate;
		}
	}
	if (selected == NULL) {
		k_mutex_unlock(&scheduler->lock);
		return -EAGAIN;
	}
	selected->state = PQCP_EDGE_JOB_RUNNING;
	++selected->attempts;
	scheduler->reserved_resource_mask |=
		selected->required_resource_mask;
	*job = selected;
	k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_edge_workload_complete(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t job_id,
	int result,
	uint64_t now_ms)
{
	struct pqcp_edge_workload_job *job;
	int index;

	if (scheduler == NULL ||
	    !scheduler->initialized ||
	    job_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&scheduler->lock, K_FOREVER);
	index = job_index(scheduler, job_id);
	if (index < 0) {
		k_mutex_unlock(&scheduler->lock);
		return index;
	}
	job = &scheduler->jobs[index];
	if (job->state != PQCP_EDGE_JOB_RUNNING &&
	    job->state != PQCP_EDGE_JOB_RESERVED) {
		k_mutex_unlock(&scheduler->lock);
		return -EPERM;
	}
	scheduler->reserved_resource_mask &=
		~job->required_resource_mask;
	if (result == 0) {
		job->state = PQCP_EDGE_JOB_COMPLETED;
		job->result = 0;
		++scheduler->completed_count;
	} else if (job->attempts <
		   job->maximum_attempts &&
		   now_ms < job->deadline_ms) {
		job->state = PQCP_EDGE_JOB_RETRY_WAIT;
		job->result = result;
		job->earliest_start_ms = now_ms;
	} else {
		job->state = PQCP_EDGE_JOB_FAILED;
		job->result = result;
		++scheduler->failed_count;
	}
	k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_edge_workload_retry(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t job_id,
	uint64_t retry_at_ms)
{
	struct pqcp_edge_workload_job *job;
	int index;

	if (scheduler == NULL ||
	    !scheduler->initialized ||
	    job_id == 0U || retry_at_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&scheduler->lock, K_FOREVER);
	index = job_index(scheduler, job_id);
	if (index < 0) {
		k_mutex_unlock(&scheduler->lock);
		return index;
	}
	job = &scheduler->jobs[index];
	if (job->state != PQCP_EDGE_JOB_RETRY_WAIT) {
		k_mutex_unlock(&scheduler->lock);
		return -EPERM;
	}
	if (job->attempts >= job->maximum_attempts) {
		fail_job(scheduler, job, -ELOOP);
		k_mutex_unlock(&scheduler->lock);
		return -ELOOP;
	}
	if (retry_at_ms >= job->deadline_ms) {
		fail_job(scheduler, job, -ETIMEDOUT);
		k_mutex_unlock(&scheduler->lock);
		return -ETIMEDOUT;
	}
	job->earliest_start_ms = retry_at_ms;
	job->state = PQCP_EDGE_JOB_QUEUED;
	k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_edge_workload_cancel(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t job_id)
{
	struct pqcp_edge_workload_job *job;
	int index;

	if (scheduler == NULL ||
	    !scheduler->initialized ||
	    job_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&scheduler->lock, K_FOREVER);
	index = job_index(scheduler, job_id);
	if (index < 0) {
		k_mutex_unlock(&scheduler->lock);
		return index;
	}
	job = &scheduler->jobs[index];
	if (terminal_state(job->state)) {
		k_mutex_unlock(&scheduler->lock);
		return -EALREADY;
	}
	if (job->state == PQCP_EDGE_JOB_RUNNING ||
	    job->state == PQCP_EDGE_JOB_RESERVED) {
		scheduler->reserved_resource_mask &=
			~job->required_resource_mask;
	}
	job->state = PQCP_EDGE_JOB_CANCELLED;
	job->result = -ECANCELED;
	k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_edge_workload_tick(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (scheduler == NULL ||
	    !scheduler->initialized) {
		return -EINVAL;
	}
	k_mutex_lock(&scheduler->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		struct pqcp_edge_workload_job *job =
			&scheduler->jobs[index];

		if (!job->occupied ||
		    terminal_state(job->state)) {
			continue;
		}
		if (job->deadline_ms <= now_ms) {
			fail_job(scheduler, job,
				 -ETIMEDOUT);
			++changed;
			continue;
		}
		if (job->state ==
			    PQCP_EDGE_JOB_RETRY_WAIT &&
		    job->earliest_start_ms <= now_ms) {
			if (job->attempts >=
			    job->maximum_attempts) {
				fail_job(scheduler, job,
					 -ELOOP);
			} else {
				job->state =
					PQCP_EDGE_JOB_QUEUED;
			}
			++changed;
		}
	}
	k_mutex_unlock(&scheduler->lock);
	if (changed_count != NULL) {
		*changed_count = changed;
	}
	return 0;
}

int pqcp_edge_workload_scheduler_audit(
	struct pqcp_edge_workload_scheduler *scheduler)
{
	uint32_t expected_reserved = 0U;
	int ret = 0;

	if (scheduler == NULL ||
	    !scheduler->initialized ||
	    scheduler->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    scheduler->jobs == NULL ||
	    scheduler->capacity == 0U ||
	    scheduler->next_job_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&scheduler->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		const struct pqcp_edge_workload_job *job =
			&scheduler->jobs[index];

		if (!job->occupied) {
			continue;
		}
		if (job->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    job->job_id == 0U ||
		    !job_shape_valid(job) ||
		    job->state <= PQCP_EDGE_JOB_EMPTY ||
		    job->state > PQCP_EDGE_JOB_CANCELLED) {
			ret = -EBADMSG;
			break;
		}
		if (job->state == PQCP_EDGE_JOB_RUNNING ||
		    job->state == PQCP_EDGE_JOB_RESERVED) {
			if ((expected_reserved &
			     job->required_resource_mask) != 0U) {
				ret = -EDEADLK;
				break;
			}
			expected_reserved |=
				job->required_resource_mask;
		}
		for (size_t other = index + 1U;
		     other < scheduler->capacity; ++other) {
			if (scheduler->jobs[other].occupied &&
			    scheduler->jobs[other].job_id ==
				    job->job_id) {
				ret = -EEXIST;
				break;
			}
		}
		if (ret != 0) {
			break;
		}
	}
	if (ret == 0 &&
	    expected_reserved !=
		    scheduler->reserved_resource_mask) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&scheduler->lock);
	return ret;
}
