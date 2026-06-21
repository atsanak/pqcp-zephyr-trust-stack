/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Conflict-aware maintenance scheduling for constrained fleet devices.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>

static bool type_valid(enum pqcp_fleet_maintenance_type type)
{
	return type > PQCP_FLEET_MAINTENANCE_NONE &&
	       type < PQCP_FLEET_MAINTENANCE_TYPE_COUNT;
}

static bool state_valid(enum pqcp_fleet_maintenance_state state)
{
	return state >= PQCP_FLEET_MAINTENANCE_EMPTY &&
	       state <= PQCP_FLEET_MAINTENANCE_EXPIRED;
}

static int job_validate(
	const struct pqcp_fleet_maintenance_job *job)
{
	if (job == NULL ||
	    job->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    job->job_id == 0U || !type_valid(job->type) ||
	    !state_valid(job->state) ||
	    job->state == PQCP_FLEET_MAINTENANCE_EMPTY ||
	    job->earliest_start_ms == 0U ||
	    job->latest_finish_ms <= job->earliest_start_ms ||
	    job->expected_duration_ms == 0U ||
	    job->expected_duration_ms >
		    job->latest_finish_ms -
			    job->earliest_start_ms ||
	    job->priority == 0U || job->resource_mask == 0U ||
	    job->maximum_attempts == 0U ||
	    job->attempt_count > job->maximum_attempts) {
		return -EINVAL;
	}
	return 0;
}

static bool terminal_state(
	enum pqcp_fleet_maintenance_state state)
{
	return state == PQCP_FLEET_MAINTENANCE_COMPLETED ||
	       state == PQCP_FLEET_MAINTENANCE_CANCELLED ||
	       state == PQCP_FLEET_MAINTENANCE_EXPIRED;
}

static int job_index(
	const struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t job_id)
{
	for (size_t index = 0U; index < scheduler->capacity;
	     ++index) {
		if (scheduler->jobs[index].state !=
			    PQCP_FLEET_MAINTENANCE_EMPTY &&
		    scheduler->jobs[index].job_id == job_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_maintenance_scheduler *scheduler)
{
	int terminal = -1;
	uint64_t oldest_completion = UINT64_MAX;

	for (size_t index = 0U; index < scheduler->capacity;
	     ++index) {
		const struct pqcp_fleet_maintenance_job *job =
			&scheduler->jobs[index];

		if (job->state == PQCP_FLEET_MAINTENANCE_EMPTY) {
			return (int)index;
		}
		if (terminal_state(job->state) &&
		    job->completed_at_ms < oldest_completion) {
			oldest_completion = job->completed_at_ms;
			terminal = (int)index;
		}
	}
	return terminal;
}

int pqcp_fleet_maintenance_scheduler_init(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	struct pqcp_fleet_maintenance_job *jobs,
	size_t capacity)
{
	if (scheduler == NULL || jobs == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(scheduler, 0, sizeof(*scheduler));
	memset(jobs, 0, sizeof(*jobs) * capacity);
	scheduler->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	scheduler->jobs = jobs;
	scheduler->capacity = capacity;
	k_mutex_init(&scheduler->lock);
	scheduler->initialized = true;
	return 0;
}

int pqcp_fleet_maintenance_schedule(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	const struct pqcp_fleet_maintenance_job *job)
{
	int index;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    job_validate(job) != 0 ||
	    job->state != PQCP_FLEET_MAINTENANCE_SCHEDULED ||
	    job->attempt_count != 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = job_index(scheduler, job->job_id);
	if (index >= 0) {
		if (memcmp(&scheduler->jobs[index], job,
			   sizeof(*job)) == 0) {
			(void)k_mutex_unlock(&scheduler->lock);
			return 0;
		}
		scheduler->rejected_count++;
		(void)k_mutex_unlock(&scheduler->lock);
		return -EEXIST;
	}
	index = free_index(scheduler);
	if (index < 0) {
		scheduler->rejected_count++;
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOSPC;
	}
	scheduler->jobs[index] = *job;
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

static bool runnable(
	const struct pqcp_fleet_maintenance_scheduler *scheduler,
	const struct pqcp_fleet_maintenance_job *job,
	uint64_t now_ms,
	bool disruption_allowed)
{
	return job->state == PQCP_FLEET_MAINTENANCE_SCHEDULED &&
	       now_ms >= job->earliest_start_ms &&
	       now_ms + job->expected_duration_ms <=
		       job->latest_finish_ms &&
	       (job->resource_mask &
		scheduler->active_resource_mask) == 0U &&
	       (!job->disruptive || disruption_allowed);
}

static bool precedes(
	const struct pqcp_fleet_maintenance_job *candidate,
	const struct pqcp_fleet_maintenance_job *selected)
{
	if (candidate->priority != selected->priority) {
		return candidate->priority > selected->priority;
	}
	if (candidate->latest_finish_ms !=
	    selected->latest_finish_ms) {
		return candidate->latest_finish_ms <
		       selected->latest_finish_ms;
	}
	return candidate->job_id < selected->job_id;
}

int pqcp_fleet_maintenance_next(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t now_ms,
	bool disruption_allowed,
	struct pqcp_fleet_maintenance_job **job)
{
	struct pqcp_fleet_maintenance_job *selected = NULL;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    now_ms == 0U || job == NULL) {
		return -EINVAL;
	}
	*job = NULL;
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < scheduler->capacity;
	     ++index) {
		struct pqcp_fleet_maintenance_job *candidate =
			&scheduler->jobs[index];

		if (candidate->state ==
			    PQCP_FLEET_MAINTENANCE_SCHEDULED &&
		    now_ms >= candidate->latest_finish_ms) {
			candidate->state =
				PQCP_FLEET_MAINTENANCE_EXPIRED;
			candidate->completed_at_ms = now_ms;
			candidate->result = -ETIMEDOUT;
			scheduler->rejected_count++;
			continue;
		}
		if (runnable(
			    scheduler, candidate, now_ms,
			    disruption_allowed) &&
		    (selected == NULL ||
		     precedes(candidate, selected))) {
			selected = candidate;
		}
	}
	if (selected == NULL) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOENT;
	}
	selected->state = PQCP_FLEET_MAINTENANCE_RUNNING;
	selected->started_at_ms = now_ms;
	selected->attempt_count++;
	scheduler->active_resource_mask |=
		selected->resource_mask;
	*job = selected;
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_fleet_maintenance_complete(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t job_id,
	int result,
	uint64_t now_ms)
{
	struct pqcp_fleet_maintenance_job *job;
	int index;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    job_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = job_index(scheduler, job_id);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOENT;
	}
	job = &scheduler->jobs[index];
	if (job->state != PQCP_FLEET_MAINTENANCE_RUNNING) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EALREADY;
	}
	scheduler->active_resource_mask &=
		~job->resource_mask;
	job->completed_at_ms = now_ms;
	job->result = result;
	if (result == 0) {
		job->state =
			PQCP_FLEET_MAINTENANCE_COMPLETED;
		scheduler->completed_count++;
	} else if (job->attempt_count >= job->maximum_attempts ||
		   now_ms >= job->latest_finish_ms) {
		job->state =
			PQCP_FLEET_MAINTENANCE_EXPIRED;
		scheduler->rejected_count++;
	} else {
		job->state =
			PQCP_FLEET_MAINTENANCE_SCHEDULED;
		job->started_at_ms = 0U;
		job->completed_at_ms = 0U;
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_fleet_maintenance_retry(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t job_id,
	uint64_t earliest_start_ms)
{
	struct pqcp_fleet_maintenance_job *job;
	int index;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    job_id == 0U || earliest_start_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = job_index(scheduler, job_id);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOENT;
	}
	job = &scheduler->jobs[index];
	if (job->state != PQCP_FLEET_MAINTENANCE_EXPIRED ||
	    job->attempt_count >= job->maximum_attempts ||
	    earliest_start_ms >= job->latest_finish_ms) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EACCES;
	}
	job->earliest_start_ms = earliest_start_ms;
	job->started_at_ms = 0U;
	job->completed_at_ms = 0U;
	job->result = 0;
	job->state = PQCP_FLEET_MAINTENANCE_SCHEDULED;
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_fleet_maintenance_cancel(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t job_id)
{
	int index;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    job_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = job_index(scheduler, job_id);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOENT;
	}
	struct pqcp_fleet_maintenance_job *job =
		&scheduler->jobs[index];

	if (terminal_state(job->state)) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EALREADY;
	}
	if (job->state == PQCP_FLEET_MAINTENANCE_RUNNING) {
		scheduler->active_resource_mask &=
			~job->resource_mask;
	}
	job->state = PQCP_FLEET_MAINTENANCE_CANCELLED;
	job->result = -ECANCELED;
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_fleet_maintenance_tick(
	struct pqcp_fleet_maintenance_scheduler *scheduler,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < scheduler->capacity;
	     ++index) {
		struct pqcp_fleet_maintenance_job *job =
			&scheduler->jobs[index];

		if (!terminal_state(job->state) &&
		    job->state != PQCP_FLEET_MAINTENANCE_EMPTY &&
		    now_ms >= job->latest_finish_ms) {
			if (job->state ==
			    PQCP_FLEET_MAINTENANCE_RUNNING) {
				scheduler->active_resource_mask &=
					~job->resource_mask;
			}
			job->state =
				PQCP_FLEET_MAINTENANCE_EXPIRED;
			job->completed_at_ms = now_ms;
			job->result = -ETIMEDOUT;
			expired++;
			scheduler->rejected_count++;
		}
	}
	(void)k_mutex_unlock(&scheduler->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_fleet_maintenance_audit(
	struct pqcp_fleet_maintenance_scheduler *scheduler)
{
	uint32_t active_mask = 0U;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    scheduler->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    scheduler->jobs == NULL || scheduler->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < scheduler->capacity;
	     ++index) {
		const struct pqcp_fleet_maintenance_job *job =
			&scheduler->jobs[index];

		if (job->state == PQCP_FLEET_MAINTENANCE_EMPTY) {
			continue;
		}
		if (job_validate(job) != 0 ||
		    (job->state ==
			     PQCP_FLEET_MAINTENANCE_RUNNING &&
		     (active_mask & job->resource_mask) != 0U)) {
			(void)k_mutex_unlock(&scheduler->lock);
			return -EBADMSG;
		}
		if (job->state ==
		    PQCP_FLEET_MAINTENANCE_RUNNING) {
			active_mask |= job->resource_mask;
		}
		for (size_t other = index + 1U;
		     other < scheduler->capacity; ++other) {
			if (scheduler->jobs[other].state !=
				    PQCP_FLEET_MAINTENANCE_EMPTY &&
			    scheduler->jobs[other].job_id ==
				    job->job_id) {
				(void)k_mutex_unlock(&scheduler->lock);
				return -EEXIST;
			}
		}
	}
	if (active_mask != scheduler->active_resource_mask) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EBADMSG;
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}
