/*
 * SPDX-License-Identifier: MIT
 *
 * Per-subject token-bucket admission and abuse containment.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>

#include "runtime_internal.h"

static int policy_validate(
	const struct pqcp_fleet_admission_policy *policy)
{
	if (policy == NULL || policy->bucket_capacity == 0U ||
	    policy->refill_tokens == 0U ||
	    policy->refill_interval_ms == 0U ||
	    policy->maximum_cost_per_request == 0U ||
	    policy->maximum_cost_per_request >
		    policy->bucket_capacity ||
	    policy->maximum_bytes_per_window == 0U ||
	    policy->maximum_concurrent == 0U ||
	    policy->failure_penalty == 0U ||
	    policy->recovery_credit == 0U) {
		return -EINVAL;
	}
	return 0;
}

static int subject_index(
	const struct pqcp_fleet_admission_controller *controller,
	const char *subject_id)
{
	for (size_t index = 0U; index < controller->capacity;
	     ++index) {
		if (controller->subjects[index].occupied &&
		    strcmp(controller->subjects[index].subject_id,
			   subject_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_admission_controller *controller)
{
	for (size_t index = 0U; index < controller->capacity;
	     ++index) {
		if (!controller->subjects[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static int initialize_subject(
	struct pqcp_fleet_admission_controller *controller,
	const char *subject_id,
	uint64_t now_ms,
	struct pqcp_fleet_admission_subject **subject)
{
	int index = free_index(controller);
	int ret;

	if (index < 0) {
		return -ENOSPC;
	}
	*subject = &controller->subjects[index];
	memset(*subject, 0, sizeof(**subject));
	(*subject)->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	ret = pqcp_runtime_internal_copy_text(
		(*subject)->subject_id,
		sizeof((*subject)->subject_id), subject_id);
	if (ret != 0) {
		memset(*subject, 0, sizeof(**subject));
		return ret;
	}
	(*subject)->tokens =
		controller->policy.bucket_capacity;
	(*subject)->last_refill_ms = now_ms;
	(*subject)->window_started_ms = now_ms;
	(*subject)->occupied = true;
	return 0;
}

static void refill_subject(
	struct pqcp_fleet_admission_controller *controller,
	struct pqcp_fleet_admission_subject *subject,
	uint64_t now_ms)
{
	uint64_t intervals;
	uint64_t refill;

	if (now_ms < subject->last_refill_ms) {
		subject->last_refill_ms = now_ms;
		return;
	}
	intervals =
		(now_ms - subject->last_refill_ms) /
		controller->policy.refill_interval_ms;
	if (intervals == 0U) {
		return;
	}
	if (intervals > UINT64_MAX /
	    controller->policy.refill_tokens) {
		refill = UINT64_MAX;
	} else {
		refill = intervals *
			 controller->policy.refill_tokens;
	}
	if (refill >= controller->policy.bucket_capacity -
		    subject->tokens) {
		subject->tokens =
			controller->policy.bucket_capacity;
	} else {
		subject->tokens += refill;
	}
	if (intervals > UINT64_MAX /
	    controller->policy.refill_interval_ms) {
		subject->last_refill_ms = now_ms;
	} else {
		subject->last_refill_ms +=
			intervals *
			controller->policy.refill_interval_ms;
	}
	if (now_ms - subject->window_started_ms >=
	    controller->policy.refill_interval_ms) {
		subject->window_started_ms = now_ms;
		subject->bytes_in_window = 0U;
	}
}

int pqcp_fleet_admission_controller_init(
	struct pqcp_fleet_admission_controller *controller,
	const struct pqcp_fleet_admission_policy *policy,
	struct pqcp_fleet_admission_subject *subjects,
	size_t capacity,
	uint64_t now_ms)
{
	if (controller == NULL || policy_validate(policy) != 0 ||
	    subjects == NULL || capacity == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	memset(controller, 0, sizeof(*controller));
	memset(subjects, 0, sizeof(*subjects) * capacity);
	controller->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	controller->policy = *policy;
	controller->subjects = subjects;
	controller->capacity = capacity;
	k_mutex_init(&controller->lock);
	controller->initialized = true;
	return 0;
}

int pqcp_fleet_admission_authorize(
	struct pqcp_fleet_admission_controller *controller,
	const char *subject_id,
	uint64_t cost,
	uint64_t bytes,
	uint64_t now_ms)
{
	struct pqcp_fleet_admission_subject *subject;
	int index;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    subject_id == NULL || cost == 0U || bytes == 0U ||
	    now_ms == 0U ||
	    cost > controller->policy.maximum_cost_per_request ||
	    bytes > controller->policy.maximum_bytes_per_window) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = subject_index(controller, subject_id);
	if (index < 0) {
		ret = initialize_subject(
			controller, subject_id, now_ms, &subject);
		if (ret != 0) {
			(void)k_mutex_unlock(&controller->lock);
			return ret;
		}
	} else {
		subject = &controller->subjects[index];
	}
	refill_subject(controller, subject, now_ms);
	if (subject->blocked_until_ms > now_ms ||
	    subject->concurrent >=
		    controller->policy.maximum_concurrent ||
	    subject->tokens < cost ||
	    bytes > controller->policy.maximum_bytes_per_window -
			    subject->bytes_in_window) {
		subject->rejected++;
		(void)k_mutex_unlock(&controller->lock);
		return -EAGAIN;
	}
	subject->tokens -= cost;
	subject->bytes_in_window += bytes;
	subject->concurrent++;
	subject->accepted++;
	(void)k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_fleet_admission_complete(
	struct pqcp_fleet_admission_controller *controller,
	const char *subject_id,
	bool success,
	uint64_t now_ms)
{
	struct pqcp_fleet_admission_subject *subject;
	int index;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    subject_id == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = subject_index(controller, subject_id);
	if (index < 0) {
		(void)k_mutex_unlock(&controller->lock);
		return -ENOENT;
	}
	subject = &controller->subjects[index];
	if (subject->concurrent == 0U) {
		(void)k_mutex_unlock(&controller->lock);
		return -EALREADY;
	}
	subject->concurrent--;
	if (success) {
		if (subject->failure_score <=
		    controller->policy.recovery_credit) {
			subject->failure_score = 0U;
		} else {
			subject->failure_score -=
				controller->policy.recovery_credit;
		}
		const uint64_t credit =
			controller->policy.recovery_credit;

		if (credit >=
		    controller->policy.bucket_capacity -
			    subject->tokens) {
			subject->tokens =
				controller->policy.bucket_capacity;
		} else {
			subject->tokens += credit;
		}
	} else {
		if (UINT32_MAX - subject->failure_score <
		    controller->policy.failure_penalty) {
			subject->failure_score = UINT32_MAX;
		} else {
			subject->failure_score +=
				controller->policy.failure_penalty;
		}
		if (subject->failure_score >= 100U) {
			const uint64_t penalty_ms =
				(uint64_t)subject->failure_score *
				controller->policy.refill_interval_ms;

			subject->blocked_until_ms =
				UINT64_MAX - now_ms < penalty_ms ?
					UINT64_MAX :
					now_ms + penalty_ms;
		}
	}
	(void)k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_fleet_admission_block(
	struct pqcp_fleet_admission_controller *controller,
	const char *subject_id,
	uint64_t until_ms)
{
	int index;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    subject_id == NULL || until_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = subject_index(controller, subject_id);
	if (index < 0) {
		(void)k_mutex_unlock(&controller->lock);
		return -ENOENT;
	}
	controller->subjects[index].blocked_until_ms = until_ms;
	controller->subjects[index].rejected++;
	(void)k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_fleet_admission_reset(
	struct pqcp_fleet_admission_controller *controller,
	const char *subject_id,
	uint64_t now_ms)
{
	int index;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    subject_id == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = subject_index(controller, subject_id);
	if (index < 0) {
		(void)k_mutex_unlock(&controller->lock);
		return -ENOENT;
	}
	struct pqcp_fleet_admission_subject *subject =
		&controller->subjects[index];

	subject->tokens = controller->policy.bucket_capacity;
	subject->last_refill_ms = now_ms;
	subject->window_started_ms = now_ms;
	subject->bytes_in_window = 0U;
	subject->failure_score = 0U;
	subject->blocked_until_ms = 0U;
	(void)k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_fleet_admission_tick(
	struct pqcp_fleet_admission_controller *controller,
	uint64_t now_ms,
	uint32_t *refilled_count)
{
	uint32_t refilled = 0U;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    now_ms == 0U || refilled_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < controller->capacity;
	     ++index) {
		struct pqcp_fleet_admission_subject *subject =
			&controller->subjects[index];
		const uint64_t before = subject->tokens;

		if (!subject->occupied) {
			continue;
		}
		refill_subject(controller, subject, now_ms);
		if (subject->tokens > before) {
			refilled++;
		}
		if (subject->blocked_until_ms != 0U &&
		    now_ms >= subject->blocked_until_ms) {
			subject->blocked_until_ms = 0U;
		}
	}
	(void)k_mutex_unlock(&controller->lock);
	*refilled_count = refilled;
	return 0;
}

int pqcp_fleet_admission_audit(
	struct pqcp_fleet_admission_controller *controller)
{
	int ret;

	if (controller == NULL || !controller->initialized ||
	    controller->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    policy_validate(&controller->policy) != 0 ||
	    controller->subjects == NULL ||
	    controller->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&controller->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < controller->capacity;
	     ++index) {
		const struct pqcp_fleet_admission_subject *subject =
			&controller->subjects[index];

		if (!subject->occupied) {
			continue;
		}
		if (subject->schema_version !=
			    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
		    !pqcp_runtime_internal_text_valid(
			    subject->subject_id,
			    sizeof(subject->subject_id)) ||
		    subject->tokens >
			    controller->policy.bucket_capacity ||
		    subject->concurrent >
			    controller->policy.maximum_concurrent ||
		    subject->bytes_in_window >
			    controller->policy.maximum_bytes_per_window ||
		    subject->last_refill_ms == 0U ||
		    subject->window_started_ms == 0U) {
			(void)k_mutex_unlock(&controller->lock);
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < controller->capacity; ++other) {
			if (controller->subjects[other].occupied &&
			    strcmp(
				    controller->subjects[other].subject_id,
				    subject->subject_id) == 0) {
				(void)k_mutex_unlock(&controller->lock);
				return -EEXIST;
			}
		}
	}
	(void)k_mutex_unlock(&controller->lock);
	return 0;
}
