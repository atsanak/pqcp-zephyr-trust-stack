/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free continuity exercise planning and objective accounting.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"

static const uint8_t exercise_step_domain[] =
	"pqcp.sovereign.continuity.exercise.step.v1";
static const uint8_t exercise_complete_domain[] =
	"pqcp.sovereign.continuity.exercise.complete.v1";

static bool digest_valid(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	if (digest == NULL) {
		return false;
	}
	for (size_t index = 0U;
	     index < PQCP_SOVEREIGN_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate != 0U;
}

static uint64_t add_u64(uint64_t left, uint64_t right)
{
	return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

static uint32_t required_mask(uint32_t required_steps)
{
	return required_steps == 32U ?
		UINT32_MAX :
		(1U << required_steps) - 1U;
}

static uint32_t bit_count(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += value & 1U;
		value >>= 1U;
	}
	return count;
}

static bool terminal_state(
	enum pqcp_sovereign_lifecycle_state state)
{
	return state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
	       state == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
}

static bool exercise_shape_valid(
	const struct pqcp_sovereign_continuity_exercise *exercise)
{
	uint32_t mask;

	if (exercise == NULL || !exercise->occupied ||
	    exercise->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    exercise->exercise_id == 0U ||
	    !pqcp_runtime_internal_text_valid(
		    exercise->service_id, sizeof(exercise->service_id)) ||
	    !pqcp_runtime_internal_text_valid(
		    exercise->scenario, sizeof(exercise->scenario)) ||
	    exercise->planned_at_ms == 0U ||
	    exercise->policy_epoch == 0U ||
	    exercise->required_steps == 0U ||
	    exercise->required_steps > 32U ||
	    exercise->maximum_failures == 0U ||
	    exercise->maximum_failures > exercise->required_steps ||
	    exercise->recovery_time_objective_ms == 0U ||
	    exercise->recovery_point_objective_ms == 0U) {
		return false;
	}
	mask = required_mask(exercise->required_steps);
	if ((exercise->completed_steps & ~mask) != 0U ||
	    (exercise->failed_steps & ~mask) != 0U ||
	    (exercise->completed_steps & exercise->failed_steps) != 0U ||
	    bit_count(exercise->failed_steps) >
		    exercise->maximum_failures) {
		return false;
	}
	switch (exercise->state) {
	case PQCP_SOVEREIGN_LIFECYCLE_DRAFT:
		return exercise->started_at_ms == 0U &&
		       exercise->completed_at_ms == 0U &&
		       exercise->completed_steps == 0U &&
		       exercise->failed_steps == 0U &&
		       exercise->observed_recovery_time_ms == 0U &&
		       exercise->observed_data_loss_ms == 0U;
	case PQCP_SOVEREIGN_LIFECYCLE_ACTIVE:
		return exercise->started_at_ms >=
			       exercise->planned_at_ms &&
		       exercise->completed_at_ms == 0U;
	case PQCP_SOVEREIGN_LIFECYCLE_RETIRED:
		return exercise->started_at_ms >=
			       exercise->planned_at_ms &&
		       exercise->completed_at_ms >=
			       exercise->started_at_ms &&
		       (exercise->completed_steps |
			exercise->failed_steps) == mask &&
		       bit_count(exercise->failed_steps) <
			       exercise->maximum_failures &&
		       exercise->observed_recovery_time_ms <=
			       exercise->recovery_time_objective_ms &&
		       exercise->observed_data_loss_ms <=
			       exercise->recovery_point_objective_ms &&
		       digest_valid(exercise->evidence_digest);
	case PQCP_SOVEREIGN_LIFECYCLE_REVOKED:
		return exercise->started_at_ms >=
			       exercise->planned_at_ms &&
		       exercise->completed_at_ms >=
			       exercise->started_at_ms &&
		       digest_valid(exercise->evidence_digest);
	default:
		return false;
	}
}

static int exercise_index_locked(
	const struct pqcp_sovereign_continuity_exerciser *exerciser,
	uint64_t exercise_id)
{
	for (size_t index = 0U; index < exerciser->capacity; ++index) {
		if (exerciser->exercises[index].occupied &&
		    exerciser->exercises[index].exercise_id ==
			    exercise_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int reusable_index_locked(
	const struct pqcp_sovereign_continuity_exerciser *exerciser)
{
	int oldest = -1;
	uint64_t oldest_time = UINT64_MAX;

	for (size_t index = 0U; index < exerciser->capacity; ++index) {
		const struct pqcp_sovereign_continuity_exercise *entry =
			&exerciser->exercises[index];

		if (!entry->occupied) {
			return (int)index;
		}
		if (terminal_state(entry->state) &&
		    entry->completed_at_ms < oldest_time) {
			oldest = (int)index;
			oldest_time = entry->completed_at_ms;
		}
	}
	return oldest >= 0 ? oldest : -ENOSPC;
}

static int active_service_index_locked(
	const struct pqcp_sovereign_continuity_exerciser *exerciser,
	const char *service_id)
{
	for (size_t index = 0U; index < exerciser->capacity; ++index) {
		const struct pqcp_sovereign_continuity_exercise *entry =
			&exerciser->exercises[index];

		if (entry->occupied &&
		    (entry->state == PQCP_SOVEREIGN_LIFECYCLE_DRAFT ||
		     entry->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) &&
		    strcmp(entry->service_id, service_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int next_exercise_id_locked(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	uint64_t *exercise_id)
{
	if (exerciser->next_exercise_id == 0U ||
	    exerciser->next_exercise_id == UINT64_MAX) {
		return -EOVERFLOW;
	}
	*exercise_id = exerciser->next_exercise_id++;
	return 0;
}

static int update_step_evidence(
	struct pqcp_sovereign_continuity_exercise *exercise,
	uint32_t step,
	bool success,
	const uint8_t external[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t numeric[28];
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	const uint8_t *parts[7];
	size_t lengths[7];
	int ret;

	pqcp_runtime_internal_write_u64(numeric, exercise->exercise_id);
	pqcp_runtime_internal_write_u64(
		numeric + 8U, exercise->policy_epoch);
	pqcp_runtime_internal_write_u32(numeric + 16U, step);
	pqcp_runtime_internal_write_u32(
		numeric + 20U, success ? 1U : 0U);
	pqcp_runtime_internal_write_u32(
		numeric + 24U,
		exercise->completed_steps ^ exercise->failed_steps);
	parts[0] = exercise_step_domain;
	lengths[0] = sizeof(exercise_step_domain) - 1U;
	parts[1] = (const uint8_t *)exercise->service_id;
	lengths[1] = strlen(exercise->service_id);
	parts[2] = (const uint8_t *)exercise->scenario;
	lengths[2] = strlen(exercise->scenario);
	parts[3] = exercise->evidence_digest;
	lengths[3] = sizeof(exercise->evidence_digest);
	parts[4] = external;
	lengths[4] = PQCP_SOVEREIGN_DIGEST_BYTES;
	parts[5] = numeric;
	lengths[5] = sizeof(numeric);
	parts[6] = (const uint8_t *)&exercise->state;
	lengths[6] = sizeof(exercise->state);
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, 7U, digest);
	if (ret == 0) {
		memcpy(exercise->evidence_digest, digest,
		       sizeof(exercise->evidence_digest));
	}
	return ret;
}

static int update_completion_evidence(
	struct pqcp_sovereign_continuity_exercise *exercise,
	bool objectives_met)
{
	uint8_t numeric[68];
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	const uint8_t *parts[5];
	size_t lengths[5];
	int ret;

	pqcp_runtime_internal_write_u64(numeric, exercise->exercise_id);
	pqcp_runtime_internal_write_u64(
		numeric + 8U, exercise->started_at_ms);
	pqcp_runtime_internal_write_u64(
		numeric + 16U, exercise->completed_at_ms);
	pqcp_runtime_internal_write_u64(
		numeric + 24U, exercise->observed_recovery_time_ms);
	pqcp_runtime_internal_write_u64(
		numeric + 32U, exercise->observed_data_loss_ms);
	pqcp_runtime_internal_write_u64(
		numeric + 40U, exercise->recovery_time_objective_ms);
	pqcp_runtime_internal_write_u64(
		numeric + 48U, exercise->recovery_point_objective_ms);
	pqcp_runtime_internal_write_u32(
		numeric + 56U, exercise->completed_steps);
	pqcp_runtime_internal_write_u32(
		numeric + 60U, exercise->failed_steps);
	pqcp_runtime_internal_write_u32(
		numeric + 64U, objectives_met ? 1U : 0U);
	parts[0] = exercise_complete_domain;
	lengths[0] = sizeof(exercise_complete_domain) - 1U;
	parts[1] = (const uint8_t *)exercise->service_id;
	lengths[1] = strlen(exercise->service_id);
	parts[2] = (const uint8_t *)exercise->scenario;
	lengths[2] = strlen(exercise->scenario);
	parts[3] = exercise->evidence_digest;
	lengths[3] = sizeof(exercise->evidence_digest);
	parts[4] = numeric;
	lengths[4] = sizeof(numeric);
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, 5U, digest);
	if (ret == 0) {
		memcpy(exercise->evidence_digest, digest,
		       sizeof(exercise->evidence_digest));
	}
	return ret;
}

int pqcp_sovereign_continuity_exerciser_init(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	struct pqcp_sovereign_continuity_exercise *exercises,
	size_t capacity)
{
	if (exerciser == NULL || exercises == NULL ||
	    capacity == 0U || capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(exerciser, 0, sizeof(*exerciser));
	memset(exercises, 0, capacity * sizeof(exercises[0]));
	exerciser->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	exerciser->exercises = exercises;
	exerciser->capacity = capacity;
	exerciser->next_exercise_id = 1U;
	k_mutex_init(&exerciser->lock);
	exerciser->initialized = true;
	return 0;
}

int pqcp_sovereign_continuity_exercise_plan(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	const char *service_id,
	const char *scenario,
	uint32_t required_steps,
	uint32_t maximum_failures,
	uint64_t recovery_time_objective_ms,
	uint64_t recovery_point_objective_ms,
	uint64_t policy_epoch,
	uint64_t now_ms,
	struct pqcp_sovereign_continuity_exercise **exercise)
{
	struct pqcp_sovereign_continuity_exercise candidate;
	int slot;
	int ret;

	if (exerciser == NULL || !exerciser->initialized ||
	    exercise == NULL ||
	    !pqcp_runtime_internal_text_valid(
		    service_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_runtime_internal_text_valid(
		    scenario, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    required_steps == 0U || required_steps > 32U ||
	    maximum_failures == 0U ||
	    maximum_failures > required_steps ||
	    recovery_time_objective_ms == 0U ||
	    recovery_point_objective_ms == 0U ||
	    policy_epoch == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	*exercise = NULL;
	k_mutex_lock(&exerciser->lock, K_FOREVER);
	slot = active_service_index_locked(exerciser, service_id);
	if (slot >= 0) {
		k_mutex_unlock(&exerciser->lock);
		return -EBUSY;
	}
	slot = reusable_index_locked(exerciser);
	if (slot < 0) {
		k_mutex_unlock(&exerciser->lock);
		return slot;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	ret = next_exercise_id_locked(
		exerciser, &candidate.exercise_id);
	if (ret == 0) {
		ret = pqcp_runtime_internal_copy_text(
			candidate.service_id,
			sizeof(candidate.service_id), service_id);
	}
	if (ret == 0) {
		ret = pqcp_runtime_internal_copy_text(
			candidate.scenario,
			sizeof(candidate.scenario), scenario);
	}
	if (ret != 0) {
		k_mutex_unlock(&exerciser->lock);
		return ret;
	}
	candidate.planned_at_ms = now_ms;
	candidate.policy_epoch = policy_epoch;
	candidate.required_steps = required_steps;
	candidate.maximum_failures = maximum_failures;
	candidate.recovery_time_objective_ms =
		recovery_time_objective_ms;
	candidate.recovery_point_objective_ms =
		recovery_point_objective_ms;
	candidate.state = PQCP_SOVEREIGN_LIFECYCLE_DRAFT;
	candidate.occupied = true;
	exerciser->exercises[slot] = candidate;
	*exercise = &exerciser->exercises[slot];
	k_mutex_unlock(&exerciser->lock);
	return 0;
}

int pqcp_sovereign_continuity_exercise_start(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	uint64_t exercise_id,
	uint64_t now_ms)
{
	struct pqcp_sovereign_continuity_exercise *exercise;
	int index;
	int ret = 0;

	if (exerciser == NULL || !exerciser->initialized ||
	    exercise_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&exerciser->lock, K_FOREVER);
	index = exercise_index_locked(exerciser, exercise_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	exercise = &exerciser->exercises[index];
	if (exercise->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = -EALREADY;
	} else if (exercise->state !=
		   PQCP_SOVEREIGN_LIFECYCLE_DRAFT) {
		ret = -EPERM;
	} else if (now_ms < exercise->planned_at_ms) {
		ret = -ETIME;
	} else {
		exercise->started_at_ms = now_ms;
		exercise->state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	}
out:
	k_mutex_unlock(&exerciser->lock);
	return ret;
}

int pqcp_sovereign_continuity_exercise_record_step(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	uint64_t exercise_id,
	uint32_t step,
	bool success,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	struct pqcp_sovereign_continuity_exercise *exercise;
	uint32_t bit;
	int index;
	int ret = 0;

	if (exerciser == NULL || !exerciser->initialized ||
	    exercise_id == 0U ||
	    !digest_valid(evidence_digest)) {
		return -EINVAL;
	}
	k_mutex_lock(&exerciser->lock, K_FOREVER);
	index = exercise_index_locked(exerciser, exercise_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	exercise = &exerciser->exercises[index];
	if (exercise->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = terminal_state(exercise->state) ?
			-EALREADY : -EPERM;
		goto out;
	}
	if (step >= exercise->required_steps) {
		ret = -ERANGE;
		goto out;
	}
	bit = 1U << step;
	if (((exercise->completed_steps |
	      exercise->failed_steps) & bit) != 0U) {
		ret = -EALREADY;
		goto out;
	}
	if (success) {
		exercise->completed_steps |= bit;
	} else {
		exercise->failed_steps |= bit;
	}
	ret = update_step_evidence(
		exercise, step, success, evidence_digest);
	if (ret != 0) {
		exercise->completed_steps &= ~bit;
		exercise->failed_steps &= ~bit;
		goto out;
	}
	if (!success &&
	    bit_count(exercise->failed_steps) >=
		    exercise->maximum_failures) {
		exercise->state = PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
		exercise->completed_at_ms = add_u64(
			exercise->started_at_ms,
			exercise->recovery_time_objective_ms);
		exerciser->failure_count =
			add_u64(exerciser->failure_count, 1U);
	}
out:
	k_mutex_unlock(&exerciser->lock);
	return ret;
}

int pqcp_sovereign_continuity_exercise_complete(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	uint64_t exercise_id,
	uint64_t observed_recovery_time_ms,
	uint64_t observed_data_loss_ms,
	uint64_t now_ms)
{
	struct pqcp_sovereign_continuity_exercise *exercise;
	uint32_t observed_steps;
	bool objectives_met;
	int index;
	int ret = 0;

	if (exerciser == NULL || !exerciser->initialized ||
	    exercise_id == 0U ||
	    observed_recovery_time_ms == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&exerciser->lock, K_FOREVER);
	index = exercise_index_locked(exerciser, exercise_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	exercise = &exerciser->exercises[index];
	if (exercise->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = terminal_state(exercise->state) ?
			-EALREADY : -EPERM;
		goto out;
	}
	if (now_ms < exercise->started_at_ms ||
	    observed_recovery_time_ms >
		    now_ms - exercise->started_at_ms) {
		ret = -ETIME;
		goto out;
	}
	observed_steps =
		exercise->completed_steps | exercise->failed_steps;
	if (observed_steps != required_mask(exercise->required_steps)) {
		ret = -EAGAIN;
		goto out;
	}
	exercise->completed_at_ms = now_ms;
	exercise->observed_recovery_time_ms =
		observed_recovery_time_ms;
	exercise->observed_data_loss_ms = observed_data_loss_ms;
	objectives_met =
		observed_recovery_time_ms <=
			exercise->recovery_time_objective_ms &&
		observed_data_loss_ms <=
			exercise->recovery_point_objective_ms &&
		bit_count(exercise->failed_steps) <
			exercise->maximum_failures;
	ret = update_completion_evidence(
		exercise, objectives_met);
	if (ret != 0) {
		exercise->completed_at_ms = 0U;
		exercise->observed_recovery_time_ms = 0U;
		exercise->observed_data_loss_ms = 0U;
		goto out;
	}
	if (objectives_met) {
		exercise->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		exerciser->success_count =
			add_u64(exerciser->success_count, 1U);
	} else {
		exercise->state = PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
		exerciser->failure_count =
			add_u64(exerciser->failure_count, 1U);
		ret = -ERANGE;
	}
out:
	k_mutex_unlock(&exerciser->lock);
	return ret;
}

int pqcp_sovereign_continuity_exerciser_audit(
	struct pqcp_sovereign_continuity_exerciser *exerciser)
{
	uint64_t maximum_id = 0U;
	uint64_t resident_successes = 0U;
	uint64_t resident_failures = 0U;
	int ret = 0;

	if (exerciser == NULL || !exerciser->initialized ||
	    exerciser->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    exerciser->exercises == NULL ||
	    exerciser->capacity == 0U ||
	    exerciser->next_exercise_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&exerciser->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < exerciser->capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_continuity_exercise *entry =
			&exerciser->exercises[index];

		if (!entry->occupied) {
			continue;
		}
		if (!exercise_shape_valid(entry)) {
			ret = -EBADMSG;
			break;
		}
		if (entry->exercise_id > maximum_id) {
			maximum_id = entry->exercise_id;
		}
		if (entry->state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED) {
			resident_successes =
				add_u64(resident_successes, 1U);
		} else if (entry->state ==
			   PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
			resident_failures =
				add_u64(resident_failures, 1U);
		}
		for (size_t other = index + 1U;
		     other < exerciser->capacity; ++other) {
			const struct pqcp_sovereign_continuity_exercise
				*peer = &exerciser->exercises[other];

			if (!peer->occupied) {
				continue;
			}
			if (peer->exercise_id == entry->exercise_id) {
				ret = -EEXIST;
				break;
			}
			if (!terminal_state(entry->state) &&
			    !terminal_state(peer->state) &&
			    strcmp(peer->service_id,
				   entry->service_id) == 0) {
				ret = -EBUSY;
				break;
			}
		}
	}
	if (ret == 0 && maximum_id != 0U &&
	    exerciser->next_exercise_id <= maximum_id) {
		ret = -EBADMSG;
	}
	if (ret == 0 &&
	    (exerciser->success_count < resident_successes ||
	     exerciser->failure_count < resident_failures)) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&exerciser->lock);
	return ret;
}
