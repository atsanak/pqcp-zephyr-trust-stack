/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Dependency-aware incident response playbook execution.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool action_valid(
	enum pqcp_edge_playbook_action action)
{
	return action > PQCP_EDGE_PLAYBOOK_NONE &&
	       action <= PQCP_EDGE_PLAYBOOK_VERIFY_INTEGRITY;
}

static bool step_state_valid(
	enum pqcp_edge_playbook_step_state state)
{
	return state >= PQCP_EDGE_PLAYBOOK_STEP_PENDING &&
	       state <= PQCP_EDGE_PLAYBOOK_STEP_SKIPPED;
}

static int playbook_index(
	const struct pqcp_edge_playbook_engine *engine,
	uint64_t execution_id)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (engine->playbooks[index].occupied &&
		    engine->playbooks[index].execution_id ==
			    execution_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_playbook_index(
	const struct pqcp_edge_playbook_engine *engine)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (!engine->playbooks[index].occupied ||
		    !engine->playbooks[index].active) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int step_index(
	const struct pqcp_edge_playbook *playbook,
	uint32_t step_id)
{
	for (uint32_t index = 0U;
	     index < playbook->step_count; ++index) {
		if (playbook->steps[index].step_id == step_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static bool dependencies_satisfied(
	const struct pqcp_edge_playbook *playbook,
	const struct pqcp_edge_playbook_step *step)
{
	return (step->dependency_mask &
		~playbook->completed_mask) == 0U;
}

static bool mandatory_failure(
	const struct pqcp_edge_playbook *playbook)
{
	for (uint32_t index = 0U;
	     index < playbook->step_count; ++index) {
		if (playbook->steps[index].mandatory &&
		    (playbook->steps[index].state ==
			     PQCP_EDGE_PLAYBOOK_STEP_FAILED ||
		     playbook->steps[index].state ==
			     PQCP_EDGE_PLAYBOOK_STEP_SKIPPED)) {
			return true;
		}
	}
	return false;
}

/*
 * Skip every not-yet-started step that (transitively) depends on a step
 * that failed terminally or was itself skipped; such a step can never
 * become runnable.
 */
static void skip_blocked_dependents(
	struct pqcp_edge_playbook *playbook,
	uint64_t now_ms)
{
	bool changed;

	do {
		uint32_t dead = playbook->failed_mask;

		changed = false;
		for (uint32_t index = 0U;
		     index < playbook->step_count; ++index) {
			if (playbook->steps[index].state ==
			    PQCP_EDGE_PLAYBOOK_STEP_SKIPPED) {
				dead |= 1U << index;
			}
		}
		for (uint32_t index = 0U;
		     index < playbook->step_count; ++index) {
			struct pqcp_edge_playbook_step *step =
				&playbook->steps[index];

			if ((step->state ==
				     PQCP_EDGE_PLAYBOOK_STEP_PENDING ||
			     step->state ==
				     PQCP_EDGE_PLAYBOOK_STEP_READY) &&
			    (step->dependency_mask & dead) != 0U) {
				step->state =
					PQCP_EDGE_PLAYBOOK_STEP_SKIPPED;
				step->completed_at_ms = now_ms;
				changed = true;
			}
		}
	} while (changed);
}

static bool all_steps_terminal(
	const struct pqcp_edge_playbook *playbook)
{
	for (uint32_t index = 0U;
	     index < playbook->step_count; ++index) {
		enum pqcp_edge_playbook_step_state state =
			playbook->steps[index].state;

		if (state != PQCP_EDGE_PLAYBOOK_STEP_SUCCEEDED &&
		    state != PQCP_EDGE_PLAYBOOK_STEP_FAILED &&
		    state != PQCP_EDGE_PLAYBOOK_STEP_SKIPPED) {
			return false;
		}
	}
	return true;
}

static int validate_steps(
	const struct pqcp_edge_playbook_step *steps,
	uint32_t step_count)
{
	uint32_t valid_mask;

	if (steps == NULL || step_count == 0U ||
	    step_count > PQCP_EDGE_MAX_PLAYBOOK_STEPS) {
		return -EINVAL;
	}
	valid_mask = (1U << step_count) - 1U;
	for (uint32_t index = 0U;
	     index < step_count; ++index) {
		const struct pqcp_edge_playbook_step *step =
			&steps[index];

		if (step->step_id == 0U ||
		    !action_valid(step->action) ||
		    step->maximum_attempts == 0U ||
		    (step->dependency_mask & ~valid_mask) != 0U ||
		    (step->dependency_mask & (1U << index)) != 0U) {
			return -EINVAL;
		}
		for (uint32_t other = index + 1U;
		     other < step_count; ++other) {
			if (steps[other].step_id == step->step_id) {
				return -EEXIST;
			}
		}
	}
	return 0;
}

int pqcp_edge_playbook_engine_init(
	struct pqcp_edge_playbook_engine *engine,
	struct pqcp_edge_playbook *playbooks,
	size_t capacity)
{
	if (engine == NULL || playbooks == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(playbooks, 0,
	       capacity * sizeof(*playbooks));
	engine->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	engine->playbooks = playbooks;
	engine->capacity = capacity;
	engine->next_execution_id = 1U;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_edge_playbook_start(
	struct pqcp_edge_playbook_engine *engine,
	uint64_t incident_id,
	const struct pqcp_edge_playbook_step *steps,
	uint32_t step_count,
	uint64_t now_ms,
	struct pqcp_edge_playbook **playbook)
{
	struct pqcp_edge_playbook candidate;
	int index;
	int ret;

	if (engine == NULL || !engine->initialized ||
	    incident_id == 0U || playbook == NULL) {
		return -EINVAL;
	}
	ret = validate_steps(steps, step_count);
	if (ret != 0) {
		return ret;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = free_playbook_index(engine);
	if (index < 0) {
		*playbook = NULL;
		k_mutex_unlock(&engine->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.execution_id =
		pqcp_edge_internal_next_identifier(
			&engine->next_execution_id);
	candidate.incident_id = incident_id;
	candidate.started_at_ms = now_ms;
	candidate.step_count = step_count;
	candidate.active = true;
	candidate.occupied = true;
	for (uint32_t step = 0U;
	     step < step_count; ++step) {
		candidate.steps[step] = steps[step];
		candidate.steps[step].state =
			candidate.steps[step].
				dependency_mask == 0U ?
				PQCP_EDGE_PLAYBOOK_STEP_READY :
				PQCP_EDGE_PLAYBOOK_STEP_PENDING;
		candidate.steps[step].attempts = 0U;
		candidate.steps[step].started_at_ms = 0U;
		candidate.steps[step].completed_at_ms = 0U;
		candidate.steps[step].retry_at_ms = 0U;
		candidate.steps[step].result = 0;
	}
	engine->playbooks[index] = candidate;
	*playbook = &engine->playbooks[index];
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_edge_playbook_next(
	struct pqcp_edge_playbook_engine *engine,
	uint64_t execution_id,
	uint64_t now_ms,
	struct pqcp_edge_playbook_step **step)
{
	struct pqcp_edge_playbook *playbook;
	struct pqcp_edge_playbook_step *selected = NULL;
	uint32_t selected_index = 0U;
	int index;

	if (engine == NULL || !engine->initialized ||
	    execution_id == 0U || step == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = playbook_index(engine, execution_id);
	if (index < 0) {
		*step = NULL;
		k_mutex_unlock(&engine->lock);
		return index;
	}
	playbook = &engine->playbooks[index];
	if (!playbook->active) {
		*step = NULL;
		k_mutex_unlock(&engine->lock);
		return -EALREADY;
	}
	for (uint32_t current = 0U;
	     current < playbook->step_count; ++current) {
		struct pqcp_edge_playbook_step *candidate =
			&playbook->steps[current];

		if (candidate->state ==
			    PQCP_EDGE_PLAYBOOK_STEP_PENDING &&
		    dependencies_satisfied(
			    playbook, candidate)) {
			candidate->state =
				PQCP_EDGE_PLAYBOOK_STEP_READY;
		}
		if (candidate->state !=
			    PQCP_EDGE_PLAYBOOK_STEP_READY ||
		    candidate->retry_at_ms > now_ms) {
			continue;
		}
		if (selected == NULL ||
		    candidate->mandatory > selected->mandatory ||
		    (candidate->mandatory == selected->mandatory &&
		     candidate->step_id < selected->step_id)) {
			selected = candidate;
			selected_index = current;
		}
	}
	if (selected == NULL) {
		*step = NULL;
		k_mutex_unlock(&engine->lock);
		return -EAGAIN;
	}
	selected->state = PQCP_EDGE_PLAYBOOK_STEP_RUNNING;
	selected->started_at_ms = now_ms;
	selected->attempts =
		pqcp_edge_internal_saturating_add_u32(
			selected->attempts, 1U);
	playbook->completed_mask &=
		~(1U << selected_index);
	*step = selected;
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_edge_playbook_complete_step(
	struct pqcp_edge_playbook_engine *engine,
	uint64_t execution_id,
	uint32_t step_id,
	int result,
	uint64_t now_ms)
{
	struct pqcp_edge_playbook *playbook;
	struct pqcp_edge_playbook_step *step;
	int playbook_slot;
	int step_slot;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    execution_id == 0U || step_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	playbook_slot = playbook_index(
		engine, execution_id);
	if (playbook_slot < 0) {
		ret = playbook_slot;
		goto out;
	}
	playbook = &engine->playbooks[playbook_slot];
	step_slot = step_index(playbook, step_id);
	if (step_slot < 0) {
		ret = step_slot;
		goto out;
	}
	step = &playbook->steps[step_slot];
	if (step->state !=
	    PQCP_EDGE_PLAYBOOK_STEP_RUNNING) {
		ret = -EALREADY;
		goto out;
	}
	step->completed_at_ms = now_ms;
	step->result = result;
	if (result == 0) {
		step->state =
			PQCP_EDGE_PLAYBOOK_STEP_SUCCEEDED;
		playbook->completed_mask |=
			1U << step_slot;
	} else if (step->attempts <
		   step->maximum_attempts) {
		step->state =
			PQCP_EDGE_PLAYBOOK_STEP_READY;
		step->retry_at_ms =
			pqcp_edge_internal_saturating_add_u64(
				now_ms,
				pqcp_edge_internal_backoff(
					250U, 60000U,
					step->attempts));
	} else {
		step->state =
			PQCP_EDGE_PLAYBOOK_STEP_FAILED;
		playbook->failed_mask |= 1U << step_slot;
		skip_blocked_dependents(playbook, now_ms);
	}
	if (all_steps_terminal(playbook)) {
		playbook->active = false;
		playbook->completed_at_ms = now_ms;
		if (mandatory_failure(playbook)) {
			++engine->failed_count;
		} else {
			++engine->completed_count;
		}
	}
out:
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_playbook_retry_step(
	struct pqcp_edge_playbook_engine *engine,
	uint64_t execution_id,
	uint32_t step_id,
	uint64_t retry_at_ms)
{
	struct pqcp_edge_playbook_step *step;
	int playbook_slot;
	int step_slot;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    execution_id == 0U || step_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	playbook_slot = playbook_index(
		engine, execution_id);
	if (playbook_slot < 0) {
		ret = playbook_slot;
		goto out;
	}
	step_slot = step_index(
		&engine->playbooks[playbook_slot], step_id);
	if (step_slot < 0) {
		ret = step_slot;
		goto out;
	}
	step = &engine->playbooks[playbook_slot].
		steps[step_slot];
	if (step->state !=
		    PQCP_EDGE_PLAYBOOK_STEP_FAILED &&
	    step->state !=
		    PQCP_EDGE_PLAYBOOK_STEP_READY) {
		ret = -EALREADY;
	} else if (step->attempts >=
		   step->maximum_attempts) {
		ret = -EOVERFLOW;
	} else {
		step->state =
			PQCP_EDGE_PLAYBOOK_STEP_READY;
		step->retry_at_ms = retry_at_ms;
		engine->playbooks[playbook_slot].
			failed_mask &= ~(1U << step_slot);
	}
out:
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_playbook_engine_audit(
	struct pqcp_edge_playbook_engine *engine)
{
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    engine->playbooks == NULL ||
	    engine->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_playbook *playbook =
			&engine->playbooks[index];

		if (!playbook->occupied) {
			continue;
		}
		if (playbook->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    playbook->execution_id == 0U ||
		    playbook->incident_id == 0U ||
		    playbook->step_count == 0U ||
		    playbook->step_count >
			    PQCP_EDGE_MAX_PLAYBOOK_STEPS ||
		    (playbook->active &&
		     playbook->completed_at_ms != 0U) ||
		    (!playbook->active &&
		     !all_steps_terminal(playbook))) {
			ret = -EBADMSG;
			break;
		}
		for (uint32_t step = 0U;
		     step < playbook->step_count; ++step) {
			const struct pqcp_edge_playbook_step *entry =
				&playbook->steps[step];

			if (entry->step_id == 0U ||
			    !action_valid(entry->action) ||
			    !step_state_valid(entry->state) ||
			    entry->maximum_attempts == 0U ||
			    entry->attempts >
				    entry->maximum_attempts) {
				ret = -EBADMSG;
				break;
			}
		}
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}
