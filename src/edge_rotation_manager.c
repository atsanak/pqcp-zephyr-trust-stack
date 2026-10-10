/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Coordinated secret rotation with overlap and retirement.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool state_valid(enum pqcp_edge_rotation_state state)
{
	return state >= PQCP_EDGE_ROTATION_EMPTY &&
	       state <= PQCP_EDGE_ROTATION_FAILED;
}

static int rotation_index(
	const struct pqcp_edge_rotation_manager *manager,
	uint64_t rotation_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->rotations[index].occupied &&
		    manager->rotations[index].rotation_id ==
			    rotation_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_rotation_index(
	const struct pqcp_edge_rotation_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->rotations[index].occupied ||
		    manager->rotations[index].state ==
			    PQCP_EDGE_ROTATION_COMPLETED ||
		    manager->rotations[index].state ==
			    PQCP_EDGE_ROTATION_FAILED) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool transition_allowed(
	enum pqcp_edge_rotation_state current,
	enum pqcp_edge_rotation_state next)
{
	switch (current) {
	case PQCP_EDGE_ROTATION_PLANNED:
		return next == PQCP_EDGE_ROTATION_GENERATING ||
		       next == PQCP_EDGE_ROTATION_FAILED;
	case PQCP_EDGE_ROTATION_GENERATING:
		return next ==
			       PQCP_EDGE_ROTATION_DISTRIBUTING ||
		       next == PQCP_EDGE_ROTATION_FAILED;
	case PQCP_EDGE_ROTATION_DISTRIBUTING:
		return next == PQCP_EDGE_ROTATION_OVERLAP ||
		       next == PQCP_EDGE_ROTATION_FAILED;
	case PQCP_EDGE_ROTATION_OVERLAP:
		return next == PQCP_EDGE_ROTATION_RETIRING ||
		       next == PQCP_EDGE_ROTATION_FAILED;
	case PQCP_EDGE_ROTATION_RETIRING:
		return next == PQCP_EDGE_ROTATION_COMPLETED ||
		       next == PQCP_EDGE_ROTATION_FAILED;
	default:
		return false;
	}
}

int pqcp_edge_rotation_manager_init(
	struct pqcp_edge_rotation_manager *manager,
	struct pqcp_edge_secret_rotation *rotations,
	size_t capacity)
{
	if (manager == NULL || rotations == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(rotations, 0,
	       capacity * sizeof(*rotations));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->rotations = rotations;
	manager->capacity = capacity;
	manager->next_rotation_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_rotation_plan(
	struct pqcp_edge_rotation_manager *manager,
	const char *secret_id,
	uint64_t current_epoch,
	uint64_t target_epoch,
	const uint8_t current_digest[PQCP_EDGE_DIGEST_BYTES],
	const uint8_t target_digest[PQCP_EDGE_DIGEST_BYTES],
	uint32_t target_count,
	uint32_t maximum_failures,
	uint64_t now_ms,
	uint64_t overlap_until_ms,
	uint64_t deadline_ms,
	struct pqcp_edge_secret_rotation **rotation)
{
	struct pqcp_edge_secret_rotation candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_edge_internal_text_valid(
		    secret_id, PQCP_EDGE_OBJECT_MAX_CHARS) ||
	    current_epoch == 0U || target_epoch <= current_epoch ||
	    current_digest == NULL || target_digest == NULL ||
	    pqcp_edge_internal_all_zero(
		    current_digest, PQCP_EDGE_DIGEST_BYTES) ||
	    pqcp_edge_internal_all_zero(
		    target_digest, PQCP_EDGE_DIGEST_BYTES) ||
	    pqcp_edge_internal_equal(
		    current_digest, target_digest,
		    PQCP_EDGE_DIGEST_BYTES) ||
	    target_count == 0U || maximum_failures == 0U ||
	    overlap_until_ms <= now_ms ||
	    deadline_ms <= overlap_until_ms || rotation == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = free_rotation_index(manager);
	if (index < 0) {
		*rotation = NULL;
		k_mutex_unlock(&manager->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.rotation_id =
		pqcp_edge_internal_next_identifier(
			&manager->next_rotation_id);
	ret = pqcp_edge_internal_copy_text(
		candidate.secret_id,
		sizeof(candidate.secret_id), secret_id);
	candidate.current_epoch = current_epoch;
	candidate.target_epoch = target_epoch;
	candidate.started_at_ms = now_ms;
	candidate.overlap_until_ms = overlap_until_ms;
	candidate.deadline_ms = deadline_ms;
	candidate.target_count = target_count;
	candidate.maximum_failures = maximum_failures;
	candidate.state = PQCP_EDGE_ROTATION_PLANNED;
	memcpy(candidate.current_digest, current_digest,
	       sizeof(candidate.current_digest));
	memcpy(candidate.target_digest, target_digest,
	       sizeof(candidate.target_digest));
	candidate.occupied = true;
	if (ret == 0) {
		manager->rotations[index] = candidate;
		*rotation = &manager->rotations[index];
	} else {
		*rotation = NULL;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_rotation_transition(
	struct pqcp_edge_rotation_manager *manager,
	uint64_t rotation_id,
	enum pqcp_edge_rotation_state state,
	uint64_t now_ms)
{
	struct pqcp_edge_secret_rotation *rotation;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    rotation_id == 0U || !state_valid(state) ||
	    state == PQCP_EDGE_ROTATION_EMPTY) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = rotation_index(manager, rotation_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	rotation = &manager->rotations[index];
	if (!transition_allowed(rotation->state, state)) {
		ret = rotation->state == state ?
			-EALREADY : -EPERM;
		goto out;
	}
	if (state == PQCP_EDGE_ROTATION_OVERLAP &&
	    rotation->acknowledged_count +
			    rotation->failure_count <
		    rotation->target_count) {
		ret = -EAGAIN;
		goto out;
	}
	if (state == PQCP_EDGE_ROTATION_RETIRING &&
	    now_ms < rotation->overlap_until_ms) {
		ret = -EAGAIN;
		goto out;
	}
	rotation->state = state;
	if (state == PQCP_EDGE_ROTATION_COMPLETED) {
		++manager->completed_count;
	} else if (state == PQCP_EDGE_ROTATION_FAILED) {
		++manager->failed_count;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_rotation_acknowledge(
	struct pqcp_edge_rotation_manager *manager,
	uint64_t rotation_id,
	bool success,
	uint64_t now_ms)
{
	struct pqcp_edge_secret_rotation *rotation;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    rotation_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = rotation_index(manager, rotation_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	rotation = &manager->rotations[index];
	if (rotation->state !=
	    PQCP_EDGE_ROTATION_DISTRIBUTING) {
		ret = -EALREADY;
	} else if (rotation->acknowledged_count +
			   rotation->failure_count >=
		   rotation->target_count) {
		ret = -EDQUOT;
	} else if (success) {
		++rotation->acknowledged_count;
	} else {
		++rotation->failure_count;
		if (rotation->failure_count >=
		    rotation->maximum_failures) {
			rotation->state =
				PQCP_EDGE_ROTATION_FAILED;
			++manager->failed_count;
		}
	}
	if (ret == 0 && now_ms >= rotation->deadline_ms) {
		rotation->state = PQCP_EDGE_ROTATION_FAILED;
		++manager->failed_count;
		ret = -ETIMEDOUT;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_rotation_tick(
	struct pqcp_edge_rotation_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (manager == NULL || !manager->initialized ||
	    changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_edge_secret_rotation *rotation =
			&manager->rotations[index];

		if (!rotation->occupied ||
		    rotation->state ==
			    PQCP_EDGE_ROTATION_COMPLETED ||
		    rotation->state ==
			    PQCP_EDGE_ROTATION_FAILED) {
			continue;
		}
		if (now_ms >= rotation->deadline_ms) {
			rotation->state =
				PQCP_EDGE_ROTATION_FAILED;
			++manager->failed_count;
			++changed;
		} else if (rotation->state ==
			   PQCP_EDGE_ROTATION_OVERLAP &&
			   now_ms >= rotation->overlap_until_ms) {
			rotation->state =
				PQCP_EDGE_ROTATION_RETIRING;
			++changed;
		}
	}
	k_mutex_unlock(&manager->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_edge_rotation_manager_audit(
	struct pqcp_edge_rotation_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->rotations == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_secret_rotation *rotation =
			&manager->rotations[index];

		if (!rotation->occupied) {
			continue;
		}
		if (rotation->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    rotation->rotation_id == 0U ||
		    !pqcp_edge_internal_text_valid(
			    rotation->secret_id,
			    sizeof(rotation->secret_id)) ||
		    rotation->target_epoch <=
			    rotation->current_epoch ||
		    rotation->overlap_until_ms <=
			    rotation->started_at_ms ||
		    rotation->deadline_ms <=
			    rotation->overlap_until_ms ||
		    rotation->target_count == 0U ||
		    rotation->acknowledged_count +
			    rotation->failure_count >
			    rotation->target_count ||
		    !state_valid(rotation->state) ||
		    rotation->state ==
			    PQCP_EDGE_ROTATION_EMPTY) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
