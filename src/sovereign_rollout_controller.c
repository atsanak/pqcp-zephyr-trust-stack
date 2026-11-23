/*
 * SPDX-License-Identifier: MIT
 *
 * Guarded sovereign deployment-ring rollout control.
 */

#include <errno.h>
#include <string.h>

#include "sovereign_policy_internal.h"

static uint32_t popcount64(uint64_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += (uint32_t)(value & 1U);
		value >>= 1U;
	}
	return count;
}

static bool lifecycle_state_valid(
	enum pqcp_sovereign_lifecycle_state state)
{
	return state >= PQCP_SOVEREIGN_LIFECYCLE_DRAFT &&
	       state <= PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
}

static bool ring_valid(const struct pqcp_sovereign_deployment_ring *ring)
{
	return ring != NULL &&
	       ring->schema_version == PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       ring->generation != 0U &&
	       pqcp_sovereign_policy_text_valid(
		       ring->ring_id, sizeof(ring->ring_id)) &&
	       pqcp_sovereign_policy_text_valid(
		       ring->tenant_id, sizeof(ring->tenant_id)) &&
	       pqcp_sovereign_policy_text_valid(
		       ring->target_zone, sizeof(ring->target_zone)) &&
	       ring->policy_epoch != 0U &&
	       ring->member_mask != 0U &&
	       ring->member_count == popcount64(ring->member_mask) &&
	       ring->maximum_parallel != 0U &&
	       ring->maximum_parallel <= ring->member_count &&
	       ring->minimum_healthy_basis_points <= 10000U &&
	       ring->maximum_failure_basis_points <= 10000U &&
	       ring->minimum_healthy_basis_points +
		       ring->maximum_failure_basis_points <= 20000U &&
	       lifecycle_state_valid(ring->state);
}

static int ring_index(
	const struct pqcp_sovereign_ring_registry *registry,
	const char *ring_id)
{
	for (size_t index = 0U; index < registry->capacity; ++index) {
		if (registry->rings[index].occupied &&
		    strcmp(registry->rings[index].ring_id, ring_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int free_ring_index(
	const struct pqcp_sovereign_ring_registry *registry)
{
	for (size_t index = 0U; index < registry->capacity; ++index) {
		if (!registry->rings[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static int rollout_index(
	const struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id)
{
	for (size_t index = 0U; index < controller->capacity; ++index) {
		if (controller->rollouts[index].occupied &&
		    controller->rollouts[index].rollout_id == rollout_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_rollout_index(
	const struct pqcp_sovereign_rollout_controller *controller)
{
	for (size_t index = 0U; index < controller->capacity; ++index) {
		if (!controller->rollouts[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static uint32_t basis_points(uint32_t numerator, uint32_t denominator)
{
	if (denominator == 0U) {
		return 0U;
	}
	return (uint32_t)(((uint64_t)numerator * 10000U) / denominator);
}

int pqcp_sovereign_ring_registry_init(
	struct pqcp_sovereign_ring_registry *registry,
	struct pqcp_sovereign_deployment_ring *rings,
	size_t capacity)
{
	if (registry == NULL || rings == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(rings, 0, capacity * sizeof(rings[0]));
	registry->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	registry->rings = rings;
	registry->capacity = capacity;
	registry->next_generation = 1U;
	k_mutex_init(&registry->lock);
	registry->initialized = true;
	return 0;
}

int pqcp_sovereign_ring_put(
	struct pqcp_sovereign_ring_registry *registry,
	const struct pqcp_sovereign_deployment_ring *ring,
	uint64_t now_ms)
{
	struct pqcp_sovereign_deployment_ring candidate;
	int index;

	if (registry == NULL || !registry->initialized ||
	    ring == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	candidate = *ring;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	if (candidate.generation == 0U) {
		candidate.generation =
			pqcp_sovereign_policy_next_generation(
				&registry->next_generation);
	}
	if (candidate.created_at_ms == 0U) {
		candidate.created_at_ms = now_ms;
	}
	if (candidate.state == PQCP_SOVEREIGN_LIFECYCLE_EMPTY) {
		candidate.state = PQCP_SOVEREIGN_LIFECYCLE_DRAFT;
	}
	if (!ring_valid(&candidate)) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = ring_index(registry, candidate.ring_id);
	if (index < 0) {
		index = free_ring_index(registry);
	}
	if (index < 0) {
		k_mutex_unlock(&registry->lock);
		return -ENOSPC;
	}
	if (registry->rings[index].occupied &&
	    registry->rings[index].state ==
		    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
	    candidate.policy_epoch <
		    registry->rings[index].policy_epoch) {
		k_mutex_unlock(&registry->lock);
		return -ESTALE;
	}
	candidate.occupied = true;
	registry->rings[index] = candidate;
	registry->registration_count =
		pqcp_sovereign_policy_add_u64(
			registry->registration_count, 1U);
	k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_sovereign_ring_find(
	struct pqcp_sovereign_ring_registry *registry,
	const char *ring_id,
	struct pqcp_sovereign_deployment_ring **ring)
{
	int index;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_policy_text_valid(
		    ring_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    ring == NULL) {
		return -EINVAL;
	}
	*ring = NULL;
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = ring_index(registry, ring_id);
	if (index >= 0) {
		*ring = &registry->rings[index];
	}
	k_mutex_unlock(&registry->lock);
	return index >= 0 ? 0 : -ENOENT;
}

int pqcp_sovereign_ring_set_state(
	struct pqcp_sovereign_ring_registry *registry,
	const char *ring_id,
	enum pqcp_sovereign_lifecycle_state state)
{
	int index;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_policy_text_valid(
		    ring_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !lifecycle_state_valid(state)) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = ring_index(registry, ring_id);
	if (index < 0) {
		k_mutex_unlock(&registry->lock);
		return -ENOENT;
	}
	if (registry->rings[index].state ==
		    PQCP_SOVEREIGN_LIFECYCLE_REVOKED ||
	    (registry->rings[index].state ==
		     PQCP_SOVEREIGN_LIFECYCLE_RETIRED &&
	     state != PQCP_SOVEREIGN_LIFECYCLE_REVOKED)) {
		k_mutex_unlock(&registry->lock);
		return -EPERM;
	}
	registry->rings[index].state = state;
	k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_sovereign_ring_registry_audit(
	struct pqcp_sovereign_ring_registry *registry)
{
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    registry->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    registry->rings == NULL || registry->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < registry->capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_deployment_ring *ring =
			&registry->rings[index];

		if (!ring->occupied) {
			continue;
		}
		if (!ring_valid(ring)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < registry->capacity; ++other) {
			if (registry->rings[other].occupied &&
			    strcmp(ring->ring_id,
				   registry->rings[other].ring_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_sovereign_rollout_controller_init(
	struct pqcp_sovereign_rollout_controller *controller,
	struct pqcp_sovereign_rollout *rollouts,
	size_t capacity)
{
	if (controller == NULL || rollouts == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(controller, 0, sizeof(*controller));
	memset(rollouts, 0, capacity * sizeof(rollouts[0]));
	controller->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	controller->rollouts = rollouts;
	controller->capacity = capacity;
	controller->next_rollout_id = 1U;
	k_mutex_init(&controller->lock);
	controller->initialized = true;
	return 0;
}

int pqcp_sovereign_rollout_plan(
	struct pqcp_sovereign_rollout_controller *controller,
	const char *artifact_id,
	const struct pqcp_sovereign_deployment_ring *ring,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t deadline_ms,
	uint32_t batch_size,
	const uint8_t plan_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	struct pqcp_sovereign_rollout **rollout)
{
	struct pqcp_sovereign_rollout *entry;
	int index;

	if (controller == NULL || !controller->initialized ||
	    !pqcp_sovereign_policy_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !ring_valid(ring) ||
	    ring->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
	    policy_epoch == 0U || policy_epoch != ring->policy_epoch ||
	    now_ms == 0U || deadline_ms <= now_ms ||
	    batch_size == 0U || batch_size > ring->maximum_parallel ||
	    plan_digest == NULL ||
	    pqcp_sovereign_policy_all_zero(
		    plan_digest, PQCP_SOVEREIGN_DIGEST_BYTES) ||
	    rollout == NULL) {
		return -EINVAL;
	}
	*rollout = NULL;
	k_mutex_lock(&controller->lock, K_FOREVER);
	index = free_rollout_index(controller);
	if (index < 0) {
		k_mutex_unlock(&controller->lock);
		return -ENOSPC;
	}
	entry = &controller->rollouts[index];
	memset(entry, 0, sizeof(*entry));
	entry->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	entry->rollout_id =
		pqcp_sovereign_policy_next_id(
			&controller->next_rollout_id);
	(void)pqcp_sovereign_policy_copy_text(
		entry->artifact_id, sizeof(entry->artifact_id),
		artifact_id);
	(void)pqcp_sovereign_policy_copy_text(
		entry->ring_id, sizeof(entry->ring_id),
		ring->ring_id);
	entry->policy_epoch = policy_epoch;
	entry->planned_at_ms = now_ms;
	entry->deadline_ms = deadline_ms;
	entry->next_action_at_ms = now_ms;
	entry->target_count = ring->member_count;
	entry->batch_size = batch_size;
	entry->state = PQCP_SOVEREIGN_ROLLOUT_PLANNED;
	memcpy(entry->plan_digest, plan_digest,
	       sizeof(entry->plan_digest));
	entry->occupied = true;
	*rollout = entry;
	k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_sovereign_rollout_start(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint64_t now_ms)
{
	int index;

	if (controller == NULL || !controller->initialized ||
	    rollout_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&controller->lock, K_FOREVER);
	index = rollout_index(controller, rollout_id);
	if (index < 0) {
		k_mutex_unlock(&controller->lock);
		return -ENOENT;
	}
	if (controller->rollouts[index].state !=
	    PQCP_SOVEREIGN_ROLLOUT_PLANNED) {
		k_mutex_unlock(&controller->lock);
		return -EALREADY;
	}
	if (now_ms >= controller->rollouts[index].deadline_ms) {
		controller->rollouts[index].state =
			PQCP_SOVEREIGN_ROLLOUT_FAILED;
		controller->rollouts[index].result = -ETIMEDOUT;
		k_mutex_unlock(&controller->lock);
		return -ETIMEDOUT;
	}
	controller->rollouts[index].started_at_ms = now_ms;
	controller->rollouts[index].next_action_at_ms = now_ms;
	controller->rollouts[index].state =
		PQCP_SOVEREIGN_ROLLOUT_CANARY;
	k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_sovereign_rollout_record_batch(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint32_t attempted,
	uint32_t succeeded,
	uint32_t failed,
	uint32_t unavailable,
	uint64_t now_ms)
{
	struct pqcp_sovereign_rollout *rollout;
	uint64_t classified;
	uint64_t total_attempted;
	uint32_t failure_bp;
	int index;

	if (controller == NULL || !controller->initialized ||
	    rollout_id == 0U || attempted == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	classified = (uint64_t)succeeded + failed + unavailable;
	if (classified > attempted) {
		return -EINVAL;
	}
	k_mutex_lock(&controller->lock, K_FOREVER);
	index = rollout_index(controller, rollout_id);
	if (index < 0) {
		k_mutex_unlock(&controller->lock);
		return -ENOENT;
	}
	rollout = &controller->rollouts[index];
	if (rollout->state != PQCP_SOVEREIGN_ROLLOUT_CANARY &&
	    rollout->state != PQCP_SOVEREIGN_ROLLOUT_EXPANDING) {
		k_mutex_unlock(&controller->lock);
		return -EPERM;
	}
	total_attempted = (uint64_t)rollout->attempted_count + attempted;
	if (total_attempted > rollout->target_count) {
		k_mutex_unlock(&controller->lock);
		return -ERANGE;
	}
	rollout->attempted_count += attempted;
	rollout->success_count += succeeded;
	rollout->failure_count += failed;
	rollout->unavailable_count += unavailable;
	rollout->current_batch++;
	rollout->health_basis_points =
		basis_points(
			rollout->success_count,
			rollout->attempted_count);
	failure_bp =
		basis_points(
			rollout->failure_count +
				rollout->unavailable_count,
			rollout->attempted_count);
	rollout->next_action_at_ms = now_ms;
	if (failure_bp > 5000U) {
		rollout->state = PQCP_SOVEREIGN_ROLLOUT_PAUSED;
		rollout->result = -EHOSTDOWN;
	} else if (rollout->attempted_count ==
		   rollout->target_count) {
		if (rollout->health_basis_points >= 5000U) {
			rollout->state =
				PQCP_SOVEREIGN_ROLLOUT_COMPLETED;
			rollout->result = 0;
			controller->completed_count =
				pqcp_sovereign_policy_add_u64(
					controller->completed_count,
					1U);
		} else {
			rollout->state =
				PQCP_SOVEREIGN_ROLLOUT_FAILED;
			rollout->result = -EIO;
		}
	} else {
		rollout->state =
			PQCP_SOVEREIGN_ROLLOUT_EXPANDING;
	}
	k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_sovereign_rollout_pause(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	int result)
{
	int index;

	if (controller == NULL || !controller->initialized ||
	    rollout_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&controller->lock, K_FOREVER);
	index = rollout_index(controller, rollout_id);
	if (index < 0) {
		k_mutex_unlock(&controller->lock);
		return -ENOENT;
	}
	if (controller->rollouts[index].state !=
		    PQCP_SOVEREIGN_ROLLOUT_CANARY &&
	    controller->rollouts[index].state !=
		    PQCP_SOVEREIGN_ROLLOUT_EXPANDING) {
		k_mutex_unlock(&controller->lock);
		return -EPERM;
	}
	controller->rollouts[index].state =
		PQCP_SOVEREIGN_ROLLOUT_PAUSED;
	controller->rollouts[index].result = result;
	k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_sovereign_rollout_resume(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint64_t now_ms)
{
	int index;

	if (controller == NULL || !controller->initialized ||
	    rollout_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&controller->lock, K_FOREVER);
	index = rollout_index(controller, rollout_id);
	if (index < 0) {
		k_mutex_unlock(&controller->lock);
		return -ENOENT;
	}
	if (controller->rollouts[index].state !=
	    PQCP_SOVEREIGN_ROLLOUT_PAUSED) {
		k_mutex_unlock(&controller->lock);
		return -EPERM;
	}
	if (now_ms >= controller->rollouts[index].deadline_ms) {
		k_mutex_unlock(&controller->lock);
		return -ETIMEDOUT;
	}
	controller->rollouts[index].state =
		PQCP_SOVEREIGN_ROLLOUT_EXPANDING;
	controller->rollouts[index].next_action_at_ms = now_ms;
	controller->rollouts[index].result = 0;
	k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_sovereign_rollout_request_rollback(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint64_t now_ms)
{
	int index;

	if (controller == NULL || !controller->initialized ||
	    rollout_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&controller->lock, K_FOREVER);
	index = rollout_index(controller, rollout_id);
	if (index < 0) {
		k_mutex_unlock(&controller->lock);
		return -ENOENT;
	}
	if (controller->rollouts[index].state ==
		    PQCP_SOVEREIGN_ROLLOUT_COMPLETED ||
	    controller->rollouts[index].state ==
		    PQCP_SOVEREIGN_ROLLOUT_ROLLING_BACK) {
		k_mutex_unlock(&controller->lock);
		return -EALREADY;
	}
	controller->rollouts[index].state =
		PQCP_SOVEREIGN_ROLLOUT_ROLLING_BACK;
	controller->rollouts[index].next_action_at_ms = now_ms;
	controller->rollback_count =
		pqcp_sovereign_policy_add_u64(
			controller->rollback_count, 1U);
	k_mutex_unlock(&controller->lock);
	return 0;
}

int pqcp_sovereign_rollout_tick(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t count = 0U;

	if (controller == NULL || !controller->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&controller->lock, K_FOREVER);
	for (size_t index = 0U; index < controller->capacity; ++index) {
		struct pqcp_sovereign_rollout *rollout =
			&controller->rollouts[index];

		if (!rollout->occupied ||
		    rollout->state == PQCP_SOVEREIGN_ROLLOUT_COMPLETED ||
		    rollout->state == PQCP_SOVEREIGN_ROLLOUT_FAILED ||
		    rollout->state ==
			    PQCP_SOVEREIGN_ROLLOUT_ROLLING_BACK) {
			continue;
		}
		if (now_ms >= rollout->deadline_ms) {
			rollout->state =
				PQCP_SOVEREIGN_ROLLOUT_FAILED;
			rollout->result = -ETIMEDOUT;
			count++;
		}
	}
	k_mutex_unlock(&controller->lock);
	if (changed_count != NULL) {
		*changed_count = count;
	}
	return 0;
}

int pqcp_sovereign_rollout_controller_audit(
	struct pqcp_sovereign_rollout_controller *controller)
{
	int ret = 0;

	if (controller == NULL || !controller->initialized ||
	    controller->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    controller->rollouts == NULL || controller->capacity == 0U ||
	    controller->next_rollout_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&controller->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < controller->capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_rollout *rollout =
			&controller->rollouts[index];
		uint64_t classified;

		if (!rollout->occupied) {
			continue;
		}
		classified = (uint64_t)rollout->success_count +
			     rollout->failure_count +
			     rollout->unavailable_count;
		if (rollout->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    rollout->rollout_id == 0U ||
		    rollout->target_count == 0U ||
		    rollout->batch_size == 0U ||
		    rollout->attempted_count > rollout->target_count ||
		    classified > rollout->attempted_count ||
		    rollout->deadline_ms <= rollout->planned_at_ms ||
		    pqcp_sovereign_policy_all_zero(
			    rollout->plan_digest,
			    sizeof(rollout->plan_digest))) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < controller->capacity; ++other) {
			if (controller->rollouts[other].occupied &&
			    controller->rollouts[other].rollout_id ==
				    rollout->rollout_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&controller->lock);
	return ret;
}
