/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Monotonic tenant/resource fencing for split-brain prevention.
 */

#include "sovereign_continuity_internal.h"

static bool fence_state_valid(
	enum pqcp_sovereign_fence_state state)
{
	return state >= PQCP_SOVEREIGN_FENCE_HELD &&
	       state <= PQCP_SOVEREIGN_FENCE_SUPERSEDED;
}

static int fence_index(
	const struct pqcp_sovereign_fence_manager *manager,
	const char *tenant_id,
	const char *resource_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_sovereign_fence *fence =
			&manager->fences[index];

		if (fence->occupied &&
		    strcmp(fence->tenant_id, tenant_id) == 0 &&
		    strcmp(fence->resource_id, resource_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_fence_index(
	const struct pqcp_sovereign_fence_manager *manager)
{
	int oldest_terminal = -1;
	uint64_t oldest_time = UINT64_MAX;

	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_sovereign_fence *fence =
			&manager->fences[index];

		if (!fence->occupied) {
			return (int)index;
		}
		if (fence->state != PQCP_SOVEREIGN_FENCE_HELD &&
		    fence->acquired_at_ms < oldest_time) {
			oldest_time = fence->acquired_at_ms;
			oldest_terminal = (int)index;
		}
	}
	return oldest_terminal >= 0 ? oldest_terminal : -ENOSPC;
}

static bool claim_valid(
	const struct pqcp_sovereign_fence_claim *claim)
{
	return claim != NULL &&
	       pqcp_sovereign_continuity_text_valid(
		       claim->tenant_id) &&
	       pqcp_sovereign_continuity_text_valid(
		       claim->resource_id) &&
	       pqcp_sovereign_continuity_text_valid(
		       claim->holder_id) &&
	       pqcp_sovereign_continuity_text_valid(
		       claim->lease_id) &&
	       claim->requested_epoch != 0U &&
	       claim->now_ms != 0U &&
	       claim->expires_at_ms > claim->now_ms &&
	       pqcp_sovereign_continuity_digest_valid(
		       claim->holder_digest) &&
	       pqcp_sovereign_continuity_digest_valid(
		       claim->authorization_digest);
}

static int validate_fence(
	const struct pqcp_sovereign_fence *fence)
{
	if (fence == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    fence->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    fence->resource_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    fence->holder_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    fence->lease_id) ||
	    fence->epoch == 0U ||
	    fence->acquired_at_ms == 0U ||
	    fence->renewed_at_ms <
		    fence->acquired_at_ms ||
	    fence->expires_at_ms <=
		    fence->acquired_at_ms ||
	    !pqcp_sovereign_continuity_digest_valid(
		    fence->holder_digest) ||
	    !pqcp_sovereign_continuity_digest_valid(
		    fence->authorization_digest)) {
		return -EINVAL;
	}
	if (fence->state ==
		    PQCP_SOVEREIGN_FENCE_RELEASED &&
	    fence->released_at_ms <
		    fence->acquired_at_ms) {
		return -ERANGE;
	}
	return 0;
}

static int validate_claim_epoch(
	const struct pqcp_sovereign_fence_manager *manager,
	const struct pqcp_sovereign_fence *current,
	uint64_t requested_epoch)
{
	if (current != NULL) {
		if (requested_epoch <= current->epoch) {
			return -ESTALE;
		}
		return 0;
	}
	if (requested_epoch < manager->highest_epoch) {
		return -ESTALE;
	}
	return 0;
}

static int update_fence_digest(
	struct pqcp_sovereign_fence_manager *manager,
	struct pqcp_sovereign_fence *fence)
{
	int ret;

	ret = pqcp_sovereign_continuity_digest_fence(
		fence, fence->fence_digest);
	if (ret == 0) {
		memcpy(manager->tail_digest,
		       fence->fence_digest,
		       sizeof(manager->tail_digest));
	}
	return ret;
}

int pqcp_sovereign_fence_manager_init(
	struct pqcp_sovereign_fence_manager *manager,
	struct pqcp_sovereign_fence *fences,
	size_t capacity,
	uint64_t initial_epoch)
{
	if (manager == NULL || fences == NULL ||
	    capacity == 0U || initial_epoch == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(fences, 0, capacity * sizeof(*fences));
	manager->schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	manager->fences = fences;
	manager->capacity = capacity;
	manager->next_generation = 1U;
	manager->highest_epoch = initial_epoch;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_fence_acquire(
	struct pqcp_sovereign_fence_manager *manager,
	const struct pqcp_sovereign_fence_claim *claim,
	struct pqcp_sovereign_fence *fence)
{
	struct pqcp_sovereign_fence candidate;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !claim_valid(claim) || fence == NULL) {
		return -EINVAL;
	}
	memset(fence, 0, sizeof(*fence));
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = fence_index(
		manager, claim->tenant_id,
		claim->resource_id);
	if (index >= 0) {
		struct pqcp_sovereign_fence *current =
			&manager->fences[index];

		if (current->state ==
			    PQCP_SOVEREIGN_FENCE_HELD &&
		    current->expires_at_ms > claim->now_ms) {
			if (strcmp(current->holder_id,
				   claim->holder_id) == 0 &&
			    current->epoch ==
				    claim->requested_epoch) {
				*fence = *current;
				ret = -EALREADY;
			} else {
				ret = -EBUSY;
			}
			goto reject;
		}
		ret = validate_claim_epoch(
			manager, current,
			claim->requested_epoch);
		if (ret != 0) {
			goto reject;
		}
		current->state =
			current->expires_at_ms <= claim->now_ms ?
				PQCP_SOVEREIGN_FENCE_EXPIRED :
				PQCP_SOVEREIGN_FENCE_SUPERSEDED;
		ret = update_fence_digest(manager, current);
		if (ret != 0) {
			goto reject;
		}
	} else if (index != -ENOENT) {
		ret = index;
		goto reject;
	} else {
		index = free_fence_index(manager);
		if (index < 0) {
			ret = index;
			goto reject;
		}
		ret = validate_claim_epoch(
			manager, NULL,
			claim->requested_epoch);
		if (ret != 0) {
			goto reject;
		}
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	candidate.generation =
		pqcp_edge_internal_next_generation(
			&manager->next_generation);
	ret = pqcp_sovereign_continuity_copy_id(
		candidate.tenant_id, claim->tenant_id);
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			candidate.resource_id,
			claim->resource_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			candidate.holder_id, claim->holder_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			candidate.lease_id, claim->lease_id);
	}
	if (ret != 0) {
		goto reject;
	}
	candidate.state = PQCP_SOVEREIGN_FENCE_HELD;
	candidate.epoch = claim->requested_epoch;
	candidate.acquired_at_ms = claim->now_ms;
	candidate.renewed_at_ms = claim->now_ms;
	candidate.expires_at_ms = claim->expires_at_ms;
	memcpy(candidate.holder_digest,
	       claim->holder_digest,
	       sizeof(candidate.holder_digest));
	memcpy(candidate.authorization_digest,
	       claim->authorization_digest,
	       sizeof(candidate.authorization_digest));
	memcpy(candidate.previous_fence_digest,
	       manager->tail_digest,
	       sizeof(candidate.previous_fence_digest));
	candidate.occupied = true;
	ret = update_fence_digest(manager, &candidate);
	if (ret == 0) {
		manager->fences[index] = candidate;
		if (candidate.epoch > manager->highest_epoch) {
			manager->highest_epoch = candidate.epoch;
		}
		manager->acquisition_count =
			pqcp_sovereign_continuity_add_u64(
				manager->acquisition_count, 1U);
		*fence = candidate;
	}
	goto out;
reject:
	manager->rejection_count =
		pqcp_sovereign_continuity_add_u64(
			manager->rejection_count, 1U);
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_fence_renew(
	struct pqcp_sovereign_fence_manager *manager,
	const struct pqcp_sovereign_fence_claim *claim,
	uint32_t generation,
	struct pqcp_sovereign_fence *fence)
{
	struct pqcp_sovereign_fence *current;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !claim_valid(claim) || generation == 0U ||
	    fence == NULL) {
		return -EINVAL;
	}
	memset(fence, 0, sizeof(*fence));
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = fence_index(
		manager, claim->tenant_id,
		claim->resource_id);
	if (index < 0) {
		ret = index;
		goto reject;
	}
	current = &manager->fences[index];
	if (current->generation != generation ||
	    current->epoch != claim->requested_epoch) {
		ret = -ESTALE;
		goto reject;
	}
	if (current->state != PQCP_SOVEREIGN_FENCE_HELD ||
	    current->expires_at_ms <= claim->now_ms) {
		current->state = PQCP_SOVEREIGN_FENCE_EXPIRED;
		ret = -ETIMEDOUT;
		goto reject;
	}
	if (strcmp(current->holder_id,
		   claim->holder_id) != 0 ||
	    strcmp(current->lease_id,
		   claim->lease_id) != 0 ||
	    !pqcp_sovereign_continuity_digest_equal(
		    current->holder_digest,
		    claim->holder_digest) ||
	    !pqcp_sovereign_continuity_digest_equal(
		    current->authorization_digest,
		    claim->authorization_digest)) {
		ret = -EACCES;
		goto reject;
	}
	if (claim->expires_at_ms <=
	    current->expires_at_ms) {
		ret = -ERANGE;
		goto reject;
	}
	current->renewed_at_ms = claim->now_ms;
	current->expires_at_ms = claim->expires_at_ms;
	ret = update_fence_digest(manager, current);
	if (ret == 0) {
		*fence = *current;
	}
	goto out;
reject:
	manager->rejection_count =
		pqcp_sovereign_continuity_add_u64(
			manager->rejection_count, 1U);
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_fence_advance(
	struct pqcp_sovereign_fence_manager *manager,
	const char *tenant_id,
	const char *resource_id,
	uint64_t minimum_epoch,
	const uint8_t authorization_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t *new_epoch)
{
	struct pqcp_sovereign_fence *current = NULL;
	uint64_t epoch;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(resource_id) ||
	    minimum_epoch == 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    authorization_digest) ||
	    now_ms == 0U || new_epoch == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = fence_index(manager, tenant_id, resource_id);
	if (index >= 0) {
		current = &manager->fences[index];
		if (current->state ==
			    PQCP_SOVEREIGN_FENCE_HELD &&
		    current->expires_at_ms > now_ms &&
		    !pqcp_sovereign_continuity_digest_equal(
			    current->authorization_digest,
			    authorization_digest)) {
			ret = -EKEYREJECTED;
			goto reject;
		}
		current->state =
			PQCP_SOVEREIGN_FENCE_SUPERSEDED;
		current->released_at_ms = now_ms;
		ret = update_fence_digest(manager, current);
		if (ret != 0) {
			goto reject;
		}
	} else if (index != -ENOENT) {
		ret = index;
		goto reject;
	}
	epoch = manager->highest_epoch;
	if (epoch < minimum_epoch) {
		epoch = minimum_epoch;
	}
	if (epoch == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto reject;
	}
	++epoch;
	manager->highest_epoch = epoch;
	*new_epoch = epoch;
	goto out;
reject:
	manager->rejection_count =
		pqcp_sovereign_continuity_add_u64(
			manager->rejection_count, 1U);
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_fence_release(
	struct pqcp_sovereign_fence_manager *manager,
	const char *tenant_id,
	const char *resource_id,
	const char *holder_id,
	uint32_t generation,
	uint64_t epoch,
	uint64_t now_ms)
{
	struct pqcp_sovereign_fence *fence;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(resource_id) ||
	    !pqcp_sovereign_continuity_text_valid(holder_id) ||
	    generation == 0U || epoch == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = fence_index(manager, tenant_id, resource_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	fence = &manager->fences[index];
	if (fence->generation != generation ||
	    fence->epoch != epoch) {
		ret = -ESTALE;
	} else if (strcmp(fence->holder_id,
			  holder_id) != 0) {
		ret = -EACCES;
	} else if (fence->state ==
		   PQCP_SOVEREIGN_FENCE_RELEASED) {
		ret = -EALREADY;
	} else if (fence->state !=
		   PQCP_SOVEREIGN_FENCE_HELD) {
		ret = -EPERM;
	} else {
		fence->state =
			PQCP_SOVEREIGN_FENCE_RELEASED;
		fence->released_at_ms = now_ms;
		ret = update_fence_digest(manager, fence);
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_fence_check(
	struct pqcp_sovereign_fence_manager *manager,
	const char *tenant_id,
	const char *resource_id,
	const char *holder_id,
	uint64_t epoch,
	uint64_t now_ms)
{
	const struct pqcp_sovereign_fence *fence;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(resource_id) ||
	    !pqcp_sovereign_continuity_text_valid(holder_id) ||
	    epoch == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = fence_index(manager, tenant_id, resource_id);
	if (index < 0) {
		ret = index;
	} else {
		fence = &manager->fences[index];
		if (fence->state !=
			    PQCP_SOVEREIGN_FENCE_HELD ||
		    fence->expires_at_ms <= now_ms) {
			ret = -ETIMEDOUT;
		} else if (fence->epoch != epoch) {
			ret = -ESTALE;
		} else if (strcmp(fence->holder_id,
				  holder_id) != 0) {
			ret = -EACCES;
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_fence_guard_capture(
	struct pqcp_sovereign_fence_manager *manager,
	const char *tenant_id,
	const char *resource_id,
	const char *holder_id,
	const char *lease_id,
	uint64_t epoch,
	uint64_t now_ms,
	struct pqcp_sovereign_fence_guard *guard)
{
	const struct pqcp_sovereign_fence *fence;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(resource_id) ||
	    !pqcp_sovereign_continuity_text_valid(holder_id) ||
	    !pqcp_sovereign_continuity_text_valid(lease_id) ||
	    epoch == 0U || now_ms == 0U || guard == NULL) {
		return -EINVAL;
	}
	memset(guard, 0, sizeof(*guard));
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = fence_index(manager, tenant_id, resource_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	fence = &manager->fences[index];
	if (fence->state != PQCP_SOVEREIGN_FENCE_HELD ||
	    fence->expires_at_ms <= now_ms) {
		ret = -ETIMEDOUT;
		goto out;
	}
	if (fence->epoch != epoch) {
		ret = -ESTALE;
		goto out;
	}
	if (strcmp(fence->holder_id, holder_id) != 0 ||
	    strcmp(fence->lease_id, lease_id) != 0) {
		ret = -EACCES;
		goto out;
	}
	guard->schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	guard->generation = fence->generation;
	memcpy(guard->tenant_id, fence->tenant_id,
	       sizeof(guard->tenant_id));
	memcpy(guard->resource_id, fence->resource_id,
	       sizeof(guard->resource_id));
	memcpy(guard->holder_id, fence->holder_id,
	       sizeof(guard->holder_id));
	memcpy(guard->lease_id, fence->lease_id,
	       sizeof(guard->lease_id));
	guard->epoch = fence->epoch;
	guard->captured_at_ms = now_ms;
	guard->expires_at_ms = fence->expires_at_ms;
	memcpy(guard->authorization_digest,
	       fence->authorization_digest,
	       sizeof(guard->authorization_digest));
	memcpy(guard->fence_digest, fence->fence_digest,
	       sizeof(guard->fence_digest));
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_fence_guard_check(
	struct pqcp_sovereign_fence_manager *manager,
	const struct pqcp_sovereign_fence_guard *guard,
	const uint8_t authorization_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms)
{
	const struct pqcp_sovereign_fence *fence;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    guard == NULL ||
	    guard->schema_version !=
		    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
	    guard->generation == 0U ||
	    !pqcp_sovereign_continuity_text_valid(
		    guard->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    guard->resource_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    guard->holder_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    guard->lease_id) ||
	    guard->epoch == 0U || guard->captured_at_ms == 0U ||
	    guard->expires_at_ms <= guard->captured_at_ms ||
	    now_ms < guard->captured_at_ms ||
	    !pqcp_sovereign_continuity_digest_valid(
		    guard->authorization_digest) ||
	    !pqcp_sovereign_continuity_digest_valid(
		    guard->fence_digest) ||
	    !pqcp_sovereign_continuity_digest_valid(
		    authorization_digest)) {
		return -EINVAL;
	}
	if (!pqcp_sovereign_continuity_digest_equal(
		    guard->authorization_digest,
		    authorization_digest)) {
		return -EKEYREJECTED;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = fence_index(
		manager, guard->tenant_id,
		guard->resource_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	fence = &manager->fences[index];
	if (fence->state != PQCP_SOVEREIGN_FENCE_HELD ||
	    fence->expires_at_ms <= now_ms ||
	    guard->expires_at_ms <= now_ms) {
		ret = -ETIMEDOUT;
		goto out;
	}
	if (fence->generation != guard->generation ||
	    fence->epoch != guard->epoch) {
		ret = -ESTALE;
		goto out;
	}
	if (strcmp(fence->holder_id, guard->holder_id) != 0 ||
	    strcmp(fence->lease_id, guard->lease_id) != 0) {
		ret = -EACCES;
		goto out;
	}
	if (!pqcp_sovereign_continuity_digest_equal(
		    fence->authorization_digest,
		    guard->authorization_digest) ||
	    !pqcp_sovereign_continuity_digest_equal(
		    fence->fence_digest,
		    guard->fence_digest)) {
		ret = -EKEYREJECTED;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_fence_expire(
	struct pqcp_sovereign_fence_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_sovereign_fence *fence =
			&manager->fences[index];

		if (!fence->occupied ||
		    fence->state != PQCP_SOVEREIGN_FENCE_HELD ||
		    fence->expires_at_ms > now_ms) {
			continue;
		}
		fence->state = PQCP_SOVEREIGN_FENCE_EXPIRED;
		fence->released_at_ms = now_ms;
		ret = update_fence_digest(manager, fence);
		if (ret != 0) {
			break;
		}
		++expired;
	}
	k_mutex_unlock(&manager->lock);
	*expired_count = expired;
	return ret;
}

int pqcp_sovereign_fence_manager_audit(
	struct pqcp_sovereign_fence_manager *manager)
{
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint64_t highest = 0U;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
	    manager->fences == NULL || manager->capacity == 0U ||
	    manager->highest_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_fence *fence =
			&manager->fences[index];

		if (!fence->occupied) {
			continue;
		}
		if (fence->schema_version !=
			    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
		    fence->generation == 0U ||
		    validate_fence(fence) != 0 ||
		    !fence_state_valid(fence->state) ||
		    !pqcp_sovereign_continuity_digest_valid(
			    fence->fence_digest)) {
			ret = -EBADMSG;
			break;
		}
		if (fence->epoch > highest) {
			highest = fence->epoch;
		}
		ret = pqcp_sovereign_continuity_digest_fence(
			fence, digest);
		if (ret == 0 &&
		    !pqcp_sovereign_continuity_digest_equal(
			    digest, fence->fence_digest)) {
			ret = -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity && ret == 0;
		     ++other) {
			const struct pqcp_sovereign_fence *peer =
				&manager->fences[other];

			if (peer->occupied &&
			    strcmp(fence->tenant_id,
				   peer->tenant_id) == 0 &&
			    strcmp(fence->resource_id,
				   peer->resource_id) == 0) {
				ret = -EEXIST;
			}
		}
	}
	if (ret == 0 &&
	    highest > manager->highest_epoch) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
