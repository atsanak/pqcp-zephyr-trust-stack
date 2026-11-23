/*
 * SPDX-License-Identifier: MIT
 *
 * Runtime isolation zones for workload and operation containment.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool isolation_state_valid(
	enum pqcp_edge_isolation_state state)
{
	return state >= PQCP_EDGE_ISOLATION_OPEN &&
	       state <= PQCP_EDGE_ISOLATION_FAILSAFE;
}

static bool operation_valid(
	enum pqcp_edge_operation operation)
{
	return operation > PQCP_EDGE_OPERATION_NONE &&
	       operation < PQCP_EDGE_OPERATION_COUNT;
}

static int zone_index(
	const struct pqcp_edge_isolation_manager *manager,
	const char *zone_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->zones[index].occupied &&
		    strcmp(manager->zones[index].zone_id,
			   zone_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_zone_index(
	const struct pqcp_edge_isolation_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->zones[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool zone_shape_valid(
	const struct pqcp_edge_isolation_zone *zone)
{
	if (zone == NULL ||
	    !pqcp_edge_internal_text_valid(
		    zone->zone_id,
		    sizeof(zone->zone_id)) ||
	    !isolation_state_valid(zone->state) ||
	    zone->maximum_workloads == 0U ||
	    zone->active_workloads >
		    zone->maximum_workloads) {
		return false;
	}
	if (zone->state == PQCP_EDGE_ISOLATION_OPEN &&
	    (zone->allowed_capabilities == 0U ||
	     zone->allowed_operations == 0U)) {
		return false;
	}
	if (zone->state == PQCP_EDGE_ISOLATION_FAILSAFE &&
	    (zone->allowed_capabilities != 0U ||
	     zone->allowed_operations != 0U)) {
		return false;
	}
	if (zone->expires_at_ms != 0U &&
	    zone->expires_at_ms <= zone->entered_at_ms) {
		return false;
	}
	return true;
}

static bool transition_allowed(
	enum pqcp_edge_isolation_state from,
	enum pqcp_edge_isolation_state to)
{
	if (from == to) {
		return true;
	}
	switch (from) {
	case PQCP_EDGE_ISOLATION_OPEN:
		return to == PQCP_EDGE_ISOLATION_RESTRICTED ||
		       to == PQCP_EDGE_ISOLATION_QUARANTINED ||
		       to == PQCP_EDGE_ISOLATION_FAILSAFE;
	case PQCP_EDGE_ISOLATION_RESTRICTED:
		return to == PQCP_EDGE_ISOLATION_OPEN ||
		       to == PQCP_EDGE_ISOLATION_QUARANTINED ||
		       to == PQCP_EDGE_ISOLATION_FAILSAFE;
	case PQCP_EDGE_ISOLATION_QUARANTINED:
		return to == PQCP_EDGE_ISOLATION_RESTRICTED ||
		       to == PQCP_EDGE_ISOLATION_FAILSAFE;
	case PQCP_EDGE_ISOLATION_FAILSAFE:
		return to == PQCP_EDGE_ISOLATION_QUARANTINED;
	default:
		return false;
	}
}

static bool state_allows_operation(
	enum pqcp_edge_isolation_state state,
	enum pqcp_edge_operation operation)
{
	switch (state) {
	case PQCP_EDGE_ISOLATION_OPEN:
		return true;
	case PQCP_EDGE_ISOLATION_RESTRICTED:
		return operation != PQCP_EDGE_OPERATION_ADMINISTER &&
		       operation != PQCP_EDGE_OPERATION_DELETE;
	case PQCP_EDGE_ISOLATION_QUARANTINED:
		return operation == PQCP_EDGE_OPERATION_ATTEST ||
		       operation == PQCP_EDGE_OPERATION_RECOVER;
	case PQCP_EDGE_ISOLATION_FAILSAFE:
	default:
		return false;
	}
}

int pqcp_edge_isolation_manager_init(
	struct pqcp_edge_isolation_manager *manager,
	struct pqcp_edge_isolation_zone *zones,
	size_t capacity)
{
	if (manager == NULL || zones == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(zones, 0, capacity * sizeof(*zones));
	manager->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	manager->zones = zones;
	manager->capacity = capacity;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_isolation_zone_put(
	struct pqcp_edge_isolation_manager *manager,
	const struct pqcp_edge_isolation_zone *zone)
{
	struct pqcp_edge_isolation_zone candidate;
	int index;

	if (manager == NULL || !manager->initialized ||
	    !zone_shape_valid(zone)) {
		return -EINVAL;
	}
	candidate = *zone;
	candidate.occupied = true;
	candidate.saved_allowed_capabilities = 0U;
	candidate.saved_allowed_operations = 0U;
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = zone_index(manager, candidate.zone_id);
	if (index >= 0) {
		const struct pqcp_edge_isolation_zone *old =
			&manager->zones[index];
		const bool old_failsafe =
			old->state == PQCP_EDGE_ISOLATION_FAILSAFE;

		if (manager->zones[index].active_workloads !=
			    candidate.active_workloads &&
		    manager->zones[index].active_workloads != 0U) {
			k_mutex_unlock(&manager->lock);
			return -EBUSY;
		}
		if (!transition_allowed(
			    manager->zones[index].state,
			    candidate.state)) {
			k_mutex_unlock(&manager->lock);
			return -EPERM;
		}
		if (candidate.state == PQCP_EDGE_ISOLATION_FAILSAFE) {
			candidate.saved_allowed_capabilities =
				old_failsafe ?
				old->saved_allowed_capabilities :
				old->allowed_capabilities;
			candidate.saved_allowed_operations =
				old_failsafe ?
				old->saved_allowed_operations :
				old->allowed_operations;
		} else if (old_failsafe &&
			   candidate.allowed_capabilities == 0U &&
			   candidate.allowed_operations == 0U) {
			candidate.allowed_capabilities =
				old->saved_allowed_capabilities;
			candidate.allowed_operations =
				old->saved_allowed_operations;
		}
	} else if (index == -ENOENT) {
		index = free_zone_index(manager);
		if (index < 0) {
			k_mutex_unlock(&manager->lock);
			return index;
		}
	} else {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	manager->zones[index] = candidate;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_isolation_transition(
	struct pqcp_edge_isolation_manager *manager,
	const char *zone_id,
	enum pqcp_edge_isolation_state state,
	uint32_t reason_mask,
	uint64_t now_ms,
	uint64_t expires_at_ms)
{
	struct pqcp_edge_isolation_zone *zone;
	int index;

	if (manager == NULL || !manager->initialized ||
	    zone_id == NULL ||
	    !isolation_state_valid(state) ||
	    (expires_at_ms != 0U &&
	     expires_at_ms <= now_ms)) {
		return -EINVAL;
	}
	if (state != PQCP_EDGE_ISOLATION_OPEN &&
	    reason_mask == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = zone_index(manager, zone_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	zone = &manager->zones[index];
	if (!transition_allowed(zone->state, state)) {
		k_mutex_unlock(&manager->lock);
		return -EPERM;
	}
	if (state == PQCP_EDGE_ISOLATION_OPEN &&
	    zone->active_workloads != 0U &&
	    zone->state == PQCP_EDGE_ISOLATION_FAILSAFE) {
		k_mutex_unlock(&manager->lock);
		return -EBUSY;
	}
	if (state == PQCP_EDGE_ISOLATION_OPEN &&
	    zone->state != PQCP_EDGE_ISOLATION_FAILSAFE &&
	    (zone->allowed_capabilities == 0U ||
	     zone->allowed_operations == 0U)) {
		/* An OPEN zone with empty allow-lists is malformed. */
		k_mutex_unlock(&manager->lock);
		return -EPERM;
	}
	if (zone->state != state) {
		++manager->transition_count;
	}
	if (zone->state == PQCP_EDGE_ISOLATION_FAILSAFE &&
	    state != PQCP_EDGE_ISOLATION_FAILSAFE) {
		/* Leaving FAILSAFE restores the pre-FAILSAFE allow-lists;
		 * the new state still gates which operations are allowed.
		 */
		zone->allowed_capabilities =
			zone->saved_allowed_capabilities;
		zone->allowed_operations =
			zone->saved_allowed_operations;
		zone->saved_allowed_capabilities = 0U;
		zone->saved_allowed_operations = 0U;
	}
	zone->state = state;
	zone->reason_mask =
		state == PQCP_EDGE_ISOLATION_OPEN ?
			0U : reason_mask;
	zone->entered_at_ms = now_ms;
	zone->expires_at_ms =
		state == PQCP_EDGE_ISOLATION_OPEN ?
			0U : expires_at_ms;
	if (state == PQCP_EDGE_ISOLATION_FAILSAFE) {
		if (zone->allowed_capabilities != 0U ||
		    zone->allowed_operations != 0U) {
			zone->saved_allowed_capabilities =
				zone->allowed_capabilities;
			zone->saved_allowed_operations =
				zone->allowed_operations;
		}
		zone->allowed_capabilities = 0U;
		zone->allowed_operations = 0U;
	}
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_isolation_authorize(
	struct pqcp_edge_isolation_manager *manager,
	const char *zone_id,
	enum pqcp_edge_operation operation,
	uint64_t capabilities,
	uint64_t now_ms)
{
	struct pqcp_edge_isolation_zone *zone;
	uint64_t operation_bit;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    zone_id == NULL || !operation_valid(operation) ||
	    capabilities == 0U) {
		return -EINVAL;
	}
	operation_bit = PQCP_EDGE_OPERATION_BIT(operation);
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = zone_index(manager, zone_id);
	if (index < 0) {
		ret = index;
		goto reject;
	}
	zone = &manager->zones[index];
	if (zone->expires_at_ms != 0U &&
	    now_ms >= zone->expires_at_ms &&
	    zone->state != PQCP_EDGE_ISOLATION_FAILSAFE) {
		zone->state = PQCP_EDGE_ISOLATION_OPEN;
		zone->reason_mask = 0U;
		zone->entered_at_ms = now_ms;
		zone->expires_at_ms = 0U;
		++manager->transition_count;
	}
	if (!state_allows_operation(zone->state,
				    operation) ||
	    (zone->allowed_operations & operation_bit) == 0U ||
	    (zone->allowed_capabilities & capabilities) !=
		    capabilities) {
		ret = -EACCES;
		goto reject;
	}
	goto out;
reject:
	++manager->denial_count;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_isolation_reserve(
	struct pqcp_edge_isolation_manager *manager,
	const char *zone_id)
{
	struct pqcp_edge_isolation_zone *zone;
	int index;

	if (manager == NULL || !manager->initialized ||
	    zone_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = zone_index(manager, zone_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	zone = &manager->zones[index];
	if (zone->state ==
		    PQCP_EDGE_ISOLATION_QUARANTINED ||
	    zone->state == PQCP_EDGE_ISOLATION_FAILSAFE) {
		++manager->denial_count;
		k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	if (zone->active_workloads >=
	    zone->maximum_workloads) {
		++manager->denial_count;
		k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	++zone->active_workloads;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_isolation_release(
	struct pqcp_edge_isolation_manager *manager,
	const char *zone_id)
{
	int index;

	if (manager == NULL || !manager->initialized ||
	    zone_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = zone_index(manager, zone_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	if (manager->zones[index].active_workloads == 0U) {
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	--manager->zones[index].active_workloads;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_isolation_tick(
	struct pqcp_edge_isolation_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (manager == NULL || !manager->initialized) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_edge_isolation_zone *zone =
			&manager->zones[index];

		if (!zone->occupied ||
		    zone->expires_at_ms == 0U ||
		    now_ms < zone->expires_at_ms ||
		    zone->state ==
			    PQCP_EDGE_ISOLATION_FAILSAFE) {
			continue;
		}
		if (zone->state ==
			    PQCP_EDGE_ISOLATION_QUARANTINED &&
		    zone->active_workloads != 0U) {
			zone->state =
				PQCP_EDGE_ISOLATION_RESTRICTED;
		} else {
			zone->state =
				PQCP_EDGE_ISOLATION_OPEN;
		}
		zone->reason_mask = 0U;
		zone->entered_at_ms = now_ms;
		zone->expires_at_ms = 0U;
		++manager->transition_count;
		++changed;
	}
	k_mutex_unlock(&manager->lock);
	if (changed_count != NULL) {
		*changed_count = changed;
	}
	return 0;
}

int pqcp_edge_isolation_manager_audit(
	struct pqcp_edge_isolation_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->zones == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_edge_isolation_zone *zone =
			&manager->zones[index];

		if (!zone->occupied) {
			continue;
		}
		if (!zone_shape_valid(zone)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->zones[other].occupied &&
			    strcmp(zone->zone_id,
				   manager->zones[other].
					   zone_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
		if (ret != 0) {
			break;
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
