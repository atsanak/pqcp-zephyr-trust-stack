/*
 * SPDX-License-Identifier: MIT
 *
 * Dependency-aware service continuity and failsafe escalation.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool mode_valid(
	enum pqcp_edge_continuity_mode mode)
{
	return mode >= PQCP_EDGE_CONTINUITY_NORMAL &&
	       mode <= PQCP_EDGE_CONTINUITY_FAILSAFE;
}

static int service_index(
	const struct pqcp_edge_continuity_manager *manager,
	const char *service_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->services[index].occupied &&
		    strcmp(manager->services[index].service_id,
			   service_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_service_index(
	const struct pqcp_edge_continuity_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->services[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static enum pqcp_edge_continuity_mode derive_mode(
	const struct pqcp_edge_continuity_service *service)
{
	const bool dependencies_met =
		(service->dependency_mask &
		 ~service->satisfied_dependencies) == 0U;

	if (service->available_endpoints == 0U) {
		return dependencies_met ?
			PQCP_EDGE_CONTINUITY_RECOVERY :
			PQCP_EDGE_CONTINUITY_FAILSAFE;
	}
	if (!dependencies_met) {
		return PQCP_EDGE_CONTINUITY_ISOLATED;
	}
	if (service->available_endpoints <
	    service->minimum_endpoints) {
		return PQCP_EDGE_CONTINUITY_DEGRADED;
	}
	return PQCP_EDGE_CONTINUITY_NORMAL;
}

int pqcp_edge_continuity_manager_init(
	struct pqcp_edge_continuity_manager *manager,
	struct pqcp_edge_continuity_service *services,
	size_t capacity)
{
	if (manager == NULL || services == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(services, 0,
	       capacity * sizeof(*services));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->services = services;
	manager->capacity = capacity;
	manager->global_mode =
		PQCP_EDGE_CONTINUITY_NORMAL;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_continuity_register(
	struct pqcp_edge_continuity_manager *manager,
	const struct pqcp_edge_continuity_service *service)
{
	struct pqcp_edge_continuity_service candidate;
	int index;

	if (manager == NULL || !manager->initialized ||
	    service == NULL ||
	    !pqcp_edge_internal_text_valid(
		    service->service_id,
		    sizeof(service->service_id)) ||
	    !mode_valid(service->mode) ||
	    service->minimum_endpoints == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = service_index(manager, service->service_id);
	if (index < 0 && index != -ENOENT) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	if (index == -ENOENT) {
		index = free_service_index(manager);
		if (index < 0) {
			k_mutex_unlock(&manager->lock);
			return index;
		}
	}
	candidate = *service;
	candidate.occupied = true;
	candidate.mode_pinned = false;
	if (!mode_valid(candidate.mode)) {
		candidate.mode =
			PQCP_EDGE_CONTINUITY_NORMAL;
	}
	manager->services[index] = candidate;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_continuity_observe(
	struct pqcp_edge_continuity_manager *manager,
	const char *service_id,
	uint32_t available_endpoints,
	uint64_t satisfied_dependencies,
	uint64_t now_ms)
{
	struct pqcp_edge_continuity_service *service;
	enum pqcp_edge_continuity_mode mode;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    service_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = service_index(manager, service_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	service = &manager->services[index];
	service->available_endpoints = available_endpoints;
	service->satisfied_dependencies =
		satisfied_dependencies &
		service->dependency_mask;
	mode = derive_mode(service);
	if (!service->mode_pinned && mode != service->mode) {
		service->mode = mode;
		service->entered_at_ms = now_ms;
		++manager->transition_count;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_continuity_set_mode(
	struct pqcp_edge_continuity_manager *manager,
	const char *service_id,
	enum pqcp_edge_continuity_mode mode,
	uint64_t now_ms)
{
	struct pqcp_edge_continuity_service *service;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    service_id == NULL || !mode_valid(mode)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = service_index(manager, service_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	service = &manager->services[index];
	if (service->mode == mode) {
		ret = -EALREADY;
	} else if (mode == PQCP_EDGE_CONTINUITY_NORMAL &&
		   derive_mode(service) !=
			   PQCP_EDGE_CONTINUITY_NORMAL) {
		ret = -EAGAIN;
	} else {
		service->mode = mode;
		/* An operator-imposed non-NORMAL mode (and leaving a
		 * latched FAILSAFE) is held until the operator returns
		 * the service to NORMAL.
		 */
		service->mode_pinned =
			mode != PQCP_EDGE_CONTINUITY_NORMAL;
		service->entered_at_ms = now_ms;
		++manager->transition_count;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_continuity_evaluate(
	struct pqcp_edge_continuity_manager *manager,
	uint64_t now_ms,
	enum pqcp_edge_continuity_mode *mode)
{
	enum pqcp_edge_continuity_mode maximum =
		PQCP_EDGE_CONTINUITY_NORMAL;

	if (manager == NULL || !manager->initialized ||
	    mode == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_edge_continuity_service *service =
			&manager->services[index];
		enum pqcp_edge_continuity_mode derived;

		if (!service->occupied) {
			continue;
		}
		derived = service->mode_pinned ?
			service->mode : derive_mode(service);
		if (service->maximum_duration_ms != 0U &&
		    service->mode !=
			    PQCP_EDGE_CONTINUITY_NORMAL &&
		    service->mode !=
			    PQCP_EDGE_CONTINUITY_FAILSAFE &&
		    now_ms > service->entered_at_ms &&
		    now_ms - service->entered_at_ms >
			    service->maximum_duration_ms) {
			/* Latch: only an operator set_mode leaves it. */
			derived =
				PQCP_EDGE_CONTINUITY_FAILSAFE;
			service->mode_pinned = true;
		}
		if (derived != service->mode) {
			service->mode = derived;
			service->entered_at_ms = now_ms;
			++manager->transition_count;
		}
		if (service->mode > maximum) {
			maximum = service->mode;
		}
	}
	if (maximum != manager->global_mode) {
		manager->global_mode = maximum;
		++manager->transition_count;
	}
	*mode = maximum;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_continuity_manager_audit(
	struct pqcp_edge_continuity_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->services == NULL ||
	    manager->capacity == 0U ||
	    !mode_valid(manager->global_mode)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_continuity_service *service =
			&manager->services[index];

		if (!service->occupied) {
			continue;
		}
		if (!pqcp_edge_internal_text_valid(
			    service->service_id,
			    sizeof(service->service_id)) ||
		    !mode_valid(service->mode) ||
		    service->minimum_endpoints == 0U ||
		    (service->satisfied_dependencies &
		     ~service->dependency_mask) != 0U) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->services[other].occupied &&
			    strcmp(
				    service->service_id,
				    manager->services[other].
					    service_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
