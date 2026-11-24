/*
 * SPDX-License-Identifier: MIT
 *
 * Lease-aware service and endpoint registry for disconnected edge meshes.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "edge_security_internal.h"

static bool service_state_valid(
	enum pqcp_edge_service_state state)
{
	return state >= PQCP_EDGE_SERVICE_EMPTY &&
	       state <= PQCP_EDGE_SERVICE_RETIRED;
}

static bool endpoint_state_valid(
	enum pqcp_edge_endpoint_state state)
{
	return state >= PQCP_EDGE_ENDPOINT_EMPTY &&
	       state <= PQCP_EDGE_ENDPOINT_DRAINING;
}

static bool transport_valid(
	enum pqcp_edge_transport transport)
{
	return transport > PQCP_EDGE_TRANSPORT_NONE &&
	       transport <= PQCP_EDGE_TRANSPORT_CAN;
}

static bool service_valid(
	const struct pqcp_edge_service *service)
{
	return service != NULL &&
	       pqcp_edge_internal_text_valid(
		       service->service_id,
		       sizeof(service->service_id)) &&
	       pqcp_edge_internal_text_valid(
		       service->service_name,
		       sizeof(service->service_name)) &&
	       pqcp_edge_internal_text_valid(
		       service->owner_principal_id,
		       sizeof(service->owner_principal_id)) &&
	       pqcp_edge_internal_text_valid(
		       service->trust_domain,
		       sizeof(service->trust_domain)) &&
	       pqcp_edge_internal_text_valid(
		       service->zone,
		       sizeof(service->zone)) &&
	       service->operation_mask != 0U &&
	       service->minimum_trust <=
		       PQCP_EDGE_TRUST_PRIVILEGED &&
	       service_state_valid(service->state);
}

static bool endpoint_valid(
	const struct pqcp_edge_endpoint *endpoint)
{
	return endpoint != NULL &&
	       pqcp_edge_internal_text_valid(
		       endpoint->endpoint_id,
		       sizeof(endpoint->endpoint_id)) &&
	       pqcp_edge_internal_text_valid(
		       endpoint->service_id,
		       sizeof(endpoint->service_id)) &&
	       pqcp_edge_internal_text_valid(
		       endpoint->principal_id,
		       sizeof(endpoint->principal_id)) &&
	       pqcp_edge_internal_text_valid(
		       endpoint->address,
		       sizeof(endpoint->address)) &&
	       pqcp_edge_internal_text_valid(
		       endpoint->zone,
		       sizeof(endpoint->zone)) &&
	       transport_valid(endpoint->transport) &&
	       endpoint_state_valid(endpoint->state) &&
	       endpoint->maximum_requests != 0U &&
	       endpoint->weight != 0U;
}

static int service_index(
	const struct pqcp_edge_service_registry *registry,
	const char *service_id)
{
	if (registry == NULL || service_id == NULL) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < registry->service_capacity; ++index) {
		if (registry->services[index].state !=
			    PQCP_EDGE_SERVICE_EMPTY &&
		    strcmp(
			    registry->services[index].service_id,
			    service_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int endpoint_index(
	const struct pqcp_edge_service_registry *registry,
	const char *endpoint_id)
{
	if (registry == NULL || endpoint_id == NULL) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < registry->endpoint_capacity; ++index) {
		if (registry->endpoints[index].state !=
			    PQCP_EDGE_ENDPOINT_EMPTY &&
		    strcmp(
			    registry->endpoints[index].endpoint_id,
			    endpoint_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_service_index(
	const struct pqcp_edge_service_registry *registry)
{
	for (size_t index = 0U;
	     index < registry->service_capacity; ++index) {
		if (registry->services[index].state ==
		    PQCP_EDGE_SERVICE_EMPTY) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int free_endpoint_index(
	const struct pqcp_edge_service_registry *registry)
{
	for (size_t index = 0U;
	     index < registry->endpoint_capacity; ++index) {
		if (registry->endpoints[index].state ==
		    PQCP_EDGE_ENDPOINT_EMPTY) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static uint32_t endpoint_count_for_service(
	const struct pqcp_edge_service_registry *registry,
	const char *service_id)
{
	uint32_t count = 0U;

	for (size_t index = 0U;
	     index < registry->endpoint_capacity; ++index) {
		if (registry->endpoints[index].state !=
			    PQCP_EDGE_ENDPOINT_EMPTY &&
		    strcmp(
			    registry->endpoints[index].service_id,
			    service_id) == 0) {
			++count;
		}
	}
	return count;
}

static bool service_update_compatible(
	const struct pqcp_edge_service *current,
	const struct pqcp_edge_service *candidate)
{
	return strcmp(
		       current->owner_principal_id,
		       candidate->owner_principal_id) == 0 &&
	       strcmp(
		       current->trust_domain,
		       candidate->trust_domain) == 0 &&
	       candidate->policy_epoch >=
		       current->policy_epoch;
}

static bool endpoint_update_compatible(
	const struct pqcp_edge_endpoint *current,
	const struct pqcp_edge_endpoint *candidate)
{
	return strcmp(
		       current->service_id,
		       candidate->service_id) == 0 &&
	       strcmp(
		       current->principal_id,
		       candidate->principal_id) == 0 &&
	       current->transport == candidate->transport;
}

int pqcp_edge_service_registry_init(
	struct pqcp_edge_service_registry *registry,
	struct pqcp_edge_service *services,
	size_t service_capacity,
	struct pqcp_edge_endpoint *endpoints,
	size_t endpoint_capacity)
{
	if (registry == NULL || services == NULL ||
	    endpoints == NULL || service_capacity == 0U ||
	    endpoint_capacity == 0U) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(services, 0,
	       service_capacity * sizeof(*services));
	memset(endpoints, 0,
	       endpoint_capacity * sizeof(*endpoints));
	registry->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	registry->services = services;
	registry->service_capacity = service_capacity;
	registry->endpoints = endpoints;
	registry->endpoint_capacity = endpoint_capacity;
	registry->next_service_generation = 1U;
	registry->next_endpoint_generation = 1U;
	k_mutex_init(&registry->lock);
	registry->initialized = true;
	return 0;
}

int pqcp_edge_service_register(
	struct pqcp_edge_service_registry *registry,
	const struct pqcp_edge_service *service,
	uint64_t now_ms)
{
	struct pqcp_edge_service candidate;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    !service_valid(service) ||
	    service->lease_expires_at_ms <= now_ms ||
	    service->policy_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = service_index(registry, service->service_id);
	if (index >= 0) {
		struct pqcp_edge_service *current =
			&registry->services[index];

		if (current->state ==
			    PQCP_EDGE_SERVICE_RETIRED ||
		    !service_update_compatible(
			    current, service)) {
			ret = -EKEYREJECTED;
			goto out;
		}
		candidate = *service;
		candidate.schema_version =
			PQCP_EDGE_SCHEMA_VERSION;
		candidate.generation =
			current->generation;
		candidate.registered_at_ms =
			current->registered_at_ms;
		candidate.endpoint_count =
			endpoint_count_for_service(
				registry,
				service->service_id);
		if (candidate.state ==
		    PQCP_EDGE_SERVICE_EMPTY) {
			candidate.state =
				PQCP_EDGE_SERVICE_REGISTERED;
		}
		*current = candidate;
	} else if (index == -ENOENT) {
		index = free_service_index(registry);
		if (index < 0) {
			ret = index;
			goto out;
		}
		candidate = *service;
		candidate.schema_version =
			PQCP_EDGE_SCHEMA_VERSION;
		candidate.generation =
			pqcp_edge_internal_next_generation(
				&registry->
					next_service_generation);
		candidate.registered_at_ms = now_ms;
		candidate.endpoint_count = 0U;
		if (candidate.state ==
		    PQCP_EDGE_SERVICE_EMPTY) {
			candidate.state =
				PQCP_EDGE_SERVICE_REGISTERED;
		}
		registry->services[index] = candidate;
	} else {
		ret = index;
		goto out;
	}
	++registry->registration_count;
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_service_set_state(
	struct pqcp_edge_service_registry *registry,
	const char *service_id,
	enum pqcp_edge_service_state state,
	uint64_t now_ms)
{
	struct pqcp_edge_service *service;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    service_id == NULL || !service_state_valid(state) ||
	    state == PQCP_EDGE_SERVICE_EMPTY) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = service_index(registry, service_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	service = &registry->services[index];
	if (service->state == PQCP_EDGE_SERVICE_RETIRED &&
	    state != PQCP_EDGE_SERVICE_RETIRED) {
		ret = -EPERM;
		goto out;
	}
	if (state == PQCP_EDGE_SERVICE_HEALTHY &&
	    service->lease_expires_at_ms <= now_ms) {
		ret = -ESTALE;
		goto out;
	}
	service->state = state;
	if (state == PQCP_EDGE_SERVICE_RETIRED) {
		for (size_t endpoint = 0U;
		     endpoint < registry->endpoint_capacity;
		     ++endpoint) {
			if (registry->endpoints[endpoint].state !=
				    PQCP_EDGE_ENDPOINT_EMPTY &&
			    strcmp(
				    registry->endpoints[endpoint].
					    service_id,
				    service_id) == 0) {
				registry->endpoints[endpoint].state =
					PQCP_EDGE_ENDPOINT_DRAINING;
			}
		}
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_endpoint_register(
	struct pqcp_edge_service_registry *registry,
	const struct pqcp_edge_endpoint *endpoint,
	uint64_t now_ms)
{
	struct pqcp_edge_endpoint candidate;
	struct pqcp_edge_service *service;
	int service_slot;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    !endpoint_valid(endpoint) ||
	    endpoint->lease_expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	service_slot = service_index(
		registry, endpoint->service_id);
	if (service_slot < 0) {
		ret = -ENOENT;
		goto out;
	}
	service = &registry->services[service_slot];
	if (service->state ==
		    PQCP_EDGE_SERVICE_RETIRED ||
	    service->state ==
		    PQCP_EDGE_SERVICE_UNAVAILABLE ||
	    service->lease_expires_at_ms <= now_ms) {
		ret = -EHOSTDOWN;
		goto out;
	}
	if (strcmp(service->trust_domain,
		   endpoint->zone) == 0 &&
	    endpoint->transport ==
		    PQCP_EDGE_TRANSPORT_NONE) {
		ret = -EINVAL;
		goto out;
	}
	index = endpoint_index(
		registry, endpoint->endpoint_id);
	if (index >= 0) {
		struct pqcp_edge_endpoint *current =
			&registry->endpoints[index];

		if (!endpoint_update_compatible(
			    current, endpoint)) {
			ret = -EKEYREJECTED;
			goto out;
		}
		candidate = *endpoint;
		candidate.schema_version =
			PQCP_EDGE_SCHEMA_VERSION;
		candidate.generation =
			current->generation;
		candidate.registered_at_ms =
			current->registered_at_ms;
		candidate.active_requests =
			current->active_requests;
		candidate.consecutive_failures =
			current->consecutive_failures;
		candidate.latency_ewma_us =
			current->latency_ewma_us;
		if (candidate.state ==
		    PQCP_EDGE_ENDPOINT_EMPTY) {
			candidate.state =
				PQCP_EDGE_ENDPOINT_PROBING;
		}
		*current = candidate;
	} else if (index == -ENOENT) {
		index = free_endpoint_index(registry);
		if (index < 0) {
			ret = index;
			goto out;
		}
		candidate = *endpoint;
		candidate.schema_version =
			PQCP_EDGE_SCHEMA_VERSION;
		candidate.generation =
			pqcp_edge_internal_next_generation(
				&registry->
					next_endpoint_generation);
		candidate.registered_at_ms = now_ms;
		candidate.last_probe_ms = now_ms;
		candidate.active_requests = 0U;
		candidate.consecutive_failures = 0U;
		if (candidate.state ==
		    PQCP_EDGE_ENDPOINT_EMPTY) {
			candidate.state =
				PQCP_EDGE_ENDPOINT_PROBING;
		}
		registry->endpoints[index] = candidate;
		++service->endpoint_count;
	} else {
		ret = index;
		goto out;
	}
	++registry->registration_count;
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_endpoint_observe(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id,
	bool success,
	uint32_t latency_us,
	uint64_t now_ms)
{
	struct pqcp_edge_endpoint *endpoint;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    endpoint_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = endpoint_index(registry, endpoint_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	endpoint = &registry->endpoints[index];
	if (endpoint->state ==
		    PQCP_EDGE_ENDPOINT_EJECTED &&
	    now_ms < endpoint->ejected_until_ms) {
		ret = -EHOSTDOWN;
		goto out;
	}
	if (endpoint->lease_expires_at_ms <= now_ms) {
		endpoint->state =
			PQCP_EDGE_ENDPOINT_DRAINING;
		ret = -ESTALE;
		goto out;
	}
	endpoint->last_probe_ms = now_ms;
	if (success) {
		endpoint->consecutive_failures = 0U;
		if (endpoint->latency_ewma_us == 0U) {
			endpoint->latency_ewma_us =
				latency_us;
		} else {
			uint64_t weighted =
				(uint64_t)endpoint->
					latency_ewma_us * 7U +
				latency_us;
			endpoint->latency_ewma_us =
				(uint32_t)(weighted / 8U);
		}
		if (endpoint->state !=
		    PQCP_EDGE_ENDPOINT_DRAINING) {
			endpoint->state =
				PQCP_EDGE_ENDPOINT_READY;
		}
	} else {
		endpoint->consecutive_failures =
			pqcp_edge_internal_saturating_add_u32(
				endpoint->
					consecutive_failures,
				1U);
		if (endpoint->consecutive_failures >= 5U) {
			endpoint->state =
				PQCP_EDGE_ENDPOINT_EJECTED;
			endpoint->ejected_until_ms =
				pqcp_edge_internal_saturating_add_u64(
					now_ms, 60000U);
		} else {
			endpoint->state =
				PQCP_EDGE_ENDPOINT_DEGRADED;
		}
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_endpoint_eject(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id,
	uint64_t until_ms)
{
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    endpoint_id == NULL || until_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = endpoint_index(registry, endpoint_id);
	if (index < 0) {
		ret = index;
	} else {
		registry->endpoints[index].state =
			PQCP_EDGE_ENDPOINT_EJECTED;
		registry->endpoints[index].ejected_until_ms =
			until_ms;
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_endpoint_reserve(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id)
{
	struct pqcp_edge_endpoint *endpoint;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    endpoint_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = endpoint_index(registry, endpoint_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	endpoint = &registry->endpoints[index];
	if (endpoint->state !=
		    PQCP_EDGE_ENDPOINT_READY &&
	    endpoint->state !=
		    PQCP_EDGE_ENDPOINT_DEGRADED) {
		ret = -EHOSTDOWN;
	} else if (endpoint->active_requests >=
		   endpoint->maximum_requests) {
		ret = -EAGAIN;
	} else {
		++endpoint->active_requests;
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_endpoint_release(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id)
{
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    endpoint_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = endpoint_index(registry, endpoint_id);
	if (index < 0) {
		ret = index;
	} else if (registry->endpoints[index].
		   active_requests == 0U) {
		ret = -EALREADY;
	} else {
		--registry->endpoints[index].
			active_requests;
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_service_find(
	struct pqcp_edge_service_registry *registry,
	const char *service_id,
	struct pqcp_edge_service **service)
{
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    service_id == NULL || service == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = service_index(registry, service_id);
	if (index < 0) {
		*service = NULL;
		ret = index;
	} else {
		*service = &registry->services[index];
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_endpoint_find(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id,
	struct pqcp_edge_endpoint **endpoint)
{
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    endpoint_id == NULL || endpoint == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = endpoint_index(registry, endpoint_id);
	if (index < 0) {
		*endpoint = NULL;
		ret = index;
	} else {
		*endpoint = &registry->endpoints[index];
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_service_tick(
	struct pqcp_edge_service_registry *registry,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (registry == NULL || !registry->initialized ||
	    changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < registry->service_capacity; ++index) {
		struct pqcp_edge_service *service =
			&registry->services[index];

		if (service->state ==
			    PQCP_EDGE_SERVICE_EMPTY ||
		    service->state ==
			    PQCP_EDGE_SERVICE_RETIRED) {
			continue;
		}
		if (service->lease_expires_at_ms <= now_ms &&
		    service->state !=
			    PQCP_EDGE_SERVICE_UNAVAILABLE) {
			service->state =
				PQCP_EDGE_SERVICE_UNAVAILABLE;
			++registry->expiry_count;
			++changed;
		}
	}
	for (size_t index = 0U;
	     index < registry->endpoint_capacity; ++index) {
		struct pqcp_edge_endpoint *endpoint =
			&registry->endpoints[index];

		if (endpoint->state ==
		    PQCP_EDGE_ENDPOINT_EMPTY) {
			continue;
		}
		if (endpoint->lease_expires_at_ms <= now_ms &&
		    endpoint->state !=
			    PQCP_EDGE_ENDPOINT_DRAINING) {
			endpoint->state =
				PQCP_EDGE_ENDPOINT_DRAINING;
			++registry->expiry_count;
			++changed;
		}
		if (endpoint->state ==
			    PQCP_EDGE_ENDPOINT_EJECTED &&
		    endpoint->ejected_until_ms != UINT64_MAX &&
		    now_ms >= endpoint->ejected_until_ms &&
		    endpoint->lease_expires_at_ms > now_ms) {
			endpoint->state =
				PQCP_EDGE_ENDPOINT_PROBING;
			endpoint->ejected_until_ms = 0U;
			endpoint->consecutive_failures = 0U;
			++changed;
		}
	}
	k_mutex_unlock(&registry->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_edge_service_registry_audit(
	struct pqcp_edge_service_registry *registry)
{
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    registry->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    registry->services == NULL ||
	    registry->endpoints == NULL ||
	    registry->service_capacity == 0U ||
	    registry->endpoint_capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < registry->service_capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_service *service =
			&registry->services[index];

		if (service->state ==
		    PQCP_EDGE_SERVICE_EMPTY) {
			continue;
		}
		if (!service_valid(service) ||
		    service->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    service->generation == 0U ||
		    service->endpoint_count !=
			    endpoint_count_for_service(
				    registry,
				    service->service_id)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < registry->service_capacity; ++other) {
			if (registry->services[other].state !=
				    PQCP_EDGE_SERVICE_EMPTY &&
			    strcmp(
				    service->service_id,
				    registry->services[other].
					    service_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	for (size_t index = 0U;
	     index < registry->endpoint_capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_endpoint *endpoint =
			&registry->endpoints[index];

		if (endpoint->state ==
		    PQCP_EDGE_ENDPOINT_EMPTY) {
			continue;
		}
		if (!endpoint_valid(endpoint) ||
		    endpoint->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    endpoint->generation == 0U ||
		    endpoint->active_requests >
			    endpoint->maximum_requests ||
		    service_index(
			    registry,
			    endpoint->service_id) < 0) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < registry->endpoint_capacity; ++other) {
			if (registry->endpoints[other].state !=
				    PQCP_EDGE_ENDPOINT_EMPTY &&
			    strcmp(
				    endpoint->endpoint_id,
				    registry->endpoints[other].
					    endpoint_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}
