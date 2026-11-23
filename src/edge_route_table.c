/*
 * SPDX-License-Identifier: MIT
 *
 * Trust-aware deterministic route selection and failover.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "edge_security_internal.h"

static bool strategy_valid(
	enum pqcp_edge_route_strategy strategy)
{
	return strategy >= PQCP_EDGE_ROUTE_LOWEST_LATENCY &&
	       strategy <= PQCP_EDGE_ROUTE_DETERMINISTIC;
}

static int route_index(
	const struct pqcp_edge_route_table *table,
	uint64_t route_id)
{
	for (size_t index = 0U;
	     index < table->capacity; ++index) {
		if (table->routes[index].occupied &&
		    table->routes[index].route_id == route_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_route_index(
	const struct pqcp_edge_route_table *table,
	uint64_t now_ms)
{
	int oldest_index = -1;
	uint64_t oldest_expiry = UINT64_MAX;

	for (size_t index = 0U;
	     index < table->capacity; ++index) {
		if (!table->routes[index].occupied) {
			return (int)index;
		}
		if (table->routes[index].expires_at_ms <= now_ms &&
		    table->routes[index].expires_at_ms <
			    oldest_expiry) {
			oldest_expiry =
				table->routes[index].expires_at_ms;
			oldest_index = (int)index;
		}
	}
	return oldest_index >= 0 ? oldest_index : -ENOSPC;
}

static uint32_t bounded_load_basis_points(
	const struct pqcp_edge_endpoint *endpoint)
{
	uint64_t value;

	if (endpoint->maximum_requests == 0U) {
		return 10000U;
	}
	value = (uint64_t)endpoint->active_requests *
		10000U / endpoint->maximum_requests;
	return value > 10000U ? 10000U :
		(uint32_t)value;
}

static bool endpoint_eligible(
	const struct pqcp_edge_endpoint *endpoint,
	const struct pqcp_edge_principal *principal,
	const char *service_id,
	const char *excluded_endpoint,
	uint64_t now_ms)
{
	if (endpoint->state != PQCP_EDGE_ENDPOINT_READY &&
	    endpoint->state != PQCP_EDGE_ENDPOINT_DEGRADED) {
		return false;
	}
	if (strcmp(endpoint->service_id, service_id) != 0 ||
	    (excluded_endpoint != NULL &&
	     strcmp(endpoint->endpoint_id,
		    excluded_endpoint) == 0) ||
	    endpoint->lease_expires_at_ms <= now_ms ||
	    endpoint->active_requests >=
		    endpoint->maximum_requests) {
		return false;
	}
	if (endpoint->state ==
		    PQCP_EDGE_ENDPOINT_EJECTED &&
	    now_ms < endpoint->ejected_until_ms) {
		return false;
	}
	if (principal != NULL &&
	    endpoint->trust_score <
		    principal->risk_score / 2U) {
		return false;
	}
	return true;
}

static uint32_t zone_penalty(
	const char *source_zone,
	const char *destination_zone)
{
	return strcmp(source_zone, destination_zone) == 0 ?
		0U : 2000U;
}

static uint32_t deterministic_component(
	const char *principal_id,
	const char *endpoint_id)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	const uint8_t *parts[2] = {
		(const uint8_t *)principal_id,
		(const uint8_t *)endpoint_id,
	};
	size_t lengths[2] = {
		strlen(principal_id),
		strlen(endpoint_id),
	};

	if (pqcp_edge_internal_sha256_parts(
		    parts, lengths, 2U, digest) != 0) {
		return UINT32_MAX;
	}
	return pqcp_edge_internal_read_u32(digest);
}

static uint32_t candidate_score(
	const struct pqcp_edge_endpoint *endpoint,
	const struct pqcp_edge_principal *principal,
	enum pqcp_edge_route_strategy strategy)
{
	const uint32_t latency =
		endpoint->latency_ewma_us == 0U ?
			1000000U :
			endpoint->latency_ewma_us;
	const uint32_t load =
		bounded_load_basis_points(endpoint);
	const uint32_t trust_penalty =
		endpoint->trust_score >= 1000U ?
			0U :
			1000U - endpoint->trust_score;
	const uint32_t zone =
		zone_penalty(
			principal->zone, endpoint->zone);

	switch (strategy) {
	case PQCP_EDGE_ROUTE_LOWEST_LATENCY:
		return pqcp_edge_internal_saturating_add_u32(
			latency,
			pqcp_edge_internal_saturating_add_u32(
				load * 10U,
				trust_penalty * 100U));
	case PQCP_EDGE_ROUTE_LEAST_LOADED:
		return pqcp_edge_internal_saturating_add_u32(
			load * 100U,
			pqcp_edge_internal_saturating_add_u32(
				latency / 10U,
				trust_penalty * 100U));
	case PQCP_EDGE_ROUTE_HIGHEST_TRUST:
		return pqcp_edge_internal_saturating_add_u32(
			trust_penalty * 10000U,
			pqcp_edge_internal_saturating_add_u32(
				latency, load * 10U));
	case PQCP_EDGE_ROUTE_ZONE_AFFINITY:
		return pqcp_edge_internal_saturating_add_u32(
			zone * 10000U,
			pqcp_edge_internal_saturating_add_u32(
				latency, load * 10U));
	case PQCP_EDGE_ROUTE_DETERMINISTIC:
	default:
		return deterministic_component(
			principal->principal_id,
			endpoint->endpoint_id);
	}
}

static int select_endpoint_index(
	struct pqcp_edge_service_registry *registry,
	const struct pqcp_edge_principal *principal,
	const char *service_id,
	enum pqcp_edge_route_strategy strategy,
	const char *excluded_endpoint,
	uint64_t now_ms,
	uint32_t *selected_score)
{
	int selected = -ENOENT;
	uint32_t best_score = UINT32_MAX;
	uint32_t best_priority = UINT32_MAX;

	for (size_t index = 0U;
	     index < registry->endpoint_capacity; ++index) {
		const struct pqcp_edge_endpoint *endpoint =
			&registry->endpoints[index];
		uint32_t score;

		if (!endpoint_eligible(
			    endpoint, principal, service_id,
			    excluded_endpoint, now_ms)) {
			continue;
		}
		score = candidate_score(
			endpoint, principal, strategy);
		if (selected < 0 ||
		    endpoint->priority < best_priority ||
		    (endpoint->priority == best_priority &&
		     score < best_score) ||
		    (endpoint->priority == best_priority &&
		     score == best_score &&
		     strcmp(
			     endpoint->endpoint_id,
			     registry->endpoints[selected].
				     endpoint_id) < 0)) {
			selected = (int)index;
			best_score = score;
			best_priority = endpoint->priority;
		}
	}
	if (selected >= 0 && selected_score != NULL) {
		*selected_score = best_score;
	}
	return selected;
}

static int compute_route_digest(
	const struct pqcp_edge_route *route,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[48];
	const uint8_t *parts[6];
	size_t lengths[6];
	size_t offset = 0U;

	pqcp_edge_internal_write_u32(
		numeric + offset, route->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, route->route_id);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, route->strategy);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, route->selected_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, route->expires_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, route->score);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, route->failover_count);
	offset += 4U;
	parts[0] = numeric;
	lengths[0] = offset;
	parts[1] =
		(const uint8_t *)route->source_principal_id;
	lengths[1] = strlen(route->source_principal_id);
	parts[2] = (const uint8_t *)route->service_id;
	lengths[2] = strlen(route->service_id);
	parts[3] = (const uint8_t *)route->endpoint_id;
	lengths[3] = strlen(route->endpoint_id);
	parts[4] = (const uint8_t *)route->source_zone;
	lengths[4] = strlen(route->source_zone);
	parts[5] =
		(const uint8_t *)route->destination_zone;
	lengths[5] = strlen(route->destination_zone);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 6U, output);
}

static bool route_valid(
	const struct pqcp_edge_route *route)
{
	return route != NULL && route->occupied &&
	       route->schema_version ==
		       PQCP_EDGE_SCHEMA_VERSION &&
	       route->route_id != 0U &&
	       strategy_valid(route->strategy) &&
	       route->expires_at_ms >
		       route->selected_at_ms &&
	       pqcp_edge_internal_text_valid(
		       route->source_principal_id,
		       sizeof(route->source_principal_id)) &&
	       pqcp_edge_internal_text_valid(
		       route->service_id,
		       sizeof(route->service_id)) &&
	       pqcp_edge_internal_text_valid(
		       route->endpoint_id,
		       sizeof(route->endpoint_id)) &&
	       pqcp_edge_internal_text_valid(
		       route->source_zone,
		       sizeof(route->source_zone)) &&
	       pqcp_edge_internal_text_valid(
		       route->destination_zone,
		       sizeof(route->destination_zone));
}

int pqcp_edge_route_table_init(
	struct pqcp_edge_route_table *table,
	struct pqcp_edge_route *routes,
	size_t capacity)
{
	if (table == NULL || routes == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(table, 0, sizeof(*table));
	memset(routes, 0, capacity * sizeof(*routes));
	table->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	table->routes = routes;
	table->capacity = capacity;
	table->next_route_id = 1U;
	k_mutex_init(&table->lock);
	table->initialized = true;
	return 0;
}

int pqcp_edge_route_select(
	struct pqcp_edge_route_table *table,
	struct pqcp_edge_service_registry *registry,
	const struct pqcp_edge_principal *principal,
	const char *service_id,
	enum pqcp_edge_route_strategy strategy,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	struct pqcp_edge_route **route)
{
	struct pqcp_edge_route candidate;
	struct pqcp_edge_service *service;
	int endpoint_slot;
	int route_slot;
	int service_slot;
	int ret = 0;
	uint32_t score = 0U;

	if (table == NULL || !table->initialized ||
	    registry == NULL || !registry->initialized ||
	    principal == NULL || service_id == NULL ||
	    route == NULL || !strategy_valid(strategy) ||
	    lifetime_ms == 0U ||
	    principal->state !=
		    PQCP_EDGE_PRINCIPAL_ACTIVE) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	service_slot = -ENOENT;
	for (size_t index = 0U;
	     index < registry->service_capacity; ++index) {
		if (registry->services[index].state !=
			    PQCP_EDGE_SERVICE_EMPTY &&
		    strcmp(
			    registry->services[index].service_id,
			    service_id) == 0) {
			service_slot = (int)index;
			break;
		}
	}
	if (service_slot < 0) {
		ret = service_slot;
		goto registry_out;
	}
	service = &registry->services[service_slot];
	if ((service->state != PQCP_EDGE_SERVICE_HEALTHY &&
	     service->state !=
		     PQCP_EDGE_SERVICE_REGISTERED) ||
	    service->lease_expires_at_ms <= now_ms) {
		ret = -EHOSTDOWN;
		goto registry_out;
	}
	endpoint_slot = select_endpoint_index(
		registry, principal, service_id, strategy,
		NULL, now_ms, &score);
	if (endpoint_slot < 0) {
		ret = endpoint_slot;
		goto registry_out;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	ret = pqcp_edge_internal_copy_text(
		candidate.source_principal_id,
		sizeof(candidate.source_principal_id),
		principal->principal_id);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.service_id,
			sizeof(candidate.service_id),
			service_id);
	}
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.endpoint_id,
			sizeof(candidate.endpoint_id),
			registry->endpoints[endpoint_slot].
				endpoint_id);
	}
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.source_zone,
			sizeof(candidate.source_zone),
			principal->zone);
	}
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.destination_zone,
			sizeof(candidate.destination_zone),
			registry->endpoints[endpoint_slot].zone);
	}
	if (ret != 0) {
		goto registry_out;
	}
	candidate.strategy = strategy;
	candidate.selected_at_ms = now_ms;
	candidate.expires_at_ms =
		pqcp_edge_internal_saturating_add_u64(
			now_ms, lifetime_ms);
	candidate.score = score;
	candidate.occupied = true;
registry_out:
	k_mutex_unlock(&registry->lock);
	if (ret != 0) {
		*route = NULL;
		return ret;
	}
	k_mutex_lock(&table->lock, K_FOREVER);
	route_slot = free_route_index(table, now_ms);
	if (route_slot < 0) {
		ret = route_slot;
		goto table_out;
	}
	candidate.route_id =
		pqcp_edge_internal_next_identifier(
			&table->next_route_id);
	ret = compute_route_digest(
		&candidate, candidate.route_digest);
	if (ret == 0) {
		table->routes[route_slot] = candidate;
		*route = &table->routes[route_slot];
		++table->selection_count;
	}
table_out:
	k_mutex_unlock(&table->lock);
	if (ret != 0) {
		*route = NULL;
	}
	return ret;
}

int pqcp_edge_route_failover(
	struct pqcp_edge_route_table *table,
	struct pqcp_edge_service_registry *registry,
	uint64_t route_id,
	uint64_t now_ms)
{
	struct pqcp_edge_principal synthetic;
	struct pqcp_edge_route *route;
	int endpoint_slot;
	int index;
	int ret = 0;
	uint32_t score = 0U;

	if (table == NULL || !table->initialized ||
	    registry == NULL || !registry->initialized ||
	    route_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&table->lock, K_FOREVER);
	index = route_index(table, route_id);
	if (index < 0) {
		ret = index;
		goto table_out;
	}
	route = &table->routes[index];
	if (route->expires_at_ms <= now_ms) {
		ret = -ESTALE;
		goto table_out;
	}
	memset(&synthetic, 0, sizeof(synthetic));
	(void)pqcp_edge_internal_copy_text(
		synthetic.principal_id,
		sizeof(synthetic.principal_id),
		route->source_principal_id);
	(void)pqcp_edge_internal_copy_text(
		synthetic.zone, sizeof(synthetic.zone),
		route->source_zone);
	k_mutex_lock(&registry->lock, K_FOREVER);
	endpoint_slot = select_endpoint_index(
		registry, &synthetic, route->service_id,
		route->strategy, route->endpoint_id,
		now_ms, &score);
	if (endpoint_slot < 0) {
		ret = endpoint_slot;
	} else {
		ret = pqcp_edge_internal_copy_text(
			route->endpoint_id,
			sizeof(route->endpoint_id),
			registry->endpoints[endpoint_slot].
				endpoint_id);
		if (ret == 0) {
			ret = pqcp_edge_internal_copy_text(
				route->destination_zone,
				sizeof(route->destination_zone),
				registry->endpoints[
					endpoint_slot].zone);
		}
		if (ret == 0) {
			route->score = score;
			route->selected_at_ms = now_ms;
			route->failover_count =
				pqcp_edge_internal_saturating_add_u32(
					route->failover_count,
					1U);
			ret = compute_route_digest(
				route, route->route_digest);
		}
	}
	k_mutex_unlock(&registry->lock);
	if (ret == 0) {
		++table->failover_count;
	}
table_out:
	k_mutex_unlock(&table->lock);
	return ret;
}

int pqcp_edge_route_expire(
	struct pqcp_edge_route_table *table,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (table == NULL || !table->initialized ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&table->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < table->capacity; ++index) {
		if (table->routes[index].occupied &&
		    table->routes[index].expires_at_ms <= now_ms) {
			memset(&table->routes[index], 0,
			       sizeof(table->routes[index]));
			++expired;
		}
	}
	k_mutex_unlock(&table->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_route_table_audit(
	struct pqcp_edge_route_table *table)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret = 0;

	if (table == NULL || !table->initialized ||
	    table->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    table->routes == NULL || table->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&table->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < table->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_route *route =
			&table->routes[index];

		if (!route->occupied) {
			continue;
		}
		if (!route_valid(route) ||
		    compute_route_digest(route, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    route->route_digest, digest,
			    sizeof(digest))) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < table->capacity; ++other) {
			if (table->routes[other].occupied &&
			    table->routes[other].route_id ==
				    route->route_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&table->lock);
	return ret;
}
