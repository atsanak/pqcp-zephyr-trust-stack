/*
 * SPDX-License-Identifier: MIT
 *
 * Attestation-aware sovereign workload placement.
 */

#include <errno.h>
#include <string.h>

#include "sovereign_policy_internal.h"

static bool optional_text_matches(const char *required, const char *actual)
{
	return required[0] == '\0' || strcmp(required, actual) == 0;
}

static bool reservation_state_valid(
	enum pqcp_sovereign_lifecycle_state state)
{
	return state >= PQCP_SOVEREIGN_LIFECYCLE_DRAFT &&
	       state <= PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
}

static bool node_valid(const struct pqcp_sovereign_placement_node *node)
{
	return node != NULL &&
	       node->schema_version == PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       node->generation != 0U &&
	       pqcp_sovereign_policy_text_valid(
		       node->node_id, sizeof(node->node_id)) &&
	       pqcp_sovereign_policy_text_valid(
		       node->tenant_id, sizeof(node->tenant_id)) &&
	       pqcp_sovereign_policy_text_valid(
		       node->zone, sizeof(node->zone)) &&
	       pqcp_sovereign_policy_text_valid(
		       node->jurisdiction, sizeof(node->jurisdiction)) &&
	       node->policy_epoch != 0U &&
	       node->attested_at_ms != 0U &&
	       node->attestation_expires_at_ms > node->attested_at_ms &&
	       node->available_compute_units <= node->total_compute_units &&
	       node->available_memory_bytes <= node->total_memory_bytes &&
	       node->active_workloads <= node->maximum_workloads;
}

static int node_index(
	const struct pqcp_sovereign_placement_engine *engine,
	const char *tenant_id,
	const char *node_id)
{
	for (size_t index = 0U; index < engine->node_capacity; ++index) {
		if (engine->nodes[index].occupied &&
		    strcmp(engine->nodes[index].tenant_id, tenant_id) == 0 &&
		    strcmp(engine->nodes[index].node_id, node_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int free_node_index(
	const struct pqcp_sovereign_placement_engine *engine)
{
	for (size_t index = 0U; index < engine->node_capacity; ++index) {
		if (!engine->nodes[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static int reservation_index(
	const struct pqcp_sovereign_placement_engine *engine,
	uint64_t reservation_id)
{
	for (size_t index = 0U;
	     index < engine->reservation_capacity; ++index) {
		if (engine->reservations[index].occupied &&
		    engine->reservations[index].reservation_id ==
			    reservation_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_reservation_index(
	const struct pqcp_sovereign_placement_engine *engine)
{
	for (size_t index = 0U;
	     index < engine->reservation_capacity; ++index) {
		if (!engine->reservations[index].occupied) {
			return (int)index;
		}
	}
	/* Released (RETIRED) and expired (REVOKED) reservations hold no
	 * resources and ids are never reused, so their slots can be recycled.
	 * Without this every reserve/release cycle leaked a slot until the
	 * table reported -ENOSPC forever.
	 */
	for (size_t index = 0U;
	     index < engine->reservation_capacity; ++index) {
		const enum pqcp_sovereign_lifecycle_state state =
			engine->reservations[index].state;

		if (state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
		    state == PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
			return (int)index;
		}
	}
	return -1;
}

static void restore_reservation(
	struct pqcp_sovereign_placement_engine *engine,
	struct pqcp_sovereign_placement_reservation *reservation)
{
	for (size_t index = 0U; index < engine->node_capacity; ++index) {
		struct pqcp_sovereign_placement_node *node =
			&engine->nodes[index];

		if (!node->occupied ||
		    strcmp(node->tenant_id, reservation->tenant_id) != 0 ||
		    strcmp(node->node_id, reservation->node_id) != 0) {
			continue;
		}
		node->available_compute_units =
			pqcp_sovereign_policy_add_u64(
				node->available_compute_units,
				reservation->compute_units);
		if (node->available_compute_units >
		    node->total_compute_units) {
			node->available_compute_units =
				node->total_compute_units;
		}
		node->available_memory_bytes =
			pqcp_sovereign_policy_add_u64(
				node->available_memory_bytes,
				reservation->memory_bytes);
		if (node->available_memory_bytes >
		    node->total_memory_bytes) {
			node->available_memory_bytes =
				node->total_memory_bytes;
		}
		if (node->active_workloads != 0U) {
			node->active_workloads--;
		}
		break;
	}
}

int pqcp_sovereign_placement_engine_init(
	struct pqcp_sovereign_placement_engine *engine,
	struct pqcp_sovereign_placement_node *nodes,
	size_t node_capacity,
	struct pqcp_sovereign_placement_reservation *reservations,
	size_t reservation_capacity)
{
	if (engine == NULL || nodes == NULL || node_capacity == 0U ||
	    reservations == NULL || reservation_capacity == 0U) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(nodes, 0, node_capacity * sizeof(nodes[0]));
	memset(reservations, 0,
	       reservation_capacity * sizeof(reservations[0]));
	engine->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	engine->nodes = nodes;
	engine->node_capacity = node_capacity;
	engine->reservations = reservations;
	engine->reservation_capacity = reservation_capacity;
	engine->next_node_generation = 1U;
	engine->next_reservation_id = 1U;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_sovereign_placement_node_put(
	struct pqcp_sovereign_placement_engine *engine,
	const struct pqcp_sovereign_placement_node *node,
	uint64_t now_ms)
{
	struct pqcp_sovereign_placement_node candidate;
	int index;

	if (engine == NULL || !engine->initialized ||
	    node == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	candidate = *node;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	if (candidate.generation == 0U) {
		candidate.generation =
			pqcp_sovereign_policy_next_generation(
				&engine->next_node_generation);
	}
	if (!node_valid(&candidate) ||
	    now_ms >= candidate.attestation_expires_at_ms) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = node_index(
		engine, candidate.tenant_id, candidate.node_id);
	if (index < 0) {
		index = free_node_index(engine);
	}
	if (index < 0) {
		k_mutex_unlock(&engine->lock);
		return -ENOSPC;
	}
	if (engine->nodes[index].occupied &&
	    engine->nodes[index].active_workloads != 0U &&
	    (candidate.available_compute_units <
		     engine->nodes[index].available_compute_units ||
	     candidate.available_memory_bytes <
		     engine->nodes[index].available_memory_bytes)) {
		k_mutex_unlock(&engine->lock);
		return -EBUSY;
	}
	candidate.occupied = true;
	engine->nodes[index] = candidate;
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_sovereign_placement_reserve(
	struct pqcp_sovereign_placement_engine *engine,
	const struct pqcp_sovereign_placement_request *request,
	uint64_t lifetime_ms,
	struct pqcp_sovereign_placement_reservation **reservation)
{
	struct pqcp_sovereign_placement_node *selected = NULL;
	struct pqcp_sovereign_placement_reservation *slot;
	int slot_index;

	if (engine == NULL || !engine->initialized ||
	    request == NULL || reservation == NULL ||
	    !pqcp_sovereign_policy_text_valid(
		    request->workload_id, sizeof(request->workload_id)) ||
	    !pqcp_sovereign_policy_text_valid(
		    request->tenant_id, sizeof(request->tenant_id)) ||
	    request->compute_units == 0U ||
	    request->memory_bytes == 0U ||
	    request->policy_epoch == 0U || request->now_ms == 0U ||
	    lifetime_ms == 0U) {
		return -EINVAL;
	}
	*reservation = NULL;
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U; index < engine->node_capacity; ++index) {
		struct pqcp_sovereign_placement_node *node =
			&engine->nodes[index];

		if (!node->occupied ||
		    strcmp(node->tenant_id, request->tenant_id) != 0 ||
		    !optional_text_matches(
			    request->required_zone, node->zone) ||
		    !optional_text_matches(
			    request->required_jurisdiction,
			    node->jurisdiction) ||
		    (node->capability_mask &
		     request->required_capabilities) !=
			    request->required_capabilities ||
		    node->available_compute_units <
			    request->compute_units ||
		    node->available_memory_bytes <
			    request->memory_bytes ||
		    node->policy_epoch != request->policy_epoch ||
		    request->now_ms >= node->attestation_expires_at_ms ||
		    node->risk_score > request->maximum_risk ||
		    node->active_workloads >= node->maximum_workloads ||
		    (request->require_confidential_compute &&
		     !node->confidential_compute)) {
			continue;
		}
		if (selected == NULL ||
		    node->risk_score < selected->risk_score ||
		    (node->risk_score == selected->risk_score &&
		     node->available_compute_units >
			     selected->available_compute_units) ||
		    (node->risk_score == selected->risk_score &&
		     node->available_compute_units ==
			     selected->available_compute_units &&
		     strcmp(node->node_id, selected->node_id) < 0)) {
			selected = node;
		}
	}
	slot_index = free_reservation_index(engine);
	if (selected == NULL || slot_index < 0) {
		engine->denial_count =
			pqcp_sovereign_policy_add_u64(
				engine->denial_count, 1U);
		k_mutex_unlock(&engine->lock);
		return selected == NULL ? -ENODEV : -ENOSPC;
	}
	slot = &engine->reservations[slot_index];
	memset(slot, 0, sizeof(*slot));
	slot->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	slot->reservation_id =
		pqcp_sovereign_policy_next_id(
			&engine->next_reservation_id);
	(void)pqcp_sovereign_policy_copy_text(
		slot->workload_id, sizeof(slot->workload_id),
		request->workload_id);
	(void)pqcp_sovereign_policy_copy_text(
		slot->tenant_id, sizeof(slot->tenant_id),
		selected->tenant_id);
	(void)pqcp_sovereign_policy_copy_text(
		slot->node_id, sizeof(slot->node_id),
		selected->node_id);
	slot->compute_units = request->compute_units;
	slot->memory_bytes = request->memory_bytes;
	slot->reserved_at_ms = request->now_ms;
	slot->expires_at_ms =
		pqcp_sovereign_policy_add_u64(
			request->now_ms, lifetime_ms);
	slot->state = PQCP_SOVEREIGN_LIFECYCLE_DRAFT;
	slot->occupied = true;
	selected->available_compute_units -= request->compute_units;
	selected->available_memory_bytes -= request->memory_bytes;
	selected->active_workloads++;
	engine->placement_count =
		pqcp_sovereign_policy_add_u64(
			engine->placement_count, 1U);
	*reservation = slot;
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_sovereign_placement_activate(
	struct pqcp_sovereign_placement_engine *engine,
	uint64_t reservation_id)
{
	int index;

	if (engine == NULL || !engine->initialized ||
	    reservation_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = reservation_index(engine, reservation_id);
	if (index < 0) {
		k_mutex_unlock(&engine->lock);
		return -ENOENT;
	}
	if (engine->reservations[index].state !=
	    PQCP_SOVEREIGN_LIFECYCLE_DRAFT) {
		k_mutex_unlock(&engine->lock);
		return -EALREADY;
	}
	engine->reservations[index].state =
		PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_sovereign_placement_release(
	struct pqcp_sovereign_placement_engine *engine,
	uint64_t reservation_id)
{
	int index;

	if (engine == NULL || !engine->initialized ||
	    reservation_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = reservation_index(engine, reservation_id);
	if (index < 0) {
		k_mutex_unlock(&engine->lock);
		return -ENOENT;
	}
	if (engine->reservations[index].state ==
		    PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
	    engine->reservations[index].state ==
		    PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
		k_mutex_unlock(&engine->lock);
		return -EALREADY;
	}
	restore_reservation(engine, &engine->reservations[index]);
	engine->reservations[index].state =
		PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_sovereign_placement_tick(
	struct pqcp_sovereign_placement_engine *engine,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t count = 0U;

	if (engine == NULL || !engine->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->reservation_capacity; ++index) {
		struct pqcp_sovereign_placement_reservation *entry =
			&engine->reservations[index];

		if (entry->occupied &&
		    entry->state == PQCP_SOVEREIGN_LIFECYCLE_DRAFT &&
		    now_ms >= entry->expires_at_ms) {
			restore_reservation(engine, entry);
			entry->state =
				PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
			count++;
		}
	}
	k_mutex_unlock(&engine->lock);
	if (expired_count != NULL) {
		*expired_count = count;
	}
	return 0;
}

int pqcp_sovereign_placement_engine_audit(
	struct pqcp_sovereign_placement_engine *engine)
{
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    engine->nodes == NULL || engine->node_capacity == 0U ||
	    engine->reservations == NULL ||
	    engine->reservation_capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->node_capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_placement_node *node =
			&engine->nodes[index];

		if (!node->occupied) {
			continue;
		}
		if (!node_valid(node)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < engine->node_capacity; ++other) {
			if (engine->nodes[other].occupied &&
			    strcmp(node->tenant_id,
				   engine->nodes[other].tenant_id) == 0 &&
			    strcmp(node->node_id,
				   engine->nodes[other].node_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	for (size_t index = 0U;
	     index < engine->reservation_capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_placement_reservation *entry =
			&engine->reservations[index];
		bool found = false;

		if (!entry->occupied) {
			continue;
		}
		if (entry->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    entry->reservation_id == 0U ||
		    !pqcp_sovereign_policy_text_valid(
			    entry->workload_id,
			    sizeof(entry->workload_id)) ||
		    !pqcp_sovereign_policy_text_valid(
			    entry->tenant_id, sizeof(entry->tenant_id)) ||
		    !pqcp_sovereign_policy_text_valid(
			    entry->node_id, sizeof(entry->node_id)) ||
		    entry->compute_units == 0U ||
		    entry->memory_bytes == 0U ||
		    entry->expires_at_ms <= entry->reserved_at_ms ||
		    !reservation_state_valid(entry->state)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t node = 0U; node < engine->node_capacity; ++node) {
			if (engine->nodes[node].occupied &&
			    strcmp(engine->nodes[node].tenant_id,
				   entry->tenant_id) == 0 &&
			    strcmp(engine->nodes[node].node_id,
				   entry->node_id) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			ret = -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < engine->reservation_capacity && ret == 0;
		     ++other) {
			if (engine->reservations[other].occupied &&
			    engine->reservations[other].reservation_id ==
				    entry->reservation_id) {
				ret = -EEXIST;
			}
		}
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}
