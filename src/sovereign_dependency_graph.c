/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free dependency topology for sovereign edge operations.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "sovereign_policy_internal.h"

#define DEPENDENCY_MAX_EDGES PQCP_SOVEREIGN_MAX_DEPENDENCIES
#define DEPENDENCY_SCORE_MAX 10000U

struct dependency_subject_set {
	char values[DEPENDENCY_MAX_EDGES + 1U]
		   [PQCP_SOVEREIGN_ID_MAX_CHARS];
	size_t count;
};

static uint64_t dependency_operation_mask(void)
{
	uint64_t mask = 0U;

	for (uint32_t operation =
		     (uint32_t)PQCP_SOVEREIGN_OPERATION_REGISTER;
	     operation < (uint32_t)PQCP_SOVEREIGN_OPERATION_COUNT;
	     ++operation) {
		mask |= 1ULL << operation;
	}
	return mask;
}

static bool dependency_edge_shape_valid(
	const struct pqcp_sovereign_dependency_edge *edge)
{
	const uint64_t allowed_operations =
		dependency_operation_mask();

	return edge != NULL &&
	       edge->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       edge->edge_id != 0U &&
	       pqcp_sovereign_policy_text_valid(
		       edge->source_id, sizeof(edge->source_id)) &&
	       pqcp_sovereign_policy_text_valid(
		       edge->destination_id,
		       sizeof(edge->destination_id)) &&
	       strcmp(edge->source_id, edge->destination_id) != 0 &&
	       pqcp_sovereign_policy_text_valid(
		       edge->dependency_type,
		       sizeof(edge->dependency_type)) &&
	       edge->operation_mask != 0U &&
	       (edge->operation_mask & ~allowed_operations) == 0U &&
	       edge->policy_epoch != 0U &&
	       edge->criticality <= DEPENDENCY_SCORE_MAX &&
	       edge->maximum_latency_ms != 0U &&
	       edge->minimum_availability_basis_points != 0U &&
	       edge->minimum_availability_basis_points <=
		       DEPENDENCY_SCORE_MAX &&
	       edge->occupied;
}

static bool dependency_edge_input_valid(
	const struct pqcp_sovereign_dependency_edge *edge)
{
	struct pqcp_sovereign_dependency_edge candidate;

	if (edge == NULL || edge->occupied) {
		return false;
	}
	candidate = *edge;
	candidate.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	if (candidate.edge_id == 0U) {
		candidate.edge_id = 1U;
	}
	candidate.occupied = true;
	return dependency_edge_shape_valid(&candidate);
}

static int dependency_lock(
	struct pqcp_sovereign_dependency_graph *graph)
{
	if (graph == NULL || !graph->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&graph->lock, K_FOREVER);
}

static void dependency_unlock(
	struct pqcp_sovereign_dependency_graph *graph)
{
	(void)k_mutex_unlock(&graph->lock);
}

static int dependency_edge_index_by_id_locked(
	const struct pqcp_sovereign_dependency_graph *graph,
	uint64_t edge_id)
{
	if (edge_id == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < graph->capacity; ++index) {
		if (graph->edges[index].occupied &&
		    graph->edges[index].edge_id == edge_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int dependency_free_index_locked(
	const struct pqcp_sovereign_dependency_graph *graph)
{
	for (size_t index = 0U; index < graph->capacity; ++index) {
		if (!graph->edges[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int dependency_tuple_index_locked(
	const struct pqcp_sovereign_dependency_graph *graph,
	const struct pqcp_sovereign_dependency_edge *edge,
	int ignored_index)
{
	for (size_t index = 0U; index < graph->capacity; ++index) {
		const struct pqcp_sovereign_dependency_edge *candidate =
			&graph->edges[index];

		if ((int)index == ignored_index ||
		    !candidate->occupied) {
			continue;
		}
		if (strcmp(candidate->source_id,
			   edge->source_id) == 0 &&
		    strcmp(candidate->destination_id,
			   edge->destination_id) == 0 &&
		    strcmp(candidate->dependency_type,
			   edge->dependency_type) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static bool dependency_edges_equal(
	const struct pqcp_sovereign_dependency_edge *left,
	const struct pqcp_sovereign_dependency_edge *right)
{
	return left->schema_version == right->schema_version &&
	       left->edge_id == right->edge_id &&
	       strcmp(left->source_id, right->source_id) == 0 &&
	       strcmp(left->destination_id,
		      right->destination_id) == 0 &&
	       strcmp(left->dependency_type,
		      right->dependency_type) == 0 &&
	       left->operation_mask == right->operation_mask &&
	       left->policy_epoch == right->policy_epoch &&
	       left->criticality == right->criticality &&
	       left->maximum_latency_ms ==
		       right->maximum_latency_ms &&
	       left->minimum_availability_basis_points ==
		       right->minimum_availability_basis_points &&
	       left->hard_dependency == right->hard_dependency &&
	       left->occupied == right->occupied;
}

static bool dependency_path_locked(
	const struct pqcp_sovereign_dependency_graph *graph,
	const char *current,
	const char *destination,
	uint32_t remaining_depth,
	int ignored_index)
{
	if (strcmp(current, destination) == 0) {
		return true;
	}
	if (remaining_depth == 0U) {
		return false;
	}
	for (size_t index = 0U; index < graph->capacity; ++index) {
		const struct pqcp_sovereign_dependency_edge *edge =
			&graph->edges[index];

		if ((int)index == ignored_index ||
		    !edge->occupied ||
		    strcmp(edge->source_id, current) != 0) {
			continue;
		}
		if (strcmp(edge->destination_id, destination) == 0) {
			return true;
		}
		if (dependency_path_locked(
			    graph, edge->destination_id,
			    destination, remaining_depth - 1U,
			    ignored_index)) {
			return true;
		}
	}
	return false;
}

static bool dependency_candidate_creates_cycle_locked(
	const struct pqcp_sovereign_dependency_graph *graph,
	const struct pqcp_sovereign_dependency_edge *candidate,
	int replaced_index)
{
	return dependency_path_locked(
		graph, candidate->destination_id,
		candidate->source_id, (uint32_t)graph->capacity,
		replaced_index);
}

static int dependency_assign_id_locked(
	struct pqcp_sovereign_dependency_graph *graph,
	uint64_t *edge_id)
{
	uint64_t candidate;
	size_t attempts = 0U;

	if (edge_id == NULL || *edge_id != 0U) {
		return -EINVAL;
	}
	while (attempts <= graph->capacity) {
		candidate = graph->next_edge_id;
		if (candidate == 0U) {
			candidate = 1U;
		}
		graph->next_edge_id =
			candidate == UINT64_MAX ? 1U : candidate + 1U;
		if (dependency_edge_index_by_id_locked(
			    graph, candidate) == -ENOENT) {
			*edge_id = candidate;
			return 0;
		}
		attempts++;
	}
	return -EOVERFLOW;
}

static void dependency_advance_generation_locked(
	struct pqcp_sovereign_dependency_graph *graph)
{
	graph->generation =
		pqcp_sovereign_policy_add_u64(
			graph->generation, 1U);
	if (graph->generation == 0U) {
		graph->generation = 1U;
	}
}

static bool dependency_subject_set_contains(
	const struct dependency_subject_set *set,
	const char *subject_id)
{
	for (size_t index = 0U; index < set->count; ++index) {
		if (strcmp(set->values[index], subject_id) == 0) {
			return true;
		}
	}
	return false;
}

static int dependency_subject_set_add(
	struct dependency_subject_set *set,
	const char *subject_id)
{
	int ret;

	if (dependency_subject_set_contains(set, subject_id)) {
		return 0;
	}
	if (set->count >= DEPENDENCY_MAX_EDGES + 1U) {
		return -ENOSPC;
	}
	ret = pqcp_sovereign_policy_copy_text(
		set->values[set->count],
		sizeof(set->values[set->count]), subject_id);
	if (ret == 0) {
		set->count++;
	}
	return ret;
}

int pqcp_sovereign_dependency_graph_init(
	struct pqcp_sovereign_dependency_graph *graph,
	struct pqcp_sovereign_dependency_edge *edges,
	size_t capacity)
{
	if (graph == NULL || edges == NULL || capacity == 0U ||
	    capacity > DEPENDENCY_MAX_EDGES) {
		return -EINVAL;
	}
	memset(graph, 0, sizeof(*graph));
	memset(edges, 0, capacity * sizeof(*edges));
	graph->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	graph->edges = edges;
	graph->capacity = capacity;
	graph->next_edge_id = 1U;
	graph->generation = 1U;
	k_mutex_init(&graph->lock);
	graph->initialized = true;
	return 0;
}

int pqcp_sovereign_dependency_put(
	struct pqcp_sovereign_dependency_graph *graph,
	const struct pqcp_sovereign_dependency_edge *edge)
{
	struct pqcp_sovereign_dependency_edge candidate;
	const struct pqcp_sovereign_dependency_edge *existing;
	int index;
	int ret;

	if (!dependency_edge_input_valid(edge)) {
		return -EINVAL;
	}
	ret = dependency_lock(graph);
	if (ret != 0) {
		return ret;
	}
	candidate = *edge;
	candidate.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.occupied = true;
	if (candidate.edge_id == 0U) {
		ret = dependency_assign_id_locked(
			graph, &candidate.edge_id);
		if (ret != 0) {
			dependency_unlock(graph);
			return ret;
		}
		index = dependency_free_index_locked(graph);
	} else {
		index = dependency_edge_index_by_id_locked(
			graph, candidate.edge_id);
		if (index < 0 && index != -ENOENT) {
			dependency_unlock(graph);
			return index;
		}
		if (index < 0) {
			index = dependency_free_index_locked(graph);
		}
	}
	if (index < 0) {
		dependency_unlock(graph);
		return index;
	}
	if (graph->edges[index].occupied) {
		existing = &graph->edges[index];
		if (strcmp(existing->source_id,
			   candidate.source_id) != 0 ||
		    strcmp(existing->destination_id,
			   candidate.destination_id) != 0 ||
		    strcmp(existing->dependency_type,
			   candidate.dependency_type) != 0) {
			dependency_unlock(graph);
			return -EACCES;
		}
		if (dependency_edges_equal(existing, &candidate)) {
			dependency_unlock(graph);
			return 0;
		}
		if (candidate.policy_epoch <=
		    existing->policy_epoch) {
			dependency_unlock(graph);
			return -ESTALE;
		}
	}
	if (dependency_tuple_index_locked(
		    graph, &candidate, index) >= 0) {
		dependency_unlock(graph);
		return -EEXIST;
	}
	if (dependency_candidate_creates_cycle_locked(
		    graph, &candidate, index)) {
		graph->cycle_rejection_count =
			pqcp_sovereign_policy_add_u64(
				graph->cycle_rejection_count, 1U);
		dependency_unlock(graph);
		return -ELOOP;
	}
	graph->edges[index] = candidate;
	dependency_advance_generation_locked(graph);
	dependency_unlock(graph);
	return 0;
}

int pqcp_sovereign_dependency_remove(
	struct pqcp_sovereign_dependency_graph *graph,
	uint64_t edge_id)
{
	int index;
	int ret;

	if (edge_id == 0U) {
		return -EINVAL;
	}
	ret = dependency_lock(graph);
	if (ret != 0) {
		return ret;
	}
	index = dependency_edge_index_by_id_locked(graph, edge_id);
	if (index < 0) {
		dependency_unlock(graph);
		return index;
	}
	memset(&graph->edges[index], 0,
	       sizeof(graph->edges[index]));
	dependency_advance_generation_locked(graph);
	dependency_unlock(graph);
	return 0;
}

int pqcp_sovereign_dependency_reachable(
	struct pqcp_sovereign_dependency_graph *graph,
	const char *source_id,
	const char *destination_id,
	uint32_t maximum_depth,
	bool *reachable)
{
	int ret;

	if (!pqcp_sovereign_policy_text_valid(
		    source_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_policy_text_valid(
		    destination_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    maximum_depth == 0U ||
	    maximum_depth > DEPENDENCY_MAX_EDGES ||
	    reachable == NULL) {
		return -EINVAL;
	}
	*reachable = false;
	ret = dependency_lock(graph);
	if (ret != 0) {
		return ret;
	}
	*reachable = dependency_path_locked(
		graph, source_id, destination_id,
		maximum_depth, -1);
	dependency_unlock(graph);
	return 0;
}

int pqcp_sovereign_dependency_impact(
	struct pqcp_sovereign_dependency_graph *graph,
	const char *subject_id,
	uint32_t *dependent_count,
	uint32_t *maximum_criticality)
{
	struct dependency_subject_set impacted;
	uint32_t highest = 0U;
	bool changed = true;
	int ret;

	if (!pqcp_sovereign_policy_text_valid(
		    subject_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    dependent_count == NULL ||
	    maximum_criticality == NULL) {
		return -EINVAL;
	}
	*dependent_count = 0U;
	*maximum_criticality = 0U;
	memset(&impacted, 0, sizeof(impacted));
	ret = dependency_subject_set_add(
		&impacted, subject_id);
	if (ret != 0) {
		return ret;
	}
	ret = dependency_lock(graph);
	if (ret != 0) {
		return ret;
	}
	for (size_t pass = 0U;
	     pass < graph->capacity && changed; ++pass) {
		changed = false;
		for (size_t index = 0U;
		     index < graph->capacity; ++index) {
			const struct pqcp_sovereign_dependency_edge *edge =
				&graph->edges[index];

			if (!edge->occupied ||
			    !dependency_subject_set_contains(
				    &impacted,
				    edge->destination_id)) {
				continue;
			}
			if (edge->criticality > highest) {
				highest = edge->criticality;
			}
			if (!dependency_subject_set_contains(
				    &impacted, edge->source_id)) {
				ret = dependency_subject_set_add(
					&impacted, edge->source_id);
				if (ret != 0) {
					dependency_unlock(graph);
					return ret;
				}
				changed = true;
			}
		}
	}
	if (changed) {
		dependency_unlock(graph);
		return -ELOOP;
	}
	*dependent_count =
		impacted.count > 0U ?
		(uint32_t)(impacted.count - 1U) : 0U;
	*maximum_criticality = highest;
	dependency_unlock(graph);
	return 0;
}

int pqcp_sovereign_dependency_graph_audit(
	struct pqcp_sovereign_dependency_graph *graph)
{
	int ret;

	if (graph == NULL || !graph->initialized ||
	    graph->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    graph->edges == NULL || graph->capacity == 0U ||
	    graph->capacity > DEPENDENCY_MAX_EDGES ||
	    graph->next_edge_id == 0U ||
	    graph->generation == 0U) {
		return -EINVAL;
	}
	ret = dependency_lock(graph);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < graph->capacity; ++index) {
		const struct pqcp_sovereign_dependency_edge *edge =
			&graph->edges[index];

		if (!edge->occupied) {
			continue;
		}
		if (!dependency_edge_shape_valid(edge)) {
			ret = -EBADMSG;
			goto out;
		}
		for (size_t other = index + 1U;
		     other < graph->capacity; ++other) {
			const struct pqcp_sovereign_dependency_edge *peer =
				&graph->edges[other];

			if (!peer->occupied) {
				continue;
			}
			if (peer->edge_id == edge->edge_id) {
				ret = -EEXIST;
				goto out;
			}
			if (strcmp(peer->source_id,
				   edge->source_id) == 0 &&
			    strcmp(peer->destination_id,
				   edge->destination_id) == 0 &&
			    strcmp(peer->dependency_type,
				   edge->dependency_type) == 0) {
				ret = -EEXIST;
				goto out;
			}
		}
		if (dependency_path_locked(
			    graph, edge->destination_id,
			    edge->source_id,
			    (uint32_t)graph->capacity,
			    (int)index)) {
			ret = -ELOOP;
			goto out;
		}
	}
	ret = 0;
out:
	dependency_unlock(graph);
	return ret;
}
