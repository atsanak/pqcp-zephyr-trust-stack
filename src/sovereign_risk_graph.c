/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free bounded risk propagation for sovereign edge operations.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "sovereign_policy_internal.h"

#define RISK_SCORE_MAX 10000U
#define RISK_MAX_NODES PQCP_SOVEREIGN_MAX_COMPONENTS
#define RISK_MAX_EDGES (PQCP_SOVEREIGN_MAX_COMPONENTS * 2U)
#define RISK_MAX_ITERATIONS (PQCP_SOVEREIGN_MAX_COMPONENTS * 2U)

static uint32_t risk_union(uint32_t left, uint32_t right)
{
	uint64_t overlap;
	uint64_t combined;

	if (left >= RISK_SCORE_MAX || right >= RISK_SCORE_MAX) {
		return RISK_SCORE_MAX;
	}
	overlap = ((uint64_t)left * (uint64_t)right) /
		  RISK_SCORE_MAX;
	combined = (uint64_t)left + (uint64_t)right - overlap;
	return combined > RISK_SCORE_MAX ?
	       RISK_SCORE_MAX : (uint32_t)combined;
}

static uint32_t risk_base(
	const struct pqcp_sovereign_risk_node *node)
{
	uint32_t gross;
	uint64_t controlled;

	gross = risk_union(
		node->inherent_risk, node->exposure_score);
	controlled =
		(uint64_t)gross *
		(uint64_t)(RISK_SCORE_MAX -
			   node->control_strength);
	controlled /= RISK_SCORE_MAX;
	return controlled > RISK_SCORE_MAX ?
	       RISK_SCORE_MAX : (uint32_t)controlled;
}

static uint32_t risk_edge_contribution(
	uint32_t source_risk,
	const struct pqcp_sovereign_risk_edge *edge)
{
	uint64_t contribution = source_risk;

	contribution *= edge->propagation_basis_points;
	contribution /= RISK_SCORE_MAX;
	contribution *= edge->confidence_basis_points;
	contribution /= RISK_SCORE_MAX;
	return contribution > RISK_SCORE_MAX ?
	       RISK_SCORE_MAX : (uint32_t)contribution;
}

static bool risk_node_shape_valid(
	const struct pqcp_sovereign_risk_node *node)
{
	return node != NULL &&
	       node->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       node->generation != 0U &&
	       pqcp_sovereign_policy_text_valid(
		       node->subject_id, sizeof(node->subject_id)) &&
	       pqcp_sovereign_policy_text_valid(
		       node->subject_type,
		       sizeof(node->subject_type)) &&
	       node->observed_at_ms != 0U &&
	       node->expires_at_ms > node->observed_at_ms &&
	       node->policy_epoch != 0U &&
	       node->inherent_risk <= RISK_SCORE_MAX &&
	       node->control_strength <= RISK_SCORE_MAX &&
	       node->exposure_score <= RISK_SCORE_MAX &&
	       node->propagated_risk <= RISK_SCORE_MAX &&
	       node->residual_risk <= RISK_SCORE_MAX &&
	       !pqcp_sovereign_policy_all_zero(
		       node->evidence_digest,
		       sizeof(node->evidence_digest)) &&
	       node->occupied;
}

static bool risk_node_input_valid(
	const struct pqcp_sovereign_risk_node *node,
	uint64_t now_ms)
{
	struct pqcp_sovereign_risk_node candidate;

	if (node == NULL || node->occupied || now_ms == 0U ||
	    node->observed_at_ms > now_ms ||
	    node->expires_at_ms <= now_ms) {
		return false;
	}
	candidate = *node;
	candidate.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	if (candidate.generation == 0U) {
		candidate.generation = 1U;
	}
	candidate.propagated_risk = 0U;
	candidate.residual_risk = risk_base(&candidate);
	candidate.occupied = true;
	return risk_node_shape_valid(&candidate);
}

static bool risk_edge_shape_valid(
	const struct pqcp_sovereign_risk_edge *edge)
{
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
	       edge->propagation_basis_points != 0U &&
	       edge->propagation_basis_points <= RISK_SCORE_MAX &&
	       edge->confidence_basis_points != 0U &&
	       edge->confidence_basis_points <= RISK_SCORE_MAX &&
	       edge->expires_at_ms != 0U &&
	       edge->occupied;
}

static bool risk_edge_input_valid(
	const struct pqcp_sovereign_risk_edge *edge)
{
	struct pqcp_sovereign_risk_edge candidate;

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
	return risk_edge_shape_valid(&candidate);
}

static int risk_lock(struct pqcp_sovereign_risk_graph *graph)
{
	if (graph == NULL || !graph->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&graph->lock, K_FOREVER);
}

static void risk_unlock(struct pqcp_sovereign_risk_graph *graph)
{
	(void)k_mutex_unlock(&graph->lock);
}

static int risk_node_index_locked(
	const struct pqcp_sovereign_risk_graph *graph,
	const char *subject_id)
{
	for (size_t index = 0U; index < graph->node_capacity;
	     ++index) {
		if (graph->nodes[index].occupied &&
		    strcmp(graph->nodes[index].subject_id,
			   subject_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int risk_free_node_index_locked(
	const struct pqcp_sovereign_risk_graph *graph)
{
	for (size_t index = 0U; index < graph->node_capacity;
	     ++index) {
		if (!graph->nodes[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int risk_edge_index_locked(
	const struct pqcp_sovereign_risk_graph *graph,
	uint64_t edge_id)
{
	if (edge_id == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < graph->edge_capacity;
	     ++index) {
		if (graph->edges[index].occupied &&
		    graph->edges[index].edge_id == edge_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int risk_free_edge_index_locked(
	const struct pqcp_sovereign_risk_graph *graph)
{
	for (size_t index = 0U; index < graph->edge_capacity;
	     ++index) {
		if (!graph->edges[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int risk_edge_tuple_index_locked(
	const struct pqcp_sovereign_risk_graph *graph,
	const struct pqcp_sovereign_risk_edge *edge,
	int ignored_index)
{
	for (size_t index = 0U; index < graph->edge_capacity;
	     ++index) {
		const struct pqcp_sovereign_risk_edge *candidate =
			&graph->edges[index];

		if ((int)index == ignored_index ||
		    !candidate->occupied) {
			continue;
		}
		if (strcmp(candidate->source_id,
			   edge->source_id) == 0 &&
		    strcmp(candidate->destination_id,
			   edge->destination_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static uint32_t risk_next_generation_locked(
	struct pqcp_sovereign_risk_graph *graph)
{
	uint32_t candidate;
	size_t attempts = 0U;
	bool collision;

	while (attempts <= graph->node_capacity) {
		candidate = graph->next_node_generation;
		if (candidate == 0U) {
			candidate = 1U;
		}
		graph->next_node_generation =
			candidate == UINT32_MAX ?
			1U : candidate + 1U;
		collision = false;
		for (size_t index = 0U;
		     index < graph->node_capacity; ++index) {
			if (graph->nodes[index].occupied &&
			    graph->nodes[index].generation ==
				    candidate) {
				collision = true;
				break;
			}
		}
		if (!collision) {
			return candidate;
		}
		attempts++;
	}
	return 0U;
}

static int risk_assign_edge_id_locked(
	struct pqcp_sovereign_risk_graph *graph,
	uint64_t *edge_id)
{
	uint64_t candidate;
	size_t attempts = 0U;

	while (attempts <= graph->edge_capacity) {
		candidate = graph->next_edge_id;
		if (candidate == 0U) {
			candidate = 1U;
		}
		graph->next_edge_id =
			candidate == UINT64_MAX ? 1U : candidate + 1U;
		if (risk_edge_index_locked(graph, candidate) ==
		    -ENOENT) {
			*edge_id = candidate;
			return 0;
		}
		attempts++;
	}
	return -EOVERFLOW;
}

static bool risk_nodes_equivalent(
	const struct pqcp_sovereign_risk_node *left,
	const struct pqcp_sovereign_risk_node *right)
{
	return strcmp(left->subject_id, right->subject_id) == 0 &&
	       strcmp(left->subject_type, right->subject_type) == 0 &&
	       left->observed_at_ms == right->observed_at_ms &&
	       left->expires_at_ms == right->expires_at_ms &&
	       left->policy_epoch == right->policy_epoch &&
	       left->inherent_risk == right->inherent_risk &&
	       left->control_strength == right->control_strength &&
	       left->exposure_score == right->exposure_score &&
	       left->signal_mask == right->signal_mask &&
	       pqcp_sovereign_policy_equal(
		       left->evidence_digest, right->evidence_digest,
		       sizeof(left->evidence_digest));
}

static bool risk_edges_equivalent(
	const struct pqcp_sovereign_risk_edge *left,
	const struct pqcp_sovereign_risk_edge *right)
{
	return left->edge_id == right->edge_id &&
	       strcmp(left->source_id, right->source_id) == 0 &&
	       strcmp(left->destination_id,
		      right->destination_id) == 0 &&
	       left->propagation_basis_points ==
		       right->propagation_basis_points &&
	       left->confidence_basis_points ==
		       right->confidence_basis_points &&
	       left->expires_at_ms == right->expires_at_ms;
}

int pqcp_sovereign_risk_graph_init(
	struct pqcp_sovereign_risk_graph *graph,
	struct pqcp_sovereign_risk_node *nodes,
	size_t node_capacity,
	struct pqcp_sovereign_risk_edge *edges,
	size_t edge_capacity)
{
	if (graph == NULL || nodes == NULL ||
	    node_capacity == 0U ||
	    node_capacity > RISK_MAX_NODES ||
	    edges == NULL || edge_capacity == 0U ||
	    edge_capacity > RISK_MAX_EDGES) {
		return -EINVAL;
	}
	memset(graph, 0, sizeof(*graph));
	memset(nodes, 0, node_capacity * sizeof(*nodes));
	memset(edges, 0, edge_capacity * sizeof(*edges));
	graph->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	graph->nodes = nodes;
	graph->node_capacity = node_capacity;
	graph->edges = edges;
	graph->edge_capacity = edge_capacity;
	graph->next_node_generation = 1U;
	graph->next_edge_id = 1U;
	k_mutex_init(&graph->lock);
	graph->initialized = true;
	return 0;
}

int pqcp_sovereign_risk_node_put(
	struct pqcp_sovereign_risk_graph *graph,
	const struct pqcp_sovereign_risk_node *node,
	uint64_t now_ms)
{
	struct pqcp_sovereign_risk_node candidate;
	const struct pqcp_sovereign_risk_node *existing;
	uint32_t generation;
	int index;
	int ret;

	if (!risk_node_input_valid(node, now_ms)) {
		return -EINVAL;
	}
	ret = risk_lock(graph);
	if (ret != 0) {
		return ret;
	}
	index = risk_node_index_locked(graph, node->subject_id);
	if (index >= 0) {
		existing = &graph->nodes[index];
		if (strcmp(existing->subject_type,
			   node->subject_type) != 0) {
			risk_unlock(graph);
			return -EACCES;
		}
		if (risk_nodes_equivalent(existing, node)) {
			risk_unlock(graph);
			return 0;
		}
		if (node->policy_epoch < existing->policy_epoch ||
		    (node->policy_epoch == existing->policy_epoch &&
		     node->observed_at_ms <=
			     existing->observed_at_ms)) {
			risk_unlock(graph);
			return -ESTALE;
		}
	} else if (index == -ENOENT) {
		index = risk_free_node_index_locked(graph);
	} else {
		risk_unlock(graph);
		return index;
	}
	if (index < 0) {
		risk_unlock(graph);
		return index;
	}
	generation = risk_next_generation_locked(graph);
	if (generation == 0U) {
		risk_unlock(graph);
		return -EOVERFLOW;
	}
	candidate = *node;
	candidate.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.generation = generation;
	candidate.propagated_risk = 0U;
	candidate.residual_risk = risk_base(&candidate);
	candidate.occupied = true;
	graph->nodes[index] = candidate;
	risk_unlock(graph);
	return 0;
}

int pqcp_sovereign_risk_edge_put(
	struct pqcp_sovereign_risk_graph *graph,
	const struct pqcp_sovereign_risk_edge *edge)
{
	struct pqcp_sovereign_risk_edge candidate;
	const struct pqcp_sovereign_risk_edge *existing;
	int index;
	int ret;

	if (!risk_edge_input_valid(edge)) {
		return -EINVAL;
	}
	ret = risk_lock(graph);
	if (ret != 0) {
		return ret;
	}
	if (risk_node_index_locked(
		    graph, edge->source_id) < 0 ||
	    risk_node_index_locked(
		    graph, edge->destination_id) < 0) {
		risk_unlock(graph);
		return -ENOENT;
	}
	candidate = *edge;
	candidate.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.occupied = true;
	if (candidate.edge_id == 0U) {
		ret = risk_assign_edge_id_locked(
			graph, &candidate.edge_id);
		if (ret != 0) {
			risk_unlock(graph);
			return ret;
		}
		index = risk_free_edge_index_locked(graph);
	} else {
		index = risk_edge_index_locked(
			graph, candidate.edge_id);
		if (index < 0 && index != -ENOENT) {
			risk_unlock(graph);
			return index;
		}
		if (index < 0) {
			index = risk_free_edge_index_locked(graph);
		}
	}
	if (index < 0) {
		risk_unlock(graph);
		return index;
	}
	if (graph->edges[index].occupied) {
		existing = &graph->edges[index];
		if (strcmp(existing->source_id,
			   candidate.source_id) != 0 ||
		    strcmp(existing->destination_id,
			   candidate.destination_id) != 0) {
			risk_unlock(graph);
			return -EACCES;
		}
		if (risk_edges_equivalent(existing, &candidate)) {
			risk_unlock(graph);
			return 0;
		}
		if (candidate.expires_at_ms <=
		    existing->expires_at_ms) {
			risk_unlock(graph);
			return -ESTALE;
		}
	}
	if (risk_edge_tuple_index_locked(
		    graph, &candidate, index) >= 0) {
		risk_unlock(graph);
		return -EEXIST;
	}
	graph->edges[index] = candidate;
	risk_unlock(graph);
	return 0;
}

static int risk_active_node_map_locked(
	const struct pqcp_sovereign_risk_graph *graph,
	uint64_t now_ms,
	int map[RISK_MAX_NODES],
	size_t *active_count)
{
	size_t count = 0U;

	for (size_t index = 0U; index < graph->node_capacity;
	     ++index) {
		map[index] = -1;
		if (!graph->nodes[index].occupied ||
		    graph->nodes[index].expires_at_ms <= now_ms) {
			continue;
		}
		if (count >= RISK_MAX_NODES) {
			return -EOVERFLOW;
		}
		map[index] = (int)count;
		count++;
	}
	*active_count = count;
	return 0;
}

static int risk_active_index_by_subject_locked(
	const struct pqcp_sovereign_risk_graph *graph,
	const int map[RISK_MAX_NODES],
	const char *subject_id)
{
	for (size_t index = 0U; index < graph->node_capacity;
	     ++index) {
		if (map[index] >= 0 &&
		    strcmp(graph->nodes[index].subject_id,
			   subject_id) == 0) {
			return map[index];
		}
	}
	return -ENOENT;
}

static int risk_graph_slot_for_active_locked(
	const int map[RISK_MAX_NODES],
	size_t node_capacity,
	size_t active_index)
{
	for (size_t index = 0U; index < node_capacity; ++index) {
		if (map[index] == (int)active_index) {
			return (int)index;
		}
	}
	return -ENOENT;
}

int pqcp_sovereign_risk_evaluate(
	struct pqcp_sovereign_risk_graph *graph,
	const char *subject_id,
	uint64_t now_ms,
	uint32_t maximum_iterations,
	uint32_t *residual_risk)
{
	uint32_t previous[RISK_MAX_NODES] = { 0 };
	uint32_t next[RISK_MAX_NODES] = { 0 };
	uint32_t propagated[RISK_MAX_NODES] = { 0 };
	int map[RISK_MAX_NODES];
	size_t active_count = 0U;
	int target_index;
	bool converged = false;
	int ret;

	if (!pqcp_sovereign_policy_text_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    now_ms == 0U || maximum_iterations == 0U ||
	    maximum_iterations > RISK_MAX_ITERATIONS ||
	    residual_risk == NULL) {
		return -EINVAL;
	}
	*residual_risk = 0U;
	ret = risk_lock(graph);
	if (ret != 0) {
		return ret;
	}
	ret = risk_active_node_map_locked(
		graph, now_ms, map, &active_count);
	if (ret != 0) {
		risk_unlock(graph);
		return ret;
	}
	target_index = risk_active_index_by_subject_locked(
		graph, map, subject_id);
	if (target_index < 0) {
		const bool known =
			risk_node_index_locked(
				graph, subject_id) >= 0;

		risk_unlock(graph);
		return known ? -ETIME : -ENOENT;
	}
	for (size_t active = 0U; active < active_count; ++active) {
		int slot = risk_graph_slot_for_active_locked(
			map, graph->node_capacity, active);

		if (slot < 0) {
			risk_unlock(graph);
			return -EBADMSG;
		}
		previous[active] =
			risk_base(&graph->nodes[slot]);
	}
	for (uint32_t iteration = 0U;
	     iteration < maximum_iterations; ++iteration) {
		bool changed = false;

		memset(propagated, 0, sizeof(propagated));
		for (size_t edge_index = 0U;
		     edge_index < graph->edge_capacity; ++edge_index) {
			const struct pqcp_sovereign_risk_edge *edge =
				&graph->edges[edge_index];
			int source;
			int destination;
			uint32_t contribution;

			if (!edge->occupied ||
			    edge->expires_at_ms <= now_ms) {
				continue;
			}
			source = risk_active_index_by_subject_locked(
				graph, map, edge->source_id);
			destination =
				risk_active_index_by_subject_locked(
					graph, map,
					edge->destination_id);
			if (source < 0 || destination < 0) {
				continue;
			}
			contribution = risk_edge_contribution(
				previous[source], edge);
			propagated[destination] = risk_union(
				propagated[destination],
				contribution);
		}
		for (size_t active = 0U;
		     active < active_count; ++active) {
			int slot = risk_graph_slot_for_active_locked(
				map, graph->node_capacity, active);
			uint32_t base;

			if (slot < 0) {
				risk_unlock(graph);
				return -EBADMSG;
			}
			base = risk_base(&graph->nodes[slot]);
			next[active] = risk_union(
				base, propagated[active]);
			if (next[active] != previous[active]) {
				changed = true;
			}
		}
		memcpy(previous, next,
		       active_count * sizeof(previous[0]));
		if (!changed) {
			converged = true;
			break;
		}
	}
	if (!converged) {
		risk_unlock(graph);
		return -EAGAIN;
	}
	for (size_t active = 0U; active < active_count; ++active) {
		int slot = risk_graph_slot_for_active_locked(
			map, graph->node_capacity, active);

		if (slot < 0) {
			risk_unlock(graph);
			return -EBADMSG;
		}
		graph->nodes[slot].propagated_risk =
			propagated[active];
		graph->nodes[slot].residual_risk =
			previous[active];
	}
	graph->evaluation_count =
		pqcp_sovereign_policy_add_u64(
			graph->evaluation_count, 1U);
	*residual_risk = previous[target_index];
	risk_unlock(graph);
	return 0;
}

int pqcp_sovereign_risk_expire(
	struct pqcp_sovereign_risk_graph *graph,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t count = 0U;
	int ret;

	if (now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	*expired_count = 0U;
	ret = risk_lock(graph);
	if (ret != 0) {
		return ret;
	}
	for (size_t edge_index = 0U;
	     edge_index < graph->edge_capacity; ++edge_index) {
		if (graph->edges[edge_index].occupied &&
		    graph->edges[edge_index].expires_at_ms <= now_ms) {
			memset(&graph->edges[edge_index], 0,
			       sizeof(graph->edges[edge_index]));
		}
	}
	for (size_t node_index = 0U;
	     node_index < graph->node_capacity; ++node_index) {
		char subject_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];

		if (!graph->nodes[node_index].occupied ||
		    graph->nodes[node_index].expires_at_ms > now_ms) {
			continue;
		}
		memcpy(subject_id, graph->nodes[node_index].subject_id,
		       sizeof(subject_id));
		for (size_t edge_index = 0U;
		     edge_index < graph->edge_capacity; ++edge_index) {
			struct pqcp_sovereign_risk_edge *edge =
				&graph->edges[edge_index];

			if (edge->occupied &&
			    (strcmp(edge->source_id, subject_id) == 0 ||
			     strcmp(edge->destination_id,
				    subject_id) == 0)) {
				memset(edge, 0, sizeof(*edge));
			}
		}
		memset(&graph->nodes[node_index], 0,
		       sizeof(graph->nodes[node_index]));
		if (count != UINT32_MAX) {
			count++;
		}
	}
	*expired_count = count;
	risk_unlock(graph);
	return 0;
}

int pqcp_sovereign_risk_graph_audit(
	struct pqcp_sovereign_risk_graph *graph)
{
	int ret;

	if (graph == NULL || !graph->initialized ||
	    graph->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    graph->nodes == NULL || graph->node_capacity == 0U ||
	    graph->node_capacity > RISK_MAX_NODES ||
	    graph->edges == NULL || graph->edge_capacity == 0U ||
	    graph->edge_capacity > RISK_MAX_EDGES ||
	    graph->next_node_generation == 0U ||
	    graph->next_edge_id == 0U) {
		return -EINVAL;
	}
	ret = risk_lock(graph);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < graph->node_capacity;
	     ++index) {
		const struct pqcp_sovereign_risk_node *node =
			&graph->nodes[index];
		uint32_t base;

		if (!node->occupied) {
			continue;
		}
		if (!risk_node_shape_valid(node)) {
			ret = -EBADMSG;
			goto out;
		}
		base = risk_base(node);
		if (node->residual_risk !=
		    risk_union(base, node->propagated_risk)) {
			ret = -EBADMSG;
			goto out;
		}
		for (size_t other = index + 1U;
		     other < graph->node_capacity; ++other) {
			if (graph->nodes[other].occupied &&
			    (strcmp(node->subject_id,
				    graph->nodes[other].
					    subject_id) == 0 ||
			     node->generation ==
				     graph->nodes[other].
					     generation)) {
				ret = -EEXIST;
				goto out;
			}
		}
	}
	for (size_t index = 0U; index < graph->edge_capacity;
	     ++index) {
		const struct pqcp_sovereign_risk_edge *edge =
			&graph->edges[index];

		if (!edge->occupied) {
			continue;
		}
		if (!risk_edge_shape_valid(edge) ||
		    risk_node_index_locked(
			    graph, edge->source_id) < 0 ||
		    risk_node_index_locked(
			    graph, edge->destination_id) < 0) {
			ret = -EBADMSG;
			goto out;
		}
		for (size_t other = index + 1U;
		     other < graph->edge_capacity; ++other) {
			const struct pqcp_sovereign_risk_edge *peer =
				&graph->edges[other];

			if (!peer->occupied) {
				continue;
			}
			if (peer->edge_id == edge->edge_id ||
			    (strcmp(peer->source_id,
				    edge->source_id) == 0 &&
			     strcmp(peer->destination_id,
				    edge->destination_id) == 0)) {
				ret = -EEXIST;
				goto out;
			}
		}
	}
	ret = 0;
out:
	risk_unlock(graph);
	return ret;
}
