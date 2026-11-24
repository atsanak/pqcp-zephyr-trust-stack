/*
 * SPDX-License-Identifier: MIT
 *
 * Fenced sovereign failover, rejoin, rollback, and disaster recovery.
 */

#include "sovereign_continuity_internal.h"

static int run_index(
	const struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	uint64_t run_id)
{
	for (size_t index = 0U;
	     index < orchestrator->capacity; ++index) {
		if (orchestrator->runs[index].occupied &&
		    orchestrator->runs[index].run_id == run_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int active_resource_run(
	const struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const char *tenant_id,
	const char *resource_id)
{
	for (size_t index = 0U;
	     index < orchestrator->capacity; ++index) {
		const struct pqcp_sovereign_recovery_run *run =
			&orchestrator->runs[index];

		if (run->occupied &&
		    !pqcp_sovereign_continuity_terminal_state(
			    run->state) &&
		    strcmp(run->tenant_id, tenant_id) == 0 &&
		    strcmp(run->resource_id, resource_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_run_index(
	const struct pqcp_sovereign_recovery_orchestrator *orchestrator)
{
	int oldest_terminal = -1;
	uint64_t oldest_time = UINT64_MAX;

	for (size_t index = 0U;
	     index < orchestrator->capacity; ++index) {
		const struct pqcp_sovereign_recovery_run *run =
			&orchestrator->runs[index];

		if (!run->occupied) {
			return (int)index;
		}
		if (pqcp_sovereign_continuity_terminal_state(
			    run->state) &&
		    run->updated_at_ms < oldest_time) {
			oldest_time = run->updated_at_ms;
			oldest_terminal = (int)index;
		}
	}
	return oldest_terminal >= 0 ? oldest_terminal : -ENOSPC;
}

static uint32_t plan_maximum_failures(
	const struct pqcp_sovereign_recovery_plan *plan)
{
	uint32_t failures = 0U;

	for (uint32_t index = 0U;
	     index < plan->step_count; ++index) {
		uint32_t allowance =
			plan->steps[index].maximum_attempts - 1U;

		failures =
			pqcp_edge_internal_saturating_add_u32(
				failures, allowance);
	}
	return failures == 0U ? 1U : failures;
}

static bool plan_requires_point(
	const struct pqcp_sovereign_recovery_plan *plan)
{
	for (uint32_t index = 0U;
	     index < plan->step_count; ++index) {
		if (plan->steps[index].point_required) {
			return true;
		}
	}
	return false;
}

static bool plan_requires_fence(
	const struct pqcp_sovereign_recovery_plan *plan)
{
	for (uint32_t index = 0U;
	     index < plan->step_count; ++index) {
		if (plan->steps[index].fence_required ||
		    plan->steps[index].kind ==
			    PQCP_SOVEREIGN_STEP_FENCE) {
			return true;
		}
	}
	return false;
}

static int current_plan_step(
	const struct pqcp_sovereign_recovery_plan *plan,
	const struct pqcp_sovereign_recovery_run *run,
	uint32_t *step_index,
	const struct pqcp_sovereign_recovery_step **step)
{
	uint32_t index;

	if (run->current_order_index >= plan->step_count) {
		return -ENODATA;
	}
	index =
		plan->topological_order[run->current_order_index];
	if (index >= plan->step_count) {
		return -EBADMSG;
	}
	*step_index = index;
	*step = &plan->steps[index];
	return 0;
}

static int build_lease_use(
	const struct pqcp_sovereign_recovery_run *run,
	uint32_t operation,
	uint64_t now_ms,
	struct pqcp_sovereign_lease_use *use)
{
	int ret;

	memset(use, 0, sizeof(*use));
	ret = pqcp_sovereign_continuity_copy_id(
		use->tenant_id, run->tenant_id);
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			use->principal_id, run->principal_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			use->lease_id, run->lease_id);
	}
	if (ret != 0) {
		return ret;
	}
	use->now_ms = now_ms;
	use->policy_epoch = run->policy_epoch;
	use->revocation_epoch = run->revocation_epoch;
	use->fencing_epoch = run->fencing_epoch;
	use->operation = operation;
	memcpy(use->plan_digest, run->plan_digest,
	       sizeof(use->plan_digest));
	memcpy(use->authorization_digest,
	       run->quorum_authorization_digest,
	       sizeof(use->authorization_digest));
	return 0;
}

static int authorize_step(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_run *run,
	const struct pqcp_sovereign_recovery_step *step,
	uint64_t now_ms)
{
	struct pqcp_sovereign_lease_use use;
	int ret;

	if (step->required_operation == 0U) {
		return 0;
	}
	ret = build_lease_use(
		run, step->required_operation, now_ms, &use);
	if (ret != 0) {
		return ret;
	}
	return pqcp_sovereign_authority_lease_use(
		orchestrator->leases, &use);
}

static int select_recovery_point(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_plan *plan,
	const struct pqcp_sovereign_continuity_objective *objective,
	struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms)
{
	struct pqcp_sovereign_recovery_point_query query;
	struct pqcp_sovereign_recovery_point_selection selection;
	int ret;

	if (!plan_requires_point(plan)) {
		return 0;
	}
	memset(&query, 0, sizeof(query));
	ret = pqcp_sovereign_continuity_copy_id(
		query.tenant_id, plan->tenant_id);
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			query.objective_id,
			plan->objective_id);
	}
	if (ret != 0) {
		return ret;
	}
	query.now_ms = now_ms;
	query.maximum_age_ms =
		plan->point_maximum_age_ms;
	query.minimum_sequence = 1U;
	query.minimum_policy_epoch = plan->policy_epoch;
	query.minimum_revocation_epoch =
		plan->revocation_epoch;
	query.maximum_fencing_epoch = run->fencing_epoch;
	query.minimum_replicas =
		objective->minimum_replicas;
	query.require_immutable = true;
	ret = pqcp_sovereign_recovery_point_select(
		orchestrator->points, &query, &selection);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_continuity_copy_id(
		run->selected_point_id, selection.point_id);
	if (ret != 0) {
		return ret;
	}
	run->selected_point_generation =
		selection.generation;
	memcpy(run->selected_point_digest,
	       selection.point_digest,
	       sizeof(run->selected_point_digest));
	return 0;
}

static int acquire_run_fence(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_plan *plan,
	struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms,
	bool *acquired)
{
	struct pqcp_sovereign_fence_claim claim;
	struct pqcp_sovereign_fence fence;
	int ret;

	if (acquired == NULL) {
		return -EINVAL;
	}
	*acquired = false;
	if (!plan_requires_fence(plan)) {
		return 0;
	}
	memset(&claim, 0, sizeof(claim));
	ret = pqcp_sovereign_continuity_copy_id(
		claim.tenant_id, run->tenant_id);
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			claim.resource_id, run->resource_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			claim.holder_id, run->principal_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			claim.lease_id, run->lease_id);
	}
	if (ret != 0) {
		return ret;
	}
	claim.requested_epoch = run->fencing_epoch;
	claim.now_ms = now_ms;
	claim.expires_at_ms = run->deadline_ms;
	memcpy(claim.holder_digest, run->plan_digest,
	       sizeof(claim.holder_digest));
	memcpy(claim.authorization_digest,
	       run->quorum_authorization_digest,
	       sizeof(claim.authorization_digest));
	ret = pqcp_sovereign_fence_acquire(
		orchestrator->fences, &claim, &fence);
	if (ret != 0 && ret != -EALREADY) {
		return ret;
	}
	*acquired = ret == 0;
	run->fencing_epoch = fence.epoch;
	run->fence_generation = fence.generation;
	run->fence_held = true;
	return 0;
}

static int release_selected_point(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms)
{
	int ret;

	if (run->selected_point_generation == 0U) {
		return 0;
	}
	ret = pqcp_sovereign_recovery_point_release(
		orchestrator->points, run->tenant_id,
		run->selected_point_id,
		run->selected_point_generation,
		run->quorum_authorization_digest, now_ms);
	if (ret == 0 || ret == -EALREADY ||
	    ret == -ETIMEDOUT) {
		run->selected_point_generation = 0U;
		memset(run->selected_point_id, 0,
		       sizeof(run->selected_point_id));
		memset(run->selected_point_digest, 0,
		       sizeof(run->selected_point_digest));
		return 0;
	}
	return ret;
}

static int check_run_fence(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms)
{
	if (!run->fence_held) {
		return 0;
	}
	return pqcp_sovereign_fence_check(
		orchestrator->fences, run->tenant_id,
		run->resource_id, run->principal_id,
		run->fencing_epoch, now_ms);
}

static int release_run_fence(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms)
{
	int ret;

	if (!run->fence_held) {
		return 0;
	}
	ret = pqcp_sovereign_fence_release(
		orchestrator->fences, run->tenant_id,
		run->resource_id, run->principal_id,
		run->fence_generation, run->fencing_epoch,
		now_ms);
	if (ret == 0 || ret == -EALREADY) {
		run->fence_held = false;
		return 0;
	}
	return ret;
}

static int edge_authorize(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_start *start,
	const struct pqcp_sovereign_recovery_plan *plan,
	struct pqcp_sovereign_recovery_run *run)
{
	struct pqcp_edge_recovery_plan *edge_plan = NULL;
	int ret;

	if (orchestrator->edge.recovery == NULL) {
		return 0;
	}
	ret = pqcp_edge_recovery_authorize(
		orchestrator->edge.recovery,
		start->incident_id, plan->resource_id,
		1U, plan_maximum_failures(plan),
		start->quorum_authorization_digest,
		start->now_ms, run->deadline_ms,
		&edge_plan);
	if (ret != 0) {
		return ret;
	}
	run->edge_recovery_id = edge_plan->recovery_id;
	run->edge_authorized = true;
	return 0;
}

static int edge_advance_one(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *run,
	enum pqcp_edge_recovery_phase phase,
	uint64_t now_ms)
{
	int ret;

	if (!run->edge_authorized ||
	    orchestrator->edge.recovery == NULL) {
		return 0;
	}
	ret = pqcp_edge_recovery_advance(
		orchestrator->edge.recovery,
		run->edge_recovery_id, phase, now_ms);
	return ret == -EALREADY ? 0 : ret;
}

static int edge_prepare_step(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *run,
	const struct pqcp_sovereign_recovery_step *step,
	uint64_t now_ms)
{
	int ret = 0;

	if (!run->edge_authorized ||
	    orchestrator->edge.recovery == NULL) {
		return 0;
	}
	switch (step->kind) {
	case PQCP_SOVEREIGN_STEP_CHECKPOINT:
		ret = edge_advance_one(
			orchestrator, run,
			PQCP_EDGE_RECOVERY_CHECKPOINTING,
			now_ms);
		break;
	case PQCP_SOVEREIGN_STEP_ISOLATE:
		ret = edge_advance_one(
			orchestrator, run,
			PQCP_EDGE_RECOVERY_ISOLATING,
			now_ms);
		break;
	case PQCP_SOVEREIGN_STEP_RESTORE:
	case PQCP_SOVEREIGN_STEP_ROLLBACK:
		ret = edge_advance_one(
			orchestrator, run,
			PQCP_EDGE_RECOVERY_RESTORING,
			now_ms);
		break;
	case PQCP_SOVEREIGN_STEP_VALIDATE:
		ret = edge_advance_one(
			orchestrator, run,
			PQCP_EDGE_RECOVERY_VALIDATING,
			now_ms);
		break;
	case PQCP_SOVEREIGN_STEP_REJOIN:
		ret = edge_advance_one(
			orchestrator, run,
			PQCP_EDGE_RECOVERY_REJOINING,
			now_ms);
		break;
	default:
		break;
	}
	return ret;
}

static int edge_record_success(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *run,
	const struct pqcp_sovereign_recovery_step *step,
	const uint8_t evidence[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms)
{
	int ret;

	if (!run->edge_authorized ||
	    orchestrator->edge.recovery == NULL) {
		return 0;
	}
	if (step->kind == PQCP_SOVEREIGN_STEP_CHECKPOINT) {
		return pqcp_edge_recovery_checkpoint(
			orchestrator->edge.recovery,
			run->edge_recovery_id,
			evidence, now_ms);
	}
	if (step->kind == PQCP_SOVEREIGN_STEP_VALIDATE) {
		ret = pqcp_edge_recovery_record_step(
			orchestrator->edge.recovery,
			run->edge_recovery_id, 0U, true,
			evidence, now_ms);
		return ret == -EALREADY ? 0 : ret;
	}
	return 0;
}

static int edge_complete(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms)
{
	int ret;

	if (!run->edge_authorized ||
	    orchestrator->edge.recovery == NULL) {
		return 0;
	}
	ret = edge_advance_one(
		orchestrator, run,
		PQCP_EDGE_RECOVERY_COMPLETE, now_ms);
	if (ret == -EPERM) {
		ret = edge_advance_one(
			orchestrator, run,
			PQCP_EDGE_RECOVERY_REJOINING, now_ms);
		if (ret == 0) {
			ret = pqcp_edge_recovery_record_step(
				orchestrator->edge.recovery,
				run->edge_recovery_id, 0U, true,
				run->evidence_digest, now_ms);
			if (ret == -EALREADY) {
				ret = 0;
			}
		}
		if (ret == 0) {
			ret = edge_advance_one(
				orchestrator, run,
				PQCP_EDGE_RECOVERY_COMPLETE,
				now_ms);
		}
	}
	return ret;
}

static int edge_abort(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms)
{
	int ret;

	if (!run->edge_authorized ||
	    orchestrator->edge.recovery == NULL) {
		return 0;
	}
	ret = pqcp_edge_recovery_advance(
		orchestrator->edge.recovery,
		run->edge_recovery_id,
		PQCP_EDGE_RECOVERY_FAILED, now_ms);
	if (ret == 0 || ret == -EALREADY ||
	    ret == -ETIMEDOUT) {
		run->edge_authorized = false;
		return 0;
	}
	return ret;
}

static int edge_set_continuity_mode(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_plan *plan,
	enum pqcp_edge_continuity_mode mode,
	uint64_t now_ms)
{
	struct pqcp_sovereign_continuity_objective objective;
	int ret;

	if (orchestrator->edge.continuity == NULL) {
		return 0;
	}
	ret = pqcp_sovereign_objective_get(
		orchestrator->objectives, plan->tenant_id,
		plan->objective_id, &objective);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_objective_sync_edge(
		orchestrator->objectives, plan->tenant_id,
		plan->objective_id,
		orchestrator->edge.continuity);
	if (ret != 0 && ret != -EALREADY) {
		return ret;
	}
	ret = pqcp_edge_continuity_set_mode(
		orchestrator->edge.continuity,
		objective.service_id, mode, now_ms);
	return ret == -EALREADY ? 0 : ret;
}

static int chain_run_evidence(
	struct pqcp_sovereign_recovery_run *run,
	const struct pqcp_sovereign_recovery_step *step,
	int result,
	const uint8_t evidence[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms)
{
	uint8_t numeric[20];
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	const uint8_t *parts[4];
	size_t lengths[4];
	int ret;

	pqcp_edge_internal_write_u32(
		numeric, step->step_id);
	pqcp_edge_internal_write_u32(
		numeric + 4U, (uint32_t)step->kind);
	pqcp_edge_internal_write_u32(
		numeric + 8U, (uint32_t)result);
	pqcp_edge_internal_write_u64(
		numeric + 12U, now_ms);
	parts[0] = run->evidence_digest;
	lengths[0] = sizeof(run->evidence_digest);
	parts[1] = run->run_digest;
	lengths[1] = sizeof(run->run_digest);
	parts[2] = evidence;
	lengths[2] = PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES;
	parts[3] = numeric;
	lengths[3] = sizeof(numeric);
	ret = pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 4U, digest);
	if (ret == 0) {
		memcpy(run->evidence_digest, digest,
		       sizeof(run->evidence_digest));
	}
	return ret;
}

static int validate_start(
	const struct pqcp_sovereign_recovery_start *start)
{
	if (start == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    start->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    start->plan_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    start->principal_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    start->lease_id) ||
	    start->incident_id == 0U ||
	    start->now_ms == 0U ||
	    start->policy_epoch == 0U ||
	    start->revocation_epoch == 0U ||
	    start->fencing_epoch == 0U ||
	    start->approval_count == 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    start->plan_digest) ||
	    !pqcp_sovereign_continuity_digest_valid(
		    start->quorum_authorization_digest)) {
		return -EINVAL;
	}
	return 0;
}

static int reserve_run(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *candidate,
	int *reserved_index)
{
	int index;
	int ret = 0;

	k_mutex_lock(&orchestrator->lock, K_FOREVER);
	index = active_resource_run(
		orchestrator, candidate->tenant_id,
		candidate->resource_id);
	if (index >= 0) {
		ret = -EBUSY;
		goto out;
	}
	index = free_run_index(orchestrator);
	if (index < 0) {
		ret = index;
		goto out;
	}
	candidate->generation =
		pqcp_edge_internal_next_generation(
			&orchestrator->next_generation);
	candidate->run_id =
		pqcp_edge_internal_next_identifier(
			&orchestrator->next_run_id);
	ret = pqcp_sovereign_continuity_digest_run(
		candidate, candidate->run_digest);
	if (ret != 0) {
		goto out;
	}
	orchestrator->runs[index] = *candidate;
	*reserved_index = index;
out:
	k_mutex_unlock(&orchestrator->lock);
	return ret;
}

static int publish_reserved_run(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	int reserved_index,
	const uint8_t reservation_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	const struct pqcp_sovereign_recovery_run *candidate)
{
	int ret = 0;

	k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (reserved_index < 0 ||
	    (size_t)reserved_index >= orchestrator->capacity ||
	    !orchestrator->runs[reserved_index].occupied ||
	    orchestrator->runs[reserved_index].run_id !=
		    candidate->run_id ||
	    orchestrator->runs[reserved_index].generation !=
		    candidate->generation ||
	    !pqcp_sovereign_continuity_digest_equal(
		    orchestrator->runs[reserved_index].run_digest,
		    reservation_digest)) {
		ret = -ESTALE;
	} else {
		orchestrator->runs[reserved_index] = *candidate;
	}
	k_mutex_unlock(&orchestrator->lock);
	return ret;
}

static void discard_reserved_run(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	int reserved_index,
	const uint8_t reservation_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	const struct pqcp_sovereign_recovery_run *candidate)
{
	k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (reserved_index >= 0 &&
	    (size_t)reserved_index < orchestrator->capacity &&
	    orchestrator->runs[reserved_index].occupied &&
	    orchestrator->runs[reserved_index].run_id ==
		    candidate->run_id &&
	    orchestrator->runs[reserved_index].generation ==
		    candidate->generation &&
	    pqcp_sovereign_continuity_digest_equal(
		    orchestrator->runs[reserved_index].run_digest,
		    reservation_digest)) {
		memset(&orchestrator->runs[reserved_index], 0,
		       sizeof(orchestrator->runs[reserved_index]));
	}
	orchestrator->rejected_count =
		pqcp_sovereign_continuity_add_u64(
			orchestrator->rejected_count, 1U);
	k_mutex_unlock(&orchestrator->lock);
}

int pqcp_sovereign_recovery_orchestrator_init(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	struct pqcp_sovereign_recovery_run *runs,
	size_t capacity,
	struct pqcp_sovereign_objective_registry *objectives,
	struct pqcp_sovereign_recovery_point_catalog *points,
	struct pqcp_sovereign_authority_lease_manager *leases,
	struct pqcp_sovereign_fence_manager *fences,
	struct pqcp_sovereign_recovery_plan_registry *plans,
	const struct pqcp_sovereign_edge_adapters *edge)
{
	if (orchestrator == NULL || runs == NULL ||
	    capacity == 0U || objectives == NULL ||
	    !objectives->initialized || points == NULL ||
	    !points->initialized || leases == NULL ||
	    !leases->initialized || fences == NULL ||
	    !fences->initialized || plans == NULL ||
	    !plans->initialized) {
		return -EINVAL;
	}
	if (edge != NULL &&
	    ((edge->continuity != NULL &&
	      !edge->continuity->initialized) ||
	     (edge->recovery != NULL &&
	      !edge->recovery->initialized))) {
		return -EINVAL;
	}
	memset(orchestrator, 0, sizeof(*orchestrator));
	memset(runs, 0, capacity * sizeof(*runs));
	orchestrator->schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	orchestrator->runs = runs;
	orchestrator->capacity = capacity;
	orchestrator->next_generation = 1U;
	orchestrator->next_run_id = 1U;
	orchestrator->objectives = objectives;
	orchestrator->points = points;
	orchestrator->leases = leases;
	orchestrator->fences = fences;
	orchestrator->plans = plans;
	if (edge != NULL) {
		orchestrator->edge = *edge;
	}
	k_mutex_init(&orchestrator->lock);
	orchestrator->initialized = true;
	return 0;
}

int pqcp_sovereign_recovery_start(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_start *start,
	struct pqcp_sovereign_recovery_run *run)
{
	struct pqcp_sovereign_recovery_plan plan;
	struct pqcp_sovereign_continuity_objective objective;
	struct pqcp_sovereign_recovery_run candidate;
	const struct pqcp_sovereign_recovery_step *first_step;
	uint32_t first_index;
	uint8_t reservation_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES] = {0};
	int reserved_index = -1;
	bool continuity_mode_set = false;
	bool fence_acquired = false;
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    validate_start(start) != 0 || run == NULL) {
		return -EINVAL;
	}
	memset(run, 0, sizeof(*run));
	ret = pqcp_sovereign_recovery_plan_get(
		orchestrator->plans, start->tenant_id,
		start->plan_id, &plan);
	if (ret != 0) {
		return ret;
	}
	if (!plan.active || plan.expires_at_ms <= start->now_ms ||
	    plan.policy_epoch != start->policy_epoch ||
	    plan.revocation_epoch !=
		    start->revocation_epoch ||
	    start->approval_count <
		    plan.required_approval_count ||
	    !pqcp_sovereign_continuity_digest_equal(
		    plan.plan_digest, start->plan_digest)) {
		return -EACCES;
	}
	ret = pqcp_sovereign_objective_get(
		orchestrator->objectives, start->tenant_id,
		plan.objective_id, &objective);
	if (ret != 0) {
		return ret;
	}
	if (objective.suspended ||
	    objective.policy_epoch > start->policy_epoch ||
	    objective.revocation_epoch >
		    start->revocation_epoch) {
		return -ESTALE;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	ret = pqcp_sovereign_continuity_copy_id(
		candidate.tenant_id, start->tenant_id);
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			candidate.plan_id, start->plan_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			candidate.objective_id,
			plan.objective_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			candidate.resource_id,
			plan.resource_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			candidate.principal_id,
			start->principal_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_continuity_copy_id(
			candidate.lease_id, start->lease_id);
	}
	if (ret != 0) {
		return ret;
	}
	candidate.mode = plan.mode;
	candidate.state = PQCP_SOVEREIGN_RUN_AUTHORIZED;
	candidate.authorized_at_ms = start->now_ms;
	candidate.started_at_ms = start->now_ms;
	candidate.updated_at_ms = start->now_ms;
	candidate.deadline_ms =
		pqcp_sovereign_continuity_add_u64(
			start->now_ms,
			plan.maximum_duration_ms);
	if (candidate.deadline_ms >
	    plan.expires_at_ms) {
		candidate.deadline_ms = plan.expires_at_ms;
	}
	candidate.policy_epoch = start->policy_epoch;
	candidate.revocation_epoch =
		start->revocation_epoch;
	candidate.fencing_epoch = start->fencing_epoch;
	memcpy(candidate.plan_digest, plan.plan_digest,
	       sizeof(candidate.plan_digest));
	memcpy(candidate.quorum_authorization_digest,
	       start->quorum_authorization_digest,
	       sizeof(candidate.quorum_authorization_digest));
	candidate.occupied = true;
	ret = reserve_run(
		orchestrator, &candidate, &reserved_index);
	if (ret != 0) {
		discard_reserved_run(
			orchestrator, reserved_index,
			reservation_digest, &candidate);
		return ret;
	}
	memcpy(reservation_digest, candidate.run_digest,
	       sizeof(reservation_digest));
	ret = select_recovery_point(
		orchestrator, &plan, &objective,
		&candidate, start->now_ms);
	if (ret != 0) {
		goto rollback;
	}
	ret = acquire_run_fence(
		orchestrator, &plan, &candidate,
		start->now_ms, &fence_acquired);
	if (ret != 0) {
		goto rollback;
	}
	ret = edge_authorize(
		orchestrator, start, &plan, &candidate);
	if (ret != 0) {
		goto rollback;
	}
	ret = current_plan_step(
		&plan, &candidate, &first_index, &first_step);
	if (ret != 0) {
		goto rollback;
	}
	ret = authorize_step(
		orchestrator, &candidate,
		first_step, start->now_ms);
	if (ret != 0) {
		goto rollback;
	}
	candidate.step_attempts[first_index] = 1U;
	candidate.attempt_mask |= 1U << first_index;
	candidate.state =
		pqcp_sovereign_continuity_state_for_step(
			first_step->kind);
	ret = edge_prepare_step(
		orchestrator, &candidate,
		first_step, start->now_ms);
	if (ret != 0) {
		goto rollback;
	}
	ret = edge_set_continuity_mode(
		orchestrator, &plan,
		PQCP_EDGE_CONTINUITY_RECOVERY,
		start->now_ms);
	if (ret == -EAGAIN) {
		ret = 0;
	}
	if (ret != 0) {
		goto rollback;
	}
	continuity_mode_set =
		orchestrator->edge.continuity != NULL;
	ret = pqcp_sovereign_continuity_digest_run(
		&candidate, candidate.run_digest);
	if (ret != 0) {
		goto rollback;
	}
	ret = publish_reserved_run(
		orchestrator, reserved_index,
		reservation_digest, &candidate);
	if (ret != 0) {
		goto rollback;
	}
	*run = candidate;
	return 0;
rollback:
	(void)edge_abort(
		orchestrator, &candidate, start->now_ms);
	if (fence_acquired) {
		(void)release_run_fence(
			orchestrator, &candidate,
			start->now_ms);
	}
	(void)release_selected_point(
		orchestrator, &candidate, start->now_ms);
	if (continuity_mode_set) {
		(void)edge_set_continuity_mode(
			orchestrator, &plan,
			PQCP_EDGE_CONTINUITY_NORMAL,
			start->now_ms);
	}
	discard_reserved_run(
		orchestrator, reserved_index,
		reservation_digest, &candidate);
	return ret;
}

int pqcp_sovereign_recovery_current_step(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	uint64_t run_id,
	struct pqcp_sovereign_recovery_step *step)
{
	struct pqcp_sovereign_recovery_run run;
	struct pqcp_sovereign_recovery_plan plan;
	const struct pqcp_sovereign_recovery_step *current;
	uint32_t index;
	int run_slot;
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    run_id == 0U || step == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&orchestrator->lock, K_FOREVER);
	run_slot = run_index(orchestrator, run_id);
	if (run_slot < 0) {
		k_mutex_unlock(&orchestrator->lock);
		return run_slot;
	}
	run = orchestrator->runs[run_slot];
	k_mutex_unlock(&orchestrator->lock);
	if (pqcp_sovereign_continuity_terminal_state(
		    run.state)) {
		return -ENODATA;
	}
	ret = pqcp_sovereign_recovery_plan_get(
		orchestrator->plans, run.tenant_id,
		run.plan_id, &plan);
	if (ret != 0) {
		return ret;
	}
	if (!pqcp_sovereign_continuity_digest_equal(
		    run.plan_digest, plan.plan_digest)) {
		return -ESTALE;
	}
	ret = current_plan_step(
		&plan, &run, &index, &current);
	if (ret == 0) {
		*step = *current;
	}
	return ret;
}

int pqcp_sovereign_recovery_get(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	uint64_t run_id,
	struct pqcp_sovereign_recovery_run *run)
{
	int index;
	int ret = 0;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    run_id == 0U || run == NULL) {
		return -EINVAL;
	}
	memset(run, 0, sizeof(*run));
	k_mutex_lock(&orchestrator->lock, K_FOREVER);
	index = run_index(orchestrator, run_id);
	if (index < 0) {
		ret = index;
	} else {
		*run = orchestrator->runs[index];
	}
	k_mutex_unlock(&orchestrator->lock);
	return ret;
}

static int finish_run(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_plan *plan,
	struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms)
{
	int ret;

	if (run->selected_point_generation != 0U) {
		ret = pqcp_sovereign_recovery_point_consume(
			orchestrator->points, run->tenant_id,
			run->selected_point_id,
			run->selected_point_generation,
			now_ms);
		if (ret != 0 && ret != -EALREADY) {
			return ret;
		}
	}
	ret = edge_complete(
		orchestrator, run, now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = release_run_fence(
		orchestrator, run, now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = edge_set_continuity_mode(
		orchestrator, plan,
		PQCP_EDGE_CONTINUITY_NORMAL, now_ms);
	if (ret != 0 && ret != -EAGAIN) {
		return ret;
	}
	run->state = PQCP_SOVEREIGN_RUN_COMPLETED;
	run->completed_at_ms = now_ms;
	orchestrator->completed_count =
		pqcp_sovereign_continuity_add_u64(
			orchestrator->completed_count, 1U);
	return 0;
}

static int advance_run_step(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_plan *plan,
	struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms)
{
	const struct pqcp_sovereign_recovery_step *next;
	enum pqcp_sovereign_recovery_run_state next_state;
	uint32_t next_index;
	int ret;

	++run->current_order_index;
	if (run->current_order_index >= plan->step_count) {
		return finish_run(
			orchestrator, plan, run, now_ms);
	}
	ret = current_plan_step(
		plan, run, &next_index, &next);
	if (ret != 0) {
		return ret;
	}
	next_state =
		pqcp_sovereign_continuity_state_for_step(
			next->kind);
	if (!pqcp_sovereign_continuity_transition_valid(
		    run->state, next_state) &&
	    next_state != PQCP_SOVEREIGN_RUN_COMPLETED) {
		return -EPERM;
	}
	ret = authorize_step(
		orchestrator, run, next, now_ms);
	if (ret != 0) {
		return ret;
	}
	run->step_attempts[next_index] = 1U;
	run->attempt_mask |= 1U << next_index;
	if (next->kind ==
	    PQCP_SOVEREIGN_STEP_RELEASE_FENCE) {
		ret = release_run_fence(
			orchestrator, run, now_ms);
		if (ret != 0) {
			return ret;
		}
	}
	run->state = next_state;
	ret = edge_prepare_step(
		orchestrator, run, next, now_ms);
	if (ret != 0) {
		return ret;
	}
	if (next->kind ==
	    PQCP_SOVEREIGN_STEP_COMPLETE) {
		run->completed_step_mask |=
			1U << next_index;
		return finish_run(
			orchestrator, plan, run, now_ms);
	}
	return 0;
}

static void mark_run_failed(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_plan *plan,
	struct pqcp_sovereign_recovery_run *run,
	uint64_t now_ms)
{
	if (run->state != PQCP_SOVEREIGN_RUN_FAILED) {
		orchestrator->failed_count =
			pqcp_sovereign_continuity_add_u64(
				orchestrator->failed_count, 1U);
	}
	run->state = PQCP_SOVEREIGN_RUN_FAILED;
	run->updated_at_ms = now_ms;
	(void)edge_abort(orchestrator, run, now_ms);
	(void)edge_set_continuity_mode(
		orchestrator, plan,
		PQCP_EDGE_CONTINUITY_FAILSAFE, now_ms);
}

int pqcp_sovereign_recovery_record(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	const struct pqcp_sovereign_recovery_step_result *result,
	struct pqcp_sovereign_recovery_run *run)
{
	struct pqcp_sovereign_recovery_plan plan;
	struct pqcp_sovereign_recovery_run candidate;
	const struct pqcp_sovereign_recovery_step *step;
	uint32_t step_index;
	int outcome;
	int index;
	int ret;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    result == NULL || result->run_id == 0U ||
	    result->step_id == 0U || result->now_ms == 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    result->evidence_digest) ||
	    run == NULL) {
		return -EINVAL;
	}
	memset(run, 0, sizeof(*run));
	k_mutex_lock(&orchestrator->lock, K_FOREVER);
	index = run_index(orchestrator, result->run_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	candidate = orchestrator->runs[index];
	if (pqcp_sovereign_continuity_terminal_state(
		    candidate.state)) {
		ret = -EALREADY;
		goto out;
	}
	if (candidate.deadline_ms <= result->now_ms) {
		(void)edge_abort(
			orchestrator, &candidate,
			result->now_ms);
		(void)release_run_fence(
			orchestrator, &candidate,
			result->now_ms);
		(void)release_selected_point(
			orchestrator, &candidate,
			result->now_ms);
		if (pqcp_sovereign_recovery_plan_get(
			    orchestrator->plans,
			    candidate.tenant_id,
			    candidate.plan_id, &plan) == 0) {
			(void)edge_set_continuity_mode(
				orchestrator, &plan,
				PQCP_EDGE_CONTINUITY_FAILSAFE,
				result->now_ms);
		}
		candidate.state = PQCP_SOVEREIGN_RUN_EXPIRED;
		candidate.updated_at_ms = result->now_ms;
		candidate.completed_at_ms = result->now_ms;
		orchestrator->failed_count =
			pqcp_sovereign_continuity_add_u64(
				orchestrator->failed_count, 1U);
		ret = pqcp_sovereign_continuity_digest_run(
			&candidate, candidate.run_digest);
		if (ret == 0) {
			orchestrator->runs[index] = candidate;
			*run = candidate;
			ret = -ETIMEDOUT;
		}
		goto out;
	}
	ret = pqcp_sovereign_recovery_plan_get(
		orchestrator->plans, candidate.tenant_id,
		candidate.plan_id, &plan);
	if (ret != 0) {
		int plan_error = ret;

		(void)edge_abort(
			orchestrator, &candidate,
			result->now_ms);
		candidate.state = PQCP_SOVEREIGN_RUN_FAILED;
		candidate.updated_at_ms = result->now_ms;
		orchestrator->failed_count =
			pqcp_sovereign_continuity_add_u64(
				orchestrator->failed_count, 1U);
		ret = pqcp_sovereign_continuity_digest_run(
			&candidate, candidate.run_digest);
		if (ret == 0) {
			orchestrator->runs[index] = candidate;
			*run = candidate;
			ret = plan_error;
		}
		goto out;
	}
	if (!plan.active ||
	    !pqcp_sovereign_continuity_digest_equal(
		    plan.plan_digest, candidate.plan_digest) ||
	    plan.policy_epoch != candidate.policy_epoch ||
	    plan.revocation_epoch !=
		    candidate.revocation_epoch) {
		mark_run_failed(
			orchestrator, &plan, &candidate,
			result->now_ms);
		ret = pqcp_sovereign_continuity_digest_run(
			&candidate, candidate.run_digest);
		if (ret == 0) {
			orchestrator->runs[index] = candidate;
			*run = candidate;
			ret = -ESTALE;
		}
		goto out;
	}
	ret = current_plan_step(
		&plan, &candidate, &step_index, &step);
	if (ret != 0) {
		goto out;
	}
	if (step->step_id != result->step_id) {
		ret = -EPROTO;
		goto out;
	}
	ret = check_run_fence(
		orchestrator, &candidate, result->now_ms);
	if (ret != 0 && step->kind !=
	    PQCP_SOVEREIGN_STEP_RELEASE_FENCE) {
		int fence_error = ret;

		mark_run_failed(
			orchestrator, &plan, &candidate,
			result->now_ms);
		ret = pqcp_sovereign_continuity_digest_run(
			&candidate, candidate.run_digest);
		if (ret == 0) {
			orchestrator->runs[index] = candidate;
			*run = candidate;
			ret = fence_error;
		}
		goto out;
	}
	if (step->evidence_required &&
	    !pqcp_sovereign_continuity_digest_equal(
		    step->expected_evidence_digest,
		    result->evidence_digest)) {
		ret = -EKEYREJECTED;
		goto out;
	}
	ret = chain_run_evidence(
		&candidate, step, result->result,
		result->evidence_digest, result->now_ms);
	if (ret != 0) {
		goto out;
	}
	candidate.updated_at_ms = result->now_ms;
	outcome = result->result;
	if (result->result == 0) {
		ret = edge_record_success(
			orchestrator, &candidate, step,
			result->evidence_digest,
			result->now_ms);
		if (ret != 0) {
			outcome = ret;
			candidate.failed_step_mask |=
				1U << step_index;
			++candidate.failure_count;
			mark_run_failed(
				orchestrator, &plan, &candidate,
				result->now_ms);
			goto digest;
		}
		candidate.completed_step_mask |=
			1U << step_index;
		candidate.failed_step_mask &=
			~(1U << step_index);
		ret = advance_run_step(
			orchestrator, &plan, &candidate,
			result->now_ms);
		if (ret != 0) {
			outcome = ret;
			candidate.failed_step_mask |=
				1U << step_index;
			++candidate.failure_count;
			mark_run_failed(
				orchestrator, &plan, &candidate,
				result->now_ms);
		}
	} else {
		++candidate.failure_count;
		candidate.failed_step_mask |=
			1U << step_index;
		if (candidate.step_attempts[step_index] >=
		    step->maximum_attempts ||
		    step->critical) {
			mark_run_failed(
				orchestrator, &plan, &candidate,
				result->now_ms);
		} else {
			ret = authorize_step(
				orchestrator, &candidate,
				step, result->now_ms);
			if (ret == 0) {
				++candidate.step_attempts[
					step_index];
			} else {
				outcome = ret;
				mark_run_failed(
					orchestrator, &plan,
					&candidate,
					result->now_ms);
			}
		}
	}
digest:
	ret = pqcp_sovereign_continuity_digest_run(
		&candidate, candidate.run_digest);
	if (ret != 0) {
		goto out;
	}
	orchestrator->runs[index] = candidate;
	*run = candidate;
	ret = outcome;
out:
	k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_sovereign_recovery_cancel(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	uint64_t run_id,
	const uint8_t authorization_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_sovereign_recovery_run *run;
	struct pqcp_sovereign_recovery_plan plan;
	int index;
	int ret = 0;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    run_id == 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    authorization_digest) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&orchestrator->lock, K_FOREVER);
	index = run_index(orchestrator, run_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	run = &orchestrator->runs[index];
	if (pqcp_sovereign_continuity_terminal_state(
		    run->state) &&
	    run->state != PQCP_SOVEREIGN_RUN_FAILED) {
		ret = -EALREADY;
		goto out;
	}
	if (!pqcp_sovereign_continuity_digest_equal(
		    run->quorum_authorization_digest,
		    authorization_digest)) {
		ret = -EKEYREJECTED;
		goto out;
	}
	ret = pqcp_sovereign_recovery_plan_get(
		orchestrator->plans, run->tenant_id,
		run->plan_id, &plan);
	if (ret != 0) {
		goto out;
	}
	(void)edge_abort(orchestrator, run, now_ms);
	ret = release_run_fence(
		orchestrator, run, now_ms);
	if (ret == 0 || ret == -EALREADY) {
		ret = release_selected_point(
			orchestrator, run, now_ms);
	}
	if (ret == 0) {
		run->state =
			PQCP_SOVEREIGN_RUN_CANCELLED;
		run->updated_at_ms = now_ms;
		run->completed_at_ms = now_ms;
		ret = pqcp_sovereign_continuity_digest_run(
			run, run->run_digest);
		if (ret == 0) {
			(void)edge_set_continuity_mode(
				orchestrator, &plan,
				PQCP_EDGE_CONTINUITY_FAILSAFE,
				now_ms);
		}
	}
out:
	k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_sovereign_recovery_tick(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret = 0;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&orchestrator->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < orchestrator->capacity; ++index) {
		struct pqcp_sovereign_recovery_run *run =
			&orchestrator->runs[index];
		struct pqcp_sovereign_recovery_plan plan;

		if (!run->occupied || run->deadline_ms > now_ms) {
			continue;
		}
		if (run->state == PQCP_SOVEREIGN_RUN_FAILED) {
			(void)release_run_fence(
				orchestrator, run, now_ms);
			(void)release_selected_point(
				orchestrator, run, now_ms);
			run->completed_at_ms = now_ms;
			ret = pqcp_sovereign_continuity_digest_run(
				run, run->run_digest);
			if (ret != 0) {
				break;
			}
			continue;
		}
		if (pqcp_sovereign_continuity_terminal_state(
			    run->state)) {
			continue;
		}
		(void)edge_abort(orchestrator, run, now_ms);
		(void)release_run_fence(
			orchestrator, run, now_ms);
		(void)release_selected_point(
			orchestrator, run, now_ms);
		if (pqcp_sovereign_recovery_plan_get(
			    orchestrator->plans, run->tenant_id,
			    run->plan_id, &plan) == 0) {
			(void)edge_set_continuity_mode(
				orchestrator, &plan,
				PQCP_EDGE_CONTINUITY_FAILSAFE,
				now_ms);
		}
		run->state = PQCP_SOVEREIGN_RUN_EXPIRED;
		run->updated_at_ms = now_ms;
		run->completed_at_ms = now_ms;
		ret = pqcp_sovereign_continuity_digest_run(
			run, run->run_digest);
		if (ret != 0) {
			break;
		}
		++expired;
		orchestrator->failed_count =
			pqcp_sovereign_continuity_add_u64(
				orchestrator->failed_count, 1U);
	}
	k_mutex_unlock(&orchestrator->lock);
	*expired_count = expired;
	return ret;
}

int pqcp_sovereign_recovery_orchestrator_audit(
	struct pqcp_sovereign_recovery_orchestrator *orchestrator)
{
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	int ret = 0;

	if (orchestrator == NULL || !orchestrator->initialized ||
	    orchestrator->schema_version !=
		    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
	    orchestrator->runs == NULL ||
	    orchestrator->capacity == 0U ||
	    orchestrator->objectives == NULL ||
	    orchestrator->points == NULL ||
	    orchestrator->leases == NULL ||
	    orchestrator->fences == NULL ||
	    orchestrator->plans == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&orchestrator->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < orchestrator->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_recovery_run *run =
			&orchestrator->runs[index];

		if (!run->occupied) {
			continue;
		}
		if (run->schema_version !=
			    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
		    run->generation == 0U || run->run_id == 0U ||
		    !pqcp_sovereign_continuity_text_valid(
			    run->tenant_id) ||
		    !pqcp_sovereign_continuity_text_valid(
			    run->plan_id) ||
		    !pqcp_sovereign_continuity_text_valid(
			    run->objective_id) ||
		    !pqcp_sovereign_continuity_text_valid(
			    run->resource_id) ||
		    !pqcp_sovereign_continuity_text_valid(
			    run->principal_id) ||
		    !pqcp_sovereign_continuity_text_valid(
			    run->lease_id) ||
		    !pqcp_sovereign_continuity_mode_valid(
			    run->mode) ||
		    run->state <= PQCP_SOVEREIGN_RUN_EMPTY ||
		    run->state > PQCP_SOVEREIGN_RUN_EXPIRED ||
		    run->deadline_ms <= run->started_at_ms ||
		    run->updated_at_ms < run->started_at_ms ||
		    run->policy_epoch == 0U ||
		    run->revocation_epoch == 0U ||
		    run->fencing_epoch == 0U ||
		    (run->completed_step_mask &
		     run->failed_step_mask) != 0U ||
		    !pqcp_sovereign_continuity_digest_valid(
			    run->plan_digest) ||
		    !pqcp_sovereign_continuity_digest_valid(
			    run->quorum_authorization_digest) ||
		    !pqcp_sovereign_continuity_digest_valid(
			    run->run_digest) ||
		    (run->fence_held &&
		     run->fence_generation == 0U) ||
		    (run->selected_point_generation != 0U &&
		     (!pqcp_sovereign_continuity_text_valid(
			      run->selected_point_id) ||
		      !pqcp_sovereign_continuity_digest_valid(
			      run->selected_point_digest)))) {
			ret = -EBADMSG;
			break;
		}
		ret = pqcp_sovereign_continuity_digest_run(
			run, digest);
		if (ret == 0 &&
		    !pqcp_sovereign_continuity_digest_equal(
			    digest, run->run_digest)) {
			ret = -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < orchestrator->capacity && ret == 0;
		     ++other) {
			const struct pqcp_sovereign_recovery_run *peer =
				&orchestrator->runs[other];

			if (peer->occupied &&
			    peer->run_id == run->run_id) {
				ret = -EEXIST;
			}
			if (peer->occupied &&
			    !pqcp_sovereign_continuity_terminal_state(
				    run->state) &&
			    !pqcp_sovereign_continuity_terminal_state(
				    peer->state) &&
			    strcmp(run->tenant_id,
				   peer->tenant_id) == 0 &&
			    strcmp(run->resource_id,
				   peer->resource_id) == 0) {
				ret = -EBUSY;
			}
		}
	}
	k_mutex_unlock(&orchestrator->lock);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_objective_registry_audit(
		orchestrator->objectives);
	if (ret == 0) {
		ret = pqcp_sovereign_recovery_point_catalog_audit(
			orchestrator->points);
	}
	if (ret == 0) {
		ret =
			pqcp_sovereign_authority_lease_manager_audit(
				orchestrator->leases);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_fence_manager_audit(
			orchestrator->fences);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_recovery_plan_registry_audit(
			orchestrator->plans);
	}
	if (ret == 0 &&
	    orchestrator->edge.continuity != NULL) {
		ret = pqcp_edge_continuity_manager_audit(
			orchestrator->edge.continuity);
	}
	if (ret == 0 &&
	    orchestrator->edge.recovery != NULL) {
		ret = pqcp_edge_recovery_coordinator_audit(
			orchestrator->edge.recovery);
	}
	return ret;
}
