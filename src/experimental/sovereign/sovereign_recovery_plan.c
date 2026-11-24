/*
 * SPDX-License-Identifier: MIT
 *
 * Recovery-plan registry with deterministic dependency-DAG ordering.
 */

#include "sovereign_continuity_internal.h"

static int plan_index(
	const struct pqcp_sovereign_recovery_plan_registry *registry,
	const char *tenant_id,
	const char *plan_id)
{
	for (size_t index = 0U;
	     index < registry->capacity; ++index) {
		const struct pqcp_sovereign_recovery_plan *plan =
			&registry->plans[index];

		if (plan->occupied &&
		    strcmp(plan->tenant_id, tenant_id) == 0 &&
		    strcmp(plan->plan_id, plan_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_plan_index(
	const struct pqcp_sovereign_recovery_plan_registry *registry)
{
	for (size_t index = 0U;
	     index < registry->capacity; ++index) {
		if (!registry->plans[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int step_index_by_id(
	const struct pqcp_sovereign_recovery_plan *plan,
	uint32_t step_id)
{
	for (uint32_t index = 0U;
	     index < plan->step_count; ++index) {
		if (plan->steps[index].step_id == step_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static bool mode_accepts_step(
	enum pqcp_sovereign_recovery_mode mode,
	enum pqcp_sovereign_recovery_step_kind kind)
{
	switch (mode) {
	case PQCP_SOVEREIGN_RECOVERY_MODE_FAILOVER:
		return kind != PQCP_SOVEREIGN_STEP_REJOIN &&
		       kind != PQCP_SOVEREIGN_STEP_ROLLBACK;
	case PQCP_SOVEREIGN_RECOVERY_MODE_REJOIN:
		return kind != PQCP_SOVEREIGN_STEP_PROMOTE &&
		       kind != PQCP_SOVEREIGN_STEP_ROLLBACK;
	case PQCP_SOVEREIGN_RECOVERY_MODE_ROLLBACK:
		return kind != PQCP_SOVEREIGN_STEP_PROMOTE &&
		       kind != PQCP_SOVEREIGN_STEP_REJOIN;
	case PQCP_SOVEREIGN_RECOVERY_MODE_DISASTER_RECOVERY:
		return true;
	default:
		return false;
	}
}

static bool required_mode_step_present(
	const struct pqcp_sovereign_recovery_plan *plan)
{
	bool restore = false;
	bool validate = false;
	bool mode_step = false;

	for (uint32_t index = 0U;
	     index < plan->step_count; ++index) {
		switch (plan->steps[index].kind) {
		case PQCP_SOVEREIGN_STEP_RESTORE:
			restore = true;
			break;
		case PQCP_SOVEREIGN_STEP_VALIDATE:
			validate = true;
			break;
		case PQCP_SOVEREIGN_STEP_PROMOTE:
			mode_step = mode_step ||
				plan->mode ==
					PQCP_SOVEREIGN_RECOVERY_MODE_FAILOVER ||
				plan->mode ==
					PQCP_SOVEREIGN_RECOVERY_MODE_DISASTER_RECOVERY;
			break;
		case PQCP_SOVEREIGN_STEP_REJOIN:
			mode_step = mode_step ||
				plan->mode ==
					PQCP_SOVEREIGN_RECOVERY_MODE_REJOIN ||
				plan->mode ==
					PQCP_SOVEREIGN_RECOVERY_MODE_DISASTER_RECOVERY;
			break;
		case PQCP_SOVEREIGN_STEP_ROLLBACK:
			mode_step = mode_step ||
				plan->mode ==
					PQCP_SOVEREIGN_RECOVERY_MODE_ROLLBACK ||
				plan->mode ==
					PQCP_SOVEREIGN_RECOVERY_MODE_DISASTER_RECOVERY;
			break;
		default:
			break;
		}
	}
	return restore && validate && mode_step;
}

static int validate_step(
	const struct pqcp_sovereign_recovery_plan *plan,
	uint32_t index)
{
	const struct pqcp_sovereign_recovery_step *step =
		&plan->steps[index];
	uint32_t valid_mask =
		pqcp_sovereign_continuity_step_mask(
			plan->step_count);
	uint32_t canonical_operation;

	if (step->step_id == 0U ||
	    !pqcp_sovereign_continuity_step_kind_valid(
		    step->kind) ||
	    !mode_accepts_step(plan->mode, step->kind) ||
	    !pqcp_sovereign_continuity_text_valid(
		    step->service_id) ||
	    (step->dependency_mask & ~valid_mask) != 0U ||
	    (step->dependency_mask & (1U << index)) != 0U ||
	    step->maximum_attempts == 0U ||
	    step->timeout_ms == 0U) {
		return -EINVAL;
	}
	canonical_operation =
		pqcp_sovereign_continuity_operation_for_step(
			step->kind);
	if (step->required_operation != canonical_operation ||
	    (step->required_operation &
	     ~plan->required_operation_mask) != 0U) {
		return -EPERM;
	}
	if (step->evidence_required &&
	    !pqcp_sovereign_continuity_digest_valid(
		    step->expected_evidence_digest)) {
		return -EBADMSG;
	}
	if (!step->evidence_required &&
	    pqcp_sovereign_continuity_digest_valid(
		    step->expected_evidence_digest)) {
		return -EINVAL;
	}
	if (step->point_required &&
	    step->kind != PQCP_SOVEREIGN_STEP_SELECT_POINT &&
	    step->kind != PQCP_SOVEREIGN_STEP_RESTORE &&
	    step->kind != PQCP_SOVEREIGN_STEP_VALIDATE &&
	    step->kind != PQCP_SOVEREIGN_STEP_ROLLBACK) {
		return -EINVAL;
	}
	if (step->fence_required &&
	    (plan->required_operation_mask &
	     PQCP_SOVEREIGN_RECOVERY_OP_FENCE) == 0U) {
		return -EPERM;
	}
	return 0;
}

static int validate_plan_identity(
	const struct pqcp_sovereign_recovery_plan *plan)
{
	if (plan == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    plan->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    plan->plan_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    plan->objective_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    plan->resource_id) ||
	    !pqcp_sovereign_continuity_mode_valid(
		    plan->mode) ||
	    plan->created_at_ms == 0U ||
	    plan->expires_at_ms <= plan->created_at_ms ||
	    plan->policy_epoch == 0U ||
	    plan->revocation_epoch == 0U ||
	    plan->maximum_duration_ms == 0U ||
	    plan->point_maximum_age_ms == 0U ||
	    plan->step_count == 0U ||
	    plan->step_count >
		    PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS ||
	    plan->required_approval_count == 0U ||
	    plan->required_operation_mask == 0U ||
	    (plan->required_operation_mask &
	     ~PQCP_SOVEREIGN_RECOVERY_OP_ALL) != 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    plan->policy_digest)) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_sovereign_recovery_plan_order(
	const struct pqcp_sovereign_recovery_plan *plan,
	uint8_t order[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS])
{
	uint32_t emitted = 0U;
	uint32_t valid_mask;

	if (validate_plan_identity(plan) != 0 ||
	    order == NULL) {
		return -EINVAL;
	}
	valid_mask =
		pqcp_sovereign_continuity_step_mask(
			plan->step_count);
	memset(order, 0,
	       PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS);
	for (uint32_t position = 0U;
	     position < plan->step_count; ++position) {
		int selected = -1;

		for (uint32_t index = 0U;
		     index < plan->step_count; ++index) {
			uint32_t bit = 1U << index;
			const struct pqcp_sovereign_recovery_step *step =
				&plan->steps[index];

			if ((emitted & bit) != 0U ||
			    (step->dependency_mask &
			     ~emitted) != 0U) {
				continue;
			}
			if (selected < 0 ||
			    step->step_id <
				    plan->steps[selected].step_id) {
				selected = (int)index;
			}
		}
		if (selected < 0) {
			return -ELOOP;
		}
		order[position] = (uint8_t)selected;
		emitted |= 1U << selected;
	}
	return emitted == valid_mask ? 0 : -ELOOP;
}

static int dependency_closure(
	const struct pqcp_sovereign_recovery_plan *plan,
	const uint8_t order[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS],
	uint32_t closure[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS])
{
	uint32_t emitted = 0U;

	memset(closure, 0,
	       sizeof(uint32_t) *
		       PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS);
	for (uint32_t position = 0U;
	     position < plan->step_count; ++position) {
		uint32_t index = order[position];
		uint32_t dependencies;

		if (index >= plan->step_count) {
			return -EBADMSG;
		}
		dependencies =
			plan->steps[index].dependency_mask;
		if ((dependencies & ~emitted) != 0U) {
			return -ELOOP;
		}
		closure[index] = dependencies;
		for (uint32_t dependency = 0U;
		     dependency < plan->step_count;
		     ++dependency) {
			if ((dependencies &
			     (1U << dependency)) != 0U) {
				closure[index] |=
					closure[dependency];
			}
		}
		emitted |= 1U << index;
	}
	return 0;
}

static int validate_dependency_contract(
	const struct pqcp_sovereign_recovery_plan *plan,
	const uint8_t order[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS])
{
	uint32_t closure[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS];
	uint32_t select_mask = 0U;
	uint32_t fence_mask = 0U;
	uint32_t restore_mask = 0U;
	uint32_t validate_mask = 0U;
	uint32_t mode_mask = 0U;
	uint32_t release_mask = 0U;
	uint32_t complete_mask = 0U;
	uint32_t fence_protected_mask = 0U;
	uint32_t valid_mask =
		pqcp_sovereign_continuity_step_mask(
			plan->step_count);
	int ret;

	ret = dependency_closure(plan, order, closure);
	if (ret != 0) {
		return ret;
	}
	for (uint32_t index = 0U;
	     index < plan->step_count; ++index) {
		uint32_t bit = 1U << index;
		const struct pqcp_sovereign_recovery_step *step =
			&plan->steps[index];

		switch (step->kind) {
		case PQCP_SOVEREIGN_STEP_SELECT_POINT:
			select_mask |= bit;
			break;
		case PQCP_SOVEREIGN_STEP_FENCE:
			fence_mask |= bit;
			break;
		case PQCP_SOVEREIGN_STEP_RESTORE:
			restore_mask |= bit;
			break;
		case PQCP_SOVEREIGN_STEP_VALIDATE:
			validate_mask |= bit;
			break;
		case PQCP_SOVEREIGN_STEP_PROMOTE:
		case PQCP_SOVEREIGN_STEP_REJOIN:
		case PQCP_SOVEREIGN_STEP_ROLLBACK:
			mode_mask |= bit;
			break;
		case PQCP_SOVEREIGN_STEP_RELEASE_FENCE:
			release_mask |= bit;
			break;
		case PQCP_SOVEREIGN_STEP_COMPLETE:
			complete_mask |= bit;
			break;
		default:
			break;
		}
		if (step->fence_required &&
		    step->kind != PQCP_SOVEREIGN_STEP_FENCE &&
		    step->kind !=
			    PQCP_SOVEREIGN_STEP_RELEASE_FENCE) {
			fence_protected_mask |= bit;
		}
	}
	if (__builtin_popcount(complete_mask) != 1 ||
	    __builtin_popcount(mode_mask) == 0 ||
	    (restore_mask == 0U) || (validate_mask == 0U)) {
		return -EPERM;
	}
	if ((fence_mask != 0U || fence_protected_mask != 0U) &&
	    (__builtin_popcount(fence_mask) != 1 ||
	     __builtin_popcount(release_mask) != 1)) {
		return -EPERM;
	}
	for (uint32_t index = 0U;
	     index < plan->step_count; ++index) {
		uint32_t ancestors = closure[index];
		uint32_t bit = 1U << index;
		const struct pqcp_sovereign_recovery_step *step =
			&plan->steps[index];

		if (step->point_required &&
		    step->kind !=
			    PQCP_SOVEREIGN_STEP_SELECT_POINT &&
		    (ancestors & select_mask) == 0U) {
			return -EPERM;
		}
		if (step->fence_required &&
		    step->kind != PQCP_SOVEREIGN_STEP_FENCE &&
		    (ancestors & fence_mask) == 0U) {
			return -EPERM;
		}
		if (step->kind == PQCP_SOVEREIGN_STEP_VALIDATE &&
		    (ancestors & restore_mask) == 0U) {
			return -EPERM;
		}
		if ((bit & mode_mask) != 0U &&
		    (ancestors & validate_mask) == 0U) {
			return -EPERM;
		}
		if (step->kind ==
			    PQCP_SOVEREIGN_STEP_RELEASE_FENCE &&
		    ((ancestors & fence_mask) != fence_mask ||
		     (ancestors & fence_protected_mask) !=
			     fence_protected_mask ||
		     (ancestors & mode_mask) != mode_mask)) {
			return -EPERM;
		}
		if (step->kind ==
			    PQCP_SOVEREIGN_STEP_COMPLETE &&
		    ancestors != (valid_mask & ~bit)) {
			return -EPERM;
		}
	}
	return 0;
}

static int validate_plan(
	const struct pqcp_sovereign_recovery_plan *plan,
	uint8_t order[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS])
{
	uint32_t operation_mask = 0U;
	bool complete_present = false;
	int ret;

	ret = validate_plan_identity(plan);
	if (ret != 0) {
		return ret;
	}
	for (uint32_t index = 0U;
	     index < plan->step_count; ++index) {
		ret = validate_step(plan, index);
		if (ret != 0) {
			return ret;
		}
		operation_mask |=
			plan->steps[index].required_operation;
		complete_present = complete_present ||
			plan->steps[index].kind ==
				PQCP_SOVEREIGN_STEP_COMPLETE;
		for (uint32_t other = index + 1U;
		     other < plan->step_count; ++other) {
			if (plan->steps[index].step_id ==
			    plan->steps[other].step_id) {
				return -EEXIST;
			}
		}
	}
	if (!required_mode_step_present(plan) ||
	    !complete_present ||
	    operation_mask != plan->required_operation_mask) {
		return -EPERM;
	}
	ret = pqcp_sovereign_recovery_plan_order(
		plan, order);
	if (ret != 0) {
		return ret;
	}
	ret = validate_dependency_contract(plan, order);
	if (ret != 0) {
		return ret;
	}
	for (uint32_t position = 0U;
	     position < plan->step_count; ++position) {
		uint32_t index = order[position];
		const struct pqcp_sovereign_recovery_step *step =
			&plan->steps[index];

		if (step->kind ==
			    PQCP_SOVEREIGN_STEP_COMPLETE &&
		    position != plan->step_count - 1U) {
			return -EPERM;
		}
		if (step->kind ==
			    PQCP_SOVEREIGN_STEP_RESTORE &&
		    step->point_required) {
			bool selector_dependency = false;

			for (uint32_t dependency = 0U;
			     dependency < plan->step_count;
			     ++dependency) {
				if ((step->dependency_mask &
				     (1U << dependency)) != 0U &&
				    plan->steps[dependency].kind ==
					    PQCP_SOVEREIGN_STEP_SELECT_POINT) {
					selector_dependency = true;
					break;
				}
			}
			if (!selector_dependency) {
				return -EPERM;
			}
		}
	}
	return 0;
}

int pqcp_sovereign_recovery_plan_registry_init(
	struct pqcp_sovereign_recovery_plan_registry *registry,
	struct pqcp_sovereign_recovery_plan *plans,
	size_t capacity)
{
	if (registry == NULL || plans == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(plans, 0, capacity * sizeof(*plans));
	registry->schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	registry->plans = plans;
	registry->capacity = capacity;
	registry->next_generation = 1U;
	k_mutex_init(&registry->lock);
	registry->initialized = true;
	return 0;
}

int pqcp_sovereign_recovery_plan_put(
	struct pqcp_sovereign_recovery_plan_registry *registry,
	const struct pqcp_sovereign_recovery_plan *plan)
{
	struct pqcp_sovereign_recovery_plan candidate;
	uint8_t order[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS];
	int index;
	int ret;

	if (registry == NULL || !registry->initialized) {
		return -EINVAL;
	}
	ret = validate_plan(plan, order);
	if (ret != 0) {
		registry->rejection_count =
			pqcp_sovereign_continuity_add_u64(
				registry->rejection_count, 1U);
		return ret;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = plan_index(
		registry, plan->tenant_id, plan->plan_id);
	if (index >= 0) {
		const struct pqcp_sovereign_recovery_plan *current =
			&registry->plans[index];

		if (plan->policy_epoch <
			    current->policy_epoch ||
		    plan->revocation_epoch <
			    current->revocation_epoch ||
		    plan->updated_at_ms <
			    current->updated_at_ms) {
			ret = -ESTALE;
			goto reject;
		}
		if (current->active &&
		    plan->generation != 0U &&
		    plan->generation != current->generation) {
			ret = -ESTALE;
			goto reject;
		}
	} else if (index == -ENOENT) {
		index = free_plan_index(registry);
	}
	if (index < 0) {
		ret = index;
		goto reject;
	}
	candidate = *plan;
	candidate.schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	candidate.generation =
		pqcp_edge_internal_next_generation(
			&registry->next_generation);
	memcpy(candidate.topological_order, order,
	       candidate.step_count);
	if (candidate.updated_at_ms == 0U) {
		candidate.updated_at_ms =
			candidate.created_at_ms;
	}
	candidate.occupied = true;
	ret = pqcp_sovereign_continuity_digest_plan(
		&candidate, candidate.plan_digest);
	if (ret == 0) {
		registry->plans[index] = candidate;
		registry->registration_count =
			pqcp_sovereign_continuity_add_u64(
				registry->registration_count, 1U);
	}
	goto out;
reject:
	registry->rejection_count =
		pqcp_sovereign_continuity_add_u64(
			registry->rejection_count, 1U);
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_sovereign_recovery_plan_get(
	struct pqcp_sovereign_recovery_plan_registry *registry,
	const char *tenant_id,
	const char *plan_id,
	struct pqcp_sovereign_recovery_plan *plan)
{
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(plan_id) ||
	    plan == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = plan_index(registry, tenant_id, plan_id);
	if (index < 0) {
		ret = index;
	} else {
		*plan = registry->plans[index];
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_sovereign_recovery_plan_remove(
	struct pqcp_sovereign_recovery_plan_registry *registry,
	const char *tenant_id,
	const char *plan_id,
	uint32_t generation)
{
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(plan_id) ||
	    generation == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = plan_index(registry, tenant_id, plan_id);
	if (index < 0) {
		ret = index;
	} else if (registry->plans[index].generation !=
		   generation) {
		ret = -ESTALE;
	} else {
		memset(&registry->plans[index], 0,
		       sizeof(registry->plans[index]));
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_sovereign_recovery_plan_registry_audit(
	struct pqcp_sovereign_recovery_plan_registry *registry)
{
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	uint8_t order[PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS];
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    registry->schema_version !=
		    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
	    registry->plans == NULL || registry->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < registry->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_recovery_plan *plan =
			&registry->plans[index];

		if (!plan->occupied) {
			continue;
		}
		if (plan->schema_version !=
			    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
		    plan->generation == 0U ||
		    validate_plan(plan, order) != 0 ||
		    !pqcp_sovereign_continuity_digest_valid(
			    plan->plan_digest) ||
		    memcmp(order, plan->topological_order,
			   plan->step_count) != 0) {
			ret = -EBADMSG;
			break;
		}
		ret = pqcp_sovereign_continuity_digest_plan(
			plan, digest);
		if (ret == 0 &&
		    !pqcp_sovereign_continuity_digest_equal(
			    digest, plan->plan_digest)) {
			ret = -EBADMSG;
		}
		for (uint32_t step = 0U;
		     step < plan->step_count && ret == 0;
		     ++step) {
			if (step_index_by_id(
				    plan,
				    plan->steps[step].step_id) !=
			    (int)step) {
				ret = -EBADMSG;
			}
		}
		for (size_t other = index + 1U;
		     other < registry->capacity && ret == 0;
		     ++other) {
			const struct pqcp_sovereign_recovery_plan *peer =
				&registry->plans[other];

			if (peer->occupied &&
			    strcmp(plan->tenant_id,
				   peer->tenant_id) == 0 &&
			    strcmp(plan->plan_id,
				   peer->plan_id) == 0) {
				ret = -EEXIST;
			}
		}
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}
