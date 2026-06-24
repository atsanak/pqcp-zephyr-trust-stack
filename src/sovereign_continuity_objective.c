/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Sovereign RPO/RTO objectives and canonical continuity object digests.
 */

#include "sovereign_continuity_internal.h"

static const uint8_t objective_domain[] = "pqcp.sovereign.objective.v1";
static const uint8_t point_domain[] = "pqcp.sovereign.recovery-point.v1";
static const uint8_t lease_domain[] = "pqcp.sovereign.authority-lease.v1";
static const uint8_t fence_domain[] = "pqcp.sovereign.fence.v1";
static const uint8_t plan_domain[] = "pqcp.sovereign.recovery-plan.v1";
static const uint8_t run_domain[] = "pqcp.sovereign.recovery-run.v1";
static const uint8_t event_domain[] = "pqcp.sovereign.continuity-event.v1";

bool pqcp_sovereign_continuity_text_valid(
	const char *value)
{
	return pqcp_edge_internal_text_valid(
		value, PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS);
}

bool pqcp_sovereign_continuity_digest_valid(
	const uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	return digest != NULL &&
	       !pqcp_edge_internal_all_zero(
		       digest,
		       PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES);
}

bool pqcp_sovereign_continuity_digest_equal(
	const uint8_t left[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	const uint8_t right[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	return left != NULL && right != NULL &&
	       pqcp_edge_internal_equal(
		       left, right,
		       PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES);
}

int pqcp_sovereign_continuity_copy_id(
	char destination[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS],
	const char *source)
{
	return pqcp_edge_internal_copy_text(
		destination,
		PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS,
		source);
}

int pqcp_sovereign_continuity_digest_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t count,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	if (parts == NULL || lengths == NULL ||
	    count == 0U || digest == NULL) {
		return -EINVAL;
	}
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, count, digest);
}

uint64_t pqcp_sovereign_continuity_add_u64(
	uint64_t left,
	uint64_t right)
{
	return pqcp_edge_internal_saturating_add_u64(
		left, right);
}

uint32_t pqcp_sovereign_continuity_step_mask(
	uint32_t step_count)
{
	if (step_count == 0U) {
		return 0U;
	}
	return step_count >= 32U ?
		UINT32_MAX : (1U << step_count) - 1U;
}

bool pqcp_sovereign_continuity_mode_valid(
	enum pqcp_sovereign_recovery_mode mode)
{
	return mode >= PQCP_SOVEREIGN_RECOVERY_MODE_FAILOVER &&
	       mode <=
		       PQCP_SOVEREIGN_RECOVERY_MODE_DISASTER_RECOVERY;
}

bool pqcp_sovereign_continuity_step_kind_valid(
	enum pqcp_sovereign_recovery_step_kind kind)
{
	return kind >= PQCP_SOVEREIGN_STEP_CHECKPOINT &&
	       kind <= PQCP_SOVEREIGN_STEP_COMPLETE;
}

uint32_t pqcp_sovereign_continuity_operation_for_step(
	enum pqcp_sovereign_recovery_step_kind kind)
{
	switch (kind) {
	case PQCP_SOVEREIGN_STEP_CHECKPOINT:
		return PQCP_SOVEREIGN_RECOVERY_OP_CHECKPOINT;
	case PQCP_SOVEREIGN_STEP_FENCE:
	case PQCP_SOVEREIGN_STEP_RELEASE_FENCE:
		return PQCP_SOVEREIGN_RECOVERY_OP_FENCE;
	case PQCP_SOVEREIGN_STEP_ISOLATE:
		return PQCP_SOVEREIGN_RECOVERY_OP_ISOLATE;
	case PQCP_SOVEREIGN_STEP_SELECT_POINT:
	case PQCP_SOVEREIGN_STEP_RESTORE:
		return PQCP_SOVEREIGN_RECOVERY_OP_RESTORE;
	case PQCP_SOVEREIGN_STEP_VALIDATE:
		return PQCP_SOVEREIGN_RECOVERY_OP_VALIDATE;
	case PQCP_SOVEREIGN_STEP_PROMOTE:
		return PQCP_SOVEREIGN_RECOVERY_OP_FAILOVER;
	case PQCP_SOVEREIGN_STEP_REJOIN:
		return PQCP_SOVEREIGN_RECOVERY_OP_REJOIN;
	case PQCP_SOVEREIGN_STEP_ROLLBACK:
		return PQCP_SOVEREIGN_RECOVERY_OP_ROLLBACK;
	case PQCP_SOVEREIGN_STEP_COMPLETE:
		return 0U;
	default:
		return 0U;
	}
}

enum pqcp_sovereign_recovery_run_state
pqcp_sovereign_continuity_state_for_step(
	enum pqcp_sovereign_recovery_step_kind kind)
{
	switch (kind) {
	case PQCP_SOVEREIGN_STEP_CHECKPOINT:
		return PQCP_SOVEREIGN_RUN_CHECKPOINTING;
	case PQCP_SOVEREIGN_STEP_FENCE:
	case PQCP_SOVEREIGN_STEP_RELEASE_FENCE:
		return PQCP_SOVEREIGN_RUN_FENCING;
	case PQCP_SOVEREIGN_STEP_ISOLATE:
		return PQCP_SOVEREIGN_RUN_ISOLATING;
	case PQCP_SOVEREIGN_STEP_SELECT_POINT:
	case PQCP_SOVEREIGN_STEP_RESTORE:
		return PQCP_SOVEREIGN_RUN_RESTORING;
	case PQCP_SOVEREIGN_STEP_VALIDATE:
		return PQCP_SOVEREIGN_RUN_VALIDATING;
	case PQCP_SOVEREIGN_STEP_PROMOTE:
		return PQCP_SOVEREIGN_RUN_PROMOTING;
	case PQCP_SOVEREIGN_STEP_REJOIN:
		return PQCP_SOVEREIGN_RUN_REJOINING;
	case PQCP_SOVEREIGN_STEP_ROLLBACK:
		return PQCP_SOVEREIGN_RUN_ROLLING_BACK;
	case PQCP_SOVEREIGN_STEP_COMPLETE:
		return PQCP_SOVEREIGN_RUN_COMPLETED;
	default:
		return PQCP_SOVEREIGN_RUN_FAILED;
	}
}

bool pqcp_sovereign_continuity_terminal_state(
	enum pqcp_sovereign_recovery_run_state state)
{
	return state == PQCP_SOVEREIGN_RUN_COMPLETED ||
	       state == PQCP_SOVEREIGN_RUN_FAILED ||
	       state == PQCP_SOVEREIGN_RUN_CANCELLED ||
	       state == PQCP_SOVEREIGN_RUN_EXPIRED;
}

bool pqcp_sovereign_continuity_transition_valid(
	enum pqcp_sovereign_recovery_run_state current,
	enum pqcp_sovereign_recovery_run_state next)
{
	if (pqcp_sovereign_continuity_terminal_state(current)) {
		return false;
	}
	if (next == PQCP_SOVEREIGN_RUN_FAILED ||
	    next == PQCP_SOVEREIGN_RUN_CANCELLED ||
	    next == PQCP_SOVEREIGN_RUN_EXPIRED) {
		return true;
	}
	switch (current) {
	case PQCP_SOVEREIGN_RUN_AUTHORIZED:
		return next == PQCP_SOVEREIGN_RUN_FENCING ||
		       next == PQCP_SOVEREIGN_RUN_CHECKPOINTING ||
		       next == PQCP_SOVEREIGN_RUN_ISOLATING ||
		       next == PQCP_SOVEREIGN_RUN_RESTORING;
	case PQCP_SOVEREIGN_RUN_FENCING:
		return next == PQCP_SOVEREIGN_RUN_CHECKPOINTING ||
		       next == PQCP_SOVEREIGN_RUN_ISOLATING ||
		       next == PQCP_SOVEREIGN_RUN_RESTORING ||
		       next == PQCP_SOVEREIGN_RUN_COMPLETED;
	case PQCP_SOVEREIGN_RUN_CHECKPOINTING:
		return next == PQCP_SOVEREIGN_RUN_FENCING ||
		       next == PQCP_SOVEREIGN_RUN_ISOLATING ||
		       next == PQCP_SOVEREIGN_RUN_RESTORING;
	case PQCP_SOVEREIGN_RUN_ISOLATING:
		return next == PQCP_SOVEREIGN_RUN_FENCING ||
		       next == PQCP_SOVEREIGN_RUN_RESTORING ||
		       next == PQCP_SOVEREIGN_RUN_ROLLING_BACK;
	case PQCP_SOVEREIGN_RUN_RESTORING:
		return next == PQCP_SOVEREIGN_RUN_VALIDATING ||
		       next == PQCP_SOVEREIGN_RUN_ROLLING_BACK;
	case PQCP_SOVEREIGN_RUN_VALIDATING:
		return next == PQCP_SOVEREIGN_RUN_PROMOTING ||
		       next == PQCP_SOVEREIGN_RUN_REJOINING ||
		       next == PQCP_SOVEREIGN_RUN_ROLLING_BACK ||
		       next == PQCP_SOVEREIGN_RUN_RESTORING;
	case PQCP_SOVEREIGN_RUN_PROMOTING:
		return next == PQCP_SOVEREIGN_RUN_REJOINING ||
		       next == PQCP_SOVEREIGN_RUN_FENCING ||
		       next == PQCP_SOVEREIGN_RUN_COMPLETED;
	case PQCP_SOVEREIGN_RUN_REJOINING:
		return next == PQCP_SOVEREIGN_RUN_FENCING ||
		       next == PQCP_SOVEREIGN_RUN_COMPLETED ||
		       next == PQCP_SOVEREIGN_RUN_ROLLING_BACK;
	case PQCP_SOVEREIGN_RUN_ROLLING_BACK:
		return next == PQCP_SOVEREIGN_RUN_VALIDATING ||
		       next == PQCP_SOVEREIGN_RUN_FENCING ||
		       next == PQCP_SOVEREIGN_RUN_COMPLETED;
	default:
		return false;
	}
}

static size_t encode_objective_numeric(
	const struct pqcp_sovereign_continuity_objective *objective,
	uint8_t *numeric)
{
	size_t offset = 0U;

#define WRITE_OBJECTIVE_U32(value) \
	do { \
		pqcp_edge_internal_write_u32(numeric + offset, (value)); \
		offset += 4U; \
	} while (false)
#define WRITE_OBJECTIVE_U64(value) \
	do { \
		pqcp_edge_internal_write_u64(numeric + offset, (value)); \
		offset += 8U; \
	} while (false)
	WRITE_OBJECTIVE_U32(objective->schema_version);
	WRITE_OBJECTIVE_U32(objective->generation);
	WRITE_OBJECTIVE_U32((uint32_t)objective->tier);
	WRITE_OBJECTIVE_U32((uint32_t)objective->status);
	WRITE_OBJECTIVE_U64(objective->created_at_ms);
	WRITE_OBJECTIVE_U64(objective->updated_at_ms);
	WRITE_OBJECTIVE_U64(objective->expires_at_ms);
	WRITE_OBJECTIVE_U64(objective->recovery_point_objective_ms);
	WRITE_OBJECTIVE_U64(objective->recovery_time_objective_ms);
	WRITE_OBJECTIVE_U64(objective->maximum_data_loss_bytes);
	WRITE_OBJECTIVE_U64(objective->latest_protected_at_ms);
	WRITE_OBJECTIVE_U64(objective->outage_started_at_ms);
	WRITE_OBJECTIVE_U64(objective->last_evaluated_at_ms);
	WRITE_OBJECTIVE_U64(objective->policy_epoch);
	WRITE_OBJECTIVE_U64(objective->revocation_epoch);
	WRITE_OBJECTIVE_U32(objective->minimum_replicas);
	WRITE_OBJECTIVE_U32(objective->available_replicas);
	WRITE_OBJECTIVE_U32(objective->priority);
	WRITE_OBJECTIVE_U32(objective->breach_count);
	WRITE_OBJECTIVE_U64(objective->dependency_mask);
	WRITE_OBJECTIVE_U64(objective->satisfied_dependency_mask);
	WRITE_OBJECTIVE_U32(objective->suspended ? 1U : 0U);
#undef WRITE_OBJECTIVE_U32
#undef WRITE_OBJECTIVE_U64
	return offset;
}

int pqcp_sovereign_continuity_digest_objective(
	const struct pqcp_sovereign_continuity_objective *objective,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	uint8_t numeric[156];
	const uint8_t *parts[6];
	size_t lengths[6];

	if (objective == NULL || digest == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    objective->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    objective->objective_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    objective->service_id)) {
		return -EINVAL;
	}
	parts[0] = objective_domain;
	lengths[0] = sizeof(objective_domain) - 1U;
	parts[1] = (const uint8_t *)objective->tenant_id;
	lengths[1] = strlen(objective->tenant_id);
	parts[2] = (const uint8_t *)objective->objective_id;
	lengths[2] = strlen(objective->objective_id);
	parts[3] = (const uint8_t *)objective->service_id;
	lengths[3] = strlen(objective->service_id);
	parts[4] = objective->policy_digest;
	lengths[4] = sizeof(objective->policy_digest);
	parts[5] = numeric;
	lengths[5] = encode_objective_numeric(
		objective, numeric);
	return pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 6U, digest);
}

int pqcp_sovereign_continuity_digest_point(
	const struct pqcp_sovereign_recovery_point *point,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	uint8_t numeric[112];
	size_t offset = 0U;
	const uint8_t *parts[10];
	size_t lengths[10];

	if (point == NULL || digest == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    point->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    point->objective_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    point->point_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    point->source_id)) {
		return -EINVAL;
	}
#define WRITE_POINT_U32(value) \
	do { \
		pqcp_edge_internal_write_u32(numeric + offset, (value)); \
		offset += 4U; \
	} while (false)
#define WRITE_POINT_U64(value) \
	do { \
		pqcp_edge_internal_write_u64(numeric + offset, (value)); \
		offset += 8U; \
	} while (false)
	WRITE_POINT_U32(point->schema_version);
	WRITE_POINT_U32(point->generation);
	WRITE_POINT_U32((uint32_t)point->state);
	WRITE_POINT_U64(point->created_at_ms);
	WRITE_POINT_U64(point->protected_at_ms);
	WRITE_POINT_U64(point->verified_at_ms);
	WRITE_POINT_U64(point->expires_at_ms);
	WRITE_POINT_U64(point->sequence);
	WRITE_POINT_U64(point->policy_epoch);
	WRITE_POINT_U64(point->revocation_epoch);
	WRITE_POINT_U64(point->fencing_epoch);
	WRITE_POINT_U64(point->logical_bytes);
	WRITE_POINT_U32(point->replica_count);
	WRITE_POINT_U32(point->verification_flags);
	WRITE_POINT_U32(point->complete ? 1U : 0U);
	WRITE_POINT_U32(point->immutable ? 1U : 0U);
#undef WRITE_POINT_U32
#undef WRITE_POINT_U64
	parts[0] = point_domain;
	lengths[0] = sizeof(point_domain) - 1U;
	parts[1] = (const uint8_t *)point->tenant_id;
	lengths[1] = strlen(point->tenant_id);
	parts[2] = (const uint8_t *)point->objective_id;
	lengths[2] = strlen(point->objective_id);
	parts[3] = (const uint8_t *)point->point_id;
	lengths[3] = strlen(point->point_id);
	parts[4] = (const uint8_t *)point->source_id;
	lengths[4] = strlen(point->source_id);
	parts[5] = point->content_digest;
	lengths[5] = sizeof(point->content_digest);
	parts[6] = point->manifest_digest;
	lengths[6] = sizeof(point->manifest_digest);
	parts[7] = point->parent_digest;
	lengths[7] = sizeof(point->parent_digest);
	parts[8] = point->evidence_digest;
	lengths[8] = sizeof(point->evidence_digest);
	parts[9] = numeric;
	lengths[9] = offset;
	return pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 10U, digest);
}

int pqcp_sovereign_continuity_digest_lease(
	const struct pqcp_sovereign_authority_lease *lease,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	uint8_t numeric[120];
	size_t offset = 0U;
	const uint8_t *parts[9];
	size_t lengths[9];

	if (lease == NULL || digest == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    lease->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    lease->principal_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    lease->lease_id)) {
		return -EINVAL;
	}
#define WRITE_LEASE_U32(value) \
	do { \
		pqcp_edge_internal_write_u32(numeric + offset, (value)); \
		offset += 4U; \
	} while (false)
#define WRITE_LEASE_U64(value) \
	do { \
		pqcp_edge_internal_write_u64(numeric + offset, (value)); \
		offset += 8U; \
	} while (false)
	WRITE_LEASE_U32(lease->schema_version);
	WRITE_LEASE_U32(lease->generation);
	WRITE_LEASE_U32((uint32_t)lease->state);
	WRITE_LEASE_U64(lease->issued_at_ms);
	WRITE_LEASE_U64(lease->valid_from_ms);
	WRITE_LEASE_U64(lease->expires_at_ms);
	WRITE_LEASE_U64(lease->maximum_offline_ms);
	WRITE_LEASE_U64(lease->last_used_at_ms);
	WRITE_LEASE_U64(lease->operation_limit);
	WRITE_LEASE_U64(lease->operation_count);
	WRITE_LEASE_U64(lease->policy_epoch);
	WRITE_LEASE_U64(lease->revocation_epoch);
	WRITE_LEASE_U64(lease->fencing_epoch);
	WRITE_LEASE_U32(lease->operation_mask);
	WRITE_LEASE_U32(lease->required_approval_count);
	WRITE_LEASE_U32(lease->offline_permitted ? 1U : 0U);
#undef WRITE_LEASE_U32
#undef WRITE_LEASE_U64
	parts[0] = lease_domain;
	lengths[0] = sizeof(lease_domain) - 1U;
	parts[1] = (const uint8_t *)lease->tenant_id;
	lengths[1] = strlen(lease->tenant_id);
	parts[2] = (const uint8_t *)lease->principal_id;
	lengths[2] = strlen(lease->principal_id);
	parts[3] = (const uint8_t *)lease->lease_id;
	lengths[3] = strlen(lease->lease_id);
	parts[4] = lease->plan_digest;
	lengths[4] = sizeof(lease->plan_digest);
	parts[5] = lease->quorum_authorization_digest;
	lengths[5] = sizeof(lease->quorum_authorization_digest);
	parts[6] = lease->previous_lease_digest;
	lengths[6] = sizeof(lease->previous_lease_digest);
	parts[7] = numeric;
	lengths[7] = offset;
	parts[8] = (const uint8_t *)&lease->occupied;
	lengths[8] = sizeof(lease->occupied);
	return pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 9U, digest);
}

int pqcp_sovereign_continuity_digest_fence(
	const struct pqcp_sovereign_fence *fence,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	uint8_t numeric[68];
	size_t offset = 0U;
	const uint8_t *parts[10];
	size_t lengths[10];

	if (fence == NULL || digest == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    fence->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    fence->resource_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    fence->holder_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    fence->lease_id)) {
		return -EINVAL;
	}
	pqcp_edge_internal_write_u32(
		numeric + offset, fence->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, fence->generation);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, (uint32_t)fence->state);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, fence->epoch);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, fence->acquired_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, fence->renewed_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, fence->expires_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, fence->released_at_ms);
	offset += 8U;
	parts[0] = fence_domain;
	lengths[0] = sizeof(fence_domain) - 1U;
	parts[1] = (const uint8_t *)fence->tenant_id;
	lengths[1] = strlen(fence->tenant_id);
	parts[2] = (const uint8_t *)fence->resource_id;
	lengths[2] = strlen(fence->resource_id);
	parts[3] = (const uint8_t *)fence->holder_id;
	lengths[3] = strlen(fence->holder_id);
	parts[4] = (const uint8_t *)fence->lease_id;
	lengths[4] = strlen(fence->lease_id);
	parts[5] = fence->holder_digest;
	lengths[5] = sizeof(fence->holder_digest);
	parts[6] = fence->authorization_digest;
	lengths[6] = sizeof(fence->authorization_digest);
	parts[7] = fence->previous_fence_digest;
	lengths[7] = sizeof(fence->previous_fence_digest);
	parts[8] = numeric;
	lengths[8] = offset;
	parts[9] = (const uint8_t *)&fence->occupied;
	lengths[9] = sizeof(fence->occupied);
	return pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 10U, digest);
}

int pqcp_sovereign_continuity_digest_plan(
	const struct pqcp_sovereign_recovery_plan *plan,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	uint8_t numeric[96];
	uint8_t step_numeric[
		PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS * 36U];
	size_t offset = 0U;
	size_t step_offset = 0U;
	const uint8_t *parts[10];
	size_t lengths[10];

	if (plan == NULL || digest == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    plan->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    plan->plan_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    plan->objective_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    plan->resource_id) ||
	    plan->step_count == 0U ||
	    plan->step_count >
		    PQCP_SOVEREIGN_CONTINUITY_MAX_STEPS) {
		return -EINVAL;
	}
#define WRITE_PLAN_U32(value) \
	do { \
		pqcp_edge_internal_write_u32(numeric + offset, (value)); \
		offset += 4U; \
	} while (false)
#define WRITE_PLAN_U64(value) \
	do { \
		pqcp_edge_internal_write_u64(numeric + offset, (value)); \
		offset += 8U; \
	} while (false)
	WRITE_PLAN_U32(plan->schema_version);
	WRITE_PLAN_U32(plan->generation);
	WRITE_PLAN_U32((uint32_t)plan->mode);
	WRITE_PLAN_U64(plan->created_at_ms);
	WRITE_PLAN_U64(plan->updated_at_ms);
	WRITE_PLAN_U64(plan->expires_at_ms);
	WRITE_PLAN_U64(plan->policy_epoch);
	WRITE_PLAN_U64(plan->revocation_epoch);
	WRITE_PLAN_U64(plan->maximum_duration_ms);
	WRITE_PLAN_U64(plan->point_maximum_age_ms);
	WRITE_PLAN_U32(plan->step_count);
	WRITE_PLAN_U32(plan->required_approval_count);
	WRITE_PLAN_U32(plan->required_operation_mask);
	WRITE_PLAN_U32(plan->active ? 1U : 0U);
#undef WRITE_PLAN_U32
#undef WRITE_PLAN_U64
	for (uint32_t index = 0U;
	     index < plan->step_count; ++index) {
		const struct pqcp_sovereign_recovery_step *step =
			&plan->steps[index];

		pqcp_edge_internal_write_u32(
			step_numeric + step_offset,
			step->step_id);
		step_offset += 4U;
		pqcp_edge_internal_write_u32(
			step_numeric + step_offset,
			(uint32_t)step->kind);
		step_offset += 4U;
		pqcp_edge_internal_write_u32(
			step_numeric + step_offset,
			step->dependency_mask);
		step_offset += 4U;
		pqcp_edge_internal_write_u32(
			step_numeric + step_offset,
			step->required_operation);
		step_offset += 4U;
		pqcp_edge_internal_write_u32(
			step_numeric + step_offset,
			step->maximum_attempts);
		step_offset += 4U;
		pqcp_edge_internal_write_u64(
			step_numeric + step_offset,
			step->timeout_ms);
		step_offset += 8U;
		pqcp_edge_internal_write_u64(
			step_numeric + step_offset,
			step->minimum_stable_ms);
		step_offset += 8U;
	}
	parts[0] = plan_domain;
	lengths[0] = sizeof(plan_domain) - 1U;
	parts[1] = (const uint8_t *)plan->tenant_id;
	lengths[1] = strlen(plan->tenant_id);
	parts[2] = (const uint8_t *)plan->plan_id;
	lengths[2] = strlen(plan->plan_id);
	parts[3] = (const uint8_t *)plan->objective_id;
	lengths[3] = strlen(plan->objective_id);
	parts[4] = (const uint8_t *)plan->resource_id;
	lengths[4] = strlen(plan->resource_id);
	parts[5] = numeric;
	lengths[5] = offset;
	parts[6] = step_numeric;
	lengths[6] = step_offset;
	parts[7] = (const uint8_t *)plan->topological_order;
	lengths[7] = plan->step_count;
	parts[8] = plan->policy_digest;
	lengths[8] = sizeof(plan->policy_digest);
	parts[9] = (const uint8_t *)plan->steps;
	lengths[9] = plan->step_count *
		     sizeof(plan->steps[0]);
	return pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 10U, digest);
}

int pqcp_sovereign_continuity_digest_run(
	const struct pqcp_sovereign_recovery_run *run,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	uint8_t numeric[148];
	size_t offset = 0U;
	const uint8_t *parts[12];
	size_t lengths[12];

	if (run == NULL || digest == NULL ||
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
		    run->lease_id)) {
		return -EINVAL;
	}
#define WRITE_RUN_U32(value) \
	do { \
		pqcp_edge_internal_write_u32(numeric + offset, (value)); \
		offset += 4U; \
	} while (false)
#define WRITE_RUN_U64(value) \
	do { \
		pqcp_edge_internal_write_u64(numeric + offset, (value)); \
		offset += 8U; \
	} while (false)
	WRITE_RUN_U32(run->schema_version);
	WRITE_RUN_U32(run->generation);
	WRITE_RUN_U64(run->run_id);
	WRITE_RUN_U32((uint32_t)run->mode);
	WRITE_RUN_U32((uint32_t)run->state);
	WRITE_RUN_U64(run->authorized_at_ms);
	WRITE_RUN_U64(run->started_at_ms);
	WRITE_RUN_U64(run->updated_at_ms);
	WRITE_RUN_U64(run->deadline_ms);
	WRITE_RUN_U64(run->completed_at_ms);
	WRITE_RUN_U64(run->policy_epoch);
	WRITE_RUN_U64(run->revocation_epoch);
	WRITE_RUN_U64(run->fencing_epoch);
	WRITE_RUN_U64(run->edge_recovery_id);
	WRITE_RUN_U32(run->current_order_index);
	WRITE_RUN_U32(run->completed_step_mask);
	WRITE_RUN_U32(run->failed_step_mask);
	WRITE_RUN_U32(run->attempt_mask);
	WRITE_RUN_U32(run->failure_count);
	WRITE_RUN_U32(run->fence_held ? 1U : 0U);
	WRITE_RUN_U32(run->edge_authorized ? 1U : 0U);
#undef WRITE_RUN_U32
#undef WRITE_RUN_U64
	parts[0] = run_domain;
	lengths[0] = sizeof(run_domain) - 1U;
	parts[1] = (const uint8_t *)run->tenant_id;
	lengths[1] = strlen(run->tenant_id);
	parts[2] = (const uint8_t *)run->plan_id;
	lengths[2] = strlen(run->plan_id);
	parts[3] = (const uint8_t *)run->objective_id;
	lengths[3] = strlen(run->objective_id);
	parts[4] = (const uint8_t *)run->resource_id;
	lengths[4] = strlen(run->resource_id);
	parts[5] = (const uint8_t *)run->principal_id;
	lengths[5] = strlen(run->principal_id);
	parts[6] = (const uint8_t *)run->lease_id;
	lengths[6] = strlen(run->lease_id);
	parts[7] = run->plan_digest;
	lengths[7] = sizeof(run->plan_digest);
	parts[8] = run->quorum_authorization_digest;
	lengths[8] = sizeof(run->quorum_authorization_digest);
	parts[9] = run->selected_point_digest;
	lengths[9] = sizeof(run->selected_point_digest);
	parts[10] = run->evidence_digest;
	lengths[10] = sizeof(run->evidence_digest);
	parts[11] = numeric;
	lengths[11] = offset;
	return pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 12U, digest);
}

int pqcp_sovereign_continuity_digest_event(
	const struct pqcp_sovereign_continuity_event *event,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	uint8_t numeric[80];
	size_t offset = 0U;
	const uint8_t *parts[7];
	size_t lengths[7];

	if (event == NULL || digest == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    event->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    event->subject_id)) {
		return -EINVAL;
	}
	pqcp_edge_internal_write_u32(
		numeric + offset, event->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, event->sequence);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, event->occurred_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, (uint32_t)event->type);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, (uint32_t)event->outcome);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, event->object_id);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, event->policy_epoch);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, event->revocation_epoch);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, event->fencing_epoch);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, (uint32_t)event->result);
	offset += 4U;
	parts[0] = event_domain;
	lengths[0] = sizeof(event_domain) - 1U;
	parts[1] = (const uint8_t *)event->tenant_id;
	lengths[1] = strlen(event->tenant_id);
	parts[2] = (const uint8_t *)event->subject_id;
	lengths[2] = strlen(event->subject_id);
	parts[3] = numeric;
	lengths[3] = offset;
	parts[4] = event->evidence_digest;
	lengths[4] = sizeof(event->evidence_digest);
	parts[5] = event->previous_digest;
	lengths[5] = sizeof(event->previous_digest);
	parts[6] = (const uint8_t *)&event->occupied;
	lengths[6] = sizeof(event->occupied);
	return pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 7U, digest);
}

static bool objective_tier_valid(
	enum pqcp_sovereign_objective_tier tier)
{
	return tier >= PQCP_SOVEREIGN_OBJECTIVE_TIER_STANDARD &&
	       tier <= PQCP_SOVEREIGN_OBJECTIVE_TIER_SAFETY;
}

static bool objective_status_valid(
	enum pqcp_sovereign_objective_status status)
{
	return status >=
		       PQCP_SOVEREIGN_OBJECTIVE_STATUS_COMPLIANT &&
	       status <=
		       PQCP_SOVEREIGN_OBJECTIVE_STATUS_SUSPENDED;
}

static int objective_index(
	const struct pqcp_sovereign_objective_registry *registry,
	const char *tenant_id,
	const char *objective_id)
{
	for (size_t index = 0U;
	     index < registry->capacity; ++index) {
		const struct pqcp_sovereign_continuity_objective *entry =
			&registry->objectives[index];

		if (entry->occupied &&
		    strcmp(entry->tenant_id, tenant_id) == 0 &&
		    strcmp(entry->objective_id, objective_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_objective_index(
	const struct pqcp_sovereign_objective_registry *registry)
{
	for (size_t index = 0U;
	     index < registry->capacity; ++index) {
		if (!registry->objectives[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int validate_objective(
	const struct pqcp_sovereign_continuity_objective *objective)
{
	if (objective == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    objective->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    objective->objective_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    objective->service_id) ||
	    !objective_tier_valid(objective->tier) ||
	    objective->recovery_point_objective_ms == 0U ||
	    objective->recovery_time_objective_ms == 0U ||
	    objective->minimum_replicas == 0U ||
	    objective->policy_epoch == 0U ||
	    objective->revocation_epoch == 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    objective->policy_digest) ||
	    (objective->satisfied_dependency_mask &
	     ~objective->dependency_mask) != 0U) {
		return -EINVAL;
	}
	if (objective->expires_at_ms != 0U &&
	    objective->expires_at_ms <=
		    objective->created_at_ms) {
		return -ERANGE;
	}
	return 0;
}

int pqcp_sovereign_objective_registry_init(
	struct pqcp_sovereign_objective_registry *registry,
	struct pqcp_sovereign_continuity_objective *objectives,
	size_t capacity)
{
	if (registry == NULL || objectives == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(objectives, 0,
	       capacity * sizeof(*objectives));
	registry->schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	registry->objectives = objectives;
	registry->capacity = capacity;
	registry->next_generation = 1U;
	k_mutex_init(&registry->lock);
	registry->initialized = true;
	return 0;
}

int pqcp_sovereign_objective_put(
	struct pqcp_sovereign_objective_registry *registry,
	const struct pqcp_sovereign_continuity_objective *objective)
{
	struct pqcp_sovereign_continuity_objective candidate;
	int index;
	int ret;

	if (registry == NULL || !registry->initialized) {
		return -EINVAL;
	}
	ret = validate_objective(objective);
	if (ret != 0) {
		return ret;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = objective_index(
		registry, objective->tenant_id,
		objective->objective_id);
	if (index == -ENOENT) {
		index = free_objective_index(registry);
	}
	if (index < 0) {
		ret = index;
		goto out;
	}
	if (registry->objectives[index].occupied &&
	    (objective->policy_epoch <
		     registry->objectives[index].policy_epoch ||
	     objective->revocation_epoch <
		     registry->objectives[index].revocation_epoch)) {
		ret = -ESTALE;
		goto out;
	}
	candidate = *objective;
	candidate.schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	candidate.generation =
		pqcp_edge_internal_next_generation(
			&registry->next_generation);
	candidate.status = candidate.suspended ?
		PQCP_SOVEREIGN_OBJECTIVE_STATUS_SUSPENDED :
		PQCP_SOVEREIGN_OBJECTIVE_STATUS_COMPLIANT;
	candidate.occupied = true;
	ret = pqcp_sovereign_continuity_digest_objective(
		&candidate, candidate.objective_digest);
	if (ret == 0) {
		registry->objectives[index] = candidate;
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_sovereign_objective_remove(
	struct pqcp_sovereign_objective_registry *registry,
	const char *tenant_id,
	const char *objective_id,
	uint32_t generation)
{
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(objective_id) ||
	    generation == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = objective_index(
		registry, tenant_id, objective_id);
	if (index < 0) {
		ret = index;
	} else if (registry->objectives[index].generation !=
		   generation) {
		ret = -ESTALE;
	} else {
		memset(&registry->objectives[index], 0,
		       sizeof(registry->objectives[index]));
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_sovereign_objective_get(
	struct pqcp_sovereign_objective_registry *registry,
	const char *tenant_id,
	const char *objective_id,
	struct pqcp_sovereign_continuity_objective *objective)
{
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(objective_id) ||
	    objective == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = objective_index(
		registry, tenant_id, objective_id);
	if (index < 0) {
		ret = index;
	} else {
		*objective = registry->objectives[index];
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_sovereign_objective_evaluate(
	const struct pqcp_sovereign_continuity_objective *objective,
	const struct pqcp_sovereign_continuity_observation *observation,
	struct pqcp_sovereign_objective_evaluation *evaluation)
{
	uint64_t data_age;
	uint64_t outage_duration;
	uint64_t unsatisfied;
	uint32_t missing_replicas;

	if (validate_objective(objective) != 0 ||
	    observation == NULL || evaluation == NULL ||
	    observation->observed_at_ms == 0U ||
	    observation->latest_protected_at_ms >
		    observation->observed_at_ms ||
	    observation->outage_started_at_ms >
		    observation->observed_at_ms ||
	    (observation->satisfied_dependency_mask &
	     ~objective->dependency_mask) != 0U) {
		return -EINVAL;
	}
	memset(evaluation, 0, sizeof(*evaluation));
	data_age = observation->latest_protected_at_ms == 0U ?
		UINT64_MAX :
		observation->observed_at_ms -
			observation->latest_protected_at_ms;
	outage_duration =
		observation->service_available ||
		observation->outage_started_at_ms == 0U ?
			0U :
			observation->observed_at_ms -
				observation->outage_started_at_ms;
	unsatisfied = objective->dependency_mask &
		      ~observation->satisfied_dependency_mask;
	missing_replicas =
		observation->available_replicas >=
				objective->minimum_replicas ?
			0U :
			objective->minimum_replicas -
				observation->available_replicas;
	evaluation->data_age_ms = data_age;
	evaluation->outage_duration_ms = outage_duration;
	evaluation->rpo_remaining_ms =
		data_age >= objective->recovery_point_objective_ms ?
			0U :
			objective->recovery_point_objective_ms -
				data_age;
	evaluation->rto_remaining_ms =
		outage_duration >=
				objective->recovery_time_objective_ms ?
			0U :
			objective->recovery_time_objective_ms -
				outage_duration;
	evaluation->unsatisfied_dependency_mask = unsatisfied;
	evaluation->missing_replicas = missing_replicas;
	evaluation->rpo_met =
		data_age <= objective->recovery_point_objective_ms &&
		observation->unprotected_bytes <=
			objective->maximum_data_loss_bytes;
	evaluation->rto_met =
		outage_duration <=
			objective->recovery_time_objective_ms;
	evaluation->dependencies_met = unsatisfied == 0U;
	evaluation->replicas_met = missing_replicas == 0U;
	if (objective->suspended) {
		evaluation->status =
			PQCP_SOVEREIGN_OBJECTIVE_STATUS_SUSPENDED;
	} else if ((!evaluation->rpo_met &&
		    !evaluation->rto_met) ||
		   !evaluation->dependencies_met ||
		   !evaluation->replicas_met) {
		evaluation->status =
			PQCP_SOVEREIGN_OBJECTIVE_STATUS_BREACHED;
	} else if (!evaluation->rpo_met) {
		evaluation->status =
			PQCP_SOVEREIGN_OBJECTIVE_STATUS_RPO_AT_RISK;
	} else if (!evaluation->rto_met) {
		evaluation->status =
			PQCP_SOVEREIGN_OBJECTIVE_STATUS_RTO_AT_RISK;
	} else {
		evaluation->status =
			PQCP_SOVEREIGN_OBJECTIVE_STATUS_COMPLIANT;
	}
	return 0;
}

int pqcp_sovereign_objective_observe(
	struct pqcp_sovereign_objective_registry *registry,
	const char *tenant_id,
	const char *objective_id,
	const struct pqcp_sovereign_continuity_observation *observation,
	struct pqcp_sovereign_objective_evaluation *evaluation)
{
	struct pqcp_sovereign_continuity_objective candidate;
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(objective_id) ||
	    observation == NULL || evaluation == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = objective_index(
		registry, tenant_id, objective_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	candidate = registry->objectives[index];
	if (candidate.expires_at_ms != 0U &&
	    candidate.expires_at_ms <=
		    observation->observed_at_ms) {
		ret = -ETIMEDOUT;
		goto out;
	}
	ret = pqcp_sovereign_objective_evaluate(
		&candidate, observation, evaluation);
	if (ret != 0) {
		goto out;
	}
	candidate.status = evaluation->status;
	candidate.latest_protected_at_ms =
		observation->latest_protected_at_ms;
	candidate.outage_started_at_ms =
		observation->outage_started_at_ms;
	candidate.last_evaluated_at_ms =
		observation->observed_at_ms;
	candidate.updated_at_ms =
		observation->observed_at_ms;
	candidate.available_replicas =
		observation->available_replicas;
	candidate.satisfied_dependency_mask =
		observation->satisfied_dependency_mask;
	if (evaluation->status ==
	    PQCP_SOVEREIGN_OBJECTIVE_STATUS_BREACHED) {
		candidate.breach_count =
			pqcp_edge_internal_saturating_add_u32(
				candidate.breach_count, 1U);
		registry->breach_count =
			pqcp_sovereign_continuity_add_u64(
				registry->breach_count, 1U);
	}
	ret = pqcp_sovereign_continuity_digest_objective(
		&candidate, candidate.objective_digest);
	if (ret == 0) {
		registry->objectives[index] = candidate;
		registry->evaluation_count =
			pqcp_sovereign_continuity_add_u64(
				registry->evaluation_count, 1U);
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_sovereign_objective_sync_edge(
	struct pqcp_sovereign_objective_registry *registry,
	const char *tenant_id,
	const char *objective_id,
	struct pqcp_edge_continuity_manager *manager)
{
	struct pqcp_sovereign_continuity_objective objective;
	struct pqcp_edge_continuity_service service;
	int ret;

	if (manager == NULL || !manager->initialized) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_objective_get(
		registry, tenant_id, objective_id, &objective);
	if (ret != 0) {
		return ret;
	}
	memset(&service, 0, sizeof(service));
	ret = pqcp_edge_internal_copy_text(
		service.service_id, sizeof(service.service_id),
		objective.service_id);
	if (ret != 0) {
		return ret;
	}
	service.mode = objective.status ==
			       PQCP_SOVEREIGN_OBJECTIVE_STATUS_BREACHED ?
		PQCP_EDGE_CONTINUITY_RECOVERY :
		PQCP_EDGE_CONTINUITY_NORMAL;
	service.entered_at_ms = objective.updated_at_ms;
	service.maximum_duration_ms =
		objective.recovery_time_objective_ms;
	service.minimum_endpoints =
		objective.minimum_replicas;
	service.available_endpoints =
		objective.available_replicas;
	service.priority = objective.priority;
	service.dependency_mask =
		objective.dependency_mask;
	service.satisfied_dependencies =
		objective.satisfied_dependency_mask;
	service.occupied = true;
	ret = pqcp_edge_continuity_register(
		manager, &service);
	if (ret != 0) {
		return ret;
	}
	return pqcp_edge_continuity_observe(
		manager, service.service_id,
		service.available_endpoints,
		service.satisfied_dependencies,
		objective.updated_at_ms);
}

int pqcp_sovereign_objective_registry_audit(
	struct pqcp_sovereign_objective_registry *registry)
{
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    registry->schema_version !=
		    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
	    registry->objectives == NULL ||
	    registry->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < registry->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_continuity_objective *entry =
			&registry->objectives[index];

		if (!entry->occupied) {
			continue;
		}
		if (entry->schema_version !=
			    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
		    entry->generation == 0U ||
		    validate_objective(entry) != 0 ||
		    !objective_status_valid(entry->status) ||
		    !pqcp_sovereign_continuity_digest_valid(
			    entry->objective_digest)) {
			ret = -EBADMSG;
			break;
		}
		ret = pqcp_sovereign_continuity_digest_objective(
			entry, digest);
		if (ret == 0 &&
		    !pqcp_sovereign_continuity_digest_equal(
			    digest, entry->objective_digest)) {
			ret = -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < registry->capacity && ret == 0;
		     ++other) {
			const struct pqcp_sovereign_continuity_objective
				*peer = &registry->objectives[other];

			if (peer->occupied &&
			    strcmp(entry->tenant_id,
				   peer->tenant_id) == 0 &&
			    strcmp(entry->objective_id,
				   peer->objective_id) == 0) {
				ret = -EEXIST;
			}
		}
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}
