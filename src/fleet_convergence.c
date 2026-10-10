/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free dependency-aware fleet convergence orchestration.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_convergence.h>

#include "fleet_internal.h"

#define PLAN_CHAIN_BYTES 768U
#define LEASE_TOKEN_BYTES 192U
#define SNAPSHOT_DIGEST_BYTES 192U
#define UNASSIGNED_WAVE UINT32_MAX

struct convergence_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

static bool digest_zero(
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static bool digest_equal(
	const uint8_t left[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t difference = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static bool text_valid(const char *text, size_t capacity)
{
	size_t length;

	if (text == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(text, capacity);
	return length > 0U && length < capacity;
}

static bool size_array_valid(size_t count, size_t element_size)
{
	return element_size != 0U && count <= SIZE_MAX / element_size;
}

static bool action_valid(enum pqcp_fleet_convergence_action action)
{
	return action > PQCP_FLEET_CONVERGENCE_ACTION_NONE &&
	       action < PQCP_FLEET_CONVERGENCE_ACTION_COUNT;
}

static bool plan_state_valid(enum pqcp_fleet_plan_state state)
{
	return state >= PQCP_FLEET_PLAN_EMPTY &&
	       state <= PQCP_FLEET_PLAN_CANCELLED;
}

static bool step_state_valid(enum pqcp_fleet_step_state state)
{
	return state >= PQCP_FLEET_STEP_EMPTY &&
	       state <= PQCP_FLEET_STEP_CANCELLED;
}

static bool dependency_kind_valid(
	enum pqcp_fleet_dependency_kind kind)
{
	return kind >= PQCP_FLEET_DEPENDENCY_HARD &&
	       kind <= PQCP_FLEET_DEPENDENCY_WAVE_GATE;
}

static bool failure_disposition_valid(
	enum pqcp_fleet_failure_disposition disposition)
{
	return disposition >= PQCP_FLEET_FAILURE_TERMINAL &&
	       disposition <= PQCP_FLEET_FAILURE_SUPERSEDE;
}

static bool terminal_step_state(enum pqcp_fleet_step_state state)
{
	return state == PQCP_FLEET_STEP_SUCCEEDED ||
	       state == PQCP_FLEET_STEP_FAILED ||
	       state == PQCP_FLEET_STEP_BLOCKED ||
	       state == PQCP_FLEET_STEP_SUPERSEDED ||
	       state == PQCP_FLEET_STEP_ROLLED_BACK ||
	       state == PQCP_FLEET_STEP_CANCELLED;
}

static bool active_step_state(enum pqcp_fleet_step_state state)
{
	return state == PQCP_FLEET_STEP_LEASED ||
	       state == PQCP_FLEET_STEP_APPLYING ||
	       state == PQCP_FLEET_STEP_AWAITING_ACK;
}

static bool plan_terminal(enum pqcp_fleet_plan_state state)
{
	return state == PQCP_FLEET_PLAN_SUCCEEDED ||
	       state == PQCP_FLEET_PLAN_FAILED ||
	       state == PQCP_FLEET_PLAN_SUPERSEDED ||
	       state == PQCP_FLEET_PLAN_CANCELLED;
}

static int add_u64(uint64_t left, uint64_t right, uint64_t *result)
{
	if (result == NULL || UINT64_MAX - left < right) {
		return -EOVERFLOW;
	}
	*result = left + right;
	return 0;
}

static void writer_init(
	struct convergence_writer *writer,
	uint8_t *buffer,
	size_t capacity)
{
	writer->buffer = buffer;
	writer->capacity = capacity;
	writer->offset = 0U;
	writer->error = 0;
}

static void writer_bytes(
	struct convergence_writer *writer,
	const uint8_t *value,
	size_t length)
{
	if (writer->error != 0) {
		return;
	}
	if ((value == NULL && length != 0U) ||
	    length > writer->capacity - writer->offset) {
		writer->error = -EOVERFLOW;
		return;
	}
	if (length != 0U) {
		memcpy(writer->buffer + writer->offset, value, length);
		writer->offset += length;
	}
}

static void writer_u8(
	struct convergence_writer *writer,
	uint8_t value)
{
	writer_bytes(writer, &value, sizeof(value));
}

static void writer_u32(
	struct convergence_writer *writer,
	uint32_t value)
{
	uint8_t encoded[4];

	encoded[0] = (uint8_t)(value >> 24);
	encoded[1] = (uint8_t)(value >> 16);
	encoded[2] = (uint8_t)(value >> 8);
	encoded[3] = (uint8_t)value;
	writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_i32(
	struct convergence_writer *writer,
	int32_t value)
{
	writer_u32(writer, (uint32_t)value);
}

static void writer_u64(
	struct convergence_writer *writer,
	uint64_t value)
{
	uint8_t encoded[8];

	for (size_t index = 0U; index < sizeof(encoded); ++index) {
		encoded[sizeof(encoded) - 1U - index] =
			(uint8_t)(value >> (index * 8U));
	}
	writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_bool(
	struct convergence_writer *writer,
	bool value)
{
	writer_u8(writer, value ? 1U : 0U);
}

static void writer_text(
	struct convergence_writer *writer,
	const char *value,
	size_t capacity)
{
	size_t length = strnlen(value, capacity);

	writer_u32(writer, (uint32_t)length);
	writer_bytes(writer, (const uint8_t *)value, length);
}

static int retry_policy_validate(
	const struct pqcp_fleet_retry_policy *policy)
{
	if (policy == NULL || policy->maximum_attempts == 0U ||
	    policy->initial_backoff_ms == 0U ||
	    policy->maximum_backoff_ms <
		    policy->initial_backoff_ms ||
	    policy->multiplier_numerator == 0U ||
	    policy->multiplier_denominator == 0U ||
	    policy->multiplier_numerator <
		    policy->multiplier_denominator ||
	    policy->jitter_basis_points > 10000U) {
		return -EINVAL;
	}
	return 0;
}

static int convergence_policy_validate(
	const struct pqcp_fleet_convergence_policy *policy)
{
	const uint32_t known_flags =
		PQCP_FLEET_PLAN_SECURITY_FIRST |
		PQCP_FLEET_PLAN_STOP_ON_FAILURE |
		PQCP_FLEET_PLAN_AUTO_ROLLBACK |
		PQCP_FLEET_PLAN_REQUIRE_LEASE |
		PQCP_FLEET_PLAN_ALLOW_PARALLEL |
		PQCP_FLEET_PLAN_BLOCK_ON_CONFLICT;

	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION ||
	    (policy->plan_flags & ~known_flags) != 0U ||
	    policy->maximum_parallel_steps == 0U ||
	    policy->maximum_wave_size == 0U ||
	    policy->plan_lease_ms == 0U ||
	    policy->step_lease_ms == 0U ||
	    policy->acknowledgement_timeout_ms == 0U ||
	    policy->plan_deadline_ms == 0U ||
	    retry_policy_validate(&policy->default_retry) != 0 ||
	    retry_policy_validate(&policy->security_retry) != 0) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_fleet_convergence_policy_default(
	struct pqcp_fleet_convergence_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version =
		PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION;
	policy->plan_flags =
		PQCP_FLEET_PLAN_SECURITY_FIRST |
		PQCP_FLEET_PLAN_STOP_ON_FAILURE |
		PQCP_FLEET_PLAN_AUTO_ROLLBACK |
		PQCP_FLEET_PLAN_REQUIRE_LEASE |
		PQCP_FLEET_PLAN_ALLOW_PARALLEL |
		PQCP_FLEET_PLAN_BLOCK_ON_CONFLICT;
	policy->maximum_parallel_steps = 4U;
	policy->maximum_wave_size = 8U;
	policy->plan_lease_ms = 60000U;
	policy->step_lease_ms = 30000U;
	policy->acknowledgement_timeout_ms = 120000U;
	policy->plan_deadline_ms = 3600000U;
	policy->default_retry.maximum_attempts = 5U;
	policy->default_retry.initial_backoff_ms = 1000U;
	policy->default_retry.maximum_backoff_ms = 60000U;
	policy->default_retry.multiplier_numerator = 2U;
	policy->default_retry.multiplier_denominator = 1U;
	policy->default_retry.jitter_basis_points = 1000U;
	policy->security_retry.maximum_attempts = 8U;
	policy->security_retry.initial_backoff_ms = 250U;
	policy->security_retry.maximum_backoff_ms = 30000U;
	policy->security_retry.multiplier_numerator = 2U;
	policy->security_retry.multiplier_denominator = 1U;
	policy->security_retry.jitter_basis_points = 500U;
	return 0;
}

static int storage_validate(
	const struct pqcp_fleet_convergence_storage *storage)
{
	if (storage == NULL ||
	    storage->drift == NULL ||
	    storage->drift_capacity == 0U ||
	    storage->steps == NULL ||
	    storage->step_capacity == 0U ||
	    storage->dependencies == NULL ||
	    storage->dependency_capacity == 0U ||
	    storage->waves == NULL ||
	    storage->wave_capacity == 0U ||
	    storage->desired_snapshot == NULL ||
	    storage->desired_snapshot_capacity == 0U ||
	    storage->observed_snapshot == NULL ||
	    storage->observed_snapshot_capacity == 0U ||
	    !size_array_valid(
		    storage->drift_capacity,
		    sizeof(*storage->drift)) ||
	    !size_array_valid(
		    storage->step_capacity,
		    sizeof(*storage->steps)) ||
	    !size_array_valid(
		    storage->dependency_capacity,
		    sizeof(*storage->dependencies)) ||
	    !size_array_valid(
		    storage->wave_capacity,
		    sizeof(*storage->waves)) ||
	    !size_array_valid(
		    storage->desired_snapshot_capacity,
		    sizeof(*storage->desired_snapshot)) ||
	    !size_array_valid(
		    storage->observed_snapshot_capacity,
		    sizeof(*storage->observed_snapshot))) {
		return -EINVAL;
	}
	if (storage->desired_snapshot_capacity <
		    storage->drift_capacity ||
	    storage->observed_snapshot_capacity <
		    storage->drift_capacity) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_fleet_convergence_init(
	struct pqcp_fleet_convergence *convergence,
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_convergence_storage *storage,
	const struct pqcp_fleet_convergence_policy *policy)
{
	struct pqcp_fleet_convergence_policy effective;
	int ret;

	if (convergence == NULL || model == NULL ||
	    !model->initialized || storage_validate(storage) != 0) {
		return -EINVAL;
	}
	if (policy == NULL) {
		ret = pqcp_fleet_convergence_policy_default(&effective);
		if (ret != 0) {
			return ret;
		}
		policy = &effective;
	}
	if (convergence_policy_validate(policy) != 0) {
		return -EINVAL;
	}
	memset(convergence, 0, sizeof(*convergence));
	memset(storage->drift, 0,
	       storage->drift_capacity * sizeof(*storage->drift));
	memset(storage->steps, 0,
	       storage->step_capacity * sizeof(*storage->steps));
	memset(storage->dependencies, 0,
	       storage->dependency_capacity *
		       sizeof(*storage->dependencies));
	memset(storage->waves, 0,
	       storage->wave_capacity * sizeof(*storage->waves));
	memset(storage->desired_snapshot, 0,
	       storage->desired_snapshot_capacity *
		       sizeof(*storage->desired_snapshot));
	memset(storage->observed_snapshot, 0,
	       storage->observed_snapshot_capacity *
		       sizeof(*storage->observed_snapshot));
	convergence->schema_version =
		PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION;
	convergence->model = model;
	convergence->policy = *policy;
	convergence->drift = storage->drift;
	convergence->drift_capacity = storage->drift_capacity;
	convergence->desired_resources =
		storage->desired_snapshot;
	convergence->desired_resource_capacity =
		storage->desired_snapshot_capacity;
	convergence->observed_resources =
		storage->observed_snapshot;
	convergence->observed_resource_capacity =
		storage->observed_snapshot_capacity;
	convergence->plan.schema_version =
		PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION;
	convergence->plan.steps = storage->steps;
	convergence->plan.step_capacity =
		storage->step_capacity;
	convergence->plan.dependencies =
		storage->dependencies;
	convergence->plan.dependency_capacity =
		storage->dependency_capacity;
	convergence->plan.waves = storage->waves;
	convergence->plan.wave_capacity =
		storage->wave_capacity;
	convergence->next_plan_id = 1U;
	convergence->next_lease_id = 1U;
	k_mutex_init(&convergence->lock);
	convergence->initialized = true;
	return 0;
}

static struct pqcp_fleet_plan_step *step_by_id(
	struct pqcp_fleet_convergence_plan *plan,
	uint32_t step_id)
{
	if (plan == NULL || step_id == 0U) {
		return NULL;
	}
	for (size_t index = 0U; index < plan->step_count; ++index) {
		if (plan->steps[index].occupied &&
		    plan->steps[index].step_id == step_id) {
			return &plan->steps[index];
		}
	}
	return NULL;
}

static const struct pqcp_fleet_plan_step *const_step_by_id(
	const struct pqcp_fleet_convergence_plan *plan,
	uint32_t step_id)
{
	if (plan == NULL || step_id == 0U) {
		return NULL;
	}
	for (size_t index = 0U; index < plan->step_count; ++index) {
		if (plan->steps[index].occupied &&
		    plan->steps[index].step_id == step_id) {
			return &plan->steps[index];
		}
	}
	return NULL;
}

static const struct pqcp_fleet_resource_state *snapshot_resource(
	const struct pqcp_fleet_state_snapshot *snapshot,
	const struct pqcp_fleet_resource_key *key)
{
	const struct pqcp_fleet_resource_state *resource = NULL;

	if (snapshot == NULL || key == NULL) {
		return NULL;
	}
	if (pqcp_fleet_snapshot_find(snapshot, key, &resource) != 0) {
		return NULL;
	}
	return resource;
}

static uint32_t action_priority(
	enum pqcp_fleet_convergence_action action)
{
	switch (action) {
	case PQCP_FLEET_CONVERGENCE_DECOMMISSION:
		return 0U;
	case PQCP_FLEET_CONVERGENCE_APPLY_REVOCATION:
		return 10U;
	case PQCP_FLEET_CONVERGENCE_QUARANTINE:
		return 12U;
	case PQCP_FLEET_CONVERGENCE_ENTER_RECOVERY:
		return 20U;
	case PQCP_FLEET_CONVERGENCE_ADVANCE_RECOVERY:
		return 22U;
	case PQCP_FLEET_CONVERGENCE_RESTRICT_IDENTITY:
		return 30U;
	case PQCP_FLEET_CONVERGENCE_INSTALL_IDENTITY:
	case PQCP_FLEET_CONVERGENCE_ROTATE_IDENTITY:
		return 40U;
	case PQCP_FLEET_CONVERGENCE_RESTRICT_POLICY:
		return 45U;
	case PQCP_FLEET_CONVERGENCE_APPLY_POLICY:
		return 50U;
	case PQCP_FLEET_CONVERGENCE_ROLLBACK_FIRMWARE:
		return 60U;
	case PQCP_FLEET_CONVERGENCE_STAGE_FIRMWARE:
		return 70U;
	case PQCP_FLEET_CONVERGENCE_ACTIVATE_FIRMWARE:
		return 75U;
	case PQCP_FLEET_CONVERGENCE_VERIFY_FIRMWARE:
		return 80U;
	case PQCP_FLEET_CONVERGENCE_CLOSE_CHANNEL:
		return 85U;
	case PQCP_FLEET_CONVERGENCE_REKEY_CHANNEL:
	case PQCP_FLEET_CONVERGENCE_ESTABLISH_CHANNEL:
		return 90U;
	case PQCP_FLEET_CONVERGENCE_EXIT_RECOVERY:
		return 95U;
	case PQCP_FLEET_CONVERGENCE_WAIT_BARRIER:
		return 98U;
	case PQCP_FLEET_CONVERGENCE_VERIFY_STATE:
		return 100U;
	default:
		return UINT32_MAX;
	}
}

static uint32_t action_flags(
	enum pqcp_fleet_convergence_action action,
	const struct pqcp_fleet_drift *drift)
{
	uint32_t flags =
		PQCP_FLEET_STEP_REQUIRE_ACK |
		PQCP_FLEET_STEP_ALLOW_RETRY |
		PQCP_FLEET_STEP_BATCHABLE;

	if (drift != NULL && drift->security_critical) {
		flags |= PQCP_FLEET_STEP_SECURITY_CRITICAL;
	}
	switch (action) {
	case PQCP_FLEET_CONVERGENCE_DECOMMISSION:
	case PQCP_FLEET_CONVERGENCE_APPLY_REVOCATION:
	case PQCP_FLEET_CONVERGENCE_RESTRICT_IDENTITY:
	case PQCP_FLEET_CONVERGENCE_RESTRICT_POLICY:
		flags |=
			PQCP_FLEET_STEP_SECURITY_CRITICAL |
			PQCP_FLEET_STEP_IRREVERSIBLE |
			PQCP_FLEET_STEP_BARRIER;
		flags &= ~PQCP_FLEET_STEP_ALLOW_ROLLBACK;
		break;
	case PQCP_FLEET_CONVERGENCE_QUARANTINE:
	case PQCP_FLEET_CONVERGENCE_ENTER_RECOVERY:
		flags |=
			PQCP_FLEET_STEP_SECURITY_CRITICAL |
			PQCP_FLEET_STEP_BARRIER;
		break;
	case PQCP_FLEET_CONVERGENCE_INSTALL_IDENTITY:
	case PQCP_FLEET_CONVERGENCE_ROTATE_IDENTITY:
	case PQCP_FLEET_CONVERGENCE_APPLY_POLICY:
		flags |= PQCP_FLEET_STEP_BARRIER;
		break;
	case PQCP_FLEET_CONVERGENCE_STAGE_FIRMWARE:
		flags |=
			PQCP_FLEET_STEP_ALLOW_ROLLBACK |
			PQCP_FLEET_STEP_OFFLINE_SAFE;
		break;
	case PQCP_FLEET_CONVERGENCE_ACTIVATE_FIRMWARE:
	case PQCP_FLEET_CONVERGENCE_ROLLBACK_FIRMWARE:
		flags |=
			PQCP_FLEET_STEP_ALLOW_ROLLBACK |
			PQCP_FLEET_STEP_DISRUPTIVE;
		break;
	case PQCP_FLEET_CONVERGENCE_ESTABLISH_CHANNEL:
	case PQCP_FLEET_CONVERGENCE_REKEY_CHANNEL:
	case PQCP_FLEET_CONVERGENCE_CLOSE_CHANNEL:
		flags |= PQCP_FLEET_STEP_ALLOW_ROLLBACK;
		break;
	case PQCP_FLEET_CONVERGENCE_WAIT_BARRIER:
		flags =
			PQCP_FLEET_STEP_SECURITY_CRITICAL |
			PQCP_FLEET_STEP_BARRIER;
		break;
	case PQCP_FLEET_CONVERGENCE_VERIFY_FIRMWARE:
	case PQCP_FLEET_CONVERGENCE_VERIFY_STATE:
		flags &= ~PQCP_FLEET_STEP_ALLOW_ROLLBACK;
		break;
	default:
		break;
	}
	return flags;
}

static const struct pqcp_fleet_retry_policy *retry_for_step(
	const struct pqcp_fleet_convergence *convergence,
	const struct pqcp_fleet_plan_step *step)
{
	return (step->flags & PQCP_FLEET_STEP_SECURITY_CRITICAL) != 0U ?
		&convergence->policy.security_retry :
		&convergence->policy.default_retry;
}

static int append_step(
	struct pqcp_fleet_convergence *convergence,
	const struct pqcp_fleet_drift *drift,
	const struct pqcp_fleet_resource_state *desired,
	enum pqcp_fleet_convergence_action action,
	uint32_t *step_id)
{
	struct pqcp_fleet_convergence_plan *plan =
		&convergence->plan;
	struct pqcp_fleet_plan_step *step;
	const struct pqcp_fleet_retry_policy *retry;
	uint32_t identifier;

	if (drift == NULL || !action_valid(action) ||
	    step_id == NULL ||
	    plan->step_count >= plan->step_capacity ||
	    plan->step_count >= UINT32_MAX) {
		return -ENOSPC;
	}
	identifier = (uint32_t)plan->step_count + 1U;
	step = &plan->steps[plan->step_count];
	memset(step, 0, sizeof(*step));
	step->schema_version =
		PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION;
	step->step_id = identifier;
	step->key = drift->key;
	step->action = action;
	step->state =
		action == PQCP_FLEET_CONVERGENCE_WAIT_BARRIER ?
			PQCP_FLEET_STEP_BLOCKED :
			PQCP_FLEET_STEP_PENDING;
	step->drift_class = drift->classification;
	step->drift_reason_mask = drift->reason_mask;
	step->flags = action_flags(action, drift);
	step->priority = action_priority(action);
	step->wave = UNASSIGNED_WAVE;
	step->desired_generation = drift->desired_generation;
	step->desired_epoch = drift->desired_epoch;
	step->plan_generation = plan->generation;
	if (desired != NULL) {
		memcpy(step->desired_digest, desired->digest,
		       sizeof(step->desired_digest));
		step->rollback_barrier_generation =
			desired->generation;
	} else {
		memcpy(step->desired_digest, drift->desired_digest,
		       sizeof(step->desired_digest));
	}
	memcpy(step->observed_digest, drift->observed_digest,
	       sizeof(step->observed_digest));
	retry = retry_for_step(convergence, step);
	step->maximum_attempts = retry->maximum_attempts;
	step->occupied = true;
	plan->step_count++;
	if (step->state == PQCP_FLEET_STEP_BLOCKED) {
		plan->blocked_steps++;
	}
	*step_id = identifier;
	return 0;
}

static bool dependency_exists(
	const struct pqcp_fleet_convergence_plan *plan,
	uint32_t predecessor,
	uint32_t successor)
{
	for (size_t index = 0U;
	     index < plan->dependency_count; ++index) {
		const struct pqcp_fleet_plan_dependency *dependency =
			&plan->dependencies[index];

		if (dependency->predecessor_step_id == predecessor &&
		    dependency->successor_step_id == successor) {
			return true;
		}
	}
	return false;
}

static int append_dependency(
	struct pqcp_fleet_convergence_plan *plan,
	uint32_t predecessor,
	uint32_t successor,
	enum pqcp_fleet_dependency_kind kind)
{
	struct pqcp_fleet_plan_dependency *dependency;

	if (plan == NULL || predecessor == 0U || successor == 0U ||
	    predecessor == successor || !dependency_kind_valid(kind) ||
	    const_step_by_id(plan, predecessor) == NULL ||
	    const_step_by_id(plan, successor) == NULL) {
		return -EINVAL;
	}
	if (dependency_exists(plan, predecessor, successor)) {
		return 0;
	}
	if (plan->dependency_count >= plan->dependency_capacity) {
		return -ENOSPC;
	}
	dependency =
		&plan->dependencies[plan->dependency_count++];
	memset(dependency, 0, sizeof(*dependency));
	dependency->predecessor_step_id = predecessor;
	dependency->successor_step_id = successor;
	dependency->kind = kind;
	return 0;
}

static bool desired_identity_restrictive(
	const struct pqcp_fleet_resource_state *desired,
	const struct pqcp_fleet_resource_state *observed)
{
	if (desired == NULL ||
	    desired->key.kind != PQCP_FLEET_RESOURCE_IDENTITY) {
		return false;
	}
	if (desired->value.identity.device_state ==
		    PQCP_FLEET_DEVICE_REVOKED ||
	    desired->value.identity.device_state ==
		    PQCP_FLEET_DEVICE_DECOMMISSIONED) {
		return true;
	}
	if (observed != NULL &&
	    (observed->value.identity.capabilities &
	     ~desired->value.identity.capabilities) != 0U) {
		return true;
	}
	return false;
}

static bool desired_policy_restrictive(
	const struct pqcp_fleet_resource_state *desired,
	const struct pqcp_fleet_resource_state *observed)
{
	if (desired == NULL ||
	    desired->key.kind != PQCP_FLEET_RESOURCE_POLICY) {
		return false;
	}
	if ((desired->value.policy.flags &
	     (PQCP_FLEET_POLICY_LOCKDOWN |
	      PQCP_FLEET_POLICY_RECOVERY_ONLY)) != 0U) {
		return true;
	}
	if (observed != NULL &&
	    desired->value.policy.minimum_security_level >
		    observed->value.policy.minimum_security_level) {
		return true;
	}
	return false;
}

static int actions_for_drift(
	struct pqcp_fleet_convergence *convergence,
	const struct pqcp_fleet_drift *drift,
	const struct pqcp_fleet_state_snapshot *desired_snapshot,
	const struct pqcp_fleet_state_snapshot *observed_snapshot,
	uint32_t *first_step,
	uint32_t *last_step)
{
	const struct pqcp_fleet_resource_state *desired =
		snapshot_resource(desired_snapshot, &drift->key);
	const struct pqcp_fleet_resource_state *observed =
		snapshot_resource(observed_snapshot, &drift->key);
	enum pqcp_fleet_convergence_action actions[4];
	size_t action_count = 0U;
	uint32_t previous = 0U;
	int ret;

	if (drift->classification == PQCP_FLEET_DRIFT_NONE) {
		return -EINVAL;
	}
	if (drift->classification == PQCP_FLEET_DRIFT_BLOCKED ||
	    drift->classification ==
		    PQCP_FLEET_DRIFT_DIGEST_CONFLICT ||
	    drift->classification ==
		    PQCP_FLEET_DRIFT_OWNERSHIP_CONFLICT) {
		actions[action_count++] =
			PQCP_FLEET_CONVERGENCE_WAIT_BARRIER;
	} else if (drift->classification ==
		   PQCP_FLEET_DRIFT_DESIRED_MISSING) {
		switch (drift->key.kind) {
		case PQCP_FLEET_RESOURCE_CHANNEL:
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_CLOSE_CHANNEL;
			break;
		case PQCP_FLEET_RESOURCE_FIRMWARE:
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_VERIFY_STATE;
			break;
		default:
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_VERIFY_STATE;
			break;
		}
	} else {
		switch (drift->key.kind) {
		case PQCP_FLEET_RESOURCE_IDENTITY:
			if (desired != NULL &&
			    desired->value.identity.device_state ==
				    PQCP_FLEET_DEVICE_DECOMMISSIONED) {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_DECOMMISSION;
			} else if (desired_identity_restrictive(
					   desired, observed)) {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_RESTRICT_IDENTITY;
			} else if (observed == NULL) {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_INSTALL_IDENTITY;
			} else {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_ROTATE_IDENTITY;
			}
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_VERIFY_STATE;
			break;
		case PQCP_FLEET_RESOURCE_POLICY:
			actions[action_count++] =
				desired_policy_restrictive(desired, observed) ?
					PQCP_FLEET_CONVERGENCE_RESTRICT_POLICY :
					PQCP_FLEET_CONVERGENCE_APPLY_POLICY;
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_VERIFY_STATE;
			break;
		case PQCP_FLEET_RESOURCE_REVOCATION:
			if (desired != NULL &&
			    desired->value.revocation.quarantine) {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_QUARANTINE;
			}
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_APPLY_REVOCATION;
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_VERIFY_STATE;
			break;
		case PQCP_FLEET_RESOURCE_FIRMWARE:
			if (drift->requires_rollback) {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_ROLLBACK_FIRMWARE;
			} else {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_STAGE_FIRMWARE;
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_ACTIVATE_FIRMWARE;
			}
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_VERIFY_FIRMWARE;
			break;
		case PQCP_FLEET_RESOURCE_CHANNEL:
			if (desired != NULL &&
			    !desired->value.channel.online) {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_CLOSE_CHANNEL;
			} else if (observed == NULL ||
				   !observed->value.channel.online) {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_ESTABLISH_CHANNEL;
			} else {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_REKEY_CHANNEL;
			}
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_VERIFY_STATE;
			break;
		case PQCP_FLEET_RESOURCE_RECOVERY:
			if (desired != NULL &&
			    desired->value.recovery.state ==
				    PQCP_FLEET_RECOVERY_COMPLETE) {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_EXIT_RECOVERY;
			} else if (observed == NULL ||
				   observed->value.recovery.state ==
					   PQCP_FLEET_RECOVERY_IDLE) {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_ENTER_RECOVERY;
			} else {
				actions[action_count++] =
					PQCP_FLEET_CONVERGENCE_ADVANCE_RECOVERY;
			}
			actions[action_count++] =
				PQCP_FLEET_CONVERGENCE_VERIFY_STATE;
			break;
		default:
			return -EINVAL;
		}
	}
	for (size_t index = 0U; index < action_count; ++index) {
		uint32_t current;

		ret = append_step(
			convergence, drift, desired,
			actions[index], &current);
		if (ret != 0) {
			return ret;
		}
		if (index == 0U) {
			*first_step = current;
		}
		if (previous != 0U) {
			ret = append_dependency(
				&convergence->plan, previous, current,
				PQCP_FLEET_DEPENDENCY_HARD);
			if (ret != 0) {
				return ret;
			}
		}
		previous = current;
	}
	*last_step = previous;
	return 0;
}

static bool action_is_revocation(
	enum pqcp_fleet_convergence_action action)
{
	return action == PQCP_FLEET_CONVERGENCE_APPLY_REVOCATION ||
	       action == PQCP_FLEET_CONVERGENCE_QUARANTINE ||
	       action == PQCP_FLEET_CONVERGENCE_DECOMMISSION;
}

static bool action_is_identity(
	enum pqcp_fleet_convergence_action action)
{
	return action == PQCP_FLEET_CONVERGENCE_INSTALL_IDENTITY ||
	       action == PQCP_FLEET_CONVERGENCE_ROTATE_IDENTITY ||
	       action == PQCP_FLEET_CONVERGENCE_RESTRICT_IDENTITY;
}

static bool action_is_policy(
	enum pqcp_fleet_convergence_action action)
{
	return action == PQCP_FLEET_CONVERGENCE_APPLY_POLICY ||
	       action == PQCP_FLEET_CONVERGENCE_RESTRICT_POLICY;
}

static bool action_is_channel(
	enum pqcp_fleet_convergence_action action)
{
	return action == PQCP_FLEET_CONVERGENCE_ESTABLISH_CHANNEL ||
	       action == PQCP_FLEET_CONVERGENCE_REKEY_CHANNEL ||
	       action == PQCP_FLEET_CONVERGENCE_CLOSE_CHANNEL;
}

static bool action_is_firmware(
	enum pqcp_fleet_convergence_action action)
{
	return action == PQCP_FLEET_CONVERGENCE_STAGE_FIRMWARE ||
	       action == PQCP_FLEET_CONVERGENCE_ACTIVATE_FIRMWARE ||
	       action == PQCP_FLEET_CONVERGENCE_ROLLBACK_FIRMWARE ||
	       action == PQCP_FLEET_CONVERGENCE_VERIFY_FIRMWARE;
}

static bool action_is_recovery(
	enum pqcp_fleet_convergence_action action)
{
	return action == PQCP_FLEET_CONVERGENCE_ENTER_RECOVERY ||
	       action == PQCP_FLEET_CONVERGENCE_ADVANCE_RECOVERY ||
	       action == PQCP_FLEET_CONVERGENCE_EXIT_RECOVERY;
}

static int add_security_dependencies(
	struct pqcp_fleet_convergence *convergence)
{
	struct pqcp_fleet_convergence_plan *plan =
		&convergence->plan;
	int ret;

	for (size_t predecessor_index = 0U;
	     predecessor_index < plan->step_count;
	     ++predecessor_index) {
		const struct pqcp_fleet_plan_step *predecessor =
			&plan->steps[predecessor_index];

		for (size_t successor_index = 0U;
		     successor_index < plan->step_count;
		     ++successor_index) {
			const struct pqcp_fleet_plan_step *successor =
				&plan->steps[successor_index];
			bool required = false;
			enum pqcp_fleet_dependency_kind kind =
				PQCP_FLEET_DEPENDENCY_HARD;

			if (predecessor_index == successor_index ||
			    predecessor->priority >= successor->priority) {
				continue;
			}
			if (action_is_revocation(predecessor->action)) {
				required = true;
				kind = PQCP_FLEET_DEPENDENCY_SECURITY;
			} else if (action_is_recovery(
					   predecessor->action) &&
				   (action_is_identity(successor->action) ||
				    action_is_policy(successor->action) ||
				    action_is_firmware(successor->action) ||
				    action_is_channel(successor->action))) {
				required = true;
				kind =
					PQCP_FLEET_DEPENDENCY_ROLLBACK_BARRIER;
			} else if (action_is_identity(
					   predecessor->action) &&
				   action_is_channel(successor->action)) {
				required = true;
			} else if (action_is_policy(
					   predecessor->action) &&
				   (action_is_firmware(successor->action) ||
				    action_is_channel(successor->action))) {
				required = true;
			} else if ((predecessor->flags &
				    PQCP_FLEET_STEP_SECURITY_CRITICAL) != 0U &&
				   (successor->flags &
				    PQCP_FLEET_STEP_SECURITY_CRITICAL) == 0U &&
				   (convergence->policy.plan_flags &
				    PQCP_FLEET_PLAN_SECURITY_FIRST) != 0U) {
				required = true;
				kind = PQCP_FLEET_DEPENDENCY_SECURITY;
			}
			if (!required ||
			    dependency_exists(
				    plan, successor->step_id,
				    predecessor->step_id)) {
				continue;
			}
			ret = append_dependency(
				plan, predecessor->step_id,
				successor->step_id, kind);
			if (ret != 0) {
				return ret;
			}
		}
	}
	return 0;
}

static bool predecessor_waves_assigned(
	const struct pqcp_fleet_convergence_plan *plan,
	const struct pqcp_fleet_plan_step *step,
	uint32_t *maximum_predecessor_wave)
{
	uint32_t maximum = 0U;
	bool has_predecessor = false;

	for (size_t index = 0U;
	     index < plan->dependency_count; ++index) {
		const struct pqcp_fleet_plan_dependency *dependency =
			&plan->dependencies[index];
		const struct pqcp_fleet_plan_step *predecessor;

		if (dependency->successor_step_id != step->step_id) {
			continue;
		}
		has_predecessor = true;
		predecessor = const_step_by_id(
			plan, dependency->predecessor_step_id);
		if (predecessor == NULL ||
		    predecessor->wave == UNASSIGNED_WAVE) {
			return false;
		}
		if (predecessor->wave > maximum) {
			maximum = predecessor->wave;
		}
	}
	*maximum_predecessor_wave =
		has_predecessor ? maximum + 1U : 0U;
	return true;
}

static int assign_waves(
	struct pqcp_fleet_convergence *convergence)
{
	struct pqcp_fleet_convergence_plan *plan =
		&convergence->plan;
	size_t assigned = 0U;
	uint32_t highest_wave = 0U;

	for (size_t index = 0U; index < plan->step_count; ++index) {
		plan->steps[index].wave = UNASSIGNED_WAVE;
	}
	for (size_t pass = 0U; pass < plan->step_count; ++pass) {
		bool progressed = false;

		for (size_t index = 0U;
		     index < plan->step_count; ++index) {
			struct pqcp_fleet_plan_step *step =
				&plan->steps[index];
			uint32_t wave;

			if (step->wave != UNASSIGNED_WAVE) {
				continue;
			}
			if (!predecessor_waves_assigned(
				    plan, step, &wave)) {
				continue;
			}
			step->wave = wave;
			if (wave > highest_wave) {
				highest_wave = wave;
			}
			assigned++;
			progressed = true;
		}
		if (assigned == plan->step_count) {
			break;
		}
		if (!progressed) {
			return -ELOOP;
		}
	}
	if ((uint64_t)highest_wave + 1U >
	    plan->wave_capacity) {
		return -ENOSPC;
	}
	memset(plan->waves, 0,
	       plan->wave_capacity * sizeof(*plan->waves));
	plan->wave_count = (size_t)highest_wave + 1U;
	for (size_t index = 0U; index < plan->wave_count; ++index) {
		plan->waves[index].wave = (uint32_t)index;
		plan->waves[index].released = index == 0U;
	}
	for (size_t index = 0U; index < plan->step_count; ++index) {
		struct pqcp_fleet_plan_step *step =
			&plan->steps[index];
		struct pqcp_fleet_plan_wave *wave;

		if (step->wave >= plan->wave_count) {
			return -EBADMSG;
		}
		wave = &plan->waves[step->wave];
		if (wave->total_steps == UINT32_MAX) {
			return -EOVERFLOW;
		}
		wave->total_steps++;
	}
	return 0;
}

static bool dependencies_satisfied(
	struct pqcp_fleet_convergence_plan *plan,
	struct pqcp_fleet_plan_step *step)
{
	bool satisfied = true;

	for (size_t index = 0U;
	     index < plan->dependency_count; ++index) {
		struct pqcp_fleet_plan_dependency *dependency =
			&plan->dependencies[index];
		const struct pqcp_fleet_plan_step *predecessor;

		if (dependency->successor_step_id != step->step_id) {
			continue;
		}
		predecessor = const_step_by_id(
			plan, dependency->predecessor_step_id);
		if (predecessor == NULL) {
			dependency->satisfied = false;
			satisfied = false;
			continue;
		}
		dependency->satisfied =
			predecessor->state == PQCP_FLEET_STEP_SUCCEEDED ||
			predecessor->state == PQCP_FLEET_STEP_ROLLED_BACK;
		if (!dependency->satisfied) {
			satisfied = false;
		}
	}
	return satisfied;
}

static void recompute_wave_summaries(
	struct pqcp_fleet_convergence_plan *plan)
{
	for (size_t index = 0U; index < plan->wave_count; ++index) {
		struct pqcp_fleet_plan_wave *wave =
			&plan->waves[index];
		const bool released = wave->released;

		memset(wave, 0, sizeof(*wave));
		wave->wave = (uint32_t)index;
		wave->released = released;
	}
	for (size_t index = 0U; index < plan->step_count; ++index) {
		const struct pqcp_fleet_plan_step *step =
			&plan->steps[index];
		struct pqcp_fleet_plan_wave *wave;

		if (step->wave >= plan->wave_count) {
			continue;
		}
		wave = &plan->waves[step->wave];
		wave->total_steps++;
		switch (step->state) {
		case PQCP_FLEET_STEP_READY:
			wave->ready_steps++;
			break;
		case PQCP_FLEET_STEP_LEASED:
		case PQCP_FLEET_STEP_APPLYING:
		case PQCP_FLEET_STEP_AWAITING_ACK:
			wave->active_steps++;
			break;
		case PQCP_FLEET_STEP_SUCCEEDED:
		case PQCP_FLEET_STEP_ROLLED_BACK:
			wave->succeeded_steps++;
			break;
		case PQCP_FLEET_STEP_FAILED:
			wave->failed_steps++;
			break;
		case PQCP_FLEET_STEP_BLOCKED:
			wave->blocked_steps++;
			break;
		default:
			break;
		}
	}
	for (size_t index = 0U; index < plan->wave_count; ++index) {
		struct pqcp_fleet_plan_wave *wave =
			&plan->waves[index];

		wave->complete =
			wave->total_steps != 0U &&
			wave->succeeded_steps == wave->total_steps;
	}
	for (size_t index = 1U; index < plan->wave_count; ++index) {
		if (plan->waves[index - 1U].complete) {
			plan->waves[index].released = true;
		}
	}
}

static void recompute_plan_counts(
	struct pqcp_fleet_convergence_plan *plan)
{
	plan->succeeded_steps = 0U;
	plan->failed_steps = 0U;
	plan->blocked_steps = 0U;
	plan->superseded_steps = 0U;
	plan->rollback_steps = 0U;
	for (size_t index = 0U; index < plan->step_count; ++index) {
		switch (plan->steps[index].state) {
		case PQCP_FLEET_STEP_SUCCEEDED:
			plan->succeeded_steps++;
			break;
		case PQCP_FLEET_STEP_FAILED:
			plan->failed_steps++;
			break;
		case PQCP_FLEET_STEP_BLOCKED:
			plan->blocked_steps++;
			break;
		case PQCP_FLEET_STEP_SUPERSEDED:
			plan->superseded_steps++;
			break;
		case PQCP_FLEET_STEP_ROLLBACK_PENDING:
		case PQCP_FLEET_STEP_ROLLED_BACK:
			plan->rollback_steps++;
			break;
		default:
			break;
		}
	}
}

static void refresh_ready_steps(
	struct pqcp_fleet_convergence_plan *plan)
{
	recompute_wave_summaries(plan);
	for (size_t index = 0U; index < plan->step_count; ++index) {
		struct pqcp_fleet_plan_step *step =
			&plan->steps[index];

		if (step->state != PQCP_FLEET_STEP_PENDING &&
		    step->state != PQCP_FLEET_STEP_ROLLBACK_PENDING) {
			continue;
		}
		if (step->wave >= plan->wave_count ||
		    !plan->waves[step->wave].released) {
			continue;
		}
		if (dependencies_satisfied(plan, step)) {
			step->state = PQCP_FLEET_STEP_READY;
		}
	}
	recompute_plan_counts(plan);
	recompute_wave_summaries(plan);
}

static void update_plan_terminal_state(
	struct pqcp_fleet_convergence *convergence)
{
	struct pqcp_fleet_convergence_plan *plan =
		&convergence->plan;
	size_t terminal = 0U;

	recompute_plan_counts(plan);
	for (size_t index = 0U; index < plan->step_count; ++index) {
		if (terminal_step_state(plan->steps[index].state)) {
			terminal++;
		}
	}
	if (plan->state == PQCP_FLEET_PLAN_SUPERSEDED ||
	    plan->state == PQCP_FLEET_PLAN_CANCELLED) {
		return;
	}
	if (plan->failed_steps != 0U &&
	    (plan->flags & PQCP_FLEET_PLAN_STOP_ON_FAILURE) != 0U) {
		plan->state = PQCP_FLEET_PLAN_FAILED;
		return;
	}
	if (plan->blocked_steps != 0U &&
	    (plan->flags & PQCP_FLEET_PLAN_BLOCK_ON_CONFLICT) != 0U) {
		plan->state = PQCP_FLEET_PLAN_BLOCKED;
		return;
	}
	if (terminal == plan->step_count && plan->step_count != 0U) {
		if (plan->failed_steps != 0U) {
			plan->state = PQCP_FLEET_PLAN_FAILED;
		} else if (plan->blocked_steps != 0U) {
			plan->state = PQCP_FLEET_PLAN_BLOCKED;
		} else {
			plan->state = PQCP_FLEET_PLAN_SUCCEEDED;
			plan->result = 0;
		}
	} else if (plan->state != PQCP_FLEET_PLAN_ROLLING_BACK) {
		plan->state = PQCP_FLEET_PLAN_RUNNING;
	}
}

static void write_step(
	struct convergence_writer *writer,
	const struct pqcp_fleet_plan_step *step)
{
	writer_u32(writer, step->schema_version);
	writer_u32(writer, step->step_id);
	writer_u32(writer, (uint32_t)step->key.kind);
	writer_u64(writer, step->key.resource_id);
	writer_text(writer, step->key.name, sizeof(step->key.name));
	writer_u32(writer, (uint32_t)step->action);
	writer_u32(writer, (uint32_t)step->state);
	writer_u32(writer, (uint32_t)step->drift_class);
	writer_u32(writer, step->drift_reason_mask);
	writer_u32(writer, step->flags);
	writer_u32(writer, step->priority);
	writer_u32(writer, step->wave);
	writer_u32(writer, step->attempts);
	writer_u32(writer, step->maximum_attempts);
	writer_u64(writer, step->desired_generation);
	writer_u64(writer, step->desired_epoch);
	writer_u64(writer, step->plan_generation);
	writer_u64(writer, step->leased_at_ms);
	writer_u64(writer, step->lease_expires_at_ms);
	writer_u64(writer, step->started_at_ms);
	writer_u64(writer, step->acknowledgement_deadline_ms);
	writer_u64(writer, step->next_retry_ms);
	writer_u64(writer, step->completed_at_ms);
	writer_u64(writer, step->rollback_barrier_generation);
	writer_i32(writer, step->result);
	writer_bytes(writer, step->desired_digest,
		     sizeof(step->desired_digest));
	writer_bytes(writer, step->observed_digest,
		     sizeof(step->observed_digest));
	writer_bytes(writer, step->acknowledgement_digest,
		     sizeof(step->acknowledgement_digest));
	writer_bool(writer, step->occupied);
}

static int hash_chain_block(
	const char *domain,
	const uint8_t previous[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t *payload,
	size_t payload_length,
	uint8_t output[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t block[PLAN_CHAIN_BYTES];
	struct convergence_writer writer;
	size_t domain_length;
	int ret;

	if (domain == NULL || previous == NULL ||
	    (payload == NULL && payload_length != 0U) ||
	    output == NULL) {
		return -EINVAL;
	}
	domain_length = strnlen(domain, 64U);
	if (domain_length == 0U || domain_length >= 64U) {
		return -EINVAL;
	}
	memset(block, 0, sizeof(block));
	writer_init(&writer, block, sizeof(block));
	writer_text(&writer, domain, 64U);
	writer_bytes(&writer, previous, PQCP_FLEET_DIGEST_BYTES);
	writer_u64(&writer, payload_length);
	writer_bytes(&writer, payload, payload_length);
	ret = writer.error;
	if (ret == 0) {
		ret = pqcp_fleet_sha256(
			block, writer.offset, output);
	}
	memset(block, 0, sizeof(block));
	return ret;
}

int pqcp_fleet_convergence_plan_digest(
	const struct pqcp_fleet_convergence_plan *plan,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t chain[PQCP_FLEET_DIGEST_BYTES] = { 0 };
	uint8_t payload[PLAN_CHAIN_BYTES];
	struct convergence_writer writer;
	int ret;

	if (plan == NULL || digest == NULL ||
	    plan->schema_version !=
		    PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION ||
	    plan->plan_id == 0U || plan->generation == 0U ||
	    !plan_state_valid(plan->state) ||
	    plan->steps == NULL ||
	    plan->step_count > plan->step_capacity ||
	    plan->dependencies == NULL ||
	    plan->dependency_count >
		    plan->dependency_capacity ||
	    plan->waves == NULL ||
	    plan->wave_count > plan->wave_capacity) {
		return -EINVAL;
	}
	memset(payload, 0, sizeof(payload));
	writer_init(&writer, payload, sizeof(payload));
	writer_u32(&writer, plan->schema_version);
	writer_u64(&writer, plan->plan_id);
	writer_u64(&writer, plan->generation);
	writer_u64(&writer, plan->desired_generation);
	writer_u64(&writer, plan->observed_generation);
	writer_u64(&writer, plan->created_at_ms);
	writer_u64(&writer, plan->deadline_ms);
	writer_u64(&writer, plan->superseded_by_generation);
	writer_u32(&writer, (uint32_t)plan->state);
	writer_u32(&writer, plan->flags);
	writer_u64(&writer, plan->step_count);
	writer_u64(&writer, plan->dependency_count);
	writer_u64(&writer, plan->wave_count);
	writer_u32(&writer, plan->succeeded_steps);
	writer_u32(&writer, plan->failed_steps);
	writer_u32(&writer, plan->blocked_steps);
	writer_u32(&writer, plan->superseded_steps);
	writer_u32(&writer, plan->rollback_steps);
	writer_i32(&writer, plan->result);
	writer_bytes(&writer, plan->desired_snapshot_digest,
		     sizeof(plan->desired_snapshot_digest));
	writer_bytes(&writer, plan->observed_snapshot_digest,
		     sizeof(plan->observed_snapshot_digest));
	if (writer.error != 0) {
		return writer.error;
	}
	ret = hash_chain_block(
		"PQCP-FLEET-PLAN-HEADER-V1", chain,
		payload, writer.offset, chain);
	for (size_t index = 0U;
	     ret == 0 && index < plan->step_count; ++index) {
		memset(payload, 0, sizeof(payload));
		writer_init(&writer, payload, sizeof(payload));
		write_step(&writer, &plan->steps[index]);
		if (writer.error != 0) {
			ret = writer.error;
			break;
		}
		ret = hash_chain_block(
			"PQCP-FLEET-PLAN-STEP-V1", chain,
			payload, writer.offset, chain);
	}
	for (size_t index = 0U;
	     ret == 0 && index < plan->dependency_count; ++index) {
		const struct pqcp_fleet_plan_dependency *dependency =
			&plan->dependencies[index];

		memset(payload, 0, sizeof(payload));
		writer_init(&writer, payload, sizeof(payload));
		writer_u32(
			&writer,
			dependency->predecessor_step_id);
		writer_u32(
			&writer,
			dependency->successor_step_id);
		writer_u32(&writer, (uint32_t)dependency->kind);
		writer_bool(&writer, dependency->satisfied);
		ret = writer.error;
		if (ret == 0) {
			ret = hash_chain_block(
				"PQCP-FLEET-PLAN-DEPENDENCY-V1",
				chain, payload, writer.offset, chain);
		}
	}
	for (size_t index = 0U;
	     ret == 0 && index < plan->wave_count; ++index) {
		const struct pqcp_fleet_plan_wave *wave =
			&plan->waves[index];

		memset(payload, 0, sizeof(payload));
		writer_init(&writer, payload, sizeof(payload));
		writer_u32(&writer, wave->wave);
		writer_u32(&writer, wave->total_steps);
		writer_u32(&writer, wave->ready_steps);
		writer_u32(&writer, wave->active_steps);
		writer_u32(&writer, wave->succeeded_steps);
		writer_u32(&writer, wave->failed_steps);
		writer_u32(&writer, wave->blocked_steps);
		writer_bool(&writer, wave->released);
		writer_bool(&writer, wave->complete);
		ret = writer.error;
		if (ret == 0) {
			ret = hash_chain_block(
				"PQCP-FLEET-PLAN-WAVE-V1",
				chain, payload, writer.offset, chain);
		}
	}
	if (ret == 0) {
		memcpy(digest, chain, sizeof(chain));
	}
	memset(chain, 0, sizeof(chain));
	memset(payload, 0, sizeof(payload));
	return ret;
}

static int step_verify(
	const struct pqcp_fleet_convergence_plan *plan,
	const struct pqcp_fleet_plan_step *step)
{
	if (step == NULL || !step->occupied ||
	    step->schema_version !=
		    PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION ||
	    step->step_id == 0U ||
	    step->step_id > plan->step_count ||
	    !action_valid(step->action) ||
	    !step_state_valid(step->state) ||
	    step->state == PQCP_FLEET_STEP_EMPTY ||
	    step->priority == UINT32_MAX ||
	    step->wave >= plan->wave_count ||
	    step->maximum_attempts == 0U ||
	    step->attempts > step->maximum_attempts ||
	    step->plan_generation != plan->generation ||
	    step->key.kind <= PQCP_FLEET_RESOURCE_NONE ||
	    step->key.kind >= PQCP_FLEET_RESOURCE_KIND_COUNT ||
	    step->key.resource_id == 0U ||
	    !text_valid(step->key.name, sizeof(step->key.name))) {
		return -EBADMSG;
	}
	if (step->state == PQCP_FLEET_STEP_LEASED &&
	    (step->leased_at_ms == 0U ||
	     step->lease_expires_at_ms <= step->leased_at_ms)) {
		return -EBADMSG;
	}
	if ((step->state == PQCP_FLEET_STEP_APPLYING ||
	     step->state == PQCP_FLEET_STEP_AWAITING_ACK) &&
	    step->started_at_ms == 0U) {
		return -EBADMSG;
	}
	if (step->state == PQCP_FLEET_STEP_AWAITING_ACK &&
	    step->acknowledgement_deadline_ms <=
		    step->started_at_ms) {
		return -EBADMSG;
	}
	if (terminal_step_state(step->state) &&
	    step->completed_at_ms == 0U &&
	    step->state != PQCP_FLEET_STEP_BLOCKED) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_fleet_convergence_plan_verify(
	const struct pqcp_fleet_convergence_plan *plan)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	uint32_t succeeded = 0U;
	uint32_t failed = 0U;
	uint32_t blocked = 0U;
	uint32_t superseded = 0U;
	uint32_t rollback = 0U;
	int ret;

	if (plan == NULL ||
	    pqcp_fleet_convergence_plan_digest(
		    plan, digest) != 0) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < plan->step_count; ++index) {
		if (step_verify(plan, &plan->steps[index]) != 0) {
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < plan->step_count; ++other) {
			if (plan->steps[index].step_id ==
			    plan->steps[other].step_id) {
				return -EEXIST;
			}
		}
		switch (plan->steps[index].state) {
		case PQCP_FLEET_STEP_SUCCEEDED:
			succeeded++;
			break;
		case PQCP_FLEET_STEP_FAILED:
			failed++;
			break;
		case PQCP_FLEET_STEP_BLOCKED:
			blocked++;
			break;
		case PQCP_FLEET_STEP_SUPERSEDED:
			superseded++;
			break;
		case PQCP_FLEET_STEP_ROLLBACK_PENDING:
		case PQCP_FLEET_STEP_ROLLED_BACK:
			rollback++;
			break;
		default:
			break;
		}
	}
	for (size_t index = 0U;
	     index < plan->dependency_count; ++index) {
		const struct pqcp_fleet_plan_dependency *dependency =
			&plan->dependencies[index];

		if (!dependency_kind_valid(dependency->kind) ||
		    dependency->predecessor_step_id == 0U ||
		    dependency->successor_step_id == 0U ||
		    dependency->predecessor_step_id ==
			    dependency->successor_step_id ||
		    const_step_by_id(
			    plan,
			    dependency->predecessor_step_id) == NULL ||
		    const_step_by_id(
			    plan,
			    dependency->successor_step_id) == NULL) {
			return -EBADMSG;
		}
	}
	for (size_t index = 0U; index < plan->wave_count; ++index) {
		if (plan->waves[index].wave != index ||
		    plan->waves[index].total_steps == 0U) {
			return -EBADMSG;
		}
	}
	if (succeeded != plan->succeeded_steps ||
	    failed != plan->failed_steps ||
	    blocked != plan->blocked_steps ||
	    superseded != plan->superseded_steps ||
	    rollback != plan->rollback_steps ||
	    !digest_equal(digest, plan->digest)) {
		ret = -EBADMSG;
	} else {
		ret = 0;
	}
	memset(digest, 0, sizeof(digest));
	return ret;
}

static int refresh_plan_digest(
	struct pqcp_fleet_convergence_plan *plan)
{
	return pqcp_fleet_convergence_plan_digest(
		plan, plan->digest);
}

static void clear_plan_storage(
	struct pqcp_fleet_convergence_plan *plan)
{
	memset(plan->steps, 0,
	       plan->step_capacity * sizeof(*plan->steps));
	memset(plan->dependencies, 0,
	       plan->dependency_capacity *
		       sizeof(*plan->dependencies));
	memset(plan->waves, 0,
	       plan->wave_capacity * sizeof(*plan->waves));
	plan->step_count = 0U;
	plan->dependency_count = 0U;
	plan->wave_count = 0U;
	plan->succeeded_steps = 0U;
	plan->failed_steps = 0U;
	plan->blocked_steps = 0U;
	plan->superseded_steps = 0U;
	plan->rollback_steps = 0U;
	plan->result = 0;
	memset(plan->digest, 0, sizeof(plan->digest));
}

static int internal_supersede(
	struct pqcp_fleet_convergence *convergence,
	uint64_t desired_generation,
	uint64_t now_ms)
{
	struct pqcp_fleet_convergence_plan *plan =
		&convergence->plan;

	if (plan->state == PQCP_FLEET_PLAN_EMPTY ||
	    plan_terminal(plan->state)) {
		return 0;
	}
	if (desired_generation <= plan->desired_generation ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < plan->step_count; ++index) {
		struct pqcp_fleet_plan_step *step =
			&plan->steps[index];

		if (!terminal_step_state(step->state)) {
			step->state = PQCP_FLEET_STEP_SUPERSEDED;
			step->completed_at_ms = now_ms;
			step->result = -ESTALE;
		}
	}
	plan->superseded_by_generation = desired_generation;
	plan->state = PQCP_FLEET_PLAN_SUPERSEDED;
	plan->result = -ESTALE;
	recompute_plan_counts(plan);
	if (convergence->lease.active) {
		convergence->lease.active = false;
		convergence->lease.revoked = true;
	}
	if (convergence->supersession_count != UINT64_MAX) {
		convergence->supersession_count++;
	}
	return refresh_plan_digest(plan);
}

int pqcp_fleet_convergence_build_plan(
	struct pqcp_fleet_convergence *convergence,
	uint64_t now_ms,
	struct pqcp_fleet_convergence_plan **plan_output)
{
	struct pqcp_fleet_state_snapshot desired_snapshot = {
		.resources = NULL,
	};
	struct pqcp_fleet_state_snapshot observed_snapshot = {
		.resources = NULL,
	};
	uint64_t deadline;
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    plan_output == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	desired_snapshot.resources =
		convergence->desired_resources;
	desired_snapshot.capacity =
		convergence->desired_resource_capacity;
	observed_snapshot.resources =
		convergence->observed_resources;
	observed_snapshot.capacity =
		convergence->observed_resource_capacity;
	ret = pqcp_fleet_desired_snapshot(
		convergence->model, &desired_snapshot, now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_fleet_observed_snapshot(
		convergence->model, &observed_snapshot, now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_fleet_snapshot_classify_drift(
		&desired_snapshot, &observed_snapshot,
		convergence->drift, convergence->drift_capacity,
		&convergence->drift_count);
	if (ret != 0) {
		return ret;
	}
	if (convergence->drift_count == 0U) {
		return -EALREADY;
	}
	ret = add_u64(
		now_ms, convergence->policy.plan_deadline_ms,
		&deadline);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (!plan_terminal(convergence->plan.state) &&
	    convergence->plan.state != PQCP_FLEET_PLAN_EMPTY) {
		ret = internal_supersede(
			convergence, desired_snapshot.generation,
			now_ms);
		if (ret != 0) {
			(void)k_mutex_unlock(&convergence->lock);
			return ret;
		}
	}
	if (convergence->next_plan_id == 0U ||
	    convergence->next_plan_id == UINT64_MAX ||
	    convergence->plan_count == UINT64_MAX) {
		(void)k_mutex_unlock(&convergence->lock);
		return -EOVERFLOW;
	}
	clear_plan_storage(&convergence->plan);
	convergence->plan.plan_id =
		convergence->next_plan_id++;
	convergence->plan.generation =
		convergence->plan_count + 1U;
	convergence->plan.desired_generation =
		desired_snapshot.generation;
	convergence->plan.observed_generation =
		observed_snapshot.generation;
	convergence->plan.created_at_ms = now_ms;
	convergence->plan.deadline_ms = deadline;
	convergence->plan.superseded_by_generation = 0U;
	convergence->plan.state = PQCP_FLEET_PLAN_BUILDING;
	convergence->plan.flags =
		convergence->policy.plan_flags;
	memcpy(convergence->plan.desired_snapshot_digest,
	       desired_snapshot.digest,
	       sizeof(convergence->plan.desired_snapshot_digest));
	memcpy(convergence->plan.observed_snapshot_digest,
	       observed_snapshot.digest,
	       sizeof(convergence->plan.observed_snapshot_digest));
	for (size_t index = 0U;
	     index < convergence->drift_count; ++index) {
		uint32_t first_step = 0U;
		uint32_t last_step = 0U;

		ret = actions_for_drift(
			convergence, &convergence->drift[index],
			&desired_snapshot, &observed_snapshot,
			&first_step, &last_step);
		if (ret != 0) {
			clear_plan_storage(&convergence->plan);
			convergence->plan.state =
				PQCP_FLEET_PLAN_EMPTY;
			(void)k_mutex_unlock(&convergence->lock);
			return ret;
		}
	}
	ret = add_security_dependencies(convergence);
	if (ret == 0) {
		ret = assign_waves(convergence);
	}
	if (ret != 0) {
		clear_plan_storage(&convergence->plan);
		convergence->plan.state = PQCP_FLEET_PLAN_EMPTY;
		(void)k_mutex_unlock(&convergence->lock);
		return ret;
	}
	convergence->plan.state =
		convergence->plan.blocked_steps != 0U ?
			PQCP_FLEET_PLAN_BLOCKED :
			PQCP_FLEET_PLAN_READY;
	refresh_ready_steps(&convergence->plan);
	if (convergence->plan.blocked_steps != 0U &&
	    (convergence->plan.flags &
	     PQCP_FLEET_PLAN_BLOCK_ON_CONFLICT) != 0U) {
		convergence->plan.state = PQCP_FLEET_PLAN_BLOCKED;
	} else {
		convergence->plan.state = PQCP_FLEET_PLAN_READY;
	}
	ret = refresh_plan_digest(&convergence->plan);
	if (ret == 0) {
		convergence->plan_count++;
		memset(&convergence->lease, 0,
		       sizeof(convergence->lease));
		*plan_output = &convergence->plan;
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

static int lease_token(
	const struct pqcp_fleet_convergence_plan *plan,
	const struct pqcp_fleet_plan_lease *lease,
	uint8_t token[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t payload[LEASE_TOKEN_BYTES];
	struct convergence_writer writer;
	int ret;

	if (plan == NULL || lease == NULL || token == NULL ||
	    !text_valid(lease->owner, sizeof(lease->owner))) {
		return -EINVAL;
	}
	memset(payload, 0, sizeof(payload));
	writer_init(&writer, payload, sizeof(payload));
	writer_bytes(
		&writer,
		(const uint8_t *)"PQCP-FLEET-PLAN-LEASE-V1", 24U);
	writer_u64(&writer, lease->lease_id);
	writer_u64(&writer, lease->plan_id);
	writer_u64(&writer, lease->plan_generation);
	writer_u64(&writer, lease->issued_at_ms);
	writer_u64(&writer, lease->expires_at_ms);
	writer_u64(&writer, lease->renewal_count);
	writer_text(&writer, lease->owner, sizeof(lease->owner));
	writer_bytes(&writer, plan->desired_snapshot_digest,
		     sizeof(plan->desired_snapshot_digest));
	writer_bytes(&writer, plan->observed_snapshot_digest,
		     sizeof(plan->observed_snapshot_digest));
	ret = writer.error;
	if (ret == 0) {
		ret = pqcp_fleet_sha256(
			payload, writer.offset, token);
	}
	memset(payload, 0, sizeof(payload));
	return ret;
}

static int validate_lease_locked(
	const struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms)
{
	const struct pqcp_fleet_plan_lease *lease =
		&convergence->lease;

	if (lease_id == 0U || token == NULL || now_ms == 0U ||
	    !lease->active || lease->revoked ||
	    lease->lease_id != lease_id ||
	    lease->plan_id != convergence->plan.plan_id ||
	    lease->plan_generation !=
		    convergence->plan.generation ||
	    now_ms < lease->issued_at_ms ||
	    now_ms >= lease->expires_at_ms ||
	    !digest_equal(token, lease->token)) {
		return -EACCES;
	}
	return 0;
}

int pqcp_fleet_convergence_acquire(
	struct pqcp_fleet_convergence *convergence,
	const char *owner,
	uint64_t now_ms,
	uint64_t requested_duration_ms,
	struct pqcp_fleet_plan_lease *lease_output)
{
	uint64_t duration;
	uint64_t expires_at;
	size_t owner_length;
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    owner == NULL || now_ms == 0U ||
	    lease_output == NULL) {
		return -EINVAL;
	}
	owner_length = strnlen(
		owner, PQCP_FLEET_PLAN_LEASE_OWNER_MAX_CHARS);
	if (owner_length == 0U ||
	    owner_length >=
		    PQCP_FLEET_PLAN_LEASE_OWNER_MAX_CHARS) {
		return -EINVAL;
	}
	duration = requested_duration_ms == 0U ?
		convergence->policy.plan_lease_ms :
		requested_duration_ms;
	if (duration > convergence->policy.plan_lease_ms) {
		duration = convergence->policy.plan_lease_ms;
	}
	ret = add_u64(now_ms, duration, &expires_at);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (convergence->plan.state != PQCP_FLEET_PLAN_READY &&
	    convergence->plan.state != PQCP_FLEET_PLAN_RUNNING) {
		(void)k_mutex_unlock(&convergence->lock);
		return -EACCES;
	}
	if (convergence->lease.active &&
	    now_ms < convergence->lease.expires_at_ms) {
		(void)k_mutex_unlock(&convergence->lock);
		return -EBUSY;
	}
	if (convergence->next_lease_id == 0U ||
	    convergence->next_lease_id == UINT64_MAX) {
		(void)k_mutex_unlock(&convergence->lock);
		return -EOVERFLOW;
	}
	memset(&convergence->lease, 0,
	       sizeof(convergence->lease));
	convergence->lease.lease_id =
		convergence->next_lease_id++;
	convergence->lease.plan_id =
		convergence->plan.plan_id;
	convergence->lease.plan_generation =
		convergence->plan.generation;
	convergence->lease.issued_at_ms = now_ms;
	convergence->lease.expires_at_ms = expires_at;
	memcpy(convergence->lease.owner, owner, owner_length);
	convergence->lease.owner[owner_length] = '\0';
	convergence->lease.active = true;
	ret = lease_token(
		&convergence->plan, &convergence->lease,
		convergence->lease.token);
	if (ret == 0) {
		*lease_output = convergence->lease;
	} else {
		memset(&convergence->lease, 0,
		       sizeof(convergence->lease));
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

int pqcp_fleet_convergence_renew(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t requested_duration_ms,
	struct pqcp_fleet_plan_lease *lease_output)
{
	uint64_t duration;
	uint64_t expires_at;
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    lease_output == NULL) {
		return -EINVAL;
	}
	duration = requested_duration_ms == 0U ?
		convergence->policy.plan_lease_ms :
		requested_duration_ms;
	if (duration > convergence->policy.plan_lease_ms) {
		duration = convergence->policy.plan_lease_ms;
	}
	ret = add_u64(now_ms, duration, &expires_at);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = validate_lease_locked(
		convergence, lease_id, token, now_ms);
	if (ret == 0 &&
	    convergence->lease.renewal_count == UINT64_MAX) {
		ret = -EOVERFLOW;
	}
	if (ret == 0) {
		convergence->lease.expires_at_ms = expires_at;
		convergence->lease.renewal_count++;
		ret = lease_token(
			&convergence->plan, &convergence->lease,
			convergence->lease.token);
	}
	if (ret == 0) {
		*lease_output = convergence->lease;
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

int pqcp_fleet_convergence_release(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms)
{
	int ret;

	if (convergence == NULL || !convergence->initialized) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = validate_lease_locked(
		convergence, lease_id, token, now_ms);
	if (ret == 0) {
		convergence->lease.active = false;
		convergence->lease.revoked = true;
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

static uint32_t active_step_count(
	const struct pqcp_fleet_convergence_plan *plan)
{
	uint32_t count = 0U;

	for (size_t index = 0U; index < plan->step_count; ++index) {
		if (active_step_state(plan->steps[index].state)) {
			count++;
		}
	}
	return count;
}

static struct pqcp_fleet_plan_step *select_ready_step(
	struct pqcp_fleet_convergence *convergence)
{
	struct pqcp_fleet_plan_step *selected = NULL;

	for (size_t index = 0U;
	     index < convergence->plan.step_count; ++index) {
		struct pqcp_fleet_plan_step *candidate =
			&convergence->plan.steps[index];

		if (candidate->state != PQCP_FLEET_STEP_READY ||
		    candidate->wave >=
			    convergence->plan.wave_count ||
		    !convergence->plan.waves[
			    candidate->wave].released) {
			continue;
		}
		if (selected == NULL ||
		    candidate->priority < selected->priority ||
		    (candidate->priority == selected->priority &&
		     candidate->step_id < selected->step_id)) {
			selected = candidate;
		}
	}
	return selected;
}

static int lease_step(
	struct pqcp_fleet_convergence *convergence,
	struct pqcp_fleet_plan_step *step,
	uint64_t now_ms,
	struct pqcp_fleet_step_claim *claim)
{
	uint64_t expires_at;
	int ret;

	ret = add_u64(
		now_ms, convergence->policy.step_lease_ms,
		&expires_at);
	if (ret != 0) {
		return ret;
	}
	if (expires_at > convergence->lease.expires_at_ms) {
		expires_at = convergence->lease.expires_at_ms;
	}
	if (expires_at <= now_ms) {
		return -EACCES;
	}
	step->state = PQCP_FLEET_STEP_LEASED;
	step->leased_at_ms = now_ms;
	step->lease_expires_at_ms = expires_at;
	memset(claim, 0, sizeof(*claim));
	claim->plan_id = convergence->plan.plan_id;
	claim->plan_generation =
		convergence->plan.generation;
	claim->lease_id = convergence->lease.lease_id;
	claim->step_id = step->step_id;
	claim->wave = step->wave;
	claim->action = step->action;
	claim->key = step->key;
	claim->desired_generation = step->desired_generation;
	claim->desired_epoch = step->desired_epoch;
	claim->lease_expires_at_ms = expires_at;
	memcpy(claim->desired_digest, step->desired_digest,
	       sizeof(claim->desired_digest));
	convergence->transition_count++;
	return 0;
}

int pqcp_fleet_convergence_next(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_fleet_step_claim *claim)
{
	struct pqcp_fleet_plan_step *step;
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    claim == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = validate_lease_locked(
		convergence, lease_id, token, now_ms);
	if (ret != 0) {
		(void)k_mutex_unlock(&convergence->lock);
		return ret;
	}
	if (convergence->plan.state != PQCP_FLEET_PLAN_READY &&
	    convergence->plan.state != PQCP_FLEET_PLAN_RUNNING &&
	    convergence->plan.state !=
		    PQCP_FLEET_PLAN_ROLLING_BACK) {
		(void)k_mutex_unlock(&convergence->lock);
		return -EACCES;
	}
	refresh_ready_steps(&convergence->plan);
	if (active_step_count(&convergence->plan) >=
	    convergence->policy.maximum_parallel_steps) {
		(void)k_mutex_unlock(&convergence->lock);
		return -EAGAIN;
	}
	step = select_ready_step(convergence);
	if (step == NULL) {
		update_plan_terminal_state(convergence);
		(void)refresh_plan_digest(&convergence->plan);
		(void)k_mutex_unlock(&convergence->lock);
		return plan_terminal(convergence->plan.state) ?
			-ENODATA : -EAGAIN;
	}
	ret = lease_step(convergence, step, now_ms, claim);
	if (ret == 0) {
		convergence->plan.state =
			convergence->plan.state ==
				PQCP_FLEET_PLAN_ROLLING_BACK ?
				PQCP_FLEET_PLAN_ROLLING_BACK :
				PQCP_FLEET_PLAN_RUNNING;
		recompute_wave_summaries(&convergence->plan);
		ret = refresh_plan_digest(&convergence->plan);
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

int pqcp_fleet_convergence_begin_apply(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t step_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_plan_step *step;
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    step_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = validate_lease_locked(
		convergence, lease_id, token, now_ms);
	step = step_by_id(&convergence->plan, step_id);
	if (ret == 0 &&
	    (step == NULL ||
	     step->state != PQCP_FLEET_STEP_LEASED ||
	     now_ms >= step->lease_expires_at_ms)) {
		ret = -EACCES;
	}
	if (ret == 0 && step->attempts == UINT32_MAX) {
		ret = -EOVERFLOW;
	}
	if (ret == 0) {
		step->state = PQCP_FLEET_STEP_APPLYING;
		step->started_at_ms = now_ms;
		step->attempts++;
		convergence->transition_count++;
		recompute_wave_summaries(&convergence->plan);
		ret = refresh_plan_digest(&convergence->plan);
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

static int complete_step(
	struct pqcp_fleet_convergence *convergence,
	struct pqcp_fleet_plan_step *step,
	int result,
	uint64_t now_ms)
{
	if (step == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	if (result != 0) {
		step->state = PQCP_FLEET_STEP_FAILED;
	} else if (convergence->plan.state ==
			   PQCP_FLEET_PLAN_ROLLING_BACK) {
		step->state = PQCP_FLEET_STEP_ROLLED_BACK;
	} else {
		step->state = PQCP_FLEET_STEP_SUCCEEDED;
	}
	step->result = result;
	step->completed_at_ms = now_ms;
	step->lease_expires_at_ms = 0U;
	step->acknowledgement_deadline_ms = 0U;
	convergence->transition_count++;
	refresh_ready_steps(&convergence->plan);
	update_plan_terminal_state(convergence);
	return refresh_plan_digest(&convergence->plan);
}

int pqcp_fleet_convergence_applied(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t step_id,
	const uint8_t result_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_fleet_plan_step *step;
	uint64_t acknowledgement_deadline;
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    step_id == 0U || result_digest == NULL ||
	    digest_zero(result_digest)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = validate_lease_locked(
		convergence, lease_id, token, now_ms);
	step = step_by_id(&convergence->plan, step_id);
	if (ret == 0 &&
	    (step == NULL ||
	     step->state != PQCP_FLEET_STEP_APPLYING)) {
		ret = -EACCES;
	}
	if (ret == 0) {
		memcpy(step->acknowledgement_digest,
		       result_digest,
		       sizeof(step->acknowledgement_digest));
		if ((step->flags &
		     PQCP_FLEET_STEP_REQUIRE_ACK) != 0U) {
			ret = add_u64(
				now_ms,
				convergence->policy.
					acknowledgement_timeout_ms,
				&acknowledgement_deadline);
			if (ret == 0) {
				step->state =
					PQCP_FLEET_STEP_AWAITING_ACK;
				step->acknowledgement_deadline_ms =
					acknowledgement_deadline;
				convergence->transition_count++;
				recompute_wave_summaries(
					&convergence->plan);
				ret = refresh_plan_digest(
					&convergence->plan);
			}
		} else {
			ret = complete_step(
				convergence, step, 0, now_ms);
		}
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

int pqcp_fleet_convergence_acknowledge(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t step_id,
	uint64_t observed_generation,
	uint64_t observed_epoch,
	const uint8_t observed_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_fleet_plan_step *step;
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    step_id == 0U || observed_generation == 0U ||
	    observed_digest == NULL ||
	    digest_zero(observed_digest)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = validate_lease_locked(
		convergence, lease_id, token, now_ms);
	step = step_by_id(&convergence->plan, step_id);
	if (ret == 0 &&
	    (step == NULL ||
	     step->state != PQCP_FLEET_STEP_AWAITING_ACK ||
	     now_ms >= step->acknowledgement_deadline_ms)) {
		ret = -EACCES;
	}
	if (ret == 0 &&
	    (observed_generation < step->desired_generation ||
	     observed_epoch < step->desired_epoch ||
	     !digest_equal(observed_digest,
			   step->desired_digest))) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		memcpy(step->observed_digest, observed_digest,
		       sizeof(step->observed_digest));
		ret = complete_step(
			convergence, step, 0, now_ms);
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

static uint32_t deterministic_jitter(
	const struct pqcp_fleet_plan_step *step,
	uint32_t basis_points)
{
	uint32_t value;

	if (basis_points == 0U) {
		return 0U;
	}
	value =
		((uint32_t)step->desired_digest[0] << 24) |
		((uint32_t)step->desired_digest[1] << 16) |
		((uint32_t)step->desired_digest[2] << 8) |
		(uint32_t)step->desired_digest[3];
	value ^= step->attempts * UINT32_C(0x9e3779b9);
	return value % (basis_points + 1U);
}

static void retry_delay(
	const struct pqcp_fleet_retry_policy *policy,
	const struct pqcp_fleet_plan_step *step,
	uint64_t *delay)
{
	uint64_t value = policy->initial_backoff_ms;

	for (uint32_t attempt = 1U;
	     attempt < step->attempts; ++attempt) {
		uint64_t multiplied;

		if (value >
		    UINT64_MAX / policy->multiplier_numerator) {
			value = policy->maximum_backoff_ms;
			break;
		}
		multiplied =
			value * policy->multiplier_numerator;
		value =
			multiplied /
			policy->multiplier_denominator;
		if (value >= policy->maximum_backoff_ms) {
			value = policy->maximum_backoff_ms;
			break;
		}
	}
	if (policy->jitter_basis_points != 0U) {
		const uint32_t jitter_points =
			deterministic_jitter(
				step,
				policy->jitter_basis_points);
		uint64_t jitter;

		if (jitter_points != 0U &&
		    value > UINT64_MAX / jitter_points) {
			jitter = UINT64_MAX;
		} else {
			jitter = value * jitter_points;
		}
		jitter /= 10000U;
		if (UINT64_MAX - value < jitter) {
			value = policy->maximum_backoff_ms;
		} else {
			value += jitter;
		}
	}
	if (value > policy->maximum_backoff_ms) {
		value = policy->maximum_backoff_ms;
	}
	*delay = value;
}

static enum pqcp_fleet_convergence_action rollback_action(
	enum pqcp_fleet_convergence_action action)
{
	switch (action) {
	case PQCP_FLEET_CONVERGENCE_STAGE_FIRMWARE:
	case PQCP_FLEET_CONVERGENCE_ACTIVATE_FIRMWARE:
	case PQCP_FLEET_CONVERGENCE_VERIFY_FIRMWARE:
		return PQCP_FLEET_CONVERGENCE_ROLLBACK_FIRMWARE;
	case PQCP_FLEET_CONVERGENCE_ESTABLISH_CHANNEL:
	case PQCP_FLEET_CONVERGENCE_REKEY_CHANNEL:
		return PQCP_FLEET_CONVERGENCE_CLOSE_CHANNEL;
	case PQCP_FLEET_CONVERGENCE_ENTER_RECOVERY:
	case PQCP_FLEET_CONVERGENCE_ADVANCE_RECOVERY:
		return PQCP_FLEET_CONVERGENCE_EXIT_RECOVERY;
	default:
		return PQCP_FLEET_CONVERGENCE_ACTION_NONE;
	}
}

static int request_rollback_locked(
	struct pqcp_fleet_convergence *convergence,
	uint32_t failed_step_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_convergence_plan *plan =
		&convergence->plan;
	bool queued = false;
	uint32_t previous_rollback = 0U;
	int ret;

	if (step_by_id(plan, failed_step_id) == NULL ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	for (size_t reverse = plan->step_count;
	     reverse > 0U; --reverse) {
		const struct pqcp_fleet_plan_step *step =
			&plan->steps[reverse - 1U];

		if (step->state == PQCP_FLEET_STEP_SUCCEEDED &&
		    (step->flags &
		     PQCP_FLEET_STEP_IRREVERSIBLE) != 0U) {
			struct pqcp_fleet_plan_step *barrier =
				&plan->steps[reverse - 1U];

			barrier->state = PQCP_FLEET_STEP_BLOCKED;
			barrier->result = -EPERM;
			barrier->completed_at_ms = now_ms;
			plan->state = PQCP_FLEET_PLAN_BLOCKED;
			plan->result = -EPERM;
			recompute_plan_counts(plan);
			return refresh_plan_digest(plan);
		}
	}
	plan->dependency_count = 0U;
	memset(plan->dependencies, 0,
	       plan->dependency_capacity *
		       sizeof(*plan->dependencies));
	for (size_t reverse = plan->step_count;
	     reverse > 0U; --reverse) {
		struct pqcp_fleet_plan_step *step =
			&plan->steps[reverse - 1U];
		enum pqcp_fleet_convergence_action action;

		if (step->state != PQCP_FLEET_STEP_SUCCEEDED) {
			continue;
		}
		if ((step->flags &
		     PQCP_FLEET_STEP_ALLOW_ROLLBACK) == 0U) {
			continue;
		}
		action = rollback_action(step->action);
		if (action == PQCP_FLEET_CONVERGENCE_ACTION_NONE) {
			continue;
		}
		step->action = action;
		step->priority = action_priority(action);
		step->state = PQCP_FLEET_STEP_ROLLBACK_PENDING;
		step->attempts = 0U;
		step->next_retry_ms = 0U;
		step->completed_at_ms = 0U;
		step->result = 0;
		if (!digest_zero(step->observed_digest)) {
			memcpy(step->desired_digest,
			       step->observed_digest,
			       sizeof(step->desired_digest));
		}
		if (previous_rollback != 0U) {
			ret = append_dependency(
				plan, previous_rollback,
				step->step_id,
				PQCP_FLEET_DEPENDENCY_HARD);
			if (ret != 0) {
				return ret;
			}
		}
		previous_rollback = step->step_id;
		queued = true;
	}
	if (!queued) {
		plan->state = PQCP_FLEET_PLAN_FAILED;
		plan->result = -ENOTRECOVERABLE;
		return refresh_plan_digest(plan);
	}
	plan->state = PQCP_FLEET_PLAN_ROLLING_BACK;
	ret = assign_waves(convergence);
	if (ret != 0) {
		return ret;
	}
	refresh_ready_steps(plan);
	update_plan_terminal_state(convergence);
	return refresh_plan_digest(plan);
}

static int fail_step_locked(
	struct pqcp_fleet_convergence *convergence,
	struct pqcp_fleet_plan_step *step,
	int result,
	enum pqcp_fleet_failure_disposition disposition,
	uint64_t now_ms)
{
	const struct pqcp_fleet_retry_policy *retry;
	uint64_t delay;
	uint64_t retry_at;
	int ret;

	if (step == NULL || result == 0 ||
	    !failure_disposition_valid(disposition) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	step->result = result;
	step->lease_expires_at_ms = 0U;
	step->acknowledgement_deadline_ms = 0U;
	switch (disposition) {
	case PQCP_FLEET_FAILURE_RETRY:
		retry = retry_for_step(convergence, step);
		if ((step->flags & PQCP_FLEET_STEP_ALLOW_RETRY) == 0U ||
		    step->attempts >= step->maximum_attempts) {
			step->state = PQCP_FLEET_STEP_FAILED;
			step->completed_at_ms = now_ms;
			break;
		}
		retry_delay(retry, step, &delay);
		ret = add_u64(now_ms, delay, &retry_at);
		if (ret != 0) {
			return ret;
		}
		step->state = PQCP_FLEET_STEP_RETRY_WAIT;
		step->next_retry_ms = retry_at;
		convergence->retry_count++;
		break;
	case PQCP_FLEET_FAILURE_ROLLBACK:
		step->state = PQCP_FLEET_STEP_FAILED;
		step->completed_at_ms = now_ms;
		ret = request_rollback_locked(
			convergence, step->step_id, now_ms);
		if (ret != 0) {
			return ret;
		}
		break;
	case PQCP_FLEET_FAILURE_BLOCK:
		step->state = PQCP_FLEET_STEP_BLOCKED;
		step->completed_at_ms = now_ms;
		break;
	case PQCP_FLEET_FAILURE_SUPERSEDE:
		step->state = PQCP_FLEET_STEP_SUPERSEDED;
		step->completed_at_ms = now_ms;
		break;
	case PQCP_FLEET_FAILURE_TERMINAL:
	default:
		step->state = PQCP_FLEET_STEP_FAILED;
		step->completed_at_ms = now_ms;
		break;
	}
	convergence->transition_count++;
	refresh_ready_steps(&convergence->plan);
	update_plan_terminal_state(convergence);
	return refresh_plan_digest(&convergence->plan);
}

int pqcp_fleet_convergence_fail(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t step_id,
	int result,
	enum pqcp_fleet_failure_disposition disposition,
	uint64_t now_ms)
{
	struct pqcp_fleet_plan_step *step;
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    step_id == 0U || result == 0 ||
	    !failure_disposition_valid(disposition)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = validate_lease_locked(
		convergence, lease_id, token, now_ms);
	step = step_by_id(&convergence->plan, step_id);
	if (ret == 0 &&
	    (step == NULL ||
	     (step->state != PQCP_FLEET_STEP_LEASED &&
	      step->state != PQCP_FLEET_STEP_APPLYING &&
	      step->state != PQCP_FLEET_STEP_AWAITING_ACK))) {
		ret = -EACCES;
	}
	if (ret == 0) {
		ret = fail_step_locked(
			convergence, step, result,
			disposition, now_ms);
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

int pqcp_fleet_convergence_request_rollback(
	struct pqcp_fleet_convergence *convergence,
	uint64_t lease_id,
	const uint8_t token[PQCP_FLEET_DIGEST_BYTES],
	uint32_t failed_step_id,
	uint64_t now_ms)
{
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    failed_step_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = validate_lease_locked(
		convergence, lease_id, token, now_ms);
	if (ret == 0) {
		ret = request_rollback_locked(
			convergence, failed_step_id, now_ms);
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

int pqcp_fleet_convergence_supersede(
	struct pqcp_fleet_convergence *convergence,
	uint64_t desired_generation,
	uint64_t now_ms)
{
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    desired_generation == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = internal_supersede(
		convergence, desired_generation, now_ms);
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

static int tick_locked(
	struct pqcp_fleet_convergence *convergence,
	uint64_t now_ms)
{
	struct pqcp_fleet_convergence_plan *plan =
		&convergence->plan;
	int first_error = 0;

	if (plan->state == PQCP_FLEET_PLAN_EMPTY ||
	    plan_terminal(plan->state)) {
		return 0;
	}
	if (now_ms >= plan->deadline_ms) {
		for (size_t index = 0U;
		     index < plan->step_count; ++index) {
			struct pqcp_fleet_plan_step *step =
				&plan->steps[index];

			if (!terminal_step_state(step->state)) {
				step->state = PQCP_FLEET_STEP_FAILED;
				step->result = -ETIMEDOUT;
				step->completed_at_ms = now_ms;
			}
		}
		plan->state = PQCP_FLEET_PLAN_FAILED;
		plan->result = -ETIMEDOUT;
		recompute_plan_counts(plan);
		return refresh_plan_digest(plan);
	}
	if (convergence->lease.active &&
	    now_ms >= convergence->lease.expires_at_ms) {
		convergence->lease.active = false;
		convergence->lease.revoked = true;
	}
	for (size_t index = 0U; index < plan->step_count; ++index) {
		struct pqcp_fleet_plan_step *step =
			&plan->steps[index];
		int ret = 0;

		if (step->state == PQCP_FLEET_STEP_RETRY_WAIT &&
		    now_ms >= step->next_retry_ms) {
			step->state = PQCP_FLEET_STEP_PENDING;
			step->next_retry_ms = 0U;
			convergence->transition_count++;
		} else if (step->state == PQCP_FLEET_STEP_LEASED &&
			   now_ms >= step->lease_expires_at_ms) {
			step->state = PQCP_FLEET_STEP_PENDING;
			step->leased_at_ms = 0U;
			step->lease_expires_at_ms = 0U;
			convergence->transition_count++;
		} else if (step->state ==
				   PQCP_FLEET_STEP_APPLYING &&
			   now_ms >= step->lease_expires_at_ms) {
			ret = fail_step_locked(
				convergence, step, -ETIMEDOUT,
				PQCP_FLEET_FAILURE_RETRY, now_ms);
		} else if (step->state ==
				   PQCP_FLEET_STEP_AWAITING_ACK &&
			   now_ms >=
				   step->acknowledgement_deadline_ms) {
			ret = fail_step_locked(
				convergence, step, -ETIMEDOUT,
				PQCP_FLEET_FAILURE_RETRY, now_ms);
		}
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
	}
	refresh_ready_steps(plan);
	update_plan_terminal_state(convergence);
	if (first_error == 0) {
		first_error = refresh_plan_digest(plan);
	}
	return first_error;
}

int pqcp_fleet_convergence_tick(
	struct pqcp_fleet_convergence *convergence,
	uint64_t now_ms)
{
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = tick_locked(convergence, now_ms);
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

int pqcp_fleet_convergence_wave(
	struct pqcp_fleet_convergence *convergence,
	uint32_t wave,
	struct pqcp_fleet_plan_wave *summary)
{
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    summary == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	recompute_wave_summaries(&convergence->plan);
	if (wave >= convergence->plan.wave_count) {
		ret = -ENOENT;
	} else {
		*summary = convergence->plan.waves[wave];
		ret = 0;
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

static int convergence_snapshot_digest(
	const struct pqcp_fleet_convergence_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t payload[SNAPSHOT_DIGEST_BYTES];
	struct convergence_writer writer;
	int ret;

	if (snapshot == NULL || digest == NULL ||
	    snapshot->schema_version !=
		    PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION ||
	    snapshot->sequence == 0U ||
	    snapshot->captured_at_ms == 0U ||
	    !plan_state_valid(snapshot->plan_state)) {
		return -EINVAL;
	}
	memset(payload, 0, sizeof(payload));
	writer_init(&writer, payload, sizeof(payload));
	writer_bytes(
		&writer,
		(const uint8_t *)"PQCP-FLEET-CONVERGENCE-SNAPSHOT-V1",
		34U);
	writer_u32(&writer, snapshot->schema_version);
	writer_u64(&writer, snapshot->sequence);
	writer_u64(&writer, snapshot->captured_at_ms);
	writer_u64(&writer, snapshot->plan_id);
	writer_u64(&writer, snapshot->plan_generation);
	writer_u64(&writer, snapshot->desired_generation);
	writer_u64(&writer, snapshot->observed_generation);
	writer_u32(&writer, (uint32_t)snapshot->plan_state);
	writer_u32(&writer, snapshot->total_steps);
	writer_u32(&writer, snapshot->pending_steps);
	writer_u32(&writer, snapshot->ready_steps);
	writer_u32(&writer, snapshot->active_steps);
	writer_u32(&writer, snapshot->retry_steps);
	writer_u32(&writer, snapshot->succeeded_steps);
	writer_u32(&writer, snapshot->failed_steps);
	writer_u32(&writer, snapshot->blocked_steps);
	writer_u32(&writer, snapshot->superseded_steps);
	writer_u32(&writer, snapshot->rollback_steps);
	writer_u32(&writer, snapshot->current_wave);
	writer_u64(&writer, snapshot->lease_id);
	writer_u64(&writer, snapshot->lease_expires_at_ms);
	writer_bytes(&writer, snapshot->plan_digest,
		     sizeof(snapshot->plan_digest));
	ret = writer.error;
	if (ret == 0) {
		ret = pqcp_fleet_sha256(
			payload, writer.offset, digest);
	}
	memset(payload, 0, sizeof(payload));
	return ret;
}

int pqcp_fleet_convergence_snapshot(
	struct pqcp_fleet_convergence *convergence,
	uint64_t now_ms,
	struct pqcp_fleet_convergence_snapshot *snapshot)
{
	uint32_t current_wave = UINT32_MAX;
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    now_ms == 0U || snapshot == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (convergence->snapshot_sequence == UINT64_MAX ||
	    convergence->plan.step_count > UINT32_MAX) {
		(void)k_mutex_unlock(&convergence->lock);
		return -EOVERFLOW;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->schema_version =
		PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION;
	snapshot->sequence = ++convergence->snapshot_sequence;
	snapshot->captured_at_ms = now_ms;
	snapshot->plan_id = convergence->plan.plan_id;
	snapshot->plan_generation =
		convergence->plan.generation;
	snapshot->desired_generation =
		convergence->plan.desired_generation;
	snapshot->observed_generation =
		convergence->plan.observed_generation;
	snapshot->plan_state = convergence->plan.state;
	snapshot->total_steps =
		(uint32_t)convergence->plan.step_count;
	for (size_t index = 0U;
	     index < convergence->plan.step_count; ++index) {
		const struct pqcp_fleet_plan_step *step =
			&convergence->plan.steps[index];

		if (!terminal_step_state(step->state) &&
		    step->wave < current_wave) {
			current_wave = step->wave;
		}
		switch (step->state) {
		case PQCP_FLEET_STEP_PENDING:
		case PQCP_FLEET_STEP_ROLLBACK_PENDING:
			snapshot->pending_steps++;
			break;
		case PQCP_FLEET_STEP_READY:
			snapshot->ready_steps++;
			break;
		case PQCP_FLEET_STEP_LEASED:
		case PQCP_FLEET_STEP_APPLYING:
		case PQCP_FLEET_STEP_AWAITING_ACK:
			snapshot->active_steps++;
			break;
		case PQCP_FLEET_STEP_RETRY_WAIT:
			snapshot->retry_steps++;
			break;
		case PQCP_FLEET_STEP_SUCCEEDED:
			snapshot->succeeded_steps++;
			break;
		case PQCP_FLEET_STEP_FAILED:
			snapshot->failed_steps++;
			break;
		case PQCP_FLEET_STEP_BLOCKED:
			snapshot->blocked_steps++;
			break;
		case PQCP_FLEET_STEP_SUPERSEDED:
			snapshot->superseded_steps++;
			break;
		case PQCP_FLEET_STEP_ROLLED_BACK:
			snapshot->rollback_steps++;
			break;
		default:
			break;
		}
	}
	snapshot->current_wave =
		current_wave == UINT32_MAX ? 0U : current_wave;
	if (convergence->lease.active) {
		snapshot->lease_id = convergence->lease.lease_id;
		snapshot->lease_expires_at_ms =
			convergence->lease.expires_at_ms;
	}
	memcpy(snapshot->plan_digest, convergence->plan.digest,
	       sizeof(snapshot->plan_digest));
	ret = convergence_snapshot_digest(
		snapshot, snapshot->digest);
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}

int pqcp_fleet_convergence_snapshot_verify(
	const struct pqcp_fleet_convergence_snapshot *snapshot)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	uint64_t total;
	int ret;

	if (snapshot == NULL) {
		return -EINVAL;
	}
	total = (uint64_t)snapshot->pending_steps +
		snapshot->ready_steps +
		snapshot->active_steps +
		snapshot->retry_steps +
		snapshot->succeeded_steps +
		snapshot->failed_steps +
		snapshot->blocked_steps +
		snapshot->superseded_steps +
		snapshot->rollback_steps;
	if (total != snapshot->total_steps) {
		return -EBADMSG;
	}
	ret = convergence_snapshot_digest(snapshot, digest);
	if (ret == 0 &&
	    !digest_equal(digest, snapshot->digest)) {
		ret = -EBADMSG;
	}
	memset(digest, 0, sizeof(digest));
	return ret;
}

static void reconcile_identity(
	const struct pqcp_fleet_resource_state *resource,
	struct pqcp_fleet_reconcile_state *state)
{
	if (resource == NULL ||
	    resource->key.kind != PQCP_FLEET_RESOURCE_IDENTITY) {
		return;
	}
	state->credential_epoch =
		resource->value.identity.credential_epoch;
	state->device_state =
		resource->value.identity.device_state;
	state->capabilities =
		resource->value.identity.capabilities;
	memcpy(state->credential_digest,
	       resource->value.identity.credential_digest,
	       sizeof(state->credential_digest));
}

static void reconcile_policy(
	const struct pqcp_fleet_resource_state *resource,
	struct pqcp_fleet_reconcile_state *state)
{
	if (resource == NULL ||
	    resource->key.kind != PQCP_FLEET_RESOURCE_POLICY) {
		return;
	}
	state->policy_epoch =
		resource->value.policy.policy_epoch;
	memcpy(state->policy_digest,
	       resource->value.policy.bundle_digest,
	       sizeof(state->policy_digest));
}

static void reconcile_revocation(
	const struct pqcp_fleet_resource_state *resource,
	struct pqcp_fleet_reconcile_state *state)
{
	if (resource == NULL ||
	    resource->key.kind != PQCP_FLEET_RESOURCE_REVOCATION) {
		return;
	}
	state->revocation_epoch =
		resource->value.revocation.revocation_epoch;
	if (resource->value.revocation.revoked) {
		state->device_state = PQCP_FLEET_DEVICE_REVOKED;
	}
}

static void reconcile_firmware(
	const struct pqcp_fleet_resource_state *resource,
	struct pqcp_fleet_reconcile_state *state)
{
	if (resource == NULL ||
	    resource->key.kind != PQCP_FLEET_RESOURCE_FIRMWARE) {
		return;
	}
	if (resource->value.firmware.version >
	    state->firmware_version) {
		state->firmware_version =
			resource->value.firmware.version;
	}
}

static int snapshot_to_reconcile(
	const struct pqcp_fleet_state_snapshot *snapshot,
	struct pqcp_fleet_reconcile_state *state)
{
	bool identity = false;
	bool policy = false;

	if (snapshot == NULL || state == NULL ||
	    pqcp_fleet_snapshot_verify(snapshot) != 0) {
		return -EINVAL;
	}
	memset(state, 0, sizeof(*state));
	state->device_state = PQCP_FLEET_DEVICE_FACTORY;
	state->firmware_version = 1U;
	for (size_t index = 0U; index < snapshot->count; ++index) {
		const struct pqcp_fleet_resource_state *resource =
			&snapshot->resources[index];

		switch (resource->key.kind) {
		case PQCP_FLEET_RESOURCE_IDENTITY:
			reconcile_identity(resource, state);
			identity = true;
			break;
		case PQCP_FLEET_RESOURCE_POLICY:
			reconcile_policy(resource, state);
			policy = true;
			break;
		case PQCP_FLEET_RESOURCE_REVOCATION:
			reconcile_revocation(resource, state);
			break;
		case PQCP_FLEET_RESOURCE_FIRMWARE:
			reconcile_firmware(resource, state);
			break;
		case PQCP_FLEET_RESOURCE_CHANNEL:
			if (resource->value.channel.
			    session_generation >
			    state->command_sequence) {
				state->command_sequence =
					resource->value.channel.
						session_generation;
			}
			break;
		case PQCP_FLEET_RESOURCE_RECOVERY:
			if (resource->value.recovery.state !=
			    PQCP_FLEET_RECOVERY_IDLE &&
			    resource->value.recovery.state !=
			    PQCP_FLEET_RECOVERY_COMPLETE) {
				state->device_state =
					PQCP_FLEET_DEVICE_RECOVERY;
			}
			break;
		default:
			break;
		}
	}
	if (!identity || !policy || state->credential_epoch == 0U ||
	    state->policy_epoch == 0U ||
	    digest_zero(state->credential_digest) ||
	    digest_zero(state->policy_digest)) {
		return -ENODATA;
	}
	return 0;
}

int pqcp_fleet_convergence_reconcile_compat(
	const struct pqcp_fleet_state_snapshot *desired,
	const struct pqcp_fleet_state_snapshot *observed,
	struct pqcp_fleet_reconcile_result *result)
{
	struct pqcp_fleet_reconcile_state local;
	struct pqcp_fleet_reconcile_state remote;
	int ret;

	if (result == NULL) {
		return -EINVAL;
	}
	ret = snapshot_to_reconcile(observed, &local);
	if (ret == 0) {
		ret = snapshot_to_reconcile(desired, &remote);
	}
	if (ret == 0) {
		ret = pqcp_fleet_reconcile(
			&local, &remote, result);
	}
	return ret;
}

static int lease_audit(
	const struct pqcp_fleet_convergence *convergence)
{
	uint8_t token[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (!convergence->lease.active &&
	    convergence->lease.lease_id == 0U) {
		return 0;
	}
	if (convergence->lease.lease_id == 0U ||
	    convergence->lease.plan_id !=
		    convergence->plan.plan_id ||
	    convergence->lease.plan_generation !=
		    convergence->plan.generation ||
	    convergence->lease.issued_at_ms == 0U ||
	    convergence->lease.expires_at_ms <=
		    convergence->lease.issued_at_ms ||
	    !text_valid(
		    convergence->lease.owner,
		    sizeof(convergence->lease.owner))) {
		return -EBADMSG;
	}
	ret = lease_token(
		&convergence->plan, &convergence->lease, token);
	if (ret == 0 &&
	    !digest_equal(token, convergence->lease.token)) {
		ret = -EBADMSG;
	}
	memset(token, 0, sizeof(token));
	return ret;
}

int pqcp_fleet_convergence_audit(
	struct pqcp_fleet_convergence *convergence)
{
	int ret;

	if (convergence == NULL || !convergence->initialized ||
	    convergence->schema_version !=
		    PQCP_FLEET_CONVERGENCE_SCHEMA_VERSION ||
	    convergence->model == NULL ||
	    !convergence->model->initialized ||
	    convergence_policy_validate(
		    &convergence->policy) != 0 ||
	    convergence->drift == NULL ||
	    convergence->drift_capacity == 0U ||
	    convergence->drift_count >
		    convergence->drift_capacity ||
	    convergence->desired_resources == NULL ||
	    convergence->desired_resource_capacity == 0U ||
	    convergence->observed_resources == NULL ||
	    convergence->observed_resource_capacity == 0U) {
		return -EINVAL;
	}
	ret = pqcp_fleet_desired_state_audit(
		convergence->model);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&convergence->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (convergence->plan.state != PQCP_FLEET_PLAN_EMPTY) {
		ret = pqcp_fleet_convergence_plan_verify(
			&convergence->plan);
	}
	if (ret == 0) {
		ret = lease_audit(convergence);
	}
	(void)k_mutex_unlock(&convergence->lock);
	return ret;
}
