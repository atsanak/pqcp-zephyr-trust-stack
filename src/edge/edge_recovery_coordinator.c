/*
 * SPDX-License-Identifier: MIT
 *
 * Evidence-chained workload recovery coordination.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static uint32_t required_step_mask(uint32_t required_steps)
{
	return required_steps >= 32U ?
		UINT32_MAX :
		(1U << required_steps) - 1U;
}

static bool phase_valid(enum pqcp_edge_recovery_phase phase)
{
	return phase >= PQCP_EDGE_RECOVERY_IDLE &&
	       phase <= PQCP_EDGE_RECOVERY_FAILED;
}

static int plan_index(
	const struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t recovery_id)
{
	for (size_t index = 0U;
	     index < coordinator->capacity; ++index) {
		if (coordinator->plans[index].occupied &&
		    coordinator->plans[index].recovery_id ==
			    recovery_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_plan_index(
	const struct pqcp_edge_recovery_coordinator *coordinator)
{
	for (size_t index = 0U;
	     index < coordinator->capacity; ++index) {
		if (!coordinator->plans[index].occupied ||
		    coordinator->plans[index].phase ==
			    PQCP_EDGE_RECOVERY_COMPLETE ||
		    coordinator->plans[index].phase ==
			    PQCP_EDGE_RECOVERY_FAILED) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool transition_allowed(
	enum pqcp_edge_recovery_phase current,
	enum pqcp_edge_recovery_phase next)
{
	switch (current) {
	case PQCP_EDGE_RECOVERY_AUTHORIZED:
		return next ==
			       PQCP_EDGE_RECOVERY_CHECKPOINTING ||
		       next == PQCP_EDGE_RECOVERY_FAILED;
	case PQCP_EDGE_RECOVERY_CHECKPOINTING:
		return next == PQCP_EDGE_RECOVERY_ISOLATING ||
		       next == PQCP_EDGE_RECOVERY_FAILED;
	case PQCP_EDGE_RECOVERY_ISOLATING:
		return next == PQCP_EDGE_RECOVERY_RESTORING ||
		       next == PQCP_EDGE_RECOVERY_FAILED;
	case PQCP_EDGE_RECOVERY_RESTORING:
		return next == PQCP_EDGE_RECOVERY_VALIDATING ||
		       next == PQCP_EDGE_RECOVERY_FAILED;
	case PQCP_EDGE_RECOVERY_VALIDATING:
		return next == PQCP_EDGE_RECOVERY_REJOINING ||
		       next == PQCP_EDGE_RECOVERY_RESTORING ||
		       next == PQCP_EDGE_RECOVERY_FAILED;
	case PQCP_EDGE_RECOVERY_REJOINING:
		return next == PQCP_EDGE_RECOVERY_COMPLETE ||
		       next == PQCP_EDGE_RECOVERY_FAILED;
	default:
		return false;
	}
}

static int chain_evidence(
	struct pqcp_edge_recovery_plan *plan,
	uint32_t step,
	bool success,
	const uint8_t evidence[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[8];
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	const uint8_t *parts[3];
	size_t lengths[3];
	int ret;

	pqcp_edge_internal_write_u32(numeric, step);
	pqcp_edge_internal_write_u32(
		numeric + 4U, success ? 1U : 0U);
	parts[0] = plan->evidence_digest;
	lengths[0] = sizeof(plan->evidence_digest);
	parts[1] = numeric;
	lengths[1] = sizeof(numeric);
	parts[2] = evidence;
	lengths[2] = PQCP_EDGE_DIGEST_BYTES;
	ret = pqcp_edge_internal_sha256_parts(
		parts, lengths, 3U, digest);
	if (ret == 0) {
		memcpy(plan->evidence_digest, digest,
		       sizeof(digest));
	}
	return ret;
}

int pqcp_edge_recovery_coordinator_init(
	struct pqcp_edge_recovery_coordinator *coordinator,
	struct pqcp_edge_recovery_plan *plans,
	size_t capacity)
{
	if (coordinator == NULL || plans == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(coordinator, 0, sizeof(*coordinator));
	memset(plans, 0, capacity * sizeof(*plans));
	coordinator->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	coordinator->plans = plans;
	coordinator->capacity = capacity;
	coordinator->next_recovery_id = 1U;
	k_mutex_init(&coordinator->lock);
	coordinator->initialized = true;
	return 0;
}

int pqcp_edge_recovery_authorize(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t incident_id,
	const char *subject_id,
	uint32_t required_steps,
	uint32_t maximum_failures,
	const uint8_t authorization_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_recovery_plan **plan)
{
	struct pqcp_edge_recovery_plan candidate;
	int index;
	int ret;

	if (coordinator == NULL || !coordinator->initialized ||
	    incident_id == 0U ||
	    !pqcp_edge_internal_text_valid(
		    subject_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    required_steps == 0U || required_steps > 32U ||
	    maximum_failures == 0U ||
	    authorization_digest == NULL ||
	    pqcp_edge_internal_all_zero(
		    authorization_digest,
		    PQCP_EDGE_DIGEST_BYTES) ||
	    expires_at_ms <= now_ms || plan == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	index = free_plan_index(coordinator);
	if (index < 0) {
		*plan = NULL;
		k_mutex_unlock(&coordinator->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.recovery_id =
		pqcp_edge_internal_next_identifier(
			&coordinator->next_recovery_id);
	candidate.incident_id = incident_id;
	ret = pqcp_edge_internal_copy_text(
		candidate.subject_id,
		sizeof(candidate.subject_id), subject_id);
	candidate.phase = PQCP_EDGE_RECOVERY_AUTHORIZED;
	candidate.authorized_at_ms = now_ms;
	candidate.updated_at_ms = now_ms;
	candidate.expires_at_ms = expires_at_ms;
	candidate.required_steps = required_steps;
	candidate.maximum_failures = maximum_failures;
	memcpy(candidate.authorization_digest,
	       authorization_digest,
	       sizeof(candidate.authorization_digest));
	candidate.occupied = true;
	if (ret == 0) {
		coordinator->plans[index] = candidate;
		*plan = &coordinator->plans[index];
	} else {
		*plan = NULL;
	}
	k_mutex_unlock(&coordinator->lock);
	return ret;
}

int pqcp_edge_recovery_advance(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t recovery_id,
	enum pqcp_edge_recovery_phase phase,
	uint64_t now_ms)
{
	struct pqcp_edge_recovery_plan *plan;
	int index;
	int ret = 0;

	if (coordinator == NULL || !coordinator->initialized ||
	    recovery_id == 0U || !phase_valid(phase) ||
	    phase == PQCP_EDGE_RECOVERY_IDLE) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	index = plan_index(coordinator, recovery_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	plan = &coordinator->plans[index];
	if (plan->phase == PQCP_EDGE_RECOVERY_COMPLETE ||
	    plan->phase == PQCP_EDGE_RECOVERY_FAILED) {
		/* Terminal phases are immutable. */
		ret = plan->phase == phase ? -EALREADY : -EPERM;
		goto out;
	}
	if (plan->expires_at_ms <= now_ms) {
		plan->phase = PQCP_EDGE_RECOVERY_FAILED;
		plan->updated_at_ms = now_ms;
		++coordinator->failed_count;
		ret = -ETIMEDOUT;
		goto out;
	}
	if (!transition_allowed(plan->phase, phase)) {
		ret = plan->phase == phase ? -EALREADY : -EPERM;
		goto out;
	}
	if (phase == PQCP_EDGE_RECOVERY_ISOLATING &&
	    pqcp_edge_internal_all_zero(
		    plan->checkpoint_digest,
		    sizeof(plan->checkpoint_digest))) {
		ret = -EAGAIN;
		goto out;
	}
	if (phase == PQCP_EDGE_RECOVERY_COMPLETE &&
	    (plan->completed_steps !=
		     required_step_mask(
			     plan->required_steps) ||
	     plan->failed_steps != 0U)) {
		ret = -EAGAIN;
		goto out;
	}
	plan->phase = phase;
	plan->updated_at_ms = now_ms;
	if (phase == PQCP_EDGE_RECOVERY_COMPLETE) {
		++coordinator->completed_count;
	} else if (phase == PQCP_EDGE_RECOVERY_FAILED) {
		++coordinator->failed_count;
	}
out:
	k_mutex_unlock(&coordinator->lock);
	return ret;
}

int pqcp_edge_recovery_record_step(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t recovery_id,
	uint32_t step,
	bool success,
	const uint8_t evidence[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_edge_recovery_plan *plan;
	uint32_t bit;
	int index;
	int ret = 0;

	if (coordinator == NULL || !coordinator->initialized ||
	    recovery_id == 0U || evidence == NULL ||
	    pqcp_edge_internal_all_zero(
		    evidence, PQCP_EDGE_DIGEST_BYTES)) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	index = plan_index(coordinator, recovery_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	plan = &coordinator->plans[index];
	if (step >= plan->required_steps ||
	    plan->phase < PQCP_EDGE_RECOVERY_ISOLATING ||
	    plan->phase > PQCP_EDGE_RECOVERY_REJOINING) {
		ret = -EINVAL;
		goto out;
	}
	bit = 1U << step;
	if ((plan->completed_steps & bit) != 0U) {
		ret = -EALREADY;
		goto out;
	}
	ret = chain_evidence(plan, step, success, evidence);
	if (ret != 0) {
		goto out;
	}
	if (success) {
		plan->completed_steps |= bit;
		plan->failed_steps &= ~bit;
	} else {
		plan->failed_steps |= bit;
		if (__builtin_popcount(plan->failed_steps) >=
		    plan->maximum_failures) {
			plan->phase =
				PQCP_EDGE_RECOVERY_FAILED;
			++coordinator->failed_count;
		}
	}
	plan->updated_at_ms = now_ms;
out:
	k_mutex_unlock(&coordinator->lock);
	return ret;
}

int pqcp_edge_recovery_checkpoint(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t recovery_id,
	const uint8_t checkpoint[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_edge_recovery_plan *plan;
	int index;
	int ret = 0;

	if (coordinator == NULL || !coordinator->initialized ||
	    recovery_id == 0U || checkpoint == NULL ||
	    pqcp_edge_internal_all_zero(
		    checkpoint, PQCP_EDGE_DIGEST_BYTES)) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	index = plan_index(coordinator, recovery_id);
	if (index < 0) {
		ret = index;
	} else {
		plan = &coordinator->plans[index];
		if (plan->phase !=
		    PQCP_EDGE_RECOVERY_CHECKPOINTING) {
			ret = -EPERM;
		} else {
			memcpy(plan->checkpoint_digest,
			       checkpoint,
			       sizeof(plan->checkpoint_digest));
			plan->updated_at_ms = now_ms;
		}
	}
	k_mutex_unlock(&coordinator->lock);
	return ret;
}

int pqcp_edge_recovery_tick(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t now_ms,
	uint32_t *failed_count)
{
	uint32_t failed = 0U;

	if (coordinator == NULL || !coordinator->initialized ||
	    failed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < coordinator->capacity; ++index) {
		struct pqcp_edge_recovery_plan *plan =
			&coordinator->plans[index];

		if (plan->occupied &&
		    plan->phase != PQCP_EDGE_RECOVERY_COMPLETE &&
		    plan->phase != PQCP_EDGE_RECOVERY_FAILED &&
		    plan->expires_at_ms <= now_ms) {
			plan->phase = PQCP_EDGE_RECOVERY_FAILED;
			plan->updated_at_ms = now_ms;
			++failed;
		}
	}
	coordinator->failed_count =
		pqcp_edge_internal_saturating_add_u64(
			coordinator->failed_count, failed);
	k_mutex_unlock(&coordinator->lock);
	*failed_count = failed;
	return 0;
}

int pqcp_edge_recovery_coordinator_audit(
	struct pqcp_edge_recovery_coordinator *coordinator)
{
	int ret = 0;

	if (coordinator == NULL ||
	    !coordinator->initialized ||
	    coordinator->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    coordinator->plans == NULL ||
	    coordinator->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < coordinator->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_recovery_plan *plan =
			&coordinator->plans[index];
		uint32_t valid_mask;

		if (!plan->occupied) {
			continue;
		}
		valid_mask =
			required_step_mask(
				plan->required_steps);
		if (plan->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    plan->recovery_id == 0U ||
		    plan->incident_id == 0U ||
		    !pqcp_edge_internal_text_valid(
			    plan->subject_id,
			    sizeof(plan->subject_id)) ||
		    !phase_valid(plan->phase) ||
		    plan->phase == PQCP_EDGE_RECOVERY_IDLE ||
		    plan->required_steps == 0U ||
		    plan->required_steps > 32U ||
		    (plan->completed_steps & ~valid_mask) != 0U ||
		    (plan->failed_steps & ~valid_mask) != 0U ||
		    (plan->completed_steps &
		     plan->failed_steps) != 0U ||
		    plan->expires_at_ms <=
			    plan->authorized_at_ms ||
		    pqcp_edge_internal_all_zero(
			    plan->authorization_digest,
			    sizeof(plan->authorization_digest))) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&coordinator->lock);
	return ret;
}
