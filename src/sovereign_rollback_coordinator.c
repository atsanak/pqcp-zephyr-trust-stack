/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Authorization-bound sovereign rollback execution.
 */

#include <errno.h>
#include <string.h>

#include "sovereign_policy_internal.h"

static int rollback_index(
	const struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollback_id)
{
	for (size_t index = 0U; index < coordinator->capacity; ++index) {
		if (coordinator->plans[index].occupied &&
		    coordinator->plans[index].rollback_id == rollback_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_rollback_index(
	const struct pqcp_sovereign_rollback_coordinator *coordinator)
{
	for (size_t index = 0U; index < coordinator->capacity; ++index) {
		if (!coordinator->plans[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_sovereign_rollback_coordinator_init(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	struct pqcp_sovereign_rollback_plan *plans,
	size_t capacity)
{
	if (coordinator == NULL || plans == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(coordinator, 0, sizeof(*coordinator));
	memset(plans, 0, capacity * sizeof(plans[0]));
	coordinator->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	coordinator->plans = plans;
	coordinator->capacity = capacity;
	coordinator->next_rollback_id = 1U;
	k_mutex_init(&coordinator->lock);
	coordinator->initialized = true;
	return 0;
}

int pqcp_sovereign_rollback_authorize(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollout_id,
	const char *current_artifact_id,
	const char *target_artifact_id,
	uint64_t policy_epoch,
	uint32_t required_steps,
	uint32_t maximum_failures,
	const uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t deadline_ms,
	struct pqcp_sovereign_rollback_plan **plan)
{
	struct pqcp_sovereign_rollback_plan *entry;
	int index;

	if (coordinator == NULL || !coordinator->initialized ||
	    rollout_id == 0U ||
	    !pqcp_sovereign_policy_text_valid(
		    current_artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_policy_text_valid(
		    target_artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    strcmp(current_artifact_id, target_artifact_id) == 0 ||
	    policy_epoch == 0U || required_steps == 0U ||
	    maximum_failures >= required_steps ||
	    authorization_digest == NULL ||
	    pqcp_sovereign_policy_all_zero(
		    authorization_digest, PQCP_SOVEREIGN_DIGEST_BYTES) ||
	    now_ms == 0U || deadline_ms <= now_ms || plan == NULL) {
		return -EINVAL;
	}
	*plan = NULL;
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	index = free_rollback_index(coordinator);
	if (index < 0) {
		k_mutex_unlock(&coordinator->lock);
		return -ENOSPC;
	}
	entry = &coordinator->plans[index];
	memset(entry, 0, sizeof(*entry));
	entry->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	entry->rollback_id =
		pqcp_sovereign_policy_next_id(
			&coordinator->next_rollback_id);
	entry->rollout_id = rollout_id;
	(void)pqcp_sovereign_policy_copy_text(
		entry->current_artifact_id,
		sizeof(entry->current_artifact_id),
		current_artifact_id);
	(void)pqcp_sovereign_policy_copy_text(
		entry->target_artifact_id,
		sizeof(entry->target_artifact_id),
		target_artifact_id);
	entry->authorized_at_ms = now_ms;
	entry->deadline_ms = deadline_ms;
	entry->policy_epoch = policy_epoch;
	entry->required_steps = required_steps;
	entry->maximum_failures = maximum_failures;
	entry->state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	memcpy(entry->authorization_digest, authorization_digest,
	       sizeof(entry->authorization_digest));
	entry->occupied = true;
	*plan = entry;
	k_mutex_unlock(&coordinator->lock);
	return 0;
}

int pqcp_sovereign_rollback_record_step(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollback_id,
	uint32_t step,
	bool success,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	struct pqcp_sovereign_rollback_plan *plan;
	uint32_t next_step;
	int index;

	if (coordinator == NULL || !coordinator->initialized ||
	    rollback_id == 0U || evidence_digest == NULL ||
	    pqcp_sovereign_policy_all_zero(
		    evidence_digest, PQCP_SOVEREIGN_DIGEST_BYTES)) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	index = rollback_index(coordinator, rollback_id);
	if (index < 0) {
		k_mutex_unlock(&coordinator->lock);
		return -ENOENT;
	}
	plan = &coordinator->plans[index];
	if (plan->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		k_mutex_unlock(&coordinator->lock);
		return -EPERM;
	}
	next_step = plan->completed_steps + plan->failed_steps;
	if (step != next_step || step >= plan->required_steps) {
		k_mutex_unlock(&coordinator->lock);
		return -EILSEQ;
	}
	memcpy(plan->evidence_digest, evidence_digest,
	       sizeof(plan->evidence_digest));
	if (success) {
		plan->completed_steps++;
	} else {
		plan->failed_steps++;
		if (plan->failed_steps > plan->maximum_failures) {
			plan->state =
				PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED;
			coordinator->failed_count =
				pqcp_sovereign_policy_add_u64(
					coordinator->failed_count, 1U);
		}
	}
	k_mutex_unlock(&coordinator->lock);
	return 0;
}

int pqcp_sovereign_rollback_complete(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollback_id)
{
	struct pqcp_sovereign_rollback_plan *plan;
	int index;

	if (coordinator == NULL || !coordinator->initialized ||
	    rollback_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	index = rollback_index(coordinator, rollback_id);
	if (index < 0) {
		k_mutex_unlock(&coordinator->lock);
		return -ENOENT;
	}
	plan = &coordinator->plans[index];
	if (plan->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
	    plan->completed_steps + plan->failed_steps !=
		    plan->required_steps ||
	    plan->failed_steps > plan->maximum_failures) {
		k_mutex_unlock(&coordinator->lock);
		return -EPERM;
	}
	plan->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
	coordinator->completed_count =
		pqcp_sovereign_policy_add_u64(
			coordinator->completed_count, 1U);
	k_mutex_unlock(&coordinator->lock);
	return 0;
}

int pqcp_sovereign_rollback_tick(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t now_ms,
	uint32_t *failed_count)
{
	uint32_t count = 0U;

	if (coordinator == NULL || !coordinator->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	for (size_t index = 0U; index < coordinator->capacity; ++index) {
		struct pqcp_sovereign_rollback_plan *plan =
			&coordinator->plans[index];

		if (plan->occupied &&
		    plan->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
		    now_ms >= plan->deadline_ms) {
			plan->state =
				PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
			coordinator->failed_count =
				pqcp_sovereign_policy_add_u64(
					coordinator->failed_count, 1U);
			count++;
		}
	}
	k_mutex_unlock(&coordinator->lock);
	if (failed_count != NULL) {
		*failed_count = count;
	}
	return 0;
}

int pqcp_sovereign_rollback_coordinator_audit(
	struct pqcp_sovereign_rollback_coordinator *coordinator)
{
	int ret = 0;

	if (coordinator == NULL || !coordinator->initialized ||
	    coordinator->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    coordinator->plans == NULL || coordinator->capacity == 0U ||
	    coordinator->next_rollback_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&coordinator->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < coordinator->capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_rollback_plan *plan =
			&coordinator->plans[index];

		if (!plan->occupied) {
			continue;
		}
		if (plan->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    plan->rollback_id == 0U || plan->rollout_id == 0U ||
		    plan->policy_epoch == 0U ||
		    plan->required_steps == 0U ||
		    plan->maximum_failures >= plan->required_steps ||
		    plan->completed_steps + plan->failed_steps >
			    plan->required_steps ||
		    plan->deadline_ms <= plan->authorized_at_ms ||
		    pqcp_sovereign_policy_all_zero(
			    plan->authorization_digest,
			    sizeof(plan->authorization_digest))) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < coordinator->capacity; ++other) {
			if (coordinator->plans[other].occupied &&
			    coordinator->plans[other].rollback_id ==
				    plan->rollback_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&coordinator->lock);
	return ret;
}
