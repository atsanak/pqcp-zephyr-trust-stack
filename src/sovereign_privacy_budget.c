/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Differential-privacy budget accounting with fixed windows and fail-closed
 * composition limits.
 */

#include "sovereign_privacy_internal.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

static ssize_t budget_index_locked(
	const struct pqcp_sovereign_privacy_budget_manager *manager,
	const char *budget_id)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		if (manager->budgets[index].occupied &&
		    strcmp(manager->budgets[index].budget_id,
			   budget_id) == 0) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static ssize_t free_budget_index_locked(
	const struct pqcp_sovereign_privacy_budget_manager *manager)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		if (!manager->budgets[index].occupied) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static bool budget_valid(
	const struct pqcp_sovereign_privacy_budget *budget,
	uint64_t now_ms)
{
	if (budget == NULL || now_ms == 0U ||
	    !pqcp_sovereign_privacy_text_valid(
		    budget->budget_id, sizeof(budget->budget_id)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    budget->tenant_id, sizeof(budget->tenant_id)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    budget->subject_scope,
		    sizeof(budget->subject_scope)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    budget->purpose, sizeof(budget->purpose)) ||
	    budget->window_ms == 0U ||
	    budget->policy_epoch == 0U ||
	    budget->epsilon_limit_micros == 0U ||
	    budget->delta_limit_nanos == 0U ||
	    budget->query_limit == 0U ||
	    budget->epsilon_used_micros >
		    budget->epsilon_limit_micros ||
	    budget->delta_used_nanos >
		    budget->delta_limit_nanos ||
	    budget->query_count > budget->query_limit ||
	    budget->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		return false;
	}
	return true;
}

static uint32_t budget_generation(uint32_t *next)
{
	uint32_t value = *next;

	if (value == 0U) {
		value = 1U;
	}
	*next = value == UINT32_MAX ? 1U : value + 1U;
	return value;
}

static bool window_elapsed(
	const struct pqcp_sovereign_privacy_budget *budget,
	uint64_t now_ms)
{
	if (now_ms < budget->window_started_ms) {
		return false;
	}
	return now_ms - budget->window_started_ms >=
	       budget->window_ms;
}

static void reset_window(
	struct pqcp_sovereign_privacy_budget *budget,
	uint64_t now_ms)
{
	uint64_t elapsed;
	uint64_t windows;
	uint64_t advance;

	if (budget->window_started_ms == 0U ||
	    now_ms < budget->window_started_ms) {
		budget->window_started_ms = now_ms;
	} else {
		elapsed = now_ms - budget->window_started_ms;
		windows = elapsed / budget->window_ms;
		if (windows == 0U) {
			windows = 1U;
		}
		if (windows > UINT64_MAX / budget->window_ms) {
			budget->window_started_ms = now_ms;
		} else {
			advance = windows * budget->window_ms;
			if (advance >
			    UINT64_MAX - budget->window_started_ms) {
				budget->window_started_ms = now_ms;
			} else {
				budget->window_started_ms += advance;
			}
		}
	}
	budget->epsilon_used_micros = 0U;
	budget->delta_used_nanos = 0U;
	budget->query_count = 0U;
}

int pqcp_sovereign_privacy_budget_manager_init(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	struct pqcp_sovereign_privacy_budget *budgets,
	size_t capacity)
{
	if (manager == NULL || budgets == NULL || capacity == 0U ||
	    capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(budgets, 0, capacity * sizeof(*budgets));
	manager->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	manager->budgets = budgets;
	manager->capacity = capacity;
	manager->next_generation = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_privacy_budget_put(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	const struct pqcp_sovereign_privacy_budget *budget,
	uint64_t now_ms)
{
	struct pqcp_sovereign_privacy_budget candidate;
	ssize_t index;

	if (manager == NULL || !manager->initialized ||
	    !budget_valid(budget, now_ms)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = budget_index_locked(manager, budget->budget_id);
	if (index >= 0) {
		const struct pqcp_sovereign_privacy_budget *existing =
			&manager->budgets[index];

		if (strcmp(existing->tenant_id, budget->tenant_id) != 0 ||
		    strcmp(existing->subject_scope,
			   budget->subject_scope) != 0 ||
		    strcmp(existing->purpose, budget->purpose) != 0) {
			manager->denied_count++;
			k_mutex_unlock(&manager->lock);
			return -EACCES;
		}
		if (budget->policy_epoch <= existing->policy_epoch) {
			manager->denied_count++;
			k_mutex_unlock(&manager->lock);
			return -ESTALE;
		}
	} else {
		index = free_budget_index_locked(manager);
		if (index < 0) {
			manager->denied_count++;
			k_mutex_unlock(&manager->lock);
			return -ENOSPC;
		}
	}
	candidate = *budget;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.generation = budget_generation(
		&manager->next_generation);
	candidate.window_started_ms = now_ms;
	candidate.epsilon_used_micros = 0U;
	candidate.delta_used_nanos = 0U;
	candidate.query_count = 0U;
	candidate.occupied = true;
	manager->budgets[index] = candidate;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_privacy_budget_consume(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	const char *budget_id,
	uint64_t epsilon_micros,
	uint64_t delta_nanos,
	uint64_t query_count,
	uint64_t policy_epoch,
	uint64_t now_ms)
{
	struct pqcp_sovereign_privacy_budget *budget;
	ssize_t index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    budget_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    epsilon_micros == 0U || delta_nanos == 0U ||
	    query_count == 0U || policy_epoch == 0U ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = budget_index_locked(manager, budget_id);
	if (index < 0) {
		ret = -ENOENT;
		goto out;
	}
	budget = &manager->budgets[index];
	if (budget->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = -EACCES;
		goto out;
	}
	if (budget->policy_epoch != policy_epoch) {
		ret = -ESTALE;
		goto out;
	}
	if (now_ms < budget->window_started_ms) {
		ret = -ETIME;
		goto out;
	}
	if (window_elapsed(budget, now_ms)) {
		reset_window(budget, now_ms);
	}
	if (epsilon_micros >
		    budget->epsilon_limit_micros -
			    budget->epsilon_used_micros ||
	    delta_nanos >
		    budget->delta_limit_nanos -
			    budget->delta_used_nanos ||
	    query_count >
		    budget->query_limit - budget->query_count) {
		ret = -EDQUOT;
		goto out;
	}
	budget->epsilon_used_micros += epsilon_micros;
	budget->delta_used_nanos += delta_nanos;
	budget->query_count += query_count;
	manager->accepted_count++;
out:
	if (ret != 0) {
		manager->denied_count++;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_privacy_budget_remaining(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	const char *budget_id,
	uint64_t now_ms,
	uint64_t *epsilon_micros,
	uint64_t *delta_nanos,
	uint64_t *query_count)
{
	struct pqcp_sovereign_privacy_budget *budget;
	ssize_t index;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    budget_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    now_ms == 0U || epsilon_micros == NULL ||
	    delta_nanos == NULL || query_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = budget_index_locked(manager, budget_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	budget = &manager->budgets[index];
	if (budget->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	if (now_ms < budget->window_started_ms) {
		k_mutex_unlock(&manager->lock);
		return -ETIME;
	}
	if (window_elapsed(budget, now_ms)) {
		reset_window(budget, now_ms);
	}
	*epsilon_micros =
		budget->epsilon_limit_micros -
		budget->epsilon_used_micros;
	*delta_nanos =
		budget->delta_limit_nanos -
		budget->delta_used_nanos;
	*query_count =
		budget->query_limit - budget->query_count;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_privacy_budget_tick(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	uint64_t now_ms,
	uint32_t *reset_count)
{
	uint32_t resets = 0U;
	size_t index;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || reset_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U; index < manager->capacity; ++index) {
		struct pqcp_sovereign_privacy_budget *budget =
			&manager->budgets[index];

		if (!budget->occupied ||
		    budget->state !=
			    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    now_ms < budget->window_started_ms ||
		    !window_elapsed(budget, now_ms)) {
			continue;
		}
		reset_window(budget, now_ms);
		resets++;
	}
	*reset_count = resets;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_privacy_budget_manager_audit(
	struct pqcp_sovereign_privacy_budget_manager *manager)
{
	size_t index;
	size_t other;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    manager->budgets == NULL || manager->capacity == 0U ||
	    manager->next_generation == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U; index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_privacy_budget *budget =
			&manager->budgets[index];

		if (!budget->occupied) {
			continue;
		}
		if (budget->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    budget->generation == 0U ||
		    !budget_valid(budget,
				  budget->window_started_ms == 0U ?
					  1U :
					  budget->window_started_ms) ||
		    budget->epsilon_used_micros >
			    budget->epsilon_limit_micros ||
		    budget->delta_used_nanos >
			    budget->delta_limit_nanos ||
		    budget->query_count > budget->query_limit) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->budgets[other].occupied &&
			    strcmp(budget->budget_id,
				   manager->budgets[other].budget_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
