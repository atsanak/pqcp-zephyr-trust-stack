/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Windowed resource budgets and pressure actions.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool resource_valid(
	enum pqcp_edge_resource_type resource)
{
	return resource >= PQCP_EDGE_RESOURCE_MEMORY_BYTES &&
	       resource < PQCP_EDGE_RESOURCE_COUNT;
}

static int budget_index(
	const struct pqcp_edge_resource_monitor *monitor,
	const char *subject_id)
{
	for (size_t index = 0U;
	     index < monitor->capacity; ++index) {
		if (monitor->budgets[index].occupied &&
		    strcmp(monitor->budgets[index].subject_id,
			   subject_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_budget_index(
	const struct pqcp_edge_resource_monitor *monitor)
{
	for (size_t index = 0U;
	     index < monitor->capacity; ++index) {
		if (!monitor->budgets[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool budget_valid(
	const struct pqcp_edge_resource_budget *budget)
{
	if (budget == NULL ||
	    !pqcp_edge_internal_text_valid(
		    budget->subject_id,
		    sizeof(budget->subject_id)) ||
	    budget->window_ms == 0U) {
		return false;
	}
	for (size_t index = 0U;
	     index < PQCP_EDGE_RESOURCE_COUNT; ++index) {
		if (budget->limit[index] == 0U ||
		    budget->warning[index] >
			    budget->limit[index] ||
		    budget->used[index] >
			    budget->limit[index]) {
			return false;
		}
	}
	return true;
}

static enum pqcp_edge_resource_action derive_action(
	const struct pqcp_edge_resource_budget *budget)
{
	bool warning = false;

	for (size_t index = 0U;
	     index < PQCP_EDGE_RESOURCE_COUNT; ++index) {
		if (budget->used[index] >= budget->limit[index]) {
			if (index == PQCP_EDGE_RESOURCE_MEMORY_BYTES ||
			    index ==
				    PQCP_EDGE_RESOURCE_STORAGE_BYTES) {
				return PQCP_EDGE_RESOURCE_ACTION_COMPACT;
			}
			return PQCP_EDGE_RESOURCE_ACTION_SHED;
		}
		if (budget->used[index] >=
		    budget->warning[index]) {
			warning = true;
		}
	}
	return warning ? PQCP_EDGE_RESOURCE_ACTION_THROTTLE :
		PQCP_EDGE_RESOURCE_ACTION_NONE;
}

static void refresh_window(
	struct pqcp_edge_resource_budget *budget,
	uint64_t now_ms)
{
	if (now_ms - budget->window_started_ms <
	    budget->window_ms) {
		return;
	}
	memset(budget->used, 0, sizeof(budget->used));
	budget->window_started_ms = now_ms;
	budget->action = PQCP_EDGE_RESOURCE_ACTION_NONE;
}

int pqcp_edge_resource_monitor_init(
	struct pqcp_edge_resource_monitor *monitor,
	struct pqcp_edge_resource_budget *budgets,
	size_t capacity)
{
	if (monitor == NULL || budgets == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(monitor, 0, sizeof(*monitor));
	memset(budgets, 0, capacity * sizeof(*budgets));
	monitor->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	monitor->budgets = budgets;
	monitor->capacity = capacity;
	k_mutex_init(&monitor->lock);
	monitor->initialized = true;
	return 0;
}

int pqcp_edge_resource_budget_put(
	struct pqcp_edge_resource_monitor *monitor,
	const struct pqcp_edge_resource_budget *budget)
{
	struct pqcp_edge_resource_budget candidate;
	int index;
	int ret = 0;

	if (monitor == NULL || !monitor->initialized ||
	    !budget_valid(budget)) {
		return -EINVAL;
	}
	k_mutex_lock(&monitor->lock, K_FOREVER);
	index = budget_index(monitor, budget->subject_id);
	if (index == -ENOENT) {
		index = free_budget_index(monitor);
	}
	if (index < 0) {
		ret = index;
		goto out;
	}
	candidate = *budget;
	candidate.occupied = true;
	if (monitor->budgets[index].occupied) {
		for (size_t resource = 0U;
		     resource < PQCP_EDGE_RESOURCE_COUNT;
		     ++resource) {
			candidate.used[resource] =
				monitor->budgets[index].
					used[resource];
			if (candidate.used[resource] >
			    candidate.limit[resource]) {
				ret = -EDQUOT;
				goto out;
			}
		}
	}
	candidate.action = derive_action(&candidate);
	monitor->budgets[index] = candidate;
out:
	k_mutex_unlock(&monitor->lock);
	return ret;
}

int pqcp_edge_resource_reserve(
	struct pqcp_edge_resource_monitor *monitor,
	const char *subject_id,
	enum pqcp_edge_resource_type resource,
	uint64_t amount,
	uint64_t now_ms,
	enum pqcp_edge_resource_action *action)
{
	struct pqcp_edge_resource_budget *budget;
	uint64_t proposed;
	int index;
	int ret = 0;

	if (monitor == NULL || !monitor->initialized ||
	    subject_id == NULL || !resource_valid(resource) ||
	    amount == 0U || action == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&monitor->lock, K_FOREVER);
	index = budget_index(monitor, subject_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	budget = &monitor->budgets[index];
	refresh_window(budget, now_ms);
	proposed = pqcp_edge_internal_saturating_add_u64(
		budget->used[resource], amount);
	if (proposed > budget->limit[resource]) {
		budget->violation_count =
			pqcp_edge_internal_saturating_add_u64(
				budget->violation_count, 1U);
		budget->action =
			resource ==
				PQCP_EDGE_RESOURCE_MEMORY_BYTES ||
			resource ==
				PQCP_EDGE_RESOURCE_STORAGE_BYTES ?
				PQCP_EDGE_RESOURCE_ACTION_COMPACT :
				PQCP_EDGE_RESOURCE_ACTION_SHED;
		++monitor->denial_count;
		ret = -EDQUOT;
	} else {
		budget->used[resource] = proposed;
		budget->action = derive_action(budget);
		++monitor->accounting_count;
	}
	*action = budget->action;
out:
	k_mutex_unlock(&monitor->lock);
	return ret;
}

int pqcp_edge_resource_release(
	struct pqcp_edge_resource_monitor *monitor,
	const char *subject_id,
	enum pqcp_edge_resource_type resource,
	uint64_t amount)
{
	struct pqcp_edge_resource_budget *budget;
	int index;
	int ret = 0;

	if (monitor == NULL || !monitor->initialized ||
	    subject_id == NULL || !resource_valid(resource) ||
	    amount == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&monitor->lock, K_FOREVER);
	index = budget_index(monitor, subject_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	budget = &monitor->budgets[index];
	if (amount > budget->used[resource]) {
		ret = -ERANGE;
	} else {
		budget->used[resource] -= amount;
		budget->action = derive_action(budget);
	}
out:
	k_mutex_unlock(&monitor->lock);
	return ret;
}

int pqcp_edge_resource_tick(
	struct pqcp_edge_resource_monitor *monitor,
	uint64_t now_ms,
	uint32_t *reset_count)
{
	uint32_t reset = 0U;

	if (monitor == NULL || !monitor->initialized ||
	    reset_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&monitor->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < monitor->capacity; ++index) {
		uint64_t started;

		if (!monitor->budgets[index].occupied) {
			continue;
		}
		started = monitor->budgets[index].
			window_started_ms;
		refresh_window(
			&monitor->budgets[index], now_ms);
		if (started != monitor->budgets[index].
		    window_started_ms) {
			++reset;
		}
	}
	k_mutex_unlock(&monitor->lock);
	*reset_count = reset;
	return 0;
}

int pqcp_edge_resource_monitor_audit(
	struct pqcp_edge_resource_monitor *monitor)
{
	int ret = 0;

	if (monitor == NULL || !monitor->initialized ||
	    monitor->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    monitor->budgets == NULL ||
	    monitor->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&monitor->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < monitor->capacity && ret == 0;
	     ++index) {
		if (!monitor->budgets[index].occupied) {
			continue;
		}
		if (!budget_valid(&monitor->budgets[index]) ||
		    monitor->budgets[index].action >
			    PQCP_EDGE_RESOURCE_ACTION_ISOLATE) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&monitor->lock);
	return ret;
}
