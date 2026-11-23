/*
 * SPDX-License-Identifier: MIT
 *
 * Atomic fixed-window compute, storage, network, and carbon governance.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"

static uint64_t add_u64(uint64_t left, uint64_t right)
{
	return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

static uint32_t add_u32(uint32_t left, uint32_t right)
{
	return UINT32_MAX - left < right ? UINT32_MAX : left + right;
}

static bool budget_state_valid(
	enum pqcp_sovereign_lifecycle_state state)
{
	return state == PQCP_SOVEREIGN_LIFECYCLE_DRAFT ||
	       state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
	       state == PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED ||
	       state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
	       state == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
}

static bool terminal_state(
	enum pqcp_sovereign_lifecycle_state state)
{
	return state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
	       state == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
}

static bool transition_valid(
	enum pqcp_sovereign_lifecycle_state current,
	enum pqcp_sovereign_lifecycle_state next)
{
	if (current == next) {
		return true;
	}
	switch (current) {
	case PQCP_SOVEREIGN_LIFECYCLE_DRAFT:
		return next == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	case PQCP_SOVEREIGN_LIFECYCLE_ACTIVE:
		return next == PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	case PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED:
		return next == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	default:
		return false;
	}
}

static bool budget_shape_valid(
	const struct pqcp_sovereign_cost_budget *budget)
{
	return budget != NULL && budget->occupied &&
	       budget->schema_version == PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       budget->budget_id != 0U &&
	       pqcp_runtime_internal_text_valid(
		       budget->tenant_id, sizeof(budget->tenant_id)) &&
	       pqcp_runtime_internal_text_valid(
		       budget->namespace_id,
		       sizeof(budget->namespace_id)) &&
	       budget->window_started_ms != 0U &&
	       budget->window_ms != 0U &&
	       (budget->compute_limit_units != 0U ||
		budget->storage_limit_byte_ms != 0U ||
		budget->network_limit_bytes != 0U ||
		budget->carbon_limit_milligrams != 0U) &&
	       budget->compute_used_units <=
		       budget->compute_limit_units &&
	       budget->storage_used_byte_ms <=
		       budget->storage_limit_byte_ms &&
	       budget->network_used_bytes <=
		       budget->network_limit_bytes &&
	       budget->carbon_used_milligrams <=
		       budget->carbon_limit_milligrams &&
	       budget->warning_basis_points != 0U &&
	       budget->warning_basis_points <= 10000U &&
	       budget_state_valid(budget->state);
}

static bool input_budget_valid(
	const struct pqcp_sovereign_cost_budget *budget,
	uint64_t now_ms)
{
	return budget != NULL && now_ms != 0U &&
	       pqcp_runtime_internal_text_valid(
		       budget->tenant_id, sizeof(budget->tenant_id)) &&
	       pqcp_runtime_internal_text_valid(
		       budget->namespace_id,
		       sizeof(budget->namespace_id)) &&
	       budget->window_ms != 0U &&
	       (budget->compute_limit_units != 0U ||
		budget->storage_limit_byte_ms != 0U ||
		budget->network_limit_bytes != 0U ||
		budget->carbon_limit_milligrams != 0U) &&
	       budget->compute_used_units <=
		       budget->compute_limit_units &&
	       budget->storage_used_byte_ms <=
		       budget->storage_limit_byte_ms &&
	       budget->network_used_bytes <=
		       budget->network_limit_bytes &&
	       budget->carbon_used_milligrams <=
		       budget->carbon_limit_milligrams &&
	       budget->warning_basis_points != 0U &&
	       budget->warning_basis_points <= 10000U &&
	       budget_state_valid(budget->state) &&
	       (budget->window_started_ms == 0U ||
		budget->window_started_ms <= now_ms);
}

static int budget_index_locked(
	const struct pqcp_sovereign_cost_governor *governor,
	const char *tenant_id,
	const char *namespace_id)
{
	for (size_t index = 0U; index < governor->capacity; ++index) {
		const struct pqcp_sovereign_cost_budget *budget =
			&governor->budgets[index];

		if (budget->occupied &&
		    strcmp(budget->tenant_id, tenant_id) == 0 &&
		    strcmp(budget->namespace_id, namespace_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int reusable_budget_index_locked(
	const struct pqcp_sovereign_cost_governor *governor)
{
	int oldest = -1;
	uint64_t oldest_window = UINT64_MAX;

	for (size_t index = 0U; index < governor->capacity; ++index) {
		const struct pqcp_sovereign_cost_budget *budget =
			&governor->budgets[index];

		if (!budget->occupied) {
			return (int)index;
		}
		if (terminal_state(budget->state) &&
		    budget->window_started_ms < oldest_window) {
			oldest = (int)index;
			oldest_window = budget->window_started_ms;
		}
	}
	return oldest >= 0 ? oldest : -ENOSPC;
}

static bool window_elapsed(
	const struct pqcp_sovereign_cost_budget *budget,
	uint64_t now_ms)
{
	return now_ms >= budget->window_started_ms &&
	       now_ms - budget->window_started_ms >=
		       budget->window_ms;
}

static void reset_window(
	struct pqcp_sovereign_cost_budget *budget,
	uint64_t now_ms)
{
	uint64_t elapsed;
	uint64_t windows;
	uint64_t advance;

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
	budget->compute_used_units = 0U;
	budget->storage_used_byte_ms = 0U;
	budget->network_used_bytes = 0U;
	budget->carbon_used_milligrams = 0U;
}

static int next_budget_id_locked(
	struct pqcp_sovereign_cost_governor *governor,
	uint32_t *budget_id)
{
	if (governor->next_budget_id == 0U ||
	    governor->next_budget_id == UINT32_MAX) {
		return -EOVERFLOW;
	}
	*budget_id = governor->next_budget_id++;
	return 0;
}

static uint64_t warning_threshold(
	uint64_t limit,
	uint32_t warning_basis_points)
{
	uint64_t whole;
	uint64_t remainder;
	uint64_t threshold;
	uint64_t fractional;

	if (limit == 0U) {
		return 0U;
	}
	whole = limit / 10000U;
	remainder = limit % 10000U;
	threshold = whole * warning_basis_points;
	fractional =
		(remainder * warning_basis_points + 9999U) / 10000U;
	return threshold + fractional;
}

static bool dimension_warns(
	uint64_t projected,
	uint64_t limit,
	uint32_t warning_basis_points)
{
	return limit != 0U &&
	       projected >= warning_threshold(
		       limit, warning_basis_points);
}

static bool addition_fits_limit(
	uint64_t used,
	uint64_t requested,
	uint64_t limit)
{
	return used <= limit && requested <= limit - used;
}

int pqcp_sovereign_cost_governor_init(
	struct pqcp_sovereign_cost_governor *governor,
	struct pqcp_sovereign_cost_budget *budgets,
	size_t capacity)
{
	if (governor == NULL || budgets == NULL ||
	    capacity == 0U || capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(governor, 0, sizeof(*governor));
	memset(budgets, 0, capacity * sizeof(budgets[0]));
	governor->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	governor->budgets = budgets;
	governor->capacity = capacity;
	governor->next_budget_id = 1U;
	k_mutex_init(&governor->lock);
	governor->initialized = true;
	return 0;
}

int pqcp_sovereign_cost_budget_put(
	struct pqcp_sovereign_cost_governor *governor,
	const struct pqcp_sovereign_cost_budget *budget,
	uint64_t now_ms)
{
	struct pqcp_sovereign_cost_budget candidate;
	struct pqcp_sovereign_cost_budget current;
	int index;
	int ret = 0;

	if (governor == NULL || !governor->initialized ||
	    !input_budget_valid(budget, now_ms)) {
		return -EINVAL;
	}
	k_mutex_lock(&governor->lock, K_FOREVER);
	index = budget_index_locked(
		governor, budget->tenant_id,
		budget->namespace_id);
	if (index >= 0) {
		current = governor->budgets[index];
		if (budget->budget_id != 0U &&
		    budget->budget_id != current.budget_id) {
			ret = -ESTALE;
			goto deny;
		}
		if (!transition_valid(current.state, budget->state)) {
			ret = -EPERM;
			goto deny;
		}
		if (now_ms < current.window_started_ms) {
			ret = -ETIME;
			goto deny;
		}
		if (window_elapsed(&current, now_ms)) {
			reset_window(&current, now_ms);
		}
		if (budget->compute_limit_units <
			    current.compute_used_units ||
		    budget->storage_limit_byte_ms <
			    current.storage_used_byte_ms ||
		    budget->network_limit_bytes <
			    current.network_used_bytes ||
		    budget->carbon_limit_milligrams <
			    current.carbon_used_milligrams) {
			ret = -EDQUOT;
			goto deny;
		}
		candidate = *budget;
		candidate.schema_version =
			PQCP_SOVEREIGN_SCHEMA_VERSION;
		candidate.budget_id = current.budget_id;
		candidate.window_started_ms =
			current.window_started_ms;
		candidate.compute_used_units =
			current.compute_used_units;
		candidate.storage_used_byte_ms =
			current.storage_used_byte_ms;
		candidate.network_used_bytes =
			current.network_used_bytes;
		candidate.carbon_used_milligrams =
			current.carbon_used_milligrams;
		candidate.occupied = true;
		governor->budgets[index] = candidate;
		goto out;
	}
	if (budget->budget_id != 0U ||
	    budget->compute_used_units != 0U ||
	    budget->storage_used_byte_ms != 0U ||
	    budget->network_used_bytes != 0U ||
	    budget->carbon_used_milligrams != 0U ||
	    terminal_state(budget->state)) {
		ret = -EINVAL;
		goto deny;
	}
	index = reusable_budget_index_locked(governor);
	if (index < 0) {
		ret = index;
		goto deny;
	}
	candidate = *budget;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	ret = next_budget_id_locked(
		governor, &candidate.budget_id);
	if (ret != 0) {
		goto deny;
	}
	candidate.window_started_ms = now_ms;
	candidate.compute_used_units = 0U;
	candidate.storage_used_byte_ms = 0U;
	candidate.network_used_bytes = 0U;
	candidate.carbon_used_milligrams = 0U;
	candidate.occupied = true;
	governor->budgets[index] = candidate;
	goto out;
deny:
	governor->denied_count =
		add_u64(governor->denied_count, 1U);
out:
	k_mutex_unlock(&governor->lock);
	return ret;
}

int pqcp_sovereign_cost_reserve(
	struct pqcp_sovereign_cost_governor *governor,
	const char *tenant_id,
	const char *namespace_id,
	uint64_t compute_units,
	uint64_t storage_byte_ms,
	uint64_t network_bytes,
	uint64_t carbon_milligrams,
	uint64_t now_ms,
	bool *warning)
{
	struct pqcp_sovereign_cost_budget *budget;
	uint64_t projected_compute;
	uint64_t projected_storage;
	uint64_t projected_network;
	uint64_t projected_carbon;
	int index;
	int ret = 0;

	if (governor == NULL || !governor->initialized ||
	    !pqcp_runtime_internal_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_runtime_internal_text_valid(
		    namespace_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    (compute_units == 0U && storage_byte_ms == 0U &&
	     network_bytes == 0U && carbon_milligrams == 0U) ||
	    now_ms == 0U || warning == NULL) {
		return -EINVAL;
	}
	*warning = false;
	k_mutex_lock(&governor->lock, K_FOREVER);
	index = budget_index_locked(
		governor, tenant_id, namespace_id);
	if (index < 0) {
		ret = index;
		goto deny;
	}
	budget = &governor->budgets[index];
	if (budget->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = -EACCES;
		goto deny;
	}
	if (now_ms < budget->window_started_ms) {
		ret = -ETIME;
		goto deny;
	}
	if (window_elapsed(budget, now_ms)) {
		reset_window(budget, now_ms);
	}
	if (!addition_fits_limit(
		    budget->compute_used_units, compute_units,
		    budget->compute_limit_units) ||
	    !addition_fits_limit(
		    budget->storage_used_byte_ms, storage_byte_ms,
		    budget->storage_limit_byte_ms) ||
	    !addition_fits_limit(
		    budget->network_used_bytes, network_bytes,
		    budget->network_limit_bytes) ||
	    !addition_fits_limit(
		    budget->carbon_used_milligrams,
		    carbon_milligrams,
		    budget->carbon_limit_milligrams)) {
		ret = -EDQUOT;
		goto deny;
	}
	projected_compute =
		budget->compute_used_units + compute_units;
	projected_storage =
		budget->storage_used_byte_ms + storage_byte_ms;
	projected_network =
		budget->network_used_bytes + network_bytes;
	projected_carbon =
		budget->carbon_used_milligrams + carbon_milligrams;
	budget->compute_used_units = projected_compute;
	budget->storage_used_byte_ms = projected_storage;
	budget->network_used_bytes = projected_network;
	budget->carbon_used_milligrams = projected_carbon;
	*warning =
		dimension_warns(
			projected_compute,
			budget->compute_limit_units,
			budget->warning_basis_points) ||
		dimension_warns(
			projected_storage,
			budget->storage_limit_byte_ms,
			budget->warning_basis_points) ||
		dimension_warns(
			projected_network,
			budget->network_limit_bytes,
			budget->warning_basis_points) ||
		dimension_warns(
			projected_carbon,
			budget->carbon_limit_milligrams,
			budget->warning_basis_points);
	governor->accepted_count =
		add_u64(governor->accepted_count, 1U);
	goto out;
deny:
	governor->denied_count =
		add_u64(governor->denied_count, 1U);
out:
	k_mutex_unlock(&governor->lock);
	return ret;
}

int pqcp_sovereign_cost_tick(
	struct pqcp_sovereign_cost_governor *governor,
	uint64_t now_ms,
	uint32_t *reset_count)
{
	uint32_t resets = 0U;

	if (governor == NULL || !governor->initialized ||
	    now_ms == 0U || reset_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&governor->lock, K_FOREVER);
	for (size_t index = 0U; index < governor->capacity; ++index) {
		struct pqcp_sovereign_cost_budget *budget =
			&governor->budgets[index];

		if (!budget->occupied || terminal_state(budget->state) ||
		    now_ms < budget->window_started_ms ||
		    !window_elapsed(budget, now_ms)) {
			continue;
		}
		reset_window(budget, now_ms);
		resets = add_u32(resets, 1U);
	}
	*reset_count = resets;
	k_mutex_unlock(&governor->lock);
	return 0;
}

int pqcp_sovereign_cost_governor_audit(
	struct pqcp_sovereign_cost_governor *governor)
{
	uint32_t maximum_id = 0U;
	int ret = 0;

	if (governor == NULL || !governor->initialized ||
	    governor->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    governor->budgets == NULL || governor->capacity == 0U ||
	    governor->next_budget_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&governor->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < governor->capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_cost_budget *budget =
			&governor->budgets[index];

		if (!budget->occupied) {
			continue;
		}
		if (!budget_shape_valid(budget)) {
			ret = -EBADMSG;
			break;
		}
		if (budget->budget_id > maximum_id) {
			maximum_id = budget->budget_id;
		}
		for (size_t other = index + 1U;
		     other < governor->capacity; ++other) {
			const struct pqcp_sovereign_cost_budget *peer =
				&governor->budgets[other];

			if (!peer->occupied) {
				continue;
			}
			if (peer->budget_id == budget->budget_id) {
				ret = -EEXIST;
				break;
			}
			if (strcmp(peer->tenant_id,
				   budget->tenant_id) == 0 &&
			    strcmp(peer->namespace_id,
				   budget->namespace_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	if (ret == 0 && maximum_id != 0U &&
	    governor->next_budget_id <= maximum_id) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&governor->lock);
	return ret;
}
