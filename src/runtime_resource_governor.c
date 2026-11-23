/*
 * SPDX-License-Identifier: MIT
 *
 * Fixed-memory resource admission and accounting for the PQC runtime.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/runtime_operations.h>

static int budget_validate(
	const struct pqcp_runtime_resource_budget *budget)
{
	if (budget == NULL ||
	    budget->schema_version !=
		    PQCP_RUNTIME_OPERATION_SCHEMA_VERSION ||
	    budget->maximum_jobs == 0U ||
	    budget->maximum_keys == 0U ||
	    budget->maximum_sessions == 0U ||
	    budget->maximum_workspaces == 0U ||
	    budget->maximum_workspace_bytes == 0U ||
	    budget->elevated_threshold_bps == 0U ||
	    budget->elevated_threshold_bps >=
		    budget->high_threshold_bps ||
	    budget->high_threshold_bps >=
		    budget->critical_threshold_bps ||
	    budget->critical_threshold_bps > 10000U) {
		return -EINVAL;
	}
	return 0;
}

static bool usage_zero(
	const struct pqcp_runtime_resource_usage *usage)
{
	return usage->jobs == 0U &&
	       usage->keys == 0U &&
	       usage->sessions == 0U &&
	       usage->workspaces == 0U &&
	       usage->workspace_bytes == 0U;
}

static bool usage_equal(
	const struct pqcp_runtime_resource_usage *left,
	const struct pqcp_runtime_resource_usage *right)
{
	return left->jobs == right->jobs &&
	       left->keys == right->keys &&
	       left->sessions == right->sessions &&
	       left->workspaces == right->workspaces &&
	       left->workspace_bytes ==
		       right->workspace_bytes;
}

static bool usage_add(
	const struct pqcp_runtime_resource_usage *left,
	const struct pqcp_runtime_resource_usage *right,
	struct pqcp_runtime_resource_usage *result)
{
	if (UINT32_MAX - left->jobs < right->jobs ||
	    UINT32_MAX - left->keys < right->keys ||
	    UINT32_MAX - left->sessions < right->sessions ||
	    UINT32_MAX - left->workspaces <
		    right->workspaces ||
	    UINT64_MAX - left->workspace_bytes <
		    right->workspace_bytes) {
		return false;
	}
	result->jobs = left->jobs + right->jobs;
	result->keys = left->keys + right->keys;
	result->sessions =
		left->sessions + right->sessions;
	result->workspaces =
		left->workspaces + right->workspaces;
	result->workspace_bytes =
		left->workspace_bytes +
		right->workspace_bytes;
	return true;
}

static bool usage_subtract(
	const struct pqcp_runtime_resource_usage *left,
	const struct pqcp_runtime_resource_usage *right,
	struct pqcp_runtime_resource_usage *result)
{
	if (left->jobs < right->jobs ||
	    left->keys < right->keys ||
	    left->sessions < right->sessions ||
	    left->workspaces < right->workspaces ||
	    left->workspace_bytes <
		    right->workspace_bytes) {
		return false;
	}
	result->jobs = left->jobs - right->jobs;
	result->keys = left->keys - right->keys;
	result->sessions =
		left->sessions - right->sessions;
	result->workspaces =
		left->workspaces - right->workspaces;
	result->workspace_bytes =
		left->workspace_bytes -
		right->workspace_bytes;
	return true;
}

static bool usage_within_budget(
	const struct pqcp_runtime_resource_usage *usage,
	const struct pqcp_runtime_resource_budget *budget)
{
	return usage->jobs <= budget->maximum_jobs &&
	       usage->keys <= budget->maximum_keys &&
	       usage->sessions <=
		       budget->maximum_sessions &&
	       usage->workspaces <=
		       budget->maximum_workspaces &&
	       usage->workspace_bytes <=
		       budget->maximum_workspace_bytes;
}

static uint32_t ratio_bps_u32(
	uint32_t value,
	uint32_t maximum)
{
	return (uint32_t)(((uint64_t)value * 10000U) /
			  maximum);
}

static uint32_t ratio_bps_u64(
	uint64_t value,
	uint64_t maximum)
{
	uint64_t divisor;

	if (value >= maximum) {
		return 10000U;
	}
	if (value <= UINT64_MAX / 10000U) {
		return (uint32_t)((value * 10000U) /
				  maximum);
	}
	divisor = maximum / 10000U;
	return divisor == 0U ?
		(uint32_t)((value * 10000U) / maximum) :
		(uint32_t)MIN(value / divisor, 10000U);
}

static uint32_t usage_peak_bps(
	const struct pqcp_runtime_resource_usage *usage,
	const struct pqcp_runtime_resource_budget *budget)
{
	uint32_t peak =
		ratio_bps_u32(
			usage->jobs,
			budget->maximum_jobs);
	uint32_t ratio =
		ratio_bps_u32(
			usage->keys,
			budget->maximum_keys);

	if (ratio > peak) {
		peak = ratio;
	}
	ratio = ratio_bps_u32(
		usage->sessions,
		budget->maximum_sessions);
	if (ratio > peak) {
		peak = ratio;
	}
	ratio = ratio_bps_u32(
		usage->workspaces,
		budget->maximum_workspaces);
	if (ratio > peak) {
		peak = ratio;
	}
	ratio = ratio_bps_u64(
		usage->workspace_bytes,
		budget->maximum_workspace_bytes);
	if (ratio > peak) {
		peak = ratio;
	}
	return peak;
}

static enum pqcp_runtime_pressure_level pressure_for(
	const struct pqcp_runtime_resource_usage *usage,
	const struct pqcp_runtime_resource_budget *budget)
{
	const uint32_t peak =
		usage_peak_bps(usage, budget);

	if (peak >= budget->critical_threshold_bps) {
		return PQCP_RUNTIME_PRESSURE_CRITICAL;
	}
	if (peak >= budget->high_threshold_bps) {
		return PQCP_RUNTIME_PRESSURE_HIGH;
	}
	if (peak >=
	    budget->elevated_threshold_bps) {
		return PQCP_RUNTIME_PRESSURE_ELEVATED;
	}
	return PQCP_RUNTIME_PRESSURE_NORMAL;
}

static int refresh_pressure(
	struct pqcp_runtime_resource_governor *governor)
{
	struct pqcp_runtime_resource_usage total;

	if (!usage_add(
		    &governor->committed,
		    &governor->reserved,
		    &total)) {
		return -EOVERFLOW;
	}
	governor->pressure =
		pressure_for(&total, &governor->budget);
	return 0;
}

static struct pqcp_runtime_resource_reservation *find_reservation(
	struct pqcp_runtime_resource_governor *governor,
	uint64_t reservation_id)
{
	for (size_t index = 0U;
	     index < governor->capacity; ++index) {
		struct pqcp_runtime_resource_reservation *entry =
			&governor->reservations[index];

		if (entry->occupied &&
		    entry->reservation_id ==
			    reservation_id) {
			return entry;
		}
	}
	return NULL;
}

static struct pqcp_runtime_resource_reservation *free_reservation(
	struct pqcp_runtime_resource_governor *governor)
{
	for (size_t index = 0U;
	     index < governor->capacity; ++index) {
		if (!governor->reservations[index].occupied) {
			return &governor->reservations[index];
		}
	}
	return NULL;
}

static int allocate_reservation_id(
	struct pqcp_runtime_resource_governor *governor,
	uint64_t *reservation_id)
{
	for (size_t attempt = 0U;
	     attempt <= governor->capacity; ++attempt) {
		uint64_t candidate =
			governor->next_reservation_id++;

		if (candidate == 0U) {
			candidate =
				governor->
					next_reservation_id++;
		}
		if (find_reservation(governor, candidate) ==
		    NULL) {
			*reservation_id = candidate;
			return 0;
		}
	}
	return -ENOSPC;
}

static int remove_reservation(
	struct pqcp_runtime_resource_governor *governor,
	struct pqcp_runtime_resource_reservation *entry)
{
	struct pqcp_runtime_resource_usage updated;
	bool valid;

	if (entry->committed) {
		valid = usage_subtract(
			&governor->committed,
			&entry->usage, &updated);
		if (valid) {
			governor->committed = updated;
		}
	} else {
		valid = usage_subtract(
			&governor->reserved,
			&entry->usage, &updated);
		if (valid) {
			governor->reserved = updated;
		}
	}
	if (!valid) {
		return -EBADMSG;
	}
	memset(entry, 0, sizeof(*entry));
	return refresh_pressure(governor);
}

int pqcp_runtime_resource_budget_default(
	struct pqcp_runtime_resource_budget *budget)
{
	if (budget == NULL) {
		return -EINVAL;
	}
	memset(budget, 0, sizeof(*budget));
	budget->schema_version =
		PQCP_RUNTIME_OPERATION_SCHEMA_VERSION;
	budget->maximum_jobs = 32U;
	budget->maximum_keys = 64U;
	budget->maximum_sessions = 16U;
	budget->maximum_workspaces = 8U;
	budget->maximum_workspace_bytes =
		1024U * 1024U;
	budget->elevated_threshold_bps = 7000U;
	budget->high_threshold_bps = 8500U;
	budget->critical_threshold_bps = 9500U;
	return 0;
}

int pqcp_runtime_resource_governor_init(
	struct pqcp_runtime_resource_governor *governor,
	const struct pqcp_runtime_resource_budget *budget,
	struct pqcp_runtime_resource_reservation *reservations,
	size_t capacity)
{
	if (governor == NULL ||
	    budget_validate(budget) != 0 ||
	    reservations == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(governor, 0, sizeof(*governor));
	memset(reservations, 0,
	       capacity * sizeof(*reservations));
	governor->budget = *budget;
	governor->reservations = reservations;
	governor->capacity = capacity;
	governor->next_reservation_id = 1U;
	governor->pressure =
		PQCP_RUNTIME_PRESSURE_NORMAL;
	k_mutex_init(&governor->lock);
	governor->initialized = true;
	return 0;
}

int pqcp_runtime_resource_reserve(
	struct pqcp_runtime_resource_governor *governor,
	uint32_t tenant_id,
	const struct pqcp_runtime_resource_usage *usage,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t *reservation_id)
{
	struct pqcp_runtime_resource_reservation *entry;
	struct pqcp_runtime_resource_usage reserved;
	struct pqcp_runtime_resource_usage total;
	uint64_t identifier;
	int ret;

	if (governor == NULL || !governor->initialized ||
	    tenant_id == 0U || usage == NULL ||
	    usage_zero(usage) || now_ms == 0U ||
	    expires_at_ms <= now_ms ||
	    reservation_id == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&governor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	entry = free_reservation(governor);
	if (entry == NULL) {
		governor->rejected++;
		ret = -ENOSPC;
		goto out;
	}
	if (!usage_add(
		    &governor->reserved, usage, &reserved) ||
	    !usage_add(
		    &governor->committed, &reserved, &total)) {
		governor->rejected++;
		ret = -EOVERFLOW;
		goto out;
	}
	if (!usage_within_budget(
		    &total, &governor->budget)) {
		governor->rejected++;
		ret = -EDQUOT;
		goto out;
	}
	ret = allocate_reservation_id(
		governor, &identifier);
	if (ret != 0) {
		governor->rejected++;
		goto out;
	}
	memset(entry, 0, sizeof(*entry));
	entry->reservation_id = identifier;
	entry->tenant_id = tenant_id;
	entry->usage = *usage;
	entry->created_at_ms = now_ms;
	entry->expires_at_ms = expires_at_ms;
	entry->occupied = true;
	governor->reserved = reserved;
	governor->accepted++;
	ret = refresh_pressure(governor);
	if (ret == 0) {
		*reservation_id = identifier;
	}
out:
	k_mutex_unlock(&governor->lock);
	return ret;
}

int pqcp_runtime_resource_commit(
	struct pqcp_runtime_resource_governor *governor,
	uint64_t reservation_id)
{
	struct pqcp_runtime_resource_reservation *entry;
	struct pqcp_runtime_resource_usage reserved;
	struct pqcp_runtime_resource_usage committed;
	int ret;

	if (governor == NULL || !governor->initialized ||
	    reservation_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&governor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	entry = find_reservation(
		governor, reservation_id);
	if (entry == NULL) {
		ret = -ENOENT;
		goto out;
	}
	if (entry->committed) {
		ret = -EALREADY;
		goto out;
	}
	if (!usage_subtract(
		    &governor->reserved,
		    &entry->usage, &reserved) ||
	    !usage_add(
		    &governor->committed,
		    &entry->usage, &committed)) {
		ret = -EBADMSG;
		goto out;
	}
	governor->reserved = reserved;
	governor->committed = committed;
	entry->committed = true;
	ret = refresh_pressure(governor);
out:
	k_mutex_unlock(&governor->lock);
	return ret;
}

int pqcp_runtime_resource_release(
	struct pqcp_runtime_resource_governor *governor,
	uint64_t reservation_id)
{
	struct pqcp_runtime_resource_reservation *entry;
	int ret;

	if (governor == NULL || !governor->initialized ||
	    reservation_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&governor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	entry = find_reservation(
		governor, reservation_id);
	ret = entry == NULL ?
		-ENOENT :
		remove_reservation(governor, entry);
	k_mutex_unlock(&governor->lock);
	return ret;
}

int pqcp_runtime_resource_tick(
	struct pqcp_runtime_resource_governor *governor,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret;

	if (governor == NULL || !governor->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&governor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < governor->capacity; ++index) {
		struct pqcp_runtime_resource_reservation *entry =
			&governor->reservations[index];

		if (!entry->occupied || entry->committed ||
		    now_ms < entry->expires_at_ms) {
			continue;
		}
		ret = remove_reservation(governor, entry);
		if (ret != 0) {
			goto out;
		}
		expired++;
	}
	governor->expired += expired;
	ret = refresh_pressure(governor);
	if (ret == 0 && expired_count != NULL) {
		*expired_count = expired;
	}
out:
	k_mutex_unlock(&governor->lock);
	return ret;
}

int pqcp_runtime_resource_governor_audit(
	struct pqcp_runtime_resource_governor *governor)
{
	struct pqcp_runtime_resource_usage reserved = {0};
	struct pqcp_runtime_resource_usage committed = {0};
	struct pqcp_runtime_resource_usage total;
	size_t occupied = 0U;
	int ret;

	if (governor == NULL || !governor->initialized ||
	    budget_validate(&governor->budget) != 0 ||
	    governor->reservations == NULL ||
	    governor->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&governor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < governor->capacity; ++index) {
		const struct pqcp_runtime_resource_reservation
			*entry = &governor->reservations[index];
		struct pqcp_runtime_resource_usage updated;

		if (!entry->occupied) {
			if (entry->reservation_id != 0U ||
			    entry->tenant_id != 0U ||
			    entry->committed ||
			    !usage_zero(&entry->usage)) {
				ret = -EBADMSG;
				goto out;
			}
			continue;
		}
		occupied++;
		if (entry->reservation_id == 0U ||
		    entry->tenant_id == 0U ||
		    entry->created_at_ms == 0U ||
		    entry->expires_at_ms <=
			    entry->created_at_ms ||
		    usage_zero(&entry->usage)) {
			ret = -EBADMSG;
			goto out;
		}
		for (size_t prior = 0U;
		     prior < index; ++prior) {
			if (governor->reservations[prior].
				    occupied &&
			    governor->reservations[prior].
				    reservation_id ==
				    entry->reservation_id) {
				ret = -EBADMSG;
				goto out;
			}
		}
		if (entry->committed) {
			if (!usage_add(
				    &committed,
				    &entry->usage, &updated)) {
				ret = -EOVERFLOW;
				goto out;
			}
			committed = updated;
		} else {
			if (!usage_add(
				    &reserved,
				    &entry->usage, &updated)) {
				ret = -EOVERFLOW;
				goto out;
			}
			reserved = updated;
		}
	}
	if (occupied > governor->capacity ||
	    !usage_equal(&reserved, &governor->reserved) ||
	    !usage_equal(
		    &committed, &governor->committed) ||
	    !usage_add(&reserved, &committed, &total) ||
	    !usage_within_budget(
		    &total, &governor->budget) ||
	    governor->pressure !=
		    pressure_for(
			    &total, &governor->budget) ||
	    governor->accepted <
		    occupied + governor->expired) {
		ret = -EBADMSG;
		goto out;
	}
	ret = 0;
out:
	k_mutex_unlock(&governor->lock);
	return ret;
}
