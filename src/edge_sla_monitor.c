/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Sliding-window service-level objective monitor.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int objective_index(
	const struct pqcp_edge_sla_monitor *monitor,
	const char *service_id)
{
	for (size_t index = 0U;
	     index < monitor->capacity; ++index) {
		if (monitor->objectives[index].occupied &&
		    strcmp(monitor->objectives[index].service_id,
			   service_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_objective_index(
	const struct pqcp_edge_sla_monitor *monitor)
{
	for (size_t index = 0U;
	     index < monitor->capacity; ++index) {
		if (!monitor->objectives[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool objective_shape_valid(
	const struct pqcp_edge_sla_objective *objective)
{
	if (objective == NULL ||
	    !pqcp_edge_internal_text_valid(
		    objective->service_id,
		    sizeof(objective->service_id)) ||
	    objective->window_ms == 0U ||
	    objective->maximum_latency_us == 0U ||
	    objective->minimum_success_basis_points > 10000U ||
	    objective->maximum_error_basis_points > 10000U ||
	    objective->minimum_success_basis_points == 0U) {
		return false;
	}
	if (objective->minimum_success_basis_points +
		    objective->maximum_error_basis_points <
	    10000U) {
		return false;
	}
	if (objective->success_count >
		    objective->request_count ||
	    objective->error_count >
		    objective->request_count ||
	    objective->success_count +
		    objective->error_count !=
		    objective->request_count) {
		return false;
	}
	if (objective->request_count == 0U &&
	    (objective->latency_sum_us != 0U ||
	     objective->maximum_observed_latency_us != 0U)) {
		return false;
	}
	if (objective->state < PQCP_EDGE_SLA_UNKNOWN ||
	    objective->state > PQCP_EDGE_SLA_BREACHED) {
		return false;
	}
	return true;
}

static void reset_window(
	struct pqcp_edge_sla_objective *objective,
	uint64_t now_ms)
{
	objective->window_started_ms = now_ms;
	objective->request_count = 0U;
	objective->success_count = 0U;
	objective->error_count = 0U;
	objective->latency_sum_us = 0U;
	objective->maximum_observed_latency_us = 0U;
	objective->state = PQCP_EDGE_SLA_UNKNOWN;
}

static bool window_expired(
	const struct pqcp_edge_sla_objective *objective,
	uint64_t now_ms)
{
	if (now_ms < objective->window_started_ms) {
		return false;
	}
	return now_ms - objective->window_started_ms >=
	       objective->window_ms;
}

static uint32_t ratio_basis_points(
	uint64_t numerator,
	uint64_t denominator)
{
	uint64_t quotient;
	uint64_t remainder;
	uint64_t scaled;

	if (denominator == 0U) {
		return 0U;
	}
	quotient = numerator / denominator;
	remainder = numerator % denominator;
	if (quotient >= 1U) {
		return 10000U;
	}
	scaled = (remainder * 10000U) /
		 denominator;
	return scaled > 10000U ?
		10000U : (uint32_t)scaled;
}

/*
 * AT_RISK warning margin: at most 250 basis points, but never more than half
 * of the headroom between the objective and the 100% / 0% extreme, so a
 * tight objective (e.g. a 99% success floor) can still report HEALTHY when
 * it is fully met.
 */
static uint32_t warning_margin(uint32_t headroom_basis_points)
{
	const uint32_t half = headroom_basis_points / 2U;

	return half < 250U ? half : 250U;
}

static enum pqcp_edge_sla_state evaluate_objective(
	const struct pqcp_edge_sla_objective *objective)
{
	uint32_t success_margin;
	uint32_t error_margin;
	uint32_t success_basis_points;
	uint32_t error_basis_points;
	uint64_t average_latency;
	bool hard_failure;
	bool warning;

	if (objective->request_count == 0U) {
		return PQCP_EDGE_SLA_UNKNOWN;
	}
	success_basis_points = ratio_basis_points(
		objective->success_count,
		objective->request_count);
	error_basis_points = ratio_basis_points(
		objective->error_count,
		objective->request_count);
	average_latency =
		objective->latency_sum_us /
		objective->request_count;
	hard_failure =
		success_basis_points <
			objective->
				minimum_success_basis_points ||
		error_basis_points >
			objective->
				maximum_error_basis_points ||
		average_latency >
			objective->maximum_latency_us ||
		objective->maximum_observed_latency_us >
			objective->maximum_latency_us * 4U;
	if (hard_failure) {
		return PQCP_EDGE_SLA_BREACHED;
	}
	success_margin = warning_margin(
		objective->minimum_success_basis_points < 10000U ?
		10000U -
			objective->minimum_success_basis_points : 0U);
	error_margin = warning_margin(
		objective->maximum_error_basis_points);
	warning =
		success_basis_points <
			objective->
				minimum_success_basis_points +
				success_margin ||
		error_basis_points >
			objective->
				maximum_error_basis_points -
				error_margin ||
		average_latency >
			(objective->maximum_latency_us *
			 9U) /
				10U ||
		objective->maximum_observed_latency_us >
			objective->maximum_latency_us * 2U;
	return warning ?
		PQCP_EDGE_SLA_AT_RISK :
		PQCP_EDGE_SLA_HEALTHY;
}

static void update_state(
	struct pqcp_edge_sla_monitor *monitor,
	struct pqcp_edge_sla_objective *objective)
{
	enum pqcp_edge_sla_state previous =
		objective->state;

	objective->state =
		evaluate_objective(objective);
	if (objective->state ==
		    PQCP_EDGE_SLA_BREACHED &&
	    previous != PQCP_EDGE_SLA_BREACHED) {
		++monitor->breach_count;
	}
}

int pqcp_edge_sla_monitor_init(
	struct pqcp_edge_sla_monitor *monitor,
	struct pqcp_edge_sla_objective *objectives,
	size_t capacity)
{
	if (monitor == NULL || objectives == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(monitor, 0, sizeof(*monitor));
	memset(objectives, 0,
	       capacity * sizeof(*objectives));
	monitor->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	monitor->objectives = objectives;
	monitor->capacity = capacity;
	k_mutex_init(&monitor->lock);
	monitor->initialized = true;
	return 0;
}

int pqcp_edge_sla_objective_put(
	struct pqcp_edge_sla_monitor *monitor,
	const struct pqcp_edge_sla_objective *objective,
	uint64_t now_ms)
{
	struct pqcp_edge_sla_objective candidate;
	int index;

	if (monitor == NULL || !monitor->initialized ||
	    !objective_shape_valid(objective) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	candidate = *objective;
	candidate.occupied = true;
	k_mutex_lock(&monitor->lock, K_FOREVER);
	index = objective_index(
		monitor, candidate.service_id);
	if (index >= 0) {
		struct pqcp_edge_sla_objective *existing =
			&monitor->objectives[index];

		if (candidate.window_started_ms == 0U) {
			candidate.window_started_ms =
				existing->window_started_ms;
			candidate.request_count =
				existing->request_count;
			candidate.success_count =
				existing->success_count;
			candidate.error_count =
				existing->error_count;
			candidate.latency_sum_us =
				existing->latency_sum_us;
			candidate.
				maximum_observed_latency_us =
				existing->
					maximum_observed_latency_us;
			candidate.state = existing->state;
		}
	} else if (index == -ENOENT) {
		index = free_objective_index(monitor);
		if (index < 0) {
			k_mutex_unlock(&monitor->lock);
			return index;
		}
		if (candidate.window_started_ms == 0U) {
			reset_window(&candidate, now_ms);
		}
	} else {
		k_mutex_unlock(&monitor->lock);
		return index;
	}
	if (candidate.window_started_ms > now_ms) {
		k_mutex_unlock(&monitor->lock);
		return -EINVAL;
	}
	monitor->objectives[index] = candidate;
	update_state(monitor,
		     &monitor->objectives[index]);
	k_mutex_unlock(&monitor->lock);
	return 0;
}

int pqcp_edge_sla_record(
	struct pqcp_edge_sla_monitor *monitor,
	const char *service_id,
	bool success,
	uint64_t latency_us,
	uint64_t now_ms)
{
	struct pqcp_edge_sla_objective *objective;
	int index;

	if (monitor == NULL || !monitor->initialized ||
	    service_id == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&monitor->lock, K_FOREVER);
	index = objective_index(monitor, service_id);
	if (index < 0) {
		k_mutex_unlock(&monitor->lock);
		return index;
	}
	objective = &monitor->objectives[index];
	if (window_expired(objective, now_ms)) {
		reset_window(objective, now_ms);
	}
	objective->request_count =
		pqcp_edge_internal_saturating_add_u64(
			objective->request_count, 1U);
	if (success) {
		objective->success_count =
			pqcp_edge_internal_saturating_add_u64(
				objective->success_count, 1U);
	} else {
		objective->error_count =
			pqcp_edge_internal_saturating_add_u64(
				objective->error_count, 1U);
	}
	objective->latency_sum_us =
		pqcp_edge_internal_saturating_add_u64(
			objective->latency_sum_us,
			latency_us);
	if (latency_us >
	    objective->maximum_observed_latency_us) {
		objective->maximum_observed_latency_us =
			latency_us;
	}
	update_state(monitor, objective);
	k_mutex_unlock(&monitor->lock);
	return 0;
}

int pqcp_edge_sla_evaluate(
	struct pqcp_edge_sla_monitor *monitor,
	const char *service_id,
	uint64_t now_ms,
	enum pqcp_edge_sla_state *state)
{
	struct pqcp_edge_sla_objective *objective;
	int index;

	if (monitor == NULL || !monitor->initialized ||
	    service_id == NULL || state == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&monitor->lock, K_FOREVER);
	index = objective_index(monitor, service_id);
	if (index < 0) {
		k_mutex_unlock(&monitor->lock);
		return index;
	}
	objective = &monitor->objectives[index];
	if (window_expired(objective, now_ms)) {
		reset_window(objective, now_ms);
	}
	update_state(monitor, objective);
	*state = objective->state;
	k_mutex_unlock(&monitor->lock);
	return 0;
}

int pqcp_edge_sla_tick(
	struct pqcp_edge_sla_monitor *monitor,
	uint64_t now_ms,
	uint32_t *reset_count)
{
	uint32_t reset = 0U;

	if (monitor == NULL || !monitor->initialized) {
		return -EINVAL;
	}
	k_mutex_lock(&monitor->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < monitor->capacity; ++index) {
		struct pqcp_edge_sla_objective *objective =
			&monitor->objectives[index];

		if (!objective->occupied ||
		    !window_expired(objective, now_ms)) {
			continue;
		}
		update_state(monitor, objective);
		reset_window(objective, now_ms);
		++reset;
	}
	k_mutex_unlock(&monitor->lock);
	if (reset_count != NULL) {
		*reset_count = reset;
	}
	return 0;
}

int pqcp_edge_sla_monitor_audit(
	struct pqcp_edge_sla_monitor *monitor)
{
	int ret = 0;

	if (monitor == NULL || !monitor->initialized ||
	    monitor->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    monitor->objectives == NULL ||
	    monitor->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&monitor->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < monitor->capacity; ++index) {
		const struct pqcp_edge_sla_objective *objective =
			&monitor->objectives[index];

		if (!objective->occupied) {
			continue;
		}
		if (!objective_shape_valid(objective) ||
		    objective->state !=
			    evaluate_objective(objective)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < monitor->capacity; ++other) {
			if (monitor->objectives[other].
				    occupied &&
			    strcmp(objective->service_id,
				   monitor->objectives[other].
					   service_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
		if (ret != 0) {
			break;
		}
	}
	k_mutex_unlock(&monitor->lock);
	return ret;
}
