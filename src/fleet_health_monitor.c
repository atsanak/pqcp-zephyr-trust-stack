/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Fleet health monitor with bounded backoff and circuit-breaker actions.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>

#include "runtime_internal.h"

static bool probe_valid(enum pqcp_fleet_health_probe probe)
{
	return probe >= PQCP_FLEET_HEALTH_CRYPTO &&
	       probe < PQCP_FLEET_HEALTH_PROBE_COUNT;
}

static bool state_valid(enum pqcp_fleet_health_state state)
{
	return state >= PQCP_FLEET_HEALTH_UNKNOWN &&
	       state <= PQCP_FLEET_HEALTH_ISOLATED;
}

static int policy_validate(
	const struct pqcp_fleet_health_policy *policy)
{
	const uint32_t valid_probe_mask =
		(1U << PQCP_FLEET_HEALTH_PROBE_COUNT) - 1U;

	if (policy == NULL ||
	    policy->degrade_after_failures == 0U ||
	    policy->fail_after_failures <
		    policy->degrade_after_failures ||
	    policy->recover_after_successes == 0U ||
	    policy->base_retry_ms == 0U ||
	    policy->maximum_retry_ms < policy->base_retry_ms ||
	    (policy->critical_probe_mask & ~valid_probe_mask) != 0U) {
		return -EINVAL;
	}
	return 0;
}

static bool critical_probe(
	const struct pqcp_fleet_health_monitor *monitor,
	enum pqcp_fleet_health_probe probe)
{
	return (monitor->policy.critical_probe_mask &
		(1U << (uint32_t)probe)) != 0U;
}

static uint64_t retry_delay(
	const struct pqcp_fleet_health_policy *policy,
	uint32_t consecutive_failures)
{
	uint64_t delay = policy->base_retry_ms;
	uint32_t shifts =
		consecutive_failures > 1U ?
			consecutive_failures - 1U : 0U;

	while (shifts != 0U &&
	       delay < policy->maximum_retry_ms) {
		if (delay >
		    policy->maximum_retry_ms / 2U) {
			delay = policy->maximum_retry_ms;
			break;
		}
		delay *= 2U;
		shifts--;
	}
	return delay > policy->maximum_retry_ms ?
		policy->maximum_retry_ms : delay;
}

int pqcp_fleet_health_monitor_init(
	struct pqcp_fleet_health_monitor *monitor,
	const struct pqcp_fleet_health_policy *policy)
{
	if (monitor == NULL || policy_validate(policy) != 0) {
		return -EINVAL;
	}
	memset(monitor, 0, sizeof(*monitor));
	monitor->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	monitor->policy = *policy;
	for (size_t probe = 0U;
	     probe < PQCP_FLEET_HEALTH_PROBE_COUNT; ++probe) {
		monitor->records[probe].schema_version =
			PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
		monitor->records[probe].probe =
			(enum pqcp_fleet_health_probe)probe;
		monitor->records[probe].state =
			PQCP_FLEET_HEALTH_UNKNOWN;
		(void)pqcp_runtime_internal_copy_text(
			monitor->records[probe].detail,
			sizeof(monitor->records[probe].detail),
			"not checked");
	}
	k_mutex_init(&monitor->lock);
	monitor->initialized = true;
	return 0;
}

static enum pqcp_fleet_health_state failure_state(
	const struct pqcp_fleet_health_monitor *monitor,
	const struct pqcp_fleet_health_record *record)
{
	if (record->consecutive_failures >=
	    monitor->policy.fail_after_failures) {
		if (critical_probe(monitor, record->probe) &&
		    record->consecutive_failures >=
			    monitor->policy.fail_after_failures * 2U) {
			return PQCP_FLEET_HEALTH_ISOLATED;
		}
		return PQCP_FLEET_HEALTH_FAILED;
	}
	if (record->consecutive_failures >=
	    monitor->policy.degrade_after_failures) {
		return PQCP_FLEET_HEALTH_DEGRADED;
	}
	return record->state == PQCP_FLEET_HEALTH_UNKNOWN ?
		PQCP_FLEET_HEALTH_DEGRADED : record->state;
}

int pqcp_fleet_health_report(
	struct pqcp_fleet_health_monitor *monitor,
	enum pqcp_fleet_health_probe probe,
	int result,
	const char *detail,
	uint64_t now_ms)
{
	struct pqcp_fleet_health_record *record;
	enum pqcp_fleet_health_state previous;
	int ret;

	if (monitor == NULL || !monitor->initialized ||
	    !probe_valid(probe) || detail == NULL ||
	    now_ms == 0U ||
	    strnlen(detail,
		    PQCP_FLEET_HEALTH_DETAIL_MAX_CHARS) == 0U ||
	    strnlen(detail,
		    PQCP_FLEET_HEALTH_DETAIL_MAX_CHARS) >=
		    PQCP_FLEET_HEALTH_DETAIL_MAX_CHARS) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&monitor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	record = &monitor->records[probe];
	previous = record->state;
	record->last_checked_ms = now_ms;
	record->last_result = result;
	ret = pqcp_runtime_internal_copy_text(
		record->detail, sizeof(record->detail), detail);
	if (ret != 0) {
		(void)k_mutex_unlock(&monitor->lock);
		return ret;
	}
	if (result == 0) {
		record->last_success_ms = now_ms;
		record->consecutive_failures = 0U;
		if (record->consecutive_successes != UINT32_MAX) {
			record->consecutive_successes++;
		}
		record->retry_after_ms = 0U;
		if (record->state == PQCP_FLEET_HEALTH_UNKNOWN ||
		    record->consecutive_successes >=
			    monitor->policy.recover_after_successes) {
			record->state =
				PQCP_FLEET_HEALTH_HEALTHY;
		}
	} else {
		record->last_failure_ms = now_ms;
		record->consecutive_successes = 0U;
		if (record->consecutive_failures != UINT32_MAX) {
			record->consecutive_failures++;
		}
		if (record->total_failures != UINT32_MAX) {
			record->total_failures++;
		}
		record->state = failure_state(monitor, record);
		const uint64_t delay = retry_delay(
			&monitor->policy,
			record->consecutive_failures);

		record->retry_after_ms =
			UINT64_MAX - now_ms < delay ?
				UINT64_MAX : now_ms + delay;
	}
	if (record->state != previous) {
		monitor->transition_count++;
	}
	(void)k_mutex_unlock(&monitor->lock);
	return 0;
}

static enum pqcp_fleet_health_action action_for_probe(
	enum pqcp_fleet_health_probe probe,
	enum pqcp_fleet_health_state state)
{
	if (state == PQCP_FLEET_HEALTH_ISOLATED) {
		return PQCP_FLEET_HEALTH_ACTION_QUARANTINE;
	}
	switch (probe) {
	case PQCP_FLEET_HEALTH_CRYPTO:
	case PQCP_FLEET_HEALTH_ENTROPY:
		return state == PQCP_FLEET_HEALTH_FAILED ?
			PQCP_FLEET_HEALTH_ACTION_RECOVERY :
			PQCP_FLEET_HEALTH_ACTION_REKEY;
	case PQCP_FLEET_HEALTH_CHANNEL:
		return PQCP_FLEET_HEALTH_ACTION_RECONNECT;
	case PQCP_FLEET_HEALTH_UPDATE:
		return state == PQCP_FLEET_HEALTH_FAILED ?
			PQCP_FLEET_HEALTH_ACTION_ROLLBACK :
			PQCP_FLEET_HEALTH_ACTION_RETRY;
	case PQCP_FLEET_HEALTH_STORAGE:
	case PQCP_FLEET_HEALTH_TIME:
	case PQCP_FLEET_HEALTH_POLICY:
		return state == PQCP_FLEET_HEALTH_FAILED ?
			PQCP_FLEET_HEALTH_ACTION_RECOVERY :
			PQCP_FLEET_HEALTH_ACTION_RETRY;
	case PQCP_FLEET_HEALTH_MEMORY:
		return state == PQCP_FLEET_HEALTH_FAILED ?
			PQCP_FLEET_HEALTH_ACTION_QUARANTINE :
			PQCP_FLEET_HEALTH_ACTION_RETRY;
	default:
		return PQCP_FLEET_HEALTH_ACTION_NONE;
	}
}

static int state_rank(enum pqcp_fleet_health_state state)
{
	switch (state) {
	case PQCP_FLEET_HEALTH_ISOLATED:
		return 5;
	case PQCP_FLEET_HEALTH_FAILED:
		return 4;
	case PQCP_FLEET_HEALTH_DEGRADED:
		return 3;
	case PQCP_FLEET_HEALTH_UNKNOWN:
		return 2;
	case PQCP_FLEET_HEALTH_HEALTHY:
		return 1;
	default:
		return 0;
	}
}

int pqcp_fleet_health_evaluate(
	struct pqcp_fleet_health_monitor *monitor,
	uint64_t now_ms,
	enum pqcp_fleet_health_state *state,
	enum pqcp_fleet_health_action *action)
{
	enum pqcp_fleet_health_state selected =
		PQCP_FLEET_HEALTH_HEALTHY;
	enum pqcp_fleet_health_probe selected_probe =
		PQCP_FLEET_HEALTH_CRYPTO;
	int ret;

	if (monitor == NULL || !monitor->initialized ||
	    now_ms == 0U || state == NULL || action == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&monitor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t probe = 0U;
	     probe < PQCP_FLEET_HEALTH_PROBE_COUNT; ++probe) {
		const struct pqcp_fleet_health_record *record =
			&monitor->records[probe];

		if (state_rank(record->state) >
		    state_rank(selected)) {
			selected = record->state;
			selected_probe =
				(enum pqcp_fleet_health_probe)probe;
		}
	}
	*state = selected;
	*action = action_for_probe(selected_probe, selected);
	if (selected == PQCP_FLEET_HEALTH_DEGRADED &&
	    monitor->records[selected_probe].retry_after_ms >
		    now_ms) {
		*action = PQCP_FLEET_HEALTH_ACTION_NONE;
	}
	(void)k_mutex_unlock(&monitor->lock);
	return 0;
}

int pqcp_fleet_health_due(
	struct pqcp_fleet_health_monitor *monitor,
	enum pqcp_fleet_health_probe probe,
	uint64_t now_ms,
	bool *due)
{
	int ret;

	if (monitor == NULL || !monitor->initialized ||
	    !probe_valid(probe) || now_ms == 0U || due == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&monitor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	const struct pqcp_fleet_health_record *record =
		&monitor->records[probe];

	*due = record->last_checked_ms == 0U ||
	       record->retry_after_ms == 0U ||
	       now_ms >= record->retry_after_ms;
	(void)k_mutex_unlock(&monitor->lock);
	return 0;
}

int pqcp_fleet_health_audit(
	struct pqcp_fleet_health_monitor *monitor)
{
	int ret;

	if (monitor == NULL || !monitor->initialized ||
	    monitor->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    policy_validate(&monitor->policy) != 0) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&monitor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t probe = 0U;
	     probe < PQCP_FLEET_HEALTH_PROBE_COUNT; ++probe) {
		const struct pqcp_fleet_health_record *record =
			&monitor->records[probe];

		if (record->schema_version !=
			    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
		    record->probe !=
			    (enum pqcp_fleet_health_probe)probe ||
		    !state_valid(record->state) ||
		    !pqcp_runtime_internal_text_valid(
			    record->detail,
			    sizeof(record->detail)) ||
		    record->consecutive_failures >
			    record->total_failures ||
		    (record->state ==
			     PQCP_FLEET_HEALTH_HEALTHY &&
		     record->consecutive_failures != 0U)) {
			(void)k_mutex_unlock(&monitor->lock);
			return -EBADMSG;
		}
	}
	(void)k_mutex_unlock(&monitor->lock);
	return 0;
}
