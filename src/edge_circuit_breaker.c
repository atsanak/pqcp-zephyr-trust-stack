/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Endpoint circuit breaking with bounded exponential recovery.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool policy_valid(
	const struct pqcp_edge_circuit_policy *policy)
{
	return policy != NULL &&
	       policy->open_after_failures != 0U &&
	       policy->close_after_successes != 0U &&
	       policy->half_open_maximum != 0U &&
	       policy->base_retry_ms != 0U &&
	       policy->maximum_retry_ms >=
		       policy->base_retry_ms;
}

static int circuit_index(
	const struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id)
{
	for (size_t index = 0U;
	     index < breaker->capacity; ++index) {
		const struct pqcp_edge_circuit *circuit =
			&breaker->circuits[index];

		if (circuit->occupied &&
		    strcmp(circuit->service_id,
			   service_id) == 0 &&
		    strcmp(circuit->endpoint_id,
			   endpoint_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_circuit_index(
	const struct pqcp_edge_circuit_breaker *breaker)
{
	for (size_t index = 0U;
	     index < breaker->capacity; ++index) {
		if (!breaker->circuits[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int get_or_create_circuit(
	struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id,
	uint64_t now_ms)
{
	struct pqcp_edge_circuit *circuit;
	int index;
	int ret;

	index = circuit_index(
		breaker, service_id, endpoint_id);
	if (index >= 0) {
		return index;
	}
	if (index != -ENOENT) {
		return index;
	}
	index = free_circuit_index(breaker);
	if (index < 0) {
		return index;
	}
	circuit = &breaker->circuits[index];
	memset(circuit, 0, sizeof(*circuit));
	ret = pqcp_edge_internal_copy_text(
		circuit->service_id,
		sizeof(circuit->service_id),
		service_id);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			circuit->endpoint_id,
			sizeof(circuit->endpoint_id),
			endpoint_id);
	}
	if (ret != 0) {
		memset(circuit, 0, sizeof(*circuit));
		return ret;
	}
	circuit->state = PQCP_EDGE_CIRCUIT_CLOSED;
	circuit->last_transition_ms = now_ms;
	circuit->occupied = true;
	return index;
}

static void open_circuit(
	struct pqcp_edge_circuit_breaker *breaker,
	struct pqcp_edge_circuit *circuit,
	uint64_t now_ms)
{
	uint64_t delay;

	circuit->state = PQCP_EDGE_CIRCUIT_OPEN;
	circuit->opened_at_ms = now_ms;
	circuit->last_transition_ms = now_ms;
	circuit->half_open_attempts = 0U;
	circuit->consecutive_successes = 0U;
	circuit->total_opens =
		pqcp_edge_internal_saturating_add_u32(
			circuit->total_opens, 1U);
	delay = pqcp_edge_internal_backoff(
		breaker->policy.base_retry_ms,
		breaker->policy.maximum_retry_ms,
		circuit->total_opens);
	circuit->retry_at_ms =
		pqcp_edge_internal_saturating_add_u64(
			now_ms, delay);
}

int pqcp_edge_circuit_breaker_init(
	struct pqcp_edge_circuit_breaker *breaker,
	const struct pqcp_edge_circuit_policy *policy,
	struct pqcp_edge_circuit *circuits,
	size_t capacity)
{
	if (breaker == NULL || !policy_valid(policy) ||
	    circuits == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(breaker, 0, sizeof(*breaker));
	memset(circuits, 0,
	       capacity * sizeof(*circuits));
	breaker->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	breaker->policy = *policy;
	breaker->circuits = circuits;
	breaker->capacity = capacity;
	k_mutex_init(&breaker->lock);
	breaker->initialized = true;
	return 0;
}

int pqcp_edge_circuit_allow(
	struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id,
	uint64_t now_ms)
{
	struct pqcp_edge_circuit *circuit;
	int index;
	int ret = 0;

	if (breaker == NULL || !breaker->initialized ||
	    !pqcp_edge_internal_text_valid(
		    service_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    endpoint_id, PQCP_EDGE_ID_MAX_CHARS)) {
		return -EINVAL;
	}
	k_mutex_lock(&breaker->lock, K_FOREVER);
	index = get_or_create_circuit(
		breaker, service_id, endpoint_id, now_ms);
	if (index < 0) {
		ret = index;
		goto out;
	}
	circuit = &breaker->circuits[index];
	switch (circuit->state) {
	case PQCP_EDGE_CIRCUIT_CLOSED:
		ret = 0;
		break;
	case PQCP_EDGE_CIRCUIT_OPEN:
		if (now_ms < circuit->retry_at_ms) {
			ret = -EHOSTDOWN;
		} else {
			circuit->state =
				PQCP_EDGE_CIRCUIT_HALF_OPEN;
			circuit->last_transition_ms = now_ms;
			circuit->half_open_attempts = 1U;
		}
		break;
	case PQCP_EDGE_CIRCUIT_HALF_OPEN:
		if (circuit->half_open_attempts >=
		    breaker->policy.half_open_maximum) {
			ret = -EAGAIN;
		} else {
			++circuit->half_open_attempts;
		}
		break;
	case PQCP_EDGE_CIRCUIT_ISOLATED:
	default:
		ret = -EACCES;
		break;
	}
out:
	k_mutex_unlock(&breaker->lock);
	return ret;
}

int pqcp_edge_circuit_record(
	struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id,
	bool success,
	uint64_t now_ms)
{
	struct pqcp_edge_circuit *circuit;
	int index;
	int ret = 0;

	if (breaker == NULL || !breaker->initialized ||
	    service_id == NULL || endpoint_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&breaker->lock, K_FOREVER);
	index = circuit_index(
		breaker, service_id, endpoint_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	circuit = &breaker->circuits[index];
	if (circuit->state ==
	    PQCP_EDGE_CIRCUIT_ISOLATED) {
		ret = -EACCES;
		goto out;
	}
	if (success) {
		circuit->consecutive_failures = 0U;
		circuit->consecutive_successes =
			pqcp_edge_internal_saturating_add_u32(
				circuit->consecutive_successes,
				1U);
		if (circuit->state ==
			    PQCP_EDGE_CIRCUIT_HALF_OPEN &&
		    circuit->consecutive_successes >=
			    breaker->policy.
				    close_after_successes) {
			circuit->state =
				PQCP_EDGE_CIRCUIT_CLOSED;
			circuit->last_transition_ms = now_ms;
			circuit->retry_at_ms = 0U;
			circuit->half_open_attempts = 0U;
			circuit->total_opens /= 2U;
		}
	} else {
		circuit->consecutive_successes = 0U;
		circuit->consecutive_failures =
			pqcp_edge_internal_saturating_add_u32(
				circuit->consecutive_failures,
				1U);
		if (circuit->state ==
			    PQCP_EDGE_CIRCUIT_HALF_OPEN ||
		    circuit->consecutive_failures >=
			    breaker->policy.open_after_failures) {
			open_circuit(breaker, circuit, now_ms);
		}
	}
out:
	k_mutex_unlock(&breaker->lock);
	return ret;
}

int pqcp_edge_circuit_isolate(
	struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id)
{
	struct pqcp_edge_circuit *circuit;
	int index;
	int ret = 0;

	if (breaker == NULL || !breaker->initialized ||
	    service_id == NULL || endpoint_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&breaker->lock, K_FOREVER);
	index = circuit_index(
		breaker, service_id, endpoint_id);
	if (index < 0) {
		ret = index;
	} else {
		circuit = &breaker->circuits[index];
		circuit->state =
			PQCP_EDGE_CIRCUIT_ISOLATED;
		circuit->retry_at_ms = 0U;
	}
	k_mutex_unlock(&breaker->lock);
	return ret;
}

int pqcp_edge_circuit_reset(
	struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id,
	uint64_t now_ms)
{
	struct pqcp_edge_circuit *circuit;
	int index;
	int ret = 0;

	if (breaker == NULL || !breaker->initialized ||
	    service_id == NULL || endpoint_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&breaker->lock, K_FOREVER);
	index = circuit_index(
		breaker, service_id, endpoint_id);
	if (index < 0) {
		ret = index;
	} else {
		circuit = &breaker->circuits[index];
		circuit->state =
			PQCP_EDGE_CIRCUIT_CLOSED;
		circuit->opened_at_ms = 0U;
		circuit->retry_at_ms = 0U;
		circuit->last_transition_ms = now_ms;
		circuit->consecutive_successes = 0U;
		circuit->consecutive_failures = 0U;
		circuit->half_open_attempts = 0U;
	}
	k_mutex_unlock(&breaker->lock);
	return ret;
}

int pqcp_edge_circuit_tick(
	struct pqcp_edge_circuit_breaker *breaker,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (breaker == NULL || !breaker->initialized ||
	    changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&breaker->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < breaker->capacity; ++index) {
		struct pqcp_edge_circuit *circuit =
			&breaker->circuits[index];

		if (!circuit->occupied ||
		    circuit->state !=
			    PQCP_EDGE_CIRCUIT_OPEN ||
		    now_ms < circuit->retry_at_ms) {
			continue;
		}
		circuit->state =
			PQCP_EDGE_CIRCUIT_HALF_OPEN;
		circuit->last_transition_ms = now_ms;
		circuit->half_open_attempts = 0U;
		circuit->consecutive_successes = 0U;
		++changed;
	}
	k_mutex_unlock(&breaker->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_edge_circuit_breaker_audit(
	struct pqcp_edge_circuit_breaker *breaker)
{
	int ret = 0;

	if (breaker == NULL || !breaker->initialized ||
	    breaker->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    !policy_valid(&breaker->policy) ||
	    breaker->circuits == NULL ||
	    breaker->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&breaker->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < breaker->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_circuit *circuit =
			&breaker->circuits[index];

		if (!circuit->occupied) {
			continue;
		}
		if (!pqcp_edge_internal_text_valid(
			    circuit->service_id,
			    sizeof(circuit->service_id)) ||
		    !pqcp_edge_internal_text_valid(
			    circuit->endpoint_id,
			    sizeof(circuit->endpoint_id)) ||
		    circuit->state >
			    PQCP_EDGE_CIRCUIT_ISOLATED ||
		    (circuit->state ==
			     PQCP_EDGE_CIRCUIT_OPEN &&
		     circuit->retry_at_ms <=
			     circuit->opened_at_ms)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < breaker->capacity; ++other) {
			if (breaker->circuits[other].occupied &&
			    strcmp(
				    circuit->service_id,
				    breaker->circuits[other].
					    service_id) == 0 &&
			    strcmp(
				    circuit->endpoint_id,
				    breaker->circuits[other].
					    endpoint_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&breaker->lock);
	return ret;
}
