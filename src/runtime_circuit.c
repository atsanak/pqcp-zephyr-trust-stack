/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Per-profile circuit breaker for repeated executable failures.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_governance.h>

#include "runtime_internal.h"

int pqcp_runtime_circuit_init(
	struct pqcp_runtime_circuit *circuit,
	const char *profile_id,
	uint32_t failure_threshold,
	uint32_t recovery_success_threshold,
	uint64_t open_duration_ms)
{
	if (circuit == NULL ||
	    !pqcp_runtime_internal_text_valid(
		    profile_id, PQCP_RUNTIME_PROFILE_MAX_CHARS) ||
	    failure_threshold == 0U ||
	    recovery_success_threshold == 0U ||
	    open_duration_ms == 0U) {
		return -EINVAL;
	}
	memset(circuit, 0, sizeof(*circuit));
	circuit->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	circuit->failure_threshold = failure_threshold;
	circuit->recovery_success_threshold =
		recovery_success_threshold;
	circuit->open_duration_ms = open_duration_ms;
	return pqcp_runtime_internal_copy_text(
		circuit->profile_id, sizeof(circuit->profile_id),
		profile_id);
}

bool pqcp_runtime_circuit_allow(
	struct pqcp_runtime_circuit *circuit,
	uint64_t now_ms)
{
	if (circuit == NULL ||
	    circuit->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    now_ms == 0U) {
		return false;
	}
	if (!circuit->open) {
		return true;
	}
	if (now_ms - circuit->opened_at_ms >=
	    circuit->open_duration_ms) {
		circuit->half_open = true;
		return true;
	}
	return false;
}

int pqcp_runtime_circuit_record(
	struct pqcp_runtime_circuit *circuit,
	bool success,
	uint64_t now_ms)
{
	if (circuit == NULL ||
	    circuit->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	if (success) {
		circuit->total_successes++;
		circuit->consecutive_successes++;
		circuit->consecutive_failures = 0U;
		if (circuit->half_open &&
		    circuit->consecutive_successes >=
			    circuit->recovery_success_threshold) {
			circuit->open = false;
			circuit->half_open = false;
			circuit->opened_at_ms = 0U;
			circuit->consecutive_successes = 0U;
		}
		return 0;
	}
	circuit->total_failures++;
	circuit->consecutive_failures++;
	circuit->consecutive_successes = 0U;
	if (circuit->half_open ||
	    circuit->consecutive_failures >=
		    circuit->failure_threshold) {
		circuit->open = true;
		circuit->half_open = false;
		circuit->opened_at_ms = now_ms;
	}
	return circuit->open ? -EHOSTDOWN : -EAGAIN;
}

int pqcp_runtime_circuit_apply_profile(
	const struct pqcp_runtime_circuit *circuit,
	struct pqcp_adaptive_profile_registry *registry)
{
	if (circuit == NULL || registry == NULL ||
	    circuit->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
		return -EINVAL;
	}
	return pqcp_adaptive_profile_registry_enable(
		registry, circuit->profile_id, !circuit->open);
}
