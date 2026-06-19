/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Runtime failure isolation and safe-mode escalation.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_RESILIENCE_DOMAIN UINT64_C(0x414450524553494c)

static bool resilience_policy_valid(
	const struct pqcp_adaptive_resilience_policy *policy)
{
	return policy != NULL &&
	       policy->warn_failure_count != 0U &&
	       policy->warn_failure_count <
		       policy->rollback_failure_count &&
	       policy->rollback_failure_count <
		       policy->recovery_failure_count &&
	       policy->recovery_failure_count <
		       policy->lockdown_failure_count &&
	       policy->maximum_profile_faults != 0U &&
	       policy->maximum_profile_faults <=
		       PQCP_ADAPTIVE_MAX_PROFILES &&
	       policy->recovery_stability_cycles != 0U;
}

static bool health_signal_valid(
	const struct pqcp_adaptive_health_signal *signal)
{
	return signal != NULL &&
	       signal->timestamp_ms != 0U &&
	       signal->consecutive_failures <= signal->total_failures &&
	       (signal->profile_fault_mask &
		~((1U << PQCP_ADAPTIVE_MAX_PROFILES) - 1U)) == 0U;
}

static int resilience_digest(
	struct pqcp_adaptive_resilience_state *state)
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_RESILIENCE_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, state->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)state->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)state->action);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, state->blocker_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, state->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, state->isolated_profile_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, state->stable_cycles);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, state->incident_count);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, state->last_incident_ms);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, state->transitions_permitted);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, state->sessions_permitted);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, state->recovery_required);
	pqcp_deployment_evidence_digest_update_text(
		&digest, state->pinned_profile_id);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, state->resilience_digest_hex);
}

static enum pqcp_adaptive_resilience_action failure_action(
	const struct pqcp_adaptive_resilience_policy *policy,
	const struct pqcp_adaptive_health_signal *signal)
{
	uint32_t failures = signal->consecutive_failures;

	if (signal->state_corrupt &&
	    policy->fail_closed_on_state_corruption) {
		return PQCP_ADAPTIVE_RESILIENCE_LOCKDOWN;
	}
	if (signal->backend_unavailable &&
	    policy->fail_closed_on_backend_loss) {
		return PQCP_ADAPTIVE_RESILIENCE_LOCKDOWN;
	}
	if (failures >= policy->lockdown_failure_count) {
		return PQCP_ADAPTIVE_RESILIENCE_LOCKDOWN;
	}
	if (failures >= policy->recovery_failure_count ||
	    signal->watchdog_resets >= 2U ||
	    signal->digest_failures >= 2U ||
	    signal->replay_failures >= 2U) {
		return PQCP_ADAPTIVE_RESILIENCE_RECOVERY;
	}
	if (failures >= policy->rollback_failure_count ||
	    signal->transition_failures >= 2U) {
		return PQCP_ADAPTIVE_RESILIENCE_ROLLBACK;
	}
	if (pqcp_adaptive_internal_bit_count(
		    signal->profile_fault_mask) != 0U) {
		return PQCP_ADAPTIVE_RESILIENCE_PIN_PROFILE;
	}
	if (failures >= policy->warn_failure_count ||
	    signal->entropy_degraded ||
	    signal->session_failures >= 2U) {
		return PQCP_ADAPTIVE_RESILIENCE_DEGRADE_PERFORMANCE;
	}
	return PQCP_ADAPTIVE_RESILIENCE_CONTINUE;
}

static const char *select_safe_profile(
	const struct pqcp_adaptive_profile_registry *registry,
	uint32_t isolated_mask)
{
	const struct pqcp_adaptive_profile *best = NULL;
	uint32_t best_strength = 0U;

	for (uint32_t index = 0U; index < registry->count; ++index) {
		const struct pqcp_adaptive_profile *profile =
			&registry->profiles[index];
		uint32_t strength;

		if ((isolated_mask & (1U << index)) != 0U ||
		    !profile->enabled ||
		    !profile->native_provider ||
		    !profile->production_allowed) {
			continue;
		}
		strength =
			pqcp_adaptive_internal_profile_security_strength(
				profile);
		if (best == NULL || strength > best_strength ||
		    (strength == best_strength &&
		     strcmp(profile->profile_id,
			    best->profile_id) < 0)) {
			best = profile;
			best_strength = strength;
		}
	}
	return best != NULL ? best->profile_id : NULL;
}

static void apply_action(
	struct pqcp_adaptive_resilience_state *state,
	const struct pqcp_adaptive_resilience_policy *policy,
	const struct pqcp_adaptive_health_signal *signal,
	const struct pqcp_adaptive_transition_controller *transition,
	const struct pqcp_adaptive_profile_registry *registry)
{
	const char *safe_profile;

	state->action = failure_action(policy, signal);
	state->isolated_profile_mask |= signal->profile_fault_mask;
	state->transitions_permitted = true;
	state->sessions_permitted = true;
	state->recovery_required = false;
	state->blocker_mask = 0U;
	state->warning_mask = 0U;
	switch (state->action) {
	case PQCP_ADAPTIVE_RESILIENCE_CONTINUE:
		state->stable_cycles++;
		if (state->stable_cycles >=
		    policy->recovery_stability_cycles) {
			state->isolated_profile_mask &=
				signal->profile_fault_mask;
		}
		break;
	case PQCP_ADAPTIVE_RESILIENCE_DEGRADE_PERFORMANCE:
		state->warning_mask |=
			PQCP_ADAPTIVE_WARNING_FORECAST_PRESSURE;
		state->stable_cycles = 0U;
		break;
	case PQCP_ADAPTIVE_RESILIENCE_PIN_PROFILE:
		state->transitions_permitted = false;
		state->warning_mask |=
			PQCP_ADAPTIVE_WARNING_TRANSITION_FLAP;
		state->stable_cycles = 0U;
		break;
	case PQCP_ADAPTIVE_RESILIENCE_ROLLBACK:
		state->transitions_permitted = true;
		state->warning_mask |=
			PQCP_ADAPTIVE_WARNING_TRANSITION_FLAP;
		state->stable_cycles = 0U;
		break;
	case PQCP_ADAPTIVE_RESILIENCE_RECOVERY:
		state->recovery_required = true;
		state->transitions_permitted = false;
		state->blocker_mask |=
			PQCP_ADAPTIVE_BLOCK_POLICY;
		state->stable_cycles = 0U;
		break;
	case PQCP_ADAPTIVE_RESILIENCE_LOCKDOWN:
	default:
		state->recovery_required = true;
		state->transitions_permitted = false;
		state->sessions_permitted = false;
		state->blocker_mask |=
			PQCP_ADAPTIVE_BLOCK_POLICY |
			PQCP_ADAPTIVE_BLOCK_PROVIDER;
		state->stable_cycles = 0U;
		break;
	}
	if (signal->entropy_degraded &&
	    policy->prohibit_transition_on_entropy_degradation) {
		state->transitions_permitted = false;
		state->blocker_mask |=
			PQCP_ADAPTIVE_BLOCK_POLICY;
	}
	if (transition != NULL &&
	    state->action == PQCP_ADAPTIVE_RESILIENCE_PIN_PROFILE) {
		pqcp_adaptive_internal_set_text(
			state->pinned_profile_id,
			sizeof(state->pinned_profile_id),
			transition->current_profile_id);
	} else {
		safe_profile = select_safe_profile(
			registry, state->isolated_profile_mask);
		if (safe_profile != NULL) {
			pqcp_adaptive_internal_set_text(
				state->pinned_profile_id,
				sizeof(state->pinned_profile_id),
				safe_profile);
		} else {
			pqcp_adaptive_internal_set_text(
				state->pinned_profile_id,
				sizeof(state->pinned_profile_id),
				"none");
			state->sessions_permitted = false;
			state->blocker_mask |=
				PQCP_ADAPTIVE_BLOCK_PROVIDER;
		}
	}
}

int pqcp_adaptive_resilience_default_policy(
	struct pqcp_adaptive_resilience_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->warn_failure_count = 2U;
	policy->rollback_failure_count = 3U;
	policy->recovery_failure_count = 5U;
	policy->lockdown_failure_count = 8U;
	policy->maximum_profile_faults = 3U;
	policy->recovery_stability_cycles = 8U;
	policy->fail_closed_on_state_corruption = true;
	policy->fail_closed_on_backend_loss = true;
	policy->prohibit_transition_on_entropy_degradation = true;
	return 0;
}

int pqcp_adaptive_resilience_init(
	struct pqcp_adaptive_resilience_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}
	memset(state, 0, sizeof(*state));
	state->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	state->status = PQCP_ADAPTIVE_STATUS_PASS;
	state->action = PQCP_ADAPTIVE_RESILIENCE_CONTINUE;
	state->transitions_permitted = true;
	state->sessions_permitted = true;
	pqcp_adaptive_internal_set_text(
		state->pinned_profile_id,
		sizeof(state->pinned_profile_id), "none");
	return resilience_digest(state);
}

int pqcp_adaptive_resilience_evaluate(
	struct pqcp_adaptive_resilience_state *state,
	const struct pqcp_adaptive_resilience_policy *policy,
	const struct pqcp_adaptive_health_signal *signal,
	const struct pqcp_adaptive_transition_controller *transition,
	const struct pqcp_adaptive_profile_registry *registry)
{
	enum pqcp_adaptive_resilience_action previous;

	if (state == NULL ||
	    state->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !resilience_policy_valid(policy) ||
	    !health_signal_valid(signal) ||
	    pqcp_adaptive_profile_registry_validate(registry) != 0) {
		return -EINVAL;
	}
	previous = state->action;
	apply_action(
		state, policy, signal, transition, registry);
	if (state->action != PQCP_ADAPTIVE_RESILIENCE_CONTINUE &&
	    (previous != state->action ||
	     state->last_incident_ms != signal->timestamp_ms)) {
		state->incident_count++;
		state->last_incident_ms = signal->timestamp_ms;
	}
	if (state->action >= PQCP_ADAPTIVE_RESILIENCE_RECOVERY ||
	    state->blocker_mask != 0U) {
		state->status = PQCP_ADAPTIVE_STATUS_FAIL;
	} else if (state->action !=
		   PQCP_ADAPTIVE_RESILIENCE_CONTINUE ||
		   state->warning_mask != 0U) {
		state->status = PQCP_ADAPTIVE_STATUS_WARN;
	} else {
		state->status = PQCP_ADAPTIVE_STATUS_PASS;
	}
	return resilience_digest(state);
}

bool pqcp_adaptive_resilience_profile_allowed(
	const struct pqcp_adaptive_resilience_state *state,
	const struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id)
{
	const struct pqcp_adaptive_profile *profile;

	if (state == NULL || registry == NULL ||
	    !pqcp_adaptive_internal_id_valid(profile_id)) {
		return false;
	}
	profile = pqcp_adaptive_profile_registry_find(
		registry, profile_id);
	if (profile == NULL) {
		return false;
	}
	for (uint32_t index = 0U; index < registry->count; ++index) {
		if (&registry->profiles[index] == profile) {
			return (state->isolated_profile_mask &
				(1U << index)) == 0U &&
			       profile->enabled &&
			       profile->native_provider;
		}
	}
	return false;
}

static const char *resilience_action_str(
	enum pqcp_adaptive_resilience_action action)
{
	switch (action) {
	case PQCP_ADAPTIVE_RESILIENCE_CONTINUE:
		return "continue";
	case PQCP_ADAPTIVE_RESILIENCE_DEGRADE_PERFORMANCE:
		return "degrade_performance";
	case PQCP_ADAPTIVE_RESILIENCE_PIN_PROFILE:
		return "pin_profile";
	case PQCP_ADAPTIVE_RESILIENCE_ROLLBACK:
		return "rollback";
	case PQCP_ADAPTIVE_RESILIENCE_RECOVERY:
		return "recovery";
	case PQCP_ADAPTIVE_RESILIENCE_LOCKDOWN:
		return "lockdown";
	default:
		return "invalid";
	}
}

int pqcp_adaptive_resilience_emit(
	const struct pqcp_adaptive_resilience_state *state)
{
	if (state == NULL ||
	    state->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_RESILIENCE schema=%u status=%s action=%s blockers=0x%08x warnings=0x%08x isolated=0x%08x stable_cycles=%u incidents=%u last_incident_ms=%llu transitions=%u sessions=%u recovery=%u pinned=%s digest=%s\n",
	       state->schema_version,
	       pqcp_adaptive_status_str(state->status),
	       resilience_action_str(state->action),
	       state->blocker_mask,
	       state->warning_mask,
	       state->isolated_profile_mask,
	       state->stable_cycles,
	       state->incident_count,
	       (unsigned long long)state->last_incident_ms,
	       state->transitions_permitted ? 1U : 0U,
	       state->sessions_permitted ? 1U : 0U,
	       state->recovery_required ? 1U : 0U,
	       state->pinned_profile_id,
	       state->resilience_digest_hex);
	return 0;
}
