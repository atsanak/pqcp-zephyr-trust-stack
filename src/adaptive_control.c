/*
 * SPDX-License-Identifier: MIT
 *
 * Closed-loop firmware-native adaptive PQC deployment controller.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

static bool mode_valid(enum pqcp_adaptive_mode mode)
{
	return mode >= PQCP_ADAPTIVE_MODE_SAFE &&
	       mode <= PQCP_ADAPTIVE_MODE_LOCKDOWN;
}

static bool control_input_valid(
	const struct pqcp_adaptive_control_input *input)
{
	if (input == NULL || input->now_ms == 0U ||
	    input->resource_limits == NULL ||
	    input->reason < PQCP_ADAPTIVE_REASON_NONE ||
	    input->reason > PQCP_ADAPTIVE_REASON_ROLLBACK ||
	    (input->required_operation_mask &
	     ~PQCP_DEPLOYMENT_OPERATION_MASK_KNOWN) != 0U) {
		return false;
	}
	if (input->telemetry != NULL &&
	    input->telemetry->timestamp_ms > input->now_ms) {
		return false;
	}
	if (input->threat_signal != NULL &&
	    input->threat_signal->timestamp_ms > input->now_ms) {
		return false;
	}
	if (input->health != NULL &&
	    input->health->timestamp_ms > input->now_ms) {
		return false;
	}
	return true;
}

static bool control_valid(
	const struct pqcp_adaptive_control_plane *control)
{
	return control != NULL &&
	       control->schema_version == PQCP_ADAPTIVE_SCHEMA_VERSION &&
	       pqcp_adaptive_internal_id_valid(control->device_id) &&
	       mode_valid(control->mode) &&
	       pqcp_adaptive_profile_registry_validate(
		       &control->registry) == 0 &&
	       pqcp_adaptive_policy_validate(&control->policy) == 0 &&
	       control->telemetry.schema_version ==
		       PQCP_ADAPTIVE_SCHEMA_VERSION &&
	       control->transition.schema_version ==
		       PQCP_ADAPTIVE_SCHEMA_VERSION &&
	       control->sessions.schema_version ==
		       PQCP_ADAPTIVE_SCHEMA_VERSION &&
	       control->workload.schema_version ==
		       PQCP_ADAPTIVE_SCHEMA_VERSION &&
	       control->resilience.schema_version ==
		       PQCP_ADAPTIVE_SCHEMA_VERSION &&
	       control->events.schema_version ==
		       PQCP_ADAPTIVE_SCHEMA_VERSION;
}

static enum pqcp_adaptive_mode mode_from_state(
	const struct pqcp_adaptive_control_plane *control)
{
	if (!control->resilience.sessions_permitted ||
	    control->resilience.action ==
		    PQCP_ADAPTIVE_RESILIENCE_LOCKDOWN ||
	    control->threat.level ==
		    PQCP_ADAPTIVE_THREAT_CRITICAL) {
		return PQCP_ADAPTIVE_MODE_LOCKDOWN;
	}
	if (control->resilience.recovery_required ||
	    control->resilience.action ==
		    PQCP_ADAPTIVE_RESILIENCE_RECOVERY) {
		return PQCP_ADAPTIVE_MODE_RECOVERY;
	}
	if (control->threat.level >=
		    PQCP_ADAPTIVE_THREAT_SEVERE ||
	    control->policy.profile ==
		    PQCP_ADAPTIVE_POLICY_CRITICAL_INFRASTRUCTURE) {
		return PQCP_ADAPTIVE_MODE_CONSERVATIVE;
	}
	if (control->resources.overall_pressure >=
		    PQCP_ADAPTIVE_PRESSURE_HIGH ||
	    control->resilience.action ==
		    PQCP_ADAPTIVE_RESILIENCE_DEGRADE_PERFORMANCE) {
		return PQCP_ADAPTIVE_MODE_SAFE;
	}
	if (control->policy.profile ==
		    PQCP_ADAPTIVE_POLICY_RESEARCH &&
	    control->resources.overall_pressure <=
		    PQCP_ADAPTIVE_PRESSURE_LOW &&
	    control->threat.level ==
		    PQCP_ADAPTIVE_THREAT_NOMINAL) {
		return PQCP_ADAPTIVE_MODE_PERFORMANCE;
	}
	return control->policy.default_mode;
}

static uint32_t default_operation_mask(
	const struct pqcp_adaptive_control_input *input)
{
	if (input->required_operation_mask != 0U) {
		return input->required_operation_mask;
	}
	return PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
	       PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING;
}

static enum pqcp_adaptive_transition_reason derive_reason(
	const struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input)
{
	if (input->reason != PQCP_ADAPTIVE_REASON_NONE) {
		return input->reason;
	}
	if (control->threat.level >= PQCP_ADAPTIVE_THREAT_HIGH) {
		return PQCP_ADAPTIVE_REASON_THREAT_ESCALATION;
	}
	if (control->resources.overall_pressure >=
	    PQCP_ADAPTIVE_PRESSURE_HIGH) {
		return PQCP_ADAPTIVE_REASON_RESOURCE_PRESSURE;
	}
	if (control->forecast.latency_limit_expected) {
		return PQCP_ADAPTIVE_REASON_LATENCY_PRESSURE;
	}
	if (control->forecast.energy_limit_expected) {
		return PQCP_ADAPTIVE_REASON_ENERGY_PRESSURE;
	}
	if (input->fleet != NULL && input->fleet->quorum_reached) {
		return PQCP_ADAPTIVE_REASON_FLEET_CONSENSUS;
	}
	return PQCP_ADAPTIVE_REASON_POLICY_CHANGE;
}

static void initialize_result(
	const struct pqcp_adaptive_control_plane *control,
	struct pqcp_adaptive_control_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	result->mode = control->mode;
	result->threat_level = control->threat.level;
	result->resource_pressure =
		control->resources.overall_pressure;
	pqcp_adaptive_internal_set_text(
		result->active_profile_id,
		sizeof(result->active_profile_id),
		control->transition.current_profile_id);
	pqcp_adaptive_internal_set_text(
		result->recommended_profile_id,
		sizeof(result->recommended_profile_id),
		control->transition.current_profile_id);
}

static void merge_status(
	enum pqcp_adaptive_status status,
	struct pqcp_adaptive_control_result *result)
{
	if (status == PQCP_ADAPTIVE_STATUS_FAIL) {
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
	} else if (status == PQCP_ADAPTIVE_STATUS_WARN &&
		   result->status == PQCP_ADAPTIVE_STATUS_PASS) {
		result->status = PQCP_ADAPTIVE_STATUS_WARN;
	}
}

static void append_event_best_effort(
	struct pqcp_adaptive_control_plane *control,
	enum pqcp_adaptive_event_type type,
	enum pqcp_adaptive_status status,
	uint64_t now_ms,
	uint32_t reason_mask,
	uint32_t blocker_mask,
	uint32_t warning_mask,
	uint32_t score,
	const char *profile_id,
	const char *related_id)
{
	if (pqcp_adaptive_event_log_append(
		    &control->events, type, status, now_ms,
		    reason_mask, blocker_mask, warning_mask,
		    score, profile_id, related_id) != 0) {
		control->failure_count++;
	}
}

static struct pqcp_adaptive_health_signal default_health(
	const struct pqcp_adaptive_control_plane *control,
	uint64_t now_ms)
{
	struct pqcp_adaptive_health_signal signal = {
		.timestamp_ms = now_ms,
		.consecutive_failures =
			control->failure_count > 16U ?
			16U : control->failure_count,
		.total_failures = control->failure_count,
		.digest_failures = 0U,
		.replay_failures = 0U,
		.transition_failures =
			control->transition.rejected_count,
		.session_failures =
			control->sessions.rejected_count,
		.watchdog_resets = 0U,
		.profile_fault_mask = 0U,
		.state_corrupt = false,
		.backend_unavailable = false,
		.entropy_degraded = false,
	};

	return signal;
}

static int process_telemetry(
	struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input,
	struct pqcp_adaptive_control_result *result)
{
	struct pqcp_adaptive_forecast_policy forecast_policy;
	int ret;

	if (input->telemetry != NULL) {
		ret = pqcp_adaptive_telemetry_push(
			&control->telemetry, input->telemetry);
		if (ret != 0) {
			result->warning_mask |=
				PQCP_ADAPTIVE_WARNING_TELEMETRY_STALE;
			control->failure_count++;
		}
	}
	if (control->telemetry.count == 0U) {
		result->warning_mask |=
			PQCP_ADAPTIVE_WARNING_LOW_CONFIDENCE;
		return 0;
	}
	ret = pqcp_adaptive_telemetry_summarize(
		&control->telemetry, input->resource_limits,
		&control->telemetry_summary);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_adaptive_forecast_default_policy(
		&forecast_policy);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_adaptive_forecast_run(
		&control->telemetry,
		&control->telemetry_summary,
		input->resource_limits,
		&forecast_policy,
		&control->forecast);
	if (ret != 0) {
		return ret;
	}
	result->warning_mask |=
		control->forecast.warning_mask;
	merge_status(
		control->telemetry_summary.status, result);
	merge_status(control->forecast.status, result);
	append_event_best_effort(
		control, PQCP_ADAPTIVE_EVENT_TELEMETRY,
		control->telemetry_summary.status,
		input->now_ms,
		control->telemetry_summary.anomaly_mask,
		0U, control->forecast.warning_mask,
		control->forecast.confidence,
		control->transition.current_profile_id,
		"telemetry");
	return 0;
}

static int process_threat(
	struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input,
	struct pqcp_adaptive_control_result *result)
{
	struct pqcp_adaptive_threat_policy policy;
	struct pqcp_adaptive_threat_signal nominal;
	const struct pqcp_adaptive_threat_signal *signal =
		input->threat_signal;
	enum pqcp_adaptive_threat_level previous =
		control->threat.level;
	int ret;

	if (signal == NULL) {
		memset(&nominal, 0, sizeof(nominal));
		nominal.timestamp_ms = input->now_ms;
		signal = &nominal;
	}
	ret = pqcp_adaptive_threat_default_policy(&policy);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_adaptive_threat_assess(
		signal,
		control->telemetry.count != 0U ?
			&control->telemetry_summary : NULL,
		&policy, &control->threat);
	if (ret != 0) {
		return ret;
	}
	result->threat_level = control->threat.level;
	merge_status(control->threat.status, result);
	if (previous != control->threat.level) {
		append_event_best_effort(
			control, PQCP_ADAPTIVE_EVENT_THREAT_CHANGE,
			control->threat.status, input->now_ms,
			control->threat.reason_mask, 0U, 0U,
			control->threat.score,
			control->transition.current_profile_id,
			"threat");
	}
	return 0;
}

static int process_resources(
	struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input,
	struct pqcp_adaptive_control_result *result)
{
	int ret = pqcp_adaptive_resource_assess(
		input->resource_limits,
		control->telemetry.count != 0U ?
			&control->telemetry_summary : NULL,
		control->telemetry.count != 0U ?
			&control->forecast : NULL,
		&control->resources);

	if (ret != 0) {
		return ret;
	}
	result->resource_pressure =
		control->resources.overall_pressure;
	result->blocker_mask |=
		control->resources.status ==
			PQCP_ADAPTIVE_STATUS_FAIL ?
		PQCP_ADAPTIVE_BLOCK_POLICY : 0U;
	merge_status(control->resources.status, result);
	return 0;
}

static int process_resilience(
	struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input,
	struct pqcp_adaptive_control_result *result)
{
	struct pqcp_adaptive_resilience_policy policy;
	struct pqcp_adaptive_health_signal fallback;
	const struct pqcp_adaptive_health_signal *signal =
		input->health;
	int ret;

	if (signal == NULL) {
		fallback = default_health(control, input->now_ms);
		signal = &fallback;
	}
	ret = pqcp_adaptive_resilience_default_policy(&policy);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_adaptive_resilience_evaluate(
		&control->resilience, &policy, signal,
		&control->transition, &control->registry);
	if (ret != 0) {
		return ret;
	}
	result->blocker_mask |= control->resilience.blocker_mask;
	result->warning_mask |= control->resilience.warning_mask;
	merge_status(control->resilience.status, result);
	if (control->resilience.action >=
	    PQCP_ADAPTIVE_RESILIENCE_RECOVERY) {
		append_event_best_effort(
			control, PQCP_ADAPTIVE_EVENT_FAULT,
			control->resilience.status,
			input->now_ms,
			(uint32_t)control->resilience.action,
			control->resilience.blocker_mask,
			control->resilience.warning_mask,
			signal->consecutive_failures,
			control->transition.current_profile_id,
			"resilience");
	}
	return 0;
}

static void restrict_recommendation_for_resilience(
	struct pqcp_adaptive_control_plane *control)
{
	const char *recommended =
		control->recommendation.recommended_profile_id;

	if (!control->resilience.transitions_permitted ||
	    !pqcp_adaptive_resilience_profile_allowed(
		    &control->resilience, &control->registry,
		    recommended)) {
		control->recommendation.transition_recommended = false;
		control->recommendation.warning_mask |=
			PQCP_ADAPTIVE_WARNING_TRANSITION_FLAP;
		pqcp_adaptive_internal_set_text(
			control->recommendation.recommended_profile_id,
			sizeof(control->recommendation
				       .recommended_profile_id),
			control->transition.current_profile_id);
	}
}

static int process_recommendation(
	struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input,
	struct pqcp_adaptive_control_result *result)
{
	char previous_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	uint32_t operations = default_operation_mask(input);
	int ret;

	pqcp_adaptive_internal_set_text(
		previous_id, sizeof(previous_id),
		control->recommendation.recommended_profile_id[0] != '\0' ?
			control->recommendation.recommended_profile_id :
			control->transition.current_profile_id);
	ret = pqcp_adaptive_optimizer_run(
		&control->registry, &control->policy,
		&control->threat, input->resource_limits,
		&control->resources,
		control->telemetry.count != 0U ?
			&control->forecast : NULL,
		input->fleet, operations,
		control->transition.current_profile_id,
		&control->recommendation);
	if (ret != 0) {
		return ret;
	}
	restrict_recommendation_for_resilience(control);
	result->confidence = control->recommendation.confidence;
	result->warning_mask |=
		control->recommendation.warning_mask;
	pqcp_adaptive_internal_set_text(
		result->recommended_profile_id,
		sizeof(result->recommended_profile_id),
		control->recommendation.recommended_profile_id);
	result->recommendation_changed =
		strcmp(previous_id,
		       control->recommendation
			       .recommended_profile_id) != 0;
	merge_status(control->recommendation.status, result);
	append_event_best_effort(
		control, PQCP_ADAPTIVE_EVENT_RECOMMENDATION,
		control->recommendation.status, input->now_ms,
		operations, 0U,
		control->recommendation.warning_mask,
		control->recommendation.evaluated_count != 0U ?
			control->recommendation.candidates[0]
				.total_score : 0U,
		control->recommendation.recommended_profile_id,
		"optimizer");
	return 0;
}

static bool transition_conflicts_with_sessions(
	const struct pqcp_adaptive_control_plane *control)
{
	return control->sessions.active_count != 0U &&
	       pqcp_adaptive_session_profile_busy(
		       &control->sessions,
		       control->transition.current_profile_id);
}

static int evaluate_downgrade_for_pending(
	struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input,
	enum pqcp_adaptive_transition_reason reason,
	struct pqcp_adaptive_downgrade_result *downgrade)
{
	const struct pqcp_adaptive_profile *from =
		pqcp_adaptive_profile_registry_find(
			&control->registry,
			control->transition.current_profile_id);
	const struct pqcp_adaptive_profile *to =
		pqcp_adaptive_profile_registry_find(
			&control->registry,
			control->transition.pending_profile_id);
	struct pqcp_adaptive_downgrade_authorization authorization;
	struct pqcp_adaptive_downgrade_authorization *auth = NULL;

	if (from == NULL || to == NULL) {
		return -ENOENT;
	}
	if (input->authorization != NULL) {
		authorization = *input->authorization;
		auth = &authorization;
	}
	return pqcp_adaptive_downgrade_evaluate(
		from, to, reason, input->now_ms,
		&control->policy, &control->threat,
		auth, downgrade);
}

static int process_transition(
	struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input,
	struct pqcp_adaptive_control_result *result)
{
	struct pqcp_adaptive_transition_result transition_result;
	struct pqcp_adaptive_downgrade_result downgrade;
	enum pqcp_adaptive_transition_reason reason =
		derive_reason(control, input);
	int ret;

	ret = pqcp_adaptive_transition_tick(
		&control->transition, input->now_ms);
	if (ret != 0) {
		return ret;
	}
	if (!control->recommendation.transition_recommended &&
	    !input->force_recommendation) {
		return 0;
	}
	if (!control->resilience.transitions_permitted) {
		result->blocker_mask |= PQCP_ADAPTIVE_BLOCK_POLICY;
		result->warning_mask |=
			PQCP_ADAPTIVE_WARNING_TRANSITION_FLAP;
		return 0;
	}
	if (transition_conflicts_with_sessions(control)) {
		result->blocker_mask |=
			PQCP_ADAPTIVE_BLOCK_SESSION_CONFLICT;
		result->warning_mask |=
			PQCP_ADAPTIVE_WARNING_PENDING_SESSIONS;
		append_event_best_effort(
			control,
			PQCP_ADAPTIVE_EVENT_TRANSITION_REJECT,
			PQCP_ADAPTIVE_STATUS_FAIL,
			input->now_ms, (uint32_t)reason,
			PQCP_ADAPTIVE_BLOCK_SESSION_CONFLICT,
			PQCP_ADAPTIVE_WARNING_PENDING_SESSIONS,
			0U,
			control->transition.current_profile_id,
			control->recommendation
				.recommended_profile_id);
		return 0;
	}
	ret = pqcp_adaptive_transition_request(
		&control->transition, &control->policy,
		&control->recommendation, reason,
		input->now_ms, &transition_result);
	if (ret != 0) {
		return ret;
	}
	result->blocker_mask |= transition_result.blocker_mask;
	result->warning_mask |= transition_result.warning_mask;
	append_event_best_effort(
		control,
		transition_result.status ==
			PQCP_ADAPTIVE_STATUS_FAIL ?
		PQCP_ADAPTIVE_EVENT_TRANSITION_REJECT :
		PQCP_ADAPTIVE_EVENT_TRANSITION_REQUEST,
		transition_result.status,
		input->now_ms, (uint32_t)reason,
		transition_result.blocker_mask,
		transition_result.warning_mask,
		transition_result.confirmations,
		transition_result.from_profile_id,
		transition_result.to_profile_id);
	if (!input->commit_transition ||
	    control->transition.state !=
		    PQCP_ADAPTIVE_TRANSITION_PREPARING) {
		return 0;
	}
	memset(&downgrade, 0, sizeof(downgrade));
	ret = evaluate_downgrade_for_pending(
		control, input, reason, &downgrade);
	if (ret != 0) {
		return ret;
	}
	result->downgrade_authorized =
		!downgrade.downgrade ||
		downgrade.authorization_valid;
	ret = pqcp_adaptive_transition_commit(
		&control->transition, &control->policy,
		&downgrade, input->now_ms,
		&transition_result);
	if (ret != 0) {
		return ret;
	}
	result->blocker_mask |= transition_result.blocker_mask;
	result->warning_mask |= transition_result.warning_mask;
	result->transition_committed = transition_result.changed;
	pqcp_adaptive_internal_set_text(
		result->active_profile_id,
		sizeof(result->active_profile_id),
		control->transition.current_profile_id);
	append_event_best_effort(
		control,
		transition_result.changed ?
		PQCP_ADAPTIVE_EVENT_TRANSITION_COMMIT :
		PQCP_ADAPTIVE_EVENT_TRANSITION_REJECT,
		transition_result.status,
		input->now_ms, (uint32_t)reason,
		transition_result.blocker_mask,
		transition_result.warning_mask,
		transition_result.confirmations,
		transition_result.from_profile_id,
		transition_result.to_profile_id);
	return 0;
}

static void finalize_result(
	struct pqcp_adaptive_control_plane *control,
	struct pqcp_adaptive_control_result *result)
{
	control->mode = mode_from_state(control);
	result->mode = control->mode;
	result->threat_level = control->threat.level;
	result->resource_pressure =
		control->resources.overall_pressure;
	if (result->blocker_mask != 0U ||
	    control->mode == PQCP_ADAPTIVE_MODE_LOCKDOWN) {
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
	} else if (result->warning_mask != 0U ||
		   control->mode == PQCP_ADAPTIVE_MODE_RECOVERY ||
		   control->mode == PQCP_ADAPTIVE_MODE_SAFE) {
		result->status = PQCP_ADAPTIVE_STATUS_WARN;
	} else if (result->status != PQCP_ADAPTIVE_STATUS_FAIL) {
		result->status = PQCP_ADAPTIVE_STATUS_PASS;
	}
	pqcp_adaptive_internal_set_text(
		result->active_profile_id,
		sizeof(result->active_profile_id),
		control->transition.current_profile_id);
	pqcp_adaptive_internal_set_text(
		result->recommended_profile_id,
		sizeof(result->recommended_profile_id),
		control->recommendation.recommended_profile_id);
}

int pqcp_adaptive_control_init(
	struct pqcp_adaptive_control_plane *control,
	const char *device_id,
	enum pqcp_adaptive_policy_profile policy_profile,
	const char *initial_profile_id,
	uint64_t now_ms)
{
	const struct pqcp_adaptive_profile *initial;
	int ret;

	if (control == NULL ||
	    !pqcp_adaptive_internal_id_valid(device_id) ||
	    !pqcp_adaptive_internal_id_valid(initial_profile_id) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	memset(control, 0, sizeof(*control));
	control->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	pqcp_adaptive_internal_set_text(
		control->device_id, sizeof(control->device_id),
		device_id);
	if ((ret = pqcp_adaptive_profile_registry_default(
		     &control->registry)) != 0 ||
	    (ret = pqcp_adaptive_policy_default(
		     policy_profile, &control->policy)) != 0) {
		return ret;
	}
	initial = pqcp_adaptive_profile_registry_find(
		&control->registry, initial_profile_id);
	if (initial == NULL || !initial->enabled) {
		return -ENOENT;
	}
	control->mode = control->policy.default_mode;
	if ((ret = pqcp_adaptive_telemetry_init(
		     &control->telemetry)) != 0 ||
	    (ret = pqcp_adaptive_transition_init(
		     &control->transition,
		     initial_profile_id, now_ms)) != 0 ||
	    (ret = pqcp_adaptive_session_table_init(
		     &control->sessions)) != 0 ||
	    (ret = pqcp_adaptive_workload_init(
		     &control->workload)) != 0 ||
	    (ret = pqcp_adaptive_resilience_init(
		     &control->resilience)) != 0 ||
	    (ret = pqcp_adaptive_event_log_init(
		     &control->events)) != 0) {
		return ret;
	}
	pqcp_adaptive_internal_set_text(
		control->recommendation.current_profile_id,
		sizeof(control->recommendation.current_profile_id),
		initial_profile_id);
	pqcp_adaptive_internal_set_text(
		control->recommendation.recommended_profile_id,
		sizeof(control->recommendation
			       .recommended_profile_id),
		initial_profile_id);
	append_event_best_effort(
		control, PQCP_ADAPTIVE_EVENT_BOOT,
		PQCP_ADAPTIVE_STATUS_PASS, now_ms,
		0U, 0U, 0U, initial->security_level,
		initial_profile_id, device_id);
	return pqcp_adaptive_internal_digest_control(
		control, control->state_digest_hex);
}

int pqcp_adaptive_control_cycle(
	struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input,
	struct pqcp_adaptive_control_result *result)
{
	int ret;

	if (!control_valid(control) ||
	    !control_input_valid(input) || result == NULL) {
		return -EINVAL;
	}
	initialize_result(control, result);
	result->status = PQCP_ADAPTIVE_STATUS_PASS;
	control->cycle_count++;
	ret = process_telemetry(control, input, result);
	if (ret == 0) {
		ret = process_threat(control, input, result);
	}
	if (ret == 0) {
		ret = process_resources(control, input, result);
	}
	if (ret == 0) {
		ret = process_resilience(control, input, result);
	}
	if (ret == 0) {
		ret = process_recommendation(control, input, result);
	}
	if (ret == 0) {
		ret = process_transition(control, input, result);
	}
	if (ret != 0) {
		control->failure_count++;
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
		result->blocker_mask |= PQCP_ADAPTIVE_BLOCK_POLICY;
		append_event_best_effort(
			control, PQCP_ADAPTIVE_EVENT_FAULT,
			PQCP_ADAPTIVE_STATUS_FAIL,
			input->now_ms, (uint32_t)-ret,
			result->blocker_mask,
			result->warning_mask,
			control->failure_count,
			control->transition.current_profile_id,
			"control_cycle");
	}
	finalize_result(control, result);
	ret = pqcp_adaptive_internal_digest_control(
		control, control->state_digest_hex);
	if (ret != 0) {
		return ret;
	}
	pqcp_adaptive_internal_set_text(
		result->control_digest_hex,
		sizeof(result->control_digest_hex),
		control->state_digest_hex);
	return result->status == PQCP_ADAPTIVE_STATUS_FAIL ?
		-EACCES : 0;
}

int pqcp_adaptive_control_emit(
	const struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_result *result)
{
	if (!control_valid(control) || result == NULL ||
	    result->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_CONTROL schema=%u device=%s status=%s mode=%s cycles=%u failures=%u threat=%s pressure=%s confidence=%u blockers=0x%08x warnings=0x%08x changed=%u committed=%u downgrade_authorized=%u active=%s recommended=%s telemetry=%s forecast=%s threat_digest=%s resource_digest=%s recommendation_digest=%s transition_digest=%s workload_digest=%s resilience_digest=%s event_root=%s control_digest=%s\n",
	       result->schema_version,
	       control->device_id,
	       pqcp_adaptive_status_str(result->status),
	       pqcp_adaptive_mode_str(result->mode),
	       control->cycle_count,
	       control->failure_count,
	       pqcp_adaptive_threat_level_str(result->threat_level),
	       pqcp_adaptive_pressure_str(
		       result->resource_pressure),
	       result->confidence,
	       result->blocker_mask,
	       result->warning_mask,
	       result->recommendation_changed ? 1U : 0U,
	       result->transition_committed ? 1U : 0U,
	       result->downgrade_authorized ? 1U : 0U,
	       result->active_profile_id,
	       result->recommended_profile_id,
	       control->telemetry_summary.telemetry_digest_hex,
	       control->forecast.forecast_digest_hex,
	       control->threat.threat_digest_hex,
	       control->resources.resource_digest_hex,
	       control->recommendation.recommendation_digest_hex,
	       control->transition.controller_digest_hex,
	       control->workload.queue_digest_hex,
	       control->resilience.resilience_digest_hex,
	       control->events.root_digest_hex,
	       result->control_digest_hex);
	return 0;
}
