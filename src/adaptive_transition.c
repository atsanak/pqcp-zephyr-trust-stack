/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Hysteretic transition state machine for adaptive PQC profiles.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_TRANSITION_DOMAIN UINT64_C(0x4144505452414e53)
#define PQCP_ADAPTIVE_HOUR_MS UINT64_C(3600000)

static bool controller_valid(
	const struct pqcp_adaptive_transition_controller *controller)
{
	return controller != NULL &&
	       controller->schema_version ==
		       PQCP_ADAPTIVE_SCHEMA_VERSION &&
	       controller->state >= PQCP_ADAPTIVE_TRANSITION_STABLE &&
	       controller->state <= PQCP_ADAPTIVE_TRANSITION_BLOCKED &&
	       pqcp_adaptive_internal_id_valid(
		       controller->current_profile_id);
}

static bool reason_valid(enum pqcp_adaptive_transition_reason reason)
{
	return reason >= PQCP_ADAPTIVE_REASON_NONE &&
	       reason <= PQCP_ADAPTIVE_REASON_ROLLBACK;
}

static void clear_pending(
	struct pqcp_adaptive_transition_controller *controller)
{
	controller->confirmation_count = 0U;
	controller->pending_since_ms = 0U;
	controller->pending_reason = PQCP_ADAPTIVE_REASON_NONE;
	controller->pending_profile_id[0] = '\0';
}

static int controller_digest(
	struct pqcp_adaptive_transition_controller *controller)
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_TRANSITION_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, controller->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)controller->state);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)controller->pending_reason);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, controller->confirmation_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, controller->cooldown_remaining);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, controller->transition_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, controller->rejected_count);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, controller->hour_window_start_ms);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, controller->last_transition_ms);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, controller->pending_since_ms);
	pqcp_deployment_evidence_digest_update_text(
		&digest, controller->current_profile_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, controller->previous_profile_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, controller->pending_profile_id);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, controller->controller_digest_hex);
}

static int result_digest(
	const struct pqcp_adaptive_transition_result *result,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_TRANSITION_DOMAIN ^ UINT64_C(0x52));
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->state);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->reason);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->blocker_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->confirmations);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->cooldown_remaining);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->changed);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->rollback_available);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->from_profile_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->to_profile_id);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

static void initialize_result(
	const struct pqcp_adaptive_transition_controller *controller,
	enum pqcp_adaptive_transition_reason reason,
	struct pqcp_adaptive_transition_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	result->state = controller->state;
	result->reason = reason;
	result->confirmations = controller->confirmation_count;
	result->cooldown_remaining = controller->cooldown_remaining;
	result->rollback_available =
		pqcp_adaptive_internal_id_valid(
			controller->previous_profile_id);
	pqcp_adaptive_internal_set_text(
		result->from_profile_id,
		sizeof(result->from_profile_id),
		controller->current_profile_id);
	pqcp_adaptive_internal_set_text(
		result->to_profile_id,
		sizeof(result->to_profile_id),
		controller->pending_profile_id[0] != '\0' ?
			controller->pending_profile_id :
			controller->current_profile_id);
}

static void reset_hour_window(
	struct pqcp_adaptive_transition_controller *controller,
	uint64_t now_ms)
{
	if (controller->hour_window_start_ms == 0U ||
	    now_ms < controller->hour_window_start_ms ||
	    now_ms - controller->hour_window_start_ms >=
		    PQCP_ADAPTIVE_HOUR_MS) {
		controller->hour_window_start_ms = now_ms;
		controller->transition_count = 0U;
	}
}

static bool rate_limited(
	struct pqcp_adaptive_transition_controller *controller,
	const struct pqcp_adaptive_policy *policy,
	uint64_t now_ms)
{
	reset_hour_window(controller, now_ms);
	return policy->maximum_transitions_per_hour != 0U &&
	       controller->transition_count >=
		       policy->maximum_transitions_per_hour;
}

static int finish_result(
	struct pqcp_adaptive_transition_controller *controller,
	struct pqcp_adaptive_transition_result *result)
{
	int ret = controller_digest(controller);

	if (ret != 0) {
		return ret;
	}
	result->state = controller->state;
	result->confirmations = controller->confirmation_count;
	result->cooldown_remaining = controller->cooldown_remaining;
	result->rollback_available =
		pqcp_adaptive_internal_id_valid(
			controller->previous_profile_id);
	return result_digest(
		result, result->transition_digest_hex);
}

int pqcp_adaptive_transition_init(
	struct pqcp_adaptive_transition_controller *controller,
	const char *initial_profile_id,
	uint64_t now_ms)
{
	if (controller == NULL ||
	    !pqcp_adaptive_internal_id_valid(initial_profile_id)) {
		return -EINVAL;
	}
	memset(controller, 0, sizeof(*controller));
	controller->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	controller->state = PQCP_ADAPTIVE_TRANSITION_STABLE;
	controller->pending_reason = PQCP_ADAPTIVE_REASON_NONE;
	controller->hour_window_start_ms = now_ms;
	controller->last_transition_ms = now_ms;
	pqcp_adaptive_internal_set_text(
		controller->current_profile_id,
		sizeof(controller->current_profile_id),
		initial_profile_id);
	return controller_digest(controller);
}

int pqcp_adaptive_transition_request(
	struct pqcp_adaptive_transition_controller *controller,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_recommendation *recommendation,
	enum pqcp_adaptive_transition_reason reason,
	uint64_t now_ms,
	struct pqcp_adaptive_transition_result *result)
{
	const char *target;

	if (!controller_valid(controller) ||
	    pqcp_adaptive_policy_validate(policy) != 0 ||
	    recommendation == NULL ||
	    recommendation->schema_version !=
		    PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !reason_valid(reason) || result == NULL) {
		return -EINVAL;
	}
	initialize_result(controller, reason, result);
	target = recommendation->recommended_profile_id;
	if (recommendation->status == PQCP_ADAPTIVE_STATUS_FAIL ||
	    !recommendation->transition_recommended ||
	    !pqcp_adaptive_internal_id_valid(target)) {
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
		result->blocker_mask |= PQCP_ADAPTIVE_BLOCK_POLICY;
		controller->rejected_count++;
		return finish_result(controller, result);
	}
	if (strcmp(target, controller->current_profile_id) == 0) {
		clear_pending(controller);
		controller->state = PQCP_ADAPTIVE_TRANSITION_STABLE;
		result->status = PQCP_ADAPTIVE_STATUS_PASS;
		return finish_result(controller, result);
	}
	if (controller->cooldown_remaining != 0U) {
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
		result->blocker_mask |= PQCP_ADAPTIVE_BLOCK_COOLDOWN;
		result->warning_mask |=
			PQCP_ADAPTIVE_WARNING_TRANSITION_FLAP;
		controller->rejected_count++;
		return finish_result(controller, result);
	}
	if (rate_limited(controller, policy, now_ms)) {
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
		result->blocker_mask |= PQCP_ADAPTIVE_BLOCK_COOLDOWN;
		result->warning_mask |=
			PQCP_ADAPTIVE_WARNING_TRANSITION_FLAP;
		controller->state = PQCP_ADAPTIVE_TRANSITION_BLOCKED;
		controller->rejected_count++;
		return finish_result(controller, result);
	}
	if (strcmp(target, controller->pending_profile_id) != 0 ||
	    controller->pending_reason != reason) {
		pqcp_adaptive_internal_set_text(
			controller->pending_profile_id,
			sizeof(controller->pending_profile_id), target);
		controller->pending_reason = reason;
		controller->pending_since_ms = now_ms;
		controller->confirmation_count = 1U;
		controller->state = PQCP_ADAPTIVE_TRANSITION_PENDING;
	} else if (controller->confirmation_count < UINT32_MAX) {
		controller->confirmation_count++;
	}
	pqcp_adaptive_internal_set_text(
		result->to_profile_id, sizeof(result->to_profile_id),
		target);
	if (controller->confirmation_count >=
	    policy->transition_confirmations) {
		controller->state = PQCP_ADAPTIVE_TRANSITION_PREPARING;
		result->status = PQCP_ADAPTIVE_STATUS_PASS;
	} else {
		result->status = PQCP_ADAPTIVE_STATUS_WARN;
	}
	return finish_result(controller, result);
}

int pqcp_adaptive_transition_commit(
	struct pqcp_adaptive_transition_controller *controller,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_downgrade_result *downgrade,
	uint64_t now_ms,
	struct pqcp_adaptive_transition_result *result)
{
	if (!controller_valid(controller) ||
	    pqcp_adaptive_policy_validate(policy) != 0 ||
	    result == NULL) {
		return -EINVAL;
	}
	initialize_result(
		controller, controller->pending_reason, result);
	if (controller->state !=
		    PQCP_ADAPTIVE_TRANSITION_PREPARING ||
	    !pqcp_adaptive_internal_id_valid(
		    controller->pending_profile_id)) {
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
		result->blocker_mask |= PQCP_ADAPTIVE_BLOCK_POLICY;
		controller->rejected_count++;
		return finish_result(controller, result);
	}
	if (downgrade != NULL && downgrade->downgrade &&
	    downgrade->status == PQCP_ADAPTIVE_STATUS_FAIL) {
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
		result->blocker_mask |= downgrade->blocker_mask |
			PQCP_ADAPTIVE_BLOCK_DOWNGRADE;
		controller->state = PQCP_ADAPTIVE_TRANSITION_BLOCKED;
		controller->rejected_count++;
		return finish_result(controller, result);
	}
	controller->state = PQCP_ADAPTIVE_TRANSITION_COMMITTING;
	pqcp_adaptive_internal_set_text(
		controller->previous_profile_id,
		sizeof(controller->previous_profile_id),
		controller->current_profile_id);
	pqcp_adaptive_internal_set_text(
		controller->current_profile_id,
		sizeof(controller->current_profile_id),
		controller->pending_profile_id);
	pqcp_adaptive_internal_set_text(
		result->to_profile_id, sizeof(result->to_profile_id),
		controller->current_profile_id);
	result->changed = true;
	result->status = downgrade != NULL && downgrade->downgrade ?
		PQCP_ADAPTIVE_STATUS_WARN :
		PQCP_ADAPTIVE_STATUS_PASS;
	controller->last_transition_ms = now_ms;
	controller->transition_count++;
	controller->cooldown_remaining = policy->cooldown_cycles;
	clear_pending(controller);
	controller->state = controller->cooldown_remaining != 0U ?
		PQCP_ADAPTIVE_TRANSITION_COOLDOWN :
		PQCP_ADAPTIVE_TRANSITION_STABLE;
	return finish_result(controller, result);
}

int pqcp_adaptive_transition_tick(
	struct pqcp_adaptive_transition_controller *controller,
	uint64_t now_ms)
{
	if (!controller_valid(controller)) {
		return -EINVAL;
	}
	reset_hour_window(controller, now_ms);
	if (controller->cooldown_remaining != 0U) {
		controller->cooldown_remaining--;
		if (controller->cooldown_remaining == 0U &&
		    controller->state ==
			    PQCP_ADAPTIVE_TRANSITION_COOLDOWN) {
			controller->state =
				PQCP_ADAPTIVE_TRANSITION_STABLE;
		}
	}
	if (controller->state == PQCP_ADAPTIVE_TRANSITION_BLOCKED &&
	    controller->cooldown_remaining == 0U) {
		controller->state = PQCP_ADAPTIVE_TRANSITION_STABLE;
		clear_pending(controller);
	}
	return controller_digest(controller);
}

int pqcp_adaptive_transition_rollback(
	struct pqcp_adaptive_transition_controller *controller,
	uint64_t now_ms,
	struct pqcp_adaptive_transition_result *result)
{
	char current[PQCP_ADAPTIVE_ID_MAX_CHARS];

	if (!controller_valid(controller) || result == NULL) {
		return -EINVAL;
	}
	initialize_result(
		controller, PQCP_ADAPTIVE_REASON_ROLLBACK, result);
	if (!pqcp_adaptive_internal_id_valid(
		    controller->previous_profile_id)) {
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
		result->blocker_mask |= PQCP_ADAPTIVE_BLOCK_POLICY;
		return finish_result(controller, result);
	}
	pqcp_adaptive_internal_set_text(
		current, sizeof(current),
		controller->current_profile_id);
	pqcp_adaptive_internal_set_text(
		controller->current_profile_id,
		sizeof(controller->current_profile_id),
		controller->previous_profile_id);
	pqcp_adaptive_internal_set_text(
		controller->previous_profile_id,
		sizeof(controller->previous_profile_id), current);
	pqcp_adaptive_internal_set_text(
		result->to_profile_id, sizeof(result->to_profile_id),
		controller->current_profile_id);
	controller->state = PQCP_ADAPTIVE_TRANSITION_ROLLBACK;
	controller->last_transition_ms = now_ms;
	controller->transition_count++;
	result->changed = true;
	result->status = PQCP_ADAPTIVE_STATUS_WARN;
	clear_pending(controller);
	controller->state = PQCP_ADAPTIVE_TRANSITION_STABLE;
	return finish_result(controller, result);
}

int pqcp_adaptive_transition_emit(
	const struct pqcp_adaptive_transition_result *result)
{
	if (result == NULL ||
	    result->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_TRANSITION schema=%u status=%s state=%s reason=%s from=%s to=%s changed=%u rollback=%u confirmations=%u cooldown=%u blockers=0x%08x warnings=0x%08x digest=%s\n",
	       result->schema_version,
	       pqcp_adaptive_status_str(result->status),
	       pqcp_adaptive_transition_state_str(result->state),
	       pqcp_adaptive_transition_reason_str(result->reason),
	       result->from_profile_id,
	       result->to_profile_id,
	       result->changed ? 1U : 0U,
	       result->rollback_available ? 1U : 0U,
	       result->confirmations,
	       result->cooldown_remaining,
	       result->blocker_mask,
	       result->warning_mask,
	       result->transition_digest_hex);
	return 0;
}
