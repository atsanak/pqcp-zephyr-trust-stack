/*
 * SPDX-License-Identifier: MIT
 *
 * Deterministic device-side fleet policy evaluation.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_operations.h>

#include "runtime_internal.h"

static bool effect_valid(
	enum pqcp_fleet_policy_effect effect)
{
	return effect >= PQCP_FLEET_POLICY_EFFECT_ALLOW &&
	       effect <= PQCP_FLEET_POLICY_EFFECT_QUARANTINE;
}

static bool operation_valid(
	enum pqcp_fleet_operation_type operation)
{
	return operation > PQCP_FLEET_OPERATION_NONE &&
	       operation < PQCP_FLEET_OPERATION_COUNT;
}

static bool device_state_valid(
	enum pqcp_fleet_device_state state)
{
	return state >= PQCP_FLEET_DEVICE_FACTORY &&
	       state <= PQCP_FLEET_DEVICE_DECOMMISSIONED;
}

static uint32_t operation_mask_all(void)
{
	uint32_t mask = 0U;

	for (uint32_t operation =
		     PQCP_FLEET_OPERATION_APPLY_POLICY;
	     operation < PQCP_FLEET_OPERATION_COUNT;
	     ++operation) {
		mask |= PQCP_FLEET_OPERATION_BIT(operation);
	}
	return mask;
}

static uint32_t device_state_mask_all(void)
{
	uint32_t mask = 0U;

	for (uint32_t state = PQCP_FLEET_DEVICE_FACTORY;
	     state <= PQCP_FLEET_DEVICE_DECOMMISSIONED;
	     ++state) {
		mask |= 1U << state;
	}
	return mask;
}

static int rule_validate(
	const struct pqcp_fleet_policy_rule *rule)
{
	if (rule == NULL || rule->rule_id == 0U ||
	    rule->priority == 0U ||
	    rule->operation_mask == 0U ||
	    (rule->operation_mask & ~operation_mask_all()) != 0U ||
	    rule->device_state_mask == 0U ||
	    (rule->device_state_mask &
	     ~device_state_mask_all()) != 0U ||
	    (rule->required_capabilities &
	     rule->forbidden_capabilities) != 0U ||
	    !effect_valid(rule->effect)) {
		return -EINVAL;
	}
	if ((rule->not_before_ms == 0U) !=
	    (rule->not_after_ms == 0U)) {
		return -EINVAL;
	}
	if (rule->not_after_ms != 0U &&
	    rule->not_after_ms <= rule->not_before_ms) {
		return -EINVAL;
	}
	return 0;
}

static int context_validate(
	const struct pqcp_fleet_policy_context *context)
{
	if (context == NULL ||
	    !operation_valid(context->operation) ||
	    !device_state_valid(context->device_state) ||
	    context->now_ms == 0U) {
		return -EINVAL;
	}
	if (context->risk_score > 1000U ||
	    context->security_level > 5U) {
		return -ERANGE;
	}
	return 0;
}

static int rule_index(
	const struct pqcp_fleet_policy_engine *engine,
	uint32_t rule_id)
{
	for (size_t index = 0U; index < engine->capacity;
	     ++index) {
		if (engine->rules[index].rule_id == rule_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_rule_index(
	const struct pqcp_fleet_policy_engine *engine)
{
	for (size_t index = 0U; index < engine->capacity;
	     ++index) {
		if (engine->rules[index].rule_id == 0U) {
			return (int)index;
		}
	}
	return -1;
}

static int decision_explanation(
	struct pqcp_fleet_policy_decision *decision,
	const char *explanation)
{
	return pqcp_runtime_internal_copy_text(
		decision->explanation,
		sizeof(decision->explanation), explanation);
}

static enum pqcp_fleet_audit_severity severity_for_effect(
	enum pqcp_fleet_policy_effect effect)
{
	switch (effect) {
	case PQCP_FLEET_POLICY_EFFECT_ALLOW:
		return PQCP_FLEET_AUDIT_INFO;
	case PQCP_FLEET_POLICY_EFFECT_DENY:
		return PQCP_FLEET_AUDIT_WARNING;
	case PQCP_FLEET_POLICY_EFFECT_REQUIRE_RECOVERY:
		return PQCP_FLEET_AUDIT_ERROR;
	case PQCP_FLEET_POLICY_EFFECT_QUARANTINE:
		return PQCP_FLEET_AUDIT_CRITICAL;
	default:
		return PQCP_FLEET_AUDIT_DEBUG;
	}
}

int pqcp_fleet_policy_engine_init(
	struct pqcp_fleet_policy_engine *engine,
	struct pqcp_fleet_policy_rule *rules,
	size_t capacity,
	enum pqcp_fleet_policy_effect default_effect)
{
	if (engine == NULL || rules == NULL || capacity == 0U ||
	    !effect_valid(default_effect)) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(rules, 0, sizeof(*rules) * capacity);
	engine->schema_version =
		PQCP_FLEET_OPERATIONS_SCHEMA_VERSION;
	engine->rules = rules;
	engine->capacity = capacity;
	engine->default_effect = default_effect;
	engine->generation = 1U;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_fleet_policy_rule_put(
	struct pqcp_fleet_policy_engine *engine,
	const struct pqcp_fleet_policy_rule *rule)
{
	int index;
	int ret;

	if (engine == NULL || !engine->initialized ||
	    rule_validate(rule) != 0) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&engine->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = rule_index(engine, rule->rule_id);
	if (index < 0) {
		index = free_rule_index(engine);
		if (index < 0) {
			(void)k_mutex_unlock(&engine->lock);
			return -ENOSPC;
		}
		engine->count++;
	}
	engine->rules[index] = *rule;
	engine->generation++;
	if (engine->generation == 0U) {
		engine->generation = 1U;
	}
	(void)k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_fleet_policy_rule_remove(
	struct pqcp_fleet_policy_engine *engine,
	uint32_t rule_id)
{
	int index;
	int ret;

	if (engine == NULL || !engine->initialized ||
	    rule_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&engine->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = rule_index(engine, rule_id);
	if (index < 0) {
		(void)k_mutex_unlock(&engine->lock);
		return -ENOENT;
	}
	memset(&engine->rules[index], 0,
	       sizeof(engine->rules[index]));
	if (engine->count != 0U) {
		engine->count--;
	}
	engine->generation++;
	if (engine->generation == 0U) {
		engine->generation = 1U;
	}
	(void)k_mutex_unlock(&engine->lock);
	return 0;
}

static bool rule_matches(
	const struct pqcp_fleet_policy_rule *rule,
	const struct pqcp_fleet_policy_context *context)
{
	if (!rule->enabled ||
	    (rule->operation_mask &
	     PQCP_FLEET_OPERATION_BIT(context->operation)) == 0U ||
	    (rule->device_state_mask &
	     (1U << (uint32_t)context->device_state)) == 0U ||
	    (context->capabilities &
	     rule->required_capabilities) !=
		    rule->required_capabilities ||
	    (context->capabilities &
	     rule->forbidden_capabilities) != 0U ||
	    context->security_level <
		    rule->minimum_security_level ||
	    context->policy_epoch <
		    rule->minimum_policy_epoch ||
	    context->revocation_epoch <
		    rule->minimum_revocation_epoch ||
	    (rule->maximum_risk_score != 0U &&
	     context->risk_score > rule->maximum_risk_score) ||
	    (rule->require_channel_identity &&
	     !context->channel_identity_verified) ||
	    (rule->require_online && !context->online)) {
		return false;
	}
	if (rule->not_before_ms != 0U &&
	    (context->now_ms < rule->not_before_ms ||
	     context->now_ms >= rule->not_after_ms)) {
		return false;
	}
	return true;
}

static bool rule_precedes(
	const struct pqcp_fleet_policy_rule *candidate,
	const struct pqcp_fleet_policy_rule *selected)
{
	if (selected == NULL) {
		return true;
	}
	if (candidate->priority != selected->priority) {
		return candidate->priority > selected->priority;
	}
	if (candidate->effect != selected->effect) {
		return candidate->effect > selected->effect;
	}
	return candidate->rule_id < selected->rule_id;
}

static int hard_guard_decision(
	const struct pqcp_fleet_policy_context *context,
	struct pqcp_fleet_policy_decision *decision)
{
	if (context->device_state ==
		    PQCP_FLEET_DEVICE_DECOMMISSIONED) {
		decision->effect =
			PQCP_FLEET_POLICY_EFFECT_DENY;
		decision->reason =
			PQCP_FLEET_POLICY_REASON_DEVICE_STATE;
		decision->severity = PQCP_FLEET_AUDIT_ERROR;
		(void)decision_explanation(
			decision, "device is decommissioned");
		return 1;
	}
	if (context->revoked ||
	    context->device_state ==
		    PQCP_FLEET_DEVICE_REVOKED) {
		decision->effect =
			PQCP_FLEET_POLICY_EFFECT_QUARANTINE;
		decision->reason =
			PQCP_FLEET_POLICY_REASON_REVOKED;
		decision->severity = PQCP_FLEET_AUDIT_CRITICAL;
		(void)decision_explanation(
			decision, "device or credential is revoked");
		return 1;
	}
	if (context->credential_valid_until_ms != 0U &&
	    context->now_ms >=
		    context->credential_valid_until_ms &&
	    context->operation !=
		    PQCP_FLEET_OPERATION_ENTER_RECOVERY &&
	    context->operation !=
		    PQCP_FLEET_OPERATION_COLLECT_ATTESTATION) {
		decision->effect =
			PQCP_FLEET_POLICY_EFFECT_REQUIRE_RECOVERY;
		decision->reason =
			PQCP_FLEET_POLICY_REASON_CREDENTIAL_EXPIRED;
		decision->severity = PQCP_FLEET_AUDIT_ERROR;
		(void)decision_explanation(
			decision, "operational credential expired");
		return 1;
	}
	if (context->device_state ==
		    PQCP_FLEET_DEVICE_RECOVERY &&
	    context->operation !=
		    PQCP_FLEET_OPERATION_EXIT_RECOVERY &&
	    context->operation !=
		    PQCP_FLEET_OPERATION_COLLECT_ATTESTATION &&
	    context->operation !=
		    PQCP_FLEET_OPERATION_APPLY_POLICY &&
	    context->operation !=
		    PQCP_FLEET_OPERATION_APPLY_REVOCATION) {
		decision->effect =
			PQCP_FLEET_POLICY_EFFECT_DENY;
		decision->reason =
			PQCP_FLEET_POLICY_REASON_DEVICE_STATE;
		decision->severity = PQCP_FLEET_AUDIT_WARNING;
		(void)decision_explanation(
			decision, "operation unavailable in recovery");
		return 1;
	}
	return 0;
}

static void infer_default_reason(
	const struct pqcp_fleet_policy_context *context,
	struct pqcp_fleet_policy_decision *decision)
{
	if (!context->channel_identity_verified) {
		decision->reason =
			PQCP_FLEET_POLICY_REASON_CHANNEL_IDENTITY;
		(void)decision_explanation(
			decision, "no matching rule without channel identity");
		return;
	}
	if (context->security_level == 0U) {
		decision->reason =
			PQCP_FLEET_POLICY_REASON_SECURITY_LEVEL;
		(void)decision_explanation(
			decision, "no matching security-level rule");
		return;
	}
	if (context->capabilities == 0U) {
		decision->reason =
			PQCP_FLEET_POLICY_REASON_CAPABILITY;
		(void)decision_explanation(
			decision, "no granted capabilities");
		return;
	}
	decision->reason = PQCP_FLEET_POLICY_REASON_DEFAULT;
	(void)decision_explanation(
		decision, "default policy effect");
}

int pqcp_fleet_policy_evaluate(
	struct pqcp_fleet_policy_engine *engine,
	const struct pqcp_fleet_policy_context *context,
	struct pqcp_fleet_policy_decision *decision)
{
	const struct pqcp_fleet_policy_rule *selected = NULL;
	int ret;

	if (engine == NULL || !engine->initialized ||
	    context_validate(context) != 0 || decision == NULL) {
		return -EINVAL;
	}
	memset(decision, 0, sizeof(*decision));
	if (hard_guard_decision(context, decision) != 0) {
		return 0;
	}
	ret = k_mutex_lock(&engine->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < engine->capacity;
	     ++index) {
		const struct pqcp_fleet_policy_rule *rule =
			&engine->rules[index];

		if (rule->rule_id != 0U &&
		    rule_matches(rule, context) &&
		    rule_precedes(rule, selected)) {
			selected = rule;
		}
	}
	if (selected != NULL) {
		decision->effect = selected->effect;
		decision->reason =
			PQCP_FLEET_POLICY_REASON_RULE_MATCH;
		decision->matched_rule_id = selected->rule_id;
		decision->matched_priority = selected->priority;
		decision->missing_capabilities =
			selected->required_capabilities &
			~context->capabilities;
		decision->severity =
			severity_for_effect(selected->effect);
		(void)decision_explanation(
			decision, "matched deterministic policy rule");
	} else {
		decision->effect = engine->default_effect;
		decision->severity =
			severity_for_effect(engine->default_effect);
		infer_default_reason(context, decision);
	}
	(void)k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_fleet_policy_engine_audit(
	struct pqcp_fleet_policy_engine *engine)
{
	size_t count = 0U;
	int ret;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    engine->rules == NULL || engine->capacity == 0U ||
	    !effect_valid(engine->default_effect) ||
	    engine->generation == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&engine->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < engine->capacity;
	     ++index) {
		const struct pqcp_fleet_policy_rule *rule =
			&engine->rules[index];

		if (rule->rule_id == 0U) {
			continue;
		}
		if (rule_validate(rule) != 0) {
			(void)k_mutex_unlock(&engine->lock);
			return -EBADMSG;
		}
		count++;
		for (size_t other = index + 1U;
		     other < engine->capacity; ++other) {
			if (engine->rules[other].rule_id ==
			    rule->rule_id) {
				(void)k_mutex_unlock(
					&engine->lock);
				return -EEXIST;
			}
		}
	}
	(void)k_mutex_unlock(&engine->lock);
	return count == engine->count ? 0 : -EBADMSG;
}
