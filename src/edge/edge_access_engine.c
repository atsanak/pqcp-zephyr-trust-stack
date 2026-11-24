/*
 * SPDX-License-Identifier: MIT
 *
 * Deterministic zero-trust authorization with explainable denials.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "edge_security_internal.h"

static bool effect_valid(
	enum pqcp_edge_policy_effect effect)
{
	return effect >= PQCP_EDGE_POLICY_UNSET &&
	       effect <= PQCP_EDGE_POLICY_QUARANTINE;
}

static bool rule_valid(
	const struct pqcp_edge_access_rule *rule)
{
	if (rule == NULL || rule->rule_id == 0U ||
	    rule->operation_mask == 0U ||
	    rule->minimum_trust >
		    PQCP_EDGE_TRUST_PRIVILEGED ||
	    !effect_valid(rule->effect) ||
	    rule->effect == PQCP_EDGE_POLICY_UNSET ||
	    (rule->not_after_ms != 0U &&
	     rule->not_before_ms > rule->not_after_ms) ||
	    (rule->required_capabilities &
	     rule->forbidden_capabilities) != 0U) {
		return false;
	}
	if (rule->source_domain[0] != '\0' &&
	    !pqcp_edge_internal_text_valid(
		    rule->source_domain,
		    sizeof(rule->source_domain))) {
		return false;
	}
	if (rule->destination_domain[0] != '\0' &&
	    !pqcp_edge_internal_text_valid(
		    rule->destination_domain,
		    sizeof(rule->destination_domain))) {
		return false;
	}
	if (rule->source_zone[0] != '\0' &&
	    !pqcp_edge_internal_text_valid(
		    rule->source_zone,
		    sizeof(rule->source_zone))) {
		return false;
	}
	if (rule->destination_zone[0] != '\0' &&
	    !pqcp_edge_internal_text_valid(
		    rule->destination_zone,
		    sizeof(rule->destination_zone))) {
		return false;
	}
	if (rule->service_id[0] != '\0' &&
	    !pqcp_edge_internal_text_valid(
		    rule->service_id,
		    sizeof(rule->service_id))) {
		return false;
	}
	return true;
}

static int rule_index(
	const struct pqcp_edge_access_engine *engine,
	uint32_t rule_id)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (engine->rules[index].enabled &&
		    engine->rules[index].rule_id == rule_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_rule_index(
	const struct pqcp_edge_access_engine *engine)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (!engine->rules[index].enabled) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool text_filter_matches(
	const char *filter,
	const char *actual)
{
	if (filter[0] == '\0') {
		return true;
	}
	return actual != NULL &&
	       strcmp(filter, actual) == 0;
}

static bool rule_scope_matches(
	const struct pqcp_edge_access_rule *rule,
	const struct pqcp_edge_access_context *context)
{
	if ((rule->operation_mask &
	     PQCP_EDGE_OPERATION_BIT(context->operation)) == 0U) {
		return false;
	}
	if (!text_filter_matches(
		    rule->source_domain,
		    context->principal->trust_domain) ||
	    !text_filter_matches(
		    rule->destination_domain,
		    context->service->trust_domain) ||
	    !text_filter_matches(
		    rule->source_zone,
		    context->source_zone) ||
	    !text_filter_matches(
		    rule->destination_zone,
		    context->destination_zone) ||
	    !text_filter_matches(
		    rule->service_id,
		    context->service->service_id)) {
		return false;
	}
	if (rule->not_before_ms != 0U &&
	    context->now_ms < rule->not_before_ms) {
		return false;
	}
	if (rule->not_after_ms != 0U &&
	    context->now_ms > rule->not_after_ms) {
		return false;
	}
	return true;
}

static void set_explanation(
	struct pqcp_edge_access_decision *decision,
	const char *text)
{
	memset(decision->explanation, 0,
	       sizeof(decision->explanation));
	if (text != NULL) {
		(void)pqcp_edge_internal_copy_text(
			decision->explanation,
			sizeof(decision->explanation), text);
	}
}

static int hard_guard(
	const struct pqcp_edge_access_context *context,
	struct pqcp_edge_access_decision *decision)
{
	const struct pqcp_edge_principal *principal =
		context->principal;
	const struct pqcp_edge_service *service =
		context->service;

	if (principal->state ==
	    PQCP_EDGE_PRINCIPAL_REVOKED) {
		decision->effect = PQCP_EDGE_POLICY_DENY;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_REVOCATION;
		set_explanation(
			decision, "principal is revoked");
		return -EKEYREVOKED;
	}
	if (principal->state ==
		    PQCP_EDGE_PRINCIPAL_QUARANTINED &&
	    (principal->quarantine_until_ms == 0U ||
	     context->now_ms <
		     principal->quarantine_until_ms)) {
		decision->effect =
			PQCP_EDGE_POLICY_QUARANTINE;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_PRINCIPAL;
		decision->retry_after_ms =
			principal->quarantine_until_ms;
		set_explanation(
			decision, "principal is quarantined");
		return -EACCES;
	}
	if (principal->credential_expires_at_ms <=
	    context->now_ms) {
		decision->effect =
			PQCP_EDGE_POLICY_CHALLENGE;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_PRINCIPAL;
		set_explanation(
			decision, "principal credential expired");
		return -EKEYEXPIRED;
	}
	if (service->state != PQCP_EDGE_SERVICE_HEALTHY &&
	    service->state !=
		    PQCP_EDGE_SERVICE_REGISTERED) {
		decision->effect = PQCP_EDGE_POLICY_DENY;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_SERVICE;
		set_explanation(
			decision, "service is not available");
		return -EHOSTDOWN;
	}
	if (service->lease_expires_at_ms <=
	    context->now_ms) {
		decision->effect = PQCP_EDGE_POLICY_DENY;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_SERVICE;
		set_explanation(
			decision, "service registration expired");
		return -ESTALE;
	}
	if ((service->operation_mask &
	     PQCP_EDGE_OPERATION_BIT(context->operation)) == 0U) {
		decision->effect = PQCP_EDGE_POLICY_DENY;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_SERVICE;
		set_explanation(
			decision, "service operation is disabled");
		return -ENOTSUP;
	}
	if ((principal->capabilities &
	     service->required_capabilities) !=
	    service->required_capabilities) {
		decision->effect = PQCP_EDGE_POLICY_DENY;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_CAPABILITY;
		decision->missing_capabilities =
			service->required_capabilities &
			~principal->capabilities;
		set_explanation(
			decision,
			"principal lacks service capabilities");
		return -EACCES;
	}
	if (principal->trust < service->minimum_trust) {
		decision->effect =
			PQCP_EDGE_POLICY_CHALLENGE;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_TRUST;
		set_explanation(
			decision,
			"principal trust level is insufficient");
		return -EAGAIN;
	}
	if (principal->risk_score >
	    service->maximum_risk) {
		decision->effect = PQCP_EDGE_POLICY_DENY;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_RISK;
		set_explanation(
			decision,
			"principal risk exceeds service limit");
		return -EACCES;
	}
	if (service->require_channel_binding &&
	    (!principal->channel_bound ||
	     !context->channel_identity_verified)) {
		decision->effect =
			PQCP_EDGE_POLICY_CHALLENGE;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_ATTESTATION;
		set_explanation(
			decision,
			"channel identity binding is required");
		return -ENOTCONN;
	}
	if (service->require_attestation &&
	    !context->attestation_fresh) {
		decision->effect =
			PQCP_EDGE_POLICY_CHALLENGE;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_ATTESTATION;
		set_explanation(
			decision, "fresh attestation is required");
		return -EAGAIN;
	}
	return 0;
}

static int apply_rule(
	const struct pqcp_edge_access_rule *rule,
	const struct pqcp_edge_access_context *context,
	struct pqcp_edge_access_decision *decision)
{
	const uint64_t capabilities =
		context->principal->capabilities;
	const uint64_t missing =
		rule->required_capabilities &
		~capabilities;
	const uint64_t forbidden =
		rule->forbidden_capabilities &
		capabilities;

	decision->rule_id = rule->rule_id;
	decision->rule_priority = rule->priority;
	decision->missing_capabilities = missing;
	decision->forbidden_capabilities = forbidden;
	if (missing != 0U || forbidden != 0U) {
		decision->effect = PQCP_EDGE_POLICY_DENY;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_CAPABILITY;
		set_explanation(
			decision,
			missing != 0U ?
				"rule-required capability missing" :
				"rule-forbidden capability present");
		return -EACCES;
	}
	if (context->principal->trust <
	    rule->minimum_trust) {
		decision->effect =
			PQCP_EDGE_POLICY_CHALLENGE;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_TRUST;
		set_explanation(
			decision,
			"rule requires a higher trust level");
		return -EAGAIN;
	}
	if (context->principal->risk_score >
	    rule->maximum_risk) {
		decision->effect =
			rule->effect ==
				PQCP_EDGE_POLICY_QUARANTINE ?
				PQCP_EDGE_POLICY_QUARANTINE :
				PQCP_EDGE_POLICY_DENY;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_RISK;
		set_explanation(
			decision,
			"rule risk threshold exceeded");
		return -EACCES;
	}
	if (rule->maximum_concurrent != 0U &&
	    context->current_concurrent >=
		    rule->maximum_concurrent) {
		decision->effect = PQCP_EDGE_POLICY_DENY;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_QUOTA;
		set_explanation(
			decision,
			"rule concurrency limit reached");
		return -EDQUOT;
	}
	if (rule->require_channel_binding &&
	    !context->channel_identity_verified) {
		decision->effect =
			PQCP_EDGE_POLICY_CHALLENGE;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_ATTESTATION;
		set_explanation(
			decision,
			"rule requires channel identity");
		return -ENOTCONN;
	}
	if (rule->require_attestation &&
	    !context->attestation_fresh) {
		decision->effect =
			PQCP_EDGE_POLICY_CHALLENGE;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_ATTESTATION;
		set_explanation(
			decision,
			"rule requires fresh attestation");
		return -EAGAIN;
	}
	decision->effect = rule->effect;
	decision->reason = PQCP_EDGE_POLICY_REASON_RULE;
	switch (rule->effect) {
	case PQCP_EDGE_POLICY_ALLOW:
		set_explanation(
			decision, "explicit policy allow");
		return 0;
	case PQCP_EDGE_POLICY_CHALLENGE:
		set_explanation(
			decision, "additional proof required");
		return -EAGAIN;
	case PQCP_EDGE_POLICY_QUARANTINE:
		set_explanation(
			decision, "policy requires quarantine");
		return -EACCES;
	case PQCP_EDGE_POLICY_DENY:
	default:
		set_explanation(
			decision, "explicit policy deny");
		return -EACCES;
	}
}

int pqcp_edge_access_engine_init(
	struct pqcp_edge_access_engine *engine,
	struct pqcp_edge_access_rule *rules,
	size_t capacity,
	enum pqcp_edge_policy_effect default_effect)
{
	if (engine == NULL || rules == NULL ||
	    capacity == 0U || !effect_valid(default_effect) ||
	    default_effect == PQCP_EDGE_POLICY_UNSET) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(rules, 0, capacity * sizeof(*rules));
	engine->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	engine->rules = rules;
	engine->capacity = capacity;
	engine->default_effect = default_effect;
	engine->generation = 1U;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_edge_access_rule_put(
	struct pqcp_edge_access_engine *engine,
	const struct pqcp_edge_access_rule *rule)
{
	int index;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    !rule_valid(rule) || !rule->enabled) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = rule_index(engine, rule->rule_id);
	if (index < 0) {
		index = free_rule_index(engine);
		if (index < 0) {
			ret = index;
			goto out;
		}
		++engine->count;
	}
	engine->rules[index] = *rule;
	engine->rules[index].schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	engine->rules[index].enabled = true;
	engine->generation =
		pqcp_edge_internal_saturating_add_u64(
			engine->generation, 1U);
out:
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_access_rule_remove(
	struct pqcp_edge_access_engine *engine,
	uint32_t rule_id)
{
	int index;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    rule_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = rule_index(engine, rule_id);
	if (index < 0) {
		ret = index;
	} else {
		memset(&engine->rules[index], 0,
		       sizeof(engine->rules[index]));
		if (engine->count != 0U) {
			--engine->count;
		}
		engine->generation =
			pqcp_edge_internal_saturating_add_u64(
				engine->generation, 1U);
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_access_evaluate(
	struct pqcp_edge_access_engine *engine,
	const struct pqcp_edge_access_context *context,
	struct pqcp_edge_access_decision *decision)
{
	const struct pqcp_edge_access_rule *selected = NULL;
	int ret;

	if (engine == NULL || !engine->initialized ||
	    context == NULL || decision == NULL ||
	    context->principal == NULL ||
	    context->service == NULL ||
	    context->operation <= PQCP_EDGE_OPERATION_NONE ||
	    context->operation >= PQCP_EDGE_OPERATION_COUNT ||
	    !pqcp_edge_internal_text_valid(
		    context->source_zone,
		    sizeof(context->source_zone)) ||
	    !pqcp_edge_internal_text_valid(
		    context->destination_zone,
		    sizeof(context->destination_zone))) {
		return -EINVAL;
	}
	memset(decision, 0, sizeof(*decision));
	ret = hard_guard(context, decision);
	if (ret != 0) {
		k_mutex_lock(&engine->lock, K_FOREVER);
		if (decision->effect ==
		    PQCP_EDGE_POLICY_CHALLENGE) {
			++engine->challenge_count;
		} else {
			++engine->deny_count;
		}
		k_mutex_unlock(&engine->lock);
		return ret;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		const struct pqcp_edge_access_rule *rule =
			&engine->rules[index];

		if (!rule->enabled ||
		    !rule_scope_matches(rule, context)) {
			continue;
		}
		if (selected == NULL ||
		    rule->priority > selected->priority ||
		    (rule->priority == selected->priority &&
		     rule->rule_id < selected->rule_id)) {
			selected = rule;
		}
	}
	if (selected != NULL) {
		ret = apply_rule(selected, context, decision);
	} else {
		decision->effect = engine->default_effect;
		decision->reason =
			PQCP_EDGE_POLICY_REASON_DEFAULT;
		switch (engine->default_effect) {
		case PQCP_EDGE_POLICY_ALLOW:
			set_explanation(
				decision,
				"default policy allows request");
			ret = 0;
			break;
		case PQCP_EDGE_POLICY_CHALLENGE:
			set_explanation(
				decision,
				"default policy requires proof");
			ret = -EAGAIN;
			break;
		case PQCP_EDGE_POLICY_QUARANTINE:
			set_explanation(
				decision,
				"default policy quarantines request");
			ret = -EACCES;
			break;
		case PQCP_EDGE_POLICY_DENY:
		default:
			set_explanation(
				decision,
				"default policy denies request");
			ret = -EACCES;
			break;
		}
	}
	if (decision->effect == PQCP_EDGE_POLICY_ALLOW) {
		++engine->allow_count;
	} else if (decision->effect ==
		   PQCP_EDGE_POLICY_CHALLENGE) {
		++engine->challenge_count;
	} else {
		++engine->deny_count;
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_access_engine_audit(
	struct pqcp_edge_access_engine *engine)
{
	size_t enabled = 0U;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    engine->rules == NULL || engine->capacity == 0U ||
	    !effect_valid(engine->default_effect) ||
	    engine->default_effect ==
		    PQCP_EDGE_POLICY_UNSET) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_access_rule *rule =
			&engine->rules[index];

		if (!rule->enabled) {
			continue;
		}
		++enabled;
		if (!rule_valid(rule) ||
		    rule->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < engine->capacity; ++other) {
			if (engine->rules[other].enabled &&
			    engine->rules[other].rule_id ==
				    rule->rule_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	if (ret == 0 && enabled != engine->count) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}
