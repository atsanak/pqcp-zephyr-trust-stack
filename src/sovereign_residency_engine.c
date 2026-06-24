/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Jurisdiction and residency policy evaluation for sovereign data movement.
 */

#include "sovereign_privacy_internal.h"

#include <errno.h>
#include <string.h>

static bool decision_valid(enum pqcp_sovereign_decision decision)
{
	return decision == PQCP_SOVEREIGN_DECISION_ALLOW ||
	       decision == PQCP_SOVEREIGN_DECISION_DENY ||
	       decision == PQCP_SOVEREIGN_DECISION_REVIEW ||
	       decision == PQCP_SOVEREIGN_DECISION_QUARANTINE;
}

static bool zone_pattern_valid(const char *zone, size_t capacity)
{
	return pqcp_sovereign_privacy_text_valid(zone, capacity);
}

static bool zone_matches(const char *pattern, const char *zone)
{
	if (strcmp(pattern, "*") == 0) {
		return true;
	}
	return strcmp(pattern, zone) == 0;
}

static bool rule_valid(
	const struct pqcp_sovereign_residency_rule *rule)
{
	if (rule == NULL || rule->rule_id == 0U ||
	    rule->priority == 0U ||
	    !pqcp_sovereign_privacy_text_valid(
		    rule->tenant_id, sizeof(rule->tenant_id)) ||
	    !zone_pattern_valid(
		    rule->source_zone, sizeof(rule->source_zone)) ||
	    !zone_pattern_valid(
		    rule->destination_zone,
		    sizeof(rule->destination_zone)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    rule->legal_basis, sizeof(rule->legal_basis)) ||
	    rule->data_class_mask == 0U ||
	    rule->not_after_ms <= rule->not_before_ms ||
	    !decision_valid(rule->effect) ||
	    !rule->enabled) {
		return false;
	}
	return (rule->data_class_mask &
		~((1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT) - 1U)) == 0U;
}

static bool context_valid(
	const struct pqcp_sovereign_residency_context *context)
{
	return context != NULL &&
	       pqcp_sovereign_privacy_text_valid(
		       context->tenant_id,
		       sizeof(context->tenant_id)) &&
	       pqcp_sovereign_privacy_text_valid(
		       context->source_zone,
		       sizeof(context->source_zone)) &&
	       pqcp_sovereign_privacy_text_valid(
		       context->destination_zone,
		       sizeof(context->destination_zone)) &&
	       pqcp_sovereign_privacy_data_class_valid(
		       context->data_class) &&
	       context->now_ms != 0U;
}

static ssize_t rule_index_locked(
	const struct pqcp_sovereign_residency_engine *engine,
	uint32_t rule_id)
{
	size_t index;

	for (index = 0U; index < engine->capacity; ++index) {
		if (engine->rules[index].enabled &&
		    engine->rules[index].rule_id == rule_id) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static ssize_t free_rule_index_locked(
	const struct pqcp_sovereign_residency_engine *engine)
{
	size_t index;

	for (index = 0U; index < engine->capacity; ++index) {
		if (!engine->rules[index].enabled) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static uint32_t decision_rank(enum pqcp_sovereign_decision decision)
{
	switch (decision) {
	case PQCP_SOVEREIGN_DECISION_DENY:
		return 4U;
	case PQCP_SOVEREIGN_DECISION_QUARANTINE:
		return 3U;
	case PQCP_SOVEREIGN_DECISION_REVIEW:
		return 2U;
	case PQCP_SOVEREIGN_DECISION_ALLOW:
		return 1U;
	default:
		return 0U;
	}
}

int pqcp_sovereign_residency_engine_init(
	struct pqcp_sovereign_residency_engine *engine,
	struct pqcp_sovereign_residency_rule *rules,
	size_t capacity,
	enum pqcp_sovereign_decision default_effect)
{
	if (engine == NULL || rules == NULL || capacity == 0U ||
	    !decision_valid(default_effect) ||
	    default_effect == PQCP_SOVEREIGN_DECISION_ALLOW) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(rules, 0, capacity * sizeof(*rules));
	engine->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	engine->rules = rules;
	engine->capacity = capacity;
	engine->default_effect = default_effect;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_sovereign_residency_rule_put(
	struct pqcp_sovereign_residency_engine *engine,
	const struct pqcp_sovereign_residency_rule *rule)
{
	struct pqcp_sovereign_residency_rule candidate;
	ssize_t index;

	if (engine == NULL || !engine->initialized ||
	    !rule_valid(rule)) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = rule_index_locked(engine, rule->rule_id);
	if (index < 0) {
		index = free_rule_index_locked(engine);
		if (index < 0) {
			k_mutex_unlock(&engine->lock);
			return -ENOSPC;
		}
		engine->count++;
	}
	candidate = *rule;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.enabled = true;
	engine->rules[index] = candidate;
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_sovereign_residency_rule_remove(
	struct pqcp_sovereign_residency_engine *engine,
	uint32_t rule_id)
{
	ssize_t index;

	if (engine == NULL || !engine->initialized ||
	    rule_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = rule_index_locked(engine, rule_id);
	if (index < 0) {
		k_mutex_unlock(&engine->lock);
		return -ENOENT;
	}
	memset(&engine->rules[index], 0, sizeof(engine->rules[index]));
	if (engine->count != 0U) {
		engine->count--;
	}
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_sovereign_residency_evaluate(
	struct pqcp_sovereign_residency_engine *engine,
	const struct pqcp_sovereign_residency_context *context,
	enum pqcp_sovereign_decision *decision,
	uint32_t *rule_id)
{
	const struct pqcp_sovereign_residency_rule *selected = NULL;
	enum pqcp_sovereign_decision outcome;
	size_t index;

	if (engine == NULL || !engine->initialized ||
	    !context_valid(context) || decision == NULL ||
	    rule_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (index = 0U; index < engine->capacity; ++index) {
		const struct pqcp_sovereign_residency_rule *rule =
			&engine->rules[index];

		if (!rule->enabled ||
		    strcmp(rule->tenant_id, context->tenant_id) != 0 ||
		    !zone_matches(rule->source_zone,
				  context->source_zone) ||
		    !zone_matches(rule->destination_zone,
				  context->destination_zone) ||
		    (rule->data_class_mask &
		     (1U << (uint32_t)context->data_class)) == 0U ||
		    context->now_ms < rule->not_before_ms ||
		    context->now_ms >= rule->not_after_ms) {
			continue;
		}
		if (selected == NULL ||
		    rule->priority > selected->priority ||
		    (rule->priority == selected->priority &&
		     decision_rank(rule->effect) >
			     decision_rank(selected->effect)) ||
		    (rule->priority == selected->priority &&
		     rule->effect == selected->effect &&
		     rule->rule_id < selected->rule_id)) {
			selected = rule;
		}
	}
	if (selected == NULL) {
		outcome = engine->default_effect;
		*rule_id = 0U;
	} else {
		outcome = selected->effect;
		*rule_id = selected->rule_id;
		if (outcome == PQCP_SOVEREIGN_DECISION_ALLOW &&
		    selected->require_encryption &&
		    !context->encrypted) {
			outcome = PQCP_SOVEREIGN_DECISION_DENY;
		}
		if (outcome == PQCP_SOVEREIGN_DECISION_ALLOW &&
		    selected->require_approval &&
		    !context->approved) {
			outcome = PQCP_SOVEREIGN_DECISION_REVIEW;
		}
	}
	*decision = outcome;
	if (outcome == PQCP_SOVEREIGN_DECISION_ALLOW) {
		engine->allow_count++;
	} else {
		engine->deny_count++;
	}
	k_mutex_unlock(&engine->lock);
	return outcome == PQCP_SOVEREIGN_DECISION_ALLOW ?
		       0 :
		       -EACCES;
}

int pqcp_sovereign_residency_engine_audit(
	struct pqcp_sovereign_residency_engine *engine)
{
	size_t active_count = 0U;
	size_t index;
	size_t other;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    engine->rules == NULL || engine->capacity == 0U ||
	    !decision_valid(engine->default_effect) ||
	    engine->default_effect == PQCP_SOVEREIGN_DECISION_ALLOW) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (index = 0U; index < engine->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_residency_rule *rule =
			&engine->rules[index];

		if (!rule->enabled) {
			continue;
		}
		active_count++;
		if (rule->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    !rule_valid(rule)) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < engine->capacity; ++other) {
			if (engine->rules[other].enabled &&
			    engine->rules[other].rule_id ==
				    rule->rule_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	if (ret == 0 && active_count != engine->count) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}
