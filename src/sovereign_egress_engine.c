/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Workload egress policy and bounded transfer-window accounting.
 */

#include "sovereign_privacy_internal.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

static bool egress_decision_valid(
	enum pqcp_sovereign_decision decision)
{
	return decision == PQCP_SOVEREIGN_DECISION_ALLOW ||
	       decision == PQCP_SOVEREIGN_DECISION_DENY ||
	       decision == PQCP_SOVEREIGN_DECISION_REVIEW ||
	       decision == PQCP_SOVEREIGN_DECISION_QUARANTINE;
}

static bool pattern_valid(const char *value, size_t capacity)
{
	return pqcp_sovereign_privacy_text_valid(value, capacity);
}

static bool pattern_matches(const char *pattern, const char *value)
{
	return strcmp(pattern, "*") == 0 ||
	       strcmp(pattern, value) == 0;
}

static bool egress_rule_valid(
	const struct pqcp_sovereign_egress_rule *rule)
{
	uint32_t class_mask =
		(1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT) - 1U;

	if (rule == NULL || rule->rule_id == 0U ||
	    rule->priority == 0U ||
	    !pqcp_sovereign_privacy_text_valid(
		    rule->tenant_id, sizeof(rule->tenant_id)) ||
	    !pattern_valid(
		    rule->workload_id, sizeof(rule->workload_id)) ||
	    !pattern_valid(
		    rule->destination_domain,
		    sizeof(rule->destination_domain)) ||
	    rule->data_class_mask == 0U ||
	    (rule->data_class_mask & ~class_mask) != 0U ||
	    rule->operation_mask == 0U ||
	    rule->window_ms == 0U ||
	    rule->maximum_risk > 1000U ||
	    !egress_decision_valid(rule->effect) ||
	    !rule->enabled) {
		return false;
	}
	if (rule->effect == PQCP_SOVEREIGN_DECISION_ALLOW &&
	    rule->maximum_bytes_per_window == 0U) {
		return false;
	}
	return true;
}

static int rule_index_locked(
	const struct pqcp_sovereign_egress_engine *engine,
	uint32_t rule_id)
{
	size_t index;

	for (index = 0U; index < engine->rule_capacity; ++index) {
		if (engine->rules[index].enabled &&
		    engine->rules[index].rule_id == rule_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_rule_index_locked(
	const struct pqcp_sovereign_egress_engine *engine)
{
	size_t index;

	for (index = 0U; index < engine->rule_capacity; ++index) {
		if (!engine->rules[index].enabled) {
			return (int)index;
		}
	}
	return -1;
}

static int usage_index_locked(
	const struct pqcp_sovereign_egress_engine *engine,
	uint32_t rule_id,
	const char *workload_id,
	const char *destination_domain)
{
	size_t index;

	for (index = 0U; index < engine->usage_capacity; ++index) {
		const struct pqcp_sovereign_egress_usage *usage =
			&engine->usage[index];

		if (usage->occupied && usage->rule_id == rule_id &&
		    strcmp(usage->workload_id, workload_id) == 0 &&
		    strcmp(usage->destination_domain,
			   destination_domain) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int free_usage_index_locked(
	const struct pqcp_sovereign_egress_engine *engine)
{
	size_t index;

	for (index = 0U; index < engine->usage_capacity; ++index) {
		if (!engine->usage[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static uint32_t effect_rank(enum pqcp_sovereign_decision effect)
{
	switch (effect) {
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

static const struct pqcp_sovereign_egress_rule *
select_rule_locked(
	const struct pqcp_sovereign_egress_engine *engine,
	const char *tenant_id,
	const char *workload_id,
	const char *destination_domain,
	enum pqcp_sovereign_operation operation,
	enum pqcp_sovereign_data_class data_class)
{
	const struct pqcp_sovereign_egress_rule *selected = NULL;
	size_t index;

	for (index = 0U; index < engine->rule_capacity; ++index) {
		const struct pqcp_sovereign_egress_rule *rule =
			&engine->rules[index];

		if (!rule->enabled ||
		    strcmp(rule->tenant_id, tenant_id) != 0 ||
		    !pattern_matches(rule->workload_id, workload_id) ||
		    !pattern_matches(rule->destination_domain,
				     destination_domain) ||
		    (rule->operation_mask &
		     PQCP_SOVEREIGN_BIT(operation)) == 0U ||
		    (rule->data_class_mask &
		     (1U << (uint32_t)data_class)) == 0U) {
			continue;
		}
		if (selected == NULL ||
		    rule->priority > selected->priority ||
		    (rule->priority == selected->priority &&
		     effect_rank(rule->effect) >
			     effect_rank(selected->effect)) ||
		    (rule->priority == selected->priority &&
		     rule->effect == selected->effect &&
		     rule->rule_id < selected->rule_id)) {
			selected = rule;
		}
	}
	return selected;
}

static bool usage_window_elapsed(
	const struct pqcp_sovereign_egress_usage *usage,
	uint64_t window_ms,
	uint64_t now_ms)
{
	return now_ms >= usage->window_started_ms &&
	       now_ms - usage->window_started_ms >= window_ms;
}

static void usage_window_reset(
	struct pqcp_sovereign_egress_usage *usage,
	uint64_t window_ms,
	uint64_t now_ms)
{
	uint64_t elapsed;
	uint64_t windows;

	if (usage->window_started_ms == 0U ||
	    now_ms < usage->window_started_ms) {
		usage->window_started_ms = now_ms;
	} else {
		elapsed = now_ms - usage->window_started_ms;
		windows = elapsed / window_ms;
		if (windows == 0U ||
		    windows > (UINT64_MAX -
			       usage->window_started_ms) / window_ms) {
			usage->window_started_ms = now_ms;
		} else {
			usage->window_started_ms += windows * window_ms;
		}
	}
	usage->bytes_used = 0U;
	usage->request_count = 0U;
}

int pqcp_sovereign_egress_engine_init(
	struct pqcp_sovereign_egress_engine *engine,
	struct pqcp_sovereign_egress_rule *rules,
	size_t rule_capacity,
	struct pqcp_sovereign_egress_usage *usage,
	size_t usage_capacity,
	enum pqcp_sovereign_decision default_effect)
{
	if (engine == NULL || rules == NULL || rule_capacity == 0U ||
	    usage == NULL || usage_capacity == 0U ||
	    !egress_decision_valid(default_effect) ||
	    default_effect == PQCP_SOVEREIGN_DECISION_ALLOW) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(rules, 0, rule_capacity * sizeof(*rules));
	memset(usage, 0, usage_capacity * sizeof(*usage));
	engine->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	engine->rules = rules;
	engine->rule_capacity = rule_capacity;
	engine->usage = usage;
	engine->usage_capacity = usage_capacity;
	engine->default_effect = default_effect;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_sovereign_egress_rule_put(
	struct pqcp_sovereign_egress_engine *engine,
	const struct pqcp_sovereign_egress_rule *rule)
{
	struct pqcp_sovereign_egress_rule candidate;
	int index;

	if (engine == NULL || !engine->initialized ||
	    !egress_rule_valid(rule)) {
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
	}
	candidate = *rule;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.enabled = true;
	engine->rules[index] = candidate;
	k_mutex_unlock(&engine->lock);
	return 0;
}

static int prepare_usage_locked(
	struct pqcp_sovereign_egress_engine *engine,
	const struct pqcp_sovereign_egress_rule *rule,
	const char *workload_id,
	const char *destination_domain,
	uint64_t now_ms,
	struct pqcp_sovereign_egress_usage **usage_out)
{
	struct pqcp_sovereign_egress_usage candidate;
	int index;
	int ret;

	index = usage_index_locked(
		engine, rule->rule_id, workload_id,
		destination_domain);
	if (index >= 0) {
		*usage_out = &engine->usage[index];
		if (now_ms <
		    engine->usage[index].window_started_ms) {
			return -ETIME;
		}
		if (usage_window_elapsed(
			    &engine->usage[index], rule->window_ms,
			    now_ms)) {
			usage_window_reset(
				&engine->usage[index], rule->window_ms,
				now_ms);
		}
		return 0;
	}
	index = free_usage_index_locked(engine);
	if (index < 0) {
		return -ENOSPC;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.rule_id = rule->rule_id;
	ret = pqcp_sovereign_privacy_copy_text(
		candidate.workload_id, sizeof(candidate.workload_id),
		workload_id);
	if (ret == 0) {
		ret = pqcp_sovereign_privacy_copy_text(
			candidate.destination_domain,
			sizeof(candidate.destination_domain),
			destination_domain);
	}
	if (ret != 0) {
		return ret;
	}
	candidate.window_started_ms = now_ms;
	candidate.occupied = true;
	engine->usage[index] = candidate;
	*usage_out = &engine->usage[index];
	return 0;
}

int pqcp_sovereign_egress_authorize(
	struct pqcp_sovereign_egress_engine *engine,
	const char *tenant_id,
	const char *workload_id,
	const char *destination_domain,
	enum pqcp_sovereign_operation operation,
	enum pqcp_sovereign_data_class data_class,
	uint64_t bytes,
	uint32_t risk_score,
	bool encrypted,
	bool dlp_passed,
	uint64_t now_ms,
	uint32_t *rule_id)
{
	const struct pqcp_sovereign_egress_rule *rule;
	struct pqcp_sovereign_egress_usage *usage;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    workload_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    destination_domain,
		    PQCP_SOVEREIGN_DOMAIN_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_operation_valid(operation) ||
	    !pqcp_sovereign_privacy_data_class_valid(data_class) ||
	    bytes == 0U || risk_score > 1000U || now_ms == 0U ||
	    rule_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	rule = select_rule_locked(
		engine, tenant_id, workload_id, destination_domain,
		operation, data_class);
	if (rule == NULL) {
		*rule_id = 0U;
		ret = -EACCES;
		goto out;
	}
	*rule_id = rule->rule_id;
	if (rule->effect != PQCP_SOVEREIGN_DECISION_ALLOW) {
		ret = -EACCES;
		goto out;
	}
	if (risk_score > rule->maximum_risk ||
	    (rule->require_encryption && !encrypted) ||
	    (rule->require_dlp && !dlp_passed)) {
		ret = -EACCES;
		goto out;
	}
	ret = prepare_usage_locked(
		engine, rule, workload_id, destination_domain,
		now_ms, &usage);
	if (ret != 0) {
		goto out;
	}
	/* A rule re-put with a cap below the bytes already used in this
	 * window must deny at once: the unsigned subtraction below would
	 * otherwise wrap and admit an arbitrary transfer.
	 */
	if (usage->bytes_used > rule->maximum_bytes_per_window ||
	    bytes >
	    rule->maximum_bytes_per_window - usage->bytes_used) {
		ret = -EDQUOT;
		goto out;
	}
	if (usage->request_count == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	usage->bytes_used += bytes;
	usage->request_count++;
	engine->allow_count++;
out:
	if (ret != 0) {
		engine->deny_count++;
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_sovereign_egress_tick(
	struct pqcp_sovereign_egress_engine *engine,
	uint64_t now_ms,
	uint32_t *reset_count)
{
	uint32_t resets = 0U;
	size_t index;

	if (engine == NULL || !engine->initialized ||
	    now_ms == 0U || reset_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (index = 0U; index < engine->usage_capacity; ++index) {
		struct pqcp_sovereign_egress_usage *usage =
			&engine->usage[index];
		int rule_slot;

		if (!usage->occupied) {
			continue;
		}
		rule_slot = rule_index_locked(
			engine, usage->rule_id);
		if (rule_slot < 0) {
			memset(usage, 0, sizeof(*usage));
			resets++;
			continue;
		}
		if (now_ms < usage->window_started_ms) {
			continue;
		}
		if (usage_window_elapsed(
			    usage,
			    engine->rules[rule_slot].window_ms,
			    now_ms)) {
			usage_window_reset(
				usage,
				engine->rules[rule_slot].window_ms,
				now_ms);
			resets++;
		}
	}
	*reset_count = resets;
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_sovereign_egress_engine_audit(
	struct pqcp_sovereign_egress_engine *engine)
{
	size_t index;
	size_t other;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    engine->rules == NULL || engine->rule_capacity == 0U ||
	    engine->usage == NULL || engine->usage_capacity == 0U ||
	    !egress_decision_valid(engine->default_effect) ||
	    engine->default_effect == PQCP_SOVEREIGN_DECISION_ALLOW) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (index = 0U;
	     index < engine->rule_capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_egress_rule *rule =
			&engine->rules[index];

		if (!rule->enabled) {
			continue;
		}
		if (rule->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    !egress_rule_valid(rule)) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < engine->rule_capacity; ++other) {
			if (engine->rules[other].enabled &&
			    engine->rules[other].rule_id ==
				    rule->rule_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	for (index = 0U;
	     index < engine->usage_capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_egress_usage *usage =
			&engine->usage[index];
		int rule_slot;

		if (!usage->occupied) {
			continue;
		}
		rule_slot = rule_index_locked(
			engine, usage->rule_id);
		if (usage->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    usage->rule_id == 0U ||
		    !pqcp_sovereign_privacy_text_valid(
			    usage->workload_id,
			    sizeof(usage->workload_id)) ||
		    !pqcp_sovereign_privacy_text_valid(
			    usage->destination_domain,
			    sizeof(usage->destination_domain)) ||
		    rule_slot < 0 ||
		    usage->bytes_used >
			    engine->rules[rule_slot].
				    maximum_bytes_per_window) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < engine->usage_capacity; ++other) {
			const struct pqcp_sovereign_egress_usage *next =
				&engine->usage[other];

			if (next->occupied &&
			    next->rule_id == usage->rule_id &&
			    strcmp(next->workload_id,
				   usage->workload_id) == 0 &&
			    strcmp(next->destination_domain,
				   usage->destination_domain) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}
