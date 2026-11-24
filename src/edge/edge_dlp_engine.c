/*
 * SPDX-License-Identifier: MIT
 *
 * Bounded data-loss-prevention inspection for edge egress.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool action_valid(enum pqcp_edge_dlp_action action)
{
	return action >= PQCP_EDGE_DLP_ALLOW &&
	       action <= PQCP_EDGE_DLP_QUARANTINE;
}

static bool rule_valid(const struct pqcp_edge_dlp_rule *rule)
{
	return rule != NULL && rule->rule_id != 0U &&
	       pqcp_edge_internal_text_valid(
		       rule->classification,
		       sizeof(rule->classification)) &&
	       (rule->destination_domain[0] == '\0' ||
		pqcp_edge_internal_text_valid(
			rule->destination_domain,
			sizeof(rule->destination_domain))) &&
	       rule->minimum_matches != 0U &&
	       rule->byte_mask <= 0xffU &&
	       rule->byte_pattern <= 0xffU &&
	       rule->maximum_payload != 0U &&
	       action_valid(rule->action);
}

static int rule_index(
	const struct pqcp_edge_dlp_engine *engine,
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
	const struct pqcp_edge_dlp_engine *engine)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (!engine->rules[index].enabled) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool scope_matches(
	const struct pqcp_edge_dlp_rule *rule,
	const char *classification,
	const char *destination_domain,
	bool encrypted)
{
	if (strcmp(rule->classification, classification) != 0) {
		return false;
	}
	if (rule->destination_domain[0] != '\0' &&
	    strcmp(rule->destination_domain,
		   destination_domain) != 0) {
		return false;
	}
	if (rule->encrypted_only && !encrypted) {
		return false;
	}
	return true;
}

static uint32_t count_matches(
	const struct pqcp_edge_dlp_rule *rule,
	const uint8_t *payload,
	size_t payload_length)
{
	uint32_t matches = 0U;
	const uint8_t pattern = (uint8_t)rule->byte_pattern;
	const uint8_t mask = (uint8_t)rule->byte_mask;

	for (size_t index = 0U;
	     index < payload_length; ++index) {
		if ((payload[index] & mask) == (pattern & mask)) {
			matches =
				pqcp_edge_internal_saturating_add_u32(
					matches, 1U);
		}
	}
	return matches;
}

int pqcp_edge_dlp_engine_init(
	struct pqcp_edge_dlp_engine *engine,
	struct pqcp_edge_dlp_rule *rules,
	size_t capacity)
{
	if (engine == NULL || rules == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(rules, 0, capacity * sizeof(*rules));
	engine->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	engine->rules = rules;
	engine->capacity = capacity;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_edge_dlp_rule_put(
	struct pqcp_edge_dlp_engine *engine,
	const struct pqcp_edge_dlp_rule *rule)
{
	int index;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    !rule_valid(rule) || !rule->enabled) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = rule_index(engine, rule->rule_id);
	if (index == -ENOENT) {
		index = free_rule_index(engine);
		if (index >= 0) {
			++engine->count;
		}
	}
	if (index < 0) {
		ret = index;
	} else {
		engine->rules[index] = *rule;
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_dlp_rule_remove(
	struct pqcp_edge_dlp_engine *engine,
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
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_dlp_scan(
	struct pqcp_edge_dlp_engine *engine,
	const char *classification,
	const char *destination_domain,
	const uint8_t *payload,
	size_t payload_length,
	bool encrypted,
	struct pqcp_edge_dlp_decision *decision)
{
	const struct pqcp_edge_dlp_rule *selected = NULL;
	uint32_t selected_matches = 0U;

	if (engine == NULL || !engine->initialized ||
	    !pqcp_edge_internal_text_valid(
		    classification, PQCP_EDGE_LABEL_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    destination_domain,
		    PQCP_EDGE_DOMAIN_MAX_CHARS) ||
	    payload == NULL || payload_length == 0U ||
	    decision == NULL) {
		return -EINVAL;
	}
	memset(decision, 0, sizeof(*decision));
	decision->action = PQCP_EDGE_DLP_ALLOW;
	decision->scanned_bytes = payload_length;
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		const struct pqcp_edge_dlp_rule *rule =
			&engine->rules[index];
		uint32_t matches;

		if (!rule->enabled ||
		    !scope_matches(
			    rule, classification,
			    destination_domain, encrypted)) {
			continue;
		}
		matches = count_matches(
			rule, payload, payload_length);
		if (payload_length > rule->maximum_payload) {
			matches = rule->minimum_matches;
		}
		if (matches < rule->minimum_matches) {
			continue;
		}
		if (selected == NULL ||
		    rule->priority > selected->priority ||
		    (rule->priority == selected->priority &&
		     rule->action > selected->action)) {
			selected = rule;
			selected_matches = matches;
		}
	}
	++engine->scan_count;
	if (selected != NULL) {
		decision->action = selected->action;
		decision->rule_id = selected->rule_id;
		decision->match_count = selected_matches;
		if (selected->action >= PQCP_EDGE_DLP_BLOCK) {
			++engine->block_count;
		}
	}
	k_mutex_unlock(&engine->lock);
	switch (decision->action) {
	case PQCP_EDGE_DLP_ALLOW:
		(void)pqcp_edge_internal_copy_text(
			decision->reason,
			sizeof(decision->reason),
			"no blocking DLP rule matched");
		return 0;
	case PQCP_EDGE_DLP_REDACT:
		(void)pqcp_edge_internal_copy_text(
			decision->reason,
			sizeof(decision->reason),
			"payload requires redaction");
		return -EAGAIN;
	case PQCP_EDGE_DLP_BLOCK:
		(void)pqcp_edge_internal_copy_text(
			decision->reason,
			sizeof(decision->reason),
			"payload blocked by DLP policy");
		return -EACCES;
	case PQCP_EDGE_DLP_QUARANTINE:
	default:
		(void)pqcp_edge_internal_copy_text(
			decision->reason,
			sizeof(decision->reason),
			"payload quarantined by DLP policy");
		return -EKEYREJECTED;
	}
}

int pqcp_edge_dlp_engine_audit(
	struct pqcp_edge_dlp_engine *engine)
{
	size_t count = 0U;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    engine->rules == NULL || engine->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity && ret == 0;
	     ++index) {
		if (!engine->rules[index].enabled) {
			continue;
		}
		++count;
		if (!rule_valid(&engine->rules[index])) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < engine->capacity; ++other) {
			if (engine->rules[other].enabled &&
			    engine->rules[other].rule_id ==
				    engine->rules[index].rule_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	if (ret == 0 && count != engine->count) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}
