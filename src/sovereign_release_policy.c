/*
 * SPDX-License-Identifier: MIT
 *
 * Deterministic sovereign release policy evaluation.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_artifact_internal.h"

#define RELEASE_RULE_BODY_BYTES 448U
#define RELEASE_POLICY_PREFIX_BYTES 96U

struct release_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

static void release_write_bytes(
	struct release_writer *writer,
	const void *value,
	size_t length)
{
	if (writer == NULL || writer->error != 0) {
		return;
	}
	if ((value == NULL && length != 0U) ||
	    length > writer->capacity - writer->offset) {
		writer->error = -EOVERFLOW;
		return;
	}
	if (length != 0U) {
		memcpy(writer->buffer + writer->offset,
		       value, length);
	}
	writer->offset += length;
}

static void release_write_u8(
	struct release_writer *writer,
	uint8_t value)
{
	release_write_bytes(writer, &value, sizeof(value));
}

static void release_write_u16(
	struct release_writer *writer,
	uint16_t value)
{
	uint8_t encoded[2];

	pqcp_runtime_internal_write_u16(encoded, value);
	release_write_bytes(writer, encoded, sizeof(encoded));
}

static void release_write_u32(
	struct release_writer *writer,
	uint32_t value)
{
	uint8_t encoded[4];

	pqcp_runtime_internal_write_u32(encoded, value);
	release_write_bytes(writer, encoded, sizeof(encoded));
}

static void release_write_u64(
	struct release_writer *writer,
	uint64_t value)
{
	uint8_t encoded[8];

	pqcp_runtime_internal_write_u64(encoded, value);
	release_write_bytes(writer, encoded, sizeof(encoded));
}

static void release_write_text(
	struct release_writer *writer,
	const char *value,
	size_t capacity)
{
	size_t length;

	if (!pqcp_sovereign_internal_text_valid(
		    value, capacity)) {
		if (writer != NULL) {
			writer->error = -EINVAL;
		}
		return;
	}
	length = strnlen(value, capacity);
	if (length > UINT16_MAX) {
		writer->error = -EOVERFLOW;
		return;
	}
	release_write_u16(writer, (uint16_t)length);
	release_write_bytes(writer, value, length);
}

static bool decision_valid(
	enum pqcp_sovereign_decision decision,
	bool allow_unset)
{
	if (allow_unset &&
	    decision == PQCP_SOVEREIGN_DECISION_UNSET) {
		return true;
	}
	return decision >= PQCP_SOVEREIGN_DECISION_ALLOW &&
	       decision <= PQCP_SOVEREIGN_DECISION_QUARANTINE;
}

static bool rule_shape_valid(
	const struct pqcp_sovereign_release_rule *rule)
{
	return rule != NULL &&
	       rule->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       rule->rule_id != 0U &&
	       pqcp_sovereign_internal_text_valid(
		       rule->tenant_id,
		       sizeof(rule->tenant_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       rule->artifact_pattern,
		       sizeof(rule->artifact_pattern)) &&
	       pqcp_sovereign_internal_text_valid(
		       rule->target_zone,
		       sizeof(rule->target_zone)) &&
	       rule->minimum_policy_epoch != 0U &&
	       (rule->forbidden_component_flags &
		~PQCP_SOVEREIGN_SBOM_KNOWN_FLAGS) == 0U &&
	       rule->maximum_artifact_risk <= 10000U &&
	       rule->maximum_component_risk <= 10000U &&
	       rule->minimum_approvals <=
		       PQCP_SOVEREIGN_MAX_APPROVERS &&
	       rule->minimum_distinct_roles <=
		       rule->minimum_approvals &&
	       decision_valid(rule->effect, false);
}

static bool context_shape_valid(
	const struct pqcp_sovereign_release_context *context)
{
	if (context == NULL || context->artifact == NULL ||
	    context->sbom == NULL || context->attestation == NULL ||
	    !pqcp_sovereign_internal_text_valid(
		    context->target_zone,
		    sizeof(context->target_zone)) ||
	    context->policy_epoch == 0U ||
	    context->approval_count >
		    PQCP_SOVEREIGN_MAX_APPROVERS ||
	    context->distinct_roles > context->approval_count) {
		return false;
	}
	if (!context->artifact->occupied ||
	    context->artifact->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    (context->artifact->state !=
		     PQCP_SOVEREIGN_ARTIFACT_APPROVED &&
	     context->artifact->state !=
		     PQCP_SOVEREIGN_ARTIFACT_RELEASED) ||
	    !context->sbom->occupied ||
	    !context->sbom->complete ||
	    context->sbom->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    !context->attestation->occupied ||
	    !context->attestation->verified ||
	    context->attestation->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION) {
		return false;
	}
	return strncmp(
		       context->artifact->artifact_id,
		       context->sbom->artifact_id,
		       sizeof(context->artifact->artifact_id)) == 0 &&
	       strncmp(
		       context->artifact->artifact_id,
		       context->attestation->artifact_id,
		       sizeof(context->artifact->artifact_id)) == 0 &&
	       pqcp_sovereign_internal_equal(
		       context->artifact->sbom_digest,
		       context->sbom->document_digest,
		       PQCP_SOVEREIGN_DIGEST_BYTES) &&
	       pqcp_sovereign_internal_equal(
		       context->artifact->content_digest,
		       context->attestation->output_digest,
		       PQCP_SOVEREIGN_DIGEST_BYTES);
}

static bool pattern_match(
	const char *pattern,
	const char *value)
{
	const char *star = NULL;
	const char *retry = NULL;

	if (pattern == NULL || value == NULL) {
		return false;
	}
	while (*value != '\0') {
		if (*pattern == '?' || *pattern == *value) {
			pattern++;
			value++;
			continue;
		}
		if (*pattern == '*') {
			star = pattern++;
			retry = value;
			continue;
		}
		if (star != NULL) {
			pattern = star + 1;
			value = ++retry;
			continue;
		}
		return false;
	}
	while (*pattern == '*') {
		pattern++;
	}
	return *pattern == '\0';
}

static bool rule_matches(
	const struct pqcp_sovereign_release_rule *rule,
	const struct pqcp_sovereign_release_context *context)
{
	return rule->enabled &&
	       strncmp(rule->tenant_id,
		       context->artifact->tenant_id,
		       sizeof(rule->tenant_id)) == 0 &&
	       strncmp(rule->target_zone,
		       context->target_zone,
		       sizeof(rule->target_zone)) == 0 &&
	       pattern_match(
		       rule->artifact_pattern,
		       context->artifact->name);
}

int pqcp_sovereign_release_rule_canonical_digest(
	const struct pqcp_sovereign_release_rule *rule,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t canonical[RELEASE_RULE_BODY_BYTES];
	struct release_writer writer = {
		.buffer = canonical,
		.capacity = sizeof(canonical),
	};
	int ret;

	if (!rule_shape_valid(rule) || output == NULL) {
		return -EINVAL;
	}
	memset(canonical, 0, sizeof(canonical));
	release_write_bytes(
		&writer, "PQCP-SOVEREIGN-RELEASE-RULE-V1", 30U);
	release_write_u32(&writer, rule->schema_version);
	release_write_u32(&writer, rule->rule_id);
	release_write_u32(&writer, rule->priority);
	release_write_text(
		&writer, rule->tenant_id,
		sizeof(rule->tenant_id));
	release_write_text(
		&writer, rule->artifact_pattern,
		sizeof(rule->artifact_pattern));
	release_write_text(
		&writer, rule->target_zone,
		sizeof(rule->target_zone));
	release_write_u64(
		&writer, rule->minimum_policy_epoch);
	release_write_u64(
		&writer, rule->required_predicate_mask);
	release_write_u64(
		&writer, rule->forbidden_component_flags);
	release_write_u32(
		&writer, rule->maximum_artifact_risk);
	release_write_u32(
		&writer, rule->maximum_component_risk);
	release_write_u32(
		&writer, rule->minimum_approvals);
	release_write_u32(
		&writer, rule->minimum_distinct_roles);
	release_write_u32(
		&writer, (uint32_t)rule->effect);
	release_write_u8(
		&writer, rule->require_reproducible ? 1U : 0U);
	release_write_u8(
		&writer, rule->require_transparency ? 1U : 0U);
	release_write_u8(
		&writer, rule->enabled ? 1U : 0U);
	if (writer.error != 0) {
		pqcp_runtime_secure_zero(
			canonical, sizeof(canonical));
		return writer.error;
	}
	ret = pqcp_runtime_internal_sha256(
		canonical, writer.offset, output);
	pqcp_runtime_secure_zero(canonical, sizeof(canonical));
	return ret;
}

static int rule_index_unlocked(
	const struct pqcp_sovereign_release_policy *policy,
	uint32_t rule_id)
{
	for (size_t index = 0U; index < policy->capacity;
	     ++index) {
		if (policy->rules[index].rule_id == rule_id &&
		    policy->rules[index].schema_version ==
			    PQCP_SOVEREIGN_SCHEMA_VERSION) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_rule_index_unlocked(
	const struct pqcp_sovereign_release_policy *policy)
{
	for (size_t index = 0U; index < policy->capacity;
	     ++index) {
		if (policy->rules[index].schema_version == 0U) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool generation_advance(
	struct pqcp_sovereign_release_policy *policy)
{
	if (policy->generation == UINT64_MAX) {
		return false;
	}
	policy->generation++;
	if (policy->generation == 0U) {
		policy->generation = 1U;
	}
	return true;
}

int pqcp_sovereign_release_policy_init(
	struct pqcp_sovereign_release_policy *policy,
	struct pqcp_sovereign_release_rule *rules,
	size_t capacity,
	enum pqcp_sovereign_decision default_effect)
{
	if (policy == NULL || rules == NULL ||
	    capacity == 0U || capacity > INT_MAX ||
	    !decision_valid(default_effect, false)) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	memset(rules, 0, sizeof(*rules) * capacity);
	policy->schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	policy->rules = rules;
	policy->capacity = capacity;
	policy->default_effect = default_effect;
	policy->generation = 1U;
	k_mutex_init(&policy->lock);
	policy->initialized = true;
	return 0;
}

int pqcp_sovereign_release_rule_put(
	struct pqcp_sovereign_release_policy *policy,
	const struct pqcp_sovereign_release_rule *rule)
{
	int index;
	int ret;

	if (policy == NULL || !policy->initialized ||
	    !rule_shape_valid(rule)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&policy->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = rule_index_unlocked(policy, rule->rule_id);
	if (index < 0) {
		index = free_rule_index_unlocked(policy);
		if (index < 0) {
			(void)k_mutex_unlock(&policy->lock);
			return index;
		}
		if (policy->count == SIZE_MAX) {
			(void)k_mutex_unlock(&policy->lock);
			return -EOVERFLOW;
		}
		policy->count++;
	}
	if (!generation_advance(policy)) {
		(void)k_mutex_unlock(&policy->lock);
		return -EOVERFLOW;
	}
	policy->rules[index] = *rule;
	(void)k_mutex_unlock(&policy->lock);
	return 0;
}

int pqcp_sovereign_release_rule_remove(
	struct pqcp_sovereign_release_policy *policy,
	uint32_t rule_id)
{
	int index;
	int ret;

	if (policy == NULL || !policy->initialized ||
	    rule_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&policy->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = rule_index_unlocked(policy, rule_id);
	if (index < 0) {
		(void)k_mutex_unlock(&policy->lock);
		return index;
	}
	if (!generation_advance(policy)) {
		(void)k_mutex_unlock(&policy->lock);
		return -EOVERFLOW;
	}
	memset(&policy->rules[index], 0,
	       sizeof(policy->rules[index]));
	if (policy->count == 0U) {
		(void)k_mutex_unlock(&policy->lock);
		return -EBADMSG;
	}
	policy->count--;
	(void)k_mutex_unlock(&policy->lock);
	return 0;
}

static const struct pqcp_sovereign_release_rule
	*select_rule_unlocked(
		const struct pqcp_sovereign_release_policy *policy,
		const struct pqcp_sovereign_release_context *context)
{
	const struct pqcp_sovereign_release_rule *selected = NULL;

	for (size_t index = 0U; index < policy->capacity;
	     ++index) {
		const struct pqcp_sovereign_release_rule *candidate =
			&policy->rules[index];

		if (candidate->schema_version == 0U ||
		    !rule_matches(candidate, context)) {
			continue;
		}
		if (selected == NULL ||
		    candidate->priority < selected->priority ||
		    (candidate->priority == selected->priority &&
		     candidate->rule_id < selected->rule_id)) {
			selected = candidate;
		}
	}
	return selected;
}

static uint32_t evaluate_failures(
	const struct pqcp_sovereign_release_rule *rule,
	const struct pqcp_sovereign_release_context *context,
	const struct pqcp_sovereign_sbom_closure *closure)
{
	uint32_t failures = 0U;

	if (context->policy_epoch <
		    rule->minimum_policy_epoch ||
	    context->artifact->policy_epoch >
		    context->policy_epoch ||
	    context->sbom->policy_epoch >
		    context->policy_epoch ||
	    context->attestation->policy_epoch >
		    context->policy_epoch) {
		failures |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_POLICY_EPOCH;
	}
	if (context->artifact->risk_score >
	    rule->maximum_artifact_risk) {
		failures |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_RISK;
	}
	if (context->sbom->maximum_vulnerability_score >
	    rule->maximum_component_risk) {
		failures |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_DEPENDENCY |
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_RISK;
	}
	if (((uint64_t)context->attestation->predicate_mask &
	     rule->required_predicate_mask) !=
		    rule->required_predicate_mask) {
		failures |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_ATTESTATION;
	}
	if (rule->require_reproducible &&
	    !context->artifact->reproducible) {
		failures |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_ATTESTATION;
	}
	if (rule->require_transparency &&
	    !context->transparency_verified) {
		failures |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_TRANSPARENCY;
	}
	if (context->approval_count <
		    rule->minimum_approvals ||
	    context->distinct_roles <
		    rule->minimum_distinct_roles) {
		failures |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_QUORUM;
	}
	if (rule->forbidden_component_flags != 0U) {
		if (closure == NULL) {
			failures |=
				PQCP_SOVEREIGN_ARTIFACT_FAILURE_DEPENDENCY;
		} else if (closure->forbidden_count != 0U ||
			   closure->revoked_count != 0U) {
			failures |=
				PQCP_SOVEREIGN_ARTIFACT_FAILURE_DEPENDENCY;
		}
	}
	if (closure != NULL &&
	    (closure->maximum_risk >
		     rule->maximum_component_risk ||
	     closure->license_failure_count != 0U)) {
		failures |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_DEPENDENCY;
		if (closure->license_failure_count != 0U) {
			failures |=
				PQCP_SOVEREIGN_ARTIFACT_FAILURE_LICENSE;
		}
	}
	return failures;
}

static void decision_explanation(
	struct pqcp_sovereign_release_decision *decision,
	const struct pqcp_sovereign_release_rule *rule,
	bool matched)
{
	const char *message;

	if (!matched) {
		message = decision->effect ==
				  PQCP_SOVEREIGN_DECISION_ALLOW ?
			"default release policy allowed artifact" :
			"default release policy denied artifact";
	} else if (decision->failure_mask != 0U) {
		message =
			"release rule requirements were not satisfied";
	} else {
		switch (decision->effect) {
		case PQCP_SOVEREIGN_DECISION_ALLOW:
			message = "release rule authorized artifact";
			break;
		case PQCP_SOVEREIGN_DECISION_DENY:
			message = "release rule denied artifact";
			break;
		case PQCP_SOVEREIGN_DECISION_REVIEW:
			message = "release rule requires review";
			break;
		case PQCP_SOVEREIGN_DECISION_QUARANTINE:
			message = "release rule quarantined artifact";
			break;
		default:
			message = "release decision is invalid";
			break;
		}
	}
	(void)pqcp_sovereign_internal_copy_text(
		decision->explanation,
		sizeof(decision->explanation), message);
	(void)rule;
}

int pqcp_sovereign_release_evaluate_evidence(
	struct pqcp_sovereign_release_policy *policy,
	const struct pqcp_sovereign_release_context *context,
	const struct pqcp_sovereign_sbom_closure *closure,
	struct pqcp_sovereign_release_decision *decision)
{
	const struct pqcp_sovereign_release_rule *rule;
	int ret;

	if (policy == NULL || !policy->initialized ||
	    !context_shape_valid(context) || decision == NULL ||
	    (closure != NULL &&
	     (closure->component_count == 0U ||
	      pqcp_sovereign_internal_all_zero(
		      closure->closure_digest,
		      sizeof(closure->closure_digest))))) {
		return -EINVAL;
	}
	memset(decision, 0, sizeof(*decision));
	ret = k_mutex_lock(&policy->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	rule = select_rule_unlocked(policy, context);
	if (rule == NULL) {
		decision->effect = policy->default_effect;
		decision_explanation(decision, NULL, false);
	} else {
		decision->effect = rule->effect;
		decision->rule_id = rule->rule_id;
		decision->rule_priority = rule->priority;
		decision->failure_mask =
			evaluate_failures(rule, context, closure);
		if (decision->failure_mask != 0U &&
		    decision->effect ==
			    PQCP_SOVEREIGN_DECISION_ALLOW) {
			decision->effect =
				PQCP_SOVEREIGN_DECISION_DENY;
		}
		decision_explanation(decision, rule, true);
	}
	if (decision->effect ==
	    PQCP_SOVEREIGN_DECISION_ALLOW) {
		policy->allow_count++;
	} else {
		policy->deny_count++;
	}
	(void)k_mutex_unlock(&policy->lock);
	return decision->effect ==
		       PQCP_SOVEREIGN_DECISION_ALLOW ?
		       0 : -EACCES;
}

int pqcp_sovereign_release_evaluate(
	struct pqcp_sovereign_release_policy *policy,
	const struct pqcp_sovereign_release_context *context,
	struct pqcp_sovereign_release_decision *decision)
{
	return pqcp_sovereign_release_evaluate_evidence(
		policy, context, NULL, decision);
}

static int next_rule_in_order(
	const struct pqcp_sovereign_release_policy *policy,
	uint32_t previous_priority,
	uint32_t previous_rule_id,
	bool first,
	const struct pqcp_sovereign_release_rule **selected)
{
	const struct pqcp_sovereign_release_rule *best = NULL;

	for (size_t index = 0U; index < policy->capacity;
	     ++index) {
		const struct pqcp_sovereign_release_rule *candidate =
			&policy->rules[index];
		bool after;

		if (candidate->schema_version == 0U) {
			continue;
		}
		after = first ||
			candidate->priority > previous_priority ||
			(candidate->priority == previous_priority &&
			 candidate->rule_id > previous_rule_id);
		if (!after) {
			continue;
		}
		if (best == NULL ||
		    candidate->priority < best->priority ||
		    (candidate->priority == best->priority &&
		     candidate->rule_id < best->rule_id)) {
			best = candidate;
		}
	}
	*selected = best;
	return best != NULL ? 0 : -ENOENT;
}

int pqcp_sovereign_release_policy_digest(
	struct pqcp_sovereign_release_policy *policy,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t prefix[RELEASE_POLICY_PREFIX_BYTES];
	uint8_t chain[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t rule_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	const struct pqcp_sovereign_release_rule *rule;
	struct release_writer writer = {
		.buffer = prefix,
		.capacity = sizeof(prefix),
	};
	uint32_t previous_priority = 0U;
	uint32_t previous_rule_id = 0U;
	bool first = true;
	size_t traversed = 0U;
	int ret;

	if (policy == NULL || !policy->initialized ||
	    output == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&policy->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(prefix, 0, sizeof(prefix));
	memset(chain, 0, sizeof(chain));
	release_write_bytes(
		&writer, "PQCP-SOVEREIGN-RELEASE-POLICY-V1", 32U);
	release_write_u32(
		&writer, policy->schema_version);
	release_write_u64(
		&writer, policy->generation);
	release_write_u64(
		&writer, (uint64_t)policy->count);
	release_write_u32(
		&writer, (uint32_t)policy->default_effect);
	if (writer.error != 0) {
		(void)k_mutex_unlock(&policy->lock);
		return writer.error;
	}
	ret = pqcp_runtime_internal_sha256(
		prefix, writer.offset, chain);
	while (ret == 0 &&
	       next_rule_in_order(
		       policy, previous_priority,
		       previous_rule_id, first, &rule) == 0) {
		const uint8_t *parts[2] = { chain, rule_digest };
		const size_t lengths[2] = {
			sizeof(chain), sizeof(rule_digest)
		};

		ret = pqcp_sovereign_release_rule_canonical_digest(
			rule, rule_digest);
		if (ret != 0) {
			break;
		}
		ret = pqcp_sovereign_internal_hash_parts(
			parts, lengths, 2U, chain);
		previous_priority = rule->priority;
		previous_rule_id = rule->rule_id;
		first = false;
		traversed++;
	}
	if (ret == 0 && traversed != policy->count) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		memcpy(output, chain, sizeof(chain));
	}
	(void)k_mutex_unlock(&policy->lock);
	pqcp_runtime_secure_zero(prefix, sizeof(prefix));
	pqcp_runtime_secure_zero(chain, sizeof(chain));
	pqcp_runtime_secure_zero(
		rule_digest, sizeof(rule_digest));
	return ret;
}

int pqcp_sovereign_release_policy_audit(
	struct pqcp_sovereign_release_policy *policy)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	size_t count = 0U;
	int ret;

	if (policy == NULL || !policy->initialized ||
	    policy->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    policy->rules == NULL || policy->capacity == 0U ||
	    !decision_valid(policy->default_effect, false) ||
	    policy->generation == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&policy->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < policy->capacity;
	     ++index) {
		const struct pqcp_sovereign_release_rule *rule =
			&policy->rules[index];

		if (rule->schema_version == 0U) {
			continue;
		}
		if (!rule_shape_valid(rule) ||
		    pqcp_sovereign_release_rule_canonical_digest(
			    rule, digest) != 0 ||
		    pqcp_sovereign_internal_all_zero(
			    digest, sizeof(digest))) {
			ret = -EBADMSG;
			goto out;
		}
		for (size_t other = index + 1U;
		     other < policy->capacity; ++other) {
			if (policy->rules[other].schema_version != 0U &&
			    policy->rules[other].rule_id ==
				    rule->rule_id) {
				ret = -EEXIST;
				goto out;
			}
		}
		count++;
	}
	if (count != policy->count) {
		ret = -EBADMSG;
	}
out:
	(void)k_mutex_unlock(&policy->lock);
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}
