/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Device posture appraisal for continuous zero-trust authorization.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static uint32_t valid_signal_mask(void)
{
	return (1U << PQCP_EDGE_POSTURE_SIGNAL_COUNT) - 1U;
}

static bool policy_valid(
	const struct pqcp_edge_posture_policy *policy)
{
	const uint32_t valid = valid_signal_mask();

	return policy != NULL &&
	       policy->required_signal_mask != 0U &&
	       (policy->required_signal_mask & ~valid) == 0U &&
	       (policy->quarantine_failure_mask & ~valid) == 0U &&
	       (policy->challenge_failure_mask & ~valid) == 0U &&
	       policy->maximum_risk <= 1000U &&
	       policy->minimum_policy_epoch != 0U &&
	       policy->maximum_age_ms != 0U;
}

static int report_index(
	const struct pqcp_edge_posture_engine *engine,
	const char *principal_id)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (engine->reports[index].occupied &&
		    strcmp(engine->reports[index].principal_id,
			   principal_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_report_index(
	const struct pqcp_edge_posture_engine *engine)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (!engine->reports[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool report_valid(
	const struct pqcp_edge_posture_report *report)
{
	const uint32_t valid = valid_signal_mask();

	return report != NULL &&
	       pqcp_edge_internal_text_valid(
		       report->principal_id,
		       sizeof(report->principal_id)) &&
	       report->expires_at_ms > report->measured_at_ms &&
	       report->policy_epoch != 0U &&
	       (report->signal_mask & ~valid) == 0U &&
	       (report->failure_mask & ~valid) == 0U &&
	       (report->failure_mask & report->signal_mask) ==
		       report->failure_mask &&
	       report->risk_score <= 1000U &&
	       !pqcp_edge_internal_all_zero(
		       report->measurement_digest,
		       sizeof(report->measurement_digest));
}

int pqcp_edge_posture_engine_init(
	struct pqcp_edge_posture_engine *engine,
	const struct pqcp_edge_posture_policy *policy,
	struct pqcp_edge_posture_report *reports,
	size_t capacity)
{
	if (engine == NULL || !policy_valid(policy) ||
	    reports == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(reports, 0, capacity * sizeof(*reports));
	engine->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	engine->policy = *policy;
	engine->reports = reports;
	engine->capacity = capacity;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_edge_posture_submit(
	struct pqcp_edge_posture_engine *engine,
	const struct pqcp_edge_posture_report *report,
	uint64_t now_ms)
{
	struct pqcp_edge_posture_report candidate;
	int index;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    !report_valid(report) ||
	    report->measured_at_ms > now_ms ||
	    report->expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = report_index(engine, report->principal_id);
	if (index >= 0) {
		if (report->measured_at_ms <=
		    engine->reports[index].measured_at_ms) {
			ret = -ESTALE;
			goto reject;
		}
	} else if (index == -ENOENT) {
		index = free_report_index(engine);
		if (index < 0) {
			ret = index;
			goto reject;
		}
	} else {
		ret = index;
		goto reject;
	}
	candidate = *report;
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.occupied = true;
	engine->reports[index] = candidate;
	++engine->accepted_count;
	goto out;
reject:
	++engine->rejected_count;
out:
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_posture_evaluate(
	struct pqcp_edge_posture_engine *engine,
	const char *principal_id,
	uint64_t now_ms,
	enum pqcp_edge_policy_effect *effect,
	uint32_t *failure_mask,
	uint32_t *risk_score)
{
	const struct pqcp_edge_posture_report *report;
	uint32_t missing;
	uint32_t failures;
	int index;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    principal_id == NULL || effect == NULL ||
	    failure_mask == NULL || risk_score == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = report_index(engine, principal_id);
	if (index < 0) {
		*effect = PQCP_EDGE_POLICY_CHALLENGE;
		*failure_mask =
			engine->policy.required_signal_mask;
		*risk_score = 1000U;
		ret = -ENOENT;
		goto out;
	}
	report = &engine->reports[index];
	missing = engine->policy.required_signal_mask &
		~report->signal_mask;
	failures = report->failure_mask | missing;
	*failure_mask = failures;
	*risk_score = report->risk_score;
	if (report->expires_at_ms <= now_ms ||
	    now_ms - report->measured_at_ms >
		    engine->policy.maximum_age_ms ||
	    report->policy_epoch <
		    engine->policy.minimum_policy_epoch ||
	    report->firmware_version <
		    engine->policy.minimum_firmware_version) {
		*effect = PQCP_EDGE_POLICY_CHALLENGE;
		ret = -ESTALE;
	} else if ((failures &
		    engine->policy.quarantine_failure_mask) !=
		   0U) {
		*effect = PQCP_EDGE_POLICY_QUARANTINE;
		ret = -EACCES;
	} else if ((failures &
		    engine->policy.challenge_failure_mask) !=
			   0U ||
		   report->risk_score >
			   engine->policy.maximum_risk) {
		*effect = PQCP_EDGE_POLICY_CHALLENGE;
		ret = -EAGAIN;
	} else if (failures != 0U) {
		*effect = PQCP_EDGE_POLICY_DENY;
		ret = -EACCES;
	} else {
		*effect = PQCP_EDGE_POLICY_ALLOW;
	}
out:
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_posture_expire(
	struct pqcp_edge_posture_engine *engine,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (engine == NULL || !engine->initialized ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (engine->reports[index].occupied &&
		    engine->reports[index].expires_at_ms <=
			    now_ms) {
			memset(&engine->reports[index], 0,
			       sizeof(engine->reports[index]));
			++expired;
		}
	}
	k_mutex_unlock(&engine->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_posture_engine_audit(
	struct pqcp_edge_posture_engine *engine)
{
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    !policy_valid(&engine->policy) ||
	    engine->reports == NULL || engine->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity && ret == 0;
	     ++index) {
		if (!engine->reports[index].occupied) {
			continue;
		}
		if (!report_valid(&engine->reports[index]) ||
		    engine->reports[index].schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < engine->capacity; ++other) {
			if (engine->reports[other].occupied &&
			    strcmp(
				    engine->reports[index].
					    principal_id,
				    engine->reports[other].
					    principal_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}
