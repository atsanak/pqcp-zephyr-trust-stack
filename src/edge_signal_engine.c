/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Security signal intake, deduplication and correlation.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool type_valid(enum pqcp_edge_signal_type type)
{
	return type >=
		       PQCP_EDGE_SIGNAL_AUTHENTICATION_FAILURE &&
	       type < PQCP_EDGE_SIGNAL_COUNT;
}

static bool severity_valid(
	enum pqcp_edge_incident_severity severity)
{
	return severity >=
		       PQCP_EDGE_INCIDENT_INFORMATIONAL &&
	       severity <= PQCP_EDGE_INCIDENT_CRITICAL;
}

static int signal_index(
	const struct pqcp_edge_signal_engine *engine,
	uint64_t signal_id)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (engine->signals[index].occupied &&
		    engine->signals[index].signal_id ==
			    signal_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int duplicate_index(
	const struct pqcp_edge_signal_engine *engine,
	const struct pqcp_edge_signal *signal)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		const struct pqcp_edge_signal *current =
			&engine->signals[index];

		if (current->occupied &&
		    current->type == signal->type &&
		    strcmp(current->source_id,
			   signal->source_id) == 0 &&
		    strcmp(current->subject_id,
			   signal->subject_id) == 0 &&
		    pqcp_edge_internal_equal(
			    current->evidence_digest,
			    signal->evidence_digest,
			    sizeof(current->evidence_digest))) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_signal_index(
	const struct pqcp_edge_signal_engine *engine)
{
	int acknowledged = -1;
	uint64_t oldest = UINT64_MAX;

	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		const struct pqcp_edge_signal *signal =
			&engine->signals[index];

		if (!signal->occupied) {
			return (int)index;
		}
		if (signal->acknowledged &&
		    signal->observed_at_ms < oldest) {
			oldest = signal->observed_at_ms;
			acknowledged = (int)index;
		}
	}
	return acknowledged >= 0 ? acknowledged : -ENOSPC;
}

static uint32_t severity_weight(
	enum pqcp_edge_incident_severity severity)
{
	switch (severity) {
	case PQCP_EDGE_INCIDENT_INFORMATIONAL:
		return 10U;
	case PQCP_EDGE_INCIDENT_LOW:
		return 40U;
	case PQCP_EDGE_INCIDENT_MEDIUM:
		return 100U;
	case PQCP_EDGE_INCIDENT_HIGH:
		return 250U;
	case PQCP_EDGE_INCIDENT_CRITICAL:
		return 500U;
	default:
		return 0U;
	}
}

static uint32_t type_weight(
	enum pqcp_edge_signal_type type)
{
	switch (type) {
	case PQCP_EDGE_SIGNAL_REPLAY:
	case PQCP_EDGE_SIGNAL_INTEGRITY_FAILURE:
	case PQCP_EDGE_SIGNAL_KEY_FAILURE:
	case PQCP_EDGE_SIGNAL_ATTESTATION_FAILURE:
		return 200U;
	case PQCP_EDGE_SIGNAL_AUTHENTICATION_FAILURE:
	case PQCP_EDGE_SIGNAL_AUTHORIZATION_FAILURE:
	case PQCP_EDGE_SIGNAL_POLICY_VIOLATION:
		return 100U;
	case PQCP_EDGE_SIGNAL_STORAGE_FAILURE:
	case PQCP_EDGE_SIGNAL_ROUTE_ANOMALY:
	case PQCP_EDGE_SIGNAL_TRAFFIC_ANOMALY:
	case PQCP_EDGE_SIGNAL_UPDATE_FAILURE:
		return 75U;
	case PQCP_EDGE_SIGNAL_OPERATOR_ALERT:
		return 150U;
	default:
		return 25U;
	}
}

static bool signal_valid(
	const struct pqcp_edge_signal *signal)
{
	return signal != NULL && type_valid(signal->type) &&
	       severity_valid(signal->severity) &&
	       pqcp_edge_internal_text_valid(
		       signal->source_id,
		       sizeof(signal->source_id)) &&
	       pqcp_edge_internal_text_valid(
		       signal->subject_id,
		       sizeof(signal->subject_id)) &&
	       signal->policy_epoch != 0U &&
	       signal->magnitude != 0U &&
	       signal->confidence <= 1000U &&
	       !pqcp_edge_internal_all_zero(
		       signal->evidence_digest,
		       sizeof(signal->evidence_digest));
}

int pqcp_edge_signal_engine_init(
	struct pqcp_edge_signal_engine *engine,
	struct pqcp_edge_signal *signals,
	size_t capacity)
{
	if (engine == NULL || signals == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(signals, 0, capacity * sizeof(*signals));
	engine->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	engine->signals = signals;
	engine->capacity = capacity;
	engine->next_signal_id = 1U;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_edge_signal_submit(
	struct pqcp_edge_signal_engine *engine,
	const struct pqcp_edge_signal *signal,
	uint64_t now_ms,
	struct pqcp_edge_signal **accepted)
{
	struct pqcp_edge_signal candidate;
	int index;

	if (engine == NULL || !engine->initialized ||
	    !signal_valid(signal) || accepted == NULL ||
	    signal->observed_at_ms > now_ms) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = duplicate_index(engine, signal);
	if (index >= 0) {
		struct pqcp_edge_signal *current =
			&engine->signals[index];

		if (signal->severity > current->severity) {
			current->severity = signal->severity;
		}
		current->magnitude =
			pqcp_edge_internal_saturating_add_u32(
				current->magnitude,
				signal->magnitude);
		if (signal->confidence >
		    current->confidence) {
			current->confidence =
				signal->confidence;
		}
		current->observed_at_ms = now_ms;
		current->acknowledged = false;
		*accepted = current;
		++engine->correlated_count;
		k_mutex_unlock(&engine->lock);
		return -EALREADY;
	}
	index = free_signal_index(engine);
	if (index < 0) {
		++engine->dropped_count;
		*accepted = NULL;
		k_mutex_unlock(&engine->lock);
		return index;
	}
	candidate = *signal;
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.signal_id =
		pqcp_edge_internal_next_identifier(
			&engine->next_signal_id);
	candidate.observed_at_ms = now_ms;
	candidate.acknowledged = false;
	candidate.occupied = true;
	engine->signals[index] = candidate;
	*accepted = &engine->signals[index];
	++engine->accepted_count;
	k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_edge_signal_acknowledge(
	struct pqcp_edge_signal_engine *engine,
	uint64_t signal_id)
{
	int index;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    signal_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = signal_index(engine, signal_id);
	if (index < 0) {
		ret = index;
	} else if (engine->signals[index].acknowledged) {
		ret = -EALREADY;
	} else {
		engine->signals[index].acknowledged = true;
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_signal_correlate(
	struct pqcp_edge_signal_engine *engine,
	const char *subject_id,
	uint64_t since_ms,
	uint32_t *risk_score,
	enum pqcp_edge_incident_severity *severity,
	uint64_t signal_ids[PQCP_EDGE_MAX_INCIDENT_SIGNALS],
	uint32_t *signal_count)
{
	uint64_t score = 0U;
	uint32_t count = 0U;
	enum pqcp_edge_incident_severity maximum =
		PQCP_EDGE_INCIDENT_INFORMATIONAL;

	if (engine == NULL || !engine->initialized ||
	    subject_id == NULL || risk_score == NULL ||
	    severity == NULL || signal_ids == NULL ||
	    signal_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		const struct pqcp_edge_signal *signal =
			&engine->signals[index];
		uint64_t contribution;

		if (!signal->occupied ||
		    signal->observed_at_ms < since_ms ||
		    strcmp(signal->subject_id, subject_id) != 0) {
			continue;
		}
		contribution =
			(uint64_t)severity_weight(signal->severity) +
			type_weight(signal->type);
		contribution *= signal->magnitude;
		contribution *= signal->confidence;
		contribution /= 1000U;
		score = pqcp_edge_internal_saturating_add_u64(
			score, contribution);
		if (signal->severity > maximum) {
			maximum = signal->severity;
		}
		if (count < PQCP_EDGE_MAX_INCIDENT_SIGNALS) {
			signal_ids[count++] = signal->signal_id;
		}
	}
	k_mutex_unlock(&engine->lock);
	*risk_score = score > 1000U ? 1000U :
		(uint32_t)score;
	*severity = maximum;
	*signal_count = count;
	return count == 0U ? -ENOENT : 0;
}

int pqcp_edge_signal_expire(
	struct pqcp_edge_signal_engine *engine,
	uint64_t before_ms,
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
		if (engine->signals[index].occupied &&
		    engine->signals[index].acknowledged &&
		    engine->signals[index].observed_at_ms <
			    before_ms) {
			memset(&engine->signals[index], 0,
			       sizeof(engine->signals[index]));
			++expired;
		}
	}
	k_mutex_unlock(&engine->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_signal_engine_audit(
	struct pqcp_edge_signal_engine *engine)
{
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    engine->signals == NULL || engine->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_signal *signal =
			&engine->signals[index];

		if (!signal->occupied) {
			continue;
		}
		if (!signal_valid(signal) ||
		    signal->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    signal->signal_id == 0U) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < engine->capacity; ++other) {
			if (engine->signals[other].occupied &&
			    engine->signals[other].signal_id ==
				    signal->signal_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}
