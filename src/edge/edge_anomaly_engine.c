/*
 * SPDX-License-Identifier: MIT
 *
 * Online integer baseline and anomaly scoring for embedded telemetry.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool metric_valid(enum pqcp_edge_metric_type metric)
{
	return metric >= PQCP_EDGE_METRIC_LATENCY_US &&
	       metric < PQCP_EDGE_METRIC_COUNT;
}

static int baseline_index(
	const struct pqcp_edge_anomaly_engine *engine,
	const char *subject_id,
	enum pqcp_edge_metric_type metric)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (engine->baselines[index].occupied &&
		    engine->baselines[index].metric == metric &&
		    strcmp(engine->baselines[index].subject_id,
			   subject_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_baseline_index(
	const struct pqcp_edge_anomaly_engine *engine)
{
	for (size_t index = 0U;
	     index < engine->capacity; ++index) {
		if (!engine->baselines[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static uint64_t absolute_difference(
	uint64_t left,
	uint64_t right)
{
	return left >= right ? left - right : right - left;
}

static uint64_t threshold_for(
	const struct pqcp_edge_anomaly_baseline *baseline)
{
	uint64_t deviation =
		baseline->deviation == 0U ?
			1U : baseline->deviation;
	uint64_t threshold =
		deviation *
		baseline->sensitivity_basis_points / 10000U;

	return threshold == 0U ? 1U : threshold;
}

static void update_baseline(
	struct pqcp_edge_anomaly_baseline *baseline,
	uint64_t value,
	uint64_t now_ms)
{
	uint64_t prior_mean = baseline->mean;
	uint64_t distance;

	baseline->sample_count =
		pqcp_edge_internal_saturating_add_u64(
			baseline->sample_count, 1U);
	if (baseline->sample_count == 1U) {
		baseline->mean = value;
		baseline->deviation = 0U;
		baseline->minimum = value;
		baseline->maximum = value;
	} else {
		if (value >= baseline->mean) {
			baseline->mean +=
				(value - baseline->mean) /
				baseline->sample_count;
		} else {
			baseline->mean -=
				(baseline->mean - value) /
				baseline->sample_count;
		}
		distance = absolute_difference(
			value, prior_mean);
		if (distance >= baseline->deviation) {
			baseline->deviation +=
				(distance - baseline->deviation) /
				baseline->sample_count;
		} else {
			baseline->deviation -=
				(baseline->deviation - distance) /
				baseline->sample_count;
		}
		if (value < baseline->minimum) {
			baseline->minimum = value;
		}
		if (value > baseline->maximum) {
			baseline->maximum = value;
		}
	}
	baseline->last_value = value;
	baseline->last_observed_ms = now_ms;
}

int pqcp_edge_anomaly_engine_init(
	struct pqcp_edge_anomaly_engine *engine,
	struct pqcp_edge_anomaly_baseline *baselines,
	size_t capacity)
{
	if (engine == NULL || baselines == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(baselines, 0,
	       capacity * sizeof(*baselines));
	engine->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	engine->baselines = baselines;
	engine->capacity = capacity;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_edge_anomaly_observe(
	struct pqcp_edge_anomaly_engine *engine,
	const char *subject_id,
	enum pqcp_edge_metric_type metric,
	uint64_t value,
	uint64_t now_ms,
	uint32_t sensitivity_basis_points,
	struct pqcp_edge_anomaly_result *result)
{
	struct pqcp_edge_anomaly_baseline *baseline;
	uint64_t distance;
	uint64_t threshold;
	int index;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    !pqcp_edge_internal_text_valid(
		    subject_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    !metric_valid(metric) ||
	    sensitivity_basis_points < 10000U ||
	    sensitivity_basis_points > 100000U ||
	    result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = baseline_index(engine, subject_id, metric);
	if (index == -ENOENT) {
		index = free_baseline_index(engine);
		if (index < 0) {
			ret = index;
			goto out;
		}
		baseline = &engine->baselines[index];
		memset(baseline, 0, sizeof(*baseline));
		ret = pqcp_edge_internal_copy_text(
			baseline->subject_id,
			sizeof(baseline->subject_id),
			subject_id);
		if (ret != 0) {
			goto out;
		}
		baseline->metric = metric;
		baseline->sensitivity_basis_points =
			sensitivity_basis_points;
		baseline->occupied = true;
	} else if (index < 0) {
		ret = index;
		goto out;
	} else {
		baseline = &engine->baselines[index];
	}
	result->expected = baseline->mean;
	if (baseline->sample_count >= 8U) {
		distance = absolute_difference(
			value, baseline->mean);
		threshold = threshold_for(baseline);
		result->distance = distance;
		result->threshold = threshold;
		if (distance > threshold) {
			uint64_t ratio =
				distance * 100U / threshold;

			result->anomalous = true;
			result->severity = ratio > 1000U ?
				1000U : (uint32_t)ratio;
			++engine->anomaly_count;
		}
	}
	update_baseline(baseline, value, now_ms);
	++engine->observation_count;
out:
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_anomaly_reset(
	struct pqcp_edge_anomaly_engine *engine,
	const char *subject_id,
	enum pqcp_edge_metric_type metric)
{
	int index;
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    subject_id == NULL || !metric_valid(metric)) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	index = baseline_index(engine, subject_id, metric);
	if (index < 0) {
		ret = index;
	} else {
		memset(&engine->baselines[index], 0,
		       sizeof(engine->baselines[index]));
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}

int pqcp_edge_anomaly_engine_audit(
	struct pqcp_edge_anomaly_engine *engine)
{
	int ret = 0;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    engine->baselines == NULL ||
	    engine->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&engine->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < engine->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_anomaly_baseline *baseline =
			&engine->baselines[index];

		if (!baseline->occupied) {
			continue;
		}
		if (!pqcp_edge_internal_text_valid(
			    baseline->subject_id,
			    sizeof(baseline->subject_id)) ||
		    !metric_valid(baseline->metric) ||
		    baseline->sample_count == 0U ||
		    baseline->minimum > baseline->maximum ||
		    baseline->mean < baseline->minimum ||
		    baseline->mean > baseline->maximum ||
		    baseline->sensitivity_basis_points <
			    10000U) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&engine->lock);
	return ret;
}
