/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded trend forecasting for adaptive PQC deployment.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_FORECAST_DOMAIN UINT64_C(0x414450464f524543)

static uint32_t physical_index(
	const struct pqcp_adaptive_telemetry_window *window,
	uint32_t logical_index)
{
	if (window->count < window->capacity) {
		return logical_index;
	}
	return (window->head + logical_index) % window->capacity;
}

static const struct pqcp_adaptive_telemetry_sample *sample_at(
	const struct pqcp_adaptive_telemetry_window *window,
	uint32_t logical_index)
{
	if (window == NULL || logical_index >= window->count) {
		return NULL;
	}
	return &window->samples[physical_index(window, logical_index)];
}

static uint64_t project_unsigned(
	uint64_t current, int64_t trend, uint32_t horizon)
{
	uint64_t change;

	if (trend == 0 || horizon == 0U) {
		return current;
	}
	change = pqcp_adaptive_internal_saturating_mul_u64(
		pqcp_adaptive_internal_abs_i64(trend), horizon);
	if (trend > 0) {
		return pqcp_adaptive_internal_saturating_add_u64(
			current, change);
	}
	return change >= current ? 0U : current - change;
}

static int32_t project_signed(
	int32_t current, int64_t trend, uint32_t horizon)
{
	int64_t projected = current;
	uint64_t change =
		pqcp_adaptive_internal_saturating_mul_u64(
			pqcp_adaptive_internal_abs_i64(trend), horizon);

	if (change > (uint64_t)INT64_MAX) {
		return trend >= 0 ? INT32_MAX : INT32_MIN;
	}
	if (trend > 0) {
		projected += (int64_t)change;
	} else {
		projected -= (int64_t)change;
	}
	if (projected > INT32_MAX) {
		return INT32_MAX;
	}
	if (projected < INT32_MIN) {
		return INT32_MIN;
	}
	return (int32_t)projected;
}

static int64_t endpoint_trend_u64(
	const struct pqcp_adaptive_telemetry_window *window,
	uint64_t (*value_fn)(
		const struct pqcp_adaptive_telemetry_sample *sample))
{
	const struct pqcp_adaptive_telemetry_sample *first;
	const struct pqcp_adaptive_telemetry_sample *last;
	uint64_t first_value;
	uint64_t last_value;
	uint32_t intervals;

	if (window == NULL || value_fn == NULL || window->count < 2U) {
		return 0;
	}
	first = sample_at(window, 0U);
	last = sample_at(window, window->count - 1U);
	if (first == NULL || last == NULL) {
		return 0;
	}
	first_value = value_fn(first);
	last_value = value_fn(last);
	intervals = window->count - 1U;
	if (last_value >= first_value) {
		const uint64_t difference =
			(last_value - first_value) / intervals;

		return difference > (uint64_t)INT64_MAX ?
			INT64_MAX : (int64_t)difference;
	}
	{
		const uint64_t difference =
			(first_value - last_value) / intervals;

		return difference > (uint64_t)INT64_MAX ?
			INT64_MIN : -(int64_t)difference;
	}
}

static int64_t endpoint_trend_i32(
	const struct pqcp_adaptive_telemetry_window *window,
	int32_t (*value_fn)(
		const struct pqcp_adaptive_telemetry_sample *sample))
{
	const struct pqcp_adaptive_telemetry_sample *first;
	const struct pqcp_adaptive_telemetry_sample *last;
	int64_t difference;

	if (window == NULL || value_fn == NULL || window->count < 2U) {
		return 0;
	}
	first = sample_at(window, 0U);
	last = sample_at(window, window->count - 1U);
	if (first == NULL || last == NULL) {
		return 0;
	}
	difference = (int64_t)value_fn(last) - value_fn(first);
	return difference / (int64_t)(window->count - 1U);
}

static uint64_t value_free_ram(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	return sample->free_ram_bytes;
}

static uint64_t value_stack(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	return sample->stack_used_bytes;
}

static uint64_t value_heap_free(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	return sample->heap_free_bytes;
}

static uint64_t value_queue(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	return sample->queue_depth;
}

static uint64_t value_battery(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	return sample->battery_permille;
}

static int32_t value_temperature(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	return sample->temperature_millic;
}

static uint32_t base_confidence(
	const struct pqcp_adaptive_telemetry_window *window,
	const struct pqcp_adaptive_telemetry_summary *summary,
	const struct pqcp_adaptive_forecast_policy *policy)
{
	uint32_t confidence;
	uint32_t sample_score;
	uint32_t variance_penalty;
	uint32_t failure_penalty;

	if (window->count == 0U) {
		return 0U;
	}
	sample_score = window->count >= policy->minimum_samples ?
		500U :
		(uint32_t)(((uint64_t)window->count * 500U) /
			   policy->minimum_samples);
	confidence = 350U + sample_score;
	variance_penalty =
		summary->latency.coefficient_variation_bps / 10U;
	if (variance_penalty > 250U) {
		variance_penalty = 250U;
	}
	failure_penalty = summary->sample_count == 0U ?
		0U :
		(uint32_t)(((uint64_t)summary->failure_count * 300U) /
			   summary->sample_count);
	if (confidence > variance_penalty) {
		confidence -= variance_penalty;
	} else {
		confidence = 0U;
	}
	if (confidence > failure_penalty) {
		confidence -= failure_penalty;
	} else {
		confidence = 0U;
	}
	if (summary->anomaly_mask != 0U) {
		const uint32_t anomaly_penalty =
			pqcp_adaptive_internal_bit_count(
				summary->anomaly_mask) * 20U;

		confidence = confidence > anomaly_penalty ?
			confidence - anomaly_penalty : 0U;
	}
	return pqcp_adaptive_internal_clamp_u32(
		confidence, 0U, PQCP_ADAPTIVE_SCORE_MAX);
}

static bool forecast_policy_valid(
	const struct pqcp_adaptive_forecast_policy *policy)
{
	return policy != NULL &&
	       policy->horizon_samples != 0U &&
	       policy->horizon_samples <= 1024U &&
	       policy->minimum_samples >= 2U &&
	       policy->minimum_samples <=
		       PQCP_ADAPTIVE_TELEMETRY_CAPACITY &&
	       policy->confidence_floor <= PQCP_ADAPTIVE_SCORE_MAX &&
	       policy->latency_growth_limit_bps <= 100000U &&
	       policy->energy_growth_limit_bps <= 100000U;
}

static uint32_t growth_bps(uint64_t current, uint64_t predicted)
{
	uint64_t difference;
	uint64_t scaled;

	if (predicted <= current || current == 0U) {
		return 0U;
	}
	difference = predicted - current;
	scaled = pqcp_adaptive_internal_saturating_mul_u64(
		difference, 10000U);
	scaled /= current;
	return scaled > UINT32_MAX ? UINT32_MAX : (uint32_t)scaled;
}

static void evaluate_limits(
	const struct pqcp_adaptive_telemetry_summary *summary,
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_forecast_policy *policy,
	struct pqcp_adaptive_forecast *forecast)
{
	uint64_t ram_floor;
	uint64_t heap_floor;

	if (limits == NULL) {
		return;
	}
	ram_floor = policy->reserve_ram_bytes;
	heap_floor = policy->reserve_heap_bytes;
	if (limits->reserve_permille != 0U) {
		const uint64_t ratio_ram =
			pqcp_adaptive_internal_saturating_mul_u64(
				limits->ram_capacity_bytes,
				limits->reserve_permille) / 1000U;
		const uint64_t ratio_heap =
			pqcp_adaptive_internal_saturating_mul_u64(
				limits->heap_capacity_bytes,
				limits->reserve_permille) / 1000U;

		if (ratio_ram > ram_floor) {
			ram_floor = ratio_ram;
		}
		if (ratio_heap > heap_floor) {
			heap_floor = ratio_heap;
		}
	}
	forecast->latency_limit_expected =
		limits->latency_budget_us != 0U &&
		forecast->predicted_latency_us >
			limits->latency_budget_us;
	forecast->ram_limit_expected =
		limits->ram_capacity_bytes != 0U &&
		forecast->predicted_free_ram_bytes < ram_floor;
	forecast->stack_limit_expected =
		limits->stack_capacity_bytes != 0U &&
		forecast->predicted_stack_used_bytes >
			limits->stack_capacity_bytes;
	forecast->heap_limit_expected =
		limits->heap_capacity_bytes != 0U &&
		forecast->predicted_heap_free_bytes < heap_floor;
	forecast->energy_limit_expected =
		limits->energy_budget_uj != 0U &&
		forecast->predicted_energy_uj >
			limits->energy_budget_uj;
	if (forecast->latency_limit_expected ||
	    forecast->ram_limit_expected ||
	    forecast->stack_limit_expected ||
	    forecast->heap_limit_expected ||
	    forecast->energy_limit_expected) {
		forecast->warning_mask |=
			PQCP_ADAPTIVE_WARNING_FORECAST_PRESSURE;
	}
	if (growth_bps(summary->latency.median,
		       forecast->predicted_latency_us) >
	    policy->latency_growth_limit_bps) {
		forecast->warning_mask |=
			PQCP_ADAPTIVE_WARNING_FORECAST_PRESSURE;
	}
	if (growth_bps(summary->energy.median,
		       forecast->predicted_energy_uj) >
	    policy->energy_growth_limit_bps) {
		forecast->warning_mask |=
			PQCP_ADAPTIVE_WARNING_FORECAST_PRESSURE;
	}
}

static int forecast_digest(
	const struct pqcp_adaptive_forecast *forecast,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (forecast == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_FORECAST_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, forecast->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)forecast->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, forecast->confidence);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, forecast->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, forecast->horizon_samples);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, forecast->predicted_latency_us);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, forecast->predicted_cycles);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, forecast->predicted_energy_uj);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, forecast->predicted_free_ram_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, forecast->predicted_stack_used_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, forecast->predicted_heap_free_bytes);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, forecast->predicted_queue_depth);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, forecast->predicted_battery_permille);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)forecast->predicted_temperature_millic);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, forecast->latency_limit_expected);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, forecast->ram_limit_expected);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, forecast->stack_limit_expected);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, forecast->heap_limit_expected);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, forecast->energy_limit_expected);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

int pqcp_adaptive_forecast_default_policy(
	struct pqcp_adaptive_forecast_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->horizon_samples = 4U;
	policy->minimum_samples = 4U;
	policy->confidence_floor = 600U;
	policy->latency_growth_limit_bps = 2000U;
	policy->energy_growth_limit_bps = 2500U;
	policy->reserve_ram_bytes = 8192U;
	policy->reserve_heap_bytes = 2048U;
	return 0;
}

int pqcp_adaptive_forecast_run(
	const struct pqcp_adaptive_telemetry_window *window,
	const struct pqcp_adaptive_telemetry_summary *summary,
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_forecast_policy *policy,
	struct pqcp_adaptive_forecast *forecast)
{
	const struct pqcp_adaptive_telemetry_sample *last;

	if (window == NULL || summary == NULL ||
	    !forecast_policy_valid(policy) || forecast == NULL ||
	    window->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    window->count == 0U || window->count > window->capacity ||
	    summary->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    summary->sample_count != window->count) {
		return -EINVAL;
	}
	last = sample_at(window, window->count - 1U);
	if (last == NULL) {
		return -EBADMSG;
	}
	memset(forecast, 0, sizeof(*forecast));
	forecast->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	forecast->horizon_samples = policy->horizon_samples;
	forecast->confidence =
		base_confidence(window, summary, policy);
	forecast->predicted_latency_us = project_unsigned(
		last->latency_us, summary->latency.trend_per_sample,
		policy->horizon_samples);
	forecast->predicted_cycles = project_unsigned(
		last->cycles, summary->cycles.trend_per_sample,
		policy->horizon_samples);
	forecast->predicted_energy_uj = project_unsigned(
		last->energy_uj, summary->energy.trend_per_sample,
		policy->horizon_samples);
	forecast->predicted_free_ram_bytes = project_unsigned(
		last->free_ram_bytes,
		endpoint_trend_u64(window, value_free_ram),
		policy->horizon_samples);
	forecast->predicted_stack_used_bytes = project_unsigned(
		last->stack_used_bytes,
		endpoint_trend_u64(window, value_stack),
		policy->horizon_samples);
	forecast->predicted_heap_free_bytes = project_unsigned(
		last->heap_free_bytes,
		endpoint_trend_u64(window, value_heap_free),
		policy->horizon_samples);
	forecast->predicted_queue_depth =
		(uint32_t)pqcp_adaptive_internal_clamp_u64(
			project_unsigned(
				last->queue_depth,
				endpoint_trend_u64(window, value_queue),
				policy->horizon_samples),
			0U, UINT32_MAX);
	forecast->predicted_battery_permille =
		(uint32_t)pqcp_adaptive_internal_clamp_u64(
			project_unsigned(
				last->battery_permille,
				endpoint_trend_u64(window, value_battery),
				policy->horizon_samples),
			0U, 1000U);
	forecast->predicted_temperature_millic = project_signed(
		last->temperature_millic,
		endpoint_trend_i32(window, value_temperature),
		policy->horizon_samples);
	evaluate_limits(summary, limits, policy, forecast);
	if (window->count < policy->minimum_samples ||
	    forecast->confidence < policy->confidence_floor) {
		forecast->warning_mask |=
			PQCP_ADAPTIVE_WARNING_LOW_CONFIDENCE;
	}
	if (window->rejected_samples != 0U) {
		forecast->warning_mask |=
			PQCP_ADAPTIVE_WARNING_TELEMETRY_STALE;
	}
	if (forecast->confidence == 0U) {
		forecast->status = PQCP_ADAPTIVE_STATUS_FAIL;
	} else if (forecast->warning_mask != 0U) {
		forecast->status = PQCP_ADAPTIVE_STATUS_WARN;
	} else {
		forecast->status = PQCP_ADAPTIVE_STATUS_PASS;
	}
	return forecast_digest(
		forecast, forecast->forecast_digest_hex);
}

int pqcp_adaptive_forecast_emit(
	const struct pqcp_adaptive_forecast *forecast)
{
	if (forecast == NULL ||
	    forecast->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_status_valid(forecast->status)) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_FORECAST schema=%u status=%s confidence=%u warnings=0x%08x horizon=%u latency_us=%llu cycles=%llu energy_uj=%llu free_ram=%llu stack=%llu heap_free=%llu queue=%u battery=%u temperature_millic=%d latency_limit=%u ram_limit=%u stack_limit=%u heap_limit=%u energy_limit=%u digest=%s\n",
	       forecast->schema_version,
	       pqcp_adaptive_status_str(forecast->status),
	       forecast->confidence,
	       forecast->warning_mask,
	       forecast->horizon_samples,
	       (unsigned long long)forecast->predicted_latency_us,
	       (unsigned long long)forecast->predicted_cycles,
	       (unsigned long long)forecast->predicted_energy_uj,
	       (unsigned long long)forecast->predicted_free_ram_bytes,
	       (unsigned long long)forecast->predicted_stack_used_bytes,
	       (unsigned long long)forecast->predicted_heap_free_bytes,
	       forecast->predicted_queue_depth,
	       forecast->predicted_battery_permille,
	       forecast->predicted_temperature_millic,
	       forecast->latency_limit_expected ? 1U : 0U,
	       forecast->ram_limit_expected ? 1U : 0U,
	       forecast->stack_limit_expected ? 1U : 0U,
	       forecast->heap_limit_expected ? 1U : 0U,
	       forecast->energy_limit_expected ? 1U : 0U,
	       forecast->forecast_digest_hex);
	return 0;
}
