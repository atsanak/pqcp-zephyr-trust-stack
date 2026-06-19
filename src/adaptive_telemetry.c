/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free telemetry aggregation for adaptive PQC deployment.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_TELEMETRY_DOMAIN UINT64_C(0x41445054454c454d)

typedef uint64_t (*sample_value_fn)(
	const struct pqcp_adaptive_telemetry_sample *sample);

static uint32_t physical_index(
	const struct pqcp_adaptive_telemetry_window *window,
	uint32_t logical_index)
{
	uint32_t oldest;

	if (window->count < window->capacity) {
		return logical_index;
	}
	oldest = window->head;
	return (oldest + logical_index) % window->capacity;
}

static const struct pqcp_adaptive_telemetry_sample *sample_at(
	const struct pqcp_adaptive_telemetry_window *window,
	uint32_t logical_index)
{
	if (window == NULL || logical_index >= window->count ||
	    window->capacity == 0U) {
		return NULL;
	}
	return &window->samples[physical_index(window, logical_index)];
}

static uint64_t latency_value(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	return sample->latency_us;
}

static uint64_t cycles_value(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	return sample->cycles;
}

static uint64_t energy_value(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	return sample->energy_uj;
}

static void sort_u64(uint64_t *values, uint32_t count)
{
	for (uint32_t index = 1U; index < count; ++index) {
		const uint64_t value = values[index];
		uint32_t position = index;

		while (position > 0U &&
		       values[position - 1U] > value) {
			values[position] = values[position - 1U];
			position--;
		}
		values[position] = value;
	}
}

static uint64_t percentile(
	const uint64_t *sorted, uint32_t count, uint32_t percentile_value)
{
	uint64_t scaled;
	uint32_t index;

	if (sorted == NULL || count == 0U) {
		return 0U;
	}
	if (percentile_value >= 100U) {
		return sorted[count - 1U];
	}
	scaled = (uint64_t)(count - 1U) * percentile_value;
	index = (uint32_t)((scaled + 99U) / 100U);
	if (index >= count) {
		index = count - 1U;
	}
	return sorted[index];
}

static uint64_t median_sorted(const uint64_t *sorted, uint32_t count)
{
	if (sorted == NULL || count == 0U) {
		return 0U;
	}
	if ((count & 1U) != 0U) {
		return sorted[count / 2U];
	}
	return sorted[count / 2U - 1U] / 2U +
	       sorted[count / 2U] / 2U +
	       ((sorted[count / 2U - 1U] & 1U) &&
		(sorted[count / 2U] & 1U));
}

static uint64_t integer_sqrt(uint64_t value)
{
	uint64_t result = 0U;
	uint64_t bit = UINT64_C(1) << 62U;

	while (bit > value) {
		bit >>= 2U;
	}
	while (bit != 0U) {
		if (value >= result + bit) {
			value -= result + bit;
			result = (result >> 1U) + bit;
		} else {
			result >>= 1U;
		}
		bit >>= 2U;
	}
	return result;
}

static uint32_t coefficient_variation_bps(
	const uint64_t *values, uint32_t count, uint64_t mean)
{
	uint64_t variance_sum = 0U;
	uint64_t variance;
	uint64_t standard_deviation;
	uint64_t scaled;

	if (values == NULL || count < 2U || mean == 0U) {
		return 0U;
	}
	for (uint32_t index = 0U; index < count; ++index) {
		const uint64_t difference =
			values[index] > mean ?
			values[index] - mean : mean - values[index];
		const uint64_t square =
			pqcp_adaptive_internal_saturating_mul_u64(
				difference, difference);

		variance_sum =
			pqcp_adaptive_internal_saturating_add_u64(
				variance_sum, square);
	}
	variance = variance_sum / (count - 1U);
	standard_deviation = integer_sqrt(variance);
	if (standard_deviation > UINT64_MAX / 10000U) {
		return UINT32_MAX;
	}
	scaled = standard_deviation * 10000U;
	scaled /= mean;
	return scaled > UINT32_MAX ? UINT32_MAX : (uint32_t)scaled;
}

static int64_t trend_per_sample(
	const uint64_t *values, uint32_t count)
{
	int64_t x_sum = 0;
	int64_t y_sum = 0;
	int64_t xy_sum = 0;
	int64_t xx_sum = 0;
	int64_t denominator;
	int64_t numerator;
	uint64_t scale = 1U;

	if (values == NULL || count < 2U) {
		return 0;
	}
	for (uint32_t index = 0U; index < count; ++index) {
		if (values[index] > (uint64_t)INT64_MAX) {
			scale = values[index] / (uint64_t)INT64_MAX + 1U;
		}
	}
	for (uint32_t index = 0U; index < count; ++index) {
		const int64_t x = (int64_t)index;
		const int64_t y = (int64_t)(values[index] / scale);

		x_sum += x;
		y_sum += y;
		xy_sum += x * y;
		xx_sum += x * x;
	}
	denominator = (int64_t)count * xx_sum - x_sum * x_sum;
	if (denominator == 0) {
		return 0;
	}
	numerator = (int64_t)count * xy_sum - x_sum * y_sum;
	if (scale > (uint64_t)INT64_MAX) {
		return numerator >= 0 ? INT64_MAX : INT64_MIN;
	}
	if (numerator > 0 &&
	    numerator > INT64_MAX / (int64_t)scale) {
		return INT64_MAX;
	}
	if (numerator < 0 &&
	    numerator < INT64_MIN / (int64_t)scale) {
		return INT64_MIN;
	}
	return (numerator * (int64_t)scale) / denominator;
}

static uint64_t mean_values(const uint64_t *values, uint32_t count)
{
	uint64_t quotient_sum = 0U;
	uint64_t remainder_sum = 0U;

	if (values == NULL || count == 0U) {
		return 0U;
	}
	for (uint32_t index = 0U; index < count; ++index) {
		quotient_sum =
			pqcp_adaptive_internal_saturating_add_u64(
				quotient_sum, values[index] / count);
		remainder_sum =
			pqcp_adaptive_internal_saturating_add_u64(
				remainder_sum, values[index] % count);
	}
	return pqcp_adaptive_internal_saturating_add_u64(
		quotient_sum, remainder_sum / count);
}

static uint64_t median_absolute_deviation(
	const uint64_t *sorted, uint32_t count, uint64_t median)
{
	uint64_t deviations[PQCP_ADAPTIVE_TELEMETRY_CAPACITY];

	if (sorted == NULL || count == 0U ||
	    count > PQCP_ADAPTIVE_TELEMETRY_CAPACITY) {
		return 0U;
	}
	for (uint32_t index = 0U; index < count; ++index) {
		deviations[index] = sorted[index] > median ?
			sorted[index] - median : median - sorted[index];
	}
	sort_u64(deviations, count);
	return median_sorted(deviations, count);
}

static int summarize_metric(
	const struct pqcp_adaptive_telemetry_window *window,
	sample_value_fn value_fn,
	struct pqcp_adaptive_metric_summary *metric)
{
	uint64_t chronological[PQCP_ADAPTIVE_TELEMETRY_CAPACITY];
	uint64_t sorted[PQCP_ADAPTIVE_TELEMETRY_CAPACITY];
	uint64_t mean;

	if (window == NULL || value_fn == NULL || metric == NULL ||
	    window->count > PQCP_ADAPTIVE_TELEMETRY_CAPACITY) {
		return -EINVAL;
	}
	memset(metric, 0, sizeof(*metric));
	metric->count = window->count;
	if (window->count == 0U) {
		return 0;
	}
	for (uint32_t index = 0U; index < window->count; ++index) {
		const struct pqcp_adaptive_telemetry_sample *sample =
			sample_at(window, index);

		if (sample == NULL) {
			return -EBADMSG;
		}
		chronological[index] = value_fn(sample);
		sorted[index] = chronological[index];
	}
	sort_u64(sorted, window->count);
	mean = mean_values(chronological, window->count);
	metric->minimum = sorted[0];
	metric->maximum = sorted[window->count - 1U];
	metric->mean = mean;
	metric->median = median_sorted(sorted, window->count);
	metric->p90 = percentile(sorted, window->count, 90U);
	metric->p99 = percentile(sorted, window->count, 99U);
	metric->mad = median_absolute_deviation(
		sorted, window->count, metric->median);
	metric->coefficient_variation_bps =
		coefficient_variation_bps(
			chronological, window->count, mean);
	metric->trend_per_sample =
		trend_per_sample(chronological, window->count);
	return 0;
}
static bool telemetry_sample_valid(
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	if (sample == NULL || sample->timestamp_ms == 0U ||
	    sample->battery_permille > 1000U ||
	    sample->network_loss_permille > 1000U ||
	    sample->temperature_millic < -100000 ||
	    sample->temperature_millic > 200000) {
		return false;
	}
	if (sample->operation_succeeded &&
	    (sample->latency_us == 0U || sample->cycles == 0U)) {
		return false;
	}
	return true;
}

static bool telemetry_window_valid(
	const struct pqcp_adaptive_telemetry_window *window)
{
	if (window == NULL ||
	    window->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    window->capacity != PQCP_ADAPTIVE_TELEMETRY_CAPACITY ||
	    window->count > window->capacity ||
	    window->head >= window->capacity) {
		return false;
	}
	for (uint32_t index = 0U; index < window->count; ++index) {
		const struct pqcp_adaptive_telemetry_sample *sample =
			sample_at(window, index);

		if (!telemetry_sample_valid(sample)) {
			return false;
		}
		if (index != 0U) {
			const struct pqcp_adaptive_telemetry_sample *previous =
				sample_at(window, index - 1U);

			if (previous == NULL ||
			    sample->timestamp_ms <= previous->timestamp_ms) {
				return false;
			}
		}
	}
	return true;
}

static enum pqcp_adaptive_pressure pressure_from_permille(
	uint32_t used_permille)
{
	if (used_permille >= 980U) {
		return PQCP_ADAPTIVE_PRESSURE_CRITICAL;
	}
	if (used_permille >= 900U) {
		return PQCP_ADAPTIVE_PRESSURE_HIGH;
	}
	if (used_permille >= 750U) {
		return PQCP_ADAPTIVE_PRESSURE_MODERATE;
	}
	if (used_permille >= 500U) {
		return PQCP_ADAPTIVE_PRESSURE_LOW;
	}
	return PQCP_ADAPTIVE_PRESSURE_NONE;
}

static enum pqcp_adaptive_pressure maximum_pressure(
	enum pqcp_adaptive_pressure left,
	enum pqcp_adaptive_pressure right)
{
	return left > right ? left : right;
}

static enum pqcp_adaptive_pressure latency_pressure(
	const struct pqcp_adaptive_metric_summary *latency,
	const struct pqcp_adaptive_resource_limits *limits)
{
	if (latency == NULL || limits == NULL ||
	    limits->latency_budget_us == 0U) {
		return PQCP_ADAPTIVE_PRESSURE_NONE;
	}
	return pressure_from_permille(
		pqcp_adaptive_internal_permille(
			latency->p99, limits->latency_budget_us));
}

static enum pqcp_adaptive_pressure memory_pressure(
	const struct pqcp_adaptive_telemetry_summary *summary,
	const struct pqcp_adaptive_resource_limits *limits)
{
	enum pqcp_adaptive_pressure pressure =
		PQCP_ADAPTIVE_PRESSURE_NONE;

	if (summary == NULL || limits == NULL) {
		return pressure;
	}
	if (limits->ram_capacity_bytes != 0U) {
		const uint64_t ram_used =
			summary->minimum_free_ram_bytes >=
				   limits->ram_capacity_bytes ?
			   0U :
			   limits->ram_capacity_bytes -
			   summary->minimum_free_ram_bytes;
		pressure = maximum_pressure(
			pressure,
			pressure_from_permille(
				pqcp_adaptive_internal_permille(
					ram_used,
					limits->ram_capacity_bytes)));
	}
	if (limits->stack_capacity_bytes != 0U) {
		pressure = maximum_pressure(
			pressure,
			pressure_from_permille(
				pqcp_adaptive_internal_permille(
					summary->maximum_stack_used_bytes,
					limits->stack_capacity_bytes)));
	}
	if (limits->heap_capacity_bytes != 0U) {
		const uint64_t heap_used =
			summary->minimum_heap_free_bytes >=
				    limits->heap_capacity_bytes ?
			    0U :
			    limits->heap_capacity_bytes -
			    summary->minimum_heap_free_bytes;
		pressure = maximum_pressure(
			pressure,
			pressure_from_permille(
				pqcp_adaptive_internal_permille(
					heap_used,
					limits->heap_capacity_bytes)));
	}
	return pressure;
}

static enum pqcp_adaptive_pressure energy_pressure(
	const struct pqcp_adaptive_metric_summary *energy,
	const struct pqcp_adaptive_resource_limits *limits)
{
	if (energy == NULL || limits == NULL ||
	    limits->energy_budget_uj == 0U) {
		return PQCP_ADAPTIVE_PRESSURE_NONE;
	}
	return pressure_from_permille(
		pqcp_adaptive_internal_permille(
			energy->p99, limits->energy_budget_uj));
}

static void summarize_scalar_fields(
	const struct pqcp_adaptive_telemetry_window *window,
	struct pqcp_adaptive_telemetry_summary *summary)
{
	uint64_t battery_sum = 0U;
	uint64_t loss_sum = 0U;

	summary->minimum_free_ram_bytes = UINT64_MAX;
	summary->minimum_heap_free_bytes = UINT64_MAX;
	summary->maximum_temperature_millic = INT32_MIN;
	for (uint32_t index = 0U; index < window->count; ++index) {
		const struct pqcp_adaptive_telemetry_sample *sample =
			sample_at(window, index);

		if (sample->operation_succeeded) {
			summary->success_count++;
		} else {
			summary->failure_count++;
		}
		if (sample->free_ram_bytes <
		    summary->minimum_free_ram_bytes) {
			summary->minimum_free_ram_bytes =
				sample->free_ram_bytes;
		}
		if (sample->stack_used_bytes >
		    summary->maximum_stack_used_bytes) {
			summary->maximum_stack_used_bytes =
				sample->stack_used_bytes;
		}
		if (sample->heap_free_bytes <
		    summary->minimum_heap_free_bytes) {
			summary->minimum_heap_free_bytes =
				sample->heap_free_bytes;
		}
		if (sample->queue_depth > summary->maximum_queue_depth) {
			summary->maximum_queue_depth =
				sample->queue_depth;
		}
		if (sample->temperature_millic >
		    summary->maximum_temperature_millic) {
			summary->maximum_temperature_millic =
				sample->temperature_millic;
		}
		battery_sum += sample->battery_permille;
		loss_sum += sample->network_loss_permille;
		summary->total_handshake_failures +=
			sample->handshake_failures;
		summary->total_auth_failures += sample->auth_failures;
	}
	if (window->count == 0U) {
		summary->minimum_free_ram_bytes = 0U;
		summary->minimum_heap_free_bytes = 0U;
		summary->maximum_temperature_millic = 0;
		return;
	}
	summary->average_battery_permille =
		(uint32_t)(battery_sum / window->count);
	summary->average_network_loss_permille =
		(uint32_t)(loss_sum / window->count);
	summary->first_timestamp_ms =
		sample_at(window, 0U)->timestamp_ms;
	summary->last_timestamp_ms =
		sample_at(window, window->count - 1U)->timestamp_ms;
}

static uint32_t anomaly_mask(
	const struct pqcp_adaptive_telemetry_summary *summary,
	const struct pqcp_adaptive_resource_limits *limits)
{
	uint32_t anomalies = 0U;

	if (summary->latency_pressure >= PQCP_ADAPTIVE_PRESSURE_HIGH ||
	    summary->latency.coefficient_variation_bps > 2500U) {
		anomalies |= PQCP_ADAPTIVE_ANOMALY_LATENCY_SPIKE;
	}
	if (summary->memory_pressure >= PQCP_ADAPTIVE_PRESSURE_HIGH) {
		anomalies |= PQCP_ADAPTIVE_ANOMALY_MEMORY_PRESSURE;
	}
	if (limits != NULL && limits->stack_capacity_bytes != 0U &&
	    pqcp_adaptive_internal_permille(
		    summary->maximum_stack_used_bytes,
		    limits->stack_capacity_bytes) >= 900U) {
		anomalies |= PQCP_ADAPTIVE_ANOMALY_STACK_PRESSURE;
	}
	if (limits != NULL && limits->heap_capacity_bytes != 0U &&
	    summary->minimum_heap_free_bytes <
		    limits->heap_capacity_bytes / 10U) {
		anomalies |= PQCP_ADAPTIVE_ANOMALY_HEAP_PRESSURE;
	}
	if (summary->energy_pressure >= PQCP_ADAPTIVE_PRESSURE_HIGH ||
	    summary->energy.coefficient_variation_bps > 3000U) {
		anomalies |= PQCP_ADAPTIVE_ANOMALY_ENERGY_SPIKE;
	}
	if (limits != NULL && limits->queue_capacity != 0U &&
	    summary->maximum_queue_depth * 10U >=
		    limits->queue_capacity * 9U) {
		anomalies |= PQCP_ADAPTIVE_ANOMALY_QUEUE_PRESSURE;
	}
	if (summary->average_network_loss_permille >= 100U) {
		anomalies |= PQCP_ADAPTIVE_ANOMALY_NETWORK_LOSS;
	}
	if (summary->total_handshake_failures != 0U) {
		anomalies |=
			PQCP_ADAPTIVE_ANOMALY_HANDSHAKE_FAILURES;
	}
	return anomalies;
}

static int telemetry_digest(
	const struct pqcp_adaptive_telemetry_window *window,
	const struct pqcp_adaptive_telemetry_summary *summary,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (window == NULL || summary == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_TELEMETRY_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, summary->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, summary->sample_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, summary->success_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, summary->failure_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, summary->anomaly_mask);
	for (uint32_t index = 0U; index < window->count; ++index) {
		const struct pqcp_adaptive_telemetry_sample *sample =
			sample_at(window, index);

		pqcp_deployment_evidence_digest_update_u64(
			&digest, sample->timestamp_ms);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, sample->latency_us);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, sample->cycles);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, sample->free_ram_bytes);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, sample->stack_used_bytes);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, sample->heap_free_bytes);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, sample->energy_uj);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, sample->queue_depth);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, (uint32_t)sample->temperature_millic);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, sample->battery_permille);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, sample->network_loss_permille);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, sample->handshake_failures);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, sample->auth_failures);
		pqcp_deployment_evidence_digest_update_bool(
			&digest, sample->operation_succeeded);
	}
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

int pqcp_adaptive_telemetry_init(
	struct pqcp_adaptive_telemetry_window *window)
{
	if (window == NULL) {
		return -EINVAL;
	}
	memset(window, 0, sizeof(*window));
	window->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	window->capacity = PQCP_ADAPTIVE_TELEMETRY_CAPACITY;
	return 0;
}

int pqcp_adaptive_telemetry_push(
	struct pqcp_adaptive_telemetry_window *window,
	const struct pqcp_adaptive_telemetry_sample *sample)
{
	if (window == NULL ||
	    window->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    window->capacity != PQCP_ADAPTIVE_TELEMETRY_CAPACITY ||
	    window->count > window->capacity ||
	    window->head >= window->capacity ||
	    !telemetry_sample_valid(sample)) {
		if (window != NULL) {
			window->rejected_samples++;
		}
		return -EINVAL;
	}
	if (window->last_timestamp_ms != 0U &&
	    sample->timestamp_ms <= window->last_timestamp_ms) {
		window->rejected_samples++;
		return -ERANGE;
	}
	window->samples[window->head] = *sample;
	window->head = (window->head + 1U) % window->capacity;
	if (window->count < window->capacity) {
		window->count++;
	}
	window->last_timestamp_ms = sample->timestamp_ms;
	return 0;
}

int pqcp_adaptive_telemetry_summarize(
	const struct pqcp_adaptive_telemetry_window *window,
	const struct pqcp_adaptive_resource_limits *limits,
	struct pqcp_adaptive_telemetry_summary *summary)
{
	int ret;

	if (!telemetry_window_valid(window) || summary == NULL) {
		return -EINVAL;
	}
	memset(summary, 0, sizeof(*summary));
	summary->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	summary->sample_count = window->count;
	ret = summarize_metric(window, latency_value, &summary->latency);
	if (ret != 0) {
		return ret;
	}
	ret = summarize_metric(window, cycles_value, &summary->cycles);
	if (ret != 0) {
		return ret;
	}
	ret = summarize_metric(window, energy_value, &summary->energy);
	if (ret != 0) {
		return ret;
	}
	summarize_scalar_fields(window, summary);
	summary->latency_pressure =
		latency_pressure(&summary->latency, limits);
	summary->memory_pressure = memory_pressure(summary, limits);
	summary->energy_pressure =
		energy_pressure(&summary->energy, limits);
	summary->anomaly_mask = anomaly_mask(summary, limits);
	if (window->count == 0U || summary->failure_count != 0U ||
	    summary->anomaly_mask != 0U) {
		summary->status = window->count == 0U ?
			PQCP_ADAPTIVE_STATUS_FAIL :
			PQCP_ADAPTIVE_STATUS_WARN;
	} else {
		summary->status = PQCP_ADAPTIVE_STATUS_PASS;
	}
	return telemetry_digest(
		window, summary, summary->telemetry_digest_hex);
}

int pqcp_adaptive_telemetry_reset(
	struct pqcp_adaptive_telemetry_window *window)
{
	uint32_t rejected;

	if (window == NULL ||
	    window->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	rejected = window->rejected_samples;
	pqcp_adaptive_telemetry_init(window);
	window->rejected_samples = rejected;
	return 0;
}

int pqcp_adaptive_telemetry_emit(
	const struct pqcp_adaptive_telemetry_summary *summary)
{
	if (summary == NULL ||
	    summary->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_status_valid(summary->status)) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_TELEMETRY schema=%u status=%s samples=%u success=%u failures=%u anomalies=0x%08x latency_pressure=%s memory_pressure=%s energy_pressure=%s latency_min=%llu latency_median=%llu latency_p90=%llu latency_p99=%llu latency_mad=%llu latency_cv_bps=%u latency_trend=%lld cycles_median=%llu energy_median=%llu free_ram_min=%llu stack_max=%llu heap_free_min=%llu queue_max=%u battery_avg=%u network_loss_avg=%u handshake_failures=%u auth_failures=%u temperature_max_millic=%d first_ms=%llu last_ms=%llu digest=%s\n",
	       summary->schema_version,
	       pqcp_adaptive_status_str(summary->status),
	       summary->sample_count,
	       summary->success_count,
	       summary->failure_count,
	       summary->anomaly_mask,
	       pqcp_adaptive_pressure_str(summary->latency_pressure),
	       pqcp_adaptive_pressure_str(summary->memory_pressure),
	       pqcp_adaptive_pressure_str(summary->energy_pressure),
	       (unsigned long long)summary->latency.minimum,
	       (unsigned long long)summary->latency.median,
	       (unsigned long long)summary->latency.p90,
	       (unsigned long long)summary->latency.p99,
	       (unsigned long long)summary->latency.mad,
	       summary->latency.coefficient_variation_bps,
	       (long long)summary->latency.trend_per_sample,
	       (unsigned long long)summary->cycles.median,
	       (unsigned long long)summary->energy.median,
	       (unsigned long long)summary->minimum_free_ram_bytes,
	       (unsigned long long)summary->maximum_stack_used_bytes,
	       (unsigned long long)summary->minimum_heap_free_bytes,
	       summary->maximum_queue_depth,
	       summary->average_battery_permille,
	       summary->average_network_loss_permille,
	       summary->total_handshake_failures,
	       summary->total_auth_failures,
	       summary->maximum_temperature_millic,
	       (unsigned long long)summary->first_timestamp_ms,
	       (unsigned long long)summary->last_timestamp_ms,
	       summary->telemetry_digest_hex);
	return 0;
}
