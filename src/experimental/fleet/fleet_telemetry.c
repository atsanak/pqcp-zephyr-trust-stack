/*
 * SPDX-License-Identifier: MIT
 *
 * Bounded telemetry windows with exact summaries and integer EWMA.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_operations.h>

static bool metric_valid(enum pqcp_fleet_metric metric)
{
	return metric >= PQCP_FLEET_METRIC_HANDSHAKE_US &&
	       metric < PQCP_FLEET_METRIC_COUNT;
}

static void recompute_window(
	struct pqcp_fleet_metric_window *window)
{
	uint64_t minimum = UINT64_MAX;
	uint64_t maximum = 0U;
	uint64_t sum = 0U;
	size_t count = 0U;

	for (size_t index = 0U; index < window->capacity;
	     ++index) {
		const struct pqcp_fleet_metric_sample *sample =
			&window->samples[index];

		if (sample->timestamp_ms == 0U) {
			continue;
		}
		if (sample->value < minimum) {
			minimum = sample->value;
		}
		if (sample->value > maximum) {
			maximum = sample->value;
		}
		if (UINT64_MAX - sum < sample->value) {
			sum = UINT64_MAX;
		} else {
			sum += sample->value;
		}
		count++;
	}
	window->count = count;
	window->minimum = count == 0U ? 0U : minimum;
	window->maximum = count == 0U ? 0U : maximum;
	window->sum = sum;
}

static uint64_t update_ewma(
	uint64_t previous,
	uint64_t value,
	uint32_t weight)
{
	if (previous == 0U || weight <= 1U) {
		return value;
	}
	if (value >= previous) {
		return previous +
		       (value - previous) / weight;
	}
	return previous -
	       (previous - value) / weight;
}

int pqcp_fleet_telemetry_init(
	struct pqcp_fleet_telemetry *telemetry,
	struct pqcp_fleet_metric_sample *samples,
	size_t samples_per_metric)
{
	if (telemetry == NULL || samples == NULL ||
	    samples_per_metric == 0U ||
	    samples_per_metric >
		    SIZE_MAX / PQCP_FLEET_METRIC_COUNT) {
		return -EINVAL;
	}
	memset(telemetry, 0, sizeof(*telemetry));
	memset(samples, 0,
	       sizeof(*samples) * samples_per_metric *
		       PQCP_FLEET_METRIC_COUNT);
	telemetry->schema_version =
		PQCP_FLEET_OPERATIONS_SCHEMA_VERSION;
	for (size_t metric = 0U;
	     metric < PQCP_FLEET_METRIC_COUNT; ++metric) {
		telemetry->windows[metric].samples =
			samples + metric * samples_per_metric;
		telemetry->windows[metric].capacity =
			samples_per_metric;
		telemetry->windows[metric].ewma_weight = 8U;
	}
	telemetry->generation = 1U;
	k_mutex_init(&telemetry->lock);
	telemetry->initialized = true;
	return 0;
}

int pqcp_fleet_telemetry_record(
	struct pqcp_fleet_telemetry *telemetry,
	enum pqcp_fleet_metric metric,
	uint64_t value,
	uint64_t now_ms)
{
	struct pqcp_fleet_metric_window *window;
	int ret;

	if (telemetry == NULL || !telemetry->initialized ||
	    !metric_valid(metric) || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&telemetry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	window = &telemetry->windows[metric];
	window->samples[window->next_index].timestamp_ms = now_ms;
	window->samples[window->next_index].value = value;
	window->next_index =
		(window->next_index + 1U) % window->capacity;
	window->ewma = update_ewma(
		window->ewma, value, window->ewma_weight);
	recompute_window(window);
	telemetry->generation++;
	if (telemetry->generation == 0U) {
		telemetry->generation = 1U;
	}
	(void)k_mutex_unlock(&telemetry->lock);
	return 0;
}

static uint64_t percentile95(
	const struct pqcp_fleet_metric_window *window)
{
	const size_t rank =
		(window->count * 95U + 99U) / 100U;
	uint64_t selected = UINT64_MAX;

	if (window->count == 0U) {
		return 0U;
	}
	for (size_t candidate_index = 0U;
	     candidate_index < window->capacity;
	     ++candidate_index) {
		const struct pqcp_fleet_metric_sample *candidate =
			&window->samples[candidate_index];
		size_t less_or_equal = 0U;

		if (candidate->timestamp_ms == 0U ||
		    candidate->value >= selected) {
			continue;
		}
		for (size_t index = 0U;
		     index < window->capacity; ++index) {
			const struct pqcp_fleet_metric_sample *sample =
				&window->samples[index];

			if (sample->timestamp_ms != 0U &&
			    sample->value <= candidate->value) {
				less_or_equal++;
			}
		}
		if (less_or_equal >= rank) {
			selected = candidate->value;
		}
	}
	return selected == UINT64_MAX ?
		window->maximum : selected;
}

int pqcp_fleet_telemetry_summary(
	struct pqcp_fleet_telemetry *telemetry,
	enum pqcp_fleet_metric metric,
	uint64_t *minimum,
	uint64_t *maximum,
	uint64_t *average,
	uint64_t *p95,
	uint64_t *ewma)
{
	const struct pqcp_fleet_metric_window *window;
	int ret;

	if (telemetry == NULL || !telemetry->initialized ||
	    !metric_valid(metric) || minimum == NULL ||
	    maximum == NULL || average == NULL || p95 == NULL ||
	    ewma == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&telemetry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	window = &telemetry->windows[metric];
	if (window->count == 0U) {
		(void)k_mutex_unlock(&telemetry->lock);
		return -ENODATA;
	}
	*minimum = window->minimum;
	*maximum = window->maximum;
	*average = window->sum == UINT64_MAX ?
		UINT64_MAX : window->sum / window->count;
	*p95 = percentile95(window);
	*ewma = window->ewma;
	(void)k_mutex_unlock(&telemetry->lock);
	return 0;
}

int pqcp_fleet_telemetry_prune(
	struct pqcp_fleet_telemetry *telemetry,
	uint64_t before_ms,
	uint32_t *pruned_count)
{
	uint32_t pruned = 0U;
	int ret;

	if (telemetry == NULL || !telemetry->initialized ||
	    before_ms == 0U || pruned_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&telemetry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t metric = 0U;
	     metric < PQCP_FLEET_METRIC_COUNT; ++metric) {
		struct pqcp_fleet_metric_window *window =
			&telemetry->windows[metric];

		for (size_t index = 0U;
		     index < window->capacity; ++index) {
			struct pqcp_fleet_metric_sample *sample =
				&window->samples[index];

			if (sample->timestamp_ms != 0U &&
			    sample->timestamp_ms < before_ms) {
				memset(sample, 0, sizeof(*sample));
				pruned++;
			}
		}
		recompute_window(window);
		if (window->count == 0U) {
			window->ewma = 0U;
		}
	}
	if (pruned != 0U) {
		telemetry->generation++;
		if (telemetry->generation == 0U) {
			telemetry->generation = 1U;
		}
	}
	(void)k_mutex_unlock(&telemetry->lock);
	*pruned_count = pruned;
	return 0;
}

int pqcp_fleet_telemetry_audit(
	struct pqcp_fleet_telemetry *telemetry)
{
	int ret;

	if (telemetry == NULL || !telemetry->initialized ||
	    telemetry->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    telemetry->generation == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&telemetry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t metric = 0U;
	     metric < PQCP_FLEET_METRIC_COUNT; ++metric) {
		const struct pqcp_fleet_metric_window *window =
			&telemetry->windows[metric];
		size_t observed = 0U;
		uint64_t minimum = UINT64_MAX;
		uint64_t maximum = 0U;
		uint64_t sum = 0U;

		if (window->samples == NULL ||
		    window->capacity == 0U ||
		    window->next_index >= window->capacity ||
		    window->count > window->capacity ||
		    window->ewma_weight == 0U) {
			(void)k_mutex_unlock(&telemetry->lock);
			return -EBADMSG;
		}
		for (size_t index = 0U;
		     index < window->capacity; ++index) {
			const struct pqcp_fleet_metric_sample *sample =
				&window->samples[index];

			if (sample->timestamp_ms == 0U) {
				continue;
			}
			observed++;
			if (sample->value < minimum) {
				minimum = sample->value;
			}
			if (sample->value > maximum) {
				maximum = sample->value;
			}
			if (UINT64_MAX - sum < sample->value) {
				sum = UINT64_MAX;
			} else {
				sum += sample->value;
			}
		}
		if (observed != window->count ||
		    (observed != 0U &&
		     (minimum != window->minimum ||
		      maximum != window->maximum ||
		      sum != window->sum)) ||
		    (observed == 0U &&
		     (window->minimum != 0U ||
		      window->maximum != 0U ||
		      window->sum != 0U))) {
			(void)k_mutex_unlock(&telemetry->lock);
			return -EBADMSG;
		}
	}
	(void)k_mutex_unlock(&telemetry->lock);
	return 0;
}
