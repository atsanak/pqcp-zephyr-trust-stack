/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Repeated executable campaigns with robust summary statistics.
 */

#include <errno.h>
#include <math.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/runtime_campaign.h>

#include "runtime_internal.h"

#define PQCP_RUNTIME_CAMPAIGN_WARNING_VARIANCE (1U << 0)
#define PQCP_RUNTIME_CAMPAIGN_WARNING_FAILURES (1U << 1)
#define PQCP_RUNTIME_CAMPAIGN_BLOCK_SUCCESS_RATE (1U << 0)
#define PQCP_RUNTIME_CAMPAIGN_BLOCK_NO_SAMPLES (1U << 1)
#define PQCP_RUNTIME_CAMPAIGN_BLOCK_VALIDATION (1U << 2)

static bool config_valid(
	const struct pqcp_runtime_campaign_config *config)
{
	return config != NULL &&
	       config->schema_version ==
		       PQCP_RUNTIME_SCHEMA_VERSION &&
	       config->repetitions >= 3U &&
	       config->repetitions <=
		       PQCP_RUNTIME_CAMPAIGN_MAX_SAMPLES &&
	       config->warmups <=
		       PQCP_RUNTIME_CAMPAIGN_MAX_SAMPLES &&
	       config->warmups + config->repetitions <=
		       PQCP_RUNTIME_CAMPAIGN_MAX_SAMPLES &&
	       config->minimum_success_permille <= 1000U &&
	       config->maximum_cv_permille <= 1000U &&
	       pqcp_runtime_internal_job_type_valid(
		       config->operation) &&
	       config->session_id != 0U &&
	       config->per_job_timeout_ms != 0U &&
	       pqcp_runtime_internal_text_valid(
		       config->profile_id,
		       sizeof(config->profile_id));
}

static void sort_values(uint64_t *values, size_t count)
{
	for (size_t index = 1U; index < count; ++index) {
		uint64_t value = values[index];
		size_t position = index;

		while (position > 0U &&
		       values[position - 1U] > value) {
			values[position] =
				values[position - 1U];
			position--;
		}
		values[position] = value;
	}
}

static uint64_t percentile(
	const uint64_t *values,
	size_t count,
	uint32_t percentile_value)
{
	size_t index;

	if (count == 0U) {
		return 0U;
	}
	index = ((count - 1U) * percentile_value + 99U) / 100U;
	if (index >= count) {
		index = count - 1U;
	}
	return values[index];
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

static void metric_summary(
	uint64_t *values,
	size_t count,
	struct pqcp_runtime_campaign_metric *metric)
{
	uint64_t sum = 0U;
	uint64_t variance_sum = 0U;
	uint64_t deviations[PQCP_RUNTIME_CAMPAIGN_MAX_SAMPLES];

	memset(metric, 0, sizeof(*metric));
	if (count == 0U) {
		return;
	}
	sort_values(values, count);
	metric->minimum = values[0];
	metric->maximum = values[count - 1U];
	for (size_t index = 0U; index < count; ++index) {
		sum += values[index];
	}
	metric->mean = sum / count;
	metric->median =
		count % 2U != 0U ?
		values[count / 2U] :
		(values[count / 2U - 1U] +
		 values[count / 2U]) / 2U;
	metric->p90 = percentile(values, count, 90U);
	metric->p99 = percentile(values, count, 99U);
	for (size_t index = 0U; index < count; ++index) {
		const uint64_t difference =
			values[index] > metric->median ?
			values[index] - metric->median :
			metric->median - values[index];
		const uint64_t mean_difference =
			values[index] > metric->mean ?
			values[index] - metric->mean :
			metric->mean - values[index];

		deviations[index] = difference;
		if (mean_difference != 0U &&
		    mean_difference <= UINT32_MAX) {
			variance_sum +=
				mean_difference * mean_difference;
		}
	}
	sort_values(deviations, count);
	metric->mad =
		count % 2U != 0U ?
		deviations[count / 2U] :
		(deviations[count / 2U - 1U] +
		 deviations[count / 2U]) / 2U;
	if (count > 1U) {
		metric->standard_deviation =
			integer_sqrt(variance_sum / (count - 1U));
	}
	if (metric->mean != 0U) {
		metric->coefficient_variation_permille =
			(uint32_t)(
				metric->standard_deviation *
				1000U / metric->mean);
	}
}

static void collect_metrics(
	const struct pqcp_runtime_campaign_sample *samples,
	size_t sample_count,
	struct pqcp_runtime_campaign_result *result)
{
	uint64_t latency[PQCP_RUNTIME_CAMPAIGN_MAX_SAMPLES];
	uint64_t cycles[PQCP_RUNTIME_CAMPAIGN_MAX_SAMPLES];
	uint64_t stack[PQCP_RUNTIME_CAMPAIGN_MAX_SAMPLES];
	uint64_t workspace[PQCP_RUNTIME_CAMPAIGN_MAX_SAMPLES];
	size_t count = 0U;

	for (size_t index = 0U; index < sample_count; ++index) {
		if (samples[index].warmup ||
		    !samples[index].success) {
			continue;
		}
		latency[count] = samples[index].latency_us;
		cycles[count] = samples[index].cycles;
		stack[count] = samples[index].stack_bytes;
		workspace[count] = samples[index].workspace_bytes;
		count++;
	}
	metric_summary(latency, count, &result->latency);
	metric_summary(cycles, count, &result->cycles);
	metric_summary(stack, count, &result->stack);
	metric_summary(workspace, count, &result->workspace);
}

static int digest_result(
	struct pqcp_runtime_campaign_result *result)
{
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
	const int ret = pqcp_runtime_internal_sha256(
		(const uint8_t *)result,
		offsetof(struct pqcp_runtime_campaign_result,
			 digest_hex),
		digest);

	if (ret != 0) {
		return ret;
	}
	return pqcp_runtime_internal_hex(
		digest, sizeof(digest), result->digest_hex,
		sizeof(result->digest_hex));
}

static void initialize_job(
	const struct pqcp_runtime_campaign_config *config,
	uint32_t iteration,
	struct pqcp_runtime_job *job)
{
	memset(job, 0, sizeof(*job));
	job->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	job->job_id =
		(config->session_id << 16U) |
		(iteration + 1U);
	job->session_id = config->session_id;
	job->type = config->operation;
	job->priority = PQCP_RUNTIME_PRIORITY_NORMAL;
	job->status = PQCP_RUNTIME_STATUS_IDLE;
	job->flags =
		PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS |
		PQCP_RUNTIME_JOB_FLAG_ZERO_OUTPUT_ON_FAILURE |
		PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION;
	job->level = config->level;
	job->deadline_ms =
		pqcp_runtime_internal_now_ms() +
		config->per_job_timeout_ms;
	(void)pqcp_runtime_internal_copy_text(
		job->profile_id, sizeof(job->profile_id),
		config->profile_id);
}

int pqcp_runtime_campaign_run(
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_campaign_config *config,
	struct pqcp_runtime_campaign_sample *samples,
	size_t sample_capacity,
	pqcp_runtime_campaign_prepare_fn prepare,
	void *prepare_user,
	struct pqcp_runtime_campaign_result *result)
{
	const uint32_t total =
		config != NULL ?
		config->warmups + config->repetitions : 0U;

	if (controller == NULL || !controller->initialized ||
	    !config_valid(config) || samples == NULL ||
	    sample_capacity < total || prepare == NULL ||
	    result == NULL) {
		return -EINVAL;
	}
	memset(samples, 0, sizeof(*samples) * sample_capacity);
	memset(result, 0, sizeof(*result));
	result->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	(void)pqcp_runtime_internal_copy_text(
		result->profile_id, sizeof(result->profile_id),
		config->profile_id);
	for (uint32_t iteration = 0U;
	     iteration < total; ++iteration) {
		struct pqcp_runtime_campaign_sample *sample =
			&samples[iteration];
		struct pqcp_runtime_job job;
		const bool warmup = iteration < config->warmups;

		initialize_job(config, iteration, &job);
		sample->schema_version =
			PQCP_RUNTIME_SCHEMA_VERSION;
		sample->index = iteration;
		sample->warmup = warmup;
		int ret = prepare(
			iteration, warmup, &job, prepare_user);

		if (ret == 0) {
			ret = pqcp_runtime_controller_submit(
				controller, config->session_id,
				&job);
		}
		sample->result = ret;
		sample->success = ret == 0;
		if (job.measurement.schema_version ==
		    PQCP_RUNTIME_SCHEMA_VERSION) {
			sample->latency_us =
				job.measurement.latency_us;
			sample->cycles = job.measurement.cycles;
			sample->stack_bytes =
				job.measurement.stack_used_bytes;
			sample->workspace_bytes =
				job.measurement.workspace_bytes;
		}
		if (!warmup) {
			result->sample_count++;
			if (ret == 0) {
				result->successful_samples++;
			} else {
				result->failed_samples++;
			}
		}
	}
	if (result->sample_count == 0U) {
		result->blocker_mask |=
			PQCP_RUNTIME_CAMPAIGN_BLOCK_NO_SAMPLES;
	} else {
		result->success_permille =
			result->successful_samples * 1000U /
			result->sample_count;
	}
	collect_metrics(samples, total, result);
	if (result->success_permille <
	    config->minimum_success_permille) {
		result->blocker_mask |=
			PQCP_RUNTIME_CAMPAIGN_BLOCK_SUCCESS_RATE;
	}
	if (result->failed_samples != 0U) {
		result->warning_mask |=
			PQCP_RUNTIME_CAMPAIGN_WARNING_FAILURES;
	}
	if (result->latency.coefficient_variation_permille >
		    config->maximum_cv_permille ||
	    result->cycles.coefficient_variation_permille >
		    config->maximum_cv_permille) {
		result->warning_mask |=
			PQCP_RUNTIME_CAMPAIGN_WARNING_VARIANCE;
	}
	result->status =
		result->blocker_mask != 0U ?
		PQCP_RUNTIME_STATUS_FAILED :
		PQCP_RUNTIME_STATUS_COMPLETED;
	if (digest_result(result) != 0) {
		return -EIO;
	}
	return result->blocker_mask == 0U ? 0 : -EACCES;
}

int pqcp_runtime_campaign_validate(
	const struct pqcp_runtime_campaign_config *config,
	const struct pqcp_runtime_campaign_sample *samples,
	size_t sample_count,
	const struct pqcp_runtime_campaign_result *result)
{
	struct pqcp_runtime_campaign_result copy;
	uint32_t non_warmup = 0U;
	uint32_t successes = 0U;

	if (!config_valid(config) || samples == NULL ||
	    result == NULL ||
	    result->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    sample_count !=
		    config->warmups + config->repetitions) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < sample_count; ++index) {
		if (samples[index].schema_version !=
			    PQCP_RUNTIME_SCHEMA_VERSION ||
		    samples[index].index != index ||
		    samples[index].warmup !=
			    (index < config->warmups)) {
			return -EBADMSG;
		}
		if (!samples[index].warmup) {
			non_warmup++;
			if (samples[index].success) {
				successes++;
			}
		}
	}
	if (non_warmup != result->sample_count ||
	    successes != result->successful_samples ||
	    result->failed_samples +
		    result->successful_samples !=
		    result->sample_count ||
	    strcmp(result->profile_id,
		   config->profile_id) != 0) {
		return -EBADMSG;
	}
	copy = *result;
	if (digest_result(&copy) != 0 ||
	    strcmp(copy.digest_hex, result->digest_hex) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_campaign_emit(
	const struct pqcp_runtime_campaign_config *config,
	const struct pqcp_runtime_campaign_result *result)
{
	if (!config_valid(config) || result == NULL) {
		return -EINVAL;
	}
	printk("PQCP_RUNTIME_CAMPAIGN schema=%u status=%s profile=%s operation=%s level=%u warmups=%u repetitions=%u success_permille=%u failures=%u latency_min=%llu latency_median=%llu latency_p90=%llu latency_p99=%llu latency_mad=%llu latency_cv_permille=%u cycles_median=%llu cycles_p90=%llu cycles_p99=%llu stack_max=%llu workspace_max=%llu blockers=0x%08x warnings=0x%08x digest=%s\n",
	       result->schema_version,
	       pqcp_runtime_status_str(result->status),
	       result->profile_id,
	       pqcp_runtime_job_type_str(config->operation),
	       config->level, config->warmups,
	       config->repetitions,
	       result->success_permille,
	       result->failed_samples,
	       (unsigned long long)result->latency.minimum,
	       (unsigned long long)result->latency.median,
	       (unsigned long long)result->latency.p90,
	       (unsigned long long)result->latency.p99,
	       (unsigned long long)result->latency.mad,
	       result->latency.coefficient_variation_permille,
	       (unsigned long long)result->cycles.median,
	       (unsigned long long)result->cycles.p90,
	       (unsigned long long)result->cycles.p99,
	       (unsigned long long)result->stack.maximum,
	       (unsigned long long)result->workspace.maximum,
	       result->blocker_mask, result->warning_mask,
	       result->digest_hex);
	return 0;
}
