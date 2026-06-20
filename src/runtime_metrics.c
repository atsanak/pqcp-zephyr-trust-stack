/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Fixed-memory runtime metrics and SLO evaluation.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/runtime_operations.h>

#include "runtime_internal.h"

static bool metric_kind_valid(
	enum pqcp_runtime_metric_kind kind)
{
	return kind >= PQCP_RUNTIME_METRIC_QUEUE_WAIT_US &&
	       kind < PQCP_RUNTIME_METRIC_KIND_COUNT;
}

static int slo_policy_validate(
	const struct pqcp_runtime_slo_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_RUNTIME_OPERATION_SCHEMA_VERSION ||
	    policy->minimum_samples == 0U ||
	    policy->maximum_failure_bps > 10000U) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < PQCP_RUNTIME_METRIC_KIND_COUNT; ++index) {
		if (policy->warning_threshold[index] == 0U ||
		    policy->failure_threshold[index] <
			    policy->warning_threshold[index]) {
			return -EINVAL;
		}
	}
	return 0;
}

static size_t metric_bucket(uint64_t value)
{
	size_t bucket = 0U;

	while (value > 1U && bucket < 15U) {
		value >>= 1U;
		bucket++;
	}
	return bucket;
}

static uint64_t saturating_sum(
	uint64_t left,
	uint64_t right)
{
	return UINT64_MAX - left < right ?
		UINT64_MAX : left + right;
}

static void aggregate_observe(
	struct pqcp_runtime_metric_aggregate *aggregate,
	const struct pqcp_runtime_metric_sample *sample)
{
	if (aggregate->count == 0U) {
		aggregate->minimum = sample->value;
		aggregate->maximum = sample->value;
		aggregate->ewma = sample->value;
	} else {
		if (sample->value < aggregate->minimum) {
			aggregate->minimum = sample->value;
		}
		if (sample->value > aggregate->maximum) {
			aggregate->maximum = sample->value;
		}
		aggregate->ewma =
			(aggregate->ewma * 7U +
			 sample->value) /
			8U;
	}
	aggregate->count++;
	if (sample->success) {
		aggregate->success_count++;
	} else {
		aggregate->failure_count++;
	}
	aggregate->sum =
		saturating_sum(aggregate->sum, sample->value);
	aggregate->buckets[
		metric_bucket(sample->value)]++;
	aggregate->last_updated_ms = sample->timestamp_ms;
}

int pqcp_runtime_slo_policy_default(
	struct pqcp_runtime_slo_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version =
		PQCP_RUNTIME_OPERATION_SCHEMA_VERSION;
	policy->warning_threshold[
		PQCP_RUNTIME_METRIC_QUEUE_WAIT_US] = 50000U;
	policy->failure_threshold[
		PQCP_RUNTIME_METRIC_QUEUE_WAIT_US] = 250000U;
	policy->warning_threshold[
		PQCP_RUNTIME_METRIC_EXECUTION_US] = 500000U;
	policy->failure_threshold[
		PQCP_RUNTIME_METRIC_EXECUTION_US] = 2000000U;
	policy->warning_threshold[
		PQCP_RUNTIME_METRIC_END_TO_END_US] = 750000U;
	policy->failure_threshold[
		PQCP_RUNTIME_METRIC_END_TO_END_US] = 3000000U;
	policy->warning_threshold[
		PQCP_RUNTIME_METRIC_CYCLES] = 100000000U;
	policy->failure_threshold[
		PQCP_RUNTIME_METRIC_CYCLES] = 500000000U;
	policy->warning_threshold[
		PQCP_RUNTIME_METRIC_STACK_BYTES] = 65536U;
	policy->failure_threshold[
		PQCP_RUNTIME_METRIC_STACK_BYTES] = 131072U;
	policy->warning_threshold[
		PQCP_RUNTIME_METRIC_WORKSPACE_BYTES] = 65536U;
	policy->failure_threshold[
		PQCP_RUNTIME_METRIC_WORKSPACE_BYTES] = 131072U;
	policy->warning_threshold[
		PQCP_RUNTIME_METRIC_QUEUE_DEPTH] = 8U;
	policy->failure_threshold[
		PQCP_RUNTIME_METRIC_QUEUE_DEPTH] = 16U;
	policy->warning_threshold[
		PQCP_RUNTIME_METRIC_FAILURES] = 1U;
	policy->failure_threshold[
		PQCP_RUNTIME_METRIC_FAILURES] = 5U;
	policy->minimum_samples = 4U;
	policy->maximum_failure_bps = 100U;
	return 0;
}

int pqcp_runtime_metrics_init(
	struct pqcp_runtime_metrics *metrics,
	const struct pqcp_runtime_slo_policy *policy)
{
	if (metrics == NULL ||
	    slo_policy_validate(policy) != 0) {
		return -EINVAL;
	}
	memset(metrics, 0, sizeof(*metrics));
	metrics->policy = *policy;
	for (size_t index = 0U;
	     index < PQCP_RUNTIME_METRIC_KIND_COUNT; ++index) {
		metrics->aggregates[index].schema_version =
			PQCP_RUNTIME_OPERATION_SCHEMA_VERSION;
		metrics->aggregates[index].kind =
			(enum pqcp_runtime_metric_kind)index;
	}
	k_mutex_init(&metrics->lock);
	metrics->initialized = true;
	return 0;
}

int pqcp_runtime_metrics_observe(
	struct pqcp_runtime_metrics *metrics,
	const struct pqcp_runtime_metric_sample *sample)
{
	int ret;

	if (metrics == NULL || !metrics->initialized ||
	    sample == NULL ||
	    sample->schema_version !=
		    PQCP_RUNTIME_OPERATION_SCHEMA_VERSION ||
	    !metric_kind_valid(sample->kind) ||
	    sample->timestamp_ms == 0U ||
	    !pqcp_runtime_internal_text_valid(
		    sample->profile_id,
		    sizeof(sample->profile_id))) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&metrics->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	aggregate_observe(
		&metrics->aggregates[sample->kind], sample);
	(void)k_mutex_unlock(&metrics->lock);
	return 0;
}

static int observe_value(
	struct pqcp_runtime_metrics *metrics,
	enum pqcp_runtime_metric_kind kind,
	const struct pqcp_runtime_job *job,
	uint64_t value,
	bool success)
{
	struct pqcp_runtime_metric_sample sample = {
		.schema_version =
			PQCP_RUNTIME_OPERATION_SCHEMA_VERSION,
		.kind = kind,
		.timestamp_ms =
			job->measurement.completed_at_ms != 0U ?
				job->measurement.completed_at_ms :
				pqcp_runtime_internal_now_ms(),
		.value = value,
		.subject_id = job->job_id,
		.success = success,
	};
	int ret;

	ret = pqcp_runtime_internal_copy_text(
		sample.profile_id, sizeof(sample.profile_id),
		job->profile_id);
	if (ret != 0) {
		return ret;
	}
	return pqcp_runtime_metrics_observe(metrics, &sample);
}

int pqcp_runtime_metrics_observe_job(
	struct pqcp_runtime_metrics *metrics,
	const struct pqcp_runtime_job *job,
	uint64_t queue_wait_us,
	uint64_t end_to_end_us)
{
	const bool success = job != NULL && job->result == 0;
	int first_error = 0;
	int ret;

	if (metrics == NULL || !metrics->initialized ||
	    job == NULL || job->job_id == 0U ||
	    !pqcp_runtime_internal_text_valid(
		    job->profile_id,
		    sizeof(job->profile_id))) {
		return -EINVAL;
	}
	ret = observe_value(
		metrics, PQCP_RUNTIME_METRIC_QUEUE_WAIT_US,
		job, queue_wait_us, success);
	if (ret != 0) {
		first_error = ret;
	}
	ret = observe_value(
		metrics, PQCP_RUNTIME_METRIC_EXECUTION_US,
		job, job->measurement.latency_us, success);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	ret = observe_value(
		metrics, PQCP_RUNTIME_METRIC_END_TO_END_US,
		job, end_to_end_us, success);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	ret = observe_value(
		metrics, PQCP_RUNTIME_METRIC_CYCLES,
		job, job->measurement.cycles, success);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	ret = observe_value(
		metrics, PQCP_RUNTIME_METRIC_STACK_BYTES,
		job, job->measurement.stack_used_bytes,
		success);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	ret = observe_value(
		metrics, PQCP_RUNTIME_METRIC_WORKSPACE_BYTES,
		job, job->measurement.workspace_bytes,
		success);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	ret = observe_value(
		metrics, PQCP_RUNTIME_METRIC_QUEUE_DEPTH,
		job, 0U, success);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	ret = observe_value(
		metrics, PQCP_RUNTIME_METRIC_FAILURES,
		job, success ? 0U : 1U, success);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	return first_error;
}

int pqcp_runtime_metrics_report(
	struct pqcp_runtime_metrics *metrics,
	uint64_t now_ms,
	struct pqcp_runtime_slo_report *report)
{
	int ret;

	if (metrics == NULL || !metrics->initialized ||
	    now_ms == 0U || report == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&metrics->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_RUNTIME_OPERATION_SCHEMA_VERSION;
	report->status = PQCP_RUNTIME_SLO_UNKNOWN;
	report->evaluated_at_ms = now_ms;
	for (size_t index = 0U;
	     index < PQCP_RUNTIME_METRIC_KIND_COUNT; ++index) {
		const struct pqcp_runtime_metric_aggregate *aggregate =
			&metrics->aggregates[index];
		uint64_t failure_bps = 0U;

		report->total_samples += aggregate->count;
		report->total_failures +=
			aggregate->failure_count;
		if (aggregate->count <
		    metrics->policy.minimum_samples) {
			continue;
		}
		report->evaluated_metrics++;
		if (aggregate->count != 0U) {
			failure_bps =
				aggregate->failure_count *
				10000U / aggregate->count;
		}
		if (aggregate->ewma >=
			    metrics->policy.
				    failure_threshold[index] ||
		    failure_bps >
			    metrics->policy.maximum_failure_bps) {
			report->failure_mask |= BIT(index);
		} else if (aggregate->ewma >=
			   metrics->policy.
				   warning_threshold[index]) {
			report->warning_mask |= BIT(index);
		}
	}
	if (report->evaluated_metrics != 0U) {
		report->status =
			report->failure_mask != 0U ?
				PQCP_RUNTIME_SLO_FAIL :
			report->warning_mask != 0U ?
				PQCP_RUNTIME_SLO_WARNING :
				PQCP_RUNTIME_SLO_PASS;
	}
	(void)k_mutex_unlock(&metrics->lock);
	return 0;
}

int pqcp_runtime_metrics_audit(
	struct pqcp_runtime_metrics *metrics)
{
	int ret;

	if (metrics == NULL || !metrics->initialized ||
	    slo_policy_validate(&metrics->policy) != 0) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&metrics->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < PQCP_RUNTIME_METRIC_KIND_COUNT; ++index) {
		const struct pqcp_runtime_metric_aggregate *aggregate =
			&metrics->aggregates[index];
		uint64_t bucket_count = 0U;

		if (aggregate->schema_version !=
			    PQCP_RUNTIME_OPERATION_SCHEMA_VERSION ||
		    aggregate->kind !=
			    (enum pqcp_runtime_metric_kind)index ||
		    aggregate->success_count +
				    aggregate->failure_count !=
			    aggregate->count ||
		    (aggregate->count != 0U &&
		     aggregate->minimum >
			     aggregate->maximum)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t bucket = 0U;
		     bucket < ARRAY_SIZE(aggregate->buckets);
		     ++bucket) {
			bucket_count +=
				aggregate->buckets[bucket];
		}
		if (bucket_count != aggregate->count) {
			ret = -EBADMSG;
			break;
		}
	}
	(void)k_mutex_unlock(&metrics->lock);
	return ret;
}
