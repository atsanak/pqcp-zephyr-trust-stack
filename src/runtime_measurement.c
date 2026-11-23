/*
 * SPDX-License-Identifier: MIT
 *
 * Runtime measurement and adaptive-control bridge.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/runtime_executor.h>

#include "runtime_internal.h"

static struct pqcp_runtime_profile_state *find_profile_state(
	struct pqcp_runtime_executor *executor,
	const char *profile_id)
{
	struct pqcp_runtime_profile_state *free_state = NULL;

	for (size_t index = 0U;
	     index < executor->profile_state_capacity; ++index) {
		struct pqcp_runtime_profile_state *state =
			&executor->profile_states[index];

		if (state->schema_version == 0U &&
		    free_state == NULL) {
			free_state = state;
			continue;
		}
		if (state->schema_version ==
			    PQCP_RUNTIME_SCHEMA_VERSION &&
		    strcmp(state->profile_id, profile_id) == 0) {
			return state;
		}
	}
	if (free_state != NULL &&
	    pqcp_runtime_profile_state_init(
		    free_state, profile_id) == 0) {
		return free_state;
	}
	return NULL;
}

static uint64_t stack_used_bytes(void)
{
#if defined(CONFIG_THREAD_STACK_INFO)
	size_t unused = 0U;
	struct k_thread *thread = k_current_get();

	if (thread != NULL &&
	    k_thread_stack_space_get(thread, &unused) == 0) {
		const size_t configured =
			IS_ENABLED(CONFIG_PQCP_RUNTIME) ?
				CONFIG_PQCP_RUNTIME_WORKER_STACK_SIZE : 0U;

		if (configured >= unused) {
			return configured - unused;
		}
	}
#endif
	return 1U;
}

void pqcp_runtime_measurement_begin(
	struct pqcp_runtime_job *job,
	uint64_t *start_cycles)
{
	const uint64_t now_ms = pqcp_runtime_internal_now_ms();

	memset(&job->measurement, 0, sizeof(job->measurement));
	job->measurement.schema_version =
		PQCP_RUNTIME_SCHEMA_VERSION;
	job->measurement.operation = job->type;
	job->measurement.submitted_at_ms =
		job->submitted_at_ms;
	job->measurement.started_at_ms = now_ms;
	if (now_ms >= job->submitted_at_ms) {
		job->measurement.queue_delay_us =
			(now_ms - job->submitted_at_ms) * 1000U;
	}
	job->measurement.input_bytes =
		(uint32_t)(job->input_length +
			   job->aux_input_length);
	if (pqcp_runtime_internal_text_valid(
		    job->profile_id, sizeof(job->profile_id))) {
		(void)pqcp_runtime_internal_copy_text(
			job->measurement.profile_id,
			sizeof(job->measurement.profile_id),
			job->profile_id);
	}
	*start_cycles = pqcp_runtime_internal_cycles();
}

void pqcp_runtime_measurement_finish(
	struct pqcp_runtime_job *job,
	uint64_t start_cycles,
	size_t workspace_bytes,
	int result)
{
	const uint64_t end_cycles =
		pqcp_runtime_internal_cycles();
	const uint64_t now_ms =
		pqcp_runtime_internal_now_ms();
	uint64_t elapsed_cycles = 0U;

	if (end_cycles >= start_cycles) {
		elapsed_cycles = end_cycles - start_cycles;
	}
	job->measurement.completed_at_ms = now_ms;
	job->measurement.cycles = elapsed_cycles;
	job->measurement.latency_us =
		pqcp_runtime_internal_cycles_to_us(
			elapsed_cycles);
	if (job->measurement.latency_us == 0U) {
		job->measurement.latency_us = 1U;
	}
	job->measurement.stack_used_bytes =
		stack_used_bytes();
	job->measurement.workspace_bytes =
		workspace_bytes;
	job->measurement.output_bytes =
		(uint32_t)(job->output_length +
			   job->aux_output_length);
	job->measurement.result = result;
	job->measurement.success = result == 0;
	job->result = result;
	job->status = result == 0 ?
		PQCP_RUNTIME_STATUS_COMPLETED :
		PQCP_RUNTIME_STATUS_FAILED;
}

static int feed_telemetry(
	struct pqcp_runtime_executor *executor,
	const struct pqcp_runtime_measurement *measurement)
{
	struct pqcp_adaptive_telemetry_sample sample = {
		.timestamp_ms = measurement->completed_at_ms,
		.latency_us = measurement->latency_us,
		.cycles = measurement->cycles,
		.free_ram_bytes = 1U,
		.stack_used_bytes =
			measurement->stack_used_bytes != 0U ?
			measurement->stack_used_bytes : 1U,
		.heap_free_bytes = 1U,
		.energy_uj = 1U,
		.queue_depth = executor->queue_count,
		.temperature_millic = 25000,
		.battery_permille = 1000U,
		.operation_succeeded = measurement->success,
	};

	if (executor->adaptive_control == NULL) {
		return 0;
	}
	return pqcp_adaptive_telemetry_push(
		&executor->adaptive_control->telemetry, &sample);
}

static int feed_calibration(
	struct pqcp_runtime_executor *executor,
	const struct pqcp_runtime_measurement *measurement)
{
	struct pqcp_adaptive_calibration_observation observation;

	if (executor->adaptive_control == NULL ||
	    executor->calibration == NULL ||
	    !pqcp_runtime_internal_text_valid(
		    measurement->profile_id,
		    sizeof(measurement->profile_id))) {
		return 0;
	}
	memset(&observation, 0, sizeof(observation));
	observation.timestamp_ms =
		measurement->completed_at_ms;
	observation.latency_us =
		measurement->latency_us;
	observation.cycles = measurement->cycles;
	observation.ram_bytes =
		measurement->workspace_bytes != 0U ?
		measurement->workspace_bytes : 1U;
	observation.stack_bytes =
		measurement->stack_used_bytes != 0U ?
		measurement->stack_used_bytes : 1U;
	observation.heap_bytes = 1U;
	observation.energy_uj = 1U;
	observation.successful = measurement->success;
	if (pqcp_runtime_internal_copy_text(
		    observation.profile_id,
		    sizeof(observation.profile_id),
		    measurement->profile_id) != 0) {
		return -EINVAL;
	}
	return pqcp_adaptive_calibration_observe(
		executor->calibration,
		&executor->adaptive_control->registry,
		&observation);
}

int pqcp_runtime_measurement_publish(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job)
{
	int telemetry_ret = 0;
	int calibration_ret = 0;
	int state_ret = 0;

	if (executor == NULL || job == NULL ||
	    job->measurement.schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
		return -EINVAL;
	}
	if (executor->profile_states != NULL &&
	    executor->profile_state_capacity != 0U &&
	    pqcp_runtime_internal_text_valid(
		    job->measurement.profile_id,
		    sizeof(job->measurement.profile_id))) {
		struct pqcp_runtime_profile_state *state =
			find_profile_state(
			executor, job->measurement.profile_id);

		if (state == NULL) {
			state_ret = -ENOSPC;
		} else {
			state_ret = pqcp_runtime_profile_state_observe(
				state, &job->measurement);
			if (state_ret == -EIO &&
			    !job->measurement.success) {
				state_ret = 0;
			}
		}
	}
	telemetry_ret = feed_telemetry(
		executor, &job->measurement);
	calibration_ret = feed_calibration(
		executor, &job->measurement);
	if (calibration_ret == -EAGAIN &&
	    !job->measurement.success) {
		calibration_ret = 0;
	}
	if (state_ret != 0) {
		return state_ret;
	}
	if (telemetry_ret != 0) {
		return telemetry_ret;
	}
	if (calibration_ret != 0 &&
	    calibration_ret != -EAGAIN) {
		return calibration_ret;
	}
	return 0;
}
