/*
 * SPDX-License-Identifier: MIT
 *
 * Runtime health appraisal from executable observations.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_control.h>

#define PQCP_RUNTIME_HEALTH_BLOCK_KEY_STORE (1U << 0)
#define PQCP_RUNTIME_HEALTH_BLOCK_EXECUTOR (1U << 1)
#define PQCP_RUNTIME_HEALTH_BLOCK_SESSIONS (1U << 2)
#define PQCP_RUNTIME_HEALTH_BLOCK_AUDIT (1U << 3)
#define PQCP_RUNTIME_HEALTH_BLOCK_FAILURE_RATE (1U << 4)
#define PQCP_RUNTIME_HEALTH_WARNING_QUEUE (1U << 0)
#define PQCP_RUNTIME_HEALTH_WARNING_LATENCY (1U << 1)
#define PQCP_RUNTIME_HEALTH_WARNING_STACK (1U << 2)
#define PQCP_RUNTIME_HEALTH_WARNING_WORKSPACE (1U << 3)
#define PQCP_RUNTIME_HEALTH_WARNING_FAILURES (1U << 4)

int pqcp_runtime_health_policy_default(
	struct pqcp_runtime_health_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	policy->maximum_consecutive_failures = 3U;
	policy->maximum_queue_depth =
		CONFIG_PQCP_RUNTIME_MAX_JOBS > 1 ?
		CONFIG_PQCP_RUNTIME_MAX_JOBS - 1U : 1U;
	policy->minimum_success_permille = 950U;
	policy->maximum_latency_us = 1000000U;
	policy->maximum_stack_bytes =
		CONFIG_PQCP_RUNTIME_WORKER_STACK_SIZE;
	policy->maximum_workspace_bytes =
		CONFIG_PQCP_RUNTIME_WORKSPACE_BYTES;
	policy->lockdown_on_audit_failure = true;
	policy->lockdown_on_key_store_failure = true;
	policy->recovery_on_profile_failure = true;
	return 0;
}

static void aggregate_profiles(
	const struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_health_report *report)
{
	if (executor->profile_states == NULL) {
		return;
	}
	for (size_t index = 0U;
	     index < executor->profile_state_capacity; ++index) {
		const struct pqcp_runtime_profile_state *state =
			&executor->profile_states[index];

		if (state->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
			continue;
		}
		report->jobs_observed += state->observation_count;
		report->jobs_failed += state->failed_observations;
		if (state->latency_ewma_us >
		    report->maximum_latency_us) {
			report->maximum_latency_us =
				state->latency_ewma_us;
		}
		if (state->stack_high_watermark >
		    report->maximum_stack_bytes) {
			report->maximum_stack_bytes =
				state->stack_high_watermark;
		}
		if (state->workspace_high_watermark >
		    report->maximum_workspace_bytes) {
			report->maximum_workspace_bytes =
				state->workspace_high_watermark;
		}
	}
}

static uint32_t success_permille(
	const struct pqcp_runtime_health_report *report)
{
	if (report->jobs_observed == 0U) {
		return 1000U;
	}
	if (report->jobs_failed >= report->jobs_observed) {
		return 0U;
	}
	return (uint32_t)(
		(report->jobs_observed - report->jobs_failed) *
		1000U / report->jobs_observed);
}

static enum pqcp_runtime_health_status determine_status(
	const struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_health_report *report)
{
	if (controller->lockdown ||
	    (report->blocker_mask &
	     (PQCP_RUNTIME_HEALTH_BLOCK_AUDIT |
	      PQCP_RUNTIME_HEALTH_BLOCK_KEY_STORE)) != 0U) {
		return PQCP_RUNTIME_HEALTH_LOCKDOWN;
	}
	if (report->blocker_mask != 0U ||
	    controller->consecutive_failures >=
		    controller->health_policy
			    .maximum_consecutive_failures) {
		return PQCP_RUNTIME_HEALTH_RECOVERY;
	}
	if (report->warning_mask != 0U) {
		return PQCP_RUNTIME_HEALTH_DEGRADED;
	}
	return PQCP_RUNTIME_HEALTH_HEALTHY;
}

int pqcp_runtime_health_evaluate(
	struct pqcp_runtime_controller *controller,
	struct pqcp_runtime_health_report *report)
{
	const struct pqcp_runtime_health_policy *policy;

	if (controller == NULL || report == NULL ||
	    !controller->initialized) {
		return -EINVAL;
	}
	policy = &controller->health_policy;
	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	report->key_store_valid =
		pqcp_runtime_key_store_audit(
			controller->key_store) == 0;
	report->executor_valid =
		pqcp_runtime_executor_audit(
			controller->executor) == 0;
	report->session_table_valid =
		pqcp_runtime_session_manager_audit(
			controller->sessions) == 0;
	report->audit_valid =
		pqcp_runtime_audit_verify(
			controller->audit) == 0;
	if (!report->key_store_valid) {
		report->blocker_mask |=
			PQCP_RUNTIME_HEALTH_BLOCK_KEY_STORE;
	}
	if (!report->executor_valid) {
		report->blocker_mask |=
			PQCP_RUNTIME_HEALTH_BLOCK_EXECUTOR;
	}
	if (!report->session_table_valid) {
		report->blocker_mask |=
			PQCP_RUNTIME_HEALTH_BLOCK_SESSIONS;
	}
	if (!report->audit_valid) {
		report->blocker_mask |=
			PQCP_RUNTIME_HEALTH_BLOCK_AUDIT;
	}
	report->queue_depth =
		controller->executor->queue_count;
	report->consecutive_failures =
		controller->consecutive_failures;
	aggregate_profiles(controller->executor, report);
	report->success_permille = success_permille(report);
	if (report->success_permille <
	    policy->minimum_success_permille) {
		report->blocker_mask |=
			PQCP_RUNTIME_HEALTH_BLOCK_FAILURE_RATE;
	}
	if (report->queue_depth >
	    policy->maximum_queue_depth) {
		report->warning_mask |=
			PQCP_RUNTIME_HEALTH_WARNING_QUEUE;
	}
	if (report->maximum_latency_us >
	    policy->maximum_latency_us) {
		report->warning_mask |=
			PQCP_RUNTIME_HEALTH_WARNING_LATENCY;
	}
	if (report->maximum_stack_bytes >
	    policy->maximum_stack_bytes) {
		report->warning_mask |=
			PQCP_RUNTIME_HEALTH_WARNING_STACK;
	}
	if (report->maximum_workspace_bytes >
	    policy->maximum_workspace_bytes) {
		report->warning_mask |=
			PQCP_RUNTIME_HEALTH_WARNING_WORKSPACE;
	}
	if (controller->consecutive_failures != 0U) {
		report->warning_mask |=
			PQCP_RUNTIME_HEALTH_WARNING_FAILURES;
	}
	report->status = determine_status(controller, report);
	controller->health = *report;
	return report->status ==
		       PQCP_RUNTIME_HEALTH_LOCKDOWN ?
		-EACCES : 0;
}
