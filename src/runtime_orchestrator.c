/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Integration layer for runtime policy, scheduling, metrics, and checkpoints.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_operations.h>

#include "runtime_internal.h"

static int orchestrator_event(
	struct pqcp_runtime_orchestrator *orchestrator,
	enum pqcp_runtime_event_kind kind,
	enum pqcp_runtime_event_severity severity,
	uint64_t subject_id,
	int result,
	uint64_t value,
	const char *profile_id,
	const char *detail)
{
	struct pqcp_runtime_event event = {
		.schema_version =
			PQCP_RUNTIME_OPERATION_SCHEMA_VERSION,
		.timestamp_ms = pqcp_runtime_internal_now_ms(),
		.kind = kind,
		.severity = severity,
		.subject_id = subject_id,
		.result = result,
		.value = value,
	};
	int ret;

	if (orchestrator->events == NULL) {
		return 0;
	}
	ret = pqcp_runtime_internal_copy_text(
		event.profile_id, sizeof(event.profile_id),
		profile_id != NULL ? profile_id : "runtime");
	if (ret == 0) {
		ret = pqcp_runtime_internal_copy_text(
			event.detail, sizeof(event.detail),
			detail);
	}
	if (ret != 0) {
		return ret;
	}
	return pqcp_runtime_event_append(
		orchestrator->events, &event, NULL);
}

static void update_state_from_health(
	struct pqcp_runtime_orchestrator *orchestrator)
{
	if (orchestrator->service->controller.lockdown) {
		orchestrator->state =
			PQCP_RUNTIME_POLICY_LOCKDOWN;
		return;
	}
	switch (orchestrator->service->controller.health.status) {
	case PQCP_RUNTIME_HEALTH_HEALTHY:
		orchestrator->state =
			PQCP_RUNTIME_POLICY_RUNNING;
		break;
	case PQCP_RUNTIME_HEALTH_DEGRADED:
		orchestrator->state =
			PQCP_RUNTIME_POLICY_DEGRADED;
		break;
	case PQCP_RUNTIME_HEALTH_RECOVERY:
		orchestrator->state =
			PQCP_RUNTIME_POLICY_RECOVERING;
		break;
	case PQCP_RUNTIME_HEALTH_LOCKDOWN:
		orchestrator->state =
			PQCP_RUNTIME_POLICY_LOCKDOWN;
		break;
	default:
		break;
	}
}

static int dispatch_once(
	struct pqcp_runtime_orchestrator *orchestrator,
	uint64_t now_ms)
{
	struct pqcp_runtime_scheduler_decision decision;
	uint64_t started_us;
	uint64_t finished_us;
	int result;
	int ret;

	ret = pqcp_runtime_scheduler_select(
		orchestrator->scheduler, now_ms, &decision);
	if (ret != 0) {
		return ret;
	}
	(void)orchestrator_event(
		orchestrator,
		PQCP_RUNTIME_EVENT_JOB_STARTED,
		PQCP_RUNTIME_EVENT_INFO,
		decision.job->job_id, 0,
		decision.tenant_id,
		decision.job->profile_id,
		"scheduled");
	started_us = k_ticks_to_us_floor64(
		k_uptime_ticks());
	result = pqcp_runtime_executor_execute(
		&orchestrator->service->executor,
		decision.job);
	finished_us = k_ticks_to_us_floor64(
		k_uptime_ticks());
	ret = pqcp_runtime_scheduler_complete(
		orchestrator->scheduler, &decision,
		result, now_ms);
	if (ret == 0 && orchestrator->metrics != NULL) {
		(void)pqcp_runtime_metrics_observe_job(
			orchestrator->metrics,
			decision.job,
			decision.waited_ms * 1000U,
			finished_us >= started_us ?
				finished_us - started_us :
				0U);
	}
	(void)orchestrator_event(
		orchestrator,
		result == 0 ?
			PQCP_RUNTIME_EVENT_JOB_COMPLETED :
			PQCP_RUNTIME_EVENT_JOB_FAILED,
		result == 0 ?
			PQCP_RUNTIME_EVENT_INFO :
			PQCP_RUNTIME_EVENT_ERROR,
		decision.job->job_id, result,
		decision.waited_ms,
		decision.job->profile_id,
		result == 0 ? "completed" : "failed");
	if (result != 0) {
		orchestrator->failures++;
	}
	return result;
}

int pqcp_runtime_orchestrator_init(
	struct pqcp_runtime_orchestrator *orchestrator,
	struct pqcp_runtime_service *service,
	struct pqcp_runtime_event_bus *events,
	struct pqcp_runtime_scheduler *scheduler,
	struct pqcp_runtime_checkpoint_store *checkpoints,
	struct pqcp_runtime_command_router *commands,
	struct pqcp_runtime_metrics *metrics,
	uint64_t now_ms)
{
	if (orchestrator == NULL || service == NULL ||
	    !service->initialized || events == NULL ||
	    !events->initialized || scheduler == NULL ||
	    !scheduler->initialized || checkpoints == NULL ||
	    !checkpoints->initialized || commands == NULL ||
	    !commands->initialized || metrics == NULL ||
	    !metrics->initialized || now_ms == 0U) {
		return -EINVAL;
	}
	memset(orchestrator, 0, sizeof(*orchestrator));
	orchestrator->service = service;
	orchestrator->events = events;
	orchestrator->scheduler = scheduler;
	orchestrator->checkpoints = checkpoints;
	orchestrator->commands = commands;
	orchestrator->metrics = metrics;
	orchestrator->state =
		PQCP_RUNTIME_POLICY_INITIALIZED;
	orchestrator->epoch = 1U;
	orchestrator->started_at_ms = now_ms;
	orchestrator->last_tick_ms = now_ms;
	k_mutex_init(&orchestrator->lock);
	orchestrator->initialized = true;
	return orchestrator_event(
		orchestrator,
		PQCP_RUNTIME_EVENT_SERVICE_INITIALIZED,
		PQCP_RUNTIME_EVENT_INFO,
		orchestrator->epoch, 0, 0U,
		"runtime", "orchestrator-initialized");
}

int pqcp_runtime_orchestrator_start(
	struct pqcp_runtime_orchestrator *orchestrator,
	uint64_t now_ms)
{
	int ret;

	if (orchestrator == NULL ||
	    !orchestrator->initialized || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->state ==
	    PQCP_RUNTIME_POLICY_RUNNING) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return 0;
	}
	if (!orchestrator->service->started) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -EAGAIN;
	}
	orchestrator->state = PQCP_RUNTIME_POLICY_RUNNING;
	orchestrator->started_at_ms = now_ms;
	orchestrator->last_tick_ms = now_ms;
	orchestrator->epoch++;
	ret = orchestrator_event(
		orchestrator,
		PQCP_RUNTIME_EVENT_SERVICE_STARTED,
		PQCP_RUNTIME_EVENT_INFO,
		orchestrator->epoch, 0, 0U,
		"runtime", "orchestrator-started");
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_runtime_orchestrator_tick(
	struct pqcp_runtime_orchestrator *orchestrator,
	uint64_t now_ms,
	uint32_t dispatch_budget)
{
	uint32_t dispatched = 0U;
	int first_error = 0;
	int ret;

	if (orchestrator == NULL ||
	    !orchestrator->initialized || now_ms == 0U ||
	    dispatch_budget == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->state !=
		    PQCP_RUNTIME_POLICY_RUNNING &&
	    orchestrator->state !=
		    PQCP_RUNTIME_POLICY_DEGRADED) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return -ESHUTDOWN;
	}
	ret = pqcp_runtime_service_tick(
		orchestrator->service, now_ms);
	if (ret != 0) {
		first_error = ret;
		orchestrator->failures++;
	}
	update_state_from_health(orchestrator);
	while (dispatched < dispatch_budget &&
	       orchestrator->state ==
		       PQCP_RUNTIME_POLICY_RUNNING) {
		ret = dispatch_once(orchestrator, now_ms);
		if (ret == -EAGAIN || ret == -EDQUOT) {
			break;
		}
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
		dispatched++;
	}
	orchestrator->last_tick_ms = now_ms;
	orchestrator->ticks++;
	(void)orchestrator_event(
		orchestrator,
		PQCP_RUNTIME_EVENT_SERVICE_TICK,
		first_error == 0 ?
			PQCP_RUNTIME_EVENT_DEBUG :
			PQCP_RUNTIME_EVENT_WARNING,
		orchestrator->ticks, first_error,
		dispatched, "runtime", "tick");
	(void)k_mutex_unlock(&orchestrator->lock);
	return first_error;
}

int pqcp_runtime_orchestrator_stop(
	struct pqcp_runtime_orchestrator *orchestrator,
	uint64_t now_ms)
{
	int ret;

	if (orchestrator == NULL ||
	    !orchestrator->initialized || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (orchestrator->state ==
	    PQCP_RUNTIME_POLICY_STOPPED) {
		(void)k_mutex_unlock(&orchestrator->lock);
		return 0;
	}
	orchestrator->state =
		PQCP_RUNTIME_POLICY_DRAINING;
	ret = pqcp_runtime_executor_drain(
		&orchestrator->service->executor,
		K_SECONDS(30));
	if (ret == 0 && orchestrator->service->started) {
		ret = pqcp_runtime_service_stop(
			orchestrator->service, K_SECONDS(30));
	}
	orchestrator->state = ret == 0 ?
		PQCP_RUNTIME_POLICY_STOPPED :
		PQCP_RUNTIME_POLICY_FAILED;
	if (ret != 0) {
		orchestrator->failures++;
	}
	(void)orchestrator_event(
		orchestrator,
		PQCP_RUNTIME_EVENT_SERVICE_STOPPED,
		ret == 0 ?
			PQCP_RUNTIME_EVENT_INFO :
			PQCP_RUNTIME_EVENT_ERROR,
		orchestrator->epoch, ret, now_ms,
		"runtime", ret == 0 ? "stopped" :
				     "stop-failed");
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_runtime_orchestrator_checkpoint(
	struct pqcp_runtime_orchestrator *orchestrator,
	uint64_t now_ms,
	uint32_t flags,
	struct pqcp_runtime_checkpoint_header *header)
{
	enum pqcp_runtime_policy_state previous;
	int ret;

	if (orchestrator == NULL ||
	    !orchestrator->initialized || now_ms == 0U ||
	    header == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&orchestrator->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	previous = orchestrator->state;
	orchestrator->state =
		PQCP_RUNTIME_POLICY_CHECKPOINTING;
	ret = pqcp_runtime_checkpoint_write(
		orchestrator->checkpoints,
		orchestrator->service, now_ms,
		orchestrator->epoch, flags, header);
	orchestrator->state = ret == 0 ?
		previous : PQCP_RUNTIME_POLICY_DEGRADED;
	if (ret != 0) {
		orchestrator->failures++;
	}
	(void)orchestrator_event(
		orchestrator,
		PQCP_RUNTIME_EVENT_CHECKPOINT_WRITTEN,
		ret == 0 ?
			PQCP_RUNTIME_EVENT_NOTICE :
			PQCP_RUNTIME_EVENT_ERROR,
		header->generation, ret,
		header->payload_bytes,
		"runtime", ret == 0 ?
			"checkpoint-written" :
			"checkpoint-failed");
	(void)k_mutex_unlock(&orchestrator->lock);
	return ret;
}

int pqcp_runtime_orchestrator_audit(
	struct pqcp_runtime_orchestrator *orchestrator)
{
	int ret;

	if (orchestrator == NULL ||
	    !orchestrator->initialized ||
	    orchestrator->service == NULL ||
	    orchestrator->events == NULL ||
	    orchestrator->scheduler == NULL ||
	    orchestrator->checkpoints == NULL ||
	    orchestrator->commands == NULL ||
	    orchestrator->metrics == NULL ||
	    orchestrator->state <
		    PQCP_RUNTIME_POLICY_UNINITIALIZED ||
	    orchestrator->state >
		    PQCP_RUNTIME_POLICY_TERMINATED ||
	    orchestrator->epoch == 0U ||
	    orchestrator->started_at_ms == 0U ||
	    orchestrator->last_tick_ms <
		    orchestrator->started_at_ms) {
		return -EINVAL;
	}
	ret = pqcp_runtime_service_audit(
		orchestrator->service);
	if (ret == 0) {
		ret = pqcp_runtime_event_bus_verify(
			orchestrator->events);
	}
	if (ret == 0) {
		ret = pqcp_runtime_scheduler_audit(
			orchestrator->scheduler);
	}
	if (ret == 0) {
		ret = pqcp_runtime_checkpoint_store_audit(
			orchestrator->checkpoints);
	}
	if (ret == 0) {
		ret = pqcp_runtime_command_router_audit(
			orchestrator->commands);
	}
	if (ret == 0) {
		ret = pqcp_runtime_metrics_audit(
			orchestrator->metrics);
	}
	if (ret == 0) {
		ret = pqcp_runtime_policy_catalog_audit();
	}
	return ret;
}
