/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Single-entry runtime service composition.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_service.h>

static bool storage_valid(
	const struct pqcp_runtime_service_storage *storage)
{
	return storage != NULL &&
	       storage->key_slots != NULL &&
	       storage->key_slot_count != 0U &&
	       storage->workspace_slots != NULL &&
	       storage->workspace_bytes != NULL &&
	       storage->workspace_slot_count != 0U &&
	       storage->workspace_bytes_per_slot != 0U &&
	       storage->queue != NULL &&
	       storage->queue_capacity != 0U &&
	       storage->sessions != NULL &&
	       storage->session_capacity != 0U &&
	       storage->profile_states != NULL &&
	       storage->profile_state_capacity != 0U &&
	       storage->audit_entries != NULL &&
	       storage->audit_capacity != 0U &&
	       storage->identities != NULL &&
	       storage->identity_capacity != 0U &&
	       storage->quotas != NULL &&
	       storage->quota_capacity != 0U;
}

int pqcp_runtime_service_init(
	struct pqcp_runtime_service *service,
	const struct pqcp_runtime_service_storage *storage,
	struct pqcp_adaptive_control_plane *adaptive_control,
	uint64_t now_ms)
{
	int ret;

	if (service == NULL || !storage_valid(storage) ||
	    adaptive_control == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	memset(service, 0, sizeof(*service));
	service->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	ret = pqcp_runtime_volatile_store_init(
		&service->key_store,
		&service->volatile_context,
		storage->key_slots,
		storage->key_slot_count);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_workspace_pool_init(
		&service->workspace_pool,
		storage->workspace_slots,
		storage->workspace_bytes,
		storage->workspace_slot_count,
		storage->workspace_bytes_per_slot);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_executor_init(
		&service->executor, &service->key_store,
		&service->workspace_pool, storage->queue,
		storage->queue_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_adaptive_calibration_init(
		&service->calibration);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_executor_bind_adaptive(
		&service->executor, adaptive_control,
		&service->calibration,
		storage->profile_states,
		storage->profile_state_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_session_manager_init(
		&service->sessions, storage->sessions,
		storage->session_capacity, &service->executor,
		adaptive_control);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_audit_init(
		&service->audit, storage->audit_entries,
		storage->audit_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_identity_store_init(
		&service->identities, storage->identities,
		storage->identity_capacity, &service->key_store);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_admission_init(
		&service->admission, storage->quotas,
		storage->quota_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_controller_init(
		&service->controller, &service->key_store,
		&service->executor, &service->sessions,
		&service->audit, now_ms);
	if (ret != 0) {
		return ret;
	}
	service->initialized = true;
	return pqcp_runtime_service_audit(service);
}

int pqcp_runtime_service_start(
	struct pqcp_runtime_service *service,
	k_thread_stack_t *worker_stack,
	size_t worker_stack_size,
	int priority)
{
	int ret;

	if (service == NULL || !service->initialized ||
	    service->started || worker_stack == NULL ||
	    worker_stack_size == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_executor_start(
		&service->executor, &service->worker_thread,
		worker_stack, worker_stack_size, priority);
	if (ret != 0) {
		return ret;
	}
	service->worker_stack = worker_stack;
	service->worker_stack_size = worker_stack_size;
	service->started = true;
	return 0;
}

int pqcp_runtime_service_stop(
	struct pqcp_runtime_service *service,
	k_timeout_t timeout)
{
	int ret = 0;

	if (service == NULL || !service->initialized) {
		return -EINVAL;
	}
	service->controller.accepting_sessions = false;
	if (service->started) {
		ret = pqcp_runtime_executor_drain(
			&service->executor, timeout);
		if (ret == 0) {
			ret = pqcp_runtime_executor_stop(
				&service->executor, timeout);
		}
		if (ret == 0) {
			service->started = false;
		}
	}
	return ret;
}

int pqcp_runtime_service_tick(
	struct pqcp_runtime_service *service,
	uint64_t now_ms)
{
	uint32_t expired_identities = 0U;
	int ret;

	if (service == NULL || !service->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_identity_expire(
		&service->identities, now_ms,
		&expired_identities);
	if (ret != 0) {
		service->controller.consecutive_failures++;
	}
	ret = pqcp_runtime_controller_tick(
		&service->controller, now_ms);
	if (ret != 0) {
		return ret;
	}
	return pqcp_runtime_service_audit(service);
}

int pqcp_runtime_service_audit(
	struct pqcp_runtime_service *service)
{
	if (service == NULL || !service->initialized ||
	    service->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    pqcp_runtime_controller_audit(
		    &service->controller) != 0 ||
	    pqcp_runtime_identity_store_audit(
		    &service->identities) != 0 ||
	    pqcp_runtime_admission_audit(
		    &service->admission) != 0 ||
	    pqcp_adaptive_calibration_validate(
		    &service->calibration,
		    &service->sessions.adaptive_control->registry) != 0) {
		return -EBADMSG;
	}
	return 0;
}
