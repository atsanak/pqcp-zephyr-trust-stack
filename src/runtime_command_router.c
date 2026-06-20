/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Idempotent command routing for the runtime service.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_operations.h>

#include "runtime_internal.h"

static bool command_kind_valid(
	enum pqcp_runtime_command_kind kind)
{
	return kind > PQCP_RUNTIME_COMMAND_NONE &&
	       kind < PQCP_RUNTIME_COMMAND_KIND_COUNT;
}

static int command_validate(
	const struct pqcp_runtime_command *command,
	uint64_t now_ms)
{
	if (command == NULL ||
	    command->schema_version !=
		    PQCP_RUNTIME_OPERATION_SCHEMA_VERSION ||
	    command->command_id == 0U ||
	    command->issued_at_ms == 0U ||
	    !command_kind_valid(command->kind) ||
	    !pqcp_runtime_internal_owner_valid(
		    command->owner) ||
	    !pqcp_runtime_internal_text_valid(
		    command->profile_id,
		    sizeof(command->profile_id)) ||
	    (command->payload == NULL &&
	     command->payload_length != 0U)) {
		return -EINVAL;
	}
	if (command->expires_at_ms != 0U &&
	    (command->expires_at_ms <=
		     command->issued_at_ms ||
	     command->expires_at_ms <= now_ms)) {
		return -ETIMEDOUT;
	}
	if (command->issued_at_ms > now_ms + 60000U) {
		return -ETIME;
	}
	return 0;
}

static enum pqcp_runtime_policy_state service_state(
	const struct pqcp_runtime_service *service)
{
	if (service == NULL || !service->initialized) {
		return PQCP_RUNTIME_POLICY_UNINITIALIZED;
	}
	if (service->controller.lockdown) {
		return PQCP_RUNTIME_POLICY_LOCKDOWN;
	}
	if (service->controller.health.status ==
	    PQCP_RUNTIME_HEALTH_DEGRADED) {
		return PQCP_RUNTIME_POLICY_DEGRADED;
	}
	if (service->controller.health.status ==
	    PQCP_RUNTIME_HEALTH_RECOVERY) {
		return PQCP_RUNTIME_POLICY_RECOVERING;
	}
	if (service->controller.health.status ==
	    PQCP_RUNTIME_HEALTH_LOCKDOWN) {
		return PQCP_RUNTIME_POLICY_LOCKDOWN;
	}
	if (service->started) {
		return PQCP_RUNTIME_POLICY_RUNNING;
	}
	return PQCP_RUNTIME_POLICY_STOPPED;
}

static const struct pqcp_runtime_command_cache_entry *cache_find(
	struct pqcp_runtime_command_router *router,
	uint64_t command_id)
{
	for (size_t index = 0U;
	     index < router->cache_capacity; ++index) {
		struct pqcp_runtime_command_cache_entry *entry =
			&router->cache[index];

		if (entry->occupied &&
		    entry->command_id == command_id) {
			return entry;
		}
	}
	return NULL;
}

static void cache_store(
	struct pqcp_runtime_command_router *router,
	const struct pqcp_runtime_command_result *result)
{
	struct pqcp_runtime_command_cache_entry *entry =
		&router->cache[router->next_cache_slot];

	memset(entry, 0, sizeof(*entry));
	entry->command_id = result->command_id;
	entry->result = *result;
	entry->occupied = true;
	router->next_cache_slot =
		(router->next_cache_slot + 1U) %
		router->cache_capacity;
}

static struct pqcp_runtime_command_handler *handler_find(
	struct pqcp_runtime_command_router *router,
	enum pqcp_runtime_command_kind kind)
{
	for (size_t index = 0U;
	     index < router->handler_capacity; ++index) {
		struct pqcp_runtime_command_handler *handler =
			&router->handlers[index];

		if (handler->registered &&
		    handler->kind == kind) {
			return handler;
		}
	}
	return NULL;
}

static int append_command_event(
	struct pqcp_runtime_command_router *router,
	const struct pqcp_runtime_command *command,
	enum pqcp_runtime_event_kind kind,
	int result,
	uint32_t reason_mask,
	const char *detail)
{
	struct pqcp_runtime_event event = {
		.schema_version =
			PQCP_RUNTIME_OPERATION_SCHEMA_VERSION,
		.timestamp_ms = pqcp_runtime_internal_now_ms(),
		.kind = kind,
		.severity = result == 0 ?
			PQCP_RUNTIME_EVENT_INFO :
			PQCP_RUNTIME_EVENT_WARNING,
		.subject_id = command->command_id,
		.result = result,
		.reason_mask = reason_mask,
		.value = (uint64_t)command->kind,
	};

	if (router->events == NULL) {
		return 0;
	}
	if (pqcp_runtime_internal_copy_text(
		    event.profile_id,
		    sizeof(event.profile_id),
		    command->profile_id) != 0 ||
	    pqcp_runtime_internal_copy_text(
		    event.detail, sizeof(event.detail),
		    detail) != 0) {
		return -EINVAL;
	}
	return pqcp_runtime_event_append(
		router->events, &event, NULL);
}

static int builtin_execute(
	struct pqcp_runtime_command_router *router,
	const struct pqcp_runtime_command *command,
	struct pqcp_runtime_command_result *result)
{
	switch (command->kind) {
	case PQCP_RUNTIME_COMMAND_START:
		if (router->service->started) {
			return 0;
		}
		return -ENOTSUP;
	case PQCP_RUNTIME_COMMAND_STOP:
		if (!router->service->started) {
			return 0;
		}
		return pqcp_runtime_service_stop(
			router->service, K_SECONDS(30));
	case PQCP_RUNTIME_COMMAND_TICK:
		return pqcp_runtime_service_tick(
			router->service,
			command->argument_u64[0] != 0U ?
				command->argument_u64[0] :
				pqcp_runtime_internal_now_ms());
	case PQCP_RUNTIME_COMMAND_SELFTEST:
		return pqcp_runtime_service_selftest(
			router->service,
			command->argument_u32[0],
			command->argument_u32[1],
			command->argument_u64[0] != 0U ?
				command->argument_u64[0] :
				pqcp_runtime_internal_now_ms());
	case PQCP_RUNTIME_COMMAND_AUDIT:
		return pqcp_runtime_service_audit(
			router->service);
	case PQCP_RUNTIME_COMMAND_LOCKDOWN:
		return pqcp_runtime_controller_lockdown(
			&router->service->controller,
			command->argument_u32[0],
			command->argument_u64[0] != 0U ?
				command->argument_u64[0] :
				pqcp_runtime_internal_now_ms());
	case PQCP_RUNTIME_COMMAND_RECOVER:
		return pqcp_runtime_controller_recover(
			&router->service->controller,
			command->argument_u64[0] != 0U ?
				command->argument_u64[0] :
				pqcp_runtime_internal_now_ms());
	case PQCP_RUNTIME_COMMAND_READ_HEALTH:
		result->output_u32[0] =
			(uint32_t)router->service->
				controller.health.status;
		result->output_u32[1] =
			router->service->controller.
				health.blocker_mask;
		result->output_u32[2] =
			router->service->controller.
				health.warning_mask;
		result->output_u64[0] =
			router->service->controller.
				last_tick_ms;
		return 0;
	case PQCP_RUNTIME_COMMAND_READ_SNAPSHOT:
		result->output_u32[0] =
			(uint32_t)router->service->
				sessions.active_count;
		result->output_u32[1] =
			router->service->key_store.active_count;
		result->output_u32[2] =
			(uint32_t)router->service->
				executor.queue_count;
		result->output_u64[0] =
			router->service->controller.
				last_tick_ms;
		return 0;
	default:
		return -ENOTSUP;
	}
}

int pqcp_runtime_command_router_init(
	struct pqcp_runtime_command_router *router,
	struct pqcp_runtime_service *service,
	struct pqcp_runtime_event_bus *events,
	struct pqcp_runtime_command_handler *handlers,
	size_t handler_capacity,
	struct pqcp_runtime_command_cache_entry *cache,
	size_t cache_capacity,
	pqcp_runtime_command_authorize_fn authorize,
	void *authorize_user_data)
{
	if (router == NULL || service == NULL ||
	    !service->initialized || handlers == NULL ||
	    handler_capacity == 0U || cache == NULL ||
	    cache_capacity == 0U) {
		return -EINVAL;
	}
	memset(handlers, 0,
	       handler_capacity * sizeof(*handlers));
	memset(cache, 0, cache_capacity * sizeof(*cache));
	memset(router, 0, sizeof(*router));
	router->service = service;
	router->events = events;
	router->handlers = handlers;
	router->handler_capacity = handler_capacity;
	router->cache = cache;
	router->cache_capacity = cache_capacity;
	router->authorize = authorize;
	router->authorize_user_data = authorize_user_data;
	k_mutex_init(&router->lock);
	router->initialized = true;
	return 0;
}

int pqcp_runtime_command_register(
	struct pqcp_runtime_command_router *router,
	enum pqcp_runtime_command_kind kind,
	pqcp_runtime_command_handler_fn callback,
	void *user_data)
{
	struct pqcp_runtime_command_handler *empty = NULL;
	int ret;

	if (router == NULL || !router->initialized ||
	    !command_kind_valid(kind) || callback == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&router->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < router->handler_capacity; ++index) {
		struct pqcp_runtime_command_handler *handler =
			&router->handlers[index];

		if (handler->registered &&
		    handler->kind == kind) {
			(void)k_mutex_unlock(&router->lock);
			return -EALREADY;
		}
		if (empty == NULL && !handler->registered) {
			empty = handler;
		}
	}
	if (empty == NULL) {
		(void)k_mutex_unlock(&router->lock);
		return -ENOSPC;
	}
	empty->kind = kind;
	empty->callback = callback;
	empty->user_data = user_data;
	empty->registered = true;
	(void)k_mutex_unlock(&router->lock);
	return 0;
}

int pqcp_runtime_command_execute(
	struct pqcp_runtime_command_router *router,
	const struct pqcp_runtime_command *command,
	struct pqcp_runtime_command_result *result)
{
	const struct pqcp_runtime_command_cache_entry *cached;
	struct pqcp_runtime_command_handler *handler;
	struct pqcp_runtime_policy_decision policy;
	uint64_t now_ms;
	int ret;

	if (router == NULL || !router->initialized ||
	    result == NULL) {
		return -EINVAL;
	}
	now_ms = pqcp_runtime_internal_now_ms();
	ret = command_validate(command, now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&router->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	cached = cache_find(router, command->command_id);
	if (cached != NULL) {
		*result = cached->result;
		result->replayed = true;
		(void)k_mutex_unlock(&router->lock);
		return result->result;
	}
	ret = pqcp_runtime_policy_lookup(
		service_state(router->service),
		command->kind, &policy);
	if (ret != 0) {
		(void)k_mutex_unlock(&router->lock);
		return ret;
	}
	if (policy.action == PQCP_RUNTIME_POLICY_DENY) {
		memset(result, 0, sizeof(*result));
		result->schema_version =
			PQCP_RUNTIME_OPERATION_SCHEMA_VERSION;
		result->command_id = command->command_id;
		result->kind = command->kind;
		result->completed_at_ms = now_ms;
		result->result = policy.error;
		result->reason_mask = policy.flags;
		cache_store(router, result);
		(void)append_command_event(
			router, command,
			PQCP_RUNTIME_EVENT_COMMAND_REJECTED,
			policy.error, policy.flags,
			"policy-denied");
		(void)k_mutex_unlock(&router->lock);
		return policy.error;
	}
	if (router->authorize != NULL) {
		ret = router->authorize(
			command, router->authorize_user_data);
		if (ret != 0) {
			memset(result, 0, sizeof(*result));
			result->schema_version =
				PQCP_RUNTIME_OPERATION_SCHEMA_VERSION;
			result->command_id = command->command_id;
			result->kind = command->kind;
			result->completed_at_ms = now_ms;
			result->result = ret;
			cache_store(router, result);
			(void)append_command_event(
				router, command,
				PQCP_RUNTIME_EVENT_COMMAND_REJECTED,
				ret, 0U, "authorization-denied");
			(void)k_mutex_unlock(&router->lock);
			return ret;
		}
	}
	handler = handler_find(router, command->kind);
	(void)append_command_event(
		router, command,
		PQCP_RUNTIME_EVENT_COMMAND_ACCEPTED,
		0, policy.flags, "accepted");
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_RUNTIME_OPERATION_SCHEMA_VERSION;
	result->command_id = command->command_id;
	result->kind = command->kind;
	if (handler != NULL) {
		ret = handler->callback(
			router->service, command, result,
			handler->user_data);
	} else {
		ret = builtin_execute(router, command, result);
	}
	result->completed_at_ms =
		pqcp_runtime_internal_now_ms();
	result->result = ret;
	result->reason_mask |= policy.flags;
	cache_store(router, result);
	(void)append_command_event(
		router, command,
		PQCP_RUNTIME_EVENT_COMMAND_COMPLETED,
		ret, result->reason_mask,
		ret == 0 ? "completed" : "failed");
	(void)k_mutex_unlock(&router->lock);
	return ret;
}

int pqcp_runtime_command_router_audit(
	struct pqcp_runtime_command_router *router)
{
	int ret;

	if (router == NULL || !router->initialized ||
	    router->service == NULL ||
	    !router->service->initialized ||
	    router->handlers == NULL ||
	    router->handler_capacity == 0U ||
	    router->cache == NULL ||
	    router->cache_capacity == 0U ||
	    router->next_cache_slot >=
		    router->cache_capacity) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&router->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t left = 0U;
	     left < router->handler_capacity; ++left) {
		const struct pqcp_runtime_command_handler *handler =
			&router->handlers[left];

		if (!handler->registered) {
			continue;
		}
		if (!command_kind_valid(handler->kind) ||
		    handler->callback == NULL) {
			ret = -EBADMSG;
			break;
		}
		for (size_t right = left + 1U;
		     right < router->handler_capacity; ++right) {
			if (router->handlers[right].registered &&
			    router->handlers[right].kind ==
				    handler->kind) {
				ret = -EBADMSG;
				break;
			}
		}
		if (ret != 0) {
			break;
		}
	}
	for (size_t left = 0U;
	     ret == 0 && left < router->cache_capacity; ++left) {
		const struct pqcp_runtime_command_cache_entry *entry =
			&router->cache[left];

		if (!entry->occupied) {
			continue;
		}
		if (entry->command_id == 0U ||
		    entry->result.command_id !=
			    entry->command_id ||
		    entry->result.schema_version !=
			    PQCP_RUNTIME_OPERATION_SCHEMA_VERSION) {
			ret = -EBADMSG;
			break;
		}
		for (size_t right = left + 1U;
		     right < router->cache_capacity; ++right) {
			if (router->cache[right].occupied &&
			    router->cache[right].command_id ==
				    entry->command_id) {
				ret = -EBADMSG;
				break;
			}
		}
	}
	(void)k_mutex_unlock(&router->lock);
	return ret;
}
