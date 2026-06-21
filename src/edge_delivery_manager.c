/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Delivery attempt lifecycle and bounded retry scheduling.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int delivery_index(
	const struct pqcp_edge_delivery_manager *manager,
	uint64_t delivery_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->deliveries[index].occupied &&
		    manager->deliveries[index].delivery_id ==
			    delivery_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_delivery_index(
	const struct pqcp_edge_delivery_manager *manager)
{
	int recyclable = -1;
	uint64_t oldest = UINT64_MAX;

	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_edge_delivery *delivery =
			&manager->deliveries[index];

		if (!delivery->occupied) {
			return (int)index;
		}
		if ((delivery->state ==
			     PQCP_EDGE_MESSAGE_ACKNOWLEDGED ||
		     delivery->state ==
			     PQCP_EDGE_MESSAGE_DEAD_LETTER ||
		     delivery->state ==
			     PQCP_EDGE_MESSAGE_EXPIRED) &&
		    delivery->dispatched_at_ms < oldest) {
			oldest = delivery->dispatched_at_ms;
			recyclable = (int)index;
		}
	}
	return recyclable >= 0 ? recyclable : -ENOSPC;
}

int pqcp_edge_delivery_manager_init(
	struct pqcp_edge_delivery_manager *manager,
	struct pqcp_edge_delivery *deliveries,
	size_t capacity)
{
	if (manager == NULL || deliveries == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(deliveries, 0,
	       capacity * sizeof(*deliveries));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->deliveries = deliveries;
	manager->capacity = capacity;
	manager->next_delivery_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_delivery_dispatch(
	struct pqcp_edge_delivery_manager *manager,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES],
	uint64_t subscription_id,
	uint64_t now_ms,
	uint64_t deadline_ms,
	uint32_t maximum_attempts,
	struct pqcp_edge_delivery **delivery)
{
	struct pqcp_edge_delivery candidate;
	int index;

	if (manager == NULL || !manager->initialized ||
	    message_id == NULL ||
	    pqcp_edge_internal_all_zero(
		    message_id,
		    PQCP_EDGE_MESSAGE_ID_BYTES) ||
	    subscription_id == 0U ||
	    deadline_ms <= now_ms ||
	    maximum_attempts == 0U || delivery == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = free_delivery_index(manager);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		*delivery = NULL;
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.delivery_id =
		pqcp_edge_internal_next_identifier(
			&manager->next_delivery_id);
	memcpy(candidate.message_id, message_id,
	       sizeof(candidate.message_id));
	candidate.subscription_id = subscription_id;
	candidate.dispatched_at_ms = now_ms;
	candidate.deadline_ms = deadline_ms;
	candidate.attempts = 1U;
	candidate.maximum_attempts = maximum_attempts;
	candidate.state = PQCP_EDGE_MESSAGE_IN_FLIGHT;
	candidate.occupied = true;
	manager->deliveries[index] = candidate;
	*delivery = &manager->deliveries[index];
	++manager->dispatch_count;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_delivery_complete(
	struct pqcp_edge_delivery_manager *manager,
	uint64_t delivery_id,
	int result,
	uint64_t now_ms)
{
	struct pqcp_edge_delivery *delivery;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    delivery_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = delivery_index(manager, delivery_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	delivery = &manager->deliveries[index];
	if (delivery->state ==
		    PQCP_EDGE_MESSAGE_ACKNOWLEDGED ||
	    delivery->state ==
		    PQCP_EDGE_MESSAGE_DEAD_LETTER ||
	    delivery->state ==
		    PQCP_EDGE_MESSAGE_EXPIRED) {
		ret = -EALREADY;
		goto out;
	}
	delivery->result = result;
	if (result == 0) {
		delivery->state =
			PQCP_EDGE_MESSAGE_ACKNOWLEDGED;
		++manager->success_count;
	} else if (delivery->attempts >=
		   delivery->maximum_attempts ||
		   now_ms >= delivery->deadline_ms) {
		delivery->state =
			now_ms >= delivery->deadline_ms ?
				PQCP_EDGE_MESSAGE_EXPIRED :
				PQCP_EDGE_MESSAGE_DEAD_LETTER;
		++manager->failure_count;
	} else {
		delivery->state =
			PQCP_EDGE_MESSAGE_RETRY_WAIT;
		delivery->retry_at_ms =
			pqcp_edge_internal_saturating_add_u64(
				now_ms,
				pqcp_edge_internal_backoff(
					100U, 30000U,
					delivery->attempts));
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_delivery_retry(
	struct pqcp_edge_delivery_manager *manager,
	uint64_t delivery_id,
	uint64_t retry_at_ms)
{
	struct pqcp_edge_delivery *delivery;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    delivery_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = delivery_index(manager, delivery_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	delivery = &manager->deliveries[index];
	if (delivery->state !=
	    PQCP_EDGE_MESSAGE_RETRY_WAIT) {
		ret = -EALREADY;
	} else if (retry_at_ms >= delivery->deadline_ms) {
		delivery->state =
			PQCP_EDGE_MESSAGE_EXPIRED;
		++manager->failure_count;
		ret = -ETIMEDOUT;
	} else if (delivery->attempts >=
		   delivery->maximum_attempts) {
		delivery->state =
			PQCP_EDGE_MESSAGE_DEAD_LETTER;
		++manager->failure_count;
		ret = -EOVERFLOW;
	} else {
		delivery->retry_at_ms = retry_at_ms;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_delivery_tick(
	struct pqcp_edge_delivery_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (manager == NULL || !manager->initialized ||
	    changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_edge_delivery *delivery =
			&manager->deliveries[index];

		if (!delivery->occupied ||
		    delivery->state ==
			    PQCP_EDGE_MESSAGE_ACKNOWLEDGED ||
		    delivery->state ==
			    PQCP_EDGE_MESSAGE_DEAD_LETTER ||
		    delivery->state ==
			    PQCP_EDGE_MESSAGE_EXPIRED) {
			continue;
		}
		if (now_ms >= delivery->deadline_ms) {
			delivery->state =
				PQCP_EDGE_MESSAGE_EXPIRED;
			++manager->failure_count;
			++changed;
		} else if (delivery->state ==
			   PQCP_EDGE_MESSAGE_RETRY_WAIT &&
			   now_ms >= delivery->retry_at_ms) {
			delivery->state =
				PQCP_EDGE_MESSAGE_IN_FLIGHT;
			delivery->attempts =
				pqcp_edge_internal_saturating_add_u32(
					delivery->attempts,
					1U);
			++changed;
		}
	}
	k_mutex_unlock(&manager->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_edge_delivery_manager_audit(
	struct pqcp_edge_delivery_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->deliveries == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_delivery *delivery =
			&manager->deliveries[index];

		if (!delivery->occupied) {
			continue;
		}
		if (delivery->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    delivery->delivery_id == 0U ||
		    delivery->subscription_id == 0U ||
		    pqcp_edge_internal_all_zero(
			    delivery->message_id,
			    sizeof(delivery->message_id)) ||
		    delivery->deadline_ms <=
			    delivery->dispatched_at_ms ||
		    delivery->maximum_attempts == 0U ||
		    delivery->attempts >
			    delivery->maximum_attempts ||
		    delivery->state <=
			    PQCP_EDGE_MESSAGE_EMPTY ||
		    delivery->state >
			    PQCP_EDGE_MESSAGE_CANCELLED) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->deliveries[other].occupied &&
			    manager->deliveries[other].
				    delivery_id ==
				    delivery->delivery_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
