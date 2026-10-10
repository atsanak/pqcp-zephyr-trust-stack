/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Capability-scoped topics and durable subscriptions.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int topic_index(
	const struct pqcp_edge_topic_registry *registry,
	const char *topic)
{
	for (size_t index = 0U;
	     index < registry->topic_capacity; ++index) {
		if (registry->topics[index].occupied &&
		    strcmp(
			    registry->topics[index].topic,
			    topic) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int subscription_index(
	const struct pqcp_edge_topic_registry *registry,
	uint64_t subscription_id)
{
	for (size_t index = 0U;
	     index < registry->subscription_capacity; ++index) {
		if (registry->subscriptions[index].occupied &&
		    registry->subscriptions[index].
			    subscription_id == subscription_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int existing_subscription_index(
	const struct pqcp_edge_topic_registry *registry,
	const char *topic,
	const char *principal_id)
{
	for (size_t index = 0U;
	     index < registry->subscription_capacity; ++index) {
		const struct pqcp_edge_subscription *subscription =
			&registry->subscriptions[index];

		if (subscription->occupied &&
		    strcmp(subscription->topic, topic) == 0 &&
		    strcmp(subscription->principal_id,
			   principal_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_topic_index(
	const struct pqcp_edge_topic_registry *registry)
{
	for (size_t index = 0U;
	     index < registry->topic_capacity; ++index) {
		if (!registry->topics[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int free_subscription_index(
	const struct pqcp_edge_topic_registry *registry)
{
	for (size_t index = 0U;
	     index < registry->subscription_capacity; ++index) {
		if (!registry->subscriptions[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool topic_valid(const struct pqcp_edge_topic *topic)
{
	return topic != NULL &&
	       pqcp_edge_internal_text_valid(
		       topic->topic, sizeof(topic->topic)) &&
	       pqcp_edge_internal_text_valid(
		       topic->owner_id,
		       sizeof(topic->owner_id)) &&
	       topic->maximum_payload != 0U &&
	       topic->maximum_payload <=
		       PQCP_EDGE_MESSAGE_PAYLOAD_MAX_BYTES &&
	       topic->maximum_subscribers != 0U;
}

int pqcp_edge_topic_registry_init(
	struct pqcp_edge_topic_registry *registry,
	struct pqcp_edge_topic *topics,
	size_t topic_capacity,
	struct pqcp_edge_subscription *subscriptions,
	size_t subscription_capacity)
{
	if (registry == NULL || topics == NULL ||
	    subscriptions == NULL || topic_capacity == 0U ||
	    subscription_capacity == 0U) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(topics, 0, topic_capacity * sizeof(*topics));
	memset(subscriptions, 0,
	       subscription_capacity *
		       sizeof(*subscriptions));
	registry->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	registry->topics = topics;
	registry->topic_capacity = topic_capacity;
	registry->subscriptions = subscriptions;
	registry->subscription_capacity =
		subscription_capacity;
	registry->next_topic_generation = 1U;
	registry->next_subscription_id = 1U;
	k_mutex_init(&registry->lock);
	registry->initialized = true;
	return 0;
}

int pqcp_edge_topic_create(
	struct pqcp_edge_topic_registry *registry,
	const struct pqcp_edge_topic *topic)
{
	struct pqcp_edge_topic candidate;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    !topic_valid(topic)) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = topic_index(registry, topic->topic);
	if (index >= 0) {
		struct pqcp_edge_topic *current =
			&registry->topics[index];

		if (strcmp(
			    current->owner_id,
			    topic->owner_id) != 0 ||
		    topic->maximum_subscribers <
			    current->active_subscribers) {
			ret = -EACCES;
			goto out;
		}
		candidate = *topic;
		candidate.schema_version =
			PQCP_EDGE_SCHEMA_VERSION;
		candidate.generation =
			current->generation;
		candidate.active_subscribers =
			current->active_subscribers;
		candidate.published_count =
			current->published_count;
		candidate.delivered_count =
			current->delivered_count;
		candidate.occupied = true;
		*current = candidate;
	} else if (index == -ENOENT) {
		index = free_topic_index(registry);
		if (index < 0) {
			ret = index;
			goto out;
		}
		candidate = *topic;
		candidate.schema_version =
			PQCP_EDGE_SCHEMA_VERSION;
		candidate.generation =
			pqcp_edge_internal_next_generation(
				&registry->
					next_topic_generation);
		candidate.active_subscribers = 0U;
		candidate.published_count = 0U;
		candidate.delivered_count = 0U;
		candidate.occupied = true;
		registry->topics[index] = candidate;
	} else {
		ret = index;
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_topic_remove(
	struct pqcp_edge_topic_registry *registry,
	const char *topic)
{
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    topic == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = topic_index(registry, topic);
	if (index < 0) {
		ret = index;
		goto out;
	}
	if (registry->topics[index].active_subscribers !=
	    0U) {
		ret = -EBUSY;
		goto out;
	}
	memset(&registry->topics[index], 0,
	       sizeof(registry->topics[index]));
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_topic_authorize_publish(
	struct pqcp_edge_topic_registry *registry,
	const char *topic,
	const struct pqcp_edge_principal *principal,
	size_t payload_length)
{
	struct pqcp_edge_topic *entry;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    topic == NULL || principal == NULL ||
	    payload_length == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = topic_index(registry, topic);
	if (index < 0) {
		ret = index;
		goto out;
	}
	entry = &registry->topics[index];
	if (principal->state !=
		    PQCP_EDGE_PRINCIPAL_ACTIVE ||
	    (principal->capabilities &
	     entry->publish_capabilities) !=
		    entry->publish_capabilities) {
		ret = -EACCES;
	} else if (payload_length >
		   entry->maximum_payload) {
		ret = -E2BIG;
	} else {
		entry->published_count =
			pqcp_edge_internal_saturating_add_u64(
				entry->published_count, 1U);
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_topic_subscribe(
	struct pqcp_edge_topic_registry *registry,
	const char *topic,
	const struct pqcp_edge_principal *principal,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	uint32_t maximum_inflight,
	struct pqcp_edge_subscription **subscription)
{
	struct pqcp_edge_subscription candidate;
	struct pqcp_edge_topic *entry;
	int topic_slot;
	int slot;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    topic == NULL || principal == NULL ||
	    subscription == NULL || lifetime_ms == 0U ||
	    maximum_inflight == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	topic_slot = topic_index(registry, topic);
	if (topic_slot < 0) {
		ret = topic_slot;
		goto out;
	}
	entry = &registry->topics[topic_slot];
	if (principal->state !=
		    PQCP_EDGE_PRINCIPAL_ACTIVE ||
	    (principal->capabilities &
	     entry->subscribe_capabilities) !=
		    entry->subscribe_capabilities) {
		ret = -EACCES;
		goto out;
	}
	slot = existing_subscription_index(
		registry, topic, principal->principal_id);
	if (slot >= 0) {
		if (registry->subscriptions[slot].
		    expires_at_ms > now_ms) {
			*subscription =
				&registry->subscriptions[slot];
			ret = -EALREADY;
			goto out;
		}
	} else if (slot != -ENOENT) {
		ret = slot;
		goto out;
	}
	if (entry->active_subscribers >=
	    entry->maximum_subscribers) {
		ret = -EDQUOT;
		goto out;
	}
	if (slot < 0) {
		slot = free_subscription_index(registry);
	}
	if (slot < 0) {
		ret = slot;
		goto out;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.subscription_id =
		pqcp_edge_internal_next_identifier(
			&registry->next_subscription_id);
	ret = pqcp_edge_internal_copy_text(
		candidate.topic, sizeof(candidate.topic),
		topic);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.principal_id,
			sizeof(candidate.principal_id),
			principal->principal_id);
	}
	if (ret != 0) {
		goto out;
	}
	candidate.created_at_ms = now_ms;
	candidate.expires_at_ms =
		pqcp_edge_internal_saturating_add_u64(
			now_ms, lifetime_ms);
	candidate.maximum_inflight = maximum_inflight;
	candidate.occupied = true;
	registry->subscriptions[slot] = candidate;
	++entry->active_subscribers;
	*subscription = &registry->subscriptions[slot];
out:
	k_mutex_unlock(&registry->lock);
	if (ret != 0 && ret != -EALREADY) {
		*subscription = NULL;
	}
	return ret;
}

int pqcp_edge_topic_unsubscribe(
	struct pqcp_edge_topic_registry *registry,
	uint64_t subscription_id)
{
	struct pqcp_edge_subscription *subscription;
	int topic_slot;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    subscription_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = subscription_index(
		registry, subscription_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	subscription = &registry->subscriptions[index];
	topic_slot = topic_index(
		registry, subscription->topic);
	if (topic_slot >= 0 &&
	    registry->topics[topic_slot].
		    active_subscribers != 0U) {
		--registry->topics[topic_slot].
			active_subscribers;
	}
	memset(subscription, 0, sizeof(*subscription));
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_topic_acknowledge(
	struct pqcp_edge_topic_registry *registry,
	uint64_t subscription_id,
	uint64_t sequence)
{
	struct pqcp_edge_subscription *subscription;
	int topic_slot;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    subscription_id == 0U || sequence == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = subscription_index(
		registry, subscription_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	subscription = &registry->subscriptions[index];
	if (sequence <=
	    subscription->last_acknowledged_sequence) {
		ret = -ESTALE;
		goto out;
	}
	subscription->last_acknowledged_sequence =
		sequence;
	if (subscription->inflight != 0U) {
		--subscription->inflight;
	}
	topic_slot = topic_index(
		registry, subscription->topic);
	if (topic_slot >= 0) {
		registry->topics[topic_slot].
			delivered_count =
			pqcp_edge_internal_saturating_add_u64(
				registry->topics[topic_slot].
					delivered_count,
				1U);
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_topic_tick(
	struct pqcp_edge_topic_registry *registry,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (registry == NULL || !registry->initialized ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < registry->subscription_capacity; ++index) {
		struct pqcp_edge_subscription *subscription =
			&registry->subscriptions[index];
		int topic_slot;

		if (!subscription->occupied ||
		    subscription->expires_at_ms > now_ms) {
			continue;
		}
		topic_slot = topic_index(
			registry, subscription->topic);
		if (topic_slot >= 0 &&
		    registry->topics[topic_slot].
			    active_subscribers != 0U) {
			--registry->topics[topic_slot].
				active_subscribers;
		}
		memset(subscription, 0,
		       sizeof(*subscription));
		++expired;
	}
	k_mutex_unlock(&registry->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_topic_registry_audit(
	struct pqcp_edge_topic_registry *registry)
{
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    registry->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    registry->topics == NULL ||
	    registry->subscriptions == NULL ||
	    registry->topic_capacity == 0U ||
	    registry->subscription_capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < registry->topic_capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_topic *topic =
			&registry->topics[index];
		uint32_t subscribers = 0U;

		if (!topic->occupied) {
			continue;
		}
		if (!topic_valid(topic) ||
		    topic->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    topic->generation == 0U ||
		    topic->active_subscribers >
			    topic->maximum_subscribers) {
			ret = -EBADMSG;
			break;
		}
		for (size_t sub = 0U;
		     sub < registry->subscription_capacity;
		     ++sub) {
			if (registry->subscriptions[sub].occupied &&
			    strcmp(
				    registry->subscriptions[sub].topic,
				    topic->topic) == 0) {
				++subscribers;
			}
		}
		if (subscribers != topic->active_subscribers) {
			ret = -EBADMSG;
			break;
		}
	}
	for (size_t index = 0U;
	     index < registry->subscription_capacity &&
		     ret == 0;
	     ++index) {
		const struct pqcp_edge_subscription *subscription =
			&registry->subscriptions[index];

		if (!subscription->occupied) {
			continue;
		}
		if (subscription->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    subscription->subscription_id == 0U ||
		    !pqcp_edge_internal_text_valid(
			    subscription->topic,
			    sizeof(subscription->topic)) ||
		    !pqcp_edge_internal_text_valid(
			    subscription->principal_id,
			    sizeof(subscription->principal_id)) ||
		    subscription->maximum_inflight == 0U ||
		    subscription->inflight >
			    subscription->maximum_inflight ||
		    topic_index(
			    registry,
			    subscription->topic) < 0) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}
