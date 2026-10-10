/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded sovereign network-intent authorization.
 */

#include <errno.h>
#include <string.h>

#include "sovereign_policy_internal.h"

static bool operation_valid(enum pqcp_sovereign_operation operation)
{
	return operation > PQCP_SOVEREIGN_OPERATION_NONE &&
	       operation < PQCP_SOVEREIGN_OPERATION_COUNT;
}

static bool intent_valid(const struct pqcp_sovereign_network_intent *intent)
{
	return intent != NULL &&
	       intent->schema_version == PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       pqcp_sovereign_policy_text_valid(
		       intent->tenant_id, sizeof(intent->tenant_id)) &&
	       pqcp_sovereign_policy_text_valid(
		       intent->source_namespace,
		       sizeof(intent->source_namespace)) &&
	       pqcp_sovereign_policy_text_valid(
		       intent->destination_namespace,
		       sizeof(intent->destination_namespace)) &&
	       pqcp_sovereign_policy_text_valid(
		       intent->protocol, sizeof(intent->protocol)) &&
	       intent->port_start <= intent->port_end &&
	       intent->operation_mask != 0U &&
	       intent->policy_epoch != 0U &&
	       intent->created_at_ms != 0U &&
	       (intent->expires_at_ms == 0U ||
		intent->expires_at_ms > intent->created_at_ms) &&
	       intent->maximum_connections != 0U &&
	       intent->active_connections <= intent->maximum_connections &&
	       (intent->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		intent->state == PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED ||
		intent->state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
		intent->state == PQCP_SOVEREIGN_LIFECYCLE_REVOKED);
}

static int intent_index(
	const struct pqcp_sovereign_network_intent_manager *manager,
	uint64_t intent_id)
{
	for (size_t index = 0U; index < manager->capacity; ++index) {
		if (manager->intents[index].occupied &&
		    manager->intents[index].intent_id == intent_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_intent_index(
	const struct pqcp_sovereign_network_intent_manager *manager)
{
	for (size_t index = 0U; index < manager->capacity; ++index) {
		if (!manager->intents[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_sovereign_network_intent_manager_init(
	struct pqcp_sovereign_network_intent_manager *manager,
	struct pqcp_sovereign_network_intent *intents,
	size_t capacity)
{
	if (manager == NULL || intents == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(intents, 0, capacity * sizeof(intents[0]));
	manager->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	manager->intents = intents;
	manager->capacity = capacity;
	manager->next_intent_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_network_intent_put(
	struct pqcp_sovereign_network_intent_manager *manager,
	const struct pqcp_sovereign_network_intent *intent,
	uint64_t now_ms)
{
	struct pqcp_sovereign_network_intent candidate;
	int index;

	if (manager == NULL || !manager->initialized ||
	    intent == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	candidate = *intent;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	if (candidate.created_at_ms == 0U) {
		candidate.created_at_ms = now_ms;
	}
	if (candidate.state == PQCP_SOVEREIGN_LIFECYCLE_EMPTY ||
	    candidate.state == PQCP_SOVEREIGN_LIFECYCLE_DRAFT) {
		candidate.state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	}
	if (!intent_valid(&candidate) ||
	    (candidate.expires_at_ms != 0U &&
	     candidate.expires_at_ms <= now_ms)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	if (candidate.intent_id == 0U) {
		candidate.intent_id =
			pqcp_sovereign_policy_next_id(
				&manager->next_intent_id);
		index = free_intent_index(manager);
	} else {
		index = intent_index(manager, candidate.intent_id);
		if (index < 0) {
			index = free_intent_index(manager);
		}
	}
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	for (size_t other = 0U; other < manager->capacity; ++other) {
		const struct pqcp_sovereign_network_intent *peer =
			&manager->intents[other];

		if ((int)other == index || !peer->occupied) {
			continue;
		}
		if (peer->intent_id == candidate.intent_id) {
			k_mutex_unlock(&manager->lock);
			return -EEXIST;
		}
	}
	candidate.occupied = true;
	manager->intents[index] = candidate;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_network_intent_authorize(
	struct pqcp_sovereign_network_intent_manager *manager,
	const char *tenant_id,
	const char *source_namespace,
	const char *destination_namespace,
	const char *protocol,
	uint16_t port,
	enum pqcp_sovereign_operation operation,
	uint32_t risk_score,
	bool mutually_authenticated,
	bool encrypted,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t *intent_id)
{
	struct pqcp_sovereign_network_intent *selected = NULL;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_policy_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_policy_text_valid(
		    source_namespace, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_policy_text_valid(
		    destination_namespace, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_policy_text_valid(
		    protocol, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !operation_valid(operation) || policy_epoch == 0U ||
	    now_ms == 0U || intent_id == NULL) {
		return -EINVAL;
	}
	*intent_id = 0U;
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U; index < manager->capacity; ++index) {
		struct pqcp_sovereign_network_intent *intent =
			&manager->intents[index];

		if (!intent->occupied ||
		    intent->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    intent->policy_epoch != policy_epoch ||
		    (intent->expires_at_ms != 0U &&
		     now_ms >= intent->expires_at_ms) ||
		    strcmp(intent->tenant_id, tenant_id) != 0 ||
		    strcmp(intent->source_namespace,
			   source_namespace) != 0 ||
		    strcmp(intent->destination_namespace,
			   destination_namespace) != 0 ||
		    strcmp(intent->protocol, protocol) != 0 ||
		    port < intent->port_start || port > intent->port_end ||
		    (intent->operation_mask &
		     PQCP_SOVEREIGN_BIT(operation)) == 0U ||
		    risk_score > intent->maximum_risk ||
		    (intent->require_mutual_auth &&
		     !mutually_authenticated) ||
		    (intent->require_encryption && !encrypted) ||
		    intent->active_connections >=
			    intent->maximum_connections) {
			continue;
		}
		if (selected == NULL ||
		    intent->port_end - intent->port_start <
			    selected->port_end - selected->port_start ||
		    (intent->port_end - intent->port_start ==
			     selected->port_end - selected->port_start &&
		     intent->intent_id < selected->intent_id)) {
			selected = intent;
		}
	}
	if (selected == NULL) {
		manager->deny_count =
			pqcp_sovereign_policy_add_u64(
				manager->deny_count, 1U);
		k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	selected->active_connections++;
	manager->allow_count =
		pqcp_sovereign_policy_add_u64(
			manager->allow_count, 1U);
	*intent_id = selected->intent_id;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_network_intent_release(
	struct pqcp_sovereign_network_intent_manager *manager,
	uint64_t intent_id)
{
	int index;

	if (manager == NULL || !manager->initialized ||
	    intent_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = intent_index(manager, intent_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	if (manager->intents[index].active_connections == 0U) {
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	manager->intents[index].active_connections--;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_network_intent_tick(
	struct pqcp_sovereign_network_intent_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t count = 0U;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U; index < manager->capacity; ++index) {
		struct pqcp_sovereign_network_intent *intent =
			&manager->intents[index];

		if (intent->occupied &&
		    intent->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
		    intent->expires_at_ms != 0U &&
		    now_ms >= intent->expires_at_ms) {
			intent->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
			count++;
		}
	}
	k_mutex_unlock(&manager->lock);
	if (expired_count != NULL) {
		*expired_count = count;
	}
	return 0;
}

int pqcp_sovereign_network_intent_manager_audit(
	struct pqcp_sovereign_network_intent_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    manager->intents == NULL || manager->capacity == 0U ||
	    manager->next_intent_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_network_intent *intent =
			&manager->intents[index];

		if (!intent->occupied) {
			continue;
		}
		if (!intent_valid(intent) || intent->intent_id == 0U) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->intents[other].occupied &&
			    manager->intents[other].intent_id ==
				    intent->intent_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
