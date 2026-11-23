/*
 * SPDX-License-Identifier: MIT
 *
 * Multi-action containment tracking with explicit release.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int containment_index(
	const struct pqcp_edge_containment_manager *manager,
	uint64_t containment_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->records[index].occupied &&
		    manager->records[index].containment_id ==
			    containment_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_containment_index(
	const struct pqcp_edge_containment_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->records[index].occupied ||
		    !manager->records[index].active) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

int pqcp_edge_containment_manager_init(
	struct pqcp_edge_containment_manager *manager,
	struct pqcp_edge_containment *records,
	size_t capacity)
{
	if (manager == NULL || records == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(records, 0, capacity * sizeof(*records));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->records = records;
	manager->capacity = capacity;
	manager->next_containment_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_containment_apply(
	struct pqcp_edge_containment_manager *manager,
	uint64_t incident_id,
	const char *subject_id,
	uint32_t action_mask,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_containment **containment)
{
	struct pqcp_edge_containment candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    incident_id == 0U ||
	    !pqcp_edge_internal_text_valid(
		    subject_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    action_mask == 0U || expires_at_ms <= now_ms ||
	    containment == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = free_containment_index(manager);
	if (index < 0) {
		*containment = NULL;
		k_mutex_unlock(&manager->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.containment_id =
		pqcp_edge_internal_next_identifier(
			&manager->next_containment_id);
	candidate.incident_id = incident_id;
	ret = pqcp_edge_internal_copy_text(
		candidate.subject_id,
		sizeof(candidate.subject_id), subject_id);
	candidate.action_mask = action_mask;
	candidate.applied_at_ms = now_ms;
	candidate.expires_at_ms = expires_at_ms;
	candidate.active = true;
	candidate.occupied = true;
	if (ret == 0) {
		manager->records[index] = candidate;
		*containment = &manager->records[index];
		++manager->applied_count;
	} else {
		*containment = NULL;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_containment_record_action(
	struct pqcp_edge_containment_manager *manager,
	uint64_t containment_id,
	uint32_t action,
	int result)
{
	struct pqcp_edge_containment *containment;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    containment_id == 0U || action == 0U ||
	    (action & (action - 1U)) != 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = containment_index(manager, containment_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	containment = &manager->records[index];
	if (!containment->active ||
	    (containment->action_mask & action) == 0U) {
		ret = -EACCES;
	} else if (result == 0) {
		containment->applied_mask |= action;
		containment->failed_mask &= ~action;
	} else {
		containment->failed_mask |= action;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_containment_release(
	struct pqcp_edge_containment_manager *manager,
	uint64_t containment_id,
	uint64_t now_ms)
{
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    containment_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = containment_index(manager, containment_id);
	if (index < 0) {
		ret = index;
	} else if (!manager->records[index].active) {
		ret = -EALREADY;
	} else {
		manager->records[index].active = false;
		manager->records[index].released_at_ms = now_ms;
		++manager->released_count;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_containment_tick(
	struct pqcp_edge_containment_manager *manager,
	uint64_t now_ms,
	uint32_t *released_count)
{
	uint32_t released = 0U;

	if (manager == NULL || !manager->initialized ||
	    released_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_edge_containment *containment =
			&manager->records[index];

		if (containment->occupied &&
		    containment->active &&
		    containment->expires_at_ms <= now_ms) {
			containment->active = false;
			containment->released_at_ms = now_ms;
			++released;
		}
	}
	manager->released_count =
		pqcp_edge_internal_saturating_add_u64(
			manager->released_count, released);
	k_mutex_unlock(&manager->lock);
	*released_count = released;
	return 0;
}

int pqcp_edge_containment_manager_audit(
	struct pqcp_edge_containment_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->records == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_containment *containment =
			&manager->records[index];

		if (!containment->occupied) {
			continue;
		}
		if (containment->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    containment->containment_id == 0U ||
		    containment->incident_id == 0U ||
		    !pqcp_edge_internal_text_valid(
			    containment->subject_id,
			    sizeof(containment->subject_id)) ||
		    containment->action_mask == 0U ||
		    (containment->applied_mask &
		     ~containment->action_mask) != 0U ||
		    (containment->failed_mask &
		     ~containment->action_mask) != 0U ||
		    containment->expires_at_ms <=
			    containment->applied_at_ms ||
		    (!containment->active &&
		     containment->released_at_ms == 0U)) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
