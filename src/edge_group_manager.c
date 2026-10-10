/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Epoch-bound secure multicast group membership.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int group_index(
	const struct pqcp_edge_group_manager *manager,
	const char *group_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->groups[index].occupied &&
		    strcmp(manager->groups[index].group_id,
			   group_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_group_index(
	const struct pqcp_edge_group_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->groups[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int member_index(
	const struct pqcp_edge_group *group,
	const char *principal_id)
{
	for (size_t index = 0U;
	     index < PQCP_EDGE_MAX_GROUP_MEMBERS; ++index) {
		if (group->members[index].active &&
		    strcmp(
			    group->members[index].principal_id,
			    principal_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_member_index(
	const struct pqcp_edge_group *group)
{
	for (size_t index = 0U;
	     index < PQCP_EDGE_MAX_GROUP_MEMBERS; ++index) {
		if (!group->members[index].active) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int key_digest(
	const uint8_t key_material[PQCP_EDGE_KEY_BYTES],
	const char *group_id,
	uint64_t epoch,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[8];
	const uint8_t *parts[3];
	size_t lengths[3];

	pqcp_edge_internal_write_u64(numeric, epoch);
	parts[0] = key_material;
	lengths[0] = PQCP_EDGE_KEY_BYTES;
	parts[1] = (const uint8_t *)group_id;
	lengths[1] = strlen(group_id);
	parts[2] = numeric;
	lengths[2] = sizeof(numeric);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 3U, output);
}

static int add_owner_member(
	struct pqcp_edge_group *group,
	const char *owner_id)
{
	struct pqcp_edge_group_member *member =
		&group->members[0];
	int ret;

	memset(member, 0, sizeof(*member));
	ret = pqcp_edge_internal_copy_text(
		member->principal_id,
		sizeof(member->principal_id), owner_id);
	if (ret != 0) {
		return ret;
	}
	member->joined_epoch = group->epoch;
	member->capabilities = UINT64_MAX;
	member->active = true;
	group->member_count = 1U;
	return 0;
}

int pqcp_edge_group_manager_init(
	struct pqcp_edge_group_manager *manager,
	struct pqcp_edge_group *groups,
	size_t capacity)
{
	if (manager == NULL || groups == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(groups, 0, capacity * sizeof(*groups));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->groups = groups;
	manager->capacity = capacity;
	manager->next_generation = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_group_create(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const char *owner_id,
	const uint8_t key_material[PQCP_EDGE_KEY_BYTES],
	uint64_t now_ms)
{
	struct pqcp_edge_group candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_edge_internal_text_valid(
		    group_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    owner_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    key_material == NULL ||
	    pqcp_edge_internal_all_zero(
		    key_material, PQCP_EDGE_KEY_BYTES)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	if (group_index(manager, group_id) >= 0) {
		k_mutex_unlock(&manager->lock);
		return -EEXIST;
	}
	index = free_group_index(manager);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.generation =
		pqcp_edge_internal_next_generation(
			&manager->next_generation);
	ret = pqcp_edge_internal_copy_text(
		candidate.group_id,
		sizeof(candidate.group_id), group_id);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.owner_id,
			sizeof(candidate.owner_id), owner_id);
	}
	candidate.epoch = 1U;
	candidate.created_at_ms = now_ms;
	candidate.rotated_at_ms = now_ms;
	if (ret == 0) {
		ret = key_digest(
			key_material, group_id,
			candidate.epoch,
			candidate.key_digest);
	}
	if (ret == 0) {
		ret = add_owner_member(
			&candidate, owner_id);
	}
	if (ret == 0) {
		candidate.occupied = true;
		manager->groups[index] = candidate;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_group_add_member(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const char *principal_id,
	uint64_t capabilities,
	uint64_t now_ms)
{
	struct pqcp_edge_group *group;
	struct pqcp_edge_group_member *member;
	int group_slot;
	int member_slot;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    group_id == NULL ||
	    !pqcp_edge_internal_text_valid(
		    principal_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    capabilities == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	group_slot = group_index(manager, group_id);
	if (group_slot < 0) {
		ret = group_slot;
		goto out;
	}
	group = &manager->groups[group_slot];
	member_slot = member_index(group, principal_id);
	if (member_slot >= 0) {
		ret = -EALREADY;
		goto out;
	}
	member_slot = free_member_index(group);
	if (member_slot < 0) {
		ret = member_slot;
		goto out;
	}
	member = &group->members[member_slot];
	memset(member, 0, sizeof(*member));
	ret = pqcp_edge_internal_copy_text(
		member->principal_id,
		sizeof(member->principal_id),
		principal_id);
	if (ret != 0) {
		goto out;
	}
	member->joined_epoch = group->epoch;
	member->capabilities = capabilities;
	member->active = true;
	++group->member_count;
	group->rotated_at_ms = now_ms;
	++manager->membership_changes;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_group_remove_member(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const char *principal_id,
	uint64_t now_ms)
{
	struct pqcp_edge_group *group;
	struct pqcp_edge_group_member *member;
	int group_slot;
	int member_slot;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    group_id == NULL || principal_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	group_slot = group_index(manager, group_id);
	if (group_slot < 0) {
		ret = group_slot;
		goto out;
	}
	group = &manager->groups[group_slot];
	if (strcmp(group->owner_id, principal_id) == 0) {
		ret = -EPERM;
		goto out;
	}
	member_slot = member_index(group, principal_id);
	if (member_slot < 0) {
		ret = member_slot;
		goto out;
	}
	member = &group->members[member_slot];
	member->active = false;
	member->removed_epoch = group->epoch + 1U;
	member->capabilities = 0U;
	if (group->member_count != 0U) {
		--group->member_count;
	}
	group->rotated_at_ms = now_ms;
	++manager->membership_changes;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_group_rotate(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const uint8_t key_material[PQCP_EDGE_KEY_BYTES],
	uint64_t now_ms)
{
	struct pqcp_edge_group *group;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    group_id == NULL || key_material == NULL ||
	    pqcp_edge_internal_all_zero(
		    key_material, PQCP_EDGE_KEY_BYTES)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = group_index(manager, group_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	group = &manager->groups[index];
	if (group->epoch == UINT64_MAX) {
		k_mutex_unlock(&manager->lock);
		return -EOVERFLOW;
	}
	ret = key_digest(
		key_material, group->group_id,
		group->epoch + 1U, digest);
	if (ret == 0 &&
	    pqcp_edge_internal_equal(
		    digest, group->key_digest,
		    sizeof(digest))) {
		ret = -EALREADY;
	}
	if (ret == 0) {
		++group->epoch;
		group->rotated_at_ms = now_ms;
		memcpy(group->key_digest, digest,
		       sizeof(digest));
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_group_authorize(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const char *principal_id,
	uint64_t required_capabilities)
{
	const struct pqcp_edge_group_member *member;
	int group_slot;
	int member_slot;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    group_id == NULL || principal_id == NULL ||
	    required_capabilities == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	group_slot = group_index(manager, group_id);
	if (group_slot < 0) {
		ret = group_slot;
		goto out;
	}
	member_slot = member_index(
		&manager->groups[group_slot], principal_id);
	if (member_slot < 0) {
		ret = -EACCES;
		goto out;
	}
	member = &manager->groups[group_slot].
		members[member_slot];
	if ((member->capabilities &
	     required_capabilities) !=
	    required_capabilities) {
		ret = -EACCES;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_group_manager_audit(
	struct pqcp_edge_group_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->groups == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_group *group =
			&manager->groups[index];
		uint32_t active = 0U;
		bool owner_active = false;

		if (!group->occupied) {
			continue;
		}
		if (group->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    group->generation == 0U ||
		    group->epoch == 0U ||
		    !pqcp_edge_internal_text_valid(
			    group->group_id,
			    sizeof(group->group_id)) ||
		    !pqcp_edge_internal_text_valid(
			    group->owner_id,
			    sizeof(group->owner_id)) ||
		    pqcp_edge_internal_all_zero(
			    group->key_digest,
			    sizeof(group->key_digest))) {
			ret = -EBADMSG;
			break;
		}
		for (size_t member = 0U;
		     member < PQCP_EDGE_MAX_GROUP_MEMBERS;
		     ++member) {
			if (!group->members[member].active) {
				continue;
			}
			++active;
			if (!pqcp_edge_internal_text_valid(
				    group->members[member].
					    principal_id,
				    sizeof(group->members[member].
					    principal_id)) ||
			    group->members[member].
				    joined_epoch == 0U ||
			    group->members[member].
				    joined_epoch > group->epoch) {
				ret = -EBADMSG;
				break;
			}
			if (strcmp(
				    group->members[member].
					    principal_id,
				    group->owner_id) == 0) {
				owner_active = true;
			}
		}
		if (ret == 0 &&
		    (active != group->member_count ||
		     !owner_active)) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
