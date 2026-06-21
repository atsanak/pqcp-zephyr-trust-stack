/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Offline-capable vault leases bound to object, principal and policy epoch.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool permissions_valid(uint32_t permissions)
{
	const uint32_t allowed =
		PQCP_EDGE_VAULT_PERMISSION_READ |
		PQCP_EDGE_VAULT_PERMISSION_WRITE |
		PQCP_EDGE_VAULT_PERMISSION_DELETE |
		PQCP_EDGE_VAULT_PERMISSION_ROTATE |
		PQCP_EDGE_VAULT_PERMISSION_SHARE |
		PQCP_EDGE_VAULT_PERMISSION_REPLICATE |
		PQCP_EDGE_VAULT_PERMISSION_AUDIT;

	return permissions != 0U &&
	       (permissions & ~allowed) == 0U;
}

static int lease_index(
	const struct pqcp_edge_vault_lease_manager *manager,
	uint64_t lease_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->leases[index].occupied &&
		    manager->leases[index].lease_id == lease_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_lease_index(
	const struct pqcp_edge_vault_lease_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->leases[index].occupied ||
		    manager->leases[index].revoked) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int lease_digest(
	const struct pqcp_edge_vault_lease *lease,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[52];
	const uint8_t *parts[3];
	size_t lengths[3];
	size_t offset = 0U;

	pqcp_edge_internal_write_u32(
		numeric + offset, lease->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, lease->lease_id);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, lease->permissions);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, lease->issued_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, lease->expires_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, lease->maximum_uses);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, lease->policy_epoch);
	offset += 8U;
	parts[0] = numeric;
	lengths[0] = offset;
	parts[1] = (const uint8_t *)lease->object_id;
	lengths[1] = strlen(lease->object_id);
	parts[2] = (const uint8_t *)lease->principal_id;
	lengths[2] = strlen(lease->principal_id);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 3U, output);
}

int pqcp_edge_vault_lease_manager_init(
	struct pqcp_edge_vault_lease_manager *manager,
	struct pqcp_edge_vault_lease *leases,
	size_t capacity)
{
	if (manager == NULL || leases == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(leases, 0, capacity * sizeof(*leases));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->leases = leases;
	manager->capacity = capacity;
	manager->next_lease_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_vault_lease_issue(
	struct pqcp_edge_vault_lease_manager *manager,
	const char *object_id,
	const char *principal_id,
	uint32_t permissions,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t maximum_uses,
	struct pqcp_edge_vault_lease **lease)
{
	struct pqcp_edge_vault_lease candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_edge_internal_text_valid(
		    object_id, PQCP_EDGE_OBJECT_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    principal_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    !permissions_valid(permissions) ||
	    policy_epoch == 0U || expires_at_ms <= now_ms ||
	    maximum_uses == 0U || lease == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = free_lease_index(manager);
	if (index < 0) {
		++manager->rejected_count;
		k_mutex_unlock(&manager->lock);
		*lease = NULL;
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.lease_id =
		pqcp_edge_internal_next_identifier(
			&manager->next_lease_id);
	ret = pqcp_edge_internal_copy_text(
		candidate.object_id,
		sizeof(candidate.object_id), object_id);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.principal_id,
			sizeof(candidate.principal_id),
			principal_id);
	}
	candidate.permissions = permissions;
	candidate.issued_at_ms = now_ms;
	candidate.expires_at_ms = expires_at_ms;
	candidate.maximum_uses = maximum_uses;
	candidate.policy_epoch = policy_epoch;
	candidate.occupied = true;
	if (ret == 0) {
		ret = lease_digest(
			&candidate, candidate.lease_digest);
	}
	if (ret == 0) {
		manager->leases[index] = candidate;
		*lease = &manager->leases[index];
		++manager->issued_count;
	} else {
		*lease = NULL;
		++manager->rejected_count;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_vault_lease_authorize(
	struct pqcp_edge_vault_lease_manager *manager,
	uint64_t lease_id,
	const char *object_id,
	const char *principal_id,
	uint32_t permissions,
	uint64_t policy_epoch,
	uint64_t now_ms)
{
	struct pqcp_edge_vault_lease *lease;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    lease_id == 0U || object_id == NULL ||
	    principal_id == NULL ||
	    !permissions_valid(permissions) ||
	    policy_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = lease_index(manager, lease_id);
	if (index < 0) {
		ret = index;
		goto reject;
	}
	lease = &manager->leases[index];
	if (lease->revoked) {
		ret = -EKEYREVOKED;
	} else if (lease->expires_at_ms <= now_ms) {
		ret = -EKEYEXPIRED;
	} else if (lease->policy_epoch != policy_epoch) {
		ret = -ESTALE;
	} else if (strcmp(lease->object_id, object_id) != 0 ||
		   strcmp(lease->principal_id,
			  principal_id) != 0) {
		ret = -EACCES;
	} else if ((lease->permissions & permissions) !=
		   permissions) {
		ret = -EACCES;
	} else if (lease->use_count >=
		   lease->maximum_uses) {
		ret = -EDQUOT;
	}
	if (ret == 0) {
		++lease->use_count;
		goto out;
	}
reject:
	++manager->rejected_count;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_vault_lease_revoke(
	struct pqcp_edge_vault_lease_manager *manager,
	uint64_t lease_id)
{
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    lease_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = lease_index(manager, lease_id);
	if (index < 0) {
		ret = index;
	} else if (manager->leases[index].revoked) {
		ret = -EALREADY;
	} else {
		manager->leases[index].revoked = true;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_vault_lease_expire(
	struct pqcp_edge_vault_lease_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (manager == NULL || !manager->initialized ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_edge_vault_lease *lease =
			&manager->leases[index];

		if (lease->occupied && !lease->revoked &&
		    (lease->expires_at_ms <= now_ms ||
		     lease->use_count >= lease->maximum_uses)) {
			lease->revoked = true;
			++expired;
		}
	}
	k_mutex_unlock(&manager->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_vault_lease_manager_audit(
	struct pqcp_edge_vault_lease_manager *manager)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->leases == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_vault_lease *lease =
			&manager->leases[index];

		if (!lease->occupied) {
			continue;
		}
		if (lease->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    lease->lease_id == 0U ||
		    !pqcp_edge_internal_text_valid(
			    lease->object_id,
			    sizeof(lease->object_id)) ||
		    !pqcp_edge_internal_text_valid(
			    lease->principal_id,
			    sizeof(lease->principal_id)) ||
		    !permissions_valid(lease->permissions) ||
		    lease->policy_epoch == 0U ||
		    lease->expires_at_ms <=
			    lease->issued_at_ms ||
		    lease->maximum_uses == 0U ||
		    lease->use_count >
			    lease->maximum_uses ||
		    lease_digest(lease, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    digest, lease->lease_digest,
			    sizeof(digest))) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
