/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Time-, trust-, risk-, and usage-bounded vault grants.
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

static bool entry_valid(
	const struct pqcp_edge_vault_acl_entry *entry)
{
	return entry != NULL &&
	       pqcp_edge_internal_text_valid(
		       entry->object_id,
		       sizeof(entry->object_id)) &&
	       pqcp_edge_internal_text_valid(
		       entry->principal_id,
		       sizeof(entry->principal_id)) &&
	       permissions_valid(entry->permissions) &&
	       (entry->expires_at_ms == 0U ||
		entry->not_before_ms <= entry->expires_at_ms) &&
	       entry->minimum_trust <=
		       PQCP_EDGE_TRUST_PRIVILEGED;
}

static int entry_index(
	const struct pqcp_edge_vault_acl *acl,
	const char *object_id,
	const char *principal_id)
{
	for (size_t index = 0U;
	     index < acl->capacity; ++index) {
		if (acl->entries[index].occupied &&
		    strcmp(acl->entries[index].object_id,
			   object_id) == 0 &&
		    strcmp(acl->entries[index].principal_id,
			   principal_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_entry_index(
	const struct pqcp_edge_vault_acl *acl)
{
	for (size_t index = 0U;
	     index < acl->capacity; ++index) {
		if (!acl->entries[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

int pqcp_edge_vault_acl_init(
	struct pqcp_edge_vault_acl *acl,
	struct pqcp_edge_vault_acl_entry *entries,
	size_t capacity)
{
	if (acl == NULL || entries == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(acl, 0, sizeof(*acl));
	memset(entries, 0, capacity * sizeof(*entries));
	acl->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	acl->entries = entries;
	acl->capacity = capacity;
	acl->next_generation = 1U;
	k_mutex_init(&acl->lock);
	acl->initialized = true;
	return 0;
}

int pqcp_edge_vault_acl_put(
	struct pqcp_edge_vault_acl *acl,
	const struct pqcp_edge_vault_acl_entry *entry)
{
	struct pqcp_edge_vault_acl_entry candidate;
	int index;
	int ret = 0;

	if (acl == NULL || !acl->initialized ||
	    !entry_valid(entry)) {
		return -EINVAL;
	}
	k_mutex_lock(&acl->lock, K_FOREVER);
	index = entry_index(
		acl, entry->object_id, entry->principal_id);
	candidate = *entry;
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.occupied = true;
	if (index >= 0) {
		candidate.generation =
			acl->entries[index].generation;
		candidate.use_count =
			acl->entries[index].use_count;
	} else if (index == -ENOENT) {
		index = free_entry_index(acl);
		if (index < 0) {
			ret = index;
			goto out;
		}
		candidate.generation =
			pqcp_edge_internal_next_generation(
				&acl->next_generation);
		candidate.use_count = 0U;
	} else {
		ret = index;
		goto out;
	}
	acl->entries[index] = candidate;
out:
	k_mutex_unlock(&acl->lock);
	return ret;
}

int pqcp_edge_vault_acl_remove(
	struct pqcp_edge_vault_acl *acl,
	const char *object_id,
	const char *principal_id)
{
	int index;
	int ret = 0;

	if (acl == NULL || !acl->initialized ||
	    object_id == NULL || principal_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&acl->lock, K_FOREVER);
	index = entry_index(acl, object_id, principal_id);
	if (index < 0) {
		ret = index;
	} else {
		memset(&acl->entries[index], 0,
		       sizeof(acl->entries[index]));
	}
	k_mutex_unlock(&acl->lock);
	return ret;
}

int pqcp_edge_vault_acl_authorize(
	struct pqcp_edge_vault_acl *acl,
	const struct pqcp_edge_vault_object *object,
	const struct pqcp_edge_principal *principal,
	uint32_t permissions,
	bool attestation_fresh,
	uint64_t now_ms)
{
	struct pqcp_edge_vault_acl_entry *entry;
	int index;
	int ret = 0;

	if (acl == NULL || !acl->initialized ||
	    object == NULL || principal == NULL ||
	    !permissions_valid(permissions)) {
		return -EINVAL;
	}
	if (!object->occupied ||
	    object->state ==
		    PQCP_EDGE_VAULT_TOMBSTONED ||
	    object->state ==
		    PQCP_EDGE_VAULT_QUARANTINED ||
	    principal->state !=
		    PQCP_EDGE_PRINCIPAL_ACTIVE ||
	    principal->credential_expires_at_ms <= now_ms) {
		++acl->deny_count;
		return -EACCES;
	}
	if (strcmp(object->owner_id,
		   principal->principal_id) == 0 &&
	    (object->permissions & permissions) ==
		    permissions) {
		++acl->allow_count;
		return 0;
	}
	k_mutex_lock(&acl->lock, K_FOREVER);
	index = entry_index(
		acl, object->object_id,
		principal->principal_id);
	if (index < 0) {
		ret = -EACCES;
		goto deny;
	}
	entry = &acl->entries[index];
	if (entry->not_before_ms != 0U &&
	    now_ms < entry->not_before_ms) {
		ret = -EAGAIN;
	} else if (entry->expires_at_ms != 0U &&
		   now_ms >= entry->expires_at_ms) {
		ret = -EKEYEXPIRED;
	} else if ((entry->permissions & permissions) !=
		   permissions) {
		ret = -EACCES;
	} else if (entry->maximum_uses != 0U &&
		   entry->use_count >=
			   entry->maximum_uses) {
		ret = -EDQUOT;
	} else if (principal->risk_score >
		   entry->maximum_risk) {
		ret = -EACCES;
	} else if (principal->trust <
		   entry->minimum_trust) {
		ret = -EAGAIN;
	} else if (entry->require_attestation &&
		   !attestation_fresh) {
		ret = -EAGAIN;
	}
	if (ret == 0) {
		entry->use_count =
			pqcp_edge_internal_saturating_add_u64(
				entry->use_count, 1U);
		++acl->allow_count;
		goto out;
	}
deny:
	++acl->deny_count;
out:
	k_mutex_unlock(&acl->lock);
	return ret;
}

int pqcp_edge_vault_acl_expire(
	struct pqcp_edge_vault_acl *acl,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (acl == NULL || !acl->initialized ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&acl->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < acl->capacity; ++index) {
		struct pqcp_edge_vault_acl_entry *entry =
			&acl->entries[index];

		if (!entry->occupied) {
			continue;
		}
		if ((entry->expires_at_ms != 0U &&
		     now_ms >= entry->expires_at_ms) ||
		    (entry->maximum_uses != 0U &&
		     entry->use_count >=
			     entry->maximum_uses)) {
			memset(entry, 0, sizeof(*entry));
			++expired;
		}
	}
	k_mutex_unlock(&acl->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_vault_acl_audit(
	struct pqcp_edge_vault_acl *acl)
{
	int ret = 0;

	if (acl == NULL || !acl->initialized ||
	    acl->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    acl->entries == NULL || acl->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&acl->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < acl->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_vault_acl_entry *entry =
			&acl->entries[index];

		if (!entry->occupied) {
			continue;
		}
		if (!entry_valid(entry) ||
		    entry->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    entry->generation == 0U ||
		    (entry->maximum_uses != 0U &&
		     entry->use_count >
			     entry->maximum_uses)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < acl->capacity; ++other) {
			if (acl->entries[other].occupied &&
			    strcmp(
				    entry->object_id,
				    acl->entries[other].
					    object_id) == 0 &&
			    strcmp(
				    entry->principal_id,
				    acl->entries[other].
					    principal_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&acl->lock);
	return ret;
}
