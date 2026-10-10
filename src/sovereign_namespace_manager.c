/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tenant-scoped namespace allocation, quota accounting, and authorization.
 */

#include "sovereign_privacy_internal.h"
#include "runtime_internal.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

static int namespace_index_locked(
	const struct pqcp_sovereign_namespace_manager *manager,
	const char *namespace_id)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		if (manager->namespaces[index].occupied &&
		    strcmp(manager->namespaces[index].namespace_id,
			   namespace_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int free_namespace_index_locked(
	const struct pqcp_sovereign_namespace_manager *manager)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		if (!manager->namespaces[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static int tenant_index_locked(
	const struct pqcp_sovereign_tenant_registry *registry,
	const char *tenant_id)
{
	size_t index;

	for (index = 0U; index < registry->capacity; ++index) {
		if (registry->tenants[index].occupied &&
		    strcmp(registry->tenants[index].tenant_id,
			   tenant_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static bool namespace_input_valid(
	const struct pqcp_sovereign_namespace *namespace_value,
	uint64_t now_ms)
{
	if (namespace_value == NULL || now_ms == 0U ||
	    !pqcp_sovereign_privacy_text_valid(
		    namespace_value->namespace_id,
		    sizeof(namespace_value->namespace_id)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    namespace_value->tenant_id,
		    sizeof(namespace_value->tenant_id)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    namespace_value->residency_zone,
		    sizeof(namespace_value->residency_zone)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    namespace_value->security_label,
		    sizeof(namespace_value->security_label)) ||
	    namespace_value->operation_mask == 0U ||
	    namespace_value->policy_epoch == 0U ||
	    namespace_value->expires_at_ms <= now_ms ||
	    namespace_value->storage_limit_bytes == 0U ||
	    namespace_value->storage_used_bytes != 0U ||
	    namespace_value->maximum_workloads == 0U ||
	    namespace_value->active_workloads != 0U ||
	    !pqcp_sovereign_privacy_data_class_valid(
		    namespace_value->maximum_data_class) ||
	    namespace_value->state !=
		    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		return false;
	}
	return true;
}

static uint32_t allocate_generation(uint32_t *next)
{
	uint32_t value = *next;

	if (value == 0U) {
		value = 1U;
	}
	*next = value == UINT32_MAX ? 1U : value + 1U;
	return value;
}

static int namespace_digest(
	const struct pqcp_sovereign_namespace *namespace_value,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t numeric[80];
	const uint8_t *parts[6];
	size_t lengths[6];
	size_t offset = 0U;

	pqcp_runtime_internal_write_u32(
		&numeric[offset], namespace_value->generation);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], namespace_value->operation_mask);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], namespace_value->policy_epoch);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], namespace_value->created_at_ms);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], namespace_value->expires_at_ms);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], namespace_value->storage_limit_bytes);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], namespace_value->maximum_workloads);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset],
		(uint32_t)namespace_value->maximum_data_class);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], (uint32_t)namespace_value->state);
	offset += sizeof(uint32_t);
	parts[0] = (const uint8_t *)namespace_value->namespace_id;
	lengths[0] = strlen(namespace_value->namespace_id);
	parts[1] = (const uint8_t *)namespace_value->tenant_id;
	lengths[1] = strlen(namespace_value->tenant_id);
	parts[2] = (const uint8_t *)namespace_value->residency_zone;
	lengths[2] = strlen(namespace_value->residency_zone);
	parts[3] = (const uint8_t *)namespace_value->security_label;
	lengths[3] = strlen(namespace_value->security_label);
	parts[4] = numeric;
	lengths[4] = offset;
	parts[5] = (const uint8_t *)"pqcp-sovereign-namespace-v1";
	lengths[5] = sizeof("pqcp-sovereign-namespace-v1") - 1U;
	return pqcp_sovereign_privacy_digest_parts(
		parts, lengths, ARRAY_SIZE(parts), output);
}

int pqcp_sovereign_namespace_manager_init(
	struct pqcp_sovereign_namespace_manager *manager,
	struct pqcp_sovereign_namespace *namespaces,
	size_t capacity)
{
	if (manager == NULL || namespaces == NULL || capacity == 0U ||
	    capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(namespaces, 0, capacity * sizeof(*namespaces));
	manager->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	manager->namespaces = namespaces;
	manager->capacity = capacity;
	manager->next_generation = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_namespace_create(
	struct pqcp_sovereign_namespace_manager *manager,
	struct pqcp_sovereign_tenant_registry *tenants,
	const struct pqcp_sovereign_namespace *namespace_value,
	uint64_t now_ms)
{
	struct pqcp_sovereign_namespace candidate;
	struct pqcp_sovereign_tenant *tenant;
	int tenant_slot;
	int namespace_slot;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    tenants == NULL || !tenants->initialized ||
	    !namespace_input_valid(namespace_value, now_ms)) {
		return -EINVAL;
	}
	k_mutex_lock(&tenants->lock, K_FOREVER);
	tenant_slot = tenant_index_locked(
		tenants, namespace_value->tenant_id);
	if (tenant_slot < 0) {
		k_mutex_unlock(&tenants->lock);
		return -ENOENT;
	}
	tenant = &tenants->tenants[tenant_slot];
	if (tenant->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
	    tenant->expires_at_ms <= now_ms ||
	    tenant->policy_epoch != namespace_value->policy_epoch) {
		tenants->rejection_count++;
		k_mutex_unlock(&tenants->lock);
		return -EACCES;
	}
	if (strcmp(tenant->home_zone,
		   namespace_value->residency_zone) != 0) {
		tenants->rejection_count++;
		k_mutex_unlock(&tenants->lock);
		return -EXDEV;
	}
	if (tenant->active_namespaces >=
	    tenant->maximum_namespaces) {
		tenants->rejection_count++;
		k_mutex_unlock(&tenants->lock);
		return -EDQUOT;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	if (namespace_index_locked(
		    manager, namespace_value->namespace_id) >= 0) {
		manager->denial_count++;
		ret = -EALREADY;
		goto out;
	}
	namespace_slot = free_namespace_index_locked(manager);
	if (namespace_slot < 0) {
		manager->denial_count++;
		ret = -ENOSPC;
		goto out;
	}
	candidate = *namespace_value;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.generation = allocate_generation(
		&manager->next_generation);
	candidate.created_at_ms = now_ms;
	candidate.storage_used_bytes = 0U;
	candidate.active_workloads = 0U;
	candidate.occupied = true;
	ret = namespace_digest(
		&candidate, candidate.policy_digest);
	if (ret != 0) {
		manager->denial_count++;
		goto out;
	}
	manager->namespaces[namespace_slot] = candidate;
	tenant->active_namespaces++;
	manager->creation_count++;
out:
	k_mutex_unlock(&manager->lock);
	k_mutex_unlock(&tenants->lock);
	return ret;
}

int pqcp_sovereign_namespace_find(
	struct pqcp_sovereign_namespace_manager *manager,
	const char *namespace_id,
	struct pqcp_sovereign_namespace **namespace_value)
{
	int index;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    namespace_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    namespace_value == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = namespace_index_locked(manager, namespace_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	*namespace_value = &manager->namespaces[index];
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_namespace_reserve_workload(
	struct pqcp_sovereign_namespace_manager *manager,
	const char *namespace_id,
	uint64_t storage_bytes)
{
	struct pqcp_sovereign_namespace *namespace_value;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    namespace_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    storage_bytes == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = namespace_index_locked(manager, namespace_id);
	if (index < 0) {
		ret = -ENOENT;
		goto out;
	}
	namespace_value = &manager->namespaces[index];
	if (namespace_value->state !=
	    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = -EACCES;
	} else if (namespace_value->active_workloads >=
		   namespace_value->maximum_workloads) {
		ret = -EDQUOT;
	} else if (storage_bytes >
		   namespace_value->storage_limit_bytes -
			   namespace_value->storage_used_bytes) {
		ret = -ENOSPC;
	} else {
		namespace_value->active_workloads++;
		namespace_value->storage_used_bytes += storage_bytes;
	}
out:
	if (ret != 0) {
		manager->denial_count++;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_namespace_release_workload(
	struct pqcp_sovereign_namespace_manager *manager,
	const char *namespace_id,
	uint64_t storage_bytes)
{
	struct pqcp_sovereign_namespace *namespace_value;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    namespace_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    storage_bytes == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = namespace_index_locked(manager, namespace_id);
	if (index < 0) {
		ret = -ENOENT;
		goto out;
	}
	namespace_value = &manager->namespaces[index];
	if (namespace_value->active_workloads == 0U ||
	    storage_bytes > namespace_value->storage_used_bytes) {
		ret = -ERANGE;
	} else {
		namespace_value->active_workloads--;
		namespace_value->storage_used_bytes -= storage_bytes;
	}
out:
	if (ret != 0) {
		manager->denial_count++;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_namespace_authorize(
	struct pqcp_sovereign_namespace_manager *manager,
	const char *namespace_id,
	enum pqcp_sovereign_operation operation,
	enum pqcp_sovereign_data_class data_class,
	uint64_t policy_epoch,
	uint64_t now_ms)
{
	const struct pqcp_sovereign_namespace *namespace_value;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    namespace_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_operation_valid(operation) ||
	    !pqcp_sovereign_privacy_data_class_valid(data_class) ||
	    policy_epoch == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = namespace_index_locked(manager, namespace_id);
	if (index < 0) {
		ret = -ENOENT;
		goto out;
	}
	namespace_value = &manager->namespaces[index];
	if (namespace_value->state !=
	    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = -EACCES;
	} else if (namespace_value->expires_at_ms <= now_ms) {
		ret = -ETIME;
	} else if (namespace_value->policy_epoch != policy_epoch) {
		ret = -ESTALE;
	} else if ((namespace_value->operation_mask &
		    PQCP_SOVEREIGN_BIT(operation)) == 0U) {
		ret = -EACCES;
	} else if ((uint32_t)data_class >
		   (uint32_t)namespace_value->maximum_data_class) {
		ret = -EACCES;
	}
out:
	if (ret != 0) {
		manager->denial_count++;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_namespace_manager_audit(
	struct pqcp_sovereign_namespace_manager *manager)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	size_t index;
	size_t other;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    manager->namespaces == NULL || manager->capacity == 0U ||
	    manager->next_generation == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U; index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_namespace *namespace_value =
			&manager->namespaces[index];

		if (!namespace_value->occupied) {
			continue;
		}
		if (namespace_value->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    namespace_value->generation == 0U ||
		    !pqcp_sovereign_privacy_text_valid(
			    namespace_value->namespace_id,
			    sizeof(namespace_value->namespace_id)) ||
		    !pqcp_sovereign_privacy_text_valid(
			    namespace_value->tenant_id,
			    sizeof(namespace_value->tenant_id)) ||
		    namespace_value->storage_used_bytes >
			    namespace_value->storage_limit_bytes ||
		    namespace_value->active_workloads >
			    namespace_value->maximum_workloads ||
		    namespace_digest(namespace_value, digest) != 0 ||
		    memcmp(digest, namespace_value->policy_digest,
			   sizeof(digest)) != 0) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->namespaces[other].occupied &&
			    strcmp(namespace_value->namespace_id,
				   manager->namespaces[other].
					   namespace_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
