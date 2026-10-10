/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Fixed-capacity sovereign tenant registry and cross-tenant federation grants.
 */

#include "sovereign_privacy_internal.h"
#include "runtime_internal.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

bool pqcp_sovereign_privacy_text_valid(const char *text, size_t capacity)
{
	size_t length;

	if (text == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(text, capacity);
	return length > 0U && length < capacity;
}

bool pqcp_sovereign_privacy_digest_zero(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;
	size_t index;

	if (digest == NULL) {
		return true;
	}
	for (index = 0U; index < PQCP_SOVEREIGN_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

bool pqcp_sovereign_privacy_data_class_valid(
	enum pqcp_sovereign_data_class data_class)
{
	return data_class >= PQCP_SOVEREIGN_DATA_PUBLIC &&
	       data_class < PQCP_SOVEREIGN_DATA_CLASS_COUNT;
}

bool pqcp_sovereign_privacy_operation_valid(
	enum pqcp_sovereign_operation operation)
{
	return operation > PQCP_SOVEREIGN_OPERATION_NONE &&
	       operation < PQCP_SOVEREIGN_OPERATION_COUNT;
}

bool pqcp_sovereign_privacy_lifecycle_active(
	enum pqcp_sovereign_lifecycle_state state)
{
	return state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
}

int pqcp_sovereign_privacy_copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	size_t length;

	if (destination == NULL ||
	    !pqcp_sovereign_privacy_text_valid(source, capacity)) {
		return -EINVAL;
	}
	length = strlen(source);
	memcpy(destination, source, length + 1U);
	return 0;
}

int pqcp_sovereign_privacy_digest_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	if (parts == NULL || lengths == NULL || part_count == 0U ||
	    output == NULL) {
		return -EINVAL;
	}
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, part_count, output);
}

static int encode_tenant_digest(
	const struct pqcp_sovereign_tenant *tenant,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t numeric[96];
	const uint8_t *parts[6];
	size_t lengths[6];
	size_t offset = 0U;

	if (tenant == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u32(
		&numeric[offset], PQCP_SOVEREIGN_SCHEMA_VERSION);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], tenant->capabilities);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], tenant->operation_mask);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], tenant->policy_epoch);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], tenant->revocation_epoch);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], tenant->created_at_ms);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], tenant->expires_at_ms);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], tenant->storage_quota_bytes);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], tenant->compute_quota_units);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], tenant->maximum_namespaces);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], tenant->risk_score);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], (uint32_t)tenant->state);
	offset += sizeof(uint32_t);

	parts[0] = (const uint8_t *)tenant->tenant_id;
	lengths[0] = strlen(tenant->tenant_id);
	parts[1] = (const uint8_t *)tenant->parent_tenant_id;
	lengths[1] = strlen(tenant->parent_tenant_id);
	parts[2] = (const uint8_t *)tenant->trust_domain;
	lengths[2] = strlen(tenant->trust_domain);
	parts[3] = (const uint8_t *)tenant->home_zone;
	lengths[3] = strlen(tenant->home_zone);
	parts[4] = numeric;
	lengths[4] = offset;
	parts[5] = (const uint8_t *)"pqcp-sovereign-tenant-v1";
	lengths[5] = sizeof("pqcp-sovereign-tenant-v1") - 1U;
	return pqcp_sovereign_privacy_digest_parts(
		parts, lengths, ARRAY_SIZE(parts), output);
}

static bool tenant_input_valid(
	const struct pqcp_sovereign_tenant *tenant,
	uint64_t now_ms)
{
	if (tenant == NULL || now_ms == 0U ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant->tenant_id, sizeof(tenant->tenant_id)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant->trust_domain, sizeof(tenant->trust_domain)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant->home_zone, sizeof(tenant->home_zone)) ||
	    tenant->capabilities == 0U ||
	    tenant->operation_mask == 0U ||
	    tenant->policy_epoch == 0U ||
	    tenant->revocation_epoch == 0U ||
	    tenant->storage_quota_bytes == 0U ||
	    tenant->compute_quota_units == 0U ||
	    tenant->maximum_namespaces == 0U ||
	    tenant->active_namespaces > tenant->maximum_namespaces ||
	    tenant->expires_at_ms <= now_ms ||
	    tenant->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		return false;
	}
	if (tenant->parent_tenant_id[0] != '\0' &&
	    (!pqcp_sovereign_privacy_text_valid(
		     tenant->parent_tenant_id,
		     sizeof(tenant->parent_tenant_id)) ||
	     strcmp(tenant->tenant_id, tenant->parent_tenant_id) == 0)) {
		return false;
	}
	return true;
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

static int free_tenant_index_locked(
	const struct pqcp_sovereign_tenant_registry *registry)
{
	size_t index;

	for (index = 0U; index < registry->capacity; ++index) {
		if (!registry->tenants[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static bool tenant_identity_alias_locked(
	const struct pqcp_sovereign_tenant_registry *registry,
	const char *tenant_id,
	const uint8_t identity_digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	size_t index;

	for (index = 0U; index < registry->capacity; ++index) {
		const struct pqcp_sovereign_tenant *existing =
			&registry->tenants[index];

		if (!existing->occupied ||
		    strcmp(existing->tenant_id, tenant_id) == 0) {
			continue;
		}
		if (memcmp(existing->identity_digest, identity_digest,
			   PQCP_SOVEREIGN_DIGEST_BYTES) == 0) {
			return true;
		}
	}
	return false;
}

static bool tenant_parent_valid_locked(
	const struct pqcp_sovereign_tenant_registry *registry,
	const struct pqcp_sovereign_tenant *tenant)
{
	int parent_index;
	const struct pqcp_sovereign_tenant *parent;

	if (tenant->parent_tenant_id[0] == '\0') {
		return true;
	}
	parent_index = tenant_index_locked(
		registry, tenant->parent_tenant_id);
	if (parent_index < 0) {
		return false;
	}
	parent = &registry->tenants[parent_index];
	return parent->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
	       parent->policy_epoch <= tenant->policy_epoch &&
	       parent->revocation_epoch <= tenant->revocation_epoch &&
	       strcmp(parent->trust_domain, tenant->trust_domain) == 0;
}

static uint32_t next_generation(uint32_t *generation)
{
	uint32_t value = *generation;

	if (value == 0U) {
		value = 1U;
	}
	if (value == UINT32_MAX) {
		*generation = 1U;
	} else {
		*generation = value + 1U;
	}
	return value;
}

int pqcp_sovereign_tenant_registry_init(
	struct pqcp_sovereign_tenant_registry *registry,
	struct pqcp_sovereign_tenant *tenants,
	size_t capacity)
{
	if (registry == NULL || tenants == NULL || capacity == 0U ||
	    capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(tenants, 0, capacity * sizeof(*tenants));
	registry->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	registry->tenants = tenants;
	registry->capacity = capacity;
	registry->next_generation = 1U;
	k_mutex_init(&registry->lock);
	registry->initialized = true;
	return 0;
}

int pqcp_sovereign_tenant_register(
	struct pqcp_sovereign_tenant_registry *registry,
	const struct pqcp_sovereign_tenant *tenant,
	uint64_t now_ms)
{
	struct pqcp_sovereign_tenant candidate;
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    !tenant_input_valid(tenant, now_ms)) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	if (tenant_index_locked(registry, tenant->tenant_id) >= 0) {
		registry->rejection_count++;
		k_mutex_unlock(&registry->lock);
		return -EALREADY;
	}
	if (!tenant_parent_valid_locked(registry, tenant)) {
		registry->rejection_count++;
		k_mutex_unlock(&registry->lock);
		return -EACCES;
	}
	index = free_tenant_index_locked(registry);
	if (index < 0) {
		registry->rejection_count++;
		k_mutex_unlock(&registry->lock);
		return -ENOSPC;
	}
	candidate = *tenant;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.generation = next_generation(
		&registry->next_generation);
	candidate.created_at_ms = now_ms;
	candidate.active_namespaces = 0U;
	candidate.occupied = true;
	ret = encode_tenant_digest(
		&candidate, candidate.identity_digest);
	if (ret != 0 ||
	    tenant_identity_alias_locked(
		    registry, candidate.tenant_id,
		    candidate.identity_digest)) {
		registry->rejection_count++;
		k_mutex_unlock(&registry->lock);
		return ret != 0 ? ret : -EEXIST;
	}
	registry->tenants[index] = candidate;
	registry->registration_count++;
	k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_sovereign_tenant_find(
	struct pqcp_sovereign_tenant_registry *registry,
	const char *tenant_id,
	struct pqcp_sovereign_tenant **tenant)
{
	int index;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    tenant == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = tenant_index_locked(registry, tenant_id);
	if (index < 0) {
		k_mutex_unlock(&registry->lock);
		return -ENOENT;
	}
	*tenant = &registry->tenants[index];
	k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_sovereign_tenant_authorize(
	struct pqcp_sovereign_tenant_registry *registry,
	const char *tenant_id,
	enum pqcp_sovereign_operation operation,
	uint64_t capabilities,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms)
{
	struct pqcp_sovereign_tenant *tenant;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_operation_valid(operation) ||
	    capabilities == 0U || policy_epoch == 0U ||
	    revocation_epoch == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = tenant_index_locked(registry, tenant_id);
	if (index < 0) {
		ret = -ENOENT;
		goto out;
	}
	tenant = &registry->tenants[index];
	if (tenant->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = -EACCES;
	} else if (tenant->expires_at_ms <= now_ms) {
		ret = -ETIME;
	} else if (tenant->policy_epoch != policy_epoch ||
		   tenant->revocation_epoch != revocation_epoch) {
		ret = -ESTALE;
	} else if ((tenant->operation_mask &
		    PQCP_SOVEREIGN_BIT(operation)) == 0U ||
		   (tenant->capabilities & capabilities) != capabilities) {
		ret = -EACCES;
	}
out:
	if (ret != 0) {
		registry->rejection_count++;
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

static bool lifecycle_transition_valid(
	enum pqcp_sovereign_lifecycle_state current,
	enum pqcp_sovereign_lifecycle_state next)
{
	switch (current) {
	case PQCP_SOVEREIGN_LIFECYCLE_DRAFT:
		return next == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	case PQCP_SOVEREIGN_LIFECYCLE_ACTIVE:
		return next == PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	case PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED:
		return next == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
		       next == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	case PQCP_SOVEREIGN_LIFECYCLE_RETIRED:
		return next == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	default:
		return false;
	}
}

int pqcp_sovereign_tenant_set_state(
	struct pqcp_sovereign_tenant_registry *registry,
	const char *tenant_id,
	enum pqcp_sovereign_lifecycle_state state,
	uint64_t now_ms)
{
	struct pqcp_sovereign_tenant *tenant;
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    now_ms == 0U || state <= PQCP_SOVEREIGN_LIFECYCLE_EMPTY ||
	    state > PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = tenant_index_locked(registry, tenant_id);
	if (index < 0) {
		k_mutex_unlock(&registry->lock);
		return -ENOENT;
	}
	tenant = &registry->tenants[index];
	if (!lifecycle_transition_valid(tenant->state, state)) {
		registry->rejection_count++;
		k_mutex_unlock(&registry->lock);
		return -EPERM;
	}
	if (state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED &&
	    tenant->active_namespaces != 0U) {
		registry->rejection_count++;
		k_mutex_unlock(&registry->lock);
		return -EBUSY;
	}
	tenant->state = state;
	if (state == PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
		if (tenant->revocation_epoch != UINT64_MAX) {
			tenant->revocation_epoch++;
		}
		tenant->expires_at_ms = now_ms;
	}
	ret = encode_tenant_digest(tenant, tenant->identity_digest);
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_sovereign_tenant_tick(
	struct pqcp_sovereign_tenant_registry *registry,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;
	size_t index;

	if (registry == NULL || !registry->initialized ||
	    now_ms == 0U || changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (index = 0U; index < registry->capacity; ++index) {
		struct pqcp_sovereign_tenant *tenant =
			&registry->tenants[index];

		if (!tenant->occupied ||
		    tenant->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    tenant->expires_at_ms > now_ms) {
			continue;
		}
		tenant->state = PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED;
		if (tenant->revocation_epoch != UINT64_MAX) {
			tenant->revocation_epoch++;
		}
		(void)encode_tenant_digest(
			tenant, tenant->identity_digest);
		changed++;
	}
	*changed_count = changed;
	k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_sovereign_tenant_registry_audit(
	struct pqcp_sovereign_tenant_registry *registry)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	size_t index;
	size_t other;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    registry->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    registry->tenants == NULL || registry->capacity == 0U ||
	    registry->next_generation == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (index = 0U; index < registry->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_tenant *tenant =
			&registry->tenants[index];

		if (!tenant->occupied) {
			continue;
		}
		if (tenant->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    tenant->generation == 0U ||
		    !pqcp_sovereign_privacy_text_valid(
			    tenant->tenant_id,
			    sizeof(tenant->tenant_id)) ||
		    tenant->maximum_namespaces == 0U ||
		    tenant->active_namespaces >
			    tenant->maximum_namespaces ||
		    encode_tenant_digest(tenant, digest) != 0 ||
		    memcmp(digest, tenant->identity_digest,
			   sizeof(digest)) != 0) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < registry->capacity; ++other) {
			if (!registry->tenants[other].occupied) {
				continue;
			}
			if (strcmp(tenant->tenant_id,
				   registry->tenants[other].tenant_id) == 0 ||
			    memcmp(tenant->identity_digest,
				   registry->tenants[other].identity_digest,
				   PQCP_SOVEREIGN_DIGEST_BYTES) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}

static bool federation_grant_input_valid(
	const struct pqcp_sovereign_federation_grant *grant,
	uint64_t now_ms)
{
	if (grant == NULL || now_ms == 0U ||
	    !pqcp_sovereign_privacy_text_valid(
		    grant->source_tenant_id,
		    sizeof(grant->source_tenant_id)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    grant->destination_tenant_id,
		    sizeof(grant->destination_tenant_id)) ||
	    strcmp(grant->source_tenant_id,
		   grant->destination_tenant_id) == 0 ||
	    !pqcp_sovereign_privacy_text_valid(
		    grant->purpose, sizeof(grant->purpose)) ||
	    !pqcp_sovereign_privacy_text_valid(
		    grant->legal_basis, sizeof(grant->legal_basis)) ||
	    grant->operation_mask == 0U ||
	    grant->resource_class_mask == 0U ||
	    grant->data_class_mask == 0U ||
	    grant->policy_epoch == 0U ||
	    grant->revocation_epoch == 0U ||
	    grant->not_before_ms < now_ms ||
	    grant->expires_at_ms <= grant->not_before_ms ||
	    grant->maximum_uses == 0U ||
	    grant->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		return false;
	}
	return true;
}

static int federation_digest(
	const struct pqcp_sovereign_federation_grant *grant,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t numeric[96];
	const uint8_t *parts[6];
	size_t lengths[6];
	size_t offset = 0U;

	pqcp_runtime_internal_write_u32(
		&numeric[offset], grant->generation);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], grant->grant_id);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], grant->operation_mask);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], grant->resource_class_mask);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u32(
		&numeric[offset], grant->data_class_mask);
	offset += sizeof(uint32_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], grant->policy_epoch);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], grant->revocation_epoch);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], grant->issued_at_ms);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], grant->not_before_ms);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], grant->expires_at_ms);
	offset += sizeof(uint64_t);
	pqcp_runtime_internal_write_u64(
		&numeric[offset], grant->maximum_uses);
	offset += sizeof(uint64_t);
	parts[0] = (const uint8_t *)grant->source_tenant_id;
	lengths[0] = strlen(grant->source_tenant_id);
	parts[1] = (const uint8_t *)grant->destination_tenant_id;
	lengths[1] = strlen(grant->destination_tenant_id);
	parts[2] = (const uint8_t *)grant->purpose;
	lengths[2] = strlen(grant->purpose);
	parts[3] = (const uint8_t *)grant->legal_basis;
	lengths[3] = strlen(grant->legal_basis);
	parts[4] = numeric;
	lengths[4] = offset;
	parts[5] = (const uint8_t *)"pqcp-federation-grant-v1";
	lengths[5] = sizeof("pqcp-federation-grant-v1") - 1U;
	return pqcp_sovereign_privacy_digest_parts(
		parts, lengths, ARRAY_SIZE(parts), output);
}

static int federation_grant_index_locked(
	const struct pqcp_sovereign_federation_manager *manager,
	uint64_t grant_id)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		if (manager->grants[index].occupied &&
		    manager->grants[index].grant_id == grant_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_federation_index_locked(
	const struct pqcp_sovereign_federation_manager *manager)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		if (!manager->grants[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_sovereign_federation_manager_init(
	struct pqcp_sovereign_federation_manager *manager,
	struct pqcp_sovereign_federation_grant *grants,
	size_t capacity)
{
	if (manager == NULL || grants == NULL || capacity == 0U ||
	    capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(grants, 0, capacity * sizeof(*grants));
	manager->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	manager->grants = grants;
	manager->capacity = capacity;
	manager->next_generation = 1U;
	manager->next_grant_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_federation_grant_issue(
	struct pqcp_sovereign_federation_manager *manager,
	const struct pqcp_sovereign_federation_grant *grant,
	uint64_t now_ms,
	struct pqcp_sovereign_federation_grant **stored)
{
	struct pqcp_sovereign_federation_grant candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    !federation_grant_input_valid(grant, now_ms) ||
	    stored == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = free_federation_index_locked(manager);
	if (index < 0) {
		manager->denial_count++;
		k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	if (manager->next_grant_id == 0U ||
	    manager->next_grant_id == UINT64_MAX) {
		manager->denial_count++;
		k_mutex_unlock(&manager->lock);
		return -EOVERFLOW;
	}
	candidate = *grant;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.generation = next_generation(
		&manager->next_generation);
	candidate.grant_id = manager->next_grant_id++;
	candidate.issued_at_ms = now_ms;
	candidate.use_count = 0U;
	candidate.occupied = true;
	ret = federation_digest(
		&candidate, candidate.grant_digest);
	if (ret != 0) {
		manager->denial_count++;
		k_mutex_unlock(&manager->lock);
		return ret;
	}
	manager->grants[index] = candidate;
	*stored = &manager->grants[index];
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_federation_authorize(
	struct pqcp_sovereign_federation_manager *manager,
	const char *source_tenant_id,
	const char *destination_tenant_id,
	enum pqcp_sovereign_resource_class resource_class,
	enum pqcp_sovereign_operation operation,
	enum pqcp_sovereign_data_class data_class,
	const char *purpose,
	const char *legal_basis,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms,
	uint64_t *grant_id)
{
	size_t index;
	int ret = -EACCES;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    source_tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    destination_tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    strcmp(source_tenant_id, destination_tenant_id) == 0 ||
	    resource_class <= PQCP_SOVEREIGN_RESOURCE_NONE ||
	    resource_class >= PQCP_SOVEREIGN_RESOURCE_COUNT ||
	    !pqcp_sovereign_privacy_operation_valid(operation) ||
	    !pqcp_sovereign_privacy_data_class_valid(data_class) ||
	    !pqcp_sovereign_privacy_text_valid(
		    purpose, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    legal_basis, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    policy_epoch == 0U || revocation_epoch == 0U ||
	    now_ms == 0U || grant_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U; index < manager->capacity; ++index) {
		struct pqcp_sovereign_federation_grant *grant =
			&manager->grants[index];

		if (!grant->occupied ||
		    grant->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    strcmp(grant->source_tenant_id,
			   source_tenant_id) != 0 ||
		    strcmp(grant->destination_tenant_id,
			   destination_tenant_id) != 0 ||
		    strcmp(grant->purpose, purpose) != 0 ||
		    strcmp(grant->legal_basis, legal_basis) != 0) {
			continue;
		}
		if (grant->not_before_ms > now_ms ||
		    grant->expires_at_ms <= now_ms) {
			ret = -ETIME;
			continue;
		}
		if (grant->policy_epoch != policy_epoch ||
		    grant->revocation_epoch != revocation_epoch) {
			ret = -ESTALE;
			continue;
		}
		if ((grant->operation_mask &
		     PQCP_SOVEREIGN_BIT(operation)) == 0U ||
		    (grant->resource_class_mask &
		     (1U << (uint32_t)resource_class)) == 0U ||
		    (grant->data_class_mask &
		     (1U << (uint32_t)data_class)) == 0U) {
			continue;
		}
		if (grant->use_count >= grant->maximum_uses) {
			ret = -EDQUOT;
			continue;
		}
		grant->use_count++;
		*grant_id = grant->grant_id;
		manager->authorization_count++;
		ret = 0;
		break;
	}
	if (ret != 0) {
		manager->denial_count++;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_federation_grant_revoke(
	struct pqcp_sovereign_federation_manager *manager,
	uint64_t grant_id)
{
	int index;

	if (manager == NULL || !manager->initialized ||
	    grant_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = federation_grant_index_locked(manager, grant_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	if (manager->grants[index].state ==
	    PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	manager->grants[index].state =
		PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_federation_manager_tick(
	struct pqcp_sovereign_federation_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	size_t index;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U; index < manager->capacity; ++index) {
		struct pqcp_sovereign_federation_grant *grant =
			&manager->grants[index];

		if (!grant->occupied ||
		    grant->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    grant->expires_at_ms > now_ms) {
			continue;
		}
		grant->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		expired++;
	}
	*expired_count = expired;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_federation_manager_audit(
	struct pqcp_sovereign_federation_manager *manager)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	size_t index;
	size_t other;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    manager->grants == NULL || manager->capacity == 0U ||
	    manager->next_generation == 0U ||
	    manager->next_grant_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U; index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_federation_grant *grant =
			&manager->grants[index];

		if (!grant->occupied) {
			continue;
		}
		if (grant->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    grant->generation == 0U ||
		    grant->grant_id == 0U ||
		    grant->use_count > grant->maximum_uses ||
		    strcmp(grant->source_tenant_id,
			   grant->destination_tenant_id) == 0 ||
		    federation_digest(grant, digest) != 0 ||
		    memcmp(digest, grant->grant_digest,
			   sizeof(digest)) != 0) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->grants[other].occupied &&
			    manager->grants[other].grant_id ==
				    grant->grant_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
