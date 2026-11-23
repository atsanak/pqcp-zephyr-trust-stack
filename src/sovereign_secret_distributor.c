/*
 * SPDX-License-Identifier: MIT
 *
 * Bounded secret grants.  Grant consumers receive opaque runtime key handles;
 * no secret bytes are stored in or returned by this subsystem.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"
#include "sovereign_ceremony_internal.h"

#define SECRET_GRANT_DOMAIN "pqcp-sovereign-secret-grant-record-v1"
#define SECRET_REFERENCE_DOMAIN "pqcp-sovereign-secret-reference-v1"

static bool grant_state_valid(
	enum pqcp_sovereign_lifecycle_state state)
{
	switch (state) {
	case PQCP_SOVEREIGN_LIFECYCLE_ACTIVE:
	case PQCP_SOVEREIGN_LIFECYCLE_RETIRED:
	case PQCP_SOVEREIGN_LIFECYCLE_REVOKED:
		return true;
	default:
		return false;
	}
}

static int lock_distributor(
	struct pqcp_sovereign_secret_distributor *distributor)
{
	if (distributor == NULL || !distributor->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&distributor->lock, K_FOREVER);
}

static void unlock_distributor(
	struct pqcp_sovereign_secret_distributor *distributor)
{
	(void)k_mutex_unlock(&distributor->lock);
}

static int grant_index_locked(
	const struct pqcp_sovereign_secret_distributor *distributor,
	uint64_t grant_id)
{
	size_t index;

	if (grant_id == 0U) {
		return -EINVAL;
	}
	for (index = 0U; index < distributor->capacity; ++index) {
		if (distributor->grants[index].occupied &&
		    distributor->grants[index].grant_id == grant_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_grant_index_locked(
	const struct pqcp_sovereign_secret_distributor *distributor)
{
	size_t index;

	for (index = 0U; index < distributor->capacity; ++index) {
		if (!distributor->grants[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int equivalent_active_grant_locked(
	const struct pqcp_sovereign_secret_distributor *distributor,
	const char *key_id,
	const char *recipient_id,
	const char *namespace_id,
	uint64_t key_epoch,
	uint32_t permissions,
	const uint8_t recipient_binding[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	size_t index;

	for (index = 0U; index < distributor->capacity; ++index) {
		const struct pqcp_sovereign_secret_grant *grant =
			&distributor->grants[index];

		if (grant->occupied &&
		    grant->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
		    grant->key_epoch == key_epoch &&
		    grant->permissions == permissions &&
		    strcmp(grant->key_id, key_id) == 0 &&
		    strcmp(grant->recipient_id, recipient_id) == 0 &&
		    strcmp(grant->namespace_id, namespace_id) == 0 &&
		    pqcp_sovereign_ceremony_digest_equal(
			    grant->recipient_binding,
			    recipient_binding)) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int secret_grant_digest(
	const struct pqcp_sovereign_secret_grant *grant,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_SECRET_GRANT_BYTES];
	size_t offset = 0U;
	int ret;

	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, SECRET_GRANT_DOMAIN,
		sizeof(SECRET_GRANT_DOMAIN));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, grant->schema_version);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, grant->grant_id);
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, grant->key_id,
		sizeof(grant->key_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, grant->recipient_id,
		sizeof(grant->recipient_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, grant->namespace_id,
		sizeof(grant->namespace_id));
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, grant->key_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, grant->policy_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, grant->issued_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, grant->expires_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, grant->maximum_uses);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, grant->permissions);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, grant->recipient_binding,
		sizeof(grant->recipient_binding));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		grant->wrapped_secret_digest,
		sizeof(grant->wrapped_secret_digest));
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_sovereign_ceremony_hash(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static bool grant_shape_valid(
	const struct pqcp_sovereign_secret_grant *grant)
{
	if (grant == NULL || !grant->occupied ||
	    grant->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    grant->grant_id == 0U ||
	    !pqcp_sovereign_ceremony_text_valid(
		    grant->key_id, sizeof(grant->key_id)) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    grant->recipient_id, sizeof(grant->recipient_id)) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    grant->namespace_id, sizeof(grant->namespace_id)) ||
	    grant->key_epoch == 0U ||
	    grant->policy_epoch == 0U ||
	    grant->issued_at_ms == 0U ||
	    grant->expires_at_ms <= grant->issued_at_ms ||
	    grant->maximum_uses == 0U ||
	    grant->use_count > grant->maximum_uses ||
	    grant->permissions == 0U ||
	    pqcp_sovereign_ceremony_digest_zero(
		    grant->recipient_binding) ||
	    pqcp_sovereign_ceremony_digest_zero(
		    grant->wrapped_secret_digest) ||
	    !grant_state_valid(grant->state)) {
		return false;
	}
	if (grant->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
	    grant->use_count >= grant->maximum_uses) {
		return false;
	}
	if (grant->state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED &&
	    grant->use_count < grant->maximum_uses) {
		return false;
	}
	return true;
}

int pqcp_sovereign_secret_distributor_init(
	struct pqcp_sovereign_secret_distributor *distributor,
	struct pqcp_sovereign_secret_grant *grants,
	size_t capacity)
{
	if (distributor == NULL || grants == NULL ||
	    capacity == 0U || capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(distributor, 0, sizeof(*distributor));
	memset(grants, 0, capacity * sizeof(*grants));
	distributor->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	distributor->grants = grants;
	distributor->capacity = capacity;
	distributor->next_grant_id = 1U;
	k_mutex_init(&distributor->lock);
	distributor->initialized = true;
	return 0;
}

int pqcp_sovereign_secret_grant_issue(
	struct pqcp_sovereign_secret_distributor *distributor,
	const char *key_id,
	const char *recipient_id,
	const char *namespace_id,
	uint64_t key_epoch,
	uint64_t policy_epoch,
	uint32_t permissions,
	const uint8_t recipient_binding[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t wrapped_secret_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t maximum_uses,
	struct pqcp_sovereign_secret_grant **grant)
{
	struct pqcp_sovereign_secret_grant staged;
	uint8_t computed[PQCP_SOVEREIGN_DIGEST_BYTES];
	int slot;
	int ret;

	if (grant == NULL) {
		return -EINVAL;
	}
	*grant = NULL;
	if (!pqcp_sovereign_ceremony_text_valid(
		    key_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    recipient_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    namespace_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    key_epoch == 0U || policy_epoch == 0U ||
	    permissions == 0U ||
	    recipient_binding == NULL ||
	    wrapped_secret_digest == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(
		    recipient_binding) ||
	    pqcp_sovereign_ceremony_digest_zero(
		    wrapped_secret_digest) ||
	    now_ms == 0U || expires_at_ms <= now_ms ||
	    maximum_uses == 0U) {
		return -EINVAL;
	}
	ret = lock_distributor(distributor);
	if (ret != 0) {
		return ret;
	}
	if (distributor->next_grant_id == 0U ||
	    distributor->next_grant_id == UINT64_MAX) {
		distributor->denial_count++;
		unlock_distributor(distributor);
		return -EOVERFLOW;
	}
	if (equivalent_active_grant_locked(
		    distributor, key_id, recipient_id, namespace_id,
		    key_epoch, permissions, recipient_binding) >= 0) {
		distributor->denial_count++;
		unlock_distributor(distributor);
		return -EALREADY;
	}
	slot = free_grant_index_locked(distributor);
	if (slot < 0) {
		distributor->denial_count++;
		unlock_distributor(distributor);
		return slot;
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.grant_id = distributor->next_grant_id++;
	ret = pqcp_sovereign_ceremony_copy_text(
		staged.key_id, sizeof(staged.key_id), key_id);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.recipient_id,
			sizeof(staged.recipient_id), recipient_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.namespace_id,
			sizeof(staged.namespace_id), namespace_id);
	}
	if (ret != 0) {
		distributor->denial_count++;
		unlock_distributor(distributor);
		return ret;
	}
	staged.key_epoch = key_epoch;
	staged.policy_epoch = policy_epoch;
	staged.issued_at_ms = now_ms;
	staged.expires_at_ms = expires_at_ms;
	staged.maximum_uses = maximum_uses;
	staged.permissions = permissions;
	memcpy(staged.recipient_binding, recipient_binding,
	       sizeof(staged.recipient_binding));
	memcpy(staged.wrapped_secret_digest, wrapped_secret_digest,
	       sizeof(staged.wrapped_secret_digest));
	staged.state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	staged.occupied = true;
	ret = secret_grant_digest(&staged, computed);
	if (ret != 0 ||
	    pqcp_sovereign_ceremony_digest_zero(computed)) {
		distributor->denial_count++;
		pqcp_runtime_secure_zero(computed, sizeof(computed));
		unlock_distributor(distributor);
		return ret != 0 ? ret : -EBADMSG;
	}
	distributor->grants[slot] = staged;
	if (distributor->issue_count != UINT64_MAX) {
		distributor->issue_count++;
	}
	*grant = &distributor->grants[slot];
	pqcp_runtime_secure_zero(computed, sizeof(computed));
	unlock_distributor(distributor);
	return 0;
}

int pqcp_sovereign_secret_grant_authorize(
	struct pqcp_sovereign_secret_distributor *distributor,
	uint64_t grant_id,
	const char *recipient_id,
	const char *namespace_id,
	uint64_t key_epoch,
	uint64_t policy_epoch,
	uint32_t permissions,
	const uint8_t recipient_binding[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_sovereign_secret_grant *grant;
	int index;
	int ret;

	if (grant_id == 0U ||
	    !pqcp_sovereign_ceremony_text_valid(
		    recipient_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    namespace_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    key_epoch == 0U || policy_epoch == 0U ||
	    permissions == 0U ||
	    recipient_binding == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(
		    recipient_binding) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_distributor(distributor);
	if (ret != 0) {
		return ret;
	}
	index = grant_index_locked(distributor, grant_id);
	if (index < 0) {
		distributor->denial_count++;
		unlock_distributor(distributor);
		return index;
	}
	grant = &distributor->grants[index];
	if (grant->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		distributor->denial_count++;
		unlock_distributor(distributor);
		return grant->state ==
		       PQCP_SOVEREIGN_LIFECYCLE_REVOKED ?
		       -EACCES : -EALREADY;
	}
	if (now_ms < grant->issued_at_ms) {
		distributor->denial_count++;
		unlock_distributor(distributor);
		return -EINVAL;
	}
	if (now_ms >= grant->expires_at_ms) {
		grant->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		distributor->denial_count++;
		unlock_distributor(distributor);
		return -ETIMEDOUT;
	}
	if (strcmp(grant->recipient_id, recipient_id) != 0 ||
	    strcmp(grant->namespace_id, namespace_id) != 0 ||
	    grant->key_epoch != key_epoch ||
	    grant->policy_epoch != policy_epoch ||
	    (permissions & grant->permissions) != permissions ||
	    !pqcp_sovereign_ceremony_digest_equal(
		    grant->recipient_binding, recipient_binding)) {
		distributor->denial_count++;
		unlock_distributor(distributor);
		return -EACCES;
	}
	if (grant->use_count >= grant->maximum_uses) {
		grant->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		distributor->denial_count++;
		unlock_distributor(distributor);
		return -EACCES;
	}
	grant->use_count++;
	if (grant->use_count == grant->maximum_uses) {
		grant->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
	}
	unlock_distributor(distributor);
	return 0;
}

int pqcp_sovereign_secret_grant_revoke(
	struct pqcp_sovereign_secret_distributor *distributor,
	uint64_t grant_id)
{
	struct pqcp_sovereign_secret_grant *grant;
	int index;
	int ret;

	ret = lock_distributor(distributor);
	if (ret != 0) {
		return ret;
	}
	index = grant_index_locked(distributor, grant_id);
	if (index < 0) {
		unlock_distributor(distributor);
		return index;
	}
	grant = &distributor->grants[index];
	if (grant->state == PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
		unlock_distributor(distributor);
		return -EALREADY;
	}
	grant->state = PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	unlock_distributor(distributor);
	return 0;
}

int pqcp_sovereign_secret_grant_tick(
	struct pqcp_sovereign_secret_distributor *distributor,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t count = 0U;
	size_t index;
	int ret;

	if (now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	*expired_count = 0U;
	ret = lock_distributor(distributor);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < distributor->capacity; ++index) {
		struct pqcp_sovereign_secret_grant *grant =
			&distributor->grants[index];

		if (grant->occupied &&
		    grant->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
		    now_ms >= grant->expires_at_ms) {
			grant->state =
				PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
			if (count != UINT32_MAX) {
				count++;
			}
		}
	}
	*expired_count = count;
	unlock_distributor(distributor);
	return 0;
}

int pqcp_sovereign_secret_distributor_audit(
	struct pqcp_sovereign_secret_distributor *distributor)
{
	uint64_t maximum_id = 0U;
	size_t left;
	size_t right;
	int ret;

	ret = lock_distributor(distributor);
	if (ret != 0) {
		return ret;
	}
	if (distributor->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    distributor->grants == NULL ||
	    distributor->capacity == 0U ||
	    distributor->next_grant_id == 0U) {
		unlock_distributor(distributor);
		return -EBADMSG;
	}
	for (left = 0U; left < distributor->capacity; ++left) {
		const struct pqcp_sovereign_secret_grant *grant =
			&distributor->grants[left];

		if (!grant->occupied) {
			continue;
		}
		if (!grant_shape_valid(grant)) {
			unlock_distributor(distributor);
			return -EBADMSG;
		}
		if (grant->grant_id > maximum_id) {
			maximum_id = grant->grant_id;
		}
		for (right = left + 1U;
		     right < distributor->capacity; ++right) {
			const struct pqcp_sovereign_secret_grant *other =
				&distributor->grants[right];

			if (other->occupied &&
			    other->grant_id == grant->grant_id) {
				unlock_distributor(distributor);
				return -EBADMSG;
			}
		}
	}
	if (maximum_id != 0U &&
	    distributor->next_grant_id <= maximum_id) {
		unlock_distributor(distributor);
		return -EBADMSG;
	}
	unlock_distributor(distributor);
	return 0;
}

static int lock_reference_store(
	struct pqcp_sovereign_secret_reference_store_internal *store)
{
	if (store == NULL || !store->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&store->lock, K_FOREVER);
}

static void unlock_reference_store(
	struct pqcp_sovereign_secret_reference_store_internal *store)
{
	(void)k_mutex_unlock(&store->lock);
}

static int reference_index_locked(
	const struct pqcp_sovereign_secret_reference_store_internal *store,
	uint64_t grant_id)
{
	size_t index;

	for (index = 0U; index < store->capacity; ++index) {
		if (store->references[index].occupied &&
		    store->references[index].grant_id == grant_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_reference_index_locked(
	const struct pqcp_sovereign_secret_reference_store_internal *store)
{
	size_t index;

	for (index = 0U; index < store->capacity; ++index) {
		if (!store->references[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int reference_digest(
	const struct pqcp_sovereign_secret_reference_internal *reference,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_SECRET_GRANT_BYTES];
	size_t offset = 0U;
	int ret;

	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, SECRET_REFERENCE_DOMAIN,
		sizeof(SECRET_REFERENCE_DOMAIN));
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, reference->grant_id);
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, reference->tenant_id,
		sizeof(reference->tenant_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, reference->recipient_id,
		sizeof(reference->recipient_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, reference->namespace_id,
		sizeof(reference->namespace_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, reference->key_id,
		sizeof(reference->key_id));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, reference->key_handle.slot);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		reference->key_handle.generation);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		(uint32_t)reference->key_handle.backend);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		(uint32_t)reference->key_handle.family);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, reference->key_handle.level);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, reference->key_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, reference->policy_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, reference->issued_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, reference->expires_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, reference->permissions);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		reference->recipient_binding,
		sizeof(reference->recipient_binding));
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_sovereign_ceremony_hash(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_sovereign_secret_reference_store_init_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store,
	struct pqcp_sovereign_secret_distributor *distributor,
	struct pqcp_sovereign_secret_reference_internal *references,
	size_t capacity,
	struct pqcp_runtime_key_store *key_store,
	struct pqcp_sovereign_custody_ledger *custody)
{
	if (store == NULL || distributor == NULL ||
	    !distributor->initialized || references == NULL ||
	    capacity == 0U || key_store == NULL ||
	    custody == NULL || !custody->initialized) {
		return -EINVAL;
	}
	memset(store, 0, sizeof(*store));
	memset(references, 0, capacity * sizeof(*references));
	store->distributor = distributor;
	store->references = references;
	store->capacity = capacity;
	store->key_store = key_store;
	store->custody = custody;
	k_mutex_init(&store->lock);
	store->initialized = true;
	return 0;
}

int pqcp_sovereign_secret_reference_bind_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store,
	uint64_t grant_id,
	const char *tenant_id,
	const struct pqcp_runtime_key_handle *key_handle,
	uint64_t now_ms)
{
	struct pqcp_sovereign_secret_reference_internal staged;
	struct pqcp_runtime_key_metadata metadata;
	struct pqcp_sovereign_secret_grant grant;
	int grant_index;
	int slot;
	int ret;

	if (grant_id == 0U ||
	    !pqcp_sovereign_ceremony_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    key_handle == NULL ||
	    !pqcp_runtime_key_handle_is_valid(key_handle) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_key_store_metadata(
		store->key_store, key_handle, &metadata);
	if (ret != 0 || !metadata.active ||
	    metadata.expires_at_ms <= now_ms ||
	    metadata.custody == PQCP_RUNTIME_CUSTODY_NONE) {
		return ret != 0 ? ret : -EACCES;
	}
	ret = lock_distributor(store->distributor);
	if (ret != 0) {
		return ret;
	}
	grant_index = grant_index_locked(
		store->distributor, grant_id);
	if (grant_index < 0) {
		unlock_distributor(store->distributor);
		return grant_index;
	}
	grant = store->distributor->grants[grant_index];
	unlock_distributor(store->distributor);
	if (grant.state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
	    grant.expires_at_ms <= now_ms ||
	    strcmp(metadata.owner, tenant_id) != 0) {
		return -EACCES;
	}
	ret = lock_reference_store(store);
	if (ret != 0) {
		return ret;
	}
	if (reference_index_locked(store, grant_id) >= 0) {
		unlock_reference_store(store);
		return -EALREADY;
	}
	slot = free_reference_index_locked(store);
	if (slot < 0) {
		unlock_reference_store(store);
		return slot;
	}
	memset(&staged, 0, sizeof(staged));
	staged.grant_id = grant_id;
	ret = pqcp_sovereign_ceremony_copy_text(
		staged.tenant_id, sizeof(staged.tenant_id), tenant_id);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.recipient_id,
			sizeof(staged.recipient_id), grant.recipient_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.namespace_id,
			sizeof(staged.namespace_id), grant.namespace_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.key_id, sizeof(staged.key_id),
			grant.key_id);
	}
	if (ret != 0) {
		unlock_reference_store(store);
		return ret;
	}
	staged.key_handle = *key_handle;
	staged.key_epoch = grant.key_epoch;
	staged.policy_epoch = grant.policy_epoch;
	staged.issued_at_ms = grant.issued_at_ms;
	staged.expires_at_ms = grant.expires_at_ms;
	staged.permissions = grant.permissions;
	memcpy(staged.recipient_binding, grant.recipient_binding,
	       sizeof(staged.recipient_binding));
	staged.occupied = true;
	ret = reference_digest(
		&staged, staged.reference_digest);
	if (ret != 0) {
		unlock_reference_store(store);
		return ret;
	}
	ret = pqcp_sovereign_custody_append(
		store->custody, staged.key_id, staged.recipient_id,
		"secret-granted", staged.key_epoch,
		grant.policy_epoch, staged.reference_digest, now_ms,
		NULL);
	if (ret == 0) {
		store->references[slot] = staged;
	}
	unlock_reference_store(store);
	return ret;
}

int pqcp_sovereign_secret_reference_authorize_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store,
	uint64_t grant_id,
	const char *tenant_id,
	const char *recipient_id,
	const char *namespace_id,
	uint64_t key_epoch,
	uint64_t policy_epoch,
	uint32_t permissions,
	const uint8_t recipient_binding[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_runtime_key_handle *key_handle)
{
	struct pqcp_sovereign_secret_reference_internal reference;
	struct pqcp_runtime_key_metadata metadata;
	int index;
	int ret;

	if (key_handle == NULL ||
	    !pqcp_sovereign_ceremony_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS)) {
		return -EINVAL;
	}
	memset(key_handle, 0, sizeof(*key_handle));
	ret = lock_reference_store(store);
	if (ret != 0) {
		return ret;
	}
	index = reference_index_locked(store, grant_id);
	if (index < 0) {
		unlock_reference_store(store);
		return index;
	}
	reference = store->references[index];
	if (strcmp(reference.tenant_id, tenant_id) != 0 ||
	    strcmp(reference.recipient_id, recipient_id) != 0 ||
	    strcmp(reference.namespace_id, namespace_id) != 0 ||
	    reference.key_epoch != key_epoch ||
	    (permissions & reference.permissions) != permissions ||
	    !pqcp_sovereign_ceremony_digest_equal(
		    reference.recipient_binding,
		    recipient_binding) ||
	    now_ms >= reference.expires_at_ms) {
		unlock_reference_store(store);
		return -EACCES;
	}
	unlock_reference_store(store);
	ret = pqcp_sovereign_secret_grant_authorize(
		store->distributor, grant_id, recipient_id,
		namespace_id, key_epoch, policy_epoch, permissions,
		recipient_binding, now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_key_store_metadata(
		store->key_store, &reference.key_handle, &metadata);
	if (ret != 0 || !metadata.active ||
	    metadata.expires_at_ms <= now_ms ||
	    strcmp(metadata.owner, tenant_id) != 0) {
		return ret != 0 ? ret : -EACCES;
	}
	*key_handle = reference.key_handle;
	ret = pqcp_sovereign_custody_append(
		store->custody, reference.key_id, recipient_id,
		"secret-used", key_epoch, policy_epoch,
		reference.reference_digest, now_ms, NULL);
	if (ret != 0) {
		memset(key_handle, 0, sizeof(*key_handle));
		return ret;
	}
	return 0;
}

int pqcp_sovereign_secret_reference_revoke_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store,
	uint64_t grant_id,
	uint64_t now_ms)
{
	struct pqcp_sovereign_secret_reference_internal reference;
	int index;
	int ret;

	if (grant_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_reference_store(store);
	if (ret != 0) {
		return ret;
	}
	index = reference_index_locked(store, grant_id);
	if (index < 0) {
		unlock_reference_store(store);
		return index;
	}
	reference = store->references[index];
	memset(&store->references[index], 0,
	       sizeof(store->references[index]));
	unlock_reference_store(store);
	ret = pqcp_sovereign_secret_grant_revoke(
		store->distributor, grant_id);
	if (ret != 0 && ret != -EALREADY) {
		return ret;
	}
	return pqcp_sovereign_custody_append(
		store->custody, reference.key_id,
		reference.recipient_id, "secret-revoked",
		reference.key_epoch, 1U, reference.reference_digest,
		now_ms, NULL);
}

int pqcp_sovereign_secret_reference_audit_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store)
{
	uint8_t expected[PQCP_SOVEREIGN_DIGEST_BYTES];
	size_t left;
	size_t right;
	int ret;

	ret = lock_reference_store(store);
	if (ret != 0) {
		return ret;
	}
	if (store->distributor == NULL ||
	    !store->distributor->initialized ||
	    store->references == NULL || store->capacity == 0U ||
	    store->key_store == NULL || store->custody == NULL ||
	    !store->custody->initialized) {
		unlock_reference_store(store);
		return -EBADMSG;
	}
	for (left = 0U; left < store->capacity; ++left) {
		const struct pqcp_sovereign_secret_reference_internal *entry =
			&store->references[left];
		struct pqcp_runtime_key_metadata metadata;

		if (!entry->occupied) {
			continue;
		}
		if (entry->grant_id == 0U ||
		    !pqcp_sovereign_ceremony_text_valid(
			    entry->tenant_id,
			    sizeof(entry->tenant_id)) ||
		    !pqcp_sovereign_ceremony_text_valid(
			    entry->recipient_id,
			    sizeof(entry->recipient_id)) ||
		    !pqcp_sovereign_ceremony_text_valid(
			    entry->namespace_id,
			    sizeof(entry->namespace_id)) ||
		    !pqcp_sovereign_ceremony_text_valid(
			    entry->key_id, sizeof(entry->key_id)) ||
		    !pqcp_runtime_key_handle_is_valid(
			    &entry->key_handle) ||
		    entry->key_epoch == 0U ||
		    entry->expires_at_ms <= entry->issued_at_ms ||
		    entry->permissions == 0U ||
		    pqcp_sovereign_ceremony_digest_zero(
			    entry->recipient_binding) ||
		    reference_digest(entry, expected) != 0 ||
		    !pqcp_sovereign_ceremony_digest_equal(
			    expected, entry->reference_digest) ||
		    pqcp_runtime_key_store_metadata(
			    store->key_store, &entry->key_handle,
			    &metadata) != 0 ||
		    !metadata.active ||
		    strcmp(metadata.owner, entry->tenant_id) != 0) {
			pqcp_runtime_secure_zero(
				expected, sizeof(expected));
			unlock_reference_store(store);
			return -EBADMSG;
		}
		for (right = left + 1U;
		     right < store->capacity; ++right) {
			if (store->references[right].occupied &&
			    store->references[right].grant_id ==
				    entry->grant_id) {
				pqcp_runtime_secure_zero(
					expected, sizeof(expected));
				unlock_reference_store(store);
				return -EBADMSG;
			}
		}
	}
	pqcp_runtime_secure_zero(expected, sizeof(expected));
	unlock_reference_store(store);
	ret = pqcp_sovereign_secret_distributor_audit(
		store->distributor);
	if (ret != 0) {
		return ret;
	}
	return pqcp_sovereign_custody_verify(store->custody);
}
