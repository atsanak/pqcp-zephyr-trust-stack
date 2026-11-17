/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Retained immutable object versions and controlled restore.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int free_version_index(
	const struct pqcp_edge_vault_version_store *store,
	uint64_t now_ms)
{
	int oldest = -1;
	uint64_t oldest_expiry = UINT64_MAX;

	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		if (!store->versions[index].occupied) {
			return (int)index;
		}
		/* Only an already expired version may be evicted. */
		if (store->versions[index].expires_at_ms <= now_ms &&
		    store->versions[index].expires_at_ms <
			    oldest_expiry) {
			oldest_expiry =
				store->versions[index].expires_at_ms;
			oldest = (int)index;
		}
	}
	return oldest >= 0 ? oldest : -ENOSPC;
}

static int version_index(
	const struct pqcp_edge_vault_version_store *store,
	const char *object_id,
	uint64_t object_version)
{
	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		if (store->versions[index].occupied &&
		    store->versions[index].object_version ==
			    object_version &&
		    strcmp(store->versions[index].object_id,
			   object_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int object_index(
	const struct pqcp_edge_vault_store *store,
	const char *object_id)
{
	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		if (store->objects[index].occupied &&
		    strcmp(store->objects[index].object_id,
			   object_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

int pqcp_edge_vault_version_store_init(
	struct pqcp_edge_vault_version_store *store,
	struct pqcp_edge_vault_version *versions,
	size_t capacity)
{
	if (store == NULL || versions == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(store, 0, sizeof(*store));
	memset(versions, 0,
	       capacity * sizeof(*versions));
	store->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	store->versions = versions;
	store->capacity = capacity;
	store->next_version_id = 1U;
	k_mutex_init(&store->lock);
	store->initialized = true;
	return 0;
}

int pqcp_edge_vault_version_capture(
	struct pqcp_edge_vault_version_store *store,
	const struct pqcp_edge_vault_object *object,
	uint64_t now_ms,
	uint64_t retention_ms)
{
	struct pqcp_edge_vault_version candidate;
	int index;

	if (store == NULL || !store->initialized ||
	    object == NULL || !object->occupied ||
	    object->value_length == 0U ||
	    object->value_length >
		    PQCP_EDGE_VAULT_VALUE_MAX_BYTES ||
	    retention_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	if (version_index(
		    store, object->object_id,
		    object->version) >= 0) {
		k_mutex_unlock(&store->lock);
		return -EALREADY;
	}
	index = free_version_index(store, now_ms);
	if (index < 0) {
		k_mutex_unlock(&store->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.version_id =
		pqcp_edge_internal_next_identifier(
			&store->next_version_id);
	(void)pqcp_edge_internal_copy_text(
		candidate.object_id,
		sizeof(candidate.object_id),
		object->object_id);
	candidate.object_version = object->version;
	candidate.created_at_ms = now_ms;
	candidate.expires_at_ms =
		pqcp_edge_internal_saturating_add_u64(
			now_ms, retention_ms);
	memcpy(candidate.value, object->value,
	       object->value_length);
	candidate.value_length = object->value_length;
	memcpy(candidate.value_digest,
	       object->value_digest,
	       sizeof(candidate.value_digest));
	candidate.occupied = true;
	store->versions[index] = candidate;
	++store->captured_count;
	k_mutex_unlock(&store->lock);
	return 0;
}

int pqcp_edge_vault_version_restore(
	struct pqcp_edge_vault_version_store *versions,
	struct pqcp_edge_vault_store *objects,
	const char *object_id,
	uint64_t object_version,
	uint64_t now_ms)
{
	struct pqcp_edge_vault_object candidate;
	const struct pqcp_edge_vault_version *version;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int version_slot;
	int object_slot;
	int ret;

	if (versions == NULL || !versions->initialized ||
	    objects == NULL || !objects->initialized ||
	    object_id == NULL || object_version == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&versions->lock, K_FOREVER);
	version_slot = version_index(
		versions, object_id, object_version);
	if (version_slot < 0) {
		k_mutex_unlock(&versions->lock);
		return version_slot;
	}
	version = &versions->versions[version_slot];
	if (version->expires_at_ms <= now_ms) {
		k_mutex_unlock(&versions->lock);
		return -EKEYEXPIRED;
	}
	k_mutex_lock(&objects->lock, K_FOREVER);
	object_slot = object_index(objects, object_id);
	if (object_slot < 0) {
		ret = object_slot;
		goto out;
	}
	if (objects->objects[object_slot].state ==
	    PQCP_EDGE_VAULT_QUARANTINED) {
		ret = -EACCES;
		goto out;
	}
	/* The retained value must still match its digest before it can be
	 * written back into the live object.
	 */
	if (version->value_length == 0U ||
	    version->value_length > sizeof(version->value) ||
	    pqcp_edge_internal_sha256(
		    version->value, version->value_length,
		    digest) != 0 ||
	    !pqcp_edge_internal_equal(
		    digest, version->value_digest,
		    sizeof(digest))) {
		ret = -EBADMSG;
		goto out;
	}
	candidate = objects->objects[object_slot];
	if (candidate.version == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	pqcp_runtime_secure_zero(
		candidate.value, sizeof(candidate.value));
	memcpy(candidate.value, version->value,
	       version->value_length);
	candidate.value_length = version->value_length;
	memcpy(candidate.value_digest,
	       version->value_digest,
	       sizeof(candidate.value_digest));
	++candidate.version;
	candidate.updated_at_ms = now_ms;
	candidate.state = PQCP_EDGE_VAULT_ACTIVE;
	ret = pqcp_edge_internal_object_digest(
		&candidate, candidate.object_digest);
	if (ret == 0) {
		objects->objects[object_slot] = candidate;
		++objects->update_count;
	}
out:
	k_mutex_unlock(&objects->lock);
	k_mutex_unlock(&versions->lock);
	return ret;
}

int pqcp_edge_vault_version_prune(
	struct pqcp_edge_vault_version_store *store,
	uint64_t now_ms,
	uint32_t *pruned_count)
{
	uint32_t pruned = 0U;

	if (store == NULL || !store->initialized ||
	    pruned_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		if (store->versions[index].occupied &&
		    store->versions[index].expires_at_ms <=
			    now_ms) {
			pqcp_runtime_secure_zero(
				&store->versions[index],
				sizeof(store->versions[index]));
			++pruned;
		}
	}
	store->pruned_count =
		pqcp_edge_internal_saturating_add_u64(
			store->pruned_count, pruned);
	k_mutex_unlock(&store->lock);
	*pruned_count = pruned;
	return 0;
}

int pqcp_edge_vault_version_store_audit(
	struct pqcp_edge_vault_version_store *store)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    store->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    store->versions == NULL || store->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < store->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_vault_version *version =
			&store->versions[index];

		if (!version->occupied) {
			continue;
		}
		if (version->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    version->version_id == 0U ||
		    version->object_version == 0U ||
		    !pqcp_edge_internal_text_valid(
			    version->object_id,
			    sizeof(version->object_id)) ||
		    version->value_length == 0U ||
		    version->value_length >
			    sizeof(version->value) ||
		    version->expires_at_ms <=
			    version->created_at_ms ||
		    pqcp_edge_internal_sha256(
			    version->value,
			    version->value_length, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    digest, version->value_digest,
			    sizeof(digest))) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&store->lock);
	return ret;
}
