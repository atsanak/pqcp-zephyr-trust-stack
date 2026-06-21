/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Optimistic-concurrency confidential object store.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool state_valid(
	enum pqcp_edge_vault_object_state state)
{
	return state >= PQCP_EDGE_VAULT_EMPTY &&
	       state <= PQCP_EDGE_VAULT_QUARANTINED;
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

static int free_object_index(
	const struct pqcp_edge_vault_store *store)
{
	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		if (!store->objects[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool object_shape_valid(
	const struct pqcp_edge_vault_object *object)
{
	return object != NULL &&
	       pqcp_edge_internal_text_valid(
		       object->object_id,
		       sizeof(object->object_id)) &&
	       pqcp_edge_internal_text_valid(
		       object->namespace_id,
		       sizeof(object->namespace_id)) &&
	       pqcp_edge_internal_text_valid(
		       object->owner_id,
		       sizeof(object->owner_id)) &&
	       pqcp_edge_internal_text_valid(
		       object->classification,
		       sizeof(object->classification)) &&
	       object->version != 0U &&
	       object->policy_epoch != 0U &&
	       object->permissions != 0U &&
	       object->value_length != 0U &&
	       object->value_length <=
		       sizeof(object->value) &&
	       state_valid(object->state);
}

static int refresh_digests(
	struct pqcp_edge_vault_object *object)
{
	int ret;

	ret = pqcp_edge_internal_sha256(
		object->value, object->value_length,
		object->value_digest);
	if (ret == 0) {
		ret = pqcp_edge_internal_object_digest(
			object, object->object_digest);
	}
	return ret;
}

static int object_integrity(
	const struct pqcp_edge_vault_object *object)
{
	uint8_t value_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t object_digest[PQCP_EDGE_DIGEST_BYTES];
	int ret;

	ret = pqcp_edge_internal_sha256(
		object->value, object->value_length,
		value_digest);
	if (ret == 0 &&
	    !pqcp_edge_internal_equal(
		    value_digest, object->value_digest,
		    sizeof(value_digest))) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_edge_internal_object_digest(
			object, object_digest);
	}
	if (ret == 0 &&
	    !pqcp_edge_internal_equal(
		    object_digest, object->object_digest,
		    sizeof(object_digest))) {
		ret = -EBADMSG;
	}
	return ret;
}

int pqcp_edge_vault_store_init(
	struct pqcp_edge_vault_store *store,
	struct pqcp_edge_vault_object *objects,
	size_t capacity)
{
	if (store == NULL || objects == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(store, 0, sizeof(*store));
	memset(objects, 0, capacity * sizeof(*objects));
	store->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	store->objects = objects;
	store->capacity = capacity;
	store->next_generation = 1U;
	k_mutex_init(&store->lock);
	store->initialized = true;
	return 0;
}

int pqcp_edge_vault_create(
	struct pqcp_edge_vault_store *store,
	const struct pqcp_edge_vault_object *object,
	uint64_t now_ms)
{
	struct pqcp_edge_vault_object candidate;
	int index;
	int ret;

	if (store == NULL || !store->initialized ||
	    !object_shape_valid(object) ||
	    object->created_at_ms > now_ms ||
	    (object->expires_at_ms != 0U &&
	     object->expires_at_ms <= now_ms)) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	if (object_index(store, object->object_id) >= 0) {
		++store->rejection_count;
		k_mutex_unlock(&store->lock);
		return -EEXIST;
	}
	index = free_object_index(store);
	if (index < 0) {
		++store->rejection_count;
		k_mutex_unlock(&store->lock);
		return index;
	}
	candidate = *object;
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.generation =
		pqcp_edge_internal_next_generation(
			&store->next_generation);
	candidate.version = 1U;
	candidate.created_at_ms = now_ms;
	candidate.updated_at_ms = now_ms;
	if (candidate.state == PQCP_EDGE_VAULT_EMPTY ||
	    candidate.state ==
		    PQCP_EDGE_VAULT_TOMBSTONED) {
		candidate.state = PQCP_EDGE_VAULT_ACTIVE;
	}
	candidate.occupied = true;
	ret = refresh_digests(&candidate);
	if (ret == 0) {
		store->objects[index] = candidate;
		++store->create_count;
	} else {
		++store->rejection_count;
	}
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_vault_read(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	uint64_t now_ms)
{
	struct pqcp_edge_vault_object *object;
	int index;
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    object_id == NULL || output == NULL ||
	    output_length == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	index = object_index(store, object_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	object = &store->objects[index];
	if (object->state ==
		    PQCP_EDGE_VAULT_TOMBSTONED ||
	    object->state ==
		    PQCP_EDGE_VAULT_QUARANTINED) {
		ret = -EACCES;
	} else if (object->expires_at_ms != 0U &&
		   object->expires_at_ms <= now_ms) {
		ret = -EKEYEXPIRED;
	} else if (output_capacity <
		   object->value_length) {
		ret = -ENOBUFS;
	} else {
		ret = object_integrity(object);
	}
	if (ret == 0) {
		memcpy(output, object->value,
		       object->value_length);
		*output_length = object->value_length;
	} else {
		*output_length = 0U;
	}
out:
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_vault_write(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	const uint8_t *value,
	size_t value_length,
	uint64_t expected_version,
	uint64_t now_ms)
{
	struct pqcp_edge_vault_object candidate;
	struct pqcp_edge_vault_object *object;
	int index;
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    object_id == NULL || value == NULL ||
	    value_length == 0U ||
	    value_length > PQCP_EDGE_VAULT_VALUE_MAX_BYTES ||
	    expected_version == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	index = object_index(store, object_id);
	if (index < 0) {
		ret = index;
		goto reject;
	}
	object = &store->objects[index];
	if (object->state != PQCP_EDGE_VAULT_ACTIVE) {
		ret = object->state == PQCP_EDGE_VAULT_SEALED ?
			-EROFS : -EACCES;
		goto reject;
	}
	if (object->version != expected_version) {
		ret = -ESTALE;
		goto reject;
	}
	if (object->version == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto reject;
	}
	candidate = *object;
	pqcp_runtime_secure_zero(
		candidate.value, sizeof(candidate.value));
	memcpy(candidate.value, value, value_length);
	candidate.value_length = value_length;
	++candidate.version;
	candidate.updated_at_ms = now_ms;
	ret = refresh_digests(&candidate);
	if (ret != 0) {
		goto reject;
	}
	*object = candidate;
	++store->update_count;
	goto out;
reject:
	++store->rejection_count;
out:
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_vault_seal(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	uint64_t now_ms)
{
	struct pqcp_edge_vault_object candidate;
	int index;
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    object_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	index = object_index(store, object_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	if (store->objects[index].state ==
	    PQCP_EDGE_VAULT_SEALED) {
		ret = -EALREADY;
		goto out;
	}
	if (store->objects[index].state !=
	    PQCP_EDGE_VAULT_ACTIVE) {
		ret = -EACCES;
		goto out;
	}
	candidate = store->objects[index];
	candidate.state = PQCP_EDGE_VAULT_SEALED;
	candidate.updated_at_ms = now_ms;
	ret = refresh_digests(&candidate);
	if (ret == 0) {
		store->objects[index] = candidate;
		++store->update_count;
	}
out:
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_vault_delete(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	uint64_t expected_version,
	uint64_t now_ms)
{
	struct pqcp_edge_vault_object candidate;
	int index;
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    object_id == NULL || expected_version == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	index = object_index(store, object_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	if (store->objects[index].version !=
	    expected_version) {
		ret = -ESTALE;
		goto out;
	}
	if (store->objects[index].state ==
	    PQCP_EDGE_VAULT_TOMBSTONED) {
		ret = -EALREADY;
		goto out;
	}
	candidate = store->objects[index];
	candidate.state =
		PQCP_EDGE_VAULT_TOMBSTONED;
	candidate.updated_at_ms = now_ms;
	if (candidate.version == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	++candidate.version;
	pqcp_runtime_secure_zero(
		candidate.value, sizeof(candidate.value));
	candidate.value_length = 1U;
	candidate.value[0] = 0U;
	ret = refresh_digests(&candidate);
	if (ret == 0) {
		store->objects[index] = candidate;
		++store->delete_count;
	}
out:
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_vault_find(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	struct pqcp_edge_vault_object **object)
{
	int index;
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    object_id == NULL || object == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	index = object_index(store, object_id);
	if (index < 0) {
		*object = NULL;
		ret = index;
	} else {
		*object = &store->objects[index];
	}
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_vault_tick(
	struct pqcp_edge_vault_store *store,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (store == NULL || !store->initialized ||
	    changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		struct pqcp_edge_vault_object candidate;
		struct pqcp_edge_vault_object *object =
			&store->objects[index];

		if (!object->occupied ||
		    object->state ==
			    PQCP_EDGE_VAULT_TOMBSTONED ||
		    object->expires_at_ms == 0U ||
		    object->expires_at_ms > now_ms) {
			continue;
		}
		candidate = *object;
		candidate.state =
			PQCP_EDGE_VAULT_TOMBSTONED;
		candidate.updated_at_ms = now_ms;
		if (candidate.version != UINT64_MAX) {
			++candidate.version;
		}
		pqcp_runtime_secure_zero(
			candidate.value,
			sizeof(candidate.value));
		candidate.value_length = 1U;
		if (refresh_digests(&candidate) == 0) {
			*object = candidate;
			++changed;
		}
	}
	k_mutex_unlock(&store->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_edge_vault_store_audit(
	struct pqcp_edge_vault_store *store)
{
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    store->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    store->objects == NULL || store->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < store->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_vault_object *object =
			&store->objects[index];

		if (!object->occupied) {
			continue;
		}
		if (!object_shape_valid(object) ||
		    object->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    object->generation == 0U ||
		    object_integrity(object) != 0) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < store->capacity; ++other) {
			if (store->objects[other].occupied &&
			    strcmp(
				    object->object_id,
				    store->objects[other].
					    object_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&store->lock);
	return ret;
}
