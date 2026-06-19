/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Common key-store dispatch and invariants.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_key_store.h>

#include "runtime_internal.h"

static bool ops_complete(const struct pqcp_runtime_key_store_ops *ops)
{
	return ops != NULL &&
	       ops->create != NULL &&
	       ops->generate != NULL &&
	       ops->metadata != NULL &&
	       ops->acquire != NULL &&
	       ops->release != NULL &&
	       ops->export_public != NULL &&
	       ops->rotate != NULL &&
	       ops->destroy != NULL &&
	       ops->expire != NULL &&
	       ops->audit != NULL;
}

static bool request_valid(
	const struct pqcp_runtime_key_request *request)
{
	if (request == NULL ||
	    !pqcp_runtime_internal_key_family_valid(request->family) ||
	    !pqcp_runtime_internal_level_valid(
		    request->family, request->level) ||
	    !pqcp_runtime_internal_usage_valid(request->usage) ||
	    !pqcp_runtime_internal_owner_valid(request->owner) ||
	    !pqcp_runtime_internal_label_valid(request->label) ||
	    request->now_ms == 0U ||
	    (request->expires_at_ms != 0U &&
	     request->expires_at_ms <= request->now_ms)) {
		return false;
	}
	switch (request->family) {
	case PQCP_RUNTIME_KEY_MLKEM_PUBLIC:
		return (request->usage &
			(PQCP_RUNTIME_USAGE_ENCAPSULATE |
			 PQCP_RUNTIME_USAGE_EXPORT_PUBLIC)) != 0U;
	case PQCP_RUNTIME_KEY_MLKEM_KEYPAIR:
		return (request->usage &
			PQCP_RUNTIME_USAGE_DECAPSULATE) != 0U;
	case PQCP_RUNTIME_KEY_MLDSA_PUBLIC:
		return (request->usage &
			(PQCP_RUNTIME_USAGE_VERIFY |
			 PQCP_RUNTIME_USAGE_EXPORT_PUBLIC)) != 0U;
	case PQCP_RUNTIME_KEY_MLDSA_KEYPAIR:
		return (request->usage &
			PQCP_RUNTIME_USAGE_SIGN) != 0U;
	case PQCP_RUNTIME_KEY_SHARED_SECRET:
	case PQCP_RUNTIME_KEY_AEAD:
		return (request->usage &
			PQCP_RUNTIME_USAGE_DERIVE) != 0U;
	default:
		return false;
	}
}

int pqcp_runtime_key_store_init(
	struct pqcp_runtime_key_store *store,
	enum pqcp_runtime_key_backend backend,
	const struct pqcp_runtime_key_store_ops *ops,
	void *context,
	uint32_t capacity)
{
	if (store == NULL ||
	    !pqcp_runtime_internal_key_backend_valid(backend) ||
	    !ops_complete(ops) ||
	    context == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(store, 0, sizeof(*store));
	store->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	store->backend = backend;
	store->ops = ops;
	store->context = context;
	store->capacity = capacity;
	store->generation_seed = 1U;
	k_mutex_init(&store->lock);
	return 0;
}

int pqcp_runtime_key_store_validate(
	const struct pqcp_runtime_key_store *store)
{
	if (store == NULL ||
	    store->schema_version != PQCP_RUNTIME_SCHEMA_VERSION ||
	    !pqcp_runtime_internal_key_backend_valid(store->backend) ||
	    !ops_complete(store->ops) ||
	    store->context == NULL ||
	    store->capacity == 0U ||
	    store->active_count > store->capacity ||
	    store->generation_seed == 0U ||
	    store->destroy_count > store->create_count) {
		return -EINVAL;
	}
	return 0;
}

static int lock_store(struct pqcp_runtime_key_store *store)
{
	if (pqcp_runtime_key_store_validate(store) != 0) {
		return -EINVAL;
	}
	return k_mutex_lock(&store->lock, K_FOREVER);
}

static void unlock_store(struct pqcp_runtime_key_store *store)
{
	(void)k_mutex_unlock(&store->lock);
}

int pqcp_runtime_key_store_create(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_request *request,
	const uint8_t *public_data,
	size_t public_length,
	const uint8_t *secret_data,
	size_t secret_length,
	struct pqcp_runtime_key_handle *handle)
{
	int ret;

	if (!request_valid(request) || handle == NULL ||
	    (public_data == NULL && public_length != 0U) ||
	    (secret_data == NULL && secret_length != 0U)) {
		return -EINVAL;
	}
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->create(
		store, request, public_data, public_length,
		secret_data, secret_length, handle);
	if (ret == 0) {
		store->create_count++;
		store->active_count++;
	} else {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_generate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_request *request,
	struct pqcp_runtime_key_handle *handle)
{
	int ret;

	if (!request_valid(request) || handle == NULL) {
		return -EINVAL;
	}
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->generate(store, request, handle);
	if (ret == 0) {
		store->create_count++;
		store->active_count++;
	} else {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_metadata(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	struct pqcp_runtime_key_metadata *metadata)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    metadata == NULL) {
		return -EINVAL;
	}
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->metadata(store, handle, metadata);
	if (ret != 0) {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_acquire(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	uint32_t required_usage,
	uint64_t now_ms,
	const uint8_t **public_data,
	size_t *public_length,
	const uint8_t **secret_data,
	size_t *secret_length)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    !pqcp_runtime_internal_usage_valid(required_usage) ||
	    now_ms == 0U || public_data == NULL ||
	    public_length == NULL || secret_data == NULL ||
	    secret_length == NULL) {
		return -EINVAL;
	}
	*public_data = NULL;
	*public_length = 0U;
	*secret_data = NULL;
	*secret_length = 0U;
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->acquire(
		store, handle, required_usage, now_ms,
		public_data, public_length,
		secret_data, secret_length);
	if (ret != 0) {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_release(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle)) {
		return -EINVAL;
	}
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->release(store, handle);
	if (ret != 0) {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_export_public(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    output == NULL || output_length == NULL) {
		return -EINVAL;
	}
	*output_length = 0U;
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->export_public(
		store, handle, output,
		output_capacity, output_length);
	if (ret != 0) {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_rotate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *old_handle,
	const struct pqcp_runtime_key_request *request,
	struct pqcp_runtime_key_handle *new_handle)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(old_handle) ||
	    !request_valid(request) || new_handle == NULL) {
		return -EINVAL;
	}
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->rotate(
		store, old_handle, request, new_handle);
	if (ret == 0) {
		store->create_count++;
		store->destroy_count++;
	} else {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_destroy(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle)) {
		return -EINVAL;
	}
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->destroy(store, handle);
	if (ret == 0) {
		if (store->active_count != 0U) {
			store->active_count--;
		}
		store->destroy_count++;
	} else {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_expire(
	struct pqcp_runtime_key_store *store,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret;

	if (now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->expire(store, now_ms, &expired);
	if (ret == 0) {
		if (expired > store->active_count) {
			ret = -EBADMSG;
		} else {
			store->active_count -= expired;
			store->destroy_count += expired;
			*expired_count = expired;
		}
	} else {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_audit(
	struct pqcp_runtime_key_store *store)
{
	int ret = lock_store(store);

	if (ret != 0) {
		return ret;
	}
	ret = store->ops->audit(store);
	unlock_store(store);
	return ret;
}
