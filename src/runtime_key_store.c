/*
 * SPDX-License-Identifier: MIT
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
	       ops->sign != NULL &&
	       ops->verify != NULL &&
	       ops->encapsulate != NULL &&
	       ops->decapsulate != NULL &&
	       ops->derive != NULL &&
	       ops->mac != NULL &&
	       ops->aead_encrypt != NULL &&
	       ops->aead_decrypt != NULL &&
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
		return (request->usage &
			PQCP_RUNTIME_USAGE_DERIVE) != 0U;
	case PQCP_RUNTIME_KEY_AEAD:
		return (request->usage &
			(PQCP_RUNTIME_USAGE_ENCRYPT |
			 PQCP_RUNTIME_USAGE_DECRYPT |
			 PQCP_RUNTIME_USAGE_MAC)) != 0U;
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
	size_t *public_length)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    !pqcp_runtime_internal_usage_valid(required_usage) ||
	    now_ms == 0U || public_data == NULL ||
	    public_length == NULL) {
		return -EINVAL;
	}
	*public_data = NULL;
	*public_length = 0U;
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->acquire(
		store, handle, required_usage, now_ms,
		public_data, public_length);
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

int pqcp_runtime_key_store_sign(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *message,
	size_t message_length,
	const uint8_t *context,
	size_t context_length,
	uint8_t *signature,
	size_t signature_capacity,
	size_t *signature_length)
{
	int ret;

	if (store == NULL || handle == NULL ||
	    (message == NULL && message_length != 0U) ||
	    (context == NULL && context_length != 0U) ||
	    context_length > PQCP_RUNTIME_MAX_CONTEXT_BYTES ||
	    signature == NULL || signature_capacity == 0U ||
	    signature_length == NULL ||
	    !pqcp_runtime_key_handle_is_valid(handle) ||
	    store->ops == NULL || store->ops->sign == NULL) {
		return -EINVAL;
	}
	*signature_length = 0U;
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->sign(
		store, handle, message, message_length,
		context, context_length, signature,
		signature_capacity, signature_length);
	if (ret != 0) {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_verify(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *message,
	size_t message_length,
	const uint8_t *context,
	size_t context_length,
	const uint8_t *signature,
	size_t signature_length)
{
	int ret;

	if (store == NULL ||
	    !pqcp_runtime_key_handle_is_valid(handle) ||
	    (message == NULL && message_length != 0U) ||
	    (context == NULL && context_length != 0U) ||
	    context_length > PQCP_RUNTIME_MAX_CONTEXT_BYTES ||
	    signature == NULL || signature_length == 0U) {
		return -EINVAL;
	}
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->verify(
		store, handle, message, message_length,
		context, context_length, signature,
		signature_length);
	if (ret != 0) {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_encapsulate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const struct pqcp_runtime_key_request *secret_request,
	uint8_t *ciphertext,
	size_t ciphertext_capacity,
	size_t *ciphertext_length,
	struct pqcp_runtime_key_handle *secret_handle)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    !request_valid(secret_request) ||
	    secret_request->family != PQCP_RUNTIME_KEY_SHARED_SECRET ||
	    ciphertext == NULL || ciphertext_capacity == 0U ||
	    ciphertext_length == NULL ||
	    secret_handle == NULL) {
		return -EINVAL;
	}
	*ciphertext_length = 0U;
	memset(secret_handle, 0, sizeof(*secret_handle));
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->encapsulate(
		store, handle, secret_request, ciphertext,
		ciphertext_capacity, ciphertext_length,
		secret_handle);
	if (ret == 0) {
		store->create_count++;
		store->active_count++;
	} else {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_decapsulate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *ciphertext,
	size_t ciphertext_length,
	const struct pqcp_runtime_key_request *secret_request,
	struct pqcp_runtime_key_handle *secret_handle)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    ciphertext == NULL || ciphertext_length == 0U ||
	    !request_valid(secret_request) ||
	    secret_request->family != PQCP_RUNTIME_KEY_SHARED_SECRET ||
	    secret_handle == NULL) {
		return -EINVAL;
	}
	memset(secret_handle, 0, sizeof(*secret_handle));
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->decapsulate(
		store, handle, ciphertext, ciphertext_length,
		secret_request, secret_handle);
	if (ret == 0) {
		store->create_count++;
		store->active_count++;
	} else {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_derive(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *salt,
	size_t salt_length,
	const uint8_t *info,
	size_t info_length,
	const struct pqcp_runtime_key_request *derived_request,
	struct pqcp_runtime_key_handle *derived_handle)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    (salt == NULL && salt_length != 0U) ||
	    (info == NULL && info_length != 0U) ||
	    !request_valid(derived_request) ||
	    derived_request->family != PQCP_RUNTIME_KEY_AEAD ||
	    (handle->family != PQCP_RUNTIME_KEY_SHARED_SECRET &&
	     handle->family != PQCP_RUNTIME_KEY_AEAD) ||
	    derived_handle == NULL) {
		return -EINVAL;
	}
	memset(derived_handle, 0, sizeof(*derived_handle));
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->derive(
		store, handle, salt, salt_length, info,
		info_length, derived_request, derived_handle);
	if (ret == 0) {
		store->create_count++;
		store->active_count++;
	} else {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_mac(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *message,
	size_t message_length,
	uint8_t *tag,
	size_t tag_capacity,
	size_t *tag_length)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    handle->family != PQCP_RUNTIME_KEY_AEAD ||
	    (message == NULL && message_length != 0U) ||
	    tag == NULL ||
	    tag_capacity < PQCP_RUNTIME_DIGEST_BYTES ||
	    tag_length == NULL) {
		return -EINVAL;
	}
	*tag_length = 0U;
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->mac(
		store, handle, message, message_length,
		tag, tag_capacity, tag_length);
	if (ret != 0) {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_aead_encrypt(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *nonce,
	size_t nonce_length,
	const uint8_t *aad,
	size_t aad_length,
	const uint8_t *plaintext,
	size_t plaintext_length,
	uint8_t *ciphertext,
	size_t ciphertext_capacity,
	size_t *ciphertext_length)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    nonce == NULL || nonce_length == 0U ||
	    (aad == NULL && aad_length != 0U) ||
	    (plaintext == NULL && plaintext_length != 0U) ||
	    ciphertext == NULL || ciphertext_capacity == 0U ||
	    ciphertext_length == NULL) {
		return -EINVAL;
	}
	*ciphertext_length = 0U;
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->aead_encrypt(
		store, handle, nonce, nonce_length, aad,
		aad_length, plaintext, plaintext_length,
		ciphertext, ciphertext_capacity,
		ciphertext_length);
	if (ret != 0) {
		store->rejected_count++;
	}
	unlock_store(store);
	return ret;
}

int pqcp_runtime_key_store_aead_decrypt(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *nonce,
	size_t nonce_length,
	const uint8_t *aad,
	size_t aad_length,
	const uint8_t *ciphertext,
	size_t ciphertext_length,
	uint8_t *plaintext,
	size_t plaintext_capacity,
	size_t *plaintext_length)
{
	int ret;

	if (!pqcp_runtime_key_handle_is_valid(handle) ||
	    nonce == NULL || nonce_length == 0U ||
	    (aad == NULL && aad_length != 0U) ||
	    ciphertext == NULL || ciphertext_length == 0U ||
	    plaintext == NULL || plaintext_capacity == 0U ||
	    plaintext_length == NULL) {
		return -EINVAL;
	}
	*plaintext_length = 0U;
	ret = lock_store(store);
	if (ret != 0) {
		return ret;
	}
	ret = store->ops->aead_decrypt(
		store, handle, nonce, nonce_length, aad,
		aad_length, ciphertext, ciphertext_length,
		plaintext, plaintext_capacity,
		plaintext_length);
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
