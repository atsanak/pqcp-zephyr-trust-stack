/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Fail-closed adapter for platform-provided persistent PQC PSA keys.
 *
 * The upstream PSA core does not yet standardize these PQC key types. The
 * weak provider hooks below intentionally return -ENOTSUP. A platform may
 * override them only when it has a real persistent provider for the
 * provisional PQC types. No raw-key settings/file fallback exists.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/toolchain.h>

#include <pqcp_zephyr/runtime_key_store.h>

#include "runtime_internal.h"

__weak int pqcp_runtime_psa_provider_probe(void)
{
	return -ENOTSUP;
}

__weak int pqcp_runtime_psa_provider_generate(
	uint32_t key_id,
	const struct pqcp_runtime_key_request *request)
{
	ARG_UNUSED(key_id);
	ARG_UNUSED(request);
	return -ENOTSUP;
}

__weak int pqcp_runtime_psa_provider_import(
	uint32_t key_id,
	const struct pqcp_runtime_key_request *request,
	const uint8_t *public_data,
	size_t public_length,
	const uint8_t *secret_data,
	size_t secret_length)
{
	ARG_UNUSED(key_id);
	ARG_UNUSED(request);
	ARG_UNUSED(public_data);
	ARG_UNUSED(public_length);
	ARG_UNUSED(secret_data);
	ARG_UNUSED(secret_length);
	return -ENOTSUP;
}

__weak int pqcp_runtime_psa_provider_open(
	uint32_t key_id,
	const struct pqcp_runtime_key_request *request)
{
	ARG_UNUSED(key_id);
	ARG_UNUSED(request);
	return -ENOTSUP;
}

__weak int pqcp_runtime_psa_provider_export_public(
	uint32_t key_id,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	ARG_UNUSED(key_id);
	ARG_UNUSED(output);
	ARG_UNUSED(output_capacity);
	ARG_UNUSED(output_length);
	return -ENOTSUP;
}

__weak int pqcp_runtime_psa_provider_destroy(uint32_t key_id)
{
	ARG_UNUSED(key_id);
	return -ENOTSUP;
}

static struct pqcp_runtime_psa_context *psa_context(
	struct pqcp_runtime_key_store *store)
{
	return store != NULL ? store->context : NULL;
}

static bool bitmap_test(
	const struct pqcp_runtime_psa_context *context,
	uint32_t index)
{
	const uint32_t word = index / 32U;
	const uint32_t bit = index % 32U;

	return word < context->allocated_bitmap_words &&
	       (context->allocated_bitmap[word] &
		(1U << bit)) != 0U;
}

static void bitmap_set(
	struct pqcp_runtime_psa_context *context,
	uint32_t index)
{
	context->allocated_bitmap[index / 32U] |=
		1U << (index % 32U);
}

static void bitmap_clear(
	struct pqcp_runtime_psa_context *context,
	uint32_t index)
{
	context->allocated_bitmap[index / 32U] &=
		~(1U << (index % 32U));
}

static int first_free_id(
	const struct pqcp_runtime_psa_context *context)
{
	for (uint32_t index = 0U;
	     index < context->key_id_count; ++index) {
		if (!bitmap_test(context, index)) {
			return (int)index;
		}
	}
	return -1;
}

static uint32_t next_generation(
	struct pqcp_runtime_psa_context *context,
	uint32_t slot)
{
	uint32_t generation = ++context->generations[slot];

	if (generation == 0U) {
		generation = ++context->generations[slot];
	}
	return generation;
}

static int initialize_metadata(
	struct pqcp_runtime_psa_context *context,
	uint32_t slot,
	const struct pqcp_runtime_key_request *request,
	struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_key_metadata *metadata =
		&context->metadata[slot];

	memset(metadata, 0, sizeof(*metadata));
	handle->slot = slot;
	handle->generation = next_generation(context, slot);
	handle->backend =
		PQCP_RUNTIME_KEY_BACKEND_PSA_PERSISTENT;
	handle->family = request->family;
	handle->level = request->level;
	metadata->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	metadata->handle = *handle;
	metadata->usage = request->usage;
	metadata->created_at_ms = request->now_ms;
	metadata->expires_at_ms = request->expires_at_ms;
	metadata->public_bytes =
		pqcp_runtime_internal_public_size(
			request->family, request->level);
	metadata->secret_bytes =
		pqcp_runtime_internal_secret_size(
			request->family, request->level);
	metadata->active = true;
	metadata->persistent = true;
	metadata->exportable_public =
		request->exportable_public;
	if (pqcp_runtime_internal_copy_text(
		    metadata->owner, sizeof(metadata->owner),
		    request->owner) != 0 ||
	    pqcp_runtime_internal_copy_text(
		    metadata->label, sizeof(metadata->label),
		    request->label) != 0) {
		memset(metadata, 0, sizeof(*metadata));
		return -EINVAL;
	}
	return 0;
}

static void clear_metadata(
	struct pqcp_runtime_psa_context *context,
	uint32_t slot)
{
	pqcp_runtime_secure_zero(
		&context->metadata[slot],
		sizeof(context->metadata[slot]));
}

static int ensure_available(
	struct pqcp_runtime_psa_context *context)
{
	int ret;

	if (context == NULL || !context->initialized) {
		return -EINVAL;
	}
	if (context->persistence_available) {
		return 0;
	}
	ret = pqcp_runtime_psa_provider_probe();
	if (ret == 0) {
		context->persistence_available = true;
		return 0;
	}
	return ret == -ENOTSUP ? -ENOTSUP : -EIO;
}

static int psa_create(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_request *request,
	const uint8_t *public_data,
	size_t public_length,
	const uint8_t *secret_data,
	size_t secret_length,
	struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_psa_context *context =
		psa_context(store);
	int index;
	int ret;

	if (!request->persistent) {
		return -EINVAL;
	}
	ret = ensure_available(context);
	if (ret != 0) {
		return ret;
	}
	index = first_free_id(context);
	if (index < 0) {
		return -ENOSPC;
	}
	ret = pqcp_runtime_psa_provider_import(
		context->key_id_base + (uint32_t)index,
		request, public_data, public_length,
		secret_data, secret_length);
	if (ret != 0) {
		return ret == -ENOTSUP ? -ENOTSUP : -EIO;
	}
	ret = initialize_metadata(
		context, (uint32_t)index, request, handle);
	if (ret != 0) {
		(void)pqcp_runtime_psa_provider_destroy(
			context->key_id_base + (uint32_t)index);
		return ret;
	}
	bitmap_set(context, (uint32_t)index);
	return 0;
}

static int psa_generate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_request *request,
	struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_psa_context *context =
		psa_context(store);
	int index;
	int ret;

	if (!request->persistent) {
		return -EINVAL;
	}
	ret = ensure_available(context);
	if (ret != 0) {
		return ret;
	}
	index = first_free_id(context);
	if (index < 0) {
		return -ENOSPC;
	}
	ret = pqcp_runtime_psa_provider_generate(
		context->key_id_base + (uint32_t)index,
		request);
	if (ret != 0) {
		return ret == -ENOTSUP ? -ENOTSUP : -EIO;
	}
	ret = initialize_metadata(
		context, (uint32_t)index, request, handle);
	if (ret != 0) {
		(void)pqcp_runtime_psa_provider_destroy(
			context->key_id_base + (uint32_t)index);
		return ret;
	}
	bitmap_set(context, (uint32_t)index);
	return 0;
}

static int validate_handle(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	uint32_t *key_id)
{
	struct pqcp_runtime_psa_context *context =
		psa_context(store);

	if (context == NULL ||
	    handle->backend !=
		    PQCP_RUNTIME_KEY_BACKEND_PSA_PERSISTENT ||
	    handle->slot >= context->key_id_count ||
	    !bitmap_test(context, handle->slot) ||
	    !context->metadata[handle->slot].active ||
	    !pqcp_runtime_key_handle_equal(
		    &context->metadata[handle->slot].handle,
		    handle)) {
		return -ENOENT;
	}
	*key_id = context->key_id_base + handle->slot;
	return 0;
}

static int psa_metadata(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	struct pqcp_runtime_key_metadata *metadata)
{
	uint32_t key_id;
	int ret = validate_handle(store, handle, &key_id);

	if (ret != 0) {
		return ret;
	}
	*metadata =
		psa_context(store)->metadata[handle->slot];
	return 0;
}

static int psa_acquire(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	uint32_t required_usage,
	uint64_t now_ms,
	const uint8_t **public_data,
	size_t *public_length,
	const uint8_t **secret_data,
	size_t *secret_length)
{
	uint32_t key_id;
	int ret;

	ARG_UNUSED(public_data);
	ARG_UNUSED(public_length);
	ARG_UNUSED(secret_data);
	ARG_UNUSED(secret_length);
	ret = validate_handle(store, handle, &key_id);
	if (ret != 0) {
		return ret;
	}
	const struct pqcp_runtime_key_metadata *metadata =
		&psa_context(store)->metadata[handle->slot];
	if ((metadata->usage & required_usage) != required_usage) {
		return -EACCES;
	}
	if (metadata->expires_at_ms != 0U &&
	    metadata->expires_at_ms <= now_ms) {
		return -EKEYEXPIRED;
	}
	/*
	 * Persistent keys are opaque. Runtime primitive execution must use a
	 * platform provider operation path, which is not standardized yet.
	 */
	return pqcp_runtime_psa_provider_open(
		key_id, NULL) == 0 ? -ENOTSUP : -ENOTSUP;
}

static int psa_release(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle)
{
	uint32_t key_id;

	return validate_handle(store, handle, &key_id);
}

static int psa_export_public(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	uint32_t key_id;
	int ret = validate_handle(store, handle, &key_id);

	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_psa_provider_export_public(
		key_id, output, output_capacity, output_length);
	return ret == -ENOTSUP ? -ENOTSUP : ret;
}

static int psa_destroy(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_psa_context *context =
		psa_context(store);
	uint32_t key_id;
	int ret = validate_handle(store, handle, &key_id);

	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_psa_provider_destroy(key_id);
	if (ret != 0) {
		return ret == -ENOTSUP ? -ENOTSUP : -EIO;
	}
	bitmap_clear(context, handle->slot);
	clear_metadata(context, handle->slot);
	(void)next_generation(context, handle->slot);
	return 0;
}

static int psa_rotate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *old_handle,
	const struct pqcp_runtime_key_request *request,
	struct pqcp_runtime_key_handle *new_handle)
{
	struct pqcp_runtime_key_handle generated;
	int ret;

	if (old_handle->family != request->family ||
	    old_handle->level != request->level) {
		return -EINVAL;
	}
	ret = psa_generate(store, request, &generated);
	if (ret != 0) {
		return ret;
	}
	ret = psa_destroy(store, old_handle);
	if (ret != 0) {
		(void)psa_destroy(store, &generated);
		return ret;
	}
	*new_handle = generated;
	return 0;
}

static int psa_expire(
	struct pqcp_runtime_key_store *store,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	struct pqcp_runtime_psa_context *context =
		psa_context(store);
	uint32_t expired = 0U;

	if (context == NULL || expired_count == NULL) {
		return -EINVAL;
	}
	for (uint32_t index = 0U;
	     index < context->key_id_count; ++index) {
		struct pqcp_runtime_key_metadata *metadata =
			&context->metadata[index];
		int ret;

		if (!bitmap_test(context, index) ||
		    !metadata->active ||
		    metadata->expires_at_ms == 0U ||
		    metadata->expires_at_ms > now_ms) {
			continue;
		}
		ret = pqcp_runtime_psa_provider_destroy(
			context->key_id_base + index);
		if (ret != 0) {
			return ret == -ENOTSUP ? -ENOTSUP : -EIO;
		}
		bitmap_clear(context, index);
		clear_metadata(context, index);
		(void)next_generation(context, index);
		expired++;
	}
	*expired_count = expired;
	return 0;
}

static int psa_audit(
	struct pqcp_runtime_key_store *store)
{
	struct pqcp_runtime_psa_context *context =
		psa_context(store);
	uint32_t allocated = 0U;

	if (context == NULL || !context->initialized ||
	    context->key_id_count != store->capacity ||
	    context->allocated_bitmap == NULL) {
		return -EBADMSG;
	}
	for (uint32_t index = 0U;
	     index < context->key_id_count; ++index) {
		if (bitmap_test(context, index)) {
			const struct pqcp_runtime_key_metadata *metadata =
				&context->metadata[index];

			if (!metadata->active ||
			    metadata->schema_version !=
				    PQCP_RUNTIME_SCHEMA_VERSION ||
			    metadata->handle.slot != index ||
			    metadata->handle.generation !=
				    context->generations[index] ||
			    metadata->handle.backend !=
				    PQCP_RUNTIME_KEY_BACKEND_PSA_PERSISTENT ||
			    !metadata->persistent ||
			    !pqcp_runtime_internal_owner_valid(
				    metadata->owner) ||
			    !pqcp_runtime_internal_label_valid(
				    metadata->label)) {
				return -EBADMSG;
			}
			allocated++;
		} else if (context->metadata[index].active) {
			return -EBADMSG;
		}
	}
	return allocated == store->active_count ? 0 : -EBADMSG;
}

static const struct pqcp_runtime_key_store_ops psa_ops = {
	.create = psa_create,
	.generate = psa_generate,
	.metadata = psa_metadata,
	.acquire = psa_acquire,
	.release = psa_release,
	.export_public = psa_export_public,
	.rotate = psa_rotate,
	.destroy = psa_destroy,
	.expire = psa_expire,
	.audit = psa_audit,
};

int pqcp_runtime_psa_store_init(
	struct pqcp_runtime_key_store *store,
	struct pqcp_runtime_psa_context *context,
	uint32_t key_id_base,
	uint32_t key_id_count,
	uint32_t *allocated_bitmap,
	size_t allocated_bitmap_words)
{
	size_t required_words;
	int ret;

	if (store == NULL || context == NULL ||
	    key_id_base == 0U || key_id_count == 0U ||
	    key_id_count > CONFIG_PQCP_RUNTIME_MAX_KEYS ||
	    allocated_bitmap == NULL) {
		return -EINVAL;
	}
	required_words = (key_id_count + 31U) / 32U;
	if (allocated_bitmap_words < required_words ||
	    allocated_bitmap_words > UINT32_MAX) {
		return -ENOSPC;
	}
	memset(allocated_bitmap, 0,
	       allocated_bitmap_words *
		       sizeof(*allocated_bitmap));
	memset(context, 0, sizeof(*context));
	context->key_id_base = key_id_base;
	context->key_id_count = key_id_count;
	context->allocated_bitmap_words =
		(uint32_t)allocated_bitmap_words;
	context->allocated_bitmap = allocated_bitmap;
	context->initialized = true;
	context->persistence_available = false;
	ret = pqcp_runtime_key_store_init(
		store,
		PQCP_RUNTIME_KEY_BACKEND_PSA_PERSISTENT,
		&psa_ops, context, key_id_count);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_psa_provider_probe();
	if (ret == 0) {
		context->persistence_available = true;
		return 0;
	}
	return ret == -ENOTSUP ? -ENOTSUP : -EIO;
}

bool pqcp_runtime_psa_persistence_available(
	const struct pqcp_runtime_key_store *store)
{
	const struct pqcp_runtime_psa_context *context;

	if (store == NULL ||
	    store->backend !=
		    PQCP_RUNTIME_KEY_BACKEND_PSA_PERSISTENT ||
	    store->context == NULL) {
		return false;
	}
	context = store->context;
	return context->initialized &&
	       context->persistence_available;
}
