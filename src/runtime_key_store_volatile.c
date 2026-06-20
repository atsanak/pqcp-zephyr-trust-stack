/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Fixed-capacity volatile key storage.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_key_store.h>

#include "runtime_internal.h"

static struct pqcp_runtime_volatile_context *volatile_context(
	struct pqcp_runtime_key_store *store)
{
	return store != NULL ? store->context : NULL;
}

static uint32_t next_generation(
	struct pqcp_runtime_key_store *store)
{
	uint32_t generation = ++store->generation_seed;

	if (generation == 0U) {
		generation = ++store->generation_seed;
	}
	return generation;
}

static int free_slot(
	const struct pqcp_runtime_volatile_context *context)
{
	for (size_t index = 0U; index < context->slot_count; ++index) {
		if (!context->slots[index].metadata.active) {
			return (int)index;
		}
	}
	return -1;
}

static struct pqcp_runtime_volatile_slot *resolve_slot(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_volatile_context *context =
		volatile_context(store);
	struct pqcp_runtime_volatile_slot *slot;

	if (context == NULL ||
	    handle->backend !=
		    PQCP_RUNTIME_KEY_BACKEND_VOLATILE ||
	    handle->slot >= context->slot_count) {
		return NULL;
	}
	slot = &context->slots[handle->slot];
	if (!slot->metadata.active ||
	    slot->generation != handle->generation ||
	    !pqcp_runtime_key_handle_equal(
		    &slot->metadata.handle, handle)) {
		return NULL;
	}
	return slot;
}

static bool request_lengths_match(
	const struct pqcp_runtime_key_request *request,
	size_t public_length,
	size_t secret_length)
{
	const size_t expected_public =
		pqcp_runtime_internal_public_size(
			request->family, request->level);
	const size_t expected_secret =
		pqcp_runtime_internal_secret_size(
			request->family, request->level);

	return public_length == expected_public &&
	       secret_length == expected_secret &&
	       public_length <=
		       PQCP_RUNTIME_MAX_PUBLIC_KEY_BYTES &&
	       secret_length <= PQCP_RUNTIME_MAX_KEY_BYTES;
}

static void clear_slot(
	struct pqcp_runtime_volatile_slot *slot)
{
	uint32_t generation;

	if (slot == NULL) {
		return;
	}
	generation = slot->generation;
	pqcp_runtime_secure_zero(
		slot->public_data, sizeof(slot->public_data));
	pqcp_runtime_secure_zero(
		slot->secret_data, sizeof(slot->secret_data));
	memset(&slot->metadata, 0, sizeof(slot->metadata));
	slot->references = 0U;
	slot->public_length = 0U;
	slot->secret_length = 0U;
	slot->generation = generation;
}

static int populate_slot(
	struct pqcp_runtime_key_store *store,
	struct pqcp_runtime_volatile_slot *slot,
	size_t slot_index,
	const struct pqcp_runtime_key_request *request,
	const uint8_t *public_data,
	size_t public_length,
	const uint8_t *secret_data,
	size_t secret_length,
	struct pqcp_runtime_key_handle *handle)
{
	uint32_t generation;

	if (!request_lengths_match(
		    request, public_length, secret_length)) {
		return -EMSGSIZE;
	}
	clear_slot(slot);
	generation = next_generation(store);
	slot->generation = generation;
	if (public_length != 0U) {
		memcpy(slot->public_data, public_data, public_length);
	}
	if (secret_length != 0U) {
		memcpy(slot->secret_data, secret_data, secret_length);
	}
	slot->public_length = public_length;
	slot->secret_length = secret_length;
	slot->metadata.schema_version =
		PQCP_RUNTIME_SCHEMA_VERSION;
	slot->metadata.handle.slot = (uint32_t)slot_index;
	slot->metadata.handle.generation = generation;
	slot->metadata.handle.backend =
		PQCP_RUNTIME_KEY_BACKEND_VOLATILE;
	slot->metadata.handle.family = request->family;
	slot->metadata.handle.level = request->level;
	slot->metadata.usage = request->usage;
	slot->metadata.created_at_ms = request->now_ms;
	slot->metadata.expires_at_ms = request->expires_at_ms;
	slot->metadata.public_bytes = (uint32_t)public_length;
	slot->metadata.secret_bytes = (uint32_t)secret_length;
	slot->metadata.active = true;
	slot->metadata.persistent = false;
	slot->metadata.exportable_public =
		request->exportable_public;
	if (pqcp_runtime_internal_copy_text(
		    slot->metadata.owner,
		    sizeof(slot->metadata.owner),
		    request->owner) != 0 ||
	    pqcp_runtime_internal_copy_text(
		    slot->metadata.label,
		    sizeof(slot->metadata.label),
		    request->label) != 0) {
		clear_slot(slot);
		return -EINVAL;
	}
	*handle = slot->metadata.handle;
	return 0;
}

static int volatile_create(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_request *request,
	const uint8_t *public_data,
	size_t public_length,
	const uint8_t *secret_data,
	size_t secret_length,
	struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_volatile_context *context =
		volatile_context(store);
	int index;

	if (context == NULL || handle == NULL) {
		return -EINVAL;
	}
	index = free_slot(context);
	if (index < 0) {
		return -ENOSPC;
	}
	return populate_slot(
		store, &context->slots[index], (size_t)index,
		request, public_data, public_length,
		secret_data, secret_length, handle);
}

static int generate_mlkem(
	const struct pqcp_runtime_key_request *request,
	uint8_t *public_data,
	size_t *public_length,
	uint8_t *secret_data,
	size_t *secret_length)
{
	const size_t pk_size = pqcp_mlkem_pk_size(
		(pqcp_mlkem_level_t)request->level);
	const size_t sk_size = pqcp_mlkem_sk_size(
		(pqcp_mlkem_level_t)request->level);
	int ret;

	if (request->family !=
	    PQCP_RUNTIME_KEY_MLKEM_KEYPAIR) {
		return -ENOTSUP;
	}
	ret = pqcp_mlkem_keypair(
		(pqcp_mlkem_level_t)request->level,
		public_data, secret_data);
	if (ret != PQCP_MLKEM_SUCCESS) {
		pqcp_runtime_secure_zero(public_data, pk_size);
		pqcp_runtime_secure_zero(secret_data, sk_size);
		return -EIO;
	}
	*public_length = pk_size;
	*secret_length = sk_size;
	return 0;
}

static int generate_mldsa(
	const struct pqcp_runtime_key_request *request,
	uint8_t *public_data,
	size_t *public_length,
	uint8_t *secret_data,
	size_t *secret_length)
{
	const size_t pk_size = pqcp_mldsa_pk_size(
		(pqcp_mldsa_level_t)request->level);
	const size_t sk_size = pqcp_mldsa_sk_size(
		(pqcp_mldsa_level_t)request->level);
	int ret;

	if (request->family !=
	    PQCP_RUNTIME_KEY_MLDSA_KEYPAIR) {
		return -ENOTSUP;
	}
	ret = pqcp_mldsa_keypair(
		(pqcp_mldsa_level_t)request->level,
		public_data, secret_data);
	if (ret != PQCP_MLDSA_SUCCESS) {
		pqcp_runtime_secure_zero(public_data, pk_size);
		pqcp_runtime_secure_zero(secret_data, sk_size);
		return -EIO;
	}
	*public_length = pk_size;
	*secret_length = sk_size;
	return 0;
}

static int volatile_generate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_request *request,
	struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_volatile_context *context =
		volatile_context(store);
	uint8_t public_data[PQCP_RUNTIME_MAX_PUBLIC_KEY_BYTES];
	uint8_t secret_data[PQCP_RUNTIME_MAX_KEY_BYTES];
	size_t public_length = 0U;
	size_t secret_length = 0U;
	int index;
	int ret;

	if (context == NULL || handle == NULL) {
		return -EINVAL;
	}
	index = free_slot(context);
	if (index < 0) {
		return -ENOSPC;
	}
	memset(public_data, 0, sizeof(public_data));
	memset(secret_data, 0, sizeof(secret_data));
	switch (request->family) {
	case PQCP_RUNTIME_KEY_MLKEM_KEYPAIR:
		ret = generate_mlkem(
			request, public_data, &public_length,
			secret_data, &secret_length);
		break;
	case PQCP_RUNTIME_KEY_MLDSA_KEYPAIR:
		ret = generate_mldsa(
			request, public_data, &public_length,
			secret_data, &secret_length);
		break;
	default:
		ret = -ENOTSUP;
		break;
	}
	if (ret == 0) {
		ret = populate_slot(
			store, &context->slots[index],
			(size_t)index, request,
			public_data, public_length,
			secret_data, secret_length, handle);
	}
	pqcp_runtime_secure_zero(
		public_data, sizeof(public_data));
	pqcp_runtime_secure_zero(
		secret_data, sizeof(secret_data));
	return ret;
}

static int volatile_metadata(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	struct pqcp_runtime_key_metadata *metadata)
{
	const struct pqcp_runtime_volatile_slot *slot =
		resolve_slot(store, handle);

	if (slot == NULL || metadata == NULL) {
		return -ENOENT;
	}
	*metadata = slot->metadata;
	return 0;
}

static int volatile_acquire(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	uint32_t required_usage,
	uint64_t now_ms,
	const uint8_t **public_data,
	size_t *public_length,
	const uint8_t **secret_data,
	size_t *secret_length)
{
	struct pqcp_runtime_volatile_slot *slot =
		resolve_slot(store, handle);

	if (slot == NULL) {
		return -ENOENT;
	}
	if ((slot->metadata.usage & required_usage) !=
	    required_usage) {
		return -EACCES;
	}
	if (slot->metadata.expires_at_ms != 0U &&
	    slot->metadata.expires_at_ms <= now_ms) {
		return -EKEYEXPIRED;
	}
	if (slot->references == UINT32_MAX) {
		return -EOVERFLOW;
	}
	slot->references++;
	slot->metadata.last_used_at_ms = now_ms;
	slot->metadata.use_count++;
	*public_data = slot->public_length != 0U ?
		slot->public_data : NULL;
	*public_length = slot->public_length;
	*secret_data = slot->secret_length != 0U ?
		slot->secret_data : NULL;
	*secret_length = slot->secret_length;
	return 0;
}

static int volatile_release(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_volatile_slot *slot =
		resolve_slot(store, handle);

	if (slot == NULL) {
		return -ENOENT;
	}
	if (slot->references == 0U) {
		return -EALREADY;
	}
	slot->references--;
	return 0;
}

static int volatile_export_public(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	const struct pqcp_runtime_volatile_slot *slot =
		resolve_slot(store, handle);

	if (slot == NULL) {
		return -ENOENT;
	}
	if (!slot->metadata.exportable_public ||
	    (slot->metadata.usage &
	     PQCP_RUNTIME_USAGE_EXPORT_PUBLIC) == 0U) {
		return -EACCES;
	}
	if (slot->public_length == 0U) {
		return -ENODATA;
	}
	if (output_capacity < slot->public_length) {
		return -ENOSPC;
	}
	memcpy(output, slot->public_data, slot->public_length);
	*output_length = slot->public_length;
	return 0;
}

static int volatile_destroy(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_volatile_slot *slot =
		resolve_slot(store, handle);

	if (slot == NULL) {
		return -ENOENT;
	}
	if (slot->references != 0U) {
		return -EBUSY;
	}
	clear_slot(slot);
	return 0;
}

static int volatile_rotate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *old_handle,
	const struct pqcp_runtime_key_request *request,
	struct pqcp_runtime_key_handle *new_handle)
{
	const struct pqcp_runtime_volatile_slot *old_slot =
		resolve_slot(store, old_handle);
	struct pqcp_runtime_key_handle generated;
	int ret;

	if (old_slot == NULL) {
		return -ENOENT;
	}
	if (old_slot->references != 0U) {
		return -EBUSY;
	}
	if (old_handle->family != request->family ||
	    old_handle->level != request->level) {
		return -EINVAL;
	}
	ret = volatile_generate(store, request, &generated);
	if (ret != 0) {
		return ret;
	}
	ret = volatile_destroy(store, old_handle);
	if (ret != 0) {
		(void)volatile_destroy(store, &generated);
		return ret;
	}
	*new_handle = generated;
	return 0;
}

static int volatile_expire(
	struct pqcp_runtime_key_store *store,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	struct pqcp_runtime_volatile_context *context =
		volatile_context(store);
	uint32_t expired = 0U;

	if (context == NULL || expired_count == NULL) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < context->slot_count; ++index) {
		struct pqcp_runtime_volatile_slot *slot =
			&context->slots[index];

		if (!slot->metadata.active ||
		    slot->metadata.expires_at_ms == 0U ||
		    slot->metadata.expires_at_ms > now_ms ||
		    slot->references != 0U) {
			continue;
		}
		clear_slot(slot);
		expired++;
	}
	*expired_count = expired;
	return 0;
}

static bool metadata_consistent(
	const struct pqcp_runtime_volatile_slot *slot,
	size_t index)
{
	if (!slot->metadata.active) {
		return slot->references == 0U &&
		       slot->public_length == 0U &&
		       slot->secret_length == 0U;
	}
	return slot->generation != 0U &&
	       slot->metadata.schema_version ==
		       PQCP_RUNTIME_SCHEMA_VERSION &&
	       slot->metadata.handle.slot == index &&
	       slot->metadata.handle.generation ==
		       slot->generation &&
	       slot->metadata.handle.backend ==
		       PQCP_RUNTIME_KEY_BACKEND_VOLATILE &&
	       pqcp_runtime_key_handle_is_valid(
		       &slot->metadata.handle) &&
	       slot->metadata.public_bytes ==
		       slot->public_length &&
	       slot->metadata.secret_bytes ==
		       slot->secret_length &&
	       pqcp_runtime_internal_owner_valid(
		       slot->metadata.owner) &&
	       pqcp_runtime_internal_label_valid(
		       slot->metadata.label);
}

static int volatile_audit(
	struct pqcp_runtime_key_store *store)
{
	struct pqcp_runtime_volatile_context *context =
		volatile_context(store);
	uint32_t active = 0U;

	if (context == NULL ||
	    context->slots == NULL ||
	    context->slot_count != store->capacity) {
		return -EBADMSG;
	}
	for (size_t index = 0U; index < context->slot_count; ++index) {
		if (!metadata_consistent(
			    &context->slots[index], index)) {
			return -EBADMSG;
		}
		if (context->slots[index].metadata.active) {
			active++;
		}
	}
	return active == store->active_count ? 0 : -EBADMSG;
}

static const struct pqcp_runtime_key_store_ops volatile_ops = {
	.create = volatile_create,
	.generate = volatile_generate,
	.metadata = volatile_metadata,
	.acquire = volatile_acquire,
	.release = volatile_release,
	.export_public = volatile_export_public,
	.rotate = volatile_rotate,
	.destroy = volatile_destroy,
	.expire = volatile_expire,
	.audit = volatile_audit,
};

int pqcp_runtime_volatile_store_init(
	struct pqcp_runtime_key_store *store,
	struct pqcp_runtime_volatile_context *context,
	struct pqcp_runtime_volatile_slot *slots,
	size_t slot_count)
{
	if (store == NULL || context == NULL ||
	    slots == NULL || slot_count == 0U ||
	    slot_count > UINT32_MAX) {
		return -EINVAL;
	}
	memset(slots, 0, sizeof(*slots) * slot_count);
	context->slots = slots;
	context->slot_count = slot_count;
	return pqcp_runtime_key_store_init(
		store, PQCP_RUNTIME_KEY_BACKEND_VOLATILE,
		&volatile_ops, context, (uint32_t)slot_count);
}
