/*
 * SPDX-License-Identifier: MIT
 *
 * Pinned ML-DSA identity lifecycle.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_identity.h>

#include "runtime_internal.h"

static struct pqcp_runtime_identity *find_unlocked(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id)
{
	for (size_t index = 0U; index < store->capacity; ++index) {
		if (store->identities[index].active &&
		    strcmp(store->identities[index].identity_id,
			   identity_id) == 0) {
			return &store->identities[index];
		}
	}
	return NULL;
}

static struct pqcp_runtime_identity *free_unlocked(
	struct pqcp_runtime_identity_store *store)
{
	for (size_t index = 0U; index < store->capacity; ++index) {
		if (!store->identities[index].active) {
			return &store->identities[index];
		}
	}
	return NULL;
}

static bool identity_id_valid(const char *identity_id)
{
	return pqcp_runtime_internal_text_valid(
		identity_id, PQCP_RUNTIME_IDENTITY_MAX_ID_CHARS);
}

static bool mldsa_level_valid(uint32_t level)
{
	return level == PQCP_MLDSA_44 ||
	       level == PQCP_MLDSA_65 ||
	       level == PQCP_MLDSA_87;
}

static int fingerprint_public_key(
	const uint8_t *public_key,
	size_t public_key_length,
	uint8_t fingerprint[PQCP_RUNTIME_DIGEST_BYTES])
{
	return pqcp_runtime_internal_sha256(
		public_key, public_key_length, fingerprint);
}

int pqcp_runtime_identity_store_init(
	struct pqcp_runtime_identity_store *store,
	struct pqcp_runtime_identity *identities,
	size_t capacity,
	struct pqcp_runtime_key_store *key_store)
{
	if (store == NULL || identities == NULL ||
	    capacity == 0U || key_store == NULL) {
		return -EINVAL;
	}
	memset(store, 0, sizeof(*store));
	memset(identities, 0,
	       sizeof(*identities) * capacity);
	store->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	store->identities = identities;
	store->capacity = capacity;
	store->generation = 1U;
	store->key_store = key_store;
	k_mutex_init(&store->lock);
	return 0;
}

static int initialize_identity(
	struct pqcp_runtime_identity *identity,
	const char *identity_id,
	uint32_t mldsa_level,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	bool local)
{
	if (identity == NULL || !identity_id_valid(identity_id) ||
	    !mldsa_level_valid(mldsa_level) || now_ms == 0U ||
	    (expires_at_ms != 0U &&
	     expires_at_ms <= now_ms)) {
		return -EINVAL;
	}
	memset(identity, 0, sizeof(*identity));
	identity->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	identity->mldsa_level = mldsa_level;
	identity->created_at_ms = now_ms;
	identity->expires_at_ms = expires_at_ms;
	identity->active = true;
	identity->local = local;
	identity->trusted = !local;
	return pqcp_runtime_internal_copy_text(
		identity->identity_id,
		sizeof(identity->identity_id), identity_id);
}

static int generate_local_key(
	struct pqcp_runtime_identity_store *store,
	struct pqcp_runtime_identity *identity,
	uint64_t now_ms,
	uint64_t expires_at_ms)
{
	struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_MLDSA_KEYPAIR,
		.level = identity->mldsa_level,
		.usage =
			PQCP_RUNTIME_USAGE_SIGN |
			PQCP_RUNTIME_USAGE_VERIFY |
			PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
			PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = now_ms,
		.expires_at_ms = expires_at_ms,
		.owner = identity->identity_id,
		.label = "identity-key",
		.persistent = false,
		.exportable_public = true,
	};
	size_t public_length = 0U;
	int ret;

	ret = pqcp_runtime_key_store_generate(
		store->key_store, &request,
		&identity->local_key);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_key_store_export_public(
		store->key_store, &identity->local_key,
		identity->peer_public_key,
		sizeof(identity->peer_public_key),
		&public_length);
	if (ret != 0) {
		(void)pqcp_runtime_key_store_destroy(
			store->key_store, &identity->local_key);
		memset(&identity->local_key, 0,
		       sizeof(identity->local_key));
		return ret;
	}
	identity->peer_public_key_length = public_length;
	return fingerprint_public_key(
		identity->peer_public_key, public_length,
		identity->fingerprint);
}

int pqcp_runtime_identity_create_local(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id,
	uint32_t mldsa_level,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_runtime_identity **identity)
{
	struct pqcp_runtime_identity *entry;
	int ret;

	if (store == NULL || identity == NULL ||
	    !identity_id_valid(identity_id)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (find_unlocked(store, identity_id) != NULL) {
		(void)k_mutex_unlock(&store->lock);
		return -EEXIST;
	}
	entry = free_unlocked(store);
	if (entry == NULL) {
		(void)k_mutex_unlock(&store->lock);
		return -ENOSPC;
	}
	ret = initialize_identity(
		entry, identity_id, mldsa_level,
		now_ms, expires_at_ms, true);
	(void)k_mutex_unlock(&store->lock);
	if (ret != 0) {
		return ret;
	}
	ret = generate_local_key(
		store, entry, now_ms, expires_at_ms);
	if (ret != 0) {
		memset(entry, 0, sizeof(*entry));
		return ret;
	}
	(void)k_mutex_lock(&store->lock, K_FOREVER);
	store->active_count++;
	store->generation++;
	*identity = entry;
	(void)k_mutex_unlock(&store->lock);
	return 0;
}

int pqcp_runtime_identity_pin_peer(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id,
	uint32_t mldsa_level,
	const uint8_t *public_key,
	size_t public_key_length,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_runtime_identity **identity)
{
	struct pqcp_runtime_identity *entry;
	int ret;

	if (store == NULL || identity == NULL ||
	    !identity_id_valid(identity_id) ||
	    public_key == NULL ||
	    public_key_length !=
		    pqcp_mldsa_pk_size(
			    (pqcp_mldsa_level_t)mldsa_level)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (find_unlocked(store, identity_id) != NULL) {
		(void)k_mutex_unlock(&store->lock);
		return -EEXIST;
	}
	entry = free_unlocked(store);
	if (entry == NULL) {
		(void)k_mutex_unlock(&store->lock);
		return -ENOSPC;
	}
	ret = initialize_identity(
		entry, identity_id, mldsa_level,
		now_ms, expires_at_ms, false);
	if (ret == 0) {
		memcpy(entry->peer_public_key,
		       public_key, public_key_length);
		entry->peer_public_key_length =
			public_key_length;
		ret = fingerprint_public_key(
			public_key, public_key_length,
			entry->fingerprint);
	}
	if (ret == 0) {
		store->active_count++;
		store->generation++;
		*identity = entry;
	} else {
		memset(entry, 0, sizeof(*entry));
	}
	(void)k_mutex_unlock(&store->lock);
	return ret;
}

struct pqcp_runtime_identity *pqcp_runtime_identity_find(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id)
{
	struct pqcp_runtime_identity *identity;

	if (store == NULL || !identity_id_valid(identity_id)) {
		return NULL;
	}
	if (k_mutex_lock(&store->lock, K_FOREVER) != 0) {
		return NULL;
	}
	identity = find_unlocked(store, identity_id);
	(void)k_mutex_unlock(&store->lock);
	return identity;
}

int pqcp_runtime_identity_rotate_local(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id,
	uint64_t now_ms,
	uint64_t expires_at_ms)
{
	struct pqcp_runtime_identity *identity;
	struct pqcp_runtime_key_request request;
	struct pqcp_runtime_key_handle new_handle;
	size_t public_length = 0U;
	int ret;

	if (store == NULL || !identity_id_valid(identity_id) ||
	    now_ms == 0U ||
	    (expires_at_ms != 0U &&
	     expires_at_ms <= now_ms)) {
		return -EINVAL;
	}
	identity = pqcp_runtime_identity_find(store, identity_id);
	if (identity == NULL || !identity->local) {
		return -ENOENT;
	}
	memset(&request, 0, sizeof(request));
	request.family = PQCP_RUNTIME_KEY_MLDSA_KEYPAIR;
	request.level = identity->mldsa_level;
	request.usage =
		PQCP_RUNTIME_USAGE_SIGN |
		PQCP_RUNTIME_USAGE_VERIFY |
		PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
		PQCP_RUNTIME_USAGE_DESTROY;
	request.now_ms = now_ms;
	request.expires_at_ms = expires_at_ms;
	request.owner = identity->identity_id;
	request.label = "identity-key";
	request.exportable_public = true;
	identity->rotation_pending = true;
	ret = pqcp_runtime_key_store_rotate(
		store->key_store, &identity->local_key,
		&request, &new_handle);
	if (ret != 0) {
		identity->rotation_pending = false;
		return ret;
	}
	identity->local_key = new_handle;
	ret = pqcp_runtime_key_store_export_public(
		store->key_store, &new_handle,
		identity->peer_public_key,
		sizeof(identity->peer_public_key),
		&public_length);
	if (ret == 0) {
		identity->peer_public_key_length = public_length;
		ret = fingerprint_public_key(
			identity->peer_public_key, public_length,
			identity->fingerprint);
	}
	identity->created_at_ms = now_ms;
	identity->expires_at_ms = expires_at_ms;
	identity->use_count = 0U;
	identity->rotation_pending = false;
	store->generation++;
	return ret;
}

int pqcp_runtime_identity_remove(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id)
{
	struct pqcp_runtime_identity *identity;
	struct pqcp_runtime_key_handle key;
	bool local;
	int ret;

	if (store == NULL || !identity_id_valid(identity_id)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	identity = find_unlocked(store, identity_id);
	if (identity == NULL) {
		(void)k_mutex_unlock(&store->lock);
		return -ENOENT;
	}
	key = identity->local_key;
	local = identity->local;
	pqcp_runtime_secure_zero(identity, sizeof(*identity));
	if (store->active_count != 0U) {
		store->active_count--;
	}
	store->generation++;
	(void)k_mutex_unlock(&store->lock);
	if (local && pqcp_runtime_key_handle_is_valid(&key)) {
		return pqcp_runtime_key_store_destroy(
			store->key_store, &key);
	}
	return 0;
}

int pqcp_runtime_identity_expire(
	struct pqcp_runtime_identity_store *store,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	char ids[CONFIG_PQCP_RUNTIME_MAX_IDENTITIES]
		[PQCP_RUNTIME_IDENTITY_MAX_ID_CHARS];
	uint32_t count = 0U;

	if (store == NULL || now_ms == 0U ||
	    expired_count == NULL ||
	    store->capacity >
		    CONFIG_PQCP_RUNTIME_MAX_IDENTITIES) {
		return -EINVAL;
	}
	if (k_mutex_lock(&store->lock, K_FOREVER) != 0) {
		return -EIO;
	}
	for (size_t index = 0U; index < store->capacity; ++index) {
		const struct pqcp_runtime_identity *identity =
			&store->identities[index];

		if (identity->active &&
		    identity->expires_at_ms != 0U &&
		    identity->expires_at_ms <= now_ms) {
			(void)pqcp_runtime_internal_copy_text(
				ids[count], sizeof(ids[count]),
				identity->identity_id);
			count++;
		}
	}
	(void)k_mutex_unlock(&store->lock);
	for (uint32_t index = 0U; index < count; ++index) {
		(void)pqcp_runtime_identity_remove(
			store, ids[index]);
	}
	*expired_count = count;
	return 0;
}

int pqcp_runtime_identity_configure_channel(
	struct pqcp_runtime_identity_store *store,
	const char *local_identity_id,
	const char *peer_identity_id,
	struct pqcp_channel_config *config)
{
	struct pqcp_runtime_identity *local;
	struct pqcp_runtime_identity *peer;

	if (store == NULL || config == NULL ||
	    !identity_id_valid(local_identity_id) ||
	    !identity_id_valid(peer_identity_id)) {
		return -EINVAL;
	}
	if (k_mutex_lock(&store->lock, K_FOREVER) != 0) {
		return -EIO;
	}
	local = find_unlocked(store, local_identity_id);
	peer = find_unlocked(store, peer_identity_id);
	if (local == NULL || peer == NULL ||
	    !local->local || peer->local || !peer->trusted ||
	    local->mldsa_level != peer->mldsa_level ||
	    local->mldsa_level != config->mldsa_level) {
		(void)k_mutex_unlock(&store->lock);
		return -EKEYREJECTED;
	}
	config->local_identity = local->local_key;
	memcpy(config->peer_identity_public,
	       peer->peer_public_key,
	       peer->peer_public_key_length);
	config->peer_identity_public_length =
		peer->peer_public_key_length;
	local->use_count++;
	peer->use_count++;
	(void)k_mutex_unlock(&store->lock);
	return 0;
}

int pqcp_runtime_identity_store_audit(
	struct pqcp_runtime_identity_store *store)
{
	uint32_t active = 0U;

	if (store == NULL ||
	    store->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    store->identities == NULL ||
	    store->capacity == 0U ||
	    store->key_store == NULL) {
		return -EINVAL;
	}
	if (k_mutex_lock(&store->lock, K_FOREVER) != 0) {
		return -EIO;
	}
	for (size_t index = 0U; index < store->capacity; ++index) {
		const struct pqcp_runtime_identity *identity =
			&store->identities[index];

		if (!identity->active) {
			continue;
		}
		active++;
		if (identity->schema_version !=
			    PQCP_RUNTIME_SCHEMA_VERSION ||
		    !identity_id_valid(identity->identity_id) ||
		    !mldsa_level_valid(identity->mldsa_level) ||
		    identity->peer_public_key_length !=
			    pqcp_mldsa_pk_size(
				    (pqcp_mldsa_level_t)
					    identity->mldsa_level) ||
		    (identity->local &&
		     !pqcp_runtime_key_handle_is_valid(
			     &identity->local_key)) ||
		    (!identity->local && !identity->trusted)) {
			(void)k_mutex_unlock(&store->lock);
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < store->capacity; ++other) {
			if (store->identities[other].active &&
			    strcmp(identity->identity_id,
				   store->identities[other]
					   .identity_id) == 0) {
				(void)k_mutex_unlock(&store->lock);
				return -EBADMSG;
			}
		}
	}
	(void)k_mutex_unlock(&store->lock);
	return active == store->active_count ? 0 : -EBADMSG;
}
