/*
 * SPDX-License-Identifier: MIT
 *
 * Pinned ML-DSA identity management for protected channels.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_IDENTITY_H_
#define PQCP_ZEPHYR_RUNTIME_IDENTITY_H_

#include <pqcp_zephyr/protected_channel.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_IDENTITY_MAX_ID_CHARS 32U

struct pqcp_runtime_identity {
	uint32_t schema_version;
	char identity_id[PQCP_RUNTIME_IDENTITY_MAX_ID_CHARS];
	uint32_t mldsa_level;
	struct pqcp_runtime_key_handle local_key;
	uint8_t peer_public_key[PQCP_MLDSA_PK_SIZE_MAX];
	size_t peer_public_key_length;
	uint8_t fingerprint[PQCP_RUNTIME_DIGEST_BYTES];
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint32_t use_count;
	bool active;
	bool local;
	bool trusted;
	bool rotation_pending;
};

struct pqcp_runtime_identity_store {
	uint32_t schema_version;
	struct pqcp_runtime_identity *identities;
	size_t capacity;
	size_t active_count;
	uint64_t generation;
	struct pqcp_runtime_key_store *key_store;
	struct k_mutex lock;
};

int pqcp_runtime_identity_store_init(
	struct pqcp_runtime_identity_store *store,
	struct pqcp_runtime_identity *identities,
	size_t capacity,
	struct pqcp_runtime_key_store *key_store);
int pqcp_runtime_identity_create_local(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id,
	uint32_t mldsa_level,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_runtime_identity **identity);
int pqcp_runtime_identity_pin_peer(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id,
	uint32_t mldsa_level,
	const uint8_t *public_key,
	size_t public_key_length,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_runtime_identity **identity);
struct pqcp_runtime_identity *pqcp_runtime_identity_find(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id);
int pqcp_runtime_identity_rotate_local(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id,
	uint64_t now_ms,
	uint64_t expires_at_ms);
int pqcp_runtime_identity_remove(
	struct pqcp_runtime_identity_store *store,
	const char *identity_id);
int pqcp_runtime_identity_expire(
	struct pqcp_runtime_identity_store *store,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_runtime_identity_configure_channel(
	struct pqcp_runtime_identity_store *store,
	const char *local_identity_id,
	const char *peer_identity_id,
	struct pqcp_channel_config *config);
int pqcp_runtime_identity_store_audit(
	struct pqcp_runtime_identity_store *store);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_IDENTITY_H_ */
