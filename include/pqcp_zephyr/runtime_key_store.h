/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP runtime key custody interface.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_KEY_STORE_H_
#define PQCP_ZEPHYR_RUNTIME_KEY_STORE_H_

#include <zephyr/kernel.h>

#include <pqcp_zephyr/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pqcp_runtime_key_store;

struct pqcp_runtime_key_store_ops {
	int (*create)(struct pqcp_runtime_key_store *store,
		      const struct pqcp_runtime_key_request *request,
		      const uint8_t *public_data,
		      size_t public_length,
		      const uint8_t *secret_data,
		      size_t secret_length,
		      struct pqcp_runtime_key_handle *handle);
	int (*generate)(struct pqcp_runtime_key_store *store,
			const struct pqcp_runtime_key_request *request,
			struct pqcp_runtime_key_handle *handle);
	int (*metadata)(struct pqcp_runtime_key_store *store,
			const struct pqcp_runtime_key_handle *handle,
			struct pqcp_runtime_key_metadata *metadata);
	int (*acquire)(struct pqcp_runtime_key_store *store,
		       const struct pqcp_runtime_key_handle *handle,
		       uint32_t required_usage,
		       uint64_t now_ms,
		       const uint8_t **public_data,
		       size_t *public_length);
	int (*release)(struct pqcp_runtime_key_store *store,
		       const struct pqcp_runtime_key_handle *handle);
	int (*export_public)(struct pqcp_runtime_key_store *store,
			     const struct pqcp_runtime_key_handle *handle,
			     uint8_t *output,
			     size_t output_capacity,
			     size_t *output_length);
	int (*sign)(struct pqcp_runtime_key_store *store,
		    const struct pqcp_runtime_key_handle *handle,
		    const uint8_t *message,
		    size_t message_length,
		    const uint8_t *context,
		    size_t context_length,
		    uint8_t *signature,
		    size_t signature_capacity,
		    size_t *signature_length);
	int (*verify)(struct pqcp_runtime_key_store *store,
		      const struct pqcp_runtime_key_handle *handle,
		      const uint8_t *message,
		      size_t message_length,
		      const uint8_t *context,
		      size_t context_length,
		      const uint8_t *signature,
		      size_t signature_length);
	int (*encapsulate)(struct pqcp_runtime_key_store *store,
			   const struct pqcp_runtime_key_handle *handle,
			   const struct pqcp_runtime_key_request *secret_request,
			   uint8_t *ciphertext,
			   size_t ciphertext_capacity,
			   size_t *ciphertext_length,
			   struct pqcp_runtime_key_handle *secret_handle);
	int (*decapsulate)(struct pqcp_runtime_key_store *store,
			   const struct pqcp_runtime_key_handle *handle,
			   const uint8_t *ciphertext,
			   size_t ciphertext_length,
			   const struct pqcp_runtime_key_request *secret_request,
			   struct pqcp_runtime_key_handle *secret_handle);
	int (*derive)(struct pqcp_runtime_key_store *store,
		      const struct pqcp_runtime_key_handle *handle,
		      const uint8_t *salt,
		      size_t salt_length,
		      const uint8_t *info,
		      size_t info_length,
		      const struct pqcp_runtime_key_request *derived_request,
		      struct pqcp_runtime_key_handle *derived_handle);
	int (*mac)(struct pqcp_runtime_key_store *store,
		   const struct pqcp_runtime_key_handle *handle,
		   const uint8_t *message,
		   size_t message_length,
		   uint8_t *tag,
		   size_t tag_capacity,
		   size_t *tag_length);
	int (*aead_encrypt)(struct pqcp_runtime_key_store *store,
			    const struct pqcp_runtime_key_handle *handle,
			    const uint8_t *nonce,
			    size_t nonce_length,
			    const uint8_t *aad,
			    size_t aad_length,
			    const uint8_t *plaintext,
			    size_t plaintext_length,
			    uint8_t *ciphertext,
			    size_t ciphertext_capacity,
			    size_t *ciphertext_length);
	int (*aead_decrypt)(struct pqcp_runtime_key_store *store,
			    const struct pqcp_runtime_key_handle *handle,
			    const uint8_t *nonce,
			    size_t nonce_length,
			    const uint8_t *aad,
			    size_t aad_length,
			    const uint8_t *ciphertext,
			    size_t ciphertext_length,
			    uint8_t *plaintext,
			    size_t plaintext_capacity,
			    size_t *plaintext_length);
	int (*rotate)(struct pqcp_runtime_key_store *store,
		      const struct pqcp_runtime_key_handle *old_handle,
		      const struct pqcp_runtime_key_request *request,
		      struct pqcp_runtime_key_handle *new_handle);
	int (*destroy)(struct pqcp_runtime_key_store *store,
		       const struct pqcp_runtime_key_handle *handle);
	int (*expire)(struct pqcp_runtime_key_store *store,
		      uint64_t now_ms,
		      uint32_t *expired_count);
	int (*audit)(struct pqcp_runtime_key_store *store);
};

struct pqcp_runtime_key_store {
	uint32_t schema_version;
	enum pqcp_runtime_key_backend backend;
	const struct pqcp_runtime_key_store_ops *ops;
	void *context;
	uint32_t capacity;
	uint32_t active_count;
	uint32_t generation_seed;
	uint32_t create_count;
	uint32_t destroy_count;
	uint32_t rejected_count;
	struct k_mutex lock;
};

struct pqcp_runtime_volatile_slot {
	struct pqcp_runtime_key_metadata metadata;
	uint32_t references;
	uint32_t generation;
	size_t public_length;
	size_t secret_length;
	uint8_t public_data[PQCP_RUNTIME_MAX_PUBLIC_KEY_BYTES];
	uint8_t secret_data[PQCP_RUNTIME_MAX_KEY_BYTES];
};

struct pqcp_runtime_volatile_context {
	struct pqcp_runtime_volatile_slot *slots;
	size_t slot_count;
};

struct pqcp_runtime_psa_context {
	uint32_t key_id_base;
	uint32_t key_id_count;
	uint32_t allocated_bitmap_words;
	uint32_t *allocated_bitmap;
	struct pqcp_runtime_key_metadata
		metadata[CONFIG_PQCP_RUNTIME_MAX_KEYS];
	uint32_t generations[CONFIG_PQCP_RUNTIME_MAX_KEYS];
	bool initialized;
	bool persistence_available;
};

int pqcp_runtime_key_store_init(
	struct pqcp_runtime_key_store *store,
	enum pqcp_runtime_key_backend backend,
	const struct pqcp_runtime_key_store_ops *ops,
	void *context,
	uint32_t capacity);
int pqcp_runtime_key_store_validate(
	const struct pqcp_runtime_key_store *store);

int pqcp_runtime_volatile_store_init(
	struct pqcp_runtime_key_store *store,
	struct pqcp_runtime_volatile_context *context,
	struct pqcp_runtime_volatile_slot *slots,
	size_t slot_count);

int pqcp_runtime_psa_store_init(
	struct pqcp_runtime_key_store *store,
	struct pqcp_runtime_psa_context *context,
	uint32_t key_id_base,
	uint32_t key_id_count,
	uint32_t *allocated_bitmap,
	size_t allocated_bitmap_words);
bool pqcp_runtime_psa_persistence_available(
	const struct pqcp_runtime_key_store *store);

int pqcp_runtime_key_store_create(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_request *request,
	const uint8_t *public_data,
	size_t public_length,
	const uint8_t *secret_data,
	size_t secret_length,
	struct pqcp_runtime_key_handle *handle);
int pqcp_runtime_key_store_generate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_request *request,
	struct pqcp_runtime_key_handle *handle);
int pqcp_runtime_key_store_metadata(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	struct pqcp_runtime_key_metadata *metadata);
int pqcp_runtime_key_store_acquire(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	uint32_t required_usage,
	uint64_t now_ms,
	const uint8_t **public_data,
	size_t *public_length);
int pqcp_runtime_key_store_release(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle);
int pqcp_runtime_key_store_export_public(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_runtime_key_store_sign(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *message,
	size_t message_length,
	const uint8_t *context,
	size_t context_length,
	uint8_t *signature,
	size_t signature_capacity,
	size_t *signature_length);
int pqcp_runtime_key_store_verify(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *message,
	size_t message_length,
	const uint8_t *context,
	size_t context_length,
	const uint8_t *signature,
	size_t signature_length);
int pqcp_runtime_key_store_encapsulate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const struct pqcp_runtime_key_request *secret_request,
	uint8_t *ciphertext,
	size_t ciphertext_capacity,
	size_t *ciphertext_length,
	struct pqcp_runtime_key_handle *secret_handle);
int pqcp_runtime_key_store_decapsulate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *ciphertext,
	size_t ciphertext_length,
	const struct pqcp_runtime_key_request *secret_request,
	struct pqcp_runtime_key_handle *secret_handle);
int pqcp_runtime_key_store_derive(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *salt,
	size_t salt_length,
	const uint8_t *info,
	size_t info_length,
	const struct pqcp_runtime_key_request *derived_request,
	struct pqcp_runtime_key_handle *derived_handle);
int pqcp_runtime_key_store_mac(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle,
	const uint8_t *message,
	size_t message_length,
	uint8_t *tag,
	size_t tag_capacity,
	size_t *tag_length);
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
	size_t *ciphertext_length);
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
	size_t *plaintext_length);
int pqcp_runtime_key_store_rotate(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *old_handle,
	const struct pqcp_runtime_key_request *request,
	struct pqcp_runtime_key_handle *new_handle);
int pqcp_runtime_key_store_destroy(
	struct pqcp_runtime_key_store *store,
	const struct pqcp_runtime_key_handle *handle);
int pqcp_runtime_key_store_expire(
	struct pqcp_runtime_key_store *store,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_runtime_key_store_audit(
	struct pqcp_runtime_key_store *store);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_KEY_STORE_H_ */
