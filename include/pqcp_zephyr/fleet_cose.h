/*
 * SPDX-License-Identifier: MIT
 *
 * Host-portable deterministic CBOR and COSE support for the PQCP fleet.
 *
 * This API intentionally has no Zephyr or PSA dependencies. Callers own all
 * buffers and provide cryptographic operations through callbacks.
 */

#ifndef PQCP_ZEPHYR_FLEET_COSE_H_
#define PQCP_ZEPHYR_FLEET_COSE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_COSE_ABI_VERSION 1U
#define PQCP_FLEET_COSE_SIGN1_TAG 18U
#define PQCP_FLEET_COSE_KEY_TAG 101U
#define PQCP_FLEET_COSE_ALG_ML_DSA_44 (-48)
#define PQCP_FLEET_COSE_ALG_ML_DSA_65 (-49)
#define PQCP_FLEET_COSE_ALG_ML_DSA_87 (-50)
#define PQCP_FLEET_COSE_KTY_AKP 7
#define PQCP_FLEET_COSE_HEADER_ALG 1
#define PQCP_FLEET_COSE_HEADER_CRIT 2
#define PQCP_FLEET_COSE_HEADER_CONTENT_TYPE 3
#define PQCP_FLEET_COSE_HEADER_KID 4
#define PQCP_FLEET_COSE_KEY_KTY 1
#define PQCP_FLEET_COSE_KEY_KID 2
#define PQCP_FLEET_COSE_KEY_ALG 3
#define PQCP_FLEET_COSE_KEY_OPS 4
#define PQCP_FLEET_COSE_KEY_BASE_IV 5
#define PQCP_FLEET_COSE_KEY_AKP_PUBLIC (-1)
#define PQCP_FLEET_COSE_KEY_AKP_PRIVATE (-2)
#define PQCP_FLEET_COSE_ML_DSA_44_PUBLIC_BYTES 1312U
#define PQCP_FLEET_COSE_ML_DSA_65_PUBLIC_BYTES 1952U
#define PQCP_FLEET_COSE_ML_DSA_87_PUBLIC_BYTES 2592U
#define PQCP_FLEET_COSE_ML_DSA_PRIVATE_SEED_BYTES 32U
#define PQCP_FLEET_COSE_ML_DSA_44_SIGNATURE_BYTES 2420U
#define PQCP_FLEET_COSE_ML_DSA_65_SIGNATURE_BYTES 3309U
#define PQCP_FLEET_COSE_ML_DSA_87_SIGNATURE_BYTES 4627U
#define PQCP_FLEET_COSE_MAX_KID_BYTES 64U
#define PQCP_FLEET_COSE_MAX_CONTENT_TYPE_BYTES 96U
#define PQCP_FLEET_COSE_MAX_PROFILE_BYTES 128U
#define PQCP_FLEET_COSE_MAX_CRITICAL_HEADERS 8U
#define PQCP_FLEET_COSE_MAX_KEY_OPERATIONS 8U
#define PQCP_FLEET_COSE_MAX_EXTERNAL_AAD_BYTES 256U
#define PQCP_FLEET_COSE_MAX_PROTECTED_BYTES 512U
#define PQCP_FLEET_COSE_MAX_SIGNATURE_BYTES \
	PQCP_FLEET_COSE_ML_DSA_87_SIGNATURE_BYTES
#define PQCP_FLEET_COSE_MAX_PUBLIC_KEY_BYTES \
	PQCP_FLEET_COSE_ML_DSA_87_PUBLIC_BYTES
#define PQCP_FLEET_COSE_MAX_PRIVATE_KEY_BYTES \
	PQCP_FLEET_COSE_ML_DSA_PRIVATE_SEED_BYTES
#define PQCP_FLEET_COSE_THUMBPRINT_BYTES 32U

enum pqcp_fleet_cbor_major {
	PQCP_FLEET_CBOR_UNSIGNED = 0,
	PQCP_FLEET_CBOR_NEGATIVE = 1,
	PQCP_FLEET_CBOR_BYTES = 2,
	PQCP_FLEET_CBOR_TEXT = 3,
	PQCP_FLEET_CBOR_ARRAY = 4,
	PQCP_FLEET_CBOR_MAP = 5,
	PQCP_FLEET_CBOR_TAG = 6,
	PQCP_FLEET_CBOR_SIMPLE = 7,
};

enum pqcp_fleet_cbor_simple {
	PQCP_FLEET_CBOR_FALSE = 20,
	PQCP_FLEET_CBOR_TRUE = 21,
	PQCP_FLEET_CBOR_NULL = 22,
};

enum pqcp_fleet_cose_content_type_kind {
	PQCP_FLEET_COSE_CONTENT_TYPE_NONE = 0,
	PQCP_FLEET_COSE_CONTENT_TYPE_INTEGER,
	PQCP_FLEET_COSE_CONTENT_TYPE_TEXT,
};

enum pqcp_fleet_cose_key_operation {
	PQCP_FLEET_COSE_KEY_OP_SIGN = 1,
	PQCP_FLEET_COSE_KEY_OP_VERIFY = 2,
	PQCP_FLEET_COSE_KEY_OP_ENCRYPT = 3,
	PQCP_FLEET_COSE_KEY_OP_DECRYPT = 4,
	PQCP_FLEET_COSE_KEY_OP_WRAP = 5,
	PQCP_FLEET_COSE_KEY_OP_UNWRAP = 6,
	PQCP_FLEET_COSE_KEY_OP_DERIVE_KEY = 7,
	PQCP_FLEET_COSE_KEY_OP_DERIVE_BITS = 8,
	PQCP_FLEET_COSE_KEY_OP_MAC_CREATE = 9,
	PQCP_FLEET_COSE_KEY_OP_MAC_VERIFY = 10,
};

enum pqcp_fleet_cose_error {
	PQCP_FLEET_COSE_OK = 0,
	PQCP_FLEET_COSE_ERR_ARGUMENT = -1,
	PQCP_FLEET_COSE_ERR_CAPACITY = -2,
	PQCP_FLEET_COSE_ERR_ENCODING = -3,
	PQCP_FLEET_COSE_ERR_NON_CANONICAL = -4,
	PQCP_FLEET_COSE_ERR_UNSUPPORTED = -5,
	PQCP_FLEET_COSE_ERR_CRYPTO = -6,
	PQCP_FLEET_COSE_ERR_SIGNATURE = -7,
	PQCP_FLEET_COSE_ERR_KEY = -8,
	PQCP_FLEET_COSE_ERR_DUPLICATE = -9,
	PQCP_FLEET_COSE_ERR_REQUIRED = -10,
	PQCP_FLEET_COSE_ERR_TRAILING = -11,
	PQCP_FLEET_COSE_ERR_POLICY = -12,
};

struct pqcp_fleet_const_bytes {
	const uint8_t *data;
	size_t length;
};

struct pqcp_fleet_mut_bytes {
	uint8_t *data;
	size_t capacity;
	size_t length;
};

struct pqcp_fleet_cbor_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
	uint8_t depth;
};

struct pqcp_fleet_cbor_reader {
	const uint8_t *buffer;
	size_t length;
	size_t offset;
	int error;
	uint8_t depth;
};

struct pqcp_fleet_cbor_head {
	enum pqcp_fleet_cbor_major major;
	uint64_t argument;
	size_t encoded_bytes;
};

struct pqcp_fleet_cbor_slice {
	const uint8_t *data;
	size_t length;
};

struct pqcp_fleet_cbor_map_key {
	bool integer;
	int64_t integer_value;
	const uint8_t *encoded;
	size_t encoded_length;
};

struct pqcp_fleet_cbor_map_cursor {
	size_t remaining;
	struct pqcp_fleet_cbor_map_key previous_key;
	bool have_previous;
};

struct pqcp_fleet_cose_headers {
	int32_t algorithm;
	enum pqcp_fleet_cose_content_type_kind content_type_kind;
	int64_t content_type_integer;
	char content_type_text[PQCP_FLEET_COSE_MAX_CONTENT_TYPE_BYTES];
	uint8_t kid[PQCP_FLEET_COSE_MAX_KID_BYTES];
	size_t kid_length;
	int64_t critical[PQCP_FLEET_COSE_MAX_CRITICAL_HEADERS];
	size_t critical_count;
	bool tagged;
};

struct pqcp_fleet_cose_sign1 {
	struct pqcp_fleet_cose_headers protected_headers;
	struct pqcp_fleet_cose_headers unprotected_headers;
	struct pqcp_fleet_cbor_slice protected_serialized;
	struct pqcp_fleet_cbor_slice payload;
	struct pqcp_fleet_cbor_slice signature;
	bool detached_payload;
	bool tagged;
};

struct pqcp_fleet_cose_key {
	int32_t key_type;
	int32_t algorithm;
	uint8_t kid[PQCP_FLEET_COSE_MAX_KID_BYTES];
	size_t kid_length;
	uint8_t public_key[PQCP_FLEET_COSE_MAX_PUBLIC_KEY_BYTES];
	size_t public_key_length;
	uint8_t private_seed[PQCP_FLEET_COSE_MAX_PRIVATE_KEY_BYTES];
	size_t private_seed_length;
	int32_t key_operations[PQCP_FLEET_COSE_MAX_KEY_OPERATIONS];
	size_t key_operation_count;
	uint8_t base_iv[32];
	size_t base_iv_length;
	bool tagged;
};

typedef int (*pqcp_fleet_cose_sign_fn)(
	void *context,
	int32_t algorithm,
	const uint8_t *key_id,
	size_t key_id_length,
	const uint8_t *message,
	size_t message_length,
	uint8_t *signature,
	size_t signature_capacity,
	size_t *signature_length);

typedef int (*pqcp_fleet_cose_verify_fn)(
	void *context,
	int32_t algorithm,
	const uint8_t *key_id,
	size_t key_id_length,
	const uint8_t *message,
	size_t message_length,
	const uint8_t *signature,
	size_t signature_length);

typedef int (*pqcp_fleet_cose_hash_fn)(
	void *context,
	const uint8_t *message,
	size_t message_length,
	uint8_t *digest,
	size_t digest_capacity,
	size_t *digest_length);

struct pqcp_fleet_cose_crypto {
	void *context;
	pqcp_fleet_cose_sign_fn sign;
	pqcp_fleet_cose_verify_fn verify;
	pqcp_fleet_cose_hash_fn hash;
};

void pqcp_fleet_cbor_writer_init(
	struct pqcp_fleet_cbor_writer *writer,
	uint8_t *buffer,
	size_t capacity);
int pqcp_fleet_cbor_write_uint(
	struct pqcp_fleet_cbor_writer *writer,
	uint64_t value);
int pqcp_fleet_cbor_write_int(
	struct pqcp_fleet_cbor_writer *writer,
	int64_t value);
int pqcp_fleet_cbor_write_bytes(
	struct pqcp_fleet_cbor_writer *writer,
	const uint8_t *value,
	size_t length);
int pqcp_fleet_cbor_write_text(
	struct pqcp_fleet_cbor_writer *writer,
	const char *value,
	size_t length);
int pqcp_fleet_cbor_write_bool(
	struct pqcp_fleet_cbor_writer *writer,
	bool value);
int pqcp_fleet_cbor_write_null(
	struct pqcp_fleet_cbor_writer *writer);
int pqcp_fleet_cbor_write_tag(
	struct pqcp_fleet_cbor_writer *writer,
	uint64_t tag);
int pqcp_fleet_cbor_write_array(
	struct pqcp_fleet_cbor_writer *writer,
	size_t count);
int pqcp_fleet_cbor_write_map(
	struct pqcp_fleet_cbor_writer *writer,
	size_t count);
int pqcp_fleet_cbor_write_encoded(
	struct pqcp_fleet_cbor_writer *writer,
	const uint8_t *encoded,
	size_t encoded_length);
int pqcp_fleet_cbor_writer_finish(
	struct pqcp_fleet_cbor_writer *writer,
	size_t *encoded_length);

void pqcp_fleet_cbor_reader_init(
	struct pqcp_fleet_cbor_reader *reader,
	const uint8_t *buffer,
	size_t length);
int pqcp_fleet_cbor_read_head(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_head *head);
int pqcp_fleet_cbor_read_uint(
	struct pqcp_fleet_cbor_reader *reader,
	uint64_t *value);
int pqcp_fleet_cbor_read_int(
	struct pqcp_fleet_cbor_reader *reader,
	int64_t *value);
int pqcp_fleet_cbor_read_bytes(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_slice *value);
int pqcp_fleet_cbor_read_text(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_slice *value);
int pqcp_fleet_cbor_read_bool(
	struct pqcp_fleet_cbor_reader *reader,
	bool *value);
int pqcp_fleet_cbor_read_null(
	struct pqcp_fleet_cbor_reader *reader);
int pqcp_fleet_cbor_read_tag(
	struct pqcp_fleet_cbor_reader *reader,
	uint64_t expected_tag);
int pqcp_fleet_cbor_read_array(
	struct pqcp_fleet_cbor_reader *reader,
	size_t *count);
int pqcp_fleet_cbor_read_map(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_map_cursor *cursor);
int pqcp_fleet_cbor_map_next(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_map_cursor *cursor,
	struct pqcp_fleet_cbor_map_key *key);
int pqcp_fleet_cbor_skip(
	struct pqcp_fleet_cbor_reader *reader);
int pqcp_fleet_cbor_reader_finish(
	struct pqcp_fleet_cbor_reader *reader);
int pqcp_fleet_cbor_validate(
	const uint8_t *encoded,
	size_t encoded_length);
int pqcp_fleet_cbor_item_span(
	const uint8_t *encoded,
	size_t encoded_length,
	size_t *item_length);
int pqcp_fleet_cbor_copy_item(
	const uint8_t *encoded,
	size_t encoded_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_fleet_cbor_array_get(
	const uint8_t *encoded,
	size_t encoded_length,
	size_t index,
	struct pqcp_fleet_cbor_slice *value);
int pqcp_fleet_cbor_array_count(
	const uint8_t *encoded,
	size_t encoded_length,
	size_t *count);
int pqcp_fleet_cbor_map_find_int(
	const uint8_t *encoded,
	size_t encoded_length,
	int64_t label,
	struct pqcp_fleet_cbor_slice *value);
int pqcp_fleet_cbor_map_count(
	const uint8_t *encoded,
	size_t encoded_length,
	size_t *count);
int pqcp_fleet_cbor_compare_encoded_keys(
	const uint8_t *left,
	size_t left_length,
	const uint8_t *right,
	size_t right_length);

size_t pqcp_fleet_cose_algorithm_public_key_bytes(
	int32_t algorithm);
size_t pqcp_fleet_cose_algorithm_signature_bytes(
	int32_t algorithm);
int pqcp_fleet_cose_headers_validate(
	const struct pqcp_fleet_cose_headers *headers,
	bool protected_bucket);
int pqcp_fleet_cose_protected_encode(
	const struct pqcp_fleet_cose_headers *headers,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_fleet_cose_protected_decode(
	const uint8_t *encoded,
	size_t encoded_length,
	struct pqcp_fleet_cose_headers *headers);
int pqcp_fleet_cose_sig_structure(
	const uint8_t *protected_serialized,
	size_t protected_length,
	const uint8_t *external_aad,
	size_t external_aad_length,
	const uint8_t *payload,
	size_t payload_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_fleet_cose_sign1_encode(
	const struct pqcp_fleet_cose_sign1 *message,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_fleet_cose_sign1_decode(
	const uint8_t *encoded,
	size_t encoded_length,
	struct pqcp_fleet_cose_sign1 *message);
int pqcp_fleet_cose_sign1_sign(
	const struct pqcp_fleet_cose_headers *protected_headers,
	const struct pqcp_fleet_cose_headers *unprotected_headers,
	const uint8_t *payload,
	size_t payload_length,
	const uint8_t *external_aad,
	size_t external_aad_length,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t *workspace,
	size_t workspace_capacity,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_fleet_cose_sign1_verify(
	const uint8_t *encoded,
	size_t encoded_length,
	const uint8_t *detached_payload,
	size_t detached_payload_length,
	const uint8_t *external_aad,
	size_t external_aad_length,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t *workspace,
	size_t workspace_capacity,
	struct pqcp_fleet_cose_sign1 *message);

int pqcp_fleet_cose_key_validate(
	const struct pqcp_fleet_cose_key *key,
	bool allow_private);
int pqcp_fleet_cose_key_encode(
	const struct pqcp_fleet_cose_key *key,
	bool include_private,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_fleet_cose_key_decode(
	const uint8_t *encoded,
	size_t encoded_length,
	bool allow_private,
	struct pqcp_fleet_cose_key *key);
int pqcp_fleet_cose_key_thumbprint_input(
	const struct pqcp_fleet_cose_key *key,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_fleet_cose_key_thumbprint(
	const struct pqcp_fleet_cose_key *key,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t output[PQCP_FLEET_COSE_THUMBPRINT_BYTES]);
int pqcp_fleet_cose_key_matches_algorithm(
	const struct pqcp_fleet_cose_key *key,
	int32_t algorithm);

const char *pqcp_fleet_cose_error_string(int error);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_COSE_H_ */
