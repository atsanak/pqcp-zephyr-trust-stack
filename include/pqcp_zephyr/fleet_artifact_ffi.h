/*
 * SPDX-License-Identifier: MIT
 *
 * Stable C ABI for host applications and Rust coordinator integration.
 */

#ifndef PQCP_ZEPHYR_FLEET_ARTIFACT_FFI_H_
#define PQCP_ZEPHYR_FLEET_ARTIFACT_FFI_H_

#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/fleet_cose.h>
#include <pqcp_zephyr/fleet_eat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_ARTIFACT_ABI_VERSION 1U
#define PQCP_FLEET_ARTIFACT_FEATURE_COSE_SIGN1 (UINT64_C(1) << 0)
#define PQCP_FLEET_ARTIFACT_FEATURE_COSE_AKP (UINT64_C(1) << 1)
#define PQCP_FLEET_ARTIFACT_FEATURE_EAT_CWT (UINT64_C(1) << 2)
#define PQCP_FLEET_ARTIFACT_FEATURE_RATS (UINT64_C(1) << 3)
#define PQCP_FLEET_ARTIFACT_FEATURE_LEGACY_V1 (UINT64_C(1) << 4)
#define PQCP_FLEET_ARTIFACT_MAX_HANDLE_BYTES 32U

enum pqcp_fleet_artifact_kind {
	PQCP_FLEET_ARTIFACT_NONE = 0,
	PQCP_FLEET_ARTIFACT_COSE_SIGN1 = 1,
	PQCP_FLEET_ARTIFACT_COSE_KEY = 2,
	PQCP_FLEET_ARTIFACT_EAT_EVIDENCE = 3,
	PQCP_FLEET_ARTIFACT_EAT_RESULT = 4,
	PQCP_FLEET_ARTIFACT_LEGACY_V1 = 5,
};

enum pqcp_fleet_artifact_operation {
	PQCP_FLEET_ARTIFACT_OP_NONE = 0,
	PQCP_FLEET_ARTIFACT_OP_VALIDATE_CBOR,
	PQCP_FLEET_ARTIFACT_OP_SIGN1_SIGN,
	PQCP_FLEET_ARTIFACT_OP_SIGN1_VERIFY,
	PQCP_FLEET_ARTIFACT_OP_KEY_ENCODE,
	PQCP_FLEET_ARTIFACT_OP_KEY_DECODE,
	PQCP_FLEET_ARTIFACT_OP_EAT_SIGN,
	PQCP_FLEET_ARTIFACT_OP_EAT_VERIFY,
	PQCP_FLEET_ARTIFACT_OP_EAT_APPRAISE,
	PQCP_FLEET_ARTIFACT_OP_EAT_RESULT_SIGN,
};

struct pqcp_fleet_artifact_version {
	uint32_t abi_version;
	uint32_t implementation_version;
	uint64_t features;
};

struct pqcp_fleet_artifact_buffer {
	uint8_t *data;
	size_t capacity;
	size_t length;
};

struct pqcp_fleet_artifact_const_buffer {
	const uint8_t *data;
	size_t length;
};

struct pqcp_fleet_artifact_crypto_vtable {
	uint32_t abi_version;
	void *context;
	pqcp_fleet_cose_sign_fn sign;
	pqcp_fleet_cose_verify_fn verify;
	pqcp_fleet_cose_hash_fn hash;
};

struct pqcp_fleet_artifact_context {
	uint32_t abi_version;
	uint32_t flags;
	struct pqcp_fleet_artifact_crypto_vtable crypto;
	uint8_t *workspace;
	size_t workspace_capacity;
	uint64_t operation_count;
	int last_error;
};

struct pqcp_fleet_artifact_sign1_options {
	const struct pqcp_fleet_cose_headers *protected_headers;
	const struct pqcp_fleet_cose_headers *unprotected_headers;
};

struct pqcp_fleet_artifact_sign1_verify_options {
	struct pqcp_fleet_cose_sign1 *decoded;
};

struct pqcp_fleet_artifact_key_options {
	struct pqcp_fleet_cose_key *key;
	bool include_private;
	bool allow_private;
};

struct pqcp_fleet_artifact_eat_verify_options {
	struct pqcp_fleet_eat_claims *claims;
	const struct pqcp_fleet_eat_freshness *freshness;
};

struct pqcp_fleet_artifact_eat_appraise_options {
	const struct pqcp_fleet_eat_claims *claims;
	const struct pqcp_fleet_eat_appraisal_policy *policy;
	struct pqcp_fleet_eat_appraisal_result *result;
};

struct pqcp_fleet_artifact_request {
	uint32_t abi_version;
	enum pqcp_fleet_artifact_operation operation;
	struct pqcp_fleet_artifact_const_buffer input;
	struct pqcp_fleet_artifact_const_buffer payload;
	struct pqcp_fleet_artifact_const_buffer external_aad;
	struct pqcp_fleet_artifact_const_buffer key_id;
	struct pqcp_fleet_artifact_buffer output;
	void *object;
	const void *options;
};

struct pqcp_fleet_artifact_response {
	uint32_t abi_version;
	enum pqcp_fleet_artifact_kind kind;
	size_t bytes_written;
	int result;
	uint8_t digest[PQCP_FLEET_EAT_DIGEST_BYTES];
	size_t digest_length;
};

int pqcp_fleet_artifact_version(
	struct pqcp_fleet_artifact_version *version);
size_t pqcp_fleet_artifact_context_size(void);
size_t pqcp_fleet_artifact_required_workspace(
	enum pqcp_fleet_artifact_operation operation,
	size_t payload_length);
int pqcp_fleet_artifact_context_init(
	struct pqcp_fleet_artifact_context *context,
	const struct pqcp_fleet_artifact_crypto_vtable *crypto,
	uint8_t *workspace,
	size_t workspace_capacity,
	uint32_t flags);
int pqcp_fleet_artifact_execute(
	struct pqcp_fleet_artifact_context *context,
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response);
int pqcp_fleet_artifact_classify(
	const uint8_t *encoded,
	size_t encoded_length,
	enum pqcp_fleet_artifact_kind *kind);
int pqcp_fleet_artifact_last_error(
	const struct pqcp_fleet_artifact_context *context);
const char *pqcp_fleet_artifact_error_string(int error);
void pqcp_fleet_artifact_secure_zero(
	void *memory,
	size_t length);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_ARTIFACT_FFI_H_ */
