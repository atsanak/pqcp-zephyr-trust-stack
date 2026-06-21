/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Policy-bound, allocation-free post-quantum crypto broker.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_CRYPTO_BROKER_H_
#define PQCP_ZEPHYR_CRYPTO_BROKER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/runtime_executor.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_CRYPTO_BROKER_SCHEMA_VERSION 1U
#define PQCP_CRYPTO_BROKER_TOKEN_BYTES 32U
#define PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES 16U
#define PQCP_CRYPTO_BROKER_RECEIPT_MAC_BYTES 32U
#define PQCP_CRYPTO_BROKER_ID_MAX_CHARS 32U
#define PQCP_CRYPTO_BROKER_TENANT_MAX_CHARS 32U
#define PQCP_CRYPTO_BROKER_DOMAIN_MAX_CHARS 32U
#define PQCP_CRYPTO_BROKER_REASON_MAX_CHARS 64U
#define PQCP_CRYPTO_BROKER_RECEIPT_CONTEXT \
	"pqcp-broker-receipt-v1"
#define PQCP_CRYPTO_BROKER_RESPONSE_MAX_BYTES \
	PQCP_RUNTIME_MAX_OUTPUT_BYTES

enum pqcp_crypto_broker_request_flag {
	PQCP_CRYPTO_BROKER_REQUEST_CHANNEL_AUTHENTICATED = (1U << 0),
	PQCP_CRYPTO_BROKER_REQUEST_ZERO_OUTPUT_ON_FAILURE = (1U << 1),
	PQCP_CRYPTO_BROKER_REQUEST_REQUIRE_SIGNED_RECEIPT = (1U << 2),
};

enum pqcp_crypto_broker_operation {
	PQCP_CRYPTO_BROKER_OPERATION_NONE = 0,
	PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE,
	PQCP_CRYPTO_BROKER_OPERATION_EXPORT_PUBLIC,
	PQCP_CRYPTO_BROKER_OPERATION_SIGN,
	PQCP_CRYPTO_BROKER_OPERATION_VERIFY,
	PQCP_CRYPTO_BROKER_OPERATION_KEM_ENCAPSULATE,
	PQCP_CRYPTO_BROKER_OPERATION_KEM_DECAPSULATE,
	PQCP_CRYPTO_BROKER_OPERATION_HKDF_DERIVE,
	PQCP_CRYPTO_BROKER_OPERATION_MAC,
	PQCP_CRYPTO_BROKER_OPERATION_AEAD_ENCRYPT,
	PQCP_CRYPTO_BROKER_OPERATION_AEAD_DECRYPT,
	PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE,
	PQCP_CRYPTO_BROKER_OPERATION_KEY_DESTROY,
	PQCP_CRYPTO_BROKER_OPERATION_KEY_METADATA,
	PQCP_CRYPTO_BROKER_OPERATION_COUNT,
};

#define PQCP_CRYPTO_BROKER_OPERATION_BIT(operation) \
	(1U << (uint32_t)(operation))
#define PQCP_CRYPTO_BROKER_FAMILY_BIT(family) \
	(1U << (uint32_t)(family))
#define PQCP_CRYPTO_BROKER_CUSTODY_BIT(custody) \
	(1U << (uint32_t)(custody))

enum pqcp_crypto_broker_principal_state {
	PQCP_CRYPTO_BROKER_PRINCIPAL_EMPTY = 0,
	PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE,
	PQCP_CRYPTO_BROKER_PRINCIPAL_SUSPENDED,
	PQCP_CRYPTO_BROKER_PRINCIPAL_REVOKED,
};

enum pqcp_crypto_broker_grant_state {
	PQCP_CRYPTO_BROKER_GRANT_EMPTY = 0,
	PQCP_CRYPTO_BROKER_GRANT_ACTIVE,
	PQCP_CRYPTO_BROKER_GRANT_EXHAUSTED,
	PQCP_CRYPTO_BROKER_GRANT_EXPIRED,
	PQCP_CRYPTO_BROKER_GRANT_REVOKED,
};

enum pqcp_crypto_broker_capability_state {
	PQCP_CRYPTO_BROKER_CAPABILITY_EMPTY = 0,
	PQCP_CRYPTO_BROKER_CAPABILITY_ACTIVE,
	PQCP_CRYPTO_BROKER_CAPABILITY_EXHAUSTED,
	PQCP_CRYPTO_BROKER_CAPABILITY_EXPIRED,
	PQCP_CRYPTO_BROKER_CAPABILITY_REVOKED,
};

enum pqcp_crypto_broker_transaction_state {
	PQCP_CRYPTO_BROKER_TRANSACTION_EMPTY = 0,
	PQCP_CRYPTO_BROKER_TRANSACTION_ACCEPTED,
	PQCP_CRYPTO_BROKER_TRANSACTION_RUNNING,
	PQCP_CRYPTO_BROKER_TRANSACTION_CANCEL_REQUESTED,
	PQCP_CRYPTO_BROKER_TRANSACTION_COMPLETED,
	PQCP_CRYPTO_BROKER_TRANSACTION_CANCELLED,
	PQCP_CRYPTO_BROKER_TRANSACTION_FAILED,
};

enum pqcp_crypto_broker_decision {
	PQCP_CRYPTO_BROKER_DECISION_UNSET = 0,
	PQCP_CRYPTO_BROKER_DECISION_ALLOW,
	PQCP_CRYPTO_BROKER_DECISION_DENY_AUTHENTICATION,
	PQCP_CRYPTO_BROKER_DECISION_DENY_CAPABILITY,
	PQCP_CRYPTO_BROKER_DECISION_DENY_GRANT,
	PQCP_CRYPTO_BROKER_DECISION_DENY_QUOTA,
	PQCP_CRYPTO_BROKER_DECISION_DENY_KEY_OWNERSHIP,
	PQCP_CRYPTO_BROKER_DECISION_DENY_CUSTODY,
	PQCP_CRYPTO_BROKER_DECISION_DENY_DEADLINE,
	PQCP_CRYPTO_BROKER_DECISION_DENY_REPLAY,
	PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY,
};

enum pqcp_crypto_broker_receipt_mode {
	PQCP_CRYPTO_BROKER_RECEIPT_HMAC = 0,
	PQCP_CRYPTO_BROKER_RECEIPT_HMAC_AND_MLDSA,
};

struct pqcp_crypto_broker_quota {
	uint32_t maximum_active_keys;
	uint32_t maximum_inflight_requests;
	uint32_t maximum_operations_per_window;
	uint64_t maximum_input_bytes_per_window;
	uint64_t maximum_output_bytes_per_window;
	uint64_t maximum_cost_units_per_window;
	uint64_t window_ms;
};

struct pqcp_crypto_broker_usage {
	uint64_t window_started_ms;
	uint32_t inflight_requests;
	uint32_t active_keys;
	uint32_t operations;
	uint64_t input_bytes;
	uint64_t output_bytes;
	uint64_t cost_units;
	uint64_t accepted_requests;
	uint64_t rejected_requests;
	uint64_t completed_requests;
	uint64_t cancelled_requests;
};

struct pqcp_crypto_broker_principal {
	uint32_t schema_version;
	uint32_t generation;
	char id[PQCP_CRYPTO_BROKER_ID_MAX_CHARS];
	char tenant[PQCP_CRYPTO_BROKER_TENANT_MAX_CHARS];
	char trust_domain[PQCP_CRYPTO_BROKER_DOMAIN_MAX_CHARS];
	uint8_t identity_digest[PQCP_RUNTIME_DIGEST_BYTES];
	struct pqcp_crypto_broker_quota quota;
	struct pqcp_crypto_broker_usage usage;
	uint64_t created_at_ms;
	uint64_t suspended_at_ms;
	uint64_t revoked_at_ms;
	enum pqcp_crypto_broker_principal_state state;
	bool channel_identity_required;
};

struct pqcp_crypto_broker_grant_policy {
	uint32_t operation_mask;
	uint32_t key_family_mask;
	uint32_t key_usage_mask;
	uint32_t custody_mask;
	uint32_t maximum_input_bytes;
	uint32_t maximum_output_bytes;
	uint64_t maximum_deadline_horizon_ms;
	uint64_t maximum_key_lifetime_ms;
	uint64_t cost_unit_limit;
	bool allow_persistent_keys;
	bool allow_public_export;
	bool require_signed_receipt;
	bool require_channel_identity;
};

struct pqcp_crypto_broker_grant {
	uint32_t schema_version;
	uint32_t grant_id;
	uint32_t generation;
	uint32_t principal_index;
	struct pqcp_crypto_broker_grant_policy policy;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint32_t maximum_uses;
	uint32_t use_count;
	uint64_t created_at_ms;
	uint64_t revoked_at_ms;
	enum pqcp_crypto_broker_grant_state state;
};

struct pqcp_crypto_broker_capability {
	uint32_t schema_version;
	uint32_t generation;
	uint32_t principal_index;
	uint32_t grant_index;
	uint8_t token_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t parent_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint32_t operation_mask;
	uint32_t key_family_mask;
	uint32_t key_usage_mask;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint32_t maximum_uses;
	uint32_t use_count;
	enum pqcp_crypto_broker_capability_state state;
	bool attenuated;
};

struct pqcp_crypto_broker_key_spec {
	enum pqcp_runtime_key_family family;
	uint32_t level;
	uint32_t usage;
	uint64_t expires_at_ms;
	char label[PQCP_RUNTIME_LABEL_MAX_CHARS];
	bool persistent;
	bool exportable_public;
};

struct pqcp_crypto_broker_request {
	uint32_t schema_version;
	uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES];
	uint8_t capability[PQCP_CRYPTO_BROKER_TOKEN_BYTES];
	char principal_id[PQCP_CRYPTO_BROKER_ID_MAX_CHARS];
	enum pqcp_crypto_broker_operation operation;
	uint64_t submitted_at_ms;
	uint64_t deadline_ms;
	uint32_t flags;
	uint32_t level;
	struct pqcp_crypto_broker_key_spec key_spec;
	struct pqcp_runtime_key_handle primary_key;
	struct pqcp_runtime_key_handle secondary_key;
	const uint8_t *input;
	size_t input_length;
	const uint8_t *aux_input;
	size_t aux_input_length;
	const uint8_t *context;
	size_t context_length;
};

struct pqcp_crypto_broker_authorization {
	uint32_t principal_index;
	uint32_t grant_index;
	uint32_t capability_index;
	enum pqcp_crypto_broker_decision decision;
	uint64_t cost_units;
	char reason[PQCP_CRYPTO_BROKER_REASON_MAX_CHARS];
};

struct pqcp_crypto_broker_receipt {
	uint32_t schema_version;
	uint64_t sequence;
	uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES];
	uint8_t request_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t principal_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t authorization_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t key_binding_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t output_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t previous_receipt_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t receipt_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t mac[PQCP_CRYPTO_BROKER_RECEIPT_MAC_BYTES];
	uint8_t signature[PQCP_MLDSA_SIG_SIZE_MAX];
	size_t signature_length;
	uint64_t accepted_at_ms;
	uint64_t completed_at_ms;
	uint64_t cost_units;
	enum pqcp_crypto_broker_operation operation;
	enum pqcp_crypto_broker_decision decision;
	int result;
	bool signed_receipt;
};

struct pqcp_crypto_broker_response {
	int result;
	bool replayed;
	bool cancelled;
	struct pqcp_runtime_key_handle primary_key;
	struct pqcp_runtime_key_handle secondary_key;
	struct pqcp_runtime_key_metadata metadata;
	uint8_t *output;
	size_t output_capacity;
	size_t output_length;
	struct pqcp_crypto_broker_receipt receipt;
};

struct pqcp_crypto_broker_transaction {
	uint32_t schema_version;
	uint32_t generation;
	uint32_t principal_index;
	uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES];
	uint8_t request_digest[PQCP_RUNTIME_DIGEST_BYTES];
	enum pqcp_crypto_broker_transaction_state state;
	enum pqcp_crypto_broker_operation operation;
	uint64_t accepted_at_ms;
	uint64_t completed_at_ms;
	uint64_t job_id;
	int result;
	struct pqcp_runtime_key_handle primary_key;
	struct pqcp_runtime_key_handle secondary_key;
	struct pqcp_runtime_key_metadata metadata;
	uint8_t output[PQCP_CRYPTO_BROKER_RESPONSE_MAX_BYTES];
	size_t output_length;
	struct pqcp_crypto_broker_receipt receipt;
};

struct pqcp_crypto_broker_storage {
	struct pqcp_crypto_broker_principal *principals;
	size_t principal_capacity;
	struct pqcp_crypto_broker_grant *grants;
	size_t grant_capacity;
	struct pqcp_crypto_broker_capability *capabilities;
	size_t capability_capacity;
	struct pqcp_crypto_broker_transaction *transactions;
	size_t transaction_capacity;
};

struct pqcp_crypto_broker_config {
	struct pqcp_runtime_executor *executor;
	struct pqcp_runtime_key_store *key_store;
	const uint8_t *receipt_mac_key;
	size_t receipt_mac_key_length;
	struct pqcp_runtime_key_handle receipt_signing_key;
	enum pqcp_crypto_broker_receipt_mode receipt_mode;
	uint64_t maximum_capability_lifetime_ms;
	uint64_t transaction_retention_ms;
	uint32_t maximum_cost_per_request;
	bool require_channel_identity;
};

struct pqcp_crypto_broker {
	uint32_t schema_version;
	struct pqcp_crypto_broker_config config;
	struct pqcp_crypto_broker_storage storage;
	uint8_t receipt_chain_head[PQCP_RUNTIME_DIGEST_BYTES];
	uint64_t next_receipt_sequence;
	uint64_t next_job_id;
	uint32_t next_principal_generation;
	uint32_t next_grant_id;
	uint32_t next_grant_generation;
	uint32_t next_capability_generation;
	uint32_t next_transaction_generation;
	uint64_t accepted_requests;
	uint64_t rejected_requests;
	uint64_t replayed_requests;
	uint64_t cancelled_requests;
	struct k_mutex lock;
	bool initialized;
};

const char *pqcp_crypto_broker_operation_str(
	enum pqcp_crypto_broker_operation operation);
const char *pqcp_crypto_broker_decision_str(
	enum pqcp_crypto_broker_decision decision);

int pqcp_crypto_broker_init(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_config *config,
	const struct pqcp_crypto_broker_storage *storage);
int pqcp_crypto_broker_register_principal(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	const char *tenant,
	const char *trust_domain,
	const uint8_t identity_digest[PQCP_RUNTIME_DIGEST_BYTES],
	const struct pqcp_crypto_broker_quota *quota,
	bool channel_identity_required,
	uint64_t now_ms);
int pqcp_crypto_broker_suspend_principal(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	uint64_t now_ms);
int pqcp_crypto_broker_resume_principal(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	uint64_t now_ms);
int pqcp_crypto_broker_revoke_principal(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	uint64_t now_ms);

int pqcp_crypto_broker_create_grant(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	const struct pqcp_crypto_broker_grant_policy *policy,
	uint64_t not_before_ms,
	uint64_t expires_at_ms,
	uint32_t maximum_uses,
	uint64_t now_ms,
	uint32_t *grant_id);
int pqcp_crypto_broker_revoke_grant(
	struct pqcp_crypto_broker *broker,
	uint32_t grant_id,
	uint64_t now_ms);

int pqcp_crypto_broker_issue_capability(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	uint32_t grant_id,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint32_t maximum_uses,
	uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES]);
int pqcp_crypto_broker_attenuate_capability(
	struct pqcp_crypto_broker *broker,
	const uint8_t parent_token[PQCP_CRYPTO_BROKER_TOKEN_BYTES],
	uint32_t operation_mask,
	uint32_t key_family_mask,
	uint32_t key_usage_mask,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint32_t maximum_uses,
	uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES]);
int pqcp_crypto_broker_revoke_capability(
	struct pqcp_crypto_broker *broker,
	const uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES]);

int pqcp_crypto_broker_authorize(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	uint64_t now_ms,
	struct pqcp_crypto_broker_authorization *authorization);
int pqcp_crypto_broker_execute(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	struct pqcp_crypto_broker_response *response);
int pqcp_crypto_broker_cancel(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	uint64_t now_ms);
int pqcp_crypto_broker_forget(
	struct pqcp_crypto_broker *broker,
	uint64_t now_ms,
	uint32_t *forgotten_count);

int pqcp_crypto_broker_receipt_verify(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_receipt *receipt);
int pqcp_crypto_broker_receipt_chain_verify(
	const struct pqcp_crypto_broker_transaction *transactions,
	size_t transaction_count,
	uint8_t chain_head[PQCP_RUNTIME_DIGEST_BYTES]);
int pqcp_crypto_broker_audit(
	struct pqcp_crypto_broker *broker);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_CRYPTO_BROKER_H_ */
