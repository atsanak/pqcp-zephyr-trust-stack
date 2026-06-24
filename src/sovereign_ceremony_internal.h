/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Private allocation-free machinery for sovereign approvals and key
 * ceremonies.  The public storage model remains in sovereign_runtime.h.
 */

#ifndef PQCP_SOVEREIGN_CEREMONY_INTERNAL_H_
#define PQCP_SOVEREIGN_CEREMONY_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/crypto_broker.h>
#include <pqcp_zephyr/runtime_key_store.h>
#include <pqcp_zephyr/sovereign_runtime.h>

#define PQCP_SOVEREIGN_CEREMONY_CONTEXT \
	"pqcp-sovereign-key-ceremony-v1"
#define PQCP_SOVEREIGN_APPROVAL_CONTEXT \
	"pqcp-sovereign-approval-v1"
#define PQCP_SOVEREIGN_AUTHORIZATION_CONTEXT \
	"pqcp-sovereign-authorization-v1"
#define PQCP_SOVEREIGN_CUSTODY_CONTEXT \
	"pqcp-sovereign-custody-v1"
#define PQCP_SOVEREIGN_SECRET_GRANT_CONTEXT \
	"pqcp-sovereign-secret-grant-v1"

#define PQCP_SOVEREIGN_MAX_SIGNATURE_BYTES PQCP_MLDSA_SIG_SIZE_MAX
#define PQCP_SOVEREIGN_MAX_AUTHORIZATIONS 16U
#define PQCP_SOVEREIGN_MAX_CEREMONY_BINDINGS 16U
#define PQCP_SOVEREIGN_MAX_SECRET_REFERENCES 16U
#define PQCP_SOVEREIGN_CANONICAL_APPROVAL_BYTES 768U
#define PQCP_SOVEREIGN_CANONICAL_AUTHORIZATION_BYTES 1024U
#define PQCP_SOVEREIGN_CANONICAL_CEREMONY_BYTES 768U
#define PQCP_SOVEREIGN_CANONICAL_CUSTODY_BYTES 512U
#define PQCP_SOVEREIGN_CANONICAL_SECRET_GRANT_BYTES 512U

enum pqcp_sovereign_ceremony_action {
	PQCP_SOVEREIGN_CEREMONY_ACTION_NONE = 0,
	PQCP_SOVEREIGN_CEREMONY_ACTION_GENERATE,
	PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE,
	PQCP_SOVEREIGN_CEREMONY_ACTION_RETIRE,
	PQCP_SOVEREIGN_CEREMONY_ACTION_DESTROY,
	PQCP_SOVEREIGN_CEREMONY_ACTION_RECOVER,
	PQCP_SOVEREIGN_CEREMONY_ACTION_COUNT,
};

enum pqcp_sovereign_approval_role {
	PQCP_SOVEREIGN_APPROVAL_ROLE_NONE = 0,
	PQCP_SOVEREIGN_APPROVAL_ROLE_SECURITY_OFFICER,
	PQCP_SOVEREIGN_APPROVAL_ROLE_KEY_CUSTODIAN,
	PQCP_SOVEREIGN_APPROVAL_ROLE_POLICY_OWNER,
	PQCP_SOVEREIGN_APPROVAL_ROLE_AUDITOR,
	PQCP_SOVEREIGN_APPROVAL_ROLE_RECOVERY_OFFICER,
	PQCP_SOVEREIGN_APPROVAL_ROLE_PRIVACY_STEWARD,
	PQCP_SOVEREIGN_APPROVAL_ROLE_COUNT,
};

#define PQCP_SOVEREIGN_APPROVAL_ROLE_BIT(role) \
	(1U << (uint32_t)(role))

enum pqcp_sovereign_authorization_state {
	PQCP_SOVEREIGN_AUTHORIZATION_EMPTY = 0,
	PQCP_SOVEREIGN_AUTHORIZATION_COLLECTING,
	PQCP_SOVEREIGN_AUTHORIZATION_COMMITTED,
	PQCP_SOVEREIGN_AUTHORIZATION_CONSUMED,
	PQCP_SOVEREIGN_AUTHORIZATION_EXPIRED,
	PQCP_SOVEREIGN_AUTHORIZATION_REVOKED,
};

enum pqcp_sovereign_custody_action {
	PQCP_SOVEREIGN_CUSTODY_ACTION_NONE = 0,
	PQCP_SOVEREIGN_CUSTODY_ACTION_CEREMONY_OPENED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_APPROVAL_ACCEPTED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_CONTRIBUTION_ACCEPTED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_KEY_GENERATED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_KEY_ROTATED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_KEY_RETIRED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_KEY_DESTROYED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_KEY_RECOVERED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_SECRET_GRANTED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_SECRET_USED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_SECRET_REVOKED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_CEREMONY_ABORTED,
	PQCP_SOVEREIGN_CUSTODY_ACTION_COUNT,
};

struct pqcp_sovereign_approval_policy_internal {
	uint32_t schema_version;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	enum pqcp_sovereign_ceremony_action action;
	uint64_t required_capabilities;
	uint32_t allowed_role_mask;
	uint32_t required_approvals;
	uint32_t required_distinct_roles;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint8_t target_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t nonce[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t previous_authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t policy_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_signer_credential_internal {
	uint32_t schema_version;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char signer_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	enum pqcp_sovereign_approval_role role;
	uint64_t capabilities;
	uint64_t credential_epoch;
	uint64_t revocation_epoch;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	struct pqcp_runtime_key_handle verification_key;
	uint8_t identity_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool revoked;
	bool occupied;
};

struct pqcp_sovereign_signed_approval_internal {
	uint32_t schema_version;
	uint64_t authorization_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char signer_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	enum pqcp_sovereign_approval_role role;
	enum pqcp_sovereign_ceremony_action action;
	uint64_t capabilities;
	uint64_t credential_epoch;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t signed_at_ms;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint8_t target_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t nonce[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t previous_authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t approval_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t signature[PQCP_SOVEREIGN_MAX_SIGNATURE_BYTES];
	size_t signature_length;
	bool approve;
	bool occupied;
};

struct pqcp_sovereign_committed_authorization_internal {
	uint32_t schema_version;
	uint64_t authorization_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	enum pqcp_sovereign_ceremony_action action;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t committed_at_ms;
	uint64_t expires_at_ms;
	uint32_t approval_count;
	uint32_t distinct_role_count;
	uint32_t signer_mask;
	uint32_t role_mask;
	uint32_t use_count;
	uint32_t maximum_uses;
	uint8_t target_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t nonce[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t previous_authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t approvals_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_authorization_state state;
	bool occupied;
};

struct pqcp_sovereign_authorization_slot_internal {
	struct pqcp_sovereign_approval_policy_internal policy;
	struct pqcp_sovereign_signed_approval_internal
		approvals[PQCP_SOVEREIGN_MAX_APPROVERS];
	struct pqcp_sovereign_committed_authorization_internal committed;
	uint32_t approval_count;
	uint32_t rejection_count;
	uint32_t distinct_role_count;
	uint32_t role_mask;
	uint64_t opened_at_ms;
	bool occupied;
};

struct pqcp_sovereign_authorization_engine_internal {
	struct pqcp_sovereign_authorization_slot_internal *slots;
	size_t capacity;
	uint64_t next_authorization_id;
	uint64_t committed_count;
	uint64_t rejected_count;
	uint64_t replay_count;
	struct pqcp_runtime_key_store *key_store;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_ceremony_binding_internal {
	uint64_t ceremony_id;
	uint64_t authorization_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	enum pqcp_sovereign_ceremony_action action;
	struct pqcp_runtime_key_handle current_key;
	struct pqcp_runtime_key_handle committed_key;
	uint8_t target_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t capability[PQCP_CRYPTO_BROKER_TOKEN_BYTES];
	char principal_id[PQCP_CRYPTO_BROKER_ID_MAX_CHARS];
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	bool executed;
	bool occupied;
};

struct pqcp_sovereign_ceremony_executor_internal {
	struct pqcp_sovereign_key_ceremony_manager *manager;
	struct pqcp_sovereign_authorization_engine_internal *authorizations;
	struct pqcp_sovereign_custody_ledger *custody;
	struct pqcp_crypto_broker *broker;
	struct pqcp_sovereign_ceremony_binding_internal *bindings;
	size_t binding_capacity;
	uint64_t execution_count;
	uint64_t failure_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_secret_reference_internal {
	uint64_t grant_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char recipient_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char namespace_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char key_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	struct pqcp_runtime_key_handle key_handle;
	uint64_t key_epoch;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint32_t permissions;
	uint8_t recipient_binding[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t reference_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_secret_reference_store_internal {
	struct pqcp_sovereign_secret_distributor *distributor;
	struct pqcp_sovereign_secret_reference_internal *references;
	size_t capacity;
	struct pqcp_runtime_key_store *key_store;
	struct pqcp_sovereign_custody_ledger *custody;
	struct k_mutex lock;
	bool initialized;
};

bool pqcp_sovereign_internal_text_valid(
	const char *text,
	size_t capacity);
int pqcp_sovereign_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source);
bool pqcp_sovereign_internal_digest_zero(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES]);
bool pqcp_sovereign_internal_digest_equal(
	const uint8_t left[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t right[PQCP_SOVEREIGN_DIGEST_BYTES]);
bool pqcp_sovereign_internal_u64_add(
	uint64_t left,
	uint64_t right,
	uint64_t *result);
bool pqcp_sovereign_internal_u32_add(
	uint32_t left,
	uint32_t right,
	uint32_t *result);
size_t pqcp_sovereign_internal_encode_text(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	const char *text,
	size_t maximum);
size_t pqcp_sovereign_internal_encode_u32(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	uint32_t value);
size_t pqcp_sovereign_internal_encode_u64(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	uint64_t value);
size_t pqcp_sovereign_internal_encode_bytes(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	const uint8_t *value,
	size_t value_length);
int pqcp_sovereign_internal_hash(
	const uint8_t *input,
	size_t input_length,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_internal_hash_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t count,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES]);

const char *pqcp_sovereign_internal_action_text(
	enum pqcp_sovereign_ceremony_action action);
const char *pqcp_sovereign_internal_role_text(
	enum pqcp_sovereign_approval_role role);
enum pqcp_sovereign_ceremony_action
pqcp_sovereign_internal_action_from_text(const char *action);

int pqcp_sovereign_internal_approval_body(
	const struct pqcp_sovereign_signed_approval_internal *approval,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_sovereign_internal_approval_digest(
	const struct pqcp_sovereign_signed_approval_internal *approval,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_internal_policy_digest(
	const struct pqcp_sovereign_approval_policy_internal *policy,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_internal_authorization_digest(
	const struct pqcp_sovereign_committed_authorization_internal *authorization,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES]);

int pqcp_sovereign_authorization_engine_init_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	struct pqcp_sovereign_authorization_slot_internal *slots,
	size_t capacity,
	struct pqcp_runtime_key_store *key_store);
int pqcp_sovereign_authorization_open_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	const struct pqcp_sovereign_approval_policy_internal *policy,
	uint64_t now_ms,
	uint64_t *authorization_id);
int pqcp_sovereign_authorization_submit_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	const struct pqcp_sovereign_signer_credential_internal *credential,
	const struct pqcp_sovereign_signed_approval_internal *approval,
	uint64_t now_ms);
int pqcp_sovereign_authorization_commit_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t authorization_id,
	uint64_t now_ms,
	uint32_t maximum_uses,
	struct pqcp_sovereign_committed_authorization_internal *authorization);
int pqcp_sovereign_authorization_consume_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t authorization_id,
	const char *tenant_id,
	enum pqcp_sovereign_ceremony_action action,
	const uint8_t target_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms,
	struct pqcp_sovereign_committed_authorization_internal *authorization);
int pqcp_sovereign_authorization_revoke_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t authorization_id);
int pqcp_sovereign_authorization_tick_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_authorization_audit_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine);

int pqcp_sovereign_ceremony_executor_init_internal(
	struct pqcp_sovereign_ceremony_executor_internal *executor,
	struct pqcp_sovereign_key_ceremony_manager *manager,
	struct pqcp_sovereign_authorization_engine_internal *authorizations,
	struct pqcp_sovereign_custody_ledger *custody,
	struct pqcp_crypto_broker *broker,
	struct pqcp_sovereign_ceremony_binding_internal *bindings,
	size_t binding_capacity);
int pqcp_sovereign_ceremony_bind_internal(
	struct pqcp_sovereign_ceremony_executor_internal *executor,
	uint64_t ceremony_id,
	uint64_t authorization_id,
	const char *tenant_id,
	enum pqcp_sovereign_ceremony_action action,
	const struct pqcp_runtime_key_handle *current_key,
	const uint8_t target_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const char *principal_id,
	const uint8_t capability[PQCP_CRYPTO_BROKER_TOKEN_BYTES],
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms);
int pqcp_sovereign_ceremony_execute_internal(
	struct pqcp_sovereign_ceremony_executor_internal *executor,
	uint64_t ceremony_id,
	const struct pqcp_crypto_broker_key_spec *key_spec,
	uint64_t now_ms,
	struct pqcp_runtime_key_handle *result_key);
int pqcp_sovereign_ceremony_executor_audit_internal(
	struct pqcp_sovereign_ceremony_executor_internal *executor);

int pqcp_sovereign_secret_reference_store_init_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store,
	struct pqcp_sovereign_secret_distributor *distributor,
	struct pqcp_sovereign_secret_reference_internal *references,
	size_t capacity,
	struct pqcp_runtime_key_store *key_store,
	struct pqcp_sovereign_custody_ledger *custody);
int pqcp_sovereign_secret_reference_bind_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store,
	uint64_t grant_id,
	const char *tenant_id,
	const struct pqcp_runtime_key_handle *key_handle,
	uint64_t now_ms);
int pqcp_sovereign_secret_reference_authorize_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store,
	uint64_t grant_id,
	const char *tenant_id,
	const char *recipient_id,
	const char *namespace_id,
	uint64_t key_epoch,
	uint64_t policy_epoch,
	uint32_t permissions,
	const uint8_t recipient_binding[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_runtime_key_handle *key_handle);
int pqcp_sovereign_secret_reference_revoke_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store,
	uint64_t grant_id,
	uint64_t now_ms);
int pqcp_sovereign_secret_reference_audit_internal(
	struct pqcp_sovereign_secret_reference_store_internal *store);

#endif /* PQCP_SOVEREIGN_CEREMONY_INTERNAL_H_ */
