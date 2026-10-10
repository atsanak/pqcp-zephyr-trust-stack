/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Private integration contracts for sovereign tenant and privacy governance.
 */

#ifndef PQCP_SOVEREIGN_PRIVACY_INTERNAL_H_
#define PQCP_SOVEREIGN_PRIVACY_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/runtime_key_store.h>
#include <pqcp_zephyr/sovereign_runtime.h>

#define PQCP_SOVEREIGN_PRIVACY_REASON_BYTES 96U
#define PQCP_SOVEREIGN_ERASURE_METHOD_CRYPTOGRAPHIC 1U
#define PQCP_SOVEREIGN_ERASURE_METHOD_OVERWRITE 2U
#define PQCP_SOVEREIGN_ERASURE_METHOD_EXTERNAL 3U

enum pqcp_sovereign_legal_basis {
	PQCP_SOVEREIGN_LEGAL_BASIS_NONE = 0,
	PQCP_SOVEREIGN_LEGAL_BASIS_CONSENT,
	PQCP_SOVEREIGN_LEGAL_BASIS_CONTRACT,
	PQCP_SOVEREIGN_LEGAL_BASIS_LEGAL_OBLIGATION,
	PQCP_SOVEREIGN_LEGAL_BASIS_VITAL_INTEREST,
	PQCP_SOVEREIGN_LEGAL_BASIS_PUBLIC_TASK,
	PQCP_SOVEREIGN_LEGAL_BASIS_LEGITIMATE_INTEREST,
	PQCP_SOVEREIGN_LEGAL_BASIS_COUNT,
};

enum pqcp_sovereign_resource_class {
	PQCP_SOVEREIGN_RESOURCE_NONE = 0,
	PQCP_SOVEREIGN_RESOURCE_NAMESPACE,
	PQCP_SOVEREIGN_RESOURCE_KEY,
	PQCP_SOVEREIGN_RESOURCE_ARTIFACT,
	PQCP_SOVEREIGN_RESOURCE_VAULT_OBJECT,
	PQCP_SOVEREIGN_RESOURCE_DEPLOYMENT,
	PQCP_SOVEREIGN_RESOURCE_AUDIT_CURSOR,
	PQCP_SOVEREIGN_RESOURCE_CONTINUITY_PLAN,
	PQCP_SOVEREIGN_RESOURCE_DATASET,
	PQCP_SOVEREIGN_RESOURCE_COUNT,
};

enum pqcp_sovereign_privacy_failure {
	PQCP_SOVEREIGN_PRIVACY_FAILURE_NONE = 0,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_ARGUMENT = 1U << 0,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_TENANT = 1U << 1,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_NAMESPACE = 1U << 2,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_FEDERATION = 1U << 3,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_CLASSIFICATION = 1U << 4,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_PURPOSE = 1U << 5,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_LEGAL_BASIS = 1U << 6,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_CONSENT = 1U << 7,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_RESIDENCY = 1U << 8,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_BUDGET = 1U << 9,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_CONTRACT = 1U << 10,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_EGRESS = 1U << 11,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_RETENTION = 1U << 12,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_POLICY_EPOCH = 1U << 13,
	PQCP_SOVEREIGN_PRIVACY_FAILURE_REVOCATION_EPOCH = 1U << 14,
};

struct pqcp_sovereign_federation_grant {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t grant_id;
	char source_tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char destination_tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char purpose[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char legal_basis[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t operation_mask;
	uint32_t resource_class_mask;
	uint32_t data_class_mask;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t issued_at_ms;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint64_t maximum_uses;
	uint64_t use_count;
	uint8_t grant_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_federation_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_federation_grant *grants;
	size_t capacity;
	uint32_t next_generation;
	uint64_t next_grant_id;
	uint64_t authorization_count;
	uint64_t denial_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_privacy_authorization_request {
	const char *request_tenant_id;
	const char *resource_tenant_id;
	const char *namespace_id;
	const char *workload_id;
	const char *subject_id;
	const char *controller_id;
	const char *dataset_id;
	const char *purpose;
	const char *legal_basis;
	const char *source_zone;
	const char *destination_zone;
	const char *destination_domain;
	const char *budget_id;
	uint64_t contract_id;
	enum pqcp_sovereign_resource_class resource_class;
	enum pqcp_sovereign_operation operation;
	enum pqcp_sovereign_data_class data_class;
	uint64_t capabilities;
	uint64_t records;
	uint64_t bytes;
	uint64_t epsilon_micros;
	uint64_t delta_nanos;
	uint64_t query_count;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t now_ms;
	uint32_t risk_score;
	bool encrypted;
	bool dlp_passed;
	bool approved;
	bool consent_required;
	bool budget_required;
	bool contract_required;
	bool egress_required;
};

struct pqcp_sovereign_privacy_authorization_result {
	enum pqcp_sovereign_decision decision;
	uint32_t failure_mask;
	uint64_t federation_grant_id;
	uint64_t consent_id;
	uint64_t retention_record_id;
	uint32_t residency_rule_id;
	uint32_t egress_rule_id;
	uint8_t decision_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	char reason[PQCP_SOVEREIGN_PRIVACY_REASON_BYTES];
};

struct pqcp_sovereign_privacy_governor {
	struct pqcp_sovereign_tenant_registry *tenants;
	struct pqcp_sovereign_namespace_manager *namespaces;
	struct pqcp_sovereign_federation_manager *federation;
	struct pqcp_sovereign_privacy_budget_manager *budgets;
	struct pqcp_sovereign_residency_engine *residency;
	struct pqcp_sovereign_consent_ledger *consent;
	struct pqcp_sovereign_purpose_engine *purposes;
	struct pqcp_sovereign_retention_manager *retention;
	struct pqcp_sovereign_data_contract_manager *contracts;
	struct pqcp_sovereign_egress_engine *egress;
	uint64_t authorization_count;
	uint64_t denial_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_erasure_tombstone {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t tombstone_id;
	uint64_t retention_record_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char object_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char namespace_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	uint64_t policy_epoch;
	uint64_t requested_at_ms;
	uint64_t completed_at_ms;
	uint32_t deletion_method;
	uint8_t object_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t key_handle_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t tombstone_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_erasure_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_erasure_tombstone *tombstones;
	size_t capacity;
	size_t next_index;
	size_t count;
	uint32_t next_generation;
	uint64_t next_tombstone_id;
	uint64_t completed_count;
	uint64_t denial_count;
	uint8_t chain_head[PQCP_SOVEREIGN_DIGEST_BYTES];
	struct pqcp_runtime_key_store *key_store;
	struct pqcp_sovereign_retention_manager *retention;
	struct k_mutex lock;
	bool initialized;
};

bool pqcp_sovereign_privacy_text_valid(const char *text, size_t capacity);
bool pqcp_sovereign_privacy_digest_zero(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES]);
bool pqcp_sovereign_privacy_data_class_valid(
	enum pqcp_sovereign_data_class data_class);
bool pqcp_sovereign_privacy_operation_valid(
	enum pqcp_sovereign_operation operation);
bool pqcp_sovereign_privacy_lifecycle_active(
	enum pqcp_sovereign_lifecycle_state state);
int pqcp_sovereign_privacy_copy_text(
	char *destination,
	size_t capacity,
	const char *source);
int pqcp_sovereign_privacy_digest_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);

int pqcp_sovereign_federation_manager_init(
	struct pqcp_sovereign_federation_manager *manager,
	struct pqcp_sovereign_federation_grant *grants,
	size_t capacity);
int pqcp_sovereign_federation_grant_issue(
	struct pqcp_sovereign_federation_manager *manager,
	const struct pqcp_sovereign_federation_grant *grant,
	uint64_t now_ms,
	struct pqcp_sovereign_federation_grant **stored);
int pqcp_sovereign_federation_authorize(
	struct pqcp_sovereign_federation_manager *manager,
	const char *source_tenant_id,
	const char *destination_tenant_id,
	enum pqcp_sovereign_resource_class resource_class,
	enum pqcp_sovereign_operation operation,
	enum pqcp_sovereign_data_class data_class,
	const char *purpose,
	const char *legal_basis,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms,
	uint64_t *grant_id);
int pqcp_sovereign_federation_grant_revoke(
	struct pqcp_sovereign_federation_manager *manager,
	uint64_t grant_id);
int pqcp_sovereign_federation_manager_tick(
	struct pqcp_sovereign_federation_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_federation_manager_audit(
	struct pqcp_sovereign_federation_manager *manager);

int pqcp_sovereign_privacy_governor_init(
	struct pqcp_sovereign_privacy_governor *governor,
	struct pqcp_sovereign_tenant_registry *tenants,
	struct pqcp_sovereign_namespace_manager *namespaces,
	struct pqcp_sovereign_federation_manager *federation,
	struct pqcp_sovereign_privacy_budget_manager *budgets,
	struct pqcp_sovereign_residency_engine *residency,
	struct pqcp_sovereign_consent_ledger *consent,
	struct pqcp_sovereign_purpose_engine *purposes,
	struct pqcp_sovereign_retention_manager *retention,
	struct pqcp_sovereign_data_contract_manager *contracts,
	struct pqcp_sovereign_egress_engine *egress);
int pqcp_sovereign_privacy_authorize(
	struct pqcp_sovereign_privacy_governor *governor,
	const struct pqcp_sovereign_privacy_authorization_request *request,
	struct pqcp_sovereign_privacy_authorization_result *result);
int pqcp_sovereign_privacy_governor_audit(
	struct pqcp_sovereign_privacy_governor *governor);

int pqcp_sovereign_erasure_manager_init(
	struct pqcp_sovereign_erasure_manager *manager,
	struct pqcp_sovereign_erasure_tombstone *tombstones,
	size_t capacity,
	struct pqcp_runtime_key_store *key_store,
	struct pqcp_sovereign_retention_manager *retention);
int pqcp_sovereign_erasure_execute(
	struct pqcp_sovereign_erasure_manager *manager,
	const char *tenant_id,
	const char *object_id,
	const char *namespace_id,
	uint64_t retention_record_id,
	const uint8_t object_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const struct pqcp_runtime_key_handle *key_handle,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t now_ms,
	struct pqcp_sovereign_erasure_tombstone **tombstone);
int pqcp_sovereign_erasure_find(
	struct pqcp_sovereign_erasure_manager *manager,
	uint64_t tombstone_id,
	struct pqcp_sovereign_erasure_tombstone **tombstone);
int pqcp_sovereign_erasure_manager_audit(
	struct pqcp_sovereign_erasure_manager *manager);

#endif /* PQCP_SOVEREIGN_PRIVACY_INTERNAL_H_ */
