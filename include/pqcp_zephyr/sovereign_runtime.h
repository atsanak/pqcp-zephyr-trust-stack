/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free sovereign software supply-chain and workload governance.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_SOVEREIGN_RUNTIME_H_
#define PQCP_ZEPHYR_SOVEREIGN_RUNTIME_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_SOVEREIGN_SCHEMA_VERSION 1U
#define PQCP_SOVEREIGN_DIGEST_BYTES 32U
#define PQCP_SOVEREIGN_TAG_BYTES 32U
#define PQCP_SOVEREIGN_ID_MAX_CHARS 48U
#define PQCP_SOVEREIGN_NAME_MAX_CHARS 64U
#define PQCP_SOVEREIGN_DOMAIN_MAX_CHARS 48U
#define PQCP_SOVEREIGN_ZONE_MAX_CHARS 32U
#define PQCP_SOVEREIGN_LABEL_MAX_CHARS 64U
#define PQCP_SOVEREIGN_URI_MAX_CHARS 128U
#define PQCP_SOVEREIGN_VERSION_MAX_CHARS 32U
#define PQCP_SOVEREIGN_REASON_MAX_CHARS 128U
#define PQCP_SOVEREIGN_SUBJECT_MAX_CHARS 64U
#define PQCP_SOVEREIGN_CONTROL_MAX_CHARS 40U
#define PQCP_SOVEREIGN_MAX_COMPONENTS 32U
#define PQCP_SOVEREIGN_MAX_DEPENDENCIES 16U
#define PQCP_SOVEREIGN_MAX_APPROVERS 16U
#define PQCP_SOVEREIGN_MAX_RING_MEMBERS 32U
#define PQCP_SOVEREIGN_MAX_EVIDENCE_REFS 24U
#define PQCP_SOVEREIGN_MAX_RECOVERY_STEPS 32U
#define PQCP_SOVEREIGN_MAX_CONTROL_REFS 24U
#define PQCP_SOVEREIGN_MAX_DATA_CLASSES 16U

#define PQCP_SOVEREIGN_BIT(value) \
	(1ULL << (uint64_t)(value))

enum pqcp_sovereign_lifecycle_state {
	PQCP_SOVEREIGN_LIFECYCLE_EMPTY = 0,
	PQCP_SOVEREIGN_LIFECYCLE_DRAFT,
	PQCP_SOVEREIGN_LIFECYCLE_ACTIVE,
	PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED,
	PQCP_SOVEREIGN_LIFECYCLE_RETIRED,
	PQCP_SOVEREIGN_LIFECYCLE_REVOKED,
};

enum pqcp_sovereign_decision {
	PQCP_SOVEREIGN_DECISION_UNSET = 0,
	PQCP_SOVEREIGN_DECISION_ALLOW,
	PQCP_SOVEREIGN_DECISION_DENY,
	PQCP_SOVEREIGN_DECISION_REVIEW,
	PQCP_SOVEREIGN_DECISION_QUARANTINE,
};

enum pqcp_sovereign_operation {
	PQCP_SOVEREIGN_OPERATION_NONE = 0,
	PQCP_SOVEREIGN_OPERATION_REGISTER,
	PQCP_SOVEREIGN_OPERATION_BUILD,
	PQCP_SOVEREIGN_OPERATION_SIGN,
	PQCP_SOVEREIGN_OPERATION_RELEASE,
	PQCP_SOVEREIGN_OPERATION_DEPLOY,
	PQCP_SOVEREIGN_OPERATION_EXECUTE,
	PQCP_SOVEREIGN_OPERATION_READ_DATA,
	PQCP_SOVEREIGN_OPERATION_WRITE_DATA,
	PQCP_SOVEREIGN_OPERATION_EXPORT_DATA,
	PQCP_SOVEREIGN_OPERATION_ROTATE_KEY,
	PQCP_SOVEREIGN_OPERATION_RECOVER,
	PQCP_SOVEREIGN_OPERATION_AUDIT,
	PQCP_SOVEREIGN_OPERATION_ADMINISTER,
	PQCP_SOVEREIGN_OPERATION_COUNT,
};

enum pqcp_sovereign_capability {
	PQCP_SOVEREIGN_CAPABILITY_ARTIFACT_PUBLISH = 0,
	PQCP_SOVEREIGN_CAPABILITY_RELEASE_APPROVE,
	PQCP_SOVEREIGN_CAPABILITY_DEPLOY,
	PQCP_SOVEREIGN_CAPABILITY_ROLLBACK,
	PQCP_SOVEREIGN_CAPABILITY_KEY_CUSTODIAN,
	PQCP_SOVEREIGN_CAPABILITY_PRIVACY_STEWARD,
	PQCP_SOVEREIGN_CAPABILITY_DATA_EXPORT,
	PQCP_SOVEREIGN_CAPABILITY_NETWORK_ADMIN,
	PQCP_SOVEREIGN_CAPABILITY_RECOVERY_OPERATOR,
	PQCP_SOVEREIGN_CAPABILITY_AUDITOR,
	PQCP_SOVEREIGN_CAPABILITY_REGULATOR,
	PQCP_SOVEREIGN_CAPABILITY_COUNT,
};

enum pqcp_sovereign_data_class {
	PQCP_SOVEREIGN_DATA_PUBLIC = 0,
	PQCP_SOVEREIGN_DATA_INTERNAL,
	PQCP_SOVEREIGN_DATA_CONFIDENTIAL,
	PQCP_SOVEREIGN_DATA_RESTRICTED,
	PQCP_SOVEREIGN_DATA_PERSONAL,
	PQCP_SOVEREIGN_DATA_SENSITIVE_PERSONAL,
	PQCP_SOVEREIGN_DATA_SECRET,
	PQCP_SOVEREIGN_DATA_CLASS_COUNT,
};

enum pqcp_sovereign_artifact_state {
	PQCP_SOVEREIGN_ARTIFACT_EMPTY = 0,
	PQCP_SOVEREIGN_ARTIFACT_REGISTERED,
	PQCP_SOVEREIGN_ARTIFACT_ATTESTED,
	PQCP_SOVEREIGN_ARTIFACT_APPROVED,
	PQCP_SOVEREIGN_ARTIFACT_RELEASED,
	PQCP_SOVEREIGN_ARTIFACT_QUARANTINED,
	PQCP_SOVEREIGN_ARTIFACT_REVOKED,
};

enum pqcp_sovereign_rollout_state {
	PQCP_SOVEREIGN_ROLLOUT_EMPTY = 0,
	PQCP_SOVEREIGN_ROLLOUT_PLANNED,
	PQCP_SOVEREIGN_ROLLOUT_CANARY,
	PQCP_SOVEREIGN_ROLLOUT_EXPANDING,
	PQCP_SOVEREIGN_ROLLOUT_PAUSED,
	PQCP_SOVEREIGN_ROLLOUT_COMPLETED,
	PQCP_SOVEREIGN_ROLLOUT_ROLLING_BACK,
	PQCP_SOVEREIGN_ROLLOUT_FAILED,
};

enum pqcp_sovereign_approval_state {
	PQCP_SOVEREIGN_APPROVAL_EMPTY = 0,
	PQCP_SOVEREIGN_APPROVAL_OPEN,
	PQCP_SOVEREIGN_APPROVAL_SATISFIED,
	PQCP_SOVEREIGN_APPROVAL_REJECTED,
	PQCP_SOVEREIGN_APPROVAL_EXPIRED,
	PQCP_SOVEREIGN_APPROVAL_CANCELLED,
};

enum pqcp_sovereign_ceremony_state {
	PQCP_SOVEREIGN_CEREMONY_EMPTY = 0,
	PQCP_SOVEREIGN_CEREMONY_PLANNED,
	PQCP_SOVEREIGN_CEREMONY_COLLECTING,
	PQCP_SOVEREIGN_CEREMONY_COMBINING,
	PQCP_SOVEREIGN_CEREMONY_COMMITTED,
	PQCP_SOVEREIGN_CEREMONY_ABORTED,
};

enum pqcp_sovereign_exception_state {
	PQCP_SOVEREIGN_EXCEPTION_EMPTY = 0,
	PQCP_SOVEREIGN_EXCEPTION_REQUESTED,
	PQCP_SOVEREIGN_EXCEPTION_APPROVED,
	PQCP_SOVEREIGN_EXCEPTION_ACTIVE,
	PQCP_SOVEREIGN_EXCEPTION_EXPIRED,
	PQCP_SOVEREIGN_EXCEPTION_REVOKED,
};

struct pqcp_sovereign_tenant {
	uint32_t schema_version;
	uint32_t generation;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char parent_tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char trust_domain[PQCP_SOVEREIGN_DOMAIN_MAX_CHARS];
	char home_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	uint64_t capabilities;
	uint64_t operation_mask;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint64_t storage_quota_bytes;
	uint64_t compute_quota_units;
	uint32_t maximum_namespaces;
	uint32_t active_namespaces;
	uint32_t risk_score;
	enum pqcp_sovereign_lifecycle_state state;
	uint8_t identity_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_tenant_registry {
	uint32_t schema_version;
	struct pqcp_sovereign_tenant *tenants;
	size_t capacity;
	uint32_t next_generation;
	uint64_t registration_count;
	uint64_t rejection_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_namespace {
	uint32_t schema_version;
	uint32_t generation;
	char namespace_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char residency_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	char security_label[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t operation_mask;
	uint64_t policy_epoch;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint64_t storage_limit_bytes;
	uint64_t storage_used_bytes;
	uint32_t maximum_workloads;
	uint32_t active_workloads;
	enum pqcp_sovereign_data_class maximum_data_class;
	enum pqcp_sovereign_lifecycle_state state;
	uint8_t policy_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_namespace_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_namespace *namespaces;
	size_t capacity;
	uint32_t next_generation;
	uint64_t creation_count;
	uint64_t denial_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_artifact {
	uint32_t schema_version;
	uint32_t generation;
	char artifact_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char name[PQCP_SOVEREIGN_NAME_MAX_CHARS];
	char version[PQCP_SOVEREIGN_VERSION_MAX_CHARS];
	char supplier[PQCP_SOVEREIGN_NAME_MAX_CHARS];
	char media_type[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t size_bytes;
	uint64_t created_at_ms;
	uint64_t policy_epoch;
	uint64_t signing_epoch;
	uint64_t release_sequence;
	uint32_t risk_score;
	enum pqcp_sovereign_artifact_state state;
	uint8_t content_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t sbom_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t provenance_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t signature_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool reproducible;
	bool occupied;
};

struct pqcp_sovereign_artifact_catalog {
	uint32_t schema_version;
	struct pqcp_sovereign_artifact *artifacts;
	size_t capacity;
	uint32_t next_generation;
	uint64_t registration_count;
	uint64_t quarantine_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_sbom_component {
	uint32_t schema_version;
	char artifact_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char component_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char name[PQCP_SOVEREIGN_NAME_MAX_CHARS];
	char version[PQCP_SOVEREIGN_VERSION_MAX_CHARS];
	char supplier[PQCP_SOVEREIGN_NAME_MAX_CHARS];
	char license_id[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t dependency_mask;
	uint32_t vulnerability_score;
	uint32_t flags;
	uint8_t component_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_sbom_document {
	uint32_t schema_version;
	char artifact_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char format[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t generated_at_ms;
	uint64_t policy_epoch;
	uint32_t component_count;
	uint32_t vulnerable_count;
	uint32_t maximum_vulnerability_score;
	uint8_t document_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool complete;
	bool occupied;
};

struct pqcp_sovereign_sbom_registry {
	uint32_t schema_version;
	struct pqcp_sovereign_sbom_document *documents;
	size_t document_capacity;
	struct pqcp_sovereign_sbom_component *components;
	size_t component_capacity;
	uint64_t ingest_count;
	uint64_t rejection_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_transparency_entry {
	uint32_t schema_version;
	uint64_t sequence;
	char subject_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char event_type[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char actor_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	uint64_t timestamp_ms;
	uint64_t policy_epoch;
	uint8_t subject_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t entry_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_transparency_log {
	uint32_t schema_version;
	struct pqcp_sovereign_transparency_entry *entries;
	size_t capacity;
	size_t next_index;
	size_t count;
	uint64_t next_sequence;
	uint64_t dropped_count;
	uint8_t chain_head[PQCP_SOVEREIGN_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_build_attestation {
	uint32_t schema_version;
	uint64_t attestation_id;
	char artifact_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char builder_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char build_environment[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char source_uri[PQCP_SOVEREIGN_URI_MAX_CHARS];
	uint64_t source_revision;
	uint64_t built_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint32_t predicate_mask;
	uint32_t risk_score;
	uint8_t source_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t recipe_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t output_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t attestation_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t signature_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool verified;
	bool occupied;
};

struct pqcp_sovereign_build_attestation_store {
	uint32_t schema_version;
	struct pqcp_sovereign_build_attestation *records;
	size_t capacity;
	uint64_t next_attestation_id;
	uint64_t verified_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_release_rule {
	uint32_t schema_version;
	uint32_t rule_id;
	uint32_t priority;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char artifact_pattern[PQCP_SOVEREIGN_NAME_MAX_CHARS];
	char target_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	uint64_t minimum_policy_epoch;
	uint64_t required_predicate_mask;
	uint64_t forbidden_component_flags;
	uint32_t maximum_artifact_risk;
	uint32_t maximum_component_risk;
	uint32_t minimum_approvals;
	uint32_t minimum_distinct_roles;
	enum pqcp_sovereign_decision effect;
	bool require_reproducible;
	bool require_transparency;
	bool enabled;
};

struct pqcp_sovereign_release_context {
	const struct pqcp_sovereign_artifact *artifact;
	const struct pqcp_sovereign_sbom_document *sbom;
	const struct pqcp_sovereign_build_attestation *attestation;
	char target_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	uint64_t policy_epoch;
	uint32_t approval_count;
	uint32_t distinct_roles;
	bool transparency_verified;
};

struct pqcp_sovereign_release_decision {
	enum pqcp_sovereign_decision effect;
	uint32_t rule_id;
	uint32_t rule_priority;
	uint32_t failure_mask;
	char explanation[PQCP_SOVEREIGN_REASON_MAX_CHARS];
};

struct pqcp_sovereign_release_policy {
	uint32_t schema_version;
	struct pqcp_sovereign_release_rule *rules;
	size_t capacity;
	size_t count;
	enum pqcp_sovereign_decision default_effect;
	uint64_t generation;
	uint64_t allow_count;
	uint64_t deny_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_deployment_ring {
	uint32_t schema_version;
	uint32_t generation;
	char ring_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char target_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	uint64_t policy_epoch;
	uint64_t member_mask;
	uint64_t created_at_ms;
	uint32_t member_count;
	uint32_t maximum_parallel;
	uint32_t minimum_healthy_basis_points;
	uint32_t maximum_failure_basis_points;
	uint32_t pause_after_failures;
	uint8_t membership_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_ring_registry {
	uint32_t schema_version;
	struct pqcp_sovereign_deployment_ring *rings;
	size_t capacity;
	uint32_t next_generation;
	uint64_t registration_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_rollout {
	uint32_t schema_version;
	uint64_t rollout_id;
	char artifact_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char ring_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	uint64_t policy_epoch;
	uint64_t planned_at_ms;
	uint64_t started_at_ms;
	uint64_t deadline_ms;
	uint64_t next_action_at_ms;
	uint32_t target_count;
	uint32_t batch_size;
	uint32_t attempted_count;
	uint32_t success_count;
	uint32_t failure_count;
	uint32_t unavailable_count;
	uint32_t health_basis_points;
	uint32_t current_batch;
	enum pqcp_sovereign_rollout_state state;
	int result;
	uint8_t plan_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_rollout_controller {
	uint32_t schema_version;
	struct pqcp_sovereign_rollout *rollouts;
	size_t capacity;
	uint64_t next_rollout_id;
	uint64_t completed_count;
	uint64_t rollback_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_rollback_plan {
	uint32_t schema_version;
	uint64_t rollback_id;
	uint64_t rollout_id;
	char current_artifact_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char target_artifact_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	uint64_t authorized_at_ms;
	uint64_t deadline_ms;
	uint64_t policy_epoch;
	uint32_t required_steps;
	uint32_t completed_steps;
	uint32_t failed_steps;
	uint32_t maximum_failures;
	enum pqcp_sovereign_lifecycle_state state;
	uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_rollback_coordinator {
	uint32_t schema_version;
	struct pqcp_sovereign_rollback_plan *plans;
	size_t capacity;
	uint64_t next_rollback_id;
	uint64_t completed_count;
	uint64_t failed_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_approval_vote {
	uint32_t schema_version;
	uint64_t request_id;
	char approver_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char role[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t capabilities;
	uint64_t voted_at_ms;
	uint64_t credential_epoch;
	bool approve;
	uint8_t vote_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_approval_request {
	uint32_t schema_version;
	uint64_t request_id;
	char subject_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char action[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t opened_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint64_t required_capabilities;
	uint32_t required_approvals;
	uint32_t required_distinct_roles;
	uint32_t approval_count;
	uint32_t rejection_count;
	uint32_t distinct_role_count;
	enum pqcp_sovereign_approval_state state;
	uint8_t subject_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_approval_quorum {
	uint32_t schema_version;
	struct pqcp_sovereign_approval_request *requests;
	size_t request_capacity;
	struct pqcp_sovereign_approval_vote *votes;
	size_t vote_capacity;
	uint64_t next_request_id;
	uint64_t satisfied_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_key_contribution {
	uint32_t schema_version;
	uint64_t ceremony_id;
	char custodian_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char role[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t submitted_at_ms;
	uint64_t credential_epoch;
	uint8_t contribution_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t proof_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool verified;
	bool occupied;
};

struct pqcp_sovereign_key_ceremony {
	uint32_t schema_version;
	uint64_t ceremony_id;
	char key_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char purpose[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t current_epoch;
	uint64_t target_epoch;
	uint64_t opened_at_ms;
	uint64_t expires_at_ms;
	uint32_t threshold;
	uint32_t required_distinct_roles;
	uint32_t contribution_count;
	uint32_t distinct_role_count;
	enum pqcp_sovereign_ceremony_state state;
	uint8_t transcript_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t committed_key_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_key_ceremony_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_key_ceremony *ceremonies;
	size_t ceremony_capacity;
	struct pqcp_sovereign_key_contribution *contributions;
	size_t contribution_capacity;
	uint64_t next_ceremony_id;
	uint64_t completed_count;
	uint64_t aborted_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_custody_event {
	uint32_t schema_version;
	uint64_t sequence;
	char key_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char custodian_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char action[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t key_epoch;
	uint64_t timestamp_ms;
	uint64_t policy_epoch;
	uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t event_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_custody_ledger {
	uint32_t schema_version;
	struct pqcp_sovereign_custody_event *events;
	size_t capacity;
	size_t next_index;
	size_t count;
	uint64_t next_sequence;
	uint64_t dropped_count;
	uint8_t chain_head[PQCP_SOVEREIGN_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_secret_grant {
	uint32_t schema_version;
	uint64_t grant_id;
	char key_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char recipient_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char namespace_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	uint64_t key_epoch;
	uint64_t policy_epoch;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t maximum_uses;
	uint64_t use_count;
	uint32_t permissions;
	uint8_t recipient_binding[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t wrapped_secret_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_secret_distributor {
	uint32_t schema_version;
	struct pqcp_sovereign_secret_grant *grants;
	size_t capacity;
	uint64_t next_grant_id;
	uint64_t issue_count;
	uint64_t denial_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_privacy_budget {
	uint32_t schema_version;
	uint32_t generation;
	char budget_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char subject_scope[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char purpose[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t window_started_ms;
	uint64_t window_ms;
	uint64_t policy_epoch;
	uint64_t epsilon_limit_micros;
	uint64_t epsilon_used_micros;
	uint64_t delta_limit_nanos;
	uint64_t delta_used_nanos;
	uint64_t query_limit;
	uint64_t query_count;
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_privacy_budget_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_privacy_budget *budgets;
	size_t capacity;
	uint32_t next_generation;
	uint64_t accepted_count;
	uint64_t denied_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_residency_rule {
	uint32_t schema_version;
	uint32_t rule_id;
	uint32_t priority;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char source_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	char destination_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	char legal_basis[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint32_t data_class_mask;
	uint64_t not_before_ms;
	uint64_t not_after_ms;
	enum pqcp_sovereign_decision effect;
	bool require_encryption;
	bool require_approval;
	bool enabled;
};

struct pqcp_sovereign_residency_context {
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char source_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	char destination_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	enum pqcp_sovereign_data_class data_class;
	uint64_t now_ms;
	bool encrypted;
	bool approved;
};

struct pqcp_sovereign_residency_engine {
	uint32_t schema_version;
	struct pqcp_sovereign_residency_rule *rules;
	size_t capacity;
	size_t count;
	enum pqcp_sovereign_decision default_effect;
	uint64_t allow_count;
	uint64_t deny_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_consent_record {
	uint32_t schema_version;
	uint64_t consent_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char subject_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char controller_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char purpose[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint32_t data_class_mask;
	uint64_t granted_at_ms;
	uint64_t expires_at_ms;
	uint64_t revoked_at_ms;
	uint64_t policy_epoch;
	uint8_t terms_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t receipt_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_consent_ledger {
	uint32_t schema_version;
	struct pqcp_sovereign_consent_record *records;
	size_t capacity;
	uint64_t next_consent_id;
	uint64_t grant_count;
	uint64_t revoke_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_purpose_binding {
	uint32_t schema_version;
	uint32_t binding_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char workload_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char purpose[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint32_t allowed_data_class_mask;
	uint64_t allowed_operation_mask;
	uint64_t policy_epoch;
	uint64_t expires_at_ms;
	uint32_t maximum_risk;
	bool require_consent;
	bool enabled;
};

struct pqcp_sovereign_purpose_engine {
	uint32_t schema_version;
	struct pqcp_sovereign_purpose_binding *bindings;
	size_t capacity;
	uint32_t next_binding_id;
	uint64_t allow_count;
	uint64_t deny_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_retention_rule {
	uint32_t schema_version;
	uint32_t rule_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char purpose[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint32_t data_class_mask;
	uint64_t minimum_retention_ms;
	uint64_t maximum_retention_ms;
	uint64_t legal_hold_until_ms;
	uint32_t deletion_method;
	uint32_t priority;
	bool enabled;
};

struct pqcp_sovereign_retention_record {
	uint32_t schema_version;
	uint64_t record_id;
	char object_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char purpose[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	enum pqcp_sovereign_data_class data_class;
	uint64_t created_at_ms;
	uint64_t delete_after_ms;
	uint64_t legal_hold_until_ms;
	uint64_t deleted_at_ms;
	uint8_t object_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_retention_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_retention_rule *rules;
	size_t rule_capacity;
	struct pqcp_sovereign_retention_record *records;
	size_t record_capacity;
	uint64_t next_record_id;
	uint64_t deletion_due_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_data_contract {
	uint32_t schema_version;
	uint64_t contract_id;
	char provider_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char consumer_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char dataset_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char purpose[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char source_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	char destination_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	enum pqcp_sovereign_data_class data_class;
	uint64_t operation_mask;
	uint64_t policy_epoch;
	uint64_t effective_at_ms;
	uint64_t expires_at_ms;
	uint64_t maximum_records;
	uint64_t records_used;
	uint64_t maximum_bytes;
	uint64_t bytes_used;
	uint32_t maximum_risk;
	bool require_consent;
	bool require_encryption;
	uint8_t terms_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_data_contract_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_data_contract *contracts;
	size_t capacity;
	uint64_t next_contract_id;
	uint64_t authorize_count;
	uint64_t denial_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_egress_rule {
	uint32_t schema_version;
	uint32_t rule_id;
	uint32_t priority;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char workload_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char destination_domain[PQCP_SOVEREIGN_DOMAIN_MAX_CHARS];
	uint32_t data_class_mask;
	uint64_t operation_mask;
	uint64_t maximum_bytes_per_window;
	uint64_t window_ms;
	uint32_t maximum_risk;
	enum pqcp_sovereign_decision effect;
	bool require_encryption;
	bool require_dlp;
	bool enabled;
};

struct pqcp_sovereign_egress_usage {
	uint32_t schema_version;
	uint32_t rule_id;
	char workload_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char destination_domain[PQCP_SOVEREIGN_DOMAIN_MAX_CHARS];
	uint64_t window_started_ms;
	uint64_t bytes_used;
	uint64_t request_count;
	bool occupied;
};

struct pqcp_sovereign_egress_engine {
	uint32_t schema_version;
	struct pqcp_sovereign_egress_rule *rules;
	size_t rule_capacity;
	struct pqcp_sovereign_egress_usage *usage;
	size_t usage_capacity;
	enum pqcp_sovereign_decision default_effect;
	uint64_t allow_count;
	uint64_t deny_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_network_intent {
	uint32_t schema_version;
	uint64_t intent_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char source_namespace[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char destination_namespace[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char protocol[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint16_t port_start;
	uint16_t port_end;
	uint64_t operation_mask;
	uint64_t policy_epoch;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint32_t maximum_connections;
	uint32_t active_connections;
	uint32_t maximum_risk;
	bool require_mutual_auth;
	bool require_encryption;
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_network_intent_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_network_intent *intents;
	size_t capacity;
	uint64_t next_intent_id;
	uint64_t allow_count;
	uint64_t deny_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_placement_node {
	uint32_t schema_version;
	uint32_t generation;
	char node_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	char jurisdiction[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t capability_mask;
	uint64_t total_compute_units;
	uint64_t available_compute_units;
	uint64_t total_memory_bytes;
	uint64_t available_memory_bytes;
	uint64_t policy_epoch;
	uint64_t attested_at_ms;
	uint64_t attestation_expires_at_ms;
	uint32_t risk_score;
	uint32_t active_workloads;
	uint32_t maximum_workloads;
	bool confidential_compute;
	bool occupied;
};

struct pqcp_sovereign_placement_request {
	char workload_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char required_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	char required_jurisdiction[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t required_capabilities;
	uint64_t compute_units;
	uint64_t memory_bytes;
	uint64_t policy_epoch;
	uint64_t now_ms;
	uint32_t maximum_risk;
	bool require_confidential_compute;
};

struct pqcp_sovereign_placement_reservation {
	uint32_t schema_version;
	uint64_t reservation_id;
	char workload_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	/* Tenant owning the reserved node; a node is identified by tenant and
	 * node id, so restoring by node id alone could credit another tenant.
	 */
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char node_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	uint64_t compute_units;
	uint64_t memory_bytes;
	uint64_t reserved_at_ms;
	uint64_t expires_at_ms;
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_placement_engine {
	uint32_t schema_version;
	struct pqcp_sovereign_placement_node *nodes;
	size_t node_capacity;
	struct pqcp_sovereign_placement_reservation *reservations;
	size_t reservation_capacity;
	uint32_t next_node_generation;
	uint64_t next_reservation_id;
	uint64_t placement_count;
	uint64_t denial_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_dependency_edge {
	uint32_t schema_version;
	uint64_t edge_id;
	char source_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char destination_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char dependency_type[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t operation_mask;
	uint64_t policy_epoch;
	uint32_t criticality;
	uint32_t maximum_latency_ms;
	uint32_t minimum_availability_basis_points;
	bool hard_dependency;
	bool occupied;
};

struct pqcp_sovereign_dependency_graph {
	uint32_t schema_version;
	struct pqcp_sovereign_dependency_edge *edges;
	size_t capacity;
	uint64_t next_edge_id;
	uint64_t generation;
	uint64_t cycle_rejection_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_risk_node {
	uint32_t schema_version;
	uint32_t generation;
	char subject_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char subject_type[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t observed_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint32_t inherent_risk;
	uint32_t control_strength;
	uint32_t exposure_score;
	uint32_t propagated_risk;
	uint32_t residual_risk;
	uint64_t signal_mask;
	uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_risk_edge {
	uint32_t schema_version;
	uint64_t edge_id;
	char source_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char destination_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	uint32_t propagation_basis_points;
	uint32_t confidence_basis_points;
	uint64_t expires_at_ms;
	bool occupied;
};

struct pqcp_sovereign_risk_graph {
	uint32_t schema_version;
	struct pqcp_sovereign_risk_node *nodes;
	size_t node_capacity;
	struct pqcp_sovereign_risk_edge *edges;
	size_t edge_capacity;
	uint32_t next_node_generation;
	uint64_t next_edge_id;
	uint64_t evaluation_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_threat_indicator {
	uint32_t schema_version;
	uint64_t indicator_id;
	char indicator_type[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char value[PQCP_SOVEREIGN_URI_MAX_CHARS];
	char source[PQCP_SOVEREIGN_NAME_MAX_CHARS];
	uint64_t first_seen_ms;
	uint64_t last_seen_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint32_t confidence_basis_points;
	uint32_t severity;
	uint64_t tactic_mask;
	uint64_t technique_mask;
	uint8_t indicator_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_threat_intelligence {
	uint32_t schema_version;
	struct pqcp_sovereign_threat_indicator *indicators;
	size_t capacity;
	uint64_t next_indicator_id;
	uint64_t match_count;
	uint64_t expiry_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_forensic_event {
	uint32_t schema_version;
	uint64_t sequence;
	char case_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char subject_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char actor_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char event_type[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t observed_at_ms;
	uint64_t ingested_at_ms;
	uint64_t policy_epoch;
	uint32_t confidence_basis_points;
	uint32_t severity;
	uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t event_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_forensic_timeline {
	uint32_t schema_version;
	struct pqcp_sovereign_forensic_event *events;
	size_t capacity;
	size_t next_index;
	size_t count;
	uint64_t next_sequence;
	uint64_t dropped_count;
	uint8_t chain_head[PQCP_SOVEREIGN_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_control_mapping {
	uint32_t schema_version;
	uint32_t mapping_id;
	char internal_control[PQCP_SOVEREIGN_CONTROL_MAX_CHARS];
	char framework[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char external_control[PQCP_SOVEREIGN_CONTROL_MAX_CHARS];
	char evidence_type[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t policy_epoch;
	uint32_t weight_basis_points;
	bool mandatory;
	bool enabled;
};

struct pqcp_sovereign_control_catalog {
	uint32_t schema_version;
	struct pqcp_sovereign_control_mapping *mappings;
	size_t capacity;
	uint32_t next_mapping_id;
	uint64_t generation;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_exception {
	uint32_t schema_version;
	uint64_t exception_id;
	char subject_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char control_id[PQCP_SOVEREIGN_CONTROL_MAX_CHARS];
	char owner_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char justification[PQCP_SOVEREIGN_REASON_MAX_CHARS];
	uint64_t requested_at_ms;
	uint64_t approved_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint32_t residual_risk;
	uint32_t compensating_control_mask;
	enum pqcp_sovereign_exception_state state;
	uint8_t approval_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_sovereign_exception_manager {
	uint32_t schema_version;
	struct pqcp_sovereign_exception *exceptions;
	size_t capacity;
	uint64_t next_exception_id;
	uint64_t approval_count;
	uint64_t expiry_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_evidence_reference {
	uint32_t schema_version;
	uint64_t package_id;
	char evidence_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char evidence_type[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char control_id[PQCP_SOVEREIGN_CONTROL_MAX_CHARS];
	uint64_t observed_at_ms;
	uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool verified;
	bool occupied;
};

struct pqcp_sovereign_evidence_package {
	uint32_t schema_version;
	uint64_t package_id;
	char subject_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char framework[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t period_started_ms;
	uint64_t period_ended_ms;
	uint64_t generated_at_ms;
	uint64_t policy_epoch;
	uint32_t evidence_count;
	uint32_t verified_count;
	uint32_t mandatory_control_count;
	uint32_t satisfied_control_count;
	uint32_t score_basis_points;
	uint8_t package_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool sealed;
	bool occupied;
};

struct pqcp_sovereign_evidence_packager {
	uint32_t schema_version;
	struct pqcp_sovereign_evidence_package *packages;
	size_t package_capacity;
	struct pqcp_sovereign_evidence_reference *references;
	size_t reference_capacity;
	uint64_t next_package_id;
	uint64_t sealed_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_export_cursor {
	uint32_t schema_version;
	uint64_t cursor_id;
	char consumer_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char framework[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t next_package_id;
	uint64_t acknowledged_package_id;
	uint64_t opened_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint32_t maximum_batch;
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_regulator_exporter {
	uint32_t schema_version;
	struct pqcp_sovereign_export_cursor *cursors;
	size_t capacity;
	uint64_t next_cursor_id;
	uint64_t export_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_continuity_exercise {
	uint32_t schema_version;
	uint64_t exercise_id;
	char service_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char scenario[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t planned_at_ms;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	uint64_t policy_epoch;
	uint32_t required_steps;
	uint32_t completed_steps;
	uint32_t failed_steps;
	uint32_t maximum_failures;
	uint64_t recovery_time_objective_ms;
	uint64_t recovery_point_objective_ms;
	uint64_t observed_recovery_time_ms;
	uint64_t observed_data_loss_ms;
	uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_continuity_exerciser {
	uint32_t schema_version;
	struct pqcp_sovereign_continuity_exercise *exercises;
	size_t capacity;
	uint64_t next_exercise_id;
	uint64_t success_count;
	uint64_t failure_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_recovery_vote {
	uint32_t schema_version;
	uint64_t recovery_id;
	char operator_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char role[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t voted_at_ms;
	uint64_t credential_epoch;
	uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool approve;
	bool occupied;
};

struct pqcp_sovereign_recovery_request {
	uint32_t schema_version;
	uint64_t recovery_id;
	char subject_id[PQCP_SOVEREIGN_SUBJECT_MAX_CHARS];
	char action[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	uint64_t opened_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint32_t threshold;
	uint32_t required_distinct_roles;
	uint32_t approval_count;
	uint32_t rejection_count;
	uint32_t distinct_role_count;
	uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_approval_state state;
	bool occupied;
};

struct pqcp_sovereign_recovery_quorum {
	uint32_t schema_version;
	struct pqcp_sovereign_recovery_request *requests;
	size_t request_capacity;
	struct pqcp_sovereign_recovery_vote *votes;
	size_t vote_capacity;
	uint64_t next_recovery_id;
	uint64_t satisfied_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_cost_budget {
	uint32_t schema_version;
	uint32_t budget_id;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char namespace_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	uint64_t window_started_ms;
	uint64_t window_ms;
	uint64_t compute_limit_units;
	uint64_t compute_used_units;
	uint64_t storage_limit_byte_ms;
	uint64_t storage_used_byte_ms;
	uint64_t network_limit_bytes;
	uint64_t network_used_bytes;
	uint64_t carbon_limit_milligrams;
	uint64_t carbon_used_milligrams;
	uint32_t warning_basis_points;
	enum pqcp_sovereign_lifecycle_state state;
	bool occupied;
};

struct pqcp_sovereign_cost_governor {
	uint32_t schema_version;
	struct pqcp_sovereign_cost_budget *budgets;
	size_t capacity;
	uint32_t next_budget_id;
	uint64_t accepted_count;
	uint64_t denied_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_supply_chain_context {
	const struct pqcp_sovereign_artifact *artifact;
	const struct pqcp_sovereign_sbom_document *sbom;
	const struct pqcp_sovereign_build_attestation *attestation;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char target_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t now_ms;
	uint32_t approval_count;
	uint32_t distinct_roles;
	bool transparency_verified;
};

struct pqcp_sovereign_supply_chain_result {
	enum pqcp_sovereign_decision decision;
	uint32_t failure_mask;
	uint32_t artifact_risk;
	uint32_t component_risk;
	int release_policy_result;
	int approval_result;
	int transparency_result;
	int attestation_result;
	char explanation[PQCP_SOVEREIGN_REASON_MAX_CHARS];
};

struct pqcp_sovereign_runtime_storage {
	struct pqcp_sovereign_tenant *tenants;
	size_t tenant_capacity;
	struct pqcp_sovereign_namespace *namespaces;
	size_t namespace_capacity;
	struct pqcp_sovereign_artifact *artifacts;
	size_t artifact_capacity;
	struct pqcp_sovereign_sbom_document *sbom_documents;
	size_t sbom_document_capacity;
	struct pqcp_sovereign_sbom_component *sbom_components;
	size_t sbom_component_capacity;
	struct pqcp_sovereign_transparency_entry *transparency_entries;
	size_t transparency_capacity;
	struct pqcp_sovereign_build_attestation *build_attestations;
	size_t build_attestation_capacity;
	struct pqcp_sovereign_release_rule *release_rules;
	size_t release_rule_capacity;
	struct pqcp_sovereign_deployment_ring *rings;
	size_t ring_capacity;
	struct pqcp_sovereign_rollout *rollouts;
	size_t rollout_capacity;
	struct pqcp_sovereign_rollback_plan *rollback_plans;
	size_t rollback_capacity;
	struct pqcp_sovereign_approval_request *approval_requests;
	size_t approval_request_capacity;
	struct pqcp_sovereign_approval_vote *approval_votes;
	size_t approval_vote_capacity;
	struct pqcp_sovereign_key_ceremony *key_ceremonies;
	size_t key_ceremony_capacity;
	struct pqcp_sovereign_key_contribution *key_contributions;
	size_t key_contribution_capacity;
	struct pqcp_sovereign_custody_event *custody_events;
	size_t custody_capacity;
	struct pqcp_sovereign_secret_grant *secret_grants;
	size_t secret_grant_capacity;
	struct pqcp_sovereign_privacy_budget *privacy_budgets;
	size_t privacy_budget_capacity;
	struct pqcp_sovereign_residency_rule *residency_rules;
	size_t residency_rule_capacity;
	struct pqcp_sovereign_consent_record *consents;
	size_t consent_capacity;
	struct pqcp_sovereign_purpose_binding *purpose_bindings;
	size_t purpose_binding_capacity;
	struct pqcp_sovereign_retention_rule *retention_rules;
	size_t retention_rule_capacity;
	struct pqcp_sovereign_retention_record *retention_records;
	size_t retention_record_capacity;
	struct pqcp_sovereign_data_contract *data_contracts;
	size_t data_contract_capacity;
	struct pqcp_sovereign_egress_rule *egress_rules;
	size_t egress_rule_capacity;
	struct pqcp_sovereign_egress_usage *egress_usage;
	size_t egress_usage_capacity;
	struct pqcp_sovereign_network_intent *network_intents;
	size_t network_intent_capacity;
	struct pqcp_sovereign_placement_node *placement_nodes;
	size_t placement_node_capacity;
	struct pqcp_sovereign_placement_reservation *placement_reservations;
	size_t placement_reservation_capacity;
	struct pqcp_sovereign_dependency_edge *dependency_edges;
	size_t dependency_capacity;
	struct pqcp_sovereign_risk_node *risk_nodes;
	size_t risk_node_capacity;
	struct pqcp_sovereign_risk_edge *risk_edges;
	size_t risk_edge_capacity;
	struct pqcp_sovereign_threat_indicator *threat_indicators;
	size_t threat_indicator_capacity;
	struct pqcp_sovereign_forensic_event *forensic_events;
	size_t forensic_capacity;
	struct pqcp_sovereign_control_mapping *control_mappings;
	size_t control_mapping_capacity;
	struct pqcp_sovereign_exception *exceptions;
	size_t exception_capacity;
	struct pqcp_sovereign_evidence_package *evidence_packages;
	size_t evidence_package_capacity;
	struct pqcp_sovereign_evidence_reference *evidence_references;
	size_t evidence_reference_capacity;
	struct pqcp_sovereign_export_cursor *export_cursors;
	size_t export_cursor_capacity;
	struct pqcp_sovereign_continuity_exercise *continuity_exercises;
	size_t continuity_exercise_capacity;
	struct pqcp_sovereign_recovery_request *recovery_requests;
	size_t recovery_request_capacity;
	struct pqcp_sovereign_recovery_vote *recovery_votes;
	size_t recovery_vote_capacity;
	struct pqcp_sovereign_cost_budget *cost_budgets;
	size_t cost_budget_capacity;
};

struct pqcp_sovereign_runtime {
	uint32_t schema_version;
	struct pqcp_sovereign_tenant_registry tenants;
	struct pqcp_sovereign_namespace_manager namespaces;
	struct pqcp_sovereign_artifact_catalog artifacts;
	struct pqcp_sovereign_sbom_registry sbom;
	struct pqcp_sovereign_transparency_log transparency;
	struct pqcp_sovereign_build_attestation_store attestations;
	struct pqcp_sovereign_release_policy releases;
	struct pqcp_sovereign_ring_registry rings;
	struct pqcp_sovereign_rollout_controller rollouts;
	struct pqcp_sovereign_rollback_coordinator rollbacks;
	struct pqcp_sovereign_approval_quorum approvals;
	struct pqcp_sovereign_key_ceremony_manager ceremonies;
	struct pqcp_sovereign_custody_ledger custody;
	struct pqcp_sovereign_secret_distributor secrets;
	struct pqcp_sovereign_privacy_budget_manager privacy;
	struct pqcp_sovereign_residency_engine residency;
	struct pqcp_sovereign_consent_ledger consent;
	struct pqcp_sovereign_purpose_engine purposes;
	struct pqcp_sovereign_retention_manager retention;
	struct pqcp_sovereign_data_contract_manager contracts;
	struct pqcp_sovereign_egress_engine egress;
	struct pqcp_sovereign_network_intent_manager network;
	struct pqcp_sovereign_placement_engine placement;
	struct pqcp_sovereign_dependency_graph dependencies;
	struct pqcp_sovereign_risk_graph risk;
	struct pqcp_sovereign_threat_intelligence threats;
	struct pqcp_sovereign_forensic_timeline forensics;
	struct pqcp_sovereign_control_catalog controls;
	struct pqcp_sovereign_exception_manager exceptions;
	struct pqcp_sovereign_evidence_packager evidence;
	struct pqcp_sovereign_regulator_exporter exporter;
	struct pqcp_sovereign_continuity_exerciser continuity;
	struct pqcp_sovereign_recovery_quorum recovery;
	struct pqcp_sovereign_cost_governor cost;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t tick_count;
	bool initialized;
};

int pqcp_sovereign_tenant_registry_init(
	struct pqcp_sovereign_tenant_registry *registry,
	struct pqcp_sovereign_tenant *tenants,
	size_t capacity);
int pqcp_sovereign_tenant_register(
	struct pqcp_sovereign_tenant_registry *registry,
	const struct pqcp_sovereign_tenant *tenant,
	uint64_t now_ms);
int pqcp_sovereign_tenant_find(
	struct pqcp_sovereign_tenant_registry *registry,
	const char *tenant_id,
	struct pqcp_sovereign_tenant **tenant);
int pqcp_sovereign_tenant_authorize(
	struct pqcp_sovereign_tenant_registry *registry,
	const char *tenant_id,
	enum pqcp_sovereign_operation operation,
	uint64_t capabilities,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms);
int pqcp_sovereign_tenant_set_state(
	struct pqcp_sovereign_tenant_registry *registry,
	const char *tenant_id,
	enum pqcp_sovereign_lifecycle_state state,
	uint64_t now_ms);
int pqcp_sovereign_tenant_tick(
	struct pqcp_sovereign_tenant_registry *registry,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_sovereign_tenant_registry_audit(
	struct pqcp_sovereign_tenant_registry *registry);

int pqcp_sovereign_namespace_manager_init(
	struct pqcp_sovereign_namespace_manager *manager,
	struct pqcp_sovereign_namespace *namespaces,
	size_t capacity);
int pqcp_sovereign_namespace_create(
	struct pqcp_sovereign_namespace_manager *manager,
	struct pqcp_sovereign_tenant_registry *tenants,
	const struct pqcp_sovereign_namespace *namespace_value,
	uint64_t now_ms);
int pqcp_sovereign_namespace_find(
	struct pqcp_sovereign_namespace_manager *manager,
	const char *namespace_id,
	struct pqcp_sovereign_namespace **namespace_value);
int pqcp_sovereign_namespace_reserve_workload(
	struct pqcp_sovereign_namespace_manager *manager,
	const char *namespace_id,
	uint64_t storage_bytes);
int pqcp_sovereign_namespace_release_workload(
	struct pqcp_sovereign_namespace_manager *manager,
	const char *namespace_id,
	uint64_t storage_bytes);
int pqcp_sovereign_namespace_authorize(
	struct pqcp_sovereign_namespace_manager *manager,
	const char *namespace_id,
	enum pqcp_sovereign_operation operation,
	enum pqcp_sovereign_data_class data_class,
	uint64_t policy_epoch,
	uint64_t now_ms);
int pqcp_sovereign_namespace_manager_audit(
	struct pqcp_sovereign_namespace_manager *manager);

int pqcp_sovereign_artifact_catalog_init(
	struct pqcp_sovereign_artifact_catalog *catalog,
	struct pqcp_sovereign_artifact *artifacts,
	size_t capacity);
int pqcp_sovereign_artifact_register(
	struct pqcp_sovereign_artifact_catalog *catalog,
	const struct pqcp_sovereign_artifact *artifact,
	uint64_t now_ms);
int pqcp_sovereign_artifact_find(
	struct pqcp_sovereign_artifact_catalog *catalog,
	const char *artifact_id,
	struct pqcp_sovereign_artifact **artifact);
int pqcp_sovereign_artifact_transition(
	struct pqcp_sovereign_artifact_catalog *catalog,
	const char *artifact_id,
	enum pqcp_sovereign_artifact_state state,
	uint64_t policy_epoch);
int pqcp_sovereign_artifact_quarantine(
	struct pqcp_sovereign_artifact_catalog *catalog,
	const char *artifact_id,
	uint32_t risk_score);
int pqcp_sovereign_artifact_catalog_audit(
	struct pqcp_sovereign_artifact_catalog *catalog);

int pqcp_sovereign_sbom_registry_init(
	struct pqcp_sovereign_sbom_registry *registry,
	struct pqcp_sovereign_sbom_document *documents,
	size_t document_capacity,
	struct pqcp_sovereign_sbom_component *components,
	size_t component_capacity);
int pqcp_sovereign_sbom_begin(
	struct pqcp_sovereign_sbom_registry *registry,
	const struct pqcp_sovereign_sbom_document *document);
int pqcp_sovereign_sbom_add_component(
	struct pqcp_sovereign_sbom_registry *registry,
	const struct pqcp_sovereign_sbom_component *component);
int pqcp_sovereign_sbom_finalize(
	struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	uint8_t document_digest[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_sbom_find(
	struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	struct pqcp_sovereign_sbom_document **document);
int pqcp_sovereign_sbom_component_risk(
	struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	uint32_t forbidden_flags,
	uint32_t *maximum_risk,
	uint32_t *failure_count);
int pqcp_sovereign_sbom_registry_audit(
	struct pqcp_sovereign_sbom_registry *registry);

int pqcp_sovereign_transparency_log_init(
	struct pqcp_sovereign_transparency_log *log,
	struct pqcp_sovereign_transparency_entry *entries,
	size_t capacity);
int pqcp_sovereign_transparency_append(
	struct pqcp_sovereign_transparency_log *log,
	const char *subject_id,
	const char *event_type,
	const char *actor_id,
	uint64_t policy_epoch,
	const uint8_t subject_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_sovereign_transparency_entry *entry);
int pqcp_sovereign_transparency_find(
	struct pqcp_sovereign_transparency_log *log,
	uint64_t sequence,
	struct pqcp_sovereign_transparency_entry *entry);
int pqcp_sovereign_transparency_subject_latest(
	struct pqcp_sovereign_transparency_log *log,
	const char *subject_id,
	struct pqcp_sovereign_transparency_entry *entry);
int pqcp_sovereign_transparency_verify(
	struct pqcp_sovereign_transparency_log *log);

int pqcp_sovereign_build_attestation_store_init(
	struct pqcp_sovereign_build_attestation_store *store,
	struct pqcp_sovereign_build_attestation *records,
	size_t capacity);
int pqcp_sovereign_build_attestation_put(
	struct pqcp_sovereign_build_attestation_store *store,
	const struct pqcp_sovereign_build_attestation *attestation,
	uint64_t now_ms);
int pqcp_sovereign_build_attestation_find(
	struct pqcp_sovereign_build_attestation_store *store,
	const char *artifact_id,
	uint64_t now_ms,
	struct pqcp_sovereign_build_attestation **attestation);
int pqcp_sovereign_build_attestation_verify(
	struct pqcp_sovereign_build_attestation_store *store,
	uint64_t attestation_id,
	const uint8_t expected_output[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t minimum_policy_epoch,
	uint64_t now_ms);
int pqcp_sovereign_build_attestation_expire(
	struct pqcp_sovereign_build_attestation_store *store,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_build_attestation_store_audit(
	struct pqcp_sovereign_build_attestation_store *store);

int pqcp_sovereign_release_policy_init(
	struct pqcp_sovereign_release_policy *policy,
	struct pqcp_sovereign_release_rule *rules,
	size_t capacity,
	enum pqcp_sovereign_decision default_effect);
int pqcp_sovereign_release_rule_put(
	struct pqcp_sovereign_release_policy *policy,
	const struct pqcp_sovereign_release_rule *rule);
int pqcp_sovereign_release_rule_remove(
	struct pqcp_sovereign_release_policy *policy,
	uint32_t rule_id);
int pqcp_sovereign_release_evaluate(
	struct pqcp_sovereign_release_policy *policy,
	const struct pqcp_sovereign_release_context *context,
	struct pqcp_sovereign_release_decision *decision);
int pqcp_sovereign_release_policy_audit(
	struct pqcp_sovereign_release_policy *policy);

int pqcp_sovereign_ring_registry_init(
	struct pqcp_sovereign_ring_registry *registry,
	struct pqcp_sovereign_deployment_ring *rings,
	size_t capacity);
int pqcp_sovereign_ring_put(
	struct pqcp_sovereign_ring_registry *registry,
	const struct pqcp_sovereign_deployment_ring *ring,
	uint64_t now_ms);
int pqcp_sovereign_ring_find(
	struct pqcp_sovereign_ring_registry *registry,
	const char *ring_id,
	struct pqcp_sovereign_deployment_ring **ring);
int pqcp_sovereign_ring_set_state(
	struct pqcp_sovereign_ring_registry *registry,
	const char *ring_id,
	enum pqcp_sovereign_lifecycle_state state);
int pqcp_sovereign_ring_registry_audit(
	struct pqcp_sovereign_ring_registry *registry);

int pqcp_sovereign_rollout_controller_init(
	struct pqcp_sovereign_rollout_controller *controller,
	struct pqcp_sovereign_rollout *rollouts,
	size_t capacity);
int pqcp_sovereign_rollout_plan(
	struct pqcp_sovereign_rollout_controller *controller,
	const char *artifact_id,
	const struct pqcp_sovereign_deployment_ring *ring,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t deadline_ms,
	uint32_t batch_size,
	const uint8_t plan_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	struct pqcp_sovereign_rollout **rollout);
int pqcp_sovereign_rollout_start(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint64_t now_ms);
int pqcp_sovereign_rollout_record_batch(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint32_t attempted,
	uint32_t succeeded,
	uint32_t failed,
	uint32_t unavailable,
	uint64_t now_ms);
int pqcp_sovereign_rollout_pause(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	int result);
int pqcp_sovereign_rollout_resume(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint64_t now_ms);
int pqcp_sovereign_rollout_request_rollback(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t rollout_id,
	uint64_t now_ms);
int pqcp_sovereign_rollout_tick(
	struct pqcp_sovereign_rollout_controller *controller,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_sovereign_rollout_controller_audit(
	struct pqcp_sovereign_rollout_controller *controller);

int pqcp_sovereign_rollback_coordinator_init(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	struct pqcp_sovereign_rollback_plan *plans,
	size_t capacity);
int pqcp_sovereign_rollback_authorize(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollout_id,
	const char *current_artifact_id,
	const char *target_artifact_id,
	uint64_t policy_epoch,
	uint32_t required_steps,
	uint32_t maximum_failures,
	const uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t deadline_ms,
	struct pqcp_sovereign_rollback_plan **plan);
int pqcp_sovereign_rollback_record_step(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollback_id,
	uint32_t step,
	bool success,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_rollback_complete(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t rollback_id);
int pqcp_sovereign_rollback_tick(
	struct pqcp_sovereign_rollback_coordinator *coordinator,
	uint64_t now_ms,
	uint32_t *failed_count);
int pqcp_sovereign_rollback_coordinator_audit(
	struct pqcp_sovereign_rollback_coordinator *coordinator);

int pqcp_sovereign_approval_quorum_init(
	struct pqcp_sovereign_approval_quorum *quorum,
	struct pqcp_sovereign_approval_request *requests,
	size_t request_capacity,
	struct pqcp_sovereign_approval_vote *votes,
	size_t vote_capacity);
int pqcp_sovereign_approval_open(
	struct pqcp_sovereign_approval_quorum *quorum,
	const char *subject_id,
	const char *action,
	uint64_t required_capabilities,
	uint32_t required_approvals,
	uint32_t required_distinct_roles,
	const uint8_t subject_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_approval_request **request);
int pqcp_sovereign_approval_vote(
	struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id,
	const char *approver_id,
	const char *role,
	uint64_t capabilities,
	uint64_t credential_epoch,
	bool approve,
	const uint8_t vote_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_approval_status(
	struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id,
	enum pqcp_sovereign_approval_state *state,
	uint32_t *approvals,
	uint32_t *distinct_roles);
int pqcp_sovereign_approval_tick(
	struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_approval_quorum_audit(
	struct pqcp_sovereign_approval_quorum *quorum);

int pqcp_sovereign_key_ceremony_manager_init(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	struct pqcp_sovereign_key_ceremony *ceremonies,
	size_t ceremony_capacity,
	struct pqcp_sovereign_key_contribution *contributions,
	size_t contribution_capacity);
int pqcp_sovereign_key_ceremony_open(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	const char *key_id,
	const char *purpose,
	uint64_t current_epoch,
	uint64_t target_epoch,
	uint32_t threshold,
	uint32_t required_distinct_roles,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_key_ceremony **ceremony);
int pqcp_sovereign_key_ceremony_contribute(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id,
	const char *custodian_id,
	const char *role,
	uint64_t credential_epoch,
	const uint8_t contribution_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t proof_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_key_ceremony_commit(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id,
	const uint8_t committed_key_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_key_ceremony_abort(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id);
int pqcp_sovereign_key_ceremony_tick(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t now_ms,
	uint32_t *aborted_count);
int pqcp_sovereign_key_ceremony_manager_audit(
	struct pqcp_sovereign_key_ceremony_manager *manager);

int pqcp_sovereign_custody_ledger_init(
	struct pqcp_sovereign_custody_ledger *ledger,
	struct pqcp_sovereign_custody_event *events,
	size_t capacity);
int pqcp_sovereign_custody_append(
	struct pqcp_sovereign_custody_ledger *ledger,
	const char *key_id,
	const char *custodian_id,
	const char *action,
	uint64_t key_epoch,
	uint64_t policy_epoch,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_sovereign_custody_event *event);
int pqcp_sovereign_custody_find(
	struct pqcp_sovereign_custody_ledger *ledger,
	uint64_t sequence,
	struct pqcp_sovereign_custody_event *event);
int pqcp_sovereign_custody_verify(
	struct pqcp_sovereign_custody_ledger *ledger);

int pqcp_sovereign_secret_distributor_init(
	struct pqcp_sovereign_secret_distributor *distributor,
	struct pqcp_sovereign_secret_grant *grants,
	size_t capacity);
int pqcp_sovereign_secret_grant_issue(
	struct pqcp_sovereign_secret_distributor *distributor,
	const char *key_id,
	const char *recipient_id,
	const char *namespace_id,
	uint64_t key_epoch,
	uint64_t policy_epoch,
	uint32_t permissions,
	const uint8_t recipient_binding[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t wrapped_secret_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t maximum_uses,
	struct pqcp_sovereign_secret_grant **grant);
int pqcp_sovereign_secret_grant_authorize(
	struct pqcp_sovereign_secret_distributor *distributor,
	uint64_t grant_id,
	const char *recipient_id,
	const char *namespace_id,
	uint64_t key_epoch,
	uint64_t policy_epoch,
	uint32_t permissions,
	const uint8_t recipient_binding[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_secret_grant_revoke(
	struct pqcp_sovereign_secret_distributor *distributor,
	uint64_t grant_id);
int pqcp_sovereign_secret_grant_tick(
	struct pqcp_sovereign_secret_distributor *distributor,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_secret_distributor_audit(
	struct pqcp_sovereign_secret_distributor *distributor);

int pqcp_sovereign_privacy_budget_manager_init(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	struct pqcp_sovereign_privacy_budget *budgets,
	size_t capacity);
int pqcp_sovereign_privacy_budget_put(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	const struct pqcp_sovereign_privacy_budget *budget,
	uint64_t now_ms);
int pqcp_sovereign_privacy_budget_consume(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	const char *budget_id,
	uint64_t epsilon_micros,
	uint64_t delta_nanos,
	uint64_t query_count,
	uint64_t policy_epoch,
	uint64_t now_ms);
int pqcp_sovereign_privacy_budget_remaining(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	const char *budget_id,
	uint64_t now_ms,
	uint64_t *epsilon_micros,
	uint64_t *delta_nanos,
	uint64_t *query_count);
int pqcp_sovereign_privacy_budget_tick(
	struct pqcp_sovereign_privacy_budget_manager *manager,
	uint64_t now_ms,
	uint32_t *reset_count);
int pqcp_sovereign_privacy_budget_manager_audit(
	struct pqcp_sovereign_privacy_budget_manager *manager);

int pqcp_sovereign_residency_engine_init(
	struct pqcp_sovereign_residency_engine *engine,
	struct pqcp_sovereign_residency_rule *rules,
	size_t capacity,
	enum pqcp_sovereign_decision default_effect);
int pqcp_sovereign_residency_rule_put(
	struct pqcp_sovereign_residency_engine *engine,
	const struct pqcp_sovereign_residency_rule *rule);
int pqcp_sovereign_residency_rule_remove(
	struct pqcp_sovereign_residency_engine *engine,
	uint32_t rule_id);
int pqcp_sovereign_residency_evaluate(
	struct pqcp_sovereign_residency_engine *engine,
	const struct pqcp_sovereign_residency_context *context,
	enum pqcp_sovereign_decision *decision,
	uint32_t *rule_id);
int pqcp_sovereign_residency_engine_audit(
	struct pqcp_sovereign_residency_engine *engine);

int pqcp_sovereign_consent_ledger_init(
	struct pqcp_sovereign_consent_ledger *ledger,
	struct pqcp_sovereign_consent_record *records,
	size_t capacity);
int pqcp_sovereign_consent_grant(
	struct pqcp_sovereign_consent_ledger *ledger,
	const char *tenant_id,
	const char *subject_id,
	const char *controller_id,
	const char *purpose,
	uint32_t data_class_mask,
	uint64_t policy_epoch,
	const uint8_t terms_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t receipt_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_consent_record **record);
int pqcp_sovereign_consent_authorize(
	struct pqcp_sovereign_consent_ledger *ledger,
	const char *tenant_id,
	const char *subject_id,
	const char *controller_id,
	const char *purpose,
	enum pqcp_sovereign_data_class data_class,
	uint64_t policy_epoch,
	uint64_t now_ms);
int pqcp_sovereign_consent_revoke(
	struct pqcp_sovereign_consent_ledger *ledger,
	uint64_t consent_id,
	uint64_t now_ms);
int pqcp_sovereign_consent_tick(
	struct pqcp_sovereign_consent_ledger *ledger,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_consent_ledger_audit(
	struct pqcp_sovereign_consent_ledger *ledger);

int pqcp_sovereign_purpose_engine_init(
	struct pqcp_sovereign_purpose_engine *engine,
	struct pqcp_sovereign_purpose_binding *bindings,
	size_t capacity);
int pqcp_sovereign_purpose_binding_put(
	struct pqcp_sovereign_purpose_engine *engine,
	const struct pqcp_sovereign_purpose_binding *binding);
int pqcp_sovereign_purpose_binding_remove(
	struct pqcp_sovereign_purpose_engine *engine,
	uint32_t binding_id);
int pqcp_sovereign_purpose_authorize(
	struct pqcp_sovereign_purpose_engine *engine,
	const char *tenant_id,
	const char *workload_id,
	const char *purpose,
	enum pqcp_sovereign_operation operation,
	enum pqcp_sovereign_data_class data_class,
	uint32_t risk_score,
	bool consent_valid,
	uint64_t policy_epoch,
	uint64_t now_ms);
int pqcp_sovereign_purpose_engine_audit(
	struct pqcp_sovereign_purpose_engine *engine);

int pqcp_sovereign_retention_manager_init(
	struct pqcp_sovereign_retention_manager *manager,
	struct pqcp_sovereign_retention_rule *rules,
	size_t rule_capacity,
	struct pqcp_sovereign_retention_record *records,
	size_t record_capacity);
int pqcp_sovereign_retention_rule_put(
	struct pqcp_sovereign_retention_manager *manager,
	const struct pqcp_sovereign_retention_rule *rule);
int pqcp_sovereign_retention_track(
	struct pqcp_sovereign_retention_manager *manager,
	const char *object_id,
	const char *tenant_id,
	const char *purpose,
	enum pqcp_sovereign_data_class data_class,
	const uint8_t object_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_sovereign_retention_record **record);
int pqcp_sovereign_retention_hold(
	struct pqcp_sovereign_retention_manager *manager,
	uint64_t record_id,
	uint64_t hold_until_ms);
int pqcp_sovereign_retention_mark_deleted(
	struct pqcp_sovereign_retention_manager *manager,
	uint64_t record_id,
	uint64_t now_ms);
int pqcp_sovereign_retention_due(
	struct pqcp_sovereign_retention_manager *manager,
	uint64_t now_ms,
	struct pqcp_sovereign_retention_record **record);
int pqcp_sovereign_retention_manager_audit(
	struct pqcp_sovereign_retention_manager *manager);

int pqcp_sovereign_data_contract_manager_init(
	struct pqcp_sovereign_data_contract_manager *manager,
	struct pqcp_sovereign_data_contract *contracts,
	size_t capacity);
int pqcp_sovereign_data_contract_put(
	struct pqcp_sovereign_data_contract_manager *manager,
	const struct pqcp_sovereign_data_contract *contract,
	uint64_t now_ms);
int pqcp_sovereign_data_contract_authorize(
	struct pqcp_sovereign_data_contract_manager *manager,
	uint64_t contract_id,
	const char *provider_id,
	const char *consumer_id,
	const char *dataset_id,
	const char *purpose,
	enum pqcp_sovereign_operation operation,
	uint64_t records,
	uint64_t bytes,
	uint32_t risk_score,
	bool consent_valid,
	bool encrypted,
	uint64_t policy_epoch,
	uint64_t now_ms);
int pqcp_sovereign_data_contract_revoke(
	struct pqcp_sovereign_data_contract_manager *manager,
	uint64_t contract_id);
int pqcp_sovereign_data_contract_tick(
	struct pqcp_sovereign_data_contract_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_data_contract_manager_audit(
	struct pqcp_sovereign_data_contract_manager *manager);

int pqcp_sovereign_egress_engine_init(
	struct pqcp_sovereign_egress_engine *engine,
	struct pqcp_sovereign_egress_rule *rules,
	size_t rule_capacity,
	struct pqcp_sovereign_egress_usage *usage,
	size_t usage_capacity,
	enum pqcp_sovereign_decision default_effect);
int pqcp_sovereign_egress_rule_put(
	struct pqcp_sovereign_egress_engine *engine,
	const struct pqcp_sovereign_egress_rule *rule);
int pqcp_sovereign_egress_authorize(
	struct pqcp_sovereign_egress_engine *engine,
	const char *tenant_id,
	const char *workload_id,
	const char *destination_domain,
	enum pqcp_sovereign_operation operation,
	enum pqcp_sovereign_data_class data_class,
	uint64_t bytes,
	uint32_t risk_score,
	bool encrypted,
	bool dlp_passed,
	uint64_t now_ms,
	uint32_t *rule_id);
int pqcp_sovereign_egress_tick(
	struct pqcp_sovereign_egress_engine *engine,
	uint64_t now_ms,
	uint32_t *reset_count);
int pqcp_sovereign_egress_engine_audit(
	struct pqcp_sovereign_egress_engine *engine);

int pqcp_sovereign_network_intent_manager_init(
	struct pqcp_sovereign_network_intent_manager *manager,
	struct pqcp_sovereign_network_intent *intents,
	size_t capacity);
int pqcp_sovereign_network_intent_put(
	struct pqcp_sovereign_network_intent_manager *manager,
	const struct pqcp_sovereign_network_intent *intent,
	uint64_t now_ms);
int pqcp_sovereign_network_intent_authorize(
	struct pqcp_sovereign_network_intent_manager *manager,
	const char *tenant_id,
	const char *source_namespace,
	const char *destination_namespace,
	const char *protocol,
	uint16_t port,
	enum pqcp_sovereign_operation operation,
	uint32_t risk_score,
	bool mutually_authenticated,
	bool encrypted,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t *intent_id);
int pqcp_sovereign_network_intent_release(
	struct pqcp_sovereign_network_intent_manager *manager,
	uint64_t intent_id);
int pqcp_sovereign_network_intent_tick(
	struct pqcp_sovereign_network_intent_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_network_intent_manager_audit(
	struct pqcp_sovereign_network_intent_manager *manager);

int pqcp_sovereign_placement_engine_init(
	struct pqcp_sovereign_placement_engine *engine,
	struct pqcp_sovereign_placement_node *nodes,
	size_t node_capacity,
	struct pqcp_sovereign_placement_reservation *reservations,
	size_t reservation_capacity);
int pqcp_sovereign_placement_node_put(
	struct pqcp_sovereign_placement_engine *engine,
	const struct pqcp_sovereign_placement_node *node,
	uint64_t now_ms);
int pqcp_sovereign_placement_reserve(
	struct pqcp_sovereign_placement_engine *engine,
	const struct pqcp_sovereign_placement_request *request,
	uint64_t lifetime_ms,
	struct pqcp_sovereign_placement_reservation **reservation);
int pqcp_sovereign_placement_activate(
	struct pqcp_sovereign_placement_engine *engine,
	uint64_t reservation_id);
int pqcp_sovereign_placement_release(
	struct pqcp_sovereign_placement_engine *engine,
	uint64_t reservation_id);
int pqcp_sovereign_placement_tick(
	struct pqcp_sovereign_placement_engine *engine,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_placement_engine_audit(
	struct pqcp_sovereign_placement_engine *engine);

int pqcp_sovereign_dependency_graph_init(
	struct pqcp_sovereign_dependency_graph *graph,
	struct pqcp_sovereign_dependency_edge *edges,
	size_t capacity);
int pqcp_sovereign_dependency_put(
	struct pqcp_sovereign_dependency_graph *graph,
	const struct pqcp_sovereign_dependency_edge *edge);
int pqcp_sovereign_dependency_remove(
	struct pqcp_sovereign_dependency_graph *graph,
	uint64_t edge_id);
int pqcp_sovereign_dependency_reachable(
	struct pqcp_sovereign_dependency_graph *graph,
	const char *source_id,
	const char *destination_id,
	uint32_t maximum_depth,
	bool *reachable);
int pqcp_sovereign_dependency_impact(
	struct pqcp_sovereign_dependency_graph *graph,
	const char *subject_id,
	uint32_t *dependent_count,
	uint32_t *maximum_criticality);
int pqcp_sovereign_dependency_graph_audit(
	struct pqcp_sovereign_dependency_graph *graph);

int pqcp_sovereign_risk_graph_init(
	struct pqcp_sovereign_risk_graph *graph,
	struct pqcp_sovereign_risk_node *nodes,
	size_t node_capacity,
	struct pqcp_sovereign_risk_edge *edges,
	size_t edge_capacity);
int pqcp_sovereign_risk_node_put(
	struct pqcp_sovereign_risk_graph *graph,
	const struct pqcp_sovereign_risk_node *node,
	uint64_t now_ms);
int pqcp_sovereign_risk_edge_put(
	struct pqcp_sovereign_risk_graph *graph,
	const struct pqcp_sovereign_risk_edge *edge);
int pqcp_sovereign_risk_evaluate(
	struct pqcp_sovereign_risk_graph *graph,
	const char *subject_id,
	uint64_t now_ms,
	uint32_t maximum_iterations,
	uint32_t *residual_risk);
int pqcp_sovereign_risk_expire(
	struct pqcp_sovereign_risk_graph *graph,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_risk_graph_audit(
	struct pqcp_sovereign_risk_graph *graph);

int pqcp_sovereign_threat_intelligence_init(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	struct pqcp_sovereign_threat_indicator *indicators,
	size_t capacity);
int pqcp_sovereign_threat_indicator_put(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	const struct pqcp_sovereign_threat_indicator *indicator,
	uint64_t now_ms);
int pqcp_sovereign_threat_match(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	const char *indicator_type,
	const char *value,
	uint64_t now_ms,
	struct pqcp_sovereign_threat_indicator **indicator);
int pqcp_sovereign_threat_revoke(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	uint64_t indicator_id);
int pqcp_sovereign_threat_tick(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_threat_intelligence_audit(
	struct pqcp_sovereign_threat_intelligence *intelligence);

int pqcp_sovereign_forensic_timeline_init(
	struct pqcp_sovereign_forensic_timeline *timeline,
	struct pqcp_sovereign_forensic_event *events,
	size_t capacity);
int pqcp_sovereign_forensic_append(
	struct pqcp_sovereign_forensic_timeline *timeline,
	const char *case_id,
	const char *subject_id,
	const char *actor_id,
	const char *event_type,
	uint64_t observed_at_ms,
	uint64_t ingested_at_ms,
	uint64_t policy_epoch,
	uint32_t confidence_basis_points,
	uint32_t severity,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	struct pqcp_sovereign_forensic_event *event);
int pqcp_sovereign_forensic_find(
	struct pqcp_sovereign_forensic_timeline *timeline,
	uint64_t sequence,
	struct pqcp_sovereign_forensic_event *event);
int pqcp_sovereign_forensic_case_bounds(
	struct pqcp_sovereign_forensic_timeline *timeline,
	const char *case_id,
	uint64_t *first_sequence,
	uint64_t *last_sequence,
	uint32_t *event_count);
int pqcp_sovereign_forensic_verify(
	struct pqcp_sovereign_forensic_timeline *timeline);

int pqcp_sovereign_control_catalog_init(
	struct pqcp_sovereign_control_catalog *catalog,
	struct pqcp_sovereign_control_mapping *mappings,
	size_t capacity);
int pqcp_sovereign_control_mapping_put(
	struct pqcp_sovereign_control_catalog *catalog,
	const struct pqcp_sovereign_control_mapping *mapping);
int pqcp_sovereign_control_mapping_remove(
	struct pqcp_sovereign_control_catalog *catalog,
	uint32_t mapping_id);
int pqcp_sovereign_control_resolve(
	struct pqcp_sovereign_control_catalog *catalog,
	const char *internal_control,
	const char *framework,
	struct pqcp_sovereign_control_mapping **mapping);
int pqcp_sovereign_control_catalog_audit(
	struct pqcp_sovereign_control_catalog *catalog);

int pqcp_sovereign_exception_manager_init(
	struct pqcp_sovereign_exception_manager *manager,
	struct pqcp_sovereign_exception *exceptions,
	size_t capacity);
int pqcp_sovereign_exception_request(
	struct pqcp_sovereign_exception_manager *manager,
	const char *subject_id,
	const char *control_id,
	const char *owner_id,
	const char *justification,
	uint32_t residual_risk,
	uint32_t compensating_control_mask,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_exception **exception);
int pqcp_sovereign_exception_approve(
	struct pqcp_sovereign_exception_manager *manager,
	uint64_t exception_id,
	const uint8_t approval_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_exception_authorize(
	struct pqcp_sovereign_exception_manager *manager,
	const char *subject_id,
	const char *control_id,
	uint32_t maximum_residual_risk,
	uint64_t policy_epoch,
	uint64_t now_ms);
int pqcp_sovereign_exception_revoke(
	struct pqcp_sovereign_exception_manager *manager,
	uint64_t exception_id);
int pqcp_sovereign_exception_tick(
	struct pqcp_sovereign_exception_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_exception_manager_audit(
	struct pqcp_sovereign_exception_manager *manager);

int pqcp_sovereign_evidence_packager_init(
	struct pqcp_sovereign_evidence_packager *packager,
	struct pqcp_sovereign_evidence_package *packages,
	size_t package_capacity,
	struct pqcp_sovereign_evidence_reference *references,
	size_t reference_capacity);
int pqcp_sovereign_evidence_package_open(
	struct pqcp_sovereign_evidence_packager *packager,
	const char *subject_id,
	const char *framework,
	uint64_t period_started_ms,
	uint64_t period_ended_ms,
	uint64_t policy_epoch,
	uint32_t mandatory_control_count,
	uint64_t now_ms,
	struct pqcp_sovereign_evidence_package **package);
int pqcp_sovereign_evidence_package_add(
	struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id,
	const char *evidence_id,
	const char *evidence_type,
	const char *control_id,
	uint64_t observed_at_ms,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	bool verified);
int pqcp_sovereign_evidence_package_seal(
	struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id,
	uint32_t satisfied_control_count,
	uint64_t now_ms);
int pqcp_sovereign_evidence_package_find(
	struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id,
	struct pqcp_sovereign_evidence_package **package);
int pqcp_sovereign_evidence_packager_audit(
	struct pqcp_sovereign_evidence_packager *packager);

int pqcp_sovereign_regulator_exporter_init(
	struct pqcp_sovereign_regulator_exporter *exporter,
	struct pqcp_sovereign_export_cursor *cursors,
	size_t capacity);
int pqcp_sovereign_regulator_export_open(
	struct pqcp_sovereign_regulator_exporter *exporter,
	const char *consumer_id,
	const char *framework,
	uint64_t first_package_id,
	uint32_t maximum_batch,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_export_cursor **cursor);
int pqcp_sovereign_regulator_export_next(
	struct pqcp_sovereign_regulator_exporter *exporter,
	struct pqcp_sovereign_evidence_packager *packager,
	uint64_t cursor_id,
	uint64_t now_ms,
	struct pqcp_sovereign_evidence_package **package);
int pqcp_sovereign_regulator_export_acknowledge(
	struct pqcp_sovereign_regulator_exporter *exporter,
	uint64_t cursor_id,
	uint64_t package_id);
int pqcp_sovereign_regulator_export_tick(
	struct pqcp_sovereign_regulator_exporter *exporter,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_regulator_exporter_audit(
	struct pqcp_sovereign_regulator_exporter *exporter);

int pqcp_sovereign_continuity_exerciser_init(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	struct pqcp_sovereign_continuity_exercise *exercises,
	size_t capacity);
int pqcp_sovereign_continuity_exercise_plan(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	const char *service_id,
	const char *scenario,
	uint32_t required_steps,
	uint32_t maximum_failures,
	uint64_t recovery_time_objective_ms,
	uint64_t recovery_point_objective_ms,
	uint64_t policy_epoch,
	uint64_t now_ms,
	struct pqcp_sovereign_continuity_exercise **exercise);
int pqcp_sovereign_continuity_exercise_start(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	uint64_t exercise_id,
	uint64_t now_ms);
int pqcp_sovereign_continuity_exercise_record_step(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	uint64_t exercise_id,
	uint32_t step,
	bool success,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_continuity_exercise_complete(
	struct pqcp_sovereign_continuity_exerciser *exerciser,
	uint64_t exercise_id,
	uint64_t observed_recovery_time_ms,
	uint64_t observed_data_loss_ms,
	uint64_t now_ms);
int pqcp_sovereign_continuity_exerciser_audit(
	struct pqcp_sovereign_continuity_exerciser *exerciser);

int pqcp_sovereign_recovery_quorum_init(
	struct pqcp_sovereign_recovery_quorum *quorum,
	struct pqcp_sovereign_recovery_request *requests,
	size_t request_capacity,
	struct pqcp_sovereign_recovery_vote *votes,
	size_t vote_capacity);
int pqcp_sovereign_recovery_open(
	struct pqcp_sovereign_recovery_quorum *quorum,
	const char *subject_id,
	const char *action,
	uint32_t threshold,
	uint32_t required_distinct_roles,
	const uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_recovery_request **request);
int pqcp_sovereign_recovery_vote(
	struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id,
	const char *operator_id,
	const char *role,
	uint64_t credential_epoch,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	bool approve,
	uint64_t now_ms);
int pqcp_sovereign_recovery_authorize(
	struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id,
	uint64_t policy_epoch,
	uint64_t now_ms);
int pqcp_sovereign_recovery_quorum_tick(
	struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_recovery_quorum_audit(
	struct pqcp_sovereign_recovery_quorum *quorum);

int pqcp_sovereign_cost_governor_init(
	struct pqcp_sovereign_cost_governor *governor,
	struct pqcp_sovereign_cost_budget *budgets,
	size_t capacity);
int pqcp_sovereign_cost_budget_put(
	struct pqcp_sovereign_cost_governor *governor,
	const struct pqcp_sovereign_cost_budget *budget,
	uint64_t now_ms);
int pqcp_sovereign_cost_reserve(
	struct pqcp_sovereign_cost_governor *governor,
	const char *tenant_id,
	const char *namespace_id,
	uint64_t compute_units,
	uint64_t storage_byte_ms,
	uint64_t network_bytes,
	uint64_t carbon_milligrams,
	uint64_t now_ms,
	bool *warning);
int pqcp_sovereign_cost_tick(
	struct pqcp_sovereign_cost_governor *governor,
	uint64_t now_ms,
	uint32_t *reset_count);
int pqcp_sovereign_cost_governor_audit(
	struct pqcp_sovereign_cost_governor *governor);

int pqcp_sovereign_supply_chain_evaluate(
	struct pqcp_sovereign_runtime *runtime,
	const struct pqcp_sovereign_supply_chain_context *context,
	struct pqcp_sovereign_supply_chain_result *result);
int pqcp_sovereign_runtime_init(
	struct pqcp_sovereign_runtime *runtime,
	const struct pqcp_sovereign_runtime_storage *storage,
	uint64_t policy_epoch,
	uint64_t revocation_epoch);
int pqcp_sovereign_runtime_advance_policy(
	struct pqcp_sovereign_runtime *runtime,
	uint64_t policy_epoch,
	uint64_t revocation_epoch);
int pqcp_sovereign_runtime_tick(
	struct pqcp_sovereign_runtime *runtime,
	uint64_t now_ms);
int pqcp_sovereign_runtime_audit(
	struct pqcp_sovereign_runtime *runtime);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_SOVEREIGN_RUNTIME_H_ */
