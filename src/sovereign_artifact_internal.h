/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Internal contracts for sovereign artifact trust and deployment admission.
 */

#ifndef PQCP_SOVEREIGN_ARTIFACT_INTERNAL_H_
#define PQCP_SOVEREIGN_ARTIFACT_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/fleet_operations.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/runtime_key_store.h>
#include <pqcp_zephyr/sovereign_runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_SOVEREIGN_ARTIFACT_CANONICAL_BYTES 512U
#define PQCP_SOVEREIGN_SBOM_CANONICAL_BYTES 512U
#define PQCP_SOVEREIGN_ATTESTATION_CANONICAL_BYTES 640U
#define PQCP_SOVEREIGN_RELEASE_CANONICAL_BYTES 512U
#define PQCP_SOVEREIGN_DEPLOYMENT_CANONICAL_BYTES 1024U
#define PQCP_SOVEREIGN_TRANSPARENCY_CANONICAL_BYTES 384U
#define PQCP_SOVEREIGN_MAX_TRUSTED_BUILDERS 16U
#define PQCP_SOVEREIGN_MAX_REVOKED_BUILDERS 16U
#define PQCP_SOVEREIGN_MAX_REVOKED_COMPONENTS 32U
#define PQCP_SOVEREIGN_MAX_ALLOWED_LICENSES 16U
#define PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES 64U
#define PQCP_SOVEREIGN_MAX_AUTHORIZATIONS 16U
#define PQCP_SOVEREIGN_MAX_DEPLOYMENT_NONCES 16U
#define PQCP_SOVEREIGN_ATTESTATION_CONTEXT_MAX 64U

#define PQCP_SOVEREIGN_SBOM_FLAG_DIRECT (1U << 0)
#define PQCP_SOVEREIGN_SBOM_FLAG_RUNTIME (1U << 1)
#define PQCP_SOVEREIGN_SBOM_FLAG_BUILD_ONLY (1U << 2)
#define PQCP_SOVEREIGN_SBOM_FLAG_OPTIONAL (1U << 3)
#define PQCP_SOVEREIGN_SBOM_FLAG_REVOKED (1U << 4)
#define PQCP_SOVEREIGN_SBOM_FLAG_UNMAINTAINED (1U << 5)
#define PQCP_SOVEREIGN_SBOM_FLAG_UNKNOWN_LICENSE (1U << 6)
#define PQCP_SOVEREIGN_SBOM_FLAG_CRITICAL (1U << 7)
#define PQCP_SOVEREIGN_SBOM_KNOWN_FLAGS \
	(PQCP_SOVEREIGN_SBOM_FLAG_DIRECT | \
	 PQCP_SOVEREIGN_SBOM_FLAG_RUNTIME | \
	 PQCP_SOVEREIGN_SBOM_FLAG_BUILD_ONLY | \
	 PQCP_SOVEREIGN_SBOM_FLAG_OPTIONAL | \
	 PQCP_SOVEREIGN_SBOM_FLAG_REVOKED | \
	 PQCP_SOVEREIGN_SBOM_FLAG_UNMAINTAINED | \
	 PQCP_SOVEREIGN_SBOM_FLAG_UNKNOWN_LICENSE | \
	 PQCP_SOVEREIGN_SBOM_FLAG_CRITICAL)

enum pqcp_sovereign_artifact_failure {
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_NONE = 0U,
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_SCHEMA = (1U << 0),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_IDENTITY = (1U << 1),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_DIGEST = (1U << 2),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_STATE = (1U << 3),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_POLICY_EPOCH = (1U << 4),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_REVOCATION_EPOCH = (1U << 5),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_BUILDER = (1U << 6),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_DEPENDENCY = (1U << 7),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_LICENSE = (1U << 8),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_RISK = (1U << 9),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_ATTESTATION = (1U << 10),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_TRANSPARENCY = (1U << 11),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_QUORUM = (1U << 12),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_TARGET = (1U << 13),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_ROLLBACK = (1U << 14),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_TIME = (1U << 15),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_REPLAY = (1U << 16),
	PQCP_SOVEREIGN_ARTIFACT_FAILURE_FLEET = (1U << 17),
};

enum pqcp_sovereign_deployment_state {
	PQCP_SOVEREIGN_DEPLOYMENT_EMPTY = 0,
	PQCP_SOVEREIGN_DEPLOYMENT_AUTHORIZED,
	PQCP_SOVEREIGN_DEPLOYMENT_CONSUMED,
	PQCP_SOVEREIGN_DEPLOYMENT_EXPIRED,
	PQCP_SOVEREIGN_DEPLOYMENT_REVOKED,
};

struct pqcp_sovereign_digest_set {
	uint8_t values[PQCP_SOVEREIGN_MAX_REVOKED_COMPONENTS]
		      [PQCP_SOVEREIGN_DIGEST_BYTES];
	size_t count;
};

struct pqcp_sovereign_text_set {
	char values[PQCP_SOVEREIGN_MAX_ALLOWED_LICENSES]
		   [PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	size_t count;
};

struct pqcp_sovereign_builder_policy {
	uint32_t schema_version;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char target_profile[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char trusted_builders[PQCP_SOVEREIGN_MAX_TRUSTED_BUILDERS]
			     [PQCP_SOVEREIGN_ID_MAX_CHARS];
	size_t trusted_builder_count;
	char revoked_builders[PQCP_SOVEREIGN_MAX_REVOKED_BUILDERS]
			     [PQCP_SOVEREIGN_ID_MAX_CHARS];
	size_t revoked_builder_count;
	struct pqcp_sovereign_digest_set revoked_components;
	struct pqcp_sovereign_text_set allowed_licenses;
	uint64_t required_predicate_mask;
	uint32_t maximum_attestation_risk;
	uint32_t maximum_component_risk;
	uint32_t forbidden_component_flags;
	bool require_reproducible;
	bool require_known_license;
	bool initialized;
};

struct pqcp_sovereign_sbom_closure {
	uint64_t component_mask;
	uint64_t direct_mask;
	uint32_t component_count;
	uint32_t maximum_depth;
	uint32_t maximum_risk;
	uint32_t forbidden_count;
	uint32_t revoked_count;
	uint32_t license_failure_count;
	uint8_t closure_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
};

struct pqcp_sovereign_transparency_checkpoint {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t dropped_count;
	uint64_t policy_epoch;
	uint8_t chain_head[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
};

struct pqcp_sovereign_transparency_inclusion_witness {
	uint32_t schema_version;
	uint64_t subject_sequence;
	uint64_t checkpoint_sequence;
	size_t entry_count;
	struct pqcp_sovereign_transparency_entry
		entries[PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES];
	uint8_t subject_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
};

struct pqcp_sovereign_transparency_consistency_witness {
	uint32_t schema_version;
	uint64_t previous_sequence;
	uint64_t current_sequence;
	size_t entry_count;
	struct pqcp_sovereign_transparency_entry
		entries[PQCP_SOVEREIGN_MAX_TRANSPARENCY_PROOF_ENTRIES];
	uint8_t previous_head[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t current_head[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t witness_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
};

struct pqcp_sovereign_signed_attestation {
	uint32_t schema_version;
	struct pqcp_sovereign_build_attestation statement;
	struct pqcp_runtime_key_handle verification_key;
	size_t signature_length;
	uint8_t signature[PQCP_MLDSA_SIG_SIZE_MAX];
	size_t context_length;
	uint8_t context[PQCP_SOVEREIGN_ATTESTATION_CONTEXT_MAX];
};

struct pqcp_sovereign_deployment_request {
	uint32_t schema_version;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char artifact_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char target_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	char target_profile[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char target_cohort[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char component_id[PQCP_FLEET_ID_MAX_CHARS];
	uint64_t request_id;
	uint64_t approval_request_id;
	uint64_t transparency_sequence;
	uint64_t installed_release_sequence;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t requested_at_ms;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint64_t authorization_nonce;
	uint32_t minimum_approvals;
	uint32_t minimum_distinct_roles;
	uint8_t expected_content_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t expected_sbom_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t expected_provenance_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
};

struct pqcp_sovereign_deployment_authorization {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t authorization_id;
	uint64_t request_id;
	uint64_t approval_request_id;
	uint64_t artifact_release_sequence;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t authorized_at_ms;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint64_t authorization_nonce;
	char tenant_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char artifact_id[PQCP_SOVEREIGN_ID_MAX_CHARS];
	char target_zone[PQCP_SOVEREIGN_ZONE_MAX_CHARS];
	char target_profile[PQCP_SOVEREIGN_LABEL_MAX_CHARS];
	char target_cohort[PQCP_SOVEREIGN_ID_MAX_CHARS];
	uint8_t artifact_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t approval_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t transparency_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	enum pqcp_sovereign_deployment_state state;
	bool occupied;
};

struct pqcp_sovereign_deployment_authorizer {
	uint32_t schema_version;
	struct pqcp_sovereign_deployment_authorization *authorizations;
	size_t capacity;
	uint32_t next_generation;
	uint64_t next_authorization_id;
	uint64_t authorization_count;
	uint64_t replay_count;
	uint64_t rejection_count;
	uint64_t highest_release_sequence;
	uint64_t highest_policy_epoch;
	uint64_t highest_revocation_epoch;
	uint8_t previous_authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_deployment_evidence {
	const struct pqcp_sovereign_artifact *artifact;
	const struct pqcp_sovereign_sbom_document *sbom;
	const struct pqcp_sovereign_build_attestation *attestation;
	struct pqcp_sovereign_sbom_closure closure;
	struct pqcp_sovereign_release_decision release;
	struct pqcp_sovereign_transparency_inclusion_witness inclusion;
	uint8_t artifact_metadata_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t approval_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t aggregate_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint32_t failure_mask;
};

bool pqcp_sovereign_internal_all_zero(
	const uint8_t *value,
	size_t length);
bool pqcp_sovereign_internal_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length);
bool pqcp_sovereign_internal_text_valid(
	const char *value,
	size_t capacity);
int pqcp_sovereign_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source);
uint32_t pqcp_sovereign_internal_next_generation(
	uint32_t *generation);
uint64_t pqcp_sovereign_internal_next_identifier(
	uint64_t *identifier);
int pqcp_sovereign_internal_hash_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
bool pqcp_sovereign_internal_artifact_state_valid(
	enum pqcp_sovereign_artifact_state state);
bool pqcp_sovereign_internal_artifact_transition_valid(
	enum pqcp_sovereign_artifact_state current,
	enum pqcp_sovereign_artifact_state next);

int pqcp_sovereign_artifact_canonical_digest(
	const struct pqcp_sovereign_artifact *artifact,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_artifact_find_const(
	const struct pqcp_sovereign_artifact_catalog *catalog,
	const char *artifact_id,
	const struct pqcp_sovereign_artifact **artifact);
int pqcp_sovereign_artifact_find_by_content(
	const struct pqcp_sovereign_artifact_catalog *catalog,
	const uint8_t content_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const struct pqcp_sovereign_artifact **artifact);
int pqcp_sovereign_artifact_highest_release(
	const struct pqcp_sovereign_artifact_catalog *catalog,
	const char *tenant_id,
	const char *name,
	uint64_t *release_sequence);

int pqcp_sovereign_sbom_component_canonical_digest(
	const struct pqcp_sovereign_sbom_component *component,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_sbom_document_canonical_digest(
	const struct pqcp_sovereign_sbom_registry *registry,
	const struct pqcp_sovereign_sbom_document *document,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_sbom_dependency_closure(
	struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	const char *root_component_id,
	const struct pqcp_sovereign_builder_policy *trust,
	struct pqcp_sovereign_sbom_closure *closure);
int pqcp_sovereign_sbom_validate_artifact_binding(
	struct pqcp_sovereign_sbom_registry *registry,
	const struct pqcp_sovereign_artifact *artifact,
	struct pqcp_sovereign_sbom_document **document);

int pqcp_sovereign_transparency_entry_digest(
	const struct pqcp_sovereign_transparency_entry *entry,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_transparency_checkpoint(
	struct pqcp_sovereign_transparency_log *log,
	uint64_t policy_epoch,
	struct pqcp_sovereign_transparency_checkpoint *checkpoint);
int pqcp_sovereign_transparency_inclusion_prove(
	struct pqcp_sovereign_transparency_log *log,
	uint64_t subject_sequence,
	uint64_t checkpoint_sequence,
	struct pqcp_sovereign_transparency_inclusion_witness *witness);
int pqcp_sovereign_transparency_inclusion_verify(
	const struct pqcp_sovereign_transparency_inclusion_witness *witness,
	const struct pqcp_sovereign_transparency_checkpoint *checkpoint);
int pqcp_sovereign_transparency_consistency_prove(
	struct pqcp_sovereign_transparency_log *log,
	const struct pqcp_sovereign_transparency_checkpoint *previous,
	const struct pqcp_sovereign_transparency_checkpoint *current,
	struct pqcp_sovereign_transparency_consistency_witness *witness);
int pqcp_sovereign_transparency_consistency_verify(
	const struct pqcp_sovereign_transparency_consistency_witness *witness,
	const struct pqcp_sovereign_transparency_checkpoint *previous,
	const struct pqcp_sovereign_transparency_checkpoint *current);

int pqcp_sovereign_builder_policy_validate(
	const struct pqcp_sovereign_builder_policy *policy);
int pqcp_sovereign_build_attestation_canonical_digest(
	const struct pqcp_sovereign_build_attestation *attestation,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_build_attestation_verify_signed(
	struct pqcp_sovereign_build_attestation_store *store,
	struct pqcp_runtime_key_store *key_store,
	const struct pqcp_sovereign_signed_attestation *signed_attestation,
	const struct pqcp_sovereign_builder_policy *policy,
	uint64_t now_ms,
	struct pqcp_sovereign_build_attestation **stored);

int pqcp_sovereign_release_rule_canonical_digest(
	const struct pqcp_sovereign_release_rule *rule,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_release_policy_digest(
	struct pqcp_sovereign_release_policy *policy,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_release_evaluate_evidence(
	struct pqcp_sovereign_release_policy *policy,
	const struct pqcp_sovereign_release_context *context,
	const struct pqcp_sovereign_sbom_closure *closure,
	struct pqcp_sovereign_release_decision *decision);

int pqcp_sovereign_approval_evidence_digest(
	const struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id,
	uint64_t now_ms,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint32_t *approval_count,
	uint32_t *distinct_roles);
int pqcp_sovereign_deployment_authorizer_init(
	struct pqcp_sovereign_deployment_authorizer *authorizer,
	struct pqcp_sovereign_deployment_authorization *authorizations,
	size_t capacity);
int pqcp_sovereign_deployment_request_digest(
	const struct pqcp_sovereign_deployment_request *request,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_deployment_authorize(
	struct pqcp_sovereign_deployment_authorizer *authorizer,
	struct pqcp_sovereign_artifact_catalog *catalog,
	struct pqcp_sovereign_sbom_registry *sbom,
	struct pqcp_sovereign_build_attestation_store *attestations,
	struct pqcp_sovereign_transparency_log *transparency,
	struct pqcp_sovereign_release_policy *release_policy,
	const struct pqcp_sovereign_approval_quorum *quorum,
	const struct pqcp_sovereign_builder_policy *builder_policy,
	const struct pqcp_sovereign_deployment_request *request,
	uint64_t now_ms,
	struct pqcp_sovereign_deployment_authorization *authorization,
	struct pqcp_sovereign_deployment_evidence *evidence);
int pqcp_sovereign_deployment_authorize_fleet(
	struct pqcp_sovereign_deployment_authorizer *authorizer,
	struct pqcp_sovereign_artifact_catalog *catalog,
	struct pqcp_sovereign_sbom_registry *sbom,
	struct pqcp_sovereign_build_attestation_store *attestations,
	struct pqcp_sovereign_transparency_log *transparency,
	struct pqcp_sovereign_release_policy *release_policy,
	const struct pqcp_sovereign_approval_quorum *quorum,
	const struct pqcp_sovereign_builder_policy *builder_policy,
	const struct pqcp_sovereign_deployment_request *request,
	const struct pqcp_fleet_update_manifest *manifest,
	struct pqcp_fleet_update_manager *fleet,
	uint64_t now_ms,
	uint64_t probation_ms,
	uint64_t rollback_window_ms,
	uint32_t required_health_checks,
	struct pqcp_sovereign_deployment_authorization *authorization,
	struct pqcp_sovereign_deployment_evidence *evidence);
int pqcp_sovereign_deployment_authorization_consume(
	struct pqcp_sovereign_deployment_authorizer *authorizer,
	uint64_t authorization_id,
	const uint8_t authorization_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_deployment_authorizer_tick(
	struct pqcp_sovereign_deployment_authorizer *authorizer,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_deployment_authorizer_audit(
	struct pqcp_sovereign_deployment_authorizer *authorizer);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_SOVEREIGN_ARTIFACT_INTERNAL_H_ */
