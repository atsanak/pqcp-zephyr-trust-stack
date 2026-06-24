/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free composition root for sovereign edge operations.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_artifact_internal.h"

static bool storage_pair_valid(
	const void *memory,
	size_t capacity,
	size_t element_size)
{
	return memory != NULL &&
	       capacity != 0U &&
	       capacity <= (size_t)INT_MAX &&
	       element_size != 0U &&
	       capacity <= SIZE_MAX / element_size;
}

#define STORAGE_PAIR_VALID(storage, member, capacity_member) \
	storage_pair_valid( \
		(storage)->member, \
		(storage)->capacity_member, \
		sizeof(*(storage)->member))

static bool runtime_storage_valid(
	const struct pqcp_sovereign_runtime_storage *storage)
{
	if (storage == NULL) {
		return false;
	}
	if (!STORAGE_PAIR_VALID(
		    storage, tenants, tenant_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, namespaces, namespace_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, artifacts, artifact_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, sbom_documents,
		    sbom_document_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, sbom_components,
		    sbom_component_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, transparency_entries,
		    transparency_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, build_attestations,
		    build_attestation_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, release_rules,
		    release_rule_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, rings, ring_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, rollouts, rollout_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, rollback_plans,
		    rollback_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, approval_requests,
		    approval_request_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, approval_votes,
		    approval_vote_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, key_ceremonies,
		    key_ceremony_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, key_contributions,
		    key_contribution_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, custody_events,
		    custody_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, secret_grants,
		    secret_grant_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, privacy_budgets,
		    privacy_budget_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, residency_rules,
		    residency_rule_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, consents, consent_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, purpose_bindings,
		    purpose_binding_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, retention_rules,
		    retention_rule_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, retention_records,
		    retention_record_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, data_contracts,
		    data_contract_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, egress_rules,
		    egress_rule_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, egress_usage,
		    egress_usage_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, network_intents,
		    network_intent_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, placement_nodes,
		    placement_node_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, placement_reservations,
		    placement_reservation_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, dependency_edges,
		    dependency_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, risk_nodes,
		    risk_node_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, risk_edges,
		    risk_edge_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, threat_indicators,
		    threat_indicator_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, forensic_events,
		    forensic_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, control_mappings,
		    control_mapping_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, exceptions,
		    exception_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, evidence_packages,
		    evidence_package_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, evidence_references,
		    evidence_reference_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, export_cursors,
		    export_cursor_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, continuity_exercises,
		    continuity_exercise_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, recovery_requests,
		    recovery_request_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, recovery_votes,
		    recovery_vote_capacity) ||
	    !STORAGE_PAIR_VALID(
		    storage, cost_budgets,
		    cost_budget_capacity)) {
		return false;
	}
	return true;
}

#undef STORAGE_PAIR_VALID

static void remember_error(
	int result,
	int *first_error)
{
	if (result != 0 && *first_error == 0) {
		*first_error = result;
	}
}

static void supply_chain_result_default(
	struct pqcp_sovereign_supply_chain_result *result)
{
	memset(result, 0, sizeof(*result));
	result->decision = PQCP_SOVEREIGN_DECISION_DENY;
	result->release_policy_result = -EACCES;
	result->approval_result = -EACCES;
	result->transparency_result = -EACCES;
	result->attestation_result = -EACCES;
	(void)pqcp_sovereign_internal_copy_text(
		result->explanation,
		sizeof(result->explanation),
		"supply-chain evaluation denied by default");
}

static void supply_chain_explain(
	struct pqcp_sovereign_supply_chain_result *result,
	const char *explanation)
{
	if (result == NULL || explanation == NULL) {
		return;
	}
	(void)pqcp_sovereign_internal_copy_text(
		result->explanation,
		sizeof(result->explanation),
		explanation);
}

static bool supply_chain_context_shape_valid(
	const struct pqcp_sovereign_supply_chain_context *context)
{
	if (context == NULL ||
	    context->artifact == NULL ||
	    context->sbom == NULL ||
	    context->attestation == NULL ||
	    !pqcp_sovereign_internal_text_valid(
		    context->tenant_id,
		    sizeof(context->tenant_id)) ||
	    !pqcp_sovereign_internal_text_valid(
		    context->target_zone,
		    sizeof(context->target_zone)) ||
	    context->policy_epoch == 0U ||
	    context->revocation_epoch == 0U ||
	    context->now_ms == 0U ||
	    context->approval_count >
		    PQCP_SOVEREIGN_MAX_APPROVERS ||
	    context->distinct_roles >
		    context->approval_count) {
		return false;
	}
	if (!context->artifact->occupied ||
	    context->artifact->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    !context->sbom->occupied ||
	    context->sbom->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    !context->attestation->occupied ||
	    context->attestation->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION) {
		return false;
	}
	return true;
}

static int supply_chain_registered_objects(
	struct pqcp_sovereign_runtime *runtime,
	const struct pqcp_sovereign_supply_chain_context *context)
{
	struct pqcp_sovereign_artifact *artifact = NULL;
	struct pqcp_sovereign_sbom_document *sbom = NULL;
	struct pqcp_sovereign_build_attestation *attestation = NULL;
	int ret;

	ret = pqcp_sovereign_artifact_find(
		&runtime->artifacts,
		context->artifact->artifact_id,
		&artifact);
	if (ret != 0) {
		return ret;
	}
	if (artifact != context->artifact) {
		return -EACCES;
	}
	ret = pqcp_sovereign_sbom_find(
		&runtime->sbom,
		context->artifact->artifact_id,
		&sbom);
	if (ret != 0) {
		return ret;
	}
	if (sbom != context->sbom) {
		return -EACCES;
	}
	ret = pqcp_sovereign_build_attestation_find(
		&runtime->attestations,
		context->artifact->artifact_id,
		context->now_ms,
		&attestation);
	if (ret != 0) {
		return ret;
	}
	if (attestation != context->attestation) {
		return -EACCES;
	}
	return 0;
}

static int supply_chain_identity_check(
	const struct pqcp_sovereign_supply_chain_context *context)
{
	if (strcmp(
		    context->tenant_id,
		    context->artifact->tenant_id) != 0 ||
	    strcmp(
		    context->artifact->artifact_id,
		    context->sbom->artifact_id) != 0 ||
	    strcmp(
		    context->artifact->artifact_id,
		    context->attestation->artifact_id) != 0) {
		return -EACCES;
	}
	if (context->artifact->state !=
		    PQCP_SOVEREIGN_ARTIFACT_APPROVED &&
	    context->artifact->state !=
		    PQCP_SOVEREIGN_ARTIFACT_RELEASED) {
		return -EACCES;
	}
	if (!context->sbom->complete ||
	    !context->attestation->verified) {
		return -EACCES;
	}
	return 0;
}

static int supply_chain_epoch_check(
	const struct pqcp_sovereign_runtime *runtime,
	const struct pqcp_sovereign_supply_chain_context *context)
{
	if (context->policy_epoch !=
		    runtime->policy_epoch ||
	    context->revocation_epoch !=
		    runtime->revocation_epoch) {
		return -ESTALE;
	}
	if (context->artifact->policy_epoch >
		    context->policy_epoch ||
	    context->sbom->policy_epoch >
		    context->policy_epoch ||
	    context->attestation->policy_epoch >
		    context->policy_epoch) {
		return -ESTALE;
	}
	return 0;
}

static int supply_chain_approval_check(
	struct pqcp_sovereign_runtime *runtime,
	const struct pqcp_sovereign_supply_chain_context *context,
	const uint8_t artifact_digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	bool matched = false;
	int ret;

	if (context->approval_count == 0U &&
	    context->distinct_roles == 0U) {
		return 0;
	}
	ret = k_mutex_lock(
		&runtime->approvals.lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < runtime->approvals.request_capacity;
	     ++index) {
		const struct pqcp_sovereign_approval_request *request =
			&runtime->approvals.requests[index];

		if (!request->occupied ||
		    request->state !=
			    PQCP_SOVEREIGN_APPROVAL_SATISFIED ||
		    request->policy_epoch !=
			    context->policy_epoch ||
		    request->expires_at_ms <=
			    context->now_ms ||
		    request->approval_count !=
			    context->approval_count ||
		    request->distinct_role_count !=
			    context->distinct_roles ||
		    strcmp(
			    request->subject_id,
			    context->artifact->artifact_id) != 0 ||
		    !pqcp_sovereign_internal_equal(
			    request->subject_digest,
			    artifact_digest,
			    PQCP_SOVEREIGN_DIGEST_BYTES)) {
			continue;
		}
		matched = true;
		break;
	}
	(void)k_mutex_unlock(&runtime->approvals.lock);
	return matched ? 0 : -EACCES;
}

static int supply_chain_transparency_check(
	struct pqcp_sovereign_runtime *runtime,
	const struct pqcp_sovereign_supply_chain_context *context,
	const uint8_t artifact_digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	struct pqcp_sovereign_transparency_entry entry;
	int ret;

	if (!context->transparency_verified) {
		return -EACCES;
	}
	ret = pqcp_sovereign_transparency_verify(
		&runtime->transparency);
	if (ret != 0) {
		return ret;
	}
	memset(&entry, 0, sizeof(entry));
	ret = pqcp_sovereign_transparency_subject_latest(
		&runtime->transparency,
		context->artifact->artifact_id,
		&entry);
	if (ret != 0) {
		return ret;
	}
	if (entry.policy_epoch >
		    context->policy_epoch ||
	    !pqcp_sovereign_internal_equal(
		    entry.subject_digest,
		    artifact_digest,
		    PQCP_SOVEREIGN_DIGEST_BYTES)) {
		return -EACCES;
	}
	return 0;
}

static int supply_chain_sbom_check(
	struct pqcp_sovereign_runtime *runtime,
	const struct pqcp_sovereign_supply_chain_context *context,
	uint32_t *component_risk)
{
	struct pqcp_sovereign_sbom_document *document = NULL;
	uint32_t revoked_count = 0U;
	int ret;

	ret = pqcp_sovereign_sbom_validate_artifact_binding(
		&runtime->sbom,
		context->artifact,
		&document);
	if (ret != 0) {
		return ret;
	}
	if (document != context->sbom) {
		return -EACCES;
	}
	ret = pqcp_sovereign_sbom_component_risk(
		&runtime->sbom,
		context->artifact->artifact_id,
		PQCP_SOVEREIGN_SBOM_FLAG_REVOKED,
		component_risk,
		&revoked_count);
	if (ret != 0) {
		return ret;
	}
	return revoked_count == 0U ? 0 : -EACCES;
}

int pqcp_sovereign_supply_chain_evaluate(
	struct pqcp_sovereign_runtime *runtime,
	const struct pqcp_sovereign_supply_chain_context *context,
	struct pqcp_sovereign_supply_chain_result *result)
{
	struct pqcp_sovereign_release_context release_context;
	struct pqcp_sovereign_release_decision release_decision;
	uint8_t artifact_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint32_t component_risk = 0U;
	int ret;

	if (result == NULL) {
		return -EINVAL;
	}
	supply_chain_result_default(result);
	if (runtime == NULL || !runtime->initialized ||
	    runtime->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    !supply_chain_context_shape_valid(context)) {
		result->failure_mask =
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_SCHEMA |
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_IDENTITY;
		supply_chain_explain(
			result,
			"invalid supply-chain evaluation context");
		return -EINVAL;
	}
	result->artifact_risk =
		context->artifact->risk_score;
	memset(artifact_digest, 0, sizeof(artifact_digest));
	ret = pqcp_sovereign_artifact_canonical_digest(
		context->artifact, artifact_digest);
	if (ret != 0) {
		result->failure_mask |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_DIGEST;
		supply_chain_explain(
			result,
			"artifact canonical identity is invalid");
		pqcp_runtime_secure_zero(
			artifact_digest,
			sizeof(artifact_digest));
		return ret;
	}
	ret = supply_chain_registered_objects(
		runtime, context);
	if (ret != 0) {
		result->failure_mask |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_IDENTITY;
		supply_chain_explain(
			result,
			"supply-chain objects are not registered");
		goto denied;
	}
	ret = supply_chain_identity_check(context);
	if (ret != 0) {
		result->failure_mask |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_IDENTITY |
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_STATE;
		supply_chain_explain(
			result,
			"artifact evidence identity or state is invalid");
		goto denied;
	}
	ret = supply_chain_epoch_check(runtime, context);
	if (ret != 0) {
		result->failure_mask |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_POLICY_EPOCH |
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_REVOCATION_EPOCH;
		supply_chain_explain(
			result,
			"supply-chain policy epochs are stale");
		goto denied;
	}
	ret = pqcp_sovereign_tenant_authorize(
		&runtime->tenants,
		context->tenant_id,
		PQCP_SOVEREIGN_OPERATION_DEPLOY,
		PQCP_SOVEREIGN_BIT(
			PQCP_SOVEREIGN_CAPABILITY_DEPLOY),
		context->policy_epoch,
		context->revocation_epoch,
		context->now_ms);
	if (ret != 0) {
		result->failure_mask |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_IDENTITY;
		supply_chain_explain(
			result,
			"tenant is not authorized to deploy artifact");
		goto denied;
	}
	ret = supply_chain_sbom_check(
		runtime, context, &component_risk);
	result->component_risk = component_risk;
	if (ret != 0) {
		result->failure_mask |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_DEPENDENCY;
		if (ret == -EBADMSG) {
			result->failure_mask |=
				PQCP_SOVEREIGN_ARTIFACT_FAILURE_DIGEST;
		}
		supply_chain_explain(
			result,
			"SBOM binding or component trust failed");
		goto denied;
	}
	ret = pqcp_sovereign_build_attestation_verify(
		&runtime->attestations,
		context->attestation->attestation_id,
		context->artifact->content_digest,
		context->policy_epoch,
		context->now_ms);
	result->attestation_result = ret;
	if (ret != 0) {
		result->failure_mask |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_ATTESTATION;
		supply_chain_explain(
			result,
			"build attestation verification failed");
		goto denied;
	}
	ret = supply_chain_transparency_check(
		runtime, context, artifact_digest);
	result->transparency_result = ret;
	if (ret != 0) {
		result->failure_mask |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_TRANSPARENCY;
		supply_chain_explain(
			result,
			"transparency chain binding failed");
		goto denied;
	}
	ret = supply_chain_approval_check(
		runtime, context, artifact_digest);
	result->approval_result = ret;
	if (ret != 0) {
		result->failure_mask |=
			PQCP_SOVEREIGN_ARTIFACT_FAILURE_QUORUM;
		supply_chain_explain(
			result,
			"approval quorum evidence did not match");
		goto denied;
	}
	memset(&release_context, 0, sizeof(release_context));
	release_context.artifact = context->artifact;
	release_context.sbom = context->sbom;
	release_context.attestation = context->attestation;
	memcpy(
		release_context.target_zone,
		context->target_zone,
		sizeof(release_context.target_zone));
	release_context.policy_epoch =
		context->policy_epoch;
	release_context.approval_count =
		context->approval_count;
	release_context.distinct_roles =
		context->distinct_roles;
	release_context.transparency_verified = true;
	memset(&release_decision, 0, sizeof(release_decision));
	ret = pqcp_sovereign_release_evaluate(
		&runtime->releases,
		&release_context,
		&release_decision);
	result->release_policy_result = ret;
	result->failure_mask |=
		release_decision.failure_mask;
	if (ret != 0 ||
	    release_decision.effect !=
		    PQCP_SOVEREIGN_DECISION_ALLOW ||
	    result->failure_mask != 0U) {
		result->decision =
			release_decision.effect ==
				PQCP_SOVEREIGN_DECISION_UNSET ?
			PQCP_SOVEREIGN_DECISION_DENY :
			release_decision.effect;
		if (release_decision.explanation[0] != '\0') {
			supply_chain_explain(
				result,
				release_decision.explanation);
		}
		goto denied;
	}
	result->decision = PQCP_SOVEREIGN_DECISION_ALLOW;
	supply_chain_explain(
		result,
		release_decision.explanation);
	pqcp_runtime_secure_zero(
		artifact_digest, sizeof(artifact_digest));
	return 0;

denied:
	if (result->decision ==
	    PQCP_SOVEREIGN_DECISION_UNSET) {
		result->decision =
			PQCP_SOVEREIGN_DECISION_DENY;
	}
	pqcp_runtime_secure_zero(
		artifact_digest, sizeof(artifact_digest));
	return -EACCES;
}

int pqcp_sovereign_runtime_init(
	struct pqcp_sovereign_runtime *runtime,
	const struct pqcp_sovereign_runtime_storage *storage,
	uint64_t policy_epoch,
	uint64_t revocation_epoch)
{
	int ret;

	if (runtime == NULL ||
	    !runtime_storage_valid(storage) ||
	    policy_epoch == 0U ||
	    revocation_epoch == 0U) {
		return -EINVAL;
	}
	memset(runtime, 0, sizeof(*runtime));
	runtime->schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;

	ret = pqcp_sovereign_tenant_registry_init(
		&runtime->tenants,
		storage->tenants,
		storage->tenant_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_namespace_manager_init(
		&runtime->namespaces,
		storage->namespaces,
		storage->namespace_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_artifact_catalog_init(
		&runtime->artifacts,
		storage->artifacts,
		storage->artifact_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_sbom_registry_init(
		&runtime->sbom,
		storage->sbom_documents,
		storage->sbom_document_capacity,
		storage->sbom_components,
		storage->sbom_component_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_transparency_log_init(
		&runtime->transparency,
		storage->transparency_entries,
		storage->transparency_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_build_attestation_store_init(
		&runtime->attestations,
		storage->build_attestations,
		storage->build_attestation_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_release_policy_init(
		&runtime->releases,
		storage->release_rules,
		storage->release_rule_capacity,
		PQCP_SOVEREIGN_DECISION_DENY);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_ring_registry_init(
		&runtime->rings,
		storage->rings,
		storage->ring_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_rollout_controller_init(
		&runtime->rollouts,
		storage->rollouts,
		storage->rollout_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_rollback_coordinator_init(
		&runtime->rollbacks,
		storage->rollback_plans,
		storage->rollback_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_approval_quorum_init(
		&runtime->approvals,
		storage->approval_requests,
		storage->approval_request_capacity,
		storage->approval_votes,
		storage->approval_vote_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_key_ceremony_manager_init(
		&runtime->ceremonies,
		storage->key_ceremonies,
		storage->key_ceremony_capacity,
		storage->key_contributions,
		storage->key_contribution_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_custody_ledger_init(
		&runtime->custody,
		storage->custody_events,
		storage->custody_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_secret_distributor_init(
		&runtime->secrets,
		storage->secret_grants,
		storage->secret_grant_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_privacy_budget_manager_init(
		&runtime->privacy,
		storage->privacy_budgets,
		storage->privacy_budget_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_residency_engine_init(
		&runtime->residency,
		storage->residency_rules,
		storage->residency_rule_capacity,
		PQCP_SOVEREIGN_DECISION_DENY);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_consent_ledger_init(
		&runtime->consent,
		storage->consents,
		storage->consent_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_purpose_engine_init(
		&runtime->purposes,
		storage->purpose_bindings,
		storage->purpose_binding_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_retention_manager_init(
		&runtime->retention,
		storage->retention_rules,
		storage->retention_rule_capacity,
		storage->retention_records,
		storage->retention_record_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_data_contract_manager_init(
		&runtime->contracts,
		storage->data_contracts,
		storage->data_contract_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_egress_engine_init(
		&runtime->egress,
		storage->egress_rules,
		storage->egress_rule_capacity,
		storage->egress_usage,
		storage->egress_usage_capacity,
		PQCP_SOVEREIGN_DECISION_DENY);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_network_intent_manager_init(
		&runtime->network,
		storage->network_intents,
		storage->network_intent_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_placement_engine_init(
		&runtime->placement,
		storage->placement_nodes,
		storage->placement_node_capacity,
		storage->placement_reservations,
		storage->placement_reservation_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_dependency_graph_init(
		&runtime->dependencies,
		storage->dependency_edges,
		storage->dependency_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_risk_graph_init(
		&runtime->risk,
		storage->risk_nodes,
		storage->risk_node_capacity,
		storage->risk_edges,
		storage->risk_edge_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_threat_intelligence_init(
		&runtime->threats,
		storage->threat_indicators,
		storage->threat_indicator_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_forensic_timeline_init(
		&runtime->forensics,
		storage->forensic_events,
		storage->forensic_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_control_catalog_init(
		&runtime->controls,
		storage->control_mappings,
		storage->control_mapping_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_exception_manager_init(
		&runtime->exceptions,
		storage->exceptions,
		storage->exception_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_evidence_packager_init(
		&runtime->evidence,
		storage->evidence_packages,
		storage->evidence_package_capacity,
		storage->evidence_references,
		storage->evidence_reference_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_regulator_exporter_init(
		&runtime->exporter,
		storage->export_cursors,
		storage->export_cursor_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_continuity_exerciser_init(
		&runtime->continuity,
		storage->continuity_exercises,
		storage->continuity_exercise_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_recovery_quorum_init(
		&runtime->recovery,
		storage->recovery_requests,
		storage->recovery_request_capacity,
		storage->recovery_votes,
		storage->recovery_vote_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_cost_governor_init(
		&runtime->cost,
		storage->cost_budgets,
		storage->cost_budget_capacity);
	if (ret != 0) {
		return ret;
	}
	runtime->policy_epoch = policy_epoch;
	runtime->revocation_epoch = revocation_epoch;
	runtime->tick_count = 0U;
	runtime->initialized = true;
	return 0;
}

int pqcp_sovereign_runtime_advance_policy(
	struct pqcp_sovereign_runtime *runtime,
	uint64_t policy_epoch,
	uint64_t revocation_epoch)
{
	if (runtime == NULL || !runtime->initialized ||
	    runtime->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    policy_epoch == 0U ||
	    revocation_epoch == 0U) {
		return -EINVAL;
	}
	if (policy_epoch < runtime->policy_epoch ||
	    revocation_epoch < runtime->revocation_epoch ||
	    (policy_epoch == runtime->policy_epoch &&
	     revocation_epoch == runtime->revocation_epoch)) {
		return -ESTALE;
	}
	runtime->policy_epoch = policy_epoch;
	runtime->revocation_epoch = revocation_epoch;
	return 0;
}

int pqcp_sovereign_runtime_tick(
	struct pqcp_sovereign_runtime *runtime,
	uint64_t now_ms)
{
	uint32_t changed = 0U;
	int first_error = 0;

	if (runtime == NULL || !runtime->initialized ||
	    runtime->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    runtime->policy_epoch == 0U ||
	    runtime->revocation_epoch == 0U ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	if (runtime->tick_count == UINT64_MAX) {
		return -EOVERFLOW;
	}
	remember_error(
		pqcp_sovereign_tenant_tick(
			&runtime->tenants,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_build_attestation_expire(
			&runtime->attestations,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_rollout_tick(
			&runtime->rollouts,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_rollback_tick(
			&runtime->rollbacks,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_approval_tick(
			&runtime->approvals,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_key_ceremony_tick(
			&runtime->ceremonies,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_secret_grant_tick(
			&runtime->secrets,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_privacy_budget_tick(
			&runtime->privacy,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_consent_tick(
			&runtime->consent,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_data_contract_tick(
			&runtime->contracts,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_egress_tick(
			&runtime->egress,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_network_intent_tick(
			&runtime->network,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_placement_tick(
			&runtime->placement,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_risk_expire(
			&runtime->risk,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_threat_tick(
			&runtime->threats,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_exception_tick(
			&runtime->exceptions,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_regulator_export_tick(
			&runtime->exporter,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_recovery_tick(
			&runtime->recovery,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_sovereign_cost_tick(
			&runtime->cost,
			now_ms, &changed),
		&first_error);
	runtime->tick_count++;
	return first_error;
}

int pqcp_sovereign_runtime_audit(
	struct pqcp_sovereign_runtime *runtime)
{
	int first_error = 0;

	if (runtime == NULL || !runtime->initialized ||
	    runtime->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    runtime->policy_epoch == 0U ||
	    runtime->revocation_epoch == 0U) {
		return -EINVAL;
	}
	if (runtime->releases.default_effect !=
		    PQCP_SOVEREIGN_DECISION_DENY ||
	    runtime->residency.default_effect !=
		    PQCP_SOVEREIGN_DECISION_DENY ||
	    runtime->egress.default_effect !=
		    PQCP_SOVEREIGN_DECISION_DENY) {
		return -EBADMSG;
	}
	remember_error(
		pqcp_sovereign_tenant_registry_audit(
			&runtime->tenants),
		&first_error);
	remember_error(
		pqcp_sovereign_namespace_manager_audit(
			&runtime->namespaces),
		&first_error);
	remember_error(
		pqcp_sovereign_artifact_catalog_audit(
			&runtime->artifacts),
		&first_error);
	remember_error(
		pqcp_sovereign_sbom_registry_audit(
			&runtime->sbom),
		&first_error);
	remember_error(
		pqcp_sovereign_transparency_verify(
			&runtime->transparency),
		&first_error);
	remember_error(
		pqcp_sovereign_build_attestation_store_audit(
			&runtime->attestations),
		&first_error);
	remember_error(
		pqcp_sovereign_release_policy_audit(
			&runtime->releases),
		&first_error);
	remember_error(
		pqcp_sovereign_ring_registry_audit(
			&runtime->rings),
		&first_error);
	remember_error(
		pqcp_sovereign_rollout_controller_audit(
			&runtime->rollouts),
		&first_error);
	remember_error(
		pqcp_sovereign_rollback_coordinator_audit(
			&runtime->rollbacks),
		&first_error);
	remember_error(
		pqcp_sovereign_approval_quorum_audit(
			&runtime->approvals),
		&first_error);
	remember_error(
		pqcp_sovereign_key_ceremony_manager_audit(
			&runtime->ceremonies),
		&first_error);
	remember_error(
		pqcp_sovereign_custody_verify(
			&runtime->custody),
		&first_error);
	remember_error(
		pqcp_sovereign_secret_distributor_audit(
			&runtime->secrets),
		&first_error);
	remember_error(
		pqcp_sovereign_privacy_budget_manager_audit(
			&runtime->privacy),
		&first_error);
	remember_error(
		pqcp_sovereign_residency_engine_audit(
			&runtime->residency),
		&first_error);
	remember_error(
		pqcp_sovereign_consent_ledger_audit(
			&runtime->consent),
		&first_error);
	remember_error(
		pqcp_sovereign_purpose_engine_audit(
			&runtime->purposes),
		&first_error);
	remember_error(
		pqcp_sovereign_retention_manager_audit(
			&runtime->retention),
		&first_error);
	remember_error(
		pqcp_sovereign_data_contract_manager_audit(
			&runtime->contracts),
		&first_error);
	remember_error(
		pqcp_sovereign_egress_engine_audit(
			&runtime->egress),
		&first_error);
	remember_error(
		pqcp_sovereign_network_intent_manager_audit(
			&runtime->network),
		&first_error);
	remember_error(
		pqcp_sovereign_placement_engine_audit(
			&runtime->placement),
		&first_error);
	remember_error(
		pqcp_sovereign_dependency_graph_audit(
			&runtime->dependencies),
		&first_error);
	remember_error(
		pqcp_sovereign_risk_graph_audit(
			&runtime->risk),
		&first_error);
	remember_error(
		pqcp_sovereign_threat_intelligence_audit(
			&runtime->threats),
		&first_error);
	remember_error(
		pqcp_sovereign_forensic_verify(
			&runtime->forensics),
		&first_error);
	remember_error(
		pqcp_sovereign_control_catalog_audit(
			&runtime->controls),
		&first_error);
	remember_error(
		pqcp_sovereign_exception_manager_audit(
			&runtime->exceptions),
		&first_error);
	remember_error(
		pqcp_sovereign_evidence_packager_audit(
			&runtime->evidence),
		&first_error);
	remember_error(
		pqcp_sovereign_regulator_exporter_audit(
			&runtime->exporter),
		&first_error);
	remember_error(
		pqcp_sovereign_continuity_exerciser_audit(
			&runtime->continuity),
		&first_error);
	remember_error(
		pqcp_sovereign_recovery_quorum_audit(
			&runtime->recovery),
		&first_error);
	remember_error(
		pqcp_sovereign_cost_governor_audit(
			&runtime->cost),
		&first_error);
	return first_error;
}
