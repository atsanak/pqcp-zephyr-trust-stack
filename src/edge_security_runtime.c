/*
 * SPDX-License-Identifier: MIT
 *
 * Composition root for the allocation-free edge security plane.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

#define POSTURE_BIT(signal) (1U << (uint32_t)(signal))

static bool storage_pair_valid(
	const void *storage,
	size_t capacity)
{
	return storage != NULL && capacity != 0U;
}

static bool runtime_storage_valid(
	const struct pqcp_edge_runtime_storage *storage)
{
	if (storage == NULL) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->principals,
		    storage->principal_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->services,
		    storage->service_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->endpoints,
		    storage->endpoint_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->access_rules,
		    storage->access_rule_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->routes,
		    storage->route_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->sessions,
		    storage->session_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->traffic_subjects,
		    storage->traffic_subject_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->circuits,
		    storage->circuit_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->messages,
		    storage->message_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->replay_entries,
		    storage->replay_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->reassemblies,
		    storage->reassembly_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->topics,
		    storage->topic_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->subscriptions,
		    storage->subscription_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->groups,
		    storage->group_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->deliveries,
		    storage->delivery_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->vault_objects,
		    storage->vault_object_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->vault_acl_entries,
		    storage->vault_acl_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->vault_versions,
		    storage->vault_version_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->vault_journal_entries,
		    storage->vault_journal_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->vault_leases,
		    storage->vault_lease_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->replicas,
		    storage->replica_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->snapshots,
		    storage->snapshot_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->signals,
		    storage->signal_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->incidents,
		    storage->incident_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->playbooks,
		    storage->playbook_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->evidence,
		    storage->evidence_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->containments,
		    storage->containment_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->continuity_services,
		    storage->continuity_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->posture_reports,
		    storage->posture_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->attestations,
		    storage->attestation_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->policy_bundles,
		    storage->policy_bundle_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->policy_acks,
		    storage->policy_ack_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->rotations,
		    storage->rotation_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->anomaly_baselines,
		    storage->anomaly_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->resource_budgets,
		    storage->resource_budget_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->export_cursors,
		    storage->export_cursor_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->recovery_plans,
		    storage->recovery_plan_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->dlp_rules,
		    storage->dlp_rule_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->trust_anchors,
		    storage->trust_anchor_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->federation_grants,
		    storage->federation_grant_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->credentials,
		    storage->credential_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->isolation_zones,
		    storage->isolation_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->provenance_records,
		    storage->provenance_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->workload_jobs,
		    storage->workload_job_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->sla_objectives,
		    storage->sla_capacity)) {
		return false;
	}
	if (!storage_pair_valid(
		    storage->config_transactions,
		    storage->config_transaction_capacity)) {
		return false;
	}
	return true;
}

static int policy_digest(
	uint64_t policy_epoch,
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES])
{
	static const uint8_t domain[] =
		"pqcp-edge-security-policy";
	uint8_t epoch[8];
	const uint8_t *parts[2];
	size_t lengths[2];

	pqcp_edge_internal_write_u64(epoch, policy_epoch);
	parts[0] = domain;
	lengths[0] = sizeof(domain) - 1U;
	parts[1] = epoch;
	lengths[1] = sizeof(epoch);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 2U, digest);
}

static struct pqcp_edge_traffic_policy
default_traffic_policy(void)
{
	struct pqcp_edge_traffic_policy policy = {
		.request_rate_per_window = 1000U,
		.byte_rate_per_window = 1024U * 1024U,
		.window_ms = 60000U,
		.maximum_concurrent = 32U,
		.burst_requests = 100U,
		.failure_penalty = 100U,
		.recovery_credit = 25U,
	};

	return policy;
}

static struct pqcp_edge_circuit_policy
default_circuit_policy(void)
{
	struct pqcp_edge_circuit_policy policy = {
		.open_after_failures = 5U,
		.close_after_successes = 3U,
		.half_open_maximum = 2U,
		.base_retry_ms = 1000U,
		.maximum_retry_ms = 60000U,
	};

	return policy;
}

static struct pqcp_edge_posture_policy
default_posture_policy(uint64_t policy_epoch)
{
	struct pqcp_edge_posture_policy policy = {
		.required_signal_mask =
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_SECURE_BOOT) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_DEBUG_LOCKED) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_POLICY_CURRENT) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_REVOCATION_CURRENT) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_STORAGE_INTEGRITY) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_CHANNEL_BOUND) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_KEY_CUSTODY),
		.quarantine_failure_mask =
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_SECURE_BOOT) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_DEBUG_LOCKED) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_STORAGE_INTEGRITY) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_KEY_CUSTODY),
		.challenge_failure_mask =
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_POLICY_CURRENT) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_REVOCATION_CURRENT) |
			POSTURE_BIT(
				PQCP_EDGE_POSTURE_CHANNEL_BOUND),
		.maximum_risk = 700U,
		.minimum_policy_epoch = policy_epoch,
		.minimum_firmware_version = 1U,
		.maximum_age_ms = 300000U,
	};

	return policy;
}

int pqcp_edge_runtime_init(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_runtime_storage *storage,
	uint64_t policy_epoch)
{
	struct pqcp_edge_traffic_policy traffic_policy;
	struct pqcp_edge_circuit_policy circuit_policy;
	struct pqcp_edge_posture_policy posture_policy;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret;

	if (runtime == NULL ||
	    !runtime_storage_valid(storage) ||
	    policy_epoch == 0U) {
		return -EINVAL;
	}
	memset(runtime, 0, sizeof(*runtime));
	runtime->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	ret = policy_digest(policy_epoch, digest);
	if (ret != 0) {
		return ret;
	}
	traffic_policy = default_traffic_policy();
	circuit_policy = default_circuit_policy();
	posture_policy =
		default_posture_policy(policy_epoch);

	ret = pqcp_edge_principal_directory_init(
		&runtime->principals,
		storage->principals,
		storage->principal_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_service_registry_init(
		&runtime->services,
		storage->services,
		storage->service_capacity,
		storage->endpoints,
		storage->endpoint_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_access_engine_init(
		&runtime->access,
		storage->access_rules,
		storage->access_rule_capacity,
		PQCP_EDGE_POLICY_DENY);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_route_table_init(
		&runtime->routes,
		storage->routes,
		storage->route_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_session_registry_init(
		&runtime->sessions,
		storage->sessions,
		storage->session_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_traffic_governor_init(
		&runtime->traffic,
		&traffic_policy,
		storage->traffic_subjects,
		storage->traffic_subject_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_circuit_breaker_init(
		&runtime->circuits,
		&circuit_policy,
		storage->circuits,
		storage->circuit_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_message_queue_init(
		&runtime->messages,
		storage->messages,
		storage->message_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_replay_guard_init(
		&runtime->replay,
		storage->replay_entries,
		storage->replay_capacity,
		64U);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_fragment_manager_init(
		&runtime->fragments,
		storage->reassemblies,
		storage->reassembly_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_topic_registry_init(
		&runtime->topics,
		storage->topics,
		storage->topic_capacity,
		storage->subscriptions,
		storage->subscription_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_group_manager_init(
		&runtime->groups,
		storage->groups,
		storage->group_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_delivery_manager_init(
		&runtime->deliveries,
		storage->deliveries,
		storage->delivery_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_vault_store_init(
		&runtime->vault,
		storage->vault_objects,
		storage->vault_object_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_vault_acl_init(
		&runtime->vault_acl,
		storage->vault_acl_entries,
		storage->vault_acl_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_vault_version_store_init(
		&runtime->versions,
		storage->vault_versions,
		storage->vault_version_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_vault_journal_init(
		&runtime->journal,
		storage->vault_journal_entries,
		storage->vault_journal_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_vault_lease_manager_init(
		&runtime->leases,
		storage->vault_leases,
		storage->vault_lease_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_replication_manager_init(
		&runtime->replication,
		storage->replicas,
		storage->replica_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_snapshot_manager_init(
		&runtime->snapshots,
		storage->snapshots,
		storage->snapshot_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_signal_engine_init(
		&runtime->signals,
		storage->signals,
		storage->signal_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_incident_manager_init(
		&runtime->incidents,
		storage->incidents,
		storage->incident_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_playbook_engine_init(
		&runtime->playbooks,
		storage->playbooks,
		storage->playbook_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_evidence_store_init(
		&runtime->evidence,
		storage->evidence,
		storage->evidence_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_containment_manager_init(
		&runtime->containment,
		storage->containments,
		storage->containment_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_continuity_manager_init(
		&runtime->continuity,
		storage->continuity_services,
		storage->continuity_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_posture_engine_init(
		&runtime->posture,
		&posture_policy,
		storage->posture_reports,
		storage->posture_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_attestation_manager_init(
		&runtime->attestation,
		storage->attestations,
		storage->attestation_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_policy_distributor_init(
		&runtime->policy,
		storage->policy_bundles,
		storage->policy_bundle_capacity,
		storage->policy_acks,
		storage->policy_ack_capacity,
		policy_epoch,
		digest);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_rotation_manager_init(
		&runtime->rotation,
		storage->rotations,
		storage->rotation_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_anomaly_engine_init(
		&runtime->anomaly,
		storage->anomaly_baselines,
		storage->anomaly_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_resource_monitor_init(
		&runtime->resources,
		storage->resource_budgets,
		storage->resource_budget_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_audit_exporter_init(
		&runtime->exporter,
		storage->export_cursors,
		storage->export_cursor_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_recovery_coordinator_init(
		&runtime->recovery,
		storage->recovery_plans,
		storage->recovery_plan_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_dlp_engine_init(
		&runtime->dlp,
		storage->dlp_rules,
		storage->dlp_rule_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_trust_federation_init(
		&runtime->federation,
		storage->trust_anchors,
		storage->trust_anchor_capacity,
		storage->federation_grants,
		storage->federation_grant_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_credential_cache_init(
		&runtime->credentials,
		storage->credentials,
		storage->credential_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_isolation_manager_init(
		&runtime->isolation,
		storage->isolation_zones,
		storage->isolation_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_provenance_ledger_init(
		&runtime->provenance,
		storage->provenance_records,
		storage->provenance_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_workload_scheduler_init(
		&runtime->scheduler,
		storage->workload_jobs,
		storage->workload_job_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_sla_monitor_init(
		&runtime->sla,
		storage->sla_objectives,
		storage->sla_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_config_manager_init(
		&runtime->configuration,
		storage->config_transactions,
		storage->config_transaction_capacity,
		policy_epoch,
		digest);
	if (ret != 0) {
		return ret;
	}
	runtime->policy_epoch = policy_epoch;
	runtime->initialized = true;
	return 0;
}

static void remember_error(
	int result,
	int *first_error)
{
	if (result != 0 && *first_error == 0) {
		*first_error = result;
	}
}

int pqcp_edge_runtime_tick(
	struct pqcp_edge_runtime *runtime,
	uint64_t now_ms)
{
	uint32_t changed;
	uint64_t replay_before;
	int first_error = 0;

	if (runtime == NULL || !runtime->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	remember_error(
		pqcp_edge_principal_tick(
			&runtime->principals,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_service_tick(
			&runtime->services,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_route_expire(
			&runtime->routes,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_session_tick(
			&runtime->sessions,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_traffic_tick(
			&runtime->traffic,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_circuit_tick(
			&runtime->circuits,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_message_tick(
			&runtime->messages,
			now_ms, &changed),
		&first_error);
	replay_before = now_ms > 3600000U ?
		now_ms - 3600000U : 0U;
	remember_error(
		pqcp_edge_replay_expire(
			&runtime->replay,
			replay_before, &changed),
		&first_error);
	remember_error(
		pqcp_edge_fragment_expire(
			&runtime->fragments,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_topic_tick(
			&runtime->topics,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_delivery_tick(
			&runtime->deliveries,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_vault_tick(
			&runtime->vault,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_vault_acl_expire(
			&runtime->vault_acl,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_vault_version_prune(
			&runtime->versions,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_vault_lease_expire(
			&runtime->leases,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_evidence_expire(
			&runtime->evidence,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_containment_tick(
			&runtime->containment,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_posture_expire(
			&runtime->posture,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_attestation_expire(
			&runtime->attestation,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_rotation_tick(
			&runtime->rotation,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_resource_tick(
			&runtime->resources,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_audit_export_expire(
			&runtime->exporter,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_recovery_tick(
			&runtime->recovery,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_credential_tick(
			&runtime->credentials,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_isolation_tick(
			&runtime->isolation,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_workload_tick(
			&runtime->scheduler,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_sla_tick(
			&runtime->sla,
			now_ms, &changed),
		&first_error);
	remember_error(
		pqcp_edge_config_tick(
			&runtime->configuration,
			now_ms, &changed),
		&first_error);
	runtime->tick_count =
		pqcp_edge_internal_saturating_add_u64(
			runtime->tick_count, 1U);
	return first_error;
}

int pqcp_edge_runtime_advance_policy(
	struct pqcp_edge_runtime *runtime,
	uint64_t policy_epoch)
{
	if (runtime == NULL || !runtime->initialized ||
	    policy_epoch == 0U) {
		return -EINVAL;
	}
	if (policy_epoch <= runtime->policy_epoch) {
		return -ESTALE;
	}
	runtime->policy_epoch = policy_epoch;
	k_mutex_lock(&runtime->posture.lock, K_FOREVER);
	runtime->posture.policy.minimum_policy_epoch =
		policy_epoch;
	k_mutex_unlock(&runtime->posture.lock);
	return 0;
}

int pqcp_edge_runtime_audit(
	struct pqcp_edge_runtime *runtime)
{
	int first_error = 0;

	if (runtime == NULL || !runtime->initialized ||
	    runtime->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    runtime->policy_epoch == 0U) {
		return -EINVAL;
	}
	remember_error(
		pqcp_edge_principal_audit(
			&runtime->principals),
		&first_error);
	remember_error(
		pqcp_edge_service_registry_audit(
			&runtime->services),
		&first_error);
	remember_error(
		pqcp_edge_access_engine_audit(
			&runtime->access),
		&first_error);
	remember_error(
		pqcp_edge_route_table_audit(
			&runtime->routes),
		&first_error);
	remember_error(
		pqcp_edge_session_registry_audit(
			&runtime->sessions),
		&first_error);
	remember_error(
		pqcp_edge_traffic_governor_audit(
			&runtime->traffic),
		&first_error);
	remember_error(
		pqcp_edge_circuit_breaker_audit(
			&runtime->circuits),
		&first_error);
	remember_error(
		pqcp_edge_replay_guard_audit(
			&runtime->replay),
		&first_error);
	remember_error(
		pqcp_edge_fragment_manager_audit(
			&runtime->fragments),
		&first_error);
	remember_error(
		pqcp_edge_topic_registry_audit(
			&runtime->topics),
		&first_error);
	remember_error(
		pqcp_edge_group_manager_audit(
			&runtime->groups),
		&first_error);
	remember_error(
		pqcp_edge_delivery_manager_audit(
			&runtime->deliveries),
		&first_error);
	remember_error(
		pqcp_edge_vault_store_audit(
			&runtime->vault),
		&first_error);
	remember_error(
		pqcp_edge_vault_acl_audit(
			&runtime->vault_acl),
		&first_error);
	remember_error(
		pqcp_edge_vault_version_store_audit(
			&runtime->versions),
		&first_error);
	remember_error(
		pqcp_edge_vault_journal_verify(
			&runtime->journal),
		&first_error);
	remember_error(
		pqcp_edge_vault_lease_manager_audit(
			&runtime->leases),
		&first_error);
	remember_error(
		pqcp_edge_replication_manager_audit(
			&runtime->replication),
		&first_error);
	remember_error(
		pqcp_edge_snapshot_manager_audit(
			&runtime->snapshots),
		&first_error);
	remember_error(
		pqcp_edge_signal_engine_audit(
			&runtime->signals),
		&first_error);
	remember_error(
		pqcp_edge_incident_manager_audit(
			&runtime->incidents),
		&first_error);
	remember_error(
		pqcp_edge_playbook_engine_audit(
			&runtime->playbooks),
		&first_error);
	remember_error(
		pqcp_edge_evidence_store_audit(
			&runtime->evidence),
		&first_error);
	remember_error(
		pqcp_edge_containment_manager_audit(
			&runtime->containment),
		&first_error);
	remember_error(
		pqcp_edge_continuity_manager_audit(
			&runtime->continuity),
		&first_error);
	remember_error(
		pqcp_edge_posture_engine_audit(
			&runtime->posture),
		&first_error);
	remember_error(
		pqcp_edge_attestation_manager_audit(
			&runtime->attestation),
		&first_error);
	remember_error(
		pqcp_edge_policy_distributor_audit(
			&runtime->policy),
		&first_error);
	remember_error(
		pqcp_edge_rotation_manager_audit(
			&runtime->rotation),
		&first_error);
	remember_error(
		pqcp_edge_anomaly_engine_audit(
			&runtime->anomaly),
		&first_error);
	remember_error(
		pqcp_edge_resource_monitor_audit(
			&runtime->resources),
		&first_error);
	remember_error(
		pqcp_edge_audit_exporter_audit(
			&runtime->exporter),
		&first_error);
	remember_error(
		pqcp_edge_recovery_coordinator_audit(
			&runtime->recovery),
		&first_error);
	remember_error(
		pqcp_edge_dlp_engine_audit(
			&runtime->dlp),
		&first_error);
	remember_error(
		pqcp_edge_trust_federation_audit(
			&runtime->federation),
		&first_error);
	remember_error(
		pqcp_edge_credential_cache_audit(
			&runtime->credentials),
		&first_error);
	remember_error(
		pqcp_edge_isolation_manager_audit(
			&runtime->isolation),
		&first_error);
	remember_error(
		pqcp_edge_provenance_verify(
			&runtime->provenance),
		&first_error);
	remember_error(
		pqcp_edge_workload_scheduler_audit(
			&runtime->scheduler),
		&first_error);
	remember_error(
		pqcp_edge_sla_monitor_audit(
			&runtime->sla),
		&first_error);
	remember_error(
		pqcp_edge_config_manager_audit(
			&runtime->configuration),
		&first_error);
	if (runtime->posture.policy.
		    minimum_policy_epoch !=
	    runtime->policy_epoch) {
		remember_error(-ESTALE, &first_error);
	}
	return first_error;
}
