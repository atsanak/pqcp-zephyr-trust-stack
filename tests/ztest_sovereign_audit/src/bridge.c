/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */
#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>
#include <pqcp_zephyr/crypto_broker.h>
#include <pqcp_zephyr/edge_security.h>
#include <pqcp_zephyr/fleet_journal.h>
#include <pqcp_zephyr/sovereign_runtime.h>
#include <pqcp_zephyr/sovereign_audit.h>
#include <pqcp_zephyr/runtime_key_store.h>

#define A(name) PQCP_SOVEREIGN_AUDIT_##name
#define T0 1000U
#define T1 1100U
#define TN 2000U

static struct pqcp_crypto_broker_receipt receipt;
static struct pqcp_fleet_journal_entry fleet_storage[2], fleet_entry;
static struct pqcp_fleet_journal fleet_journal;
static struct pqcp_edge_incident incident;
static struct pqcp_sovereign_rollout rollout;
static struct pqcp_sovereign_key_ceremony ceremony;
static struct pqcp_sovereign_privacy_budget budget;
static struct pqcp_sovereign_retention_record retention;
static struct pqcp_sovereign_recovery_request recovery;
static struct pqcp_sovereign_continuity_exercise continuity;
static struct pqcp_sovereign_event event, prior, events[12];
static struct pqcp_sovereign_event_ledger ledger;
static const uint8_t anchor[32] = {1U};

static void before_bridge(void *fixture)
{
	ARG_UNUSED(fixture);
	memset(&receipt, 0, sizeof(receipt));
	receipt.schema_version = PQCP_CRYPTO_BROKER_SCHEMA_VERSION;
	receipt.sequence = 1U;
	receipt.accepted_at_ms = T0;
	receipt.completed_at_ms = T1;
	receipt.operation = PQCP_CRYPTO_BROKER_OPERATION_SIGN;
	receipt.decision = PQCP_CRYPTO_BROKER_DECISION_ALLOW;
	memset(receipt.receipt_digest, 0x11, sizeof(receipt.receipt_digest));
	memset(receipt.principal_digest, 0x12, sizeof(receipt.principal_digest));
	memset(receipt.output_digest, 0x13, sizeof(receipt.output_digest));

	const struct pqcp_fleet_journal_append append = {
		.timestamp_ms = T1, .correlation_id = 99U, .policy_epoch = 7U, .revocation_epoch = 3U,
		.kind = PQCP_FLEET_JOURNAL_POLICY_APPLIED, .severity = PQCP_FLEET_JOURNAL_INFO,
		.subject = "device-1", .component = "fleet-policy",
	};
	zassert_ok(pqcp_fleet_journal_init(&fleet_journal, fleet_storage, ARRAY_SIZE(fleet_storage), 1U, anchor));
	zassert_ok(pqcp_fleet_journal_append(&fleet_journal, &append, &fleet_entry));

	incident = (struct pqcp_edge_incident){
		.schema_version = PQCP_EDGE_SCHEMA_VERSION, .incident_id = 2U,
		.severity = PQCP_EDGE_INCIDENT_HIGH, .state = PQCP_EDGE_INCIDENT_OPEN,
		.title = "replay detected", .subject_id = "device-1", .owner_id = "alice",
		.opened_at_ms = T0, .updated_at_ms = T1, .risk_score = 600U, .occupied = true,
	};
	memset(incident.incident_digest, 0x22, sizeof(incident.incident_digest));
	rollout = (struct pqcp_sovereign_rollout){
		.schema_version = 1U, .rollout_id = 3U, .artifact_id = "firmware", .ring_id = "canary",
		.policy_epoch = 7U, .planned_at_ms = T0, .started_at_ms = T1, .deadline_ms = 3000U,
		.target_count = 2U, .batch_size = 1U, .attempted_count = 2U, .success_count = 2U,
		.health_basis_points = 10000U, .state = PQCP_SOVEREIGN_ROLLOUT_COMPLETED, .occupied = true,
	};
	memset(rollout.plan_digest, 0x33, sizeof(rollout.plan_digest));
	ceremony = (struct pqcp_sovereign_key_ceremony){
		.schema_version = 1U, .ceremony_id = 4U, .key_id = "key-1", .purpose = "rotate",
		.current_epoch = 1U, .target_epoch = 2U, .opened_at_ms = T0, .expires_at_ms = 3000U,
		.threshold = 2U, .required_distinct_roles = 2U, .contribution_count = 2U,
		.distinct_role_count = 2U, .state = PQCP_SOVEREIGN_CEREMONY_COMMITTED, .occupied = true,
	};
	memset(ceremony.transcript_digest, 0x44, sizeof(ceremony.transcript_digest));
	memset(ceremony.committed_key_digest, 0x45, sizeof(ceremony.committed_key_digest));
	budget = (struct pqcp_sovereign_privacy_budget){
		.schema_version = 1U, .generation = 1U, .budget_id = "budget-1", .tenant_id = "tenant-a",
		.subject_scope = "cohort", .purpose = "analytics", .window_started_ms = T0,
		.window_ms = 3000U, .policy_epoch = 7U, .epsilon_limit_micros = 1000U,
		.epsilon_used_micros = 10U, .delta_limit_nanos = 1000U, .delta_used_nanos = 10U,
		.query_limit = 10U, .query_count = 1U, .state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE, .occupied = true,
	};
	retention = (struct pqcp_sovereign_retention_record){
		.schema_version = 1U, .record_id = 5U, .object_id = "object-1", .tenant_id = "tenant-a",
		.purpose = "analytics", .data_class = PQCP_SOVEREIGN_DATA_PERSONAL, .created_at_ms = T0,
		.delete_after_ms = T1, .deleted_at_ms = T1, .state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED, .occupied = true,
	};
	memset(retention.object_digest, 0x55, sizeof(retention.object_digest));
	recovery = (struct pqcp_sovereign_recovery_request){
		.schema_version = 1U, .recovery_id = 6U, .subject_id = "device-1", .action = "recover",
		.opened_at_ms = T0, .expires_at_ms = 3000U, .policy_epoch = 7U, .threshold = 2U,
		.required_distinct_roles = 2U, .approval_count = 2U, .distinct_role_count = 2U,
		.state = PQCP_SOVEREIGN_APPROVAL_SATISFIED, .occupied = true,
	};
	memset(recovery.authorization_digest, 0x66, sizeof(recovery.authorization_digest));
	continuity = (struct pqcp_sovereign_continuity_exercise){
		.schema_version = 1U, .exercise_id = 7U, .service_id = "service-1", .scenario = "site-failure",
		.planned_at_ms = T0, .started_at_ms = T1, .completed_at_ms = 1200U, .policy_epoch = 7U,
		.required_steps = 2U, .completed_steps = 3U, .maximum_failures = 1U,
		.recovery_time_objective_ms = 100U, .recovery_point_objective_ms = 20U,
		.observed_recovery_time_ms = 90U, .observed_data_loss_ms = 5U,
		.state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED, .occupied = true,
	};
	memset(continuity.evidence_digest, 0x77, sizeof(continuity.evidence_digest));
	memset(&event, 0xa5, sizeof(event));
	prior = event;
	zassert_ok(pqcp_sovereign_event_ledger_init(&ledger, events, ARRAY_SIZE(events), 1U, anchor));
}

static int bridge(unsigned int index, uint64_t ingested, struct pqcp_sovereign_event *output)
{
	switch (index) {
	case 0: return pqcp_sovereign_audit_bridge_broker_receipt("tenant-a", "eu", "broker", &receipt, ingested, output);
	case 1: return pqcp_sovereign_audit_bridge_fleet_journal("tenant-a", "eu", &fleet_entry, ingested, output);
	case 2: return pqcp_sovereign_audit_bridge_edge_incident("tenant-a", "eu", &incident, ingested, output);
	case 3: return pqcp_sovereign_audit_bridge_deployment("tenant-a", "eu", &rollout, ingested, output);
	case 4: return pqcp_sovereign_audit_bridge_ceremony("tenant-a", "eu", &ceremony, ingested, output);
	case 5: return pqcp_sovereign_audit_bridge_privacy_budget("eu", &budget, true, ingested, output);
	case 6: return pqcp_sovereign_audit_bridge_erasure("eu", &retention, ingested, output);
	case 7: return pqcp_sovereign_audit_bridge_recovery("tenant-a", "eu", &recovery, ingested, output);
	case 8: return pqcp_sovereign_audit_bridge_continuity("tenant-a", "eu", &continuity, ingested, output);
	default: return -EINVAL;
	}
}

static uint64_t attribute(const char *key)
{
	for (size_t i = 0U; i < event.attribute_count; ++i) {
		if (!strcmp(event.attributes[i].key, key)) {
			return event.attributes[i].value.u64;
		}
	}
	zassert_unreachable("missing attribute %s", key);
	return 0U;
}

ZTEST_SUITE(pqcp_sovereign_audit_bridge, NULL, NULL, before_bridge, NULL, NULL);

ZTEST(pqcp_sovereign_audit_bridge, test_all_nine_sources_are_appendable_and_verifiable)
{
	const enum pqcp_sovereign_audit_event_class classes[] = {
		A(CLASS_CRYPTO_OPERATION), A(CLASS_FLEET_OPERATION), A(CLASS_SECURITY_INCIDENT),
		A(CLASS_DEPLOYMENT), A(CLASS_KEY_CEREMONY), A(CLASS_PRIVACY), A(CLASS_PRIVACY),
		A(CLASS_RECOVERY), A(CLASS_CONTINUITY),
	};

	for (unsigned int i = 0U; i < ARRAY_SIZE(classes); ++i) {
		zassert_ok(bridge(i, TN, &event), "source %u", i);
		zassert_equal(event.event_class, classes[i]);
		zassert_str_equal(event.tenant.tenant_id, "tenant-a");
		zassert_equal(event.sequence, 0U);
		zassert_false(event.occupied);
		zassert_false(event.flags & A(EVENT_SIGNED_SOURCE));
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event, &event));
		zassert_ok(pqcp_sovereign_event_verify(&event));
	}
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));
	zassert_equal(ledger.count, 9U);
}

ZTEST(pqcp_sovereign_audit_bridge, test_reingestion_identity_excludes_ingestion_but_binds_state)
{
	for (unsigned int i = 0U; i < 5U; ++i) {
		zassert_ok(bridge(i, TN, &event));
		prior = event;
		zassert_ok(bridge(i, TN + 1U, &event));
		zassert_mem_equal(event.event_id, prior.event_id, sizeof(event.event_id));
	}
	zassert_ok(bridge(0U, TN, &prior));
	receipt.cost_units++;
	zassert_ok(bridge(0U, TN, &event));
	zassert_not_equal(memcmp(event.event_id, prior.event_id, sizeof(event.event_id)), 0);
	zassert_ok(bridge(7U, TN, &prior));
	recovery.approval_count++;
	zassert_ok(bridge(7U, TN, &event));
	zassert_not_equal(memcmp(event.event_id, prior.event_id, sizeof(event.event_id)), 0);
}

ZTEST(pqcp_sovereign_audit_bridge, test_broker_preserves_bindings_without_forging_verification)
{
	receipt.signed_receipt = true;
	receipt.signature_length = 1U; /* Structurally present; not authenticated here. */
	zassert_ok(bridge(0U, TN, &event));
	zassert_mem_equal(event.receipt_digest, receipt.receipt_digest, sizeof(event.receipt_digest));
	zassert_mem_equal(event.actor_digest, receipt.principal_digest, sizeof(event.actor_digest));
	zassert_mem_equal(event.evidence_digest, receipt.output_digest, sizeof(event.evidence_digest));
	zassert_false(event.flags & A(EVENT_SIGNED_SOURCE));
	zassert_equal(attribute("signed_receipt"), 1U);
	receipt.decision = PQCP_CRYPTO_BROKER_DECISION_DENY_QUOTA;
	receipt.result = -EACCES;
	zassert_ok(bridge(0U, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_DENIED));
	receipt.result = 0;
	zassert_equal(bridge(0U, TN, &event), -EINVAL);
}

ZTEST(pqcp_sovereign_audit_bridge, test_fleet_entry_tamper_is_rejected_atomically)
{
	fleet_entry.digest[0] ^= 1U;
	zassert_equal(bridge(1U, TN, &event), -EBADMSG);
	zassert_mem_equal(&event, &prior, sizeof(event));
	fleet_entry.digest[0] ^= 1U;
	zassert_ok(bridge(1U, TN, &event));
	zassert_equal(event.policy_epoch, fleet_entry.policy_epoch);
	zassert_equal(event.revocation_epoch, fleet_entry.revocation_epoch);
	zassert_mem_equal(event.receipt_digest, fleet_entry.digest, sizeof(event.receipt_digest));
}

ZTEST(pqcp_sovereign_audit_bridge, test_null_sources_leave_output_unchanged)
{
	zassert_equal(pqcp_sovereign_audit_bridge_broker_receipt("tenant-a", "eu", "broker", NULL, TN, &event), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_bridge_fleet_journal("tenant-a", "eu", NULL, TN, &event), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_bridge_edge_incident("tenant-a", "eu", NULL, TN, &event), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_bridge_deployment("tenant-a", "eu", NULL, TN, &event), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_bridge_ceremony("tenant-a", "eu", NULL, TN, &event), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_bridge_privacy_budget("eu", NULL, false, TN, &event), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_bridge_erasure("eu", NULL, TN, &event), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_bridge_recovery("tenant-a", "eu", NULL, TN, &event), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_bridge_continuity("tenant-a", "eu", NULL, TN, &event), -EINVAL);
	zassert_mem_equal(&event, &prior, sizeof(event));
}

ZTEST(pqcp_sovereign_audit_bridge, test_ceremony_actions_and_epochs_are_not_conflated)
{
	const char *purposes[] = {"generate", "rotate", "recover", "retire", "destroy"};
	const enum pqcp_sovereign_audit_activity activities[] = {
		A(ACTIVITY_CREATE), A(ACTIVITY_ROTATE), A(ACTIVITY_RECOVER), A(ACTIVITY_REVOKE), A(ACTIVITY_DESTROY),
	};
	for (size_t i = 0U; i < ARRAY_SIZE(purposes); ++i) {
		strcpy(ceremony.purpose, purposes[i]);
		ceremony.current_epoch = i == 0U ? 0U : 1U;
		ceremony.target_epoch = i >= 3U ? 1U : 2U;
		zassert_ok(bridge(4U, TN, &event));
		zassert_equal(event.activity, activities[i]);
	}
	strcpy(ceremony.purpose, "rotate");
	zassert_equal(bridge(4U, TN, &event), -EINVAL);
	strcpy(ceremony.purpose, "unsupported-action");
	zassert_equal(bridge(4U, TN, &event), -EINVAL);
}

ZTEST(pqcp_sovereign_audit_bridge, test_bad_schema_null_output_and_time_are_rejected)
{
	uint32_t *schemas[] = {&receipt.schema_version, &fleet_entry.schema_version,
		&incident.schema_version, &rollout.schema_version, &ceremony.schema_version,
		&budget.schema_version, &retention.schema_version, &recovery.schema_version, &continuity.schema_version};

	for (unsigned int i = 0U; i < ARRAY_SIZE(schemas); ++i) {
		*schemas[i] = 99U;
		zassert_not_equal(bridge(i, TN, &event), 0, "schema %u", i);
		zassert_mem_equal(&event, &prior, sizeof(event));
		*schemas[i] = 1U;
		zassert_equal(bridge(i, TN, NULL), -EINVAL);
		zassert_not_equal(bridge(i, 0U, &event), 0, "time %u", i);
		zassert_mem_equal(&event, &prior, sizeof(event));
	}
}

ZTEST(pqcp_sovereign_audit_bridge, test_unterminated_source_fields_never_escape_bounds)
{
	memset(incident.title, 'x', sizeof(incident.title));
	zassert_equal(bridge(2U, TN, &event), -EINVAL);
	memset(rollout.artifact_id, 'x', sizeof(rollout.artifact_id));
	zassert_equal(bridge(3U, TN, &event), -EINVAL);
	memset(ceremony.purpose, 'x', sizeof(ceremony.purpose));
	zassert_equal(bridge(4U, TN, &event), -EINVAL);
	memset(budget.tenant_id, 'x', sizeof(budget.tenant_id));
	zassert_equal(bridge(5U, TN, &event), -EINVAL);
	memset(retention.object_id, 'x', sizeof(retention.object_id));
	zassert_equal(bridge(6U, TN, &event), -EINVAL);
	memset(recovery.action, 'x', sizeof(recovery.action));
	zassert_equal(bridge(7U, TN, &event), -EINVAL);
	memset(continuity.scenario, 'x', sizeof(continuity.scenario));
	zassert_equal(bridge(8U, TN, &event), -EINVAL);
	zassert_mem_equal(&event, &prior, sizeof(event));
}

ZTEST(pqcp_sovereign_audit_bridge, test_success_requires_source_evidence_and_thresholds)
{
	incident.state = PQCP_EDGE_INCIDENT_RESOLVED;
	zassert_equal(bridge(2U, TN, &event), -EINVAL);
	incident.resolved_at_ms = T1;
	zassert_ok(bridge(2U, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_SUCCESS));
	rollout.success_count = UINT32_MAX;
	zassert_equal(bridge(3U, TN, &event), -EINVAL);
	ceremony.contribution_count = 1U;
	zassert_equal(bridge(4U, TN, &event), -EINVAL);
	recovery.distinct_role_count = 1U;
	zassert_equal(bridge(7U, TN, &event), -EINVAL);
	continuity.observed_recovery_time_ms = 101U;
	zassert_equal(bridge(8U, TN, &event), -EINVAL);
}

ZTEST(pqcp_sovereign_audit_bridge, test_partial_rollout_completion_keeps_failure_counts)
{
	/* Source controller declares completed at >=50% health. Preserve that
	 * outcome AND the failures; do not invent a 100% deployment claim.
	 */
	rollout.success_count = 1U;
	rollout.failure_count = 1U;
	rollout.health_basis_points = 5000U;
	zassert_ok(bridge(3U, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_SUCCESS));
	zassert_equal(attribute("success_count"), 1U);
	zassert_equal(attribute("failure_count"), 1U);
	rollout.state = PQCP_SOVEREIGN_ROLLOUT_FAILED;
	rollout.result = -EIO;
	zassert_ok(bridge(3U, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_FAILURE));
}

ZTEST(pqcp_sovereign_audit_bridge, test_privacy_denial_and_erasure_hold_remain_distinct)
{
	zassert_ok(pqcp_sovereign_audit_bridge_privacy_budget("eu", &budget, false, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_DENIED));
	zassert_equal(event.data_class, A(DATA_PERSONAL));
	zassert_true(event.flags & A(EVENT_PRIVACY_RELEVANT));
	budget.query_count = budget.query_limit + 1U;
	zassert_equal(bridge(5U, TN, &event), -EINVAL);
	retention.legal_hold_until_ms = TN + 1U;
	zassert_equal(bridge(6U, TN, &event), -EINVAL);
	retention.state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	retention.deleted_at_ms = 0U;
	zassert_ok(bridge(6U, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_PENDING));
}

ZTEST(pqcp_sovereign_audit_bridge, test_expired_recovery_never_reads_as_live_authorization)
{
	zassert_ok(bridge(7U, 3000U, &event));
	zassert_equal(event.outcome, A(OUTCOME_EXPIRED));
	recovery.state = PQCP_SOVEREIGN_APPROVAL_REJECTED;
	zassert_ok(bridge(7U, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_DENIED));
	recovery.state = PQCP_SOVEREIGN_APPROVAL_CANCELLED;
	zassert_ok(bridge(7U, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_CANCELLED));
}

ZTEST(pqcp_sovereign_audit_bridge, test_continuity_32_step_mask_and_failure_projection)
{
	continuity.required_steps = 32U;
	continuity.completed_steps = UINT32_MAX;
	zassert_ok(bridge(8U, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_SUCCESS));
	continuity.failed_steps = 1U;
	zassert_equal(bridge(8U, TN, &event), -EINVAL);
	continuity.completed_steps &= ~1U;
	continuity.state = PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	zassert_ok(bridge(8U, TN, &event));
	zassert_equal(event.outcome, A(OUTCOME_FAILURE));
	continuity.required_steps = 33U;
	zassert_equal(bridge(8U, TN, &event), -EINVAL);
}

ZTEST(pqcp_sovereign_audit_bridge, test_cross_plane_signed_export_replay_and_source_tamper)
{
	static struct pqcp_runtime_key_store store;
	static struct pqcp_runtime_volatile_context context;
	static struct pqcp_runtime_volatile_slot slots[1];
	static struct pqcp_sovereign_audit_exporter exporter;
	static struct pqcp_sovereign_audit_cursor cursor[1];
	static struct pqcp_sovereign_event workspace[3];
	static struct pqcp_sovereign_export_batch batch;
	static uint8_t output[32768], replay[32768];
	const struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_MLDSA_KEYPAIR, .level = 65U,
		.usage = PQCP_RUNTIME_USAGE_SIGN | PQCP_RUNTIME_USAGE_VERIFY | PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = T0, .owner = "cross-plane", .label = "audit-export",
	};
	const struct pqcp_sovereign_audit_export_storage storage = {
		.cursors = cursor, .cursor_capacity = ARRAY_SIZE(cursor),
		.workspace_events = workspace, .workspace_event_capacity = ARRAY_SIZE(workspace),
	};
	struct pqcp_sovereign_audit_export_config config = {
		.key_store = &store, .maximum_cursor_lifetime_ms = 10000U,
		.maximum_batch_events = 3U, .signing_enabled = true, .signature_required = true,
	};
	struct pqcp_sovereign_audit_export_policy policy = {
		.tenant_id = "tenant-a", .realm = "eu", .maximum_events = 3U, .policy_epoch = 7U,
		.maximum_data_class = A(DATA_SECRET), .redaction = A(REDACTION_STRICT),
		.format = A(FORMAT_CBOR), .require_signature = true,
	};
	uint64_t cursor_id;
	uint8_t previous[32] = {0};

	for (unsigned int i = 0U; i < 9U; ++i) {
		zassert_ok(bridge(i, TN, &event));
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event, NULL));
	}
	zassert_ok(pqcp_runtime_volatile_store_init(&store, &context, slots, ARRAY_SIZE(slots)));
	zassert_ok(pqcp_runtime_key_store_generate(&store, &request, &config.signing_key));
	zassert_ok(pqcp_sovereign_audit_exporter_init(&exporter, &ledger, &config, &storage));
	zassert_ok(pqcp_sovereign_audit_export_open(&exporter, "auditor", "tenant-a",
		0U, TN, 9000U, 7U, &cursor_id));
	for (unsigned int i = 0U; i < 3U; ++i) {
		zassert_ok(pqcp_sovereign_audit_export_prepare(&exporter, cursor_id, &policy,
			TN + 1U + i, output, sizeof(output), &batch));
		zassert_equal(batch.event_count, 3U);
		zassert_equal(batch.first_sequence, 1U + i * 3U);
		zassert_equal(batch.last_sequence, 3U + i * 3U);
		zassert_equal(batch.complete, i == 2U);
		zassert_mem_equal(batch.previous_batch_digest, previous, sizeof(previous));
		zassert_ok(pqcp_runtime_key_store_verify(&store, &config.signing_key, batch.batch_digest,
			sizeof(batch.batch_digest), (const uint8_t *)A(SIGNATURE_CONTEXT),
			sizeof(A(SIGNATURE_CONTEXT)) - 1U, batch.signature, batch.signature_length));
		for (size_t j = 0U; j < batch.event_count; ++j) {
			zassert_equal(batch.events[j].actor[0], '\0');
			zassert_equal(batch.events[j].reason[0], '\0');
			zassert_equal(batch.events[j].attribute_count, 0U);
			zassert_mem_equal(batch.events[j].event_digest,
				events[i * 3U + j].event_digest, sizeof(batch.events[j].event_digest));
		}
		memcpy(previous, batch.batch_digest, sizeof(previous));
		const size_t length = batch.encoded_length;

		memcpy(replay, output, length);
		if (i == 2U) {
			/* Freeze protects delivery even if the underlying source log is
			 * corrupted after prepare. A fresh scan must detect that corruption.
			 */
			events[8].action[0] ^= 1U;
		}
		zassert_ok(pqcp_sovereign_audit_export_prepare(&exporter, cursor_id, &policy,
			TN + 2U + i, output, sizeof(output), &batch));
		zassert_true(batch.resumed);
		zassert_mem_equal(replay, output, length);
		previous[0] ^= 1U;
		zassert_equal(pqcp_sovereign_audit_export_acknowledge(&exporter, cursor_id,
			batch.first_sequence, batch.last_sequence, previous, TN + 2U + i), -EBADMSG);
		previous[0] ^= 1U;
		zassert_ok(pqcp_sovereign_audit_export_acknowledge(&exporter, cursor_id,
			batch.first_sequence, batch.last_sequence, previous, TN + 2U + i));
	}
	zassert_not_equal(pqcp_sovereign_audit_export_prepare(&exporter, cursor_id,
		&policy, TN + 5U, output, sizeof(output), &batch), 0);
	events[8].action[0] ^= 1U;
	zassert_equal(pqcp_sovereign_audit_export_prepare(&exporter, cursor_id,
		&policy, TN + 5U, output, sizeof(output), &batch), -ENOENT);
	zassert_ok(pqcp_sovereign_audit_exporter_audit(&exporter));
	zassert_ok(pqcp_runtime_key_store_destroy(&store, &config.signing_key));
}
