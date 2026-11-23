/*
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/operation_conformance.h>
#include <pqcp_zephyr/operation_plan_conformance.h>
#include <pqcp_zephyr/operation_scenario.h>
#include <pqcp_zephyr/operation_transition.h>
#include <pqcp_zephyr/protected_channel_guard.h>
#include <pqcp_zephyr/protected_channel_memory.h>
#include <pqcp_zephyr/protected_channel_operations.h>
#include <pqcp_zephyr/runtime_guard.h>
#include <pqcp_zephyr/runtime_operations.h>

#define EVENT_CAPACITY 8U
#define SUBSCRIPTION_CAPACITY 2U
#define SCHEDULER_CAPACITY 6U
#define TENANT_CAPACITY 3U
#define RESERVATION_CAPACITY 4U
#define PATH_CAPACITY 4U
#define SERVICE_KEYS 16U
#define SERVICE_WORKSPACES 1U
#define SERVICE_WORKSPACE_BYTES 49152U
#define SERVICE_JOBS 4U
#define SERVICE_SESSIONS 2U
#define SERVICE_PROFILES 4U
#define SERVICE_AUDIT_ENTRIES 16U
#define SERVICE_IDENTITIES 2U
#define SERVICE_QUOTAS 2U
#define CHECKPOINT_SLOT_BYTES 4096U
#define COMMAND_HANDLERS 4U
#define COMMAND_CACHE 4U
#define TICKET_REPLAY_ENTRIES 4U

static struct pqcp_runtime_event event_entries[EVENT_CAPACITY];
static struct pqcp_runtime_event_subscription
	event_subscriptions[SUBSCRIPTION_CAPACITY];
static struct pqcp_runtime_scheduler_entry
	scheduler_entries[SCHEDULER_CAPACITY];
static struct pqcp_runtime_scheduler_tenant
	scheduler_tenants[TENANT_CAPACITY];
static struct pqcp_runtime_resource_reservation
	reservations[RESERVATION_CAPACITY];
static struct pqcp_channel_path paths[PATH_CAPACITY];
static struct pqcp_adaptive_control_plane adaptive;
static struct pqcp_runtime_service service;
static struct pqcp_runtime_volatile_slot
	service_key_slots[SERVICE_KEYS];
static struct pqcp_runtime_workspace_slot
	service_workspace_slots[SERVICE_WORKSPACES];
static uint8_t service_workspace_bytes[
	SERVICE_WORKSPACES * SERVICE_WORKSPACE_BYTES];
static struct pqcp_runtime_queue_entry
	service_queue[SERVICE_JOBS];
static struct pqcp_runtime_session
	service_sessions[SERVICE_SESSIONS];
static struct pqcp_runtime_profile_state
	service_profiles[SERVICE_PROFILES];
static struct pqcp_runtime_audit_entry
	service_audit_entries[SERVICE_AUDIT_ENTRIES];
static struct pqcp_runtime_identity
	service_identities[SERVICE_IDENTITIES];
static struct pqcp_runtime_admission_quota
	service_quotas[SERVICE_QUOTAS];
static uint8_t checkpoint_buffers[2][CHECKPOINT_SLOT_BYTES];

static const struct pqcp_runtime_service_storage service_storage = {
	.key_slots = service_key_slots,
	.key_slot_count = ARRAY_SIZE(service_key_slots),
	.workspace_slots = service_workspace_slots,
	.workspace_bytes = service_workspace_bytes,
	.workspace_slot_count =
		ARRAY_SIZE(service_workspace_slots),
	.workspace_bytes_per_slot = SERVICE_WORKSPACE_BYTES,
	.queue = service_queue,
	.queue_capacity = ARRAY_SIZE(service_queue),
	.sessions = service_sessions,
	.session_capacity = ARRAY_SIZE(service_sessions),
	.profile_states = service_profiles,
	.profile_state_capacity = ARRAY_SIZE(service_profiles),
	.audit_entries = service_audit_entries,
	.audit_capacity = ARRAY_SIZE(service_audit_entries),
	.identities = service_identities,
	.identity_capacity = ARRAY_SIZE(service_identities),
	.quotas = service_quotas,
	.quota_capacity = ARRAY_SIZE(service_quotas),
};

static void reset_service(void)
{
	memset(&adaptive, 0, sizeof(adaptive));
	memset(&service, 0, sizeof(service));
	zassert_ok(pqcp_adaptive_control_init(
		&adaptive, "operations-test",
		PQCP_ADAPTIVE_POLICY_GATEWAY,
		"hybrid768-65-runtime", 1000U));
	zassert_ok(pqcp_runtime_service_init(
		&service, &service_storage,
		&adaptive, 1000U));
}

static void initialize_fake_channel(
	struct pqcp_channel *channel)
{
	static const uint8_t transcript_seed[] = {
		0x50U, 0x51U, 0x43U, 0x50U,
		0x2dU, 0x4fU, 0x50U, 0x53U,
	};
	uint8_t client_key[PQCP_CHANNEL_AEAD_KEY_BYTES];
	uint8_t server_key[PQCP_CHANNEL_AEAD_KEY_BYTES];
	struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_AEAD,
		.level = 256U,
		.usage = PQCP_RUNTIME_USAGE_ENCRYPT |
			 PQCP_RUNTIME_USAGE_DECRYPT |
			 PQCP_RUNTIME_USAGE_MAC |
			 PQCP_RUNTIME_USAGE_DERIVE |
			 PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = 1000U,
		.owner = "operations-test",
		.persistent = false,
		.exportable_public = false,
	};

	memset(channel, 0, sizeof(*channel));
	channel->schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	channel->config.schema_version =
		PQCP_CHANNEL_SCHEMA_VERSION;
	channel->config.role = PQCP_CHANNEL_ROLE_CLIENT;
	channel->config.session_id =
		UINT64_C(0x7061746368323030);
	channel->config.mlkem_level = 768U;
	channel->config.mldsa_level = 65U;
	channel->config.max_payload_bytes =
		PQCP_CHANNEL_MAX_PAYLOAD_BYTES;
	strcpy(channel->config.profile_id,
	       "hybrid768-65-runtime");
	channel->state = PQCP_CHANNEL_STATE_ESTABLISHED;
	channel->established = true;
	channel->executor = &service.executor;
	channel->key_store = &service.key_store;
	channel->keys.exporter_ready = true;
	channel->keys.traffic_keys_ready = true;
	for (size_t index = 0U;
	     index < sizeof(channel->keys.exporter); ++index) {
		channel->keys.exporter[index] =
			(uint8_t)(0x10U + index);
	}
	for (size_t index = 0U;
	     index < sizeof(client_key);
	     ++index) {
		client_key[index] = (uint8_t)(0x40U + index);
		server_key[index] = (uint8_t)(0x80U + index);
	}
	request.label = "client-write";
	zassert_ok(pqcp_runtime_key_store_create(
		channel->key_store, &request, NULL, 0U,
		client_key, sizeof(client_key),
		&channel->keys.client_write_key));
	request.label = "server-write";
	zassert_ok(pqcp_runtime_key_store_create(
		channel->key_store, &request, NULL, 0U,
		server_key, sizeof(server_key),
		&channel->keys.server_write_key));
	pqcp_runtime_secure_zero(client_key, sizeof(client_key));
	pqcp_runtime_secure_zero(server_key, sizeof(server_key));
	zassert_ok(pqcp_channel_transcript_init(
		&channel->transcript));
	zassert_ok(pqcp_channel_transcript_update(
		&channel->transcript,
		transcript_seed, sizeof(transcript_seed)));
	zassert_ok(pqcp_channel_replay_reset(
		&channel->inbound_replay));
}

static void event_counter(
	const struct pqcp_runtime_event *event,
	void *user_data)
{
	uint32_t *count = user_data;

	zassert_not_null(event);
	(*count)++;
}

ZTEST(pqcp_operations, test_exhaustive_policy_catalogs)
{
	struct pqcp_runtime_resource_policy_decision resource;
	struct pqcp_runtime_recovery_policy_decision recovery;
	struct pqcp_channel_path_policy_decision path;
	struct pqcp_channel_fault_policy_decision fault;

	zassert_ok(pqcp_runtime_policy_catalog_audit());
	zassert_ok(
		pqcp_runtime_resource_policy_catalog_audit());
	zassert_ok(
		pqcp_runtime_recovery_policy_catalog_audit());
	zassert_ok(pqcp_channel_policy_catalog_audit());
	zassert_ok(pqcp_channel_path_policy_catalog_audit());
	zassert_ok(pqcp_channel_fault_policy_catalog_audit());

	zassert_ok(pqcp_runtime_resource_policy_lookup(
		PQCP_RUNTIME_RESOURCE_JOBS_EXHAUSTED,
		PQCP_RUNTIME_COMMAND_SUBMIT_JOB,
		&resource));
	zassert_equal(
		resource.disposition,
		PQCP_RUNTIME_RESOURCE_DENY);
	zassert_equal(resource.error, -EDQUOT);

	zassert_ok(pqcp_runtime_recovery_policy_lookup(
		PQCP_RUNTIME_RECOVERY_AUDIT_INVALID,
		PQCP_RUNTIME_COMMAND_TICK,
		&recovery));
	zassert_equal(
		recovery.directive,
		PQCP_RUNTIME_RECOVERY_LOCK_DOWN);
	zassert_equal(
		recovery.next_state,
		PQCP_RUNTIME_POLICY_LOCKDOWN);

	zassert_ok(pqcp_channel_path_policy_lookup(
		PQCP_CHANNEL_PATH_CONDITION_NO_VALID_PATH,
		PQCP_CHANNEL_CONTROL_PATH_CHALLENGE,
		&path));
	zassert_equal(
		path.disposition,
		PQCP_CHANNEL_PATH_ALLOW_PROBE);
	zassert_equal(
		path.next_state,
		PQCP_CHANNEL_POLICY_MIGRATING);

	zassert_ok(pqcp_channel_fault_policy_lookup(
		PQCP_CHANNEL_FAULT_REPLAY,
		PQCP_CHANNEL_CONTROL_STREAM_OPEN,
		&fault));
	zassert_equal(
		fault.directive,
		PQCP_CHANNEL_FAULT_CLOSE_CHANNEL);
	zassert_equal(
		fault.next_state,
		PQCP_CHANNEL_POLICY_CLOSING);
}

ZTEST(pqcp_operations, test_operation_conformance_catalogs)
{
	struct pqcp_operation_conformance_case test_case;
	uint64_t fingerprints[
		PQCP_OPERATION_CONFORMANCE_DOMAIN_COUNT];

	zassert_ok(pqcp_operation_conformance_audit_all());
	for (size_t domain = 0U;
	     domain < ARRAY_SIZE(fingerprints); ++domain) {
		zassert_equal(
			pqcp_operation_conformance_count(domain),
			PQCP_OPERATION_CONFORMANCE_CASES_PER_DOMAIN);
		zassert_ok(
			pqcp_operation_conformance_fingerprint(
				domain, &fingerprints[domain]));
		zassert_not_equal(fingerprints[domain], 0U);
		zassert_not_equal(
			strcmp(
				pqcp_operation_conformance_domain_str(
					domain),
				"unknown"),
			0);
	}
	zassert_not_equal(fingerprints[0], fingerprints[1]);
	zassert_not_equal(fingerprints[3], fingerprints[4]);

	zassert_ok(pqcp_operation_conformance_find(
		PQCP_OPERATION_CONFORMANCE_RUNTIME_POLICY,
		PQCP_RUNTIME_POLICY_RUNNING,
		PQCP_RUNTIME_COMMAND_TICK,
		&test_case));
	zassert_equal(
		test_case.decision,
		PQCP_RUNTIME_POLICY_ALLOW_IDEMPOTENT);
	zassert_equal(
		test_case.next_state,
		PQCP_RUNTIME_POLICY_RUNNING);

	zassert_ok(pqcp_operation_conformance_find(
		PQCP_OPERATION_CONFORMANCE_CHANNEL_FAULT,
		PQCP_CHANNEL_FAULT_REPLAY,
		PQCP_CHANNEL_CONTROL_STREAM_OPEN,
		&test_case));
	zassert_equal(
		test_case.decision,
		PQCP_CHANNEL_FAULT_CLOSE_CHANNEL);
	zassert_equal(
		test_case.next_state,
		PQCP_CHANNEL_POLICY_CLOSING);
}

ZTEST(pqcp_operations, test_operation_plan_conformance_catalogs)
{
	struct pqcp_runtime_operation_plan_case runtime_case;
	struct pqcp_channel_operation_plan_case channel_case;
	uint64_t runtime_fingerprint;
	uint64_t channel_fingerprint;

	zassert_ok(pqcp_operation_plan_conformance_audit_all());
	zassert_equal(
		pqcp_runtime_operation_plan_conformance_count(),
		PQCP_RUNTIME_OPERATION_PLAN_CONFORMANCE_CASES);
	zassert_equal(
		pqcp_channel_operation_plan_conformance_count(),
		PQCP_CHANNEL_OPERATION_PLAN_CONFORMANCE_CASES);

	zassert_ok(pqcp_runtime_operation_plan_conformance_find(
		PQCP_OPERATION_PLAN_SCENARIO_BASELINE,
		PQCP_RUNTIME_POLICY_RUNNING,
		PQCP_RUNTIME_COMMAND_SUBMIT_JOB,
		&runtime_case));
	zassert_equal(
		runtime_case.disposition,
		PQCP_RUNTIME_PLAN_ALLOW);
	zassert_equal(runtime_case.expected_error, 0);

	zassert_ok(pqcp_channel_operation_plan_conformance_find(
		PQCP_OPERATION_PLAN_SCENARIO_STRESS,
		PQCP_CHANNEL_POLICY_ESTABLISHED,
		PQCP_CHANNEL_CONTROL_STREAM_OPEN,
		&channel_case));
	zassert_true(
		channel_case.disposition >= PQCP_CHANNEL_PLAN_DENY);
	zassert_true(
		channel_case.disposition <
			PQCP_CHANNEL_PLAN_DISPOSITION_COUNT);

	zassert_ok(
		pqcp_runtime_operation_plan_conformance_fingerprint(
			&runtime_fingerprint));
	zassert_ok(
		pqcp_channel_operation_plan_conformance_fingerprint(
			&channel_fingerprint));
	zassert_not_equal(runtime_fingerprint, 0U);
	zassert_not_equal(channel_fingerprint, 0U);
	zassert_not_equal(
		runtime_fingerprint, channel_fingerprint);
}

ZTEST(pqcp_operations, test_operation_scenario_catalogs)
{
	struct pqcp_operation_scenario_case test_case;
	struct pqcp_operation_scenario_result replay;
	uint64_t fingerprints[
		PQCP_OPERATION_SCENARIO_DOMAIN_COUNT];

	zassert_ok(pqcp_operation_scenario_audit_all());
	for (size_t domain = 0U;
	     domain < ARRAY_SIZE(fingerprints); ++domain) {
		zassert_equal(
			pqcp_operation_scenario_count(domain),
			PQCP_OPERATION_SCENARIO_CASES_PER_DOMAIN);
		zassert_ok(
			pqcp_operation_scenario_fingerprint(
				domain, &fingerprints[domain]));
		zassert_not_equal(fingerprints[domain], 0U);
		zassert_not_equal(
			strcmp(
				pqcp_operation_scenario_domain_str(
					domain),
				"unknown"),
			0);
	}
	zassert_not_equal(fingerprints[0], fingerprints[1]);
	zassert_not_equal(fingerprints[3], fingerprints[4]);

	zassert_ok(pqcp_operation_scenario_find(
		PQCP_OPERATION_SCENARIO_RUNTIME_POLICY,
		PQCP_RUNTIME_POLICY_INITIALIZED,
		PQCP_RUNTIME_COMMAND_START,
		PQCP_RUNTIME_COMMAND_SUBMIT_JOB,
		&test_case));
	zassert_equal(
		test_case.expected.second_condition,
		PQCP_RUNTIME_POLICY_RUNNING);
	zassert_equal(
		test_case.expected.first_decision,
		PQCP_RUNTIME_POLICY_ALLOW_IDEMPOTENT);
	zassert_equal(
		test_case.expected.second_decision,
		PQCP_RUNTIME_POLICY_ALLOW);
	zassert_equal(test_case.expected.terminal_error, 0);
	zassert_ok(pqcp_operation_scenario_replay(
		&test_case, &replay));
	zassert_equal(
		replay.second_condition,
		PQCP_RUNTIME_POLICY_RUNNING);

	zassert_ok(pqcp_operation_scenario_find(
		PQCP_OPERATION_SCENARIO_CHANNEL_POLICY,
		PQCP_CHANNEL_POLICY_ESTABLISHED,
		PQCP_CHANNEL_CONTROL_REKEY_PREPARE,
		PQCP_CHANNEL_CONTROL_REKEY_COMMIT,
		&test_case));
	zassert_equal(
		test_case.expected.second_condition,
		PQCP_CHANNEL_POLICY_REKEY_PREPARED);
	zassert_equal(
		test_case.expected.first_decision,
		PQCP_CHANNEL_POLICY_REQUIRE_REKEY);
	zassert_equal(
		test_case.expected.second_decision,
		PQCP_CHANNEL_POLICY_DENY);
	zassert_equal(
		test_case.expected.terminal_error,
		-EACCES);

	zassert_ok(pqcp_operation_scenario_find(
		PQCP_OPERATION_SCENARIO_CHANNEL_FAULT,
		PQCP_CHANNEL_FAULT_REPLAY,
		PQCP_CHANNEL_CONTROL_STREAM_OPEN,
		PQCP_CHANNEL_CONTROL_GOAWAY,
		&test_case));
	zassert_equal(
		test_case.expected.first_decision,
		PQCP_CHANNEL_FAULT_CLOSE_CHANNEL);
	zassert_equal(
		test_case.expected.first_next_state,
		PQCP_CHANNEL_POLICY_CLOSING);
	zassert_ok(pqcp_operation_scenario_verify(
		&test_case));
}

ZTEST(pqcp_operations, test_runtime_and_channel_guards)
{
	struct pqcp_runtime_guard_decision runtime;
	struct pqcp_channel_guard_decision channel;

	zassert_ok(pqcp_runtime_guard_audit());
	zassert_ok(pqcp_channel_guard_audit());

	zassert_ok(pqcp_runtime_guard_evaluate(
		PQCP_RUNTIME_POLICY_RUNNING,
		PQCP_RUNTIME_AUTHORIZATION_AUDITOR,
		PQCP_RUNTIME_CONTINUITY_HEALTHY,
		PQCP_RUNTIME_COMMAND_READ_SNAPSHOT,
		&runtime));
	zassert_true(runtime.allowed);
	zassert_equal(
		runtime.verdict,
		PQCP_RUNTIME_GUARD_ALLOW_READ_ONLY);

	zassert_ok(pqcp_runtime_guard_evaluate(
		PQCP_RUNTIME_POLICY_RUNNING,
		PQCP_RUNTIME_AUTHORIZATION_TOKEN_REVOKED,
		PQCP_RUNTIME_CONTINUITY_HEALTHY,
		PQCP_RUNTIME_COMMAND_SUBMIT_JOB,
		&runtime));
	zassert_false(runtime.allowed);
	zassert_equal(runtime.error, -EKEYREJECTED);

	zassert_ok(pqcp_channel_guard_evaluate(
		PQCP_CHANNEL_POLICY_ESTABLISHED,
		PQCP_CHANNEL_EPOCH_CURRENT,
		PQCP_CHANNEL_STREAM_CONDITION_FLOW_BLOCKED_LOCAL,
		PQCP_CHANNEL_CONTROL_STREAM_OPEN,
		&channel));
	zassert_false(channel.allowed);
	zassert_equal(
		channel.verdict,
		PQCP_CHANNEL_GUARD_DEFER);
	zassert_equal(channel.retry_after_ms, 25U);

	zassert_ok(pqcp_channel_guard_evaluate(
		PQCP_CHANNEL_POLICY_ESTABLISHED,
		PQCP_CHANNEL_EPOCH_CONFIRMATION_INVALID,
		PQCP_CHANNEL_STREAM_CONDITION_OPEN,
		PQCP_CHANNEL_CONTROL_STREAM_WINDOW,
		&channel));
	zassert_false(channel.allowed);
	zassert_equal(
		channel.verdict,
		PQCP_CHANNEL_GUARD_CLOSE);
	zassert_equal(
		channel.next_state,
		PQCP_CHANNEL_POLICY_CLOSING);
}

ZTEST(pqcp_operations, test_operation_transition_catalogs)
{
	struct pqcp_runtime_transition_trace runtime_trace;
	struct pqcp_channel_transition_trace channel_trace;
	struct pqcp_runtime_transition_replay_result runtime_result;
	struct pqcp_channel_transition_replay_result channel_result;
	uint64_t runtime_fingerprint;
	uint64_t channel_fingerprint;

	zassert_ok(pqcp_operation_transition_audit_all());
	zassert_equal(
		pqcp_runtime_transition_trace_count(),
		PQCP_OPERATION_TRANSITION_TRACES_PER_DOMAIN);
	zassert_equal(
		pqcp_channel_transition_trace_count(),
		PQCP_OPERATION_TRANSITION_TRACES_PER_DOMAIN);

	zassert_ok(pqcp_runtime_transition_trace_get(
		0U, &runtime_trace));
	zassert_ok(pqcp_runtime_transition_trace_replay(
		&runtime_trace, &runtime_result));
	zassert_equal(
		runtime_result.steps_replayed,
		PQCP_OPERATION_TRANSITION_STEPS_PER_TRACE);
	zassert_equal(
		runtime_result.fingerprint,
		runtime_trace.expected_fingerprint);

	zassert_ok(pqcp_channel_transition_trace_get(
		0U, &channel_trace));
	zassert_ok(pqcp_channel_transition_trace_replay(
		&channel_trace, &channel_result));
	zassert_equal(
		channel_result.steps_replayed,
		PQCP_OPERATION_TRANSITION_STEPS_PER_TRACE);
	zassert_equal(
		channel_result.fingerprint,
		channel_trace.expected_fingerprint);

	zassert_ok(pqcp_runtime_transition_trace_fingerprint(
		&runtime_fingerprint));
	zassert_ok(pqcp_channel_transition_trace_fingerprint(
		&channel_fingerprint));
	zassert_not_equal(runtime_fingerprint, 0U);
	zassert_not_equal(channel_fingerprint, 0U);
	zassert_not_equal(
		runtime_fingerprint, channel_fingerprint);
	zassert_not_equal(
		strcmp(
			pqcp_operation_transition_domain_str(
				PQCP_OPERATION_TRANSITION_RUNTIME),
			"unknown"),
		0);
}

ZTEST(pqcp_operations, test_resource_governor_lifecycle)
{
	struct pqcp_runtime_resource_governor governor;
	struct pqcp_runtime_resource_budget budget;
	const struct pqcp_runtime_resource_usage one_job = {
		.jobs = 1U,
		.workspaces = 1U,
		.workspace_bytes = 1024U,
	};
	uint64_t first;
	uint64_t second;
	uint32_t expired;

	zassert_ok(pqcp_runtime_resource_budget_default(&budget));
	budget.maximum_jobs = 2U;
	budget.maximum_keys = 2U;
	budget.maximum_sessions = 2U;
	budget.maximum_workspaces = 2U;
	budget.maximum_workspace_bytes = 2048U;
	budget.elevated_threshold_bps = 5000U;
	budget.high_threshold_bps = 7500U;
	budget.critical_threshold_bps = 9000U;
	zassert_ok(pqcp_runtime_resource_governor_init(
		&governor, &budget, reservations,
		ARRAY_SIZE(reservations)));

	zassert_ok(pqcp_runtime_resource_reserve(
		&governor, 1U, &one_job,
		1000U, 2000U, &first));
	zassert_equal(
		governor.pressure,
		PQCP_RUNTIME_PRESSURE_ELEVATED);
	zassert_ok(pqcp_runtime_resource_commit(
		&governor, first));

	zassert_ok(pqcp_runtime_resource_reserve(
		&governor, 2U, &one_job,
		1100U, 1200U, &second));
	zassert_equal(
		governor.pressure,
		PQCP_RUNTIME_PRESSURE_CRITICAL);
	zassert_equal(pqcp_runtime_resource_reserve(
		&governor, 3U, &one_job,
		1100U, 1300U, &second), -EDQUOT);

	zassert_ok(pqcp_runtime_resource_tick(
		&governor, 1200U, &expired));
	zassert_equal(expired, 1U);
	zassert_equal(governor.expired, 1U);
	zassert_ok(pqcp_runtime_resource_release(
		&governor, first));
	zassert_equal(
		governor.pressure,
		PQCP_RUNTIME_PRESSURE_NORMAL);
	zassert_ok(
		pqcp_runtime_resource_governor_audit(
			&governor));
}

ZTEST(pqcp_operations, test_event_chain_and_subscription)
{
	struct pqcp_runtime_event_bus bus;
	struct pqcp_runtime_event_filter filter = {
		.kind_mask_low =
			BIT(PQCP_RUNTIME_EVENT_JOB_COMPLETED),
		.severity_mask =
			BIT(PQCP_RUNTIME_EVENT_INFO),
	};
	struct pqcp_runtime_event event = {
		.kind = PQCP_RUNTIME_EVENT_JOB_COMPLETED,
		.severity = PQCP_RUNTIME_EVENT_INFO,
		.subject_id = 42U,
		.result = 0,
		.value = 7U,
		.profile_id = "hybrid768-65-runtime",
		.detail = "operation-complete",
	};
	struct pqcp_runtime_event read_back;
	uint64_t sequence;
	size_t subscription_id;
	uint32_t callback_count = 0U;

	zassert_ok(pqcp_runtime_event_bus_init(
		&bus, event_entries, ARRAY_SIZE(event_entries),
		event_subscriptions,
		ARRAY_SIZE(event_subscriptions)));
	zassert_ok(pqcp_runtime_event_subscribe(
		&bus, &filter, event_counter,
		&callback_count, &subscription_id));
	zassert_ok(pqcp_runtime_event_append(
		&bus, &event, &sequence));
	zassert_equal(sequence, 1U);
	event.subject_id++;
	zassert_ok(pqcp_runtime_event_append(
		&bus, &event, &sequence));
	zassert_equal(callback_count, 2U);
	zassert_ok(pqcp_runtime_event_read(
		&bus, 1U, &read_back));
	zassert_equal(read_back.subject_id, 42U);
	zassert_ok(pqcp_runtime_event_bus_verify(&bus));

	event_entries[1].detail[0] ^= 1;
	zassert_equal(
		pqcp_runtime_event_bus_verify(&bus),
		-EBADMSG);
	event_entries[1].detail[0] ^= 1;
	zassert_ok(pqcp_runtime_event_unsubscribe(
		&bus, subscription_id));
	zassert_ok(pqcp_runtime_event_bus_verify(&bus));
}

ZTEST(pqcp_operations, test_scheduler_dispatch_and_deadline)
{
	struct pqcp_runtime_scheduler scheduler;
	struct pqcp_runtime_scheduler_policy policy;
	struct pqcp_runtime_scheduler_decision decision;
	struct pqcp_runtime_job expired = {
		.schema_version = PQCP_RUNTIME_SCHEMA_VERSION,
		.job_id = 1U,
		.profile_id = "hybrid768-65-runtime",
	};
	struct pqcp_runtime_job ready = {
		.schema_version = PQCP_RUNTIME_SCHEMA_VERSION,
		.job_id = 2U,
		.profile_id = "hybrid768-65-runtime",
	};
	uint64_t now_ms = (uint64_t)k_uptime_get();

	if (now_ms == 0U) {
		now_ms = 1U;
	}
	expired.deadline_ms = now_ms;
	ready.deadline_ms = now_ms + 1000U;
	zassert_ok(
		pqcp_runtime_scheduler_policy_default(&policy));
	zassert_ok(pqcp_runtime_scheduler_init(
		&scheduler, &policy,
		scheduler_entries,
		ARRAY_SIZE(scheduler_entries),
		scheduler_tenants,
		ARRAY_SIZE(scheduler_tenants)));
	zassert_ok(pqcp_runtime_scheduler_configure_tenant(
		&scheduler, 1U, 1U, true));
	zassert_ok(pqcp_runtime_scheduler_configure_tenant(
		&scheduler, 2U, 2U, true));
	zassert_ok(pqcp_runtime_scheduler_submit(
		&scheduler, &expired,
		PQCP_RUNTIME_SCHEDULER_DEFAULT,
		1U, 1U, 0U));
	zassert_ok(pqcp_runtime_scheduler_submit(
		&scheduler, &ready,
		PQCP_RUNTIME_SCHEDULER_INTERACTIVE,
		2U, 1U, 0U));

	zassert_ok(pqcp_runtime_scheduler_select(
		&scheduler, now_ms, &decision));
	zassert_equal(expired.result, -ETIMEDOUT);
	zassert_equal(
		expired.status,
		PQCP_RUNTIME_STATUS_FAILED);
	zassert_equal(decision.job, &ready);
	zassert_equal(
		decision.reason,
		PQCP_RUNTIME_SCHEDULER_REASON_SELECTED);
	zassert_ok(pqcp_runtime_scheduler_complete(
		&scheduler, &decision, 0, now_ms + 1U));
	zassert_equal(
		ready.status,
		PQCP_RUNTIME_STATUS_COMPLETED);
	zassert_ok(pqcp_runtime_scheduler_audit(&scheduler));
}

ZTEST(pqcp_operations, test_control_codec_detects_tampering)
{
	struct pqcp_channel_control_message message = {
		.schema_version =
			PQCP_CHANNEL_OPERATION_SCHEMA_VERSION,
		.kind = PQCP_CHANNEL_CONTROL_STREAM_OPEN,
		.flags = 3U,
		.message_id = 7U,
		.timestamp_ms = 1000U,
		.stream_id = 9U,
		.value = 4096U,
		.payload = { 1U, 2U, 3U, 4U },
		.payload_length = 4U,
	};
	struct pqcp_channel_control_message decoded;
	uint8_t encoded[PQCP_CHANNEL_CONTROL_MAX_BYTES + 128U];
	size_t encoded_length;

	zassert_ok(pqcp_channel_control_encode(
		&message, encoded, sizeof(encoded),
		&encoded_length));
	zassert_ok(pqcp_channel_control_decode(
		encoded, encoded_length, &decoded));
	zassert_equal(decoded.kind, message.kind);
	zassert_equal(decoded.stream_id, message.stream_id);
	zassert_mem_equal(
		decoded.payload, message.payload,
		message.payload_length);

	encoded[56] ^= 1U;
	zassert_equal(pqcp_channel_control_decode(
		encoded, encoded_length, &decoded), -EBADMSG);
}

ZTEST(pqcp_operations, test_flow_control_updates_windows)
{
	struct pqcp_channel_flow_controller controller;
	struct pqcp_channel_flow_policy policy;
	struct pqcp_channel_stream stream = {
		.stream_id = 1U,
		.state = PQCP_CHANNEL_STREAM_OPEN,
		.occupied = true,
	};
	uint32_t connection_credit;
	uint32_t stream_credit;

	zassert_ok(pqcp_channel_flow_policy_default(&policy));
	stream.local_window = policy.initial_stream_window;
	stream.remote_window = policy.initial_stream_window;
	zassert_ok(pqcp_channel_flow_init(
		&controller, &policy));
	zassert_ok(pqcp_channel_flow_reserve_send(
		&controller, &stream, 1024U));
	zassert_equal(
		stream.remote_window,
		policy.initial_stream_window - 1024U);
	zassert_ok(pqcp_channel_flow_consume_receive(
		&controller, &stream,
		policy.initial_stream_window -
			policy.update_threshold + 1U,
		&connection_credit, &stream_credit));
	zassert_equal(connection_credit, 0U);
	zassert_not_equal(stream_credit, 0U);
	zassert_ok(pqcp_channel_flow_apply_update(
		&controller, &stream, 1024U, 1024U));
	zassert_ok(pqcp_channel_flow_audit(&controller));
}

ZTEST(pqcp_operations, test_path_manager_migrates_to_better_path)
{
	struct pqcp_channel_path_manager manager;
	struct pqcp_channel_path_policy policy;
	struct pqcp_channel_path *first;
	struct pqcp_channel_path *second;
	uint32_t selected;

	zassert_ok(pqcp_channel_path_policy_default(&policy));
	zassert_ok(pqcp_channel_path_manager_init(
		&manager, &policy, paths, ARRAY_SIZE(paths)));
	zassert_ok(pqcp_channel_path_begin_probe(
		&manager, 11U, 1U, 1000U, &first));
	zassert_ok(pqcp_channel_path_validate(
		&manager, first->path_id, 11U,
		5000U, 1100U));
	zassert_equal(
		manager.active_path_id,
		first->path_id);

	zassert_ok(pqcp_channel_path_begin_probe(
		&manager, 22U, 1U, 1200U, &second));
	zassert_ok(pqcp_channel_path_validate(
		&manager, second->path_id, 22U,
		1000U, 1300U));
	zassert_equal(
		manager.active_path_id,
		second->path_id);
	zassert_equal(manager.migrations, 1U);
	zassert_ok(pqcp_channel_path_record_io(
		&manager, second->path_id,
		1400U, 128U, 256U));
	zassert_ok(pqcp_channel_path_select(
		&manager, 1500U, &selected));
	zassert_equal(selected, second->path_id);
	zassert_ok(
		pqcp_channel_path_manager_audit(&manager));
}

ZTEST(pqcp_operations, test_path_manager_selects_without_active_path)
{
	struct pqcp_channel_path_manager manager;
	struct pqcp_channel_path_policy policy;
	struct pqcp_channel_path *first;
	struct pqcp_channel_path *second;
	uint32_t selected;

	zassert_ok(pqcp_channel_path_policy_default(&policy));
	policy.allow_automatic_migration = false;
	zassert_ok(pqcp_channel_path_manager_init(
		&manager, &policy, paths, ARRAY_SIZE(paths)));
	zassert_ok(pqcp_channel_path_begin_probe(
		&manager, 31U, 1U, 1000U, &first));
	zassert_ok(pqcp_channel_path_validate(
		&manager, first->path_id, 31U,
		5000U, 1100U));
	zassert_ok(pqcp_channel_path_begin_probe(
		&manager, 32U, 1U, 1200U, &second));
	zassert_ok(pqcp_channel_path_validate(
		&manager, second->path_id, 32U,
		1000U, 1300U));

	zassert_equal(
		pqcp_channel_path_fail(
			&manager, first->path_id, 1400U),
		-EHOSTUNREACH);
	zassert_equal(manager.active_path_id, 0U);
	manager.policy.allow_automatic_migration = true;
	zassert_ok(pqcp_channel_path_select(
		&manager, 1500U, &selected));
	zassert_equal(selected, second->path_id);
	zassert_equal(
		manager.active_path_id,
		second->path_id);
	zassert_ok(
		pqcp_channel_path_manager_audit(&manager));
}

ZTEST(pqcp_operations, test_peer_health_timeout_and_recovery)
{
	struct pqcp_channel_peer_policy policy;
	struct pqcp_channel_peer_health health;

	zassert_ok(pqcp_channel_peer_policy_default(&policy));
	zassert_ok(pqcp_channel_peer_health_init(
		&health, &policy, 1000U));
	zassert_false(pqcp_channel_peer_probe_due(
		&health, &policy, 2000U));
	zassert_true(pqcp_channel_peer_probe_due(
		&health, &policy,
		1000U + policy.keepalive_interval_ms));
	zassert_ok(pqcp_channel_peer_probe_sent(
		&health,
		1000U + policy.keepalive_interval_ms));
	zassert_ok(pqcp_channel_peer_tick(
		&health, &policy,
		1000U + policy.keepalive_interval_ms +
			policy.keepalive_timeout_ms));
	zassert_equal(
		health.status,
		PQCP_CHANNEL_PEER_SUSPECT);
	zassert_ok(pqcp_channel_peer_record_io(
		&health,
		1000U + policy.keepalive_interval_ms +
			policy.keepalive_timeout_ms + 1U,
		0U, 64U));
	zassert_equal(
		health.status,
		PQCP_CHANNEL_PEER_HEALTHY);
	zassert_ok(pqcp_channel_peer_health_audit(
		&health, &policy));
}

ZTEST(pqcp_operations,
      test_checkpoint_command_metrics_and_orchestrator)
{
	struct pqcp_runtime_checkpoint_slot slots[2] = {
		{
			.buffer = checkpoint_buffers[0],
			.capacity = sizeof(checkpoint_buffers[0]),
		},
		{
			.buffer = checkpoint_buffers[1],
			.capacity = sizeof(checkpoint_buffers[1]),
		},
	};
	struct pqcp_runtime_checkpoint_store checkpoints;
	struct pqcp_runtime_checkpoint_header header;
	struct pqcp_runtime_checkpoint_header decoded_header;
	struct pqcp_runtime_event_bus events;
	struct pqcp_runtime_scheduler scheduler;
	struct pqcp_runtime_scheduler_policy scheduler_policy;
	struct pqcp_runtime_command_router router;
	struct pqcp_runtime_command_handler
		handlers[COMMAND_HANDLERS];
	struct pqcp_runtime_command_cache_entry
		cache[COMMAND_CACHE];
	struct pqcp_runtime_metrics metrics;
	struct pqcp_runtime_slo_policy slo_policy;
	struct pqcp_runtime_slo_report slo_report;
	struct pqcp_runtime_orchestrator orchestrator;
	struct pqcp_runtime_command command = {
		.schema_version =
			PQCP_RUNTIME_OPERATION_SCHEMA_VERSION,
		.command_id = 1U,
		.issued_at_ms = 1U,
		.kind = PQCP_RUNTIME_COMMAND_READ_SNAPSHOT,
		.owner = "operations-test",
		.profile_id = "hybrid768-65-runtime",
	};
	struct pqcp_runtime_command_result result;
	struct pqcp_runtime_metric_sample sample = {
		.schema_version =
			PQCP_RUNTIME_OPERATION_SCHEMA_VERSION,
		.kind = PQCP_RUNTIME_METRIC_QUEUE_WAIT_US,
		.timestamp_ms = 2000U,
		.value = 1U,
		.subject_id = 1U,
		.profile_id = "hybrid768-65-runtime",
		.success = true,
	};
	uint8_t checkpoint[CHECKPOINT_SLOT_BYTES];
	size_t checkpoint_length;

	reset_service();
	zassert_ok(pqcp_runtime_event_bus_init(
		&events, event_entries, ARRAY_SIZE(event_entries),
		event_subscriptions,
		ARRAY_SIZE(event_subscriptions)));
	zassert_ok(
		pqcp_runtime_scheduler_policy_default(
			&scheduler_policy));
	zassert_ok(pqcp_runtime_scheduler_init(
		&scheduler, &scheduler_policy,
		scheduler_entries,
		ARRAY_SIZE(scheduler_entries),
		scheduler_tenants,
		ARRAY_SIZE(scheduler_tenants)));
	zassert_ok(pqcp_runtime_checkpoint_store_init(
		&checkpoints, slots, ARRAY_SIZE(slots)));
	zassert_ok(pqcp_runtime_command_router_init(
		&router, &service, &events,
		handlers, ARRAY_SIZE(handlers),
		cache, ARRAY_SIZE(cache), NULL, NULL));
	zassert_ok(pqcp_runtime_slo_policy_default(
		&slo_policy));
	zassert_ok(pqcp_runtime_metrics_init(
		&metrics, &slo_policy));
	zassert_ok(pqcp_runtime_orchestrator_init(
		&orchestrator, &service, &events,
		&scheduler, &checkpoints, &router,
		&metrics, 1000U));

	zassert_ok(pqcp_runtime_command_execute(
		&router, &command, &result));
	zassert_false(result.replayed);
	zassert_ok(pqcp_runtime_command_execute(
		&router, &command, &result));
	zassert_true(result.replayed);

	zassert_ok(pqcp_runtime_orchestrator_checkpoint(
		&orchestrator, 2000U, 0x5aU, &header));
	zassert_equal(
		header.header_bytes,
		PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES);
	zassert_ok(pqcp_runtime_checkpoint_read(
		&checkpoints, header.generation,
		checkpoint, sizeof(checkpoint),
		&checkpoint_length, &decoded_header));
	zassert_equal(
		decoded_header.generation,
		header.generation);
	zassert_ok(pqcp_runtime_checkpoint_verify(
		checkpoint, checkpoint_length,
		&decoded_header));
	checkpoint[
		PQCP_RUNTIME_CHECKPOINT_HEADER_BYTES] ^= 1U;
	zassert_equal(pqcp_runtime_checkpoint_verify(
		checkpoint, checkpoint_length,
		&decoded_header), -EBADMSG);

	for (uint32_t index = 0U; index < 4U; ++index) {
		sample.subject_id = index + 1U;
		sample.timestamp_ms += 1U;
		zassert_ok(pqcp_runtime_metrics_observe(
			&metrics, &sample));
	}
	zassert_ok(pqcp_runtime_metrics_report(
		&metrics, 3000U, &slo_report));
	zassert_equal(
		slo_report.status,
		PQCP_RUNTIME_SLO_PASS);
	zassert_ok(pqcp_runtime_orchestrator_audit(
		&orchestrator));
}

ZTEST(pqcp_operations, test_rekey_and_resumption_lifecycle)
{
	struct pqcp_channel channel;
	struct pqcp_channel_rekey_policy rekey_policy;
	struct pqcp_channel_rekey_context rekey = {0};
	struct pqcp_channel_resumption_store resumption;
	struct pqcp_channel_ticket_replay_entry
		replay_entries[TICKET_REPLAY_ENTRIES];
	struct pqcp_channel_resumption_ticket ticket;
	struct pqcp_channel_resumption_claims claims;
	uint8_t salt[PQCP_CHANNEL_REKEY_SALT_BYTES];
	uint8_t secret[PQCP_CHANNEL_RESUMPTION_SECRET_BYTES];
	uint8_t peer_digest[PQCP_CHANNEL_HASH_BYTES];
	struct pqcp_runtime_key_handle old_client_key;

	zassert_equal(psa_crypto_init(), PSA_SUCCESS);
	reset_service();
	initialize_fake_channel(&channel);
	for (size_t index = 0U; index < sizeof(salt); ++index) {
		salt[index] = (uint8_t)(0xa0U + index);
		secret[index] = (uint8_t)(0x20U + index);
		peer_digest[index] = (uint8_t)(0x60U + index);
	}
	old_client_key = channel.keys.client_write_key;

	zassert_ok(pqcp_channel_rekey_policy_default(
		&rekey_policy));
	zassert_ok(pqcp_channel_rekey_prepare(
		&channel, &rekey_policy, &rekey,
		1000U, 1U, salt, true));
	zassert_equal(
		rekey.state,
		PQCP_CHANNEL_REKEY_PREPARED);
	zassert_ok(pqcp_channel_rekey_accept(
		&channel, &rekey,
		rekey.expected_peer_confirmation, 1100U));
	zassert_ok(pqcp_channel_rekey_commit(
		&channel, &rekey, 1200U));
	zassert_equal(rekey.current_epoch, 1U);
	zassert_false(pqcp_runtime_key_handle_equal(
		&old_client_key,
		&channel.keys.client_write_key));
	zassert_ok(pqcp_channel_rekey_audit(
		&channel, &rekey));

	zassert_ok(pqcp_channel_resumption_store_init(
		&resumption, secret,
		replay_entries, ARRAY_SIZE(replay_entries)));
	zassert_ok(pqcp_channel_resumption_issue(
		&resumption, &channel, peer_digest,
		2000U, 5000U, &ticket));
	zassert_ok(pqcp_channel_resumption_accept(
		&resumption, &ticket, 2100U, &claims));
	zassert_equal(
		claims.original_session_id,
		channel.config.session_id);
	zassert_mem_equal(
		claims.peer_identity_digest,
		peer_digest, sizeof(peer_digest));
	zassert_equal(pqcp_channel_resumption_accept(
		&resumption, &ticket, 2200U, &claims),
		-EALREADY);
	zassert_ok(pqcp_channel_resumption_store_audit(
		&resumption));
}

ZTEST(pqcp_operations, test_two_peer_rekey_cutover)
{
	static struct pqcp_channel client;
	static struct pqcp_channel server;
	static struct pqcp_channel_memory_pipe client_to_server;
	static struct pqcp_channel_memory_pipe server_to_client;
	static struct pqcp_channel_memory_endpoint client_endpoint;
	static struct pqcp_channel_memory_endpoint server_endpoint;
	static uint8_t client_to_server_bytes[4096];
	static uint8_t server_to_client_bytes[4096];
	static struct pqcp_channel_multiplexer client_mux;
	static struct pqcp_channel_multiplexer server_mux;
	static struct pqcp_channel_stream client_streams[2];
	static struct pqcp_channel_stream server_streams[2];
	static struct pqcp_channel_flow_controller client_flow;
	static struct pqcp_channel_flow_controller server_flow;
	static struct pqcp_channel_rekey_context client_rekey;
	static struct pqcp_channel_rekey_context server_rekey;
	static struct pqcp_channel_resumption_store client_resumption;
	static struct pqcp_channel_resumption_store server_resumption;
	static struct pqcp_channel_ticket_replay_entry
		client_replay[TICKET_REPLAY_ENTRIES];
	static struct pqcp_channel_ticket_replay_entry
		server_replay[TICKET_REPLAY_ENTRIES];
	static struct pqcp_channel_peer_health client_peer;
	static struct pqcp_channel_peer_health server_peer;
	static struct pqcp_channel_operations client_operations;
	static struct pqcp_channel_operations server_operations;
	struct pqcp_channel_flow_policy flow_policy;
	struct pqcp_channel_peer_policy peer_policy;
	struct pqcp_channel_rekey_policy rekey_policy;
	struct pqcp_channel_control_message received;
	struct pqcp_runtime_key_handle old_client_write;
	struct pqcp_runtime_key_handle old_server_write;
	uint8_t resumption_secret[
		PQCP_CHANNEL_RESUMPTION_SECRET_BYTES];
	uint8_t exporter[PQCP_CHANNEL_EXPORTER_BYTES];
	uint8_t plaintext[] = "post-rekey application record";
	uint8_t output[sizeof(plaintext)];
	size_t output_length = 0U;
	int ret;

	zassert_equal(psa_crypto_init(), PSA_SUCCESS);
	reset_service();
	initialize_fake_channel(&client);
	initialize_fake_channel(&server);
	server.config.role = PQCP_CHANNEL_ROLE_SERVER;
	client.config.timeout_ms = 100U;
	server.config.timeout_ms = 100U;
	old_client_write = client.keys.client_write_key;
	old_server_write = server.keys.server_write_key;
	memcpy(exporter, client.keys.exporter, sizeof(exporter));
	for (size_t index = 0U;
	     index < sizeof(resumption_secret); ++index) {
		resumption_secret[index] =
			(uint8_t)(0xc0U + index);
	}

	zassert_ok(pqcp_channel_memory_pipe_init(
		&client_to_server, client_to_server_bytes,
		sizeof(client_to_server_bytes)));
	zassert_ok(pqcp_channel_memory_pipe_init(
		&server_to_client, server_to_client_bytes,
		sizeof(server_to_client_bytes)));
	zassert_ok(pqcp_channel_memory_pair_init(
		&client_endpoint, &server_endpoint,
		&client_to_server, &server_to_client,
		exporter));
	zassert_ok(pqcp_channel_memory_make_transport(
		&client_endpoint, &client.transport));
	zassert_ok(pqcp_channel_memory_make_transport(
		&server_endpoint, &server.transport));

	zassert_ok(pqcp_channel_flow_policy_default(
		&flow_policy));
	zassert_ok(pqcp_channel_flow_init(
		&client_flow, &flow_policy));
	zassert_ok(pqcp_channel_flow_init(
		&server_flow, &flow_policy));
	zassert_ok(pqcp_channel_multiplexer_init(
		&client_mux, &client, client_streams,
		ARRAY_SIZE(client_streams),
		flow_policy.initial_connection_window,
		flow_policy.initial_stream_window));
	zassert_ok(pqcp_channel_multiplexer_init(
		&server_mux, &server, server_streams,
		ARRAY_SIZE(server_streams),
		flow_policy.initial_connection_window,
		flow_policy.initial_stream_window));
	zassert_ok(pqcp_channel_resumption_store_init(
		&client_resumption, resumption_secret,
		client_replay, ARRAY_SIZE(client_replay)));
	zassert_ok(pqcp_channel_resumption_store_init(
		&server_resumption, resumption_secret,
		server_replay, ARRAY_SIZE(server_replay)));
	zassert_ok(pqcp_channel_peer_policy_default(
		&peer_policy));
	peer_policy.keepalive_interval_ms = 60000U;
	peer_policy.keepalive_timeout_ms = 120000U;
	peer_policy.idle_timeout_ms = 180000U;
	zassert_ok(pqcp_channel_peer_health_init(
		&client_peer, &peer_policy, 1000U));
	zassert_ok(pqcp_channel_peer_health_init(
		&server_peer, &peer_policy, 1000U));
	zassert_ok(pqcp_channel_operations_init(
		&client_operations, &client, &client_mux,
		&client_flow, &client_rekey,
		&client_resumption, &client_peer,
		&peer_policy, 1000U));
	zassert_ok(pqcp_channel_operations_init(
		&server_operations, &server, &server_mux,
		&server_flow, &server_rekey,
		&server_resumption, &server_peer,
		&peer_policy, 1000U));
	zassert_ok(pqcp_channel_rekey_policy_default(
		&rekey_policy));
	rekey_policy.maximum_epoch_bytes = 1U;
	rekey_policy.handshake_timeout_ms = 10000U;
	client.application_bytes_sent = 1U;

	zassert_ok(pqcp_channel_operations_tick(
		&client_operations, &rekey_policy, 2000U));
	zassert_true(client.application_send_blocked);
	zassert_equal(pqcp_channel_send(
		&client, plaintext, sizeof(plaintext)),
		-EBUSY);

	zassert_ok(pqcp_channel_operations_receive_control(
		&server_operations, &received, 2010U));
	zassert_equal(received.kind,
		PQCP_CHANNEL_CONTROL_REKEY_PREPARE);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 2020U));
	zassert_equal(received.kind,
		PQCP_CHANNEL_CONTROL_REKEY_ACCEPT);
	zassert_ok(pqcp_channel_operations_receive_control(
		&server_operations, &received, 2030U));
	zassert_equal(received.value, 1U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 2040U));
	zassert_equal(received.value, 2U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&server_operations, &received, 2050U));
	zassert_equal(received.value, 3U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 2060U));
	zassert_equal(received.value, 4U);

	zassert_equal(client_rekey.current_epoch, 2U);
	zassert_equal(server_rekey.current_epoch, 2U);
	zassert_equal(client_rekey.state,
		PQCP_CHANNEL_REKEY_COMMITTED);
	zassert_equal(server_rekey.state,
		PQCP_CHANNEL_REKEY_COMMITTED);
	zassert_false(client.application_send_blocked);
	zassert_false(server.application_send_blocked);
	zassert_false(pqcp_runtime_key_handle_equal(
		&old_client_write,
		&client.keys.client_write_key));
	zassert_false(pqcp_runtime_key_handle_equal(
		&old_server_write,
		&server.keys.server_write_key));

	zassert_ok(pqcp_channel_send(
		&client, plaintext, sizeof(plaintext)));
	zassert_ok(pqcp_channel_receive(
		&server, output, sizeof(output),
		&output_length));
	zassert_equal(output_length, sizeof(plaintext));
	zassert_mem_equal(
		output, plaintext, sizeof(plaintext));
	zassert_ok(pqcp_channel_rekey_audit(
		&client, &client_rekey));
	zassert_ok(pqcp_channel_rekey_audit(
		&server, &server_rekey));
	zassert_ok(pqcp_channel_multiplexer_audit(
		&client_mux));
	zassert_ok(pqcp_channel_multiplexer_audit(
		&server_mux));

	/*
	 * Start the next epoch from both sides.  The client proposal wins,
	 * while queued duplicate PREPARE/ACCEPT/REQUEST/ACK/ACTIVATE records
	 * exercise idempotent recovery at every cutover phase.
	 */
	rekey_policy.maximum_epoch_ms = 1U;
	rekey_policy.minimum_interval_ms = 1U;
	zassert_true(pqcp_channel_rekey_due(
		&server, &rekey_policy, 33002U,
		server_operations.epoch_started_at_ms,
		server_operations.epoch_started_bytes));
	zassert_ok(pqcp_channel_operations_tick(
		&client_operations, &rekey_policy, 33001U));
	zassert_ok(pqcp_channel_operations_tick(
		&server_operations, &rekey_policy, 33002U));
	zassert_equal(server_rekey.state,
		PQCP_CHANNEL_REKEY_PREPARED,
		"server state=%u policy=%u phase=%u cleanup=%u pending_cleanup=%u expires=%llu epoch_start=%llu",
		server_rekey.state, server_operations.state,
		server_operations.rekey_phase,
		server_rekey.cleanup_pending,
		server_rekey.pending_cleanup,
		(unsigned long long)server_rekey.expires_at_ms,
		(unsigned long long)
			server_operations.epoch_started_at_ms);
	zassert_true(server_rekey.initiator);
	zassert_equal(server_rekey.pending_epoch, 3U);
	ret = pqcp_channel_operations_receive_control(
		&server_operations, &received, 33010U);
	zassert_equal(ret, 0,
		      "server collision receive failed: %d state=%u cleanup=%u pending_cleanup=%u",
		      ret, server_rekey.state,
		      server_rekey.cleanup_pending,
		      server_rekey.pending_cleanup);
	zassert_equal(received.kind,
		PQCP_CHANNEL_CONTROL_REKEY_PREPARE);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 33020U));
	zassert_equal(received.kind,
		PQCP_CHANNEL_CONTROL_REKEY_PREPARE);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 33030U));
	zassert_equal(received.kind,
		PQCP_CHANNEL_CONTROL_REKEY_ACCEPT);
	zassert_ok(pqcp_channel_operations_receive_control(
		&server_operations, &received, 33040U));
	zassert_equal(received.kind,
		PQCP_CHANNEL_CONTROL_REKEY_PREPARE);
	zassert_ok(pqcp_channel_operations_receive_control(
		&server_operations, &received, 33050U));
	zassert_equal(received.value, 1U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 33060U));
	zassert_equal(received.kind,
		PQCP_CHANNEL_CONTROL_REKEY_ACCEPT);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 33070U));
	zassert_equal(received.value, 2U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&server_operations, &received, 33080U));
	zassert_equal(received.value, 1U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&server_operations, &received, 33090U));
	zassert_equal(received.value, 3U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 33100U));
	zassert_equal(received.value, 2U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 33110U));
	zassert_equal(received.value, 4U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&server_operations, &received, 33120U));
	zassert_equal(received.value, 3U);
	zassert_ok(pqcp_channel_operations_receive_control(
		&client_operations, &received, 33130U));
	zassert_equal(received.value, 4U);
	zassert_equal(client_rekey.current_epoch, 3U);
	zassert_equal(server_rekey.current_epoch, 3U);
	zassert_false(client.application_send_blocked);
	zassert_false(server.application_send_blocked);
	zassert_ok(pqcp_channel_rekey_audit(
		&client, &client_rekey));
	zassert_ok(pqcp_channel_rekey_audit(
		&server, &server_rekey));
}

ZTEST_SUITE(pqcp_operations, NULL, NULL, NULL, NULL, NULL);
