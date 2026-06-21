/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/protected_channel_journal.h>
#include <pqcp_zephyr/protected_channel_memory.h>
#include <pqcp_zephyr/protected_channel_policy.h>
#include <pqcp_zephyr/runtime_service.h>

#define PIPE_BYTES 9000U
#define JOURNAL_ENTRIES 8U
#define HANDSHAKE_KEYS 10U
#define HANDSHAKE_WORKSPACES 2U
#define HANDSHAKE_WORKSPACE_BYTES 49152U
#define HANDSHAKE_JOBS 8U
#define HANDSHAKE_SESSIONS 2U
#define HANDSHAKE_PROFILES 8U
#define HANDSHAKE_AUDIT_ENTRIES 16U
#define HANDSHAKE_IDENTITIES 4U
#define HANDSHAKE_QUOTAS 2U
#define HANDSHAKE_STACK_BYTES 131072U

static uint8_t client_to_server_bytes[PIPE_BYTES];
static uint8_t server_to_client_bytes[PIPE_BYTES];
static struct pqcp_channel_memory_pipe client_to_server;
static struct pqcp_channel_memory_pipe server_to_client;
static struct pqcp_channel_memory_endpoint client_endpoint;
static struct pqcp_channel_memory_endpoint server_endpoint;
static struct pqcp_channel_transport client_transport;
static struct pqcp_channel_transport server_transport;
static struct pqcp_channel client;
static struct pqcp_channel server;

struct handshake_runtime_storage {
	struct pqcp_runtime_volatile_slot key_slots[HANDSHAKE_KEYS];
	struct pqcp_runtime_workspace_slot
		workspace_slots[HANDSHAKE_WORKSPACES];
	uint8_t workspace_bytes[
		HANDSHAKE_WORKSPACES * HANDSHAKE_WORKSPACE_BYTES];
	struct pqcp_runtime_queue_entry queue[HANDSHAKE_JOBS];
	struct pqcp_runtime_session sessions[HANDSHAKE_SESSIONS];
	struct pqcp_runtime_profile_state profiles[HANDSHAKE_PROFILES];
	struct pqcp_runtime_audit_entry
		audit_entries[HANDSHAKE_AUDIT_ENTRIES];
	struct pqcp_runtime_identity identities[HANDSHAKE_IDENTITIES];
	struct pqcp_runtime_admission_quota quotas[HANDSHAKE_QUOTAS];
};

static struct handshake_runtime_storage client_runtime_storage;
static struct handshake_runtime_storage server_runtime_storage;
static struct pqcp_runtime_service client_runtime;
static struct pqcp_runtime_service server_runtime;
static struct pqcp_adaptive_control_plane client_adaptive;
static struct pqcp_adaptive_control_plane server_adaptive;
static struct pqcp_channel handshake_client;
static struct pqcp_channel handshake_server;
static struct k_thread client_handshake_thread;
static struct k_thread server_handshake_thread;
K_THREAD_STACK_DEFINE(client_handshake_stack, HANDSHAKE_STACK_BYTES);
K_THREAD_STACK_DEFINE(server_handshake_stack, HANDSHAKE_STACK_BYTES);
static int client_handshake_result;
static int server_handshake_result;

static void initialize_runtime_service(
	struct pqcp_runtime_service *service,
	struct pqcp_adaptive_control_plane *adaptive,
	struct handshake_runtime_storage *runtime_storage,
	const char *device_id)
{
	const struct pqcp_runtime_service_storage storage = {
		.key_slots = runtime_storage->key_slots,
		.key_slot_count = ARRAY_SIZE(runtime_storage->key_slots),
		.workspace_slots = runtime_storage->workspace_slots,
		.workspace_bytes = runtime_storage->workspace_bytes,
		.workspace_slot_count =
			ARRAY_SIZE(runtime_storage->workspace_slots),
		.workspace_bytes_per_slot = HANDSHAKE_WORKSPACE_BYTES,
		.queue = runtime_storage->queue,
		.queue_capacity = ARRAY_SIZE(runtime_storage->queue),
		.sessions = runtime_storage->sessions,
		.session_capacity =
			ARRAY_SIZE(runtime_storage->sessions),
		.profile_states = runtime_storage->profiles,
		.profile_state_capacity =
			ARRAY_SIZE(runtime_storage->profiles),
		.audit_entries = runtime_storage->audit_entries,
		.audit_capacity =
			ARRAY_SIZE(runtime_storage->audit_entries),
		.identities = runtime_storage->identities,
		.identity_capacity =
			ARRAY_SIZE(runtime_storage->identities),
		.quotas = runtime_storage->quotas,
		.quota_capacity = ARRAY_SIZE(runtime_storage->quotas),
	};

	memset(runtime_storage, 0, sizeof(*runtime_storage));
	memset(service, 0, sizeof(*service));
	memset(adaptive, 0, sizeof(*adaptive));
	zassert_ok(pqcp_adaptive_control_init(
		adaptive, device_id, PQCP_ADAPTIVE_POLICY_GATEWAY,
		"hybrid768-65-runtime", 1000U));
	zassert_ok(pqcp_runtime_service_init(
		service, &storage, adaptive, 1000U));
}

static void client_handshake_entry(
	void *first, void *second, void *third)
{
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	client_handshake_result =
		pqcp_channel_handshake(first);
}

static void server_handshake_entry(
	void *first, void *second, void *third)
{
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	server_handshake_result =
		pqcp_channel_handshake(first);
}

static void install_record_key(
	struct pqcp_runtime_service *service,
	const uint8_t key[PQCP_CHANNEL_AEAD_KEY_BYTES],
	const char *label,
	struct pqcp_runtime_key_handle *handle)
{
	const struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_AEAD,
		.level = 256U,
		.usage = PQCP_RUNTIME_USAGE_ENCRYPT |
			 PQCP_RUNTIME_USAGE_DECRYPT |
			 PQCP_RUNTIME_USAGE_MAC |
			 PQCP_RUNTIME_USAGE_DERIVE |
			 PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = 1000U,
		.owner = "channel-test",
		.label = label,
		.persistent = false,
		.exportable_public = false,
	};

	zassert_ok(pqcp_runtime_key_store_create(
		&service->key_store, &request,
		NULL, 0U, key, PQCP_CHANNEL_AEAD_KEY_BYTES,
		handle));
}

static void initialize_record_pair(void)
{
	uint8_t exporter[PQCP_CHANNEL_EXPORTER_BYTES];
	uint8_t client_key[PQCP_CHANNEL_AEAD_KEY_BYTES];
	uint8_t server_key[PQCP_CHANNEL_AEAD_KEY_BYTES];

	for (size_t index = 0U; index < sizeof(exporter); ++index) {
		exporter[index] = (uint8_t)(0xa0U + index);
	}
	zassert_ok(pqcp_channel_memory_pipe_init(
		&client_to_server, client_to_server_bytes,
		sizeof(client_to_server_bytes)));
	zassert_ok(pqcp_channel_memory_pipe_init(
		&server_to_client, server_to_client_bytes,
		sizeof(server_to_client_bytes)));
	zassert_ok(pqcp_channel_memory_pair_init(
		&client_endpoint, &server_endpoint,
		&client_to_server, &server_to_client, exporter));
	zassert_ok(pqcp_channel_memory_make_transport(
		&client_endpoint, &client_transport));
	zassert_ok(pqcp_channel_memory_make_transport(
		&server_endpoint, &server_transport));
	memset(&client, 0, sizeof(client));
	memset(&server, 0, sizeof(server));
	client.schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	server.schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	client.config.schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	server.config.schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	client.config.role = PQCP_CHANNEL_ROLE_CLIENT;
	server.config.role = PQCP_CHANNEL_ROLE_SERVER;
	client.config.session_id = UINT64_C(0x1234567890abcdef);
	server.config.session_id = client.config.session_id;
	client.config.timeout_ms = 1000U;
	server.config.timeout_ms = 1000U;
	client.config.max_payload_bytes = PQCP_CHANNEL_MAX_PAYLOAD_BYTES;
	server.config.max_payload_bytes = PQCP_CHANNEL_MAX_PAYLOAD_BYTES;
	client.transport = client_transport;
	server.transport = server_transport;
	initialize_runtime_service(
		&client_runtime, &client_adaptive,
		&client_runtime_storage, "record-client");
	initialize_runtime_service(
		&server_runtime, &server_adaptive,
		&server_runtime_storage, "record-server");
	client.executor = &client_runtime.executor;
	client.key_store = &client_runtime.key_store;
	server.executor = &server_runtime.executor;
	server.key_store = &server_runtime.key_store;
	client.state = PQCP_CHANNEL_STATE_ESTABLISHED;
	server.state = PQCP_CHANNEL_STATE_ESTABLISHED;
	client.established = true;
	server.established = true;
	client.keys.traffic_keys_ready = true;
	server.keys.traffic_keys_ready = true;
	for (size_t index = 0U;
	     index < PQCP_CHANNEL_AEAD_KEY_BYTES; ++index) {
		client_key[index] = (uint8_t)(0x10U + index);
		server_key[index] = (uint8_t)(0x80U + index);
	}
	install_record_key(
		&client_runtime, client_key, "client-write",
		&client.keys.client_write_key);
	install_record_key(
		&client_runtime, server_key, "server-read",
		&client.keys.server_write_key);
	install_record_key(
		&server_runtime, client_key, "client-read",
		&server.keys.client_write_key);
	install_record_key(
		&server_runtime, server_key, "server-write",
		&server.keys.server_write_key);
	pqcp_runtime_secure_zero(client_key, sizeof(client_key));
	pqcp_runtime_secure_zero(server_key, sizeof(server_key));
	for (size_t index = 0U;
	     index < PQCP_CHANNEL_AEAD_NONCE_BYTES; ++index) {
		client.keys.client_nonce_base[index] =
			(uint8_t)(0x30U + index);
		server.keys.client_nonce_base[index] =
			client.keys.client_nonce_base[index];
		client.keys.server_nonce_base[index] =
			(uint8_t)(0x60U + index);
		server.keys.server_nonce_base[index] =
			client.keys.server_nonce_base[index];
	}
	zassert_ok(pqcp_channel_transcript_init(&client.transcript));
	zassert_ok(pqcp_channel_transcript_init(&server.transcript));
	zassert_ok(pqcp_channel_replay_reset(&client.inbound_replay));
	zassert_ok(pqcp_channel_replay_reset(&server.inbound_replay));
}

static void initialize_authenticated_pair(void)
{
	uint8_t exporter[PQCP_CHANNEL_EXPORTER_BYTES];
	struct pqcp_runtime_identity *client_identity;
	struct pqcp_runtime_identity *server_identity;
	struct pqcp_runtime_identity *pinned_identity;
	struct pqcp_channel_config client_config = {
		.schema_version = PQCP_CHANNEL_SCHEMA_VERSION,
		.role = PQCP_CHANNEL_ROLE_CLIENT,
		.session_id = UINT64_C(0xa11ce00000000001),
		.mlkem_level = 768U,
		.mldsa_level = 65U,
		.timeout_ms = 120000U,
		.max_payload_bytes = PQCP_CHANNEL_MAX_PAYLOAD_BYTES,
		.require_mutual_authentication = false,
		.profile_id = "hybrid768-65-runtime",
	};
	struct pqcp_channel_config server_config = client_config;

	server_config.role = PQCP_CHANNEL_ROLE_SERVER;
	for (size_t index = 0U; index < sizeof(exporter); ++index) {
		exporter[index] = (uint8_t)(0x55U ^ index);
	}
	initialize_runtime_service(
		&client_runtime, &client_adaptive,
		&client_runtime_storage, "channel-client");
	initialize_runtime_service(
		&server_runtime, &server_adaptive,
		&server_runtime_storage, "channel-server");
	zassert_ok(pqcp_runtime_identity_create_local(
		&client_runtime.identities, "client-local",
		65U, 2000U, 300000U, &client_identity));
	zassert_ok(pqcp_runtime_identity_create_local(
		&server_runtime.identities, "server-local",
		65U, 2000U, 300000U, &server_identity));
	zassert_ok(pqcp_runtime_identity_pin_peer(
		&client_runtime.identities, "server-peer", 65U,
		server_identity->peer_public_key,
		server_identity->peer_public_key_length,
		2000U, 300000U, &pinned_identity));
	zassert_ok(pqcp_runtime_identity_pin_peer(
		&server_runtime.identities, "client-peer", 65U,
		client_identity->peer_public_key,
		client_identity->peer_public_key_length,
		2000U, 300000U, &pinned_identity));
	zassert_ok(pqcp_runtime_identity_configure_channel(
		&client_runtime.identities, "client-local",
		"server-peer", &client_config));
	zassert_ok(pqcp_runtime_identity_configure_channel(
		&server_runtime.identities, "server-local",
		"client-peer", &server_config));
	zassert_ok(pqcp_channel_memory_pipe_init(
		&client_to_server, client_to_server_bytes,
		sizeof(client_to_server_bytes)));
	zassert_ok(pqcp_channel_memory_pipe_init(
		&server_to_client, server_to_client_bytes,
		sizeof(server_to_client_bytes)));
	zassert_ok(pqcp_channel_memory_pair_init(
		&client_endpoint, &server_endpoint,
		&client_to_server, &server_to_client, exporter));
	zassert_ok(pqcp_channel_memory_make_transport(
		&client_endpoint, &client_transport));
	zassert_ok(pqcp_channel_memory_make_transport(
		&server_endpoint, &server_transport));
	zassert_ok(pqcp_channel_init(
		&handshake_client, &client_config,
		&client_transport, &client_runtime.executor,
		&client_runtime.key_store));
	zassert_ok(pqcp_channel_init(
		&handshake_server, &server_config,
		&server_transport, &server_runtime.executor,
		&server_runtime.key_store));
}

ZTEST(pqcp_channel, test_frame_codec_and_replay_rejection)
{
	static const uint8_t payload[] = { 1U, 2U, 3U, 4U };
	struct pqcp_channel_frame_header header = {
		.magic = PQCP_CHANNEL_MAGIC,
		.schema_version = PQCP_CHANNEL_SCHEMA_VERSION,
		.type = PQCP_CHANNEL_FRAME_APPLICATION,
		.session_id = 7U,
		.sequence = 3U,
		.payload_length = sizeof(payload),
	};
	struct pqcp_channel_frame_header decoded;
	uint8_t encoded[128];
	const uint8_t *decoded_payload;
	size_t encoded_length;
	size_t decoded_length;
	struct pqcp_channel_replay_state replay;

	zassert_ok(pqcp_channel_frame_encode(
		&header, payload, sizeof(payload),
		encoded, sizeof(encoded), &encoded_length));
	zassert_ok(pqcp_channel_frame_decode(
		encoded, encoded_length, &decoded,
		&decoded_payload, &decoded_length));
	zassert_equal(decoded.sequence, 3U);
	zassert_equal(decoded_length, sizeof(payload));
	zassert_mem_equal(decoded_payload, payload, sizeof(payload));
	zassert_ok(pqcp_channel_replay_reset(&replay));
	zassert_ok(pqcp_channel_replay_accept(&replay, 3U));
	zassert_equal(pqcp_channel_replay_accept(&replay, 3U),
		      -EALREADY);
}

ZTEST(pqcp_channel, test_profile_negotiation_selects_compiled_pair)
{
	struct pqcp_runtime_capability capability = {
		.schema_version = PQCP_RUNTIME_SCHEMA_VERSION,
		.mlkem_level_mask = PQCP_BUILD_MLKEM_LEVEL_768,
		.mldsa_level_mask = PQCP_BUILD_MLDSA_LEVEL_65,
		.operation_mask = 0x7fU,
		.key_backend_mask = 1U,
		.max_jobs = 8U,
		.max_keys = 8U,
		.workspace_bytes = 49152U,
		.executable_runtime = true,
		.protected_channel = true,
	};
	struct pqcp_channel_profile_offer local[] = {
		{
			.schema_version = PQCP_CHANNEL_SCHEMA_VERSION,
			.profile_id = "hybrid768-65-runtime",
			.mlkem_level = 768U,
			.mldsa_level = 65U,
			.security_level = 3U,
			.evidence_score = 90U,
			.preference = 10U,
			.maximum_handshake_latency_us = 500000U,
			.maximum_workspace_bytes = 49152U,
			.enabled = true,
		},
	};
	struct pqcp_channel_profile_offer peer[] = { local[0] };
	struct pqcp_channel_policy policy;
	struct pqcp_channel_negotiation negotiation;

	zassert_ok(pqcp_channel_policy_default(&policy));
	zassert_ok(pqcp_channel_negotiate(
		&policy, &capability, local, ARRAY_SIZE(local),
		peer, ARRAY_SIZE(peer), NULL, &negotiation));
	zassert_true(negotiation.accepted);
	zassert_equal(negotiation.selected.mlkem_level, 768U);
	zassert_equal(negotiation.selected.mldsa_level, 65U);
	zassert_ok(pqcp_channel_negotiation_verify(
		&policy, &negotiation));
}

ZTEST(pqcp_channel, test_aead_record_exchange_and_tamper_failure)
{
	static const uint8_t message[] = "exporter-bound payload";
	uint8_t plaintext[64];
	size_t plaintext_length = 0U;

	initialize_record_pair();
	zassert_ok(pqcp_channel_send(
		&client, message, sizeof(message) - 1U));
	zassert_ok(pqcp_channel_receive(
		&server, plaintext, sizeof(plaintext),
		&plaintext_length));
	zassert_equal(plaintext_length, sizeof(message) - 1U);
	zassert_mem_equal(plaintext, message, plaintext_length);

	initialize_record_pair();
	zassert_ok(pqcp_channel_send(
		&client, message, sizeof(message) - 1U));
	zassert_ok(pqcp_channel_memory_tamper_next(
		&client_to_server,
		PQCP_CHANNEL_FRAME_HEADER_BYTES + 1U, 0x01U));
	zassert_not_equal(pqcp_channel_receive(
		&server, plaintext, sizeof(plaintext),
		&plaintext_length), 0);
	zassert_equal(server.state, PQCP_CHANNEL_STATE_FAILED);
}

ZTEST(pqcp_channel, test_journal_detects_tampering)
{
	struct pqcp_channel_journal_entry entries[JOURNAL_ENTRIES];
	struct pqcp_channel_journal journal;
	struct pqcp_channel_journal_snapshot snapshot;

	initialize_record_pair();
	strcpy(client.config.profile_id, "hybrid768-65-runtime");
	zassert_ok(pqcp_channel_journal_init(
		&journal, client.config.session_id,
		entries, ARRAY_SIZE(entries)));
	zassert_ok(pqcp_channel_journal_append(
		&journal, &client,
		PQCP_CHANNEL_JOURNAL_TLS_READY, 0,
		0U, 0U, 0, "tls-ready", 1000U));
	zassert_ok(pqcp_channel_journal_append(
		&journal, &client,
		PQCP_CHANNEL_JOURNAL_RECORD_SENT,
		PQCP_CHANNEL_FRAME_APPLICATION,
		0U, 32U, 0, "record", 1001U));
	zassert_ok(pqcp_channel_journal_snapshot(
		&journal, &snapshot));
	zassert_ok(pqcp_channel_journal_snapshot_verify(&snapshot));
	entries[0].detail[0] ^= 1;
	zassert_equal(pqcp_channel_journal_verify(&journal), -EBADMSG);
}

ZTEST(pqcp_channel, test_complete_native_handshake_and_records)
{
	static const uint8_t client_message[] =
		"client protected payload";
	static const uint8_t server_message[] =
		"server protected payload";
	uint8_t plaintext[64];
	size_t plaintext_length = 0U;

	initialize_authenticated_pair();
	client_handshake_result = -EINPROGRESS;
	server_handshake_result = -EINPROGRESS;
	k_thread_create(
		&server_handshake_thread, server_handshake_stack,
		K_THREAD_STACK_SIZEOF(server_handshake_stack),
		server_handshake_entry, &handshake_server,
		NULL, NULL, 5, 0, K_NO_WAIT);
	k_thread_create(
		&client_handshake_thread, client_handshake_stack,
		K_THREAD_STACK_SIZEOF(client_handshake_stack),
		client_handshake_entry, &handshake_client,
		NULL, NULL, 5, 0, K_NO_WAIT);
	zassert_ok(k_thread_join(
		&client_handshake_thread, K_SECONDS(120)));
	zassert_ok(k_thread_join(
		&server_handshake_thread, K_SECONDS(120)));
	printk("PQCP_CHANNEL_TEST client_ret=%d client_state=%s client_alert=%s client_sent=%llu client_received=%llu server_ret=%d server_state=%s server_alert=%s server_sent=%llu server_received=%llu\n",
	       client_handshake_result,
	       pqcp_channel_state_str(handshake_client.state),
	       pqcp_channel_alert_str(handshake_client.last_alert),
	       (unsigned long long)handshake_client.frames_sent,
	       (unsigned long long)handshake_client.frames_received,
	       server_handshake_result,
	       pqcp_channel_state_str(handshake_server.state),
	       pqcp_channel_alert_str(handshake_server.last_alert),
	       (unsigned long long)handshake_server.frames_sent,
	       (unsigned long long)handshake_server.frames_received);
	zassert_equal(client_handshake_result, 0,
		      "client handshake returned %d",
		      client_handshake_result);
	zassert_equal(server_handshake_result, 0,
		      "server handshake returned %d",
		      server_handshake_result);
	zassert_true(handshake_client.established);
	zassert_true(handshake_server.established);
	zassert_true(handshake_client.peer_authenticated);
	zassert_true(handshake_server.local_authenticated);
	zassert_ok(pqcp_channel_audit(&handshake_client));
	zassert_ok(pqcp_channel_audit(&handshake_server));

	zassert_ok(pqcp_channel_send(
		&handshake_client, client_message,
		sizeof(client_message) - 1U));
	zassert_ok(pqcp_channel_receive(
		&handshake_server, plaintext, sizeof(plaintext),
		&plaintext_length));
	zassert_equal(plaintext_length,
		      sizeof(client_message) - 1U);
	zassert_mem_equal(
		plaintext, client_message, plaintext_length);
	zassert_ok(pqcp_channel_send(
		&handshake_server, server_message,
		sizeof(server_message) - 1U));
	zassert_ok(pqcp_channel_receive(
		&handshake_client, plaintext, sizeof(plaintext),
		&plaintext_length));
	zassert_equal(plaintext_length,
		      sizeof(server_message) - 1U);
	zassert_mem_equal(
		plaintext, server_message, plaintext_length);
	zassert_ok(pqcp_channel_emit(&handshake_client));
	zassert_ok(pqcp_channel_emit(&handshake_server));
}

ZTEST_SUITE(pqcp_channel, NULL, NULL, NULL, NULL, NULL);
