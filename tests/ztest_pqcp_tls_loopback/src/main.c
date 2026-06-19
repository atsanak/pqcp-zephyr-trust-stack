/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/protected_channel_tls.h>
#include <pqcp_zephyr/runtime_service.h>

#define TLS_THREAD_STACK_BYTES 131072U
#define TLS_TIMEOUT_MS 30000U
#define TLS_PIPE_BYTES 32768U
#define RUNTIME_KEYS 10U
#define RUNTIME_WORKSPACES 2U
#define RUNTIME_WORKSPACE_BYTES 49152U
#define RUNTIME_JOBS 8U
#define RUNTIME_SESSIONS 2U
#define RUNTIME_PROFILES 8U
#define RUNTIME_AUDIT_ENTRIES 16U
#define RUNTIME_IDENTITIES 4U
#define RUNTIME_QUOTAS 2U

static const uint8_t loopback_psk[32] = {
	0x2d, 0x57, 0xb1, 0xa0, 0x9c, 0x63, 0x74, 0xe8,
	0xf5, 0x11, 0x6b, 0x0c, 0x47, 0x2e, 0xa9, 0x35,
	0x83, 0xcd, 0x16, 0x79, 0x20, 0x44, 0xde, 0x8a,
	0x6f, 0x32, 0x91, 0xbb, 0x05, 0xd7, 0xca, 0x4e,
};
static const uint8_t loopback_identity[] = "pqcp-qemu-loopback";

static struct pqcp_tls_endpoint client_endpoint;
static struct pqcp_tls_endpoint server_endpoint;
static struct k_thread client_thread;
static struct k_thread server_thread;
K_THREAD_STACK_DEFINE(client_stack, TLS_THREAD_STACK_BYTES);
K_THREAD_STACK_DEFINE(server_stack, TLS_THREAD_STACK_BYTES);
static int client_result;
static int server_result;

struct tls_pipe {
	uint8_t bytes[TLS_PIPE_BYTES];
	size_t read_offset;
	size_t write_offset;
	size_t used;
	struct k_mutex lock;
	struct k_sem data_ready;
};

struct tls_bio_endpoint {
	struct tls_pipe *incoming;
	struct tls_pipe *outgoing;
};

static struct tls_pipe client_to_server;
static struct tls_pipe server_to_client;
static struct tls_bio_endpoint client_bio;
static struct tls_bio_endpoint server_bio;

struct loopback_runtime_storage {
	struct pqcp_runtime_volatile_slot key_slots[RUNTIME_KEYS];
	struct pqcp_runtime_workspace_slot
		workspace_slots[RUNTIME_WORKSPACES];
	uint8_t workspace_bytes[
		RUNTIME_WORKSPACES * RUNTIME_WORKSPACE_BYTES];
	struct pqcp_runtime_queue_entry queue[RUNTIME_JOBS];
	struct pqcp_runtime_session sessions[RUNTIME_SESSIONS];
	struct pqcp_runtime_profile_state profiles[RUNTIME_PROFILES];
	struct pqcp_runtime_audit_entry audit_entries[RUNTIME_AUDIT_ENTRIES];
	struct pqcp_runtime_identity identities[RUNTIME_IDENTITIES];
	struct pqcp_runtime_admission_quota quotas[RUNTIME_QUOTAS];
};

static struct loopback_runtime_storage client_runtime_storage;
static struct loopback_runtime_storage server_runtime_storage;
static struct pqcp_runtime_service client_runtime;
static struct pqcp_runtime_service server_runtime;
static struct pqcp_adaptive_control_plane client_adaptive;
static struct pqcp_adaptive_control_plane server_adaptive;
static struct pqcp_channel client_channel;
static struct pqcp_channel server_channel;

static void tls_pipe_init(struct tls_pipe *pipe)
{
	memset(pipe, 0, sizeof(*pipe));
	k_mutex_init(&pipe->lock);
	k_sem_init(&pipe->data_ready, 0U, 1U);
}

static int tls_bio_send(
	void *context, const unsigned char *buffer, size_t length)
{
	struct tls_bio_endpoint *endpoint = context;
	struct tls_pipe *pipe = endpoint->outgoing;
	size_t writable;
	size_t contiguous;
	size_t chunk;

	if (k_mutex_lock(&pipe->lock, K_FOREVER) != 0) {
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
	}
	writable = sizeof(pipe->bytes) - pipe->used;
	if (writable == 0U) {
		(void)k_mutex_unlock(&pipe->lock);
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	contiguous = sizeof(pipe->bytes) - pipe->write_offset;
	chunk = MIN(length, MIN(writable, contiguous));
	memcpy(pipe->bytes + pipe->write_offset, buffer, chunk);
	pipe->write_offset =
		(pipe->write_offset + chunk) % sizeof(pipe->bytes);
	pipe->used += chunk;
	k_sem_give(&pipe->data_ready);
	(void)k_mutex_unlock(&pipe->lock);
	return (int)chunk;
}

static int tls_bio_receive_timeout(
	void *context, unsigned char *buffer, size_t length,
	uint32_t timeout_ms)
{
	struct tls_bio_endpoint *endpoint = context;
	struct tls_pipe *pipe = endpoint->incoming;
	const int64_t deadline = k_uptime_get() + timeout_ms;

	for (;;) {
		size_t contiguous;
		size_t chunk;

		if (k_mutex_lock(&pipe->lock, K_FOREVER) != 0) {
			return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
		}
		if (pipe->used != 0U) {
			contiguous =
				sizeof(pipe->bytes) - pipe->read_offset;
			chunk = MIN(length, MIN(pipe->used, contiguous));
			memcpy(buffer,
			       pipe->bytes + pipe->read_offset, chunk);
			memset(pipe->bytes + pipe->read_offset, 0, chunk);
			pipe->read_offset =
				(pipe->read_offset + chunk) %
				sizeof(pipe->bytes);
			pipe->used -= chunk;
			(void)k_mutex_unlock(&pipe->lock);
			return (int)chunk;
		}
		(void)k_mutex_unlock(&pipe->lock);
		if (timeout_ms == 0U) {
			return MBEDTLS_ERR_SSL_WANT_READ;
		}
		if (k_uptime_get() >= deadline) {
			return MBEDTLS_ERR_SSL_TIMEOUT;
		}
		(void)k_sem_take(&pipe->data_ready, K_MSEC(1));
	}
}

static int tls_bio_receive(
	void *context, unsigned char *buffer, size_t length)
{
	return tls_bio_receive_timeout(
		context, buffer, length, 0U);
}

static int stalled_bio_send(
	void *context, const unsigned char *buffer, size_t length)
{
	ARG_UNUSED(context);
	ARG_UNUSED(buffer);
	ARG_UNUSED(length);
	return MBEDTLS_ERR_SSL_WANT_WRITE;
}

static int stalled_bio_receive(
	void *context, unsigned char *buffer, size_t length)
{
	ARG_UNUSED(context);
	ARG_UNUSED(buffer);
	ARG_UNUSED(length);
	return MBEDTLS_ERR_SSL_WANT_READ;
}

ZTEST(pqcp_tls_loopback, test_tls_handshake_honors_deadline)
{
	struct pqcp_tls_endpoint endpoint;
	uint8_t context = 0U;
	int64_t started_at;
	int ret;

	zassert_ok(pqcp_tls_endpoint_init_psk(
		&endpoint, PQCP_CHANNEL_ROLE_CLIENT,
		loopback_psk, sizeof(loopback_psk),
		loopback_identity, sizeof(loopback_identity) - 1U));
	started_at = k_uptime_get();
	ret = pqcp_tls_endpoint_handshake_bio(
		&endpoint, &context, stalled_bio_send,
		stalled_bio_receive, NULL, 20U);
	zassert_equal(ret, -ETIMEDOUT);
	zassert_true(k_uptime_get() - started_at >= 20);
	zassert_true(k_uptime_get() - started_at < 1000);
	pqcp_tls_endpoint_free(&endpoint);
}

static void initialize_runtime(
	struct pqcp_runtime_service *service,
	struct pqcp_adaptive_control_plane *adaptive,
	struct loopback_runtime_storage *runtime_storage,
	const char *device_id)
{
	const struct pqcp_runtime_service_storage storage = {
		.key_slots = runtime_storage->key_slots,
		.key_slot_count = ARRAY_SIZE(runtime_storage->key_slots),
		.workspace_slots = runtime_storage->workspace_slots,
		.workspace_bytes = runtime_storage->workspace_bytes,
		.workspace_slot_count =
			ARRAY_SIZE(runtime_storage->workspace_slots),
		.workspace_bytes_per_slot = RUNTIME_WORKSPACE_BYTES,
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

static void client_handshake(
	void *first, void *second, void *third)
{
	ARG_UNUSED(first);
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	client_result = pqcp_tls_endpoint_handshake_bio(
		&client_endpoint, &client_bio,
		tls_bio_send, tls_bio_receive,
		tls_bio_receive_timeout, TLS_TIMEOUT_MS);
}

static void server_handshake(
	void *first, void *second, void *third)
{
	ARG_UNUSED(first);
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	server_result = pqcp_tls_endpoint_handshake_bio(
		&server_endpoint, &server_bio,
		tls_bio_send, tls_bio_receive,
		tls_bio_receive_timeout, TLS_TIMEOUT_MS);
}

static void client_channel_handshake(
	void *first, void *second, void *third)
{
	ARG_UNUSED(first);
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	client_result = pqcp_channel_handshake(&client_channel);
}

static void server_channel_handshake(
	void *first, void *second, void *third)
{
	ARG_UNUSED(first);
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	server_result = pqcp_channel_handshake(&server_channel);
}

ZTEST(pqcp_tls_loopback, test_tls13_psk_exporter_and_transport)
{
	static const uint8_t export_context[] =
		"pqcp-loopback-export-context";
	static const uint8_t message[] =
		"outer TLS protected payload";
	static const uint8_t protected_message[] =
		"ML-KEM bound inner record";
	struct pqcp_channel_transport client_transport;
	struct pqcp_channel_transport server_transport;
	struct pqcp_channel_mbedtls_context client_adapter;
	struct pqcp_channel_mbedtls_context server_adapter;
	struct pqcp_runtime_identity *client_identity;
	struct pqcp_runtime_identity *server_identity;
	struct pqcp_runtime_identity *pinned_identity;
	struct pqcp_channel_config client_config = {
		.schema_version = PQCP_CHANNEL_SCHEMA_VERSION,
		.role = PQCP_CHANNEL_ROLE_CLIENT,
		.session_id = UINT64_C(0x544c530000000001),
		.mlkem_level = 768U,
		.mldsa_level = 65U,
		.timeout_ms = 120000U,
		.max_payload_bytes = PQCP_CHANNEL_MAX_PAYLOAD_BYTES,
		.require_mutual_authentication = false,
		.profile_id = "hybrid768-65-runtime",
	};
	struct pqcp_channel_config server_config = client_config;
	uint8_t client_exporter[PQCP_CHANNEL_EXPORTER_BYTES];
	uint8_t server_exporter[PQCP_CHANNEL_EXPORTER_BYTES];
	uint8_t received[64];
	size_t received_length = 0U;

	server_config.role = PQCP_CHANNEL_ROLE_SERVER;
	tls_pipe_init(&client_to_server);
	tls_pipe_init(&server_to_client);
	client_bio.incoming = &server_to_client;
	client_bio.outgoing = &client_to_server;
	server_bio.incoming = &client_to_server;
	server_bio.outgoing = &server_to_client;
	zassert_ok(pqcp_tls_endpoint_init_psk(
		&client_endpoint, PQCP_CHANNEL_ROLE_CLIENT,
		loopback_psk, sizeof(loopback_psk),
		loopback_identity, sizeof(loopback_identity) - 1U));
	zassert_ok(pqcp_tls_endpoint_init_psk(
		&server_endpoint, PQCP_CHANNEL_ROLE_SERVER,
		loopback_psk, sizeof(loopback_psk),
		loopback_identity, sizeof(loopback_identity) - 1U));
	client_result = -EINPROGRESS;
	server_result = -EINPROGRESS;
	k_thread_create(
		&server_thread, server_stack,
		K_THREAD_STACK_SIZEOF(server_stack),
		server_handshake, NULL, NULL, NULL,
		5, 0, K_NO_WAIT);
	k_thread_create(
		&client_thread, client_stack,
		K_THREAD_STACK_SIZEOF(client_stack),
		client_handshake, NULL, NULL, NULL,
		5, 0, K_NO_WAIT);
	zassert_ok(k_thread_join(
		&client_thread, K_SECONDS(60)));
	zassert_ok(k_thread_join(
		&server_thread, K_SECONDS(60)));
	zassert_equal(client_result, 0,
		      "client TLS handshake returned %d",
		      client_result);
	zassert_equal(server_result, 0,
		      "server TLS handshake returned %d",
		      server_result);
	zassert_ok(pqcp_tls_endpoint_make_transport(
		&client_endpoint, &client_transport,
		&client_adapter, TLS_TIMEOUT_MS));
	zassert_ok(pqcp_tls_endpoint_make_transport(
		&server_endpoint, &server_transport,
		&server_adapter, TLS_TIMEOUT_MS));
	zassert_ok(client_transport.export_keying_material(
		client_transport.context,
		PQCP_CHANNEL_EXPORTER_LABEL,
		export_context, sizeof(export_context) - 1U,
		client_exporter, sizeof(client_exporter)));
	zassert_ok(server_transport.export_keying_material(
		server_transport.context,
		PQCP_CHANNEL_EXPORTER_LABEL,
		export_context, sizeof(export_context) - 1U,
		server_exporter, sizeof(server_exporter)));
	zassert_mem_equal(
		client_exporter, server_exporter,
		sizeof(client_exporter));
	zassert_ok(client_transport.send(
		client_transport.context, message,
		sizeof(message) - 1U, TLS_TIMEOUT_MS));
	zassert_ok(server_transport.receive(
		server_transport.context, received,
		sizeof(received), &received_length,
		TLS_TIMEOUT_MS));
	zassert_equal(received_length, sizeof(message) - 1U);
	zassert_mem_equal(received, message, received_length);

	initialize_runtime(
		&client_runtime, &client_adaptive,
		&client_runtime_storage, "tls-client");
	initialize_runtime(
		&server_runtime, &server_adaptive,
		&server_runtime_storage, "tls-server");
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
	zassert_ok(pqcp_channel_init(
		&client_channel, &client_config, &client_transport,
		&client_runtime.executor, &client_runtime.key_store));
	zassert_ok(pqcp_channel_init(
		&server_channel, &server_config, &server_transport,
		&server_runtime.executor, &server_runtime.key_store));
	client_result = -EINPROGRESS;
	server_result = -EINPROGRESS;
	k_thread_create(
		&server_thread, server_stack,
		K_THREAD_STACK_SIZEOF(server_stack),
		server_channel_handshake, NULL, NULL, NULL,
		5, 0, K_NO_WAIT);
	k_thread_create(
		&client_thread, client_stack,
		K_THREAD_STACK_SIZEOF(client_stack),
		client_channel_handshake, NULL, NULL, NULL,
		5, 0, K_NO_WAIT);
	zassert_ok(k_thread_join(
		&client_thread, K_SECONDS(120)));
	zassert_ok(k_thread_join(
		&server_thread, K_SECONDS(120)));
	zassert_equal(client_result, 0,
		      "client PQC handshake returned %d", client_result);
	zassert_equal(server_result, 0,
		      "server PQC handshake returned %d", server_result);
	zassert_ok(pqcp_channel_send(
		&client_channel, protected_message,
		sizeof(protected_message) - 1U));
	zassert_ok(pqcp_channel_receive(
		&server_channel, received, sizeof(received),
		&received_length));
	zassert_equal(
		received_length, sizeof(protected_message) - 1U);
	zassert_mem_equal(
		received, protected_message, received_length);
	zassert_ok(pqcp_channel_audit(&client_channel));
	zassert_ok(pqcp_channel_audit(&server_channel));
	zassert_ok(pqcp_channel_emit(&client_channel));
	zassert_ok(pqcp_channel_emit(&server_channel));
	pqcp_tls_endpoint_free(&client_endpoint);
	pqcp_tls_endpoint_free(&server_endpoint);
}

ZTEST_SUITE(pqcp_tls_loopback, NULL, NULL, NULL, NULL, NULL);
