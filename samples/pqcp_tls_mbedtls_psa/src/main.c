/*
 * SPDX-License-Identifier: MIT
 *
 * Direct mbedTLS TLS 1.3 PSK plus exporter-bound PQCP channel demo.
 *
 * This is an experimental application-layer PQC binding carried inside a
 * standard TLS connection. It is not a standardized PQC TLS ciphersuite.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/protected_channel_tls.h>
#include <pqcp_zephyr/runtime_service.h>

#define DEMO_STACK_BYTES 131072U
#define DEMO_TIMEOUT_MS 120000U
#define DEMO_PIPE_BYTES 32768U
#define DEMO_KEYS 10U
#define DEMO_WORKSPACES 2U
#define DEMO_WORKSPACE_BYTES 49152U
#define DEMO_JOBS 8U
#define DEMO_SESSIONS 2U
#define DEMO_PROFILES 8U
#define DEMO_AUDIT_ENTRIES 16U
#define DEMO_IDENTITIES 4U
#define DEMO_QUOTAS 2U

static const uint8_t demo_psk[32] = {
	0x2d, 0x57, 0xb1, 0xa0, 0x9c, 0x63, 0x74, 0xe8,
	0xf5, 0x11, 0x6b, 0x0c, 0x47, 0x2e, 0xa9, 0x35,
	0x83, 0xcd, 0x16, 0x79, 0x20, 0x44, 0xde, 0x8a,
	0x6f, 0x32, 0x91, 0xbb, 0x05, 0xd7, 0xca, 0x4e,
};
static const uint8_t demo_identity[] = "pqcp-qemu-loopback";
static const uint8_t demo_request[] =
	"protected request from PQCP client";
static const uint8_t demo_response[] =
	"protected response from PQCP server";

struct demo_pipe {
	uint8_t bytes[DEMO_PIPE_BYTES];
	size_t read_offset;
	size_t write_offset;
	size_t used;
	struct k_mutex lock;
	struct k_sem data_ready;
};

struct demo_bio_endpoint {
	struct demo_pipe *incoming;
	struct demo_pipe *outgoing;
};

struct demo_runtime_storage {
	struct pqcp_runtime_volatile_slot key_slots[DEMO_KEYS];
	struct pqcp_runtime_workspace_slot
		workspace_slots[DEMO_WORKSPACES];
	uint8_t workspace_bytes[
		DEMO_WORKSPACES * DEMO_WORKSPACE_BYTES];
	struct pqcp_runtime_queue_entry queue[DEMO_JOBS];
	struct pqcp_runtime_session sessions[DEMO_SESSIONS];
	struct pqcp_runtime_profile_state profiles[DEMO_PROFILES];
	struct pqcp_runtime_audit_entry audit_entries[DEMO_AUDIT_ENTRIES];
	struct pqcp_runtime_identity identities[DEMO_IDENTITIES];
	struct pqcp_runtime_admission_quota quotas[DEMO_QUOTAS];
};

static struct demo_pipe client_to_server;
static struct demo_pipe server_to_client;
static struct demo_bio_endpoint client_bio;
static struct demo_bio_endpoint server_bio;
static struct pqcp_tls_endpoint client_tls;
static struct pqcp_tls_endpoint server_tls;
static struct pqcp_channel_mbedtls_context client_adapter;
static struct pqcp_channel_mbedtls_context server_adapter;
static struct pqcp_channel_transport client_transport;
static struct pqcp_channel_transport server_transport;
static struct demo_runtime_storage client_storage;
static struct demo_runtime_storage server_storage;
static struct pqcp_runtime_service client_runtime;
static struct pqcp_runtime_service server_runtime;
static struct pqcp_adaptive_control_plane client_adaptive;
static struct pqcp_adaptive_control_plane server_adaptive;
static struct pqcp_channel client_channel;
static struct pqcp_channel server_channel;
static struct k_thread client_thread;
static struct k_thread server_thread;
K_THREAD_STACK_DEFINE(client_stack, DEMO_STACK_BYTES);
K_THREAD_STACK_DEFINE(server_stack, DEMO_STACK_BYTES);
static int client_result;
static int server_result;

static void demo_pipe_init(struct demo_pipe *pipe)
{
	memset(pipe, 0, sizeof(*pipe));
	k_mutex_init(&pipe->lock);
	k_sem_init(&pipe->data_ready, 0U, 1U);
}

static int demo_bio_send(
	void *context, const unsigned char *buffer, size_t length)
{
	struct demo_bio_endpoint *endpoint = context;
	struct demo_pipe *pipe = endpoint->outgoing;
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

static int demo_bio_receive_timeout(
	void *context, unsigned char *buffer, size_t length,
	uint32_t timeout_ms)
{
	struct demo_bio_endpoint *endpoint = context;
	struct demo_pipe *pipe = endpoint->incoming;
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

static int demo_bio_receive(
	void *context, unsigned char *buffer, size_t length)
{
	return demo_bio_receive_timeout(
		context, buffer, length, 0U);
}

static int initialize_runtime(
	struct pqcp_runtime_service *service,
	struct pqcp_adaptive_control_plane *adaptive,
	struct demo_runtime_storage *runtime_storage,
	const char *device_id)
{
	const struct pqcp_runtime_service_storage storage = {
		.key_slots = runtime_storage->key_slots,
		.key_slot_count = ARRAY_SIZE(runtime_storage->key_slots),
		.workspace_slots = runtime_storage->workspace_slots,
		.workspace_bytes = runtime_storage->workspace_bytes,
		.workspace_slot_count =
			ARRAY_SIZE(runtime_storage->workspace_slots),
		.workspace_bytes_per_slot = DEMO_WORKSPACE_BYTES,
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
	int ret;

	memset(runtime_storage, 0, sizeof(*runtime_storage));
	memset(service, 0, sizeof(*service));
	memset(adaptive, 0, sizeof(*adaptive));
	ret = pqcp_adaptive_control_init(
		adaptive, device_id, PQCP_ADAPTIVE_POLICY_GATEWAY,
		"hybrid768-65-runtime", 1000U);
	if (ret != 0) {
		return ret;
	}
	return pqcp_runtime_service_init(
		service, &storage, adaptive, 1000U);
}

static void client_tls_entry(
	void *first, void *second, void *third)
{
	ARG_UNUSED(first);
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	client_result = pqcp_tls_endpoint_handshake_bio(
		&client_tls, &client_bio,
		demo_bio_send, demo_bio_receive,
		demo_bio_receive_timeout, DEMO_TIMEOUT_MS);
}

static void server_tls_entry(
	void *first, void *second, void *third)
{
	ARG_UNUSED(first);
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	server_result = pqcp_tls_endpoint_handshake_bio(
		&server_tls, &server_bio,
		demo_bio_send, demo_bio_receive,
		demo_bio_receive_timeout, DEMO_TIMEOUT_MS);
}

static void client_channel_entry(
	void *first, void *second, void *third)
{
	ARG_UNUSED(first);
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	client_result = pqcp_channel_handshake(&client_channel);
}

static void server_channel_entry(
	void *first, void *second, void *third)
{
	ARG_UNUSED(first);
	ARG_UNUSED(second);
	ARG_UNUSED(third);
	server_result = pqcp_channel_handshake(&server_channel);
}

static int run_pair(
	k_thread_entry_t client_entry,
	k_thread_entry_t server_entry,
	k_timeout_t timeout)
{
	int ret;

	client_result = -EINPROGRESS;
	server_result = -EINPROGRESS;
	k_thread_create(
		&server_thread, server_stack,
		K_THREAD_STACK_SIZEOF(server_stack),
		server_entry, NULL, NULL, NULL, 5, 0, K_NO_WAIT);
	k_thread_create(
		&client_thread, client_stack,
		K_THREAD_STACK_SIZEOF(client_stack),
		client_entry, NULL, NULL, NULL, 5, 0, K_NO_WAIT);
	ret = k_thread_join(&client_thread, timeout);
	if (ret == 0) {
		ret = k_thread_join(&server_thread, timeout);
	}
	if (ret != 0) {
		k_thread_abort(&client_thread);
		k_thread_abort(&server_thread);
		(void)k_thread_join(&client_thread, K_FOREVER);
		(void)k_thread_join(&server_thread, K_FOREVER);
		return -ETIMEDOUT;
	}
	return client_result != 0 ? client_result : server_result;
}

static int verify_tls_transport_ready(void)
{
	static const uint8_t client_probe[] =
		"pqcp-client-ready";
	static const uint8_t server_probe[] =
		"pqcp-server-ready";
	uint8_t received[sizeof(client_probe) > sizeof(server_probe) ?
			 sizeof(client_probe) : sizeof(server_probe)];
	size_t received_length = 0U;
	int ret;

	ret = client_transport.send(
		client_transport.context, client_probe,
		sizeof(client_probe) - 1U, DEMO_TIMEOUT_MS);
	if (ret == 0) {
		ret = server_transport.receive(
			server_transport.context, received,
			sizeof(received), &received_length,
			DEMO_TIMEOUT_MS);
	}
	if (ret == 0 &&
	    (received_length != sizeof(client_probe) - 1U ||
	     memcmp(received, client_probe, received_length) != 0)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = server_transport.send(
			server_transport.context, server_probe,
			sizeof(server_probe) - 1U,
			DEMO_TIMEOUT_MS);
	}
	if (ret == 0) {
		ret = client_transport.receive(
			client_transport.context, received,
			sizeof(received), &received_length,
			DEMO_TIMEOUT_MS);
	}
	if (ret == 0 &&
	    (received_length != sizeof(server_probe) - 1U ||
	     memcmp(received, server_probe, received_length) != 0)) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(received, sizeof(received));
	return ret;
}

static int configure_identities(
	struct pqcp_channel_config *client_config,
	struct pqcp_channel_config *server_config)
{
	struct pqcp_runtime_identity *client_identity;
	struct pqcp_runtime_identity *server_identity;
	struct pqcp_runtime_identity *pinned_identity;
	int ret;

	ret = pqcp_runtime_identity_create_local(
		&client_runtime.identities, "client-local",
		65U, 2000U, 300000U, &client_identity);
	if (ret == 0) {
		ret = pqcp_runtime_identity_create_local(
			&server_runtime.identities, "server-local",
			65U, 2000U, 300000U, &server_identity);
	}
	if (ret == 0) {
		ret = pqcp_runtime_identity_pin_peer(
			&client_runtime.identities, "server-peer", 65U,
			server_identity->peer_public_key,
			server_identity->peer_public_key_length,
			2000U, 300000U, &pinned_identity);
	}
	if (ret == 0) {
		ret = pqcp_runtime_identity_pin_peer(
			&server_runtime.identities, "client-peer", 65U,
			client_identity->peer_public_key,
			client_identity->peer_public_key_length,
			2000U, 300000U, &pinned_identity);
	}
	if (ret == 0) {
		ret = pqcp_runtime_identity_configure_channel(
			&client_runtime.identities, "client-local",
			"server-peer", client_config);
	}
	if (ret == 0) {
		ret = pqcp_runtime_identity_configure_channel(
			&server_runtime.identities, "server-local",
			"client-peer", server_config);
	}
	return ret;
}

static int run_demo(void)
{
	struct pqcp_channel_config client_config = {
		.schema_version = PQCP_CHANNEL_SCHEMA_VERSION,
		.role = PQCP_CHANNEL_ROLE_CLIENT,
		.session_id = UINT64_C(0x544c530000000001),
		.mlkem_level = 768U,
		.mldsa_level = 65U,
		.timeout_ms = DEMO_TIMEOUT_MS,
		.max_payload_bytes = PQCP_CHANNEL_MAX_PAYLOAD_BYTES,
		.require_mutual_authentication = false,
		.profile_id = "hybrid768-65-runtime",
	};
	struct pqcp_channel_config server_config = client_config;
	uint8_t plaintext[64];
	size_t plaintext_length = 0U;
	int ret;

	server_config.role = PQCP_CHANNEL_ROLE_SERVER;
	demo_pipe_init(&client_to_server);
	demo_pipe_init(&server_to_client);
	client_bio.incoming = &server_to_client;
	client_bio.outgoing = &client_to_server;
	server_bio.incoming = &client_to_server;
	server_bio.outgoing = &server_to_client;
	ret = pqcp_tls_endpoint_init_psk(
		&client_tls, PQCP_CHANNEL_ROLE_CLIENT,
		demo_psk, sizeof(demo_psk),
		demo_identity, sizeof(demo_identity) - 1U);
	if (ret == 0) {
		ret = pqcp_tls_endpoint_init_psk(
			&server_tls, PQCP_CHANNEL_ROLE_SERVER,
			demo_psk, sizeof(demo_psk),
			demo_identity, sizeof(demo_identity) - 1U);
	}
	if (ret == 0) {
		ret = run_pair(
			client_tls_entry, server_tls_entry,
			K_SECONDS(60));
	}
	if (ret != 0) {
		return ret;
	}
	printk("PQCP_TLS_LOOPBACK schema=1 stage=tls13_psk status=PASS exporter=available\n");
	ret = pqcp_tls_endpoint_make_transport(
		&client_tls, &client_transport,
		&client_adapter, DEMO_TIMEOUT_MS);
	if (ret == 0) {
		ret = pqcp_tls_endpoint_make_transport(
			&server_tls, &server_transport,
			&server_adapter, DEMO_TIMEOUT_MS);
	}
	if (ret == 0) {
		ret = verify_tls_transport_ready();
	}
	if (ret == 0) {
		ret = initialize_runtime(
			&client_runtime, &client_adaptive,
			&client_storage, "tls-client");
	}
	if (ret == 0) {
		ret = initialize_runtime(
			&server_runtime, &server_adaptive,
			&server_storage, "tls-server");
	}
	if (ret == 0) {
		ret = configure_identities(
			&client_config, &server_config);
	}
	if (ret == 0) {
		ret = pqcp_channel_init(
			&client_channel, &client_config,
			&client_transport, &client_runtime.executor,
			&client_runtime.key_store);
	}
	if (ret == 0) {
		ret = pqcp_channel_init(
			&server_channel, &server_config,
			&server_transport, &server_runtime.executor,
			&server_runtime.key_store);
	}
	if (ret == 0) {
		ret = run_pair(
			client_channel_entry, server_channel_entry,
			K_SECONDS(120));
	}
	if (ret != 0) {
		return ret;
	}
	printk("PQCP_TLS_LOOPBACK schema=1 stage=pqc_handshake status=PASS mlkem=768 mldsa=65 authentication=pinned_server\n");
	ret = pqcp_channel_send(
		&client_channel, demo_request,
		sizeof(demo_request) - 1U);
	if (ret == 0) {
		ret = pqcp_channel_receive(
			&server_channel, plaintext,
			sizeof(plaintext), &plaintext_length);
	}
	if (ret == 0 &&
	    (plaintext_length != sizeof(demo_request) - 1U ||
	     memcmp(plaintext, demo_request, plaintext_length) != 0)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_channel_send(
			&server_channel, demo_response,
			sizeof(demo_response) - 1U);
	}
	if (ret == 0) {
		ret = pqcp_channel_receive(
			&client_channel, plaintext,
			sizeof(plaintext), &plaintext_length);
	}
	if (ret == 0 &&
	    (plaintext_length != sizeof(demo_response) - 1U ||
	     memcmp(plaintext, demo_response, plaintext_length) != 0)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_channel_audit(&client_channel);
	}
	if (ret == 0) {
		ret = pqcp_channel_audit(&server_channel);
	}
	if (ret == 0) {
		ret = pqcp_channel_emit(&client_channel);
	}
	if (ret == 0) {
		ret = pqcp_channel_emit(&server_channel);
	}
	if (ret == 0) {
		printk("PQCP_TLS_LOOPBACK schema=1 stage=inner_aead status=PASS request_bytes=%u response_bytes=%u\n",
		       (unsigned int)(sizeof(demo_request) - 1U),
		       (unsigned int)(sizeof(demo_response) - 1U));
	}
	pqcp_runtime_secure_zero(plaintext, sizeof(plaintext));
	return ret;
}

int main(void)
{
	const int ret = run_demo();

	printk("PQCP_TLS_LOOPBACK schema=1 status=%s result=%d transport=mbedtls_tls13_psk binding=exporter_mlkem_mldsa\n",
	       ret == 0 ? "PASS" : "FAIL", ret);
	pqcp_tls_endpoint_free(&client_tls);
	pqcp_tls_endpoint_free(&server_tls);
	return ret;
}
