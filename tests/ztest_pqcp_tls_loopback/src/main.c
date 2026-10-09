/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#include <errno.h>
#include <string.h>
#include <psa/crypto.h>
#include <mbedtls/threading.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>
#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
#include <zephyr/net/socket.h>
#endif

#include <pqcp_zephyr/protected_channel_tls.h>
#include <pqcp_zephyr/protected_channel_operations.h>
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
#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
static int client_socket;
static int server_socket;

static void connect_tcp_pair(void)
{
	struct net_sockaddr_in address = {
		.sin_family = NET_AF_INET,
		.sin_port = 0,
	};
	net_socklen_t size = sizeof(address);
	int listener = zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TCP);

	zassert_true(listener >= 0, "listener: %d", errno);
	zassert_equal(zsock_inet_pton(NET_AF_INET, "127.0.0.1", &address.sin_addr), 1);
	zassert_ok(zsock_bind(listener, (struct net_sockaddr *)&address, sizeof(address)));
	zassert_ok(zsock_getsockname(listener, (struct net_sockaddr *)&address, &size));
	zassert_ok(zsock_listen(listener, 1));
	client_socket = zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TCP);
	zassert_true(client_socket >= 0);
	zassert_ok(zsock_connect(client_socket, (struct net_sockaddr *)&address, sizeof(address)));
	server_socket = zsock_accept(listener, NULL, NULL);
	zassert_true(server_socket >= 0, "accept: %d", errno);
	zassert_ok(zsock_close(listener));
}
#endif

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

struct live_operations {
	struct pqcp_channel_multiplexer mux;
	struct pqcp_channel_stream streams[2];
	struct pqcp_channel_flow_controller flow;
	struct pqcp_channel_rekey_context rekey;
	struct pqcp_channel_resumption_store resumption;
	struct pqcp_channel_ticket_replay_entry replay[8];
	struct pqcp_channel_peer_health peer;
	struct pqcp_channel_operations operations;
};

static struct live_operations client_operations;
static struct live_operations server_operations;
static uint8_t previous_record[PQCP_CHANNEL_MAX_FRAME_BYTES];
static size_t previous_record_length;
static uint8_t previous_exporter[PQCP_CHANNEL_EXPORTER_BYTES];

enum live_test_mode {
	LIVE_BASIC,
	LIVE_RECOVERY,
	LIVE_STALE_RECORD,
	LIVE_UNCERTAIN_CONTROL,
	LIVE_IDLE_TIMEOUT,
	LIVE_CLOSE_TIMEOUT,
};

struct interrupted_transport {
	struct pqcp_channel_transport underlying;
	bool prefix_sent;
};

static void initialize_operations(struct live_operations *storage,
	struct pqcp_channel *channel);
static void exchange_records(void);

static int send_prefix_then_fail(void *context, const uint8_t *bytes, size_t size,
	uint32_t timeout_ms)
{
	struct interrupted_transport *fault = context;

	if (!fault->prefix_sent && size > 1U) {
		int ret = fault->underlying.send(fault->underlying.context,
			bytes, size / 2U, timeout_ms);

		if (ret != 0) {
			return ret;
		}
		fault->prefix_sent = true;
	}
	return -EIO;
}

static void exercise_terminal_control_failure(void)
{
	struct pqcp_channel_rekey_policy policy;
	struct interrupted_transport fault = {.underlying = client_channel.transport};

	initialize_operations(&client_operations, &client_channel);
	exchange_records();
	zassert_ok(pqcp_channel_rekey_policy_default(&policy));
	policy.maximum_epoch_bytes = 1U;
	client_channel.transport.context = &fault;
	client_channel.transport.send = send_prefix_then_fail;
	zassert_equal(pqcp_channel_operations_tick(&client_operations.operations, &policy, 2000U), -EIO);
	zassert_true(fault.prefix_sent);
	zassert_false(client_channel.established);
	zassert_true(client_channel.application_send_blocked);
	zassert_equal(client_operations.operations.state, PQCP_CHANNEL_POLICY_FAILED);
	zassert_equal(client_runtime.key_store.active_count, 1U);
	client_channel.transport = fault.underlying;
	printk("PQCP_CHANNEL_RECOVERY case=partial_control_send status=PASS traffic_keys=0 environment=qemu\n");
}

static void initialize_operations(struct live_operations *storage,
	struct pqcp_channel *channel)
{
	struct pqcp_channel_flow_policy flow_policy;
	struct pqcp_channel_peer_policy peer_policy;
	uint8_t secret[PQCP_CHANNEL_RESUMPTION_SECRET_BYTES];

	memset(storage, 0, sizeof(*storage));
	/* Fixture-only ticket secret; tickets are not used in this campaign. */
	memset(secret, 0x41, sizeof(secret));
	zassert_ok(pqcp_channel_flow_policy_default(&flow_policy));
	zassert_ok(pqcp_channel_flow_init(&storage->flow, &flow_policy));
	zassert_ok(pqcp_channel_multiplexer_init(&storage->mux, channel,
		storage->streams, ARRAY_SIZE(storage->streams),
		flow_policy.initial_connection_window, flow_policy.initial_stream_window));
	zassert_ok(pqcp_channel_resumption_store_init(&storage->resumption,
		secret, storage->replay, ARRAY_SIZE(storage->replay)));
	zassert_ok(pqcp_channel_peer_policy_default(&peer_policy));
	peer_policy.keepalive_interval_ms = 60000U;
	peer_policy.keepalive_timeout_ms = 120000U;
	peer_policy.idle_timeout_ms = 180000U;
	zassert_ok(pqcp_channel_peer_health_init(&storage->peer, &peer_policy, 1000U));
	zassert_ok(pqcp_channel_operations_init(&storage->operations, channel,
		&storage->mux, &storage->flow, &storage->rekey, &storage->resumption,
		&storage->peer, &peer_policy, 1000U));
	pqcp_runtime_secure_zero(secret, sizeof(secret));
}

static void control_receive(struct live_operations *storage, uint64_t now_ms)
{
	struct pqcp_channel_control_message message;
	int ret = pqcp_channel_operations_receive_control(&storage->operations, &message, now_ms);

	zassert_equal(ret, 0, "control receive at %llu returned %d",
		(unsigned long long)now_ms, ret);
}

static void exchange_records(void)
{
	const uint8_t message[] = "fresh bidirectional inner AEAD";
	uint8_t output[64];
	size_t size;

	zassert_ok(pqcp_channel_send(&client_channel, message, sizeof(message)));
	zassert_ok(pqcp_channel_receive(&server_channel, output, sizeof(output), &size));
	zassert_equal(size, sizeof(message));
	zassert_mem_equal(output, message, size);
	zassert_ok(pqcp_channel_send(&server_channel, message, sizeof(message)));
	zassert_ok(pqcp_channel_receive(&client_channel, output, sizeof(output), &size));
	zassert_equal(size, sizeof(message));
	zassert_mem_equal(output, message, size);
}

static void exercise_live_recovery(void)
{
	struct pqcp_channel_rekey_policy policy;
	uint8_t ignored[PQCP_CHANNEL_CONTROL_MAX_BYTES + 128U];
	size_t ignored_length;
	uint32_t start;
	uint64_t epoch;

	initialize_operations(&client_operations, &client_channel);
	initialize_operations(&server_operations, &server_channel);
	zassert_ok(pqcp_channel_rekey_policy_default(&policy));
	policy.maximum_epoch_bytes = 1U;
	policy.minimum_interval_ms = 1U;
	policy.handshake_timeout_ms = 1000U;
	exchange_records();

	/* Consume but deliberately do not dispatch PREPARE, modeling a peer
	 * stalled before entering rekey. An authenticated abort preserves keys.
	 */
	zassert_ok(pqcp_channel_operations_tick(&client_operations.operations, &policy, 2000U));
	zassert_ok(pqcp_channel_receive(&server_channel, ignored, sizeof(ignored), &ignored_length));
	zassert_ok(pqcp_channel_operations_tick(&client_operations.operations, &policy, 3001U));
	zassert_equal(client_operations.rekey.state, PQCP_CHANNEL_REKEY_ABORTED);
	zassert_ok(pqcp_channel_receive(&server_channel, ignored, sizeof(ignored), &ignored_length));
	zassert_true(client_channel.established);
	zassert_false(client_channel.application_send_blocked);
	zassert_equal(client_runtime.key_store.active_count, 3U);
	exchange_records();

	for (unsigned int trial = 0U; trial < 3U; ++trial) {
		uint64_t now = 5000U + trial * 2000U;

		start = k_cycle_get_32();
		zassert_ok(pqcp_channel_operations_tick(&client_operations.operations, &policy, now));
		control_receive(&server_operations, now + 10U);
		control_receive(&client_operations, now + 20U);
		control_receive(&server_operations, now + 30U);
		control_receive(&client_operations, now + 40U);
		control_receive(&server_operations, now + 50U);
		control_receive(&client_operations, now + 60U);
		zassert_equal(client_operations.rekey.current_epoch, 2U + trial);
		zassert_equal(server_operations.rekey.current_epoch, 2U + trial);
		exchange_records();
		zassert_ok(pqcp_channel_rekey_cleanup(&client_operations.rekey));
		zassert_ok(pqcp_channel_rekey_cleanup(&server_operations.rekey));
		zassert_equal(client_runtime.key_store.active_count, 3U);
		zassert_equal(server_runtime.key_store.active_count, 3U);
		printk("PQCP_CHANNEL_RECOVERY case=rekey trial=%u epoch=%llu cycles=%u keys=3 environment=qemu\n",
			trial, (unsigned long long)client_operations.rekey.current_epoch,
			k_cycle_get_32() - start);
	}

	/* Both peers propose the same next epoch; process queued duplicate
	 * controls in order, as on a real TLS byte stream, without resetting it.
	 */
	epoch = client_operations.rekey.current_epoch + 1U;
	zassert_ok(pqcp_channel_operations_tick(&client_operations.operations, &policy, 12000U));
	zassert_ok(pqcp_channel_operations_tick(&server_operations.operations, &policy, 12001U));
	control_receive(&server_operations, 12010U);
	control_receive(&client_operations, 12020U);
	control_receive(&client_operations, 12030U);
	control_receive(&server_operations, 12040U);
	control_receive(&server_operations, 12050U);
	control_receive(&client_operations, 12060U);
	control_receive(&client_operations, 12070U);
	control_receive(&server_operations, 12080U);
	control_receive(&server_operations, 12090U);
	control_receive(&client_operations, 12100U);
	control_receive(&client_operations, 12110U);
	control_receive(&server_operations, 12120U);
	control_receive(&client_operations, 12130U);
	zassert_equal(client_operations.rekey.current_epoch, epoch);
	zassert_equal(server_operations.rekey.current_epoch, epoch);
	exchange_records();
	zassert_ok(pqcp_channel_rekey_cleanup(&client_operations.rekey));
	zassert_ok(pqcp_channel_rekey_cleanup(&server_operations.rekey));

	/* Lose the peer after local-direction cutover. Resuming old keys is
	 * unsafe: deadline expiry must erase active, pending and retired keys.
	 */
	zassert_ok(pqcp_channel_operations_tick(&client_operations.operations, &policy, 15000U));
	control_receive(&server_operations, 15010U);
	control_receive(&client_operations, 15020U);
	control_receive(&server_operations, 15030U);
	control_receive(&client_operations, 15040U);
	zassert_true(client_operations.rekey.local_direction_committed);
	zassert_equal(pqcp_channel_operations_tick(&client_operations.operations, &policy, 16001U),
		-ETIMEDOUT);
	zassert_false(client_channel.established);
	zassert_false(client_channel.keys.traffic_keys_ready);
	zassert_equal(client_runtime.key_store.active_count, 1U); /* provisioned identity only */
	zassert_not_equal(pqcp_channel_send(&client_channel, ignored, 1U), 0);
	zassert_ok(pqcp_channel_close(&client_channel));
	zassert_ok(pqcp_channel_close(&server_channel));
	zassert_equal(server_runtime.key_store.active_count, 1U);
	printk("PQCP_CHANNEL_RECOVERY case=post_cutover_timeout status=PASS traffic_keys=0 environment=qemu\n");
}

static void tls_pipe_init(struct tls_pipe *pipe)
{
	memset(pipe, 0, sizeof(*pipe));
	k_mutex_init(&pipe->lock);
	k_sem_init(&pipe->data_ready, 0U, 1U);
}

#if !defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
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
#endif

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
#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
	client_result = pqcp_tls_endpoint_handshake(
		&client_endpoint, client_socket, true, TLS_TIMEOUT_MS);
#else
	client_result = pqcp_tls_endpoint_handshake_bio(
		&client_endpoint, &client_bio,
		tls_bio_send, tls_bio_receive,
		tls_bio_receive_timeout, TLS_TIMEOUT_MS);
#endif
}

static void server_handshake(
	void *first, void *second, void *third)
{
	ARG_UNUSED(first);
	ARG_UNUSED(second);
	ARG_UNUSED(third);
#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
	server_result = pqcp_tls_endpoint_handshake(
		&server_endpoint, server_socket, true, TLS_TIMEOUT_MS);
#else
	server_result = pqcp_tls_endpoint_handshake_bio(
		&server_endpoint, &server_bio,
		tls_bio_send, tls_bio_receive,
		tls_bio_receive_timeout, TLS_TIMEOUT_MS);
#endif
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

struct threading_probe {
	mbedtls_threading_mutex_t mutex;
	mbedtls_threading_condition_variable_t condition;
	struct k_sem entered;
	bool released;
	int result;
};

static void condition_waiter(void *first, void *second, void *third)
{
	struct threading_probe *probe = first;

	ARG_UNUSED(second);
	ARG_UNUSED(third);
	probe->result = mbedtls_mutex_lock(&probe->mutex);
	k_sem_give(&probe->entered);
	while (probe->result == 0 && !probe->released) {
		probe->result = mbedtls_condition_variable_wait(&probe->condition, &probe->mutex);
	}
	if (probe->result == 0) {
		probe->result = mbedtls_mutex_unlock(&probe->mutex);
	}
}

ZTEST(pqcp_tls_loopback, test_threading_condition_wait_and_lifecycle)
{
	struct threading_probe probe = {0};

	mbedtls_mutex_init(&probe.mutex);
	zassert_ok(mbedtls_condition_variable_init(&probe.condition));
	k_sem_init(&probe.entered, 0U, 1U);
	k_thread_create(&client_thread, client_stack, K_THREAD_STACK_SIZEOF(client_stack),
		condition_waiter, &probe, NULL, NULL, 5, 0, K_NO_WAIT);
	zassert_ok(k_sem_take(&probe.entered, K_SECONDS(1)));
	zassert_ok(mbedtls_mutex_lock(&probe.mutex));
	probe.released = true;
	zassert_ok(mbedtls_condition_variable_signal(&probe.condition));
	zassert_ok(mbedtls_condition_variable_broadcast(&probe.condition));
	zassert_ok(mbedtls_mutex_unlock(&probe.mutex));
	zassert_ok(k_thread_join(&client_thread, K_SECONDS(1)));
	zassert_ok(probe.result);
	mbedtls_condition_variable_free(&probe.condition);
	mbedtls_mutex_free(&probe.mutex);
	mbedtls_mutex_free(&probe.mutex);
	zassert_equal(mbedtls_mutex_lock(&probe.mutex), MBEDTLS_ERR_THREADING_USAGE_ERROR);
}

struct allocator_probe {
	struct k_sem *start;
	psa_status_t result;
	uint8_t output[32];
};

static void concurrent_psa_worker(void *first, void *second, void *third)
{
	struct allocator_probe *probe = first;
	const uint8_t secret[32] = {0x73};
	const uint8_t message[] = "parallel allocator and key-slot regression";
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	ARG_UNUSED(second);
	ARG_UNUSED(third);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, 256U);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	(void)k_sem_take(probe->start, K_FOREVER);
	for (unsigned int i = 0U; i < 256U; ++i) {
		mbedtls_svc_key_id_t key = 0;
		size_t length = 0U;
		psa_status_t cleanup;

		probe->result = psa_import_key(&attributes, secret, sizeof(secret), &key);
		if (probe->result == PSA_SUCCESS) {
			probe->result = psa_mac_compute(key, PSA_ALG_HMAC(PSA_ALG_SHA_256),
				message, sizeof(message), probe->output, sizeof(probe->output), &length);
		}
		cleanup = psa_destroy_key(key);
		if (probe->result == PSA_SUCCESS && cleanup != PSA_SUCCESS) {
			probe->result = cleanup;
		}
		if (probe->result != PSA_SUCCESS || length != sizeof(probe->output)) {
			if (probe->result == PSA_SUCCESS) {
				probe->result = PSA_ERROR_CORRUPTION_DETECTED;
			}
			break;
		}
		k_yield();
	}
	psa_reset_key_attributes(&attributes);
}

ZTEST(pqcp_tls_loopback, test_parallel_psa_allocator_and_key_slots)
{
	struct k_sem start;
	struct allocator_probe left = {.start = &start};
	struct allocator_probe right = {.start = &start};

	zassert_equal(psa_crypto_init(), PSA_SUCCESS);
	k_sem_init(&start, 0U, 2U);
	k_thread_create(&client_thread, client_stack, K_THREAD_STACK_SIZEOF(client_stack),
		concurrent_psa_worker, &left, NULL, NULL, 5, 0, K_NO_WAIT);
	k_thread_create(&server_thread, server_stack, K_THREAD_STACK_SIZEOF(server_stack),
		concurrent_psa_worker, &right, NULL, NULL, 5, 0, K_NO_WAIT);
	k_sem_give(&start);
	k_sem_give(&start);
	zassert_ok(k_thread_join(&client_thread, K_SECONDS(10)));
	zassert_ok(k_thread_join(&server_thread, K_SECONDS(10)));
	zassert_equal(left.result, PSA_SUCCESS);
	zassert_equal(right.result, PSA_SUCCESS);
	zassert_mem_equal(left.output, right.output, sizeof(left.output));
}

static void run_tls_pair(enum live_test_mode mode)
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
	uint32_t started = k_cycle_get_32();

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
#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
	connect_tcp_pair();
#endif
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

	if (mode != LIVE_STALE_RECORD) {
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
	} else {
		/* Reconnect under the same out-of-band provisioned identity/pin.
		 * Do not trust a replacement public key delivered by this session.
		 */
		zassert_not_null(pqcp_runtime_identity_find(&client_runtime.identities, "server-peer"));
		zassert_not_null(pqcp_runtime_identity_find(&server_runtime.identities, "server-local"));
		zassert_equal(client_runtime.key_store.active_count, 1U);
		zassert_equal(server_runtime.key_store.active_count, 1U);
	}
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
		&server_thread, K_SECONDS(150)));
	zassert_equal(client_result, 0,
		      "client PQC handshake returned %d", client_result);
	zassert_equal(server_result, 0,
		      "server PQC handshake returned %d", server_result);
	printk("PQCP_CHANNEL_RECOVERY case=handshake mode=%u cycles=%u environment=qemu\n",
		mode, k_cycle_get_32() - started);
	if (mode == LIVE_STALE_RECORD) {
		zassert_true(previous_record_length > 0U);
		zassert_not_equal(memcmp(previous_exporter, client_exporter, sizeof(client_exporter)), 0);
		/* Same session ID and first application sequence, but fresh TLS/KEM
		 * keys: rejection must depend on authentication, not an ID mismatch.
		 */
		zassert_ok(client_transport.send(client_transport.context, previous_record,
			previous_record_length, TLS_TIMEOUT_MS));
		zassert_equal(pqcp_channel_receive(&server_channel, received,
			sizeof(received), &received_length), -EBADMSG);
		zassert_equal(received_length, 0U);
		zassert_equal(server_runtime.key_store.active_count, 1U);
		printk("PQCP_CHANNEL_RECOVERY case=old_record_fresh_handshake status=PASS environment=qemu\n");
		goto cleanup;
	}
	zassert_ok(pqcp_channel_send(
		&client_channel, protected_message,
		sizeof(protected_message) - 1U));
	if (mode == LIVE_RECOVERY) {
		previous_record_length = PQCP_CHANNEL_FRAME_HEADER_BYTES +
			sizeof(protected_message) - 1U + PQCP_CHANNEL_AEAD_TAG_BYTES;
		zassert_true(previous_record_length <= sizeof(previous_record));
		memcpy(previous_record, client_channel.tx_frame, previous_record_length);
		memcpy(previous_exporter, client_exporter, sizeof(previous_exporter));
	}
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
	if (mode == LIVE_RECOVERY) {
		exercise_live_recovery();
	} else if (mode == LIVE_UNCERTAIN_CONTROL) {
		exercise_terminal_control_failure();
	} else if (mode == LIVE_IDLE_TIMEOUT) {
		struct pqcp_channel_rekey_policy policy;

		initialize_operations(&client_operations, &client_channel);
		zassert_ok(pqcp_channel_rekey_policy_default(&policy));
		zassert_equal(pqcp_channel_operations_tick(&client_operations.operations,
			&policy, 181001U), -ETIMEDOUT);
		zassert_false(client_channel.established);
		zassert_equal(client_runtime.key_store.active_count, 1U);
		printk("PQCP_CHANNEL_RECOVERY case=unreachable_peer status=PASS traffic_keys=0 environment=qemu\n");
	} else if (mode == LIVE_CLOSE_TIMEOUT) {
		int64_t close_started = k_uptime_get();

		mbedtls_ssl_set_bio(&client_endpoint.ssl, &client_bio,
			stalled_bio_send, stalled_bio_receive, NULL);
		client_adapter.default_timeout_ms = 20U;
		zassert_equal(pqcp_channel_mbedtls_close(&client_adapter), -ETIMEDOUT);
		zassert_true(k_uptime_get() - close_started >= 20);
		zassert_true(k_uptime_get() - close_started < 500);
		zassert_false(client_adapter.handshake_complete);
		zassert_equal(pqcp_channel_close(&client_channel), -EINVAL);
		zassert_equal(client_runtime.key_store.active_count, 1U);
		printk("PQCP_CHANNEL_RECOVERY case=close_notify_deadline status=PASS environment=qemu\n");
	}
cleanup:
	zassert_ok(pqcp_channel_close(&client_channel));
	zassert_ok(pqcp_channel_close(&server_channel));
	zassert_equal(client_runtime.key_store.active_count, 1U);
	zassert_equal(server_runtime.key_store.active_count, 1U);
	if (mode != LIVE_RECOVERY) {
		zassert_ok(pqcp_runtime_identity_remove(&client_runtime.identities, "client-local"));
		zassert_ok(pqcp_runtime_identity_remove(&server_runtime.identities, "server-local"));
		zassert_equal(client_runtime.key_store.active_count, 0U);
		zassert_equal(server_runtime.key_store.active_count, 0U);
	}
	pqcp_tls_endpoint_free(&client_endpoint);
	pqcp_tls_endpoint_free(&server_endpoint);
}

ZTEST(pqcp_tls_loopback, test_tls13_psk_exporter_and_transport)
{
	run_tls_pair(LIVE_BASIC);
}

ZTEST(pqcp_tls_loopback, test_live_rekey_recovery_and_fresh_handshake)
{
	run_tls_pair(LIVE_RECOVERY);
	run_tls_pair(LIVE_STALE_RECORD);
}

ZTEST(pqcp_tls_loopback, test_partial_control_send_erases_keys)
{
	run_tls_pair(LIVE_UNCERTAIN_CONTROL);
}

ZTEST(pqcp_tls_loopback, test_unreachable_peer_erases_keys)
{
	run_tls_pair(LIVE_IDLE_TIMEOUT);
}

ZTEST(pqcp_tls_loopback, test_close_notify_honors_deadline)
{
	run_tls_pair(LIVE_CLOSE_TIMEOUT);
}

static void release_tls_fixture(void *fixture)
{
	ARG_UNUSED(fixture);
	if (client_endpoint.configured) {
		pqcp_tls_endpoint_free(&client_endpoint);
	}
	if (server_endpoint.configured) {
		pqcp_tls_endpoint_free(&server_endpoint);
	}
}

ZTEST_SUITE(pqcp_tls_loopback, NULL, NULL, NULL, release_tls_fixture, NULL);
