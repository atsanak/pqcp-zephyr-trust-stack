/*
 * SPDX-License-Identifier: MIT
 *
 * Bounded multi-transport routing for fleet control traffic.
 *
 * The multiplexer is allocation-free. Every adapter, queued message,
 * reassembly buffer, wire scratch buffer, and audit record is supplied by the
 * caller and must remain valid for the lifetime of the multiplexer.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_TRANSPORT_MUX_H_
#define PQCP_ZEPHYR_FLEET_TRANSPORT_MUX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_TRANSPORT_SCHEMA_VERSION 1U
#define PQCP_FLEET_TRANSPORT_MAGIC 0x5046544dU
#define PQCP_FLEET_TRANSPORT_BINDING_BYTES PQCP_FLEET_DIGEST_BYTES
#define PQCP_FLEET_TRANSPORT_FRAME_DIGEST_BYTES PQCP_FLEET_DIGEST_BYTES
#define PQCP_FLEET_TRANSPORT_HEADER_BYTES 136U
#define PQCP_FLEET_TRANSPORT_MIN_MTU \
	(PQCP_FLEET_TRANSPORT_HEADER_BYTES + 1U)
#define PQCP_FLEET_TRANSPORT_REPLAY_WINDOW 64U
#define PQCP_FLEET_TRANSPORT_PRIORITY_COUNT 4U
#define PQCP_FLEET_TRANSPORT_MAX_ADAPTER_SNAPSHOTS 32U
#define PQCP_FLEET_TRANSPORT_MAX_ROUTE_SCORE UINT32_MAX

#define PQCP_FLEET_TRANSPORT_CAP_RELIABLE (1U << 0)
#define PQCP_FLEET_TRANSPORT_CAP_ORDERED (1U << 1)
#define PQCP_FLEET_TRANSPORT_CAP_DATAGRAM (1U << 2)
#define PQCP_FLEET_TRANSPORT_CAP_FULL_DUPLEX (1U << 3)
#define PQCP_FLEET_TRANSPORT_CAP_BROADCAST (1U << 4)
#define PQCP_FLEET_TRANSPORT_CAP_METERED (1U << 5)
#define PQCP_FLEET_TRANSPORT_CAP_LOW_POWER (1U << 6)
#define PQCP_FLEET_TRANSPORT_CAP_LOW_LATENCY (1U << 7)
#define PQCP_FLEET_TRANSPORT_CAP_HARDWARE_BOUND (1U << 8)
#define PQCP_FLEET_TRANSPORT_CAP_CONFIDENTIAL (1U << 9)
#define PQCP_FLEET_TRANSPORT_CAP_AUTHENTICATED (1U << 10)
#define PQCP_FLEET_TRANSPORT_CAP_ROAMING (1U << 11)
#define PQCP_FLEET_TRANSPORT_CAP_WAKE_ON_RX (1U << 12)
#define PQCP_FLEET_TRANSPORT_CAP_FRAGMENTATION (1U << 13)
#define PQCP_FLEET_TRANSPORT_CAP_KNOWN_MASK \
	(PQCP_FLEET_TRANSPORT_CAP_RELIABLE | \
	 PQCP_FLEET_TRANSPORT_CAP_ORDERED | \
	 PQCP_FLEET_TRANSPORT_CAP_DATAGRAM | \
	 PQCP_FLEET_TRANSPORT_CAP_FULL_DUPLEX | \
	 PQCP_FLEET_TRANSPORT_CAP_BROADCAST | \
	 PQCP_FLEET_TRANSPORT_CAP_METERED | \
	 PQCP_FLEET_TRANSPORT_CAP_LOW_POWER | \
	 PQCP_FLEET_TRANSPORT_CAP_LOW_LATENCY | \
	 PQCP_FLEET_TRANSPORT_CAP_HARDWARE_BOUND | \
	 PQCP_FLEET_TRANSPORT_CAP_CONFIDENTIAL | \
	 PQCP_FLEET_TRANSPORT_CAP_AUTHENTICATED | \
	 PQCP_FLEET_TRANSPORT_CAP_ROAMING | \
	 PQCP_FLEET_TRANSPORT_CAP_WAKE_ON_RX | \
	 PQCP_FLEET_TRANSPORT_CAP_FRAGMENTATION)

#define PQCP_FLEET_TRANSPORT_FLAG_FIRST (1U << 0)
#define PQCP_FLEET_TRANSPORT_FLAG_LAST (1U << 1)
#define PQCP_FLEET_TRANSPORT_FLAG_ACK_REQUIRED (1U << 2)
#define PQCP_FLEET_TRANSPORT_FLAG_RETRANSMIT (1U << 3)
#define PQCP_FLEET_TRANSPORT_FLAG_FAILOVER (1U << 4)
#define PQCP_FLEET_TRANSPORT_FLAG_CONTROL (1U << 5)
#define PQCP_FLEET_TRANSPORT_FLAG_KNOWN_MASK \
	(PQCP_FLEET_TRANSPORT_FLAG_FIRST | \
	 PQCP_FLEET_TRANSPORT_FLAG_LAST | \
	 PQCP_FLEET_TRANSPORT_FLAG_ACK_REQUIRED | \
	 PQCP_FLEET_TRANSPORT_FLAG_RETRANSMIT | \
	 PQCP_FLEET_TRANSPORT_FLAG_FAILOVER | \
	 PQCP_FLEET_TRANSPORT_FLAG_CONTROL)

enum pqcp_fleet_transport_priority {
	PQCP_FLEET_TRANSPORT_PRIORITY_BACKGROUND = 0,
	PQCP_FLEET_TRANSPORT_PRIORITY_NORMAL,
	PQCP_FLEET_TRANSPORT_PRIORITY_URGENT,
	PQCP_FLEET_TRANSPORT_PRIORITY_CRITICAL,
};

enum pqcp_fleet_transport_frame_type {
	PQCP_FLEET_TRANSPORT_FRAME_DATA = 1,
	PQCP_FLEET_TRANSPORT_FRAME_ACK,
	PQCP_FLEET_TRANSPORT_FRAME_WINDOW_UPDATE,
	PQCP_FLEET_TRANSPORT_FRAME_PROBE,
	PQCP_FLEET_TRANSPORT_FRAME_PROBE_ACK,
	PQCP_FLEET_TRANSPORT_FRAME_RESET,
};

enum pqcp_fleet_transport_link_state {
	PQCP_FLEET_TRANSPORT_LINK_UNUSED = 0,
	PQCP_FLEET_TRANSPORT_LINK_DOWN,
	PQCP_FLEET_TRANSPORT_LINK_PROBING,
	PQCP_FLEET_TRANSPORT_LINK_HEALTHY,
	PQCP_FLEET_TRANSPORT_LINK_DEGRADED,
	PQCP_FLEET_TRANSPORT_LINK_BACKOFF,
	PQCP_FLEET_TRANSPORT_LINK_DISABLED,
};

enum pqcp_fleet_transport_message_state {
	PQCP_FLEET_TRANSPORT_MESSAGE_FREE = 0,
	PQCP_FLEET_TRANSPORT_MESSAGE_QUEUED,
	PQCP_FLEET_TRANSPORT_MESSAGE_SENDING,
	PQCP_FLEET_TRANSPORT_MESSAGE_WAITING_ACK,
	PQCP_FLEET_TRANSPORT_MESSAGE_RETRY_WAIT,
	PQCP_FLEET_TRANSPORT_MESSAGE_DELIVERED,
	PQCP_FLEET_TRANSPORT_MESSAGE_FAILED,
};

enum pqcp_fleet_transport_reassembly_state {
	PQCP_FLEET_TRANSPORT_REASSEMBLY_FREE = 0,
	PQCP_FLEET_TRANSPORT_REASSEMBLY_RECEIVING,
	PQCP_FLEET_TRANSPORT_REASSEMBLY_COMPLETE,
};

enum pqcp_fleet_transport_audit_event {
	PQCP_FLEET_TRANSPORT_AUDIT_NONE = 0,
	PQCP_FLEET_TRANSPORT_AUDIT_ADAPTER_REGISTERED,
	PQCP_FLEET_TRANSPORT_AUDIT_ADAPTER_STATE,
	PQCP_FLEET_TRANSPORT_AUDIT_CHANNEL_BOUND,
	PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_QUEUED,
	PQCP_FLEET_TRANSPORT_AUDIT_ROUTE_SELECTED,
	PQCP_FLEET_TRANSPORT_AUDIT_FRAME_SENT,
	PQCP_FLEET_TRANSPORT_AUDIT_FRAME_RECEIVED,
	PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_ACKED,
	PQCP_FLEET_TRANSPORT_AUDIT_WINDOW_UPDATED,
	PQCP_FLEET_TRANSPORT_AUDIT_RETRY_SCHEDULED,
	PQCP_FLEET_TRANSPORT_AUDIT_FAILOVER,
	PQCP_FLEET_TRANSPORT_AUDIT_DUPLICATE_REJECTED,
	PQCP_FLEET_TRANSPORT_AUDIT_REPLAY_REJECTED,
	PQCP_FLEET_TRANSPORT_AUDIT_FRAME_REJECTED,
	PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_DELIVERED,
	PQCP_FLEET_TRANSPORT_AUDIT_MESSAGE_DROPPED,
	PQCP_FLEET_TRANSPORT_AUDIT_PROBE_SENT,
	PQCP_FLEET_TRANSPORT_AUDIT_PROBE_ACKED,
	PQCP_FLEET_TRANSPORT_AUDIT_EVENT_COUNT,
};

struct pqcp_fleet_transport_adapter;

struct pqcp_fleet_transport_adapter_ops {
	int (*open)(void *context);
	int (*close)(void *context);
	int (*send)(
		void *context,
		const uint8_t *frame,
		size_t frame_length,
		uint32_t timeout_ms);
	int (*receive)(
		void *context,
		uint8_t *frame,
		size_t frame_capacity,
		size_t *frame_length,
		uint32_t timeout_ms);
	int (*probe)(
		void *context,
		uint64_t probe_id,
		uint32_t timeout_ms);
};

struct pqcp_fleet_transport_metadata {
	uint32_t schema_version;
	uint32_t adapter_id;
	uint32_t capabilities;
	uint32_t mtu;
	uint32_t framing_overhead;
	uint32_t nominal_latency_ms;
	uint32_t nominal_jitter_ms;
	uint32_t nominal_bandwidth_bps;
	uint32_t energy_cost;
	uint32_t monetary_cost;
	uint32_t administrative_priority;
	uint32_t failure_domain;
};

struct pqcp_fleet_transport_health {
	enum pqcp_fleet_transport_link_state state;
	uint64_t last_state_change_ms;
	uint64_t last_send_ms;
	uint64_t last_receive_ms;
	uint64_t last_success_ms;
	uint64_t last_failure_ms;
	uint64_t backoff_until_ms;
	uint64_t last_probe_id;
	uint64_t probe_sent_at_ms;
	uint64_t smoothed_rtt_us;
	uint64_t rtt_variance_us;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t frames_sent;
	uint64_t frames_received;
	uint64_t send_failures;
	uint64_t receive_failures;
	uint64_t probe_count;
	uint64_t probe_failures;
	uint32_t consecutive_successes;
	uint32_t consecutive_failures;
	int last_error;
	bool probe_outstanding;
};

struct pqcp_fleet_transport_adapter {
	struct pqcp_fleet_transport_metadata metadata;
	struct pqcp_fleet_transport_adapter_ops ops;
	struct pqcp_fleet_transport_health health;
	void *context;
	uint32_t generation;
	bool enabled;
	bool opened;
	bool occupied;
};

struct pqcp_fleet_transport_policy {
	uint32_t schema_version;
	uint32_t required_capabilities;
	uint32_t preferred_capabilities;
	uint32_t forbidden_capabilities;
	uint32_t send_timeout_ms;
	uint32_t receive_timeout_ms;
	uint32_t initial_remote_window;
	uint32_t initial_local_window;
	uint32_t maximum_window;
	uint32_t window_update_threshold;
	uint32_t maximum_attempts;
	uint32_t degrade_after_failures;
	uint32_t down_after_failures;
	uint32_t recover_after_successes;
	uint32_t route_switch_hysteresis;
	uint32_t latency_weight;
	uint32_t jitter_weight;
	uint32_t energy_weight;
	uint32_t monetary_weight;
	uint32_t failure_weight;
	uint32_t priority_weight;
	uint64_t acknowledgement_timeout_ms;
	uint64_t base_retry_ms;
	uint64_t maximum_retry_ms;
	uint64_t adapter_backoff_ms;
	uint64_t probe_interval_ms;
	uint64_t probe_timeout_ms;
	uint64_t reassembly_timeout_ms;
	bool require_acknowledgements;
	bool allow_fragmentation;
	bool allow_metered_failover;
	bool prefer_sticky_route;
};

struct pqcp_fleet_transport_frame_header {
	uint32_t magic;
	uint16_t schema_version;
	uint16_t type;
	uint32_t flags;
	uint32_t header_bytes;
	uint64_t channel_id;
	uint64_t message_id;
	uint64_t sequence;
	uint64_t acknowledgement_sequence;
	uint32_t fragment_offset;
	uint32_t message_length;
	uint32_t payload_length;
	uint32_t window_credit;
	uint32_t priority;
	uint32_t adapter_hint;
	uint8_t channel_binding[PQCP_FLEET_TRANSPORT_BINDING_BYTES];
	uint8_t payload_digest[PQCP_FLEET_TRANSPORT_FRAME_DIGEST_BYTES];
};

struct pqcp_fleet_transport_frame_view {
	struct pqcp_fleet_transport_frame_header header;
	const uint8_t *payload;
	size_t payload_length;
};

struct pqcp_fleet_transport_message {
	uint64_t message_id;
	uint64_t sequence;
	uint64_t enqueued_at_ms;
	uint64_t expires_at_ms;
	uint64_t next_attempt_ms;
	uint64_t acknowledgement_deadline_ms;
	size_t length;
	size_t next_offset;
	uint8_t *storage;
	size_t storage_capacity;
	uint32_t required_capabilities;
	uint32_t preferred_adapter_id;
	uint32_t active_adapter_id;
	uint32_t previous_adapter_id;
	uint32_t attempts;
	uint32_t route_failures;
	enum pqcp_fleet_transport_priority priority;
	enum pqcp_fleet_transport_message_state state;
	int last_error;
	bool acknowledgement_required;
	bool failover_used;
	bool occupied;
};

struct pqcp_fleet_transport_reassembly {
	uint64_t message_id;
	uint64_t sequence;
	uint64_t started_at_ms;
	uint64_t last_fragment_at_ms;
	size_t total_length;
	size_t received_length;
	uint8_t *storage;
	size_t storage_capacity;
	uint32_t adapter_id;
	enum pqcp_fleet_transport_priority priority;
	enum pqcp_fleet_transport_reassembly_state state;
	uint8_t message_digest[PQCP_FLEET_DIGEST_BYTES];
	bool acknowledgement_sent;
	bool occupied;
};

struct pqcp_fleet_transport_replay_state {
	uint64_t highest_sequence;
	uint64_t bitmap;
	bool initialized;
};

struct pqcp_fleet_transport_audit_entry {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t timestamp_ms;
	enum pqcp_fleet_transport_audit_event event;
	uint64_t channel_id;
	uint64_t message_id;
	uint64_t transport_sequence;
	uint32_t adapter_id;
	uint32_t detail;
	int result;
	uint8_t previous_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t entry_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_transport_adapter_snapshot {
	uint32_t adapter_id;
	uint32_t generation;
	uint32_t capabilities;
	uint32_t mtu;
	uint32_t route_score;
	enum pqcp_fleet_transport_link_state state;
	uint64_t smoothed_rtt_us;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t frames_sent;
	uint64_t frames_received;
	uint64_t send_failures;
	uint64_t receive_failures;
	uint32_t consecutive_failures;
	int last_error;
	bool enabled;
	bool opened;
};

struct pqcp_fleet_transport_snapshot {
	uint32_t schema_version;
	uint64_t captured_at_ms;
	uint64_t channel_id;
	uint64_t next_message_id;
	uint64_t next_send_sequence;
	uint64_t highest_receive_sequence;
	uint64_t total_frames_sent;
	uint64_t total_frames_received;
	uint64_t total_bytes_sent;
	uint64_t total_bytes_received;
	uint64_t acknowledged_messages;
	uint64_t delivered_messages;
	uint64_t retry_count;
	uint64_t failover_count;
	uint64_t duplicate_rejections;
	uint64_t replay_rejections;
	uint64_t malformed_rejections;
	uint64_t expired_messages;
	uint32_t remote_window;
	uint32_t local_window;
	uint32_t queued_by_priority[PQCP_FLEET_TRANSPORT_PRIORITY_COUNT];
	size_t adapter_count;
	size_t reassembly_count;
	size_t audit_count;
	struct pqcp_fleet_transport_adapter_snapshot *adapters;
	size_t adapter_capacity;
	uint8_t channel_binding[PQCP_FLEET_TRANSPORT_BINDING_BYTES];
	uint8_t audit_chain_head[PQCP_FLEET_DIGEST_BYTES];
	uint8_t snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_transport_mux {
	uint32_t schema_version;
	struct pqcp_fleet_transport_policy policy;
	struct pqcp_fleet_transport_adapter *adapters;
	size_t adapter_capacity;
	size_t adapter_count;
	struct pqcp_fleet_transport_message *messages;
	size_t message_capacity;
	size_t message_count;
	struct pqcp_fleet_transport_reassembly *reassemblies;
	size_t reassembly_capacity;
	size_t reassembly_count;
	struct pqcp_fleet_transport_audit_entry *audit_entries;
	size_t audit_capacity;
	size_t audit_count;
	size_t audit_next;
	uint8_t *message_storage;
	size_t message_storage_bytes;
	size_t message_slot_bytes;
	uint8_t *reassembly_storage;
	size_t reassembly_storage_bytes;
	size_t reassembly_slot_bytes;
	uint8_t *tx_scratch;
	size_t tx_scratch_capacity;
	uint8_t *rx_scratch;
	size_t rx_scratch_capacity;
	uint64_t channel_id;
	uint64_t next_message_id;
	uint64_t next_send_sequence;
	uint64_t next_audit_sequence;
	uint64_t next_probe_id;
	uint64_t total_frames_sent;
	uint64_t total_frames_received;
	uint64_t total_bytes_sent;
	uint64_t total_bytes_received;
	uint64_t acknowledged_messages;
	uint64_t delivered_messages;
	uint64_t retry_count;
	uint64_t failover_count;
	uint64_t duplicate_rejections;
	uint64_t replay_rejections;
	uint64_t malformed_rejections;
	uint64_t expired_messages;
	uint32_t remote_window;
	uint32_t local_window;
	uint32_t pending_window_credit;
	uint32_t sticky_adapter_id;
	struct pqcp_fleet_transport_replay_state inbound_replay;
	uint8_t channel_binding[PQCP_FLEET_TRANSPORT_BINDING_BYTES];
	uint8_t audit_chain_head[PQCP_FLEET_DIGEST_BYTES];
	struct k_mutex lock;
	struct k_mutex tx_lock;
	struct k_mutex rx_lock;
	bool channel_bound;
	bool initialized;
};

int pqcp_fleet_transport_policy_default(
	struct pqcp_fleet_transport_policy *policy);

int pqcp_fleet_transport_mux_init(
	struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_policy *policy,
	struct pqcp_fleet_transport_adapter *adapters,
	size_t adapter_capacity,
	struct pqcp_fleet_transport_message *messages,
	size_t message_capacity,
	uint8_t *message_storage,
	size_t message_storage_bytes,
	size_t message_slot_bytes,
	struct pqcp_fleet_transport_reassembly *reassemblies,
	size_t reassembly_capacity,
	uint8_t *reassembly_storage,
	size_t reassembly_storage_bytes,
	size_t reassembly_slot_bytes,
	uint8_t *tx_scratch,
	size_t tx_scratch_capacity,
	uint8_t *rx_scratch,
	size_t rx_scratch_capacity,
	struct pqcp_fleet_transport_audit_entry *audit_entries,
	size_t audit_capacity);

int pqcp_fleet_transport_adapter_register(
	struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_metadata *metadata,
	const struct pqcp_fleet_transport_adapter_ops *ops,
	void *context,
	uint64_t now_ms);

int pqcp_fleet_transport_adapter_unregister(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms);

int pqcp_fleet_transport_adapter_set_enabled(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	bool enabled,
	uint64_t now_ms);

int pqcp_fleet_transport_adapter_open(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms);

int pqcp_fleet_transport_adapter_close(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms);

int pqcp_fleet_transport_bind_channel(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t channel_id,
	const uint8_t *exporter,
	size_t exporter_length,
	const uint8_t *transcript_digest,
	size_t transcript_digest_length,
	const uint8_t *peer_identity_digest,
	size_t peer_identity_digest_length,
	uint64_t now_ms);

int pqcp_fleet_transport_frame_encode(
	const struct pqcp_fleet_transport_frame_header *header,
	const uint8_t *payload,
	size_t payload_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);

int pqcp_fleet_transport_frame_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_fleet_transport_frame_view *frame);

int pqcp_fleet_transport_route_score(
	const struct pqcp_fleet_transport_mux *mux,
	const struct pqcp_fleet_transport_adapter *adapter,
	uint32_t required_capabilities,
	size_t message_length,
	uint64_t now_ms,
	uint32_t *score);

int pqcp_fleet_transport_enqueue(
	struct pqcp_fleet_transport_mux *mux,
	const uint8_t *message,
	size_t message_length,
	enum pqcp_fleet_transport_priority priority,
	uint32_t required_capabilities,
	uint32_t preferred_adapter_id,
	bool acknowledgement_required,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t *message_id);

int pqcp_fleet_transport_service_tx(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t now_ms,
	uint64_t *message_id,
	bool *progressed);

int pqcp_fleet_transport_poll_adapter(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms,
	bool *progressed);

int pqcp_fleet_transport_poll(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t now_ms,
	uint32_t *frames_received);

int pqcp_fleet_transport_ingest(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	const uint8_t *frame,
	size_t frame_length,
	uint64_t now_ms);

int pqcp_fleet_transport_receive(
	struct pqcp_fleet_transport_mux *mux,
	uint8_t *message,
	size_t message_capacity,
	size_t *message_length,
	uint64_t *message_id,
	enum pqcp_fleet_transport_priority *priority,
	uint32_t *adapter_id,
	uint64_t now_ms);

int pqcp_fleet_transport_tick(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t now_ms,
	uint32_t *state_changes);

int pqcp_fleet_transport_probe(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	uint64_t now_ms);

int pqcp_fleet_transport_report_link_result(
	struct pqcp_fleet_transport_mux *mux,
	uint32_t adapter_id,
	int result,
	uint64_t rtt_us,
	uint64_t now_ms);

int pqcp_fleet_transport_snapshot(
	struct pqcp_fleet_transport_mux *mux,
	uint64_t now_ms,
	struct pqcp_fleet_transport_snapshot *snapshot);

int pqcp_fleet_transport_snapshot_verify(
	const struct pqcp_fleet_transport_snapshot *snapshot);

int pqcp_fleet_transport_audit(
	struct pqcp_fleet_transport_mux *mux);

int pqcp_fleet_transport_reset(
	struct pqcp_fleet_transport_mux *mux,
	bool retain_adapters,
	uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_TRANSPORT_MUX_H_ */
