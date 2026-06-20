/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Multiplexing, flow control, rekeying, and resumption for protected channels.
 */

#ifndef PQCP_ZEPHYR_PROTECTED_CHANNEL_OPERATIONS_H_
#define PQCP_ZEPHYR_PROTECTED_CHANNEL_OPERATIONS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/protected_channel.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_CHANNEL_OPERATION_SCHEMA_VERSION 1U
#define PQCP_CHANNEL_STREAM_HEADER_BYTES 32U
#define PQCP_CHANNEL_CONTROL_MAX_BYTES 512U
#define PQCP_CHANNEL_RESUMPTION_SECRET_BYTES 32U
#define PQCP_CHANNEL_RESUMPTION_NONCE_BYTES 12U
#define PQCP_CHANNEL_RESUMPTION_TAG_BYTES 16U
#define PQCP_CHANNEL_RESUMPTION_TICKET_MAX_BYTES 384U
#define PQCP_CHANNEL_REKEY_SALT_BYTES 32U
#define PQCP_CHANNEL_POLICY_STATE_COUNT 16U
#define PQCP_CHANNEL_POLICY_CONTROL_COUNT 32U

enum pqcp_channel_stream_state {
	PQCP_CHANNEL_STREAM_IDLE = 0,
	PQCP_CHANNEL_STREAM_OPEN,
	PQCP_CHANNEL_STREAM_HALF_CLOSED_LOCAL,
	PQCP_CHANNEL_STREAM_HALF_CLOSED_REMOTE,
	PQCP_CHANNEL_STREAM_CLOSED,
	PQCP_CHANNEL_STREAM_RESET,
};

enum pqcp_channel_stream_frame_type {
	PQCP_CHANNEL_STREAM_FRAME_OPEN = 1,
	PQCP_CHANNEL_STREAM_FRAME_DATA,
	PQCP_CHANNEL_STREAM_FRAME_WINDOW_UPDATE,
	PQCP_CHANNEL_STREAM_FRAME_CLOSE,
	PQCP_CHANNEL_STREAM_FRAME_RESET,
	PQCP_CHANNEL_STREAM_FRAME_PING,
	PQCP_CHANNEL_STREAM_FRAME_PONG,
};

enum pqcp_channel_stream_error {
	PQCP_CHANNEL_STREAM_ERROR_NONE = 0,
	PQCP_CHANNEL_STREAM_ERROR_PROTOCOL,
	PQCP_CHANNEL_STREAM_ERROR_FLOW_CONTROL,
	PQCP_CHANNEL_STREAM_ERROR_REFUSED,
	PQCP_CHANNEL_STREAM_ERROR_CANCELLED,
	PQCP_CHANNEL_STREAM_ERROR_TIMEOUT,
	PQCP_CHANNEL_STREAM_ERROR_INTERNAL,
};

enum pqcp_channel_control_kind {
	PQCP_CHANNEL_CONTROL_NONE = 0,
	PQCP_CHANNEL_CONTROL_STREAM_OPEN,
	PQCP_CHANNEL_CONTROL_STREAM_ACCEPT,
	PQCP_CHANNEL_CONTROL_STREAM_REFUSE,
	PQCP_CHANNEL_CONTROL_STREAM_CLOSE,
	PQCP_CHANNEL_CONTROL_STREAM_RESET,
	PQCP_CHANNEL_CONTROL_STREAM_WINDOW,
	PQCP_CHANNEL_CONTROL_CONNECTION_WINDOW,
	PQCP_CHANNEL_CONTROL_REKEY_PREPARE,
	PQCP_CHANNEL_CONTROL_REKEY_ACCEPT,
	PQCP_CHANNEL_CONTROL_REKEY_COMMIT,
	PQCP_CHANNEL_CONTROL_REKEY_ABORT,
	PQCP_CHANNEL_CONTROL_TICKET_REQUEST,
	PQCP_CHANNEL_CONTROL_TICKET_ISSUE,
	PQCP_CHANNEL_CONTROL_TICKET_ACCEPT,
	PQCP_CHANNEL_CONTROL_TICKET_REJECT,
	PQCP_CHANNEL_CONTROL_PATH_CHALLENGE,
	PQCP_CHANNEL_CONTROL_PATH_RESPONSE,
	PQCP_CHANNEL_CONTROL_PEER_HEALTH,
	PQCP_CHANNEL_CONTROL_PEER_DRAIN,
	PQCP_CHANNEL_CONTROL_PEER_DRAINED,
	PQCP_CHANNEL_CONTROL_KEEPALIVE,
	PQCP_CHANNEL_CONTROL_KEEPALIVE_ACK,
	PQCP_CHANNEL_CONTROL_PROFILE_OFFER,
	PQCP_CHANNEL_CONTROL_PROFILE_ACCEPT,
	PQCP_CHANNEL_CONTROL_PROFILE_REJECT,
	PQCP_CHANNEL_CONTROL_KEY_UPDATE_REQUEST,
	PQCP_CHANNEL_CONTROL_KEY_UPDATE_ACK,
	PQCP_CHANNEL_CONTROL_GOAWAY,
	PQCP_CHANNEL_CONTROL_ERROR,
	PQCP_CHANNEL_CONTROL_AUDIT_REQUEST,
	PQCP_CHANNEL_CONTROL_AUDIT_RESPONSE,
	PQCP_CHANNEL_CONTROL_KIND_COUNT,
};

enum pqcp_channel_policy_state {
	PQCP_CHANNEL_POLICY_NEW = 0,
	PQCP_CHANNEL_POLICY_NEGOTIATING,
	PQCP_CHANNEL_POLICY_AUTHENTICATING,
	PQCP_CHANNEL_POLICY_ESTABLISHED,
	PQCP_CHANNEL_POLICY_REKEY_PREPARED,
	PQCP_CHANNEL_POLICY_REKEY_ACCEPTED,
	PQCP_CHANNEL_POLICY_REKEY_COMMITTING,
	PQCP_CHANNEL_POLICY_RESUMING,
	PQCP_CHANNEL_POLICY_MIGRATING,
	PQCP_CHANNEL_POLICY_DRAINING,
	PQCP_CHANNEL_POLICY_CLOSING,
	PQCP_CHANNEL_POLICY_CLOSED,
	PQCP_CHANNEL_POLICY_FAILED,
	PQCP_CHANNEL_POLICY_SUSPENDED,
	PQCP_CHANNEL_POLICY_RECOVERING,
	PQCP_CHANNEL_POLICY_TERMINATED,
};

enum pqcp_channel_policy_action {
	PQCP_CHANNEL_POLICY_DENY = 0,
	PQCP_CHANNEL_POLICY_ALLOW,
	PQCP_CHANNEL_POLICY_ALLOW_IDEMPOTENT,
	PQCP_CHANNEL_POLICY_REQUIRE_ESTABLISHED,
	PQCP_CHANNEL_POLICY_REQUIRE_REKEY,
	PQCP_CHANNEL_POLICY_REQUIRE_DRAIN,
	PQCP_CHANNEL_POLICY_CLOSE_ON_FAILURE,
};

enum pqcp_channel_rekey_state {
	PQCP_CHANNEL_REKEY_IDLE = 0,
	PQCP_CHANNEL_REKEY_PREPARED,
	PQCP_CHANNEL_REKEY_ACCEPTED,
	PQCP_CHANNEL_REKEY_COMMITTED,
	PQCP_CHANNEL_REKEY_ABORTED,
};

enum pqcp_channel_peer_status {
	PQCP_CHANNEL_PEER_UNKNOWN = 0,
	PQCP_CHANNEL_PEER_HEALTHY,
	PQCP_CHANNEL_PEER_SUSPECT,
	PQCP_CHANNEL_PEER_UNREACHABLE,
	PQCP_CHANNEL_PEER_DRAINING,
	PQCP_CHANNEL_PEER_CLOSED,
};

enum pqcp_channel_path_state {
	PQCP_CHANNEL_PATH_UNUSED = 0,
	PQCP_CHANNEL_PATH_PROBING,
	PQCP_CHANNEL_PATH_VALIDATED,
	PQCP_CHANNEL_PATH_ACTIVE,
	PQCP_CHANNEL_PATH_DRAINING,
	PQCP_CHANNEL_PATH_FAILED,
};

enum pqcp_channel_path_condition {
	PQCP_CHANNEL_PATH_CONDITION_PRIMARY_HEALTHY = 0,
	PQCP_CHANNEL_PATH_CONDITION_PRIMARY_SLOW,
	PQCP_CHANNEL_PATH_CONDITION_PRIMARY_IDLE,
	PQCP_CHANNEL_PATH_CONDITION_PRIMARY_FAILED,
	PQCP_CHANNEL_PATH_CONDITION_CANDIDATE_PROBING,
	PQCP_CHANNEL_PATH_CONDITION_CANDIDATE_VALIDATED,
	PQCP_CHANNEL_PATH_CONDITION_CANDIDATE_FASTER,
	PQCP_CHANNEL_PATH_CONDITION_CANDIDATE_SLOWER,
	PQCP_CHANNEL_PATH_CONDITION_MIGRATING,
	PQCP_CHANNEL_PATH_CONDITION_DRAINING,
	PQCP_CHANNEL_PATH_CONDITION_REKEYING,
	PQCP_CHANNEL_PATH_CONDITION_RESUMING,
	PQCP_CHANNEL_PATH_CONDITION_PEER_SUSPECT,
	PQCP_CHANNEL_PATH_CONDITION_PEER_UNREACHABLE,
	PQCP_CHANNEL_PATH_CONDITION_NO_VALID_PATH,
	PQCP_CHANNEL_PATH_CONDITION_TERMINATED,
	PQCP_CHANNEL_PATH_CONDITION_COUNT,
};

enum pqcp_channel_path_disposition {
	PQCP_CHANNEL_PATH_DENY = 0,
	PQCP_CHANNEL_PATH_ALLOW,
	PQCP_CHANNEL_PATH_ALLOW_PROBE,
	PQCP_CHANNEL_PATH_ALLOW_MIGRATE,
	PQCP_CHANNEL_PATH_ALLOW_DRAIN,
	PQCP_CHANNEL_PATH_REQUIRE_REKEY,
	PQCP_CHANNEL_PATH_CLOSE,
};

enum pqcp_channel_fault_condition {
	PQCP_CHANNEL_FAULT_NONE = 0,
	PQCP_CHANNEL_FAULT_TRANSIENT_IO,
	PQCP_CHANNEL_FAULT_TIMEOUT,
	PQCP_CHANNEL_FAULT_FLOW_CONTROL,
	PQCP_CHANNEL_FAULT_STREAM_PROTOCOL,
	PQCP_CHANNEL_FAULT_CONTROL_PROTOCOL,
	PQCP_CHANNEL_FAULT_AUTHENTICATION,
	PQCP_CHANNEL_FAULT_REPLAY,
	PQCP_CHANNEL_FAULT_REKEY,
	PQCP_CHANNEL_FAULT_TICKET,
	PQCP_CHANNEL_FAULT_PATH_VALIDATION,
	PQCP_CHANNEL_FAULT_PEER_SUSPECT,
	PQCP_CHANNEL_FAULT_PEER_UNREACHABLE,
	PQCP_CHANNEL_FAULT_POLICY,
	PQCP_CHANNEL_FAULT_INTERNAL,
	PQCP_CHANNEL_FAULT_TERMINAL,
	PQCP_CHANNEL_FAULT_CONDITION_COUNT,
};

enum pqcp_channel_fault_directive {
	PQCP_CHANNEL_FAULT_IGNORE = 0,
	PQCP_CHANNEL_FAULT_OBSERVE,
	PQCP_CHANNEL_FAULT_RETRY,
	PQCP_CHANNEL_FAULT_BACKOFF,
	PQCP_CHANNEL_FAULT_RESET_STREAM,
	PQCP_CHANNEL_FAULT_REKEY_CHANNEL,
	PQCP_CHANNEL_FAULT_MIGRATE_PATH,
	PQCP_CHANNEL_FAULT_DRAIN_CHANNEL,
	PQCP_CHANNEL_FAULT_CLOSE_CHANNEL,
	PQCP_CHANNEL_FAULT_TERMINATE_CHANNEL,
};

struct pqcp_channel_stream_header {
	uint32_t schema_version;
	enum pqcp_channel_stream_frame_type type;
	uint32_t flags;
	uint32_t stream_id;
	uint64_t sequence;
	uint32_t payload_length;
	uint32_t credit;
	uint32_t error;
};

struct pqcp_channel_stream {
	uint32_t stream_id;
	enum pqcp_channel_stream_state state;
	uint32_t priority;
	uint32_t local_window;
	uint32_t remote_window;
	uint64_t next_send_sequence;
	uint64_t next_receive_sequence;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t opened_at_ms;
	uint64_t last_activity_ms;
	enum pqcp_channel_stream_error error;
	bool locally_initiated;
	bool occupied;
};

struct pqcp_channel_multiplexer {
	struct pqcp_channel *channel;
	struct pqcp_channel_stream *streams;
	size_t capacity;
	size_t count;
	uint32_t next_local_stream_id;
	uint32_t connection_local_window;
	uint32_t connection_remote_window;
	uint32_t initial_stream_window;
	uint64_t frames_sent;
	uint64_t frames_received;
	uint64_t rejected_frames;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_channel_flow_policy {
	uint32_t schema_version;
	uint32_t initial_connection_window;
	uint32_t initial_stream_window;
	uint32_t maximum_connection_window;
	uint32_t maximum_stream_window;
	uint32_t update_threshold;
	uint32_t maximum_frame_payload;
	bool reject_window_overflow;
	bool auto_update;
};

struct pqcp_channel_flow_controller {
	struct pqcp_channel_flow_policy policy;
	uint32_t local_connection_window;
	uint32_t remote_connection_window;
	uint64_t consumed_local;
	uint64_t consumed_remote;
	uint64_t updates_sent;
	uint64_t updates_received;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_channel_rekey_context {
	uint32_t schema_version;
	enum pqcp_channel_rekey_state state;
	uint64_t current_epoch;
	uint64_t pending_epoch;
	uint64_t prepared_at_ms;
	uint64_t expires_at_ms;
	uint64_t bytes_at_prepare;
	uint8_t salt[PQCP_CHANNEL_REKEY_SALT_BYTES];
	uint8_t confirmation[PQCP_CHANNEL_FINISHED_BYTES];
	struct pqcp_channel_keys pending_keys;
	bool initiator;
};

struct pqcp_channel_rekey_policy {
	uint32_t schema_version;
	uint64_t maximum_epoch_bytes;
	uint64_t maximum_epoch_ms;
	uint32_t minimum_interval_ms;
	uint32_t handshake_timeout_ms;
	bool require_peer_confirmation;
	bool close_on_failure;
};

struct pqcp_channel_resumption_claims {
	uint32_t schema_version;
	uint64_t ticket_id;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t original_session_id;
	uint64_t channel_epoch;
	uint32_t mlkem_level;
	uint32_t mldsa_level;
	uint32_t flags;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	uint8_t peer_identity_digest[PQCP_CHANNEL_HASH_BYTES];
	uint8_t transcript_digest[PQCP_CHANNEL_HASH_BYTES];
};

struct pqcp_channel_resumption_ticket {
	uint8_t bytes[PQCP_CHANNEL_RESUMPTION_TICKET_MAX_BYTES];
	size_t length;
	uint64_t ticket_id;
	uint64_t expires_at_ms;
};

struct pqcp_channel_ticket_replay_entry {
	uint64_t ticket_id;
	uint64_t accepted_at_ms;
	bool occupied;
};

struct pqcp_channel_resumption_store {
	uint8_t secret[PQCP_CHANNEL_RESUMPTION_SECRET_BYTES];
	struct pqcp_channel_ticket_replay_entry *replay_entries;
	size_t replay_capacity;
	size_t next_replay_slot;
	uint64_t next_ticket_id;
	uint64_t issued;
	uint64_t accepted;
	uint64_t rejected;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_channel_control_message {
	uint32_t schema_version;
	enum pqcp_channel_control_kind kind;
	uint32_t flags;
	uint64_t message_id;
	uint64_t timestamp_ms;
	uint64_t epoch;
	uint32_t stream_id;
	uint32_t value;
	uint32_t error;
	uint8_t payload[PQCP_CHANNEL_CONTROL_MAX_BYTES];
	size_t payload_length;
};

struct pqcp_channel_policy_decision {
	enum pqcp_channel_policy_state state;
	enum pqcp_channel_control_kind control;
	enum pqcp_channel_policy_action action;
	enum pqcp_channel_policy_state next_state;
	int error;
	uint32_t flags;
};

struct pqcp_channel_peer_policy {
	uint32_t schema_version;
	uint32_t keepalive_interval_ms;
	uint32_t keepalive_timeout_ms;
	uint32_t maximum_missed_keepalives;
	uint32_t suspect_rtt_ms;
	uint32_t unreachable_rtt_ms;
	uint32_t idle_timeout_ms;
};

struct pqcp_channel_peer_health {
	uint32_t schema_version;
	enum pqcp_channel_peer_status status;
	uint64_t last_send_ms;
	uint64_t last_receive_ms;
	uint64_t last_probe_ms;
	uint64_t last_ack_ms;
	uint64_t smoothed_rtt_us;
	uint64_t rtt_variance_us;
	uint64_t probes_sent;
	uint64_t probes_acked;
	uint64_t probes_missed;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint32_t consecutive_misses;
	bool probe_outstanding;
};

struct pqcp_channel_operations {
	struct pqcp_channel *channel;
	struct pqcp_channel_multiplexer *multiplexer;
	struct pqcp_channel_flow_controller *flow;
	struct pqcp_channel_rekey_context *rekey;
	struct pqcp_channel_resumption_store *resumption;
	struct pqcp_channel_peer_health *peer;
	struct pqcp_channel_peer_policy peer_policy;
	enum pqcp_channel_policy_state state;
	uint64_t epoch_started_at_ms;
	uint64_t next_control_id;
	uint64_t controls_sent;
	uint64_t controls_received;
	uint64_t failures;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_channel_path {
	uint32_t path_id;
	enum pqcp_channel_path_state state;
	uint64_t challenge;
	uint64_t created_at_ms;
	uint64_t validated_at_ms;
	uint64_t last_activity_ms;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t smoothed_rtt_us;
	uint32_t failures;
	uint32_t priority;
	bool occupied;
};

struct pqcp_channel_path_policy {
	uint32_t schema_version;
	uint32_t validation_timeout_ms;
	uint32_t idle_timeout_ms;
	uint32_t maximum_failures;
	uint32_t migration_hysteresis_bps;
	bool allow_automatic_migration;
};

struct pqcp_channel_path_manager {
	struct pqcp_channel_path_policy policy;
	struct pqcp_channel_path *paths;
	size_t capacity;
	size_t count;
	uint32_t active_path_id;
	uint32_t next_path_id;
	uint64_t migrations;
	uint64_t failed_migrations;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_channel_path_policy_decision {
	enum pqcp_channel_path_condition condition;
	enum pqcp_channel_control_kind control;
	enum pqcp_channel_path_disposition disposition;
	uint32_t probe_timeout_ms;
	uint32_t migration_hysteresis_bps;
	uint32_t reason_mask;
	enum pqcp_channel_policy_state next_state;
	int error;
};

struct pqcp_channel_fault_policy_decision {
	enum pqcp_channel_fault_condition condition;
	enum pqcp_channel_control_kind control;
	enum pqcp_channel_fault_directive directive;
	enum pqcp_channel_policy_state next_state;
	uint32_t maximum_attempts;
	uint32_t delay_ms;
	uint32_t reason_mask;
	int error;
};

int pqcp_channel_stream_header_encode(
	const struct pqcp_channel_stream_header *header,
	uint8_t output[PQCP_CHANNEL_STREAM_HEADER_BYTES]);
int pqcp_channel_stream_header_decode(
	const uint8_t input[PQCP_CHANNEL_STREAM_HEADER_BYTES],
	struct pqcp_channel_stream_header *header);
int pqcp_channel_multiplexer_init(
	struct pqcp_channel_multiplexer *multiplexer,
	struct pqcp_channel *channel,
	struct pqcp_channel_stream *streams,
	size_t capacity,
	uint32_t initial_connection_window,
	uint32_t initial_stream_window);
int pqcp_channel_stream_open(
	struct pqcp_channel_multiplexer *multiplexer,
	uint32_t priority,
	uint64_t now_ms,
	struct pqcp_channel_stream **stream);
int pqcp_channel_stream_send(
	struct pqcp_channel_multiplexer *multiplexer,
	uint32_t stream_id,
	const uint8_t *payload,
	size_t payload_length,
	uint32_t flags,
	uint64_t now_ms);
int pqcp_channel_stream_receive(
	struct pqcp_channel_multiplexer *multiplexer,
	uint8_t *payload,
	size_t payload_capacity,
	size_t *payload_length,
	struct pqcp_channel_stream_header *header,
	uint64_t now_ms);
int pqcp_channel_stream_close(
	struct pqcp_channel_multiplexer *multiplexer,
	uint32_t stream_id,
	enum pqcp_channel_stream_error error,
	uint64_t now_ms);
int pqcp_channel_multiplexer_audit(
	struct pqcp_channel_multiplexer *multiplexer);

int pqcp_channel_flow_policy_default(
	struct pqcp_channel_flow_policy *policy);
int pqcp_channel_flow_init(
	struct pqcp_channel_flow_controller *controller,
	const struct pqcp_channel_flow_policy *policy);
int pqcp_channel_flow_reserve_send(
	struct pqcp_channel_flow_controller *controller,
	struct pqcp_channel_stream *stream,
	size_t bytes);
int pqcp_channel_flow_consume_receive(
	struct pqcp_channel_flow_controller *controller,
	struct pqcp_channel_stream *stream,
	size_t bytes,
	uint32_t *connection_credit,
	uint32_t *stream_credit);
int pqcp_channel_flow_apply_update(
	struct pqcp_channel_flow_controller *controller,
	struct pqcp_channel_stream *stream,
	uint32_t connection_credit,
	uint32_t stream_credit);
int pqcp_channel_flow_audit(
	struct pqcp_channel_flow_controller *controller);

int pqcp_channel_rekey_policy_default(
	struct pqcp_channel_rekey_policy *policy);
bool pqcp_channel_rekey_due(
	const struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_policy *policy,
	uint64_t now_ms,
	uint64_t epoch_started_at_ms);
int pqcp_channel_rekey_prepare(
	struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_policy *policy,
	struct pqcp_channel_rekey_context *context,
	uint64_t now_ms,
	uint64_t next_epoch,
	const uint8_t salt[PQCP_CHANNEL_REKEY_SALT_BYTES],
	bool initiator);
int pqcp_channel_rekey_accept(
	struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	const uint8_t confirmation[PQCP_CHANNEL_FINISHED_BYTES],
	uint64_t now_ms);
int pqcp_channel_rekey_commit(
	struct pqcp_channel *channel,
	struct pqcp_channel_rekey_context *context,
	uint64_t now_ms);
int pqcp_channel_rekey_abort(
	struct pqcp_channel_rekey_context *context);
int pqcp_channel_rekey_audit(
	const struct pqcp_channel *channel,
	const struct pqcp_channel_rekey_context *context);

int pqcp_channel_resumption_store_init(
	struct pqcp_channel_resumption_store *store,
	const uint8_t secret[PQCP_CHANNEL_RESUMPTION_SECRET_BYTES],
	struct pqcp_channel_ticket_replay_entry *replay_entries,
	size_t replay_capacity);
int pqcp_channel_resumption_issue(
	struct pqcp_channel_resumption_store *store,
	const struct pqcp_channel *channel,
	const uint8_t peer_identity_digest[PQCP_CHANNEL_HASH_BYTES],
	uint64_t now_ms,
	uint64_t lifetime_ms,
	struct pqcp_channel_resumption_ticket *ticket);
int pqcp_channel_resumption_accept(
	struct pqcp_channel_resumption_store *store,
	const struct pqcp_channel_resumption_ticket *ticket,
	uint64_t now_ms,
	struct pqcp_channel_resumption_claims *claims);
int pqcp_channel_resumption_store_audit(
	struct pqcp_channel_resumption_store *store);

int pqcp_channel_peer_policy_default(
	struct pqcp_channel_peer_policy *policy);
int pqcp_channel_peer_health_init(
	struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy,
	uint64_t now_ms);
bool pqcp_channel_peer_probe_due(
	const struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy,
	uint64_t now_ms);
int pqcp_channel_peer_probe_sent(
	struct pqcp_channel_peer_health *health,
	uint64_t now_ms);
int pqcp_channel_peer_probe_ack(
	struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy,
	uint64_t now_ms);
int pqcp_channel_peer_record_io(
	struct pqcp_channel_peer_health *health,
	uint64_t now_ms,
	size_t sent_bytes,
	size_t received_bytes);
int pqcp_channel_peer_tick(
	struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy,
	uint64_t now_ms);
int pqcp_channel_peer_health_audit(
	const struct pqcp_channel_peer_health *health,
	const struct pqcp_channel_peer_policy *policy);

int pqcp_channel_operations_init(
	struct pqcp_channel_operations *operations,
	struct pqcp_channel *channel,
	struct pqcp_channel_multiplexer *multiplexer,
	struct pqcp_channel_flow_controller *flow,
	struct pqcp_channel_rekey_context *rekey,
	struct pqcp_channel_resumption_store *resumption,
	struct pqcp_channel_peer_health *peer,
	const struct pqcp_channel_peer_policy *peer_policy,
	uint64_t now_ms);
int pqcp_channel_operations_send_control(
	struct pqcp_channel_operations *operations,
	struct pqcp_channel_control_message *message,
	uint64_t now_ms);
int pqcp_channel_operations_receive_control(
	struct pqcp_channel_operations *operations,
	struct pqcp_channel_control_message *message,
	uint64_t now_ms);
int pqcp_channel_operations_tick(
	struct pqcp_channel_operations *operations,
	const struct pqcp_channel_rekey_policy *rekey_policy,
	uint64_t now_ms);
int pqcp_channel_operations_audit(
	struct pqcp_channel_operations *operations);

int pqcp_channel_path_policy_default(
	struct pqcp_channel_path_policy *policy);
int pqcp_channel_path_manager_init(
	struct pqcp_channel_path_manager *manager,
	const struct pqcp_channel_path_policy *policy,
	struct pqcp_channel_path *paths,
	size_t capacity);
int pqcp_channel_path_begin_probe(
	struct pqcp_channel_path_manager *manager,
	uint64_t challenge,
	uint32_t priority,
	uint64_t now_ms,
	struct pqcp_channel_path **path);
int pqcp_channel_path_validate(
	struct pqcp_channel_path_manager *manager,
	uint32_t path_id,
	uint64_t challenge,
	uint64_t rtt_us,
	uint64_t now_ms);
int pqcp_channel_path_record_io(
	struct pqcp_channel_path_manager *manager,
	uint32_t path_id,
	uint64_t now_ms,
	size_t sent_bytes,
	size_t received_bytes);
int pqcp_channel_path_fail(
	struct pqcp_channel_path_manager *manager,
	uint32_t path_id,
	uint64_t now_ms);
int pqcp_channel_path_select(
	struct pqcp_channel_path_manager *manager,
	uint64_t now_ms,
	uint32_t *path_id);
int pqcp_channel_path_manager_audit(
	struct pqcp_channel_path_manager *manager);

int pqcp_channel_path_policy_lookup(
	enum pqcp_channel_path_condition condition,
	enum pqcp_channel_control_kind control,
	struct pqcp_channel_path_policy_decision *decision);
int pqcp_channel_path_policy_catalog_audit(void);
int pqcp_channel_fault_policy_lookup(
	enum pqcp_channel_fault_condition condition,
	enum pqcp_channel_control_kind control,
	struct pqcp_channel_fault_policy_decision *decision);
int pqcp_channel_fault_policy_catalog_audit(void);

int pqcp_channel_control_encode(
	const struct pqcp_channel_control_message *message,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_channel_control_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_channel_control_message *message);
int pqcp_channel_policy_lookup(
	enum pqcp_channel_policy_state state,
	enum pqcp_channel_control_kind control,
	struct pqcp_channel_policy_decision *decision);
int pqcp_channel_policy_catalog_audit(void);
const char *pqcp_channel_control_kind_str(
	enum pqcp_channel_control_kind kind);
const char *pqcp_channel_policy_state_str(
	enum pqcp_channel_policy_state state);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROTECTED_CHANNEL_OPERATIONS_H_ */
