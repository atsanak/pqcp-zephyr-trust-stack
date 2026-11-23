/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free authenticated fleet receipt correlation and quorum tracking.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_RECEIPT_H_
#define PQCP_ZEPHYR_FLEET_RECEIPT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_RECEIPT_SCHEMA_VERSION 1U
#define PQCP_FLEET_RECEIPT_PEER_MAX_CHARS PQCP_FLEET_ID_MAX_CHARS
#define PQCP_FLEET_RECEIPT_KEY_ID_MAX_CHARS 32U
#define PQCP_FLEET_RECEIPT_KEY_MAX_BYTES 64U
#define PQCP_FLEET_RECEIPT_AUTH_TAG_BYTES PQCP_FLEET_DIGEST_BYTES
#define PQCP_FLEET_RECEIPT_NONCE_BYTES 16U
#define PQCP_FLEET_RECEIPT_REPLAY_WORDS 4U
#define PQCP_FLEET_RECEIPT_REPLAY_BITS \
	(PQCP_FLEET_RECEIPT_REPLAY_WORDS * 64U)

enum pqcp_fleet_receipt_kind {
	PQCP_FLEET_RECEIPT_NONE = 0,
	PQCP_FLEET_RECEIPT_CHUNK,
	PQCP_FLEET_RECEIPT_ARTIFACT,
	PQCP_FLEET_RECEIPT_FINAL,
	PQCP_FLEET_RECEIPT_REJECTION,
	PQCP_FLEET_RECEIPT_KIND_COUNT,
};

enum pqcp_fleet_receipt_status {
	PQCP_FLEET_RECEIPT_STATUS_NONE = 0,
	PQCP_FLEET_RECEIPT_STATUS_ACCEPTED,
	PQCP_FLEET_RECEIPT_STATUS_STORED,
	PQCP_FLEET_RECEIPT_STATUS_APPLIED,
	PQCP_FLEET_RECEIPT_STATUS_REJECTED,
	PQCP_FLEET_RECEIPT_STATUS_FAILED,
	PQCP_FLEET_RECEIPT_STATUS_COUNT,
};

enum pqcp_fleet_receipt_tracker_state {
	PQCP_FLEET_RECEIPT_TRACKER_EMPTY = 0,
	PQCP_FLEET_RECEIPT_TRACKER_PENDING,
	PQCP_FLEET_RECEIPT_TRACKER_QUORUM,
	PQCP_FLEET_RECEIPT_TRACKER_COMPLETE,
	PQCP_FLEET_RECEIPT_TRACKER_FAILED,
	PQCP_FLEET_RECEIPT_TRACKER_CANCELLED,
	PQCP_FLEET_RECEIPT_TRACKER_EXPIRED,
	PQCP_FLEET_RECEIPT_TRACKER_CONFLICT,
	PQCP_FLEET_RECEIPT_TRACKER_STATE_COUNT,
};

enum pqcp_fleet_receipt_tracker_flag {
	PQCP_FLEET_RECEIPT_TRACK_REQUIRE_CHUNKS = (1U << 0),
	PQCP_FLEET_RECEIPT_TRACK_REQUIRE_APPLIED = (1U << 1),
	PQCP_FLEET_RECEIPT_TRACK_FAIL_REQUIRED_REJECTION = (1U << 2),
	PQCP_FLEET_RECEIPT_TRACK_FAIL_ANY_REJECTION = (1U << 3),
	PQCP_FLEET_RECEIPT_TRACK_RETAIN_TERMINAL_RECEIPTS = (1U << 4),
	PQCP_FLEET_RECEIPT_TRACK_STRICT_POLICY_EPOCH = (1U << 5),
	PQCP_FLEET_RECEIPT_TRACK_STRICT_REVOCATION_EPOCH = (1U << 6),
	PQCP_FLEET_RECEIPT_TRACK_HIGH_INTEGRITY = (1U << 7),
};

enum pqcp_fleet_receipt_audit_flag {
	PQCP_FLEET_RECEIPT_AUDIT_NONE = 0U,
	PQCP_FLEET_RECEIPT_AUDIT_MANAGER = (1U << 0),
	PQCP_FLEET_RECEIPT_AUDIT_STORAGE = (1U << 1),
	PQCP_FLEET_RECEIPT_AUDIT_SCHEMA = (1U << 2),
	PQCP_FLEET_RECEIPT_AUDIT_PEER = (1U << 3),
	PQCP_FLEET_RECEIPT_AUDIT_KEY = (1U << 4),
	PQCP_FLEET_RECEIPT_AUDIT_REPLAY = (1U << 5),
	PQCP_FLEET_RECEIPT_AUDIT_TRACKER = (1U << 6),
	PQCP_FLEET_RECEIPT_AUDIT_ACK = (1U << 7),
	PQCP_FLEET_RECEIPT_AUDIT_BINDING = (1U << 8),
	PQCP_FLEET_RECEIPT_AUDIT_PROGRESS = (1U << 9),
	PQCP_FLEET_RECEIPT_AUDIT_QUORUM = (1U << 10),
	PQCP_FLEET_RECEIPT_AUDIT_RECEIPT = (1U << 11),
	PQCP_FLEET_RECEIPT_AUDIT_DIGEST = (1U << 12),
	PQCP_FLEET_RECEIPT_AUDIT_DUPLICATE = (1U << 13),
	PQCP_FLEET_RECEIPT_AUDIT_COUNTER = (1U << 14),
	PQCP_FLEET_RECEIPT_AUDIT_OVERFLOW = (1U << 15),
};

struct pqcp_fleet_receipt_packet {
	uint32_t schema_version;
	enum pqcp_fleet_receipt_kind kind;
	enum pqcp_fleet_receipt_status status;
	uint32_t flags;
	uint32_t reason;
	int32_t result;
	uint64_t receipt_id;
	uint64_t receipt_epoch;
	uint64_t sequence;
	uint64_t artifact_id;
	uint64_t message_id;
	uint64_t correlation_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t artifact_size;
	uint64_t acknowledged_bytes;
	uint32_t chunk_index;
	uint32_t chunk_count;
	uint32_t chunk_length;
	char peer_id[PQCP_FLEET_RECEIPT_PEER_MAX_CHARS];
	char key_id[PQCP_FLEET_RECEIPT_KEY_ID_MAX_CHARS];
	uint8_t nonce[PQCP_FLEET_RECEIPT_NONCE_BYTES];
	uint8_t artifact_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t auth_tag[PQCP_FLEET_RECEIPT_AUTH_TAG_BYTES];
};

struct pqcp_fleet_receipt_peer_registration {
	const char *peer_id;
	const char *key_id;
	const uint8_t *key;
	size_t key_length;
	uint64_t key_epoch;
	uint64_t valid_from_ms;
	uint64_t valid_until_ms;
	uint64_t minimum_receipt_epoch;
	bool enabled;
};

struct pqcp_fleet_receipt_peer {
	uint32_t schema_version;
	uint32_t generation;
	char peer_id[PQCP_FLEET_RECEIPT_PEER_MAX_CHARS];
	char key_id[PQCP_FLEET_RECEIPT_KEY_ID_MAX_CHARS];
	uint8_t key[PQCP_FLEET_RECEIPT_KEY_MAX_BYTES];
	size_t key_length;
	uint8_t key_digest[PQCP_FLEET_DIGEST_BYTES];
	uint64_t key_epoch;
	uint64_t valid_from_ms;
	uint64_t valid_until_ms;
	uint64_t minimum_receipt_epoch;
	uint64_t replay_epoch;
	uint64_t replay_high_sequence;
	uint64_t replay_bitmap[PQCP_FLEET_RECEIPT_REPLAY_WORDS];
	uint64_t accepted_count;
	uint64_t rejected_count;
	uint64_t replay_count;
	uint64_t authentication_failure_count;
	bool replay_initialized;
	bool enabled;
	bool occupied;
};

struct pqcp_fleet_receipt_track_request {
	uint64_t artifact_id;
	uint64_t message_id;
	uint64_t correlation_id;
	uint64_t receipt_epoch;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint64_t artifact_size;
	uint32_t chunk_count;
	uint32_t quorum;
	uint32_t flags;
	uint8_t artifact_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_receipt_tracker_handle {
	uint64_t artifact_id;
	uint32_t generation;
};

struct pqcp_fleet_receipt_tracker {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t artifact_id;
	uint64_t message_id;
	uint64_t correlation_id;
	uint64_t receipt_epoch;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint64_t completed_at_ms;
	uint64_t artifact_size;
	uint32_t chunk_count;
	uint32_t quorum;
	uint32_t flags;
	uint32_t required_count;
	uint32_t required_ack_count;
	uint32_t acknowledged_count;
	uint32_t rejected_count;
	uint32_t failed_count;
	enum pqcp_fleet_receipt_tracker_state state;
	int32_t terminal_result;
	uint32_t terminal_reason;
	uint8_t artifact_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t tracker_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_receipt_ack {
	uint32_t schema_version;
	uint32_t tracker_generation;
	uint64_t artifact_id;
	char peer_id[PQCP_FLEET_RECEIPT_PEER_MAX_CHARS];
	uint64_t last_receipt_id;
	uint64_t last_sequence;
	uint64_t acknowledged_bytes;
	uint32_t next_chunk;
	uint32_t accepted_receipts;
	uint32_t rejected_receipts;
	enum pqcp_fleet_receipt_status terminal_status;
	int32_t result;
	uint32_t reason;
	uint8_t last_chunk_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t last_receipt_digest[PQCP_FLEET_DIGEST_BYTES];
	bool required;
	bool final_acknowledged;
	bool occupied;
};

struct pqcp_fleet_receipt_record {
	uint32_t schema_version;
	uint64_t received_order;
	uint64_t received_at_ms;
	uint64_t receipt_id;
	uint64_t receipt_epoch;
	uint64_t sequence;
	uint64_t artifact_id;
	uint64_t message_id;
	uint64_t correlation_id;
	char peer_id[PQCP_FLEET_RECEIPT_PEER_MAX_CHARS];
	enum pqcp_fleet_receipt_kind kind;
	enum pqcp_fleet_receipt_status status;
	int32_t processing_result;
	uint8_t receipt_digest[PQCP_FLEET_DIGEST_BYTES];
	bool authenticated;
	bool replay;
	bool collision;
	bool occupied;
};

struct pqcp_fleet_receipt_outcome {
	struct pqcp_fleet_receipt_tracker_handle tracker;
	enum pqcp_fleet_receipt_tracker_state tracker_state;
	uint32_t acknowledged_count;
	uint32_t required_ack_count;
	uint32_t required_count;
	uint32_t quorum;
	uint32_t next_chunk;
	uint64_t acknowledged_bytes;
	bool authenticated;
	bool duplicate;
	bool replay;
	bool collision;
	bool quorum_reached;
	bool complete;
};

struct pqcp_fleet_receipt_snapshot {
	uint32_t schema_version;
	uint64_t generation;
	uint64_t minimum_policy_epoch;
	uint64_t minimum_revocation_epoch;
	uint64_t authenticated_count;
	uint64_t authentication_failure_count;
	uint64_t replay_count;
	uint64_t collision_count;
	uint64_t binding_failure_count;
	uint64_t accepted_count;
	uint64_t rejected_count;
	uint64_t expired_count;
	uint64_t completed_count;
	uint64_t failed_count;
	uint64_t dropped_receipt_records;
	size_t peer_capacity;
	size_t peer_count;
	size_t tracker_capacity;
	size_t tracker_count;
	size_t ack_capacity;
	size_t ack_count;
	size_t receipt_capacity;
	size_t receipt_count;
	size_t pending_trackers;
	size_t quorum_trackers;
	size_t terminal_trackers;
	uint8_t aggregate_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_receipt_audit {
	uint32_t schema_version;
	uint32_t violation_mask;
	size_t inspected_peers;
	size_t inspected_trackers;
	size_t inspected_acks;
	size_t inspected_receipts;
	size_t first_bad_index;
	uint64_t first_bad_artifact_id;
	uint64_t duplicate_artifact_id;
	uint64_t duplicate_receipt_id;
	uint32_t recomputed_tracker_ack_count;
	uint32_t recomputed_required_ack_count;
	uint8_t aggregate_digest[PQCP_FLEET_DIGEST_BYTES];
	bool consistent;
};

struct pqcp_fleet_receipt_manager {
	uint32_t schema_version;
	struct pqcp_fleet_receipt_peer *peers;
	size_t peer_capacity;
	size_t peer_count;
	struct pqcp_fleet_receipt_tracker *trackers;
	size_t tracker_capacity;
	size_t tracker_count;
	struct pqcp_fleet_receipt_ack *acks;
	size_t ack_capacity;
	size_t ack_count;
	struct pqcp_fleet_receipt_record *receipts;
	size_t receipt_capacity;
	size_t receipt_head;
	size_t receipt_count;
	uint32_t next_peer_generation;
	uint32_t next_tracker_generation;
	uint64_t next_received_order;
	uint64_t generation;
	uint64_t minimum_policy_epoch;
	uint64_t minimum_revocation_epoch;
	uint64_t authenticated_count;
	uint64_t authentication_failure_count;
	uint64_t replay_count;
	uint64_t collision_count;
	uint64_t binding_failure_count;
	uint64_t accepted_count;
	uint64_t rejected_count;
	uint64_t expired_count;
	uint64_t completed_count;
	uint64_t failed_count;
	uint64_t cancelled_count;
	uint64_t dropped_receipt_records;
	struct k_mutex lock;
	bool initialized;
};

int pqcp_fleet_receipt_manager_init(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_peer *peers,
	size_t peer_capacity,
	struct pqcp_fleet_receipt_tracker *trackers,
	size_t tracker_capacity,
	struct pqcp_fleet_receipt_ack *acks,
	size_t ack_capacity,
	struct pqcp_fleet_receipt_record *receipts,
	size_t receipt_capacity);
int pqcp_fleet_receipt_manager_deinit(
	struct pqcp_fleet_receipt_manager *manager);
int pqcp_fleet_receipt_register_peer(
	struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_peer_registration *registration,
	uint64_t now_ms);
int pqcp_fleet_receipt_unregister_peer(
	struct pqcp_fleet_receipt_manager *manager,
	const char *peer_id);
int pqcp_fleet_receipt_advance_epochs(
	struct pqcp_fleet_receipt_manager *manager,
	uint64_t policy_epoch,
	uint64_t revocation_epoch);
int pqcp_fleet_receipt_track(
	struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_track_request *request,
	struct pqcp_fleet_receipt_tracker_handle *handle,
	bool *replayed);
int pqcp_fleet_receipt_require_peer(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle,
	const char *peer_id);
int pqcp_fleet_receipt_ingest(
	struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_packet *packet,
	uint64_t now_ms,
	struct pqcp_fleet_receipt_outcome *outcome);
int pqcp_fleet_receipt_cancel(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle,
	int result,
	uint32_t reason,
	uint64_t now_ms);
int pqcp_fleet_receipt_tick(
	struct pqcp_fleet_receipt_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_fleet_receipt_get_tracker(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle,
	struct pqcp_fleet_receipt_tracker *tracker);
int pqcp_fleet_receipt_get_ack(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle,
	const char *peer_id,
	struct pqcp_fleet_receipt_ack *ack);
int pqcp_fleet_receipt_remove_tracker(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle);
int pqcp_fleet_receipt_prune_records(
	struct pqcp_fleet_receipt_manager *manager,
	size_t maximum_to_prune,
	uint64_t received_before_ms,
	size_t *pruned_count);
int pqcp_fleet_receipt_snapshot(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_snapshot *snapshot);
int pqcp_fleet_receipt_audit(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_audit *audit);
int pqcp_fleet_receipt_authenticate(
	struct pqcp_fleet_receipt_packet *packet,
	const uint8_t *key,
	size_t key_length);
int pqcp_fleet_receipt_verify_auth(
	const struct pqcp_fleet_receipt_packet *packet,
	const uint8_t *key,
	size_t key_length);
int pqcp_fleet_receipt_digest(
	const struct pqcp_fleet_receipt_packet *packet,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES]);
bool pqcp_fleet_receipt_tracker_terminal(
	enum pqcp_fleet_receipt_tracker_state state);
const char *pqcp_fleet_receipt_kind_str(
	enum pqcp_fleet_receipt_kind kind);
const char *pqcp_fleet_receipt_status_str(
	enum pqcp_fleet_receipt_status status);
const char *pqcp_fleet_receipt_tracker_state_str(
	enum pqcp_fleet_receipt_tracker_state state);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_RECEIPT_H_ */
