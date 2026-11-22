/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Cross-boot evidence continuity for intermittently connected Zephyr devices.
 *
 * The subsystem binds per-boot evidence into a durable sequence of anchors,
 * checkpoints, witness receipts, and replication acknowledgements. Storage is
 * caller-supplied and allocation-free. A platform may back the storage and
 * monotonic-counter callbacks with PSA ITS, a secure element, protected flash,
 * or the provided in-memory development adapter.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_EVIDENCE_CONTINUITY_H_
#define PQCP_ZEPHYR_EVIDENCE_CONTINUITY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION 1U
#define PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES PQCP_FLEET_DIGEST_BYTES
#define PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS 48U
#define PQCP_EVIDENCE_CONTINUITY_LABEL_MAX_CHARS 64U
#define PQCP_EVIDENCE_CONTINUITY_DETAIL_MAX_BYTES 192U
#define PQCP_EVIDENCE_CONTINUITY_MAX_BATCH_ENTRIES 32U
#define PQCP_EVIDENCE_CONTINUITY_MAX_WITNESSES 16U
#define PQCP_EVIDENCE_CONTINUITY_MAX_RECEIPTS 16U
#define PQCP_EVIDENCE_CONTINUITY_MAX_PROOF_NODES 24U
#define PQCP_EVIDENCE_CONTINUITY_MAX_REPLICA_PEERS 8U
#define PQCP_EVIDENCE_CONTINUITY_MAX_CHUNK_ENTRIES 16U
#define PQCP_EVIDENCE_CONTINUITY_MAX_STORAGE_SLOTS 24U
#define PQCP_EVIDENCE_CONTINUITY_STORE_SLOT_ANY UINT32_MAX

enum pqcp_evidence_continuity_object {
	PQCP_EVIDENCE_CONTINUITY_OBJECT_NONE = 0,
	PQCP_EVIDENCE_CONTINUITY_OBJECT_ANCHOR,
	PQCP_EVIDENCE_CONTINUITY_OBJECT_JOURNAL,
	PQCP_EVIDENCE_CONTINUITY_OBJECT_CHECKPOINT,
	PQCP_EVIDENCE_CONTINUITY_OBJECT_WITNESS_STATE,
	PQCP_EVIDENCE_CONTINUITY_OBJECT_REPLICATION_STATE,
	PQCP_EVIDENCE_CONTINUITY_OBJECT_SNAPSHOT,
	PQCP_EVIDENCE_CONTINUITY_OBJECT_COMPACTION_STATE,
	PQCP_EVIDENCE_CONTINUITY_OBJECT_COUNT,
};

enum pqcp_evidence_continuity_anchor_state {
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_EMPTY = 0,
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_BOOTSTRAP,
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_OPEN,
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_CHECKPOINTED,
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_WITNESSED,
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_REPLICATED,
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_COMPACTED,
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_RECOVERED,
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_QUARANTINED,
};

enum pqcp_evidence_continuity_session_state {
	PQCP_EVIDENCE_CONTINUITY_SESSION_EMPTY = 0,
	PQCP_EVIDENCE_CONTINUITY_SESSION_OPEN,
	PQCP_EVIDENCE_CONTINUITY_SESSION_CLOSING,
	PQCP_EVIDENCE_CONTINUITY_SESSION_CLOSED,
	PQCP_EVIDENCE_CONTINUITY_SESSION_ABORTED,
	PQCP_EVIDENCE_CONTINUITY_SESSION_QUARANTINED,
};

enum pqcp_evidence_continuity_event_type {
	PQCP_EVIDENCE_CONTINUITY_EVENT_NONE = 0,
	PQCP_EVIDENCE_CONTINUITY_EVENT_BOOT_OPENED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_BOOT_CLOSED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_BOOT_ABORTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_EVIDENCE_IMPORTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_EVIDENCE_REJECTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_POLICY_CHANGED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_FIRMWARE_CHANGED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_KEY_ROTATED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_CHECKPOINT_CREATED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_CHECKPOINT_SEALED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_CHECKPOINT_WITNESSED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_WITNESS_REJECTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_QUORUM_REACHED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_QUORUM_LOST,
	PQCP_EVIDENCE_CONTINUITY_EVENT_REPLICATION_STARTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_REPLICATION_ACKED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_REPLICATION_FAILED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_COMPACTION_STARTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_COMPACTION_COMMITTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_COMPACTION_ABORTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_RECOVERY_STARTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_RECOVERY_COMPLETED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_RECOVERY_FAILED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_ROLLBACK_DETECTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_FORK_DETECTED,
	PQCP_EVIDENCE_CONTINUITY_EVENT_COUNTER_MISMATCH,
	PQCP_EVIDENCE_CONTINUITY_EVENT_STORAGE_FAILURE,
	PQCP_EVIDENCE_CONTINUITY_EVENT_OPERATOR_NOTE,
	PQCP_EVIDENCE_CONTINUITY_EVENT_COUNT,
};

enum pqcp_evidence_continuity_severity {
	PQCP_EVIDENCE_CONTINUITY_SEVERITY_DEBUG = 0,
	PQCP_EVIDENCE_CONTINUITY_SEVERITY_INFO,
	PQCP_EVIDENCE_CONTINUITY_SEVERITY_NOTICE,
	PQCP_EVIDENCE_CONTINUITY_SEVERITY_WARNING,
	PQCP_EVIDENCE_CONTINUITY_SEVERITY_ERROR,
	PQCP_EVIDENCE_CONTINUITY_SEVERITY_CRITICAL,
};

enum pqcp_evidence_continuity_checkpoint_state {
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_EMPTY = 0,
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_BUILDING,
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_SEALED,
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_WITNESS_PENDING,
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_WITNESSED,
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_REPLICATED,
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_SUPERSEDED,
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_QUARANTINED,
};

enum pqcp_evidence_continuity_witness_trust {
	PQCP_EVIDENCE_CONTINUITY_WITNESS_DISABLED = 0,
	PQCP_EVIDENCE_CONTINUITY_WITNESS_OBSERVER,
	PQCP_EVIDENCE_CONTINUITY_WITNESS_AUTHORIZED,
	PQCP_EVIDENCE_CONTINUITY_WITNESS_PRIVILEGED,
	PQCP_EVIDENCE_CONTINUITY_WITNESS_ROOT,
};

enum pqcp_evidence_continuity_receipt_status {
	PQCP_EVIDENCE_CONTINUITY_RECEIPT_EMPTY = 0,
	PQCP_EVIDENCE_CONTINUITY_RECEIPT_ACCEPTED,
	PQCP_EVIDENCE_CONTINUITY_RECEIPT_DUPLICATE,
	PQCP_EVIDENCE_CONTINUITY_RECEIPT_STALE,
	PQCP_EVIDENCE_CONTINUITY_RECEIPT_REJECTED,
	PQCP_EVIDENCE_CONTINUITY_RECEIPT_REVOKED,
	PQCP_EVIDENCE_CONTINUITY_RECEIPT_EXPIRED,
};

enum pqcp_evidence_continuity_quorum_decision {
	PQCP_EVIDENCE_CONTINUITY_QUORUM_UNDECIDED = 0,
	PQCP_EVIDENCE_CONTINUITY_QUORUM_PENDING,
	PQCP_EVIDENCE_CONTINUITY_QUORUM_SATISFIED,
	PQCP_EVIDENCE_CONTINUITY_QUORUM_DEGRADED,
	PQCP_EVIDENCE_CONTINUITY_QUORUM_DENIED,
	PQCP_EVIDENCE_CONTINUITY_QUORUM_EXPIRED,
};

enum pqcp_evidence_continuity_replication_state {
	PQCP_EVIDENCE_CONTINUITY_REPLICATION_EMPTY = 0,
	PQCP_EVIDENCE_CONTINUITY_REPLICATION_IDLE,
	PQCP_EVIDENCE_CONTINUITY_REPLICATION_NEGOTIATING,
	PQCP_EVIDENCE_CONTINUITY_REPLICATION_SENDING,
	PQCP_EVIDENCE_CONTINUITY_REPLICATION_WAITING_ACK,
	PQCP_EVIDENCE_CONTINUITY_REPLICATION_CAUGHT_UP,
	PQCP_EVIDENCE_CONTINUITY_REPLICATION_BACKOFF,
	PQCP_EVIDENCE_CONTINUITY_REPLICATION_FAILED,
	PQCP_EVIDENCE_CONTINUITY_REPLICATION_REVOKED,
};

enum pqcp_evidence_continuity_recovery_reason {
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_NONE = 0,
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_UNCLEAN_SHUTDOWN,
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_CORRUPT_PRIMARY,
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_COUNTER_AHEAD,
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_COUNTER_BEHIND,
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_FORK,
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_ROLLBACK,
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_PARTIAL_COMPACTION,
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_REPLICA_IMPORT,
	PQCP_EVIDENCE_CONTINUITY_RECOVERY_OPERATOR,
};

enum pqcp_evidence_continuity_event_flag {
	PQCP_EVIDENCE_CONTINUITY_EVENT_SECURITY_RELEVANT = (1U << 0),
	PQCP_EVIDENCE_CONTINUITY_EVENT_REQUIRES_WITNESS = (1U << 1),
	PQCP_EVIDENCE_CONTINUITY_EVENT_REQUIRES_REPLICATION = (1U << 2),
	PQCP_EVIDENCE_CONTINUITY_EVENT_PRIVACY_REDACTED = (1U << 3),
	PQCP_EVIDENCE_CONTINUITY_EVENT_RECOVERY_RELEVANT = (1U << 4),
	PQCP_EVIDENCE_CONTINUITY_EVENT_CHECKPOINT_BOUND = (1U << 5),
	PQCP_EVIDENCE_CONTINUITY_EVENT_WITNESSED = (1U << 6),
	PQCP_EVIDENCE_CONTINUITY_EVENT_REPLICATED = (1U << 7),
	PQCP_EVIDENCE_CONTINUITY_EVENT_ACKNOWLEDGED = (1U << 8),
	PQCP_EVIDENCE_CONTINUITY_EVENT_SYNTHETIC = (1U << 9),
};

enum pqcp_evidence_continuity_anchor_flag {
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_CLEAN_CLOSE = (1U << 0),
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_COUNTER_BOUND = (1U << 1),
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_WITNESS_BOUND = (1U << 2),
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_REPLICA_BOUND = (1U << 3),
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_COMPACTION_BOUND = (1U << 4),
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_RECOVERY_BOUND = (1U << 5),
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_DEGRADED = (1U << 6),
	PQCP_EVIDENCE_CONTINUITY_ANCHOR_OPERATOR_OVERRIDE = (1U << 7),
};

enum pqcp_evidence_continuity_checkpoint_flag {
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_COMPLETE = (1U << 0),
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_CLEAN_CLOSE = (1U << 1),
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_POLICY_CHANGE = (1U << 2),
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_FIRMWARE_CHANGE = (1U << 3),
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_RECOVERY = (1U << 4),
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_COMPACTION = (1U << 5),
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_QUORUM_REQUIRED = (1U << 6),
	PQCP_EVIDENCE_CONTINUITY_CHECKPOINT_REPLICATION_REQUIRED = (1U << 7),
};

typedef int (*pqcp_evidence_continuity_store_read_fn)(
	void *context,
	enum pqcp_evidence_continuity_object object,
	uint32_t slot,
	size_t offset,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);

typedef int (*pqcp_evidence_continuity_store_write_fn)(
	void *context,
	enum pqcp_evidence_continuity_object object,
	uint32_t slot,
	size_t offset,
	const uint8_t *input,
	size_t input_length);

typedef int (*pqcp_evidence_continuity_store_erase_fn)(
	void *context,
	enum pqcp_evidence_continuity_object object,
	uint32_t slot);

typedef int (*pqcp_evidence_continuity_store_sync_fn)(
	void *context);

typedef int (*pqcp_evidence_continuity_counter_read_fn)(
	void *context,
	uint64_t *value);

typedef int (*pqcp_evidence_continuity_counter_advance_fn)(
	void *context,
	uint64_t expected,
	uint64_t *advanced);

typedef int (*pqcp_evidence_continuity_sign_fn)(
	void *context,
	const uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES],
	uint8_t *signature,
	size_t signature_capacity,
	size_t *signature_length);

typedef int (*pqcp_evidence_continuity_verify_fn)(
	void *context,
	const char *signer_id,
	const uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES],
	const uint8_t *signature,
	size_t signature_length);

struct pqcp_evidence_continuity_store {
	pqcp_evidence_continuity_store_read_fn read;
	pqcp_evidence_continuity_store_write_fn write;
	pqcp_evidence_continuity_store_erase_fn erase;
	pqcp_evidence_continuity_store_sync_fn sync;
	pqcp_evidence_continuity_counter_read_fn counter_read;
	pqcp_evidence_continuity_counter_advance_fn counter_advance;
	void *context;
	size_t maximum_record_bytes;
	bool atomic_slot_replace;
	bool rollback_resistant_counter;
};

struct pqcp_evidence_continuity_memory_slot {
	enum pqcp_evidence_continuity_object object;
	uint32_t slot;
	uint8_t *bytes;
	size_t capacity;
	size_t length;
	uint64_t write_generation;
	bool occupied;
};

struct pqcp_evidence_continuity_memory_store {
	struct pqcp_evidence_continuity_memory_slot *slots;
	size_t slot_count;
	uint64_t monotonic_counter;
	uint64_t write_generation;
	uint64_t read_count;
	uint64_t write_count;
	uint64_t erase_count;
	uint64_t sync_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_evidence_continuity_anchor {
	uint32_t schema_version;
	uint32_t generation;
	enum pqcp_evidence_continuity_anchor_state state;
	uint32_t flags;
	char device_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char domain_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint64_t monotonic_counter;
	uint64_t boot_epoch;
	uint64_t session_id;
	uint64_t first_event_sequence;
	uint64_t last_event_sequence;
	uint64_t latest_checkpoint_sequence;
	uint64_t created_at_ms;
	uint64_t updated_at_ms;
	uint64_t closed_at_ms;
	uint64_t policy_epoch;
	uint64_t firmware_epoch;
	uint64_t witness_epoch;
	uint64_t replication_epoch;
	uint64_t compaction_epoch;
	uint64_t recovery_epoch;
	uint8_t device_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t firmware_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t policy_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t previous_anchor_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t journal_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t checkpoint_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t witness_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t replication_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t compaction_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t recovery_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t anchor_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_evidence_continuity_anchor_commit {
	enum pqcp_evidence_continuity_anchor_state state;
	uint32_t set_flags;
	uint32_t clear_flags;
	uint64_t now_ms;
	uint64_t session_id;
	uint64_t first_event_sequence;
	uint64_t last_event_sequence;
	uint64_t latest_checkpoint_sequence;
	uint64_t policy_epoch;
	uint64_t firmware_epoch;
	uint64_t witness_epoch;
	uint64_t replication_epoch;
	uint64_t compaction_epoch;
	uint64_t recovery_epoch;
	const uint8_t *firmware_digest;
	const uint8_t *policy_digest;
	const uint8_t *journal_root;
	const uint8_t *checkpoint_root;
	const uint8_t *witness_root;
	const uint8_t *replication_root;
	const uint8_t *compaction_root;
	const uint8_t *recovery_root;
	bool close_cleanly;
	bool advance_counter;
};

struct pqcp_evidence_continuity_anchor_manager {
	struct pqcp_evidence_continuity_store store;
	struct pqcp_evidence_continuity_anchor current;
	uint32_t active_slot;
	uint32_t slot_count;
	uint64_t loaded_counter;
	uint64_t commit_count;
	uint64_t failed_commit_count;
	uint64_t rollback_count;
	uint64_t corruption_count;
	struct k_mutex lock;
	bool initialized;
	bool loaded;
	bool quarantined;
};

struct pqcp_evidence_continuity_session_begin {
	uint64_t now_ms;
	uint64_t session_id;
	uint64_t policy_epoch;
	uint64_t firmware_epoch;
	const char *device_id;
	const char *domain_id;
	const uint8_t *boot_nonce;
	size_t boot_nonce_length;
	const uint8_t *device_digest;
	const uint8_t *firmware_digest;
	const uint8_t *policy_digest;
	bool require_witness;
	bool require_replication;
};

struct pqcp_evidence_continuity_boot_session {
	uint32_t schema_version;
	uint32_t generation;
	enum pqcp_evidence_continuity_session_state state;
	uint32_t flags;
	char device_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char domain_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint64_t boot_epoch;
	uint64_t session_id;
	uint64_t opened_at_ms;
	uint64_t closed_at_ms;
	uint64_t first_event_sequence;
	uint64_t last_event_sequence;
	uint64_t event_count;
	uint64_t rejected_event_count;
	uint64_t policy_epoch;
	uint64_t firmware_epoch;
	uint8_t boot_nonce_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t device_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t firmware_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t policy_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t inherited_anchor_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t journal_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t terminal_evidence_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t session_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool require_witness;
	bool require_replication;
	bool occupied;
};

struct pqcp_evidence_continuity_event {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t boot_epoch;
	uint64_t session_id;
	uint64_t sequence;
	uint64_t timestamp_ms;
	uint64_t correlation_id;
	uint64_t policy_epoch;
	uint64_t firmware_epoch;
	enum pqcp_evidence_continuity_event_type type;
	enum pqcp_evidence_continuity_severity severity;
	uint32_t flags;
	int32_t result;
	uint32_t reason;
	char component[PQCP_EVIDENCE_CONTINUITY_LABEL_MAX_CHARS];
	char subject[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint32_t detail_length;
	uint8_t detail[PQCP_EVIDENCE_CONTINUITY_DETAIL_MAX_BYTES];
	uint8_t payload_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t event_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_evidence_continuity_event_append {
	uint64_t timestamp_ms;
	uint64_t correlation_id;
	uint64_t policy_epoch;
	uint64_t firmware_epoch;
	enum pqcp_evidence_continuity_event_type type;
	enum pqcp_evidence_continuity_severity severity;
	uint32_t flags;
	int32_t result;
	uint32_t reason;
	const char *component;
	const char *subject;
	const uint8_t *detail;
	size_t detail_length;
	const uint8_t *payload_digest;
};

struct pqcp_evidence_continuity_event_filter {
	uint64_t sequence_after;
	uint64_t sequence_before;
	uint64_t timestamp_after_ms;
	uint64_t timestamp_before_ms;
	uint64_t boot_epoch;
	uint64_t session_id;
	uint64_t correlation_id;
	uint32_t required_flags;
	uint32_t forbidden_flags;
	enum pqcp_evidence_continuity_event_type type;
	enum pqcp_evidence_continuity_severity minimum_severity;
	const char *component;
	const char *subject;
};

struct pqcp_evidence_continuity_event_batch {
	struct pqcp_evidence_continuity_event
		entries[PQCP_EVIDENCE_CONTINUITY_MAX_BATCH_ENTRIES];
	size_t count;
	uint64_t first_sequence;
	uint64_t last_sequence;
	uint8_t first_previous_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t last_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool complete;
};

struct pqcp_evidence_continuity_journal {
	struct pqcp_evidence_continuity_event *entries;
	size_t capacity;
	size_t head;
	size_t count;
	uint32_t next_generation;
	uint64_t boot_epoch;
	uint64_t session_id;
	uint64_t next_sequence;
	uint64_t checkpointed_through;
	uint64_t witnessed_through;
	uint64_t replicated_through;
	uint64_t acknowledged_through;
	uint64_t dropped_count;
	uint64_t rejected_count;
	uint64_t security_count;
	uint64_t recovery_count;
	uint8_t anchor_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t tail_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
	bool sealed;
};

struct pqcp_evidence_continuity_checkpoint {
	uint32_t schema_version;
	uint32_t generation;
	enum pqcp_evidence_continuity_checkpoint_state state;
	uint32_t flags;
	char device_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char domain_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint64_t checkpoint_sequence;
	uint64_t boot_epoch;
	uint64_t session_id;
	uint64_t first_event_sequence;
	uint64_t last_event_sequence;
	uint64_t event_count;
	uint64_t created_at_ms;
	uint64_t sealed_at_ms;
	uint64_t policy_epoch;
	uint64_t firmware_epoch;
	uint64_t monotonic_counter;
	uint32_t security_event_count;
	uint32_t recovery_event_count;
	uint32_t witness_receipt_count;
	uint32_t replica_ack_count;
	uint8_t previous_checkpoint_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t anchor_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t event_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t witness_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t replica_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_evidence_continuity_witness {
	uint32_t schema_version;
	uint32_t generation;
	enum pqcp_evidence_continuity_witness_trust trust;
	char witness_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char operator_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char jurisdiction[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char failure_domain[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint64_t valid_from_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint32_t weight;
	uint32_t maximum_receipts_per_epoch;
	uint64_t last_receipt_sequence;
	uint64_t last_seen_at_ms;
	uint32_t receipt_count;
	uint32_t rejection_count;
	uint8_t public_key_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t witness_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool enabled;
	bool occupied;
};

struct pqcp_evidence_continuity_witness_challenge {
	uint32_t schema_version;
	char device_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char domain_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint64_t checkpoint_sequence;
	uint64_t monotonic_counter;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint64_t witness_epoch;
	uint8_t nonce[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t challenge_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
};

struct pqcp_evidence_continuity_witness_receipt {
	uint32_t schema_version;
	uint32_t generation;
	enum pqcp_evidence_continuity_receipt_status status;
	char witness_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char jurisdiction[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char failure_domain[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint64_t receipt_sequence;
	uint64_t checkpoint_sequence;
	uint64_t monotonic_counter;
	uint64_t observed_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint64_t witness_epoch;
	uint32_t weight;
	uint32_t signature_length;
	uint8_t challenge_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t previous_receipt_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t receipt_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
	bool verified;
	bool occupied;
};

struct pqcp_evidence_continuity_quorum_policy {
	uint32_t schema_version;
	uint32_t generation;
	char policy_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint64_t policy_epoch;
	uint64_t valid_from_ms;
	uint64_t expires_at_ms;
	uint32_t minimum_receipts;
	uint32_t minimum_weight;
	uint32_t minimum_jurisdictions;
	uint32_t minimum_failure_domains;
	uint32_t maximum_receipt_age_ms;
	enum pqcp_evidence_continuity_witness_trust minimum_trust;
	bool require_root_witness;
	bool reject_mixed_checkpoint;
	uint8_t policy_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_evidence_continuity_quorum_result {
	enum pqcp_evidence_continuity_quorum_decision decision;
	uint64_t checkpoint_sequence;
	uint64_t evaluated_at_ms;
	uint32_t accepted_receipts;
	uint32_t rejected_receipts;
	uint32_t accepted_weight;
	uint32_t jurisdiction_count;
	uint32_t failure_domain_count;
	uint32_t root_witness_count;
	uint32_t stale_receipt_count;
	uint32_t duplicate_witness_count;
	uint8_t checkpoint_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t receipt_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t result_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool receipts_met;
	bool weight_met;
	bool jurisdiction_met;
	bool failure_domain_met;
	bool root_met;
};

struct pqcp_evidence_continuity_replication_peer {
	uint32_t schema_version;
	uint32_t generation;
	enum pqcp_evidence_continuity_replication_state state;
	char peer_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char transport_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char failure_domain[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t last_attempt_at_ms;
	uint64_t next_attempt_at_ms;
	uint64_t last_acked_sequence;
	uint64_t last_acked_checkpoint;
	uint64_t transmitted_entries;
	uint64_t transmitted_bytes;
	uint32_t consecutive_failures;
	uint32_t retry_after_ms;
	uint8_t resume_token[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t last_acked_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t peer_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool required;
	bool enabled;
	bool occupied;
};

struct pqcp_evidence_continuity_replication_chunk {
	uint32_t schema_version;
	char device_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	char peer_id[PQCP_EVIDENCE_CONTINUITY_ID_MAX_CHARS];
	uint64_t chunk_sequence;
	uint64_t first_event_sequence;
	uint64_t last_event_sequence;
	uint64_t checkpoint_sequence;
	uint64_t policy_epoch;
	uint32_t event_count;
	uint32_t flags;
	struct pqcp_evidence_continuity_event
		events[PQCP_EVIDENCE_CONTINUITY_MAX_CHUNK_ENTRIES];
	uint8_t previous_chunk_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t chunk_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
};

struct pqcp_evidence_continuity_compaction_policy {
	uint32_t schema_version;
	uint64_t policy_epoch;
	uint64_t minimum_retention_ms;
	uint64_t minimum_recovery_window_ms;
	uint32_t minimum_checkpoints;
	uint32_t minimum_witness_receipts;
	uint32_t minimum_replica_acks;
	uint32_t maximum_entries_per_cycle;
	bool require_quorum;
	bool require_replication;
	bool preserve_security_events;
	bool preserve_recovery_events;
	bool preserve_policy_changes;
	bool preserve_firmware_changes;
};

struct pqcp_evidence_continuity_compaction_result {
	uint64_t started_at_ms;
	uint64_t committed_at_ms;
	uint64_t first_pruned_sequence;
	uint64_t last_pruned_sequence;
	uint64_t preserved_through_sequence;
	uint64_t policy_epoch;
	uint32_t considered_entries;
	uint32_t pruned_entries;
	uint32_t preserved_entries;
	uint32_t blocked_entries;
	uint8_t previous_anchor_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t pruned_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t preserved_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t compaction_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool committed;
};

struct pqcp_evidence_continuity_recovery_report {
	enum pqcp_evidence_continuity_recovery_reason reason;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	uint64_t stored_counter;
	uint64_t platform_counter;
	uint64_t selected_generation;
	uint64_t selected_boot_epoch;
	uint64_t selected_event_sequence;
	uint32_t valid_anchor_slots;
	uint32_t corrupt_anchor_slots;
	uint32_t fork_count;
	uint32_t discarded_records;
	uint8_t selected_anchor_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t discarded_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t recovery_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool rollback_detected;
	bool fork_detected;
	bool counter_reconciled;
	bool recovered;
	bool quarantined;
};

struct pqcp_evidence_continuity_summary {
	uint64_t boot_epoch;
	uint64_t session_id;
	uint64_t monotonic_counter;
	uint64_t latest_event_sequence;
	uint64_t latest_checkpoint_sequence;
	uint64_t checkpointed_through;
	uint64_t witnessed_through;
	uint64_t replicated_through;
	uint64_t acknowledged_through;
	uint32_t journal_entries;
	uint32_t witness_receipts;
	uint32_t caught_up_replicas;
	uint32_t degraded_replicas;
	enum pqcp_evidence_continuity_anchor_state anchor_state;
	enum pqcp_evidence_continuity_session_state session_state;
	enum pqcp_evidence_continuity_quorum_decision quorum_decision;
	uint8_t anchor_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t journal_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t witness_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	uint8_t replication_root[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	bool continuity_healthy;
	bool witness_required;
	bool replication_required;
	bool recovery_required;
};

/*
 * Foundation only. This header defines the persisted-object types, constants
 * and digest layouts for cross-boot evidence continuity. The lifecycle API
 * (memory store, anchor manager, boot session, event journal) is NOT yet
 * implemented, so it is deliberately not declared: declaring functions that
 * no source defines looks like supported API and fails at link time. The
 * implemented internals (validators, canonical digests, the persisted record
 * codec and the two-phase store/load) are in evidence_continuity_internal.h.
 */

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_EVIDENCE_CONTINUITY_H_ */
