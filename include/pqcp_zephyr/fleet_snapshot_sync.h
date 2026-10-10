/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free fleet state snapshot and delta synchronization.
 */

#ifndef PQCP_ZEPHYR_FLEET_SNAPSHOT_SYNC_H_
#define PQCP_ZEPHYR_FLEET_SNAPSHOT_SYNC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_SNAPSHOT_SYNC_SCHEMA_VERSION 1U
#define PQCP_FLEET_STATE_KEY_MAX_BYTES 64U
#define PQCP_FLEET_STATE_MAX_CHUNKS 256U
#define PQCP_FLEET_STATE_CHUNK_BITMAP_BYTES \
	(PQCP_FLEET_STATE_MAX_CHUNKS / 8U)
#define PQCP_FLEET_STATE_MERKLE_LEVELS 64U
#define PQCP_FLEET_STATE_HISTORY_CAPACITY 8U
#define PQCP_FLEET_STATE_MANIFEST_SCHEMA_VERSION 1U
#define PQCP_FLEET_STATE_RANGE_SCHEMA_VERSION 1U

enum pqcp_fleet_state_domain {
	PQCP_FLEET_STATE_DOMAIN_NONE = 0,
	PQCP_FLEET_STATE_DOMAIN_DEVICE,
	PQCP_FLEET_STATE_DOMAIN_POLICY,
	PQCP_FLEET_STATE_DOMAIN_REVOCATION,
	PQCP_FLEET_STATE_DOMAIN_CREDENTIAL,
	PQCP_FLEET_STATE_DOMAIN_ROLLOUT,
	PQCP_FLEET_STATE_DOMAIN_CONFIGURATION,
	PQCP_FLEET_STATE_DOMAIN_APPLICATION,
	PQCP_FLEET_STATE_DOMAIN_AUDIT_ANCHOR,
	PQCP_FLEET_STATE_DOMAIN_RECOVERY,
	PQCP_FLEET_STATE_DOMAIN_COUNT,
};

enum pqcp_fleet_state_leaf_flag {
	PQCP_FLEET_STATE_LEAF_TOMBSTONE = (1U << 0),
	PQCP_FLEET_STATE_LEAF_CRITICAL = (1U << 1),
	PQCP_FLEET_STATE_LEAF_CONFIDENTIAL = (1U << 2),
	PQCP_FLEET_STATE_LEAF_IMMUTABLE = (1U << 3),
	PQCP_FLEET_STATE_LEAF_OFFLINE_VALID = (1U << 4),
	PQCP_FLEET_STATE_LEAF_STAGED = (1U << 5),
	PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED = (1U << 6),
};

enum pqcp_fleet_snapshot_mode {
	PQCP_FLEET_SNAPSHOT_MODE_NONE = 0,
	PQCP_FLEET_SNAPSHOT_MODE_FULL,
	PQCP_FLEET_SNAPSHOT_MODE_DELTA,
};

enum pqcp_fleet_snapshot_manifest_flag {
	PQCP_FLEET_SNAPSHOT_MANIFEST_FULL = (1U << 0),
	PQCP_FLEET_SNAPSHOT_MANIFEST_DELTA = (1U << 1),
	PQCP_FLEET_SNAPSHOT_MANIFEST_OFFLINE = (1U << 2),
	PQCP_FLEET_SNAPSHOT_MANIFEST_SIGNED = (1U << 3),
	PQCP_FLEET_SNAPSHOT_MANIFEST_CONTAINS_TOMBSTONES =
		(1U << 4),
};

enum pqcp_fleet_snapshot_negotiation_action {
	PQCP_FLEET_SNAPSHOT_NEGOTIATION_NONE = 0,
	PQCP_FLEET_SNAPSHOT_NEGOTIATION_NOOP,
	PQCP_FLEET_SNAPSHOT_NEGOTIATION_DELTA,
	PQCP_FLEET_SNAPSHOT_NEGOTIATION_FULL,
	PQCP_FLEET_SNAPSHOT_NEGOTIATION_REJECT_ROLLBACK,
	PQCP_FLEET_SNAPSHOT_NEGOTIATION_REJECT_INCOMPATIBLE,
};

enum pqcp_fleet_state_missing_reason {
	PQCP_FLEET_STATE_MISSING_ABSENT = 0,
	PQCP_FLEET_STATE_MISSING_DIGEST,
	PQCP_FLEET_STATE_MISSING_REVISION,
	PQCP_FLEET_STATE_MISSING_FLAGS,
};

struct pqcp_fleet_state_leaf_descriptor {
	uint32_t schema_version;
	enum pqcp_fleet_state_domain domain;
	uint32_t flags;
	uint64_t revision;
	uint64_t updated_at_ms;
	uint64_t expires_at_ms;
	uint32_t key_length;
	size_t value_length;
	size_t chunk_size;
	uint32_t chunk_count;
	uint8_t key[PQCP_FLEET_STATE_KEY_MAX_BYTES];
	uint8_t value_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t leaf_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_state_leaf {
	uint32_t schema_version;
	enum pqcp_fleet_state_domain domain;
	uint32_t flags;
	uint64_t revision;
	uint64_t updated_at_ms;
	uint64_t expires_at_ms;
	uint32_t key_length;
	size_t value_offset;
	size_t value_capacity;
	size_t value_length;
	size_t chunk_size;
	uint32_t chunk_count;
	uint32_t complete_chunks;
	uint8_t key[PQCP_FLEET_STATE_KEY_MAX_BYTES];
	uint8_t value_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t leaf_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t chunk_bitmap[PQCP_FLEET_STATE_CHUNK_BITMAP_BYTES];
	bool occupied;
};

struct pqcp_fleet_state_bank {
	struct pqcp_fleet_state_leaf *leaves;
	size_t leaf_capacity;
	size_t leaf_count;
	uint8_t *value_arena;
	size_t value_arena_capacity;
	size_t value_alignment;
	size_t value_bytes;
	uint64_t generation;
	uint8_t root[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_snapshot_manifest {
	uint32_t schema_version;
	uint32_t flags;
	uint64_t generation;
	uint64_t base_generation;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	size_t leaf_count;
	size_t tombstone_count;
	size_t value_bytes;
	size_t maximum_chunk_size;
	uint8_t root[PQCP_FLEET_DIGEST_BYTES];
	uint8_t base_root[PQCP_FLEET_DIGEST_BYTES];
	uint8_t manifest_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_state_history_entry {
	uint64_t generation;
	uint64_t committed_at_ms;
	size_t leaf_count;
	uint8_t root[PQCP_FLEET_DIGEST_BYTES];
	uint8_t manifest_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_state_range {
	uint32_t schema_version;
	uint64_t generation;
	size_t first_index;
	size_t leaf_count;
	uint8_t first_key_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t last_key_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t range_root[PQCP_FLEET_DIGEST_BYTES];
	uint8_t state_root[PQCP_FLEET_DIGEST_BYTES];
	uint8_t descriptor_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_snapshot_negotiation {
	uint32_t schema_version;
	uint32_t supported_manifest_flags;
	size_t maximum_leaf_count;
	size_t maximum_value_bytes;
	size_t maximum_chunk_size;
	bool allow_full_snapshot;
	bool allow_delta;
	bool require_exact_base;
};

struct pqcp_fleet_snapshot_negotiation_result {
	enum pqcp_fleet_snapshot_negotiation_action action;
	size_t agreed_chunk_size;
	uint64_t base_generation;
	uint64_t target_generation;
	uint8_t base_root[PQCP_FLEET_DIGEST_BYTES];
	uint8_t target_root[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_state_leaf_summary {
	enum pqcp_fleet_state_domain domain;
	uint32_t flags;
	uint64_t revision;
	uint32_t key_length;
	uint8_t key[PQCP_FLEET_STATE_KEY_MAX_BYTES];
	uint8_t leaf_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_state_missing_cursor {
	uint64_t source_generation;
	size_t source_index;
	size_t remote_index;
	bool initialized;
	bool complete;
};

struct pqcp_fleet_state_missing_leaf {
	enum pqcp_fleet_state_missing_reason reason;
	size_t source_index;
	struct pqcp_fleet_state_leaf_descriptor descriptor;
};

struct pqcp_fleet_state_transfer_selection {
	size_t source_index;
	uint8_t leaf_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_state_transfer_cursor {
	uint64_t generation;
	uint8_t root[PQCP_FLEET_DIGEST_BYTES];
	size_t selection_index;
	size_t leaf_index;
	size_t value_offset;
	size_t chunk_size;
	bool use_selection;
	bool initialized;
	bool complete;
};

struct pqcp_fleet_state_transfer_chunk {
	struct pqcp_fleet_state_leaf_descriptor descriptor;
	size_t source_index;
	size_t offset;
	size_t length;
	size_t total_length;
	uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t state_root[PQCP_FLEET_DIGEST_BYTES];
	bool first_chunk;
	bool final_chunk;
	bool final_leaf;
};

struct pqcp_fleet_state_mutation {
	enum pqcp_fleet_state_domain domain;
	uint32_t flags;
	uint64_t revision;
	uint64_t updated_at_ms;
	uint64_t expires_at_ms;
	const uint8_t *key;
	size_t key_length;
	const uint8_t *value;
	size_t value_length;
	size_t chunk_size;
};

struct pqcp_fleet_snapshot_stage_status {
	enum pqcp_fleet_snapshot_mode mode;
	uint64_t base_generation;
	uint64_t target_generation;
	size_t staged_leaf_count;
	size_t staged_value_bytes;
	size_t descriptors_received;
	size_t leaves_verified;
	size_t chunks_received;
	size_t bytes_received;
	uint8_t expected_root[PQCP_FLEET_DIGEST_BYTES];
	bool active;
	bool ready_to_commit;
};

struct pqcp_fleet_snapshot_sync_snapshot {
	uint32_t schema_version;
	uint64_t state_generation;
	uint64_t rollback_floor_generation;
	size_t leaf_capacity;
	size_t leaf_count;
	size_t tombstone_count;
	size_t value_arena_capacity;
	size_t value_bytes;
	size_t staged_leaf_count;
	size_t staged_value_bytes;
	size_t history_count;
	uint64_t applied_snapshot_count;
	uint64_t applied_delta_count;
	uint64_t local_commit_count;
	uint64_t rejected_rollback_count;
	uint64_t rejected_manifest_count;
	uint64_t digest_failure_count;
	uint64_t transferred_leaf_count;
	uint64_t transferred_byte_count;
	uint8_t state_root[PQCP_FLEET_DIGEST_BYTES];
	uint8_t staged_root[PQCP_FLEET_DIGEST_BYTES];
	uint8_t metadata_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
	bool stage_active;
};

struct pqcp_fleet_snapshot_sync {
	struct pqcp_fleet_state_bank banks[2];
	uint8_t active_bank;
	struct pqcp_fleet_snapshot_manifest current_manifest;
	struct pqcp_fleet_snapshot_manifest staged_manifest;
	struct pqcp_fleet_state_history_entry
		history[PQCP_FLEET_STATE_HISTORY_CAPACITY];
	size_t history_head;
	size_t history_count;
	enum pqcp_fleet_snapshot_mode stage_mode;
	uint64_t rollback_floor_generation;
	size_t descriptors_received;
	size_t leaves_verified;
	size_t chunks_received;
	size_t bytes_received;
	uint64_t applied_snapshot_count;
	uint64_t applied_delta_count;
	uint64_t local_commit_count;
	uint64_t rejected_rollback_count;
	uint64_t rejected_manifest_count;
	uint64_t digest_failure_count;
	uint64_t transferred_leaf_count;
	uint64_t transferred_byte_count;
	struct k_mutex lock;
	bool stage_active;
	bool initialized;
};

int pqcp_fleet_snapshot_sync_init(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_state_leaf *bank_a_leaves,
	size_t bank_a_leaf_capacity,
	uint8_t *bank_a_value_arena,
	size_t bank_a_value_arena_capacity,
	struct pqcp_fleet_state_leaf *bank_b_leaves,
	size_t bank_b_leaf_capacity,
	uint8_t *bank_b_value_arena,
	size_t bank_b_value_arena_capacity,
	size_t value_alignment,
	uint64_t initial_generation,
	uint64_t created_at_ms);

int pqcp_fleet_state_leaf_descriptor_verify(
	const struct pqcp_fleet_state_leaf_descriptor *descriptor);

int pqcp_fleet_snapshot_manifest_verify(
	const struct pqcp_fleet_snapshot_manifest *manifest);

int pqcp_fleet_snapshot_sync_manifest(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_snapshot_manifest *manifest);

int pqcp_fleet_snapshot_sync_leaf_summary(
	struct pqcp_fleet_snapshot_sync *sync,
	size_t first_index,
	struct pqcp_fleet_state_leaf_summary *summaries,
	size_t summary_capacity,
	size_t *summary_count);

int pqcp_fleet_snapshot_sync_lookup(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length,
	struct pqcp_fleet_state_leaf_descriptor *descriptor,
	size_t *leaf_index);

int pqcp_fleet_snapshot_sync_read(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length,
	size_t offset,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	uint64_t now_ms);

int pqcp_fleet_snapshot_sync_apply_local(
	struct pqcp_fleet_snapshot_sync *sync,
	const struct pqcp_fleet_state_mutation *mutations,
	size_t mutation_count,
	uint64_t new_generation,
	uint64_t created_at_ms,
	uint64_t expires_at_ms,
	struct pqcp_fleet_snapshot_manifest *manifest);

int pqcp_fleet_snapshot_sync_range(
	struct pqcp_fleet_snapshot_sync *sync,
	size_t first_index,
	size_t maximum_leaves,
	struct pqcp_fleet_state_range *range);

int pqcp_fleet_snapshot_sync_range_verify(
	const struct pqcp_fleet_state_range *range);

int pqcp_fleet_snapshot_sync_negotiate(
	const struct pqcp_fleet_snapshot_manifest *source,
	const struct pqcp_fleet_snapshot_manifest *receiver,
	const struct pqcp_fleet_snapshot_negotiation *capability,
	struct pqcp_fleet_snapshot_negotiation_result *result);

int pqcp_fleet_snapshot_sync_select_missing(
	struct pqcp_fleet_snapshot_sync *sync,
	const struct pqcp_fleet_state_leaf_summary *remote,
	size_t remote_count,
	struct pqcp_fleet_state_missing_cursor *cursor,
	struct pqcp_fleet_state_missing_leaf *missing,
	size_t missing_capacity,
	size_t *missing_count);

int pqcp_fleet_snapshot_transfer_cursor_init(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_state_transfer_cursor *cursor,
	size_t chunk_size,
	bool use_selection);

int pqcp_fleet_snapshot_transfer_next(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_state_transfer_cursor *cursor,
	const struct pqcp_fleet_state_transfer_selection *selection,
	size_t selection_count,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	struct pqcp_fleet_state_transfer_chunk *chunk);

int pqcp_fleet_snapshot_stage_begin(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_snapshot_mode mode,
	const struct pqcp_fleet_snapshot_manifest *manifest,
	uint64_t now_ms);

int pqcp_fleet_snapshot_stage_leaf_begin(
	struct pqcp_fleet_snapshot_sync *sync,
	const struct pqcp_fleet_state_leaf_descriptor *descriptor);

int pqcp_fleet_snapshot_stage_write_chunk(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length,
	size_t offset,
	const uint8_t *data,
	size_t length,
	const uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES]);

int pqcp_fleet_snapshot_stage_leaf_finalize(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length);

int pqcp_fleet_snapshot_stage_status(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_snapshot_stage_status *status);

int pqcp_fleet_snapshot_stage_commit(
	struct pqcp_fleet_snapshot_sync *sync,
	uint64_t now_ms,
	struct pqcp_fleet_snapshot_manifest *committed);

int pqcp_fleet_snapshot_stage_abort(
	struct pqcp_fleet_snapshot_sync *sync);

int pqcp_fleet_snapshot_sync_set_rollback_floor(
	struct pqcp_fleet_snapshot_sync *sync,
	uint64_t minimum_generation);

int pqcp_fleet_snapshot_sync_snapshot(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_snapshot_sync_snapshot *snapshot);

int pqcp_fleet_snapshot_sync_audit(
	struct pqcp_fleet_snapshot_sync *sync,
	bool verify_values);

const char *pqcp_fleet_state_domain_str(
	enum pqcp_fleet_state_domain domain);

const char *pqcp_fleet_snapshot_negotiation_action_str(
	enum pqcp_fleet_snapshot_negotiation_action action);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_SNAPSHOT_SYNC_H_ */
