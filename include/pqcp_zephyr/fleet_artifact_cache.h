/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free bounded content-addressed artifact cache for fleet nodes.
 */

#ifndef PQCP_ZEPHYR_FLEET_ARTIFACT_CACHE_H_
#define PQCP_ZEPHYR_FLEET_ARTIFACT_CACHE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_ARTIFACT_CACHE_SCHEMA_VERSION 1U
#define PQCP_FLEET_ARTIFACT_MAX_CHUNKS 256U
#define PQCP_FLEET_ARTIFACT_CHUNK_BITMAP_BYTES \
	(PQCP_FLEET_ARTIFACT_MAX_CHUNKS / 8U)
#define PQCP_FLEET_ARTIFACT_MAX_OWNERS 8U
#define PQCP_FLEET_ARTIFACT_LABEL_MAX_CHARS 48U
#define PQCP_FLEET_ARTIFACT_COMPACTION_SCHEMA_VERSION 1U

enum pqcp_fleet_artifact_kind {
	PQCP_FLEET_ARTIFACT_NONE = 0,
	PQCP_FLEET_ARTIFACT_FIRMWARE,
	PQCP_FLEET_ARTIFACT_POLICY,
	PQCP_FLEET_ARTIFACT_REVOCATION_SET,
	PQCP_FLEET_ARTIFACT_CREDENTIAL,
	PQCP_FLEET_ARTIFACT_ATTESTATION,
	PQCP_FLEET_ARTIFACT_SNAPSHOT,
	PQCP_FLEET_ARTIFACT_DELTA,
	PQCP_FLEET_ARTIFACT_EVIDENCE,
	PQCP_FLEET_ARTIFACT_RECOVERY,
	PQCP_FLEET_ARTIFACT_APPLICATION,
	PQCP_FLEET_ARTIFACT_KIND_COUNT,
};

enum pqcp_fleet_artifact_priority {
	PQCP_FLEET_ARTIFACT_PRIORITY_DISCARDABLE = 0,
	PQCP_FLEET_ARTIFACT_PRIORITY_BACKGROUND,
	PQCP_FLEET_ARTIFACT_PRIORITY_NORMAL,
	PQCP_FLEET_ARTIFACT_PRIORITY_IMPORTANT,
	PQCP_FLEET_ARTIFACT_PRIORITY_CRITICAL,
};

enum pqcp_fleet_artifact_state {
	PQCP_FLEET_ARTIFACT_STATE_EMPTY = 0,
	PQCP_FLEET_ARTIFACT_STATE_WRITING,
	PQCP_FLEET_ARTIFACT_STATE_VERIFIED,
	PQCP_FLEET_ARTIFACT_STATE_RETIRED,
	PQCP_FLEET_ARTIFACT_STATE_EXPIRED,
	PQCP_FLEET_ARTIFACT_STATE_CORRUPT,
};

enum pqcp_fleet_artifact_flag {
	PQCP_FLEET_ARTIFACT_FLAG_CONFIDENTIAL = (1U << 0),
	PQCP_FLEET_ARTIFACT_FLAG_NO_EVICT = (1U << 1),
	PQCP_FLEET_ARTIFACT_FLAG_ALLOW_OFFLINE = (1U << 2),
	PQCP_FLEET_ARTIFACT_FLAG_OPERATOR_PINNED = (1U << 3),
	PQCP_FLEET_ARTIFACT_FLAG_REPLACEMENT = (1U << 4),
	PQCP_FLEET_ARTIFACT_FLAG_CURRENT = (1U << 5),
	PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED = (1U << 6),
	PQCP_FLEET_ARTIFACT_FLAG_RETAIN_ROLLBACK = (1U << 7),
};

enum pqcp_fleet_artifact_owner_flag {
	PQCP_FLEET_ARTIFACT_OWNER_REFERENCE = (1U << 0),
	PQCP_FLEET_ARTIFACT_OWNER_PIN = (1U << 1),
	PQCP_FLEET_ARTIFACT_OWNER_INSTALL = (1U << 2),
	PQCP_FLEET_ARTIFACT_OWNER_TRANSFER = (1U << 3),
	PQCP_FLEET_ARTIFACT_OWNER_RECOVERY = (1U << 4),
};

enum pqcp_fleet_artifact_reserve_flag {
	PQCP_FLEET_ARTIFACT_RESERVE_ALLOW_EVICTION = (1U << 0),
	PQCP_FLEET_ARTIFACT_RESERVE_ALLOW_CURRENT_EVICTION = (1U << 1),
	PQCP_FLEET_ARTIFACT_RESERVE_IDEMPOTENT = (1U << 2),
	PQCP_FLEET_ARTIFACT_RESERVE_KEEP_ROLLBACK = (1U << 3),
};

enum pqcp_fleet_artifact_evict_flag {
	PQCP_FLEET_ARTIFACT_EVICT_EXPIRED = (1U << 0),
	PQCP_FLEET_ARTIFACT_EVICT_RETIRED = (1U << 1),
	PQCP_FLEET_ARTIFACT_EVICT_INCOMPLETE = (1U << 2),
	PQCP_FLEET_ARTIFACT_EVICT_CURRENT = (1U << 3),
	PQCP_FLEET_ARTIFACT_EVICT_CORRUPT = (1U << 4),
};

enum pqcp_fleet_artifact_remove_flag {
	PQCP_FLEET_ARTIFACT_REMOVE_ALLOW_CURRENT = (1U << 0),
	PQCP_FLEET_ARTIFACT_REMOVE_ALLOW_INCOMPLETE = (1U << 1),
};

struct pqcp_fleet_artifact_handle {
	uint32_t slot;
	uint32_t slot_generation;
};

struct pqcp_fleet_artifact_owner {
	uint64_t owner_id;
	uint32_t references;
	uint32_t flags;
	uint64_t acquired_at_ms;
	uint64_t expires_at_ms;
	bool occupied;
};

struct pqcp_fleet_artifact_entry {
	uint32_t schema_version;
	uint32_t slot_generation;
	uint64_t object_id;
	uint64_t object_generation;
	uint64_t cache_generation;
	enum pqcp_fleet_artifact_kind kind;
	enum pqcp_fleet_artifact_priority priority;
	enum pqcp_fleet_artifact_state state;
	uint32_t flags;
	size_t extent_offset;
	size_t extent_capacity;
	size_t content_length;
	size_t stored_bytes;
	size_t chunk_size;
	uint32_t chunk_count;
	uint32_t complete_chunks;
	uint32_t owner_count;
	uint32_t reference_count;
	uint32_t pin_count;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint64_t last_access_at_ms;
	uint64_t access_count;
	uint32_t replacement_slot;
	uint32_t replacement_generation;
	char label[PQCP_FLEET_ARTIFACT_LABEL_MAX_CHARS];
	uint8_t expected_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t verified_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t replaced_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t chunk_bitmap[PQCP_FLEET_ARTIFACT_CHUNK_BITMAP_BYTES];
	struct pqcp_fleet_artifact_owner
		owners[PQCP_FLEET_ARTIFACT_MAX_OWNERS];
	bool occupied;
};

struct pqcp_fleet_artifact_reader_lease {
	uint64_t lease_id;
	uint64_t owner_id;
	struct pqcp_fleet_artifact_handle artifact;
	uint64_t opened_at_ms;
	uint64_t expires_at_ms;
	uint64_t bytes_read;
	uint32_t read_count;
	bool active;
};

struct pqcp_fleet_artifact_reserve {
	uint64_t object_id;
	uint64_t object_generation;
	enum pqcp_fleet_artifact_kind kind;
	enum pqcp_fleet_artifact_priority priority;
	uint32_t artifact_flags;
	uint32_t reserve_flags;
	size_t content_length;
	size_t chunk_size;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	const char *label;
	const uint8_t *expected_digest;
	const uint8_t *expected_current_digest;
};

struct pqcp_fleet_artifact_chunk_status {
	uint32_t chunk_count;
	uint32_t complete_chunks;
	size_t stored_bytes;
	size_t content_length;
	uint32_t first_missing_chunk;
	bool complete;
	bool digest_verified;
};

struct pqcp_fleet_artifact_evict_request {
	size_t bytes_required;
	enum pqcp_fleet_artifact_priority maximum_priority;
	uint32_t flags;
	uint64_t now_ms;
	size_t maximum_entries;
};

struct pqcp_fleet_artifact_evict_result {
	size_t bytes_released;
	size_t entries_evicted;
	size_t expired_evicted;
	size_t retired_evicted;
	size_t incomplete_evicted;
	size_t current_evicted;
};

struct pqcp_fleet_artifact_compaction_move {
	struct pqcp_fleet_artifact_handle artifact;
	size_t source_offset;
	size_t destination_offset;
	size_t length;
};

struct pqcp_fleet_artifact_compaction_plan {
	uint32_t schema_version;
	uint64_t cache_generation;
	size_t move_count;
	size_t bytes_moved;
	size_t packed_bytes;
	size_t free_tail_bytes;
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_artifact_snapshot {
	uint32_t schema_version;
	uint64_t generation;
	size_t entry_capacity;
	size_t occupied_entries;
	size_t writing_entries;
	size_t verified_entries;
	size_t retired_entries;
	size_t expired_entries;
	size_t corrupt_entries;
	size_t current_entries;
	size_t pinned_entries;
	size_t referenced_entries;
	size_t arena_capacity;
	size_t arena_allocated;
	size_t arena_payload_bytes;
	size_t arena_free_bytes;
	size_t largest_free_extent;
	size_t lease_capacity;
	size_t active_leases;
	uint64_t reserve_count;
	uint64_t commit_count;
	uint64_t abort_count;
	uint64_t eviction_count;
	uint64_t expiry_count;
	uint64_t digest_failure_count;
	uint64_t rejected_count;
	uint64_t compaction_count;
	uint8_t metadata_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t snapshot_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_artifact_cache {
	struct pqcp_fleet_artifact_entry *entries;
	size_t entry_capacity;
	uint8_t *arena;
	size_t arena_capacity;
	size_t arena_alignment;
	struct pqcp_fleet_artifact_reader_lease *leases;
	size_t lease_capacity;
	uint64_t generation;
	uint64_t next_lease_id;
	uint64_t reserve_count;
	uint64_t commit_count;
	uint64_t abort_count;
	uint64_t eviction_count;
	uint64_t expiry_count;
	uint64_t digest_failure_count;
	uint64_t rejected_count;
	uint64_t compaction_count;
	struct k_mutex lock;
	bool initialized;
};

int pqcp_fleet_artifact_cache_init(
	struct pqcp_fleet_artifact_cache *cache,
	struct pqcp_fleet_artifact_entry *entries,
	size_t entry_capacity,
	uint8_t *arena,
	size_t arena_capacity,
	size_t arena_alignment,
	struct pqcp_fleet_artifact_reader_lease *leases,
	size_t lease_capacity,
	uint64_t first_generation);

int pqcp_fleet_artifact_cache_reserve(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_reserve *request,
	struct pqcp_fleet_artifact_handle *handle);

int pqcp_fleet_artifact_cache_write_chunk(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	size_t offset,
	const uint8_t *data,
	size_t length,
	const uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES]);

int pqcp_fleet_artifact_cache_chunk_status(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	struct pqcp_fleet_artifact_chunk_status *status);

int pqcp_fleet_artifact_cache_finalize(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle);

int pqcp_fleet_artifact_cache_commit(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	const uint8_t expected_current_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms);

int pqcp_fleet_artifact_cache_abort(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle);

int pqcp_fleet_artifact_cache_find_digest(
	struct pqcp_fleet_artifact_cache *cache,
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES],
	struct pqcp_fleet_artifact_handle *handle);

int pqcp_fleet_artifact_cache_find_current(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t object_id,
	enum pqcp_fleet_artifact_kind kind,
	struct pqcp_fleet_artifact_handle *handle);

int pqcp_fleet_artifact_cache_get(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	struct pqcp_fleet_artifact_entry *entry);

int pqcp_fleet_artifact_cache_retain(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint64_t owner_id,
	uint32_t owner_flags,
	uint64_t now_ms,
	uint64_t expires_at_ms);

int pqcp_fleet_artifact_cache_release(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint64_t owner_id,
	uint32_t owner_flags);

int pqcp_fleet_artifact_cache_release_owner(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t owner_id,
	uint32_t owner_flags,
	size_t *released_references);

int pqcp_fleet_artifact_cache_touch(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint64_t now_ms);

int pqcp_fleet_artifact_cache_read(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	size_t offset,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	uint64_t now_ms);

int pqcp_fleet_artifact_cache_lease_open(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint64_t owner_id,
	uint64_t now_ms,
	uint64_t duration_ms,
	uint64_t *lease_id);

int pqcp_fleet_artifact_cache_lease_read(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t lease_id,
	size_t offset,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	uint64_t now_ms);

int pqcp_fleet_artifact_cache_lease_renew(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t lease_id,
	uint64_t now_ms,
	uint64_t duration_ms);

int pqcp_fleet_artifact_cache_lease_close(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t lease_id);

int pqcp_fleet_artifact_cache_lease_reap(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t now_ms,
	size_t *reaped_count);

int pqcp_fleet_artifact_cache_expire(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t now_ms,
	bool erase_unowned,
	size_t *expired_count);

int pqcp_fleet_artifact_cache_evict(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_evict_request *request,
	struct pqcp_fleet_artifact_evict_result *result);

int pqcp_fleet_artifact_cache_remove(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint32_t flags);

int pqcp_fleet_artifact_cache_compaction_plan(
	struct pqcp_fleet_artifact_cache *cache,
	struct pqcp_fleet_artifact_compaction_move *moves,
	size_t move_capacity,
	struct pqcp_fleet_artifact_compaction_plan *plan);

int pqcp_fleet_artifact_cache_compact(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_compaction_move *moves,
	size_t move_count,
	const struct pqcp_fleet_artifact_compaction_plan *plan);

int pqcp_fleet_artifact_cache_snapshot(
	struct pqcp_fleet_artifact_cache *cache,
	struct pqcp_fleet_artifact_snapshot *snapshot);

int pqcp_fleet_artifact_cache_entry_verify(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	bool verify_content);

int pqcp_fleet_artifact_cache_audit(
	struct pqcp_fleet_artifact_cache *cache,
	bool verify_content);

const char *pqcp_fleet_artifact_kind_str(
	enum pqcp_fleet_artifact_kind kind);

const char *pqcp_fleet_artifact_state_str(
	enum pqcp_fleet_artifact_state state);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_ARTIFACT_CACHE_H_ */
