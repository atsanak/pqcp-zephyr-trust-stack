/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free bounded content-addressed artifact cache for fleet nodes.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_artifact_cache.h>
#include <pqcp_zephyr/runtime.h>

#include "runtime_internal.h"

#define ARTIFACT_ENTRY_DIGEST_BODY_BYTES 320U
#define ARTIFACT_PLAN_DIGEST_BODY_BYTES 128U
#define ARTIFACT_SNAPSHOT_DIGEST_BODY_BYTES 384U
#define ARTIFACT_INVALID_SLOT UINT32_MAX

static bool artifact_kind_valid(enum pqcp_fleet_artifact_kind kind)
{
	return kind > PQCP_FLEET_ARTIFACT_NONE &&
	       kind < PQCP_FLEET_ARTIFACT_KIND_COUNT;
}

static bool artifact_priority_valid(
	enum pqcp_fleet_artifact_priority priority)
{
	return priority >= PQCP_FLEET_ARTIFACT_PRIORITY_DISCARDABLE &&
	       priority <= PQCP_FLEET_ARTIFACT_PRIORITY_CRITICAL;
}

static bool artifact_state_valid(
	enum pqcp_fleet_artifact_state state)
{
	return state >= PQCP_FLEET_ARTIFACT_STATE_EMPTY &&
	       state <= PQCP_FLEET_ARTIFACT_STATE_CORRUPT;
}

static bool digest_is_zero(
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	if (digest == NULL) {
		return true;
	}
	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static bool digest_equal(
	const uint8_t left[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t difference = 0U;

	if (left == NULL || right == NULL) {
		return false;
	}
	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static bool text_valid(const char *text, size_t capacity)
{
	if (text == NULL || capacity < 2U) {
		return false;
	}
	return strnlen(text, capacity) < capacity;
}

static int size_add(size_t left, size_t right, size_t *result)
{
	if (result == NULL || left > SIZE_MAX - right) {
		return -EOVERFLOW;
	}
	*result = left + right;
	return 0;
}

static int size_multiply(size_t left, size_t right, size_t *result)
{
	if (result == NULL ||
	    (left != 0U && right > SIZE_MAX / left)) {
		return -EOVERFLOW;
	}
	*result = left * right;
	return 0;
}

static int align_up(
	size_t value,
	size_t alignment,
	size_t *result)
{
	size_t remainder;
	size_t addition;

	if (result == NULL || alignment == 0U) {
		return -EINVAL;
	}
	remainder = value % alignment;
	if (remainder == 0U) {
		*result = value;
		return 0;
	}
	addition = alignment - remainder;
	return size_add(value, addition, result);
}

static uint64_t generation_next(uint64_t generation)
{
	return generation == UINT64_MAX ? 1U : generation + 1U;
}

static uint32_t slot_generation_next(uint32_t generation)
{
	return generation == UINT32_MAX ? 1U : generation + 1U;
}

static bool cache_ready(
	const struct pqcp_fleet_artifact_cache *cache)
{
	return cache != NULL &&
	       cache->initialized &&
	       cache->entries != NULL &&
	       cache->entry_capacity != 0U &&
	       cache->arena != NULL &&
	       cache->arena_capacity != 0U &&
	       cache->arena_alignment != 0U &&
	       cache->leases != NULL &&
	       cache->lease_capacity != 0U &&
	       cache->generation != 0U &&
	       cache->next_lease_id != 0U;
}

static void write_u32(
	uint8_t *output,
	size_t *offset,
	uint32_t value)
{
	pqcp_runtime_internal_write_u32(output + *offset, value);
	*offset += 4U;
}

static void write_u64(
	uint8_t *output,
	size_t *offset,
	uint64_t value)
{
	pqcp_runtime_internal_write_u64(output + *offset, value);
	*offset += 8U;
}

static void write_size(
	uint8_t *output,
	size_t *offset,
	size_t value)
{
	write_u64(output, offset, (uint64_t)value);
}

static bool bit_test(const uint8_t *bitmap, uint32_t index)
{
	return (bitmap[index / 8U] &
		(uint8_t)(1U << (index % 8U))) != 0U;
}

static void bit_set(uint8_t *bitmap, uint32_t index)
{
	bitmap[index / 8U] |=
		(uint8_t)(1U << (index % 8U));
}

static void bit_clear(uint8_t *bitmap, uint32_t index)
{
	bitmap[index / 8U] &=
		(uint8_t)~(uint8_t)(1U << (index % 8U));
}

static uint32_t bitmap_count(
	const uint8_t bitmap[PQCP_FLEET_ARTIFACT_CHUNK_BITMAP_BYTES],
	uint32_t bit_count)
{
	uint32_t count = 0U;

	for (uint32_t index = 0U; index < bit_count; ++index) {
		if (bit_test(bitmap, index)) {
			count++;
		}
	}
	return count;
}

static bool bitmap_tail_clear(
	const uint8_t bitmap[PQCP_FLEET_ARTIFACT_CHUNK_BITMAP_BYTES],
	uint32_t bit_count)
{
	for (uint32_t index = bit_count;
	     index < PQCP_FLEET_ARTIFACT_MAX_CHUNKS; ++index) {
		if (bit_test(bitmap, index)) {
			return false;
		}
	}
	return true;
}

static size_t chunk_expected_length(
	const struct pqcp_fleet_artifact_entry *entry,
	uint32_t chunk_index)
{
	size_t offset;
	size_t remaining;

	if (entry == NULL || chunk_index >= entry->chunk_count ||
	    entry->chunk_size == 0U ||
	    size_multiply(
		    (size_t)chunk_index,
		    entry->chunk_size, &offset) != 0 ||
	    offset >= entry->content_length) {
		return 0U;
	}
	remaining = entry->content_length - offset;
	return remaining < entry->chunk_size ?
		remaining : entry->chunk_size;
}

static size_t completed_payload_bytes(
	const struct pqcp_fleet_artifact_entry *entry)
{
	size_t total = 0U;

	for (uint32_t index = 0U;
	     index < entry->chunk_count; ++index) {
		if (bit_test(entry->chunk_bitmap, index)) {
			size_t length =
				chunk_expected_length(entry, index);

			if (length > SIZE_MAX - total) {
				return SIZE_MAX;
			}
			total += length;
		}
	}
	return total;
}

static bool extent_bounds_valid(
	const struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_entry *entry)
{
	if (!entry->occupied) {
		return entry->extent_offset == 0U &&
		       entry->extent_capacity == 0U &&
		       entry->content_length == 0U;
	}
	if (entry->extent_capacity == 0U ||
	    entry->content_length == 0U ||
	    entry->content_length > entry->extent_capacity ||
	    entry->extent_offset % cache->arena_alignment != 0U ||
	    entry->extent_capacity % cache->arena_alignment != 0U ||
	    entry->extent_offset > cache->arena_capacity ||
	    entry->extent_capacity >
		    cache->arena_capacity - entry->extent_offset) {
		return false;
	}
	return true;
}

static bool extents_overlap(
	size_t left_offset,
	size_t left_length,
	size_t right_offset,
	size_t right_length)
{
	size_t left_end;
	size_t right_end;

	if (left_length == 0U || right_length == 0U ||
	    size_add(left_offset, left_length, &left_end) != 0 ||
	    size_add(right_offset, right_length, &right_end) != 0) {
		return left_length != 0U && right_length != 0U;
	}
	return left_offset < right_end &&
	       right_offset < left_end;
}

static int handle_entry_locked(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	struct pqcp_fleet_artifact_entry **entry)
{
	struct pqcp_fleet_artifact_entry *candidate;

	if (handle == NULL || entry == NULL ||
	    handle->slot >= cache->entry_capacity ||
	    handle->slot_generation == 0U) {
		return -EINVAL;
	}
	candidate = &cache->entries[handle->slot];
	if (!candidate->occupied ||
	    candidate->slot_generation !=
		    handle->slot_generation) {
		return -ESTALE;
	}
	*entry = candidate;
	return 0;
}

static struct pqcp_fleet_artifact_handle entry_handle(
	const struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_entry *entry)
{
	struct pqcp_fleet_artifact_handle handle = { 0 };
	size_t index = (size_t)(entry - cache->entries);

	handle.slot = index > UINT32_MAX ?
		UINT32_MAX : (uint32_t)index;
	handle.slot_generation = entry->slot_generation;
	return handle;
}

static int free_entry_index_locked(
	const struct pqcp_fleet_artifact_cache *cache)
{
	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		if (!cache->entries[index].occupied) {
			return index > INT_MAX ? -1 : (int)index;
		}
	}
	return -1;
}

static int digest_entry_index_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		const struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[index];

		if (!entry->occupied) {
			continue;
		}
		if (digest_equal(entry->expected_digest, digest)) {
			return index > INT_MAX ? -1 : (int)index;
		}
	}
	return -1;
}

static int current_entry_index_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	uint64_t object_id,
	enum pqcp_fleet_artifact_kind kind)
{
	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		const struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[index];

		if (entry->occupied &&
		    entry->object_id == object_id &&
		    entry->kind == kind &&
		    (entry->flags &
		     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U) {
			return index > INT_MAX ? -1 : (int)index;
		}
	}
	return -1;
}

static int owner_index(
	const struct pqcp_fleet_artifact_entry *entry,
	uint64_t owner_id)
{
	for (size_t index = 0U;
	     index < PQCP_FLEET_ARTIFACT_MAX_OWNERS; ++index) {
		if (entry->owners[index].occupied &&
		    entry->owners[index].owner_id == owner_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_owner_index(
	const struct pqcp_fleet_artifact_entry *entry)
{
	for (size_t index = 0U;
	     index < PQCP_FLEET_ARTIFACT_MAX_OWNERS; ++index) {
		if (!entry->owners[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static int lease_index_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	uint64_t lease_id)
{
	for (size_t index = 0U;
	     index < cache->lease_capacity; ++index) {
		if (cache->leases[index].active &&
		    cache->leases[index].lease_id == lease_id) {
			return index > INT_MAX ? -1 : (int)index;
		}
	}
	return -1;
}

static int free_lease_index_locked(
	const struct pqcp_fleet_artifact_cache *cache)
{
	for (size_t index = 0U;
	     index < cache->lease_capacity; ++index) {
		if (!cache->leases[index].active) {
			return index > INT_MAX ? -1 : (int)index;
		}
	}
	return -1;
}

static uint64_t next_lease_id_locked(
	struct pqcp_fleet_artifact_cache *cache)
{
	uint64_t candidate = cache->next_lease_id;

	for (size_t attempt = 0U;
	     attempt <= cache->lease_capacity; ++attempt) {
		if (candidate == 0U) {
			candidate = 1U;
		}
		if (lease_index_locked(cache, candidate) < 0) {
			cache->next_lease_id =
				generation_next(candidate);
			return candidate;
		}
		candidate = generation_next(candidate);
	}
	return 0U;
}

static void cache_generation_advance_locked(
	struct pqcp_fleet_artifact_cache *cache)
{
	cache->generation = generation_next(cache->generation);
}

static int find_extent_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	size_t required,
	size_t *offset)
{
	size_t cursor = 0U;

	if (required == 0U || offset == NULL ||
	    required > cache->arena_capacity) {
		return -EINVAL;
	}
	for (;;) {
		size_t nearest_offset = SIZE_MAX;
		size_t nearest_length = 0U;
		bool cursor_inside = false;

		for (size_t index = 0U;
		     index < cache->entry_capacity; ++index) {
			const struct pqcp_fleet_artifact_entry *entry =
				&cache->entries[index];
			size_t end;

			if (!entry->occupied ||
			    entry->extent_capacity == 0U ||
			    size_add(
				    entry->extent_offset,
				    entry->extent_capacity,
				    &end) != 0) {
				continue;
			}
			if (entry->extent_offset <= cursor &&
			    cursor < end) {
				if (!cursor_inside ||
				    end > nearest_offset) {
					nearest_offset = end;
					cursor_inside = true;
				}
				continue;
			}
			if (!cursor_inside &&
			    entry->extent_offset >= cursor &&
			    entry->extent_offset < nearest_offset) {
				nearest_offset =
					entry->extent_offset;
				nearest_length =
					entry->extent_capacity;
			}
		}
		if (cursor_inside) {
			if (align_up(
				    nearest_offset,
				    cache->arena_alignment,
				    &cursor) != 0 ||
			    cursor > cache->arena_capacity) {
				return -ENOSPC;
			}
			continue;
		}
		if (nearest_offset == SIZE_MAX) {
			if (cursor <= cache->arena_capacity &&
			    required <=
				    cache->arena_capacity - cursor) {
				*offset = cursor;
				return 0;
			}
			return -ENOSPC;
		}
		if (nearest_offset >= cursor &&
		    required <= nearest_offset - cursor) {
			*offset = cursor;
			return 0;
		}
		if (size_add(
			    nearest_offset, nearest_length,
			    &cursor) != 0 ||
		    align_up(
			    cursor, cache->arena_alignment,
			    &cursor) != 0 ||
		    cursor > cache->arena_capacity) {
			return -ENOSPC;
		}
	}
}

static size_t largest_free_extent_locked(
	const struct pqcp_fleet_artifact_cache *cache)
{
	size_t largest = 0U;
	size_t cursor = 0U;
	size_t processed = 0U;

	while (processed < cache->entry_capacity) {
		size_t selected_offset = SIZE_MAX;
		size_t selected_end = 0U;
		bool found = false;

		for (size_t index = 0U;
		     index < cache->entry_capacity; ++index) {
			const struct pqcp_fleet_artifact_entry *entry =
				&cache->entries[index];
			size_t end;

			if (!entry->occupied ||
			    entry->extent_capacity == 0U ||
			    entry->extent_offset < cursor ||
			    size_add(
				    entry->extent_offset,
				    entry->extent_capacity,
				    &end) != 0) {
				continue;
			}
			if (!found ||
			    entry->extent_offset < selected_offset) {
				selected_offset =
					entry->extent_offset;
				selected_end = end;
				found = true;
			}
		}
		if (!found) {
			break;
		}
		if (selected_offset > cursor &&
		    selected_offset - cursor > largest) {
			largest = selected_offset - cursor;
		}
		cursor = selected_end;
		processed++;
	}
	if (cursor < cache->arena_capacity &&
	    cache->arena_capacity - cursor > largest) {
		largest = cache->arena_capacity - cursor;
	}
	return largest;
}

static size_t allocated_bytes_locked(
	const struct pqcp_fleet_artifact_cache *cache)
{
	size_t total = 0U;

	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		const struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[index];

		if (!entry->occupied) {
			continue;
		}
		if (entry->extent_capacity > SIZE_MAX - total) {
			return SIZE_MAX;
		}
		total += entry->extent_capacity;
	}
	return total;
}

static size_t payload_bytes_locked(
	const struct pqcp_fleet_artifact_cache *cache)
{
	size_t total = 0U;

	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		const struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[index];

		if (!entry->occupied) {
			continue;
		}
		if (entry->content_length > SIZE_MAX - total) {
			return SIZE_MAX;
		}
		total += entry->content_length;
	}
	return total;
}

static void erase_entry_locked(
	struct pqcp_fleet_artifact_cache *cache,
	size_t index)
{
	struct pqcp_fleet_artifact_entry *entry =
		&cache->entries[index];
	uint32_t next_generation =
		slot_generation_next(entry->slot_generation);

	if (entry->occupied &&
	    extent_bounds_valid(cache, entry)) {
		pqcp_runtime_secure_zero(
			cache->arena + entry->extent_offset,
			entry->extent_capacity);
	}
	pqcp_runtime_secure_zero(entry, sizeof(*entry));
	entry->slot_generation = next_generation;
	cache_generation_advance_locked(cache);
}

static bool entry_has_active_lease_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_entry *entry)
{
	const struct pqcp_fleet_artifact_handle handle =
		entry_handle(cache, entry);

	for (size_t index = 0U;
	     index < cache->lease_capacity; ++index) {
		const struct pqcp_fleet_artifact_reader_lease *lease =
			&cache->leases[index];

		if (lease->active &&
		    lease->artifact.slot == handle.slot &&
		    lease->artifact.slot_generation ==
			    handle.slot_generation) {
			return true;
		}
	}
	return false;
}

static bool entry_evictable_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_entry *entry,
	enum pqcp_fleet_artifact_priority maximum_priority,
	uint32_t flags,
	uint64_t now_ms)
{
	bool allowed_state = false;

	if (!entry->occupied ||
	    entry->priority > maximum_priority ||
	    entry->reference_count != 0U ||
	    entry->pin_count != 0U ||
	    entry->owner_count != 0U ||
	    (entry->flags &
	     (PQCP_FLEET_ARTIFACT_FLAG_NO_EVICT |
	      PQCP_FLEET_ARTIFACT_FLAG_OPERATOR_PINNED)) != 0U ||
	    entry_has_active_lease_locked(cache, entry)) {
		return false;
	}
	if ((entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U &&
	    (flags & PQCP_FLEET_ARTIFACT_EVICT_CURRENT) == 0U) {
		return false;
	}
	if ((flags & PQCP_FLEET_ARTIFACT_EVICT_EXPIRED) != 0U &&
	    (entry->state == PQCP_FLEET_ARTIFACT_STATE_EXPIRED ||
	     (entry->expires_at_ms != 0U &&
	      now_ms != 0U &&
	      now_ms >= entry->expires_at_ms))) {
		allowed_state = true;
	}
	if ((flags & PQCP_FLEET_ARTIFACT_EVICT_RETIRED) != 0U &&
	    entry->state == PQCP_FLEET_ARTIFACT_STATE_RETIRED) {
		allowed_state = true;
	}
	if ((flags & PQCP_FLEET_ARTIFACT_EVICT_INCOMPLETE) != 0U &&
	    entry->state == PQCP_FLEET_ARTIFACT_STATE_WRITING) {
		allowed_state = true;
	}
	if ((flags & PQCP_FLEET_ARTIFACT_EVICT_CORRUPT) != 0U &&
	    entry->state == PQCP_FLEET_ARTIFACT_STATE_CORRUPT) {
		allowed_state = true;
	}
	if ((flags & PQCP_FLEET_ARTIFACT_EVICT_CURRENT) != 0U &&
	    (entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U) {
		allowed_state = true;
	}
	return allowed_state;
}

static uint32_t eviction_state_rank(
	const struct pqcp_fleet_artifact_entry *entry,
	uint64_t now_ms)
{
	if (entry->state == PQCP_FLEET_ARTIFACT_STATE_CORRUPT) {
		return 0U;
	}
	if (entry->state == PQCP_FLEET_ARTIFACT_STATE_EXPIRED ||
	    (entry->expires_at_ms != 0U &&
	     now_ms >= entry->expires_at_ms)) {
		return 1U;
	}
	if (entry->state == PQCP_FLEET_ARTIFACT_STATE_WRITING) {
		return 2U;
	}
	if (entry->state == PQCP_FLEET_ARTIFACT_STATE_RETIRED) {
		return 3U;
	}
	if ((entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) == 0U) {
		return 4U;
	}
	return 5U;
}

static bool eviction_candidate_better(
	const struct pqcp_fleet_artifact_entry *candidate,
	const struct pqcp_fleet_artifact_entry *selected,
	uint64_t now_ms)
{
	uint32_t candidate_rank =
		eviction_state_rank(candidate, now_ms);
	uint32_t selected_rank =
		eviction_state_rank(selected, now_ms);

	if (candidate_rank != selected_rank) {
		return candidate_rank < selected_rank;
	}
	if (candidate->priority != selected->priority) {
		return candidate->priority < selected->priority;
	}
	if (candidate->last_access_at_ms !=
	    selected->last_access_at_ms) {
		return candidate->last_access_at_ms <
		       selected->last_access_at_ms;
	}
	if (candidate->access_count != selected->access_count) {
		return candidate->access_count <
		       selected->access_count;
	}
	if (candidate->extent_capacity !=
	    selected->extent_capacity) {
		return candidate->extent_capacity >
		       selected->extent_capacity;
	}
	if (candidate->object_generation !=
	    selected->object_generation) {
		return candidate->object_generation <
		       selected->object_generation;
	}
	return candidate->object_id < selected->object_id;
}

static int eviction_candidate_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	enum pqcp_fleet_artifact_priority maximum_priority,
	uint32_t flags,
	uint64_t now_ms)
{
	int selected = -1;

	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		const struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[index];

		if (!entry_evictable_locked(
			    cache, entry, maximum_priority,
			    flags, now_ms)) {
			continue;
		}
		if (selected < 0 ||
		    eviction_candidate_better(
			    entry, &cache->entries[selected],
			    now_ms)) {
			selected = (int)index;
		}
	}
	return selected;
}

static void eviction_result_add(
	struct pqcp_fleet_artifact_evict_result *result,
	const struct pqcp_fleet_artifact_entry *entry,
	uint64_t now_ms)
{
	result->bytes_released += entry->extent_capacity;
	result->entries_evicted++;
	if (entry->state == PQCP_FLEET_ARTIFACT_STATE_EXPIRED ||
	    (entry->expires_at_ms != 0U &&
	     now_ms >= entry->expires_at_ms)) {
		result->expired_evicted++;
	}
	if (entry->state == PQCP_FLEET_ARTIFACT_STATE_RETIRED) {
		result->retired_evicted++;
	}
	if (entry->state == PQCP_FLEET_ARTIFACT_STATE_WRITING) {
		result->incomplete_evicted++;
	}
	if ((entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U) {
		result->current_evicted++;
	}
}

static int entry_digest_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	size_t slot,
	const uint8_t previous[PQCP_FLEET_DIGEST_BYTES],
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	const struct pqcp_fleet_artifact_entry *entry =
		&cache->entries[slot];
	uint8_t body[ARTIFACT_ENTRY_DIGEST_BODY_BYTES];
	size_t offset = 0U;
	size_t label_length;
	int ret;

	if (!entry->occupied || previous == NULL ||
	    digest == NULL ||
	    slot > UINT32_MAX ||
	    !text_valid(entry->label, sizeof(entry->label))) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-ARTIFACT-METADATA-V1", 25U);
	offset += 25U;
	write_u32(body, &offset, (uint32_t)slot);
	write_u32(body, &offset, entry->schema_version);
	write_u32(body, &offset, entry->slot_generation);
	write_u64(body, &offset, entry->object_id);
	write_u64(body, &offset, entry->object_generation);
	write_u64(body, &offset, entry->cache_generation);
	write_u32(body, &offset, (uint32_t)entry->kind);
	write_u32(body, &offset, (uint32_t)entry->priority);
	write_u32(body, &offset, (uint32_t)entry->state);
	write_u32(body, &offset, entry->flags);
	write_size(body, &offset, entry->extent_offset);
	write_size(body, &offset, entry->extent_capacity);
	write_size(body, &offset, entry->content_length);
	write_size(body, &offset, entry->stored_bytes);
	write_size(body, &offset, entry->chunk_size);
	write_u32(body, &offset, entry->chunk_count);
	write_u32(body, &offset, entry->complete_chunks);
	write_u32(body, &offset, entry->owner_count);
	write_u32(body, &offset, entry->reference_count);
	write_u32(body, &offset, entry->pin_count);
	write_u64(body, &offset, entry->created_at_ms);
	write_u64(body, &offset, entry->expires_at_ms);
	write_u64(body, &offset, entry->last_access_at_ms);
	write_u64(body, &offset, entry->access_count);
	label_length = strnlen(entry->label, sizeof(entry->label));
	body[offset++] = (uint8_t)label_length;
	memcpy(body + offset, entry->label, label_length);
	offset += label_length;
	memcpy(body + offset, entry->expected_digest,
	       sizeof(entry->expected_digest));
	offset += sizeof(entry->expected_digest);
	memcpy(body + offset, entry->verified_digest,
	       sizeof(entry->verified_digest));
	offset += sizeof(entry->verified_digest);
	memcpy(body + offset, previous,
	       PQCP_FLEET_DIGEST_BYTES);
	offset += PQCP_FLEET_DIGEST_BYTES;
	if (offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int metadata_digest_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t chain[PQCP_FLEET_DIGEST_BYTES];
	uint8_t next[PQCP_FLEET_DIGEST_BYTES];
	static const uint8_t empty_tag[] =
		"PQCP-ARTIFACT-METADATA-EMPTY-V1";
	int ret;

	ret = pqcp_runtime_internal_sha256(
		empty_tag, sizeof(empty_tag) - 1U, chain);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		if (!cache->entries[index].occupied) {
			continue;
		}
		ret = entry_digest_locked(
			cache, index, chain, next);
		if (ret != 0) {
			break;
		}
		memcpy(chain, next, sizeof(chain));
	}
	if (ret == 0) {
		memcpy(digest, chain, sizeof(chain));
	}
	pqcp_runtime_secure_zero(chain, sizeof(chain));
	pqcp_runtime_secure_zero(next, sizeof(next));
	return ret;
}

static int reserve_validate(
	const struct pqcp_fleet_artifact_reserve *request,
	size_t arena_alignment,
	size_t arena_capacity,
	size_t *extent_capacity,
	uint32_t *chunk_count)
{
	size_t count;

	if (request == NULL ||
	    extent_capacity == NULL ||
	    chunk_count == NULL ||
	    request->object_id == 0U ||
	    request->object_generation == 0U ||
	    !artifact_kind_valid(request->kind) ||
	    !artifact_priority_valid(request->priority) ||
	    request->content_length == 0U ||
	    request->content_length > arena_capacity ||
	    request->chunk_size == 0U ||
	    request->chunk_size > request->content_length ||
	    request->created_at_ms == 0U ||
	    (request->expires_at_ms != 0U &&
	     request->expires_at_ms <= request->created_at_ms) ||
	    request->label == NULL ||
	    !text_valid(
		    request->label,
		    PQCP_FLEET_ARTIFACT_LABEL_MAX_CHARS) ||
	    request->expected_digest == NULL ||
	    digest_is_zero(request->expected_digest) ||
	    (request->expected_current_digest != NULL &&
	     digest_is_zero(request->expected_current_digest))) {
		return -EINVAL;
	}
	count = request->content_length / request->chunk_size;
	if (request->content_length % request->chunk_size != 0U) {
		if (count == SIZE_MAX) {
			return -EOVERFLOW;
		}
		count++;
	}
	if (count == 0U ||
	    count > PQCP_FLEET_ARTIFACT_MAX_CHUNKS ||
	    count > UINT32_MAX) {
		return -E2BIG;
	}
	if (align_up(
		    request->content_length,
		    arena_alignment,
		    extent_capacity) != 0 ||
	    *extent_capacity > arena_capacity) {
		return -EOVERFLOW;
	}
	*chunk_count = (uint32_t)count;
	return 0;
}

int pqcp_fleet_artifact_cache_init(
	struct pqcp_fleet_artifact_cache *cache,
	struct pqcp_fleet_artifact_entry *entries,
	size_t entry_capacity,
	uint8_t *arena,
	size_t arena_capacity,
	size_t arena_alignment,
	struct pqcp_fleet_artifact_reader_lease *leases,
	size_t lease_capacity,
	uint64_t first_generation)
{
	size_t entry_bytes;
	size_t lease_bytes;

	if (cache == NULL || entries == NULL ||
	    entry_capacity == 0U ||
	    entry_capacity > UINT32_MAX ||
	    arena == NULL || arena_capacity == 0U ||
	    arena_alignment == 0U ||
	    arena_alignment > arena_capacity ||
	    leases == NULL || lease_capacity == 0U ||
	    first_generation == 0U ||
	    size_multiply(
		    entry_capacity, sizeof(*entries),
		    &entry_bytes) != 0 ||
	    size_multiply(
		    lease_capacity, sizeof(*leases),
		    &lease_bytes) != 0) {
		return -EINVAL;
	}
	memset(cache, 0, sizeof(*cache));
	memset(entries, 0, entry_bytes);
	pqcp_runtime_secure_zero(arena, arena_capacity);
	memset(leases, 0, lease_bytes);
	for (size_t index = 0U;
	     index < entry_capacity; ++index) {
		entries[index].slot_generation = 1U;
	}
	cache->entries = entries;
	cache->entry_capacity = entry_capacity;
	cache->arena = arena;
	cache->arena_capacity = arena_capacity;
	cache->arena_alignment = arena_alignment;
	cache->leases = leases;
	cache->lease_capacity = lease_capacity;
	cache->generation = first_generation;
	cache->next_lease_id = 1U;
	k_mutex_init(&cache->lock);
	cache->initialized = true;
	return 0;
}

int pqcp_fleet_artifact_cache_reserve(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_reserve *request,
	struct pqcp_fleet_artifact_handle *handle)
{
	struct pqcp_fleet_artifact_entry staged;
	size_t extent_capacity;
	size_t extent_offset = 0U;
	uint32_t chunk_count;
	int existing_index;
	int current_index;
	int entry_index;
	int ret;

	if (!cache_ready(cache) || handle == NULL) {
		return -EINVAL;
	}
	ret = reserve_validate(
		request, cache->arena_alignment,
		cache->arena_capacity,
		&extent_capacity, &chunk_count);
	if (ret != 0) {
		return ret;
	}
	memset(&staged, 0, sizeof(staged));
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	existing_index = digest_entry_index_locked(
		cache, request->expected_digest);
	if (existing_index >= 0) {
		const struct pqcp_fleet_artifact_entry *existing =
			&cache->entries[existing_index];

		if ((request->reserve_flags &
		     PQCP_FLEET_ARTIFACT_RESERVE_IDEMPOTENT) != 0U &&
		    existing->object_id == request->object_id &&
		    existing->object_generation ==
			    request->object_generation &&
		    existing->kind == request->kind &&
		    (existing->state ==
			     PQCP_FLEET_ARTIFACT_STATE_VERIFIED ||
		     existing->state ==
			     PQCP_FLEET_ARTIFACT_STATE_RETIRED)) {
			*handle = entry_handle(cache, existing);
			(void)k_mutex_unlock(&cache->lock);
			return 0;
		}
		cache->rejected_count++;
		(void)k_mutex_unlock(&cache->lock);
		return -EEXIST;
	}
	current_index = current_entry_index_locked(
		cache, request->object_id, request->kind);
	if (current_index >= 0) {
		const struct pqcp_fleet_artifact_entry *current =
			&cache->entries[current_index];

		if (request->object_generation <=
		    current->object_generation) {
			cache->rejected_count++;
			(void)k_mutex_unlock(&cache->lock);
			return -EKEYREJECTED;
		}
		if (request->expected_current_digest != NULL &&
		    !digest_equal(
			    request->expected_current_digest,
			    current->verified_digest)) {
			cache->rejected_count++;
			(void)k_mutex_unlock(&cache->lock);
			return -ESTALE;
		}
	} else if (request->expected_current_digest != NULL) {
		cache->rejected_count++;
		(void)k_mutex_unlock(&cache->lock);
		return -ENOENT;
	}
	for (;;) {
		entry_index = free_entry_index_locked(cache);
		ret = find_extent_locked(
			cache, extent_capacity, &extent_offset);
		if (entry_index >= 0 && ret == 0) {
			break;
		}
		if ((request->reserve_flags &
		     PQCP_FLEET_ARTIFACT_RESERVE_ALLOW_EVICTION) == 0U) {
			cache->rejected_count++;
			(void)k_mutex_unlock(&cache->lock);
			return -ENOSPC;
		}
		enum pqcp_fleet_artifact_priority maximum_priority =
			request->priority ==
				PQCP_FLEET_ARTIFACT_PRIORITY_DISCARDABLE ?
			PQCP_FLEET_ARTIFACT_PRIORITY_DISCARDABLE :
			(enum pqcp_fleet_artifact_priority)
				(request->priority - 1);
		uint32_t eviction_flags =
			PQCP_FLEET_ARTIFACT_EVICT_EXPIRED |
			PQCP_FLEET_ARTIFACT_EVICT_RETIRED |
			PQCP_FLEET_ARTIFACT_EVICT_INCOMPLETE |
			PQCP_FLEET_ARTIFACT_EVICT_CORRUPT;

		if ((request->reserve_flags &
		     PQCP_FLEET_ARTIFACT_RESERVE_ALLOW_CURRENT_EVICTION) !=
		    0U) {
			eviction_flags |=
				PQCP_FLEET_ARTIFACT_EVICT_CURRENT;
		}
		int victim = eviction_candidate_locked(
			cache, maximum_priority, eviction_flags,
			request->created_at_ms);

		if (victim < 0 ||
		    victim == current_index) {
			cache->rejected_count++;
			(void)k_mutex_unlock(&cache->lock);
			return -ENOSPC;
		}
		erase_entry_locked(cache, (size_t)victim);
		cache->eviction_count++;
	}
	staged.schema_version =
		PQCP_FLEET_ARTIFACT_CACHE_SCHEMA_VERSION;
	staged.slot_generation =
		cache->entries[entry_index].slot_generation;
	if (staged.slot_generation == 0U) {
		staged.slot_generation = 1U;
	}
	staged.object_id = request->object_id;
	staged.object_generation = request->object_generation;
	staged.cache_generation = cache->generation;
	staged.kind = request->kind;
	staged.priority = request->priority;
	staged.state = PQCP_FLEET_ARTIFACT_STATE_WRITING;
	staged.flags = request->artifact_flags &
		~(PQCP_FLEET_ARTIFACT_FLAG_CURRENT |
		  PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED |
		  PQCP_FLEET_ARTIFACT_FLAG_REPLACEMENT);
	if (current_index >= 0) {
		staged.flags |=
			PQCP_FLEET_ARTIFACT_FLAG_REPLACEMENT;
		if ((request->reserve_flags &
		     PQCP_FLEET_ARTIFACT_RESERVE_KEEP_ROLLBACK) != 0U) {
			staged.flags |=
				PQCP_FLEET_ARTIFACT_FLAG_RETAIN_ROLLBACK;
		}
		staged.replacement_slot =
			(uint32_t)current_index;
		staged.replacement_generation =
			cache->entries[current_index].slot_generation;
		memcpy(
			staged.replaced_digest,
			cache->entries[current_index].verified_digest,
			sizeof(staged.replaced_digest));
	} else {
		staged.replacement_slot = ARTIFACT_INVALID_SLOT;
	}
	staged.extent_offset = extent_offset;
	staged.extent_capacity = extent_capacity;
	staged.content_length = request->content_length;
	staged.chunk_size = request->chunk_size;
	staged.chunk_count = chunk_count;
	staged.created_at_ms = request->created_at_ms;
	staged.expires_at_ms = request->expires_at_ms;
	staged.last_access_at_ms = request->created_at_ms;
	memcpy(staged.expected_digest, request->expected_digest,
	       sizeof(staged.expected_digest));
	memcpy(
		staged.label, request->label,
		strnlen(
			request->label,
			sizeof(staged.label) - 1U));
	staged.occupied = true;
	pqcp_runtime_secure_zero(
		cache->arena + extent_offset, extent_capacity);
	cache->entries[entry_index] = staged;
	cache->reserve_count++;
	cache_generation_advance_locked(cache);
	cache->entries[entry_index].cache_generation =
		cache->generation;
	*handle = entry_handle(
		cache, &cache->entries[entry_index]);
	(void)k_mutex_unlock(&cache->lock);
	pqcp_runtime_secure_zero(&staged, sizeof(staged));
	return 0;
}

int pqcp_fleet_artifact_cache_write_chunk(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	size_t offset,
	const uint8_t *data,
	size_t length,
	const uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES])
{
	struct pqcp_fleet_artifact_entry *entry;
	uint8_t computed[PQCP_FLEET_DIGEST_BYTES];
	size_t chunk_index_size;
	size_t expected_length;
	size_t arena_offset;
	uint32_t chunk_index;
	int ret;

	if (!cache_ready(cache) || data == NULL ||
	    length == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret != 0) {
		(void)k_mutex_unlock(&cache->lock);
		return ret;
	}
	if (entry->state !=
	    PQCP_FLEET_ARTIFACT_STATE_WRITING ||
	    entry->chunk_size == 0U ||
	    offset % entry->chunk_size != 0U) {
		(void)k_mutex_unlock(&cache->lock);
		return -EPERM;
	}
	chunk_index_size = offset / entry->chunk_size;
	if (chunk_index_size > UINT32_MAX ||
	    chunk_index_size >= entry->chunk_count) {
		(void)k_mutex_unlock(&cache->lock);
		return -ERANGE;
	}
	chunk_index = (uint32_t)chunk_index_size;
	expected_length =
		chunk_expected_length(entry, chunk_index);
	if (length != expected_length ||
	    offset > entry->content_length ||
	    length > entry->content_length - offset ||
	    size_add(entry->extent_offset, offset,
		     &arena_offset) != 0 ||
	    arena_offset > cache->arena_capacity ||
	    length > cache->arena_capacity - arena_offset) {
		(void)k_mutex_unlock(&cache->lock);
		return -EMSGSIZE;
	}
	if (chunk_digest != NULL) {
		ret = pqcp_runtime_internal_sha256(
			data, length, computed);
		if (ret != 0 ||
		    !digest_equal(computed, chunk_digest)) {
			cache->digest_failure_count++;
			cache->rejected_count++;
			pqcp_runtime_secure_zero(
				computed, sizeof(computed));
			(void)k_mutex_unlock(&cache->lock);
			return ret != 0 ? ret : -EBADMSG;
		}
		pqcp_runtime_secure_zero(
			computed, sizeof(computed));
	}
	if (bit_test(entry->chunk_bitmap, chunk_index)) {
		if (memcmp(
			    cache->arena + arena_offset,
			    data, length) != 0) {
			cache->digest_failure_count++;
			cache->rejected_count++;
			(void)k_mutex_unlock(&cache->lock);
			return -EBADMSG;
		}
		(void)k_mutex_unlock(&cache->lock);
		return 0;
	}
	memcpy(cache->arena + arena_offset, data, length);
	bit_set(entry->chunk_bitmap, chunk_index);
	entry->complete_chunks++;
	entry->stored_bytes += length;
	cache_generation_advance_locked(cache);
	entry->cache_generation = cache->generation;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

int pqcp_fleet_artifact_cache_chunk_status(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	struct pqcp_fleet_artifact_chunk_status *status)
{
	struct pqcp_fleet_artifact_entry *entry;
	int ret;

	if (!cache_ready(cache) || status == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret == 0) {
		memset(status, 0, sizeof(*status));
		status->chunk_count = entry->chunk_count;
		status->complete_chunks =
			entry->complete_chunks;
		status->stored_bytes = entry->stored_bytes;
		status->content_length = entry->content_length;
		status->first_missing_chunk =
			entry->chunk_count;
		for (uint32_t index = 0U;
		     index < entry->chunk_count; ++index) {
			if (!bit_test(
				    entry->chunk_bitmap, index)) {
				status->first_missing_chunk =
					index;
				break;
			}
		}
		status->complete =
			entry->complete_chunks ==
				entry->chunk_count &&
			entry->stored_bytes ==
				entry->content_length;
		status->digest_verified =
			(entry->flags &
			 PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED) !=
			0U;
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_fleet_artifact_cache_finalize(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle)
{
	struct pqcp_fleet_artifact_entry *entry;
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (!cache_ready(cache)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret != 0) {
		(void)k_mutex_unlock(&cache->lock);
		return ret;
	}
	if (entry->state ==
		    PQCP_FLEET_ARTIFACT_STATE_VERIFIED ||
	    entry->state ==
		    PQCP_FLEET_ARTIFACT_STATE_RETIRED) {
		(void)k_mutex_unlock(&cache->lock);
		return 0;
	}
	if (entry->state !=
		    PQCP_FLEET_ARTIFACT_STATE_WRITING ||
	    entry->complete_chunks != entry->chunk_count ||
	    entry->stored_bytes != entry->content_length ||
	    bitmap_count(
		    entry->chunk_bitmap,
		    entry->chunk_count) != entry->chunk_count) {
		(void)k_mutex_unlock(&cache->lock);
		return -EAGAIN;
	}
	ret = pqcp_runtime_internal_sha256(
		cache->arena + entry->extent_offset,
		entry->content_length, digest);
	if (ret == 0 &&
	    !digest_equal(digest, entry->expected_digest)) {
		ret = -EBADMSG;
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			cache->arena + entry->extent_offset,
			entry->extent_capacity);
		memset(entry->chunk_bitmap, 0,
		       sizeof(entry->chunk_bitmap));
		entry->complete_chunks = 0U;
		entry->stored_bytes = 0U;
		memset(entry->verified_digest, 0,
		       sizeof(entry->verified_digest));
		entry->flags &=
			~PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED;
		entry->state =
			PQCP_FLEET_ARTIFACT_STATE_WRITING;
		cache->digest_failure_count++;
		cache->rejected_count++;
		cache_generation_advance_locked(cache);
		entry->cache_generation = cache->generation;
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		(void)k_mutex_unlock(&cache->lock);
		return ret;
	}
	memcpy(entry->verified_digest, digest,
	       sizeof(entry->verified_digest));
	entry->flags |=
		PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED;
	entry->state =
		PQCP_FLEET_ARTIFACT_STATE_VERIFIED;
	cache_generation_advance_locked(cache);
	entry->cache_generation = cache->generation;
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

int pqcp_fleet_artifact_cache_commit(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	const uint8_t expected_current_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_fleet_artifact_entry *entry;
	struct pqcp_fleet_artifact_entry *current = NULL;
	int current_index;
	int ret;

	if (!cache_ready(cache) || now_ms == 0U ||
	    (expected_current_digest != NULL &&
	     digest_is_zero(expected_current_digest))) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret != 0) {
		(void)k_mutex_unlock(&cache->lock);
		return ret;
	}
	if (entry->state !=
		    PQCP_FLEET_ARTIFACT_STATE_VERIFIED ||
	    (entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED) == 0U ||
	    !digest_equal(
		    entry->expected_digest,
		    entry->verified_digest)) {
		cache->rejected_count++;
		(void)k_mutex_unlock(&cache->lock);
		return -EKEYREJECTED;
	}
	if (entry->expires_at_ms != 0U &&
	    now_ms >= entry->expires_at_ms) {
		entry->state =
			PQCP_FLEET_ARTIFACT_STATE_EXPIRED;
		cache->rejected_count++;
		(void)k_mutex_unlock(&cache->lock);
		return -EKEYEXPIRED;
	}
	current_index = current_entry_index_locked(
		cache, entry->object_id, entry->kind);
	if (current_index >= 0) {
		current = &cache->entries[current_index];
		if (current == entry) {
			(void)k_mutex_unlock(&cache->lock);
			return 0;
		}
		if (entry->object_generation <=
		    current->object_generation ||
		    (expected_current_digest != NULL &&
		     !digest_equal(
			     expected_current_digest,
			     current->verified_digest)) ||
		    ((entry->flags &
		      PQCP_FLEET_ARTIFACT_FLAG_REPLACEMENT) != 0U &&
		     (entry->replacement_slot !=
			      (uint32_t)current_index ||
		      entry->replacement_generation !=
			      current->slot_generation ||
		      !digest_equal(
			      entry->replaced_digest,
			      current->verified_digest)))) {
			cache->rejected_count++;
			(void)k_mutex_unlock(&cache->lock);
			return -ESTALE;
		}
	} else if (expected_current_digest != NULL ||
		   (entry->flags &
		    PQCP_FLEET_ARTIFACT_FLAG_REPLACEMENT) != 0U) {
		cache->rejected_count++;
		(void)k_mutex_unlock(&cache->lock);
		return -ESTALE;
	}
	if (current != NULL) {
		current->flags &=
			~PQCP_FLEET_ARTIFACT_FLAG_CURRENT;
		current->state =
			PQCP_FLEET_ARTIFACT_STATE_RETIRED;
		current->last_access_at_ms = now_ms;
	}
	entry->flags |=
		PQCP_FLEET_ARTIFACT_FLAG_CURRENT;
	entry->flags &=
		~PQCP_FLEET_ARTIFACT_FLAG_REPLACEMENT;
	entry->state =
		PQCP_FLEET_ARTIFACT_STATE_VERIFIED;
	entry->last_access_at_ms = now_ms;
	cache_generation_advance_locked(cache);
	entry->cache_generation = cache->generation;
	if (current != NULL) {
		current->cache_generation = cache->generation;
	}
	cache->commit_count++;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

int pqcp_fleet_artifact_cache_abort(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle)
{
	struct pqcp_fleet_artifact_entry *entry;
	size_t index;
	int ret;

	if (!cache_ready(cache)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret != 0) {
		(void)k_mutex_unlock(&cache->lock);
		return ret;
	}
	if ((entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U ||
	    entry->reference_count != 0U ||
	    entry->pin_count != 0U ||
	    entry_has_active_lease_locked(cache, entry)) {
		cache->rejected_count++;
		(void)k_mutex_unlock(&cache->lock);
		return -EBUSY;
	}
	index = (size_t)(entry - cache->entries);
	erase_entry_locked(cache, index);
	cache->abort_count++;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

int pqcp_fleet_artifact_cache_find_digest(
	struct pqcp_fleet_artifact_cache *cache,
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES],
	struct pqcp_fleet_artifact_handle *handle)
{
	int index;
	int ret;

	if (!cache_ready(cache) || digest_is_zero(digest) ||
	    handle == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = digest_entry_index_locked(cache, digest);
	if (index >= 0) {
		*handle = entry_handle(
			cache, &cache->entries[index]);
		ret = 0;
	} else {
		ret = -ENOENT;
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_fleet_artifact_cache_find_current(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t object_id,
	enum pqcp_fleet_artifact_kind kind,
	struct pqcp_fleet_artifact_handle *handle)
{
	int index;
	int ret;

	if (!cache_ready(cache) || object_id == 0U ||
	    !artifact_kind_valid(kind) || handle == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = current_entry_index_locked(
		cache, object_id, kind);
	if (index >= 0) {
		*handle = entry_handle(
			cache, &cache->entries[index]);
		ret = 0;
	} else {
		ret = -ENOENT;
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_fleet_artifact_cache_get(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	struct pqcp_fleet_artifact_entry *entry)
{
	struct pqcp_fleet_artifact_entry *found;
	int ret;

	if (!cache_ready(cache) || entry == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &found);
	if (ret == 0) {
		*entry = *found;
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

static bool owner_flags_valid(uint32_t flags)
{
	const uint32_t valid =
		PQCP_FLEET_ARTIFACT_OWNER_REFERENCE |
		PQCP_FLEET_ARTIFACT_OWNER_PIN |
		PQCP_FLEET_ARTIFACT_OWNER_INSTALL |
		PQCP_FLEET_ARTIFACT_OWNER_TRANSFER |
		PQCP_FLEET_ARTIFACT_OWNER_RECOVERY;

	return flags != 0U && (flags & ~valid) == 0U &&
	       (flags &
		(PQCP_FLEET_ARTIFACT_OWNER_REFERENCE |
		 PQCP_FLEET_ARTIFACT_OWNER_PIN)) != 0U;
}

int pqcp_fleet_artifact_cache_retain(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint64_t owner_id,
	uint32_t owner_flags,
	uint64_t now_ms,
	uint64_t expires_at_ms)
{
	struct pqcp_fleet_artifact_entry *entry;
	struct pqcp_fleet_artifact_owner *owner;
	int index;
	int ret;

	if (!cache_ready(cache) || owner_id == 0U ||
	    !owner_flags_valid(owner_flags) ||
	    now_ms == 0U ||
	    (expires_at_ms != 0U &&
	     expires_at_ms <= now_ms)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret != 0) {
		(void)k_mutex_unlock(&cache->lock);
		return ret;
	}
	if (entry->state == PQCP_FLEET_ARTIFACT_STATE_EXPIRED ||
	    entry->state == PQCP_FLEET_ARTIFACT_STATE_CORRUPT ||
	    (entry->expires_at_ms != 0U &&
	     now_ms >= entry->expires_at_ms)) {
		(void)k_mutex_unlock(&cache->lock);
		return -ESTALE;
	}
	index = owner_index(entry, owner_id);
	if (index < 0) {
		index = free_owner_index(entry);
		if (index < 0) {
			cache->rejected_count++;
			(void)k_mutex_unlock(&cache->lock);
			return -ENOSPC;
		}
		owner = &entry->owners[index];
		memset(owner, 0, sizeof(*owner));
		owner->owner_id = owner_id;
		owner->acquired_at_ms = now_ms;
		owner->expires_at_ms = expires_at_ms;
		owner->occupied = true;
		entry->owner_count++;
	} else {
		owner = &entry->owners[index];
		if (expires_at_ms != 0U &&
		    (owner->expires_at_ms == 0U ||
		     expires_at_ms > owner->expires_at_ms)) {
			owner->expires_at_ms = expires_at_ms;
		}
	}
	if ((owner_flags &
	     PQCP_FLEET_ARTIFACT_OWNER_REFERENCE) != 0U) {
		if (owner->references == UINT32_MAX ||
		    entry->reference_count == UINT32_MAX) {
			cache->rejected_count++;
			(void)k_mutex_unlock(&cache->lock);
			return -EOVERFLOW;
		}
		owner->references++;
		entry->reference_count++;
	}
	if ((owner_flags &
	     PQCP_FLEET_ARTIFACT_OWNER_PIN) != 0U &&
	    (owner->flags &
	     PQCP_FLEET_ARTIFACT_OWNER_PIN) == 0U) {
		if (entry->pin_count == UINT32_MAX) {
			if ((owner_flags &
			     PQCP_FLEET_ARTIFACT_OWNER_REFERENCE) != 0U) {
				owner->references--;
				entry->reference_count--;
			}
			cache->rejected_count++;
			(void)k_mutex_unlock(&cache->lock);
			return -EOVERFLOW;
		}
		entry->pin_count++;
	}
	owner->flags |= owner_flags;
	entry->last_access_at_ms = now_ms;
	cache_generation_advance_locked(cache);
	entry->cache_generation = cache->generation;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

static void owner_maybe_clear(
	struct pqcp_fleet_artifact_entry *entry,
	struct pqcp_fleet_artifact_owner *owner)
{
	if (owner->references == 0U &&
	    (owner->flags &
	     PQCP_FLEET_ARTIFACT_OWNER_PIN) == 0U) {
		pqcp_runtime_secure_zero(owner, sizeof(*owner));
		if (entry->owner_count != 0U) {
			entry->owner_count--;
		}
	}
}

int pqcp_fleet_artifact_cache_release(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint64_t owner_id,
	uint32_t owner_flags)
{
	struct pqcp_fleet_artifact_entry *entry;
	struct pqcp_fleet_artifact_owner *owner;
	int index;
	int ret;

	if (!cache_ready(cache) || owner_id == 0U ||
	    !owner_flags_valid(owner_flags)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret != 0) {
		(void)k_mutex_unlock(&cache->lock);
		return ret;
	}
	index = owner_index(entry, owner_id);
	if (index < 0) {
		(void)k_mutex_unlock(&cache->lock);
		return -ENOENT;
	}
	owner = &entry->owners[index];
	if ((owner_flags &
	     PQCP_FLEET_ARTIFACT_OWNER_REFERENCE) != 0U) {
		if (owner->references == 0U ||
		    entry->reference_count == 0U) {
			(void)k_mutex_unlock(&cache->lock);
			return -EALREADY;
		}
		owner->references--;
		entry->reference_count--;
		if (owner->references == 0U) {
			owner->flags &=
				~PQCP_FLEET_ARTIFACT_OWNER_REFERENCE;
		}
	}
	if ((owner_flags &
	     PQCP_FLEET_ARTIFACT_OWNER_PIN) != 0U) {
		if ((owner->flags &
		     PQCP_FLEET_ARTIFACT_OWNER_PIN) == 0U ||
		    entry->pin_count == 0U) {
			(void)k_mutex_unlock(&cache->lock);
			return -EALREADY;
		}
		owner->flags &=
			~PQCP_FLEET_ARTIFACT_OWNER_PIN;
		entry->pin_count--;
	}
	owner_maybe_clear(entry, owner);
	cache_generation_advance_locked(cache);
	entry->cache_generation = cache->generation;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

int pqcp_fleet_artifact_cache_release_owner(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t owner_id,
	uint32_t owner_flags,
	size_t *released_references)
{
	size_t released = 0U;
	int ret;

	if (!cache_ready(cache) || owner_id == 0U ||
	    !owner_flags_valid(owner_flags) ||
	    released_references == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t entry_index = 0U;
	     entry_index < cache->entry_capacity;
	     ++entry_index) {
		struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[entry_index];
		int index;

		if (!entry->occupied) {
			continue;
		}
		index = owner_index(entry, owner_id);
		if (index < 0) {
			continue;
		}
		struct pqcp_fleet_artifact_owner *owner =
			&entry->owners[index];

		if ((owner_flags &
		     PQCP_FLEET_ARTIFACT_OWNER_REFERENCE) != 0U) {
			if (owner->references >
			    entry->reference_count) {
				(void)k_mutex_unlock(&cache->lock);
				return -EBADMSG;
			}
			released += owner->references;
			entry->reference_count -=
				owner->references;
			owner->references = 0U;
			owner->flags &=
				~PQCP_FLEET_ARTIFACT_OWNER_REFERENCE;
		}
		if ((owner_flags &
		     PQCP_FLEET_ARTIFACT_OWNER_PIN) != 0U &&
		    (owner->flags &
		     PQCP_FLEET_ARTIFACT_OWNER_PIN) != 0U) {
			if (entry->pin_count == 0U) {
				(void)k_mutex_unlock(&cache->lock);
				return -EBADMSG;
			}
			entry->pin_count--;
			owner->flags &=
				~PQCP_FLEET_ARTIFACT_OWNER_PIN;
		}
		owner_maybe_clear(entry, owner);
		cache_generation_advance_locked(cache);
		entry->cache_generation = cache->generation;
	}
	*released_references = released;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

int pqcp_fleet_artifact_cache_touch(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint64_t now_ms)
{
	struct pqcp_fleet_artifact_entry *entry;
	int ret;

	if (!cache_ready(cache) || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret == 0) {
		if (entry->expires_at_ms != 0U &&
		    now_ms >= entry->expires_at_ms) {
			ret = -ESTALE;
		} else if (entry->access_count == UINT64_MAX) {
			ret = -EOVERFLOW;
		} else {
			entry->last_access_at_ms = now_ms;
			entry->access_count++;
		}
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

static int entry_read_locked(
	struct pqcp_fleet_artifact_cache *cache,
	struct pqcp_fleet_artifact_entry *entry,
	size_t offset,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	uint64_t now_ms)
{
	size_t available;
	size_t copied;

	if (output == NULL || output_capacity == 0U ||
	    output_length == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	if (entry->state !=
		    PQCP_FLEET_ARTIFACT_STATE_VERIFIED &&
	    entry->state !=
		    PQCP_FLEET_ARTIFACT_STATE_RETIRED) {
		return -EAGAIN;
	}
	if ((entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED) == 0U) {
		return -EKEYREJECTED;
	}
	if (entry->expires_at_ms != 0U &&
	    now_ms >= entry->expires_at_ms) {
		return -ESTALE;
	}
	if (offset > entry->content_length) {
		return -ERANGE;
	}
	available = entry->content_length - offset;
	copied = available < output_capacity ?
		available : output_capacity;
	if (copied != 0U) {
		memcpy(
			output,
			cache->arena + entry->extent_offset + offset,
			copied);
	}
	*output_length = copied;
	entry->last_access_at_ms = now_ms;
	if (entry->access_count != UINT64_MAX) {
		entry->access_count++;
	}
	return copied == 0U && available != 0U ?
		-ENOSPC : 0;
}

int pqcp_fleet_artifact_cache_read(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	size_t offset,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	uint64_t now_ms)
{
	struct pqcp_fleet_artifact_entry *entry;
	int ret;

	if (!cache_ready(cache)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret == 0) {
		ret = entry_read_locked(
			cache, entry, offset, output,
			output_capacity, output_length, now_ms);
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_fleet_artifact_cache_lease_open(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint64_t owner_id,
	uint64_t now_ms,
	uint64_t duration_ms,
	uint64_t *lease_id)
{
	struct pqcp_fleet_artifact_entry *entry;
	struct pqcp_fleet_artifact_reader_lease *lease;
	uint64_t expires_at_ms;
	uint64_t identifier;
	int index;
	int ret;

	if (!cache_ready(cache) || owner_id == 0U ||
	    now_ms == 0U || duration_ms == 0U ||
	    duration_ms > UINT64_MAX - now_ms ||
	    lease_id == NULL) {
		return -EINVAL;
	}
	expires_at_ms = now_ms + duration_ms;
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret != 0) {
		(void)k_mutex_unlock(&cache->lock);
		return ret;
	}
	if ((entry->state !=
		     PQCP_FLEET_ARTIFACT_STATE_VERIFIED &&
	     entry->state !=
		     PQCP_FLEET_ARTIFACT_STATE_RETIRED) ||
	    (entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED) == 0U ||
	    (entry->expires_at_ms != 0U &&
	     now_ms >= entry->expires_at_ms)) {
		(void)k_mutex_unlock(&cache->lock);
		return -ESTALE;
	}
	index = free_lease_index_locked(cache);
	identifier = next_lease_id_locked(cache);
	if (index < 0 || identifier == 0U ||
	    entry->reference_count == UINT32_MAX) {
		cache->rejected_count++;
		(void)k_mutex_unlock(&cache->lock);
		return index < 0 ? -ENOSPC : -EOVERFLOW;
	}
	lease = &cache->leases[index];
	memset(lease, 0, sizeof(*lease));
	lease->lease_id = identifier;
	lease->owner_id = owner_id;
	lease->artifact = *handle;
	lease->opened_at_ms = now_ms;
	lease->expires_at_ms = expires_at_ms;
	lease->active = true;
	entry->reference_count++;
	entry->last_access_at_ms = now_ms;
	cache_generation_advance_locked(cache);
	entry->cache_generation = cache->generation;
	*lease_id = identifier;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

int pqcp_fleet_artifact_cache_lease_read(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t lease_id,
	size_t offset,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	uint64_t now_ms)
{
	struct pqcp_fleet_artifact_reader_lease *lease;
	struct pqcp_fleet_artifact_entry *entry;
	int index;
	int ret;

	if (!cache_ready(cache) || lease_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = lease_index_locked(cache, lease_id);
	if (index < 0) {
		(void)k_mutex_unlock(&cache->lock);
		return -ENOENT;
	}
	lease = &cache->leases[index];
	if (now_ms == 0U || now_ms >= lease->expires_at_ms) {
		(void)k_mutex_unlock(&cache->lock);
		return -EKEYEXPIRED;
	}
	ret = handle_entry_locked(
		cache, &lease->artifact, &entry);
	if (ret == 0) {
		ret = entry_read_locked(
			cache, entry, offset, output,
			output_capacity, output_length, now_ms);
	}
	if (ret == 0) {
		if (*output_length >
		    UINT64_MAX - lease->bytes_read) {
			ret = -EOVERFLOW;
		} else if (lease->read_count == UINT32_MAX) {
			ret = -EOVERFLOW;
		} else {
			lease->bytes_read += *output_length;
			lease->read_count++;
		}
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_fleet_artifact_cache_lease_renew(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t lease_id,
	uint64_t now_ms,
	uint64_t duration_ms)
{
	struct pqcp_fleet_artifact_reader_lease *lease;
	struct pqcp_fleet_artifact_entry *entry;
	uint64_t expires_at_ms;
	int index;
	int ret;

	if (!cache_ready(cache) || lease_id == 0U ||
	    now_ms == 0U || duration_ms == 0U ||
	    duration_ms > UINT64_MAX - now_ms) {
		return -EINVAL;
	}
	expires_at_ms = now_ms + duration_ms;
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = lease_index_locked(cache, lease_id);
	if (index < 0) {
		(void)k_mutex_unlock(&cache->lock);
		return -ENOENT;
	}
	lease = &cache->leases[index];
	if (now_ms >= lease->expires_at_ms) {
		(void)k_mutex_unlock(&cache->lock);
		return -EKEYEXPIRED;
	}
	ret = handle_entry_locked(
		cache, &lease->artifact, &entry);
	if (ret == 0 &&
	    entry->expires_at_ms != 0U &&
	    expires_at_ms > entry->expires_at_ms) {
		ret = -ERANGE;
	}
	if (ret == 0) {
		lease->expires_at_ms = expires_at_ms;
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

static int lease_close_locked(
	struct pqcp_fleet_artifact_cache *cache,
	size_t lease_index)
{
	struct pqcp_fleet_artifact_reader_lease *lease =
		&cache->leases[lease_index];
	struct pqcp_fleet_artifact_entry *entry;
	int ret;

	ret = handle_entry_locked(
		cache, &lease->artifact, &entry);
	if (ret == 0) {
		if (entry->reference_count == 0U) {
			return -EBADMSG;
		}
		entry->reference_count--;
		cache_generation_advance_locked(cache);
		entry->cache_generation = cache->generation;
	} else if (ret != -ESTALE) {
		return ret;
	}
	pqcp_runtime_secure_zero(lease, sizeof(*lease));
	return 0;
}

int pqcp_fleet_artifact_cache_lease_close(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t lease_id)
{
	int index;
	int ret;

	if (!cache_ready(cache) || lease_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = lease_index_locked(cache, lease_id);
	if (index < 0) {
		(void)k_mutex_unlock(&cache->lock);
		return -ENOENT;
	}
	ret = lease_close_locked(cache, (size_t)index);
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_fleet_artifact_cache_lease_reap(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t now_ms,
	size_t *reaped_count)
{
	size_t reaped = 0U;
	int ret;

	if (!cache_ready(cache) || now_ms == 0U ||
	    reaped_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < cache->lease_capacity; ++index) {
		if (!cache->leases[index].active ||
		    now_ms < cache->leases[index].expires_at_ms) {
			continue;
		}
		ret = lease_close_locked(cache, index);
		if (ret != 0) {
			(void)k_mutex_unlock(&cache->lock);
			return ret;
		}
		reaped++;
	}
	*reaped_count = reaped;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

static void expire_owner_references_locked(
	struct pqcp_fleet_artifact_entry *entry,
	uint64_t now_ms)
{
	for (size_t index = 0U;
	     index < PQCP_FLEET_ARTIFACT_MAX_OWNERS; ++index) {
		struct pqcp_fleet_artifact_owner *owner =
			&entry->owners[index];

		if (!owner->occupied ||
		    owner->expires_at_ms == 0U ||
		    now_ms < owner->expires_at_ms) {
			continue;
		}
		if (owner->references <=
		    entry->reference_count) {
			entry->reference_count -=
				owner->references;
		} else {
			entry->reference_count = 0U;
		}
		if ((owner->flags &
		     PQCP_FLEET_ARTIFACT_OWNER_PIN) != 0U &&
		    entry->pin_count != 0U) {
			entry->pin_count--;
		}
		pqcp_runtime_secure_zero(owner, sizeof(*owner));
		if (entry->owner_count != 0U) {
			entry->owner_count--;
		}
	}
}

int pqcp_fleet_artifact_cache_expire(
	struct pqcp_fleet_artifact_cache *cache,
	uint64_t now_ms,
	bool erase_unowned,
	size_t *expired_count)
{
	size_t expired = 0U;
	int ret;

	if (!cache_ready(cache) || now_ms == 0U ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[index];

		if (!entry->occupied) {
			continue;
		}
		expire_owner_references_locked(entry, now_ms);
		if (entry->expires_at_ms == 0U ||
		    now_ms < entry->expires_at_ms ||
		    entry->state ==
			    PQCP_FLEET_ARTIFACT_STATE_EXPIRED) {
			continue;
		}
		entry->state =
			PQCP_FLEET_ARTIFACT_STATE_EXPIRED;
		entry->flags &=
			~PQCP_FLEET_ARTIFACT_FLAG_CURRENT;
		expired++;
		cache->expiry_count++;
		cache_generation_advance_locked(cache);
		entry->cache_generation = cache->generation;
		if (erase_unowned &&
		    entry->owner_count == 0U &&
		    entry->reference_count == 0U &&
		    entry->pin_count == 0U &&
		    !entry_has_active_lease_locked(
			    cache, entry) &&
		    (entry->flags &
		     PQCP_FLEET_ARTIFACT_FLAG_NO_EVICT) == 0U) {
			erase_entry_locked(cache, index);
			cache->eviction_count++;
		}
	}
	*expired_count = expired;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

int pqcp_fleet_artifact_cache_evict(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_evict_request *request,
	struct pqcp_fleet_artifact_evict_result *result)
{
	size_t limit;
	int ret;

	if (!cache_ready(cache) || request == NULL ||
	    result == NULL ||
	    request->bytes_required == 0U ||
	    !artifact_priority_valid(
		    request->maximum_priority) ||
	    request->now_ms == 0U ||
	    request->flags == 0U) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	limit = request->maximum_entries == 0U ?
		cache->entry_capacity :
		request->maximum_entries;
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	while (result->bytes_released <
		       request->bytes_required &&
	       result->entries_evicted < limit) {
		int victim = eviction_candidate_locked(
			cache, request->maximum_priority,
			request->flags, request->now_ms);

		if (victim < 0) {
			break;
		}
		eviction_result_add(
			result, &cache->entries[victim],
			request->now_ms);
		erase_entry_locked(cache, (size_t)victim);
		cache->eviction_count++;
	}
	ret = result->bytes_released >=
		      request->bytes_required ?
		0 : -ENOSPC;
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_fleet_artifact_cache_remove(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	uint32_t flags)
{
	struct pqcp_fleet_artifact_entry *entry;
	size_t index;
	int ret;

	if (!cache_ready(cache)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret != 0) {
		(void)k_mutex_unlock(&cache->lock);
		return ret;
	}
	if (entry->owner_count != 0U ||
	    entry->reference_count != 0U ||
	    entry->pin_count != 0U ||
	    entry_has_active_lease_locked(cache, entry) ||
	    (entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_NO_EVICT) != 0U ||
	    ((entry->flags &
	      PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U &&
	     (flags &
	      PQCP_FLEET_ARTIFACT_REMOVE_ALLOW_CURRENT) == 0U) ||
	    (entry->state ==
		     PQCP_FLEET_ARTIFACT_STATE_WRITING &&
	     (flags &
	      PQCP_FLEET_ARTIFACT_REMOVE_ALLOW_INCOMPLETE) == 0U)) {
		cache->rejected_count++;
		(void)k_mutex_unlock(&cache->lock);
		return -EBUSY;
	}
	index = (size_t)(entry - cache->entries);
	erase_entry_locked(cache, index);
	cache->eviction_count++;
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

static int next_extent_index_locked(
	const struct pqcp_fleet_artifact_cache *cache,
	size_t after_offset,
	bool inclusive,
	const bool *selected)
{
	size_t best_offset = SIZE_MAX;
	int best = -1;

	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		const struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[index];

		if (!entry->occupied ||
		    (selected != NULL && selected[index]) ||
		    (!inclusive &&
		     entry->extent_offset <= after_offset) ||
		    (inclusive &&
		     entry->extent_offset < after_offset)) {
			continue;
		}
		if (entry->extent_offset < best_offset ||
		    (entry->extent_offset == best_offset &&
		     (best < 0 || index < (size_t)best))) {
			best_offset = entry->extent_offset;
			best = (int)index;
		}
	}
	return best;
}

static int compaction_plan_digest(
	const struct pqcp_fleet_artifact_compaction_plan *plan,
	const struct pqcp_fleet_artifact_compaction_move *moves,
	size_t move_count,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t chain[PQCP_FLEET_DIGEST_BYTES];
	uint8_t body[ARTIFACT_PLAN_DIGEST_BODY_BYTES];
	uint8_t next[PQCP_FLEET_DIGEST_BYTES];
	size_t offset = 0U;
	int ret;

	if (plan == NULL || digest == NULL ||
	    (move_count != 0U && moves == NULL) ||
	    move_count != plan->move_count) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-ARTIFACT-COMPACTION-V1", 27U);
	offset += 27U;
	write_u32(body, &offset, plan->schema_version);
	write_u64(body, &offset, plan->cache_generation);
	write_size(body, &offset, plan->move_count);
	write_size(body, &offset, plan->bytes_moved);
	write_size(body, &offset, plan->packed_bytes);
	write_size(body, &offset, plan->free_tail_bytes);
	ret = pqcp_runtime_internal_sha256(
		body, offset, chain);
	for (size_t index = 0U;
	     ret == 0 && index < move_count; ++index) {
		offset = 0U;
		memset(body, 0, sizeof(body));
		memcpy(body + offset, "PQCP-ARTIFACT-MOVE-V1", 21U);
		offset += 21U;
		write_u32(
			body, &offset,
			moves[index].artifact.slot);
		write_u32(
			body, &offset,
			moves[index].artifact.slot_generation);
		write_size(
			body, &offset,
			moves[index].source_offset);
		write_size(
			body, &offset,
			moves[index].destination_offset);
		write_size(
			body, &offset,
			moves[index].length);
		memcpy(body + offset, chain, sizeof(chain));
		offset += sizeof(chain);
		ret = pqcp_runtime_internal_sha256(
			body, offset, next);
		if (ret == 0) {
			memcpy(chain, next, sizeof(chain));
		}
	}
	if (ret == 0) {
		memcpy(digest, chain, sizeof(chain));
	}
	pqcp_runtime_secure_zero(chain, sizeof(chain));
	pqcp_runtime_secure_zero(next, sizeof(next));
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_fleet_artifact_cache_compaction_plan(
	struct pqcp_fleet_artifact_cache *cache,
	struct pqcp_fleet_artifact_compaction_move *moves,
	size_t move_capacity,
	struct pqcp_fleet_artifact_compaction_plan *plan)
{
	bool selected_stack[64];
	bool *selected = selected_stack;
	size_t cursor = 0U;
	size_t occupied = 0U;
	size_t move_count = 0U;
	size_t bytes_moved = 0U;
	int ret;

	if (!cache_ready(cache) || plan == NULL ||
	    (move_capacity != 0U && moves == NULL) ||
	    cache->entry_capacity >
		    sizeof(selected_stack) / sizeof(selected_stack[0])) {
		/*
		 * Planning is deliberately bounded without heap allocation.
		 * Larger caches may compact in windows by provisioning no
		 * more than 64 metadata entries per cache instance.
		 */
		return -E2BIG;
	}
	memset(selected, 0, sizeof(selected_stack));
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		if (cache->entries[index].occupied) {
			occupied++;
		}
	}
	for (size_t processed = 0U;
	     processed < occupied; ++processed) {
		int index = next_extent_index_locked(
			cache, 0U, true, selected);
		struct pqcp_fleet_artifact_entry *entry;
		size_t destination;

		if (index < 0) {
			(void)k_mutex_unlock(&cache->lock);
			return -EBADMSG;
		}
		selected[index] = true;
		entry = &cache->entries[index];
		ret = align_up(
			cursor, cache->arena_alignment,
			&destination);
		if (ret != 0 ||
		    destination > cache->arena_capacity ||
		    entry->extent_capacity >
			    cache->arena_capacity - destination) {
			(void)k_mutex_unlock(&cache->lock);
			return ret != 0 ? ret : -EOVERFLOW;
		}
		if (entry->extent_offset != destination) {
			if (move_count >= move_capacity) {
				(void)k_mutex_unlock(&cache->lock);
				return -ENOSPC;
			}
			moves[move_count].artifact =
				entry_handle(cache, entry);
			moves[move_count].source_offset =
				entry->extent_offset;
			moves[move_count].destination_offset =
				destination;
			moves[move_count].length =
				entry->extent_capacity;
			if (entry->extent_capacity >
			    SIZE_MAX - bytes_moved) {
				(void)k_mutex_unlock(&cache->lock);
				return -EOVERFLOW;
			}
			bytes_moved += entry->extent_capacity;
			move_count++;
		}
		cursor = destination + entry->extent_capacity;
	}
	memset(plan, 0, sizeof(*plan));
	plan->schema_version =
		PQCP_FLEET_ARTIFACT_COMPACTION_SCHEMA_VERSION;
	plan->cache_generation = cache->generation;
	plan->move_count = move_count;
	plan->bytes_moved = bytes_moved;
	plan->packed_bytes = cursor;
	plan->free_tail_bytes =
		cache->arena_capacity - cursor;
	ret = compaction_plan_digest(
		plan, moves, move_count, plan->digest);
	(void)k_mutex_unlock(&cache->lock);
	pqcp_runtime_secure_zero(
		selected_stack, sizeof(selected_stack));
	return ret;
}

int pqcp_fleet_artifact_cache_compact(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_compaction_move *moves,
	size_t move_count,
	const struct pqcp_fleet_artifact_compaction_plan *plan)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	size_t previous_destination = 0U;
	int ret;

	if (!cache_ready(cache) || plan == NULL ||
	    plan->schema_version !=
		    PQCP_FLEET_ARTIFACT_COMPACTION_SCHEMA_VERSION ||
	    plan->move_count != move_count ||
	    (move_count != 0U && moves == NULL) ||
	    plan->packed_bytes > cache->arena_capacity ||
	    plan->free_tail_bytes !=
		    cache->arena_capacity - plan->packed_bytes) {
		return -EINVAL;
	}
	ret = compaction_plan_digest(
		plan, moves, move_count, digest);
	if (ret != 0 ||
	    !digest_equal(digest, plan->digest)) {
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return ret != 0 ? ret : -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (plan->cache_generation != cache->generation) {
		(void)k_mutex_unlock(&cache->lock);
		return -ESTALE;
	}
	for (size_t index = 0U;
	     index < move_count; ++index) {
		struct pqcp_fleet_artifact_entry *entry;

		ret = handle_entry_locked(
			cache, &moves[index].artifact, &entry);
		if (ret != 0 ||
		    entry->extent_offset !=
			    moves[index].source_offset ||
		    entry->extent_capacity !=
			    moves[index].length ||
		    moves[index].destination_offset >
			    moves[index].source_offset ||
		    moves[index].destination_offset <
			    previous_destination ||
		    moves[index].destination_offset >
			    cache->arena_capacity ||
		    moves[index].length >
			    cache->arena_capacity -
				    moves[index].destination_offset) {
			(void)k_mutex_unlock(&cache->lock);
			return ret != 0 ? ret : -EBADMSG;
		}
		previous_destination =
			moves[index].destination_offset;
	}
	for (size_t index = 0U;
	     index < move_count; ++index) {
		struct pqcp_fleet_artifact_entry *entry;

		ret = handle_entry_locked(
			cache, &moves[index].artifact, &entry);
		if (ret != 0) {
			(void)k_mutex_unlock(&cache->lock);
			return ret;
		}
		memmove(
			cache->arena +
				moves[index].destination_offset,
			cache->arena + moves[index].source_offset,
			moves[index].length);
		entry->extent_offset =
			moves[index].destination_offset;
	}
	if (plan->free_tail_bytes != 0U) {
		pqcp_runtime_secure_zero(
			cache->arena + plan->packed_bytes,
			plan->free_tail_bytes);
	}
	if (move_count != 0U) {
		cache_generation_advance_locked(cache);
		for (size_t index = 0U;
		     index < cache->entry_capacity; ++index) {
			if (cache->entries[index].occupied) {
				cache->entries[index].cache_generation =
					cache->generation;
			}
		}
		cache->compaction_count++;
	}
	(void)k_mutex_unlock(&cache->lock);
	return 0;
}

static int snapshot_digest_compute(
	const struct pqcp_fleet_artifact_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[ARTIFACT_SNAPSHOT_DIGEST_BODY_BYTES];
	size_t offset = 0U;
	int ret;

	if (snapshot == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-ARTIFACT-SNAPSHOT-V1", 25U);
	offset += 25U;
	write_u32(body, &offset, snapshot->schema_version);
	write_u64(body, &offset, snapshot->generation);
	write_size(body, &offset, snapshot->entry_capacity);
	write_size(body, &offset, snapshot->occupied_entries);
	write_size(body, &offset, snapshot->writing_entries);
	write_size(body, &offset, snapshot->verified_entries);
	write_size(body, &offset, snapshot->retired_entries);
	write_size(body, &offset, snapshot->expired_entries);
	write_size(body, &offset, snapshot->corrupt_entries);
	write_size(body, &offset, snapshot->current_entries);
	write_size(body, &offset, snapshot->pinned_entries);
	write_size(body, &offset, snapshot->referenced_entries);
	write_size(body, &offset, snapshot->arena_capacity);
	write_size(body, &offset, snapshot->arena_allocated);
	write_size(body, &offset, snapshot->arena_payload_bytes);
	write_size(body, &offset, snapshot->arena_free_bytes);
	write_size(body, &offset, snapshot->largest_free_extent);
	write_size(body, &offset, snapshot->lease_capacity);
	write_size(body, &offset, snapshot->active_leases);
	write_u64(body, &offset, snapshot->reserve_count);
	write_u64(body, &offset, snapshot->commit_count);
	write_u64(body, &offset, snapshot->abort_count);
	write_u64(body, &offset, snapshot->eviction_count);
	write_u64(body, &offset, snapshot->expiry_count);
	write_u64(body, &offset, snapshot->digest_failure_count);
	write_u64(body, &offset, snapshot->rejected_count);
	write_u64(body, &offset, snapshot->compaction_count);
	memcpy(body + offset, snapshot->metadata_digest,
	       sizeof(snapshot->metadata_digest));
	offset += sizeof(snapshot->metadata_digest);
	if (offset > sizeof(body)) {
		return -EOVERFLOW;
	}
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_fleet_artifact_cache_snapshot(
	struct pqcp_fleet_artifact_cache *cache,
	struct pqcp_fleet_artifact_snapshot *snapshot)
{
	int ret;

	if (!cache_ready(cache) || snapshot == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->schema_version =
		PQCP_FLEET_ARTIFACT_CACHE_SCHEMA_VERSION;
	snapshot->generation = cache->generation;
	snapshot->entry_capacity = cache->entry_capacity;
	snapshot->arena_capacity = cache->arena_capacity;
	snapshot->lease_capacity = cache->lease_capacity;
	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		const struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[index];

		if (!entry->occupied) {
			continue;
		}
		snapshot->occupied_entries++;
		switch (entry->state) {
		case PQCP_FLEET_ARTIFACT_STATE_WRITING:
			snapshot->writing_entries++;
			break;
		case PQCP_FLEET_ARTIFACT_STATE_VERIFIED:
			snapshot->verified_entries++;
			break;
		case PQCP_FLEET_ARTIFACT_STATE_RETIRED:
			snapshot->retired_entries++;
			break;
		case PQCP_FLEET_ARTIFACT_STATE_EXPIRED:
			snapshot->expired_entries++;
			break;
		case PQCP_FLEET_ARTIFACT_STATE_CORRUPT:
			snapshot->corrupt_entries++;
			break;
		default:
			break;
		}
		if ((entry->flags &
		     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U) {
			snapshot->current_entries++;
		}
		if (entry->pin_count != 0U) {
			snapshot->pinned_entries++;
		}
		if (entry->reference_count != 0U) {
			snapshot->referenced_entries++;
		}
	}
	for (size_t index = 0U;
	     index < cache->lease_capacity; ++index) {
		if (cache->leases[index].active) {
			snapshot->active_leases++;
		}
	}
	snapshot->arena_allocated =
		allocated_bytes_locked(cache);
	snapshot->arena_payload_bytes =
		payload_bytes_locked(cache);
	if (snapshot->arena_allocated == SIZE_MAX ||
	    snapshot->arena_payload_bytes == SIZE_MAX ||
	    snapshot->arena_allocated >
		    cache->arena_capacity) {
		(void)k_mutex_unlock(&cache->lock);
		return -EOVERFLOW;
	}
	snapshot->arena_free_bytes =
		cache->arena_capacity -
		snapshot->arena_allocated;
	snapshot->largest_free_extent =
		largest_free_extent_locked(cache);
	snapshot->reserve_count = cache->reserve_count;
	snapshot->commit_count = cache->commit_count;
	snapshot->abort_count = cache->abort_count;
	snapshot->eviction_count = cache->eviction_count;
	snapshot->expiry_count = cache->expiry_count;
	snapshot->digest_failure_count =
		cache->digest_failure_count;
	snapshot->rejected_count = cache->rejected_count;
	snapshot->compaction_count =
		cache->compaction_count;
	ret = metadata_digest_locked(
		cache, snapshot->metadata_digest);
	if (ret == 0) {
		ret = snapshot_digest_compute(
			snapshot, snapshot->snapshot_digest);
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

static int owner_audit(
	const struct pqcp_fleet_artifact_entry *entry)
{
	uint32_t owner_count = 0U;
	uint32_t reference_count = 0U;
	uint32_t pin_count = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_ARTIFACT_MAX_OWNERS; ++index) {
		const struct pqcp_fleet_artifact_owner *owner =
			&entry->owners[index];

		if (!owner->occupied) {
			if (owner->owner_id != 0U ||
			    owner->references != 0U ||
			    owner->flags != 0U ||
			    owner->acquired_at_ms != 0U ||
			    owner->expires_at_ms != 0U) {
				return -EBADMSG;
			}
			continue;
		}
		if (owner->owner_id == 0U ||
		    owner->acquired_at_ms == 0U ||
		    (owner->expires_at_ms != 0U &&
		     owner->expires_at_ms <=
			     owner->acquired_at_ms) ||
		    (owner->references == 0U &&
		     (owner->flags &
		      PQCP_FLEET_ARTIFACT_OWNER_PIN) == 0U) ||
		    !owner_flags_valid(
			    owner->flags |
			    (owner->references != 0U ?
			     PQCP_FLEET_ARTIFACT_OWNER_REFERENCE :
			     PQCP_FLEET_ARTIFACT_OWNER_PIN))) {
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < PQCP_FLEET_ARTIFACT_MAX_OWNERS;
		     ++other) {
			if (entry->owners[other].occupied &&
			    entry->owners[other].owner_id ==
				    owner->owner_id) {
				return -EEXIST;
			}
		}
		if (UINT32_MAX - reference_count <
		    owner->references) {
			return -EOVERFLOW;
		}
		reference_count += owner->references;
		if ((owner->flags &
		     PQCP_FLEET_ARTIFACT_OWNER_PIN) != 0U) {
			pin_count++;
		}
		owner_count++;
	}
	if (owner_count != entry->owner_count ||
	    reference_count > entry->reference_count ||
	    pin_count != entry->pin_count) {
		return -EBADMSG;
	}
	return 0;
}

static int entry_audit_locked(
	struct pqcp_fleet_artifact_cache *cache,
	size_t index,
	bool verify_content)
{
	const struct pqcp_fleet_artifact_entry *entry =
		&cache->entries[index];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	size_t expected_stored;
	int ret;

	if (!entry->occupied) {
		if (entry->schema_version != 0U ||
		    entry->object_id != 0U ||
		    entry->extent_capacity != 0U ||
		    entry->state !=
			    PQCP_FLEET_ARTIFACT_STATE_EMPTY) {
			return -EBADMSG;
		}
		return 0;
	}
	if (entry->schema_version !=
		    PQCP_FLEET_ARTIFACT_CACHE_SCHEMA_VERSION ||
	    entry->slot_generation == 0U ||
	    entry->object_id == 0U ||
	    entry->object_generation == 0U ||
	    entry->cache_generation == 0U ||
	    entry->cache_generation > cache->generation ||
	    !artifact_kind_valid(entry->kind) ||
	    !artifact_priority_valid(entry->priority) ||
	    !artifact_state_valid(entry->state) ||
	    entry->state ==
		    PQCP_FLEET_ARTIFACT_STATE_EMPTY ||
	    !extent_bounds_valid(cache, entry) ||
	    entry->chunk_size == 0U ||
	    entry->chunk_count == 0U ||
	    entry->chunk_count >
		    PQCP_FLEET_ARTIFACT_MAX_CHUNKS ||
	    entry->complete_chunks > entry->chunk_count ||
	    entry->created_at_ms == 0U ||
	    (entry->expires_at_ms != 0U &&
	     entry->expires_at_ms <= entry->created_at_ms) ||
	    entry->last_access_at_ms <
		    entry->created_at_ms ||
	    !text_valid(entry->label, sizeof(entry->label)) ||
	    digest_is_zero(entry->expected_digest) ||
	    !bitmap_tail_clear(
		    entry->chunk_bitmap,
		    entry->chunk_count) ||
	    bitmap_count(
		    entry->chunk_bitmap,
		    entry->chunk_count) !=
		    entry->complete_chunks) {
		return -EBADMSG;
	}
	expected_stored = completed_payload_bytes(entry);
	if (expected_stored == SIZE_MAX ||
	    expected_stored != entry->stored_bytes ||
	    entry->stored_bytes > entry->content_length) {
		return -EBADMSG;
	}
	if (entry->state ==
		    PQCP_FLEET_ARTIFACT_STATE_VERIFIED ||
	    entry->state ==
		    PQCP_FLEET_ARTIFACT_STATE_RETIRED ||
	    entry->state ==
		    PQCP_FLEET_ARTIFACT_STATE_EXPIRED) {
		if (entry->complete_chunks != entry->chunk_count ||
		    entry->stored_bytes != entry->content_length ||
		    (entry->flags &
		     PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED) == 0U ||
		    !digest_equal(
			    entry->expected_digest,
			    entry->verified_digest)) {
			return -EBADMSG;
		}
	}
	if ((entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U &&
	    entry->state !=
		    PQCP_FLEET_ARTIFACT_STATE_VERIFIED) {
		return -EBADMSG;
	}
	ret = owner_audit(entry);
	if (ret != 0) {
		return ret;
	}
	if (verify_content &&
	    (entry->flags &
	     PQCP_FLEET_ARTIFACT_FLAG_DIGEST_VERIFIED) != 0U) {
		ret = pqcp_runtime_internal_sha256(
			cache->arena + entry->extent_offset,
			entry->content_length, digest);
		if (ret == 0 &&
		    !digest_equal(
			    digest,
			    entry->verified_digest)) {
			ret = -EBADMSG;
		}
		pqcp_runtime_secure_zero(
			digest, sizeof(digest));
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

int pqcp_fleet_artifact_cache_entry_verify(
	struct pqcp_fleet_artifact_cache *cache,
	const struct pqcp_fleet_artifact_handle *handle,
	bool verify_content)
{
	struct pqcp_fleet_artifact_entry *entry;
	size_t index;
	int ret;

	if (!cache_ready(cache)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = handle_entry_locked(cache, handle, &entry);
	if (ret == 0) {
		index = (size_t)(entry - cache->entries);
		ret = entry_audit_locked(
			cache, index, verify_content);
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

static int leases_audit_locked(
	const struct pqcp_fleet_artifact_cache *cache)
{
	for (size_t index = 0U;
	     index < cache->lease_capacity; ++index) {
		const struct pqcp_fleet_artifact_reader_lease *lease =
			&cache->leases[index];

		if (!lease->active) {
			if (lease->lease_id != 0U ||
			    lease->owner_id != 0U) {
				return -EBADMSG;
			}
			continue;
		}
		if (lease->lease_id == 0U ||
		    lease->owner_id == 0U ||
		    lease->opened_at_ms == 0U ||
		    lease->expires_at_ms <=
			    lease->opened_at_ms ||
		    lease->artifact.slot >=
			    cache->entry_capacity ||
		    lease->artifact.slot_generation == 0U) {
			return -EBADMSG;
		}
		const struct pqcp_fleet_artifact_entry *entry =
			&cache->entries[lease->artifact.slot];

		if (!entry->occupied ||
		    entry->slot_generation !=
			    lease->artifact.slot_generation ||
		    entry->reference_count == 0U) {
			return -ESTALE;
		}
		for (size_t other = index + 1U;
		     other < cache->lease_capacity; ++other) {
			if (cache->leases[other].active &&
			    cache->leases[other].lease_id ==
				    lease->lease_id) {
				return -EEXIST;
			}
		}
	}
	return 0;
}

int pqcp_fleet_artifact_cache_audit(
	struct pqcp_fleet_artifact_cache *cache,
	bool verify_content)
{
	int ret;

	if (!cache_ready(cache)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&cache->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < cache->entry_capacity; ++index) {
		ret = entry_audit_locked(
			cache, index, verify_content);
		if (ret != 0) {
			(void)k_mutex_unlock(&cache->lock);
			return ret;
		}
		if (!cache->entries[index].occupied) {
			continue;
		}
		for (size_t other = index + 1U;
		     other < cache->entry_capacity; ++other) {
			const struct pqcp_fleet_artifact_entry *left =
				&cache->entries[index];
			const struct pqcp_fleet_artifact_entry *right =
				&cache->entries[other];

			if (!right->occupied) {
				continue;
			}
			if (extents_overlap(
				    left->extent_offset,
				    left->extent_capacity,
				    right->extent_offset,
				    right->extent_capacity)) {
				(void)k_mutex_unlock(&cache->lock);
				return -EADDRINUSE;
			}
			if (digest_equal(
				    left->expected_digest,
				    right->expected_digest)) {
				(void)k_mutex_unlock(&cache->lock);
				return -EEXIST;
			}
			if (left->object_id == right->object_id &&
			    left->kind == right->kind &&
			    (left->flags &
			     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U &&
			    (right->flags &
			     PQCP_FLEET_ARTIFACT_FLAG_CURRENT) != 0U) {
				(void)k_mutex_unlock(&cache->lock);
				return -EEXIST;
			}
		}
	}
	ret = leases_audit_locked(cache);
	if (ret == 0) {
		size_t allocated =
			allocated_bytes_locked(cache);

		if (allocated == SIZE_MAX ||
		    allocated > cache->arena_capacity) {
			ret = -EOVERFLOW;
		}
	}
	(void)k_mutex_unlock(&cache->lock);
	return ret;
}

const char *pqcp_fleet_artifact_kind_str(
	enum pqcp_fleet_artifact_kind kind)
{
	switch (kind) {
	case PQCP_FLEET_ARTIFACT_FIRMWARE:
		return "firmware";
	case PQCP_FLEET_ARTIFACT_POLICY:
		return "policy";
	case PQCP_FLEET_ARTIFACT_REVOCATION_SET:
		return "revocation_set";
	case PQCP_FLEET_ARTIFACT_CREDENTIAL:
		return "credential";
	case PQCP_FLEET_ARTIFACT_ATTESTATION:
		return "attestation";
	case PQCP_FLEET_ARTIFACT_SNAPSHOT:
		return "snapshot";
	case PQCP_FLEET_ARTIFACT_DELTA:
		return "delta";
	case PQCP_FLEET_ARTIFACT_EVIDENCE:
		return "evidence";
	case PQCP_FLEET_ARTIFACT_RECOVERY:
		return "recovery";
	case PQCP_FLEET_ARTIFACT_APPLICATION:
		return "application";
	default:
		return "none";
	}
}

const char *pqcp_fleet_artifact_state_str(
	enum pqcp_fleet_artifact_state state)
{
	switch (state) {
	case PQCP_FLEET_ARTIFACT_STATE_EMPTY:
		return "empty";
	case PQCP_FLEET_ARTIFACT_STATE_WRITING:
		return "writing";
	case PQCP_FLEET_ARTIFACT_STATE_VERIFIED:
		return "verified";
	case PQCP_FLEET_ARTIFACT_STATE_RETIRED:
		return "retired";
	case PQCP_FLEET_ARTIFACT_STATE_EXPIRED:
		return "expired";
	case PQCP_FLEET_ARTIFACT_STATE_CORRUPT:
		return "corrupt";
	default:
		return "invalid";
	}
}
