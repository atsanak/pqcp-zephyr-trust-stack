/*
 * SPDX-License-Identifier: MIT
 *
 * Sliding-window replay protection keyed by producer and epoch.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int replay_index(
	const struct pqcp_edge_replay_guard *guard,
	const char *producer_id)
{
	for (size_t index = 0U;
	     index < guard->capacity; ++index) {
		if (guard->entries[index].occupied &&
		    strcmp(
			    guard->entries[index].producer_id,
			    producer_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_replay_index(
	const struct pqcp_edge_replay_guard *guard)
{
	for (size_t index = 0U;
	     index < guard->capacity; ++index) {
		if (!guard->entries[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int create_entry(
	struct pqcp_edge_replay_guard *guard,
	const char *producer_id,
	uint64_t epoch,
	uint64_t sequence,
	uint64_t now_ms)
{
	struct pqcp_edge_replay_entry *entry;
	int index;
	int ret;

	index = free_replay_index(guard);
	if (index < 0) {
		return index;
	}
	entry = &guard->entries[index];
	memset(entry, 0, sizeof(*entry));
	ret = pqcp_edge_internal_copy_text(
		entry->producer_id,
		sizeof(entry->producer_id),
		producer_id);
	if (ret != 0) {
		return ret;
	}
	entry->epoch = epoch;
	entry->highest_sequence = sequence;
	entry->window_bits = 1U;
	entry->updated_at_ms = now_ms;
	entry->occupied = true;
	return 0;
}

int pqcp_edge_replay_guard_init(
	struct pqcp_edge_replay_guard *guard,
	struct pqcp_edge_replay_entry *entries,
	size_t capacity,
	uint32_t window_size)
{
	if (guard == NULL || entries == NULL ||
	    capacity == 0U || window_size == 0U ||
	    window_size > 64U) {
		return -EINVAL;
	}
	memset(guard, 0, sizeof(*guard));
	memset(entries, 0, capacity * sizeof(*entries));
	guard->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	guard->entries = entries;
	guard->capacity = capacity;
	guard->window_size = window_size;
	k_mutex_init(&guard->lock);
	guard->initialized = true;
	return 0;
}

int pqcp_edge_replay_accept(
	struct pqcp_edge_replay_guard *guard,
	const char *producer_id,
	uint64_t epoch,
	uint64_t sequence,
	uint64_t now_ms)
{
	struct pqcp_edge_replay_entry *entry;
	uint64_t distance;
	uint64_t bit;
	int index;
	int ret = 0;

	if (guard == NULL || !guard->initialized ||
	    !pqcp_edge_internal_text_valid(
		    producer_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    epoch == 0U || sequence == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&guard->lock, K_FOREVER);
	index = replay_index(guard, producer_id);
	if (index == -ENOENT) {
		ret = create_entry(
			guard, producer_id, epoch,
			sequence, now_ms);
		if (ret == 0) {
			++guard->accepted_count;
		}
		goto out;
	}
	if (index < 0) {
		ret = index;
		goto out;
	}
	entry = &guard->entries[index];
	if (epoch < entry->epoch) {
		++guard->stale_count;
		ret = -ESTALE;
		goto out;
	}
	if (epoch > entry->epoch) {
		entry->epoch = epoch;
		entry->highest_sequence = sequence;
		entry->window_bits = 1U;
		entry->updated_at_ms = now_ms;
		++guard->accepted_count;
		goto out;
	}
	if (sequence > entry->highest_sequence) {
		distance = sequence - entry->highest_sequence;
		if (distance >= guard->window_size) {
			entry->window_bits = 1U;
		} else {
			entry->window_bits =
				(entry->window_bits << distance) | 1U;
		}
		entry->highest_sequence = sequence;
		entry->updated_at_ms = now_ms;
		++guard->accepted_count;
		goto out;
	}
	distance = entry->highest_sequence - sequence;
	if (distance >= guard->window_size) {
		++guard->stale_count;
		ret = -ESTALE;
		goto out;
	}
	bit = 1ULL << distance;
	if ((entry->window_bits & bit) != 0U) {
		++guard->replay_count;
		ret = -EALREADY;
		goto out;
	}
	entry->window_bits |= bit;
	entry->updated_at_ms = now_ms;
	++guard->accepted_count;
out:
	k_mutex_unlock(&guard->lock);
	return ret;
}

int pqcp_edge_replay_advance_epoch(
	struct pqcp_edge_replay_guard *guard,
	const char *producer_id,
	uint64_t epoch,
	uint64_t now_ms)
{
	struct pqcp_edge_replay_entry *entry;
	int index;
	int ret = 0;

	if (guard == NULL || !guard->initialized ||
	    producer_id == NULL || epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&guard->lock, K_FOREVER);
	index = replay_index(guard, producer_id);
	if (index < 0) {
		ret = index;
	} else {
		entry = &guard->entries[index];
		if (epoch <= entry->epoch) {
			ret = -ESTALE;
		} else {
			entry->epoch = epoch;
			entry->highest_sequence = 0U;
			entry->window_bits = 0U;
			entry->updated_at_ms = now_ms;
		}
	}
	k_mutex_unlock(&guard->lock);
	return ret;
}

int pqcp_edge_replay_expire(
	struct pqcp_edge_replay_guard *guard,
	uint64_t before_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (guard == NULL || !guard->initialized ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&guard->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < guard->capacity; ++index) {
		if (guard->entries[index].occupied &&
		    guard->entries[index].updated_at_ms <
			    before_ms) {
			memset(&guard->entries[index], 0,
			       sizeof(guard->entries[index]));
			++expired;
		}
	}
	k_mutex_unlock(&guard->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_replay_guard_audit(
	struct pqcp_edge_replay_guard *guard)
{
	int ret = 0;

	if (guard == NULL || !guard->initialized ||
	    guard->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    guard->entries == NULL || guard->capacity == 0U ||
	    guard->window_size == 0U ||
	    guard->window_size > 64U) {
		return -EINVAL;
	}
	k_mutex_lock(&guard->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < guard->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_replay_entry *entry =
			&guard->entries[index];

		if (!entry->occupied) {
			continue;
		}
		if (!pqcp_edge_internal_text_valid(
			    entry->producer_id,
			    sizeof(entry->producer_id)) ||
		    entry->epoch == 0U ||
		    (entry->highest_sequence == 0U &&
		     entry->window_bits != 0U) ||
		    (entry->highest_sequence != 0U &&
		     (entry->window_bits & 1U) == 0U)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < guard->capacity; ++other) {
			if (guard->entries[other].occupied &&
			    strcmp(
				    entry->producer_id,
				    guard->entries[other].
					    producer_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&guard->lock);
	return ret;
}
