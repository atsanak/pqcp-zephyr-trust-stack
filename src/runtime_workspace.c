/*
 * SPDX-License-Identifier: MIT
 *
 * Fixed-size workspace pool for PQCP jobs.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_executor.h>

static bool slot_consistent(
	const struct pqcp_runtime_workspace_slot *slot)
{
	if (slot == NULL || slot->buffer == NULL ||
	    slot->capacity == 0U ||
	    slot->used > slot->capacity) {
		return false;
	}
	if (!slot->allocated) {
		return slot->used == 0U &&
		       slot->owner_job_id == 0U;
	}
	return slot->owner_job_id != 0U &&
	       slot->generation != 0U &&
	       slot->used != 0U;
}

int pqcp_runtime_workspace_pool_init(
	struct pqcp_runtime_workspace_pool *pool,
	struct pqcp_runtime_workspace_slot *slots,
	uint8_t *storage,
	size_t slot_count,
	size_t bytes_per_slot)
{
	if (pool == NULL || slots == NULL ||
	    storage == NULL || slot_count == 0U ||
	    bytes_per_slot == 0U ||
	    slot_count > UINT32_MAX ||
	    bytes_per_slot > UINT32_MAX) {
		return -EINVAL;
	}
	memset(pool, 0, sizeof(*pool));
	memset(slots, 0, sizeof(*slots) * slot_count);
	memset(storage, 0, slot_count * bytes_per_slot);
	pool->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	pool->slots = slots;
	pool->slot_count = slot_count;
	k_mutex_init(&pool->lock);
	for (size_t index = 0U; index < slot_count; ++index) {
		slots[index].buffer =
			storage + index * bytes_per_slot;
		slots[index].capacity = bytes_per_slot;
		slots[index].generation = 1U;
	}
	return pqcp_runtime_workspace_audit(pool);
}

static int find_free_slot(
	const struct pqcp_runtime_workspace_pool *pool,
	size_t required_bytes)
{
	int best = -1;
	size_t best_capacity = SIZE_MAX;

	for (size_t index = 0U; index < pool->slot_count; ++index) {
		const struct pqcp_runtime_workspace_slot *slot =
			&pool->slots[index];

		if (slot->allocated ||
		    slot->capacity < required_bytes) {
			continue;
		}
		if (slot->capacity < best_capacity) {
			best = (int)index;
			best_capacity = slot->capacity;
		}
	}
	return best;
}

int pqcp_runtime_workspace_acquire(
	struct pqcp_runtime_workspace_pool *pool,
	uint64_t job_id,
	size_t required_bytes,
	uint8_t **workspace,
	size_t *workspace_capacity,
	uint32_t *generation)
{
	struct pqcp_runtime_workspace_slot *slot;
	int index;
	int ret;

	if (pool == NULL || job_id == 0U ||
	    required_bytes == 0U || workspace == NULL ||
	    workspace_capacity == NULL || generation == NULL ||
	    pool->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&pool->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = find_free_slot(pool, required_bytes);
	if (index < 0) {
		(void)k_mutex_unlock(&pool->lock);
		return -ENOSPC;
	}
	slot = &pool->slots[index];
	slot->generation++;
	if (slot->generation == 0U) {
		slot->generation++;
	}
	slot->allocated = true;
	slot->owner_job_id = job_id;
	slot->used = required_bytes;
	memset(slot->buffer, 0, slot->capacity);
	pool->allocated_count++;
	if (pool->allocated_count > pool->high_watermark) {
		pool->high_watermark =
			pool->allocated_count;
	}
	*workspace = slot->buffer;
	*workspace_capacity = slot->capacity;
	*generation = slot->generation;
	(void)k_mutex_unlock(&pool->lock);
	return 0;
}

int pqcp_runtime_workspace_release(
	struct pqcp_runtime_workspace_pool *pool,
	uint64_t job_id,
	uint32_t generation)
{
	struct pqcp_runtime_workspace_slot *slot = NULL;
	int ret;

	if (pool == NULL || job_id == 0U ||
	    generation == 0U ||
	    pool->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&pool->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < pool->slot_count; ++index) {
		if (pool->slots[index].allocated &&
		    pool->slots[index].owner_job_id == job_id) {
			slot = &pool->slots[index];
			break;
		}
	}
	if (slot == NULL) {
		(void)k_mutex_unlock(&pool->lock);
		return -ENOENT;
	}
	if (slot->generation != generation) {
		(void)k_mutex_unlock(&pool->lock);
		return -ESTALE;
	}
	pqcp_runtime_secure_zero(slot->buffer, slot->capacity);
	slot->allocated = false;
	slot->owner_job_id = 0U;
	slot->used = 0U;
	if (pool->allocated_count != 0U) {
		pool->allocated_count--;
	}
	(void)k_mutex_unlock(&pool->lock);
	return 0;
}

int pqcp_runtime_workspace_audit(
	struct pqcp_runtime_workspace_pool *pool)
{
	uint32_t allocated = 0U;
	int ret;

	if (pool == NULL ||
	    pool->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    pool->slots == NULL || pool->slot_count == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&pool->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < pool->slot_count; ++index) {
		if (!slot_consistent(&pool->slots[index])) {
			(void)k_mutex_unlock(&pool->lock);
			return -EBADMSG;
		}
		if (pool->slots[index].allocated) {
			allocated++;
		}
	}
	ret = allocated == pool->allocated_count &&
	      pool->high_watermark <= pool->slot_count ?
		0 : -EBADMSG;
	(void)k_mutex_unlock(&pool->lock);
	return ret;
}
