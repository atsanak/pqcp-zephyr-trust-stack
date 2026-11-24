/*
 * SPDX-License-Identifier: MIT
 *
 * Compact vault state checkpoints bound to the audit-chain head.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int snapshot_index(
	const struct pqcp_edge_snapshot_manager *manager,
	uint64_t snapshot_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->snapshots[index].occupied &&
		    manager->snapshots[index].snapshot_id ==
			    snapshot_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_snapshot_index(
	const struct pqcp_edge_snapshot_manager *manager)
{
	int oldest = -1;
	uint64_t oldest_time = UINT64_MAX;

	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->snapshots[index].occupied) {
			return (int)index;
		}
		if (manager->snapshots[index].created_at_ms <
		    oldest_time) {
			oldest_time =
				manager->snapshots[index].
					created_at_ms;
			oldest = (int)index;
		}
	}
	return oldest >= 0 ? oldest : -ENOSPC;
}

static int snapshot_digest(
	const struct pqcp_edge_vault_snapshot *snapshot,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[36];
	const uint8_t *parts[3];
	size_t lengths[3];
	size_t offset = 0U;

	pqcp_edge_internal_write_u32(
		numeric + offset, snapshot->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, snapshot->snapshot_id);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, snapshot->created_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, snapshot->object_count);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset,
		snapshot->highest_object_version);
	offset += 8U;
	parts[0] = numeric;
	lengths[0] = offset;
	parts[1] = snapshot->store_digest;
	lengths[1] = sizeof(snapshot->store_digest);
	parts[2] = snapshot->journal_head;
	lengths[2] = sizeof(snapshot->journal_head);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 3U, output);
}

static int compute_store_digest(
	const struct pqcp_edge_vault_store *store,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES],
	uint64_t *object_count,
	uint64_t *highest_version)
{
	uint8_t aggregate[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	uint8_t next[PQCP_EDGE_DIGEST_BYTES];
	const uint8_t *parts[2];
	size_t lengths[2];
	uint64_t count = 0U;
	uint64_t highest = 0U;
	int ret = 0;

	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		const struct pqcp_edge_vault_object *object =
			&store->objects[index];

		if (!object->occupied) {
			continue;
		}
		parts[0] = aggregate;
		lengths[0] = sizeof(aggregate);
		parts[1] = object->object_digest;
		lengths[1] = sizeof(object->object_digest);
		ret = pqcp_edge_internal_sha256_parts(
			parts, lengths, 2U, next);
		if (ret != 0) {
			break;
		}
		memcpy(aggregate, next, sizeof(aggregate));
		++count;
		if (object->version > highest) {
			highest = object->version;
		}
	}
	if (ret == 0) {
		memcpy(output, aggregate, sizeof(aggregate));
		*object_count = count;
		*highest_version = highest;
	}
	return ret;
}

int pqcp_edge_snapshot_manager_init(
	struct pqcp_edge_snapshot_manager *manager,
	struct pqcp_edge_vault_snapshot *snapshots,
	size_t capacity)
{
	if (manager == NULL || snapshots == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(snapshots, 0,
	       capacity * sizeof(*snapshots));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->snapshots = snapshots;
	manager->capacity = capacity;
	manager->next_snapshot_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_snapshot_capture(
	struct pqcp_edge_snapshot_manager *manager,
	struct pqcp_edge_vault_store *store,
	struct pqcp_edge_vault_journal *journal,
	uint64_t now_ms,
	struct pqcp_edge_vault_snapshot **snapshot)
{
	struct pqcp_edge_vault_snapshot candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    store == NULL || !store->initialized ||
	    journal == NULL || !journal->initialized ||
	    snapshot == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	k_mutex_lock(&journal->lock, K_FOREVER);
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = free_snapshot_index(manager);
	if (index < 0) {
		ret = index;
		goto out;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.snapshot_id =
		pqcp_edge_internal_next_identifier(
			&manager->next_snapshot_id);
	candidate.created_at_ms = now_ms;
	ret = compute_store_digest(
		store, candidate.store_digest,
		&candidate.object_count,
		&candidate.highest_object_version);
	if (ret == 0) {
		memcpy(candidate.journal_head,
		       journal->chain_head,
		       sizeof(candidate.journal_head));
		ret = snapshot_digest(
			&candidate,
			candidate.snapshot_digest);
	}
	if (ret == 0) {
		candidate.occupied = true;
		manager->snapshots[index] = candidate;
		*snapshot = &manager->snapshots[index];
		++manager->captured_count;
	} else {
		*snapshot = NULL;
	}
out:
	k_mutex_unlock(&manager->lock);
	k_mutex_unlock(&journal->lock);
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_snapshot_verify(
	struct pqcp_edge_snapshot_manager *manager,
	uint64_t snapshot_id)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    snapshot_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = snapshot_index(manager, snapshot_id);
	if (index < 0) {
		ret = index;
	} else if (snapshot_digest(
			   &manager->snapshots[index],
			   digest) != 0 ||
		   !pqcp_edge_internal_equal(
			   digest,
			   manager->snapshots[index].
				   snapshot_digest,
			   sizeof(digest))) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_snapshot_manager_audit(
	struct pqcp_edge_snapshot_manager *manager)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->snapshots == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_vault_snapshot *snapshot =
			&manager->snapshots[index];

		if (!snapshot->occupied) {
			continue;
		}
		if (snapshot->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    snapshot->snapshot_id == 0U ||
		    snapshot_digest(snapshot, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    digest, snapshot->snapshot_digest,
			    sizeof(digest))) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->snapshots[other].occupied &&
			    manager->snapshots[other].snapshot_id ==
				    snapshot->snapshot_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
