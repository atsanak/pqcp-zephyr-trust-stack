/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded append-only transparency log with a compact Merkle frontier.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_transparency.h>

static bool digest_equal(
	const uint8_t left[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	uint8_t difference = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES;
	     ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static bool digest_nonzero(
	const uint8_t value[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES;
	     ++index) {
		aggregate |= value[index];
	}
	return aggregate != 0U;
}

static bool log_config_valid(
	const struct pqcp_fleet_transparency_log *log)
{
	return log != NULL && log->initialized &&
	       log->schema_version ==
		       PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION &&
	       digest_nonzero(log->log_id) &&
	       log->leaf_hashes != NULL && log->capacity != 0U &&
	       log->hash.digest != NULL &&
	       log->tree_size <= log->capacity;
}

static int root_from_frontier(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t frontier[PQCP_FLEET_TRANSPARENCY_MAX_LEVELS]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	uint64_t frontier_mask,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	uint8_t accumulated[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t combined[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	bool have_accumulated = false;
	int ret;

	if (frontier_mask == 0U) {
		return pqcp_fleet_transparency_empty_root(hash, output);
	}

	for (size_t level = 0U;
	     level < PQCP_FLEET_TRANSPARENCY_MAX_LEVELS;
	     ++level) {
		if ((frontier_mask & (UINT64_C(1) << level)) == 0U) {
			continue;
		}
		if (!have_accumulated) {
			memcpy(accumulated, frontier[level],
			       sizeof(accumulated));
			have_accumulated = true;
			continue;
		}
		ret = pqcp_fleet_transparency_node_hash(
			hash, frontier[level], accumulated, combined);
		if (ret != 0) {
			return ret;
		}
		memcpy(accumulated, combined, sizeof(accumulated));
	}
	memcpy(output, accumulated,
	       PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES);
	return 0;
}

static int frontier_append(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	struct pqcp_fleet_transparency_workspace *workspace,
	const uint8_t leaf_hash[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	uint8_t combined[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t level = 0U;
	int ret;

	memcpy(workspace->carry, leaf_hash,
	       PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES);
	while (level < PQCP_FLEET_TRANSPARENCY_MAX_LEVELS &&
	       (workspace->frontier_mask &
		(UINT64_C(1) << level)) != 0U) {
		ret = pqcp_fleet_transparency_node_hash(
			hash, workspace->frontier[level],
			workspace->carry, combined);
		if (ret != 0) {
			return ret;
		}
		memcpy(workspace->carry, combined, sizeof(combined));
		memset(workspace->frontier[level], 0,
		       PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES);
		workspace->frontier_mask &=
			~(UINT64_C(1) << level);
		++level;
	}
	if (level == PQCP_FLEET_TRANSPARENCY_MAX_LEVELS) {
		return -EOVERFLOW;
	}
	memcpy(workspace->frontier[level], workspace->carry,
	       PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES);
	workspace->frontier_mask |= UINT64_C(1) << level;
	return root_from_frontier(
		hash, workspace->frontier,
		workspace->frontier_mask, workspace->root);
}

static void workspace_from_log(
	const struct pqcp_fleet_transparency_log *log,
	struct pqcp_fleet_transparency_workspace *workspace)
{
	memcpy(workspace->frontier, log->frontier,
	       sizeof(workspace->frontier));
	workspace->frontier_mask = log->frontier_mask;
	memcpy(workspace->root, log->root, sizeof(workspace->root));
	memset(workspace->carry, 0, sizeof(workspace->carry));
}

static void commit_workspace(
	struct pqcp_fleet_transparency_log *log,
	const struct pqcp_fleet_transparency_workspace *workspace)
{
	memcpy(log->frontier, workspace->frontier,
	       sizeof(log->frontier));
	log->frontier_mask = workspace->frontier_mask;
	memcpy(log->root, workspace->root, sizeof(log->root));
}

int pqcp_fleet_transparency_log_init(
	struct pqcp_fleet_transparency_log *log,
	const uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES],
	uint8_t (*leaf_hashes)[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	size_t capacity,
	const struct pqcp_fleet_transparency_hash_ops *hash)
{
	uint8_t empty_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	int ret;

	if (log == NULL || log_id == NULL ||
	    !digest_nonzero(log_id) || leaf_hashes == NULL ||
	    capacity == 0U || capacity > UINT64_MAX ||
	    hash == NULL || hash->digest == NULL) {
		return -EINVAL;
	}
	ret = pqcp_fleet_transparency_empty_root(hash, empty_root);
	if (ret != 0) {
		return ret;
	}

	memset(log, 0, sizeof(*log));
	log->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	memcpy(log->log_id, log_id, sizeof(log->log_id));
	log->leaf_hashes = leaf_hashes;
	log->capacity = capacity;
	log->generation = 1U;
	memcpy(log->root, empty_root, sizeof(log->root));
	log->hash = *hash;
	log->initialized = true;
	return 0;
}

int pqcp_fleet_transparency_log_restore(
	struct pqcp_fleet_transparency_log *log,
	size_t leaf_count,
	uint64_t generation,
	struct pqcp_fleet_transparency_workspace *workspace)
{
	int ret;

	if (!log_config_valid(log) || workspace == NULL ||
	    leaf_count > log->capacity || generation == 0U) {
		return -EINVAL;
	}
	memset(workspace, 0, sizeof(*workspace));
	ret = pqcp_fleet_transparency_empty_root(
		&log->hash, workspace->root);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < leaf_count; ++index) {
		ret = frontier_append(
			&log->hash, workspace,
			log->leaf_hashes[index]);
		if (ret != 0) {
			return ret;
		}
	}
	commit_workspace(log, workspace);
	log->tree_size = leaf_count;
	log->generation = generation;
	return 0;
}

int pqcp_fleet_transparency_log_append(
	struct pqcp_fleet_transparency_log *log,
	const uint8_t *statement,
	size_t statement_length,
	struct pqcp_fleet_transparency_workspace *workspace,
	uint64_t *leaf_index)
{
	uint8_t leaf_hash[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint64_t index;
	int ret;

	if (!log_config_valid(log) ||
	    (statement == NULL && statement_length != 0U) ||
	    workspace == NULL || leaf_index == NULL) {
		return -EINVAL;
	}
	if (log->tree_size >= log->capacity) {
		return -ENOSPC;
	}
	if (log->tree_size == UINT64_MAX ||
	    log->generation == UINT64_MAX) {
		return -EOVERFLOW;
	}

	ret = pqcp_fleet_transparency_leaf_hash(
		&log->hash, statement, statement_length, leaf_hash);
	if (ret != 0) {
		return ret;
	}
	workspace_from_log(log, workspace);
	ret = frontier_append(&log->hash, workspace, leaf_hash);
	if (ret != 0) {
		return ret;
	}

	index = log->tree_size;
	memcpy(log->leaf_hashes[index], leaf_hash,
	       sizeof(leaf_hash));
	commit_workspace(log, workspace);
	log->tree_size = index + 1U;
	++log->generation;
	*leaf_index = index;
	return 0;
}

int pqcp_fleet_transparency_log_snapshot(
	const struct pqcp_fleet_transparency_log *log,
	struct pqcp_fleet_transparency_snapshot *snapshot)
{
	if (!log_config_valid(log) || snapshot == NULL) {
		return -EINVAL;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	snapshot->tree_size = log->tree_size;
	snapshot->generation = log->generation;
	memcpy(snapshot->log_id, log->log_id,
	       sizeof(snapshot->log_id));
	memcpy(snapshot->root, log->root,
	       sizeof(snapshot->root));
	return 0;
}

int pqcp_fleet_transparency_log_verify(
	const struct pqcp_fleet_transparency_log *log,
	struct pqcp_fleet_transparency_workspace *workspace)
{
	uint64_t expected_mask;
	int ret;

	if (!log_config_valid(log) || workspace == NULL) {
		return -EINVAL;
	}
	memset(workspace, 0, sizeof(*workspace));
	ret = pqcp_fleet_transparency_empty_root(
		&log->hash, workspace->root);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < (size_t)log->tree_size;
	     ++index) {
		ret = frontier_append(
			&log->hash, workspace,
			log->leaf_hashes[index]);
		if (ret != 0) {
			return ret;
		}
	}
	expected_mask = log->tree_size;
	if (workspace->frontier_mask != expected_mask ||
	    log->frontier_mask != expected_mask ||
	    !digest_equal(workspace->root, log->root)) {
		return -EILSEQ;
	}
	for (size_t level = 0U;
	     level < PQCP_FLEET_TRANSPARENCY_MAX_LEVELS;
	     ++level) {
		if ((expected_mask & (UINT64_C(1) << level)) != 0U &&
		    !digest_equal(
			    workspace->frontier[level],
			    log->frontier[level])) {
			return -EILSEQ;
		}
	}
	return 0;
}
