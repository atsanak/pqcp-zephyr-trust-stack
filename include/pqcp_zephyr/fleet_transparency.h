/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Host-portable transparency primitives for fleet security artifacts.
 *
 * The Merkle construction follows the domain separation and tree shape from
 * RFC 9162. Storage, hashing, signing, and persistence are supplied by the
 * caller so the implementation can be used by firmware and hosted tools
 * without a second protocol authority or a dynamic allocator.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_TRANSPARENCY_H_
#define PQCP_ZEPHYR_FLEET_TRANSPARENCY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION 1U
#define PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES 32U
#define PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES 32U
#define PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES 32U
#define PQCP_FLEET_TRANSPARENCY_MAX_LEVELS 64U
#define PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES 65U

/**
 * One immutable byte range supplied to a hashing or signing callback.
 *
 * A NULL data pointer is valid only when length is zero.
 */
struct pqcp_fleet_transparency_part {
	const uint8_t *data;
	size_t length;
};

/**
 * Hash provider used by every transparency primitive.
 *
 * The callback computes one SHA-256-compatible 32-byte digest over the exact
 * concatenation of parts[0] through parts[part_count - 1]. A zero-part call
 * hashes the empty string. The callback must not retain any input pointer.
 */
struct pqcp_fleet_transparency_hash_ops {
	void *context;
	int (*digest)(
		void *context,
		const struct pqcp_fleet_transparency_part *parts,
		size_t part_count,
		uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);
};

/**
 * Caller-owned scratch area for transactional frontier updates.
 *
 * A workspace may be reused between calls after each call returns. It must
 * not be shared concurrently by multiple operations.
 */
struct pqcp_fleet_transparency_workspace {
	uint8_t frontier[PQCP_FLEET_TRANSPARENCY_MAX_LEVELS]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint64_t frontier_mask;
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t carry[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
};

/**
 * Compact state summary suitable for persistence and checkpoint binding.
 */
struct pqcp_fleet_transparency_snapshot {
	uint32_t schema_version;
	uint64_t tree_size;
	uint64_t generation;
	uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
};

/**
 * Bounded append-only transparency log.
 *
 * leaf_hashes points to capacity caller-owned 32-byte slots. The complete
 * leaf-hash history is retained so inclusion and consistency proofs can be
 * produced without dynamic allocation. The compact frontier keeps append
 * cost logarithmic in tree size.
 */
struct pqcp_fleet_transparency_log {
	uint32_t schema_version;
	uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t (*leaf_hashes)[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t capacity;
	uint64_t tree_size;
	uint64_t generation;
	uint8_t frontier[PQCP_FLEET_TRANSPARENCY_MAX_LEVELS]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint64_t frontier_mask;
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	struct pqcp_fleet_transparency_hash_ops hash;
	bool initialized;
};

/**
 * RFC 9162-style Merkle inclusion proof.
 *
 * nodes are ordered from the leaf level toward the root.
 */
struct pqcp_fleet_transparency_inclusion_proof {
	uint32_t schema_version;
	uint64_t tree_size;
	uint64_t leaf_index;
	uint8_t leaf_hash[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t nodes[PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t node_count;
};

/**
 * RFC 9162-style proof that a newer tree extends an older tree.
 */
struct pqcp_fleet_transparency_consistency_proof {
	uint32_t schema_version;
	uint64_t old_tree_size;
	uint64_t new_tree_size;
	uint8_t old_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t new_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t nodes[PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t node_count;
};

/**
 * Compute HASH("") for the configured digest provider.
 */
int pqcp_fleet_transparency_empty_root(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);

/**
 * Compute HASH(0x00 || leaf), as required by RFC 9162.
 */
int pqcp_fleet_transparency_leaf_hash(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t *leaf,
	size_t leaf_length,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);

/**
 * Compute HASH(0x01 || left || right), as required by RFC 9162.
 */
int pqcp_fleet_transparency_node_hash(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t left[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);

/**
 * Compute the canonical RFC 9162 root over already domain-separated leaves.
 */
int pqcp_fleet_transparency_root_from_hashes(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t (*leaf_hashes)
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	size_t leaf_count,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);

/**
 * Initialize an empty bounded log.
 */
int pqcp_fleet_transparency_log_init(
	struct pqcp_fleet_transparency_log *log,
	const uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES],
	uint8_t (*leaf_hashes)[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	size_t capacity,
	const struct pqcp_fleet_transparency_hash_ops *hash);

/**
 * Restore a log from leaf hashes already present in its caller-owned storage.
 *
 * The function rebuilds the frontier and root transactionally. No state is
 * committed when a hash callback fails or the supplied count is invalid.
 */
int pqcp_fleet_transparency_log_restore(
	struct pqcp_fleet_transparency_log *log,
	size_t leaf_count,
	uint64_t generation,
	struct pqcp_fleet_transparency_workspace *workspace);

/**
 * Append one exact statement representation to the log.
 *
 * On success leaf_index receives the immutable zero-based index. The append
 * is transactional with respect to callback failures.
 */
int pqcp_fleet_transparency_log_append(
	struct pqcp_fleet_transparency_log *log,
	const uint8_t *statement,
	size_t statement_length,
	struct pqcp_fleet_transparency_workspace *workspace,
	uint64_t *leaf_index);

/**
 * Return a stable state summary.
 */
int pqcp_fleet_transparency_log_snapshot(
	const struct pqcp_fleet_transparency_log *log,
	struct pqcp_fleet_transparency_snapshot *snapshot);

/**
 * Rebuild and audit all compact log state against retained leaves.
 */
int pqcp_fleet_transparency_log_verify(
	const struct pqcp_fleet_transparency_log *log,
	struct pqcp_fleet_transparency_workspace *workspace);

/**
 * Generate and verify Merkle inclusion proofs.
 */
int pqcp_fleet_transparency_inclusion_proof_generate(
	const struct pqcp_fleet_transparency_log *log,
	uint64_t leaf_index,
	uint64_t tree_size,
	struct pqcp_fleet_transparency_inclusion_proof *proof);
int pqcp_fleet_transparency_inclusion_proof_verify(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_inclusion_proof *proof);

/**
 * Generate and verify append-only consistency proofs.
 */
int pqcp_fleet_transparency_consistency_proof_generate(
	const struct pqcp_fleet_transparency_log *log,
	uint64_t old_tree_size,
	uint64_t new_tree_size,
	struct pqcp_fleet_transparency_consistency_proof *proof);
int pqcp_fleet_transparency_consistency_proof_verify(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_consistency_proof *proof);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_TRANSPARENCY_H_ */
