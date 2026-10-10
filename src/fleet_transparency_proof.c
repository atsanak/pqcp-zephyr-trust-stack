/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * RFC 9162 Merkle inclusion and consistency proofs.
 */

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

static bool log_valid(
	const struct pqcp_fleet_transparency_log *log)
{
	return log != NULL && log->initialized &&
	       log->schema_version ==
		       PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION &&
	       log->leaf_hashes != NULL &&
	       log->tree_size <= log->capacity &&
	       log->hash.digest != NULL;
}

static size_t largest_power_of_two_less_than(size_t value)
{
	size_t power = 1U;

	while (power <= (SIZE_MAX >> 1U) &&
	       (power << 1U) < value) {
		power <<= 1U;
	}
	return power;
}

static int range_root(
	const struct pqcp_fleet_transparency_log *log,
	size_t start,
	size_t count,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	return pqcp_fleet_transparency_root_from_hashes(
		&log->hash, log->leaf_hashes + start,
		count, output);
}

static int proof_append(
	uint8_t nodes[PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	size_t *node_count,
	const uint8_t node[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	if (*node_count >=
	    PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES) {
		return -ENOSPC;
	}
	memcpy(nodes[*node_count], node,
	       PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES);
	++(*node_count);
	return 0;
}

static int inclusion_path(
	const struct pqcp_fleet_transparency_log *log,
	size_t start,
	size_t count,
	size_t leaf_index,
	struct pqcp_fleet_transparency_inclusion_proof *proof)
{
	uint8_t sibling[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t split;
	int ret;

	if (count == 1U) {
		return 0;
	}
	split = largest_power_of_two_less_than(count);
	if (leaf_index < split) {
		ret = inclusion_path(
			log, start, split, leaf_index, proof);
		if (ret != 0) {
			return ret;
		}
		ret = range_root(
			log, start + split, count - split, sibling);
	} else {
		ret = inclusion_path(
			log, start + split, count - split,
			leaf_index - split, proof);
		if (ret != 0) {
			return ret;
		}
		ret = range_root(log, start, split, sibling);
	}
	if (ret != 0) {
		return ret;
	}
	return proof_append(
		proof->nodes, &proof->node_count, sibling);
}

int pqcp_fleet_transparency_inclusion_proof_generate(
	const struct pqcp_fleet_transparency_log *log,
	uint64_t leaf_index,
	uint64_t tree_size,
	struct pqcp_fleet_transparency_inclusion_proof *proof)
{
	int ret;

	if (!log_valid(log) || proof == NULL ||
	    tree_size == 0U || tree_size > log->tree_size ||
	    tree_size > SIZE_MAX || leaf_index >= tree_size) {
		return -EINVAL;
	}
	memset(proof, 0, sizeof(*proof));
	proof->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	proof->tree_size = tree_size;
	proof->leaf_index = leaf_index;
	memcpy(proof->leaf_hash, log->leaf_hashes[leaf_index],
	       sizeof(proof->leaf_hash));
	ret = range_root(
		log, 0U, (size_t)tree_size, proof->root);
	if (ret != 0) {
		memset(proof, 0, sizeof(*proof));
		return ret;
	}
	ret = inclusion_path(
		log, 0U, (size_t)tree_size,
		(size_t)leaf_index, proof);
	if (ret != 0) {
		memset(proof, 0, sizeof(*proof));
	}
	return ret;
}

int pqcp_fleet_transparency_inclusion_proof_verify(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_inclusion_proof *proof)
{
	uint8_t calculated[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t combined[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint64_t leaf;
	uint64_t last;
	int ret;

	if (hash == NULL || hash->digest == NULL ||
	    proof == NULL ||
	    proof->schema_version !=
		    PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION ||
	    proof->tree_size == 0U ||
	    proof->leaf_index >= proof->tree_size ||
	    proof->node_count >
		    PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES) {
		return -EINVAL;
	}
	memcpy(calculated, proof->leaf_hash, sizeof(calculated));
	leaf = proof->leaf_index;
	last = proof->tree_size - 1U;

	for (size_t index = 0U;
	     index < proof->node_count;
	     ++index) {
		if (last == 0U) {
			return -EBADMSG;
		}
		if ((leaf & UINT64_C(1)) != 0U || leaf == last) {
			ret = pqcp_fleet_transparency_node_hash(
				hash, proof->nodes[index],
				calculated, combined);
			if ((leaf & UINT64_C(1)) == 0U) {
				do {
					leaf >>= 1U;
					last >>= 1U;
				} while (leaf != 0U &&
					 (leaf & UINT64_C(1)) == 0U);
			}
		} else {
			ret = pqcp_fleet_transparency_node_hash(
				hash, calculated,
				proof->nodes[index], combined);
		}
		if (ret != 0) {
			return ret;
		}
		memcpy(calculated, combined, sizeof(calculated));
		leaf >>= 1U;
		last >>= 1U;
	}
	if (last != 0U ||
	    !digest_equal(calculated, proof->root)) {
		return -EKEYREJECTED;
	}
	return 0;
}

static int consistency_path(
	const struct pqcp_fleet_transparency_log *log,
	size_t start,
	size_t old_count,
	size_t new_count,
	bool complete_subtree,
	struct pqcp_fleet_transparency_consistency_proof *proof)
{
	uint8_t node[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t split;
	int ret;

	if (old_count == new_count) {
		if (complete_subtree) {
			return 0;
		}
		ret = range_root(log, start, old_count, node);
		if (ret != 0) {
			return ret;
		}
		return proof_append(
			proof->nodes, &proof->node_count, node);
	}

	split = largest_power_of_two_less_than(new_count);
	if (old_count <= split) {
		ret = consistency_path(
			log, start, old_count, split,
			complete_subtree, proof);
		if (ret != 0) {
			return ret;
		}
		ret = range_root(
			log, start + split, new_count - split, node);
	} else {
		ret = consistency_path(
			log, start + split, old_count - split,
			new_count - split, false, proof);
		if (ret != 0) {
			return ret;
		}
		ret = range_root(log, start, split, node);
	}
	if (ret != 0) {
		return ret;
	}
	return proof_append(
		proof->nodes, &proof->node_count, node);
}

int pqcp_fleet_transparency_consistency_proof_generate(
	const struct pqcp_fleet_transparency_log *log,
	uint64_t old_tree_size,
	uint64_t new_tree_size,
	struct pqcp_fleet_transparency_consistency_proof *proof)
{
	int ret;

	if (!log_valid(log) || proof == NULL ||
	    old_tree_size > new_tree_size ||
	    new_tree_size > log->tree_size ||
	    new_tree_size > SIZE_MAX) {
		return -EINVAL;
	}
	memset(proof, 0, sizeof(*proof));
	proof->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	proof->old_tree_size = old_tree_size;
	proof->new_tree_size = new_tree_size;
	ret = range_root(
		log, 0U, (size_t)old_tree_size, proof->old_root);
	if (ret != 0) {
		goto fail;
	}
	ret = range_root(
		log, 0U, (size_t)new_tree_size, proof->new_root);
	if (ret != 0 || old_tree_size == 0U ||
	    old_tree_size == new_tree_size) {
		goto done;
	}
	ret = consistency_path(
		log, 0U, (size_t)old_tree_size,
		(size_t)new_tree_size, true, proof);
done:
	if (ret == 0) {
		return 0;
	}
fail:
	memset(proof, 0, sizeof(*proof));
	return ret;
}

int pqcp_fleet_transparency_consistency_proof_verify(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_consistency_proof *proof)
{
	uint8_t old_calculated[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t new_calculated[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t combined[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t empty[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint64_t old_index;
	uint64_t new_index;
	size_t proof_index = 0U;
	int ret;

	if (hash == NULL || hash->digest == NULL ||
	    proof == NULL ||
	    proof->schema_version !=
		    PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION ||
	    proof->old_tree_size > proof->new_tree_size ||
	    proof->node_count >
		    PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES) {
		return -EINVAL;
	}
	if (proof->old_tree_size == 0U) {
		ret = pqcp_fleet_transparency_empty_root(hash, empty);
		if (ret != 0) {
			return ret;
		}
		return proof->node_count == 0U &&
		       digest_equal(empty, proof->old_root) ? 0 :
		       -EKEYREJECTED;
	}
	if (proof->old_tree_size == proof->new_tree_size) {
		return proof->node_count == 0U &&
		       digest_equal(
			       proof->old_root, proof->new_root) ? 0 :
		       -EKEYREJECTED;
	}
	if (proof->node_count == 0U) {
		return -EBADMSG;
	}

	old_index = proof->old_tree_size - 1U;
	new_index = proof->new_tree_size - 1U;
	while ((old_index & UINT64_C(1)) != 0U) {
		old_index >>= 1U;
		new_index >>= 1U;
	}
	if (old_index == 0U) {
		memcpy(old_calculated, proof->old_root,
		       sizeof(old_calculated));
		memcpy(new_calculated, proof->old_root,
		       sizeof(new_calculated));
	} else {
		memcpy(old_calculated, proof->nodes[0],
		       sizeof(old_calculated));
		memcpy(new_calculated, proof->nodes[0],
		       sizeof(new_calculated));
		proof_index = 1U;
	}

	for (; proof_index < proof->node_count; ++proof_index) {
		if (new_index == 0U) {
			return -EBADMSG;
		}
		if ((old_index & UINT64_C(1)) != 0U ||
		    old_index == new_index) {
			ret = pqcp_fleet_transparency_node_hash(
				hash, proof->nodes[proof_index],
				old_calculated, combined);
			if (ret != 0) {
				return ret;
			}
			memcpy(old_calculated, combined,
			       sizeof(old_calculated));
			ret = pqcp_fleet_transparency_node_hash(
				hash, proof->nodes[proof_index],
				new_calculated, combined);
			if (ret != 0) {
				return ret;
			}
			memcpy(new_calculated, combined,
			       sizeof(new_calculated));
			while (old_index != 0U &&
			       (old_index & UINT64_C(1)) == 0U) {
				old_index >>= 1U;
				new_index >>= 1U;
			}
		} else {
			ret = pqcp_fleet_transparency_node_hash(
				hash, new_calculated,
				proof->nodes[proof_index], combined);
			if (ret != 0) {
				return ret;
			}
			memcpy(new_calculated, combined,
			       sizeof(new_calculated));
		}
		old_index >>= 1U;
		new_index >>= 1U;
	}

	if (new_index != 0U ||
	    !digest_equal(old_calculated, proof->old_root) ||
	    !digest_equal(new_calculated, proof->new_root)) {
		return -EKEYREJECTED;
	}
	return 0;
}
