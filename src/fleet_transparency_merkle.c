/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * RFC 9162-compatible domain-separated Merkle hashing.
 */

#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_transparency.h>

static bool hash_valid(
	const struct pqcp_fleet_transparency_hash_ops *hash)
{
	return hash != NULL && hash->digest != NULL;
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

int pqcp_fleet_transparency_empty_root(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	if (!hash_valid(hash) || output == NULL) {
		return -EINVAL;
	}
	return hash->digest(hash->context, NULL, 0U, output);
}

int pqcp_fleet_transparency_leaf_hash(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t *leaf,
	size_t leaf_length,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	static const uint8_t domain = 0x00U;
	const struct pqcp_fleet_transparency_part parts[] = {
		{
			.data = &domain,
			.length = sizeof(domain),
		},
		{
			.data = leaf,
			.length = leaf_length,
		},
	};

	if (!hash_valid(hash) ||
	    (leaf == NULL && leaf_length != 0U) ||
	    output == NULL) {
		return -EINVAL;
	}
	return hash->digest(
		hash->context, parts,
		sizeof(parts) / sizeof(parts[0]), output);
}

int pqcp_fleet_transparency_node_hash(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t left[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	static const uint8_t domain = 0x01U;
	const struct pqcp_fleet_transparency_part parts[] = {
		{
			.data = &domain,
			.length = sizeof(domain),
		},
		{
			.data = left,
			.length = PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES,
		},
		{
			.data = right,
			.length = PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES,
		},
	};

	if (!hash_valid(hash) || left == NULL ||
	    right == NULL || output == NULL) {
		return -EINVAL;
	}
	return hash->digest(
		hash->context, parts,
		sizeof(parts) / sizeof(parts[0]), output);
}

static int root_range(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t (*leaf_hashes)
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	size_t start,
	size_t count,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	uint8_t left[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t right[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t split;
	int ret;

	if (count == 1U) {
		for (size_t index = 0U;
		     index < PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES;
		     ++index) {
			output[index] = leaf_hashes[start][index];
		}
		return 0;
	}

	split = largest_power_of_two_less_than(count);
	ret = root_range(hash, leaf_hashes, start, split, left);
	if (ret != 0) {
		return ret;
	}
	ret = root_range(
		hash, leaf_hashes, start + split,
		count - split, right);
	if (ret != 0) {
		return ret;
	}
	return pqcp_fleet_transparency_node_hash(
		hash, left, right, output);
}

int pqcp_fleet_transparency_root_from_hashes(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t (*leaf_hashes)
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	size_t leaf_count,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	if (!hash_valid(hash) || output == NULL ||
	    (leaf_hashes == NULL && leaf_count != 0U)) {
		return -EINVAL;
	}
	if (leaf_count == 0U) {
		return pqcp_fleet_transparency_empty_root(hash, output);
	}
	return root_range(hash, leaf_hashes, 0U, leaf_count, output);
}
