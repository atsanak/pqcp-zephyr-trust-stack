/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free fleet state snapshot and delta synchronization.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_snapshot_sync.h>
#include <pqcp_zephyr/runtime.h>

#include "runtime_internal.h"

#define STATE_CANONICAL_FLAG_MASK \
	(PQCP_FLEET_STATE_LEAF_TOMBSTONE | \
	 PQCP_FLEET_STATE_LEAF_CRITICAL | \
	 PQCP_FLEET_STATE_LEAF_CONFIDENTIAL | \
	 PQCP_FLEET_STATE_LEAF_IMMUTABLE | \
	 PQCP_FLEET_STATE_LEAF_OFFLINE_VALID)
#define STATE_LEAF_DIGEST_BODY_BYTES 256U
#define STATE_NODE_DIGEST_BODY_BYTES 128U
#define STATE_MANIFEST_DIGEST_BODY_BYTES 256U
#define STATE_RANGE_DIGEST_BODY_BYTES 256U
#define STATE_SNAPSHOT_DIGEST_BODY_BYTES 384U

static bool state_domain_valid(enum pqcp_fleet_state_domain domain)
{
	return domain > PQCP_FLEET_STATE_DOMAIN_NONE &&
	       domain < PQCP_FLEET_STATE_DOMAIN_COUNT;
}

static bool snapshot_mode_valid(
	enum pqcp_fleet_snapshot_mode mode)
{
	return mode == PQCP_FLEET_SNAPSHOT_MODE_FULL ||
	       mode == PQCP_FLEET_SNAPSHOT_MODE_DELTA;
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

	if (result == NULL || alignment == 0U) {
		return -EINVAL;
	}
	remainder = value % alignment;
	if (remainder == 0U) {
		*result = value;
		return 0;
	}
	return size_add(value, alignment - remainder, result);
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

static uint32_t bitmap_count(
	const uint8_t bitmap[PQCP_FLEET_STATE_CHUNK_BITMAP_BYTES],
	uint32_t bits)
{
	uint32_t count = 0U;

	for (uint32_t index = 0U; index < bits; ++index) {
		if (bit_test(bitmap, index)) {
			count++;
		}
	}
	return count;
}

static bool bitmap_tail_clear(
	const uint8_t bitmap[PQCP_FLEET_STATE_CHUNK_BITMAP_BYTES],
	uint32_t bits)
{
	for (uint32_t index = bits;
	     index < PQCP_FLEET_STATE_MAX_CHUNKS; ++index) {
		if (bit_test(bitmap, index)) {
			return false;
		}
	}
	return true;
}

static bool sync_ready(
	const struct pqcp_fleet_snapshot_sync *sync)
{
	if (sync == NULL || !sync->initialized ||
	    sync->active_bank > 1U ||
	    sync->rollback_floor_generation == 0U) {
		return false;
	}
	for (size_t index = 0U; index < 2U; ++index) {
		const struct pqcp_fleet_state_bank *bank =
			&sync->banks[index];

		if (bank->leaves == NULL ||
		    bank->leaf_capacity == 0U ||
		    bank->value_arena == NULL ||
		    bank->value_arena_capacity == 0U ||
		    bank->value_alignment == 0U ||
		    bank->value_alignment >
			    bank->value_arena_capacity ||
		    bank->leaf_count > bank->leaf_capacity) {
			return false;
		}
	}
	return true;
}

static struct pqcp_fleet_state_bank *active_bank(
	struct pqcp_fleet_snapshot_sync *sync)
{
	return &sync->banks[sync->active_bank];
}

static const struct pqcp_fleet_state_bank *active_bank_const(
	const struct pqcp_fleet_snapshot_sync *sync)
{
	return &sync->banks[sync->active_bank];
}

static struct pqcp_fleet_state_bank *staging_bank(
	struct pqcp_fleet_snapshot_sync *sync)
{
	return &sync->banks[sync->active_bank ^ 1U];
}

static const struct pqcp_fleet_state_bank *staging_bank_const(
	const struct pqcp_fleet_snapshot_sync *sync)
{
	return &sync->banks[sync->active_bank ^ 1U];
}

static int key_compare_raw(
	enum pqcp_fleet_state_domain left_domain,
	const uint8_t *left_key,
	size_t left_length,
	enum pqcp_fleet_state_domain right_domain,
	const uint8_t *right_key,
	size_t right_length)
{
	size_t common;
	int comparison;

	if (left_domain < right_domain) {
		return -1;
	}
	if (left_domain > right_domain) {
		return 1;
	}
	common = left_length < right_length ?
		left_length : right_length;
	comparison = common == 0U ?
		0 : memcmp(left_key, right_key, common);
	if (comparison != 0) {
		return comparison < 0 ? -1 : 1;
	}
	if (left_length < right_length) {
		return -1;
	}
	if (left_length > right_length) {
		return 1;
	}
	return 0;
}

static int leaf_key_compare(
	const struct pqcp_fleet_state_leaf *left,
	const struct pqcp_fleet_state_leaf *right)
{
	return key_compare_raw(
		left->domain, left->key, left->key_length,
		right->domain, right->key, right->key_length);
}

static int summary_key_compare(
	const struct pqcp_fleet_state_leaf_summary *left,
	const struct pqcp_fleet_state_leaf_summary *right)
{
	return key_compare_raw(
		left->domain, left->key, left->key_length,
		right->domain, right->key, right->key_length);
}

static int leaf_summary_key_compare(
	const struct pqcp_fleet_state_leaf *left,
	const struct pqcp_fleet_state_leaf_summary *right)
{
	return key_compare_raw(
		left->domain, left->key, left->key_length,
		right->domain, right->key, right->key_length);
}

static size_t leaf_lower_bound(
	const struct pqcp_fleet_state_bank *bank,
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length,
	bool *found)
{
	size_t low = 0U;
	size_t high = bank->leaf_count;

	while (low < high) {
		size_t middle = low + (high - low) / 2U;
		const struct pqcp_fleet_state_leaf *leaf =
			&bank->leaves[middle];
		int comparison = key_compare_raw(
			leaf->domain, leaf->key,
			leaf->key_length,
			domain, key, key_length);

		if (comparison < 0) {
			low = middle + 1U;
		} else {
			high = middle;
		}
	}
	if (found != NULL) {
		*found = low < bank->leaf_count &&
			key_compare_raw(
				bank->leaves[low].domain,
				bank->leaves[low].key,
				bank->leaves[low].key_length,
				domain, key, key_length) == 0;
	}
	return low;
}

static int empty_value_digest(
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	return pqcp_runtime_internal_sha256(NULL, 0U, digest);
}

static uint32_t canonical_flags(uint32_t flags)
{
	return flags & STATE_CANONICAL_FLAG_MASK;
}

static int leaf_digest_compute(
	const struct pqcp_fleet_state_leaf_descriptor *descriptor,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[STATE_LEAF_DIGEST_BODY_BYTES];
	size_t offset = 0U;
	int ret;

	if (descriptor == NULL || digest == NULL ||
	    descriptor->key_length == 0U ||
	    descriptor->key_length >
		    PQCP_FLEET_STATE_KEY_MAX_BYTES) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-FLEET-STATE-LEAF-V1", 24U);
	offset += 24U;
	write_u32(body, &offset, descriptor->schema_version);
	write_u32(body, &offset, (uint32_t)descriptor->domain);
	write_u32(
		body, &offset,
		canonical_flags(descriptor->flags));
	write_u64(body, &offset, descriptor->revision);
	write_u64(body, &offset, descriptor->updated_at_ms);
	write_u64(body, &offset, descriptor->expires_at_ms);
	write_u32(body, &offset, descriptor->key_length);
	write_size(body, &offset, descriptor->value_length);
	body[offset++] = (uint8_t)descriptor->key_length;
	memcpy(body + offset, descriptor->key,
	       descriptor->key_length);
	offset += descriptor->key_length;
	memcpy(body + offset, descriptor->value_digest,
	       sizeof(descriptor->value_digest));
	offset += sizeof(descriptor->value_digest);
	if (offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static void descriptor_from_leaf(
	const struct pqcp_fleet_state_leaf *leaf,
	struct pqcp_fleet_state_leaf_descriptor *descriptor)
{
	memset(descriptor, 0, sizeof(*descriptor));
	descriptor->schema_version =
		PQCP_FLEET_SNAPSHOT_SYNC_SCHEMA_VERSION;
	descriptor->domain = leaf->domain;
	descriptor->flags = canonical_flags(leaf->flags);
	descriptor->revision = leaf->revision;
	descriptor->updated_at_ms = leaf->updated_at_ms;
	descriptor->expires_at_ms = leaf->expires_at_ms;
	descriptor->key_length = leaf->key_length;
	descriptor->value_length = leaf->value_length;
	descriptor->chunk_size = leaf->chunk_size;
	descriptor->chunk_count = leaf->chunk_count;
	memcpy(descriptor->key, leaf->key,
	       leaf->key_length);
	memcpy(descriptor->value_digest,
	       leaf->value_digest,
	       sizeof(descriptor->value_digest));
	memcpy(descriptor->leaf_digest,
	       leaf->leaf_digest,
	       sizeof(descriptor->leaf_digest));
}

static int descriptor_chunk_geometry(
	size_t value_length,
	size_t chunk_size,
	uint32_t *chunk_count)
{
	size_t count;

	if (chunk_count == NULL) {
		return -EINVAL;
	}
	if (value_length == 0U) {
		if (chunk_size != 0U) {
			return -EINVAL;
		}
		*chunk_count = 0U;
		return 0;
	}
	if (chunk_size == 0U ||
	    chunk_size > value_length) {
		return -EINVAL;
	}
	count = value_length / chunk_size;
	if (value_length % chunk_size != 0U) {
		if (count == SIZE_MAX) {
			return -EOVERFLOW;
		}
		count++;
	}
	if (count == 0U ||
	    count > PQCP_FLEET_STATE_MAX_CHUNKS ||
	    count > UINT32_MAX) {
		return -E2BIG;
	}
	*chunk_count = (uint32_t)count;
	return 0;
}

int pqcp_fleet_state_leaf_descriptor_verify(
	const struct pqcp_fleet_state_leaf_descriptor *descriptor)
{
	uint8_t computed[PQCP_FLEET_DIGEST_BYTES];
	uint8_t empty[PQCP_FLEET_DIGEST_BYTES];
	uint32_t chunk_count;
	int ret;

	if (descriptor == NULL ||
	    descriptor->schema_version !=
		    PQCP_FLEET_SNAPSHOT_SYNC_SCHEMA_VERSION ||
	    !state_domain_valid(descriptor->domain) ||
	    (descriptor->flags &
	     ~STATE_CANONICAL_FLAG_MASK) != 0U ||
	    descriptor->revision == 0U ||
	    descriptor->updated_at_ms == 0U ||
	    (descriptor->expires_at_ms != 0U &&
	     descriptor->expires_at_ms <=
		     descriptor->updated_at_ms) ||
	    descriptor->key_length == 0U ||
	    descriptor->key_length >
		    PQCP_FLEET_STATE_KEY_MAX_BYTES ||
	    digest_is_zero(descriptor->value_digest) ||
	    digest_is_zero(descriptor->leaf_digest)) {
		return -EINVAL;
	}
	ret = descriptor_chunk_geometry(
		descriptor->value_length,
		descriptor->chunk_size, &chunk_count);
	if (ret != 0 ||
	    chunk_count != descriptor->chunk_count) {
		return ret != 0 ? ret : -EBADMSG;
	}
	if ((descriptor->flags &
	     PQCP_FLEET_STATE_LEAF_TOMBSTONE) != 0U) {
		if (descriptor->value_length != 0U ||
		    descriptor->chunk_size != 0U ||
		    descriptor->chunk_count != 0U) {
			return -EINVAL;
		}
		ret = empty_value_digest(empty);
		if (ret != 0 ||
		    !digest_equal(
			    empty,
			    descriptor->value_digest)) {
			pqcp_runtime_secure_zero(
				empty, sizeof(empty));
			return ret != 0 ? ret : -EBADMSG;
		}
		pqcp_runtime_secure_zero(empty, sizeof(empty));
	} else if (descriptor->value_length == 0U) {
		return -EINVAL;
	}
	ret = leaf_digest_compute(descriptor, computed);
	if (ret == 0 &&
	    !digest_equal(
		    computed, descriptor->leaf_digest)) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(computed, sizeof(computed));
	return ret;
}

static int node_digest(
	uint32_t level,
	const uint8_t left[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_DIGEST_BYTES],
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[STATE_NODE_DIGEST_BODY_BYTES];
	size_t offset = 0U;
	int ret;

	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-FLEET-STATE-NODE-V1", 24U);
	offset += 24U;
	write_u32(body, &offset, level);
	memcpy(body + offset, left, PQCP_FLEET_DIGEST_BYTES);
	offset += PQCP_FLEET_DIGEST_BYTES;
	memcpy(body + offset, right, PQCP_FLEET_DIGEST_BYTES);
	offset += PQCP_FLEET_DIGEST_BYTES;
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int bag_digest(
	uint32_t level,
	const uint8_t left[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_DIGEST_BYTES],
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[STATE_NODE_DIGEST_BODY_BYTES];
	size_t offset = 0U;
	int ret;

	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-FLEET-STATE-BAG-V1", 23U);
	offset += 23U;
	write_u32(body, &offset, level);
	memcpy(body + offset, left, PQCP_FLEET_DIGEST_BYTES);
	offset += PQCP_FLEET_DIGEST_BYTES;
	memcpy(body + offset, right, PQCP_FLEET_DIGEST_BYTES);
	offset += PQCP_FLEET_DIGEST_BYTES;
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int merkle_root_from_digests(
	const struct pqcp_fleet_state_leaf *leaves,
	size_t first,
	size_t count,
	bool range_root,
	uint8_t root[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t peaks[PQCP_FLEET_STATE_MERKLE_LEVELS]
		     [PQCP_FLEET_DIGEST_BYTES];
	bool occupied[PQCP_FLEET_STATE_MERKLE_LEVELS];
	uint8_t node[PQCP_FLEET_DIGEST_BYTES];
	uint8_t combined[PQCP_FLEET_DIGEST_BYTES];
	uint8_t body[STATE_NODE_DIGEST_BODY_BYTES];
	bool accumulator_set = false;
	size_t offset = 0U;
	int ret = 0;

	if ((count != 0U && leaves == NULL) || root == NULL ||
	    first > SIZE_MAX - count) {
		return -EINVAL;
	}
	memset(peaks, 0, sizeof(peaks));
	memset(occupied, 0, sizeof(occupied));
	for (size_t index = 0U; index < count; ++index) {
		size_t absolute = first + index;

		if (!leaves[absolute].occupied ||
		    digest_is_zero(leaves[absolute].leaf_digest)) {
			ret = -EBADMSG;
			goto done;
		}
		memcpy(node, leaves[absolute].leaf_digest,
		       sizeof(node));
		for (uint32_t level = 0U;
		     level < PQCP_FLEET_STATE_MERKLE_LEVELS;
		     ++level) {
			if (!occupied[level]) {
				memcpy(peaks[level], node,
				       sizeof(node));
				occupied[level] = true;
				break;
			}
			ret = node_digest(
				level, peaks[level], node,
				combined);
			if (ret != 0) {
				goto done;
			}
			occupied[level] = false;
			memset(peaks[level], 0,
			       sizeof(peaks[level]));
			memcpy(node, combined, sizeof(node));
			if (level ==
			    PQCP_FLEET_STATE_MERKLE_LEVELS - 1U) {
				ret = -EOVERFLOW;
				goto done;
			}
		}
	}
	for (int level =
		     (int)PQCP_FLEET_STATE_MERKLE_LEVELS - 1;
	     level >= 0; --level) {
		if (!occupied[level]) {
			continue;
		}
		if (!accumulator_set) {
			memcpy(node, peaks[level], sizeof(node));
			accumulator_set = true;
		} else {
			ret = bag_digest(
				(uint32_t)level,
				peaks[level], node, combined);
			if (ret != 0) {
				goto done;
			}
			memcpy(node, combined, sizeof(node));
		}
	}
	memset(body, 0, sizeof(body));
	if (range_root) {
		memcpy(body + offset,
		       "PQCP-FLEET-STATE-RANGE-ROOT-V1", 30U);
		offset += 30U;
		write_size(body, &offset, first);
	} else {
		memcpy(body + offset,
		       "PQCP-FLEET-STATE-ROOT-V1", 24U);
		offset += 24U;
	}
	write_size(body, &offset, count);
	if (accumulator_set) {
		memcpy(body + offset, node, sizeof(node));
		offset += sizeof(node);
	}
	ret = pqcp_runtime_internal_sha256(body, offset, root);

done:
	pqcp_runtime_secure_zero(peaks, sizeof(peaks));
	pqcp_runtime_secure_zero(occupied, sizeof(occupied));
	pqcp_runtime_secure_zero(node, sizeof(node));
	pqcp_runtime_secure_zero(combined, sizeof(combined));
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int bank_root_compute(
	const struct pqcp_fleet_state_bank *bank,
	uint8_t root[PQCP_FLEET_DIGEST_BYTES])
{
	return merkle_root_from_digests(
		bank->leaves, 0U, bank->leaf_count,
		false, root);
}

static int key_digest(
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[PQCP_FLEET_STATE_KEY_MAX_BYTES + 16U];
	size_t offset = 0U;
	int ret;

	if (!state_domain_valid(domain) || key == NULL ||
	    key_length == 0U ||
	    key_length > PQCP_FLEET_STATE_KEY_MAX_BYTES ||
	    digest == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-KEY-V1", 11U);
	offset += 11U;
	write_u32(body, &offset, (uint32_t)domain);
	body[offset++] = (uint8_t)key_length;
	memcpy(body + offset, key, key_length);
	offset += key_length;
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int manifest_digest_compute(
	const struct pqcp_fleet_snapshot_manifest *manifest,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[STATE_MANIFEST_DIGEST_BODY_BYTES];
	size_t offset = 0U;
	int ret;

	if (manifest == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-FLEET-MANIFEST-V1", 22U);
	offset += 22U;
	write_u32(body, &offset, manifest->schema_version);
	write_u32(body, &offset, manifest->flags);
	write_u64(body, &offset, manifest->generation);
	write_u64(body, &offset, manifest->base_generation);
	write_u64(body, &offset, manifest->created_at_ms);
	write_u64(body, &offset, manifest->expires_at_ms);
	write_size(body, &offset, manifest->leaf_count);
	write_size(body, &offset, manifest->tombstone_count);
	write_size(body, &offset, manifest->value_bytes);
	write_size(body, &offset, manifest->maximum_chunk_size);
	memcpy(body + offset, manifest->root,
	       sizeof(manifest->root));
	offset += sizeof(manifest->root);
	memcpy(body + offset, manifest->base_root,
	       sizeof(manifest->base_root));
	offset += sizeof(manifest->base_root);
	if (offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_fleet_snapshot_manifest_verify(
	const struct pqcp_fleet_snapshot_manifest *manifest)
{
	uint8_t computed[PQCP_FLEET_DIGEST_BYTES];
	const uint32_t valid_flags =
		PQCP_FLEET_SNAPSHOT_MANIFEST_FULL |
		PQCP_FLEET_SNAPSHOT_MANIFEST_DELTA |
		PQCP_FLEET_SNAPSHOT_MANIFEST_OFFLINE |
		PQCP_FLEET_SNAPSHOT_MANIFEST_SIGNED |
		PQCP_FLEET_SNAPSHOT_MANIFEST_CONTAINS_TOMBSTONES;
	bool full;
	bool delta;
	int ret;

	if (manifest == NULL ||
	    manifest->schema_version !=
		    PQCP_FLEET_STATE_MANIFEST_SCHEMA_VERSION ||
	    (manifest->flags & ~valid_flags) != 0U ||
	    manifest->generation == 0U ||
	    manifest->created_at_ms == 0U ||
	    (manifest->expires_at_ms != 0U &&
	     manifest->expires_at_ms <=
		     manifest->created_at_ms) ||
	    manifest->tombstone_count >
		    manifest->leaf_count ||
	    manifest->maximum_chunk_size == 0U ||
	    digest_is_zero(manifest->root) ||
	    digest_is_zero(manifest->manifest_digest)) {
		return -EINVAL;
	}
	full = (manifest->flags &
		PQCP_FLEET_SNAPSHOT_MANIFEST_FULL) != 0U;
	delta = (manifest->flags &
		 PQCP_FLEET_SNAPSHOT_MANIFEST_DELTA) != 0U;
	if (full == delta) {
		return -EINVAL;
	}
	if (full) {
		if (manifest->base_generation != 0U ||
		    !digest_is_zero(manifest->base_root)) {
			return -EINVAL;
		}
	} else if (manifest->base_generation == 0U ||
		   manifest->base_generation >=
			   manifest->generation ||
		   digest_is_zero(manifest->base_root)) {
		return -EINVAL;
	}
	if (((manifest->flags &
	      PQCP_FLEET_SNAPSHOT_MANIFEST_CONTAINS_TOMBSTONES) != 0U) !=
	    (manifest->tombstone_count != 0U)) {
		return -EBADMSG;
	}
	ret = manifest_digest_compute(manifest, computed);
	if (ret == 0 &&
	    !digest_equal(
		    computed, manifest->manifest_digest)) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(computed, sizeof(computed));
	return ret;
}

static void bank_clear(struct pqcp_fleet_state_bank *bank)
{
	size_t leaf_bytes;

	if (size_multiply(
		    bank->leaf_capacity,
		    sizeof(*bank->leaves),
		    &leaf_bytes) == 0) {
		pqcp_runtime_secure_zero(
			bank->leaves, leaf_bytes);
	}
	pqcp_runtime_secure_zero(
		bank->value_arena,
		bank->value_arena_capacity);
	bank->leaf_count = 0U;
	bank->value_bytes = 0U;
	bank->generation = 0U;
	memset(bank->root, 0, sizeof(bank->root));
}

static bool value_extents_overlap(
	size_t left_offset,
	size_t left_length,
	size_t right_offset,
	size_t right_length)
{
	size_t left_end;
	size_t right_end;

	if (left_length == 0U || right_length == 0U) {
		return false;
	}
	if (size_add(left_offset, left_length, &left_end) != 0 ||
	    size_add(right_offset, right_length, &right_end) != 0) {
		return true;
	}
	return left_offset < right_end &&
	       right_offset < left_end;
}

static int bank_find_extent(
	const struct pqcp_fleet_state_bank *bank,
	size_t required,
	size_t excluded_index,
	size_t *offset)
{
	size_t cursor = 0U;

	if (required == 0U || offset == NULL ||
	    required > bank->value_arena_capacity) {
		return -EINVAL;
	}
	for (;;) {
		size_t nearest_start = SIZE_MAX;
		size_t nearest_end = 0U;
		bool cursor_inside = false;

		for (size_t index = 0U;
		     index < bank->leaf_count; ++index) {
			const struct pqcp_fleet_state_leaf *leaf =
				&bank->leaves[index];
			size_t end;

			if (index == excluded_index ||
			    !leaf->occupied ||
			    leaf->value_capacity == 0U ||
			    size_add(
				    leaf->value_offset,
				    leaf->value_capacity,
				    &end) != 0) {
				continue;
			}
			if (leaf->value_offset <= cursor &&
			    cursor < end) {
				if (!cursor_inside ||
				    end > nearest_end) {
					nearest_end = end;
					cursor_inside = true;
				}
			} else if (!cursor_inside &&
				   leaf->value_offset >= cursor &&
				   leaf->value_offset <
					   nearest_start) {
				nearest_start =
					leaf->value_offset;
				nearest_end = end;
			}
		}
		if (cursor_inside) {
			if (align_up(
				    nearest_end,
				    bank->value_alignment,
				    &cursor) != 0 ||
			    cursor > bank->value_arena_capacity) {
				return -ENOSPC;
			}
			continue;
		}
		if (nearest_start == SIZE_MAX) {
			if (cursor <= bank->value_arena_capacity &&
			    required <=
				    bank->value_arena_capacity -
					    cursor) {
				*offset = cursor;
				return 0;
			}
			return -ENOSPC;
		}
		if (required <= nearest_start - cursor) {
			*offset = cursor;
			return 0;
		}
		if (align_up(
			    nearest_end,
			    bank->value_alignment,
			    &cursor) != 0 ||
		    cursor > bank->value_arena_capacity) {
			return -ENOSPC;
		}
	}
}

static int bank_copy(
	const struct pqcp_fleet_state_bank *source,
	struct pqcp_fleet_state_bank *destination)
{
	size_t cursor = 0U;

	if (source->leaf_count >
		    destination->leaf_capacity ||
	    source->value_bytes >
		    destination->value_arena_capacity) {
		return -ENOSPC;
	}
	bank_clear(destination);
	for (size_t index = 0U;
	     index < source->leaf_count; ++index) {
		const struct pqcp_fleet_state_leaf *input =
			&source->leaves[index];
		struct pqcp_fleet_state_leaf *output =
			&destination->leaves[index];
		size_t capacity = 0U;

		*output = *input;
		if (input->value_length != 0U) {
			if (align_up(
				    input->value_length,
				    destination->value_alignment,
				    &capacity) != 0 ||
			    align_up(
				    cursor,
				    destination->value_alignment,
				    &cursor) != 0 ||
			    cursor >
				    destination->value_arena_capacity ||
			    capacity >
				    destination->value_arena_capacity -
					    cursor) {
				bank_clear(destination);
				return -ENOSPC;
			}
			memcpy(
				destination->value_arena + cursor,
				source->value_arena +
					input->value_offset,
				input->value_length);
			if (capacity > input->value_length) {
				memset(
					destination->value_arena +
						cursor +
						input->value_length,
					0,
					capacity -
						input->value_length);
			}
			output->value_offset = cursor;
			output->value_capacity = capacity;
			cursor += capacity;
		} else {
			output->value_offset = 0U;
			output->value_capacity = 0U;
		}
	}
	destination->leaf_count = source->leaf_count;
	destination->value_bytes = source->value_bytes;
	destination->generation = source->generation;
	memcpy(destination->root, source->root,
	       sizeof(destination->root));
	return 0;
}

static size_t bank_tombstone_count(
	const struct pqcp_fleet_state_bank *bank)
{
	size_t count = 0U;

	for (size_t index = 0U;
	     index < bank->leaf_count; ++index) {
		if ((bank->leaves[index].flags &
		     PQCP_FLEET_STATE_LEAF_TOMBSTONE) != 0U) {
			count++;
		}
	}
	return count;
}

static size_t bank_maximum_chunk_size(
	const struct pqcp_fleet_state_bank *bank)
{
	size_t maximum = 1U;

	for (size_t index = 0U;
	     index < bank->leaf_count; ++index) {
		if (bank->leaves[index].chunk_size > maximum) {
			maximum = bank->leaves[index].chunk_size;
		}
	}
	return maximum;
}

static size_t bank_verified_count(
	const struct pqcp_fleet_state_bank *bank)
{
	size_t count = 0U;

	for (size_t index = 0U;
	     index < bank->leaf_count; ++index) {
		if ((bank->leaves[index].flags &
		     PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) != 0U) {
			count++;
		}
	}
	return count;
}

static int history_append_locked(
	struct pqcp_fleet_snapshot_sync *sync,
	const struct pqcp_fleet_snapshot_manifest *manifest,
	uint64_t committed_at_ms)
{
	struct pqcp_fleet_state_history_entry *entry;

	if (manifest == NULL || committed_at_ms == 0U) {
		return -EINVAL;
	}
	entry = &sync->history[sync->history_head];
	memset(entry, 0, sizeof(*entry));
	entry->generation = manifest->generation;
	entry->committed_at_ms = committed_at_ms;
	entry->leaf_count = manifest->leaf_count;
	memcpy(entry->root, manifest->root,
	       sizeof(entry->root));
	memcpy(entry->manifest_digest,
	       manifest->manifest_digest,
	       sizeof(entry->manifest_digest));
	entry->occupied = true;
	sync->history_head =
		(sync->history_head + 1U) %
		PQCP_FLEET_STATE_HISTORY_CAPACITY;
	if (sync->history_count <
	    PQCP_FLEET_STATE_HISTORY_CAPACITY) {
		sync->history_count++;
	}
	return 0;
}

static int manifest_build(
	const struct pqcp_fleet_state_bank *bank,
	uint32_t flags,
	uint64_t generation,
	uint64_t base_generation,
	const uint8_t base_root[PQCP_FLEET_DIGEST_BYTES],
	uint64_t created_at_ms,
	uint64_t expires_at_ms,
	struct pqcp_fleet_snapshot_manifest *manifest)
{
	int ret;

	if (bank == NULL || manifest == NULL ||
	    generation == 0U || created_at_ms == 0U ||
	    (expires_at_ms != 0U &&
	     expires_at_ms <= created_at_ms)) {
		return -EINVAL;
	}
	memset(manifest, 0, sizeof(*manifest));
	manifest->schema_version =
		PQCP_FLEET_STATE_MANIFEST_SCHEMA_VERSION;
	manifest->flags = flags;
	manifest->generation = generation;
	manifest->base_generation = base_generation;
	manifest->created_at_ms = created_at_ms;
	manifest->expires_at_ms = expires_at_ms;
	manifest->leaf_count = bank->leaf_count;
	manifest->tombstone_count =
		bank_tombstone_count(bank);
	manifest->value_bytes = bank->value_bytes;
	manifest->maximum_chunk_size =
		bank_maximum_chunk_size(bank);
	memcpy(manifest->root, bank->root,
	       sizeof(manifest->root));
	if (base_root != NULL) {
		memcpy(manifest->base_root, base_root,
		       sizeof(manifest->base_root));
	}
	if (manifest->tombstone_count != 0U) {
		manifest->flags |=
			PQCP_FLEET_SNAPSHOT_MANIFEST_CONTAINS_TOMBSTONES;
	}
	ret = manifest_digest_compute(
		manifest, manifest->manifest_digest);
	return ret;
}

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
	uint64_t created_at_ms)
{
	size_t bank_a_leaf_bytes;
	size_t bank_b_leaf_bytes;
	int ret;

	if (sync == NULL ||
	    bank_a_leaves == NULL ||
	    bank_a_leaf_capacity == 0U ||
	    bank_a_value_arena == NULL ||
	    bank_a_value_arena_capacity == 0U ||
	    bank_b_leaves == NULL ||
	    bank_b_leaf_capacity == 0U ||
	    bank_b_value_arena == NULL ||
	    bank_b_value_arena_capacity == 0U ||
	    value_alignment == 0U ||
	    value_alignment > bank_a_value_arena_capacity ||
	    value_alignment > bank_b_value_arena_capacity ||
	    initial_generation == 0U ||
	    created_at_ms == 0U ||
	    size_multiply(
		    bank_a_leaf_capacity,
		    sizeof(*bank_a_leaves),
		    &bank_a_leaf_bytes) != 0 ||
	    size_multiply(
		    bank_b_leaf_capacity,
		    sizeof(*bank_b_leaves),
		    &bank_b_leaf_bytes) != 0) {
		return -EINVAL;
	}
	memset(sync, 0, sizeof(*sync));
	memset(bank_a_leaves, 0, bank_a_leaf_bytes);
	memset(bank_b_leaves, 0, bank_b_leaf_bytes);
	pqcp_runtime_secure_zero(
		bank_a_value_arena,
		bank_a_value_arena_capacity);
	pqcp_runtime_secure_zero(
		bank_b_value_arena,
		bank_b_value_arena_capacity);
	sync->banks[0].leaves = bank_a_leaves;
	sync->banks[0].leaf_capacity =
		bank_a_leaf_capacity;
	sync->banks[0].value_arena =
		bank_a_value_arena;
	sync->banks[0].value_arena_capacity =
		bank_a_value_arena_capacity;
	sync->banks[0].value_alignment = value_alignment;
	sync->banks[1].leaves = bank_b_leaves;
	sync->banks[1].leaf_capacity =
		bank_b_leaf_capacity;
	sync->banks[1].value_arena =
		bank_b_value_arena;
	sync->banks[1].value_arena_capacity =
		bank_b_value_arena_capacity;
	sync->banks[1].value_alignment = value_alignment;
	sync->active_bank = 0U;
	sync->banks[0].generation = initial_generation;
	ret = bank_root_compute(
		&sync->banks[0], sync->banks[0].root);
	if (ret != 0) {
		return ret;
	}
	ret = manifest_build(
		&sync->banks[0],
		PQCP_FLEET_SNAPSHOT_MANIFEST_FULL,
		initial_generation, 0U, NULL,
		created_at_ms, 0U,
		&sync->current_manifest);
	if (ret != 0) {
		return ret;
	}
	sync->rollback_floor_generation =
		initial_generation;
	k_mutex_init(&sync->lock);
	sync->initialized = true;
	ret = history_append_locked(
		sync, &sync->current_manifest,
		created_at_ms);
	if (ret != 0) {
		sync->initialized = false;
		return ret;
	}
	return 0;
}

int pqcp_fleet_snapshot_sync_manifest(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_snapshot_manifest *manifest)
{
	int ret;

	if (!sync_ready(sync) || manifest == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	*manifest = sync->current_manifest;
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

int pqcp_fleet_snapshot_sync_leaf_summary(
	struct pqcp_fleet_snapshot_sync *sync,
	size_t first_index,
	struct pqcp_fleet_state_leaf_summary *summaries,
	size_t summary_capacity,
	size_t *summary_count)
{
	const struct pqcp_fleet_state_bank *bank;
	size_t count;
	int ret;

	if (!sync_ready(sync) ||
	    (summary_capacity != 0U && summaries == NULL) ||
	    summary_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	bank = active_bank_const(sync);
	if (first_index > bank->leaf_count) {
		(void)k_mutex_unlock(&sync->lock);
		return -ERANGE;
	}
	count = bank->leaf_count - first_index;
	if (count > summary_capacity) {
		count = summary_capacity;
	}
	for (size_t index = 0U; index < count; ++index) {
		const struct pqcp_fleet_state_leaf *leaf =
			&bank->leaves[first_index + index];
		struct pqcp_fleet_state_leaf_summary *summary =
			&summaries[index];

		memset(summary, 0, sizeof(*summary));
		summary->domain = leaf->domain;
		summary->flags = canonical_flags(leaf->flags);
		summary->revision = leaf->revision;
		summary->key_length = leaf->key_length;
		memcpy(summary->key, leaf->key,
		       leaf->key_length);
		memcpy(summary->leaf_digest,
		       leaf->leaf_digest,
		       sizeof(summary->leaf_digest));
	}
	*summary_count = count;
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

int pqcp_fleet_snapshot_sync_lookup(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length,
	struct pqcp_fleet_state_leaf_descriptor *descriptor,
	size_t *leaf_index)
{
	const struct pqcp_fleet_state_bank *bank;
	size_t index;
	bool found;
	int ret;

	if (!sync_ready(sync) ||
	    !state_domain_valid(domain) ||
	    key == NULL || key_length == 0U ||
	    key_length > PQCP_FLEET_STATE_KEY_MAX_BYTES ||
	    descriptor == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	bank = active_bank_const(sync);
	index = leaf_lower_bound(
		bank, domain, key, key_length, &found);
	if (!found) {
		(void)k_mutex_unlock(&sync->lock);
		return -ENOENT;
	}
	descriptor_from_leaf(
		&bank->leaves[index], descriptor);
	if (leaf_index != NULL) {
		*leaf_index = index;
	}
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

int pqcp_fleet_snapshot_sync_read(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length,
	size_t offset,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	uint64_t now_ms)
{
	const struct pqcp_fleet_state_bank *bank;
	const struct pqcp_fleet_state_leaf *leaf;
	size_t index;
	size_t available;
	size_t copied;
	bool found;
	int ret;

	if (!sync_ready(sync) ||
	    !state_domain_valid(domain) ||
	    key == NULL || key_length == 0U ||
	    key_length > PQCP_FLEET_STATE_KEY_MAX_BYTES ||
	    output == NULL || output_capacity == 0U ||
	    output_length == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	bank = active_bank_const(sync);
	index = leaf_lower_bound(
		bank, domain, key, key_length, &found);
	if (!found) {
		(void)k_mutex_unlock(&sync->lock);
		return -ENOENT;
	}
	leaf = &bank->leaves[index];
	if ((leaf->flags &
	     PQCP_FLEET_STATE_LEAF_TOMBSTONE) != 0U) {
		(void)k_mutex_unlock(&sync->lock);
		return -ENOENT;
	}
	if ((leaf->flags &
	     PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) == 0U) {
		(void)k_mutex_unlock(&sync->lock);
		return -EKEYREJECTED;
	}
	if (leaf->expires_at_ms != 0U &&
	    now_ms >= leaf->expires_at_ms) {
		(void)k_mutex_unlock(&sync->lock);
		return -ESTALE;
	}
	if (offset > leaf->value_length) {
		(void)k_mutex_unlock(&sync->lock);
		return -ERANGE;
	}
	available = leaf->value_length - offset;
	copied = available < output_capacity ?
		available : output_capacity;
	memcpy(output,
	       bank->value_arena + leaf->value_offset + offset,
	       copied);
	*output_length = copied;
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

static int bank_remove_leaf_value(
	struct pqcp_fleet_state_bank *bank,
	size_t index)
{
	struct pqcp_fleet_state_leaf *leaf =
		&bank->leaves[index];

	if (leaf->value_length > bank->value_bytes) {
		return -EBADMSG;
	}
	if (leaf->value_capacity != 0U) {
		if (leaf->value_offset >
			    bank->value_arena_capacity ||
		    leaf->value_capacity >
			    bank->value_arena_capacity -
				    leaf->value_offset) {
			return -EBADMSG;
		}
		pqcp_runtime_secure_zero(
			bank->value_arena + leaf->value_offset,
			leaf->value_capacity);
	}
	bank->value_bytes -= leaf->value_length;
	return 0;
}

static int bank_insert_descriptor(
	struct pqcp_fleet_state_bank *bank,
	const struct pqcp_fleet_state_leaf_descriptor *descriptor,
	size_t *inserted_index,
	bool *already_complete)
{
	struct pqcp_fleet_state_leaf staged;
	struct pqcp_fleet_state_leaf *leaf;
	size_t index;
	size_t capacity = 0U;
	size_t offset = 0U;
	bool found;
	int ret;

	index = leaf_lower_bound(
		bank, descriptor->domain,
		descriptor->key, descriptor->key_length,
		&found);
	if (found) {
		leaf = &bank->leaves[index];
		if (descriptor->revision <
		    leaf->revision) {
			return -EKEYREJECTED;
		}
		if (descriptor->revision ==
		    leaf->revision) {
			if (digest_equal(
				    descriptor->leaf_digest,
				    leaf->leaf_digest) &&
			    (leaf->flags &
			     PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) !=
				    0U) {
				*inserted_index = index;
				*already_complete = true;
				return 0;
			}
			return -EKEYREJECTED;
		}
		if ((leaf->flags &
		     PQCP_FLEET_STATE_LEAF_IMMUTABLE) != 0U) {
			return -EPERM;
		}
	} else if (bank->leaf_count >=
		   bank->leaf_capacity) {
		return -ENOSPC;
	}
	if (descriptor->value_length != 0U) {
		ret = align_up(
			descriptor->value_length,
			bank->value_alignment, &capacity);
		if (ret != 0) {
			return ret;
		}
		if (found &&
		    capacity <=
			    bank->leaves[index].value_capacity) {
			offset =
				bank->leaves[index].value_offset;
			capacity =
				bank->leaves[index].value_capacity;
		} else {
			ret = bank_find_extent(
				bank, capacity,
				found ? index : SIZE_MAX,
				&offset);
			if (ret != 0) {
				return ret;
			}
		}
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version =
		PQCP_FLEET_SNAPSHOT_SYNC_SCHEMA_VERSION;
	staged.domain = descriptor->domain;
	staged.flags = canonical_flags(descriptor->flags) |
		PQCP_FLEET_STATE_LEAF_STAGED;
	staged.revision = descriptor->revision;
	staged.updated_at_ms = descriptor->updated_at_ms;
	staged.expires_at_ms = descriptor->expires_at_ms;
	staged.key_length = descriptor->key_length;
	staged.value_offset = offset;
	staged.value_capacity = capacity;
	staged.value_length = descriptor->value_length;
	staged.chunk_size = descriptor->chunk_size;
	staged.chunk_count = descriptor->chunk_count;
	memcpy(staged.key, descriptor->key,
	       descriptor->key_length);
	memcpy(staged.value_digest,
	       descriptor->value_digest,
	       sizeof(staged.value_digest));
	memcpy(staged.leaf_digest,
	       descriptor->leaf_digest,
	       sizeof(staged.leaf_digest));
	staged.occupied = true;
	if ((staged.flags &
	     PQCP_FLEET_STATE_LEAF_TOMBSTONE) != 0U) {
		staged.flags |=
			PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED;
	}
	if (found) {
		struct pqcp_fleet_state_leaf previous =
			bank->leaves[index];

		if (previous.value_offset != staged.value_offset ||
		    previous.value_capacity !=
			    staged.value_capacity) {
			ret = bank_remove_leaf_value(bank, index);
			if (ret != 0) {
				return ret;
			}
		} else if (previous.value_length >
			   bank->value_bytes) {
			return -EBADMSG;
		} else {
			bank->value_bytes -=
				previous.value_length;
			pqcp_runtime_secure_zero(
				bank->value_arena +
					previous.value_offset,
				previous.value_capacity);
		}
		bank->leaves[index] = staged;
	} else {
		if (index < bank->leaf_count) {
			memmove(
				&bank->leaves[index + 1U],
				&bank->leaves[index],
				(bank->leaf_count - index) *
					sizeof(bank->leaves[0]));
		}
		bank->leaves[index] = staged;
		bank->leaf_count++;
	}
	if (staged.value_capacity != 0U) {
		pqcp_runtime_secure_zero(
			bank->value_arena +
				staged.value_offset,
			staged.value_capacity);
	}
	*inserted_index = index;
	*already_complete =
		(staged.flags &
		 PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) != 0U;
	return 0;
}

static size_t leaf_chunk_length(
	const struct pqcp_fleet_state_leaf *leaf,
	uint32_t chunk_index)
{
	size_t offset;
	size_t remaining;

	if (leaf == NULL ||
	    chunk_index >= leaf->chunk_count ||
	    leaf->chunk_size == 0U ||
	    size_multiply(
		    (size_t)chunk_index,
		    leaf->chunk_size, &offset) != 0 ||
	    offset >= leaf->value_length) {
		return 0U;
	}
	remaining = leaf->value_length - offset;
	return remaining < leaf->chunk_size ?
		remaining : leaf->chunk_size;
}

static size_t leaf_received_bytes(
	const struct pqcp_fleet_state_leaf *leaf)
{
	size_t total = 0U;

	for (uint32_t index = 0U;
	     index < leaf->chunk_count; ++index) {
		if (bit_test(leaf->chunk_bitmap, index)) {
			size_t length =
				leaf_chunk_length(leaf, index);

			if (length > SIZE_MAX - total) {
				return SIZE_MAX;
			}
			total += length;
		}
	}
	return total;
}

static int bank_write_chunk(
	struct pqcp_fleet_state_bank *bank,
	size_t leaf_index,
	size_t offset,
	const uint8_t *data,
	size_t length,
	const uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES],
	bool *new_chunk)
{
	struct pqcp_fleet_state_leaf *leaf =
		&bank->leaves[leaf_index];
	uint8_t computed[PQCP_FLEET_DIGEST_BYTES];
	size_t chunk_index_size;
	size_t expected;
	size_t arena_offset;
	uint32_t chunk_index;
	int ret;

	if (data == NULL || length == 0U ||
	    (leaf->flags &
	     PQCP_FLEET_STATE_LEAF_TOMBSTONE) != 0U ||
	    (leaf->flags &
	     PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) != 0U ||
	    leaf->chunk_size == 0U ||
	    offset % leaf->chunk_size != 0U) {
		return -EINVAL;
	}
	chunk_index_size = offset / leaf->chunk_size;
	if (chunk_index_size > UINT32_MAX ||
	    chunk_index_size >= leaf->chunk_count) {
		return -ERANGE;
	}
	chunk_index = (uint32_t)chunk_index_size;
	expected = leaf_chunk_length(leaf, chunk_index);
	if (expected == 0U || length != expected ||
	    offset > leaf->value_length ||
	    length > leaf->value_length - offset ||
	    size_add(
		    leaf->value_offset, offset,
		    &arena_offset) != 0 ||
	    arena_offset > bank->value_arena_capacity ||
	    length >
		    bank->value_arena_capacity - arena_offset) {
		return -EMSGSIZE;
	}
	if (chunk_digest != NULL) {
		ret = pqcp_runtime_internal_sha256(
			data, length, computed);
		if (ret != 0 ||
		    !digest_equal(computed, chunk_digest)) {
			pqcp_runtime_secure_zero(
				computed, sizeof(computed));
			return ret != 0 ? ret : -EBADMSG;
		}
		pqcp_runtime_secure_zero(
			computed, sizeof(computed));
	}
	if (bit_test(leaf->chunk_bitmap, chunk_index)) {
		if (memcmp(
			    bank->value_arena + arena_offset,
			    data, length) != 0) {
			return -EBADMSG;
		}
		*new_chunk = false;
		return 0;
	}
	memcpy(bank->value_arena + arena_offset,
	       data, length);
	bit_set(leaf->chunk_bitmap, chunk_index);
	leaf->complete_chunks++;
	*new_chunk = true;
	return 0;
}

static int bank_finalize_leaf(
	struct pqcp_fleet_state_bank *bank,
	size_t index)
{
	struct pqcp_fleet_state_leaf *leaf =
		&bank->leaves[index];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if ((leaf->flags &
	     PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) != 0U) {
		return 0;
	}
	if ((leaf->flags &
	     PQCP_FLEET_STATE_LEAF_TOMBSTONE) != 0U) {
		leaf->flags |=
			PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED;
		return 0;
	}
	if (leaf->complete_chunks != leaf->chunk_count ||
	    bitmap_count(
		    leaf->chunk_bitmap,
		    leaf->chunk_count) != leaf->chunk_count ||
	    leaf_received_bytes(leaf) !=
		    leaf->value_length) {
		return -EAGAIN;
	}
	ret = pqcp_runtime_internal_sha256(
		bank->value_arena + leaf->value_offset,
		leaf->value_length, digest);
	if (ret == 0 &&
	    !digest_equal(digest, leaf->value_digest)) {
		ret = -EBADMSG;
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			bank->value_arena + leaf->value_offset,
			leaf->value_capacity);
		memset(leaf->chunk_bitmap, 0,
		       sizeof(leaf->chunk_bitmap));
		leaf->complete_chunks = 0U;
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return ret;
	}
	leaf->flags |=
		PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED;
	bank->value_bytes += leaf->value_length;
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return 0;
}

static int bank_apply_complete(
	struct pqcp_fleet_state_bank *bank,
	const struct pqcp_fleet_state_leaf_descriptor *descriptor,
	const uint8_t *value)
{
	struct pqcp_fleet_state_leaf *leaf;
	size_t index;
	bool already_complete;
	int ret;

	ret = bank_insert_descriptor(
		bank, descriptor, &index,
		&already_complete);
	if (ret != 0 || already_complete) {
		return ret;
	}
	leaf = &bank->leaves[index];
	for (uint32_t chunk = 0U;
	     chunk < leaf->chunk_count; ++chunk) {
		size_t offset;
		size_t length =
			leaf_chunk_length(leaf, chunk);
		bool new_chunk;

		ret = size_multiply(
			(size_t)chunk,
			leaf->chunk_size, &offset);
		if (ret != 0) {
			return ret;
		}
		ret = bank_write_chunk(
			bank, index, offset,
			value + offset, length,
			NULL, &new_chunk);
		if (ret != 0) {
			return ret;
		}
	}
	return bank_finalize_leaf(bank, index);
}

static int mutation_descriptor(
	const struct pqcp_fleet_state_mutation *mutation,
	struct pqcp_fleet_state_leaf_descriptor *descriptor)
{
	uint32_t chunk_count;
	int ret;

	if (mutation == NULL || descriptor == NULL ||
	    !state_domain_valid(mutation->domain) ||
	    (mutation->flags &
	     ~STATE_CANONICAL_FLAG_MASK) != 0U ||
	    mutation->revision == 0U ||
	    mutation->updated_at_ms == 0U ||
	    (mutation->expires_at_ms != 0U &&
	     mutation->expires_at_ms <=
		     mutation->updated_at_ms) ||
	    mutation->key == NULL ||
	    mutation->key_length == 0U ||
	    mutation->key_length >
		    PQCP_FLEET_STATE_KEY_MAX_BYTES) {
		return -EINVAL;
	}
	if ((mutation->flags &
	     PQCP_FLEET_STATE_LEAF_TOMBSTONE) != 0U) {
		if (mutation->value != NULL ||
		    mutation->value_length != 0U ||
		    mutation->chunk_size != 0U) {
			return -EINVAL;
		}
	} else if (mutation->value == NULL ||
		   mutation->value_length == 0U) {
		return -EINVAL;
	}
	ret = descriptor_chunk_geometry(
		mutation->value_length,
		mutation->chunk_size, &chunk_count);
	if (ret != 0) {
		return ret;
	}
	memset(descriptor, 0, sizeof(*descriptor));
	descriptor->schema_version =
		PQCP_FLEET_SNAPSHOT_SYNC_SCHEMA_VERSION;
	descriptor->domain = mutation->domain;
	descriptor->flags = mutation->flags;
	descriptor->revision = mutation->revision;
	descriptor->updated_at_ms =
		mutation->updated_at_ms;
	descriptor->expires_at_ms =
		mutation->expires_at_ms;
	descriptor->key_length =
		(uint32_t)mutation->key_length;
	descriptor->value_length =
		mutation->value_length;
	descriptor->chunk_size = mutation->chunk_size;
	descriptor->chunk_count = chunk_count;
	memcpy(descriptor->key, mutation->key,
	       mutation->key_length);
	ret = pqcp_runtime_internal_sha256(
		mutation->value, mutation->value_length,
		descriptor->value_digest);
	if (ret == 0) {
		ret = leaf_digest_compute(
			descriptor,
			descriptor->leaf_digest);
	}
	return ret;
}

static void stage_counters_reset(
	struct pqcp_fleet_snapshot_sync *sync)
{
	sync->descriptors_received = 0U;
	sync->leaves_verified = 0U;
	sync->chunks_received = 0U;
	sync->bytes_received = 0U;
}

static int stage_prepare_locked(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_snapshot_mode mode)
{
	struct pqcp_fleet_state_bank *stage =
		staging_bank(sync);
	int ret;

	bank_clear(stage);
	if (mode == PQCP_FLEET_SNAPSHOT_MODE_DELTA) {
		ret = bank_copy(active_bank(sync), stage);
		if (ret != 0) {
			return ret;
		}
	}
	sync->stage_mode = mode;
	sync->stage_active = true;
	stage_counters_reset(sync);
	memset(&sync->staged_manifest, 0,
	       sizeof(sync->staged_manifest));
	return 0;
}

static int commit_stage_locked(
	struct pqcp_fleet_snapshot_sync *sync,
	uint64_t now_ms,
	struct pqcp_fleet_snapshot_manifest *committed,
	bool local_commit)
{
	struct pqcp_fleet_state_bank *stage =
		staging_bank(sync);
	struct pqcp_fleet_state_bank *old_active =
		active_bank(sync);
	uint8_t root[PQCP_FLEET_DIGEST_BYTES];
	size_t tombstones;
	size_t verified;
	int ret;

	if (!sync->stage_active ||
	    !snapshot_mode_valid(sync->stage_mode) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_fleet_snapshot_manifest_verify(
		&sync->staged_manifest);
	if (ret != 0) {
		sync->rejected_manifest_count++;
		return ret;
	}
	if (sync->staged_manifest.generation <=
		    sync->current_manifest.generation ||
	    sync->staged_manifest.generation <
		    sync->rollback_floor_generation) {
		sync->rejected_rollback_count++;
		return -EKEYREJECTED;
	}
	if (sync->staged_manifest.expires_at_ms != 0U &&
	    now_ms >=
		    sync->staged_manifest.expires_at_ms) {
		sync->rejected_manifest_count++;
		return -EKEYEXPIRED;
	}
	if (sync->stage_mode ==
	    PQCP_FLEET_SNAPSHOT_MODE_DELTA) {
		if (sync->staged_manifest.base_generation !=
			    sync->current_manifest.generation ||
		    !digest_equal(
			    sync->staged_manifest.base_root,
			    sync->current_manifest.root)) {
			sync->rejected_rollback_count++;
			return -ESTALE;
		}
	} else if (sync->staged_manifest.base_generation != 0U ||
		   !digest_is_zero(
			   sync->staged_manifest.base_root)) {
		return -EBADMSG;
	}
	verified = bank_verified_count(stage);
	tombstones = bank_tombstone_count(stage);
	if (stage->leaf_count !=
		    sync->staged_manifest.leaf_count ||
	    verified != stage->leaf_count ||
	    tombstones !=
		    sync->staged_manifest.tombstone_count ||
	    stage->value_bytes !=
		    sync->staged_manifest.value_bytes) {
		return -EAGAIN;
	}
	ret = bank_root_compute(stage, root);
	if (ret != 0 ||
	    !digest_equal(
		    root, sync->staged_manifest.root)) {
		sync->digest_failure_count++;
		pqcp_runtime_secure_zero(root, sizeof(root));
		return ret != 0 ? ret : -EBADMSG;
	}
	memcpy(stage->root, root, sizeof(stage->root));
	stage->generation =
		sync->staged_manifest.generation;
	pqcp_runtime_secure_zero(root, sizeof(root));
	sync->active_bank ^= 1U;
	sync->current_manifest =
		sync->staged_manifest;
	ret = history_append_locked(
		sync, &sync->current_manifest, now_ms);
	if (ret != 0) {
		/*
		 * The state swap is already authoritative. History storage is
		 * fixed and append cannot fail for a valid manifest.
		 */
		return ret;
	}
	if (local_commit) {
		sync->local_commit_count++;
	} else if (sync->stage_mode ==
		   PQCP_FLEET_SNAPSHOT_MODE_FULL) {
		sync->applied_snapshot_count++;
	} else {
		sync->applied_delta_count++;
	}
	sync->rollback_floor_generation =
		sync->current_manifest.generation >
			sync->rollback_floor_generation ?
		sync->current_manifest.generation :
		sync->rollback_floor_generation;
	if (committed != NULL) {
		*committed = sync->current_manifest;
	}
	bank_clear(old_active);
	memset(&sync->staged_manifest, 0,
	       sizeof(sync->staged_manifest));
	sync->stage_mode =
		PQCP_FLEET_SNAPSHOT_MODE_NONE;
	sync->stage_active = false;
	stage_counters_reset(sync);
	return 0;
}

int pqcp_fleet_snapshot_sync_apply_local(
	struct pqcp_fleet_snapshot_sync *sync,
	const struct pqcp_fleet_state_mutation *mutations,
	size_t mutation_count,
	uint64_t new_generation,
	uint64_t created_at_ms,
	uint64_t expires_at_ms,
	struct pqcp_fleet_snapshot_manifest *manifest)
{
	struct pqcp_fleet_state_bank *stage;
	struct pqcp_fleet_state_leaf_descriptor descriptor;
	int ret;

	if (!sync_ready(sync) || mutations == NULL ||
	    mutation_count == 0U ||
	    new_generation == 0U ||
	    created_at_ms == 0U ||
	    (expires_at_ms != 0U &&
	     expires_at_ms <= created_at_ms)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (sync->stage_active) {
		(void)k_mutex_unlock(&sync->lock);
		return -EBUSY;
	}
	if (new_generation <=
		    sync->current_manifest.generation ||
	    new_generation <
		    sync->rollback_floor_generation) {
		sync->rejected_rollback_count++;
		(void)k_mutex_unlock(&sync->lock);
		return -EKEYREJECTED;
	}
	ret = stage_prepare_locked(
		sync, PQCP_FLEET_SNAPSHOT_MODE_DELTA);
	if (ret != 0) {
		(void)k_mutex_unlock(&sync->lock);
		return ret;
	}
	stage = staging_bank(sync);
	for (size_t index = 0U;
	     index < mutation_count; ++index) {
		ret = mutation_descriptor(
			&mutations[index], &descriptor);
		if (ret == 0) {
			ret = bank_apply_complete(
				stage, &descriptor,
				mutations[index].value);
		}
		pqcp_runtime_secure_zero(
			&descriptor, sizeof(descriptor));
		if (ret != 0) {
			bank_clear(stage);
			sync->stage_active = false;
			sync->stage_mode =
				PQCP_FLEET_SNAPSHOT_MODE_NONE;
			sync->rejected_manifest_count++;
			(void)k_mutex_unlock(&sync->lock);
			return ret;
		}
	}
	ret = bank_root_compute(stage, stage->root);
	if (ret == 0) {
		ret = manifest_build(
			stage,
			PQCP_FLEET_SNAPSHOT_MANIFEST_DELTA,
			new_generation,
			sync->current_manifest.generation,
			sync->current_manifest.root,
			created_at_ms, expires_at_ms,
			&sync->staged_manifest);
	}
	if (ret == 0) {
		ret = commit_stage_locked(
			sync, created_at_ms,
			manifest, true);
	}
	if (ret != 0 && sync->stage_active) {
		bank_clear(staging_bank(sync));
		memset(&sync->staged_manifest, 0,
		       sizeof(sync->staged_manifest));
		sync->stage_mode =
			PQCP_FLEET_SNAPSHOT_MODE_NONE;
		sync->stage_active = false;
	}
	(void)k_mutex_unlock(&sync->lock);
	return ret;
}

static int range_descriptor_digest(
	const struct pqcp_fleet_state_range *range,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[STATE_RANGE_DIGEST_BODY_BYTES];
	size_t offset = 0U;
	int ret;

	if (range == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-FLEET-RANGE-V1", 19U);
	offset += 19U;
	write_u32(body, &offset, range->schema_version);
	write_u64(body, &offset, range->generation);
	write_size(body, &offset, range->first_index);
	write_size(body, &offset, range->leaf_count);
	memcpy(body + offset, range->first_key_digest,
	       sizeof(range->first_key_digest));
	offset += sizeof(range->first_key_digest);
	memcpy(body + offset, range->last_key_digest,
	       sizeof(range->last_key_digest));
	offset += sizeof(range->last_key_digest);
	memcpy(body + offset, range->range_root,
	       sizeof(range->range_root));
	offset += sizeof(range->range_root);
	memcpy(body + offset, range->state_root,
	       sizeof(range->state_root));
	offset += sizeof(range->state_root);
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_fleet_snapshot_sync_range(
	struct pqcp_fleet_snapshot_sync *sync,
	size_t first_index,
	size_t maximum_leaves,
	struct pqcp_fleet_state_range *range)
{
	const struct pqcp_fleet_state_bank *bank;
	size_t count;
	int ret;

	if (!sync_ready(sync) || maximum_leaves == 0U ||
	    range == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	bank = active_bank_const(sync);
	if (first_index >= bank->leaf_count) {
		(void)k_mutex_unlock(&sync->lock);
		return -ENOENT;
	}
	count = bank->leaf_count - first_index;
	if (count > maximum_leaves) {
		count = maximum_leaves;
	}
	memset(range, 0, sizeof(*range));
	range->schema_version =
		PQCP_FLEET_STATE_RANGE_SCHEMA_VERSION;
	range->generation = bank->generation;
	range->first_index = first_index;
	range->leaf_count = count;
	ret = key_digest(
		bank->leaves[first_index].domain,
		bank->leaves[first_index].key,
		bank->leaves[first_index].key_length,
		range->first_key_digest);
	if (ret == 0) {
		size_t last = first_index + count - 1U;

		ret = key_digest(
			bank->leaves[last].domain,
			bank->leaves[last].key,
			bank->leaves[last].key_length,
			range->last_key_digest);
	}
	if (ret == 0) {
		ret = merkle_root_from_digests(
			bank->leaves, first_index, count,
			true, range->range_root);
	}
	if (ret == 0) {
		memcpy(range->state_root, bank->root,
		       sizeof(range->state_root));
		ret = range_descriptor_digest(
			range, range->descriptor_digest);
	}
	(void)k_mutex_unlock(&sync->lock);
	return ret;
}

int pqcp_fleet_snapshot_sync_range_verify(
	const struct pqcp_fleet_state_range *range)
{
	uint8_t computed[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (range == NULL ||
	    range->schema_version !=
		    PQCP_FLEET_STATE_RANGE_SCHEMA_VERSION ||
	    range->generation == 0U ||
	    range->leaf_count == 0U ||
	    digest_is_zero(range->first_key_digest) ||
	    digest_is_zero(range->last_key_digest) ||
	    digest_is_zero(range->range_root) ||
	    digest_is_zero(range->state_root) ||
	    digest_is_zero(range->descriptor_digest)) {
		return -EINVAL;
	}
	ret = range_descriptor_digest(range, computed);
	if (ret == 0 &&
	    !digest_equal(
		    computed, range->descriptor_digest)) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(computed, sizeof(computed));
	return ret;
}

int pqcp_fleet_snapshot_sync_negotiate(
	const struct pqcp_fleet_snapshot_manifest *source,
	const struct pqcp_fleet_snapshot_manifest *receiver,
	const struct pqcp_fleet_snapshot_negotiation *capability,
	struct pqcp_fleet_snapshot_negotiation_result *result)
{
	size_t chunk_size;
	int ret;

	if (capability == NULL || result == NULL ||
	    capability->schema_version !=
		    PQCP_FLEET_SNAPSHOT_SYNC_SCHEMA_VERSION ||
	    capability->maximum_leaf_count == 0U ||
	    capability->maximum_value_bytes == 0U ||
	    capability->maximum_chunk_size == 0U) {
		return -EINVAL;
	}
	ret = pqcp_fleet_snapshot_manifest_verify(source);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_fleet_snapshot_manifest_verify(receiver);
	if (ret != 0) {
		return ret;
	}
	memset(result, 0, sizeof(*result));
	result->base_generation = receiver->generation;
	result->target_generation = source->generation;
	memcpy(result->base_root, receiver->root,
	       sizeof(result->base_root));
	memcpy(result->target_root, source->root,
	       sizeof(result->target_root));
	chunk_size = source->maximum_chunk_size <
			     capability->maximum_chunk_size ?
		source->maximum_chunk_size :
		capability->maximum_chunk_size;
	result->agreed_chunk_size = chunk_size;
	if (digest_equal(source->root, receiver->root)) {
		result->action =
			PQCP_FLEET_SNAPSHOT_NEGOTIATION_NOOP;
		return 0;
	}
	if (source->generation < receiver->generation) {
		result->action =
			PQCP_FLEET_SNAPSHOT_NEGOTIATION_REJECT_ROLLBACK;
		return -EKEYREJECTED;
	}
	if (source->leaf_count >
		    capability->maximum_leaf_count ||
	    source->value_bytes >
		    capability->maximum_value_bytes ||
	    (source->flags &
	     capability->supported_manifest_flags) !=
		    (source->flags &
		     (PQCP_FLEET_SNAPSHOT_MANIFEST_FULL |
		      PQCP_FLEET_SNAPSHOT_MANIFEST_DELTA |
		      PQCP_FLEET_SNAPSHOT_MANIFEST_OFFLINE))) {
		result->action =
			PQCP_FLEET_SNAPSHOT_NEGOTIATION_REJECT_INCOMPATIBLE;
		return -ENOTSUP;
	}
	if (capability->allow_delta &&
	    (source->flags &
	     PQCP_FLEET_SNAPSHOT_MANIFEST_DELTA) != 0U &&
	    source->base_generation ==
		    receiver->generation &&
	    digest_equal(
		    source->base_root, receiver->root)) {
		result->action =
			PQCP_FLEET_SNAPSHOT_NEGOTIATION_DELTA;
		return 0;
	}
	if (capability->require_exact_base &&
	    (source->flags &
	     PQCP_FLEET_SNAPSHOT_MANIFEST_DELTA) != 0U) {
		result->action =
			PQCP_FLEET_SNAPSHOT_NEGOTIATION_REJECT_INCOMPATIBLE;
		return -ESTALE;
	}
	if (!capability->allow_full_snapshot) {
		result->action =
			PQCP_FLEET_SNAPSHOT_NEGOTIATION_REJECT_INCOMPATIBLE;
		return -ENOTSUP;
	}
	result->action =
		PQCP_FLEET_SNAPSHOT_NEGOTIATION_FULL;
	return 0;
}

static int remote_summaries_verify(
	const struct pqcp_fleet_state_leaf_summary *remote,
	size_t remote_count)
{
	for (size_t index = 0U; index < remote_count; ++index) {
		if (!state_domain_valid(remote[index].domain) ||
		    (remote[index].flags &
		     ~STATE_CANONICAL_FLAG_MASK) != 0U ||
		    remote[index].revision == 0U ||
		    remote[index].key_length == 0U ||
		    remote[index].key_length >
			    PQCP_FLEET_STATE_KEY_MAX_BYTES ||
		    digest_is_zero(remote[index].leaf_digest)) {
			return -EINVAL;
		}
		if (index != 0U &&
		    summary_key_compare(
			    &remote[index - 1U],
			    &remote[index]) >= 0) {
			return -EBADMSG;
		}
	}
	return 0;
}

int pqcp_fleet_snapshot_sync_select_missing(
	struct pqcp_fleet_snapshot_sync *sync,
	const struct pqcp_fleet_state_leaf_summary *remote,
	size_t remote_count,
	struct pqcp_fleet_state_missing_cursor *cursor,
	struct pqcp_fleet_state_missing_leaf *missing,
	size_t missing_capacity,
	size_t *missing_count)
{
	const struct pqcp_fleet_state_bank *bank;
	size_t produced = 0U;
	int ret;

	if (!sync_ready(sync) ||
	    (remote_count != 0U && remote == NULL) ||
	    cursor == NULL ||
	    (missing_capacity != 0U && missing == NULL) ||
	    missing_count == NULL) {
		return -EINVAL;
	}
	ret = remote_summaries_verify(remote, remote_count);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	bank = active_bank_const(sync);
	if (!cursor->initialized) {
		memset(cursor, 0, sizeof(*cursor));
		cursor->source_generation = bank->generation;
		cursor->initialized = true;
	} else if (cursor->source_generation !=
		   bank->generation) {
		(void)k_mutex_unlock(&sync->lock);
		return -ESTALE;
	}
	if (cursor->complete) {
		*missing_count = 0U;
		(void)k_mutex_unlock(&sync->lock);
		return 0;
	}
	while (cursor->source_index < bank->leaf_count &&
	       produced < missing_capacity) {
		const struct pqcp_fleet_state_leaf *leaf =
			&bank->leaves[cursor->source_index];
		enum pqcp_fleet_state_missing_reason reason =
			PQCP_FLEET_STATE_MISSING_ABSENT;
		bool differs = true;

		while (cursor->remote_index < remote_count &&
		       leaf_summary_key_compare(
			       leaf,
			       &remote[cursor->remote_index]) > 0) {
			cursor->remote_index++;
		}
		if (cursor->remote_index < remote_count &&
		    leaf_summary_key_compare(
			    leaf,
			    &remote[cursor->remote_index]) == 0) {
			const struct pqcp_fleet_state_leaf_summary *peer =
				&remote[cursor->remote_index];

			if (digest_equal(
				    leaf->leaf_digest,
				    peer->leaf_digest)) {
				differs = false;
			} else if (leaf->revision !=
				   peer->revision) {
				reason =
					PQCP_FLEET_STATE_MISSING_REVISION;
			} else if (canonical_flags(leaf->flags) !=
				   canonical_flags(peer->flags)) {
				reason =
					PQCP_FLEET_STATE_MISSING_FLAGS;
			} else {
				reason =
					PQCP_FLEET_STATE_MISSING_DIGEST;
			}
		}
		if (differs) {
			memset(&missing[produced], 0,
			       sizeof(missing[produced]));
			missing[produced].reason = reason;
			missing[produced].source_index =
				cursor->source_index;
			descriptor_from_leaf(
				leaf,
				&missing[produced].descriptor);
			produced++;
		}
		cursor->source_index++;
	}
	if (cursor->source_index >= bank->leaf_count) {
		cursor->complete = true;
	}
	*missing_count = produced;
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

int pqcp_fleet_snapshot_transfer_cursor_init(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_state_transfer_cursor *cursor,
	size_t chunk_size,
	bool use_selection)
{
	const struct pqcp_fleet_state_bank *bank;
	int ret;

	if (!sync_ready(sync) || cursor == NULL ||
	    chunk_size == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	bank = active_bank_const(sync);
	memset(cursor, 0, sizeof(*cursor));
	cursor->generation = bank->generation;
	memcpy(cursor->root, bank->root,
	       sizeof(cursor->root));
	cursor->chunk_size = chunk_size;
	cursor->use_selection = use_selection;
	cursor->initialized = true;
	cursor->complete = !use_selection &&
		bank->leaf_count == 0U;
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

static int transfer_source_index(
	const struct pqcp_fleet_state_bank *bank,
	const struct pqcp_fleet_state_transfer_cursor *cursor,
	const struct pqcp_fleet_state_transfer_selection *selection,
	size_t selection_count,
	size_t *source_index)
{
	if (cursor->use_selection) {
		if (selection == NULL ||
		    cursor->selection_index >= selection_count) {
			return -ENOENT;
		}
		*source_index =
			selection[cursor->selection_index].
				source_index;
		if (*source_index >= bank->leaf_count ||
		    !digest_equal(
			    bank->leaves[*source_index].
				    leaf_digest,
			    selection[cursor->selection_index].
				    leaf_digest)) {
			return -ESTALE;
		}
	} else {
		*source_index = cursor->leaf_index;
		if (*source_index >= bank->leaf_count) {
			return -ENOENT;
		}
	}
	return 0;
}

int pqcp_fleet_snapshot_transfer_next(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_state_transfer_cursor *cursor,
	const struct pqcp_fleet_state_transfer_selection *selection,
	size_t selection_count,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	struct pqcp_fleet_state_transfer_chunk *chunk)
{
	const struct pqcp_fleet_state_bank *bank;
	const struct pqcp_fleet_state_leaf *leaf;
	size_t source_index;
	size_t remaining;
	size_t length;
	bool final_selection;
	int ret;

	if (!sync_ready(sync) || cursor == NULL ||
	    !cursor->initialized || cursor->chunk_size == 0U ||
	    output == NULL || output_capacity == 0U ||
	    output_length == NULL || chunk == NULL ||
	    (cursor->use_selection &&
	     selection_count != 0U && selection == NULL)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	bank = active_bank_const(sync);
	if (cursor->generation != bank->generation ||
	    !digest_equal(cursor->root, bank->root)) {
		(void)k_mutex_unlock(&sync->lock);
		return -ESTALE;
	}
	if (cursor->complete) {
		*output_length = 0U;
		(void)k_mutex_unlock(&sync->lock);
		return -ENOENT;
	}
	ret = transfer_source_index(
		bank, cursor, selection,
		selection_count, &source_index);
	if (ret != 0) {
		if (ret == -ENOENT) {
			cursor->complete = true;
		}
		(void)k_mutex_unlock(&sync->lock);
		return ret;
	}
	leaf = &bank->leaves[source_index];
	if (cursor->value_offset > leaf->value_length) {
		(void)k_mutex_unlock(&sync->lock);
		return -EBADMSG;
	}
	remaining = leaf->value_length -
		cursor->value_offset;
	length = remaining;
	if (length > cursor->chunk_size) {
		length = cursor->chunk_size;
	}
	if (length > output_capacity) {
		length = output_capacity;
	}
	memset(chunk, 0, sizeof(*chunk));
	descriptor_from_leaf(leaf, &chunk->descriptor);
	chunk->source_index = source_index;
	chunk->offset = cursor->value_offset;
	chunk->length = length;
	chunk->total_length = leaf->value_length;
	memcpy(chunk->state_root, bank->root,
	       sizeof(chunk->state_root));
	chunk->first_chunk =
		cursor->value_offset == 0U;
	if (length != 0U) {
		memcpy(
			output,
			bank->value_arena +
				leaf->value_offset +
				cursor->value_offset,
			length);
		ret = pqcp_runtime_internal_sha256(
			output, length,
			chunk->chunk_digest);
		if (ret != 0) {
			(void)k_mutex_unlock(&sync->lock);
			return ret;
		}
	} else {
		ret = empty_value_digest(
			chunk->chunk_digest);
		if (ret != 0) {
			(void)k_mutex_unlock(&sync->lock);
			return ret;
		}
	}
	chunk->final_chunk =
		cursor->value_offset + length >=
			leaf->value_length;
	if (!chunk->final_chunk && length == 0U) {
		(void)k_mutex_unlock(&sync->lock);
		return -ENOSPC;
	}
	if (chunk->final_chunk) {
		cursor->value_offset = 0U;
		if (cursor->use_selection) {
			cursor->selection_index++;
			final_selection =
				cursor->selection_index >=
					selection_count;
			cursor->complete = final_selection;
		} else {
			cursor->leaf_index++;
			cursor->complete =
				cursor->leaf_index >=
					bank->leaf_count;
		}
		chunk->final_leaf = true;
	} else {
		cursor->value_offset += length;
	}
	*output_length = length;
	sync->transferred_leaf_count +=
		chunk->final_leaf ? 1U : 0U;
	if (length <=
	    UINT64_MAX - sync->transferred_byte_count) {
		sync->transferred_byte_count += length;
	} else {
		sync->transferred_byte_count = UINT64_MAX;
	}
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

int pqcp_fleet_snapshot_stage_begin(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_snapshot_mode mode,
	const struct pqcp_fleet_snapshot_manifest *manifest,
	uint64_t now_ms)
{
	int ret;

	if (!sync_ready(sync) ||
	    !snapshot_mode_valid(mode) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_fleet_snapshot_manifest_verify(manifest);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (sync->stage_active) {
		(void)k_mutex_unlock(&sync->lock);
		return -EBUSY;
	}
	if (manifest->generation ==
		    sync->current_manifest.generation &&
	    digest_equal(
		    manifest->root,
		    sync->current_manifest.root)) {
		(void)k_mutex_unlock(&sync->lock);
		return -EALREADY;
	}
	if (manifest->generation <=
		    sync->current_manifest.generation ||
	    manifest->generation <
		    sync->rollback_floor_generation) {
		sync->rejected_rollback_count++;
		(void)k_mutex_unlock(&sync->lock);
		return -EKEYREJECTED;
	}
	if (manifest->created_at_ms > now_ms ||
	    (manifest->expires_at_ms != 0U &&
	     now_ms >= manifest->expires_at_ms)) {
		sync->rejected_manifest_count++;
		(void)k_mutex_unlock(&sync->lock);
		return -EKEYEXPIRED;
	}
	if ((mode == PQCP_FLEET_SNAPSHOT_MODE_FULL) !=
	    ((manifest->flags &
	      PQCP_FLEET_SNAPSHOT_MANIFEST_FULL) != 0U)) {
		sync->rejected_manifest_count++;
		(void)k_mutex_unlock(&sync->lock);
		return -EINVAL;
	}
	if (mode == PQCP_FLEET_SNAPSHOT_MODE_DELTA &&
	    (manifest->base_generation !=
		     sync->current_manifest.generation ||
	     !digest_equal(
		     manifest->base_root,
		     sync->current_manifest.root))) {
		sync->rejected_rollback_count++;
		(void)k_mutex_unlock(&sync->lock);
		return -ESTALE;
	}
	if (manifest->leaf_count >
		    staging_bank(sync)->leaf_capacity ||
	    manifest->value_bytes >
		    staging_bank(sync)->value_arena_capacity) {
		sync->rejected_manifest_count++;
		(void)k_mutex_unlock(&sync->lock);
		return -ENOSPC;
	}
	ret = stage_prepare_locked(sync, mode);
	if (ret == 0) {
		sync->staged_manifest = *manifest;
	}
	(void)k_mutex_unlock(&sync->lock);
	return ret;
}

int pqcp_fleet_snapshot_stage_leaf_begin(
	struct pqcp_fleet_snapshot_sync *sync,
	const struct pqcp_fleet_state_leaf_descriptor *descriptor)
{
	struct pqcp_fleet_state_bank *bank;
	size_t index;
	bool already_complete;
	int ret;

	if (!sync_ready(sync)) {
		return -EINVAL;
	}
	ret = pqcp_fleet_state_leaf_descriptor_verify(
		descriptor);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (!sync->stage_active) {
		(void)k_mutex_unlock(&sync->lock);
		return -EPERM;
	}
	bank = staging_bank(sync);
	ret = bank_insert_descriptor(
		bank, descriptor, &index,
		&already_complete);
	if (ret == 0 && !already_complete) {
		sync->descriptors_received++;
	} else if (ret == 0 && already_complete) {
		sync->descriptors_received++;
		sync->leaves_verified++;
	}
	if (ret != 0) {
		sync->rejected_manifest_count++;
	}
	(void)k_mutex_unlock(&sync->lock);
	return ret;
}

int pqcp_fleet_snapshot_stage_write_chunk(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length,
	size_t offset,
	const uint8_t *data,
	size_t length,
	const uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES])
{
	struct pqcp_fleet_state_bank *bank;
	size_t index;
	bool found;
	bool new_chunk = false;
	int ret;

	if (!sync_ready(sync) ||
	    !state_domain_valid(domain) ||
	    key == NULL || key_length == 0U ||
	    key_length > PQCP_FLEET_STATE_KEY_MAX_BYTES ||
	    data == NULL || length == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (!sync->stage_active) {
		(void)k_mutex_unlock(&sync->lock);
		return -EPERM;
	}
	bank = staging_bank(sync);
	index = leaf_lower_bound(
		bank, domain, key, key_length, &found);
	if (!found) {
		(void)k_mutex_unlock(&sync->lock);
		return -ENOENT;
	}
	ret = bank_write_chunk(
		bank, index, offset, data, length,
		chunk_digest, &new_chunk);
	if (ret == 0 && new_chunk) {
		sync->chunks_received++;
		if (length > SIZE_MAX - sync->bytes_received) {
			ret = -EOVERFLOW;
		} else {
			sync->bytes_received += length;
		}
	}
	if (ret == -EBADMSG) {
		sync->digest_failure_count++;
	}
	(void)k_mutex_unlock(&sync->lock);
	return ret;
}

int pqcp_fleet_snapshot_stage_leaf_finalize(
	struct pqcp_fleet_snapshot_sync *sync,
	enum pqcp_fleet_state_domain domain,
	const uint8_t *key,
	size_t key_length)
{
	struct pqcp_fleet_state_bank *bank;
	size_t index;
	bool found;
	bool was_verified;
	int ret;

	if (!sync_ready(sync) ||
	    !state_domain_valid(domain) ||
	    key == NULL || key_length == 0U ||
	    key_length > PQCP_FLEET_STATE_KEY_MAX_BYTES) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (!sync->stage_active) {
		(void)k_mutex_unlock(&sync->lock);
		return -EPERM;
	}
	bank = staging_bank(sync);
	index = leaf_lower_bound(
		bank, domain, key, key_length, &found);
	if (!found) {
		(void)k_mutex_unlock(&sync->lock);
		return -ENOENT;
	}
	was_verified =
		(bank->leaves[index].flags &
		 PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) != 0U;
	ret = bank_finalize_leaf(bank, index);
	if (ret == 0 && !was_verified) {
		sync->leaves_verified++;
	}
	if (ret == -EBADMSG) {
		sync->digest_failure_count++;
	}
	(void)k_mutex_unlock(&sync->lock);
	return ret;
}

int pqcp_fleet_snapshot_stage_status(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_snapshot_stage_status *status)
{
	const struct pqcp_fleet_state_bank *bank;
	int ret;

	if (!sync_ready(sync) || status == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(status, 0, sizeof(*status));
	status->active = sync->stage_active;
	status->mode = sync->stage_mode;
	if (sync->stage_active) {
		bank = staging_bank_const(sync);
		status->base_generation =
			sync->staged_manifest.base_generation;
		status->target_generation =
			sync->staged_manifest.generation;
		status->staged_leaf_count =
			bank->leaf_count;
		status->staged_value_bytes =
			bank->value_bytes;
		status->descriptors_received =
			sync->descriptors_received;
		status->leaves_verified =
			sync->leaves_verified;
		status->chunks_received =
			sync->chunks_received;
		status->bytes_received =
			sync->bytes_received;
		memcpy(status->expected_root,
		       sync->staged_manifest.root,
		       sizeof(status->expected_root));
		status->ready_to_commit =
			bank->leaf_count ==
				sync->staged_manifest.leaf_count &&
			bank_verified_count(bank) ==
				bank->leaf_count &&
			bank->value_bytes ==
				sync->staged_manifest.value_bytes;
	}
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

int pqcp_fleet_snapshot_stage_commit(
	struct pqcp_fleet_snapshot_sync *sync,
	uint64_t now_ms,
	struct pqcp_fleet_snapshot_manifest *committed)
{
	int ret;

	if (!sync_ready(sync) || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = commit_stage_locked(
		sync, now_ms, committed, false);
	(void)k_mutex_unlock(&sync->lock);
	return ret;
}

int pqcp_fleet_snapshot_stage_abort(
	struct pqcp_fleet_snapshot_sync *sync)
{
	int ret;

	if (!sync_ready(sync)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (!sync->stage_active) {
		(void)k_mutex_unlock(&sync->lock);
		return -EALREADY;
	}
	bank_clear(staging_bank(sync));
	memset(&sync->staged_manifest, 0,
	       sizeof(sync->staged_manifest));
	sync->stage_mode =
		PQCP_FLEET_SNAPSHOT_MODE_NONE;
	sync->stage_active = false;
	stage_counters_reset(sync);
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

int pqcp_fleet_snapshot_sync_set_rollback_floor(
	struct pqcp_fleet_snapshot_sync *sync,
	uint64_t minimum_generation)
{
	int ret;

	if (!sync_ready(sync) ||
	    minimum_generation == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (minimum_generation <
		    sync->rollback_floor_generation ||
	    minimum_generation >
		    sync->current_manifest.generation) {
		(void)k_mutex_unlock(&sync->lock);
		return -ERANGE;
	}
	sync->rollback_floor_generation =
		minimum_generation;
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

static int metadata_digest_locked(
	const struct pqcp_fleet_snapshot_sync *sync,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	const struct pqcp_fleet_state_bank *bank =
		active_bank_const(sync);
	uint8_t chain[PQCP_FLEET_DIGEST_BYTES];
	uint8_t body[STATE_LEAF_DIGEST_BODY_BYTES];
	uint8_t next[PQCP_FLEET_DIGEST_BYTES];
	size_t offset = 0U;
	int ret;

	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-SYNC-METADATA-V1", 21U);
	offset += 21U;
	write_u64(body, &offset, bank->generation);
	write_size(body, &offset, bank->leaf_count);
	write_size(body, &offset, bank->value_bytes);
	write_u64(
		body, &offset,
		sync->rollback_floor_generation);
	memcpy(body + offset, bank->root,
	       sizeof(bank->root));
	offset += sizeof(bank->root);
	memcpy(body + offset,
	       sync->current_manifest.manifest_digest,
	       sizeof(sync->current_manifest.manifest_digest));
	offset +=
		sizeof(sync->current_manifest.manifest_digest);
	ret = pqcp_runtime_internal_sha256(
		body, offset, chain);
	for (size_t index = 0U;
	     ret == 0 && index < bank->leaf_count; ++index) {
		offset = 0U;
		memset(body, 0, sizeof(body));
		memcpy(body + offset,
		       "PQCP-SYNC-LEAF-META-V1", 22U);
		offset += 22U;
		write_size(body, &offset, index);
		write_size(
			body, &offset,
			bank->leaves[index].value_offset);
		write_size(
			body, &offset,
			bank->leaves[index].value_capacity);
		memcpy(body + offset, chain, sizeof(chain));
		offset += sizeof(chain);
		memcpy(body + offset,
		       bank->leaves[index].leaf_digest,
		       sizeof(bank->leaves[index].leaf_digest));
		offset +=
			sizeof(bank->leaves[index].leaf_digest);
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

static int sync_snapshot_digest(
	const struct pqcp_fleet_snapshot_sync_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[STATE_SNAPSHOT_DIGEST_BODY_BYTES];
	size_t offset = 0U;
	int ret;

	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-SYNC-SNAPSHOT-V1", 21U);
	offset += 21U;
	write_u32(body, &offset, snapshot->schema_version);
	write_u64(body, &offset, snapshot->state_generation);
	write_u64(
		body, &offset,
		snapshot->rollback_floor_generation);
	write_size(body, &offset, snapshot->leaf_capacity);
	write_size(body, &offset, snapshot->leaf_count);
	write_size(body, &offset, snapshot->tombstone_count);
	write_size(
		body, &offset,
		snapshot->value_arena_capacity);
	write_size(body, &offset, snapshot->value_bytes);
	write_size(
		body, &offset,
		snapshot->staged_leaf_count);
	write_size(
		body, &offset,
		snapshot->staged_value_bytes);
	write_size(body, &offset, snapshot->history_count);
	write_u64(
		body, &offset,
		snapshot->applied_snapshot_count);
	write_u64(
		body, &offset,
		snapshot->applied_delta_count);
	write_u64(
		body, &offset,
		snapshot->local_commit_count);
	write_u64(
		body, &offset,
		snapshot->rejected_rollback_count);
	write_u64(
		body, &offset,
		snapshot->rejected_manifest_count);
	write_u64(
		body, &offset,
		snapshot->digest_failure_count);
	write_u64(
		body, &offset,
		snapshot->transferred_leaf_count);
	write_u64(
		body, &offset,
		snapshot->transferred_byte_count);
	memcpy(body + offset, snapshot->state_root,
	       sizeof(snapshot->state_root));
	offset += sizeof(snapshot->state_root);
	memcpy(body + offset, snapshot->staged_root,
	       sizeof(snapshot->staged_root));
	offset += sizeof(snapshot->staged_root);
	memcpy(body + offset, snapshot->metadata_digest,
	       sizeof(snapshot->metadata_digest));
	offset += sizeof(snapshot->metadata_digest);
	body[offset++] = snapshot->stage_active ? 1U : 0U;
	if (offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_fleet_snapshot_sync_snapshot(
	struct pqcp_fleet_snapshot_sync *sync,
	struct pqcp_fleet_snapshot_sync_snapshot *snapshot)
{
	const struct pqcp_fleet_state_bank *bank;
	int ret;

	if (!sync_ready(sync) || snapshot == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	bank = active_bank_const(sync);
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->schema_version =
		PQCP_FLEET_SNAPSHOT_SYNC_SCHEMA_VERSION;
	snapshot->state_generation = bank->generation;
	snapshot->rollback_floor_generation =
		sync->rollback_floor_generation;
	snapshot->leaf_capacity = bank->leaf_capacity;
	snapshot->leaf_count = bank->leaf_count;
	snapshot->tombstone_count =
		bank_tombstone_count(bank);
	snapshot->value_arena_capacity =
		bank->value_arena_capacity;
	snapshot->value_bytes = bank->value_bytes;
	snapshot->history_count = sync->history_count;
	snapshot->applied_snapshot_count =
		sync->applied_snapshot_count;
	snapshot->applied_delta_count =
		sync->applied_delta_count;
	snapshot->local_commit_count =
		sync->local_commit_count;
	snapshot->rejected_rollback_count =
		sync->rejected_rollback_count;
	snapshot->rejected_manifest_count =
		sync->rejected_manifest_count;
	snapshot->digest_failure_count =
		sync->digest_failure_count;
	snapshot->transferred_leaf_count =
		sync->transferred_leaf_count;
	snapshot->transferred_byte_count =
		sync->transferred_byte_count;
	memcpy(snapshot->state_root, bank->root,
	       sizeof(snapshot->state_root));
	snapshot->stage_active = sync->stage_active;
	if (sync->stage_active) {
		const struct pqcp_fleet_state_bank *stage =
			staging_bank_const(sync);

		snapshot->staged_leaf_count =
			stage->leaf_count;
		snapshot->staged_value_bytes =
			stage->value_bytes;
		if (bank_root_compute(
			    stage, snapshot->staged_root) != 0) {
			(void)k_mutex_unlock(&sync->lock);
			return -EBADMSG;
		}
	}
	ret = metadata_digest_locked(
		sync, snapshot->metadata_digest);
	if (ret == 0) {
		ret = sync_snapshot_digest(
			snapshot,
			snapshot->snapshot_digest);
	}
	(void)k_mutex_unlock(&sync->lock);
	return ret;
}

static int leaf_record_audit(
	const struct pqcp_fleet_state_bank *bank,
	size_t index,
	bool verify_values)
{
	const struct pqcp_fleet_state_leaf *leaf =
		&bank->leaves[index];
	struct pqcp_fleet_state_leaf_descriptor descriptor;
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	size_t received;
	int ret;

	if (!leaf->occupied ||
	    leaf->schema_version !=
		    PQCP_FLEET_SNAPSHOT_SYNC_SCHEMA_VERSION ||
	    !state_domain_valid(leaf->domain) ||
	    (leaf->flags &
	     ~(STATE_CANONICAL_FLAG_MASK |
	       PQCP_FLEET_STATE_LEAF_STAGED |
	       PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED)) != 0U ||
	    leaf->revision == 0U ||
	    leaf->updated_at_ms == 0U ||
	    (leaf->expires_at_ms != 0U &&
	     leaf->expires_at_ms <= leaf->updated_at_ms) ||
	    leaf->key_length == 0U ||
	    leaf->key_length >
		    PQCP_FLEET_STATE_KEY_MAX_BYTES ||
	    leaf->complete_chunks > leaf->chunk_count ||
	    !bitmap_tail_clear(
		    leaf->chunk_bitmap,
		    leaf->chunk_count) ||
	    bitmap_count(
		    leaf->chunk_bitmap,
		    leaf->chunk_count) !=
		    leaf->complete_chunks ||
	    digest_is_zero(leaf->value_digest) ||
	    digest_is_zero(leaf->leaf_digest)) {
		return -EBADMSG;
	}
	descriptor_from_leaf(leaf, &descriptor);
	ret = pqcp_fleet_state_leaf_descriptor_verify(
		&descriptor);
	pqcp_runtime_secure_zero(
		&descriptor, sizeof(descriptor));
	if (ret != 0) {
		return ret;
	}
	if ((leaf->flags &
	     PQCP_FLEET_STATE_LEAF_TOMBSTONE) != 0U) {
		if (leaf->value_length != 0U ||
		    leaf->value_capacity != 0U ||
		    leaf->value_offset != 0U ||
		    leaf->chunk_count != 0U ||
		    leaf->complete_chunks != 0U ||
		    (leaf->flags &
		     PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) == 0U) {
			return -EBADMSG;
		}
		return 0;
	}
	if (leaf->value_length == 0U ||
	    leaf->value_capacity < leaf->value_length ||
	    leaf->value_offset %
		    bank->value_alignment != 0U ||
	    leaf->value_capacity %
		    bank->value_alignment != 0U ||
	    leaf->value_offset >
		    bank->value_arena_capacity ||
	    leaf->value_capacity >
		    bank->value_arena_capacity -
			    leaf->value_offset) {
		return -EBADMSG;
	}
	received = leaf_received_bytes(leaf);
	if (received == SIZE_MAX ||
	    received > leaf->value_length) {
		return -EOVERFLOW;
	}
	if ((leaf->flags &
	     PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) != 0U) {
		if (leaf->complete_chunks !=
			    leaf->chunk_count ||
		    received != leaf->value_length) {
			return -EBADMSG;
		}
		if (verify_values) {
			ret = pqcp_runtime_internal_sha256(
				bank->value_arena +
					leaf->value_offset,
				leaf->value_length, digest);
			if (ret == 0 &&
			    !digest_equal(
				    digest,
				    leaf->value_digest)) {
				ret = -EBADMSG;
			}
			pqcp_runtime_secure_zero(
				digest, sizeof(digest));
			if (ret != 0) {
				return ret;
			}
		}
	}
	return 0;
}

static int bank_audit(
	const struct pqcp_fleet_state_bank *bank,
	bool verify_values,
	bool require_all_verified)
{
	uint8_t root[PQCP_FLEET_DIGEST_BYTES];
	size_t value_bytes = 0U;
	int ret;

	if (bank == NULL || bank->leaves == NULL ||
	    bank->leaf_capacity == 0U ||
	    bank->leaf_count > bank->leaf_capacity ||
	    bank->value_arena == NULL ||
	    bank->value_arena_capacity == 0U ||
	    bank->value_alignment == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < bank->leaf_count; ++index) {
		const struct pqcp_fleet_state_leaf *leaf =
			&bank->leaves[index];

		ret = leaf_record_audit(
			bank, index, verify_values);
		if (ret != 0) {
			return ret;
		}
		if (require_all_verified &&
		    (leaf->flags &
		     PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) == 0U) {
			return -EAGAIN;
		}
		if (index != 0U &&
		    leaf_key_compare(
			    &bank->leaves[index - 1U],
			    leaf) >= 0) {
			return -EEXIST;
		}
		if ((leaf->flags &
		     PQCP_FLEET_STATE_LEAF_VALUE_VERIFIED) != 0U) {
			if (leaf->value_length >
			    SIZE_MAX - value_bytes) {
				return -EOVERFLOW;
			}
			value_bytes += leaf->value_length;
		}
		for (size_t other = index + 1U;
		     other < bank->leaf_count; ++other) {
			const struct pqcp_fleet_state_leaf *peer =
				&bank->leaves[other];

			if (value_extents_overlap(
				    leaf->value_offset,
				    leaf->value_capacity,
				    peer->value_offset,
				    peer->value_capacity)) {
				return -EADDRINUSE;
			}
		}
	}
	for (size_t index = bank->leaf_count;
	     index < bank->leaf_capacity; ++index) {
		if (bank->leaves[index].occupied) {
			return -EBADMSG;
		}
	}
	if (value_bytes != bank->value_bytes) {
		return -EBADMSG;
	}
	if (bank->generation != 0U) {
		ret = bank_root_compute(bank, root);
		if (ret == 0 &&
		    !digest_equal(root, bank->root)) {
			ret = -EBADMSG;
		}
		pqcp_runtime_secure_zero(root, sizeof(root));
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

static int history_audit(
	const struct pqcp_fleet_snapshot_sync *sync)
{
	size_t occupied = 0U;

	if (sync->history_head >=
		    PQCP_FLEET_STATE_HISTORY_CAPACITY ||
	    sync->history_count >
		    PQCP_FLEET_STATE_HISTORY_CAPACITY) {
		return -EBADMSG;
	}
	for (size_t index = 0U;
	     index < PQCP_FLEET_STATE_HISTORY_CAPACITY;
	     ++index) {
		const struct pqcp_fleet_state_history_entry *entry =
			&sync->history[index];

		if (!entry->occupied) {
			continue;
		}
		if (entry->generation == 0U ||
		    entry->committed_at_ms == 0U ||
		    digest_is_zero(entry->root) ||
		    digest_is_zero(entry->manifest_digest)) {
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < PQCP_FLEET_STATE_HISTORY_CAPACITY;
		     ++other) {
			if (sync->history[other].occupied &&
			    sync->history[other].generation ==
				    entry->generation &&
			    !digest_equal(
				    sync->history[other].root,
				    entry->root)) {
				return -EEXIST;
			}
		}
		occupied++;
	}
	if (occupied != sync->history_count) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_fleet_snapshot_sync_audit(
	struct pqcp_fleet_snapshot_sync *sync,
	bool verify_values)
{
	const struct pqcp_fleet_state_bank *active;
	const struct pqcp_fleet_state_bank *stage;
	int ret;

	if (!sync_ready(sync)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&sync->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	active = active_bank_const(sync);
	ret = bank_audit(active, verify_values, true);
	if (ret != 0) {
		(void)k_mutex_unlock(&sync->lock);
		return ret;
	}
	ret = pqcp_fleet_snapshot_manifest_verify(
		&sync->current_manifest);
	if (ret != 0 ||
	    sync->current_manifest.generation !=
		    active->generation ||
	    sync->current_manifest.leaf_count !=
		    active->leaf_count ||
	    sync->current_manifest.value_bytes !=
		    active->value_bytes ||
	    !digest_equal(
		    sync->current_manifest.root,
		    active->root) ||
	    sync->rollback_floor_generation >
		    active->generation) {
		(void)k_mutex_unlock(&sync->lock);
		return ret != 0 ? ret : -EBADMSG;
	}
	ret = history_audit(sync);
	if (ret != 0) {
		(void)k_mutex_unlock(&sync->lock);
		return ret;
	}
	stage = staging_bank_const(sync);
	if (sync->stage_active) {
		ret = bank_audit(stage, verify_values, false);
		if (ret == 0) {
			ret = pqcp_fleet_snapshot_manifest_verify(
				&sync->staged_manifest);
		}
		if (ret != 0 ||
		    !snapshot_mode_valid(sync->stage_mode)) {
			(void)k_mutex_unlock(&sync->lock);
			return ret != 0 ? ret : -EBADMSG;
		}
	} else if (stage->leaf_count != 0U ||
		   stage->value_bytes != 0U ||
		   stage->generation != 0U ||
		   !digest_is_zero(stage->root) ||
		   sync->stage_mode !=
			   PQCP_FLEET_SNAPSHOT_MODE_NONE) {
		(void)k_mutex_unlock(&sync->lock);
		return -EBADMSG;
	}
	(void)k_mutex_unlock(&sync->lock);
	return 0;
}

const char *pqcp_fleet_state_domain_str(
	enum pqcp_fleet_state_domain domain)
{
	switch (domain) {
	case PQCP_FLEET_STATE_DOMAIN_DEVICE:
		return "device";
	case PQCP_FLEET_STATE_DOMAIN_POLICY:
		return "policy";
	case PQCP_FLEET_STATE_DOMAIN_REVOCATION:
		return "revocation";
	case PQCP_FLEET_STATE_DOMAIN_CREDENTIAL:
		return "credential";
	case PQCP_FLEET_STATE_DOMAIN_ROLLOUT:
		return "rollout";
	case PQCP_FLEET_STATE_DOMAIN_CONFIGURATION:
		return "configuration";
	case PQCP_FLEET_STATE_DOMAIN_APPLICATION:
		return "application";
	case PQCP_FLEET_STATE_DOMAIN_AUDIT_ANCHOR:
		return "audit_anchor";
	case PQCP_FLEET_STATE_DOMAIN_RECOVERY:
		return "recovery";
	default:
		return "none";
	}
}

const char *pqcp_fleet_snapshot_negotiation_action_str(
	enum pqcp_fleet_snapshot_negotiation_action action)
{
	switch (action) {
	case PQCP_FLEET_SNAPSHOT_NEGOTIATION_NOOP:
		return "noop";
	case PQCP_FLEET_SNAPSHOT_NEGOTIATION_DELTA:
		return "delta";
	case PQCP_FLEET_SNAPSHOT_NEGOTIATION_FULL:
		return "full";
	case PQCP_FLEET_SNAPSHOT_NEGOTIATION_REJECT_ROLLBACK:
		return "reject_rollback";
	case PQCP_FLEET_SNAPSHOT_NEGOTIATION_REJECT_INCOMPATIBLE:
		return "reject_incompatible";
	default:
		return "none";
	}
}
