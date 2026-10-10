/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded out-of-order fragmentation and reassembly.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool fragment_shape_valid(
	const struct pqcp_edge_fragment *fragment)
{
	uint64_t end;

	if (fragment == NULL ||
	    pqcp_edge_internal_all_zero(
		    fragment->message_id,
		    sizeof(fragment->message_id)) ||
	    fragment->fragment_count == 0U ||
	    fragment->fragment_count > 64U ||
	    fragment->fragment_index >=
		    fragment->fragment_count ||
	    fragment->total_length == 0U ||
	    fragment->payload_length == 0U ||
	    fragment->payload_length >
		    sizeof(fragment->payload)) {
		return false;
	}
	end = (uint64_t)fragment->offset +
		fragment->payload_length;
	return end <= fragment->total_length;
}

static int assembly_index(
	const struct pqcp_edge_fragment_manager *manager,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES])
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->assemblies[index].occupied &&
		    pqcp_edge_internal_equal(
			    manager->assemblies[index].message_id,
			    message_id,
			    PQCP_EDGE_MESSAGE_ID_BYTES)) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_assembly_index(
	const struct pqcp_edge_fragment_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->assemblies[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

int pqcp_edge_fragment_manager_init(
	struct pqcp_edge_fragment_manager *manager,
	struct pqcp_edge_reassembly *assemblies,
	size_t capacity)
{
	if (manager == NULL || assemblies == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(assemblies, 0,
	       capacity * sizeof(*assemblies));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->assemblies = assemblies;
	manager->capacity = capacity;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_message_fragment(
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES],
	const uint8_t *payload,
	size_t payload_length,
	uint16_t fragment_index,
	struct pqcp_edge_fragment *fragment)
{
	size_t fragment_count;
	size_t offset;
	size_t remaining;
	size_t copied;

	if (message_id == NULL || payload == NULL ||
	    payload_length == 0U || fragment == NULL ||
	    pqcp_edge_internal_all_zero(
		    message_id,
		    PQCP_EDGE_MESSAGE_ID_BYTES)) {
		return -EINVAL;
	}
	fragment_count =
		(payload_length +
		 PQCP_EDGE_FRAGMENT_PAYLOAD_MAX_BYTES - 1U) /
		PQCP_EDGE_FRAGMENT_PAYLOAD_MAX_BYTES;
	if (fragment_count == 0U || fragment_count > 64U ||
	    fragment_index >= fragment_count ||
	    payload_length > UINT32_MAX) {
		return -E2BIG;
	}
	offset = (size_t)fragment_index *
		PQCP_EDGE_FRAGMENT_PAYLOAD_MAX_BYTES;
	remaining = payload_length - offset;
	copied = remaining <
			PQCP_EDGE_FRAGMENT_PAYLOAD_MAX_BYTES ?
			remaining :
			PQCP_EDGE_FRAGMENT_PAYLOAD_MAX_BYTES;
	memset(fragment, 0, sizeof(*fragment));
	fragment->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	memcpy(fragment->message_id, message_id,
	       sizeof(fragment->message_id));
	fragment->fragment_index = fragment_index;
	fragment->fragment_count =
		(uint16_t)fragment_count;
	fragment->total_length =
		(uint32_t)payload_length;
	fragment->offset = (uint32_t)offset;
	memcpy(fragment->payload, payload + offset, copied);
	fragment->payload_length = copied;
	return pqcp_edge_internal_sha256(
		fragment->payload,
		fragment->payload_length,
		fragment->payload_digest);
}

static int initialize_assembly(
	struct pqcp_edge_reassembly *assembly,
	const struct pqcp_edge_fragment *fragment,
	uint8_t *output,
	size_t output_capacity,
	uint64_t now_ms,
	uint64_t lifetime_ms)
{
	if (output == NULL ||
	    output_capacity < fragment->total_length ||
	    lifetime_ms == 0U) {
		return -ENOBUFS;
	}
	memset(assembly, 0, sizeof(*assembly));
	memcpy(assembly->message_id,
	       fragment->message_id,
	       sizeof(assembly->message_id));
	assembly->output = output;
	assembly->output_capacity = output_capacity;
	assembly->total_length =
		fragment->total_length;
	assembly->fragment_count =
		fragment->fragment_count;
	assembly->expires_at_ms =
		pqcp_edge_internal_saturating_add_u64(
			now_ms, lifetime_ms);
	assembly->occupied = true;
	return 0;
}

int pqcp_edge_fragment_accept(
	struct pqcp_edge_fragment_manager *manager,
	const struct pqcp_edge_fragment *fragment,
	uint8_t *output,
	size_t output_capacity,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	bool *complete,
	size_t *message_length)
{
	struct pqcp_edge_reassembly *assembly;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t bit;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !fragment_shape_valid(fragment) ||
	    complete == NULL || message_length == NULL) {
		return -EINVAL;
	}
	*complete = false;
	*message_length = 0U;
	ret = pqcp_edge_internal_sha256(
		fragment->payload,
		fragment->payload_length, digest);
	if (ret != 0 ||
	    !pqcp_edge_internal_equal(
		    digest, fragment->payload_digest,
		    sizeof(digest))) {
		++manager->rejected_count;
		return ret != 0 ? ret : -EBADMSG;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = assembly_index(
		manager, fragment->message_id);
	if (index == -ENOENT) {
		index = free_assembly_index(manager);
		if (index < 0) {
			ret = index;
			goto out;
		}
		ret = initialize_assembly(
			&manager->assemblies[index], fragment,
			output, output_capacity, now_ms,
			lifetime_ms);
		if (ret != 0) {
			goto out;
		}
	} else if (index < 0) {
		ret = index;
		goto out;
	}
	assembly = &manager->assemblies[index];
	if (assembly->expires_at_ms <= now_ms) {
		ret = -ETIMEDOUT;
		goto reject;
	}
	if (assembly->output != output ||
	    assembly->output_capacity != output_capacity ||
	    assembly->total_length !=
		    fragment->total_length ||
	    assembly->fragment_count !=
		    fragment->fragment_count) {
		ret = -EKEYREJECTED;
		goto reject;
	}
	bit = 1ULL << fragment->fragment_index;
	if ((assembly->received_bitmap & bit) != 0U) {
		if (memcmp(
			    assembly->output + fragment->offset,
			    fragment->payload,
			    fragment->payload_length) != 0) {
			ret = -EKEYREJECTED;
			goto reject;
		}
		ret = -EALREADY;
		goto out;
	}
	memcpy(assembly->output + fragment->offset,
	       fragment->payload,
	       fragment->payload_length);
	assembly->received_bitmap |= bit;
	++assembly->received_count;
	if (assembly->received_count ==
	    assembly->fragment_count) {
		*complete = true;
		*message_length = assembly->total_length;
		assembly->occupied = false;
		assembly->output = NULL;
		++manager->completed_count;
	}
	goto out;
reject:
	++manager->rejected_count;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_fragment_expire(
	struct pqcp_edge_fragment_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (manager == NULL || !manager->initialized ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->assemblies[index].occupied &&
		    manager->assemblies[index].expires_at_ms <=
			    now_ms) {
			memset(
				&manager->assemblies[index], 0,
				sizeof(manager->assemblies[index]));
			++expired;
		}
	}
	k_mutex_unlock(&manager->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_fragment_manager_audit(
	struct pqcp_edge_fragment_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->assemblies == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_reassembly *assembly =
			&manager->assemblies[index];

		if (!assembly->occupied) {
			continue;
		}
		if (pqcp_edge_internal_all_zero(
			    assembly->message_id,
			    sizeof(assembly->message_id)) ||
		    assembly->output == NULL ||
		    assembly->output_capacity <
			    assembly->total_length ||
		    assembly->fragment_count == 0U ||
		    assembly->fragment_count > 64U ||
		    assembly->received_count >
			    assembly->fragment_count ||
		    __builtin_popcountll(
			    assembly->received_bitmap) !=
			    assembly->received_count) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->assemblies[other].occupied &&
			    pqcp_edge_internal_equal(
				    assembly->message_id,
				    manager->assemblies[other].
					    message_id,
				    sizeof(assembly->message_id))) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
