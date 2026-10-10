/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Staged policy distribution with acknowledgements and rollback.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int bundle_index(
	const struct pqcp_edge_policy_distributor *distributor,
	uint64_t bundle_id)
{
	for (size_t index = 0U;
	     index < distributor->bundle_capacity; ++index) {
		if (distributor->bundles[index].occupied &&
		    distributor->bundles[index].bundle_id ==
			    bundle_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_bundle_index(
	const struct pqcp_edge_policy_distributor *distributor)
{
	for (size_t index = 0U;
	     index < distributor->bundle_capacity; ++index) {
		if (!distributor->bundles[index].occupied ||
		    distributor->bundles[index].stage ==
			    PQCP_EDGE_POLICY_STAGE_RETIRED) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int ack_index(
	const struct pqcp_edge_policy_distributor *distributor,
	uint64_t bundle_id,
	const char *principal_id)
{
	for (size_t index = 0U;
	     index < distributor->ack_capacity; ++index) {
		if (distributor->acks[index].occupied &&
		    distributor->acks[index].bundle_id ==
			    bundle_id &&
		    strcmp(distributor->acks[index].principal_id,
			   principal_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_ack_index(
	const struct pqcp_edge_policy_distributor *distributor)
{
	for (size_t index = 0U;
	     index < distributor->ack_capacity; ++index) {
		if (!distributor->acks[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int bundle_digest(
	const struct pqcp_edge_policy_bundle *bundle,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[72];
	const uint8_t *parts[3];
	size_t lengths[3];
	size_t offset = 0U;

	pqcp_edge_internal_write_u32(
		numeric + offset, bundle->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, bundle->bundle_id);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, bundle->policy_epoch);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, bundle->previous_epoch);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, bundle->created_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, bundle->not_before_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, bundle->expires_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, bundle->required_acks);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, bundle->maximum_failures);
	offset += 4U;
	parts[0] = numeric;
	lengths[0] = offset;
	parts[1] = bundle->content_digest;
	lengths[1] = sizeof(bundle->content_digest);
	parts[2] = bundle->previous_digest;
	lengths[2] = sizeof(bundle->previous_digest);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 3U, output);
}

static bool stage_transition_allowed(
	enum pqcp_edge_policy_stage current,
	enum pqcp_edge_policy_stage next)
{
	switch (current) {
	case PQCP_EDGE_POLICY_STAGE_STAGED:
		return next == PQCP_EDGE_POLICY_STAGE_CANARY ||
		       next == PQCP_EDGE_POLICY_STAGE_ROLLBACK;
	case PQCP_EDGE_POLICY_STAGE_CANARY:
		return next == PQCP_EDGE_POLICY_STAGE_PROMOTED ||
		       next == PQCP_EDGE_POLICY_STAGE_ROLLBACK;
	case PQCP_EDGE_POLICY_STAGE_PROMOTED:
		return next == PQCP_EDGE_POLICY_STAGE_ACTIVE ||
		       next == PQCP_EDGE_POLICY_STAGE_ROLLBACK;
	case PQCP_EDGE_POLICY_STAGE_ACTIVE:
		return next == PQCP_EDGE_POLICY_STAGE_RETIRED ||
		       next == PQCP_EDGE_POLICY_STAGE_ROLLBACK;
	case PQCP_EDGE_POLICY_STAGE_ROLLBACK:
		return next == PQCP_EDGE_POLICY_STAGE_RETIRED;
	default:
		return false;
	}
}

int pqcp_edge_policy_distributor_init(
	struct pqcp_edge_policy_distributor *distributor,
	struct pqcp_edge_policy_bundle *bundles,
	size_t bundle_capacity,
	struct pqcp_edge_policy_ack *acks,
	size_t ack_capacity,
	uint64_t active_policy_epoch,
	const uint8_t active_digest[PQCP_EDGE_DIGEST_BYTES])
{
	if (distributor == NULL || bundles == NULL ||
	    bundle_capacity == 0U || acks == NULL ||
	    ack_capacity == 0U || active_policy_epoch == 0U ||
	    active_digest == NULL ||
	    pqcp_edge_internal_all_zero(
		    active_digest, PQCP_EDGE_DIGEST_BYTES)) {
		return -EINVAL;
	}
	memset(distributor, 0, sizeof(*distributor));
	memset(bundles, 0,
	       bundle_capacity * sizeof(*bundles));
	memset(acks, 0, ack_capacity * sizeof(*acks));
	distributor->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	distributor->bundles = bundles;
	distributor->bundle_capacity = bundle_capacity;
	distributor->acks = acks;
	distributor->ack_capacity = ack_capacity;
	distributor->next_bundle_id = 1U;
	distributor->active_policy_epoch =
		active_policy_epoch;
	memcpy(distributor->active_digest, active_digest,
	       sizeof(distributor->active_digest));
	k_mutex_init(&distributor->lock);
	distributor->initialized = true;
	return 0;
}

int pqcp_edge_policy_stage(
	struct pqcp_edge_policy_distributor *distributor,
	const uint8_t content_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t not_before_ms,
	uint64_t expires_at_ms,
	uint32_t required_acks,
	uint32_t maximum_failures,
	struct pqcp_edge_policy_bundle **bundle)
{
	struct pqcp_edge_policy_bundle candidate;
	int index;
	int ret;

	if (distributor == NULL || !distributor->initialized ||
	    content_digest == NULL ||
	    pqcp_edge_internal_all_zero(
		    content_digest, PQCP_EDGE_DIGEST_BYTES) ||
	    policy_epoch <= distributor->active_policy_epoch ||
	    not_before_ms < now_ms || expires_at_ms <=
		    not_before_ms ||
	    required_acks == 0U || maximum_failures == 0U ||
	    bundle == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&distributor->lock, K_FOREVER);
	for (size_t current = 0U;
	     current < distributor->bundle_capacity; ++current) {
		if (distributor->bundles[current].occupied &&
		    distributor->bundles[current].policy_epoch ==
			    policy_epoch &&
		    distributor->bundles[current].stage !=
			    PQCP_EDGE_POLICY_STAGE_RETIRED) {
			*bundle = &distributor->bundles[current];
			k_mutex_unlock(&distributor->lock);
			return -EALREADY;
		}
	}
	index = free_bundle_index(distributor);
	if (index < 0) {
		*bundle = NULL;
		k_mutex_unlock(&distributor->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.bundle_id =
		pqcp_edge_internal_next_identifier(
			&distributor->next_bundle_id);
	candidate.policy_epoch = policy_epoch;
	candidate.previous_epoch =
		distributor->active_policy_epoch;
	candidate.created_at_ms = now_ms;
	candidate.not_before_ms = not_before_ms;
	candidate.expires_at_ms = expires_at_ms;
	candidate.required_acks = required_acks;
	candidate.maximum_failures = maximum_failures;
	candidate.stage = PQCP_EDGE_POLICY_STAGE_STAGED;
	memcpy(candidate.content_digest, content_digest,
	       sizeof(candidate.content_digest));
	memcpy(candidate.previous_digest,
	       distributor->active_digest,
	       sizeof(candidate.previous_digest));
	ret = bundle_digest(
		&candidate, candidate.bundle_digest);
	if (ret == 0) {
		candidate.occupied = true;
		distributor->bundles[index] = candidate;
		*bundle = &distributor->bundles[index];
	} else {
		*bundle = NULL;
	}
	k_mutex_unlock(&distributor->lock);
	return ret;
}

int pqcp_edge_policy_acknowledge(
	struct pqcp_edge_policy_distributor *distributor,
	uint64_t bundle_id,
	const char *principal_id,
	const uint8_t applied_digest[PQCP_EDGE_DIGEST_BYTES],
	int result,
	uint64_t now_ms)
{
	struct pqcp_edge_policy_bundle *bundle;
	struct pqcp_edge_policy_ack ack;
	int bundle_slot;
	int slot;
	int ret = 0;

	if (distributor == NULL || !distributor->initialized ||
	    bundle_id == 0U ||
	    !pqcp_edge_internal_text_valid(
		    principal_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    applied_digest == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&distributor->lock, K_FOREVER);
	bundle_slot = bundle_index(distributor, bundle_id);
	if (bundle_slot < 0) {
		ret = bundle_slot;
		goto out;
	}
	bundle = &distributor->bundles[bundle_slot];
	if (bundle->expires_at_ms <= now_ms ||
	    bundle->stage ==
		    PQCP_EDGE_POLICY_STAGE_RETIRED ||
	    bundle->stage ==
		    PQCP_EDGE_POLICY_STAGE_ROLLBACK) {
		ret = -ESTALE;
		goto out;
	}
	slot = ack_index(
		distributor, bundle_id, principal_id);
	if (slot >= 0) {
		ret = -EALREADY;
		goto out;
	}
	slot = free_ack_index(distributor);
	if (slot < 0) {
		ret = slot;
		goto out;
	}
	memset(&ack, 0, sizeof(ack));
	ack.bundle_id = bundle_id;
	ret = pqcp_edge_internal_copy_text(
		ack.principal_id, sizeof(ack.principal_id),
		principal_id);
	ack.acknowledged_at_ms = now_ms;
	memcpy(ack.applied_digest, applied_digest,
	       sizeof(ack.applied_digest));
	if (result == 0 &&
	    !pqcp_edge_internal_equal(
		    applied_digest, bundle->content_digest,
		    sizeof(bundle->content_digest))) {
		result = -EBADMSG;
	}
	ack.result = result;
	ack.occupied = true;
	if (ret == 0) {
		distributor->acks[slot] = ack;
		if (result == 0) {
			++bundle->received_acks;
		} else {
			++bundle->failure_count;
		}
	}
out:
	k_mutex_unlock(&distributor->lock);
	return ret != 0 ? ret : result;
}

int pqcp_edge_policy_promote(
	struct pqcp_edge_policy_distributor *distributor,
	uint64_t bundle_id,
	uint64_t now_ms)
{
	struct pqcp_edge_policy_bundle *bundle;
	enum pqcp_edge_policy_stage next;
	int index;
	int ret = 0;

	if (distributor == NULL || !distributor->initialized ||
	    bundle_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&distributor->lock, K_FOREVER);
	index = bundle_index(distributor, bundle_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	bundle = &distributor->bundles[index];
	if (bundle->expires_at_ms <= now_ms ||
	    now_ms < bundle->not_before_ms ||
	    bundle->failure_count >=
		    bundle->maximum_failures) {
		ret = -EACCES;
		goto out;
	}
	switch (bundle->stage) {
	case PQCP_EDGE_POLICY_STAGE_STAGED:
		next = PQCP_EDGE_POLICY_STAGE_CANARY;
		break;
	case PQCP_EDGE_POLICY_STAGE_CANARY:
		if (bundle->received_acks <
		    bundle->required_acks) {
			ret = -EAGAIN;
			goto out;
		}
		next = PQCP_EDGE_POLICY_STAGE_PROMOTED;
		break;
	case PQCP_EDGE_POLICY_STAGE_PROMOTED:
		next = PQCP_EDGE_POLICY_STAGE_ACTIVE;
		break;
	default:
		ret = -EALREADY;
		goto out;
	}
	if (!stage_transition_allowed(bundle->stage, next)) {
		ret = -EPERM;
		goto out;
	}
	bundle->stage = next;
	if (next == PQCP_EDGE_POLICY_STAGE_ACTIVE) {
		for (size_t current = 0U;
		     current < distributor->bundle_capacity;
		     ++current) {
			if (current != (size_t)index &&
			    distributor->bundles[current].occupied &&
			    distributor->bundles[current].stage ==
				    PQCP_EDGE_POLICY_STAGE_ACTIVE) {
				distributor->bundles[current].stage =
					PQCP_EDGE_POLICY_STAGE_RETIRED;
			}
		}
		distributor->active_policy_epoch =
			bundle->policy_epoch;
		memcpy(distributor->active_digest,
		       bundle->content_digest,
		       sizeof(distributor->active_digest));
	}
	++distributor->promotion_count;
out:
	k_mutex_unlock(&distributor->lock);
	return ret;
}

int pqcp_edge_policy_rollback(
	struct pqcp_edge_policy_distributor *distributor,
	uint64_t bundle_id,
	uint64_t now_ms)
{
	struct pqcp_edge_policy_bundle *bundle;
	int index;
	int ret = 0;

	if (distributor == NULL || !distributor->initialized ||
	    bundle_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&distributor->lock, K_FOREVER);
	index = bundle_index(distributor, bundle_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	bundle = &distributor->bundles[index];
	if (!stage_transition_allowed(
		    bundle->stage,
		    PQCP_EDGE_POLICY_STAGE_ROLLBACK)) {
		ret = -EPERM;
		goto out;
	}
	bundle->stage = PQCP_EDGE_POLICY_STAGE_ROLLBACK;
	if (bundle->policy_epoch ==
	    distributor->active_policy_epoch) {
		distributor->active_policy_epoch =
			bundle->previous_epoch;
		memcpy(distributor->active_digest,
		       bundle->previous_digest,
		       sizeof(distributor->active_digest));
	}
	bundle->expires_at_ms = now_ms;
	++distributor->rollback_count;
out:
	k_mutex_unlock(&distributor->lock);
	return ret;
}

int pqcp_edge_policy_distributor_audit(
	struct pqcp_edge_policy_distributor *distributor)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret = 0;

	if (distributor == NULL ||
	    !distributor->initialized ||
	    distributor->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    distributor->bundles == NULL ||
	    distributor->acks == NULL ||
	    distributor->bundle_capacity == 0U ||
	    distributor->ack_capacity == 0U ||
	    distributor->active_policy_epoch == 0U ||
	    pqcp_edge_internal_all_zero(
		    distributor->active_digest,
		    sizeof(distributor->active_digest))) {
		return -EINVAL;
	}
	k_mutex_lock(&distributor->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < distributor->bundle_capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_policy_bundle *bundle =
			&distributor->bundles[index];

		if (!bundle->occupied) {
			continue;
		}
		if (bundle->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    bundle->bundle_id == 0U ||
		    bundle->policy_epoch <=
			    bundle->previous_epoch ||
		    bundle->expires_at_ms <=
			    bundle->not_before_ms ||
		    bundle->required_acks == 0U ||
		    bundle->maximum_failures == 0U ||
		    bundle->stage <=
			    PQCP_EDGE_POLICY_STAGE_EMPTY ||
		    bundle->stage >
			    PQCP_EDGE_POLICY_STAGE_RETIRED ||
		    bundle_digest(bundle, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    digest, bundle->bundle_digest,
			    sizeof(digest))) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&distributor->lock);
	return ret;
}
