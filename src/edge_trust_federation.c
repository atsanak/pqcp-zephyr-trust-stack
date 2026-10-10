/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Cross-domain trust anchors and attenuated federation grants.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int anchor_index(
	const struct pqcp_edge_trust_federation *federation,
	const char *domain_id)
{
	for (size_t index = 0U;
	     index < federation->anchor_capacity; ++index) {
		if (federation->anchors[index].active &&
		    strcmp(federation->anchors[index].domain_id,
			   domain_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_anchor_index(
	const struct pqcp_edge_trust_federation *federation)
{
	for (size_t index = 0U;
	     index < federation->anchor_capacity; ++index) {
		if (!federation->anchors[index].active) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int grant_index(
	const struct pqcp_edge_trust_federation *federation,
	uint64_t grant_id)
{
	for (size_t index = 0U;
	     index < federation->grant_capacity; ++index) {
		if (federation->grants[index].occupied &&
		    federation->grants[index].grant_id ==
			    grant_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_grant_index(
	const struct pqcp_edge_trust_federation *federation)
{
	for (size_t index = 0U;
	     index < federation->grant_capacity; ++index) {
		if (!federation->grants[index].occupied ||
		    federation->grants[index].revoked) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool anchor_valid(
	const struct pqcp_edge_trust_anchor *anchor)
{
	return anchor != NULL &&
	       pqcp_edge_internal_text_valid(
		       anchor->domain_id,
		       sizeof(anchor->domain_id)) &&
	       anchor->policy_epoch != 0U &&
	       anchor->revocation_epoch != 0U &&
	       anchor->expires_at_ms > anchor->not_before_ms &&
	       anchor->maximum_risk <= 1000U &&
	       !pqcp_edge_internal_all_zero(
		       anchor->public_key_digest,
		       sizeof(anchor->public_key_digest));
}

static int grant_digest(
	const struct pqcp_edge_federation_grant *grant,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[60];
	const uint8_t *parts[3];
	size_t lengths[3];
	size_t offset = 0U;

	pqcp_edge_internal_write_u64(
		numeric + offset, grant->grant_id);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, grant->capabilities);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, grant->operation_mask);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, grant->issued_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, grant->expires_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, grant->maximum_uses);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, grant->maximum_risk);
	offset += 4U;
	parts[0] = numeric;
	lengths[0] = offset;
	parts[1] =
		(const uint8_t *)grant->source_domain;
	lengths[1] = strlen(grant->source_domain);
	parts[2] =
		(const uint8_t *)grant->destination_domain;
	lengths[2] = strlen(grant->destination_domain);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 3U, output);
}

int pqcp_edge_trust_federation_init(
	struct pqcp_edge_trust_federation *federation,
	struct pqcp_edge_trust_anchor *anchors,
	size_t anchor_capacity,
	struct pqcp_edge_federation_grant *grants,
	size_t grant_capacity)
{
	if (federation == NULL || anchors == NULL ||
	    anchor_capacity == 0U || grants == NULL ||
	    grant_capacity == 0U) {
		return -EINVAL;
	}
	memset(federation, 0, sizeof(*federation));
	memset(anchors, 0,
	       anchor_capacity * sizeof(*anchors));
	memset(grants, 0,
	       grant_capacity * sizeof(*grants));
	federation->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	federation->anchors = anchors;
	federation->anchor_capacity = anchor_capacity;
	federation->grants = grants;
	federation->grant_capacity = grant_capacity;
	federation->next_anchor_generation = 1U;
	federation->next_grant_id = 1U;
	k_mutex_init(&federation->lock);
	federation->initialized = true;
	return 0;
}

int pqcp_edge_trust_anchor_put(
	struct pqcp_edge_trust_federation *federation,
	const struct pqcp_edge_trust_anchor *anchor)
{
	struct pqcp_edge_trust_anchor candidate;
	int index;
	int ret = 0;

	if (federation == NULL || !federation->initialized ||
	    !anchor_valid(anchor)) {
		return -EINVAL;
	}
	k_mutex_lock(&federation->lock, K_FOREVER);
	index = anchor_index(federation, anchor->domain_id);
	if (index >= 0) {
		if (anchor->policy_epoch <
			    federation->anchors[index].
				    policy_epoch ||
		    anchor->revocation_epoch <
			    federation->anchors[index].
				    revocation_epoch) {
			ret = -ESTALE;
			goto out;
		}
		candidate = *anchor;
		candidate.generation =
			federation->anchors[index].generation;
	} else if (index == -ENOENT) {
		index = free_anchor_index(federation);
		if (index < 0) {
			ret = index;
			goto out;
		}
		candidate = *anchor;
		candidate.generation =
			pqcp_edge_internal_next_generation(
				&federation->
					next_anchor_generation);
	} else {
		ret = index;
		goto out;
	}
	candidate.active = true;
	federation->anchors[index] = candidate;
out:
	k_mutex_unlock(&federation->lock);
	return ret;
}

int pqcp_edge_federation_grant_issue(
	struct pqcp_edge_trust_federation *federation,
	const char *source_domain,
	const char *destination_domain,
	uint64_t capabilities,
	uint64_t operation_mask,
	uint32_t maximum_risk,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t maximum_uses,
	struct pqcp_edge_federation_grant **grant)
{
	struct pqcp_edge_federation_grant candidate;
	int index;
	int ret;

	if (federation == NULL || !federation->initialized ||
	    !pqcp_edge_internal_text_valid(
		    source_domain, PQCP_EDGE_DOMAIN_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    destination_domain,
		    PQCP_EDGE_DOMAIN_MAX_CHARS) ||
	    strcmp(source_domain, destination_domain) == 0 ||
	    capabilities == 0U || operation_mask == 0U ||
	    maximum_risk > 1000U || expires_at_ms <= now_ms ||
	    maximum_uses == 0U || grant == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&federation->lock, K_FOREVER);
	if (anchor_index(federation, source_domain) < 0 ||
	    anchor_index(federation, destination_domain) < 0) {
		*grant = NULL;
		k_mutex_unlock(&federation->lock);
		return -ENOKEY;
	}
	index = free_grant_index(federation);
	if (index < 0) {
		*grant = NULL;
		k_mutex_unlock(&federation->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.grant_id =
		pqcp_edge_internal_next_identifier(
			&federation->next_grant_id);
	ret = pqcp_edge_internal_copy_text(
		candidate.source_domain,
		sizeof(candidate.source_domain),
		source_domain);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.destination_domain,
			sizeof(candidate.destination_domain),
			destination_domain);
	}
	candidate.capabilities = capabilities;
	candidate.operation_mask = operation_mask;
	candidate.issued_at_ms = now_ms;
	candidate.expires_at_ms = expires_at_ms;
	candidate.maximum_uses = maximum_uses;
	candidate.maximum_risk = maximum_risk;
	candidate.occupied = true;
	if (ret == 0) {
		ret = grant_digest(
			&candidate, candidate.grant_digest);
	}
	if (ret == 0) {
		federation->grants[index] = candidate;
		*grant = &federation->grants[index];
	} else {
		*grant = NULL;
	}
	k_mutex_unlock(&federation->lock);
	return ret;
}

int pqcp_edge_federation_authorize(
	struct pqcp_edge_trust_federation *federation,
	const char *source_domain,
	const char *destination_domain,
	enum pqcp_edge_operation operation,
	uint64_t capabilities,
	uint32_t risk_score,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms)
{
	struct pqcp_edge_trust_anchor *source;
	struct pqcp_edge_trust_anchor *destination;
	int source_slot;
	int destination_slot;
	int ret = -EACCES;

	if (federation == NULL || !federation->initialized ||
	    source_domain == NULL || destination_domain == NULL ||
	    operation <= PQCP_EDGE_OPERATION_NONE ||
	    operation >= PQCP_EDGE_OPERATION_COUNT ||
	    risk_score > 1000U || policy_epoch == 0U ||
	    revocation_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&federation->lock, K_FOREVER);
	source_slot = anchor_index(federation, source_domain);
	destination_slot =
		anchor_index(federation, destination_domain);
	if (source_slot < 0 || destination_slot < 0) {
		ret = -ENOKEY;
		goto reject;
	}
	source = &federation->anchors[source_slot];
	destination =
		&federation->anchors[destination_slot];
	if (source->not_before_ms > now_ms ||
	    source->expires_at_ms <= now_ms ||
	    destination->not_before_ms > now_ms ||
	    destination->expires_at_ms <= now_ms ||
	    policy_epoch < source->policy_epoch ||
	    revocation_epoch < source->revocation_epoch ||
	    risk_score > source->maximum_risk ||
	    risk_score > destination->maximum_risk) {
		ret = -EKEYREJECTED;
		goto reject;
	}
	for (size_t index = 0U;
	     index < federation->grant_capacity; ++index) {
		struct pqcp_edge_federation_grant *grant =
			&federation->grants[index];

		if (!grant->occupied || grant->revoked ||
		    strcmp(grant->source_domain,
			   source_domain) != 0 ||
		    strcmp(grant->destination_domain,
			   destination_domain) != 0 ||
		    grant->expires_at_ms <= now_ms ||
		    grant->use_count >= grant->maximum_uses ||
		    risk_score > grant->maximum_risk ||
		    (grant->operation_mask &
		     PQCP_EDGE_OPERATION_BIT(operation)) == 0U ||
		    (capabilities & grant->capabilities) !=
			    capabilities) {
			continue;
		}
		++grant->use_count;
		++federation->authorization_count;
		ret = 0;
		break;
	}
reject:
	if (ret != 0) {
		++federation->rejection_count;
	}
	k_mutex_unlock(&federation->lock);
	return ret;
}

int pqcp_edge_federation_revoke(
	struct pqcp_edge_trust_federation *federation,
	uint64_t grant_id)
{
	int index;
	int ret = 0;

	if (federation == NULL || !federation->initialized ||
	    grant_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&federation->lock, K_FOREVER);
	index = grant_index(federation, grant_id);
	if (index < 0) {
		ret = index;
	} else if (federation->grants[index].revoked) {
		ret = -EALREADY;
	} else {
		federation->grants[index].revoked = true;
	}
	k_mutex_unlock(&federation->lock);
	return ret;
}

int pqcp_edge_trust_federation_audit(
	struct pqcp_edge_trust_federation *federation)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret = 0;

	if (federation == NULL || !federation->initialized ||
	    federation->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    federation->anchors == NULL ||
	    federation->grants == NULL ||
	    federation->anchor_capacity == 0U ||
	    federation->grant_capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&federation->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < federation->anchor_capacity && ret == 0;
	     ++index) {
		if (federation->anchors[index].active &&
		    (!anchor_valid(&federation->anchors[index]) ||
		     federation->anchors[index].generation == 0U)) {
			ret = -EBADMSG;
		}
	}
	for (size_t index = 0U;
	     index < federation->grant_capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_federation_grant *grant =
			&federation->grants[index];

		if (!grant->occupied) {
			continue;
		}
		if (grant->grant_id == 0U ||
		    !pqcp_edge_internal_text_valid(
			    grant->source_domain,
			    sizeof(grant->source_domain)) ||
		    !pqcp_edge_internal_text_valid(
			    grant->destination_domain,
			    sizeof(grant->destination_domain)) ||
		    grant->capabilities == 0U ||
		    grant->operation_mask == 0U ||
		    grant->expires_at_ms <=
			    grant->issued_at_ms ||
		    grant->maximum_uses == 0U ||
		    grant->use_count >
			    grant->maximum_uses ||
		    grant_digest(grant, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    digest, grant->grant_digest,
			    sizeof(digest))) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&federation->lock);
	return ret;
}
