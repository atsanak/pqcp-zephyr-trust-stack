/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded recovery-point catalog and deterministic digest-based selection.
 */

#include "sovereign_continuity_internal.h"

static bool point_state_valid(
	enum pqcp_sovereign_recovery_point_state state)
{
	return state >= PQCP_SOVEREIGN_POINT_CANDIDATE &&
	       state <= PQCP_SOVEREIGN_POINT_EXPIRED;
}

static int point_index(
	const struct pqcp_sovereign_recovery_point_catalog *catalog,
	const char *tenant_id,
	const char *point_id)
{
	for (size_t index = 0U;
	     index < catalog->capacity; ++index) {
		const struct pqcp_sovereign_recovery_point *point =
			&catalog->points[index];

		if (point->occupied &&
		    strcmp(point->tenant_id, tenant_id) == 0 &&
		    strcmp(point->point_id, point_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_point_index(
	const struct pqcp_sovereign_recovery_point_catalog *catalog)
{
	int oldest_terminal = -1;
	uint64_t oldest_time = UINT64_MAX;

	for (size_t index = 0U;
	     index < catalog->capacity; ++index) {
		const struct pqcp_sovereign_recovery_point *point =
			&catalog->points[index];

		if (!point->occupied) {
			return (int)index;
		}
		if ((point->state == PQCP_SOVEREIGN_POINT_EXPIRED ||
		     point->state ==
			     PQCP_SOVEREIGN_POINT_QUARANTINED ||
		     point->state ==
			     PQCP_SOVEREIGN_POINT_CONSUMED) &&
		    point->created_at_ms < oldest_time) {
			oldest_time = point->created_at_ms;
			oldest_terminal = (int)index;
		}
	}
	return oldest_terminal >= 0 ? oldest_terminal : -ENOSPC;
}

static int validate_point(
	const struct pqcp_sovereign_recovery_point *point)
{
	if (point == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    point->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    point->objective_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    point->point_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    point->source_id) ||
	    point->created_at_ms == 0U ||
	    point->protected_at_ms == 0U ||
	    point->protected_at_ms > point->created_at_ms ||
	    point->sequence == 0U ||
	    point->policy_epoch == 0U ||
	    point->revocation_epoch == 0U ||
	    point->fencing_epoch == 0U ||
	    point->logical_bytes == 0U ||
	    point->replica_count == 0U ||
	    !point->complete ||
	    !pqcp_sovereign_continuity_digest_valid(
		    point->content_digest) ||
	    !pqcp_sovereign_continuity_digest_valid(
		    point->manifest_digest)) {
		return -EINVAL;
	}
	if (point->expires_at_ms != 0U &&
	    point->expires_at_ms <= point->created_at_ms) {
		return -ERANGE;
	}
	return 0;
}

static bool query_valid(
	const struct pqcp_sovereign_recovery_point_query *query)
{
	return query != NULL &&
	       pqcp_sovereign_continuity_text_valid(
		       query->tenant_id) &&
	       pqcp_sovereign_continuity_text_valid(
		       query->objective_id) &&
	       query->now_ms != 0U &&
	       query->maximum_age_ms != 0U &&
	       query->minimum_policy_epoch != 0U &&
	       query->minimum_revocation_epoch != 0U &&
	       query->maximum_fencing_epoch != 0U &&
	       query->minimum_replicas != 0U;
}

static bool point_matches_query(
	const struct pqcp_sovereign_recovery_point *point,
	const struct pqcp_sovereign_recovery_point_query *query,
	uint64_t *age)
{
	uint64_t point_age;

	if (!point->occupied ||
	    point->state != PQCP_SOVEREIGN_POINT_VERIFIED ||
	    strcmp(point->tenant_id, query->tenant_id) != 0 ||
	    strcmp(point->objective_id,
		   query->objective_id) != 0 ||
	    point->protected_at_ms > query->now_ms ||
	    (point->expires_at_ms != 0U &&
	     point->expires_at_ms <= query->now_ms)) {
		return false;
	}
	point_age = query->now_ms - point->protected_at_ms;
	if (point_age > query->maximum_age_ms ||
	    point->sequence < query->minimum_sequence ||
	    point->policy_epoch <
		    query->minimum_policy_epoch ||
	    point->revocation_epoch <
		    query->minimum_revocation_epoch ||
	    point->fencing_epoch >
		    query->maximum_fencing_epoch ||
	    (query->maximum_logical_bytes != 0U &&
	     point->logical_bytes >
		     query->maximum_logical_bytes) ||
	    point->replica_count < query->minimum_replicas ||
	    (point->verification_flags &
	     query->required_verification_flags) !=
		    query->required_verification_flags ||
	    (query->require_immutable && !point->immutable) ||
	    (query->require_parent_binding &&
	     !pqcp_sovereign_continuity_digest_valid(
		     point->parent_digest))) {
		return false;
	}
	*age = point_age;
	return true;
}

static int selection_digest(
	const struct pqcp_sovereign_recovery_point *point,
	const struct pqcp_sovereign_recovery_point_query *query,
	uint64_t age,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES])
{
	static const uint8_t domain[] =
		"pqcp.sovereign.recovery-point-selection.v1";
	uint8_t numeric[64];
	size_t offset = 0U;
	const uint8_t *parts[6];
	size_t lengths[6];

	pqcp_edge_internal_write_u64(
		numeric + offset, query->now_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, age);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, query->maximum_age_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, query->minimum_sequence);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, query->minimum_policy_epoch);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, query->minimum_revocation_epoch);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, query->maximum_fencing_epoch);
	offset += 8U;
	parts[0] = domain;
	lengths[0] = sizeof(domain) - 1U;
	parts[1] = (const uint8_t *)query->tenant_id;
	lengths[1] = strlen(query->tenant_id);
	parts[2] = (const uint8_t *)query->objective_id;
	lengths[2] = strlen(query->objective_id);
	parts[3] = (const uint8_t *)point->point_id;
	lengths[3] = strlen(point->point_id);
	parts[4] = point->point_digest;
	lengths[4] = sizeof(point->point_digest);
	parts[5] = numeric;
	lengths[5] = offset;
	return pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 6U, digest);
}

static int chain_evidence(
	struct pqcp_sovereign_recovery_point *point,
	const uint8_t evidence_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms,
	uint32_t discriminator)
{
	uint8_t numeric[12];
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	const uint8_t *parts[4];
	size_t lengths[4];
	int ret;

	pqcp_edge_internal_write_u64(numeric, now_ms);
	pqcp_edge_internal_write_u32(
		numeric + 8U, discriminator);
	parts[0] = point->evidence_digest;
	lengths[0] = sizeof(point->evidence_digest);
	parts[1] = point->point_digest;
	lengths[1] = sizeof(point->point_digest);
	parts[2] = evidence_digest;
	lengths[2] = PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES;
	parts[3] = numeric;
	lengths[3] = sizeof(numeric);
	ret = pqcp_sovereign_continuity_digest_parts(
		parts, lengths, 4U, digest);
	if (ret == 0) {
		memcpy(point->evidence_digest, digest,
		       sizeof(point->evidence_digest));
	}
	return ret;
}

int pqcp_sovereign_recovery_point_catalog_init(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	struct pqcp_sovereign_recovery_point *points,
	size_t capacity)
{
	if (catalog == NULL || points == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(catalog, 0, sizeof(*catalog));
	memset(points, 0, capacity * sizeof(*points));
	catalog->schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	catalog->points = points;
	catalog->capacity = capacity;
	catalog->next_generation = 1U;
	k_mutex_init(&catalog->lock);
	catalog->initialized = true;
	return 0;
}

int pqcp_sovereign_recovery_point_put(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const struct pqcp_sovereign_recovery_point *point)
{
	struct pqcp_sovereign_recovery_point candidate;
	int index;
	int ret;

	if (catalog == NULL || !catalog->initialized) {
		return -EINVAL;
	}
	ret = validate_point(point);
	if (ret != 0) {
		return ret;
	}
	k_mutex_lock(&catalog->lock, K_FOREVER);
	index = point_index(
		catalog, point->tenant_id, point->point_id);
	if (index >= 0) {
		const struct pqcp_sovereign_recovery_point *current =
			&catalog->points[index];

		if (current->immutable ||
		    current->state ==
			    PQCP_SOVEREIGN_POINT_SELECTED ||
		    current->state ==
			    PQCP_SOVEREIGN_POINT_CONSUMED) {
			ret = -EPERM;
			goto out;
		}
		if (point->sequence <= current->sequence ||
		    point->policy_epoch <
			    current->policy_epoch ||
		    point->revocation_epoch <
			    current->revocation_epoch ||
		    point->fencing_epoch <
			    current->fencing_epoch) {
			ret = -ESTALE;
			goto out;
		}
	} else if (index == -ENOENT) {
		index = free_point_index(catalog);
	}
	if (index < 0) {
		ret = index;
		goto out;
	}
	candidate = *point;
	candidate.schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	candidate.generation =
		pqcp_edge_internal_next_generation(
			&catalog->next_generation);
	candidate.state =
		PQCP_SOVEREIGN_POINT_CANDIDATE;
	candidate.verified_at_ms = 0U;
	candidate.verification_flags = 0U;
	candidate.occupied = true;
	ret = pqcp_sovereign_continuity_digest_point(
		&candidate, candidate.point_digest);
	if (ret == 0) {
		catalog->points[index] = candidate;
	}
out:
	k_mutex_unlock(&catalog->lock);
	return ret;
}

int pqcp_sovereign_recovery_point_verify(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const char *tenant_id,
	const char *point_id,
	uint32_t generation,
	uint32_t verification_flags,
	const uint8_t evidence_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_sovereign_recovery_point *point;
	int index;
	int ret = 0;

	if (catalog == NULL || !catalog->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(point_id) ||
	    generation == 0U || verification_flags == 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    evidence_digest) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&catalog->lock, K_FOREVER);
	index = point_index(catalog, tenant_id, point_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	point = &catalog->points[index];
	if (point->generation != generation) {
		ret = -ESTALE;
	} else if (point->state !=
		   PQCP_SOVEREIGN_POINT_CANDIDATE) {
		ret = point->state ==
			      PQCP_SOVEREIGN_POINT_VERIFIED ?
			-EALREADY : -EPERM;
	} else if (point->expires_at_ms != 0U &&
		   point->expires_at_ms <= now_ms) {
		point->state = PQCP_SOVEREIGN_POINT_EXPIRED;
		ret = -ETIMEDOUT;
	} else {
		point->state = PQCP_SOVEREIGN_POINT_VERIFIED;
		point->verified_at_ms = now_ms;
		point->verification_flags = verification_flags;
		ret = chain_evidence(
			point, evidence_digest, now_ms,
			(uint32_t)PQCP_SOVEREIGN_POINT_VERIFIED);
		if (ret == 0) {
			ret = pqcp_sovereign_continuity_digest_point(
				point, point->point_digest);
		}
	}
out:
	k_mutex_unlock(&catalog->lock);
	return ret;
}

int pqcp_sovereign_recovery_point_quarantine(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const char *tenant_id,
	const char *point_id,
	uint32_t generation,
	const uint8_t evidence_digest[
		PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_sovereign_recovery_point *point;
	int index;
	int ret = 0;

	if (catalog == NULL || !catalog->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(point_id) ||
	    generation == 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    evidence_digest) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&catalog->lock, K_FOREVER);
	index = point_index(catalog, tenant_id, point_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	point = &catalog->points[index];
	if (point->generation != generation) {
		ret = -ESTALE;
	} else if (point->state ==
		   PQCP_SOVEREIGN_POINT_CONSUMED) {
		ret = -EPERM;
	} else if (point->state ==
		   PQCP_SOVEREIGN_POINT_QUARANTINED) {
		ret = -EALREADY;
	} else {
		point->state =
			PQCP_SOVEREIGN_POINT_QUARANTINED;
		ret = chain_evidence(
			point, evidence_digest, now_ms,
			(uint32_t)
				PQCP_SOVEREIGN_POINT_QUARANTINED);
		if (ret == 0) {
			ret = pqcp_sovereign_continuity_digest_point(
				point, point->point_digest);
		}
	}
	k_mutex_unlock(&catalog->lock);
	return ret;
out:
	k_mutex_unlock(&catalog->lock);
	return ret;
}

int pqcp_sovereign_recovery_point_select(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const struct pqcp_sovereign_recovery_point_query *query,
	struct pqcp_sovereign_recovery_point_selection *selection)
{
	struct pqcp_sovereign_recovery_point *best = NULL;
	uint64_t best_age = UINT64_MAX;
	int ret = 0;

	if (catalog == NULL || !catalog->initialized ||
	    !query_valid(query) || selection == NULL) {
		return -EINVAL;
	}
	memset(selection, 0, sizeof(*selection));
	k_mutex_lock(&catalog->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < catalog->capacity; ++index) {
		struct pqcp_sovereign_recovery_point *candidate =
			&catalog->points[index];
		uint64_t age;

		if (!point_matches_query(
			    candidate, query, &age)) {
			continue;
		}
		if (best == NULL ||
		    candidate->sequence > best->sequence ||
		    (candidate->sequence == best->sequence &&
		     age < best_age) ||
		    (candidate->sequence == best->sequence &&
		     age == best_age &&
		     memcmp(candidate->point_digest,
			    best->point_digest,
			    sizeof(candidate->point_digest)) < 0)) {
			best = candidate;
			best_age = age;
		}
	}
	if (best == NULL) {
		catalog->rejection_count =
			pqcp_sovereign_continuity_add_u64(
				catalog->rejection_count, 1U);
		ret = -ENOENT;
		goto out;
	}
	best->state = PQCP_SOVEREIGN_POINT_SELECTED;
	selection->generation = best->generation;
	selection->selected_at_ms = query->now_ms;
	selection->age_ms = best_age;
	selection->sequence = best->sequence;
	selection->fencing_epoch = best->fencing_epoch;
	memcpy(selection->point_digest,
	       best->point_digest,
	       sizeof(selection->point_digest));
	ret = pqcp_sovereign_continuity_copy_id(
		selection->point_id, best->point_id);
	if (ret == 0) {
		ret = selection_digest(
			best, query, best_age,
			selection->selection_digest);
	}
	if (ret == 0) {
		catalog->selection_count =
			pqcp_sovereign_continuity_add_u64(
				catalog->selection_count, 1U);
		ret = pqcp_sovereign_continuity_digest_point(
			best, best->point_digest);
	}
out:
	k_mutex_unlock(&catalog->lock);
	return ret;
}

int pqcp_sovereign_recovery_point_consume(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	const char *tenant_id,
	const char *point_id,
	uint32_t generation,
	uint64_t now_ms)
{
	struct pqcp_sovereign_recovery_point *point;
	int index;
	int ret = 0;

	if (catalog == NULL || !catalog->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(point_id) ||
	    generation == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&catalog->lock, K_FOREVER);
	index = point_index(catalog, tenant_id, point_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	point = &catalog->points[index];
	if (point->generation != generation) {
		ret = -ESTALE;
	} else if (point->state !=
		   PQCP_SOVEREIGN_POINT_SELECTED) {
		ret = point->state ==
			      PQCP_SOVEREIGN_POINT_CONSUMED ?
			-EALREADY : -EPERM;
	} else if (point->expires_at_ms != 0U &&
		   point->expires_at_ms <= now_ms) {
		point->state = PQCP_SOVEREIGN_POINT_EXPIRED;
		ret = -ETIMEDOUT;
	} else {
		point->state = PQCP_SOVEREIGN_POINT_CONSUMED;
		ret = pqcp_sovereign_continuity_digest_point(
			point, point->point_digest);
	}
out:
	k_mutex_unlock(&catalog->lock);
	return ret;
}

int pqcp_sovereign_recovery_point_catalog_expire(
	struct pqcp_sovereign_recovery_point_catalog *catalog,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (catalog == NULL || !catalog->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&catalog->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < catalog->capacity; ++index) {
		struct pqcp_sovereign_recovery_point *point =
			&catalog->points[index];

		if (!point->occupied ||
		    point->expires_at_ms == 0U ||
		    point->expires_at_ms > now_ms ||
		    point->state ==
			    PQCP_SOVEREIGN_POINT_EXPIRED ||
		    point->state ==
			    PQCP_SOVEREIGN_POINT_CONSUMED ||
		    point->state ==
			    PQCP_SOVEREIGN_POINT_QUARANTINED) {
			continue;
		}
		point->state = PQCP_SOVEREIGN_POINT_EXPIRED;
		if (pqcp_sovereign_continuity_digest_point(
			    point, point->point_digest) == 0) {
			++expired;
		}
	}
	k_mutex_unlock(&catalog->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_sovereign_recovery_point_catalog_audit(
	struct pqcp_sovereign_recovery_point_catalog *catalog)
{
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	int ret = 0;

	if (catalog == NULL || !catalog->initialized ||
	    catalog->schema_version !=
		    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
	    catalog->points == NULL || catalog->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&catalog->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < catalog->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_recovery_point *point =
			&catalog->points[index];

		if (!point->occupied) {
			continue;
		}
		if (point->schema_version !=
			    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
		    point->generation == 0U ||
		    validate_point(point) != 0 ||
		    !point_state_valid(point->state) ||
		    !pqcp_sovereign_continuity_digest_valid(
			    point->point_digest) ||
		    ((point->state ==
			      PQCP_SOVEREIGN_POINT_VERIFIED ||
		      point->state ==
			      PQCP_SOVEREIGN_POINT_SELECTED ||
		      point->state ==
			      PQCP_SOVEREIGN_POINT_CONSUMED) &&
		     (point->verified_at_ms == 0U ||
		      point->verification_flags == 0U ||
		      !pqcp_sovereign_continuity_digest_valid(
			      point->evidence_digest)))) {
			ret = -EBADMSG;
			break;
		}
		ret = pqcp_sovereign_continuity_digest_point(
			point, digest);
		if (ret == 0 &&
		    !pqcp_sovereign_continuity_digest_equal(
			    digest, point->point_digest)) {
			ret = -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < catalog->capacity && ret == 0;
		     ++other) {
			const struct pqcp_sovereign_recovery_point *peer =
				&catalog->points[other];

			if (peer->occupied &&
			    strcmp(point->tenant_id,
				   peer->tenant_id) == 0 &&
			    strcmp(point->point_id,
				   peer->point_id) == 0) {
				ret = -EEXIST;
			}
		}
	}
	k_mutex_unlock(&catalog->lock);
	return ret;
}
