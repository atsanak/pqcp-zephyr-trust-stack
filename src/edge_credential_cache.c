/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Monotonic workload credential cache.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int record_index(
	const struct pqcp_edge_credential_cache *cache,
	const char *credential_id)
{
	for (size_t index = 0U;
	     index < cache->capacity; ++index) {
		if (cache->records[index].occupied &&
		    strcmp(cache->records[index].credential_id,
			   credential_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_record_index(
	const struct pqcp_edge_credential_cache *cache)
{
	for (size_t index = 0U;
	     index < cache->capacity; ++index) {
		/* Revoked records are tombstones and are never recycled. */
		if (!cache->records[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool record_valid(
	const struct pqcp_edge_credential_record *record)
{
	return record != NULL &&
	       pqcp_edge_internal_text_valid(
		       record->credential_id,
		       sizeof(record->credential_id)) &&
	       pqcp_edge_internal_text_valid(
		       record->principal_id,
		       sizeof(record->principal_id)) &&
	       pqcp_edge_internal_text_valid(
		       record->issuer_domain,
		       sizeof(record->issuer_domain)) &&
	       record->issuance_epoch != 0U &&
	       record->policy_epoch != 0U &&
	       record->revocation_epoch != 0U &&
	       record->refresh_at_ms >= record->issued_at_ms &&
	       record->expires_at_ms > record->refresh_at_ms &&
	       record->capabilities != 0U &&
	       !pqcp_edge_internal_all_zero(
		       record->public_key_digest,
		       sizeof(record->public_key_digest)) &&
	       !pqcp_edge_internal_all_zero(
		       record->credential_digest,
		       sizeof(record->credential_digest));
}

int pqcp_edge_credential_cache_init(
	struct pqcp_edge_credential_cache *cache,
	struct pqcp_edge_credential_record *records,
	size_t capacity)
{
	if (cache == NULL || records == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(cache, 0, sizeof(*cache));
	memset(records, 0, capacity * sizeof(*records));
	cache->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	cache->records = records;
	cache->capacity = capacity;
	cache->next_generation = 1U;
	k_mutex_init(&cache->lock);
	cache->initialized = true;
	return 0;
}

int pqcp_edge_credential_put(
	struct pqcp_edge_credential_cache *cache,
	const struct pqcp_edge_credential_record *record,
	uint64_t now_ms)
{
	struct pqcp_edge_credential_record candidate;
	int index;
	int ret = 0;

	if (cache == NULL || !cache->initialized ||
	    !record_valid(record) ||
	    record->issued_at_ms > now_ms ||
	    record->expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	k_mutex_lock(&cache->lock, K_FOREVER);
	index = record_index(cache, record->credential_id);
	if (index >= 0) {
		/* A revoked id stays revoked until an explicit policy
		 * (none exists) clears the tombstone.
		 */
		if (cache->records[index].state ==
		    PQCP_EDGE_CREDENTIAL_REVOKED) {
			ret = -EKEYREVOKED;
			goto reject;
		}
		if (record->issuance_epoch <=
			    cache->records[index].issuance_epoch ||
		    record->policy_epoch <
			    cache->records[index].policy_epoch ||
		    record->revocation_epoch <
			    cache->records[index].
				    revocation_epoch ||
		    strcmp(record->principal_id,
			   cache->records[index].principal_id) != 0) {
			ret = -ESTALE;
			goto reject;
		}
		candidate = *record;
		candidate.generation =
			cache->records[index].generation;
	} else if (index == -ENOENT) {
		index = free_record_index(cache);
		if (index < 0) {
			ret = index;
			goto reject;
		}
		candidate = *record;
		candidate.generation =
			pqcp_edge_internal_next_generation(
				&cache->next_generation);
	} else {
		ret = index;
		goto reject;
	}
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.state =
		now_ms >= candidate.refresh_at_ms ?
			PQCP_EDGE_CREDENTIAL_REFRESH_REQUIRED :
			PQCP_EDGE_CREDENTIAL_ACTIVE;
	candidate.occupied = true;
	cache->records[index] = candidate;
	goto out;
reject:
	++cache->rejection_count;
out:
	k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_edge_credential_authorize(
	struct pqcp_edge_credential_cache *cache,
	const char *credential_id,
	const char *principal_id,
	uint64_t required_capabilities,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms)
{
	const struct pqcp_edge_credential_record *record;
	int index;
	int ret = 0;

	if (cache == NULL || !cache->initialized ||
	    credential_id == NULL || principal_id == NULL ||
	    required_capabilities == 0U || policy_epoch == 0U ||
	    revocation_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&cache->lock, K_FOREVER);
	index = record_index(cache, credential_id);
	if (index < 0) {
		ret = index;
		goto reject;
	}
	record = &cache->records[index];
	if (strcmp(record->principal_id, principal_id) != 0) {
		ret = -EACCES;
	} else if (record->state ==
		   PQCP_EDGE_CREDENTIAL_REVOKED) {
		ret = -EKEYREVOKED;
	} else if ((record->capabilities & required_capabilities) !=
		   required_capabilities) {
		ret = -EACCES;
	} else if (record->expires_at_ms <= now_ms) {
		ret = -EKEYEXPIRED;
	} else if (record->policy_epoch < policy_epoch ||
		   record->revocation_epoch < revocation_epoch) {
		ret = -ESTALE;
	} else if (record->state ==
		   PQCP_EDGE_CREDENTIAL_REFRESH_REQUIRED) {
		ret = -EAGAIN;
	}
	if (ret == 0) {
		goto out;
	}
reject:
	++cache->rejection_count;
out:
	k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_edge_credential_revoke(
	struct pqcp_edge_credential_cache *cache,
	const char *credential_id,
	uint64_t revocation_epoch)
{
	int index;
	int ret = 0;

	if (cache == NULL || !cache->initialized ||
	    credential_id == NULL || revocation_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&cache->lock, K_FOREVER);
	index = record_index(cache, credential_id);
	if (index < 0) {
		ret = index;
	} else if (revocation_epoch <=
		   cache->records[index].revocation_epoch) {
		ret = -ESTALE;
	} else {
		cache->records[index].revocation_epoch =
			revocation_epoch;
		cache->records[index].state =
			PQCP_EDGE_CREDENTIAL_REVOKED;
	}
	k_mutex_unlock(&cache->lock);
	return ret;
}

int pqcp_edge_credential_tick(
	struct pqcp_edge_credential_cache *cache,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (cache == NULL || !cache->initialized ||
	    changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&cache->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < cache->capacity; ++index) {
		struct pqcp_edge_credential_record *record =
			&cache->records[index];

		if (!record->occupied ||
		    record->state ==
			    PQCP_EDGE_CREDENTIAL_REVOKED) {
			continue;
		}
		if (record->expires_at_ms <= now_ms &&
		    record->state !=
			    PQCP_EDGE_CREDENTIAL_EXPIRED) {
			record->state =
				PQCP_EDGE_CREDENTIAL_EXPIRED;
			++changed;
		} else if (record->refresh_at_ms <= now_ms &&
			   record->state ==
				   PQCP_EDGE_CREDENTIAL_ACTIVE) {
			record->state =
				PQCP_EDGE_CREDENTIAL_REFRESH_REQUIRED;
			++cache->refresh_count;
			++changed;
		}
	}
	k_mutex_unlock(&cache->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_edge_credential_cache_audit(
	struct pqcp_edge_credential_cache *cache)
{
	int ret = 0;

	if (cache == NULL || !cache->initialized ||
	    cache->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    cache->records == NULL || cache->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&cache->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < cache->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_credential_record *record =
			&cache->records[index];

		if (!record->occupied) {
			continue;
		}
		if (!record_valid(record) ||
		    record->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    record->generation == 0U ||
		    record->state <= PQCP_EDGE_CREDENTIAL_EMPTY ||
		    record->state >
			    PQCP_EDGE_CREDENTIAL_REVOKED) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&cache->lock);
	return ret;
}
