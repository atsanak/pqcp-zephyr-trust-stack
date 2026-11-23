/*
 * SPDX-License-Identifier: MIT
 *
 * Nonce- and channel-bound workload attestation challenges.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int record_index(
	const struct pqcp_edge_attestation_manager *manager,
	uint64_t challenge_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->records[index].occupied &&
		    manager->records[index].challenge_id ==
			    challenge_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_record_index(
	const struct pqcp_edge_attestation_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->records[index].occupied ||
		    manager->records[index].state ==
			    PQCP_EDGE_ATTESTATION_EXPIRED) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool nonce_exists(
	const struct pqcp_edge_attestation_manager *manager,
	const uint8_t nonce[PQCP_EDGE_NONCE_BYTES])
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->records[index].occupied &&
		    pqcp_edge_internal_equal(
			    manager->records[index].nonce,
			    nonce, PQCP_EDGE_NONCE_BYTES)) {
			return true;
		}
	}
	return false;
}

int pqcp_edge_attestation_manager_init(
	struct pqcp_edge_attestation_manager *manager,
	struct pqcp_edge_attestation_record *records,
	size_t capacity)
{
	if (manager == NULL || records == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(records, 0, capacity * sizeof(*records));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->records = records;
	manager->capacity = capacity;
	manager->next_challenge_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_attestation_challenge(
	struct pqcp_edge_attestation_manager *manager,
	const char *principal_id,
	const uint8_t nonce[PQCP_EDGE_NONCE_BYTES],
	const uint8_t expected_binding[PQCP_EDGE_DIGEST_BYTES],
	uint32_t required_posture_mask,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_attestation_record **record)
{
	struct pqcp_edge_attestation_record candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_edge_internal_text_valid(
		    principal_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    nonce == NULL || expected_binding == NULL ||
	    pqcp_edge_internal_all_zero(
		    nonce, PQCP_EDGE_NONCE_BYTES) ||
	    pqcp_edge_internal_all_zero(
		    expected_binding, PQCP_EDGE_DIGEST_BYTES) ||
	    required_posture_mask == 0U ||
	    expires_at_ms <= now_ms || record == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	if (nonce_exists(manager, nonce)) {
		*record = NULL;
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	index = free_record_index(manager);
	if (index < 0) {
		*record = NULL;
		k_mutex_unlock(&manager->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.challenge_id =
		pqcp_edge_internal_next_identifier(
			&manager->next_challenge_id);
	ret = pqcp_edge_internal_copy_text(
		candidate.principal_id,
		sizeof(candidate.principal_id), principal_id);
	memcpy(candidate.nonce, nonce, sizeof(candidate.nonce));
	memcpy(candidate.expected_binding, expected_binding,
	       sizeof(candidate.expected_binding));
	candidate.issued_at_ms = now_ms;
	candidate.expires_at_ms = expires_at_ms;
	candidate.required_posture_mask =
		required_posture_mask;
	candidate.state = PQCP_EDGE_ATTESTATION_CHALLENGED;
	candidate.occupied = true;
	if (ret == 0) {
		manager->records[index] = candidate;
		*record = &manager->records[index];
	} else {
		*record = NULL;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_attestation_submit(
	struct pqcp_edge_attestation_manager *manager,
	uint64_t challenge_id,
	uint32_t observed_posture_mask,
	const uint8_t evidence_digest[PQCP_EDGE_DIGEST_BYTES],
	const uint8_t binding_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_edge_attestation_record *record;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    challenge_id == 0U || evidence_digest == NULL ||
	    binding_digest == NULL ||
	    pqcp_edge_internal_all_zero(
		    evidence_digest, PQCP_EDGE_DIGEST_BYTES)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = record_index(manager, challenge_id);
	if (index < 0) {
		ret = index;
		goto reject;
	}
	record = &manager->records[index];
	if (record->state !=
	    PQCP_EDGE_ATTESTATION_CHALLENGED) {
		ret = -EALREADY;
		goto reject;
	}
	if (record->expires_at_ms <= now_ms) {
		record->state = PQCP_EDGE_ATTESTATION_EXPIRED;
		ret = -ETIMEDOUT;
		goto reject;
	}
	record->state = PQCP_EDGE_ATTESTATION_RECEIVED;
	record->observed_posture_mask =
		observed_posture_mask;
	memcpy(record->evidence_digest, evidence_digest,
	       sizeof(record->evidence_digest));
	if (!pqcp_edge_internal_equal(
		    record->expected_binding, binding_digest,
		    sizeof(record->expected_binding)) ||
	    (record->required_posture_mask &
	     ~observed_posture_mask) != 0U) {
		record->state = PQCP_EDGE_ATTESTATION_REJECTED;
		ret = -EKEYREJECTED;
		goto reject;
	}
	record->state = PQCP_EDGE_ATTESTATION_VERIFIED;
	record->verified_at_ms = now_ms;
	++manager->verified_count;
	goto out;
reject:
	++manager->rejected_count;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_attestation_is_fresh(
	struct pqcp_edge_attestation_manager *manager,
	const char *principal_id,
	uint64_t now_ms,
	bool *fresh)
{
	uint64_t newest = 0U;

	if (manager == NULL || !manager->initialized ||
	    principal_id == NULL || fresh == NULL) {
		return -EINVAL;
	}
	*fresh = false;
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_edge_attestation_record *record =
			&manager->records[index];

		if (record->occupied &&
		    record->state ==
			    PQCP_EDGE_ATTESTATION_VERIFIED &&
		    record->expires_at_ms > now_ms &&
		    strcmp(record->principal_id,
			   principal_id) == 0 &&
		    record->verified_at_ms > newest) {
			newest = record->verified_at_ms;
			*fresh = true;
		}
	}
	k_mutex_unlock(&manager->lock);
	return *fresh ? 0 : -ENOENT;
}

int pqcp_edge_attestation_expire(
	struct pqcp_edge_attestation_manager *manager,
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
		if (manager->records[index].occupied &&
		    manager->records[index].expires_at_ms <=
			    now_ms &&
		    manager->records[index].state !=
			    PQCP_EDGE_ATTESTATION_EXPIRED) {
			manager->records[index].state =
				PQCP_EDGE_ATTESTATION_EXPIRED;
			++expired;
		}
	}
	k_mutex_unlock(&manager->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_attestation_manager_audit(
	struct pqcp_edge_attestation_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->records == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_attestation_record *record =
			&manager->records[index];

		if (!record->occupied) {
			continue;
		}
		if (record->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    record->challenge_id == 0U ||
		    !pqcp_edge_internal_text_valid(
			    record->principal_id,
			    sizeof(record->principal_id)) ||
		    record->expires_at_ms <=
			    record->issued_at_ms ||
		    record->required_posture_mask == 0U ||
		    record->state <=
			    PQCP_EDGE_ATTESTATION_EMPTY ||
		    record->state >
			    PQCP_EDGE_ATTESTATION_EXPIRED ||
		    pqcp_edge_internal_all_zero(
			    record->nonce, sizeof(record->nonce)) ||
		    pqcp_edge_internal_all_zero(
			    record->expected_binding,
			    sizeof(record->expected_binding))) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
