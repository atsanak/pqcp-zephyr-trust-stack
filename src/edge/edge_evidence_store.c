/*
 * SPDX-License-Identifier: MIT
 *
 * Chain-bound incident evidence custody.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int evidence_index(
	const struct pqcp_edge_evidence_store *store,
	uint64_t evidence_id)
{
	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		if (store->evidence[index].occupied &&
		    store->evidence[index].evidence_id ==
			    evidence_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_evidence_index(
	const struct pqcp_edge_evidence_store *store)
{
	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		if (!store->evidence[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int evidence_digest(
	const struct pqcp_edge_evidence *evidence,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[36];
	const uint8_t *parts[5];
	size_t lengths[5];
	size_t offset = 0U;

	pqcp_edge_internal_write_u32(
		numeric + offset, evidence->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, evidence->evidence_id);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, evidence->incident_id);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, evidence->captured_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, evidence->expires_at_ms);
	offset += 8U;
	parts[0] = numeric;
	lengths[0] = offset;
	parts[1] = (const uint8_t *)evidence->source_id;
	lengths[1] = strlen(evidence->source_id);
	parts[2] =
		(const uint8_t *)evidence->classification;
	lengths[2] = strlen(evidence->classification);
	parts[3] = evidence->payload_digest;
	lengths[3] = sizeof(evidence->payload_digest);
	parts[4] = evidence->previous_digest;
	lengths[4] = sizeof(evidence->previous_digest);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 5U, output);
}

int pqcp_edge_evidence_store_init(
	struct pqcp_edge_evidence_store *store,
	struct pqcp_edge_evidence *evidence,
	size_t capacity)
{
	if (store == NULL || evidence == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(store, 0, sizeof(*store));
	memset(evidence, 0, capacity * sizeof(*evidence));
	store->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	store->evidence = evidence;
	store->capacity = capacity;
	store->next_evidence_id = 1U;
	k_mutex_init(&store->lock);
	store->initialized = true;
	return 0;
}

int pqcp_edge_evidence_capture(
	struct pqcp_edge_evidence_store *store,
	uint64_t incident_id,
	const char *source_id,
	const char *classification,
	const uint8_t *payload,
	size_t payload_length,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_evidence **evidence)
{
	struct pqcp_edge_evidence candidate;
	int index;
	int ret;

	if (store == NULL || !store->initialized ||
	    incident_id == 0U ||
	    !pqcp_edge_internal_text_valid(
		    source_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    classification, PQCP_EDGE_LABEL_MAX_CHARS) ||
	    payload == NULL || payload_length == 0U ||
	    payload_length > PQCP_EDGE_EVIDENCE_MAX_BYTES ||
	    expires_at_ms <= now_ms || evidence == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	index = free_evidence_index(store);
	if (index < 0) {
		*evidence = NULL;
		k_mutex_unlock(&store->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.evidence_id =
		pqcp_edge_internal_next_identifier(
			&store->next_evidence_id);
	candidate.incident_id = incident_id;
	ret = pqcp_edge_internal_copy_text(
		candidate.source_id,
		sizeof(candidate.source_id), source_id);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.classification,
			sizeof(candidate.classification),
			classification);
	}
	candidate.captured_at_ms = now_ms;
	candidate.expires_at_ms = expires_at_ms;
	memcpy(candidate.payload, payload, payload_length);
	candidate.payload_length = payload_length;
	if (ret == 0) {
		ret = pqcp_edge_internal_sha256(
			payload, payload_length,
			candidate.payload_digest);
	}
	if (ret == 0) {
		memcpy(candidate.previous_digest,
		       store->chain_head,
		       sizeof(candidate.previous_digest));
		ret = evidence_digest(
			&candidate, candidate.evidence_digest);
	}
	if (ret == 0) {
		candidate.occupied = true;
		store->evidence[index] = candidate;
		memcpy(store->chain_head,
		       candidate.evidence_digest,
		       sizeof(store->chain_head));
		*evidence = &store->evidence[index];
		++store->capture_count;
	} else {
		*evidence = NULL;
	}
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_evidence_seal(
	struct pqcp_edge_evidence_store *store,
	uint64_t evidence_id)
{
	int index;
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    evidence_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	index = evidence_index(store, evidence_id);
	if (index < 0) {
		ret = index;
	} else if (store->evidence[index].sealed) {
		ret = -EALREADY;
	} else {
		store->evidence[index].sealed = true;
	}
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_evidence_export(
	struct pqcp_edge_evidence_store *store,
	uint64_t evidence_id,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	const struct pqcp_edge_evidence *evidence;
	int index;
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    evidence_id == 0U || output == NULL ||
	    output_length == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	index = evidence_index(store, evidence_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	evidence = &store->evidence[index];
	if (!evidence->sealed) {
		ret = -EAGAIN;
	} else if (output_capacity <
		   evidence->payload_length) {
		ret = -ENOBUFS;
	} else {
		memcpy(output, evidence->payload,
		       evidence->payload_length);
		*output_length = evidence->payload_length;
	}
out:
	if (ret != 0) {
		*output_length = 0U;
	}
	k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_edge_evidence_expire(
	struct pqcp_edge_evidence_store *store,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (store == NULL || !store->initialized ||
	    expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < store->capacity; ++index) {
		if (store->evidence[index].occupied &&
		    !store->evidence[index].sealed &&
		    store->evidence[index].expires_at_ms <=
			    now_ms) {
			pqcp_runtime_secure_zero(
				&store->evidence[index],
				sizeof(store->evidence[index]));
			++expired;
		}
	}
	k_mutex_unlock(&store->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_edge_evidence_store_audit(
	struct pqcp_edge_evidence_store *store)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t payload[PQCP_EDGE_DIGEST_BYTES];
	int ret = 0;

	if (store == NULL || !store->initialized ||
	    store->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    store->evidence == NULL || store->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&store->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < store->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_evidence *evidence =
			&store->evidence[index];

		if (!evidence->occupied) {
			continue;
		}
		if (evidence->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    evidence->evidence_id == 0U ||
		    evidence->incident_id == 0U ||
		    !pqcp_edge_internal_text_valid(
			    evidence->source_id,
			    sizeof(evidence->source_id)) ||
		    !pqcp_edge_internal_text_valid(
			    evidence->classification,
			    sizeof(evidence->classification)) ||
		    evidence->payload_length == 0U ||
		    evidence->payload_length >
			    sizeof(evidence->payload) ||
		    pqcp_edge_internal_sha256(
			    evidence->payload,
			    evidence->payload_length,
			    payload) != 0 ||
		    !pqcp_edge_internal_equal(
			    payload, evidence->payload_digest,
			    sizeof(payload)) ||
		    evidence_digest(evidence, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    digest, evidence->evidence_digest,
			    sizeof(digest))) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&store->lock);
	return ret;
}
