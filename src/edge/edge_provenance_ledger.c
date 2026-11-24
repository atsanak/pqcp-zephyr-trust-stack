/*
 * SPDX-License-Identifier: MIT
 *
 * Tamper-evident bounded provenance ledger.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

#define PROVENANCE_CANONICAL_BYTES \
	(4U + 8U + PQCP_EDGE_OBJECT_MAX_CHARS + \
	 PQCP_EDGE_ACTOR_MAX_CHARS + PQCP_EDGE_ID_MAX_CHARS + \
	 4U + 8U + 8U + (4U * PQCP_EDGE_DIGEST_BYTES))

static bool event_valid(
	enum pqcp_edge_provenance_event event)
{
	return event >= PQCP_EDGE_PROVENANCE_CREATED &&
	       event <= PQCP_EDGE_PROVENANCE_DELETED;
}

static bool record_text_valid(
	const struct pqcp_edge_provenance_record *record)
{
	return pqcp_edge_internal_text_valid(
		       record->artifact_id,
		       sizeof(record->artifact_id)) &&
	       pqcp_edge_internal_text_valid(
		       record->actor_id,
		       sizeof(record->actor_id)) &&
	       pqcp_edge_internal_text_valid(
		       record->location_id,
		       sizeof(record->location_id));
}

static bool digest_required(
	enum pqcp_edge_provenance_event event,
	bool output)
{
	switch (event) {
	case PQCP_EDGE_PROVENANCE_CREATED:
		return output;
	case PQCP_EDGE_PROVENANCE_TRANSFORMED:
		return true;
	case PQCP_EDGE_PROVENANCE_TRANSMITTED:
	case PQCP_EDGE_PROVENANCE_STORED:
	case PQCP_EDGE_PROVENANCE_REPLICATED:
		return true;
	case PQCP_EDGE_PROVENANCE_REDACTED:
		return true;
	case PQCP_EDGE_PROVENANCE_DELETED:
		return !output;
	default:
		return false;
	}
}

static bool digest_semantics_valid(
	const struct pqcp_edge_provenance_record *record)
{
	bool input_zero = pqcp_edge_internal_all_zero(
		record->input_digest,
		sizeof(record->input_digest));
	bool output_zero = pqcp_edge_internal_all_zero(
		record->output_digest,
		sizeof(record->output_digest));

	if (digest_required(record->event, false) &&
	    input_zero) {
		return false;
	}
	if (digest_required(record->event, true) &&
	    output_zero) {
		return false;
	}
	if (record->event == PQCP_EDGE_PROVENANCE_CREATED &&
	    !input_zero) {
		return false;
	}
	if (record->event == PQCP_EDGE_PROVENANCE_DELETED &&
	    !output_zero) {
		return false;
	}
	if (record->event ==
		    PQCP_EDGE_PROVENANCE_TRANSFORMED &&
	    pqcp_edge_internal_equal(
		    record->input_digest,
		    record->output_digest,
		    sizeof(record->input_digest))) {
		return false;
	}
	return true;
}

static int canonical_record(
	const struct pqcp_edge_provenance_record *record,
	uint8_t output[PROVENANCE_CANONICAL_BYTES])
{
	size_t offset = 0U;

	if (record == NULL || output == NULL ||
	    !record_text_valid(record) ||
	    !event_valid(record->event) ||
	    !digest_semantics_valid(record)) {
		return -EINVAL;
	}
	memset(output, 0, PROVENANCE_CANONICAL_BYTES);
	pqcp_edge_internal_write_u32(
		&output[offset], record->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		&output[offset], record->sequence);
	offset += 8U;
	memcpy(&output[offset],
	       record->artifact_id,
	       strnlen(record->artifact_id,
		       sizeof(record->artifact_id)));
	offset += sizeof(record->artifact_id);
	memcpy(&output[offset],
	       record->actor_id,
	       strnlen(record->actor_id,
		       sizeof(record->actor_id)));
	offset += sizeof(record->actor_id);
	memcpy(&output[offset],
	       record->location_id,
	       strnlen(record->location_id,
		       sizeof(record->location_id)));
	offset += sizeof(record->location_id);
	pqcp_edge_internal_write_u32(
		&output[offset], (uint32_t)record->event);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		&output[offset], record->timestamp_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		&output[offset], record->policy_epoch);
	offset += 8U;
	memcpy(&output[offset],
	       record->input_digest,
	       sizeof(record->input_digest));
	offset += sizeof(record->input_digest);
	memcpy(&output[offset],
	       record->output_digest,
	       sizeof(record->output_digest));
	offset += sizeof(record->output_digest);
	memcpy(&output[offset],
	       record->previous_digest,
	       sizeof(record->previous_digest));
	offset += sizeof(record->previous_digest);
	memset(&output[offset],
	       0,
	       PQCP_EDGE_DIGEST_BYTES);
	return 0;
}

static int calculate_record_digest(
	const struct pqcp_edge_provenance_record *record,
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t canonical[PROVENANCE_CANONICAL_BYTES];
	int ret;

	ret = canonical_record(record, canonical);
	if (ret != 0) {
		return ret;
	}
	return pqcp_edge_internal_sha256(
		canonical, sizeof(canonical), digest);
}

static bool record_shape_valid(
	const struct pqcp_edge_provenance_record *record)
{
	return record != NULL &&
	       record->schema_version ==
		       PQCP_EDGE_SCHEMA_VERSION &&
	       record->sequence != 0U &&
	       record->timestamp_ms != 0U &&
	       record->policy_epoch != 0U &&
	       record_text_valid(record) &&
	       event_valid(record->event) &&
	       digest_semantics_valid(record) &&
	       !pqcp_edge_internal_all_zero(
		       record->record_digest,
		       sizeof(record->record_digest));
}

static size_t oldest_index(
	const struct pqcp_edge_provenance_ledger *ledger)
{
	if (ledger->count < ledger->capacity) {
		return 0U;
	}
	return ledger->next_index;
}

static size_t logical_index(
	const struct pqcp_edge_provenance_ledger *ledger,
	size_t logical_offset)
{
	return (oldest_index(ledger) + logical_offset) %
	       ledger->capacity;
}

static int sequence_index(
	const struct pqcp_edge_provenance_ledger *ledger,
	uint64_t sequence)
{
	for (size_t offset = 0U;
	     offset < ledger->count; ++offset) {
		size_t index = logical_index(ledger, offset);

		if (ledger->records[index].occupied &&
		    ledger->records[index].sequence ==
			    sequence) {
			return (int)index;
		}
	}
	return -ENOENT;
}

int pqcp_edge_provenance_ledger_init(
	struct pqcp_edge_provenance_ledger *ledger,
	struct pqcp_edge_provenance_record *records,
	size_t capacity)
{
	if (ledger == NULL || records == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(ledger, 0, sizeof(*ledger));
	memset(records, 0, capacity * sizeof(*records));
	ledger->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	ledger->records = records;
	ledger->capacity = capacity;
	ledger->next_sequence = 1U;
	k_mutex_init(&ledger->lock);
	ledger->initialized = true;
	return 0;
}

int pqcp_edge_provenance_append(
	struct pqcp_edge_provenance_ledger *ledger,
	const char *artifact_id,
	const char *actor_id,
	const char *location_id,
	enum pqcp_edge_provenance_event event,
	uint64_t policy_epoch,
	const uint8_t input_digest[PQCP_EDGE_DIGEST_BYTES],
	const uint8_t output_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_edge_provenance_record *record)
{
	struct pqcp_edge_provenance_record candidate;
	int ret;

	if (ledger == NULL || !ledger->initialized ||
	    artifact_id == NULL || actor_id == NULL ||
	    location_id == NULL || !event_valid(event) ||
	    policy_epoch == 0U || input_digest == NULL ||
	    output_digest == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	ret = pqcp_edge_internal_copy_text(
		candidate.artifact_id,
		sizeof(candidate.artifact_id),
		artifact_id);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_internal_copy_text(
		candidate.actor_id,
		sizeof(candidate.actor_id),
		actor_id);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_internal_copy_text(
		candidate.location_id,
		sizeof(candidate.location_id),
		location_id);
	if (ret != 0) {
		return ret;
	}
	candidate.event = event;
	candidate.timestamp_ms = now_ms;
	candidate.policy_epoch = policy_epoch;
	memcpy(candidate.input_digest,
	       input_digest,
	       sizeof(candidate.input_digest));
	memcpy(candidate.output_digest,
	       output_digest,
	       sizeof(candidate.output_digest));
	if (!digest_semantics_valid(&candidate)) {
		return -EINVAL;
	}
	k_mutex_lock(&ledger->lock, K_FOREVER);
	candidate.sequence =
		pqcp_edge_internal_next_identifier(
			&ledger->next_sequence);
	memcpy(candidate.previous_digest,
	       ledger->chain_head,
	       sizeof(candidate.previous_digest));
	ret = calculate_record_digest(
		&candidate, candidate.record_digest);
	if (ret != 0) {
		k_mutex_unlock(&ledger->lock);
		return ret;
	}
	candidate.occupied = true;
	if (ledger->count == ledger->capacity) {
		++ledger->dropped_count;
	} else {
		++ledger->count;
	}
	ledger->records[ledger->next_index] = candidate;
	ledger->next_index =
		(ledger->next_index + 1U) %
		ledger->capacity;
	memcpy(ledger->chain_head,
	       candidate.record_digest,
	       sizeof(ledger->chain_head));
	if (record != NULL) {
		*record = candidate;
	}
	k_mutex_unlock(&ledger->lock);
	return 0;
}

int pqcp_edge_provenance_find(
	struct pqcp_edge_provenance_ledger *ledger,
	uint64_t sequence,
	struct pqcp_edge_provenance_record *record)
{
	int index;

	if (ledger == NULL || !ledger->initialized ||
	    sequence == 0U || record == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&ledger->lock, K_FOREVER);
	index = sequence_index(ledger, sequence);
	if (index >= 0) {
		*record = ledger->records[index];
	}
	k_mutex_unlock(&ledger->lock);
	return index < 0 ? index : 0;
}

int pqcp_edge_provenance_verify(
	struct pqcp_edge_provenance_ledger *ledger)
{
	uint8_t expected_previous[PQCP_EDGE_DIGEST_BYTES];
	uint8_t expected_digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t previous_sequence = 0U;
	int ret = 0;

	if (ledger == NULL || !ledger->initialized ||
	    ledger->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    ledger->records == NULL ||
	    ledger->capacity == 0U ||
	    ledger->count > ledger->capacity ||
	    ledger->next_index >= ledger->capacity) {
		return -EINVAL;
	}
	memset(expected_previous, 0,
	       sizeof(expected_previous));
	k_mutex_lock(&ledger->lock, K_FOREVER);
	for (size_t offset = 0U;
	     offset < ledger->count; ++offset) {
		size_t index = logical_index(ledger, offset);
		const struct pqcp_edge_provenance_record *current =
			&ledger->records[index];

		if (!record_shape_valid(current)) {
			ret = -EBADMSG;
			break;
		}
		if (previous_sequence != 0U &&
		    current->sequence !=
			    previous_sequence + 1U) {
			ret = -ESTALE;
			break;
		}
		if (offset != 0U &&
		    !pqcp_edge_internal_equal(
			    current->previous_digest,
			    expected_previous,
			    sizeof(expected_previous))) {
			ret = -EILSEQ;
			break;
		}
		ret = calculate_record_digest(
			current, expected_digest);
		if (ret != 0 ||
		    !pqcp_edge_internal_equal(
			    current->record_digest,
			    expected_digest,
			    sizeof(expected_digest))) {
			ret = ret != 0 ? ret : -EBADMSG;
			break;
		}
		memcpy(expected_previous,
		       current->record_digest,
		       sizeof(expected_previous));
		previous_sequence = current->sequence;
	}
	if (ret == 0 && ledger->count != 0U &&
	    !pqcp_edge_internal_equal(
		    ledger->chain_head,
		    expected_previous,
		    sizeof(expected_previous))) {
		ret = -EBADMSG;
	}
	if (ret == 0 && ledger->count == 0U &&
	    !pqcp_edge_internal_all_zero(
		    ledger->chain_head,
		    sizeof(ledger->chain_head))) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&ledger->lock);
	return ret;
}
