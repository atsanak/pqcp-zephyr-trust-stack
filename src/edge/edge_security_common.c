/*
 * SPDX-License-Identifier: MIT
 *
 * Shared bounded primitives for the edge security plane.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "edge_security_internal.h"
#include "runtime_internal.h"

bool pqcp_edge_internal_all_zero(
	const uint8_t *value,
	size_t length)
{
	uint8_t aggregate = 0U;

	if (value == NULL) {
		return length == 0U;
	}
	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate == 0U;
}

bool pqcp_edge_internal_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if ((left == NULL || right == NULL) && length != 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

bool pqcp_edge_internal_text_valid(
	const char *value,
	size_t capacity)
{
	if (value == NULL || capacity < 2U) {
		return false;
	}
	for (size_t index = 0U; index < capacity; ++index) {
		if (value[index] == '\0') {
			return index != 0U;
		}
	}
	return false;
}

int pqcp_edge_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	size_t length;

	if (destination == NULL || source == NULL ||
	    capacity < 2U) {
		return -EINVAL;
	}
	length = strnlen(source, capacity);
	if (length == 0U || length >= capacity) {
		return -ENAMETOOLONG;
	}
	memcpy(destination, source, length);
	destination[length] = '\0';
	return 0;
}

uint32_t pqcp_edge_internal_next_generation(
	uint32_t *generation)
{
	if (generation == NULL) {
		return 0U;
	}
	if (*generation == 0U || *generation == UINT32_MAX) {
		*generation = 1U;
	} else {
		++(*generation);
	}
	return *generation;
}

uint64_t pqcp_edge_internal_next_identifier(
	uint64_t *identifier)
{
	if (identifier == NULL) {
		return 0U;
	}
	/*
	 * The counter holds the next identifier to issue: hand it out
	 * unchanged (0 means uninitialised and starts at 1) and advance
	 * afterwards, so the first identifier is 1 and not 2. UINT64_MAX is
	 * never issued: a counter that reached it wraps back to 1.
	 */
	uint64_t issued = *identifier;

	if (issued == 0U || issued == UINT64_MAX) {
		issued = 1U;
	}
	*identifier = issued + 1U;
	return issued;
}

uint64_t pqcp_edge_internal_saturating_add_u64(
	uint64_t left,
	uint64_t right)
{
	if (UINT64_MAX - left < right) {
		return UINT64_MAX;
	}
	return left + right;
}

uint32_t pqcp_edge_internal_saturating_add_u32(
	uint32_t left,
	uint32_t right)
{
	if (UINT32_MAX - left < right) {
		return UINT32_MAX;
	}
	return left + right;
}

uint64_t pqcp_edge_internal_backoff(
	uint64_t base_ms,
	uint64_t maximum_ms,
	uint32_t attempt)
{
	uint64_t delay;

	if (base_ms == 0U || maximum_ms < base_ms) {
		return 0U;
	}
	delay = base_ms;
	for (uint32_t index = 1U; index < attempt; ++index) {
		if (delay >= maximum_ms ||
		    delay > maximum_ms / 2U) {
			return maximum_ms;
		}
		delay *= 2U;
	}
	return delay > maximum_ms ? maximum_ms : delay;
}

int pqcp_edge_internal_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	return pqcp_runtime_internal_sha256(
		input, input_length, output);
}

int pqcp_edge_internal_sha256_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, part_count, output);
}

int pqcp_edge_internal_hmac(
	const uint8_t key[PQCP_EDGE_KEY_BYTES],
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_EDGE_TAG_BYTES])
{
	if (key == NULL || output == NULL ||
	    (input == NULL && input_length != 0U)) {
		return -EINVAL;
	}
	return pqcp_runtime_internal_hmac_sha256(
		key, PQCP_EDGE_KEY_BYTES,
		input, input_length, output);
}

int pqcp_edge_internal_hkdf(
	const uint8_t salt[PQCP_EDGE_KEY_BYTES],
	const uint8_t input_key[PQCP_EDGE_KEY_BYTES],
	const uint8_t *info,
	size_t info_length,
	uint8_t output[PQCP_EDGE_KEY_BYTES])
{
	if (salt == NULL || input_key == NULL ||
	    output == NULL ||
	    (info == NULL && info_length != 0U)) {
		return -EINVAL;
	}
	return pqcp_runtime_internal_hkdf_sha256(
		salt, PQCP_EDGE_KEY_BYTES,
		input_key, PQCP_EDGE_KEY_BYTES,
		info, info_length,
		output, PQCP_EDGE_KEY_BYTES);
}

void pqcp_edge_internal_write_u16(
	uint8_t output[2],
	uint16_t value)
{
	output[0] = (uint8_t)(value >> 8);
	output[1] = (uint8_t)value;
}

void pqcp_edge_internal_write_u32(
	uint8_t output[4],
	uint32_t value)
{
	output[0] = (uint8_t)(value >> 24);
	output[1] = (uint8_t)(value >> 16);
	output[2] = (uint8_t)(value >> 8);
	output[3] = (uint8_t)value;
}

void pqcp_edge_internal_write_u64(
	uint8_t output[8],
	uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[7U - index] =
			(uint8_t)(value >> (index * 8U));
	}
}

uint16_t pqcp_edge_internal_read_u16(
	const uint8_t input[2])
{
	return ((uint16_t)input[0] << 8) |
	       input[1];
}

uint32_t pqcp_edge_internal_read_u32(
	const uint8_t input[4])
{
	return ((uint32_t)input[0] << 24) |
	       ((uint32_t)input[1] << 16) |
	       ((uint32_t)input[2] << 8) |
	       input[3];
}

uint64_t pqcp_edge_internal_read_u64(
	const uint8_t input[8])
{
	uint64_t value = 0U;

	for (size_t index = 0U; index < 8U; ++index) {
		value = (value << 8) | input[index];
	}
	return value;
}

static size_t bounded_text_length(
	const char *text,
	size_t capacity)
{
	size_t length;

	if (text == NULL) {
		return 0U;
	}
	length = strnlen(text, capacity);
	return length < capacity ? length : 0U;
}

int pqcp_edge_internal_object_digest(
	const struct pqcp_edge_vault_object *object,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[52];
	const uint8_t *parts[8];
	size_t lengths[8];
	size_t part_count = 0U;
	size_t offset = 0U;

	if (object == NULL || output == NULL ||
	    !pqcp_edge_internal_text_valid(
		    object->object_id,
		    sizeof(object->object_id)) ||
	    !pqcp_edge_internal_text_valid(
		    object->namespace_id,
		    sizeof(object->namespace_id)) ||
	    !pqcp_edge_internal_text_valid(
		    object->owner_id,
		    sizeof(object->owner_id)) ||
	    !pqcp_edge_internal_text_valid(
		    object->classification,
		    sizeof(object->classification)) ||
	    object->value_length >
		    sizeof(object->value)) {
		return -EINVAL;
	}
	pqcp_edge_internal_write_u32(
		numeric + offset, object->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, object->generation);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, object->version);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, object->created_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, object->updated_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, object->expires_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, object->policy_epoch);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, object->permissions);
	offset += 4U;
	parts[part_count] = numeric;
	lengths[part_count++] = offset;
	parts[part_count] =
		(const uint8_t *)object->object_id;
	lengths[part_count++] = bounded_text_length(
		object->object_id,
		sizeof(object->object_id));
	parts[part_count] =
		(const uint8_t *)object->namespace_id;
	lengths[part_count++] = bounded_text_length(
		object->namespace_id,
		sizeof(object->namespace_id));
	parts[part_count] =
		(const uint8_t *)object->owner_id;
	lengths[part_count++] = bounded_text_length(
		object->owner_id,
		sizeof(object->owner_id));
	parts[part_count] =
		(const uint8_t *)object->classification;
	lengths[part_count++] = bounded_text_length(
		object->classification,
		sizeof(object->classification));
	parts[part_count] = object->value;
	lengths[part_count++] = object->value_length;
	parts[part_count] = object->value_digest;
	lengths[part_count++] = sizeof(object->value_digest);
	parts[part_count] =
		(const uint8_t *)&object->state;
	lengths[part_count++] = sizeof(object->state);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, part_count, output);
}

int pqcp_edge_internal_incident_digest(
	const struct pqcp_edge_incident *incident,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[64U +
		PQCP_EDGE_MAX_INCIDENT_SIGNALS * 8U];
	const uint8_t *parts[4];
	size_t lengths[4];
	size_t offset = 0U;

	if (incident == NULL || output == NULL ||
	    incident->signal_count >
		    PQCP_EDGE_MAX_INCIDENT_SIGNALS ||
	    !pqcp_edge_internal_text_valid(
		    incident->title,
		    sizeof(incident->title)) ||
	    !pqcp_edge_internal_text_valid(
		    incident->subject_id,
		    sizeof(incident->subject_id)) ||
	    !pqcp_edge_internal_text_valid(
		    incident->owner_id,
		    sizeof(incident->owner_id))) {
		return -EINVAL;
	}
	pqcp_edge_internal_write_u32(
		numeric + offset, incident->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, incident->incident_id);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, incident->severity);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, incident->state);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, incident->opened_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, incident->updated_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, incident->resolved_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, incident->signal_count);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, incident->risk_score);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, incident->containment_mask);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, incident->remediation_mask);
	offset += 4U;
	for (uint32_t index = 0U;
	     index < incident->signal_count; ++index) {
		pqcp_edge_internal_write_u64(
			numeric + offset,
			incident->signal_ids[index]);
		offset += 8U;
	}
	parts[0] = numeric;
	lengths[0] = offset;
	parts[1] = (const uint8_t *)incident->title;
	lengths[1] = bounded_text_length(
		incident->title, sizeof(incident->title));
	parts[2] = (const uint8_t *)incident->subject_id;
	lengths[2] = bounded_text_length(
		incident->subject_id,
		sizeof(incident->subject_id));
	parts[3] = (const uint8_t *)incident->owner_id;
	lengths[3] = bounded_text_length(
		incident->owner_id,
		sizeof(incident->owner_id));
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 4U, output);
}

const char *pqcp_edge_operation_str(
	enum pqcp_edge_operation operation)
{
	switch (operation) {
	case PQCP_EDGE_OPERATION_NONE:
		return "none";
	case PQCP_EDGE_OPERATION_DISCOVER:
		return "discover";
	case PQCP_EDGE_OPERATION_CONNECT:
		return "connect";
	case PQCP_EDGE_OPERATION_PUBLISH:
		return "publish";
	case PQCP_EDGE_OPERATION_SUBSCRIBE:
		return "subscribe";
	case PQCP_EDGE_OPERATION_READ:
		return "read";
	case PQCP_EDGE_OPERATION_WRITE:
		return "write";
	case PQCP_EDGE_OPERATION_DELETE:
		return "delete";
	case PQCP_EDGE_OPERATION_ROTATE:
		return "rotate";
	case PQCP_EDGE_OPERATION_ATTEST:
		return "attest";
	case PQCP_EDGE_OPERATION_ADMINISTER:
		return "administer";
	case PQCP_EDGE_OPERATION_RECOVER:
		return "recover";
	case PQCP_EDGE_OPERATION_REPLICATE:
		return "replicate";
	case PQCP_EDGE_OPERATION_COUNT:
	default:
		return "invalid";
	}
}

const char *pqcp_edge_incident_state_str(
	enum pqcp_edge_incident_state state)
{
	switch (state) {
	case PQCP_EDGE_INCIDENT_EMPTY:
		return "empty";
	case PQCP_EDGE_INCIDENT_OPEN:
		return "open";
	case PQCP_EDGE_INCIDENT_TRIAGED:
		return "triaged";
	case PQCP_EDGE_INCIDENT_CONTAINING:
		return "containing";
	case PQCP_EDGE_INCIDENT_REMEDIATING:
		return "remediating";
	case PQCP_EDGE_INCIDENT_MONITORING:
		return "monitoring";
	case PQCP_EDGE_INCIDENT_RESOLVED:
		return "resolved";
	case PQCP_EDGE_INCIDENT_CLOSED:
		return "closed";
	default:
		return "invalid";
	}
}
