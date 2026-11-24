/*
 * SPDX-License-Identifier: MIT
 *
 * Canonical CBOR encoding and bounded text writer primitives.
 */

#include <errno.h>
#include <string.h>

#include "sovereign_audit_internal.h"

#define EVENT_MAP_FIELDS 31U
#define TENANT_MAP_FIELDS 5U
#define ATTRIBUTE_MAP_FIELDS 4U
#define BATCH_BODY_MAP_FIELDS 16U
#define BATCH_AUTH_MAP_FIELDS 19U

static void writer_fail(
	struct pqcp_sovereign_audit_writer *writer,
	int error)
{
	if (writer != NULL && writer->error == 0) {
		writer->error = error;
	}
}

void pqcp_sovereign_audit_writer_init(
	struct pqcp_sovereign_audit_writer *writer,
	uint8_t *output,
	size_t capacity)
{
	if (writer == NULL) {
		return;
	}
	memset(writer, 0, sizeof(*writer));
	writer->output = output;
	writer->capacity = capacity;
	if (output == NULL || capacity == 0U) {
		writer->error = -EINVAL;
	}
}

int pqcp_sovereign_audit_writer_finish(
	struct pqcp_sovereign_audit_writer *writer,
	size_t *output_length)
{
	if (writer == NULL || output_length == NULL) {
		return -EINVAL;
	}
	if (writer->error != 0) {
		*output_length = 0U;
		return writer->error;
	}
	*output_length = writer->offset;
	return 0;
}

void pqcp_sovereign_audit_writer_bytes(
	struct pqcp_sovereign_audit_writer *writer,
	const void *bytes,
	size_t length)
{
	if (writer == NULL || writer->error != 0) {
		return;
	}
	if ((bytes == NULL && length != 0U) ||
	    length > writer->capacity - writer->offset) {
		writer_fail(
			writer, bytes == NULL ? -EINVAL : -ENOSPC);
		return;
	}
	if (length != 0U) {
		memcpy(writer->output + writer->offset,
		       bytes, length);
		writer->offset += length;
	}
}

void pqcp_sovereign_audit_writer_char(
	struct pqcp_sovereign_audit_writer *writer,
	char value)
{
	pqcp_sovereign_audit_writer_bytes(
		writer, &value, 1U);
}

void pqcp_sovereign_audit_writer_text(
	struct pqcp_sovereign_audit_writer *writer,
	const char *text)
{
	size_t length;

	if (writer == NULL || writer->error != 0) {
		return;
	}
	if (text == NULL) {
		writer_fail(writer, -EINVAL);
		return;
	}
	length = strlen(text);
	pqcp_sovereign_audit_writer_bytes(
		writer, text, length);
}

void pqcp_sovereign_audit_writer_u64(
	struct pqcp_sovereign_audit_writer *writer,
	uint64_t value)
{
	char digits[21U];
	size_t count = 0U;

	if (writer == NULL || writer->error != 0) {
		return;
	}
	do {
		digits[count++] =
			(char)('0' + value % 10U);
		value /= 10U;
	} while (value != 0U && count < sizeof(digits));
	while (count != 0U) {
		pqcp_sovereign_audit_writer_char(
			writer, digits[--count]);
	}
}

void pqcp_sovereign_audit_writer_i64(
	struct pqcp_sovereign_audit_writer *writer,
	int64_t value)
{
	uint64_t magnitude;

	if (writer == NULL || writer->error != 0) {
		return;
	}
	if (value < 0) {
		pqcp_sovereign_audit_writer_char(writer, '-');
		magnitude = (uint64_t)(-(value + 1)) + 1U;
	} else {
		magnitude = (uint64_t)value;
	}
	pqcp_sovereign_audit_writer_u64(writer, magnitude);
}

void pqcp_sovereign_audit_writer_hex(
	struct pqcp_sovereign_audit_writer *writer,
	const uint8_t *bytes,
	size_t length)
{
	static const char hex[] = "0123456789abcdef";

	if (writer == NULL || writer->error != 0) {
		return;
	}
	if (bytes == NULL && length != 0U) {
		writer_fail(writer, -EINVAL);
		return;
	}
	for (size_t index = 0U; index < length; ++index) {
		pqcp_sovereign_audit_writer_char(
			writer, hex[bytes[index] >> 4U]);
		pqcp_sovereign_audit_writer_char(
			writer, hex[bytes[index] & 0x0fU]);
	}
}

void pqcp_sovereign_audit_writer_json_text(
	struct pqcp_sovereign_audit_writer *writer,
	const char *text)
{
	static const char hex[] = "0123456789abcdef";

	if (writer == NULL || writer->error != 0) {
		return;
	}
	if (text == NULL) {
		writer_fail(writer, -EINVAL);
		return;
	}
	pqcp_sovereign_audit_writer_char(writer, '"');
	for (size_t index = 0U; text[index] != '\0'; ++index) {
		unsigned char value = (unsigned char)text[index];

		switch (value) {
		case '"':
			pqcp_sovereign_audit_writer_text(
				writer, "\\\"");
			break;
		case '\\':
			pqcp_sovereign_audit_writer_text(
				writer, "\\\\");
			break;
		case '\b':
			pqcp_sovereign_audit_writer_text(
				writer, "\\b");
			break;
		case '\f':
			pqcp_sovereign_audit_writer_text(
				writer, "\\f");
			break;
		case '\n':
			pqcp_sovereign_audit_writer_text(
				writer, "\\n");
			break;
		case '\r':
			pqcp_sovereign_audit_writer_text(
				writer, "\\r");
			break;
		case '\t':
			pqcp_sovereign_audit_writer_text(
				writer, "\\t");
			break;
		default:
			if (value < 0x20U) {
				pqcp_sovereign_audit_writer_text(
					writer, "\\u00");
				pqcp_sovereign_audit_writer_char(
					writer, hex[value >> 4U]);
				pqcp_sovereign_audit_writer_char(
					writer, hex[value & 0x0fU]);
			} else {
				pqcp_sovereign_audit_writer_char(
					writer, (char)value);
			}
			break;
		}
	}
	pqcp_sovereign_audit_writer_char(writer, '"');
}

void pqcp_sovereign_audit_writer_cef_header_text(
	struct pqcp_sovereign_audit_writer *writer,
	const char *text)
{
	if (writer == NULL || writer->error != 0) {
		return;
	}
	if (text == NULL) {
		writer_fail(writer, -EINVAL);
		return;
	}
	for (size_t index = 0U; text[index] != '\0'; ++index) {
		if (text[index] == '\\' || text[index] == '|') {
			pqcp_sovereign_audit_writer_char(
				writer, '\\');
		}
		if (text[index] == '\n' || text[index] == '\r') {
			pqcp_sovereign_audit_writer_text(
				writer, "\\n");
		} else {
			pqcp_sovereign_audit_writer_char(
				writer, text[index]);
		}
	}
}

void pqcp_sovereign_audit_writer_cef_extension_text(
	struct pqcp_sovereign_audit_writer *writer,
	const char *text)
{
	if (writer == NULL || writer->error != 0) {
		return;
	}
	if (text == NULL) {
		writer_fail(writer, -EINVAL);
		return;
	}
	for (size_t index = 0U; text[index] != '\0'; ++index) {
		switch (text[index]) {
		case '\\':
			pqcp_sovereign_audit_writer_text(
				writer, "\\\\");
			break;
		case '=':
			pqcp_sovereign_audit_writer_text(
				writer, "\\=");
			break;
		case '\n':
		case '\r':
			pqcp_sovereign_audit_writer_text(
				writer, "\\n");
			break;
		default:
			pqcp_sovereign_audit_writer_char(
				writer, text[index]);
			break;
		}
	}
}

static void cbor_fail(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	int error)
{
	if (writer != NULL && writer->error == 0) {
		writer->error = error;
	}
}

void pqcp_sovereign_audit_cbor_init(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	uint8_t *output,
	size_t capacity)
{
	if (writer == NULL) {
		return;
	}
	memset(writer, 0, sizeof(*writer));
	writer->output = output;
	writer->capacity = capacity;
	if (output == NULL || capacity == 0U) {
		writer->error = -EINVAL;
	}
}

int pqcp_sovereign_audit_cbor_finish(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	size_t *output_length)
{
	if (writer == NULL || output_length == NULL) {
		return -EINVAL;
	}
	if (writer->error != 0) {
		*output_length = 0U;
		return writer->error;
	}
	*output_length = writer->offset;
	return 0;
}

static void cbor_raw(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const void *bytes,
	size_t length)
{
	if (writer == NULL || writer->error != 0) {
		return;
	}
	if ((bytes == NULL && length != 0U) ||
	    length > writer->capacity - writer->offset) {
		cbor_fail(
			writer, bytes == NULL ? -EINVAL : -ENOSPC);
		return;
	}
	if (length != 0U) {
		memcpy(writer->output + writer->offset,
		       bytes, length);
		writer->offset += length;
	}
}

static void cbor_head(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	uint8_t major,
	uint64_t value)
{
	uint8_t encoded[9U];
	size_t length;

	if (value < 24U) {
		encoded[0] = (uint8_t)(major | value);
		length = 1U;
	} else if (value <= UINT8_MAX) {
		encoded[0] = major | 24U;
		encoded[1] = (uint8_t)value;
		length = 2U;
	} else if (value <= UINT16_MAX) {
		encoded[0] = major | 25U;
		pqcp_sovereign_audit_internal_write_u16(
			encoded + 1U, (uint16_t)value);
		length = 3U;
	} else if (value <= UINT32_MAX) {
		encoded[0] = major | 26U;
		pqcp_sovereign_audit_internal_write_u32(
			encoded + 1U, (uint32_t)value);
		length = 5U;
	} else {
		encoded[0] = major | 27U;
		pqcp_sovereign_audit_internal_write_u64(
			encoded + 1U, value);
		length = 9U;
	}
	cbor_raw(writer, encoded, length);
}

void pqcp_sovereign_audit_cbor_uint(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	uint64_t value)
{
	cbor_head(writer, 0x00U, value);
}

void pqcp_sovereign_audit_cbor_int(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	int64_t value)
{
	if (value >= 0) {
		cbor_head(writer, 0x00U, (uint64_t)value);
	} else {
		uint64_t encoded =
			(uint64_t)(-(value + 1));

		cbor_head(writer, 0x20U, encoded);
	}
}

void pqcp_sovereign_audit_cbor_bool(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	bool value)
{
	uint8_t encoded = value ? 0xf5U : 0xf4U;

	cbor_raw(writer, &encoded, 1U);
}

void pqcp_sovereign_audit_cbor_bytes(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const uint8_t *bytes,
	size_t length)
{
	if (bytes == NULL && length != 0U) {
		cbor_fail(writer, -EINVAL);
		return;
	}
	cbor_head(writer, 0x40U, length);
	cbor_raw(writer, bytes, length);
}

void pqcp_sovereign_audit_cbor_text(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const char *text)
{
	size_t length;

	if (text == NULL) {
		cbor_fail(writer, -EINVAL);
		return;
	}
	length = strlen(text);
	cbor_head(writer, 0x60U, length);
	cbor_raw(writer, text, length);
}

void pqcp_sovereign_audit_cbor_array(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	size_t count)
{
	cbor_head(writer, 0x80U, count);
}

void pqcp_sovereign_audit_cbor_map(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	size_t count)
{
	cbor_head(writer, 0xa0U, count);
}

static void cbor_key(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	uint64_t key)
{
	pqcp_sovereign_audit_cbor_uint(writer, key);
}

static void cbor_tenant(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const struct pqcp_sovereign_audit_tenant_scope *tenant)
{
	pqcp_sovereign_audit_cbor_map(
		writer, TENANT_MAP_FIELDS);
	cbor_key(writer, 1U);
	pqcp_sovereign_audit_cbor_text(
		writer, tenant->tenant_id);
	cbor_key(writer, 2U);
	pqcp_sovereign_audit_cbor_text(
		writer, tenant->realm);
	cbor_key(writer, 3U);
	pqcp_sovereign_audit_cbor_uint(
		writer, tenant->policy_epoch);
	cbor_key(writer, 4U);
	pqcp_sovereign_audit_cbor_uint(
		writer, tenant->revocation_epoch);
	cbor_key(writer, 5U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, tenant->scope_digest,
		sizeof(tenant->scope_digest));
}

static void cbor_attribute_value(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const struct pqcp_sovereign_audit_attribute *attribute)
{
	switch (attribute->type) {
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_U64:
		pqcp_sovereign_audit_cbor_uint(
			writer, attribute->value.u64);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_I64:
		pqcp_sovereign_audit_cbor_int(
			writer, attribute->value.i64);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_BOOL:
		pqcp_sovereign_audit_cbor_bool(
			writer, attribute->value.boolean);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT:
		pqcp_sovereign_audit_cbor_text(
			writer, attribute->value.text);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST:
		pqcp_sovereign_audit_cbor_bytes(
			writer, attribute->value.digest,
			sizeof(attribute->value.digest));
		break;
	default:
		cbor_fail(writer, -EINVAL);
		break;
	}
}

static void cbor_attribute(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const struct pqcp_sovereign_audit_attribute *attribute)
{
	pqcp_sovereign_audit_cbor_map(
		writer, ATTRIBUTE_MAP_FIELDS);
	cbor_key(writer, 1U);
	pqcp_sovereign_audit_cbor_text(
		writer, attribute->key);
	cbor_key(writer, 2U);
	pqcp_sovereign_audit_cbor_uint(
		writer, (uint32_t)attribute->type);
	cbor_key(writer, 3U);
	pqcp_sovereign_audit_cbor_uint(
		writer, attribute->flags);
	cbor_key(writer, 4U);
	cbor_attribute_value(writer, attribute);
}

void pqcp_sovereign_audit_cbor_event(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const struct pqcp_sovereign_event *event)
{
	if (writer == NULL || event == NULL ||
	    event->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    !event->occupied ||
	    event->attribute_count >
		    PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES) {
		cbor_fail(writer, -EINVAL);
		return;
	}
	pqcp_sovereign_audit_cbor_map(
		writer, EVENT_MAP_FIELDS);
	cbor_key(writer, 1U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->schema_version);
	cbor_key(writer, 2U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->generation);
	cbor_key(writer, 3U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->sequence);
	cbor_key(writer, 4U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->observed_at_ms);
	cbor_key(writer, 5U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->ingested_at_ms);
	cbor_key(writer, 6U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->expires_at_ms);
	cbor_key(writer, 7U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->correlation_id);
	cbor_key(writer, 8U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->policy_epoch);
	cbor_key(writer, 9U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->revocation_epoch);
	cbor_key(writer, 10U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, event->event_id,
		sizeof(event->event_id));
	cbor_key(writer, 11U);
	cbor_tenant(writer, &event->tenant);
	cbor_key(writer, 12U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->event_class);
	cbor_key(writer, 13U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->activity);
	cbor_key(writer, 14U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->severity);
	cbor_key(writer, 15U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->outcome);
	cbor_key(writer, 16U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->data_class);
	cbor_key(writer, 17U);
	pqcp_sovereign_audit_cbor_uint(
		writer, event->flags);
	cbor_key(writer, 18U);
	pqcp_sovereign_audit_cbor_int(
		writer, event->result);
	cbor_key(writer, 19U);
	pqcp_sovereign_audit_cbor_text(
		writer, event->source);
	cbor_key(writer, 20U);
	pqcp_sovereign_audit_cbor_text(
		writer, event->actor);
	cbor_key(writer, 21U);
	pqcp_sovereign_audit_cbor_text(
		writer, event->object);
	cbor_key(writer, 22U);
	pqcp_sovereign_audit_cbor_text(
		writer, event->action);
	cbor_key(writer, 23U);
	pqcp_sovereign_audit_cbor_text(
		writer, event->reason);
	cbor_key(writer, 24U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, event->actor_digest,
		sizeof(event->actor_digest));
	cbor_key(writer, 25U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, event->subject_digest,
		sizeof(event->subject_digest));
	cbor_key(writer, 26U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, event->resource_digest,
		sizeof(event->resource_digest));
	cbor_key(writer, 27U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, event->evidence_digest,
		sizeof(event->evidence_digest));
	cbor_key(writer, 28U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, event->receipt_digest,
		sizeof(event->receipt_digest));
	cbor_key(writer, 29U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, event->previous_digest,
		sizeof(event->previous_digest));
	cbor_key(writer, 30U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, event->event_digest,
		sizeof(event->event_digest));
	cbor_key(writer, 31U);
	pqcp_sovereign_audit_cbor_array(
		writer, event->attribute_count);
	for (size_t index = 0U;
	     index < event->attribute_count; ++index) {
		cbor_attribute(
			writer, &event->attributes[index]);
	}
}

int pqcp_sovereign_audit_cbor_encode_event(
	const struct pqcp_sovereign_event *event,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_sovereign_audit_cbor_writer writer;

	if (event == NULL || output == NULL ||
	    output_capacity == 0U || output_length == NULL) {
		return -EINVAL;
	}
	*output_length = 0U;
	pqcp_sovereign_audit_cbor_init(
		&writer, output, output_capacity);
	pqcp_sovereign_audit_cbor_event(
		&writer, event);
	return pqcp_sovereign_audit_cbor_finish(
		&writer, output_length);
}

static bool batch_basic_valid(
	const struct pqcp_sovereign_export_batch *batch)
{
	return batch != NULL &&
	       batch->schema_version ==
		       PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION &&
	       batch->cursor_id != 0U &&
	       batch->created_at_ms != 0U &&
	       batch->first_sequence != 0U &&
	       batch->last_sequence >= batch->first_sequence &&
	       batch->scanned_through_sequence >=
		       batch->last_sequence &&
	       batch->event_count != 0U &&
	       batch->events != NULL &&
	       batch->event_count <= SIZE_MAX;
}

static void cbor_batch_common(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const struct pqcp_sovereign_export_batch *batch,
	bool include_authentication)
{
	pqcp_sovereign_audit_cbor_map(
		writer,
		include_authentication ?
			BATCH_AUTH_MAP_FIELDS :
			BATCH_BODY_MAP_FIELDS);
	cbor_key(writer, 1U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->schema_version);
	cbor_key(writer, 2U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->cursor_id);
	cbor_key(writer, 3U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->created_at_ms);
	cbor_key(writer, 4U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->policy_epoch);
	cbor_key(writer, 5U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->first_sequence);
	cbor_key(writer, 6U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->last_sequence);
	cbor_key(writer, 7U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->scanned_through_sequence);
	cbor_key(writer, 8U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->event_count);
	cbor_key(writer, 9U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->format);
	cbor_key(writer, 10U);
	pqcp_sovereign_audit_cbor_uint(
		writer, batch->redaction);
	cbor_key(writer, 11U);
	pqcp_sovereign_audit_cbor_text(
		writer, batch->tenant_id);
	cbor_key(writer, 12U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, batch->source_anchor_digest,
		sizeof(batch->source_anchor_digest));
	cbor_key(writer, 13U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, batch->source_chain_head,
		sizeof(batch->source_chain_head));
	cbor_key(writer, 14U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, batch->previous_batch_digest,
		sizeof(batch->previous_batch_digest));
	cbor_key(writer, 15U);
	pqcp_sovereign_audit_cbor_bytes(
		writer, batch->receipt_digest,
		sizeof(batch->receipt_digest));
	cbor_key(writer, 16U);
	pqcp_sovereign_audit_cbor_array(
		writer, batch->event_count);
	for (size_t index = 0U;
	     index < batch->event_count; ++index) {
		pqcp_sovereign_audit_cbor_event(
			writer, &batch->events[index]);
	}
	if (include_authentication) {
		cbor_key(writer, 17U);
		pqcp_sovereign_audit_cbor_bytes(
			writer, batch->batch_digest,
			sizeof(batch->batch_digest));
		cbor_key(writer, 18U);
		pqcp_sovereign_audit_cbor_uint(
			writer, batch->signature_algorithm);
		cbor_key(writer, 19U);
		pqcp_sovereign_audit_cbor_bytes(
			writer, batch->signature,
			batch->signature_length);
	}
}

int pqcp_sovereign_audit_cbor_encode_batch_body(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_sovereign_audit_cbor_writer writer;

	if (!batch_basic_valid(batch) ||
	    output == NULL || output_capacity == 0U ||
	    output_length == NULL) {
		return -EINVAL;
	}
	*output_length = 0U;
	pqcp_sovereign_audit_cbor_init(
		&writer, output, output_capacity);
	cbor_batch_common(&writer, batch, false);
	return pqcp_sovereign_audit_cbor_finish(
		&writer, output_length);
}

int pqcp_sovereign_audit_cbor_encode_batch(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_sovereign_audit_cbor_writer writer;

	if (!batch_basic_valid(batch) ||
	    output == NULL || output_capacity == 0U ||
	    output_length == NULL ||
	    batch->signature_length >
		    sizeof(batch->signature) ||
	    (batch->signature_algorithm ==
		     PQCP_SOVEREIGN_AUDIT_SIGNATURE_NONE &&
	     batch->signature_length != 0U) ||
	    (batch->signature_algorithm ==
		     PQCP_SOVEREIGN_AUDIT_SIGNATURE_MLDSA &&
	     batch->signature_length == 0U)) {
		return -EINVAL;
	}
	*output_length = 0U;
	pqcp_sovereign_audit_cbor_init(
		&writer, output, output_capacity);
	cbor_batch_common(&writer, batch, true);
	return pqcp_sovereign_audit_cbor_finish(
		&writer, output_length);
}

int pqcp_sovereign_audit_internal_encode_batch(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	if (batch == NULL) {
		return -EINVAL;
	}
	switch (batch->format) {
	case PQCP_SOVEREIGN_AUDIT_FORMAT_CBOR:
		return pqcp_sovereign_audit_cbor_encode_batch(
			batch, output, output_capacity,
			output_length);
	case PQCP_SOVEREIGN_AUDIT_FORMAT_CEF_SYSLOG:
		return pqcp_sovereign_audit_cef_encode_batch(
			batch, output, output_capacity,
			output_length);
	case PQCP_SOVEREIGN_AUDIT_FORMAT_OCSF_JSON:
		return pqcp_sovereign_audit_ocsf_encode_batch(
			batch, output, output_capacity,
			output_length);
	default:
		return -EINVAL;
	}
}
