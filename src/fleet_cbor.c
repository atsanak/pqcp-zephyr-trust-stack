/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Minimal canonical CBOR codec used by the fleet protocol.
 */

#include <errno.h>
#include <string.h>

#include "fleet_internal.h"

static void writer_byte(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	uint8_t value)
{
	if (writer->error != 0) {
		return;
	}
	if (writer->offset >= writer->capacity) {
		writer->error = -ENOSPC;
		return;
	}
	writer->buffer[writer->offset++] = value;
}

static void writer_data(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	const uint8_t *value,
	size_t length)
{
	if (writer->error != 0) {
		return;
	}
	if (length > writer->capacity - writer->offset) {
		writer->error = -ENOSPC;
		return;
	}
	if (length != 0U) {
		memcpy(writer->buffer + writer->offset, value, length);
		writer->offset += length;
	}
}

static int write_head(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	uint8_t major,
	uint64_t value)
{
	if (writer == NULL || major > 7U) {
		return -EINVAL;
	}
	if (value < 24U) {
		writer_byte(writer, (uint8_t)((major << 5) | value));
	} else if (value <= UINT8_MAX) {
		writer_byte(writer, (uint8_t)((major << 5) | 24U));
		writer_byte(writer, (uint8_t)value);
	} else if (value <= UINT16_MAX) {
		writer_byte(writer, (uint8_t)((major << 5) | 25U));
		writer_byte(writer, (uint8_t)(value >> 8));
		writer_byte(writer, (uint8_t)value);
	} else if (value <= UINT32_MAX) {
		writer_byte(writer, (uint8_t)((major << 5) | 26U));
		for (int shift = 24; shift >= 0; shift -= 8) {
			writer_byte(writer, (uint8_t)(value >> shift));
		}
	} else {
		writer_byte(writer, (uint8_t)((major << 5) | 27U));
		for (int shift = 56; shift >= 0; shift -= 8) {
			writer_byte(writer, (uint8_t)(value >> shift));
		}
	}
	return writer->error;
}

void pqcp_fleet_legacy_cbor_writer_init(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	uint8_t *buffer,
	size_t capacity)
{
	if (writer == NULL) {
		return;
	}
	memset(writer, 0, sizeof(*writer));
	writer->buffer = buffer;
	writer->capacity = capacity;
	if (buffer == NULL || capacity == 0U) {
		writer->error = -EINVAL;
	}
}

int pqcp_fleet_legacy_cbor_write_array(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	size_t count)
{
	return write_head(writer, 4U, count);
}

int pqcp_fleet_legacy_cbor_write_uint(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	uint64_t value)
{
	return write_head(writer, 0U, value);
}

int pqcp_fleet_legacy_cbor_write_int(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	int64_t value)
{
	if (value >= 0) {
		return write_head(writer, 0U, (uint64_t)value);
	}
	return write_head(
		writer, 1U, (uint64_t)(-(value + 1)));
}

int pqcp_fleet_legacy_cbor_write_bool(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	bool value)
{
	if (writer == NULL) {
		return -EINVAL;
	}
	writer_byte(writer, value ? 0xf5U : 0xf4U);
	return writer->error;
}

int pqcp_fleet_legacy_cbor_write_bytes(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	const uint8_t *value,
	size_t length)
{
	if (writer == NULL || (value == NULL && length != 0U)) {
		return -EINVAL;
	}
	(void)write_head(writer, 2U, length);
	writer_data(writer, value, length);
	return writer->error;
}

int pqcp_fleet_legacy_cbor_write_text(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	const char *value,
	size_t maximum)
{
	size_t length;

	if (writer == NULL || value == NULL || maximum < 2U) {
		return -EINVAL;
	}
	length = strnlen(value, maximum);
	if (length == 0U || length >= maximum) {
		return -EINVAL;
	}
	(void)write_head(writer, 3U, length);
	writer_data(writer, (const uint8_t *)value, length);
	return writer->error;
}

static int reader_byte(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	uint8_t *value)
{
	if (reader == NULL || value == NULL || reader->error != 0) {
		return reader == NULL ? -EINVAL : reader->error;
	}
	if (reader->offset >= reader->length) {
		reader->error = -EBADMSG;
		return reader->error;
	}
	*value = reader->buffer[reader->offset++];
	return 0;
}

static int read_head(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	uint8_t expected_major,
	uint64_t *value)
{
	uint8_t head;
	uint8_t additional;
	uint64_t decoded = 0U;
	size_t bytes = 0U;
	int ret;

	if (reader == NULL || value == NULL) {
		return -EINVAL;
	}
	ret = reader_byte(reader, &head);
	if (ret != 0 || (head >> 5) != expected_major) {
		reader->error = -EBADMSG;
		return reader->error;
	}
	additional = head & 0x1fU;
	if (additional < 24U) {
		*value = additional;
		return 0;
	}
	switch (additional) {
	case 24U:
		bytes = 1U;
		break;
	case 25U:
		bytes = 2U;
		break;
	case 26U:
		bytes = 4U;
		break;
	case 27U:
		bytes = 8U;
		break;
	default:
		reader->error = -EBADMSG;
		return reader->error;
	}
	for (size_t index = 0U; index < bytes; ++index) {
		uint8_t byte;

		ret = reader_byte(reader, &byte);
		if (ret != 0) {
			return ret;
		}
		decoded = (decoded << 8) | byte;
	}
	if ((bytes == 1U && decoded < 24U) ||
	    (bytes == 2U && decoded <= UINT8_MAX) ||
	    (bytes == 4U && decoded <= UINT16_MAX) ||
	    (bytes == 8U && decoded <= UINT32_MAX)) {
		reader->error = -EBADMSG;
		return reader->error;
	}
	*value = decoded;
	return 0;
}

void pqcp_fleet_legacy_cbor_reader_init(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	const uint8_t *buffer,
	size_t length)
{
	if (reader == NULL) {
		return;
	}
	memset(reader, 0, sizeof(*reader));
	reader->buffer = buffer;
	reader->length = length;
	if (buffer == NULL || length == 0U) {
		reader->error = -EINVAL;
	}
}

int pqcp_fleet_legacy_cbor_read_array(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	size_t expected)
{
	uint64_t count;
	int ret = read_head(reader, 4U, &count);

	if (ret != 0) {
		return ret;
	}
	if (count != expected) {
		reader->error = -EBADMSG;
		return reader->error;
	}
	return 0;
}

int pqcp_fleet_legacy_cbor_read_uint(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	uint64_t *value)
{
	return read_head(reader, 0U, value);
}

int pqcp_fleet_legacy_cbor_read_int(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	int64_t *value)
{
	uint8_t head;
	uint8_t major;
	uint64_t decoded;
	size_t saved;
	int ret;

	if (reader == NULL || value == NULL) {
		return -EINVAL;
	}
	saved = reader->offset;
	ret = reader_byte(reader, &head);
	if (ret != 0) {
		return ret;
	}
	major = head >> 5;
	reader->offset = saved;
	if (major == 0U) {
		ret = read_head(reader, 0U, &decoded);
		if (ret != 0 || decoded > INT64_MAX) {
			reader->error = -EBADMSG;
			return reader->error;
		}
		*value = (int64_t)decoded;
		return 0;
	}
	if (major == 1U) {
		ret = read_head(reader, 1U, &decoded);
		if (ret != 0 || decoded > INT64_MAX) {
			reader->error = -EBADMSG;
			return reader->error;
		}
		*value = -(int64_t)decoded - 1;
		return 0;
	}
	reader->error = -EBADMSG;
	return reader->error;
}

int pqcp_fleet_legacy_cbor_read_bool(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	bool *value)
{
	uint8_t encoded;
	int ret;

	if (reader == NULL || value == NULL) {
		return -EINVAL;
	}
	ret = reader_byte(reader, &encoded);
	if (ret != 0) {
		return ret;
	}
	if (encoded == 0xf4U) {
		*value = false;
		return 0;
	}
	if (encoded == 0xf5U) {
		*value = true;
		return 0;
	}
	reader->error = -EBADMSG;
	return reader->error;
}

int pqcp_fleet_legacy_cbor_read_bytes(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	uint8_t *value,
	size_t capacity,
	size_t *length)
{
	uint64_t encoded_length;
	int ret;

	if (reader == NULL || value == NULL || length == NULL) {
		return -EINVAL;
	}
	ret = read_head(reader, 2U, &encoded_length);
	if (ret != 0) {
		return ret;
	}
	if (encoded_length > capacity ||
	    encoded_length > reader->length - reader->offset) {
		reader->error = -EBADMSG;
		return reader->error;
	}
	memcpy(value, reader->buffer + reader->offset,
	       (size_t)encoded_length);
	reader->offset += (size_t)encoded_length;
	*length = (size_t)encoded_length;
	return 0;
}

int pqcp_fleet_legacy_cbor_read_text(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	char *value,
	size_t capacity)
{
	uint64_t encoded_length;
	int ret;

	if (reader == NULL || value == NULL || capacity < 2U) {
		return -EINVAL;
	}
	ret = read_head(reader, 3U, &encoded_length);
	if (ret != 0) {
		return ret;
	}
	if (encoded_length == 0U || encoded_length >= capacity ||
	    encoded_length > reader->length - reader->offset) {
		reader->error = -EBADMSG;
		return reader->error;
	}
	memcpy(value, reader->buffer + reader->offset,
	       (size_t)encoded_length);
	value[encoded_length] = '\0';
	reader->offset += (size_t)encoded_length;
	return 0;
}

int pqcp_fleet_legacy_cbor_finish(
	struct pqcp_fleet_legacy_cbor_reader *reader)
{
	if (reader == NULL) {
		return -EINVAL;
	}
	if (reader->error != 0) {
		return reader->error;
	}
	return reader->offset == reader->length ? 0 : -EBADMSG;
}

int pqcp_fleet_legacy_cbor_peek_envelope_type(
	const uint8_t *input,
	size_t length,
	enum pqcp_fleet_message_type *type)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	uint64_t value;
	int ret;

	if (input == NULL || type == NULL) {
		return -EINVAL;
	}
	pqcp_fleet_legacy_cbor_reader_init(&reader, input, length);
	ret = pqcp_fleet_legacy_cbor_read_array(&reader, 2U);
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_array(&reader, 12U);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(&reader, &value);
	}
	if (ret == 0 && value != PQCP_FLEET_SCHEMA_VERSION) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(&reader, &value);
	}
	if (ret == 0 && value != PQCP_FLEET_PROTOCOL_VERSION) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(&reader, &value);
	}
	if (ret != 0 || value == PQCP_FLEET_MESSAGE_NONE ||
	    value >= PQCP_FLEET_MESSAGE_TYPE_COUNT) {
		return -EBADMSG;
	}
	*type = (enum pqcp_fleet_message_type)value;
	return 0;
}
