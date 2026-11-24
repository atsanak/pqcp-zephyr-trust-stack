/*
 * SPDX-License-Identifier: MIT
 *
 * Canonical allocation-free deployment evidence binary codec.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/deployment_evidence_codec.h>

#define PQCP_CODEC_FNV_PRIME UINT64_C(1099511628211)
#define PQCP_CODEC_FNV_OFFSET UINT64_C(1469598103934665603)
#define PQCP_CODEC_MIX_A UINT64_C(0x9e3779b97f4a7c15)
#define PQCP_CODEC_MIX_B UINT64_C(0xbf58476d1ce4e5b9)
#define PQCP_CODEC_MIX_C UINT64_C(0x94d049bb133111eb)

static int codec_errno(enum pqcp_deployment_evidence_codec_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK:
		return 0;
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT:
		return -EINVAL;
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_OVERFLOW:
		return -ENOSPC;
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRUNCATED:
		return -EMSGSIZE;
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_RANGE:
		return -ERANGE;
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_DUPLICATE:
		return -EEXIST;
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_ORDER:
		return -EPROTO;
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRAILING_DATA:
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_MISMATCH:
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED:
	default:
		return -EBADMSG;
	}
}

static int writer_fail(
	struct pqcp_deployment_evidence_codec_writer *writer,
	enum pqcp_deployment_evidence_codec_error error)
{
	if (writer != NULL &&
	    writer->error == PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK) {
		writer->error = error;
	}
	return codec_errno(error);
}

static int reader_fail(
	struct pqcp_deployment_evidence_codec_reader *reader,
	enum pqcp_deployment_evidence_codec_error error)
{
	if (reader != NULL &&
	    reader->error == PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK) {
		reader->error = error;
	}
	return codec_errno(error);
}

static bool checked_add_size(size_t left, size_t right, size_t *result)
{
	if (result == NULL || left > SIZE_MAX - right) {
		return false;
	}
	*result = left + right;
	return true;
}

static bool checked_round_up(size_t value, size_t alignment, size_t *result)
{
	size_t remainder;
	size_t padding;

	if (result == NULL || alignment == 0U ||
	    (alignment & (alignment - 1U)) != 0U) {
		return false;
	}
	remainder = value & (alignment - 1U);
	padding = remainder == 0U ? 0U : alignment - remainder;
	return checked_add_size(value, padding, result);
}

static uint64_t rotate_left64(uint64_t value, unsigned int shift)
{
	shift &= 63U;
	if (shift == 0U) {
		return value;
	}
	return (value << shift) | (value >> (64U - shift));
}

static uint64_t avalanche64(uint64_t value)
{
	value ^= value >> 30U;
	value *= PQCP_CODEC_MIX_B;
	value ^= value >> 27U;
	value *= PQCP_CODEC_MIX_C;
	value ^= value >> 31U;
	return value;
}

static uint8_t hex_nibble(char value, bool *valid)
{
	if (value >= '0' && value <= '9') {
		return (uint8_t)(value - '0');
	}
	if (value >= 'a' && value <= 'f') {
		return (uint8_t)(value - 'a' + 10);
	}
	if (valid != NULL) {
		*valid = false;
	}
	return 0U;
}

const char *pqcp_deployment_evidence_codec_error_str(
	enum pqcp_deployment_evidence_codec_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK:
		return "none";
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_OVERFLOW:
		return "overflow";
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRUNCATED:
		return "truncated";
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED:
		return "malformed";
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_RANGE:
		return "range";
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_DUPLICATE:
		return "duplicate";
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_ORDER:
		return "order";
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRAILING_DATA:
		return "trailing_data";
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_MISMATCH:
		return "digest_mismatch";
	default:
		return "unknown";
	}
}

void pqcp_deployment_evidence_codec_writer_init(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint8_t *buffer,
	size_t capacity)
{
	if (writer == NULL) {
		return;
	}
	memset(writer, 0, sizeof(*writer));
	writer->buffer = buffer;
	writer->capacity = capacity;
	if (buffer == NULL && capacity != 0U) {
		writer->error = PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT;
	}
}

size_t pqcp_deployment_evidence_codec_writer_used(
	const struct pqcp_deployment_evidence_codec_writer *writer)
{
	return writer != NULL ? writer->offset : 0U;
}

size_t pqcp_deployment_evidence_codec_writer_remaining(
	const struct pqcp_deployment_evidence_codec_writer *writer)
{
	if (writer == NULL || writer->offset > writer->capacity) {
		return 0U;
	}
	return writer->capacity - writer->offset;
}

bool pqcp_deployment_evidence_codec_writer_ok(
	const struct pqcp_deployment_evidence_codec_writer *writer)
{
	return writer != NULL &&
	       writer->error == PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK &&
	       writer->offset <= writer->capacity &&
	       (writer->buffer != NULL || writer->capacity == 0U);
}

int pqcp_deployment_evidence_codec_write_u8(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint8_t value)
{
	return pqcp_deployment_evidence_codec_write_bytes(writer, &value,
							  sizeof(value));
}

int pqcp_deployment_evidence_codec_write_u16(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint16_t value)
{
	uint8_t encoded[2];

	encoded[0] = (uint8_t)(value & 0xffU);
	encoded[1] = (uint8_t)((value >> 8U) & 0xffU);
	return pqcp_deployment_evidence_codec_write_bytes(writer, encoded,
							  sizeof(encoded));
}

int pqcp_deployment_evidence_codec_write_u32(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint32_t value)
{
	uint8_t encoded[4];

	encoded[0] = (uint8_t)(value & 0xffU);
	encoded[1] = (uint8_t)((value >> 8U) & 0xffU);
	encoded[2] = (uint8_t)((value >> 16U) & 0xffU);
	encoded[3] = (uint8_t)((value >> 24U) & 0xffU);
	return pqcp_deployment_evidence_codec_write_bytes(writer, encoded,
							  sizeof(encoded));
}

int pqcp_deployment_evidence_codec_write_u64(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint64_t value)
{
	uint8_t encoded[8];

	for (size_t index = 0U; index < sizeof(encoded); ++index) {
		encoded[index] = (uint8_t)((value >> (index * 8U)) & 0xffU);
	}
	return pqcp_deployment_evidence_codec_write_bytes(writer, encoded,
							  sizeof(encoded));
}

int pqcp_deployment_evidence_codec_write_i32(
	struct pqcp_deployment_evidence_codec_writer *writer,
	int32_t value)
{
	return pqcp_deployment_evidence_codec_write_u32(
		writer, (uint32_t)value);
}

int pqcp_deployment_evidence_codec_write_bool(
	struct pqcp_deployment_evidence_codec_writer *writer,
	bool value)
{
	return pqcp_deployment_evidence_codec_write_u8(
		writer, value ? 1U : 0U);
}

int pqcp_deployment_evidence_codec_write_bytes(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const void *data,
	size_t length)
{
	size_t end;

	if (writer == NULL || (data == NULL && length != 0U)) {
		return writer_fail(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	if (!pqcp_deployment_evidence_codec_writer_ok(writer)) {
		return codec_errno(writer->error);
	}
	if (!checked_add_size(writer->offset, length, &end) ||
	    end > writer->capacity) {
		return writer_fail(writer,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_OVERFLOW);
	}
	if (length != 0U) {
		memcpy(writer->buffer + writer->offset, data, length);
	}
	writer->offset = end;
	return 0;
}

int pqcp_deployment_evidence_codec_write_zeros(
	struct pqcp_deployment_evidence_codec_writer *writer,
	size_t length)
{
	size_t end;

	if (writer == NULL) {
		return -EINVAL;
	}
	if (!pqcp_deployment_evidence_codec_writer_ok(writer)) {
		return codec_errno(writer->error);
	}
	if (!checked_add_size(writer->offset, length, &end) ||
	    end > writer->capacity) {
		return writer_fail(writer,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_OVERFLOW);
	}
	if (length != 0U) {
		memset(writer->buffer + writer->offset, 0, length);
	}
	writer->offset = end;
	return 0;
}

int pqcp_deployment_evidence_codec_write_text(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const char *text,
	size_t max_length)
{
	size_t length;
	int ret;

	if (writer == NULL || text == NULL || max_length == 0U ||
	    max_length > UINT16_MAX) {
		return writer_fail(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	length = strnlen(text, max_length + 1U);
	if (length > max_length || length > UINT16_MAX) {
		return writer_fail(writer,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_RANGE);
	}
	ret = pqcp_deployment_evidence_codec_write_u16(
		writer, (uint16_t)length);
	if (ret != 0) {
		return ret;
	}
	return pqcp_deployment_evidence_codec_write_bytes(writer, text,
							  length);
}

int pqcp_deployment_evidence_codec_align_writer(
	struct pqcp_deployment_evidence_codec_writer *writer,
	size_t alignment)
{
	size_t aligned;

	if (writer == NULL ||
	    !checked_round_up(writer->offset, alignment, &aligned)) {
		return writer_fail(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	return pqcp_deployment_evidence_codec_write_zeros(
		writer, aligned - writer->offset);
}

int pqcp_deployment_evidence_codec_patch_u16(
	struct pqcp_deployment_evidence_codec_writer *writer,
	size_t offset,
	uint16_t value)
{
	if (writer == NULL || writer->buffer == NULL ||
	    offset > writer->offset || writer->offset - offset < 2U) {
		return writer_fail(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	writer->buffer[offset] = (uint8_t)(value & 0xffU);
	writer->buffer[offset + 1U] = (uint8_t)((value >> 8U) & 0xffU);
	return 0;
}

int pqcp_deployment_evidence_codec_patch_u32(
	struct pqcp_deployment_evidence_codec_writer *writer,
	size_t offset,
	uint32_t value)
{
	if (writer == NULL || writer->buffer == NULL ||
	    offset > writer->offset || writer->offset - offset < 4U) {
		return writer_fail(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	writer->buffer[offset] = (uint8_t)(value & 0xffU);
	writer->buffer[offset + 1U] = (uint8_t)((value >> 8U) & 0xffU);
	writer->buffer[offset + 2U] =
		(uint8_t)((value >> 16U) & 0xffU);
	writer->buffer[offset + 3U] =
		(uint8_t)((value >> 24U) & 0xffU);
	return 0;
}

int pqcp_deployment_evidence_codec_begin_record(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint16_t type,
	uint16_t flags,
	struct pqcp_deployment_evidence_codec_record_scope *scope)
{
	int ret;

	if (writer == NULL || scope == NULL || type == 0U) {
		return writer_fail(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	memset(scope, 0, sizeof(*scope));
	ret = pqcp_deployment_evidence_codec_align_writer(
		writer, PQCP_DEPLOYMENT_EVIDENCE_CODEC_ALIGNMENT);
	if (ret != 0) {
		return ret;
	}
	scope->header_offset = writer->offset;
	scope->type = type;
	scope->flags = flags;
	ret = pqcp_deployment_evidence_codec_write_u16(writer, type);
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u16(writer, flags);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(writer, 0U);
	}
	if (ret != 0) {
		return ret;
	}
	scope->payload_offset = writer->offset;
	scope->open = true;
	return 0;
}

int pqcp_deployment_evidence_codec_end_record(
	struct pqcp_deployment_evidence_codec_writer *writer,
	struct pqcp_deployment_evidence_codec_record_scope *scope)
{
	size_t payload_length;
	int ret;

	if (writer == NULL || scope == NULL || !scope->open ||
	    writer->offset < scope->payload_offset) {
		return writer_fail(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	payload_length = writer->offset - scope->payload_offset;
	if (payload_length > UINT32_MAX) {
		return writer_fail(writer,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_RANGE);
	}
	ret = pqcp_deployment_evidence_codec_patch_u32(
		writer, scope->header_offset + 4U,
		(uint32_t)payload_length);
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_align_writer(
			writer, PQCP_DEPLOYMENT_EVIDENCE_CODEC_ALIGNMENT);
	}
	if (ret == 0) {
		scope->open = false;
	}
	return ret;
}

void pqcp_deployment_evidence_codec_reader_init(
	struct pqcp_deployment_evidence_codec_reader *reader,
	const uint8_t *buffer,
	size_t length)
{
	if (reader == NULL) {
		return;
	}
	memset(reader, 0, sizeof(*reader));
	reader->buffer = buffer;
	reader->length = length;
	if (buffer == NULL && length != 0U) {
		reader->error = PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT;
	}
}

size_t pqcp_deployment_evidence_codec_reader_remaining(
	const struct pqcp_deployment_evidence_codec_reader *reader)
{
	if (reader == NULL || reader->offset > reader->length) {
		return 0U;
	}
	return reader->length - reader->offset;
}

bool pqcp_deployment_evidence_codec_reader_ok(
	const struct pqcp_deployment_evidence_codec_reader *reader)
{
	return reader != NULL &&
	       reader->error == PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK &&
	       reader->offset <= reader->length &&
	       (reader->buffer != NULL || reader->length == 0U);
}

int pqcp_deployment_evidence_codec_read_u8(
	struct pqcp_deployment_evidence_codec_reader *reader,
	uint8_t *value)
{
	return pqcp_deployment_evidence_codec_read_bytes(reader, value,
							 sizeof(*value));
}

int pqcp_deployment_evidence_codec_read_u16(
	struct pqcp_deployment_evidence_codec_reader *reader,
	uint16_t *value)
{
	uint8_t encoded[2];
	int ret;

	if (value == NULL) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	ret = pqcp_deployment_evidence_codec_read_bytes(reader, encoded,
						       sizeof(encoded));
	if (ret != 0) {
		return ret;
	}
	*value = (uint16_t)encoded[0] |
		 ((uint16_t)encoded[1] << 8U);
	return 0;
}

int pqcp_deployment_evidence_codec_read_u32(
	struct pqcp_deployment_evidence_codec_reader *reader,
	uint32_t *value)
{
	uint8_t encoded[4];
	int ret;

	if (value == NULL) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	ret = pqcp_deployment_evidence_codec_read_bytes(reader, encoded,
						       sizeof(encoded));
	if (ret != 0) {
		return ret;
	}
	*value = (uint32_t)encoded[0] |
		 ((uint32_t)encoded[1] << 8U) |
		 ((uint32_t)encoded[2] << 16U) |
		 ((uint32_t)encoded[3] << 24U);
	return 0;
}

int pqcp_deployment_evidence_codec_read_u64(
	struct pqcp_deployment_evidence_codec_reader *reader,
	uint64_t *value)
{
	uint8_t encoded[8];
	uint64_t result = 0U;
	int ret;

	if (value == NULL) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	ret = pqcp_deployment_evidence_codec_read_bytes(reader, encoded,
						       sizeof(encoded));
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < sizeof(encoded); ++index) {
		result |= (uint64_t)encoded[index] << (index * 8U);
	}
	*value = result;
	return 0;
}

int pqcp_deployment_evidence_codec_read_i32(
	struct pqcp_deployment_evidence_codec_reader *reader,
	int32_t *value)
{
	uint32_t encoded;
	int ret;

	if (value == NULL) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	ret = pqcp_deployment_evidence_codec_read_u32(reader, &encoded);
	if (ret == 0) {
		*value = (int32_t)encoded;
	}
	return ret;
}

int pqcp_deployment_evidence_codec_read_bool(
	struct pqcp_deployment_evidence_codec_reader *reader,
	bool *value)
{
	uint8_t encoded;
	int ret;

	if (value == NULL) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	ret = pqcp_deployment_evidence_codec_read_u8(reader, &encoded);
	if (ret != 0) {
		return ret;
	}
	if (encoded > 1U) {
		return reader_fail(reader,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED);
	}
	*value = encoded != 0U;
	return 0;
}

int pqcp_deployment_evidence_codec_read_bytes(
	struct pqcp_deployment_evidence_codec_reader *reader,
	void *destination,
	size_t length)
{
	size_t end;

	if (reader == NULL || (destination == NULL && length != 0U)) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	if (!pqcp_deployment_evidence_codec_reader_ok(reader)) {
		return codec_errno(reader->error);
	}
	if (!checked_add_size(reader->offset, length, &end) ||
	    end > reader->length) {
		return reader_fail(reader,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRUNCATED);
	}
	if (length != 0U) {
		memcpy(destination, reader->buffer + reader->offset, length);
	}
	reader->offset = end;
	return 0;
}

int pqcp_deployment_evidence_codec_read_text(
	struct pqcp_deployment_evidence_codec_reader *reader,
	char *destination,
	size_t capacity,
	size_t max_length)
{
	uint16_t encoded_length;
	int ret;

	if (reader == NULL || destination == NULL || capacity == 0U ||
	    max_length == 0U) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	ret = pqcp_deployment_evidence_codec_read_u16(
		reader, &encoded_length);
	if (ret != 0) {
		return ret;
	}
	if ((size_t)encoded_length > max_length ||
	    (size_t)encoded_length >= capacity) {
		return reader_fail(reader,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_RANGE);
	}
	ret = pqcp_deployment_evidence_codec_read_bytes(
		reader, destination, encoded_length);
	if (ret != 0) {
		return ret;
	}
	destination[encoded_length] = '\0';
	if (memchr(destination, '\0', encoded_length) != NULL) {
		destination[0] = '\0';
		return reader_fail(reader,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED);
	}
	return 0;
}

int pqcp_deployment_evidence_codec_skip(
	struct pqcp_deployment_evidence_codec_reader *reader,
	size_t length)
{
	size_t end;

	if (reader == NULL) {
		return -EINVAL;
	}
	if (!pqcp_deployment_evidence_codec_reader_ok(reader)) {
		return codec_errno(reader->error);
	}
	if (!checked_add_size(reader->offset, length, &end) ||
	    end > reader->length) {
		return reader_fail(reader,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRUNCATED);
	}
	reader->offset = end;
	return 0;
}

int pqcp_deployment_evidence_codec_align_reader(
	struct pqcp_deployment_evidence_codec_reader *reader,
	size_t alignment)
{
	size_t aligned;

	if (reader == NULL ||
	    !checked_round_up(reader->offset, alignment, &aligned)) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	if (aligned > reader->length) {
		return reader_fail(reader,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRUNCATED);
	}
	for (size_t index = reader->offset; index < aligned; ++index) {
		if (reader->buffer[index] != 0U) {
			return reader_fail(
				reader,
				PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED);
		}
	}
	reader->offset = aligned;
	return 0;
}

int pqcp_deployment_evidence_codec_next_record(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_deployment_evidence_codec_record *record)
{
	size_t payload_end;
	size_t next_offset;
	int ret;

	if (reader == NULL || record == NULL) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	ret = pqcp_deployment_evidence_codec_align_reader(
		reader, PQCP_DEPLOYMENT_EVIDENCE_CODEC_ALIGNMENT);
	if (ret != 0) {
		return ret;
	}
	if (pqcp_deployment_evidence_codec_reader_remaining(reader) == 0U) {
		return -ENOENT;
	}
	if (pqcp_deployment_evidence_codec_reader_remaining(reader) <
	    PQCP_DEPLOYMENT_EVIDENCE_CODEC_RECORD_HEADER_BYTES) {
		return reader_fail(reader,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRUNCATED);
	}
	memset(record, 0, sizeof(*record));
	record->header_offset = reader->offset;
	ret = pqcp_deployment_evidence_codec_read_u16(reader, &record->type);
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_u16(
			reader, &record->flags);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_u32(
			reader, &record->length);
	}
	if (ret != 0) {
		return ret;
	}
	if (record->type == 0U) {
		return reader_fail(reader,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED);
	}
	record->payload_offset = reader->offset;
	if (!checked_add_size(record->payload_offset, record->length,
			      &payload_end) ||
	    payload_end > reader->length ||
	    !checked_round_up(payload_end,
			      PQCP_DEPLOYMENT_EVIDENCE_CODEC_ALIGNMENT,
			      &next_offset) ||
	    next_offset > reader->length) {
		return reader_fail(reader,
				   PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRUNCATED);
	}
	record->next_offset = next_offset;
	return 0;
}

int pqcp_deployment_evidence_codec_record_reader(
	const struct pqcp_deployment_evidence_codec_reader *parent,
	const struct pqcp_deployment_evidence_codec_record *record,
	struct pqcp_deployment_evidence_codec_reader *payload)
{
	if (parent == NULL || record == NULL || payload == NULL ||
	    parent->buffer == NULL ||
	    record->payload_offset > parent->length ||
	    record->length > parent->length - record->payload_offset) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_codec_reader_init(
		payload, parent->buffer + record->payload_offset,
		record->length);
	return 0;
}

int pqcp_deployment_evidence_codec_finish_record(
	struct pqcp_deployment_evidence_codec_reader *parent,
	const struct pqcp_deployment_evidence_codec_record *record,
	const struct pqcp_deployment_evidence_codec_reader *payload)
{
	if (parent == NULL || record == NULL || payload == NULL) {
		return reader_fail(
			parent,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	}
	if (!pqcp_deployment_evidence_codec_reader_ok(payload) ||
	    payload->offset != payload->length) {
		return reader_fail(
			parent,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRAILING_DATA);
	}
	for (size_t index = record->payload_offset + record->length;
	     index < record->next_offset; ++index) {
		if (parent->buffer[index] != 0U) {
			return reader_fail(
				parent,
				PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED);
		}
	}
	parent->offset = record->next_offset;
	return 0;
}

int pqcp_deployment_evidence_codec_require_eof(
	struct pqcp_deployment_evidence_codec_reader *reader)
{
	if (reader == NULL) {
		return -EINVAL;
	}
	if (!pqcp_deployment_evidence_codec_reader_ok(reader)) {
		return codec_errno(reader->error);
	}
	if (reader->offset != reader->length) {
		return reader_fail(
			reader,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRAILING_DATA);
	}
	return 0;
}

bool pqcp_deployment_evidence_codec_is_lower_hex(
	const char *text,
	size_t expected_length)
{
	if (text == NULL || strlen(text) != expected_length) {
		return false;
	}
	for (size_t index = 0U; index < expected_length; ++index) {
		const char value = text[index];

		if (!((value >= '0' && value <= '9') ||
		      (value >= 'a' && value <= 'f'))) {
			return false;
		}
	}
	return true;
}

int pqcp_deployment_evidence_codec_hex_to_bytes(
	const char *hex,
	size_t hex_length,
	uint8_t *output,
	size_t output_capacity)
{
	bool valid = true;
	size_t byte_length;

	if (hex == NULL || output == NULL || (hex_length & 1U) != 0U) {
		return -EINVAL;
	}
	byte_length = hex_length / 2U;
	if (byte_length > output_capacity) {
		return -ENOSPC;
	}
	for (size_t index = 0U; index < byte_length; ++index) {
		const uint8_t high = hex_nibble(hex[index * 2U], &valid);
		const uint8_t low = hex_nibble(hex[index * 2U + 1U], &valid);

		output[index] = (uint8_t)((high << 4U) | low);
	}
	return valid ? 0 : -EBADMSG;
}

int pqcp_deployment_evidence_codec_bytes_to_hex(
	const uint8_t *bytes,
	size_t byte_length,
	char *output,
	size_t output_capacity)
{
	static const char alphabet[] = "0123456789abcdef";
	size_t required;

	if (bytes == NULL || output == NULL ||
	    byte_length > (SIZE_MAX - 1U) / 2U) {
		return -EINVAL;
	}
	required = byte_length * 2U + 1U;
	if (output_capacity < required) {
		return -ENOSPC;
	}
	for (size_t index = 0U; index < byte_length; ++index) {
		output[index * 2U] = alphabet[bytes[index] >> 4U];
		output[index * 2U + 1U] =
			alphabet[bytes[index] & 0x0fU];
	}
	output[byte_length * 2U] = '\0';
	return 0;
}

void pqcp_deployment_evidence_digest_init(
	struct pqcp_deployment_evidence_digest *digest,
	uint64_t domain)
{
	if (digest == NULL) {
		return;
	}
	digest->lane[0] = PQCP_CODEC_FNV_OFFSET ^ domain;
	digest->lane[1] = PQCP_CODEC_MIX_A ^ rotate_left64(domain, 13U);
	digest->lane[2] = PQCP_CODEC_MIX_B ^ rotate_left64(domain, 29U);
	digest->lane[3] = PQCP_CODEC_MIX_C ^ rotate_left64(domain, 47U);
	digest->total_bytes = 0U;
}

void pqcp_deployment_evidence_digest_update(
	struct pqcp_deployment_evidence_digest *digest,
	const void *data,
	size_t length)
{
	const uint8_t *bytes = data;

	if (digest == NULL || (data == NULL && length != 0U)) {
		return;
	}
	for (size_t index = 0U; index < length; ++index) {
		const uint64_t position =
			digest->total_bytes + (uint64_t)index + 1U;
		const uint64_t value = bytes[index];

		digest->lane[0] ^= value;
		digest->lane[0] *= PQCP_CODEC_FNV_PRIME;
		digest->lane[1] += value + position * PQCP_CODEC_MIX_A;
		digest->lane[1] =
			rotate_left64(digest->lane[1], 11U) *
			PQCP_CODEC_MIX_B;
		digest->lane[2] ^= value + rotate_left64(position, 17U);
		digest->lane[2] =
			rotate_left64(digest->lane[2], 23U) *
			PQCP_CODEC_MIX_C;
		digest->lane[3] +=
			(value ^ (digest->lane[0] >> 32U)) +
			position;
		digest->lane[3] =
			rotate_left64(digest->lane[3], 37U) *
			PQCP_CODEC_FNV_PRIME;
		digest->lane[1] ^= digest->lane[0] >> 7U;
		digest->lane[2] += digest->lane[1] ^ PQCP_CODEC_MIX_A;
		digest->lane[3] ^= digest->lane[2] >> 11U;
	}
	digest->total_bytes += length;
}

void pqcp_deployment_evidence_digest_update_u8(
	struct pqcp_deployment_evidence_digest *digest,
	uint8_t value)
{
	pqcp_deployment_evidence_digest_update(digest, &value, sizeof(value));
}

void pqcp_deployment_evidence_digest_update_u16(
	struct pqcp_deployment_evidence_digest *digest,
	uint16_t value)
{
	uint8_t encoded[2] = {
		(uint8_t)(value & 0xffU),
		(uint8_t)((value >> 8U) & 0xffU),
	};

	pqcp_deployment_evidence_digest_update(digest, encoded,
					       sizeof(encoded));
}

void pqcp_deployment_evidence_digest_update_u32(
	struct pqcp_deployment_evidence_digest *digest,
	uint32_t value)
{
	uint8_t encoded[4] = {
		(uint8_t)(value & 0xffU),
		(uint8_t)((value >> 8U) & 0xffU),
		(uint8_t)((value >> 16U) & 0xffU),
		(uint8_t)((value >> 24U) & 0xffU),
	};

	pqcp_deployment_evidence_digest_update(digest, encoded,
					       sizeof(encoded));
}

void pqcp_deployment_evidence_digest_update_u64(
	struct pqcp_deployment_evidence_digest *digest,
	uint64_t value)
{
	uint8_t encoded[8];

	for (size_t index = 0U; index < sizeof(encoded); ++index) {
		encoded[index] =
			(uint8_t)((value >> (index * 8U)) & 0xffU);
	}
	pqcp_deployment_evidence_digest_update(digest, encoded,
					       sizeof(encoded));
}

void pqcp_deployment_evidence_digest_update_bool(
	struct pqcp_deployment_evidence_digest *digest,
	bool value)
{
	pqcp_deployment_evidence_digest_update_u8(
		digest, value ? 1U : 0U);
}

void pqcp_deployment_evidence_digest_update_text(
	struct pqcp_deployment_evidence_digest *digest,
	const char *text)
{
	uint32_t length = 0U;

	if (text != NULL) {
		const size_t measured = strlen(text);

		length = measured > UINT32_MAX ? UINT32_MAX :
						 (uint32_t)measured;
	}
	pqcp_deployment_evidence_digest_update_u32(digest, length);
	if (length != 0U) {
		pqcp_deployment_evidence_digest_update(
			digest, text, length);
	}
}

void pqcp_deployment_evidence_digest_final_bytes(
	const struct pqcp_deployment_evidence_digest *digest,
	uint8_t output[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES])
{
	uint64_t lane[4];

	if (digest == NULL || output == NULL) {
		return;
	}
	lane[0] = avalanche64(digest->lane[0] ^
			      digest->total_bytes ^ PQCP_CODEC_MIX_A);
	lane[1] = avalanche64(digest->lane[1] ^
			      rotate_left64(digest->lane[0], 17U) ^
			      digest->total_bytes);
	lane[2] = avalanche64(digest->lane[2] ^
			      rotate_left64(digest->lane[1], 31U) ^
			      (digest->total_bytes * PQCP_CODEC_MIX_B));
	lane[3] = avalanche64(digest->lane[3] ^
			      rotate_left64(digest->lane[2], 43U) ^
			      (digest->total_bytes * PQCP_CODEC_MIX_C));
	for (size_t index = 0U; index < 4U; ++index) {
		for (size_t byte = 0U; byte < 8U; ++byte) {
			output[index * 8U + byte] =
				(uint8_t)((lane[index] >> (byte * 8U)) &
					  0xffU);
		}
	}
}

int pqcp_deployment_evidence_digest_final_hex(
	const struct pqcp_deployment_evidence_digest *digest,
	char output[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U])
{
	uint8_t bytes[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES];

	if (digest == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_final_bytes(digest, bytes);
	return pqcp_deployment_evidence_codec_bytes_to_hex(
		bytes, sizeof(bytes), output,
		PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U);
}

int pqcp_deployment_evidence_digest_buffer_hex(
	uint64_t domain,
	const void *data,
	size_t length,
	char output[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if ((data == NULL && length != 0U) || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(&digest, domain);
	pqcp_deployment_evidence_digest_update(&digest, data, length);
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}
