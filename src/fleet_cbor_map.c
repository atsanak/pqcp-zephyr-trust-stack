/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deterministic, allocation-free CBOR codec.
 */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/fleet_cose.h>

#define CBOR_MAX_DEPTH 32U
#define CBOR_ADDITIONAL_ONE_BYTE 24U
#define CBOR_ADDITIONAL_TWO_BYTES 25U
#define CBOR_ADDITIONAL_FOUR_BYTES 26U
#define CBOR_ADDITIONAL_EIGHT_BYTES 27U
#define CBOR_ADDITIONAL_INDEFINITE 31U

static int writer_fail(
	struct pqcp_fleet_cbor_writer *writer,
	int error)
{
	if (writer != NULL && writer->error == 0) {
		writer->error = error;
	}
	return error;
}

static int reader_fail(
	struct pqcp_fleet_cbor_reader *reader,
	int error)
{
	if (reader != NULL && reader->error == 0) {
		reader->error = error;
	}
	return error;
}

static int writer_reserve(
	struct pqcp_fleet_cbor_writer *writer,
	size_t length,
	uint8_t **destination)
{
	if (writer == NULL || destination == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (writer->error != 0) {
		return writer->error;
	}
	if (length > writer->capacity ||
	    writer->offset > writer->capacity - length) {
		return writer_fail(
			writer, PQCP_FLEET_COSE_ERR_CAPACITY);
	}
	*destination = writer->buffer + writer->offset;
	writer->offset += length;
	return 0;
}

static int writer_byte(
	struct pqcp_fleet_cbor_writer *writer,
	uint8_t value)
{
	uint8_t *destination;
	int ret = writer_reserve(writer, 1U, &destination);

	if (ret == 0) {
		destination[0] = value;
	}
	return ret;
}

static int writer_copy(
	struct pqcp_fleet_cbor_writer *writer,
	const uint8_t *value,
	size_t length)
{
	uint8_t *destination;
	int ret;

	if (value == NULL && length != 0U) {
		return writer_fail(
			writer, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = writer_reserve(writer, length, &destination);
	if (ret == 0 && length != 0U) {
		memcpy(destination, value, length);
	}
	return ret;
}

static int write_argument(
	struct pqcp_fleet_cbor_writer *writer,
	enum pqcp_fleet_cbor_major major,
	uint64_t argument)
{
	uint8_t encoded[9];
	size_t length;

	if (writer == NULL ||
	    major < PQCP_FLEET_CBOR_UNSIGNED ||
	    major > PQCP_FLEET_CBOR_SIMPLE) {
		return writer_fail(
			writer, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	if (argument < 24U) {
		encoded[0] =
			(uint8_t)(((uint8_t)major << 5) |
				  (uint8_t)argument);
		length = 1U;
	} else if (argument <= UINT8_MAX) {
		encoded[0] =
			(uint8_t)(((uint8_t)major << 5) |
				  CBOR_ADDITIONAL_ONE_BYTE);
		encoded[1] = (uint8_t)argument;
		length = 2U;
	} else if (argument <= UINT16_MAX) {
		encoded[0] =
			(uint8_t)(((uint8_t)major << 5) |
				  CBOR_ADDITIONAL_TWO_BYTES);
		encoded[1] = (uint8_t)(argument >> 8);
		encoded[2] = (uint8_t)argument;
		length = 3U;
	} else if (argument <= UINT32_MAX) {
		encoded[0] =
			(uint8_t)(((uint8_t)major << 5) |
				  CBOR_ADDITIONAL_FOUR_BYTES);
		for (size_t index = 0U; index < 4U; ++index) {
			const unsigned shift =
				(unsigned)((3U - index) * 8U);

			encoded[1U + index] =
				(uint8_t)(argument >> shift);
		}
		length = 5U;
	} else {
		encoded[0] =
			(uint8_t)(((uint8_t)major << 5) |
				  CBOR_ADDITIONAL_EIGHT_BYTES);
		for (size_t index = 0U; index < 8U; ++index) {
			const unsigned shift =
				(unsigned)((7U - index) * 8U);

			encoded[1U + index] =
				(uint8_t)(argument >> shift);
		}
		length = 9U;
	}
	return writer_copy(writer, encoded, length);
}

static int reader_take(
	struct pqcp_fleet_cbor_reader *reader,
	size_t length,
	const uint8_t **value)
{
	if (reader == NULL || value == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (reader->error != 0) {
		return reader->error;
	}
	if (length > reader->length ||
	    reader->offset > reader->length - length) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ENCODING);
	}
	*value = reader->buffer + reader->offset;
	reader->offset += length;
	return 0;
}

static int decode_argument(
	struct pqcp_fleet_cbor_reader *reader,
	uint8_t additional,
	uint64_t *argument,
	size_t *extra_bytes)
{
	const uint8_t *encoded;
	size_t length;
	uint64_t value = 0U;
	int ret;

	if (argument == NULL || extra_bytes == NULL) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	if (additional < 24U) {
		*argument = additional;
		*extra_bytes = 0U;
		return 0;
	}
	switch (additional) {
	case CBOR_ADDITIONAL_ONE_BYTE:
		length = 1U;
		break;
	case CBOR_ADDITIONAL_TWO_BYTES:
		length = 2U;
		break;
	case CBOR_ADDITIONAL_FOUR_BYTES:
		length = 4U;
		break;
	case CBOR_ADDITIONAL_EIGHT_BYTES:
		length = 8U;
		break;
	case CBOR_ADDITIONAL_INDEFINITE:
	default:
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_UNSUPPORTED);
	}
	ret = reader_take(reader, length, &encoded);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < length; ++index) {
		value = (value << 8) | encoded[index];
	}
	if ((length == 1U && value < 24U) ||
	    (length == 2U && value <= UINT8_MAX) ||
	    (length == 4U && value <= UINT16_MAX) ||
	    (length == 8U && value <= UINT32_MAX)) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_NON_CANONICAL);
	}
	*argument = value;
	*extra_bytes = length;
	return 0;
}

static int read_expected_head(
	struct pqcp_fleet_cbor_reader *reader,
	enum pqcp_fleet_cbor_major major,
	struct pqcp_fleet_cbor_head *head)
{
	int ret = pqcp_fleet_cbor_read_head(reader, head);

	if (ret != 0) {
		return ret;
	}
	if (head->major != major) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ENCODING);
	}
	return 0;
}

void pqcp_fleet_cbor_writer_init(
	struct pqcp_fleet_cbor_writer *writer,
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
		writer->error = PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
}

int pqcp_fleet_cbor_write_uint(
	struct pqcp_fleet_cbor_writer *writer,
	uint64_t value)
{
	return write_argument(
		writer, PQCP_FLEET_CBOR_UNSIGNED, value);
}

int pqcp_fleet_cbor_write_int(
	struct pqcp_fleet_cbor_writer *writer,
	int64_t value)
{
	if (value >= 0) {
		return write_argument(
			writer, PQCP_FLEET_CBOR_UNSIGNED,
			(uint64_t)value);
	}
	return write_argument(
		writer, PQCP_FLEET_CBOR_NEGATIVE,
		(uint64_t)(-(value + 1)));
}

int pqcp_fleet_cbor_write_bytes(
	struct pqcp_fleet_cbor_writer *writer,
	const uint8_t *value,
	size_t length)
{
	int ret;

	if (value == NULL && length != 0U) {
		return writer_fail(
			writer, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = write_argument(
		writer, PQCP_FLEET_CBOR_BYTES, length);
	if (ret == 0) {
		ret = writer_copy(writer, value, length);
	}
	return ret;
}

int pqcp_fleet_cbor_write_text(
	struct pqcp_fleet_cbor_writer *writer,
	const char *value,
	size_t length)
{
	int ret;

	if (value == NULL && length != 0U) {
		return writer_fail(
			writer, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = write_argument(
		writer, PQCP_FLEET_CBOR_TEXT, length);
	if (ret == 0) {
		ret = writer_copy(
			writer, (const uint8_t *)value, length);
	}
	return ret;
}

int pqcp_fleet_cbor_write_bool(
	struct pqcp_fleet_cbor_writer *writer,
	bool value)
{
	return writer_byte(
		writer, value ? UINT8_C(0xf5) : UINT8_C(0xf4));
}

int pqcp_fleet_cbor_write_null(
	struct pqcp_fleet_cbor_writer *writer)
{
	return writer_byte(writer, UINT8_C(0xf6));
}

int pqcp_fleet_cbor_write_tag(
	struct pqcp_fleet_cbor_writer *writer,
	uint64_t tag)
{
	return write_argument(writer, PQCP_FLEET_CBOR_TAG, tag);
}

int pqcp_fleet_cbor_write_array(
	struct pqcp_fleet_cbor_writer *writer,
	size_t count)
{
	return write_argument(
		writer, PQCP_FLEET_CBOR_ARRAY, count);
}

int pqcp_fleet_cbor_write_map(
	struct pqcp_fleet_cbor_writer *writer,
	size_t count)
{
	return write_argument(
		writer, PQCP_FLEET_CBOR_MAP, count);
}

int pqcp_fleet_cbor_write_encoded(
	struct pqcp_fleet_cbor_writer *writer,
	const uint8_t *encoded,
	size_t encoded_length)
{
	struct pqcp_fleet_cbor_reader reader;
	int ret;

	if (encoded == NULL || encoded_length == 0U) {
		return writer_fail(
			writer, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	ret = pqcp_fleet_cbor_skip(&reader);
	if (ret == 0) {
		ret = pqcp_fleet_cbor_reader_finish(&reader);
	}
	if (ret == 0) {
		ret = writer_copy(
			writer, encoded, encoded_length);
	}
	return ret;
}

int pqcp_fleet_cbor_writer_finish(
	struct pqcp_fleet_cbor_writer *writer,
	size_t *encoded_length)
{
	if (writer == NULL || encoded_length == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (writer->error != 0) {
		return writer->error;
	}
	*encoded_length = writer->offset;
	return 0;
}

void pqcp_fleet_cbor_reader_init(
	struct pqcp_fleet_cbor_reader *reader,
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
		reader->error = PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
}

int pqcp_fleet_cbor_read_head(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_head *head)
{
	const uint8_t *initial;
	uint8_t encoded;
	uint8_t additional;
	size_t extra_bytes;
	int ret;

	if (reader == NULL || head == NULL) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = reader_take(reader, 1U, &initial);
	if (ret != 0) {
		return ret;
	}
	encoded = initial[0];
	additional = encoded & UINT8_C(0x1f);
	memset(head, 0, sizeof(*head));
	head->major =
		(enum pqcp_fleet_cbor_major)(encoded >> 5);
	ret = decode_argument(
		reader, additional, &head->argument,
		&extra_bytes);
	if (ret != 0) {
		return ret;
	}
	head->encoded_bytes = 1U + extra_bytes;
	if (head->major == PQCP_FLEET_CBOR_SIMPLE &&
	    head->argument != PQCP_FLEET_CBOR_FALSE &&
	    head->argument != PQCP_FLEET_CBOR_TRUE &&
	    head->argument != PQCP_FLEET_CBOR_NULL) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_UNSUPPORTED);
	}
	return 0;
}

int pqcp_fleet_cbor_read_uint(
	struct pqcp_fleet_cbor_reader *reader,
	uint64_t *value)
{
	struct pqcp_fleet_cbor_head head;
	int ret;

	if (value == NULL) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = read_expected_head(
		reader, PQCP_FLEET_CBOR_UNSIGNED, &head);
	if (ret == 0) {
		*value = head.argument;
	}
	return ret;
}

int pqcp_fleet_cbor_read_int(
	struct pqcp_fleet_cbor_reader *reader,
	int64_t *value)
{
	struct pqcp_fleet_cbor_head head;
	int ret;

	if (value == NULL) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = pqcp_fleet_cbor_read_head(reader, &head);
	if (ret != 0) {
		return ret;
	}
	if (head.major == PQCP_FLEET_CBOR_UNSIGNED) {
		if (head.argument > INT64_MAX) {
			return reader_fail(
				reader, PQCP_FLEET_COSE_ERR_ENCODING);
		}
		*value = (int64_t)head.argument;
		return 0;
	}
	if (head.major == PQCP_FLEET_CBOR_NEGATIVE) {
		if (head.argument > INT64_MAX) {
			return reader_fail(
				reader, PQCP_FLEET_COSE_ERR_ENCODING);
		}
		*value = -(int64_t)head.argument - 1;
		return 0;
	}
	return reader_fail(
		reader, PQCP_FLEET_COSE_ERR_ENCODING);
}

static int read_string(
	struct pqcp_fleet_cbor_reader *reader,
	enum pqcp_fleet_cbor_major expected,
	struct pqcp_fleet_cbor_slice *value)
{
	struct pqcp_fleet_cbor_head head;
	const uint8_t *content;
	int ret;

	if (value == NULL) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = read_expected_head(reader, expected, &head);
	if (ret != 0) {
		return ret;
	}
	if (head.argument > SIZE_MAX) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_CAPACITY);
	}
	ret = reader_take(
		reader, (size_t)head.argument, &content);
	if (ret == 0) {
		value->data = content;
		value->length = (size_t)head.argument;
	}
	return ret;
}

int pqcp_fleet_cbor_read_bytes(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_slice *value)
{
	return read_string(reader, PQCP_FLEET_CBOR_BYTES, value);
}

int pqcp_fleet_cbor_read_text(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_slice *value)
{
	return read_string(reader, PQCP_FLEET_CBOR_TEXT, value);
}

int pqcp_fleet_cbor_read_bool(
	struct pqcp_fleet_cbor_reader *reader,
	bool *value)
{
	struct pqcp_fleet_cbor_head head;
	int ret;

	if (value == NULL) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = read_expected_head(
		reader, PQCP_FLEET_CBOR_SIMPLE, &head);
	if (ret != 0) {
		return ret;
	}
	if (head.argument == PQCP_FLEET_CBOR_FALSE) {
		*value = false;
		return 0;
	}
	if (head.argument == PQCP_FLEET_CBOR_TRUE) {
		*value = true;
		return 0;
	}
	return reader_fail(
		reader, PQCP_FLEET_COSE_ERR_ENCODING);
}

int pqcp_fleet_cbor_read_null(
	struct pqcp_fleet_cbor_reader *reader)
{
	struct pqcp_fleet_cbor_head head;
	int ret = read_expected_head(
		reader, PQCP_FLEET_CBOR_SIMPLE, &head);

	if (ret == 0 &&
	    head.argument != PQCP_FLEET_CBOR_NULL) {
		ret = reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ENCODING);
	}
	return ret;
}

int pqcp_fleet_cbor_read_tag(
	struct pqcp_fleet_cbor_reader *reader,
	uint64_t expected_tag)
{
	struct pqcp_fleet_cbor_head head;
	int ret = read_expected_head(
		reader, PQCP_FLEET_CBOR_TAG, &head);

	if (ret == 0 && head.argument != expected_tag) {
		ret = reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ENCODING);
	}
	return ret;
}

int pqcp_fleet_cbor_read_array(
	struct pqcp_fleet_cbor_reader *reader,
	size_t *count)
{
	struct pqcp_fleet_cbor_head head;
	int ret;

	if (count == NULL) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = read_expected_head(
		reader, PQCP_FLEET_CBOR_ARRAY, &head);
	if (ret == 0) {
		if (head.argument > SIZE_MAX) {
			ret = reader_fail(
				reader,
				PQCP_FLEET_COSE_ERR_CAPACITY);
		} else {
			*count = (size_t)head.argument;
		}
	}
	return ret;
}

int pqcp_fleet_cbor_read_map(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_map_cursor *cursor)
{
	struct pqcp_fleet_cbor_head head;
	int ret;

	if (cursor == NULL) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	ret = read_expected_head(
		reader, PQCP_FLEET_CBOR_MAP, &head);
	if (ret != 0) {
		return ret;
	}
	if (head.argument > SIZE_MAX) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_CAPACITY);
	}
	memset(cursor, 0, sizeof(*cursor));
	cursor->remaining = (size_t)head.argument;
	return 0;
}

int pqcp_fleet_cbor_compare_encoded_keys(
	const uint8_t *left,
	size_t left_length,
	const uint8_t *right,
	size_t right_length)
{
	int comparison;

	if ((left == NULL && left_length != 0U) ||
	    (right == NULL && right_length != 0U)) {
		return 0;
	}
	if (left_length < right_length) {
		return -1;
	}
	if (left_length > right_length) {
		return 1;
	}
	if (left_length == 0U) {
		return 0;
	}
	comparison = memcmp(left, right, left_length);
	return comparison < 0 ? -1 : comparison > 0 ? 1 : 0;
}

int pqcp_fleet_cbor_map_next(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cbor_map_cursor *cursor,
	struct pqcp_fleet_cbor_map_key *key)
{
	struct pqcp_fleet_cbor_reader probe;
	struct pqcp_fleet_cbor_head head;
	size_t start;
	size_t end;
	int comparison;
	int ret;

	if (reader == NULL || cursor == NULL || key == NULL ||
	    cursor->remaining == 0U) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ARGUMENT);
	}
	memset(key, 0, sizeof(*key));
	start = reader->offset;
	ret = pqcp_fleet_cbor_skip(reader);
	if (ret != 0) {
		return ret;
	}
	end = reader->offset;
	if (end <= start) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_ENCODING);
	}
	key->encoded = reader->buffer + start;
	key->encoded_length = end - start;
	probe = *reader;
	probe.offset = start;
	probe.error = 0;
	ret = pqcp_fleet_cbor_read_head(&probe, &head);
	if (ret != 0) {
		return ret;
	}
	if (head.major == PQCP_FLEET_CBOR_UNSIGNED) {
		if (head.argument <= INT64_MAX) {
			key->integer = true;
			key->integer_value = (int64_t)head.argument;
		}
	} else if (head.major == PQCP_FLEET_CBOR_NEGATIVE) {
		if (head.argument <= INT64_MAX) {
			key->integer = true;
			key->integer_value =
				-(int64_t)head.argument - 1;
		}
	}
	if (cursor->have_previous) {
		comparison = pqcp_fleet_cbor_compare_encoded_keys(
			cursor->previous_key.encoded,
			cursor->previous_key.encoded_length,
			key->encoded, key->encoded_length);
		if (comparison == 0) {
			return reader_fail(
				reader,
				PQCP_FLEET_COSE_ERR_DUPLICATE);
		}
		if (comparison > 0) {
			return reader_fail(
				reader,
				PQCP_FLEET_COSE_ERR_NON_CANONICAL);
		}
	}
	cursor->previous_key = *key;
	cursor->have_previous = true;
	cursor->remaining--;
	return 0;
}

static int skip_item(
	struct pqcp_fleet_cbor_reader *reader,
	unsigned depth)
{
	struct pqcp_fleet_cbor_head head;
	const uint8_t *discard;
	uint64_t child_count;
	int ret;

	if (depth > CBOR_MAX_DEPTH) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_CAPACITY);
	}
	ret = pqcp_fleet_cbor_read_head(reader, &head);
	if (ret != 0) {
		return ret;
	}
	switch (head.major) {
	case PQCP_FLEET_CBOR_UNSIGNED:
	case PQCP_FLEET_CBOR_NEGATIVE:
	case PQCP_FLEET_CBOR_SIMPLE:
		return 0;
	case PQCP_FLEET_CBOR_BYTES:
	case PQCP_FLEET_CBOR_TEXT:
		if (head.argument > SIZE_MAX) {
			return reader_fail(
				reader,
				PQCP_FLEET_COSE_ERR_CAPACITY);
		}
		return reader_take(
			reader, (size_t)head.argument, &discard);
	case PQCP_FLEET_CBOR_TAG:
		return skip_item(reader, depth + 1U);
	case PQCP_FLEET_CBOR_ARRAY:
		child_count = head.argument;
		break;
	case PQCP_FLEET_CBOR_MAP:
		if (head.argument > UINT64_MAX / 2U) {
			return reader_fail(
				reader,
				PQCP_FLEET_COSE_ERR_CAPACITY);
		}
		child_count = head.argument * 2U;
		break;
	default:
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_UNSUPPORTED);
	}
	for (uint64_t index = 0U;
	     index < child_count; ++index) {
		ret = skip_item(reader, depth + 1U);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

int pqcp_fleet_cbor_skip(
	struct pqcp_fleet_cbor_reader *reader)
{
	return skip_item(reader, 0U);
}

int pqcp_fleet_cbor_reader_finish(
	struct pqcp_fleet_cbor_reader *reader)
{
	if (reader == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (reader->error != 0) {
		return reader->error;
	}
	if (reader->offset != reader->length) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_TRAILING);
	}
	return 0;
}

static int validate_item(
	struct pqcp_fleet_cbor_reader *reader,
	unsigned depth)
{
	struct pqcp_fleet_cbor_reader probe;
	struct pqcp_fleet_cbor_head head;
	struct pqcp_fleet_cbor_map_cursor cursor;
	struct pqcp_fleet_cbor_map_key key;
	const uint8_t *discard;
	int ret;

	if (depth > CBOR_MAX_DEPTH) {
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_CAPACITY);
	}
	probe = *reader;
	ret = pqcp_fleet_cbor_read_head(&probe, &head);
	if (ret != 0) {
		return reader_fail(reader, ret);
	}
	switch (head.major) {
	case PQCP_FLEET_CBOR_UNSIGNED:
	case PQCP_FLEET_CBOR_NEGATIVE:
	case PQCP_FLEET_CBOR_SIMPLE:
		*reader = probe;
		return 0;
	case PQCP_FLEET_CBOR_BYTES:
	case PQCP_FLEET_CBOR_TEXT:
		if (head.argument > SIZE_MAX) {
			return reader_fail(
				reader,
				PQCP_FLEET_COSE_ERR_CAPACITY);
		}
		ret = reader_take(
			&probe, (size_t)head.argument, &discard);
		if (ret == 0) {
			*reader = probe;
		}
		return ret;
	case PQCP_FLEET_CBOR_TAG:
		*reader = probe;
		return validate_item(reader, depth + 1U);
	case PQCP_FLEET_CBOR_ARRAY:
		*reader = probe;
		for (uint64_t index = 0U;
		     index < head.argument; ++index) {
			ret = validate_item(reader, depth + 1U);
			if (ret != 0) {
				return ret;
			}
		}
		return 0;
	case PQCP_FLEET_CBOR_MAP:
		break;
	default:
		return reader_fail(
			reader, PQCP_FLEET_COSE_ERR_UNSUPPORTED);
	}
	ret = pqcp_fleet_cbor_read_map(reader, &cursor);
	if (ret != 0) {
		return ret;
	}
	while (cursor.remaining != 0U) {
		ret = pqcp_fleet_cbor_map_next(
			reader, &cursor, &key);
		if (ret != 0) {
			return ret;
		}
		ret = pqcp_fleet_cbor_validate(
			key.encoded, key.encoded_length);
		if (ret != 0) {
			return reader_fail(reader, ret);
		}
		ret = validate_item(reader, depth + 1U);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

int pqcp_fleet_cbor_validate(
	const uint8_t *encoded,
	size_t encoded_length)
{
	struct pqcp_fleet_cbor_reader reader;
	int ret;

	if (encoded == NULL || encoded_length == 0U) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	ret = validate_item(&reader, 0U);
	if (ret == 0) {
		ret = pqcp_fleet_cbor_reader_finish(&reader);
	}
	return ret;
}

int pqcp_fleet_cbor_item_span(
	const uint8_t *encoded,
	size_t encoded_length,
	size_t *item_length)
{
	struct pqcp_fleet_cbor_reader reader;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    item_length == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	*item_length = 0U;
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	ret = pqcp_fleet_cbor_skip(&reader);
	if (ret != 0) {
		return ret;
	}
	if (reader.offset == 0U ||
	    reader.offset > encoded_length) {
		return PQCP_FLEET_COSE_ERR_ENCODING;
	}
	ret = pqcp_fleet_cbor_validate(
		encoded, reader.offset);
	if (ret == 0) {
		*item_length = reader.offset;
	}
	return ret;
}

int pqcp_fleet_cbor_copy_item(
	const uint8_t *encoded,
	size_t encoded_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	size_t item_length = 0U;
	int ret;

	if (output == NULL || output_length == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	*output_length = 0U;
	ret = pqcp_fleet_cbor_item_span(
		encoded, encoded_length, &item_length);
	if (ret != 0) {
		return ret;
	}
	if (item_length > output_capacity) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	memcpy(output, encoded, item_length);
	*output_length = item_length;
	return 0;
}

int pqcp_fleet_cbor_array_count(
	const uint8_t *encoded,
	size_t encoded_length,
	size_t *count)
{
	struct pqcp_fleet_cbor_reader reader;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    count == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	*count = 0U;
	ret = pqcp_fleet_cbor_validate(
		encoded, encoded_length);
	if (ret != 0) {
		return ret;
	}
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	ret = pqcp_fleet_cbor_read_array(&reader, count);
	return ret;
}

int pqcp_fleet_cbor_array_get(
	const uint8_t *encoded,
	size_t encoded_length,
	size_t index,
	struct pqcp_fleet_cbor_slice *value)
{
	struct pqcp_fleet_cbor_reader reader;
	size_t count;
	size_t start;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    value == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memset(value, 0, sizeof(*value));
	ret = pqcp_fleet_cbor_validate(
		encoded, encoded_length);
	if (ret != 0) {
		return ret;
	}
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	ret = pqcp_fleet_cbor_read_array(&reader, &count);
	if (ret != 0) {
		return ret;
	}
	if (index >= count) {
		return PQCP_FLEET_COSE_ERR_REQUIRED;
	}
	for (size_t current = 0U;
	     current < count; ++current) {
		start = reader.offset;
		ret = pqcp_fleet_cbor_skip(&reader);
		if (ret != 0) {
			return ret;
		}
		if (current == index) {
			value->data = encoded + start;
			value->length = reader.offset - start;
		}
	}
	ret = pqcp_fleet_cbor_reader_finish(&reader);
	return ret;
}

int pqcp_fleet_cbor_map_count(
	const uint8_t *encoded,
	size_t encoded_length,
	size_t *count)
{
	struct pqcp_fleet_cbor_reader reader;
	struct pqcp_fleet_cbor_map_cursor cursor;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    count == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	*count = 0U;
	ret = pqcp_fleet_cbor_validate(
		encoded, encoded_length);
	if (ret != 0) {
		return ret;
	}
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	ret = pqcp_fleet_cbor_read_map(&reader, &cursor);
	if (ret == 0) {
		*count = cursor.remaining;
	}
	return ret;
}

int pqcp_fleet_cbor_map_find_int(
	const uint8_t *encoded,
	size_t encoded_length,
	int64_t label,
	struct pqcp_fleet_cbor_slice *value)
{
	struct pqcp_fleet_cbor_reader reader;
	struct pqcp_fleet_cbor_map_cursor cursor;
	struct pqcp_fleet_cbor_map_key key;
	size_t value_start;
	bool found = false;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    value == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memset(value, 0, sizeof(*value));
	ret = pqcp_fleet_cbor_validate(
		encoded, encoded_length);
	if (ret != 0) {
		return ret;
	}
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	ret = pqcp_fleet_cbor_read_map(&reader, &cursor);
	if (ret != 0) {
		return ret;
	}
	while (cursor.remaining != 0U) {
		ret = pqcp_fleet_cbor_map_next(
			&reader, &cursor, &key);
		if (ret != 0) {
			return ret;
		}
		value_start = reader.offset;
		ret = pqcp_fleet_cbor_skip(&reader);
		if (ret != 0) {
			return ret;
		}
		if (key.integer && key.integer_value == label) {
			value->data = encoded + value_start;
			value->length =
				reader.offset - value_start;
			found = true;
		}
	}
	ret = pqcp_fleet_cbor_reader_finish(&reader);
	if (ret != 0) {
		return ret;
	}
	return found ? 0 : PQCP_FLEET_COSE_ERR_REQUIRED;
}
