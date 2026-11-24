/*
 * SPDX-License-Identifier: MIT
 *
 * RFC 9052 COSE_Sign1 support with RFC 9964 ML-DSA algorithms.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/fleet_cose.h>

#define COSE_SIGN1_FIELDS 4U
#define COSE_SIGNATURE_CONTEXT "Signature1"
#define COSE_SIGNATURE_CONTEXT_BYTES 10U

static bool algorithm_supported(int32_t algorithm)
{
	return algorithm == PQCP_FLEET_COSE_ALG_ML_DSA_44 ||
	       algorithm == PQCP_FLEET_COSE_ALG_ML_DSA_65 ||
	       algorithm == PQCP_FLEET_COSE_ALG_ML_DSA_87;
}

size_t pqcp_fleet_cose_algorithm_public_key_bytes(
	int32_t algorithm)
{
	switch (algorithm) {
	case PQCP_FLEET_COSE_ALG_ML_DSA_44:
		return PQCP_FLEET_COSE_ML_DSA_44_PUBLIC_BYTES;
	case PQCP_FLEET_COSE_ALG_ML_DSA_65:
		return PQCP_FLEET_COSE_ML_DSA_65_PUBLIC_BYTES;
	case PQCP_FLEET_COSE_ALG_ML_DSA_87:
		return PQCP_FLEET_COSE_ML_DSA_87_PUBLIC_BYTES;
	default:
		return 0U;
	}
}

size_t pqcp_fleet_cose_algorithm_signature_bytes(
	int32_t algorithm)
{
	switch (algorithm) {
	case PQCP_FLEET_COSE_ALG_ML_DSA_44:
		return PQCP_FLEET_COSE_ML_DSA_44_SIGNATURE_BYTES;
	case PQCP_FLEET_COSE_ALG_ML_DSA_65:
		return PQCP_FLEET_COSE_ML_DSA_65_SIGNATURE_BYTES;
	case PQCP_FLEET_COSE_ALG_ML_DSA_87:
		return PQCP_FLEET_COSE_ML_DSA_87_SIGNATURE_BYTES;
	default:
		return 0U;
	}
}

static bool critical_label_supported(int64_t label)
{
	return label == PQCP_FLEET_COSE_HEADER_ALG ||
	       label == PQCP_FLEET_COSE_HEADER_CONTENT_TYPE ||
	       label == PQCP_FLEET_COSE_HEADER_KID;
}

static bool critical_contains(
	const struct pqcp_fleet_cose_headers *headers,
	int64_t label)
{
	for (size_t index = 0U;
	     index < headers->critical_count; ++index) {
		if (headers->critical[index] == label) {
			return true;
		}
	}
	return false;
}

static size_t bounded_string_length(
	const char *value,
	size_t capacity)
{
	size_t length = 0U;

	if (value == NULL) {
		return 0U;
	}
	while (length < capacity && value[length] != '\0') {
		length++;
	}
	return length;
}

int pqcp_fleet_cose_headers_validate(
	const struct pqcp_fleet_cose_headers *headers,
	bool protected_bucket)
{
	size_t content_length;

	if (headers == NULL ||
	    headers->kid_length >
		    sizeof(headers->kid) ||
	    headers->critical_count >
		    PQCP_FLEET_COSE_MAX_CRITICAL_HEADERS ||
	    headers->content_type_kind >
		    PQCP_FLEET_COSE_CONTENT_TYPE_TEXT) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (protected_bucket) {
		if (!algorithm_supported(headers->algorithm)) {
			return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		}
	} else if (headers->algorithm != 0) {
		return PQCP_FLEET_COSE_ERR_POLICY;
	}
	if (headers->critical_count != 0U && !protected_bucket) {
		return PQCP_FLEET_COSE_ERR_POLICY;
	}
	for (size_t index = 0U;
	     index < headers->critical_count; ++index) {
		if (!critical_label_supported(
			    headers->critical[index])) {
			return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		}
		for (size_t previous = 0U;
		     previous < index; ++previous) {
			if (headers->critical[previous] ==
			    headers->critical[index]) {
				return PQCP_FLEET_COSE_ERR_DUPLICATE;
			}
		}
	}
	if (headers->critical_count != 0U &&
	    critical_contains(
		    headers, PQCP_FLEET_COSE_HEADER_ALG) &&
	    headers->algorithm == 0) {
		return PQCP_FLEET_COSE_ERR_REQUIRED;
	}
	if (critical_contains(
		    headers,
		    PQCP_FLEET_COSE_HEADER_CONTENT_TYPE) &&
	    headers->content_type_kind ==
		    PQCP_FLEET_COSE_CONTENT_TYPE_NONE) {
		return PQCP_FLEET_COSE_ERR_REQUIRED;
	}
	if (critical_contains(
		    headers, PQCP_FLEET_COSE_HEADER_KID) &&
	    headers->kid_length == 0U) {
		return PQCP_FLEET_COSE_ERR_REQUIRED;
	}
	if (headers->content_type_kind ==
	    PQCP_FLEET_COSE_CONTENT_TYPE_TEXT) {
		content_length = bounded_string_length(
			headers->content_type_text,
			sizeof(headers->content_type_text));
		if (content_length == 0U ||
		    content_length >=
			    sizeof(headers->content_type_text)) {
			return PQCP_FLEET_COSE_ERR_ARGUMENT;
		}
	}
	if (headers->content_type_kind ==
	    PQCP_FLEET_COSE_CONTENT_TYPE_INTEGER &&
	    headers->content_type_integer < 0) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	return 0;
}

static size_t protected_map_fields(
	const struct pqcp_fleet_cose_headers *headers)
{
	size_t fields = 1U;

	if (headers->critical_count != 0U) {
		fields++;
	}
	if (headers->content_type_kind !=
	    PQCP_FLEET_COSE_CONTENT_TYPE_NONE) {
		fields++;
	}
	if (headers->kid_length != 0U) {
		fields++;
	}
	return fields;
}

static size_t unprotected_map_fields(
	const struct pqcp_fleet_cose_headers *headers)
{
	size_t fields = 0U;

	if (headers == NULL) {
		return 0U;
	}
	if (headers->content_type_kind !=
	    PQCP_FLEET_COSE_CONTENT_TYPE_NONE) {
		fields++;
	}
	if (headers->kid_length != 0U) {
		fields++;
	}
	return fields;
}

static int write_content_type(
	struct pqcp_fleet_cbor_writer *writer,
	const struct pqcp_fleet_cose_headers *headers)
{
	size_t length;

	if (headers->content_type_kind ==
	    PQCP_FLEET_COSE_CONTENT_TYPE_INTEGER) {
		return pqcp_fleet_cbor_write_int(
			writer, headers->content_type_integer);
	}
	if (headers->content_type_kind ==
	    PQCP_FLEET_COSE_CONTENT_TYPE_TEXT) {
		length = bounded_string_length(
			headers->content_type_text,
			sizeof(headers->content_type_text));
		return pqcp_fleet_cbor_write_text(
			writer, headers->content_type_text, length);
	}
	return PQCP_FLEET_COSE_ERR_ARGUMENT;
}

static int encode_headers_map(
	const struct pqcp_fleet_cose_headers *headers,
	bool protected_bucket,
	struct pqcp_fleet_cbor_writer *writer)
{
	size_t fields;
	int ret;

	ret = pqcp_fleet_cose_headers_validate(
		headers, protected_bucket);
	if (ret != 0) {
		return ret;
	}
	fields = protected_bucket ?
		protected_map_fields(headers) :
		unprotected_map_fields(headers);
	ret = pqcp_fleet_cbor_write_map(writer, fields);
	if (ret != 0) {
		return ret;
	}
	if (protected_bucket) {
		ret = pqcp_fleet_cbor_write_int(
			writer, PQCP_FLEET_COSE_HEADER_ALG);
		if (ret == 0) {
			ret = pqcp_fleet_cbor_write_int(
				writer, headers->algorithm);
		}
	}
	if (ret == 0 && protected_bucket &&
	    headers->critical_count != 0U) {
		ret = pqcp_fleet_cbor_write_int(
			writer, PQCP_FLEET_COSE_HEADER_CRIT);
		if (ret == 0) {
			ret = pqcp_fleet_cbor_write_array(
				writer, headers->critical_count);
		}
		for (size_t index = 0U;
		     ret == 0 &&
		     index < headers->critical_count;
		     ++index) {
			ret = pqcp_fleet_cbor_write_int(
				writer, headers->critical[index]);
		}
	}
	if (ret == 0 &&
	    headers->content_type_kind !=
		    PQCP_FLEET_COSE_CONTENT_TYPE_NONE) {
		ret = pqcp_fleet_cbor_write_int(
			writer,
			PQCP_FLEET_COSE_HEADER_CONTENT_TYPE);
		if (ret == 0) {
			ret = write_content_type(writer, headers);
		}
	}
	if (ret == 0 && headers->kid_length != 0U) {
		ret = pqcp_fleet_cbor_write_int(
			writer, PQCP_FLEET_COSE_HEADER_KID);
		if (ret == 0) {
			ret = pqcp_fleet_cbor_write_bytes(
				writer, headers->kid,
				headers->kid_length);
		}
	}
	return ret;
}

int pqcp_fleet_cose_protected_encode(
	const struct pqcp_fleet_cose_headers *headers,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_fleet_cbor_writer writer;
	int ret;

	if (output == NULL || output_length == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	pqcp_fleet_cbor_writer_init(
		&writer, output, output_capacity);
	ret = encode_headers_map(headers, true, &writer);
	if (ret == 0) {
		ret = pqcp_fleet_cbor_writer_finish(
			&writer, output_length);
	}
	return ret;
}

static int copy_slice(
	const struct pqcp_fleet_cbor_slice *slice,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (slice == NULL || output == NULL || length == NULL ||
	    slice->length > capacity) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	if (slice->length != 0U) {
		memcpy(output, slice->data, slice->length);
	}
	*length = slice->length;
	return 0;
}

static int read_content_type(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cose_headers *headers)
{
	struct pqcp_fleet_cbor_reader probe;
	struct pqcp_fleet_cbor_head head;
	struct pqcp_fleet_cbor_slice text;
	int64_t integer;
	int ret;

	probe = *reader;
	ret = pqcp_fleet_cbor_read_head(&probe, &head);
	if (ret != 0) {
		return ret;
	}
	if (head.major == PQCP_FLEET_CBOR_UNSIGNED) {
		ret = pqcp_fleet_cbor_read_int(reader, &integer);
		if (ret == 0) {
			headers->content_type_kind =
				PQCP_FLEET_COSE_CONTENT_TYPE_INTEGER;
			headers->content_type_integer = integer;
		}
		return ret;
	}
	if (head.major != PQCP_FLEET_CBOR_TEXT) {
		return PQCP_FLEET_COSE_ERR_ENCODING;
	}
	ret = pqcp_fleet_cbor_read_text(reader, &text);
	if (ret != 0) {
		return ret;
	}
	if (text.length == 0U ||
	    text.length >= sizeof(headers->content_type_text)) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	/* The decoded type is a C string. An embedded NUL would make the
	 * string callers compare shorter than the signed header bytes, so
	 * two different protected headers would decode to the same type and
	 * the codec could not round-trip. Refuse it outright.
	 */
	if (memchr(text.data, 0, text.length) != NULL) {
		return PQCP_FLEET_COSE_ERR_ENCODING;
	}
	memcpy(headers->content_type_text, text.data, text.length);
	headers->content_type_text[text.length] = '\0';
	headers->content_type_kind =
		PQCP_FLEET_COSE_CONTENT_TYPE_TEXT;
	return 0;
}

static int read_critical(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cose_headers *headers)
{
	size_t count;
	int ret = pqcp_fleet_cbor_read_array(reader, &count);

	if (ret != 0) {
		return ret;
	}
	if (count == 0U ||
	    count > PQCP_FLEET_COSE_MAX_CRITICAL_HEADERS) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	for (size_t index = 0U; index < count; ++index) {
		ret = pqcp_fleet_cbor_read_int(
			reader, &headers->critical[index]);
		if (ret != 0) {
			return ret;
		}
	}
	headers->critical_count = count;
	return 0;
}

static int decode_headers_map(
	struct pqcp_fleet_cbor_reader *reader,
	bool protected_bucket,
	struct pqcp_fleet_cose_headers *headers)
{
	struct pqcp_fleet_cbor_map_cursor cursor;
	struct pqcp_fleet_cbor_map_key key;
	struct pqcp_fleet_cbor_slice bytes;
	int64_t algorithm;
	int ret;

	if (reader == NULL || headers == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memset(headers, 0, sizeof(*headers));
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
		if (!key.integer) {
			return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		}
		switch (key.integer_value) {
		case PQCP_FLEET_COSE_HEADER_ALG:
			if (!protected_bucket) {
				return PQCP_FLEET_COSE_ERR_POLICY;
			}
			ret = pqcp_fleet_cbor_read_int(
				reader, &algorithm);
			if (ret == 0 &&
			    (algorithm < INT32_MIN ||
			     algorithm > INT32_MAX)) {
				ret =
					PQCP_FLEET_COSE_ERR_ENCODING;
			}
			if (ret == 0) {
				headers->algorithm =
					(int32_t)algorithm;
			}
			break;
		case PQCP_FLEET_COSE_HEADER_CRIT:
			if (!protected_bucket) {
				return PQCP_FLEET_COSE_ERR_POLICY;
			}
			ret = read_critical(reader, headers);
			break;
		case PQCP_FLEET_COSE_HEADER_CONTENT_TYPE:
			ret = read_content_type(reader, headers);
			break;
		case PQCP_FLEET_COSE_HEADER_KID:
			ret = pqcp_fleet_cbor_read_bytes(
				reader, &bytes);
			if (ret == 0 && bytes.length == 0U) {
				/* An empty kid decodes to "no kid", so the
				 * signed header bytes and the decoded view
				 * would disagree and verify() would fall back
				 * to the unprotected kid. Reject it.
				 */
				ret = PQCP_FLEET_COSE_ERR_ENCODING;
			}
			if (ret == 0) {
				ret = copy_slice(
					&bytes, headers->kid,
					sizeof(headers->kid),
					&headers->kid_length);
			}
			break;
		default:
			return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		}
		if (ret != 0) {
			return ret;
		}
	}
	return pqcp_fleet_cose_headers_validate(
		headers, protected_bucket);
}

int pqcp_fleet_cose_protected_decode(
	const uint8_t *encoded,
	size_t encoded_length,
	struct pqcp_fleet_cose_headers *headers)
{
	struct pqcp_fleet_cbor_reader reader;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    headers == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	ret = decode_headers_map(&reader, true, headers);
	if (ret == 0) {
		ret = pqcp_fleet_cbor_reader_finish(&reader);
	}
	if (ret != 0) {
		/* Never hand back partially decoded header fields. */
		memset(headers, 0, sizeof(*headers));
	}
	return ret;
}

static int headers_disjoint(
	const struct pqcp_fleet_cose_headers *protected_headers,
	const struct pqcp_fleet_cose_headers *unprotected_headers)
{
	if (unprotected_headers == NULL) {
		return 0;
	}
	if (protected_headers->kid_length != 0U &&
	    unprotected_headers->kid_length != 0U) {
		return PQCP_FLEET_COSE_ERR_DUPLICATE;
	}
	if (protected_headers->content_type_kind !=
		    PQCP_FLEET_COSE_CONTENT_TYPE_NONE &&
	    unprotected_headers->content_type_kind !=
		    PQCP_FLEET_COSE_CONTENT_TYPE_NONE) {
		return PQCP_FLEET_COSE_ERR_DUPLICATE;
	}
	return 0;
}

int pqcp_fleet_cose_sig_structure(
	const uint8_t *protected_serialized,
	size_t protected_length,
	const uint8_t *external_aad,
	size_t external_aad_length,
	const uint8_t *payload,
	size_t payload_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_fleet_cbor_writer writer;
	int ret;

	if (protected_serialized == NULL ||
	    protected_length == 0U ||
	    (external_aad == NULL &&
	     external_aad_length != 0U) ||
	    (payload == NULL && payload_length != 0U) ||
	    output == NULL || output_length == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	pqcp_fleet_cbor_writer_init(
		&writer, output, output_capacity);
	ret = pqcp_fleet_cbor_write_array(&writer, 4U);
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_text(
			&writer, COSE_SIGNATURE_CONTEXT,
			COSE_SIGNATURE_CONTEXT_BYTES);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_bytes(
			&writer, protected_serialized,
			protected_length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_bytes(
			&writer, external_aad,
			external_aad_length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_bytes(
			&writer, payload, payload_length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_writer_finish(
			&writer, output_length);
	}
	return ret;
}

static int encode_sign1_unprotected(
	const struct pqcp_fleet_cose_headers *headers,
	struct pqcp_fleet_cbor_writer *writer)
{
	struct pqcp_fleet_cose_headers empty;

	if (headers == NULL) {
		memset(&empty, 0, sizeof(empty));
		headers = &empty;
	}
	return encode_headers_map(headers, false, writer);
}

int pqcp_fleet_cose_sign1_encode(
	const struct pqcp_fleet_cose_sign1 *message,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_fleet_cbor_writer writer;
	int ret;

	if (message == NULL || output == NULL ||
	    output_length == NULL ||
	    message->protected_serialized.data == NULL ||
	    message->protected_serialized.length == 0U ||
	    message->signature.data == NULL ||
	    message->signature.length == 0U ||
	    (!message->detached_payload &&
	     message->payload.data == NULL &&
	     message->payload.length != 0U)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_headers_validate(
		&message->protected_headers, true);
	if (ret == 0) {
		ret = pqcp_fleet_cose_headers_validate(
			&message->unprotected_headers, false);
	}
	if (ret == 0) {
		ret = headers_disjoint(
			&message->protected_headers,
			&message->unprotected_headers);
	}
	if (ret != 0) {
		return ret;
	}
	if (message->signature.length !=
	    pqcp_fleet_cose_algorithm_signature_bytes(
		    message->protected_headers.algorithm)) {
		return PQCP_FLEET_COSE_ERR_SIGNATURE;
	}
	pqcp_fleet_cbor_writer_init(
		&writer, output, output_capacity);
	if (message->tagged) {
		ret = pqcp_fleet_cbor_write_tag(
			&writer, PQCP_FLEET_COSE_SIGN1_TAG);
	} else {
		ret = 0;
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_array(
			&writer, COSE_SIGN1_FIELDS);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_bytes(
			&writer,
			message->protected_serialized.data,
			message->protected_serialized.length);
	}
	if (ret == 0) {
		ret = encode_sign1_unprotected(
			&message->unprotected_headers, &writer);
	}
	if (ret == 0) {
		ret = message->detached_payload ?
			pqcp_fleet_cbor_write_null(&writer) :
			pqcp_fleet_cbor_write_bytes(
				&writer, message->payload.data,
				message->payload.length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_bytes(
			&writer, message->signature.data,
			message->signature.length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_writer_finish(
			&writer, output_length);
	}
	return ret;
}

static int decode_payload_or_null(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cose_sign1 *message)
{
	struct pqcp_fleet_cbor_reader probe = *reader;
	struct pqcp_fleet_cbor_head head;
	int ret = pqcp_fleet_cbor_read_head(&probe, &head);

	if (ret != 0) {
		return ret;
	}
	if (head.major == PQCP_FLEET_CBOR_SIMPLE &&
	    head.argument == PQCP_FLEET_CBOR_NULL) {
		ret = pqcp_fleet_cbor_read_null(reader);
		if (ret == 0) {
			message->detached_payload = true;
		}
		return ret;
	}
	if (head.major != PQCP_FLEET_CBOR_BYTES) {
		return PQCP_FLEET_COSE_ERR_ENCODING;
	}
	message->detached_payload = false;
	return pqcp_fleet_cbor_read_bytes(
		reader, &message->payload);
}

static int sign1_decode_fields(
	const uint8_t *encoded,
	size_t encoded_length,
	struct pqcp_fleet_cose_sign1 *message)
{
	struct pqcp_fleet_cbor_reader reader;
	struct pqcp_fleet_cbor_reader probe;
	struct pqcp_fleet_cbor_head head;
	struct pqcp_fleet_cbor_slice protected_bytes;
	size_t count;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    message == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memset(message, 0, sizeof(*message));
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	probe = reader;
	ret = pqcp_fleet_cbor_read_head(&probe, &head);
	if (ret != 0) {
		return ret;
	}
	if (head.major == PQCP_FLEET_CBOR_TAG) {
		if (head.argument !=
		    PQCP_FLEET_COSE_SIGN1_TAG) {
			return PQCP_FLEET_COSE_ERR_ENCODING;
		}
		ret = pqcp_fleet_cbor_read_tag(
			&reader, PQCP_FLEET_COSE_SIGN1_TAG);
		if (ret != 0) {
			return ret;
		}
		message->tagged = true;
	}
	ret = pqcp_fleet_cbor_read_array(&reader, &count);
	if (ret != 0 || count != COSE_SIGN1_FIELDS) {
		return ret != 0 ? ret :
			PQCP_FLEET_COSE_ERR_ENCODING;
	}
	ret = pqcp_fleet_cbor_read_bytes(
		&reader, &protected_bytes);
	if (ret != 0 || protected_bytes.length == 0U) {
		return ret != 0 ? ret :
			PQCP_FLEET_COSE_ERR_REQUIRED;
	}
	message->protected_serialized = protected_bytes;
	ret = pqcp_fleet_cose_protected_decode(
		protected_bytes.data, protected_bytes.length,
		&message->protected_headers);
	if (ret != 0) {
		return ret;
	}
	/*
	 * decode_headers_map() consumes the map head itself. The head is 1 to
	 * 9 bytes depending on the entry count, so never pre-read it and
	 * rewind by a fixed amount: that left the reader inside a multi-byte
	 * head and parsed its count bytes as the map, letting a token with a
	 * "map(161)" bucket decode as an empty bucket plus smuggled fields.
	 */
	ret = decode_headers_map(
		&reader, false,
		&message->unprotected_headers);
	if (ret != 0) {
		return ret;
	}
	ret = headers_disjoint(
		&message->protected_headers,
		&message->unprotected_headers);
	if (ret == 0) {
		ret = decode_payload_or_null(
			&reader, message);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_read_bytes(
			&reader, &message->signature);
	}
	if (ret == 0 &&
	    message->signature.length !=
		    pqcp_fleet_cose_algorithm_signature_bytes(
			    message->protected_headers.algorithm)) {
		ret = PQCP_FLEET_COSE_ERR_SIGNATURE;
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_reader_finish(&reader);
	}
	return ret;
}

int pqcp_fleet_cose_sign1_decode(
	const uint8_t *encoded,
	size_t encoded_length,
	struct pqcp_fleet_cose_sign1 *message)
{
	int ret = sign1_decode_fields(
		encoded, encoded_length, message);

	/* A rejected token must not leave a half-built message (protected
	 * slice, partly decoded headers) that a caller ignoring the status
	 * could mistake for decoded input.
	 */
	if (ret != 0 && message != NULL) {
		memset(message, 0, sizeof(*message));
	}
	return ret;
}

int pqcp_fleet_cose_sign1_sign(
	const struct pqcp_fleet_cose_headers *protected_headers,
	const struct pqcp_fleet_cose_headers *unprotected_headers,
	const uint8_t *payload,
	size_t payload_length,
	const uint8_t *external_aad,
	size_t external_aad_length,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t *workspace,
	size_t workspace_capacity,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_fleet_cose_sign1 message;
	size_t protected_length = 0U;
	size_t structure_length = 0U;
	size_t signature_length = 0U;
	size_t expected_signature;
	uint8_t *structure;
	uint8_t *signature;
	int ret;

	if (protected_headers == NULL ||
	    (payload == NULL && payload_length != 0U) ||
	    (external_aad == NULL &&
	     external_aad_length != 0U) ||
	    crypto == NULL || crypto->sign == NULL ||
	    workspace == NULL || output == NULL ||
	    output_length == NULL ||
	    workspace_capacity <
		    PQCP_FLEET_COSE_MAX_PROTECTED_BYTES) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = headers_disjoint(
		protected_headers, unprotected_headers);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_fleet_cose_protected_encode(
		protected_headers, workspace,
		PQCP_FLEET_COSE_MAX_PROTECTED_BYTES,
		&protected_length);
	if (ret != 0) {
		return ret;
	}
	structure = workspace + protected_length;
	if (protected_length > workspace_capacity) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	ret = pqcp_fleet_cose_sig_structure(
		workspace, protected_length,
		external_aad, external_aad_length,
		payload, payload_length, structure,
		workspace_capacity - protected_length,
		&structure_length);
	if (ret != 0) {
		return ret;
	}
	if (structure_length >
	    workspace_capacity - protected_length) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	signature = structure + structure_length;
	expected_signature =
		pqcp_fleet_cose_algorithm_signature_bytes(
			protected_headers->algorithm);
	if (expected_signature == 0U ||
	    expected_signature >
		    workspace_capacity -
			    protected_length -
			    structure_length) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	ret = crypto->sign(
		crypto->context, protected_headers->algorithm,
		protected_headers->kid,
		protected_headers->kid_length,
		structure, structure_length, signature,
		expected_signature, &signature_length);
	if (ret != 0) {
		return PQCP_FLEET_COSE_ERR_CRYPTO;
	}
	if (signature_length != expected_signature) {
		return PQCP_FLEET_COSE_ERR_SIGNATURE;
	}
	memset(&message, 0, sizeof(message));
	message.protected_headers = *protected_headers;
	if (unprotected_headers != NULL) {
		message.unprotected_headers =
			*unprotected_headers;
	}
	message.protected_serialized.data = workspace;
	message.protected_serialized.length =
		protected_length;
	message.payload.data = payload;
	message.payload.length = payload_length;
	message.signature.data = signature;
	message.signature.length = signature_length;
	message.tagged = protected_headers->tagged;
	ret = pqcp_fleet_cose_sign1_encode(
		&message, output, output_capacity,
		output_length);
	memset(signature, 0, signature_length);
	memset(structure, 0, structure_length);
	return ret;
}

int pqcp_fleet_cose_sign1_verify(
	const uint8_t *encoded,
	size_t encoded_length,
	const uint8_t *detached_payload,
	size_t detached_payload_length,
	const uint8_t *external_aad,
	size_t external_aad_length,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t *workspace,
	size_t workspace_capacity,
	struct pqcp_fleet_cose_sign1 *message)
{
	const uint8_t *payload;
	size_t payload_length;
	size_t structure_length = 0U;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    (detached_payload == NULL &&
	     detached_payload_length != 0U) ||
	    (external_aad == NULL &&
	     external_aad_length != 0U) ||
	    crypto == NULL || crypto->verify == NULL ||
	    workspace == NULL || message == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_sign1_decode(
		encoded, encoded_length, message);
	if (ret != 0) {
		return ret;
	}
	if (message->detached_payload) {
		if (detached_payload == NULL) {
			return PQCP_FLEET_COSE_ERR_REQUIRED;
		}
		payload = detached_payload;
		payload_length = detached_payload_length;
	} else {
		if (detached_payload_length != 0U) {
			return PQCP_FLEET_COSE_ERR_POLICY;
		}
		payload = message->payload.data;
		payload_length = message->payload.length;
	}
	ret = pqcp_fleet_cose_sig_structure(
		message->protected_serialized.data,
		message->protected_serialized.length,
		external_aad, external_aad_length,
		payload, payload_length, workspace,
		workspace_capacity, &structure_length);
	if (ret != 0) {
		return ret;
	}
	const uint8_t *kid =
		message->protected_headers.kid_length != 0U ?
			message->protected_headers.kid :
			message->unprotected_headers.kid;
	const size_t kid_length =
		message->protected_headers.kid_length != 0U ?
			message->protected_headers.kid_length :
			message->unprotected_headers.kid_length;

	ret = crypto->verify(
		crypto->context,
		message->protected_headers.algorithm,
		kid, kid_length, workspace, structure_length,
		message->signature.data,
		message->signature.length);
	memset(workspace, 0, structure_length);
	return ret == 0 ? 0 :
		PQCP_FLEET_COSE_ERR_SIGNATURE;
}
