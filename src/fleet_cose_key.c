/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * RFC 9964 Algorithm Key Pair (AKP) COSE_Key support.
 */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/fleet_cose.h>

static bool operation_supported(int32_t operation)
{
	return operation >= PQCP_FLEET_COSE_KEY_OP_SIGN &&
	       operation <= PQCP_FLEET_COSE_KEY_OP_MAC_VERIFY;
}

static bool operation_present(
	const struct pqcp_fleet_cose_key *key,
	int32_t operation)
{
	for (size_t index = 0U;
	     index < key->key_operation_count; ++index) {
		if (key->key_operations[index] == operation) {
			return true;
		}
	}
	return false;
}

static int validate_operations(
	const struct pqcp_fleet_cose_key *key)
{
	for (size_t index = 0U;
	     index < key->key_operation_count; ++index) {
		const int32_t operation =
			key->key_operations[index];

		if (!operation_supported(operation)) {
			return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		}
		for (size_t previous = 0U;
		     previous < index; ++previous) {
			if (key->key_operations[previous] ==
			    operation) {
				return PQCP_FLEET_COSE_ERR_DUPLICATE;
			}
		}
	}
	if (key->private_seed_length == 0U &&
	    operation_present(
		    key, PQCP_FLEET_COSE_KEY_OP_SIGN)) {
		return PQCP_FLEET_COSE_ERR_POLICY;
	}
	if (operation_present(
		    key, PQCP_FLEET_COSE_KEY_OP_ENCRYPT) ||
	    operation_present(
		    key, PQCP_FLEET_COSE_KEY_OP_DECRYPT) ||
	    operation_present(
		    key, PQCP_FLEET_COSE_KEY_OP_WRAP) ||
	    operation_present(
		    key, PQCP_FLEET_COSE_KEY_OP_UNWRAP) ||
	    operation_present(
		    key, PQCP_FLEET_COSE_KEY_OP_DERIVE_KEY) ||
	    operation_present(
		    key, PQCP_FLEET_COSE_KEY_OP_DERIVE_BITS) ||
	    operation_present(
		    key, PQCP_FLEET_COSE_KEY_OP_MAC_CREATE) ||
	    operation_present(
		    key, PQCP_FLEET_COSE_KEY_OP_MAC_VERIFY)) {
		return PQCP_FLEET_COSE_ERR_POLICY;
	}
	return 0;
}

int pqcp_fleet_cose_key_matches_algorithm(
	const struct pqcp_fleet_cose_key *key,
	int32_t algorithm)
{
	const size_t public_bytes =
		pqcp_fleet_cose_algorithm_public_key_bytes(
			algorithm);

	if (key == NULL || public_bytes == 0U ||
	    key->key_type != PQCP_FLEET_COSE_KTY_AKP ||
	    key->algorithm != algorithm ||
	    key->public_key_length != public_bytes) {
		return PQCP_FLEET_COSE_ERR_KEY;
	}
	return 0;
}

int pqcp_fleet_cose_key_validate(
	const struct pqcp_fleet_cose_key *key,
	bool allow_private)
{
	int ret;

	if (key == NULL ||
	    key->key_type != PQCP_FLEET_COSE_KTY_AKP ||
	    key->kid_length > sizeof(key->kid) ||
	    key->public_key_length >
		    sizeof(key->public_key) ||
	    key->private_seed_length >
		    sizeof(key->private_seed) ||
	    key->key_operation_count >
		    PQCP_FLEET_COSE_MAX_KEY_OPERATIONS ||
	    key->base_iv_length > sizeof(key->base_iv)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_key_matches_algorithm(
		key, key->algorithm);
	if (ret != 0) {
		return ret;
	}
	if (key->private_seed_length != 0U &&
	    key->private_seed_length !=
		    PQCP_FLEET_COSE_ML_DSA_PRIVATE_SEED_BYTES) {
		return PQCP_FLEET_COSE_ERR_KEY;
	}
	if (!allow_private && key->private_seed_length != 0U) {
		return PQCP_FLEET_COSE_ERR_POLICY;
	}
	if (key->base_iv_length != 0U) {
		return PQCP_FLEET_COSE_ERR_POLICY;
	}
	ret = validate_operations(key);
	if (ret != 0) {
		return ret;
	}
	return 0;
}

static size_t encoded_fields(
	const struct pqcp_fleet_cose_key *key,
	bool include_private)
{
	size_t fields = 3U;

	if (key->kid_length != 0U) {
		fields++;
	}
	if (key->key_operation_count != 0U) {
		fields++;
	}
	if (key->base_iv_length != 0U) {
		fields++;
	}
	if (include_private &&
	    key->private_seed_length != 0U) {
		fields++;
	}
	return fields;
}

static int write_operations(
	struct pqcp_fleet_cbor_writer *writer,
	const struct pqcp_fleet_cose_key *key)
{
	int ret = pqcp_fleet_cbor_write_array(
		writer, key->key_operation_count);

	for (size_t index = 0U;
	     ret == 0 &&
	     index < key->key_operation_count; ++index) {
		ret = pqcp_fleet_cbor_write_int(
			writer, key->key_operations[index]);
	}
	return ret;
}

int pqcp_fleet_cose_key_encode(
	const struct pqcp_fleet_cose_key *key,
	bool include_private,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_fleet_cbor_writer writer;
	int ret;

	if (output == NULL || output_length == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_key_validate(
		key, include_private);
	if (ret != 0) {
		return ret;
	}
	if (include_private &&
	    key->private_seed_length == 0U) {
		return PQCP_FLEET_COSE_ERR_REQUIRED;
	}
	pqcp_fleet_cbor_writer_init(
		&writer, output, output_capacity);
	if (key->tagged) {
		ret = pqcp_fleet_cbor_write_tag(
			&writer, PQCP_FLEET_COSE_KEY_TAG);
	} else {
		ret = 0;
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_map(
			&writer,
			encoded_fields(key, include_private));
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_KTY);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, key->key_type);
	}
	if (ret == 0 && key->kid_length != 0U) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_KID);
		if (ret == 0) {
			ret = pqcp_fleet_cbor_write_bytes(
				&writer, key->kid,
				key->kid_length);
		}
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_ALG);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, key->algorithm);
	}
	if (ret == 0 &&
	    key->key_operation_count != 0U) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_OPS);
		if (ret == 0) {
			ret = write_operations(&writer, key);
		}
	}
	if (ret == 0 && key->base_iv_length != 0U) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_BASE_IV);
		if (ret == 0) {
			ret = pqcp_fleet_cbor_write_bytes(
				&writer, key->base_iv,
				key->base_iv_length);
		}
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_AKP_PUBLIC);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_bytes(
			&writer, key->public_key,
			key->public_key_length);
	}
	if (ret == 0 && include_private) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_AKP_PRIVATE);
		if (ret == 0) {
			ret = pqcp_fleet_cbor_write_bytes(
				&writer, key->private_seed,
				key->private_seed_length);
		}
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_writer_finish(
			&writer, output_length);
	}
	return ret;
}

static int copy_bytes(
	const struct pqcp_fleet_cbor_slice *slice,
	uint8_t *output,
	size_t capacity,
	size_t *output_length)
{
	if (slice == NULL || output == NULL ||
	    output_length == NULL ||
	    slice->length > capacity) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	if (slice->length != 0U) {
		memcpy(output, slice->data, slice->length);
	}
	*output_length = slice->length;
	return 0;
}

static int read_int32(
	struct pqcp_fleet_cbor_reader *reader,
	int32_t *output)
{
	int64_t value;
	int ret;

	if (output == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cbor_read_int(reader, &value);
	if (ret == 0 &&
	    (value < INT32_MIN || value > INT32_MAX)) {
		ret = PQCP_FLEET_COSE_ERR_ENCODING;
	}
	if (ret == 0) {
		*output = (int32_t)value;
	}
	return ret;
}

static int read_operations(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_cose_key *key)
{
	size_t count;
	int ret = pqcp_fleet_cbor_read_array(reader, &count);

	if (ret != 0) {
		return ret;
	}
	if (count == 0U ||
	    count > PQCP_FLEET_COSE_MAX_KEY_OPERATIONS) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	for (size_t index = 0U; index < count; ++index) {
		ret = read_int32(
			reader, &key->key_operations[index]);
		if (ret != 0) {
			return ret;
		}
	}
	key->key_operation_count = count;
	return 0;
}

static int decode_key_map(
	struct pqcp_fleet_cbor_reader *reader,
	bool allow_private,
	struct pqcp_fleet_cose_key *key)
{
	struct pqcp_fleet_cbor_map_cursor cursor;
	struct pqcp_fleet_cbor_map_key map_key;
	struct pqcp_fleet_cbor_slice bytes;
	bool have_kty = false;
	bool have_alg = false;
	bool have_public = false;
	int ret;

	ret = pqcp_fleet_cbor_read_map(reader, &cursor);
	if (ret != 0) {
		return ret;
	}
	while (cursor.remaining != 0U) {
		ret = pqcp_fleet_cbor_map_next(
			reader, &cursor, &map_key);
		if (ret != 0) {
			return ret;
		}
		if (!map_key.integer) {
			return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		}
		switch (map_key.integer_value) {
		case PQCP_FLEET_COSE_KEY_KTY:
			ret = read_int32(
				reader, &key->key_type);
			have_kty = ret == 0;
			break;
		case PQCP_FLEET_COSE_KEY_KID:
			ret = pqcp_fleet_cbor_read_bytes(
				reader, &bytes);
			if (ret == 0) {
				ret = copy_bytes(
					&bytes, key->kid,
					sizeof(key->kid),
					&key->kid_length);
			}
			break;
		case PQCP_FLEET_COSE_KEY_ALG:
			ret = read_int32(
				reader, &key->algorithm);
			have_alg = ret == 0;
			break;
		case PQCP_FLEET_COSE_KEY_OPS:
			ret = read_operations(reader, key);
			break;
		case PQCP_FLEET_COSE_KEY_BASE_IV:
			ret = pqcp_fleet_cbor_read_bytes(
				reader, &bytes);
			if (ret == 0) {
				ret = copy_bytes(
					&bytes, key->base_iv,
					sizeof(key->base_iv),
					&key->base_iv_length);
			}
			break;
		case PQCP_FLEET_COSE_KEY_AKP_PUBLIC:
			ret = pqcp_fleet_cbor_read_bytes(
				reader, &bytes);
			if (ret == 0) {
				ret = copy_bytes(
					&bytes, key->public_key,
					sizeof(key->public_key),
					&key->public_key_length);
			}
			have_public = ret == 0;
			break;
		case PQCP_FLEET_COSE_KEY_AKP_PRIVATE:
			if (!allow_private) {
				return PQCP_FLEET_COSE_ERR_POLICY;
			}
			ret = pqcp_fleet_cbor_read_bytes(
				reader, &bytes);
			if (ret == 0) {
				ret = copy_bytes(
					&bytes, key->private_seed,
					sizeof(key->private_seed),
					&key->private_seed_length);
			}
			break;
		default:
			return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		}
		if (ret != 0) {
			return ret;
		}
	}
	if (!have_kty || !have_alg || !have_public) {
		return PQCP_FLEET_COSE_ERR_REQUIRED;
	}
	return 0;
}

int pqcp_fleet_cose_key_decode(
	const uint8_t *encoded,
	size_t encoded_length,
	bool allow_private,
	struct pqcp_fleet_cose_key *key)
{
	struct pqcp_fleet_cbor_reader reader;
	struct pqcp_fleet_cbor_reader probe;
	struct pqcp_fleet_cbor_head head;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    key == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memset(key, 0, sizeof(*key));
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	probe = reader;
	ret = pqcp_fleet_cbor_read_head(&probe, &head);
	if (ret != 0) {
		return ret;
	}
	if (head.major == PQCP_FLEET_CBOR_TAG) {
		if (head.argument != PQCP_FLEET_COSE_KEY_TAG) {
			return PQCP_FLEET_COSE_ERR_ENCODING;
		}
		ret = pqcp_fleet_cbor_read_tag(
			&reader, PQCP_FLEET_COSE_KEY_TAG);
		if (ret != 0) {
			return ret;
		}
		key->tagged = true;
	}
	ret = decode_key_map(&reader, allow_private, key);
	if (ret == 0) {
		ret = pqcp_fleet_cbor_reader_finish(&reader);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cose_key_validate(
			key, allow_private);
	}
	if (ret != 0) {
		memset(key, 0, sizeof(*key));
	}
	return ret;
}

int pqcp_fleet_cose_key_thumbprint_input(
	const struct pqcp_fleet_cose_key *key,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_fleet_cbor_writer writer;
	int ret;

	if (output == NULL || output_length == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_key_validate(key, true);
	if (ret != 0) {
		return ret;
	}
	pqcp_fleet_cbor_writer_init(
		&writer, output, output_capacity);
	ret = pqcp_fleet_cbor_write_map(&writer, 3U);
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_KTY);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, key->key_type);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_ALG);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, key->algorithm);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(
			&writer, PQCP_FLEET_COSE_KEY_AKP_PUBLIC);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_bytes(
			&writer, key->public_key,
			key->public_key_length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_writer_finish(
			&writer, output_length);
	}
	return ret;
}

int pqcp_fleet_cose_key_thumbprint(
	const struct pqcp_fleet_cose_key *key,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t output[PQCP_FLEET_COSE_THUMBPRINT_BYTES])
{
	uint8_t encoded[
		PQCP_FLEET_COSE_MAX_PUBLIC_KEY_BYTES + 64U];
	size_t encoded_length = 0U;
	size_t digest_length = 0U;
	int ret;

	if (crypto == NULL || crypto->hash == NULL ||
	    output == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_key_thumbprint_input(
		key, encoded, sizeof(encoded), &encoded_length);
	if (ret == 0) {
		ret = crypto->hash(
			crypto->context, encoded, encoded_length,
			output, PQCP_FLEET_COSE_THUMBPRINT_BYTES,
			&digest_length);
		if (ret != 0) {
			ret = PQCP_FLEET_COSE_ERR_CRYPTO;
		}
	}
	memset(encoded, 0, sizeof(encoded));
	if (ret == 0 &&
	    digest_length !=
		    PQCP_FLEET_COSE_THUMBPRINT_BYTES) {
		memset(
			output, 0,
			PQCP_FLEET_COSE_THUMBPRINT_BYTES);
		ret = PQCP_FLEET_COSE_ERR_CRYPTO;
	}
	return ret;
}
