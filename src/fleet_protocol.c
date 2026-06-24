/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Canonical fleet message encoding, signing, and verification.
 */

#include <errno.h>
#include <string.h>

#include "fleet_internal.h"

#define ENVELOPE_FIELDS 12U
#define TOP_LEVEL_FIELDS 2U

static bool text_valid(const char *text, size_t capacity)
{
	size_t length;

	if (text == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(text, capacity);
	if (length == 0U || length >= capacity) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		const uint8_t value = (uint8_t)text[index];

		if (value < 0x21U || value > 0x7eU) {
			return false;
		}
	}
	return true;
}

static bool bytes_nonzero(const uint8_t *value, size_t length)
{
	uint8_t combined = 0U;

	if (value == NULL || length == 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		combined |= value[index];
	}
	return combined != 0U;
}

static bool mlkem_mask_valid(uint32_t mask)
{
	const uint32_t known =
		PQCP_FLEET_MLKEM_512 |
		PQCP_FLEET_MLKEM_768 |
		PQCP_FLEET_MLKEM_1024;

	return mask != 0U && (mask & ~known) == 0U;
}

static bool mldsa_mask_valid(uint32_t mask)
{
	const uint32_t known =
		PQCP_FLEET_MLDSA_44 |
		PQCP_FLEET_MLDSA_65 |
		PQCP_FLEET_MLDSA_87;

	return mask != 0U && (mask & ~known) == 0U;
}

static bool capability_mask_valid(uint32_t mask)
{
	const uint32_t known =
		PQCP_FLEET_CAP_APPLICATION |
		PQCP_FLEET_CAP_POLICY_UPDATE |
		PQCP_FLEET_CAP_KEY_ROTATION |
		PQCP_FLEET_CAP_FIRMWARE_UPDATE |
		PQCP_FLEET_CAP_PROFILE_MIGRATION |
		PQCP_FLEET_CAP_RECOVERY |
		PQCP_FLEET_CAP_EMERGENCY_DOWNGRADE |
		PQCP_FLEET_CAP_DECOMMISSION;

	return mask != 0U && (mask & ~known) == 0U;
}

int pqcp_fleet_envelope_validate(
	const struct pqcp_fleet_envelope *envelope,
	enum pqcp_fleet_message_type type,
	uint64_t now_ms)
{
	if (envelope == NULL ||
	    envelope->schema_version != PQCP_FLEET_SCHEMA_VERSION ||
	    envelope->protocol_version != PQCP_FLEET_PROTOCOL_VERSION ||
	    envelope->type != type ||
	    type <= PQCP_FLEET_MESSAGE_NONE ||
	    type >= PQCP_FLEET_MESSAGE_TYPE_COUNT ||
	    envelope->message_id == 0U ||
	    envelope->sequence == 0U ||
	    envelope->issued_at_ms == 0U ||
	    envelope->expires_at_ms <= envelope->issued_at_ms ||
	    !bytes_nonzero(envelope->nonce, sizeof(envelope->nonce)) ||
	    !text_valid(envelope->device_id,
			sizeof(envelope->device_id)) ||
	    !text_valid(envelope->domain_id,
			sizeof(envelope->domain_id))) {
		return -EINVAL;
	}
	if (now_ms != 0U &&
	    (envelope->expires_at_ms <= now_ms ||
	     envelope->issued_at_ms > now_ms + UINT64_C(60000))) {
		return -ETIMEDOUT;
	}
	return 0;
}

int pqcp_fleet_public_key_fingerprint(
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint8_t fingerprint[PQCP_FLEET_DIGEST_BYTES])
{
	if (public_key == NULL || fingerprint == NULL ||
	    !bytes_nonzero(public_key, PQCP_FLEET_PUBLIC_KEY_BYTES)) {
		return -EINVAL;
	}
	return pqcp_fleet_sha256(
		public_key, PQCP_FLEET_PUBLIC_KEY_BYTES,
		fingerprint);
}

int pqcp_fleet_sign_buffer(
	const uint8_t *message,
	size_t message_length,
	const struct pqcp_fleet_signer *signer,
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES])
{
	size_t signature_length = 0U;
	int ret;

	if (message == NULL || message_length == 0U ||
	    signer == NULL || signer->sign == NULL ||
	    signature == NULL) {
		return -EINVAL;
	}
	ret = signer->sign(
		signer->context, message, message_length,
		(const uint8_t *)PQCP_FLEET_SIGNATURE_CONTEXT,
		PQCP_FLEET_SIGNATURE_CONTEXT_BYTES,
		signature, PQCP_FLEET_SIGNATURE_BYTES,
		&signature_length);
	if (ret != 0) {
		return ret;
	}
	return signature_length == PQCP_FLEET_SIGNATURE_BYTES ?
		       0 :
		       -EBADMSG;
}

int pqcp_fleet_verify_buffer(
	const uint8_t *message,
	size_t message_length,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	const uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES])
{
	if (message == NULL || message_length == 0U ||
	    public_key == NULL || signature == NULL) {
		return -EINVAL;
	}
	return pqcp_mldsa_verify(
		       PQCP_MLDSA_65, public_key,
		       message, message_length,
		       (const uint8_t *)PQCP_FLEET_SIGNATURE_CONTEXT,
		       PQCP_FLEET_SIGNATURE_CONTEXT_BYTES,
		       signature) == PQCP_MLDSA_SUCCESS ?
		       0 :
		       -EKEYREJECTED;
}

static int write_envelope(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	const struct pqcp_fleet_envelope *envelope)
{
	int ret = pqcp_fleet_legacy_cbor_write_array(
		writer, ENVELOPE_FIELDS);

	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			writer, envelope->schema_version);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			writer, envelope->protocol_version);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			writer, envelope->type);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			writer, envelope->message_id);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			writer, envelope->sequence);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			writer, envelope->policy_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			writer, envelope->revocation_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			writer, envelope->issued_at_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			writer, envelope->expires_at_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			writer, envelope->nonce,
			sizeof(envelope->nonce));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			writer, envelope->device_id,
			sizeof(envelope->device_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			writer, envelope->domain_id,
			sizeof(envelope->domain_id));
	}
	return ret;
}

static int read_u32(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	uint32_t *value)
{
	uint64_t decoded;
	int ret = pqcp_fleet_legacy_cbor_read_uint(reader, &decoded);

	if (ret != 0 || decoded > UINT32_MAX) {
		return -EBADMSG;
	}
	*value = (uint32_t)decoded;
	return 0;
}

static int read_envelope(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	struct pqcp_fleet_envelope *envelope)
{
	uint64_t value = 0U;
	size_t length;
	uint32_t decoded;
	int ret = pqcp_fleet_legacy_cbor_read_array(
		reader, ENVELOPE_FIELDS);

	memset(envelope, 0, sizeof(*envelope));
	if (ret == 0) {
		ret = read_u32(reader, &envelope->schema_version);
	}
	if (ret == 0) {
		ret = read_u32(reader, &envelope->protocol_version);
	}
	if (ret == 0) {
		ret = read_u32(reader, &decoded);
		envelope->type =
			(enum pqcp_fleet_message_type)decoded;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			reader, &envelope->message_id);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			reader, &envelope->sequence);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			reader, &envelope->policy_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			reader, &envelope->revocation_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			reader, &envelope->issued_at_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			reader, &envelope->expires_at_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_bytes(
			reader, envelope->nonce,
			sizeof(envelope->nonce), &length);
	}
	if (ret == 0 && length != sizeof(envelope->nonce)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			reader, envelope->device_id,
			sizeof(envelope->device_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			reader, envelope->domain_id,
			sizeof(envelope->domain_id));
	}
	(void)value;
	return ret;
}

static int begin_encode(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	uint8_t *output,
	size_t capacity,
	const struct pqcp_fleet_envelope *envelope,
	size_t payload_fields)
{
	int ret;

	if (output == NULL || capacity == 0U || envelope == NULL) {
		return -EINVAL;
	}
	pqcp_fleet_legacy_cbor_writer_init(writer, output, capacity);
	ret = pqcp_fleet_legacy_cbor_write_array(
		writer, TOP_LEVEL_FIELDS);
	if (ret == 0) {
		ret = write_envelope(writer, envelope);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_array(
			writer, payload_fields);
	}
	return ret;
}

static int begin_decode(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_envelope *envelope,
	size_t payload_fields)
{
	int ret;

	if (input == NULL || length == 0U || envelope == NULL) {
		return -EINVAL;
	}
	pqcp_fleet_legacy_cbor_reader_init(reader, input, length);
	ret = pqcp_fleet_legacy_cbor_read_array(
		reader, TOP_LEVEL_FIELDS);
	if (ret == 0) {
		ret = read_envelope(reader, envelope);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_array(
			reader, payload_fields);
	}
	return ret;
}

static int finish_encode(
	const struct pqcp_fleet_legacy_cbor_writer *writer,
	size_t *length)
{
	if (writer == NULL || length == NULL) {
		return -EINVAL;
	}
	if (writer->error != 0) {
		return writer->error;
	}
	*length = writer->offset;
	return 0;
}

static int write_signature(
	struct pqcp_fleet_legacy_cbor_writer *writer,
	const uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES])
{
	return pqcp_fleet_legacy_cbor_write_bytes(
		writer, signature, PQCP_FLEET_SIGNATURE_BYTES);
}

static int read_signature(
	struct pqcp_fleet_legacy_cbor_reader *reader,
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES])
{
	size_t length;
	int ret = pqcp_fleet_legacy_cbor_read_bytes(
		reader, signature,
		PQCP_FLEET_SIGNATURE_BYTES, &length);

	return ret == 0 && length == PQCP_FLEET_SIGNATURE_BYTES ?
		       0 :
		       -EBADMSG;
}

static int validate_enrollment(
	const struct pqcp_fleet_enrollment_request *message,
	uint64_t now_ms)
{
	uint8_t fingerprint[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (message == NULL ||
	    message->stage < PQCP_FLEET_ENROLLMENT_FACTORY ||
	    message->stage > PQCP_FLEET_ENROLLMENT_RECOVERY ||
	    message->boot_counter == 0U ||
	    message->enrollment_counter == 0U ||
	    !mlkem_mask_valid(message->supported_mlkem_mask) ||
	    !mldsa_mask_valid(message->supported_mldsa_mask) ||
	    !capability_mask_valid(message->requested_capabilities) ||
	    !text_valid(message->firmware_version,
			sizeof(message->firmware_version)) ||
	    !text_valid(message->product_class,
			sizeof(message->product_class)) ||
	    !bytes_nonzero(message->factory_public_key,
			sizeof(message->factory_public_key)) ||
	    !bytes_nonzero(message->hardware_id_digest,
			sizeof(message->hardware_id_digest))) {
		return -EINVAL;
	}
	ret = pqcp_fleet_envelope_validate(
		&message->envelope,
		PQCP_FLEET_MESSAGE_ENROLLMENT_REQUEST,
		now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_fleet_public_key_fingerprint(
		message->factory_public_key, fingerprint);
	if (ret != 0 ||
	    memcmp(fingerprint, message->factory_fingerprint,
		   sizeof(fingerprint)) != 0) {
		return -EKEYREJECTED;
	}
	if (message->operational_key_present !=
	    bytes_nonzero(message->operational_public_key,
			  sizeof(message->operational_public_key))) {
		return -EINVAL;
	}
	return 0;
}

static int encode_enrollment(
	const struct pqcp_fleet_enrollment_request *message,
	bool include_signature,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_legacy_cbor_writer writer;
	int ret = begin_encode(
		&writer, output, capacity, &message->envelope,
		include_signature ? 14U : 13U);

	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->stage);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->boot_counter);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->enrollment_counter);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->supported_mlkem_mask);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->supported_mldsa_mask);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->requested_capabilities);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->firmware_version,
			sizeof(message->firmware_version));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->product_class,
			sizeof(message->product_class));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->factory_public_key,
			sizeof(message->factory_public_key));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->factory_fingerprint,
			sizeof(message->factory_fingerprint));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->hardware_id_digest,
			sizeof(message->hardware_id_digest));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->operational_public_key,
			sizeof(message->operational_public_key));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bool(
			&writer, message->operational_key_present);
	}
	if (ret == 0 && include_signature) {
		ret = write_signature(
			&writer, message->signature);
	}
	return ret == 0 ? finish_encode(&writer, length) : ret;
}

int pqcp_fleet_enrollment_request_encode(
	const struct pqcp_fleet_enrollment_request *message,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (validate_enrollment(message, 0U) != 0) {
		return -EINVAL;
	}
	return encode_enrollment(
		message, true, output, capacity, length);
}

int pqcp_fleet_enrollment_request_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_enrollment_request *message)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	uint32_t decoded;
	size_t bytes;
	int ret;

	if (message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	ret = begin_decode(
		&reader, input, length, &message->envelope, 14U);
	if (ret == 0) {
		ret = read_u32(&reader, &decoded);
		message->stage =
			(enum pqcp_fleet_enrollment_stage)decoded;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->boot_counter);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->enrollment_counter);
	}
	if (ret == 0) {
		ret = read_u32(
			&reader, &message->supported_mlkem_mask);
	}
	if (ret == 0) {
		ret = read_u32(
			&reader, &message->supported_mldsa_mask);
	}
	if (ret == 0) {
		ret = read_u32(
			&reader, &message->requested_capabilities);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->firmware_version,
			sizeof(message->firmware_version));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->product_class,
			sizeof(message->product_class));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_bytes(
			&reader, message->factory_public_key,
			sizeof(message->factory_public_key), &bytes);
	}
	if (ret == 0 && bytes != sizeof(message->factory_public_key)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_bytes(
			&reader, message->factory_fingerprint,
			sizeof(message->factory_fingerprint), &bytes);
	}
	if (ret == 0 && bytes != sizeof(message->factory_fingerprint)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_bytes(
			&reader, message->hardware_id_digest,
			sizeof(message->hardware_id_digest), &bytes);
	}
	if (ret == 0 && bytes != sizeof(message->hardware_id_digest)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_bytes(
			&reader, message->operational_public_key,
			sizeof(message->operational_public_key), &bytes);
	}
	if (ret == 0 &&
	    bytes != sizeof(message->operational_public_key)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_bool(
			&reader, &message->operational_key_present);
	}
	if (ret == 0) {
		ret = read_signature(&reader, message->signature);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_finish(&reader);
	}
	return ret == 0 ? validate_enrollment(message, 0U) : ret;
}

int pqcp_fleet_enrollment_request_sign(
	struct pqcp_fleet_enrollment_request *message,
	const struct pqcp_fleet_signer *signer,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_enrollment(message, now_ms);

	if (ret == 0) {
		ret = encode_enrollment(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			encoded, length, signer,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_enrollment_request_verify(
	const struct pqcp_fleet_enrollment_request *message,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_enrollment(message, now_ms);

	if (ret == 0) {
		ret = encode_enrollment(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			encoded, length, public_key,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

static int validate_voucher(
	const struct pqcp_fleet_ownership_voucher *message,
	uint64_t now_ms)
{
	if (message == NULL ||
	    !bytes_nonzero(message->factory_fingerprint,
			sizeof(message->factory_fingerprint)) ||
	    !bytes_nonzero(message->operational_key_fingerprint,
			sizeof(message->operational_key_fingerprint)) ||
	    !bytes_nonzero(message->registrar_public_key,
			sizeof(message->registrar_public_key)) ||
	    !capability_mask_valid(message->granted_capabilities) ||
	    !text_valid(message->product_class,
			sizeof(message->product_class))) {
		return -EINVAL;
	}
	return pqcp_fleet_envelope_validate(
		&message->envelope,
		PQCP_FLEET_MESSAGE_OWNERSHIP_VOUCHER,
		now_ms);
}

static int encode_voucher(
	const struct pqcp_fleet_ownership_voucher *message,
	bool include_signature,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_legacy_cbor_writer writer;
	int ret = begin_encode(
		&writer, output, capacity, &message->envelope,
		include_signature ? 6U : 5U);

	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->factory_fingerprint,
			sizeof(message->factory_fingerprint));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->operational_key_fingerprint,
			sizeof(message->operational_key_fingerprint));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->registrar_public_key,
			sizeof(message->registrar_public_key));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->granted_capabilities);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->product_class,
			sizeof(message->product_class));
	}
	if (ret == 0 && include_signature) {
		ret = write_signature(&writer, message->signature);
	}
	return ret == 0 ? finish_encode(&writer, length) : ret;
}

int pqcp_fleet_voucher_encode(
	const struct pqcp_fleet_ownership_voucher *message,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (validate_voucher(message, 0U) != 0) {
		return -EINVAL;
	}
	return encode_voucher(
		message, true, output, capacity, length);
}

int pqcp_fleet_voucher_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_ownership_voucher *message)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	size_t bytes = 0U;
	int ret;

	if (message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	ret = begin_decode(
		&reader, input, length, &message->envelope, 6U);
#define READ_FIXED(member) \
	if (ret == 0) { \
		ret = pqcp_fleet_legacy_cbor_read_bytes( \
			&reader, message->member, \
			sizeof(message->member), &bytes); \
	} \
	if (ret == 0 && bytes != sizeof(message->member)) { \
		ret = -EBADMSG; \
	}
	READ_FIXED(factory_fingerprint);
	READ_FIXED(operational_key_fingerprint);
	READ_FIXED(registrar_public_key);
#undef READ_FIXED
	if (ret == 0) {
		ret = read_u32(
			&reader, &message->granted_capabilities);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->product_class,
			sizeof(message->product_class));
	}
	if (ret == 0) {
		ret = read_signature(&reader, message->signature);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_finish(&reader);
	}
	return ret == 0 ? validate_voucher(message, 0U) : ret;
}

int pqcp_fleet_voucher_sign(
	struct pqcp_fleet_ownership_voucher *message,
	const struct pqcp_fleet_signer *signer,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_voucher(message, now_ms);

	if (ret == 0) {
		ret = encode_voucher(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			encoded, length, signer,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_voucher_verify(
	const struct pqcp_fleet_ownership_voucher *message,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_voucher(message, now_ms);

	if (ret == 0) {
		ret = encode_voucher(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			encoded, length, public_key,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

static int validate_credential(
	const struct pqcp_fleet_credential *message,
	uint64_t now_ms)
{
	if (message == NULL ||
	    !text_valid(message->credential_id,
			sizeof(message->credential_id)) ||
	    !bytes_nonzero(message->subject_public_key,
			sizeof(message->subject_public_key)) ||
	    !mlkem_mask_valid(message->allowed_mlkem_mask) ||
	    !mldsa_mask_valid(message->allowed_mldsa_mask) ||
	    !capability_mask_valid(message->capabilities) ||
	    message->valid_from_ms == 0U ||
	    message->valid_until_ms <= message->valid_from_ms ||
	    message->issuance_epoch == 0U ||
	    !text_valid(message->product_class,
			sizeof(message->product_class))) {
		return -EINVAL;
	}
	if (now_ms != 0U &&
	    (now_ms < message->valid_from_ms ||
	     now_ms >= message->valid_until_ms)) {
		return -ETIMEDOUT;
	}
	return pqcp_fleet_envelope_validate(
		&message->envelope,
		PQCP_FLEET_MESSAGE_OPERATIONAL_CREDENTIAL,
		now_ms);
}

static int encode_credential(
	const struct pqcp_fleet_credential *message,
	bool include_signature,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_legacy_cbor_writer writer;
	int ret = begin_encode(
		&writer, output, capacity, &message->envelope,
		include_signature ? 10U : 9U);

	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->credential_id,
			sizeof(message->credential_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->subject_public_key,
			sizeof(message->subject_public_key));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->allowed_mlkem_mask);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->allowed_mldsa_mask);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->capabilities);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->valid_from_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->valid_until_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->issuance_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->product_class,
			sizeof(message->product_class));
	}
	if (ret == 0 && include_signature) {
		ret = write_signature(&writer, message->signature);
	}
	return ret == 0 ? finish_encode(&writer, length) : ret;
}

int pqcp_fleet_credential_encode(
	const struct pqcp_fleet_credential *message,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (validate_credential(message, 0U) != 0) {
		return -EINVAL;
	}
	return encode_credential(
		message, true, output, capacity, length);
}

int pqcp_fleet_credential_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_credential *message)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	size_t bytes;
	int ret;

	if (message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	ret = begin_decode(
		&reader, input, length, &message->envelope, 10U);
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->credential_id,
			sizeof(message->credential_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_bytes(
			&reader, message->subject_public_key,
			sizeof(message->subject_public_key), &bytes);
	}
	if (ret == 0 && bytes != sizeof(message->subject_public_key)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = read_u32(
			&reader, &message->allowed_mlkem_mask);
	}
	if (ret == 0) {
		ret = read_u32(
			&reader, &message->allowed_mldsa_mask);
	}
	if (ret == 0) {
		ret = read_u32(&reader, &message->capabilities);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->valid_from_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->valid_until_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->issuance_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->product_class,
			sizeof(message->product_class));
	}
	if (ret == 0) {
		ret = read_signature(&reader, message->signature);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_finish(&reader);
	}
	return ret == 0 ? validate_credential(message, 0U) : ret;
}

int pqcp_fleet_credential_sign(
	struct pqcp_fleet_credential *message,
	const struct pqcp_fleet_signer *signer,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_credential(message, now_ms);

	if (ret == 0) {
		ret = encode_credential(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			encoded, length, signer,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_credential_verify(
	const struct pqcp_fleet_credential *message,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_credential(message, now_ms);

	if (ret == 0) {
		ret = encode_credential(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			encoded, length, public_key,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

static bool policy_level_valid(uint32_t level, bool kem)
{
	if (kem) {
		return level == 512U || level == 768U ||
		       level == 1024U;
	}
	return level == 44U || level == 65U || level == 87U;
}

static int validate_policy(
	const struct pqcp_fleet_policy_bundle *message,
	uint64_t now_ms)
{
	const uint32_t known_flags =
		PQCP_FLEET_POLICY_HYBRID_REQUIRED |
		PQCP_FLEET_POLICY_FORBID_DOWNGRADE |
		PQCP_FLEET_POLICY_RECOVERY_ONLY |
		PQCP_FLEET_POLICY_LOCKDOWN;

	if (message == NULL ||
	    !mlkem_mask_valid(message->allowed_mlkem_mask) ||
	    !mldsa_mask_valid(message->allowed_mldsa_mask) ||
	    !policy_level_valid(message->preferred_mlkem_level, true) ||
	    !policy_level_valid(message->preferred_mldsa_level, false) ||
	    message->minimum_security_level == 0U ||
	    message->minimum_security_level > 5U ||
	    !capability_mask_valid(message->required_capabilities) ||
	    (message->flags & ~known_flags) != 0U ||
	    message->maximum_sessions == 0U ||
	    message->maximum_jobs == 0U ||
	    message->canary_percent > 100U ||
	    message->credential_lifetime_ms == 0U ||
	    message->rotation_window_ms == 0U ||
	    message->rotation_window_ms >=
		    message->credential_lifetime_ms ||
	    message->rekey_after_bytes == 0U ||
	    message->rekey_after_ms == 0U ||
	    !text_valid(message->preferred_profile,
			sizeof(message->preferred_profile))) {
		return -EINVAL;
	}
	return pqcp_fleet_envelope_validate(
		&message->envelope,
		PQCP_FLEET_MESSAGE_POLICY_BUNDLE,
		now_ms);
}

static int encode_policy(
	const struct pqcp_fleet_policy_bundle *message,
	bool include_signature,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_legacy_cbor_writer writer;
	int ret = begin_encode(
		&writer, output, capacity, &message->envelope,
		include_signature ? 16U : 15U);

#define WRITE_UINT(member) \
	if (ret == 0) { \
		ret = pqcp_fleet_legacy_cbor_write_uint( \
			&writer, message->member); \
	}
	WRITE_UINT(allowed_mlkem_mask);
	WRITE_UINT(allowed_mldsa_mask);
	WRITE_UINT(preferred_mlkem_level);
	WRITE_UINT(preferred_mldsa_level);
	WRITE_UINT(minimum_security_level);
	WRITE_UINT(required_capabilities);
	WRITE_UINT(flags);
	WRITE_UINT(maximum_sessions);
	WRITE_UINT(maximum_jobs);
	WRITE_UINT(canary_percent);
	WRITE_UINT(credential_lifetime_ms);
	WRITE_UINT(rotation_window_ms);
	WRITE_UINT(rekey_after_bytes);
	WRITE_UINT(rekey_after_ms);
#undef WRITE_UINT
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->preferred_profile,
			sizeof(message->preferred_profile));
	}
	if (ret == 0 && include_signature) {
		ret = write_signature(&writer, message->signature);
	}
	return ret == 0 ? finish_encode(&writer, length) : ret;
}

int pqcp_fleet_policy_encode(
	const struct pqcp_fleet_policy_bundle *message,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (validate_policy(message, 0U) != 0) {
		return -EINVAL;
	}
	return encode_policy(
		message, true, output, capacity, length);
}

int pqcp_fleet_policy_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_policy_bundle *message)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	int ret;

	if (message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	ret = begin_decode(
		&reader, input, length, &message->envelope, 16U);
#define READ_U32(member) \
	if (ret == 0) { \
		ret = read_u32(&reader, &message->member); \
	}
	READ_U32(allowed_mlkem_mask);
	READ_U32(allowed_mldsa_mask);
	READ_U32(preferred_mlkem_level);
	READ_U32(preferred_mldsa_level);
	READ_U32(minimum_security_level);
	READ_U32(required_capabilities);
	READ_U32(flags);
	READ_U32(maximum_sessions);
	READ_U32(maximum_jobs);
	READ_U32(canary_percent);
#undef READ_U32
#define READ_U64(member) \
	if (ret == 0) { \
		ret = pqcp_fleet_legacy_cbor_read_uint( \
			&reader, &message->member); \
	}
	READ_U64(credential_lifetime_ms);
	READ_U64(rotation_window_ms);
	READ_U64(rekey_after_bytes);
	READ_U64(rekey_after_ms);
#undef READ_U64
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->preferred_profile,
			sizeof(message->preferred_profile));
	}
	if (ret == 0) {
		ret = read_signature(&reader, message->signature);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_finish(&reader);
	}
	return ret == 0 ? validate_policy(message, 0U) : ret;
}

int pqcp_fleet_policy_sign(
	struct pqcp_fleet_policy_bundle *message,
	const struct pqcp_fleet_signer *signer,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_policy(message, now_ms);

	if (ret == 0) {
		ret = encode_policy(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			encoded, length, signer,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_policy_verify(
	const struct pqcp_fleet_policy_bundle *message,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_policy(message, now_ms);

	if (ret == 0) {
		ret = encode_policy(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			encoded, length, public_key,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

static int validate_revocation(
	const struct pqcp_fleet_revocation_update *message,
	uint64_t now_ms)
{
	if (message == NULL ||
	    message->entry_count == 0U ||
	    message->entry_count > PQCP_FLEET_MAX_REVOCATIONS ||
	    message->envelope.revocation_epoch == 0U ||
	    message->previous_epoch + 1U !=
		    message->envelope.revocation_epoch ||
	    message->next_refresh_ms <= message->envelope.issued_at_ms ||
	    message->offline_grace_ms == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < message->entry_count; ++index) {
		const struct pqcp_fleet_revocation_entry *entry =
			&message->entries[index];

		if (entry->kind < PQCP_FLEET_REVOKE_CREDENTIAL ||
		    entry->kind > PQCP_FLEET_REVOKE_DOMAIN ||
		    !text_valid(entry->subject_id,
				sizeof(entry->subject_id)) ||
		    entry->effective_at_ms == 0U) {
			return -EINVAL;
		}
	}
	return pqcp_fleet_envelope_validate(
		&message->envelope,
		PQCP_FLEET_MESSAGE_REVOCATION_UPDATE,
		now_ms);
}

static int encode_revocation(
	const struct pqcp_fleet_revocation_update *message,
	bool include_signature,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_legacy_cbor_writer writer;
	int ret = begin_encode(
		&writer, output, capacity, &message->envelope,
		include_signature ? 5U : 4U);

	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->previous_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->next_refresh_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->offline_grace_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_array(
			&writer, message->entry_count);
	}
	for (size_t index = 0U;
	     ret == 0 && index < message->entry_count;
	     ++index) {
		const struct pqcp_fleet_revocation_entry *entry =
			&message->entries[index];

		ret = pqcp_fleet_legacy_cbor_write_array(&writer, 4U);
		if (ret == 0) {
			ret = pqcp_fleet_legacy_cbor_write_uint(
				&writer, entry->kind);
		}
		if (ret == 0) {
			ret = pqcp_fleet_legacy_cbor_write_text(
				&writer, entry->subject_id,
				sizeof(entry->subject_id));
		}
		if (ret == 0) {
			ret = pqcp_fleet_legacy_cbor_write_uint(
				&writer, entry->effective_at_ms);
		}
		if (ret == 0) {
			ret = pqcp_fleet_legacy_cbor_write_uint(
				&writer, entry->reason);
		}
	}
	if (ret == 0 && include_signature) {
		ret = write_signature(&writer, message->signature);
	}
	return ret == 0 ? finish_encode(&writer, length) : ret;
}

int pqcp_fleet_revocation_encode(
	const struct pqcp_fleet_revocation_update *message,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (validate_revocation(message, 0U) != 0) {
		return -EINVAL;
	}
	return encode_revocation(
		message, true, output, capacity, length);
}

int pqcp_fleet_revocation_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_revocation_update *message)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	uint32_t value;
	uint64_t count;
	int ret;

	if (message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	ret = begin_decode(
		&reader, input, length, &message->envelope, 5U);
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->previous_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->next_refresh_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->offline_grace_ms);
	}
	if (ret == 0) {
		uint8_t head;

		if (reader.offset >= reader.length) {
			ret = -EBADMSG;
		} else {
			head = reader.buffer[reader.offset];
			if ((head >> 5) != 4U) {
				ret = -EBADMSG;
			} else {
				for (count = 0U;
				     count <= PQCP_FLEET_MAX_REVOCATIONS;
				     ++count) {
					struct pqcp_fleet_legacy_cbor_reader copy =
						reader;
					if (pqcp_fleet_legacy_cbor_read_array(
						    &copy, count) == 0) {
						reader = copy;
						break;
					}
				}
				if (count == 0U ||
				    count > PQCP_FLEET_MAX_REVOCATIONS) {
					ret = -EBADMSG;
				}
			}
		}
	}
	if (ret == 0) {
		message->entry_count = (uint32_t)count;
	}
	for (size_t index = 0U;
	     ret == 0 && index < message->entry_count;
	     ++index) {
		struct pqcp_fleet_revocation_entry *entry =
			&message->entries[index];

		ret = pqcp_fleet_legacy_cbor_read_array(&reader, 4U);
		if (ret == 0) {
			ret = read_u32(&reader, &value);
			entry->kind =
				(enum pqcp_fleet_revocation_kind)value;
		}
		if (ret == 0) {
			ret = pqcp_fleet_legacy_cbor_read_text(
				&reader, entry->subject_id,
				sizeof(entry->subject_id));
		}
		if (ret == 0) {
			ret = pqcp_fleet_legacy_cbor_read_uint(
				&reader, &entry->effective_at_ms);
		}
		if (ret == 0) {
			ret = read_u32(&reader, &entry->reason);
		}
	}
	if (ret == 0) {
		ret = read_signature(&reader, message->signature);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_finish(&reader);
	}
	return ret == 0 ? validate_revocation(message, 0U) : ret;
}

int pqcp_fleet_revocation_sign(
	struct pqcp_fleet_revocation_update *message,
	const struct pqcp_fleet_signer *signer,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_revocation(message, now_ms);

	if (ret == 0) {
		ret = encode_revocation(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			encoded, length, signer,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_revocation_verify(
	const struct pqcp_fleet_revocation_update *message,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_revocation(message, now_ms);

	if (ret == 0) {
		ret = encode_revocation(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			encoded, length, public_key,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

static int validate_update(
	const struct pqcp_fleet_update_manifest *message,
	uint64_t now_ms)
{
	const uint32_t known_flags =
		PQCP_FLEET_UPDATE_REQUIRE_DRAIN |
		PQCP_FLEET_UPDATE_REQUIRE_REBOOT |
		PQCP_FLEET_UPDATE_ALLOW_RECOVERY;

	if (message == NULL ||
	    !text_valid(message->component_id,
			sizeof(message->component_id)) ||
	    !text_valid(message->product_class,
			sizeof(message->product_class)) ||
	    message->version == 0U ||
	    message->minimum_current_version > message->version ||
	    message->image_size == 0U ||
	    !capability_mask_valid(message->required_capabilities) ||
	    (message->flags & ~known_flags) != 0U ||
	    !bytes_nonzero(message->image_digest,
			sizeof(message->image_digest))) {
		return -EINVAL;
	}
	return pqcp_fleet_envelope_validate(
		&message->envelope,
		PQCP_FLEET_MESSAGE_UPDATE_MANIFEST,
		now_ms);
}

static int encode_update(
	const struct pqcp_fleet_update_manifest *message,
	bool include_signature,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_legacy_cbor_writer writer;
	int ret = begin_encode(
		&writer, output, capacity, &message->envelope,
		include_signature ? 9U : 8U);

	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->component_id,
			sizeof(message->component_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->product_class,
			sizeof(message->product_class));
	}
#define WRITE_UPDATE_UINT(member) \
	if (ret == 0) { \
		ret = pqcp_fleet_legacy_cbor_write_uint( \
			&writer, message->member); \
	}
	WRITE_UPDATE_UINT(version);
	WRITE_UPDATE_UINT(minimum_current_version);
	WRITE_UPDATE_UINT(image_size);
	WRITE_UPDATE_UINT(required_capabilities);
	WRITE_UPDATE_UINT(flags);
#undef WRITE_UPDATE_UINT
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->image_digest,
			sizeof(message->image_digest));
	}
	if (ret == 0 && include_signature) {
		ret = write_signature(&writer, message->signature);
	}
	return ret == 0 ? finish_encode(&writer, length) : ret;
}

int pqcp_fleet_update_manifest_encode(
	const struct pqcp_fleet_update_manifest *message,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (validate_update(message, 0U) != 0) {
		return -EINVAL;
	}
	return encode_update(
		message, true, output, capacity, length);
}

int pqcp_fleet_update_manifest_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_update_manifest *message)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	size_t bytes;
	int ret;

	if (message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	ret = begin_decode(
		&reader, input, length, &message->envelope, 9U);
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->component_id,
			sizeof(message->component_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->product_class,
			sizeof(message->product_class));
	}
#define READ_UPDATE_U64(member) \
	if (ret == 0) { \
		ret = pqcp_fleet_legacy_cbor_read_uint( \
			&reader, &message->member); \
	}
	READ_UPDATE_U64(version);
	READ_UPDATE_U64(minimum_current_version);
	READ_UPDATE_U64(image_size);
#undef READ_UPDATE_U64
	if (ret == 0) {
		ret = read_u32(
			&reader, &message->required_capabilities);
	}
	if (ret == 0) {
		ret = read_u32(&reader, &message->flags);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_bytes(
			&reader, message->image_digest,
			sizeof(message->image_digest), &bytes);
	}
	if (ret == 0 && bytes != sizeof(message->image_digest)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = read_signature(&reader, message->signature);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_finish(&reader);
	}
	return ret == 0 ? validate_update(message, 0U) : ret;
}

int pqcp_fleet_update_manifest_sign(
	struct pqcp_fleet_update_manifest *message,
	const struct pqcp_fleet_signer *signer,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_update(message, now_ms);

	if (ret == 0) {
		ret = encode_update(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			encoded, length, signer,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_update_manifest_verify(
	const struct pqcp_fleet_update_manifest *message,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_update(message, now_ms);

	if (ret == 0) {
		ret = encode_update(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			encoded, length, public_key,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

static int validate_rotation_request(
	const struct pqcp_fleet_rotation_request *message,
	uint64_t now_ms)
{
	uint8_t fingerprint[PQCP_FLEET_DIGEST_BYTES];

	if (message == NULL ||
	    !text_valid(message->current_credential_id,
			sizeof(message->current_credential_id)) ||
	    !bytes_nonzero(message->current_key_fingerprint,
			sizeof(message->current_key_fingerprint)) ||
	    !bytes_nonzero(message->new_operational_public_key,
			sizeof(message->new_operational_public_key)) ||
	    message->requested_overlap_ms == 0U ||
	    pqcp_fleet_public_key_fingerprint(
		    message->new_operational_public_key,
		    fingerprint) != 0) {
		return -EINVAL;
	}
	return pqcp_fleet_envelope_validate(
		&message->envelope,
		PQCP_FLEET_MESSAGE_ROTATION_REQUEST,
		now_ms);
}

static int encode_rotation_request(
	const struct pqcp_fleet_rotation_request *message,
	bool include_signature,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_legacy_cbor_writer writer;
	int ret = begin_encode(
		&writer, output, capacity, &message->envelope,
		include_signature ? 5U : 4U);

	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->current_credential_id,
			sizeof(message->current_credential_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->current_key_fingerprint,
			sizeof(message->current_key_fingerprint));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->new_operational_public_key,
			sizeof(message->new_operational_public_key));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->requested_overlap_ms);
	}
	if (ret == 0 && include_signature) {
		ret = write_signature(&writer, message->signature);
	}
	return ret == 0 ? finish_encode(&writer, length) : ret;
}

int pqcp_fleet_rotation_request_encode(
	const struct pqcp_fleet_rotation_request *message,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (validate_rotation_request(message, 0U) != 0) {
		return -EINVAL;
	}
	return encode_rotation_request(
		message, true, output, capacity, length);
}

int pqcp_fleet_rotation_request_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_rotation_request *message)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	size_t bytes;
	int ret;

	if (message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	ret = begin_decode(
		&reader, input, length, &message->envelope, 5U);
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->current_credential_id,
			sizeof(message->current_credential_id));
	}
#define READ_ROTATION_FIXED(member) \
	if (ret == 0) { \
		ret = pqcp_fleet_legacy_cbor_read_bytes( \
			&reader, message->member, \
			sizeof(message->member), &bytes); \
	} \
	if (ret == 0 && bytes != sizeof(message->member)) { \
		ret = -EBADMSG; \
	}
	READ_ROTATION_FIXED(current_key_fingerprint);
	READ_ROTATION_FIXED(new_operational_public_key);
#undef READ_ROTATION_FIXED
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->requested_overlap_ms);
	}
	if (ret == 0) {
		ret = read_signature(&reader, message->signature);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_finish(&reader);
	}
	return ret == 0 ?
		validate_rotation_request(message, 0U) : ret;
}

int pqcp_fleet_rotation_request_sign(
	struct pqcp_fleet_rotation_request *message,
	const struct pqcp_fleet_signer *signer,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_rotation_request(message, now_ms);

	if (ret == 0) {
		ret = encode_rotation_request(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			encoded, length, signer,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_rotation_request_verify(
	const struct pqcp_fleet_rotation_request *message,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_rotation_request(message, now_ms);

	if (ret == 0) {
		ret = encode_rotation_request(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			encoded, length, public_key,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

static int validate_rotation_authorization(
	const struct pqcp_fleet_rotation_authorization *message,
	uint64_t now_ms)
{
	if (message == NULL ||
	    !text_valid(message->authorization_id,
			sizeof(message->authorization_id)) ||
	    !text_valid(message->replacement_credential_id,
			sizeof(message->replacement_credential_id)) ||
	    !bytes_nonzero(message->old_key_fingerprint,
			sizeof(message->old_key_fingerprint)) ||
	    !bytes_nonzero(message->new_key_fingerprint,
			sizeof(message->new_key_fingerprint)) ||
	    message->valid_from_ms == 0U ||
	    message->valid_until_ms <= message->valid_from_ms ||
	    message->overlap_until_ms < message->valid_from_ms ||
	    message->overlap_until_ms > message->valid_until_ms) {
		return -EINVAL;
	}
	return pqcp_fleet_envelope_validate(
		&message->envelope,
		PQCP_FLEET_MESSAGE_ROTATION_AUTHORIZATION,
		now_ms);
}

static int encode_rotation_authorization(
	const struct pqcp_fleet_rotation_authorization *message,
	bool include_signature,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_legacy_cbor_writer writer;
	int ret = begin_encode(
		&writer, output, capacity, &message->envelope,
		include_signature ? 8U : 7U);

	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->authorization_id,
			sizeof(message->authorization_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_text(
			&writer, message->replacement_credential_id,
			sizeof(message->replacement_credential_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->old_key_fingerprint,
			sizeof(message->old_key_fingerprint));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_bytes(
			&writer, message->new_key_fingerprint,
			sizeof(message->new_key_fingerprint));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->valid_from_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->valid_until_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->overlap_until_ms);
	}
	if (ret == 0 && include_signature) {
		ret = write_signature(&writer, message->signature);
	}
	return ret == 0 ? finish_encode(&writer, length) : ret;
}

int pqcp_fleet_rotation_authorization_encode(
	const struct pqcp_fleet_rotation_authorization *message,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (validate_rotation_authorization(message, 0U) != 0) {
		return -EINVAL;
	}
	return encode_rotation_authorization(
		message, true, output, capacity, length);
}

int pqcp_fleet_rotation_authorization_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_rotation_authorization *message)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	size_t bytes;
	int ret;

	if (message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	ret = begin_decode(
		&reader, input, length, &message->envelope, 8U);
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->authorization_id,
			sizeof(message->authorization_id));
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_text(
			&reader, message->replacement_credential_id,
			sizeof(message->replacement_credential_id));
	}
#define READ_AUTH_FIXED(member) \
	if (ret == 0) { \
		ret = pqcp_fleet_legacy_cbor_read_bytes( \
			&reader, message->member, \
			sizeof(message->member), &bytes); \
	} \
	if (ret == 0 && bytes != sizeof(message->member)) { \
		ret = -EBADMSG; \
	}
	READ_AUTH_FIXED(old_key_fingerprint);
	READ_AUTH_FIXED(new_key_fingerprint);
#undef READ_AUTH_FIXED
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->valid_from_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->valid_until_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->overlap_until_ms);
	}
	if (ret == 0) {
		ret = read_signature(&reader, message->signature);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_finish(&reader);
	}
	return ret == 0 ?
		validate_rotation_authorization(message, 0U) : ret;
}

int pqcp_fleet_rotation_authorization_sign(
	struct pqcp_fleet_rotation_authorization *message,
	const struct pqcp_fleet_signer *signer,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_rotation_authorization(message, now_ms);

	if (ret == 0) {
		ret = encode_rotation_authorization(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			encoded, length, signer,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_rotation_authorization_verify(
	const struct pqcp_fleet_rotation_authorization *message,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_rotation_authorization(message, now_ms);

	if (ret == 0) {
		ret = encode_rotation_authorization(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			encoded, length, public_key,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

static int validate_command_result(
	const struct pqcp_fleet_command_result *message,
	uint64_t now_ms)
{
	if (message == NULL ||
	    message->command_message_id == 0U ||
	    message->status > PQCP_FLEET_COMMAND_FAILED) {
		return -EINVAL;
	}
	return pqcp_fleet_envelope_validate(
		&message->envelope,
		PQCP_FLEET_MESSAGE_COMMAND_RESULT,
		now_ms);
}

static int encode_command_result(
	const struct pqcp_fleet_command_result *message,
	bool include_signature,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct pqcp_fleet_legacy_cbor_writer writer;
	int ret = begin_encode(
		&writer, output, capacity, &message->envelope,
		include_signature ? 8U : 7U);

	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->command_message_id);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->applied_policy_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->applied_revocation_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->device_state);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->status);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_int(
			&writer, message->result);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_write_uint(
			&writer, message->reason);
	}
	if (ret == 0 && include_signature) {
		ret = write_signature(&writer, message->signature);
	}
	return ret == 0 ? finish_encode(&writer, length) : ret;
}

int pqcp_fleet_command_result_encode(
	const struct pqcp_fleet_command_result *message,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (validate_command_result(message, 0U) != 0) {
		return -EINVAL;
	}
	return encode_command_result(
		message, true, output, capacity, length);
}

int pqcp_fleet_command_result_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_command_result *message)
{
	struct pqcp_fleet_legacy_cbor_reader reader;
	int64_t signed_value;
	uint32_t value;
	int ret;

	if (message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	ret = begin_decode(
		&reader, input, length, &message->envelope, 8U);
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->command_message_id);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->applied_policy_epoch);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_uint(
			&reader, &message->applied_revocation_epoch);
	}
	if (ret == 0) {
		ret = read_u32(&reader, &message->device_state);
	}
	if (ret == 0) {
		ret = read_u32(&reader, &value);
		message->status =
			(enum pqcp_fleet_command_status)value;
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_read_int(
			&reader, &signed_value);
	}
	if (ret == 0 &&
	    (signed_value < INT32_MIN || signed_value > INT32_MAX)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		message->result = (int32_t)signed_value;
		ret = read_u32(&reader, &message->reason);
	}
	if (ret == 0) {
		ret = read_signature(&reader, message->signature);
	}
	if (ret == 0) {
		ret = pqcp_fleet_legacy_cbor_finish(&reader);
	}
	return ret == 0 ?
		validate_command_result(message, 0U) : ret;
}

int pqcp_fleet_command_result_sign(
	struct pqcp_fleet_command_result *message,
	const struct pqcp_fleet_signer *signer,
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_command_result(message, now_ms);

	if (ret == 0) {
		ret = encode_command_result(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			encoded, length, signer,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_command_result_verify(
	const struct pqcp_fleet_command_result *message,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t encoded[PQCP_FLEET_MESSAGE_MAX_BYTES];
	size_t length = 0U;
	int ret = validate_command_result(message, now_ms);

	if (ret == 0) {
		ret = encode_command_result(
			message, false, encoded,
			sizeof(encoded), &length);
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			encoded, length, public_key,
			message->signature);
	}
	memset(encoded, 0, sizeof(encoded));
	return ret;
}

int pqcp_fleet_message_type_peek(
	const uint8_t *input,
	size_t length,
	enum pqcp_fleet_message_type *type)
{
	return pqcp_fleet_legacy_cbor_peek_envelope_type(
		input, length, type);
}

const char *pqcp_fleet_message_type_str(
	enum pqcp_fleet_message_type type)
{
	switch (type) {
	case PQCP_FLEET_MESSAGE_ENROLLMENT_REQUEST:
		return "enrollment-request";
	case PQCP_FLEET_MESSAGE_OWNERSHIP_VOUCHER:
		return "ownership-voucher";
	case PQCP_FLEET_MESSAGE_OPERATIONAL_CREDENTIAL:
		return "operational-credential";
	case PQCP_FLEET_MESSAGE_POLICY_BUNDLE:
		return "policy-bundle";
	case PQCP_FLEET_MESSAGE_REVOCATION_UPDATE:
		return "revocation-update";
	case PQCP_FLEET_MESSAGE_UPDATE_MANIFEST:
		return "update-manifest";
	case PQCP_FLEET_MESSAGE_ROTATION_REQUEST:
		return "rotation-request";
	case PQCP_FLEET_MESSAGE_ROTATION_AUTHORIZATION:
		return "rotation-authorization";
	case PQCP_FLEET_MESSAGE_COMMAND_RESULT:
		return "command-result";
	default:
		return "unknown";
	}
}
