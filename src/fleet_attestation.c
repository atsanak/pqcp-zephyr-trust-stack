/*
 * SPDX-License-Identifier: MIT
 *
 * Signed, nonce-bound device posture attestations.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_operations.h>

#include "fleet_internal.h"
#include "runtime_internal.h"

#define FLEET_ATTESTATION_MAGIC UINT32_C(0x50464131)
#define FLEET_ATTESTATION_HEADER_BYTES 8U
#define FLEET_ATTESTATION_CLAIMS_MAX_BYTES 512U

struct attestation_writer {
	uint8_t *output;
	size_t capacity;
	size_t offset;
	int error;
};

struct attestation_reader {
	const uint8_t *input;
	size_t length;
	size_t offset;
	int error;
};

static bool all_zero(const uint8_t *value, size_t length)
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate == 0U;
}

static void writer_bytes(
	struct attestation_writer *writer,
	const uint8_t *value,
	size_t length)
{
	if (writer->error != 0) {
		return;
	}
	if ((value == NULL && length != 0U) ||
	    length > writer->capacity - writer->offset) {
		writer->error = -ENOSPC;
		return;
	}
	if (length != 0U) {
		memcpy(writer->output + writer->offset,
		       value, length);
		writer->offset += length;
	}
}

static void writer_u16(
	struct attestation_writer *writer,
	uint16_t value)
{
	uint8_t encoded[2];

	pqcp_runtime_internal_write_u16(encoded, value);
	writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_u32(
	struct attestation_writer *writer,
	uint32_t value)
{
	uint8_t encoded[4];

	pqcp_runtime_internal_write_u32(encoded, value);
	writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_u64(
	struct attestation_writer *writer,
	uint64_t value)
{
	uint8_t encoded[8];

	pqcp_runtime_internal_write_u64(encoded, value);
	writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_text(
	struct attestation_writer *writer,
	const char *value,
	size_t maximum)
{
	const size_t length = value != NULL ?
		strnlen(value, maximum) : maximum;

	if (value == NULL || length == 0U ||
	    length >= maximum || length > UINT16_MAX) {
		writer->error = -EINVAL;
		return;
	}
	writer_u16(writer, (uint16_t)length);
	writer_bytes(writer, (const uint8_t *)value, length);
}

static int claims_encode(
	const struct pqcp_fleet_attestation_claims *claims,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct attestation_writer writer = {
		.output = output,
		.capacity = capacity,
	};

	if (claims == NULL || output == NULL || length == NULL ||
	    claims->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    !pqcp_runtime_internal_text_valid(
		    claims->device_id,
		    sizeof(claims->device_id)) ||
	    !pqcp_runtime_internal_text_valid(
		    claims->product_class,
		    sizeof(claims->product_class)) ||
	    !pqcp_runtime_internal_text_valid(
		    claims->firmware_version,
		    sizeof(claims->firmware_version)) ||
	    claims->device_state >
		    PQCP_FLEET_DEVICE_DECOMMISSIONED ||
	    claims->boot_counter == 0U ||
	    claims->issued_at_ms == 0U ||
	    claims->expires_at_ms <= claims->issued_at_ms ||
	    claims->risk_score > 1000U ||
	    claims->security_level > 5U ||
	    all_zero(claims->hardware_id_digest,
		     sizeof(claims->hardware_id_digest)) ||
	    all_zero(claims->nonce, sizeof(claims->nonce))) {
		return -EINVAL;
	}
	writer_u32(&writer, FLEET_ATTESTATION_MAGIC);
	writer_u32(&writer, claims->schema_version);
	writer_text(
		&writer, claims->device_id,
		sizeof(claims->device_id));
	writer_text(
		&writer, claims->product_class,
		sizeof(claims->product_class));
	writer_text(
		&writer, claims->firmware_version,
		sizeof(claims->firmware_version));
	writer_u32(
		&writer, (uint32_t)claims->device_state);
	writer_u64(&writer, claims->boot_counter);
	writer_u64(
		&writer, claims->firmware_version_number);
	writer_u64(&writer, claims->policy_epoch);
	writer_u64(&writer, claims->revocation_epoch);
	writer_u64(
		&writer, claims->credential_issuance_epoch);
	writer_u64(&writer, claims->audit_sequence);
	writer_u32(&writer, claims->capabilities);
	writer_u32(&writer, claims->risk_score);
	writer_u32(&writer, claims->security_level);
	writer_bytes(
		&writer, claims->hardware_id_digest,
		sizeof(claims->hardware_id_digest));
	writer_bytes(
		&writer, claims->audit_chain_head,
		sizeof(claims->audit_chain_head));
	writer_bytes(
		&writer, claims->nonce, sizeof(claims->nonce));
	writer_u64(&writer, claims->issued_at_ms);
	writer_u64(&writer, claims->expires_at_ms);
	if (writer.error != 0) {
		return writer.error;
	}
	*length = writer.offset;
	return 0;
}

static void reader_bytes(
	struct attestation_reader *reader,
	uint8_t *value,
	size_t length)
{
	if (reader->error != 0) {
		return;
	}
	if (value == NULL ||
	    length > reader->length - reader->offset) {
		reader->error = -EBADMSG;
		return;
	}
	memcpy(value, reader->input + reader->offset, length);
	reader->offset += length;
}

static uint16_t reader_u16(
	struct attestation_reader *reader)
{
	uint8_t encoded[2] = { 0 };

	reader_bytes(reader, encoded, sizeof(encoded));
	return reader->error == 0 ?
		pqcp_runtime_internal_read_u16(encoded) : 0U;
}

static uint32_t reader_u32(
	struct attestation_reader *reader)
{
	uint8_t encoded[4] = { 0 };

	reader_bytes(reader, encoded, sizeof(encoded));
	return reader->error == 0 ?
		pqcp_runtime_internal_read_u32(encoded) : 0U;
}

static uint64_t reader_u64(
	struct attestation_reader *reader)
{
	uint8_t encoded[8] = { 0 };

	reader_bytes(reader, encoded, sizeof(encoded));
	return reader->error == 0 ?
		pqcp_runtime_internal_read_u64(encoded) : 0U;
}

static void reader_text(
	struct attestation_reader *reader,
	char *value,
	size_t capacity)
{
	const uint16_t length = reader_u16(reader);

	if (reader->error != 0) {
		return;
	}
	if (length == 0U || length >= capacity ||
	    length > reader->length - reader->offset) {
		reader->error = -EBADMSG;
		return;
	}
	memcpy(value, reader->input + reader->offset, length);
	value[length] = '\0';
	reader->offset += length;
}

static int claims_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_attestation_claims *claims,
	size_t *consumed)
{
	struct attestation_reader reader = {
		.input = input,
		.length = length,
	};
	uint32_t magic;

	if (input == NULL || claims == NULL || consumed == NULL) {
		return -EINVAL;
	}
	memset(claims, 0, sizeof(*claims));
	magic = reader_u32(&reader);
	claims->schema_version = reader_u32(&reader);
	reader_text(
		&reader, claims->device_id,
		sizeof(claims->device_id));
	reader_text(
		&reader, claims->product_class,
		sizeof(claims->product_class));
	reader_text(
		&reader, claims->firmware_version,
		sizeof(claims->firmware_version));
	claims->device_state =
		(enum pqcp_fleet_device_state)reader_u32(&reader);
	claims->boot_counter = reader_u64(&reader);
	claims->firmware_version_number =
		reader_u64(&reader);
	claims->policy_epoch = reader_u64(&reader);
	claims->revocation_epoch = reader_u64(&reader);
	claims->credential_issuance_epoch =
		reader_u64(&reader);
	claims->audit_sequence = reader_u64(&reader);
	claims->capabilities = reader_u32(&reader);
	claims->risk_score = reader_u32(&reader);
	claims->security_level = reader_u32(&reader);
	reader_bytes(
		&reader, claims->hardware_id_digest,
		sizeof(claims->hardware_id_digest));
	reader_bytes(
		&reader, claims->audit_chain_head,
		sizeof(claims->audit_chain_head));
	reader_bytes(
		&reader, claims->nonce, sizeof(claims->nonce));
	claims->issued_at_ms = reader_u64(&reader);
	claims->expires_at_ms = reader_u64(&reader);
	if (reader.error != 0 || magic != FLEET_ATTESTATION_MAGIC) {
		pqcp_runtime_secure_zero(claims, sizeof(*claims));
		return reader.error != 0 ?
			reader.error : -EBADMSG;
	}
	uint8_t canonical[FLEET_ATTESTATION_CLAIMS_MAX_BYTES];
	size_t canonical_length = 0U;
	int ret = claims_encode(
		claims, canonical, sizeof(canonical),
		&canonical_length);

	if (ret == 0 &&
	    (canonical_length != reader.offset ||
	     memcmp(canonical, input, canonical_length) != 0)) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(
		canonical, sizeof(canonical));
	if (ret != 0) {
		pqcp_runtime_secure_zero(claims, sizeof(*claims));
		return ret;
	}
	*consumed = reader.offset;
	return 0;
}

static int claims_digest(
	const struct pqcp_fleet_attestation_claims *claims,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[FLEET_ATTESTATION_CLAIMS_MAX_BYTES];
	size_t length = 0U;
	int ret = claims_encode(
		claims, encoded, sizeof(encoded), &length);

	if (ret == 0) {
		ret = pqcp_runtime_internal_sha256(
			encoded, length, digest);
	}
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

int pqcp_fleet_attestation_collect(
	const struct pqcp_fleet_device *device,
	const struct pqcp_fleet_audit_ledger *ledger,
	uint32_t risk_score,
	uint32_t security_level,
	const uint8_t nonce[PQCP_FLEET_NONCE_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_fleet_attestation *attestation)
{
	struct pqcp_fleet_attestation_claims *claims;
	int ret;

	if (device == NULL || !device->initialized ||
	    ledger == NULL || !ledger->initialized ||
	    nonce == NULL || all_zero(nonce, PQCP_FLEET_NONCE_BYTES) ||
	    risk_score > 1000U || security_level > 5U ||
	    now_ms == 0U || expires_at_ms <= now_ms ||
	    attestation == NULL) {
		return -EINVAL;
	}
	memset(attestation, 0, sizeof(*attestation));
	claims = &attestation->claims;
	claims->schema_version =
		PQCP_FLEET_OPERATIONS_SCHEMA_VERSION;
	ret = pqcp_runtime_internal_copy_text(
		claims->device_id, sizeof(claims->device_id),
		device->device_id);
	if (ret == 0) {
		ret = pqcp_runtime_internal_copy_text(
			claims->product_class,
			sizeof(claims->product_class),
			device->product_class);
	}
	if (ret == 0) {
		ret = pqcp_runtime_internal_copy_text(
			claims->firmware_version,
			sizeof(claims->firmware_version),
			device->firmware_version);
	}
	if (ret != 0) {
		return ret;
	}
	claims->device_state = device->record.state;
	claims->boot_counter = device->record.boot_counter;
	claims->firmware_version_number =
		device->record.current_firmware_version;
	claims->policy_epoch =
		device->record.policy.envelope.policy_epoch;
	claims->revocation_epoch =
		device->record.revocation_epoch;
	claims->credential_issuance_epoch =
		device->record.credential.issuance_epoch;
	claims->audit_sequence =
		ledger->next_sequence != 0U ?
			ledger->next_sequence - 1U : 0U;
	claims->capabilities =
		device->record.granted_capabilities;
	claims->risk_score = risk_score;
	claims->security_level = security_level;
	memcpy(claims->hardware_id_digest,
	       device->hardware_id_digest,
	       sizeof(claims->hardware_id_digest));
	memcpy(claims->audit_chain_head, ledger->chain_head,
	       sizeof(claims->audit_chain_head));
	memcpy(claims->nonce, nonce, sizeof(claims->nonce));
	claims->issued_at_ms = now_ms;
	claims->expires_at_ms = expires_at_ms;
	return claims_digest(
		claims, attestation->claims_digest);
}

int pqcp_fleet_attestation_sign(
	struct pqcp_fleet_attestation *attestation,
	const struct pqcp_fleet_signer *signer)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (attestation == NULL || signer == NULL) {
		return -EINVAL;
	}
	ret = claims_digest(&attestation->claims, digest);
	if (ret == 0 &&
	    memcmp(digest, attestation->claims_digest,
		   sizeof(digest)) != 0) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_sign_buffer(
			attestation->claims_digest,
			sizeof(attestation->claims_digest),
			signer, attestation->signature);
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_fleet_attestation_verify(
	const struct pqcp_fleet_attestation *attestation,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (attestation == NULL || public_key == NULL ||
	    now_ms == 0U ||
	    now_ms < attestation->claims.issued_at_ms ||
	    now_ms >= attestation->claims.expires_at_ms) {
		return -EINVAL;
	}
	ret = claims_digest(&attestation->claims, digest);
	if (ret == 0 &&
	    memcmp(digest, attestation->claims_digest,
		   sizeof(digest)) != 0) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_verify_buffer(
			attestation->claims_digest,
			sizeof(attestation->claims_digest),
			public_key, attestation->signature);
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_fleet_attestation_encode(
	const struct pqcp_fleet_attestation *attestation,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	size_t claims_length = 0U;
	int ret;

	if (attestation == NULL || output == NULL ||
	    length == NULL) {
		return -EINVAL;
	}
	ret = claims_encode(
		&attestation->claims, output, capacity,
		&claims_length);
	if (ret != 0) {
		return ret;
	}
	if (capacity - claims_length <
	    sizeof(attestation->claims_digest) +
		    sizeof(attestation->signature)) {
		pqcp_runtime_secure_zero(output, claims_length);
		return -ENOSPC;
	}
	memcpy(output + claims_length,
	       attestation->claims_digest,
	       sizeof(attestation->claims_digest));
	claims_length += sizeof(attestation->claims_digest);
	memcpy(output + claims_length, attestation->signature,
	       sizeof(attestation->signature));
	claims_length += sizeof(attestation->signature);
	*length = claims_length;
	return 0;
}

int pqcp_fleet_attestation_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_attestation *attestation)
{
	size_t claims_length = 0U;
	int ret;

	if (input == NULL || attestation == NULL ||
	    length > PQCP_FLEET_ATTESTATION_MAX_BYTES ||
	    length < FLEET_ATTESTATION_HEADER_BYTES +
		    PQCP_FLEET_DIGEST_BYTES +
		    PQCP_FLEET_SIGNATURE_BYTES) {
		return -EINVAL;
	}
	memset(attestation, 0, sizeof(*attestation));
	ret = claims_decode(
		input, length, &attestation->claims,
		&claims_length);
	if (ret != 0) {
		return ret;
	}
	if (length - claims_length !=
	    sizeof(attestation->claims_digest) +
		    sizeof(attestation->signature)) {
		pqcp_runtime_secure_zero(
			attestation, sizeof(*attestation));
		return -EBADMSG;
	}
	memcpy(attestation->claims_digest,
	       input + claims_length,
	       sizeof(attestation->claims_digest));
	claims_length += sizeof(attestation->claims_digest);
	memcpy(attestation->signature, input + claims_length,
	       sizeof(attestation->signature));
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];

	ret = claims_digest(&attestation->claims, digest);
	if (ret == 0 &&
	    memcmp(digest, attestation->claims_digest,
		   sizeof(digest)) != 0) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			attestation, sizeof(*attestation));
	}
	return ret;
}
