/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#ifndef PQCP_FLEET_INTERNAL_H_
#define PQCP_FLEET_INTERNAL_H_

#include <pqcp_zephyr/fleet_protocol.h>

struct pqcp_fleet_cbor_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

struct pqcp_fleet_cbor_reader {
	const uint8_t *buffer;
	size_t length;
	size_t offset;
	int error;
};

void pqcp_fleet_cbor_writer_init(
	struct pqcp_fleet_cbor_writer *writer,
	uint8_t *buffer, size_t capacity);
int pqcp_fleet_cbor_write_array(
	struct pqcp_fleet_cbor_writer *writer, size_t count);
int pqcp_fleet_cbor_write_uint(
	struct pqcp_fleet_cbor_writer *writer, uint64_t value);
int pqcp_fleet_cbor_write_int(
	struct pqcp_fleet_cbor_writer *writer, int64_t value);
int pqcp_fleet_cbor_write_bool(
	struct pqcp_fleet_cbor_writer *writer, bool value);
int pqcp_fleet_cbor_write_bytes(
	struct pqcp_fleet_cbor_writer *writer,
	const uint8_t *value, size_t length);
int pqcp_fleet_cbor_write_text(
	struct pqcp_fleet_cbor_writer *writer,
	const char *value, size_t maximum);

void pqcp_fleet_cbor_reader_init(
	struct pqcp_fleet_cbor_reader *reader,
	const uint8_t *buffer, size_t length);
int pqcp_fleet_cbor_read_array(
	struct pqcp_fleet_cbor_reader *reader, size_t expected);
int pqcp_fleet_cbor_read_uint(
	struct pqcp_fleet_cbor_reader *reader, uint64_t *value);
int pqcp_fleet_cbor_read_int(
	struct pqcp_fleet_cbor_reader *reader, int64_t *value);
int pqcp_fleet_cbor_read_bool(
	struct pqcp_fleet_cbor_reader *reader, bool *value);
int pqcp_fleet_cbor_read_bytes(
	struct pqcp_fleet_cbor_reader *reader,
	uint8_t *value, size_t capacity, size_t *length);
int pqcp_fleet_cbor_read_text(
	struct pqcp_fleet_cbor_reader *reader,
	char *value, size_t capacity);
int pqcp_fleet_cbor_finish(
	struct pqcp_fleet_cbor_reader *reader);

int pqcp_fleet_cbor_peek_envelope_type(
	const uint8_t *input,
	size_t length,
	enum pqcp_fleet_message_type *type);

int pqcp_fleet_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_FLEET_DIGEST_BYTES]);
int pqcp_fleet_sign_buffer(
	const uint8_t *message, size_t message_length,
	const struct pqcp_fleet_signer *signer,
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES]);
int pqcp_fleet_verify_buffer(
	const uint8_t *message, size_t message_length,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	const uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES]);

#endif /* PQCP_FLEET_INTERNAL_H_ */
