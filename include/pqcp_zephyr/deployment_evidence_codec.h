/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Canonical deployment evidence binary codec
 *
 * Stability: experimental evidence API. The codec provides allocation-free,
 * bounds-checked little-endian encoding, TLV framing, strict decoding, and a
 * deterministic 256-bit rolling digest for firmware evidence containers.
 * The rolling digest is an integrity and replay binding, not a cryptographic
 * signature or replacement for SHA-256.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_CODEC_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_CODEC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_DEPLOYMENT_EVIDENCE_CODEC_SCHEMA_VERSION 1U
#define PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES 32U
#define PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS 64U
#define PQCP_DEPLOYMENT_EVIDENCE_CODEC_RECORD_HEADER_BYTES 8U
#define PQCP_DEPLOYMENT_EVIDENCE_CODEC_ALIGNMENT 4U
#define PQCP_DEPLOYMENT_EVIDENCE_CODEC_MAX_TEXT_BYTES 255U

enum pqcp_deployment_evidence_codec_error {
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK = 0,
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_OVERFLOW,
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRUNCATED,
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED,
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_RANGE,
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_DUPLICATE,
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_ORDER,
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRAILING_DATA,
	PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_MISMATCH,
};

struct pqcp_deployment_evidence_codec_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	enum pqcp_deployment_evidence_codec_error error;
};

struct pqcp_deployment_evidence_codec_reader {
	const uint8_t *buffer;
	size_t length;
	size_t offset;
	enum pqcp_deployment_evidence_codec_error error;
};

struct pqcp_deployment_evidence_codec_record {
	uint16_t type;
	uint16_t flags;
	uint32_t length;
	size_t header_offset;
	size_t payload_offset;
	size_t next_offset;
};

struct pqcp_deployment_evidence_codec_record_scope {
	size_t header_offset;
	size_t payload_offset;
	uint16_t type;
	uint16_t flags;
	bool open;
};

struct pqcp_deployment_evidence_digest {
	uint64_t lane[4];
	uint64_t total_bytes;
};

const char *pqcp_deployment_evidence_codec_error_str(
	enum pqcp_deployment_evidence_codec_error error);

void pqcp_deployment_evidence_codec_writer_init(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint8_t *buffer,
	size_t capacity);

size_t pqcp_deployment_evidence_codec_writer_used(
	const struct pqcp_deployment_evidence_codec_writer *writer);

size_t pqcp_deployment_evidence_codec_writer_remaining(
	const struct pqcp_deployment_evidence_codec_writer *writer);

bool pqcp_deployment_evidence_codec_writer_ok(
	const struct pqcp_deployment_evidence_codec_writer *writer);

int pqcp_deployment_evidence_codec_write_u8(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint8_t value);

int pqcp_deployment_evidence_codec_write_u16(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint16_t value);

int pqcp_deployment_evidence_codec_write_u32(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint32_t value);

int pqcp_deployment_evidence_codec_write_u64(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint64_t value);

int pqcp_deployment_evidence_codec_write_i32(
	struct pqcp_deployment_evidence_codec_writer *writer,
	int32_t value);

int pqcp_deployment_evidence_codec_write_bool(
	struct pqcp_deployment_evidence_codec_writer *writer,
	bool value);

int pqcp_deployment_evidence_codec_write_bytes(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const void *data,
	size_t length);

int pqcp_deployment_evidence_codec_write_zeros(
	struct pqcp_deployment_evidence_codec_writer *writer,
	size_t length);

int pqcp_deployment_evidence_codec_write_text(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const char *text,
	size_t max_length);

int pqcp_deployment_evidence_codec_align_writer(
	struct pqcp_deployment_evidence_codec_writer *writer,
	size_t alignment);

int pqcp_deployment_evidence_codec_patch_u16(
	struct pqcp_deployment_evidence_codec_writer *writer,
	size_t offset,
	uint16_t value);

int pqcp_deployment_evidence_codec_patch_u32(
	struct pqcp_deployment_evidence_codec_writer *writer,
	size_t offset,
	uint32_t value);

int pqcp_deployment_evidence_codec_begin_record(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint16_t type,
	uint16_t flags,
	struct pqcp_deployment_evidence_codec_record_scope *scope);

int pqcp_deployment_evidence_codec_end_record(
	struct pqcp_deployment_evidence_codec_writer *writer,
	struct pqcp_deployment_evidence_codec_record_scope *scope);

void pqcp_deployment_evidence_codec_reader_init(
	struct pqcp_deployment_evidence_codec_reader *reader,
	const uint8_t *buffer,
	size_t length);

size_t pqcp_deployment_evidence_codec_reader_remaining(
	const struct pqcp_deployment_evidence_codec_reader *reader);

bool pqcp_deployment_evidence_codec_reader_ok(
	const struct pqcp_deployment_evidence_codec_reader *reader);

int pqcp_deployment_evidence_codec_read_u8(
	struct pqcp_deployment_evidence_codec_reader *reader,
	uint8_t *value);

int pqcp_deployment_evidence_codec_read_u16(
	struct pqcp_deployment_evidence_codec_reader *reader,
	uint16_t *value);

int pqcp_deployment_evidence_codec_read_u32(
	struct pqcp_deployment_evidence_codec_reader *reader,
	uint32_t *value);

int pqcp_deployment_evidence_codec_read_u64(
	struct pqcp_deployment_evidence_codec_reader *reader,
	uint64_t *value);

int pqcp_deployment_evidence_codec_read_i32(
	struct pqcp_deployment_evidence_codec_reader *reader,
	int32_t *value);

int pqcp_deployment_evidence_codec_read_bool(
	struct pqcp_deployment_evidence_codec_reader *reader,
	bool *value);

int pqcp_deployment_evidence_codec_read_bytes(
	struct pqcp_deployment_evidence_codec_reader *reader,
	void *destination,
	size_t length);

int pqcp_deployment_evidence_codec_read_text(
	struct pqcp_deployment_evidence_codec_reader *reader,
	char *destination,
	size_t capacity,
	size_t max_length);

int pqcp_deployment_evidence_codec_skip(
	struct pqcp_deployment_evidence_codec_reader *reader,
	size_t length);

int pqcp_deployment_evidence_codec_align_reader(
	struct pqcp_deployment_evidence_codec_reader *reader,
	size_t alignment);

int pqcp_deployment_evidence_codec_next_record(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_deployment_evidence_codec_record *record);

int pqcp_deployment_evidence_codec_record_reader(
	const struct pqcp_deployment_evidence_codec_reader *parent,
	const struct pqcp_deployment_evidence_codec_record *record,
	struct pqcp_deployment_evidence_codec_reader *payload);

int pqcp_deployment_evidence_codec_finish_record(
	struct pqcp_deployment_evidence_codec_reader *parent,
	const struct pqcp_deployment_evidence_codec_record *record,
	const struct pqcp_deployment_evidence_codec_reader *payload);

int pqcp_deployment_evidence_codec_require_eof(
	struct pqcp_deployment_evidence_codec_reader *reader);

bool pqcp_deployment_evidence_codec_is_lower_hex(
	const char *text,
	size_t expected_length);

int pqcp_deployment_evidence_codec_hex_to_bytes(
	const char *hex,
	size_t hex_length,
	uint8_t *output,
	size_t output_capacity);

int pqcp_deployment_evidence_codec_bytes_to_hex(
	const uint8_t *bytes,
	size_t byte_length,
	char *output,
	size_t output_capacity);

void pqcp_deployment_evidence_digest_init(
	struct pqcp_deployment_evidence_digest *digest,
	uint64_t domain);

void pqcp_deployment_evidence_digest_update(
	struct pqcp_deployment_evidence_digest *digest,
	const void *data,
	size_t length);

void pqcp_deployment_evidence_digest_update_u8(
	struct pqcp_deployment_evidence_digest *digest,
	uint8_t value);

void pqcp_deployment_evidence_digest_update_u16(
	struct pqcp_deployment_evidence_digest *digest,
	uint16_t value);

void pqcp_deployment_evidence_digest_update_u32(
	struct pqcp_deployment_evidence_digest *digest,
	uint32_t value);

void pqcp_deployment_evidence_digest_update_u64(
	struct pqcp_deployment_evidence_digest *digest,
	uint64_t value);

void pqcp_deployment_evidence_digest_update_bool(
	struct pqcp_deployment_evidence_digest *digest,
	bool value);

void pqcp_deployment_evidence_digest_update_text(
	struct pqcp_deployment_evidence_digest *digest,
	const char *text);

void pqcp_deployment_evidence_digest_final_bytes(
	const struct pqcp_deployment_evidence_digest *digest,
	uint8_t output[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES]);

int pqcp_deployment_evidence_digest_final_hex(
	const struct pqcp_deployment_evidence_digest *digest,
	char output[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U]);

int pqcp_deployment_evidence_digest_buffer_hex(
	uint64_t domain,
	const void *data,
	size_t length,
	char output[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U]);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_CODEC_H_ */
