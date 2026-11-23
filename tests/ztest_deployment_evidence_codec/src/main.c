/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the canonical deployment evidence binary codec.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_codec.h>

static uint8_t buffer[512];

ZTEST(pqcp_deployment_evidence_codec, test_error_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_codec_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK),
			  "none");
	zassert_str_equal(pqcp_deployment_evidence_codec_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_CODEC_OVERFLOW),
			  "overflow");
	zassert_str_equal(pqcp_deployment_evidence_codec_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_MISMATCH),
			  "digest_mismatch");
	zassert_str_equal(
		pqcp_deployment_evidence_codec_error_str(99), "unknown");
}

ZTEST(pqcp_deployment_evidence_codec, test_writer_initial_state)
{
	struct pqcp_deployment_evidence_codec_writer writer;

	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, sizeof(buffer));
	zassert_true(pqcp_deployment_evidence_codec_writer_ok(&writer));
	zassert_equal(
		pqcp_deployment_evidence_codec_writer_used(&writer), 0U);
	zassert_equal(
		pqcp_deployment_evidence_codec_writer_remaining(&writer),
		sizeof(buffer));
}

ZTEST(pqcp_deployment_evidence_codec, test_invalid_writer_state)
{
	struct pqcp_deployment_evidence_codec_writer writer;

	pqcp_deployment_evidence_codec_writer_init(&writer, NULL, 4U);
	zassert_false(pqcp_deployment_evidence_codec_writer_ok(&writer));
	zassert_equal(writer.error,
		      PQCP_DEPLOYMENT_EVIDENCE_CODEC_INVALID_ARGUMENT);
	zassert_equal(
		pqcp_deployment_evidence_codec_write_u32(&writer, 1U),
		-EINVAL);
}

ZTEST(pqcp_deployment_evidence_codec, test_integer_roundtrip)
{
	struct pqcp_deployment_evidence_codec_writer writer;
	struct pqcp_deployment_evidence_codec_reader reader;
	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	uint64_t u64;
	int32_t i32;
	bool boolean;

	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_evidence_codec_write_u8(
			      &writer, 0xa5U),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_write_u16(
			      &writer, 0x1234U),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_write_u32(
			      &writer, 0x89abcdefU),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_write_u64(
			      &writer, UINT64_C(0x0123456789abcdef)),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_write_i32(
			      &writer, -1234567),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_write_bool(
			      &writer, true),
		      0);

	pqcp_deployment_evidence_codec_reader_init(
		&reader, buffer, writer.offset);
	zassert_equal(pqcp_deployment_evidence_codec_read_u8(
			      &reader, &u8),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_read_u16(
			      &reader, &u16),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_read_u32(
			      &reader, &u32),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_read_u64(
			      &reader, &u64),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_read_i32(
			      &reader, &i32),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_read_bool(
			      &reader, &boolean),
		      0);
	zassert_equal(u8, 0xa5U);
	zassert_equal(u16, 0x1234U);
	zassert_equal(u32, 0x89abcdefU);
	zassert_equal(u64, UINT64_C(0x0123456789abcdef));
	zassert_equal(i32, -1234567);
	zassert_true(boolean);
	zassert_equal(
		pqcp_deployment_evidence_codec_require_eof(&reader), 0);
}

ZTEST(pqcp_deployment_evidence_codec, test_little_endian_encoding)
{
	struct pqcp_deployment_evidence_codec_writer writer;

	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_evidence_codec_write_u32(
			      &writer, 0x12345678U),
		      0);
	zassert_equal(buffer[0], 0x78U);
	zassert_equal(buffer[1], 0x56U);
	zassert_equal(buffer[2], 0x34U);
	zassert_equal(buffer[3], 0x12U);
}

ZTEST(pqcp_deployment_evidence_codec, test_writer_overflow_is_sticky)
{
	struct pqcp_deployment_evidence_codec_writer writer;
	uint8_t small[3];

	pqcp_deployment_evidence_codec_writer_init(
		&writer, small, sizeof(small));
	zassert_equal(pqcp_deployment_evidence_codec_write_u32(
			      &writer, 1U),
		      -ENOSPC);
	zassert_equal(writer.error,
		      PQCP_DEPLOYMENT_EVIDENCE_CODEC_OVERFLOW);
	zassert_equal(pqcp_deployment_evidence_codec_write_u8(
			      &writer, 1U),
		      -ENOSPC);
	zassert_equal(writer.offset, 0U);
}

ZTEST(pqcp_deployment_evidence_codec, test_reader_truncation_is_sticky)
{
	struct pqcp_deployment_evidence_codec_reader reader;
	uint32_t value;

	pqcp_deployment_evidence_codec_reader_init(&reader, buffer, 3U);
	zassert_equal(pqcp_deployment_evidence_codec_read_u32(
			      &reader, &value),
		      -EMSGSIZE);
	zassert_equal(reader.error,
		      PQCP_DEPLOYMENT_EVIDENCE_CODEC_TRUNCATED);
	zassert_equal(pqcp_deployment_evidence_codec_read_u8(
			      &reader, buffer),
		      -EMSGSIZE);
}

ZTEST(pqcp_deployment_evidence_codec, test_boolean_rejects_noncanonical)
{
	struct pqcp_deployment_evidence_codec_reader reader;
	bool value;
	uint8_t encoded = 2U;

	pqcp_deployment_evidence_codec_reader_init(
		&reader, &encoded, sizeof(encoded));
	zassert_equal(pqcp_deployment_evidence_codec_read_bool(
			      &reader, &value),
		      -EBADMSG);
	zassert_equal(reader.error,
		      PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED);
}

ZTEST(pqcp_deployment_evidence_codec, test_text_roundtrip)
{
	struct pqcp_deployment_evidence_codec_writer writer;
	struct pqcp_deployment_evidence_codec_reader reader;
	char output[32];

	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_evidence_codec_write_text(
			      &writer, "hybrid768", 20U),
		      0);
	pqcp_deployment_evidence_codec_reader_init(
		&reader, buffer, writer.offset);
	zassert_equal(pqcp_deployment_evidence_codec_read_text(
			      &reader, output, sizeof(output), 20U),
		      0);
	zassert_str_equal(output, "hybrid768");
}

ZTEST(pqcp_deployment_evidence_codec, test_text_rejects_embedded_nul)
{
	struct pqcp_deployment_evidence_codec_reader reader;
	char output[16];
	uint8_t encoded[] = {3U, 0U, 'a', 0U, 'b'};

	pqcp_deployment_evidence_codec_reader_init(
		&reader, encoded, sizeof(encoded));
	zassert_equal(pqcp_deployment_evidence_codec_read_text(
			      &reader, output, sizeof(output), 10U),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_evidence_codec, test_text_range_checks)
{
	struct pqcp_deployment_evidence_codec_writer writer;
	char long_text[20];

	memset(long_text, 'x', sizeof(long_text));
	long_text[sizeof(long_text) - 1U] = '\0';
	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_evidence_codec_write_text(
			      &writer, long_text, 8U),
		      -ERANGE);
}

ZTEST(pqcp_deployment_evidence_codec, test_alignment_zero_fills)
{
	struct pqcp_deployment_evidence_codec_writer writer;

	memset(buffer, 0xff, sizeof(buffer));
	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_evidence_codec_write_u8(
			      &writer, 0xaaU),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_align_writer(
			      &writer, 4U),
		      0);
	zassert_equal(writer.offset, 4U);
	zassert_equal(buffer[1], 0U);
	zassert_equal(buffer[2], 0U);
	zassert_equal(buffer[3], 0U);
}

ZTEST(pqcp_deployment_evidence_codec, test_reader_rejects_nonzero_padding)
{
	struct pqcp_deployment_evidence_codec_reader reader;
	uint8_t encoded[] = {0xaaU, 0U, 1U, 0U};

	pqcp_deployment_evidence_codec_reader_init(
		&reader, encoded, sizeof(encoded));
	reader.offset = 1U;
	zassert_equal(pqcp_deployment_evidence_codec_align_reader(
			      &reader, 4U),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_evidence_codec, test_record_roundtrip)
{
	struct pqcp_deployment_evidence_codec_writer writer;
	struct pqcp_deployment_evidence_codec_reader reader;
	struct pqcp_deployment_evidence_codec_reader payload;
	struct pqcp_deployment_evidence_codec_record_scope scope;
	struct pqcp_deployment_evidence_codec_record record;
	uint32_t value;

	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_evidence_codec_begin_record(
			      &writer, 7U, 3U, &scope),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_write_u32(
			      &writer, 0xdeadbeefU),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_end_record(
			      &writer, &scope),
		      0);
	pqcp_deployment_evidence_codec_reader_init(
		&reader, buffer, writer.offset);
	zassert_equal(pqcp_deployment_evidence_codec_next_record(
			      &reader, &record),
		      0);
	zassert_equal(record.type, 7U);
	zassert_equal(record.flags, 3U);
	zassert_equal(record.length, 4U);
	zassert_equal(pqcp_deployment_evidence_codec_record_reader(
			      &reader, &record, &payload),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_read_u32(
			      &payload, &value),
		      0);
	zassert_equal(value, 0xdeadbeefU);
	zassert_equal(pqcp_deployment_evidence_codec_finish_record(
			      &reader, &record, &payload),
		      0);
	zassert_equal(
		pqcp_deployment_evidence_codec_require_eof(&reader), 0);
}

ZTEST(pqcp_deployment_evidence_codec, test_record_rejects_trailing_payload)
{
	struct pqcp_deployment_evidence_codec_writer writer;
	struct pqcp_deployment_evidence_codec_reader reader;
	struct pqcp_deployment_evidence_codec_reader payload;
	struct pqcp_deployment_evidence_codec_record_scope scope;
	struct pqcp_deployment_evidence_codec_record record;
	uint8_t value;

	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_evidence_codec_begin_record(
			      &writer, 1U, 0U, &scope),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_write_u16(
			      &writer, 0x1234U),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_end_record(
			      &writer, &scope),
		      0);
	pqcp_deployment_evidence_codec_reader_init(
		&reader, buffer, writer.offset);
	zassert_equal(pqcp_deployment_evidence_codec_next_record(
			      &reader, &record),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_record_reader(
			      &reader, &record, &payload),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_read_u8(
			      &payload, &value),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_finish_record(
			      &reader, &record, &payload),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_evidence_codec, test_record_rejects_zero_type)
{
	struct pqcp_deployment_evidence_codec_reader reader;
	struct pqcp_deployment_evidence_codec_record record;
	uint8_t encoded[8] = {0};

	pqcp_deployment_evidence_codec_reader_init(
		&reader, encoded, sizeof(encoded));
	zassert_equal(pqcp_deployment_evidence_codec_next_record(
			      &reader, &record),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_evidence_codec, test_patch_integer)
{
	struct pqcp_deployment_evidence_codec_writer writer;

	memset(buffer, 0, sizeof(buffer));
	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, sizeof(buffer));
	zassert_equal(pqcp_deployment_evidence_codec_write_zeros(
			      &writer, 8U),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_patch_u16(
			      &writer, 1U, 0x1234U),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_patch_u32(
			      &writer, 4U, 0x89abcdefU),
		      0);
	zassert_equal(buffer[1], 0x34U);
	zassert_equal(buffer[2], 0x12U);
	zassert_equal(buffer[4], 0xefU);
	zassert_equal(buffer[7], 0x89U);
}

ZTEST(pqcp_deployment_evidence_codec, test_hex_roundtrip)
{
	uint8_t bytes[] = {0x00U, 0x12U, 0xabU, 0xffU};
	uint8_t decoded[sizeof(bytes)];
	char hex[sizeof(bytes) * 2U + 1U];

	zassert_equal(pqcp_deployment_evidence_codec_bytes_to_hex(
			      bytes, sizeof(bytes), hex, sizeof(hex)),
		      0);
	zassert_str_equal(hex, "0012abff");
	zassert_true(pqcp_deployment_evidence_codec_is_lower_hex(
		hex, strlen(hex)));
	zassert_equal(pqcp_deployment_evidence_codec_hex_to_bytes(
			      hex, strlen(hex), decoded, sizeof(decoded)),
		      0);
	zassert_mem_equal(decoded, bytes, sizeof(bytes));
}

ZTEST(pqcp_deployment_evidence_codec, test_hex_rejects_uppercase)
{
	uint8_t output[2];

	zassert_false(pqcp_deployment_evidence_codec_is_lower_hex(
		"ABCD", 4U));
	zassert_equal(pqcp_deployment_evidence_codec_hex_to_bytes(
			      "ABCD", 4U, output, sizeof(output)),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_evidence_codec, test_digest_stability)
{
	char first[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	char second[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	const char input[] = "deployment evidence";

	zassert_equal(pqcp_deployment_evidence_digest_buffer_hex(
			      42U, input, strlen(input), first),
		      0);
	zassert_equal(pqcp_deployment_evidence_digest_buffer_hex(
			      42U, input, strlen(input), second),
		      0);
	zassert_str_equal(first, second);
	zassert_true(pqcp_deployment_evidence_codec_is_lower_hex(
		first, PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS));
}

ZTEST(pqcp_deployment_evidence_codec, test_digest_domain_separation)
{
	char first[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	char second[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	const char input[] = "deployment evidence";

	zassert_equal(pqcp_deployment_evidence_digest_buffer_hex(
			      1U, input, strlen(input), first),
		      0);
	zassert_equal(pqcp_deployment_evidence_digest_buffer_hex(
			      2U, input, strlen(input), second),
		      0);
	zassert_not_equal(strcmp(first, second), 0);
}

ZTEST(pqcp_deployment_evidence_codec, test_digest_incremental_matches_buffer)
{
	struct pqcp_deployment_evidence_digest digest;
	char incremental[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	char complete[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	const char input[] = "abcdef0123456789";

	pqcp_deployment_evidence_digest_init(&digest, 77U);
	pqcp_deployment_evidence_digest_update(&digest, input, 5U);
	pqcp_deployment_evidence_digest_update(
		&digest, input + 5U, strlen(input) - 5U);
	zassert_equal(pqcp_deployment_evidence_digest_final_hex(
			      &digest, incremental),
		      0);
	zassert_equal(pqcp_deployment_evidence_digest_buffer_hex(
			      77U, input, strlen(input), complete),
		      0);
	zassert_str_equal(incremental, complete);
}

ZTEST_SUITE(pqcp_deployment_evidence_codec, NULL, NULL, NULL, NULL, NULL);
