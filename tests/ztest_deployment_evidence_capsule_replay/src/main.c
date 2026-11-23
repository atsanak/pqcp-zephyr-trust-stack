/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for deployment evidence capsule replay verification.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_capsule_replay.h>

#include "deployment_evidence_archive_fixture.h"

static const char board[] = "qemu_x86_64";
static const char top[] = "hybrid768_65_campaign";
static const char nonce[] = "00112233445566778899aabbccddeeff";
static uint8_t capsule_buffer[PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES];

struct replay_fixture {
	struct pqcp_archive_test_fixture passport;
	struct pqcp_deployment_evidence_capsule capsule;
	struct pqcp_deployment_evidence_capsule_replay_workspace workspace;
	struct pqcp_deployment_evidence_capsule_replay_result result;
};

static void build_capsule(struct replay_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	zassert_equal(pqcp_archive_test_build_passport(
			      &fixture->passport, board, top, nonce, true),
		      0);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture->passport.passport,
			      &fixture->passport.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &fixture->capsule),
		      0);
}

static bool find_record(
	const uint8_t *buffer,
	size_t length,
	uint16_t type,
	struct pqcp_deployment_evidence_codec_record *found)
{
	struct pqcp_deployment_evidence_codec_reader reader;
	struct pqcp_deployment_evidence_codec_record record;

	pqcp_deployment_evidence_codec_reader_init(
		&reader, buffer, length);
	reader.offset = PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES;
	while (pqcp_deployment_evidence_codec_next_record(
		       &reader, &record) == 0) {
		if (record.type == type) {
			*found = record;
			return true;
		}
		reader.offset = record.next_offset;
	}
	return false;
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_error_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_evidence_capsule_replay_error_str(
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_NONE),
		"none");
	zassert_str_equal(
		pqcp_deployment_evidence_capsule_replay_error_str(
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DIGEST_MISMATCH),
		"digest_mismatch");
	zassert_str_equal(
		pqcp_deployment_evidence_capsule_replay_error_str(
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_SIGNATURE),
		"signature");
	zassert_str_equal(
		pqcp_deployment_evidence_capsule_replay_error_str(99),
		"unknown");
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_valid_capsule_replays)
{
	struct replay_fixture fixture;

	build_capsule(&fixture);
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      0);
	zassert_true(fixture.result.passed);
	zassert_true(fixture.result.passport_replayed);
	zassert_true(fixture.result.digest_verified);
	zassert_false(fixture.result.signature_present);
	zassert_false(fixture.result.signature_verified);
	zassert_true(fixture.result.production_allowed);
	zassert_equal(fixture.result.records_seen, 5U);
	zassert_equal(fixture.result.records_expected, 5U);
	zassert_equal(fixture.result.bytes_consumed,
		      fixture.capsule.byte_count);
	zassert_str_equal(fixture.result.board, board);
	zassert_str_equal(fixture.result.top_candidate_id, top);
	zassert_str_equal(fixture.result.nonce_hex, nonce);
	zassert_str_equal(fixture.result.passport_digest_hex,
			  fixture.passport.passport.passport_digest_hex);
	zassert_str_equal(fixture.result.capsule_digest_hex,
			  fixture.capsule.capsule_digest_hex);
	zassert_equal(
		pqcp_deployment_evidence_capsule_replay_emit(
			&fixture.result),
		0);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_null_input_fails)
{
	struct replay_fixture fixture;

	build_capsule(&fixture);
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      NULL, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EINVAL);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_INVALID_ARGUMENT);
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      NULL, &fixture.result),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_truncated_header_fails)
{
	struct replay_fixture fixture;

	build_capsule(&fixture);
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer,
			      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES - 1U,
			      &fixture.workspace, &fixture.result),
		      -EINVAL);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_INVALID_ARGUMENT);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_bad_magic_fails)
{
	struct replay_fixture fixture;

	build_capsule(&fixture);
	capsule_buffer[0] ^= 0x01U;
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_HEADER);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_bad_schema_fails)
{
	struct replay_fixture fixture;

	build_capsule(&fixture);
	capsule_buffer[4] = 99U;
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EPROTONOSUPPORT);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_SCHEMA);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_unknown_flags_fail)
{
	struct replay_fixture fixture;

	build_capsule(&fixture);
	capsule_buffer[11] |= 0x80U;
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_FLAGS);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_total_length_mismatch_fails)
{
	struct replay_fixture fixture;

	build_capsule(&fixture);
	capsule_buffer[20]--;
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EMSGSIZE);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_LENGTH);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_record_payload_tamper_fails)
{
	struct replay_fixture fixture;
	struct pqcp_deployment_evidence_codec_record record;

	build_capsule(&fixture);
	zassert_true(find_record(
		capsule_buffer, fixture.capsule.byte_count,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_IDENTITY,
		&record));
	capsule_buffer[record.payload_offset + 3U] ^= 0x01U;
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EBADMSG);
	zassert_true(
		fixture.result.first_error ==
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DIGEST_MISMATCH ||
		fixture.result.first_error ==
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_PASSPORT_REPLAY);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_terminal_digest_tamper_fails)
{
	struct replay_fixture fixture;
	struct pqcp_deployment_evidence_codec_record record;

	build_capsule(&fixture);
	zassert_true(find_record(
		capsule_buffer, fixture.capsule.byte_count,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_DIGEST, &record));
	capsule_buffer[record.payload_offset] ^= 0x01U;
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DIGEST_MISMATCH);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_duplicate_record_fails)
{
	struct replay_fixture fixture;
	struct pqcp_deployment_evidence_codec_record first;
	struct pqcp_deployment_evidence_codec_record second;

	build_capsule(&fixture);
	zassert_true(find_record(
		capsule_buffer, fixture.capsule.byte_count,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_CORE,
		&first));
	zassert_true(find_record(
		capsule_buffer, fixture.capsule.byte_count,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_IDENTITY,
		&second));
	capsule_buffer[second.header_offset] =
		capsule_buffer[first.header_offset];
	capsule_buffer[second.header_offset + 1U] =
		capsule_buffer[first.header_offset + 1U];
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DUPLICATE_RECORD);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_record_order_fails)
{
	struct replay_fixture fixture;
	struct pqcp_deployment_evidence_codec_record digests;

	build_capsule(&fixture);
	zassert_true(find_record(
		capsule_buffer, fixture.capsule.byte_count,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_DIGESTS,
		&digests));
	capsule_buffer[digests.header_offset] =
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_CORE;
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EBADMSG);
	zassert_equal(
		fixture.result.first_error,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_RECORD_ORDER);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_missing_digest_record_fails)
{
	struct replay_fixture fixture;

	build_capsule(&fixture);
	capsule_buffer[16] = 4U;
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MISSING_RECORD);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_flag_mismatch_fails)
{
	struct replay_fixture fixture;

	build_capsule(&fixture);
	capsule_buffer[8] &=
		(uint8_t)~PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PRODUCTION;
	/*
	 * Recompute the terminal capsule digest so the replay reaches the
	 * semantic flag-consistency check instead of failing integrity first.
	 */
	struct pqcp_deployment_evidence_codec_record digest_record;
	char digest_hex[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U];
	uint8_t digest_bytes[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES];

	zassert_true(find_record(
		capsule_buffer, fixture.capsule.byte_count,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_DIGEST,
		&digest_record));
	zassert_equal(pqcp_deployment_evidence_digest_buffer_hex(
			      UINT64_C(0x5051435043415053),
			      capsule_buffer, digest_record.header_offset,
			      digest_hex),
		      0);
	zassert_equal(pqcp_deployment_evidence_codec_hex_to_bytes(
			      digest_hex, strlen(digest_hex), digest_bytes,
			      sizeof(digest_bytes)),
		      0);
	memcpy(capsule_buffer + digest_record.payload_offset,
	       digest_bytes, sizeof(digest_bytes));
	zassert_equal(pqcp_deployment_evidence_capsule_replay_verify(
			      capsule_buffer, fixture.capsule.byte_count,
			      &fixture.workspace, &fixture.result),
		      -EBADMSG);
	zassert_equal(fixture.result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_FLAG_MISMATCH);
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_nonzero_padding_fails)
{
	struct replay_fixture fixture;
	struct pqcp_deployment_evidence_codec_record identity;

	build_capsule(&fixture);
	zassert_true(find_record(
		capsule_buffer, fixture.capsule.byte_count,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_IDENTITY,
		&identity));
	if (identity.next_offset >
	    identity.payload_offset + identity.length) {
		capsule_buffer[identity.payload_offset + identity.length] = 1U;
		zassert_equal(
			pqcp_deployment_evidence_capsule_replay_verify(
				capsule_buffer, fixture.capsule.byte_count,
				&fixture.workspace, &fixture.result),
			-EBADMSG);
		zassert_equal(
			fixture.result.first_error,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MALFORMED_RECORD);
	} else {
		ztest_test_skip();
	}
}

ZTEST(pqcp_deployment_evidence_capsule_replay, test_emit_rejects_bad_result)
{
	struct pqcp_deployment_evidence_capsule_replay_result result = {
		.schema_version =
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_SCHEMA_VERSION,
		.records_seen = 2U,
		.records_expected = 1U,
	};

	zassert_equal(
		pqcp_deployment_evidence_capsule_replay_emit(&result),
		-EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_capsule_replay, NULL, NULL, NULL, NULL,
	    NULL);
