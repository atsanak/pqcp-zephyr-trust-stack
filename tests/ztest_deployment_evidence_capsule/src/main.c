/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for firmware deployment evidence capsule construction.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_capsule.h>

#include "deployment_evidence_archive_fixture.h"

static const char board[] = "qemu_x86_64";
static const char top[] = "hybrid768_65_campaign";
static const char nonce[] = "00112233445566778899aabbccddeeff";
static uint8_t capsule_buffer[PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES];

static void build_fixture(struct pqcp_archive_test_fixture *fixture)
{
	zassert_equal(pqcp_archive_test_build_passport(
			      fixture, board, top, nonce, true),
		      0);
	zassert_true(fixture->passport_replay.passed);
}

ZTEST(pqcp_deployment_evidence_capsule, test_status_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_capsule_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_PASS),
			  "PASS");
	zassert_str_equal(pqcp_deployment_evidence_capsule_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_WARN),
			  "WARN");
	zassert_str_equal(pqcp_deployment_evidence_capsule_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FAIL),
			  "FAIL");
	zassert_str_equal(
		pqcp_deployment_evidence_capsule_status_str(99), "FAIL");
}

ZTEST(pqcp_deployment_evidence_capsule, test_error_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_capsule_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_NONE),
			  "none");
	zassert_str_equal(pqcp_deployment_evidence_capsule_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_SIGNATURE),
			  "bad_signature");
	zassert_str_equal(pqcp_deployment_evidence_capsule_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_DIGEST),
			  "digest");
	zassert_str_equal(
		pqcp_deployment_evidence_capsule_error_str(99), "unknown");
}

ZTEST(pqcp_deployment_evidence_capsule, test_required_size_is_bounded)
{
	size_t unsigned_size =
		pqcp_deployment_evidence_capsule_required_bytes(false);
	size_t signed_size =
		pqcp_deployment_evidence_capsule_required_bytes(true);

	zassert_true(unsigned_size >=
		     PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES);
	zassert_true(signed_size > unsigned_size);
	zassert_true(signed_size <=
		     PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES);
	zassert_equal(unsigned_size & 3U, 0U);
	zassert_equal(signed_size & 3U, 0U);
}

ZTEST(pqcp_deployment_evidence_capsule, test_unsigned_capsule_builds)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule capsule;

	build_fixture(&fixture);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &capsule),
		      0);
	zassert_equal(capsule.schema_version,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_SCHEMA_VERSION);
	zassert_equal(capsule.status,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_PASS);
	zassert_equal(capsule.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_NONE);
	zassert_false(capsule.signature_present);
	zassert_false(capsule.signature_verified);
	zassert_true(capsule.replay_passed);
	zassert_true(capsule.production_allowed);
	zassert_equal(capsule.record_count, 5U);
	zassert_true(capsule.byte_count > 0U);
	zassert_true(capsule.byte_count <
		     PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES);
	zassert_str_equal(capsule.board, board);
	zassert_str_equal(capsule.top_candidate_id, top);
	zassert_str_equal(capsule.nonce_hex, nonce);
	zassert_str_equal(capsule.passport_digest_hex,
			  fixture.passport.passport_digest_hex);
	zassert_true(pqcp_deployment_evidence_codec_is_lower_hex(
		capsule.capsule_digest_hex,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS));
	zassert_equal(
		pqcp_deployment_evidence_capsule_emit(&capsule), 0);
}

ZTEST(pqcp_deployment_evidence_capsule, test_capsule_is_deterministic)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule first;
	struct pqcp_deployment_evidence_capsule second;
	uint8_t first_buffer[PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES];
	uint8_t second_buffer[PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES];

	build_fixture(&fixture);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      first_buffer, sizeof(first_buffer), &first),
		      0);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      second_buffer, sizeof(second_buffer), &second),
		      0);
	zassert_equal(first.byte_count, second.byte_count);
	zassert_str_equal(first.capsule_digest_hex,
			  second.capsule_digest_hex);
	zassert_mem_equal(first_buffer, second_buffer,
			  first.byte_count);
}

ZTEST(pqcp_deployment_evidence_capsule, test_buffer_too_small_fails)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule capsule;
	size_t needed =
		pqcp_deployment_evidence_capsule_required_bytes(false);

	build_fixture(&fixture);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      capsule_buffer, needed - 1U, &capsule),
		      -ENOSPC);
	zassert_equal(capsule.status,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FAIL);
	zassert_equal(capsule.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BUFFER_TOO_SMALL);
}

ZTEST(pqcp_deployment_evidence_capsule, test_null_inputs_fail)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule capsule;

	build_fixture(&fixture);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      NULL, &fixture.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &capsule),
		      -EINVAL);
	zassert_equal(capsule.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_INVALID_ARGUMENT);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport, NULL, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &capsule),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      NULL, sizeof(capsule_buffer), &capsule),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_capsule, test_bad_passport_schema_fails)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule capsule;

	build_fixture(&fixture);
	fixture.passport.schema_version = 99U;
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &capsule),
		      -EBADMSG);
	zassert_equal(capsule.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_PASSPORT);
}

ZTEST(pqcp_deployment_evidence_capsule, test_bad_passport_digest_fails)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule capsule;

	build_fixture(&fixture);
	fixture.passport.passport_digest_hex[0] = 'z';
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &capsule),
		      -EBADMSG);
	zassert_equal(capsule.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_PASSPORT);
}

ZTEST(pqcp_deployment_evidence_capsule, test_replay_mismatch_fails)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule capsule;

	build_fixture(&fixture);
	fixture.passport_replay.passport_score--;
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &capsule),
		      -EBADMSG);
	zassert_equal(capsule.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_REPLAY);
}

ZTEST(pqcp_deployment_evidence_capsule, test_replay_digest_mismatch_fails)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule capsule;

	build_fixture(&fixture);
	fixture.passport_replay.computed_digest_hex[0] =
		fixture.passport_replay.computed_digest_hex[0] == '0' ?
			'1' : '0';
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &capsule),
		      -EBADMSG);
	zassert_equal(capsule.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_REPLAY);
}

ZTEST(pqcp_deployment_evidence_capsule, test_nonproduction_capsule_warns)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule capsule;

	zassert_equal(pqcp_archive_test_build_passport(
			      &fixture, board, top, nonce, false),
		      0);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &capsule),
		      0);
	zassert_false(capsule.production_allowed);
	zassert_equal(capsule.status,
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_WARN);
	zassert_equal(
		capsule.flags &
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PRODUCTION,
		0U);
}

ZTEST(pqcp_deployment_evidence_capsule, test_header_is_canonical)
{
	struct pqcp_archive_test_fixture fixture;
	struct pqcp_deployment_evidence_capsule capsule;

	build_fixture(&fixture);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &fixture.passport,
			      &fixture.passport_replay, NULL,
			      capsule_buffer, sizeof(capsule_buffer),
			      &capsule),
		      0);
	zassert_equal(capsule_buffer[0], 0x50U);
	zassert_equal(capsule_buffer[1], 0x50U);
	zassert_equal(capsule_buffer[2], 0x51U);
	zassert_equal(capsule_buffer[3], 0x43U);
	zassert_equal(capsule_buffer[4],
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_SCHEMA_VERSION);
	zassert_equal(capsule_buffer[12],
		      PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES);
}

ZTEST(pqcp_deployment_evidence_capsule, test_digest_changes_with_identity)
{
	struct pqcp_archive_test_fixture first_fixture;
	struct pqcp_archive_test_fixture second_fixture;
	struct pqcp_deployment_evidence_capsule first;
	struct pqcp_deployment_evidence_capsule second;
	uint8_t first_buffer[PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES];
	uint8_t second_buffer[PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES];

	zassert_equal(pqcp_archive_test_build_passport(
			      &first_fixture, board, top, nonce, true),
		      0);
	zassert_equal(pqcp_archive_test_build_passport(
			      &second_fixture, "nucleo_h743zi", top,
			      nonce, true),
		      0);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &first_fixture.passport,
			      &first_fixture.passport_replay, NULL,
			      first_buffer, sizeof(first_buffer), &first),
		      0);
	zassert_equal(pqcp_deployment_evidence_capsule_build(
			      &second_fixture.passport,
			      &second_fixture.passport_replay, NULL,
			      second_buffer, sizeof(second_buffer), &second),
		      0);
	zassert_not_equal(strcmp(first.capsule_digest_hex,
				 second.capsule_digest_hex),
			  0);
}

ZTEST(pqcp_deployment_evidence_capsule, test_emit_rejects_bad_summary)
{
	struct pqcp_deployment_evidence_capsule capsule = {
		.schema_version =
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_SCHEMA_VERSION,
		.record_count = 0U,
	};

	zassert_equal(
		pqcp_deployment_evidence_capsule_emit(&capsule),
		-EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_capsule, NULL, NULL, NULL, NULL, NULL);
