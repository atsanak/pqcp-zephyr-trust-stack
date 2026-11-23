/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the deterministic evidence tamper engine.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_tamper_engine.h>

static const char sample_line[] =
	"PQCP_DEMO_MARKER schema=1 profile=product status=PASS score=87 "
	"top=hybrid768_65_campaign nonce=00112233445566778899aabbccddeeff "
	"seal_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

ZTEST(pqcp_deployment_tamper_engine, test_class_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_tamper_class_str(
				  PQCP_DEPLOYMENT_TAMPER_NONE),
			  "control");
	zassert_str_equal(pqcp_deployment_tamper_class_str(
				  PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP),
			  "digest_flip");
	zassert_str_equal(pqcp_deployment_tamper_class_str(
				  PQCP_DEPLOYMENT_TAMPER_OMIT),
			  "omit");
	zassert_str_equal(pqcp_deployment_tamper_class_str(99), "unknown");
}

ZTEST(pqcp_deployment_tamper_engine, test_line_mutation_classification)
{
	zassert_false(pqcp_deployment_tamper_class_mutates_line(
		PQCP_DEPLOYMENT_TAMPER_NONE));
	zassert_false(pqcp_deployment_tamper_class_mutates_line(
		PQCP_DEPLOYMENT_TAMPER_DUPLICATE));
	zassert_false(pqcp_deployment_tamper_class_mutates_line(
		PQCP_DEPLOYMENT_TAMPER_OMIT));
	zassert_true(pqcp_deployment_tamper_class_mutates_line(
		PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP));
	zassert_true(pqcp_deployment_tamper_class_mutates_line(
		PQCP_DEPLOYMENT_TAMPER_TRUNCATE));
}

ZTEST(pqcp_deployment_tamper_engine, test_control_copies_line_unchanged)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_NONE, 7U, NULL,
			      sample_line, out, sizeof(out), &record),
		      0);
	zassert_str_equal(out, sample_line);
	zassert_false(record.applied);
	zassert_equal(record.schema_version,
		      PQCP_DEPLOYMENT_TAMPER_ENGINE_SCHEMA_VERSION);
}

ZTEST(pqcp_deployment_tamper_engine, test_digest_flip_is_deterministic)
{
	struct pqcp_deployment_tamper_record record_a;
	struct pqcp_deployment_tamper_record record_b;
	char out_a[256];
	char out_b[256];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP, 1234U,
			      "seal_digest", sample_line, out_a,
			      sizeof(out_a), &record_a),
		      0);
	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP, 1234U,
			      "seal_digest", sample_line, out_b,
			      sizeof(out_b), &record_b),
		      0);
	zassert_str_equal(out_a, out_b);
	zassert_equal(record_a.offset, record_b.offset);
	zassert_true(record_a.applied);
	zassert_true(strcmp(out_a, sample_line) != 0);
	zassert_str_equal(record_a.field_key, "seal_digest");
	/* The flipped character stays lowercase hex. */
	zassert_true((record_a.mutated_char >= '0' &&
		      record_a.mutated_char <= '9') ||
		     (record_a.mutated_char >= 'a' &&
		      record_a.mutated_char <= 'f'));
	zassert_not_equal(record_a.mutated_char, record_a.original_char);
}

ZTEST(pqcp_deployment_tamper_engine, test_status_forge_swaps_token)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_STATUS_FORGE, 0U, NULL,
			      sample_line, out, sizeof(out), &record),
		      0);
	zassert_true(record.applied);
	zassert_not_null(strstr(out, "status=WARN"));
	zassert_is_null(strstr(out, "status=PASS"));
}

ZTEST(pqcp_deployment_tamper_engine, test_score_inflate_changes_score)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_SCORE_INFLATE, 0U, NULL,
			      sample_line, out, sizeof(out), &record),
		      0);
	zassert_true(record.applied);
	zassert_is_null(strstr(out, "score=87"));
	zassert_not_null(strstr(out, "score=97"));
}

ZTEST(pqcp_deployment_tamper_engine, test_schema_bump_rewrites_schema)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_SCHEMA_BUMP, 0U, NULL,
			      sample_line, out, sizeof(out), &record),
		      0);
	zassert_not_null(strstr(out, "schema=99"));
}

ZTEST(pqcp_deployment_tamper_engine, test_nonce_swap_keeps_shape)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];
	const char *nonce;

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_NONCE_SWAP, 0U, NULL,
			      sample_line, out, sizeof(out), &record),
		      0);
	nonce = strstr(out, "nonce=");
	zassert_not_null(nonce);
	nonce += strlen("nonce=");
	for (size_t i = 0U; i < 32U; ++i) {
		zassert_true((nonce[i] >= '0' && nonce[i] <= '9') ||
			     (nonce[i] >= 'a' && nonce[i] <= 'f'));
	}
	zassert_true(strncmp(nonce, "00112233445566778899aabbccddeeff",
			     32U) != 0);
}

ZTEST(pqcp_deployment_tamper_engine, test_profile_swap_changes_profile)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_PROFILE_SWAP, 0U, NULL,
			      sample_line, out, sizeof(out), &record),
		      0);
	zassert_is_null(strstr(out, "profile=product"));
	zassert_not_null(strstr(out, "profile="));
}

ZTEST(pqcp_deployment_tamper_engine, test_field_strip_removes_field)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_FIELD_STRIP, 0U,
			      "seal_digest", sample_line, out, sizeof(out),
			      &record),
		      0);
	zassert_is_null(strstr(out, "seal_digest="));
	zassert_not_null(strstr(out, "nonce="));
}

ZTEST(pqcp_deployment_tamper_engine, test_truncate_shortens_line)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_TRUNCATE, 0U, NULL,
			      sample_line, out, sizeof(out), &record),
		      0);
	zassert_equal(strlen(out), (strlen(sample_line) * 2U) / 3U);
	zassert_true(strncmp(out, sample_line, strlen(out)) == 0);
}

ZTEST(pqcp_deployment_tamper_engine, test_bit_noise_mutates_value_char)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_BIT_NOISE, 99U, "top",
			      sample_line, out, sizeof(out), &record),
		      0);
	zassert_true(record.applied);
	zassert_true(strcmp(out, sample_line) != 0);
	zassert_str_equal(record.field_key, "top");
}

ZTEST(pqcp_deployment_tamper_engine, test_error_paths)
{
	struct pqcp_deployment_tamper_record record;
	char out[256];
	char tiny[8];

	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_NONE, 0U, NULL, NULL,
			      out, sizeof(out), &record),
		      -EINVAL);
	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_NONE, 0U, NULL,
			      sample_line, NULL, 0U, &record),
		      -EINVAL);
	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_NONE, 0U, NULL,
			      sample_line, out, sizeof(out), NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_tamper_apply(
			      99, 0U, NULL, sample_line, out, sizeof(out),
			      &record),
		      -EINVAL);
	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP, 0U, NULL,
			      sample_line, out, sizeof(out), &record),
		      -EINVAL);
	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_DIGEST_FLIP, 0U,
			      "absent_field", sample_line, out, sizeof(out),
			      &record),
		      -ENOENT);
	zassert_equal(pqcp_deployment_tamper_apply(
			      PQCP_DEPLOYMENT_TAMPER_NONE, 0U, NULL,
			      sample_line, tiny, sizeof(tiny), &record),
		      -ENOSPC);
}

ZTEST_SUITE(pqcp_deployment_tamper_engine, NULL, NULL, NULL, NULL, NULL);
