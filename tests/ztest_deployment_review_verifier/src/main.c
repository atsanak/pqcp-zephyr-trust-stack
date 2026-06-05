/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_review_verifier.h>

static const char *const clean_lines[] = {
	"PQCP_DEPLOYMENT_REVIEW_FACT schema=1 field=scenario id=review_product_m7 operation=kem target=cortex_m7 evidence_level=product hardware_required=0 native_required=1",
	"PQCP_DEPLOYMENT_REVIEW_FACT schema=1 field=pipeline status=PASS errors=0x00000000 candidates=3 gaps=0 top=mlkem768_m7 top_score=92 replay=PASS appraisal=PASS claims=PASS readiness=100 claim_score=94 trace_digest=4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e",
	"PQCP_DEPLOYMENT_REVIEW_FACT schema=1 field=budget status=PASS candidates=3 pass=3 warn=0 fail=0 blockers=0x00000000 warnings=0x00000000 top=mlkem768_m7 top_status=PASS top_margin=100",
	"PQCP_DEPLOYMENT_REVIEW_FACT schema=1 field=experiments status=PASS rows=0 blocking=0 recommended=0 top=mlkem768_m7 budget=PASS pipeline=PASS replay=PASS appraisal=PASS claims=PASS",
	"PQCP_DEPLOYMENT_REVIEW_PACKET schema=1 status=PASS errors=0x00000000 warnings=0x00000000 lines=4 bytes=805 digest=863c3f8ab7b174d111c5b497449e0d6f47e556b43aabef93c7caa7616f4416c3 trace_digest=4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e top=mlkem768_m7 candidates=3 experiments=0 blocking=0 readiness=100 claim_score=94 review_score=100 pipeline=PASS replay=PASS budget=PASS experiment_plan=PASS",
};

static const char clean_fact_buffer[] =
	"PQCP_DEPLOYMENT_REVIEW_FACT schema=1 field=scenario id=review_product_m7 operation=kem target=cortex_m7 evidence_level=product hardware_required=0 native_required=1\n"
	"PQCP_DEPLOYMENT_REVIEW_FACT schema=1 field=pipeline status=PASS errors=0x00000000 candidates=3 gaps=0 top=mlkem768_m7 top_score=92 replay=PASS appraisal=PASS claims=PASS readiness=100 claim_score=94 trace_digest=4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e\n"
	"PQCP_DEPLOYMENT_REVIEW_FACT schema=1 field=budget status=PASS candidates=3 pass=3 warn=0 fail=0 blockers=0x00000000 warnings=0x00000000 top=mlkem768_m7 top_status=PASS top_margin=100\n"
	"PQCP_DEPLOYMENT_REVIEW_FACT schema=1 field=experiments status=PASS rows=0 blocking=0 recommended=0 top=mlkem768_m7 budget=PASS pipeline=PASS replay=PASS appraisal=PASS claims=PASS\n";

static const struct pqcp_deployment_review_packet clean_packet = {
	.schema_version = PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION,
	.status = PQCP_DEPLOYMENT_REVIEW_PACKET_PASS,
	.error_mask = 0U,
	.warning_mask = 0U,
	.line_count = 4U,
	.byte_count = 805U,
	.candidate_count = 3U,
	.experiment_count = 0U,
	.blocking_experiment_count = 0U,
	.top_candidate_id = "mlkem768_m7",
	.readiness_score = 100U,
	.claim_score = 94U,
	.review_score = 100U,
	.pipeline_passed = true,
	.replay_passed = true,
	.budget_passed = true,
	.experiment_plan_passed = true,
	.trace_digest_hex =
		"4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e",
	.packet_digest_hex =
		"863c3f8ab7b174d111c5b497449e0d6f47e556b43aabef93c7caa7616f4416c3",
};

static int ingest_clean(
	struct pqcp_deployment_review_verifier_state *state,
	struct pqcp_deployment_review_verifier_result *result)
{
	int ret = pqcp_deployment_review_verifier_init(state);

	if (ret != 0) {
		return ret;
	}
	for (size_t i = 0U; i < ARRAY_SIZE(clean_lines); ++i) {
		ret = pqcp_deployment_review_verifier_ingest_line(
			state, clean_lines[i]);
		if (ret != 0) {
			return ret;
		}
	}

	return pqcp_deployment_review_verifier_finish(state, result);
}

ZTEST(pqcp_deployment_review_verifier,
      test_clean_review_packet_replays)
{
	struct pqcp_deployment_review_verifier_state state;
	struct pqcp_deployment_review_verifier_result result;

	zassert_equal(ingest_clean(&state, &result), 0);
	zassert_true(result.passed);
	zassert_equal(result.marker_mask,
		      PQCP_DEPLOYMENT_REVIEW_VERIFIER_REQUIRED_MASK);
	zassert_equal(result.fact_lines, 4U);
	zassert_equal(result.fact_bytes, 805U);
	zassert_equal(result.candidate_count, 3U);
	zassert_equal(result.review_score, 100U);
	zassert_mem_equal(result.computed_digest_hex,
			  clean_packet.packet_digest_hex,
			  strlen(clean_packet.packet_digest_hex));
	zassert_equal(pqcp_deployment_review_verifier_emit_result(&result), 0);
}

ZTEST(pqcp_deployment_review_verifier,
      test_verify_packet_helper_replays_fact_buffer)
{
	struct pqcp_deployment_review_verifier_result result;

	zassert_equal(pqcp_deployment_review_verifier_verify_packet(
			      clean_fact_buffer, &clean_packet, &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.lines_seen, 5U);
	zassert_equal(result.packet_status,
		      PQCP_DEPLOYMENT_REVIEW_PACKET_PASS);
	zassert_mem_equal(result.top_candidate_id, "mlkem768_m7",
			  strlen("mlkem768_m7"));
}

ZTEST(pqcp_deployment_review_verifier,
      test_tampered_fact_fails_digest_replay)
{
	struct pqcp_deployment_review_verifier_state state;
	struct pqcp_deployment_review_verifier_result result;

	zassert_equal(pqcp_deployment_review_verifier_init(&state), 0);
	zassert_equal(pqcp_deployment_review_verifier_ingest_line(
			      &state,
			      "PQCP_DEPLOYMENT_REVIEW_FACT schema=1 field=scenario id=review_product_x7 operation=kem target=cortex_m7 evidence_level=product hardware_required=0 native_required=1"),
		      0);
	for (size_t i = 1U; i < ARRAY_SIZE(clean_lines); ++i) {
		zassert_equal(pqcp_deployment_review_verifier_ingest_line(
				      &state, clean_lines[i]),
			      0);
	}
	zassert_equal(pqcp_deployment_review_verifier_finish(&state,
							     &result),
		      -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DIGEST_MISMATCH);
}

ZTEST(pqcp_deployment_review_verifier,
      test_missing_final_packet_fails)
{
	struct pqcp_deployment_review_verifier_state state;
	struct pqcp_deployment_review_verifier_result result;

	zassert_equal(pqcp_deployment_review_verifier_init(&state), 0);
	for (size_t i = 0U; i < ARRAY_SIZE(clean_lines) - 1U; ++i) {
		zassert_equal(pqcp_deployment_review_verifier_ingest_line(
				      &state, clean_lines[i]),
			      0);
	}
	zassert_equal(pqcp_deployment_review_verifier_finish(&state,
							     &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MISSING_REQUIRED);
}

ZTEST(pqcp_deployment_review_verifier,
      test_duplicate_fact_fails_immediately)
{
	struct pqcp_deployment_review_verifier_state state;

	zassert_equal(pqcp_deployment_review_verifier_init(&state), 0);
	zassert_equal(pqcp_deployment_review_verifier_ingest_line(
			      &state, clean_lines[0]),
		      0);
	zassert_equal(pqcp_deployment_review_verifier_ingest_line(
			      &state, clean_lines[0]),
		      -EBADMSG);
	zassert_equal(state.first_error,
		      PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DUPLICATE_MARKER);
}

ZTEST(pqcp_deployment_review_verifier,
      test_declared_line_count_mismatch_fails)
{
	struct pqcp_deployment_review_verifier_state state;
	struct pqcp_deployment_review_verifier_result result;

	zassert_equal(pqcp_deployment_review_verifier_init(&state), 0);
	for (size_t i = 0U; i < ARRAY_SIZE(clean_lines) - 1U; ++i) {
		zassert_equal(pqcp_deployment_review_verifier_ingest_line(
				      &state, clean_lines[i]),
			      0);
	}
	zassert_equal(pqcp_deployment_review_verifier_ingest_line(
			      &state,
			      "PQCP_DEPLOYMENT_REVIEW_PACKET schema=1 status=PASS errors=0x00000000 warnings=0x00000000 lines=5 bytes=805 digest=863c3f8ab7b174d111c5b497449e0d6f47e556b43aabef93c7caa7616f4416c3 trace_digest=4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e top=mlkem768_m7 candidates=3 experiments=0 blocking=0 readiness=100 claim_score=94 review_score=100 pipeline=PASS replay=PASS budget=PASS experiment_plan=PASS"),
		      0);
	zassert_equal(pqcp_deployment_review_verifier_finish(&state,
							     &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_LINE_COUNT_MISMATCH);
}

ZTEST(pqcp_deployment_review_verifier,
      test_status_contradiction_fails)
{
	struct pqcp_deployment_review_verifier_state state;
	struct pqcp_deployment_review_verifier_result result;

	zassert_equal(pqcp_deployment_review_verifier_init(&state), 0);
	for (size_t i = 0U; i < ARRAY_SIZE(clean_lines) - 1U; ++i) {
		zassert_equal(pqcp_deployment_review_verifier_ingest_line(
				      &state, clean_lines[i]),
			      0);
	}
	zassert_equal(pqcp_deployment_review_verifier_ingest_line(
			      &state,
			      "PQCP_DEPLOYMENT_REVIEW_PACKET schema=1 status=PASS errors=0x00000000 warnings=0x00000000 lines=4 bytes=805 digest=863c3f8ab7b174d111c5b497449e0d6f47e556b43aabef93c7caa7616f4416c3 trace_digest=4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e top=mlkem768_m7 candidates=3 experiments=0 blocking=0 readiness=100 claim_score=94 review_score=100 pipeline=FAIL replay=PASS budget=PASS experiment_plan=PASS"),
		      -EBADMSG);
	zassert_equal(pqcp_deployment_review_verifier_finish(&state,
							     &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_COUNT_MISMATCH);
}

ZTEST(pqcp_deployment_review_verifier,
      test_error_tokens_are_stable)
{
	zassert_mem_equal(
		pqcp_deployment_review_verifier_error_str(
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DIGEST_MISMATCH),
		"digest_mismatch", strlen("digest_mismatch"));
	zassert_mem_equal(
		pqcp_deployment_review_verifier_error_str(
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_UNKNOWN_MARKER),
		"unknown_marker", strlen("unknown_marker"));
}

ZTEST_SUITE(pqcp_deployment_review_verifier, NULL, NULL, NULL, NULL, NULL);
