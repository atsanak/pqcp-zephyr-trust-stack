/*
 * SPDX-License-Identifier: MIT
 *
 * Deployment trace-builder tests.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_trace_builder.h>

#define PRODUCT_EVIDENCE \
	(PQCP_DEPLOYMENT_EVIDENCE_KAT | \
	 PQCP_DEPLOYMENT_EVIDENCE_ACVP | \
	 PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE | \
	 PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE | \
	 PQCP_DEPLOYMENT_EVIDENCE_HARDWARE | \
	 PQCP_DEPLOYMENT_EVIDENCE_POLICY | \
	 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER | \
	 PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT | \
	 PQCP_DEPLOYMENT_EVIDENCE_RESOURCE | \
	 PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE)

#define EXPECTED_SCENARIO \
	"PQCP_DEPLOYMENT_SCENARIO schema=1 id=lab_kem_decision operation=kem target=any security=3 preference=balanced evidence_level=prototype latency_budget_us=10000 ram_budget=65536 stack_budget=16384 heap_budget=4096 flash_budget=262144 energy_budget_uj=0 native_required=1 hardware_required=0\n"

static const struct pqcp_deployment_scenario scenario = {
	.scenario_id = "lab_kem_decision",
	.operation = PQCP_DEPLOYMENT_OPERATION_KEM,
	.target_class = PQCP_DEPLOYMENT_TARGET_ANY,
	.minimum_security_level = 3U,
	.latency_budget_us = 10000U,
	.ram_budget_bytes = 65536U,
	.stack_budget_bytes = 16384U,
	.heap_budget_bytes = 4096U,
	.flash_budget_bytes = 262144U,
	.preference = PQCP_DEPLOYMENT_PREFERENCE_BALANCED,
	.required_evidence_level = PQCP_DEPLOYMENT_EVIDENCE_LEVEL_PROTOTYPE,
	.require_native_provider = true,
};

static const struct pqcp_deployment_candidate candidates[] = {
	{
		.candidate_id = "mlkem768_m7",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
		.security_level = 3U,
		.mlkem_level = 768U,
		.latency_us = 6200U,
		.cycles = 2480000U,
		.ram_bytes = 31000U,
		.stack_bytes = 6400U,
		.heap_bytes = 1200U,
		.flash_bytes = 148000U,
		.evidence_mask = PRODUCT_EVIDENCE,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	},
};

static int build_trace(char *buffer, size_t buffer_size,
		       struct pqcp_deployment_trace_digest *digest)
{
	struct pqcp_deployment_candidate_result results[ARRAY_SIZE(candidates)];
	struct pqcp_deployment_candidate_robustness robustness[
		ARRAY_SIZE(candidates)];
	struct pqcp_deployment_report report;
	struct pqcp_deployment_robustness_report robustness_report;
	struct pqcp_deployment_trace_builder builder;
	int ret;

	ret = pqcp_deployment_robustness_analyze(
		&scenario, candidates, ARRAY_SIZE(candidates), results,
		robustness, &report, &robustness_report);
	zassert_equal(ret, 0);
	zassert_equal(pqcp_deployment_trace_builder_init(
			      &builder, buffer, buffer_size), 0);
	zassert_equal(pqcp_deployment_trace_builder_append_scenario(
			      &builder, &scenario), 0);
	for (size_t i = 0U; i < ARRAY_SIZE(candidates); ++i) {
		zassert_equal(pqcp_deployment_trace_builder_append_candidate(
				      &builder, &scenario, &candidates[i],
				      &results[i]), 0);
		zassert_equal(
			pqcp_deployment_trace_builder_append_robust_candidate(
				&builder, &robustness[i]), 0);
	}
	zassert_equal(pqcp_deployment_trace_builder_append_decision(
			      &builder, &report, results), 0);
	zassert_equal(pqcp_deployment_trace_builder_append_robustness(
			      &builder, &robustness_report, robustness), 0);
	return pqcp_deployment_trace_builder_finish(&builder, digest);
}

ZTEST(pqcp_deployment_trace_builder, test_exact_scenario_line_format)
{
	struct pqcp_deployment_trace_builder builder;
	char buffer[512];

	zassert_equal(pqcp_deployment_trace_builder_init(
			      &builder, buffer, sizeof(buffer)), 0);
	zassert_equal(pqcp_deployment_trace_builder_append_scenario(
			      &builder, &scenario), 0);
	zassert_true(strcmp(buffer, EXPECTED_SCENARIO) == 0,
		     "scenario marker changed: %s", buffer);
}

ZTEST(pqcp_deployment_trace_builder, test_overflow_failure_is_recorded)
{
	struct pqcp_deployment_trace_builder builder;
	char buffer[32];

	zassert_equal(pqcp_deployment_trace_builder_init(
			      &builder, buffer, sizeof(buffer)), 0);
	zassert_equal(pqcp_deployment_trace_builder_append_scenario(
			      &builder, &scenario), -ENOSPC);
	zassert_true((builder.error_mask &
		      PQCP_DEPLOYMENT_TRACE_ERROR_OVERFLOW) != 0U);
}

ZTEST(pqcp_deployment_trace_builder, test_digest_is_stable)
{
	struct pqcp_deployment_trace_digest first;
	struct pqcp_deployment_trace_digest second;
	char first_buffer[4096];
	char second_buffer[4096];

	zassert_equal(build_trace(first_buffer, sizeof(first_buffer), &first), 0);
	zassert_equal(build_trace(second_buffer, sizeof(second_buffer), &second),
		      0);
	zassert_true(strcmp(first.digest_hex, second.digest_hex) == 0);
	zassert_equal(first.line_count, second.line_count);
	zassert_equal(first.byte_count, second.byte_count);
	zassert_true(strcmp(first_buffer, second_buffer) == 0);
}

ZTEST(pqcp_deployment_trace_builder, test_replay_success_and_digest_emit)
{
	struct pqcp_deployment_trace_digest digest;
	char buffer[4096];

	zassert_equal(build_trace(buffer, sizeof(buffer), &digest), 0);
	zassert_true(digest.passed);
	zassert_true(digest.replay_result.passed);
	zassert_equal(digest.replay_result.candidate_count,
		      ARRAY_SIZE(candidates));
	zassert_equal(pqcp_deployment_trace_digest_emit(&digest), 0);
}

ZTEST(pqcp_deployment_trace_builder, test_tamper_failure_is_detected)
{
	static const char *const lines[] = {
		"PQCP_DEPLOYMENT_SCENARIO schema=1 id=lab_kem_decision operation=kem target=any security=3 preference=balanced evidence_level=prototype latency_budget_us=10000 ram_budget=65536 stack_budget=16384 heap_budget=4096 flash_budget=262144 energy_budget_uj=0 native_required=1 hardware_required=0",
		"PQCP_DEPLOYMENT_CANDIDATE scenario=lab_kem_decision rank=1 id=mlkem768_m7 kind=mlkem target=cortex_m7 status=ACCEPTED score=70 confidence=90 blockers=0x00000000 gaps=0x00000000 security=3 mlkem=768 mldsa=0 latency_us=6200 ram=31000 stack=6400 heap=1200 flash=148000 energy_uj=0 evidence=0x00000fff independent=1",
		"PQCP_DEPLOYMENT_ROBUSTNESS_CANDIDATE schema=1 index=0 id=mlkem768_m7 status=ROBUST score=60 configured=0x0000001f measured=0x0000001f missing=0x00000000 binding=flash min_headroom_permille=435 avg_headroom_permille=550 preference_wins=0x0000000f stress_pass=0x0000000f max_reduction_percent=40 dominates=0 dominated_by=0 pareto=1 complete=1",
		"PQCP_DEPLOYMENT_DECISION schema=1 id=lab_kem_decision status=PASS candidates=1 feasible=1 accepted=1 conditional=0 rejected=0 top=missing_top top_score=70 top_confidence=90",
		"PQCP_DEPLOYMENT_ROBUSTNESS schema=1 id=lab_kem_decision status=ROBUST candidates=1 feasible=1 frontier=1 top=mlkem768_m7 top_score=60 top_preference_wins=4 stable=1 robust=1",
	};
	struct pqcp_deployment_trace_builder builder;
	struct pqcp_deployment_trace_digest digest;
	char buffer[4096];

	zassert_equal(pqcp_deployment_trace_builder_init(
			      &builder, buffer, sizeof(buffer)), 0);
	for (size_t i = 0U; i < ARRAY_SIZE(lines); ++i) {
		(void)pqcp_deployment_trace_builder_append_line(
			&builder, lines[i]);
	}
	zassert_equal(pqcp_deployment_trace_builder_finish(
			      &builder, &digest), -EBADMSG);
	zassert_false(digest.passed);
	zassert_equal(digest.replay_result.first_error,
		      PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_TOP_MISMATCH);
}

ZTEST(pqcp_deployment_trace_builder, test_missing_marker_failure)
{
	struct pqcp_deployment_trace_builder builder;
	struct pqcp_deployment_trace_digest digest;
	char buffer[512];

	zassert_equal(pqcp_deployment_trace_builder_init(
			      &builder, buffer, sizeof(buffer)), 0);
	zassert_equal(pqcp_deployment_trace_builder_append_scenario(
			      &builder, &scenario), 0);
	zassert_equal(pqcp_deployment_trace_builder_finish(
			      &builder, &digest), -EBADMSG);
	zassert_false(digest.passed);
	zassert_equal(digest.replay_result.first_error,
		      PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MISSING_REQUIRED);
}

ZTEST(pqcp_deployment_trace_builder, test_duplicate_marker_failure)
{
	struct pqcp_deployment_trace_builder builder;
	struct pqcp_deployment_trace_digest digest;
	char buffer[1024];

	zassert_equal(pqcp_deployment_trace_builder_init(
			      &builder, buffer, sizeof(buffer)), 0);
	zassert_equal(pqcp_deployment_trace_builder_append_scenario(
			      &builder, &scenario), 0);
	zassert_equal(pqcp_deployment_trace_builder_append_scenario(
			      &builder, &scenario),
		      -EBADMSG);
	zassert_true((builder.error_mask &
		      PQCP_DEPLOYMENT_TRACE_ERROR_REPLAY_APPEND) != 0U);
	zassert_equal(pqcp_deployment_trace_builder_finish(
			      &builder, &digest), -EBADMSG);
	zassert_false(digest.passed);
	zassert_equal(digest.replay_result.first_error,
		      PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_DUPLICATE_SUMMARY);
}

ZTEST_SUITE(pqcp_deployment_trace_builder, NULL, NULL, NULL, NULL, NULL);
