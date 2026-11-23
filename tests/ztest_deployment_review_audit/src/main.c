/*
 * SPDX-License-Identifier: MIT
 */

#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_review_audit.h>

static struct pqcp_deployment_review_verifier_result pass_result(void)
{
	return (struct pqcp_deployment_review_verifier_result) {
		.schema_version =
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION,
		.lines_seen = 5U,
		.marker_mask = PQCP_DEPLOYMENT_REVIEW_VERIFIER_REQUIRED_MASK,
		.fact_lines = 4U,
		.fact_bytes = 805U,
		.candidate_count = 3U,
		.experiment_count = 0U,
		.blocking_count = 0U,
		.readiness_score = 100U,
		.claim_score = 94U,
		.review_score = 100U,
		.first_error_line = 0U,
		.first_error = PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_NONE,
		.packet_status = PQCP_DEPLOYMENT_REVIEW_PACKET_PASS,
		.passed = true,
		.top_candidate_id = "mlkem768_m7",
		.trace_digest_hex =
			"4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e",
		.computed_digest_hex =
			"863c3f8ab7b174d111c5b497449e0d6f47e556b43aabef93c7caa7616f4416c3",
	};
}

static struct pqcp_deployment_review_verifier_result warning_result(void)
{
	struct pqcp_deployment_review_verifier_result result = pass_result();

	result.packet_status = PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
	result.experiment_count = 18U;
	result.blocking_count = 17U;
	result.readiness_score = 88U;
	result.claim_score = 71U;
	result.review_score = 20U;
	(void)snprintk(result.top_candidate_id, sizeof(result.top_candidate_id),
		       "%s", "hybrid768_65_campaign");
	(void)snprintk(result.trace_digest_hex, sizeof(result.trace_digest_hex),
		       "%s",
		       "e2ed1c1657db0daf61af8f0cb19f0b244b4830b7413ac11b350e2165c8cd8e05");
	(void)snprintk(result.computed_digest_hex,
		       sizeof(result.computed_digest_hex), "%s",
		       "3d27fb0742a4c3cc59e0d679c4c4c4565d0f32967498f03a1589c6c26875a8ca");

	return result;
}

static void default_policy(
	struct pqcp_deployment_review_audit_policy *policy)
{
	zassert_equal(pqcp_deployment_review_audit_default_policy(policy), 0);
}

ZTEST(pqcp_deployment_review_audit, test_single_pass_result_passes)
{
	struct pqcp_deployment_review_verifier_result result = pass_result();
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	zassert_equal(pqcp_deployment_review_audit_run(&result, 1U, &policy,
						       &report),
		      0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS);
	zassert_equal(report.result_count, 1U);
	zassert_equal(report.replay_pass_count, 1U);
	zassert_equal(report.packet_pass_count, 1U);
	zassert_equal(report.unique_packet_digest_count, 1U);
	zassert_true(report.stable_top_candidate);
	zassert_true(report.stable_trace_digest);
	zassert_true(report.stable_packet_digest);
	zassert_equal(report.avg_review_score, 100U);
	zassert_equal(pqcp_deployment_review_audit_emit(&report), 0);
}

ZTEST(pqcp_deployment_review_audit, test_packet_fail_allowed_warns)
{
	struct pqcp_deployment_review_verifier_result result = warning_result();
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	zassert_equal(pqcp_deployment_review_audit_run(&result, 1U, &policy,
						       &report),
		      0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_NOT_PASS) !=
		     0U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_REVIEW_SCORE) !=
		     0U);
	zassert_equal(pqcp_deployment_review_audit_emit(&report), 0);
}

ZTEST(pqcp_deployment_review_audit, test_packet_pass_required_fails)
{
	struct pqcp_deployment_review_verifier_result result = warning_result();
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	policy.require_packet_pass = true;
	zassert_equal(pqcp_deployment_review_audit_run(&result, 1U, &policy,
						       &report),
		      -EBADMSG);
	zassert_equal(report.status, PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_PACKET_STATUS) != 0U);
}

ZTEST(pqcp_deployment_review_audit, test_failed_replay_fails)
{
	struct pqcp_deployment_review_verifier_result result = pass_result();
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	result.passed = false;
	result.first_error =
		PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DIGEST_MISMATCH;
	zassert_equal(pqcp_deployment_review_audit_run(&result, 1U, &policy,
						       &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_REPLAY_FAILED) !=
		     0U);
}

ZTEST(pqcp_deployment_review_audit, test_top_drift_fails)
{
	struct pqcp_deployment_review_verifier_result results[2] = {
		pass_result(), pass_result()
	};
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	(void)snprintk(results[1].top_candidate_id,
		       sizeof(results[1].top_candidate_id), "%s",
		       "hybrid768_65_m7");
	zassert_equal(pqcp_deployment_review_audit_run(results,
						       ARRAY_SIZE(results),
						       &policy, &report),
		      -EBADMSG);
	zassert_false(report.stable_top_candidate);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_TOP_DRIFT) != 0U);
}

ZTEST(pqcp_deployment_review_audit, test_trace_digest_drift_fails)
{
	struct pqcp_deployment_review_verifier_result results[2] = {
		pass_result(), pass_result()
	};
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	(void)snprintk(results[1].trace_digest_hex,
		       sizeof(results[1].trace_digest_hex), "%s",
		       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	zassert_equal(pqcp_deployment_review_audit_run(results,
						       ARRAY_SIZE(results),
						       &policy, &report),
		      -EBADMSG);
	zassert_false(report.stable_trace_digest);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_TRACE_DIGEST_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_review_audit, test_packet_digest_diversity_warns)
{
	struct pqcp_deployment_review_verifier_result results[2] = {
		pass_result(), pass_result()
	};
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	(void)snprintk(results[1].computed_digest_hex,
		       sizeof(results[1].computed_digest_hex), "%s",
		       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
	zassert_equal(pqcp_deployment_review_audit_run(results,
						       ARRAY_SIZE(results),
						       &policy, &report),
		      0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN);
	zassert_false(report.stable_packet_digest);
	zassert_equal(report.unique_packet_digest_count, 2U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_DIVERSITY) !=
		     0U);
}

ZTEST(pqcp_deployment_review_audit, test_packet_digest_stability_required_fails)
{
	struct pqcp_deployment_review_verifier_result results[2] = {
		pass_result(), pass_result()
	};
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	policy.require_stable_packet_digest = true;
	(void)snprintk(results[1].computed_digest_hex,
		       sizeof(results[1].computed_digest_hex), "%s",
		       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
	zassert_equal(pqcp_deployment_review_audit_run(results,
						       ARRAY_SIZE(results),
						       &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_PACKET_DIGEST_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_review_audit, test_low_sample_count_warns)
{
	struct pqcp_deployment_review_verifier_result result = pass_result();
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	policy.minimum_results = 2U;
	zassert_equal(pqcp_deployment_review_audit_run(&result, 1U, &policy,
						       &report),
		      0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_SAMPLE_COUNT) !=
		     0U);
}

ZTEST(pqcp_deployment_review_audit, test_invalid_score_fails)
{
	struct pqcp_deployment_review_verifier_result result = pass_result();
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	result.review_score = 101U;
	zassert_equal(pqcp_deployment_review_audit_run(&result, 1U, &policy,
						       &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_SCORE_RANGE) != 0U);
}

ZTEST(pqcp_deployment_review_audit, test_no_results_fails)
{
	struct pqcp_deployment_review_audit_policy policy;
	struct pqcp_deployment_review_audit_report report;

	default_policy(&policy);
	zassert_equal(pqcp_deployment_review_audit_run(NULL, 0U, &policy,
						       &report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_review_audit_run((void *)1, 0U,
						       &policy, &report),
		      -ENODATA);
	zassert_equal(report.error_mask,
		      PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_NO_RESULTS);
}

ZTEST(pqcp_deployment_review_audit, test_status_tokens_are_stable)
{
	zassert_mem_equal(
		pqcp_deployment_review_audit_status_str(
			PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS),
		"PASS", strlen("PASS"));
	zassert_mem_equal(
		pqcp_deployment_review_audit_status_str(
			PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN),
		"WARN", strlen("WARN"));
	zassert_mem_equal(
		pqcp_deployment_review_audit_status_str(
			PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL),
		"FAIL", strlen("FAIL"));
}

ZTEST_SUITE(pqcp_deployment_review_audit, NULL, NULL, NULL, NULL, NULL);
