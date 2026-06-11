/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for the tamper matrix replay audit.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_tamper_matrix_audit.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char top_b[] = "hybrid1024_87_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char matrix_digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char matrix_digest_b[] =
	"1111111111111111111111111111111111111111111111111111111111111111";
static const char passport_digest_a[] =
	"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

static void set_text(char *dst, size_t dst_size, const char *src)
{
	zassert_not_null(dst);
	zassert_not_null(src);
	zassert_true(dst_size > 0U);
	(void)snprintk(dst, dst_size, "%s", src);
}

static void fill_result(
	struct pqcp_deployment_tamper_matrix_replay_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_SCHEMA_VERSION;
	result->lines_seen = 1U;
	result->marker_mask =
		PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_REQUIRED_MASK;
	result->first_error = PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE;
	result->matrix_status = PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS;
	result->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	result->stage_mask = PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_KNOWN_MASK;
	result->cell_count = 36U;
	result->attack_count = 33U;
	result->detected_count = 33U;
	result->missed_count = 0U;
	result->control_pass_count = 3U;
	result->coverage_permille = 1000U;
	result->passed = true;
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 top_a);
	set_text(result->nonce_hex, sizeof(result->nonce_hex), nonce_a);
	set_text(result->passport_digest_hex,
		 sizeof(result->passport_digest_hex), passport_digest_a);
	set_text(result->computed_digest_hex,
		 sizeof(result->computed_digest_hex), matrix_digest_a);
}

ZTEST(pqcp_deployment_tamper_matrix_audit, test_status_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_tamper_matrix_audit_status_str(
				  PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_PASS),
			  "PASS");
	zassert_str_equal(pqcp_deployment_tamper_matrix_audit_status_str(
				  PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARN),
			  "WARN");
	zassert_str_equal(pqcp_deployment_tamper_matrix_audit_status_str(
				  PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_FAIL),
			  "FAIL");
	zassert_str_equal(pqcp_deployment_tamper_matrix_audit_status_str(99),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_tamper_matrix_audit, test_stable_results_pass)
{
	struct pqcp_deployment_tamper_matrix_replay_result results[2];
	struct pqcp_deployment_tamper_matrix_audit_policy policy;
	struct pqcp_deployment_tamper_matrix_audit_report report;

	fill_result(&results[0]);
	fill_result(&results[1]);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_default_policy(
			      &policy),
		      0);

	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      results, 2U, &policy, &report),
		      0);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_PASS);
	zassert_equal(report.error_mask, 0U);
	zassert_equal(report.warning_mask, 0U);
	zassert_equal(report.result_count, 2U);
	zassert_equal(report.replay_pass_count, 2U);
	zassert_equal(report.matrix_pass_count, 2U);
	zassert_equal(report.min_coverage_permille, 1000U);
	zassert_equal(report.max_coverage_permille, 1000U);
	zassert_equal(report.avg_coverage_permille, 1000U);
	zassert_equal(report.total_attack_count, 66U);
	zassert_equal(report.total_detected_count, 66U);
	zassert_true(report.stable_matrix_digest);
	zassert_true(report.stable_coverage);
	zassert_str_equal(report.matrix_digest_hex, matrix_digest_a);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_emit(&report), 0);
}

ZTEST(pqcp_deployment_tamper_matrix_audit, test_drift_is_detected)
{
	struct pqcp_deployment_tamper_matrix_replay_result results[2];
	struct pqcp_deployment_tamper_matrix_audit_policy policy;
	struct pqcp_deployment_tamper_matrix_audit_report report;

	zassert_equal(pqcp_deployment_tamper_matrix_audit_default_policy(
			      &policy),
		      0);

	/* Digest drift. */
	fill_result(&results[0]);
	fill_result(&results[1]);
	set_text(results[1].computed_digest_hex,
		 sizeof(results[1].computed_digest_hex), matrix_digest_b);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_DIGEST_DRIFT) !=
		     0U);
	zassert_false(report.stable_matrix_digest);

	/* Coverage drift plus floor breach. */
	fill_result(&results[0]);
	fill_result(&results[1]);
	results[1].coverage_permille = 800U;
	results[1].detected_count = 26U;
	results[1].missed_count = 7U;
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_COVERAGE_DRIFT) !=
		     0U);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_COVERAGE_FLOOR) !=
		     0U);
	zassert_equal(report.min_coverage_permille, 800U);

	/* Top candidate drift. */
	fill_result(&results[0]);
	fill_result(&results[1]);
	set_text(results[1].top_candidate_id,
		 sizeof(results[1].top_candidate_id), top_b);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_TOP_DRIFT) !=
		     0U);
	zassert_str_equal(report.top_candidate_id, "none");
}

ZTEST(pqcp_deployment_tamper_matrix_audit, test_replay_failure_blocks)
{
	struct pqcp_deployment_tamper_matrix_replay_result result;
	struct pqcp_deployment_tamper_matrix_audit_policy policy;
	struct pqcp_deployment_tamper_matrix_audit_report report;

	fill_result(&result);
	result.passed = false;
	result.first_error =
		PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DIGEST_MISMATCH;
	zassert_equal(pqcp_deployment_tamper_matrix_audit_default_policy(
			      &policy),
		      0);

	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_FAIL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_REPLAY_FAILED) !=
		     0U);
}

ZTEST(pqcp_deployment_tamper_matrix_audit, test_matrix_status_policy)
{
	struct pqcp_deployment_tamper_matrix_replay_result result;
	struct pqcp_deployment_tamper_matrix_audit_policy policy;
	struct pqcp_deployment_tamper_matrix_audit_report report;

	fill_result(&result);
	result.matrix_status = PQCP_DEPLOYMENT_TAMPER_MATRIX_WARN;
	zassert_equal(pqcp_deployment_tamper_matrix_audit_default_policy(
			      &policy),
		      0);

	/* Default policy tolerates WARN matrices with a warning. */
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      &result, 1U, &policy, &report),
		      0);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_WARNING_MATRIX_NOT_PASS) !=
		     0U);

	/* Strict policy blocks. */
	policy.require_matrix_pass = true;
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_MATRIX_STATUS) !=
		     0U);
}

ZTEST(pqcp_deployment_tamper_matrix_audit, test_invalid_inputs)
{
	struct pqcp_deployment_tamper_matrix_replay_result result;
	struct pqcp_deployment_tamper_matrix_audit_policy policy;
	struct pqcp_deployment_tamper_matrix_audit_report report;

	fill_result(&result);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_default_policy(
			      &policy),
		      0);

	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      NULL, 1U, &policy, &report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      &result, 0U, &policy, &report),
		      -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_NO_RESULTS) !=
		     0U);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      &result, 1U, NULL, &report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      &result, 1U, &policy, NULL),
		      -EINVAL);

	/* Malformed result shape. */
	fill_result(&result);
	result.coverage_permille = 1001U;
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT_ERROR_MALFORMED_RESULT) !=
		     0U);
}

ZTEST(pqcp_deployment_tamper_matrix_audit, test_emit_rejects_invalid_report)
{
	struct pqcp_deployment_tamper_matrix_replay_result result;
	struct pqcp_deployment_tamper_matrix_audit_policy policy;
	struct pqcp_deployment_tamper_matrix_audit_report report;

	fill_result(&result);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_default_policy(
			      &policy),
		      0);
	zassert_equal(pqcp_deployment_tamper_matrix_audit_run(
			      &result, 1U, &policy, &report),
		      0);

	zassert_equal(pqcp_deployment_tamper_matrix_audit_emit(NULL),
		      -EINVAL);

	report.schema_version = 99U;
	zassert_equal(pqcp_deployment_tamper_matrix_audit_emit(&report),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_tamper_matrix_audit, NULL, NULL, NULL, NULL,
	    NULL);
