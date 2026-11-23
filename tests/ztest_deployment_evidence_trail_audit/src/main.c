/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the deployment evidence trail replay audit.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_trail_audit.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char top_b[] = "hybrid1024_87_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char head_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char head_b[] =
	"1111111111111111111111111111111111111111111111111111111111111111";

static void set_text(char *dst, size_t dst_size, const char *src)
{
	zassert_not_null(dst);
	zassert_not_null(src);
	zassert_true(dst_size > 0U);
	(void)snprintk(dst, dst_size, "%s", src);
}

static void fill_result(
	struct pqcp_deployment_evidence_trail_replay_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_SCHEMA_VERSION;
	result->lines_seen = 6U;
	result->marker_mask =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_REQUIRED_MASK;
	result->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE;
	result->trail_status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS;
	result->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	result->entry_count = 5U;
	result->observed_stage_mask = 0x1fU;
	result->passed = true;
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 top_a);
	set_text(result->nonce_hex, sizeof(result->nonce_hex), nonce_a);
	set_text(result->computed_head_digest_hex,
		 sizeof(result->computed_head_digest_hex), head_a);
}

ZTEST(pqcp_deployment_evidence_trail_audit, test_status_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_trail_audit_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_PASS),
			  "PASS");
	zassert_str_equal(pqcp_deployment_evidence_trail_audit_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARN),
			  "WARN");
	zassert_str_equal(pqcp_deployment_evidence_trail_audit_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_FAIL),
			  "FAIL");
	zassert_str_equal(pqcp_deployment_evidence_trail_audit_status_str(99),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_evidence_trail_audit, test_stable_results_pass)
{
	struct pqcp_deployment_evidence_trail_replay_result results[2];
	struct pqcp_deployment_evidence_trail_audit_policy policy;
	struct pqcp_deployment_evidence_trail_audit_report report;

	fill_result(&results[0]);
	fill_result(&results[1]);
	zassert_equal(pqcp_deployment_evidence_trail_audit_default_policy(
			      &policy),
		      0);

	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      results, 2U, &policy, &report),
		      0);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_PASS);
	zassert_equal(report.error_mask, 0U);
	zassert_equal(report.result_count, 2U);
	zassert_equal(report.replay_pass_count, 2U);
	zassert_equal(report.trail_pass_count, 2U);
	zassert_equal(report.entry_count, 5U);
	zassert_true(report.stable_head_digest);
	zassert_true(report.stable_entry_count);
	zassert_str_equal(report.head_digest_hex, head_a);
	zassert_equal(pqcp_deployment_evidence_trail_audit_emit(&report), 0);
}

ZTEST(pqcp_deployment_evidence_trail_audit, test_drift_is_detected)
{
	struct pqcp_deployment_evidence_trail_replay_result results[2];
	struct pqcp_deployment_evidence_trail_audit_policy policy;
	struct pqcp_deployment_evidence_trail_audit_report report;

	zassert_equal(pqcp_deployment_evidence_trail_audit_default_policy(
			      &policy),
		      0);

	/* Head digest drift. */
	fill_result(&results[0]);
	fill_result(&results[1]);
	set_text(results[1].computed_head_digest_hex,
		 sizeof(results[1].computed_head_digest_hex), head_b);
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_HEAD_DRIFT) !=
		     0U);
	zassert_false(report.stable_head_digest);

	/* Entry count drift. */
	fill_result(&results[0]);
	fill_result(&results[1]);
	results[1].entry_count = 4U;
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_COUNT_DRIFT) !=
		     0U);

	/* Stage drift. */
	fill_result(&results[0]);
	fill_result(&results[1]);
	results[1].observed_stage_mask = 0x0fU;
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_STAGE_DRIFT) !=
		     0U);

	/* Identity drift. */
	fill_result(&results[0]);
	fill_result(&results[1]);
	set_text(results[1].top_candidate_id,
		 sizeof(results[1].top_candidate_id), top_b);
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_TOP_DRIFT) !=
		     0U);
	zassert_str_equal(report.top_candidate_id, "none");
}

ZTEST(pqcp_deployment_evidence_trail_audit, test_replay_and_status_policy)
{
	struct pqcp_deployment_evidence_trail_replay_result result;
	struct pqcp_deployment_evidence_trail_audit_policy policy;
	struct pqcp_deployment_evidence_trail_audit_report report;

	zassert_equal(pqcp_deployment_evidence_trail_audit_default_policy(
			      &policy),
		      0);

	/* Replay failure blocks. */
	fill_result(&result);
	result.passed = false;
	result.first_error =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_HEAD_MISMATCH;
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_REPLAY_FAILED) !=
		     0U);

	/* Trail WARN status only warns by default. */
	fill_result(&result);
	result.trail_status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN;
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      &result, 1U, &policy, &report),
		      0);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARNING_TRAIL_NOT_PASS) !=
		     0U);

	/* Strict policy blocks non-PASS trails. */
	policy.require_trail_pass = true;
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_TRAIL_STATUS) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_trail_audit, test_invalid_inputs)
{
	struct pqcp_deployment_evidence_trail_replay_result result;
	struct pqcp_deployment_evidence_trail_audit_policy policy;
	struct pqcp_deployment_evidence_trail_audit_report report;

	fill_result(&result);
	zassert_equal(pqcp_deployment_evidence_trail_audit_default_policy(
			      &policy),
		      0);

	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      NULL, 1U, &policy, &report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      &result, 0U, &policy, &report),
		      -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_NO_RESULTS) !=
		     0U);
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      &result, 1U, NULL, &report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      &result, 1U, &policy, NULL),
		      -EINVAL);

	/* Malformed result shape. */
	fill_result(&result);
	result.entry_count = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES + 1U;
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_MALFORMED_RESULT) !=
		     0U);

	/* Emit validation. */
	fill_result(&result);
	zassert_equal(pqcp_deployment_evidence_trail_audit_run(
			      &result, 1U, &policy, &report),
		      0);
	zassert_equal(pqcp_deployment_evidence_trail_audit_emit(NULL),
		      -EINVAL);
	report.warning_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_evidence_trail_audit_emit(&report),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_trail_audit, NULL, NULL, NULL, NULL,
	    NULL);
