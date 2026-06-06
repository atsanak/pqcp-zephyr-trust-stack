/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for firmware-native deployment device-token replay audit aggregation.
 */

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/deployment_device_token_audit.h>

static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char nonce_b[] = "ffeeddccbbaa99887766554433221100";
static const char digest_a[] =
	"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
static const char digest_b[] =
	"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
static const char top_a[] = "mlkem768_m7";
static const char top_b[] = "mlkem1024_m7";

static void set_text(char *dst, size_t dst_size, const char *src)
{
	zassert_not_null(dst);
	zassert_not_null(src);
	zassert_true(dst_size > 0U);
	(void)snprintk(dst, dst_size, "%s", src);
}

static void fill_result(
	struct pqcp_deployment_device_token_replay_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION;
	result->passed = true;
	result->lines_seen = 4U;
	result->marker_mask = PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK;
	result->first_error = PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONE;
	result->token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	result->gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	result->capability_readiness_score = 100U;
	result->gate_score = 94U;
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 top_a);
	set_text(result->nonce_hex, sizeof(result->nonce_hex), nonce_a);
	set_text(result->token_digest_hex, sizeof(result->token_digest_hex),
		 digest_a);
	set_text(result->computed_digest_hex,
		 sizeof(result->computed_digest_hex), digest_a);
}

static void default_policy(
	struct pqcp_deployment_device_token_audit_policy *policy)
{
	zassert_equal(pqcp_deployment_device_token_audit_default_policy(
			      policy),
		      0);
}

static int run_audit(
	struct pqcp_deployment_device_token_replay_result *results,
	size_t count,
	struct pqcp_deployment_device_token_audit_policy *policy,
	struct pqcp_deployment_device_token_audit_report *report)
{
	return pqcp_deployment_device_token_audit_run(results, count, policy,
						     report);
}

ZTEST(pqcp_deployment_device_token_audit, test_status_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_device_token_audit_status_str(
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_device_token_audit_status_str(
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_device_token_audit_status_str(
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL),
		"FAIL");
	zassert_str_equal(pqcp_deployment_device_token_audit_status_str(42),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_device_token_audit, test_default_policy_is_reviewable)
{
	struct pqcp_deployment_device_token_audit_policy policy;

	default_policy(&policy);
	zassert_equal(policy.minimum_results, 1U);
	zassert_equal(policy.capability_score_warn_floor, 70U);
	zassert_equal(policy.gate_score_warn_floor, 60U);
	zassert_true(policy.require_replay_pass);
	zassert_false(policy.require_token_pass);
	zassert_false(policy.require_gate_pass);
	zassert_true(policy.require_stable_nonce);
	zassert_true(policy.require_stable_top);
	zassert_true(policy.require_stable_token_digest);
	zassert_false(policy.require_stable_gate_status);
}

ZTEST(pqcp_deployment_device_token_audit, test_single_pass_result_emits)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	default_policy(&policy);
	zassert_equal(run_audit(&result, 1U, &policy, &report), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS);
	zassert_equal(report.result_count, 1U);
	zassert_equal(report.replay_pass_count, 1U);
	zassert_equal(report.unique_token_digest_count, 1U);
	zassert_true(report.stable_nonce);
	zassert_true(report.stable_top_candidate);
	zassert_true(report.stable_token_digest);
	zassert_true(report.stable_gate_status);
	zassert_str_equal(report.top_candidate_id, top_a);
	zassert_str_equal(report.nonce_hex, nonce_a);
	zassert_str_equal(report.token_digest_hex, digest_a);
	zassert_equal(pqcp_deployment_device_token_audit_emit(&report), 0);
}

ZTEST(pqcp_deployment_device_token_audit, test_low_sample_count_warns)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	default_policy(&policy);
	policy.minimum_results = 2U;
	zassert_equal(run_audit(&result, 1U, &policy, &report), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_SAMPLE_COUNT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_replay_failure_blocks)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	result.passed = false;
	result.first_error =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH;
	default_policy(&policy);
	zassert_equal(run_audit(&result, 1U, &policy, &report), -EBADMSG);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_REPLAY_FAILED) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_nonce_drift_blocks)
{
	struct pqcp_deployment_device_token_replay_result results[2];
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&results[0]);
	fill_result(&results[1]);
	set_text(results[1].nonce_hex, sizeof(results[1].nonce_hex), nonce_b);
	default_policy(&policy);
	zassert_equal(run_audit(results, ARRAY_SIZE(results), &policy,
				&report),
		      -EBADMSG);
	zassert_false(report.stable_nonce);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_NONCE_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_top_candidate_drift_blocks)
{
	struct pqcp_deployment_device_token_replay_result results[2];
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&results[0]);
	fill_result(&results[1]);
	set_text(results[1].top_candidate_id,
		 sizeof(results[1].top_candidate_id), top_b);
	default_policy(&policy);
	zassert_equal(run_audit(results, ARRAY_SIZE(results), &policy,
				&report),
		      -EBADMSG);
	zassert_false(report.stable_top_candidate);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOP_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_token_digest_drift_blocks)
{
	struct pqcp_deployment_device_token_replay_result results[2];
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&results[0]);
	fill_result(&results[1]);
	set_text(results[1].token_digest_hex,
		 sizeof(results[1].token_digest_hex), digest_b);
	set_text(results[1].computed_digest_hex,
		 sizeof(results[1].computed_digest_hex), digest_b);
	default_policy(&policy);
	zassert_equal(run_audit(results, ARRAY_SIZE(results), &policy,
				&report),
		      -EBADMSG);
	zassert_equal(report.unique_token_digest_count, 2U);
	zassert_false(report.stable_token_digest);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOKEN_DIGEST_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_token_digest_diversity_can_warn)
{
	struct pqcp_deployment_device_token_replay_result results[2];
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&results[0]);
	fill_result(&results[1]);
	set_text(results[1].token_digest_hex,
		 sizeof(results[1].token_digest_hex), digest_b);
	set_text(results[1].computed_digest_hex,
		 sizeof(results[1].computed_digest_hex), digest_b);
	default_policy(&policy);
	policy.require_stable_token_digest = false;
	zassert_equal(run_audit(results, ARRAY_SIZE(results), &policy,
				&report),
		      0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_TOKEN_DIVERSITY) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_gate_status_drift_can_block)
{
	struct pqcp_deployment_device_token_replay_result results[2];
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&results[0]);
	fill_result(&results[1]);
	results[1].gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_WARN;
	default_policy(&policy);
	policy.require_stable_gate_status = true;
	zassert_equal(run_audit(results, ARRAY_SIZE(results), &policy,
				&report),
		      -EBADMSG);
	zassert_false(report.stable_gate_status);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_GATE_STATUS_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_token_fail_warns_by_default)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	result.token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;
	default_policy(&policy);
	zassert_equal(run_audit(&result, 1U, &policy, &report), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN);
	zassert_equal(report.token_fail_count, 1U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_TOKEN_NOT_PASS) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_token_fail_blocks_when_required)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	result.token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;
	default_policy(&policy);
	policy.require_token_pass = true;
	zassert_equal(run_audit(&result, 1U, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOKEN_STATUS) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_gate_fail_blocks_when_required)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	result.gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
	default_policy(&policy);
	policy.require_gate_pass = true;
	zassert_equal(run_audit(&result, 1U, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_GATE_STATUS) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_low_scores_warn)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	result.capability_readiness_score = 69U;
	result.gate_score = 59U;
	default_policy(&policy);
	zassert_equal(run_audit(&result, 1U, &policy, &report), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_CAPABILITY_SCORE) !=
		     0U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_GATE_SCORE) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_bad_schema_fails_as_malformed)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	result.schema_version = 99U;
	default_policy(&policy);
	zassert_equal(run_audit(&result, 1U, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_MALFORMED_RESULT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_score_range_fails)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	result.gate_score = 101U;
	default_policy(&policy);
	zassert_equal(run_audit(&result, 1U, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_SCORE_RANGE) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token_audit, test_invalid_arguments_fail)
{
	struct pqcp_deployment_device_token_replay_result result;
	struct pqcp_deployment_device_token_audit_policy policy;
	struct pqcp_deployment_device_token_audit_report report;

	fill_result(&result);
	default_policy(&policy);
	zassert_equal(pqcp_deployment_device_token_audit_run(
			      NULL, 1U, &policy, &report),
		      -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_INVALID_INPUT) !=
		     0U);
	zassert_equal(pqcp_deployment_device_token_audit_run(
			      &result, 0U, &policy, &report),
		      -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_NO_RESULTS) !=
		     0U);
	zassert_equal(pqcp_deployment_device_token_audit_emit(NULL), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_device_token_audit, NULL, NULL, NULL, NULL, NULL);
