/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the firmware-native deployment evidence verdict replay audit.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_verdict_audit.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char top_b[] = "hybrid1024_87_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char nonce_b[] = "ffeeddccbbaa99887766554433221100";
static const char digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char digest_b[] =
	"1111111111111111111111111111111111111111111111111111111111111111";

static void set_text(char *dst, size_t dst_size, const char *src)
{
	zassert_not_null(dst);
	zassert_not_null(src);
	zassert_true(dst_size > 0U);
	(void)snprintk(dst, dst_size, "%s", src);
}

static uint32_t full_caps(void)
{
	return PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK;
}

static void fill_replay_result(
	struct pqcp_deployment_evidence_verdict_replay_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_SCHEMA_VERSION;
	result->lines_seen = 1U;
	result->marker_mask =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_REQUIRED_MASK;
	result->first_error_line = 0U;
	result->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE;
	result->verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	result->verdict_error_mask = 0U;
	result->verdict_warning_mask = 0U;
	result->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	result->verdict_score = 87U;
	result->min_chain_score = 87U;
	result->stage_count = 16U;
	result->consistency_checks = 7U;
	result->consistency_pass_count = 7U;
	result->evidence_capabilities_all = full_caps();
	result->evidence_capabilities_any = full_caps();
	result->passed = true;
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 top_a);
	set_text(result->nonce_hex, sizeof(result->nonce_hex), nonce_a);
	set_text(result->computed_digest_hex,
		 sizeof(result->computed_digest_hex), digest_a);
}

static void default_policy(
	struct pqcp_deployment_evidence_verdict_audit_policy *policy)
{
	zassert_equal(pqcp_deployment_evidence_verdict_audit_default_policy(
			      policy),
		      0);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_status_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_verdict_audit_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS),
			  "PASS");
	zassert_str_equal(pqcp_deployment_evidence_verdict_audit_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARN),
			  "WARN");
	zassert_str_equal(pqcp_deployment_evidence_verdict_audit_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_FAIL),
			  "FAIL");
	zassert_str_equal(pqcp_deployment_evidence_verdict_audit_status_str(42),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_default_policy_is_conservative)
{
	struct pqcp_deployment_evidence_verdict_audit_policy policy;

	default_policy(&policy);
	zassert_equal(policy.minimum_results, 1U);
	zassert_true(policy.require_replay_pass);
	zassert_false(policy.require_verdict_pass);
	zassert_true(policy.require_stable_top);
	zassert_true(policy.require_stable_nonce);
	zassert_true(policy.require_stable_digest);
	zassert_true(policy.require_stable_capabilities);
	zassert_false(policy.require_stable_verdict_status);
	zassert_true(policy.require_stable_profile);
	zassert_true(policy.require_verdict_capability);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_default_policy(
			      NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_single_result_passes)
{
	struct pqcp_deployment_evidence_verdict_replay_result result;
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&result);
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      0);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS);
	zassert_equal(report.error_mask, 0U);
	zassert_equal(report.warning_mask, 0U);
	zassert_equal(report.result_count, 1U);
	zassert_equal(report.replay_pass_count, 1U);
	zassert_equal(report.replay_fail_count, 0U);
	zassert_equal(report.verdict_pass_count, 1U);
	zassert_equal(report.unique_verdict_digest_count, 1U);
	zassert_equal(report.min_verdict_score, 87U);
	zassert_equal(report.max_verdict_score, 87U);
	zassert_equal(report.avg_verdict_score, 87U);
	zassert_equal(report.min_chain_score, 87U);
	zassert_equal(report.profile,
		      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT);
	zassert_true(report.stable_top_candidate);
	zassert_true(report.stable_nonce);
	zassert_true(report.stable_verdict_digest);
	zassert_true(report.stable_capabilities);
	zassert_true(report.stable_verdict_status);
	zassert_true(report.stable_profile);
	zassert_str_equal(report.top_candidate_id, top_a);
	zassert_str_equal(report.nonce_hex, nonce_a);
	zassert_str_equal(report.verdict_digest_hex, digest_a);
	zassert_true(report.audit_digest_hex[0] != '\0');
	zassert_equal(pqcp_deployment_evidence_verdict_audit_emit(&report), 0);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_audit_digest_is_input_bound)
{
	struct pqcp_deployment_evidence_verdict_replay_result result;
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report_a;
	struct pqcp_deployment_evidence_verdict_audit_report report_b;

	fill_replay_result(&result);
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report_a),
		      0);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report_b),
		      0);
	zassert_str_equal(report_a.audit_digest_hex, report_b.audit_digest_hex);

	result.verdict_score = 86U;
	result.min_chain_score = 86U;
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report_b),
		      0);
	zassert_not_equal(strcmp(report_a.audit_digest_hex,
				 report_b.audit_digest_hex),
			  0);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_replay_failure_blocks)
{
	struct pqcp_deployment_evidence_verdict_replay_result results[2];
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&results[0]);
	fill_replay_result(&results[1]);
	results[1].passed = false;
	results[1].first_error =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_DIGEST_MISMATCH;
	results[1].first_error_line = 1U;
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_FAIL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_MALFORMED_RESULT) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_top_drift_blocks)
{
	struct pqcp_deployment_evidence_verdict_replay_result results[2];
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&results[0]);
	fill_replay_result(&results[1]);
	set_text(results[1].top_candidate_id,
		 sizeof(results[1].top_candidate_id), top_b);
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_TOP_DRIFT) !=
		     0U);
	zassert_false(report.stable_top_candidate);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_nonce_drift_blocks)
{
	struct pqcp_deployment_evidence_verdict_replay_result results[2];
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&results[0]);
	fill_replay_result(&results[1]);
	set_text(results[1].nonce_hex, sizeof(results[1].nonce_hex), nonce_b);
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_NONCE_DRIFT) !=
		     0U);
	zassert_false(report.stable_nonce);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_digest_drift_blocks_or_warns)
{
	struct pqcp_deployment_evidence_verdict_replay_result results[2];
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&results[0]);
	fill_replay_result(&results[1]);
	set_text(results[1].computed_digest_hex,
		 sizeof(results[1].computed_digest_hex), digest_b);
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_DIGEST_DRIFT) !=
		     0U);
	zassert_equal(report.unique_verdict_digest_count, 2U);

	policy.require_stable_digest = false;
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      results, 2U, &policy, &report),
		      0);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARNING_DIGEST_DIVERSITY) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_profile_drift_blocks)
{
	struct pqcp_deployment_evidence_verdict_replay_result results[2];
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&results[0]);
	fill_replay_result(&results[1]);
	results[1].profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      results, 2U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_PROFILE_DRIFT) !=
		     0U);
	zassert_false(report.stable_profile);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_verdict_warn_status_warns)
{
	struct pqcp_deployment_evidence_verdict_replay_result result;
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&result);
	result.verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN;
	result.verdict_warning_mask =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_LOCAL_ONLY;
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      0);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARNING_VERDICT_NOT_PASS) !=
		     0U);

	policy.require_verdict_pass = true;
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_VERDICT_STATUS) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_score_floors_warn)
{
	struct pqcp_deployment_evidence_verdict_replay_result result;
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&result);
	result.verdict_score = 65U;
	result.min_chain_score = 55U;
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      0);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARNING_LOW_VERDICT_SCORE) !=
		     0U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARNING_LOW_CHAIN_SCORE) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_low_sample_count_warns)
{
	struct pqcp_deployment_evidence_verdict_replay_result result;
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&result);
	default_policy(&policy);
	policy.minimum_results = 3U;
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      0);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARNING_LOW_SAMPLE_COUNT) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_missing_capability_blocks)
{
	struct pqcp_deployment_evidence_verdict_replay_result result;
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&result);
	result.evidence_capabilities_all &=
		~PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY;
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_MISSING_CAPABILITY) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_malformed_result_blocks)
{
	struct pqcp_deployment_evidence_verdict_replay_result result;
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&result);
	result.schema_version = 99U;
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_MALFORMED_RESULT) !=
		     0U);

	fill_replay_result(&result);
	result.verdict_score = 101U;
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_SCORE_RANGE) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_invalid_input_rejected)
{
	struct pqcp_deployment_evidence_verdict_replay_result result;
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&result);
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      NULL, 1U, &policy, &report),
		      -EINVAL);
	zassert_equal(report.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_FAIL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_INVALID_INPUT) !=
		     0U);

	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 0U, &policy, &report),
		      -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_NO_RESULTS) !=
		     0U);

	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result,
			      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_MAX_RESULTS + 1U,
			      &policy, &report),
		      -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_ERROR_INVALID_INPUT) !=
		     0U);

	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, NULL, &report),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, NULL),
		      -EINVAL);

	policy.verdict_score_warn_floor = 101U;
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_verdict_audit, test_emit_rejects_invalid_report)
{
	struct pqcp_deployment_evidence_verdict_replay_result result;
	struct pqcp_deployment_evidence_verdict_audit_policy policy;
	struct pqcp_deployment_evidence_verdict_audit_report report;

	fill_replay_result(&result);
	default_policy(&policy);
	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      0);

	zassert_equal(pqcp_deployment_evidence_verdict_audit_emit(NULL),
		      -EINVAL);

	report.warning_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_evidence_verdict_audit_emit(&report),
		      -EINVAL);

	zassert_equal(pqcp_deployment_evidence_verdict_audit_run(
			      &result, 1U, &policy, &report),
		      0);
	report.schema_version = 99U;
	zassert_equal(pqcp_deployment_evidence_verdict_audit_emit(&report),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_verdict_audit, NULL, NULL, NULL, NULL,
	    NULL);
