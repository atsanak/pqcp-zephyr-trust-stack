/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for firmware-native deployment device-packet replay audit.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_device_packet_audit.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char top_b[] = "hybrid1024_87_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char nonce_b[] = "ffeeddccbbaa99887766554433221100";
static const char digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char digest_b[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static uint32_t replay_caps(void)
{
	return PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST |
	       PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT |
	       PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET_REPLAY |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET_AUDIT;
}

static void set_text(char *dst, size_t dst_size, const char *src)
{
	zassert_not_null(dst);
	zassert_not_null(src);
	zassert_true(dst_size > 0U);
	(void)snprintk(dst, dst_size, "%s", src);
}

static void fill_result(
	struct pqcp_deployment_device_packet_replay_result *result,
	enum pqcp_deployment_device_packet_status status)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_SCHEMA_VERSION;
	result->lines_seen = 7U;
	result->marker_mask = PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_REQUIRED_MASK;
	result->fact_lines = 6U;
	result->fact_bytes = 1700U;
	result->evidence_capabilities = replay_caps();
	result->capability_readiness_score = 96U;
	result->release_gate_score = 91U;
	result->audit_gate_score = 89U;
	result->first_error_line = 0U;
	result->first_error =
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONE;
	result->packet_status = status;
	result->passed = true;
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 top_a);
	set_text(result->nonce_hex, sizeof(result->nonce_hex), nonce_a);
	set_text(result->computed_digest_hex,
		 sizeof(result->computed_digest_hex), digest_a);
}

static void default_policy(
	struct pqcp_deployment_device_packet_audit_policy *policy)
{
	zassert_equal(
		pqcp_deployment_device_packet_audit_default_policy(policy),
		0);
}

static void run_expect(
	const struct pqcp_deployment_device_packet_replay_result *results,
	size_t count,
	const struct pqcp_deployment_device_packet_audit_policy *policy,
	struct pqcp_deployment_device_packet_audit_report *report,
	int expected_ret)
{
	zassert_equal(pqcp_deployment_device_packet_audit_run(
			      results, count, policy, report),
		      expected_ret);
}

ZTEST(pqcp_deployment_device_packet_audit, test_status_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_device_packet_audit_status_str(
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_device_packet_audit_status_str(
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_device_packet_audit_status_str(
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL),
		"FAIL");
	zassert_str_equal(
		pqcp_deployment_device_packet_audit_status_str(42),
		"UNKNOWN");
}

ZTEST(pqcp_deployment_device_packet_audit, test_default_policy_is_conservative)
{
	struct pqcp_deployment_device_packet_audit_policy policy;

	default_policy(&policy);
	zassert_equal(policy.minimum_results, 1U);
	zassert_true(policy.require_replay_pass);
	zassert_false(policy.require_packet_pass);
	zassert_true(policy.require_stable_top);
	zassert_true(policy.require_stable_nonce);
	zassert_true(policy.require_stable_digest);
	zassert_true(policy.require_stable_capabilities);
	zassert_false(policy.require_stable_packet_status);
	zassert_true(policy.require_replay_capability);
}

ZTEST(pqcp_deployment_device_packet_audit, test_single_pass_result_passes)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	default_policy(&policy);
	run_expect(&result, 1U, &policy, &report, 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS);
	zassert_equal(report.result_count, 1U);
	zassert_equal(report.replay_pass_count, 1U);
	zassert_equal(report.packet_pass_count, 1U);
	zassert_equal(report.unique_packet_digest_count, 1U);
	zassert_true(report.stable_top_candidate);
	zassert_true(report.stable_nonce);
	zassert_true(report.stable_packet_digest);
	zassert_true(report.stable_capabilities);
	zassert_true(report.stable_packet_status);
	zassert_str_equal(report.top_candidate_id, top_a);
	zassert_str_equal(report.nonce_hex, nonce_a);
	zassert_str_equal(report.packet_digest_hex, digest_a);
	zassert_equal(pqcp_deployment_device_packet_audit_emit(&report), 0);
}

ZTEST(pqcp_deployment_device_packet_audit, test_sample_count_warning)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	default_policy(&policy);
	policy.minimum_results = 2U;
	run_expect(&result, 1U, &policy, &report, 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_SAMPLE_COUNT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_packet_warn_is_warning_by_default)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_WARN);
	default_policy(&policy);
	run_expect(&result, 1U, &policy, &report, 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN);
	zassert_equal(report.packet_warn_count, 1U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_PACKET_NOT_PASS) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_packet_pass_requirement_fails_warn_packet)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_WARN);
	default_policy(&policy);
	policy.require_packet_pass = true;
	run_expect(&result, 1U, &policy, &report, -EBADMSG);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_PACKET_STATUS) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_replay_failure_fails)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	result.passed = false;
	default_policy(&policy);
	run_expect(&result, 1U, &policy, &report, -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_REPLAY_FAILED) !=
		     0U);
	zassert_equal(report.replay_fail_count, 1U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_top_drift_fails)
{
	struct pqcp_deployment_device_packet_replay_result results[2];
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&results[0], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	fill_result(&results[1], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	set_text(results[1].top_candidate_id,
		 sizeof(results[1].top_candidate_id), top_b);
	default_policy(&policy);
	run_expect(results, 2U, &policy, &report, -EBADMSG);
	zassert_false(report.stable_top_candidate);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_TOP_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_nonce_drift_fails)
{
	struct pqcp_deployment_device_packet_replay_result results[2];
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&results[0], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	fill_result(&results[1], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	set_text(results[1].nonce_hex, sizeof(results[1].nonce_hex), nonce_b);
	default_policy(&policy);
	run_expect(results, 2U, &policy, &report, -EBADMSG);
	zassert_false(report.stable_nonce);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_NONCE_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_digest_drift_fails)
{
	struct pqcp_deployment_device_packet_replay_result results[2];
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&results[0], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	fill_result(&results[1], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	set_text(results[1].computed_digest_hex,
		 sizeof(results[1].computed_digest_hex), digest_b);
	default_policy(&policy);
	run_expect(results, 2U, &policy, &report, -EBADMSG);
	zassert_false(report.stable_packet_digest);
	zassert_equal(report.unique_packet_digest_count, 2U);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_DIGEST_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_digest_diversity_can_warn)
{
	struct pqcp_deployment_device_packet_replay_result results[2];
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&results[0], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	fill_result(&results[1], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	set_text(results[1].computed_digest_hex,
		 sizeof(results[1].computed_digest_hex), digest_b);
	default_policy(&policy);
	policy.require_stable_digest = false;
	run_expect(results, 2U, &policy, &report, 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_DIGEST_DIVERSITY) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_capability_drift_fails)
{
	struct pqcp_deployment_device_packet_replay_result results[2];
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&results[0], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	fill_result(&results[1], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	results[1].evidence_capabilities ^= PQCP_CAPABILITY_EVIDENCE_SESSION;
	default_policy(&policy);
	run_expect(results, 2U, &policy, &report, -EBADMSG);
	zassert_false(report.stable_capabilities);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_CAPABILITY_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_packet_status_drift_can_fail)
{
	struct pqcp_deployment_device_packet_replay_result results[2];
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&results[0], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	fill_result(&results[1], PQCP_DEPLOYMENT_DEVICE_PACKET_WARN);
	default_policy(&policy);
	policy.require_stable_packet_status = true;
	run_expect(results, 2U, &policy, &report, -EBADMSG);
	zassert_false(report.stable_packet_status);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_STATUS_DRIFT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_missing_replay_capability_fails)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	result.evidence_capabilities &=
		~PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET_REPLAY;
	default_policy(&policy);
	run_expect(&result, 1U, &policy, &report, -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_MISSING_CAPABILITY) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_low_scores_warn)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	result.capability_readiness_score = 60U;
	result.release_gate_score = 55U;
	result.audit_gate_score = 50U;
	default_policy(&policy);
	run_expect(&result, 1U, &policy, &report, 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_CAPABILITY_SCORE) !=
		     0U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_RELEASE_SCORE) !=
		     0U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_AUDIT_SCORE) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_score_range_fails)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	result.release_gate_score = 101U;
	default_policy(&policy);
	run_expect(&result, 1U, &policy, &report, -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_SCORE_RANGE) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_malformed_result_fails)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	result.marker_mask = 0U;
	default_policy(&policy);
	run_expect(&result, 1U, &policy, &report, -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_MALFORMED_RESULT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_no_results_fails)
{
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	default_policy(&policy);
	run_expect(NULL, 0U, &policy, &report, -EINVAL);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_INVALID_INPUT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_zero_count_with_valid_pointer_fails)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	default_policy(&policy);
	run_expect(&result, 0U, &policy, &report, -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_NO_RESULTS) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_bad_policy_fails)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	default_policy(&policy);
	policy.minimum_results =
		PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_MAX_RESULTS + 1U;
	run_expect(&result, 1U, &policy, &report, -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_INVALID_INPUT) !=
		     0U);
}

ZTEST(pqcp_deployment_device_packet_audit, test_audit_digest_is_stable)
{
	struct pqcp_deployment_device_packet_replay_result results[2];
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report first;
	struct pqcp_deployment_device_packet_audit_report second;

	fill_result(&results[0], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	fill_result(&results[1], PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	default_policy(&policy);
	run_expect(results, 2U, &policy, &first, 0);
	run_expect(results, 2U, &policy, &second, 0);
	zassert_str_equal(first.audit_digest_hex, second.audit_digest_hex);
}

ZTEST(pqcp_deployment_device_packet_audit, test_audit_digest_changes_with_input)
{
	struct pqcp_deployment_device_packet_replay_result left;
	struct pqcp_deployment_device_packet_replay_result right;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report first;
	struct pqcp_deployment_device_packet_audit_report second;

	fill_result(&left, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	fill_result(&right, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	set_text(right.computed_digest_hex, sizeof(right.computed_digest_hex),
		 digest_b);
	default_policy(&policy);
	run_expect(&left, 1U, &policy, &first, 0);
	run_expect(&right, 1U, &policy, &second, 0);
	zassert_true(strcmp(first.audit_digest_hex,
			    second.audit_digest_hex) != 0);
}

ZTEST(pqcp_deployment_device_packet_audit, test_emit_rejects_bad_report)
{
	struct pqcp_deployment_device_packet_replay_result result;
	struct pqcp_deployment_device_packet_audit_policy policy;
	struct pqcp_deployment_device_packet_audit_report report;

	fill_result(&result, PQCP_DEPLOYMENT_DEVICE_PACKET_PASS);
	default_policy(&policy);
	run_expect(&result, 1U, &policy, &report, 0);
	report.error_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_device_packet_audit_emit(&report),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_device_packet_audit, NULL, NULL, NULL, NULL,
	    NULL);
