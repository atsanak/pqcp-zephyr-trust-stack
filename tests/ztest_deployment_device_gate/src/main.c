/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for firmware-native deployment device evidence gate.
 */

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/deployment_device_gate.h>

static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char nonce_b[] = "ffeeddccbbaa99887766554433221100";
static const char top_a[] = "hybrid768_65_campaign";
static const char top_b[] = "hybrid1024_87_campaign";
static const char trace_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char trace_b[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char packet_a[] =
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char packet_b[] =
	"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
static const char token_digest_a[] =
	"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
static const char token_digest_b[] =
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

struct fixture {
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report release_gate;
	struct pqcp_deployment_device_token token;
	struct pqcp_deployment_device_token_verification verification;
	struct pqcp_deployment_device_token_replay_result replay;
	struct pqcp_deployment_device_token_audit_report audit;
};

static void set_text(char *dst, size_t dst_size, const char *src)
{
	zassert_not_null(dst);
	zassert_not_null(src);
	zassert_true(dst_size > 0U);
	(void)snprintk(dst, dst_size, "%s", src);
}

static uint32_t full_device_gate_capabilities(void)
{
	return PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST |
	       PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT |
	       PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_RELEASE_GATE |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN_REPLAY |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN_AUDIT |
	       PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_GATE;
}

static void fill_capability(struct pqcp_capability_descriptor *capability)
{
	memset(capability, 0, sizeof(*capability));
	capability->schema_version = PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION;
	capability->pqcp_version = "1.0.0";
	capability->zephyr_version = "4.4.0";
	capability->board = "qemu_x86_64";
	capability->profile = PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL;
	capability->mlkem_level_mask = 0x00000300U;
	capability->mldsa_level_mask = 0x00000041U;
	capability->rng_mode = "zephyr_entropy";
	capability->provider_summary = PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	capability->backend_selector = "auto";
	capability->evidence_capabilities = full_device_gate_capabilities();
	capability->policy_passed = true;
	capability->production_allowed = true;
	capability->evidence_readiness_score = 100U;
}

static void fill_release_gate(
	struct pqcp_deployment_release_gate_report *release_gate)
{
	memset(release_gate, 0, sizeof(*release_gate));
	release_gate->schema_version = PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION;
	release_gate->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	release_gate->status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	release_gate->candidate_count = 3U;
	release_gate->readiness_score = 100U;
	release_gate->claim_score = 95U;
	release_gate->review_score = 92U;
	release_gate->gate_score = 94U;
	release_gate->top_consistent = true;
	release_gate->digest_bound = true;
	release_gate->pipeline_passed = true;
	release_gate->budget_passed = true;
	release_gate->experiment_plan_passed = true;
	release_gate->packet_passed = true;
	release_gate->replay_passed = true;
	release_gate->audit_passed = true;
	set_text(release_gate->top_candidate_id,
		 sizeof(release_gate->top_candidate_id), top_a);
	set_text(release_gate->trace_digest_hex,
		 sizeof(release_gate->trace_digest_hex), trace_a);
	set_text(release_gate->packet_digest_hex,
		 sizeof(release_gate->packet_digest_hex), packet_a);
}

static void fill_token(struct pqcp_deployment_device_token *token)
{
	memset(token, 0, sizeof(*token));
	token->schema_version = PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION;
	token->status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	token->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	set_text(token->nonce_hex, sizeof(token->nonce_hex), nonce_a);
	token->evidence_capabilities = full_device_gate_capabilities();
	token->capability_readiness_score = 100U;
	token->gate_score = 94U;
	token->gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	token->capability_policy_passed = true;
	token->production_allowed = true;
	token->native_provider = true;
	token->gate_digest_bound = true;
	set_text(token->top_candidate_id, sizeof(token->top_candidate_id),
		 top_a);
	set_text(token->trace_digest_hex, sizeof(token->trace_digest_hex),
		 trace_a);
	set_text(token->packet_digest_hex, sizeof(token->packet_digest_hex),
		 packet_a);
	set_text(token->token_digest_hex, sizeof(token->token_digest_hex),
		 token_digest_a);
}

static void fill_verification(
	struct pqcp_deployment_device_token_verification *verification)
{
	memset(verification, 0, sizeof(*verification));
	verification->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION;
	verification->passed = true;
	verification->expected_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	verification->observed_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	set_text(verification->expected_digest_hex,
		 sizeof(verification->expected_digest_hex), token_digest_a);
	set_text(verification->observed_digest_hex,
		 sizeof(verification->observed_digest_hex), token_digest_a);
}

static void fill_replay(
	struct pqcp_deployment_device_token_replay_result *replay)
{
	memset(replay, 0, sizeof(*replay));
	replay->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION;
	replay->passed = true;
	replay->lines_seen = 4U;
	replay->marker_mask = PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK;
	replay->first_error = PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONE;
	replay->token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	replay->gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	replay->capability_readiness_score = 100U;
	replay->gate_score = 94U;
	set_text(replay->top_candidate_id, sizeof(replay->top_candidate_id),
		 top_a);
	set_text(replay->nonce_hex, sizeof(replay->nonce_hex), nonce_a);
	set_text(replay->token_digest_hex, sizeof(replay->token_digest_hex),
		 token_digest_a);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex), token_digest_a);
}

static void fill_audit(
	struct pqcp_deployment_device_token_audit_report *audit)
{
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_SCHEMA_VERSION;
	audit->status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS;
	audit->result_count = 1U;
	audit->replay_pass_count = 1U;
	audit->token_pass_count = 1U;
	audit->gate_pass_count = 1U;
	audit->unique_token_digest_count = 1U;
	audit->min_capability_readiness_score = 100U;
	audit->min_gate_score = 94U;
	audit->max_gate_score = 94U;
	audit->avg_gate_score = 94U;
	audit->stable_nonce = true;
	audit->stable_top_candidate = true;
	audit->stable_token_digest = true;
	audit->stable_gate_status = true;
	set_text(audit->nonce_hex, sizeof(audit->nonce_hex), nonce_a);
	set_text(audit->top_candidate_id, sizeof(audit->top_candidate_id),
		 top_a);
	set_text(audit->token_digest_hex, sizeof(audit->token_digest_hex),
		 token_digest_a);
}

static void fill_fixture(struct fixture *fixture)
{
	fill_capability(&fixture->capability);
	fill_release_gate(&fixture->release_gate);
	fill_token(&fixture->token);
	fill_verification(&fixture->verification);
	fill_replay(&fixture->replay);
	fill_audit(&fixture->audit);
}

static void default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_device_gate_policy *policy)
{
	zassert_equal(pqcp_deployment_device_gate_default_policy(profile,
								policy),
		      0);
}

static int evaluate(
	const struct fixture *fixture,
	const struct pqcp_deployment_device_gate_policy *policy,
	struct pqcp_deployment_device_gate_report *report)
{
	return pqcp_deployment_device_gate_evaluate(
		&fixture->capability, &fixture->release_gate, &fixture->token,
		&fixture->verification, &fixture->replay, &fixture->audit,
		policy, report);
}

ZTEST(pqcp_deployment_device_gate, test_status_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_device_gate_status_str(
			PQCP_DEPLOYMENT_DEVICE_GATE_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_device_gate_status_str(
			PQCP_DEPLOYMENT_DEVICE_GATE_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_device_gate_status_str(
			PQCP_DEPLOYMENT_DEVICE_GATE_FAIL),
		"FAIL");
	zassert_str_equal(pqcp_deployment_device_gate_status_str(42),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_device_gate, test_product_policy_is_strict)
{
	struct pqcp_deployment_device_gate_policy policy;

	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_true(policy.score_floor_blocks);
	zassert_true(policy.require_capability_policy_pass);
	zassert_true(policy.require_production_allowed);
	zassert_true(policy.require_native_provider);
	zassert_true(policy.require_device_token_audit_capability);
	zassert_true(policy.require_release_gate_pass);
	zassert_true(policy.require_token_pass);
	zassert_true(policy.require_verification_pass);
	zassert_true(policy.require_replay_pass);
	zassert_true(policy.require_audit_pass);
	zassert_equal(policy.min_capability_readiness_score, 80U);
	zassert_equal(policy.min_release_gate_score, 80U);
	zassert_equal(policy.min_audit_gate_score, 80U);
}

ZTEST(pqcp_deployment_device_gate, test_partner_policy_keeps_review_warnings)
{
	struct pqcp_deployment_device_gate_policy policy;

	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER, &policy);
	zassert_false(policy.score_floor_blocks);
	zassert_false(policy.require_release_gate_pass);
	zassert_false(policy.require_token_pass);
	zassert_false(policy.require_audit_pass);
	zassert_true(policy.require_verification_pass);
	zassert_true(policy.require_replay_pass);
}

ZTEST(pqcp_deployment_device_gate, test_clean_product_chain_passes)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_GATE_PASS);
	zassert_equal(report.error_mask, 0U);
	zassert_equal(report.warning_mask, 0U);
	zassert_true(report.top_consistent);
	zassert_true(report.nonce_consistent);
	zassert_true(report.token_digest_consistent);
	zassert_true(report.release_digest_consistent);
	zassert_str_equal(report.top_candidate_id, top_a);
	zassert_str_equal(report.nonce_hex, nonce_a);
	zassert_str_equal(report.token_digest_hex, token_digest_a);
	zassert_equal(pqcp_deployment_device_gate_emit(&report), 0);
}

ZTEST(pqcp_deployment_device_gate, test_missing_audit_capability_blocks)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	fixture.capability.evidence_capabilities &=
		~PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN_AUDIT;
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_MISSING_CAPABILITY) !=
		     0U);
}

ZTEST(pqcp_deployment_device_gate, test_nonproduction_blocks_product)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	fixture.capability.production_allowed = false;
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PRODUCTION) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_nonproduction_can_warn_partner)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	fixture.capability.production_allowed = false;
	fixture.release_gate.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
	fixture.token.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), 0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_DEVICE_GATE_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_NOT_PRODUCTION) !=
		     0U);
}

ZTEST(pqcp_deployment_device_gate, test_release_gate_failure_blocks_product)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	fixture.release_gate.status = PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_RELEASE_GATE) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_token_failure_blocks_product)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	fixture.token.status = PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;
	fixture.replay.token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;
	fixture.audit.status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL;
	fixture.audit.token_fail_count = 1U;
	fixture.audit.token_pass_count = 0U;
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOKEN) != 0U);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_AUDIT) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_verification_failure_blocks)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	fixture.verification.passed = false;
	fixture.verification.error_mask =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_TOKEN_MISMATCH;
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_VERIFY) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_replay_failure_blocks)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	fixture.replay.passed = false;
	fixture.replay.first_error =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH;
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_REPLAY) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_top_mismatch_blocks)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	set_text(fixture.replay.top_candidate_id,
		 sizeof(fixture.replay.top_candidate_id), top_b);
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_false(report.top_consistent);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOP_MISMATCH) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_nonce_mismatch_blocks)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	set_text(fixture.audit.nonce_hex, sizeof(fixture.audit.nonce_hex),
		 nonce_b);
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_false(report.nonce_consistent);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_NONCE_MISMATCH) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_token_digest_mismatch_blocks)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	set_text(fixture.verification.observed_digest_hex,
		 sizeof(fixture.verification.observed_digest_hex),
		 token_digest_b);
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_false(report.token_digest_consistent);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOKEN_DIGEST) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_release_digest_mismatch_blocks)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	set_text(fixture.token.trace_digest_hex,
		 sizeof(fixture.token.trace_digest_hex), trace_b);
	set_text(fixture.token.packet_digest_hex,
		 sizeof(fixture.token.packet_digest_hex), packet_b);
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_false(report.release_digest_consistent);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_RELEASE_DIGEST) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_score_floor_blocks_product)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	fixture.capability.evidence_readiness_score = 79U;
	fixture.release_gate.gate_score = 79U;
	fixture.audit.min_gate_score = 79U;
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_SCORE_FLOOR) != 0U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_CAPABILITY_SCORE) !=
		     0U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_GATE_SCORE) != 0U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_AUDIT_SCORE) != 0U);
}

ZTEST(pqcp_deployment_device_gate, test_profile_mismatch_blocks)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	fixture.token.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(evaluate(&fixture, &policy, &report), -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PROFILE_MISMATCH) !=
		     0U);
}

ZTEST(pqcp_deployment_device_gate, test_invalid_inputs_fail)
{
	struct fixture fixture;
	struct pqcp_deployment_device_gate_policy policy;
	struct pqcp_deployment_device_gate_report report;

	fill_fixture(&fixture);
	default_policy(PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT, &policy);
	zassert_equal(pqcp_deployment_device_gate_evaluate(
			      NULL, &fixture.release_gate, &fixture.token,
			      &fixture.verification, &fixture.replay,
			      &fixture.audit, &policy, &report),
		      -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_INVALID_INPUT) !=
		     0U);
	fixture.replay.marker_mask = 0U;
	zassert_equal(evaluate(&fixture, &policy, &report), -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_INVALID_INPUT) !=
		     0U);
	zassert_equal(pqcp_deployment_device_gate_emit(NULL), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_device_gate, NULL, NULL, NULL, NULL, NULL);
