/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_device_token.h>

static const char nonce_hex[] = "00112233445566778899aabbccddeeff";
static const char trace_digest[] =
	"4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e";
static const char packet_digest[] =
	"863c3f8ab7b174d111c5b497449e0d6f47e556b43aabef93c7caa7616f4416c3";

static void fill_capability(struct pqcp_capability_descriptor *descriptor)
{
	memset(descriptor, 0, sizeof(*descriptor));
	descriptor->schema_version = PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION;
	descriptor->pqcp_version = "1.0.0";
	descriptor->zephyr_version = "4.4.0";
	descriptor->board = "nucleo_h743zi";
	descriptor->profile = PQCP_FIRMWARE_POLICY_PROFILE_MCU_MINIMAL;
	descriptor->mlkem_level_mask = PQCP_BUILD_MLKEM_LEVEL_768;
	descriptor->mldsa_level_mask = PQCP_BUILD_MLDSA_LEVEL_65;
	descriptor->rng_mode = "zephyr_entropy";
	descriptor->provider_summary = PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	descriptor->backend_selector = "auto";
	descriptor->evidence_capabilities =
		PQCP_CAPABILITY_EVIDENCE_BUILD_MANIFEST |
		PQCP_CAPABILITY_EVIDENCE_PROVIDER_CONTRACT |
		PQCP_CAPABILITY_EVIDENCE_FIRMWARE_POLICY |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_RELEASE_GATE |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN;
	descriptor->policy_passed = true;
	descriptor->production_allowed = true;
	descriptor->evidence_readiness_score = 100U;
}

static void fill_gate(struct pqcp_deployment_release_gate_report *gate)
{
	memset(gate, 0, sizeof(*gate));
	gate->schema_version = PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION;
	gate->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	gate->status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	gate->candidate_count = 3U;
	gate->readiness_score = 100U;
	gate->claim_score = 94U;
	gate->review_score = 100U;
	gate->gate_score = 94U;
	gate->top_consistent = true;
	gate->digest_bound = true;
	gate->pipeline_passed = true;
	gate->budget_passed = true;
	gate->experiment_plan_passed = true;
	gate->packet_passed = true;
	gate->replay_passed = true;
	gate->audit_passed = true;
	(void)snprintk(gate->top_candidate_id,
		       sizeof(gate->top_candidate_id), "%s", "mlkem768_m7");
	(void)snprintk(gate->trace_digest_hex,
		       sizeof(gate->trace_digest_hex), "%s", trace_digest);
	(void)snprintk(gate->packet_digest_hex,
		       sizeof(gate->packet_digest_hex), "%s", packet_digest);
}

static void fill_policy(
	struct pqcp_deployment_device_token_policy *policy)
{
	zassert_equal(pqcp_deployment_device_token_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      policy),
		      0);
}

ZTEST(pqcp_deployment_device_token, test_status_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_device_token_status_str(
			PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS),
		"PASS");
	zassert_str_equal(
		pqcp_deployment_device_token_status_str(
			PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN),
		"WARN");
	zassert_str_equal(
		pqcp_deployment_device_token_status_str(
			PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL),
		"FAIL");
}

ZTEST(pqcp_deployment_device_token, test_product_token_passes_clean_inputs)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;

	fill_capability(&capability);
	fill_gate(&gate);
	fill_policy(&policy);
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &token),
		      0);
	zassert_equal(token.status, PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS);
	zassert_equal(token.error_mask, 0U);
	zassert_equal(token.warning_mask, 0U);
	zassert_str_equal(token.top_candidate_id, "mlkem768_m7");
	zassert_str_equal(token.nonce_hex, nonce_hex);
	zassert_true(token.token_digest_hex[0] != '\0');
	zassert_equal(pqcp_deployment_device_token_emit(&token), 0);
}

ZTEST(pqcp_deployment_device_token, test_digest_is_stable_for_same_inputs)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token a;
	struct pqcp_deployment_device_token b;

	fill_capability(&capability);
	fill_gate(&gate);
	fill_policy(&policy);
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &a),
		      0);
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &b),
		      0);
	zassert_str_equal(a.token_digest_hex, b.token_digest_hex);
}

ZTEST(pqcp_deployment_device_token, test_bad_nonce_is_rejected)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;

	fill_capability(&capability);
	fill_gate(&gate);
	fill_policy(&policy);
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, "not-a-nonce", &policy,
			      &token),
		      -EINVAL);
	zassert_equal(token.status, PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL);
	zassert_true((token.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_BAD_NONCE) != 0U);
}

ZTEST(pqcp_deployment_device_token, test_product_token_requires_gate_pass)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;

	fill_capability(&capability);
	fill_gate(&gate);
	fill_policy(&policy);
	gate.status = PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
	gate.error_mask = PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_BUDGET;
	gate.gate_score = 44U;
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &token),
		      -EBADMSG);
	zassert_true((token.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_GATE_STATUS) != 0U);
	zassert_true((token.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_SCORE_FLOOR) != 0U);
}

ZTEST(pqcp_deployment_device_token, test_missing_capability_bit_fails)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;

	fill_capability(&capability);
	fill_gate(&gate);
	fill_policy(&policy);
	capability.evidence_capabilities &=
		~PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN;
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &token),
		      -EBADMSG);
	zassert_true((token.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_MISSING_TOKEN_CAP) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token, test_product_token_requires_native_provider)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;

	fill_capability(&capability);
	fill_gate(&gate);
	fill_policy(&policy);
	capability.provider_summary = PQCP_CAPABILITY_PROVIDER_BASELINE_C;
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &token),
		      -EBADMSG);
	zassert_true((token.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_PROVIDER) != 0U);
}

ZTEST(pqcp_deployment_device_token, test_prototype_warns_for_nonproduction)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;

	fill_capability(&capability);
	fill_gate(&gate);
	zassert_equal(pqcp_deployment_device_token_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			      &policy),
		      0);
	gate.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	capability.production_allowed = false;
	capability.profile = PQCP_FIRMWARE_POLICY_PROFILE_EVIDENCE_LAB;
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &token),
		      0);
	zassert_equal(token.status, PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN);
	zassert_true((token.warning_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_NOT_PRODUCTION) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token, test_verifier_accepts_matching_token)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;
	struct pqcp_deployment_device_token_verification verification;

	fill_capability(&capability);
	fill_gate(&gate);
	fill_policy(&policy);
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &token),
		      0);
	zassert_equal(pqcp_deployment_device_token_verify(
			      &token, &capability, &gate, nonce_hex, &policy,
			      &verification),
		      0);
	zassert_true(verification.passed);
	zassert_equal(pqcp_deployment_device_token_verification_emit(
			      &verification),
		      0);
}

ZTEST(pqcp_deployment_device_token, test_verifier_rejects_tampered_digest)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;
	struct pqcp_deployment_device_token_verification verification;

	fill_capability(&capability);
	fill_gate(&gate);
	fill_policy(&policy);
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &token),
		      0);
	token.token_digest_hex[0] =
		token.token_digest_hex[0] == '0' ? '1' : '0';
	zassert_equal(pqcp_deployment_device_token_verify(
			      &token, &capability, &gate, nonce_hex, &policy,
			      &verification),
		      -EBADMSG);
	zassert_false(verification.passed);
	zassert_true((verification.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_TOKEN_MISMATCH) !=
		     0U);
}

ZTEST(pqcp_deployment_device_token, test_verifier_rejects_wrong_nonce)
{
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_release_gate_report gate;
	struct pqcp_deployment_device_token_policy policy;
	struct pqcp_deployment_device_token token;
	struct pqcp_deployment_device_token_verification verification;

	fill_capability(&capability);
	fill_gate(&gate);
	fill_policy(&policy);
	zassert_equal(pqcp_deployment_device_token_build(
			      &capability, &gate, nonce_hex, &policy, &token),
		      0);
	zassert_equal(pqcp_deployment_device_token_verify(
			      &token, &capability, &gate,
			      "ffeeddccbbaa99887766554433221100", &policy,
			      &verification),
		      -EBADMSG);
	zassert_true((verification.error_mask &
		      PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_TOKEN_MISMATCH) !=
		     0U);
}

ZTEST_SUITE(pqcp_deployment_device_token, NULL, NULL, NULL, NULL, NULL);
