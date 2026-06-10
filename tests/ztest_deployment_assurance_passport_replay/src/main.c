/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for the firmware-native deployment assurance passport replay
 * verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_assurance_passport_replay.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char seal_digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char audit_digest_a[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct fixture {
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_evidence_seal seal;
	struct pqcp_deployment_evidence_seal_replay_result seal_replay;
	struct pqcp_deployment_evidence_seal_audit_report seal_audit;
	struct pqcp_deployment_assurance_passport_policy policy;
	struct pqcp_deployment_assurance_passport passport;
};

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
	capability->evidence_capabilities = full_caps();
	capability->policy_passed = true;
	capability->production_allowed = true;
	capability->evidence_readiness_score = 96U;
}

static void fill_seal(struct pqcp_deployment_evidence_seal *seal)
{
	memset(seal, 0, sizeof(*seal));
	seal->schema_version = PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION;
	seal->status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
	seal->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	seal->seal_score = 87U;
	seal->min_terminal_score = 87U;
	seal->verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	seal->audit_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS;
	seal->audited_result_count = 1U;
	seal->chain_stage_count = 16U;
	seal->chain_consistency_checks = 7U;
	seal->evidence_capabilities_all = full_caps();
	seal->evidence_capabilities_any = full_caps();
	seal->replay_passed = true;
	seal->top_consistent = true;
	seal->nonce_consistent = true;
	seal->verdict_digest_consistent = true;
	seal->profile_consistent = true;
	seal->status_consistent = true;
	set_text(seal->top_candidate_id, sizeof(seal->top_candidate_id),
		 top_a);
	set_text(seal->nonce_hex, sizeof(seal->nonce_hex), nonce_a);
	set_text(seal->verdict_digest_hex, sizeof(seal->verdict_digest_hex),
		 seal_digest_a);
	set_text(seal->audit_digest_hex, sizeof(seal->audit_digest_hex),
		 audit_digest_a);
	set_text(seal->seal_digest_hex, sizeof(seal->seal_digest_hex),
		 seal_digest_a);
}

static void fill_seal_replay(
	struct pqcp_deployment_evidence_seal_replay_result *replay)
{
	memset(replay, 0, sizeof(*replay));
	replay->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_SCHEMA_VERSION;
	replay->lines_seen = 1U;
	replay->marker_mask =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_REQUIRED_MASK;
	replay->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE;
	replay->seal_status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
	replay->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	replay->seal_score = 87U;
	replay->min_terminal_score = 87U;
	replay->verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	replay->audit_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS;
	replay->sealed_replay_passed = true;
	replay->audited_result_count = 1U;
	replay->chain_stage_count = 16U;
	replay->chain_consistency_checks = 7U;
	replay->evidence_capabilities_all = full_caps();
	replay->evidence_capabilities_any = full_caps();
	replay->passed = true;
	set_text(replay->top_candidate_id, sizeof(replay->top_candidate_id),
		 top_a);
	set_text(replay->nonce_hex, sizeof(replay->nonce_hex), nonce_a);
	set_text(replay->verdict_digest_hex,
		 sizeof(replay->verdict_digest_hex), seal_digest_a);
	set_text(replay->audit_digest_hex, sizeof(replay->audit_digest_hex),
		 audit_digest_a);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex), seal_digest_a);
}

static void fill_seal_audit(
	struct pqcp_deployment_evidence_seal_audit_report *audit)
{
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_SCHEMA_VERSION;
	audit->status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS;
	audit->result_count = 1U;
	audit->replay_pass_count = 1U;
	audit->seal_pass_count = 1U;
	audit->unique_seal_digest_count = 1U;
	audit->min_seal_score = 87U;
	audit->max_seal_score = 87U;
	audit->avg_seal_score = 87U;
	audit->min_terminal_score = 87U;
	audit->max_terminal_score = 87U;
	audit->avg_terminal_score = 87U;
	audit->evidence_capabilities_all = full_caps();
	audit->evidence_capabilities_any = full_caps();
	audit->stable_top_candidate = true;
	audit->stable_nonce = true;
	audit->stable_seal_digest = true;
	audit->stable_capabilities = true;
	audit->stable_seal_status = true;
	audit->stable_profile = true;
	audit->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	set_text(audit->top_candidate_id, sizeof(audit->top_candidate_id),
		 top_a);
	set_text(audit->nonce_hex, sizeof(audit->nonce_hex), nonce_a);
	set_text(audit->seal_digest_hex, sizeof(audit->seal_digest_hex),
		 seal_digest_a);
	set_text(audit->audit_digest_hex, sizeof(audit->audit_digest_hex),
		 audit_digest_a);
}

static void build_passport(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fill_capability(&fixture->capability);
	fill_seal(&fixture->seal);
	fill_seal_replay(&fixture->seal_replay);
	fill_seal_audit(&fixture->seal_audit);
	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &fixture->policy),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_run(
			      &fixture->capability, &fixture->seal,
			      &fixture->seal_replay, &fixture->seal_audit,
			      &fixture->policy, &fixture->passport),
		      0);
	zassert_equal(fixture->passport.status,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS);
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_error_tokens_are_stable)
{
	zassert_str_equal(
		pqcp_deployment_assurance_passport_replay_error_str(
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE),
		"none");
	zassert_str_equal(
		pqcp_deployment_assurance_passport_replay_error_str(
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_DIGEST_MISMATCH),
		"digest_mismatch");
	zassert_str_equal(
		pqcp_deployment_assurance_passport_replay_error_str(
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_BAD_SCHEMA),
		"bad_schema");
	zassert_str_equal(
		pqcp_deployment_assurance_passport_replay_error_str(99),
		"unknown");
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_passport_verify_passes)
{
	struct fixture fixture;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_passport(&fixture);
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE);
	zassert_equal(result.passport_status,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS);
	zassert_equal(result.profile,
		      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT);
	zassert_str_equal(result.board, "qemu_x86_64");
	zassert_str_equal(result.top_candidate_id, top_a);
	zassert_str_equal(result.nonce_hex, nonce_a);
	zassert_str_equal(result.computed_digest_hex,
			  fixture.passport.passport_digest_hex);
	zassert_equal(
		pqcp_deployment_assurance_passport_replay_emit_result(&result),
		0);
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_passport_tamper_detected)
{
	struct fixture fixture;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_passport(&fixture);
	fixture.passport.passport_score =
		fixture.passport.passport_score > 0U ?
			fixture.passport.passport_score - 1U : 1U;
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, &result),
		      -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_DIGEST_MISMATCH);
	zassert_equal(
		pqcp_deployment_assurance_passport_replay_emit_result(&result),
		-EBADMSG);
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_identity_tamper_detected)
{
	struct fixture fixture;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_passport(&fixture);
	set_text(fixture.passport.board, sizeof(fixture.passport.board),
		 "tampered_board");
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_DIGEST_MISMATCH);
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_bad_schema_detected)
{
	struct fixture fixture;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_passport(&fixture);
	fixture.passport.schema_version = 99U;
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_BAD_SCHEMA);
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_unknown_mask_bits_fail)
{
	struct fixture fixture;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_passport(&fixture);
	fixture.passport.warning_mask |= 0x80000000U;
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MASK_RANGE);
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_status_inconsistency_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_passport(&fixture);
	fixture.passport.status = PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL;
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_STATUS_MISMATCH);
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_score_range_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_passport(&fixture);
	fixture.passport.min_terminal_score = 101U;
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_SCORE_RANGE);
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_invalid_arguments_rejected)
{
	struct fixture fixture;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_passport(&fixture);
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      NULL, &result),
		      -EINVAL);
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_assurance_passport_replay_emit_result(
			      NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_assurance_passport_replay, test_emit_rejects_invalid_result)
{
	struct fixture fixture;
	struct pqcp_deployment_assurance_passport_replay_result result;

	build_passport(&fixture);
	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, &result),
		      0);

	result.schema_version = 99U;
	zassert_equal(pqcp_deployment_assurance_passport_replay_emit_result(
			      &result),
		      -EINVAL);

	zassert_equal(pqcp_deployment_assurance_passport_replay_verify(
			      &fixture.passport, &result),
		      0);
	result.passport_score = 101U;
	zassert_equal(pqcp_deployment_assurance_passport_replay_emit_result(
			      &result),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_assurance_passport_replay, NULL, NULL, NULL, NULL,
	    NULL);
