/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the firmware-native deployment assurance passport.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_assurance_passport.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char top_b[] = "hybrid1024_87_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char nonce_b[] = "ffeeddccbbaa99887766554433221100";
static const char seal_digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char seal_digest_b[] =
	"1111111111111111111111111111111111111111111111111111111111111111";
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

static void fill_fixture(struct fixture *fixture)
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
}

static int run_passport(struct fixture *fixture)
{
	return pqcp_deployment_assurance_passport_run(
		&fixture->capability, &fixture->seal, &fixture->seal_replay,
		&fixture->seal_audit, &fixture->policy, &fixture->passport);
}

ZTEST(pqcp_deployment_assurance_passport, test_status_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_assurance_passport_status_str(
				  PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS),
			  "PASS");
	zassert_str_equal(pqcp_deployment_assurance_passport_status_str(
				  PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN),
			  "WARN");
	zassert_str_equal(pqcp_deployment_assurance_passport_status_str(
				  PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL),
			  "FAIL");
	zassert_str_equal(pqcp_deployment_assurance_passport_status_str(42),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_assurance_passport, test_default_policies_are_profile_specific)
{
	struct pqcp_deployment_assurance_passport_policy policy;

	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			      &policy),
		      0);
	zassert_false(policy.score_floor_blocks);
	zassert_false(policy.require_seal_pass);
	zassert_false(policy.require_production_allowed);
	zassert_true(policy.require_seal_replay_pass);
	zassert_true(policy.require_consistency);
	zassert_true(policy.require_chain_capability);

	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);
	zassert_true(policy.score_floor_blocks);
	zassert_true(policy.require_seal_pass);
	zassert_true(policy.require_seal_audit_pass);
	zassert_true(policy.require_production_allowed);
	zassert_equal(policy.min_passport_score, 75U);

	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      99, &policy),
		      -EINVAL);
	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_assurance_passport, test_terminal_chain_issues_passport)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(run_passport(&fixture), 0);
	zassert_equal(fixture.passport.status,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS);
	zassert_equal(fixture.passport.error_mask, 0U);
	zassert_equal(fixture.passport.warning_mask, 0U);
	zassert_equal(fixture.passport.passport_score, 87U);
	zassert_equal(fixture.passport.min_terminal_score, 87U);
	zassert_equal(fixture.passport.capability_readiness_score, 96U);
	zassert_equal(fixture.passport.seal_status,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS);
	zassert_equal(fixture.passport.seal_audit_status,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS);
	zassert_equal(fixture.passport.audited_result_count, 1U);
	zassert_equal(fixture.passport.chain_stage_count, 16U);
	zassert_equal(fixture.passport.mlkem_level_mask, 0x00000300U);
	zassert_equal(fixture.passport.mldsa_level_mask, 0x00000041U);
	zassert_true(fixture.passport.seal_replay_passed);
	zassert_true(fixture.passport.top_consistent);
	zassert_true(fixture.passport.nonce_consistent);
	zassert_true(fixture.passport.seal_digest_consistent);
	zassert_true(fixture.passport.profile_consistent);
	zassert_true(fixture.passport.production_allowed);
	zassert_str_equal(fixture.passport.pqcp_version, "1.0.0");
	zassert_str_equal(fixture.passport.zephyr_version, "4.4.0");
	zassert_str_equal(fixture.passport.board, "qemu_x86_64");
	zassert_str_equal(fixture.passport.top_candidate_id, top_a);
	zassert_str_equal(fixture.passport.nonce_hex, nonce_a);
	zassert_str_equal(fixture.passport.seal_digest_hex, seal_digest_a);
	zassert_str_equal(fixture.passport.seal_audit_digest_hex,
			  audit_digest_a);
	zassert_true(fixture.passport.passport_digest_hex[0] != '\0');
	zassert_equal(pqcp_deployment_assurance_passport_emit(
			      &fixture.passport),
		      0);
}

ZTEST(pqcp_deployment_assurance_passport, test_passport_digest_is_input_bound)
{
	struct fixture a;
	struct fixture b;

	fill_fixture(&a);
	fill_fixture(&b);
	zassert_equal(run_passport(&a), 0);
	zassert_equal(run_passport(&b), 0);
	zassert_str_equal(a.passport.passport_digest_hex,
			  b.passport.passport_digest_hex);

	b.capability.board = "nucleo_h743zi";
	zassert_equal(run_passport(&b), 0);
	zassert_not_equal(strcmp(a.passport.passport_digest_hex,
				 b.passport.passport_digest_hex),
			  0);
}

ZTEST(pqcp_deployment_assurance_passport, test_top_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.seal_replay.top_candidate_id,
		 sizeof(fixture.seal_replay.top_candidate_id), top_b);
	zassert_equal(run_passport(&fixture), -EBADMSG);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_TOP_MISMATCH) !=
		     0U);
	zassert_false(fixture.passport.top_consistent);
	zassert_str_equal(fixture.passport.top_candidate_id, "none");
}

ZTEST(pqcp_deployment_assurance_passport, test_nonce_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.seal_audit.nonce_hex,
		 sizeof(fixture.seal_audit.nonce_hex), nonce_b);
	zassert_equal(run_passport(&fixture), -EBADMSG);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_NONCE_MISMATCH) !=
		     0U);
	zassert_false(fixture.passport.nonce_consistent);
}

ZTEST(pqcp_deployment_assurance_passport, test_seal_digest_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.seal_replay.computed_digest_hex,
		 sizeof(fixture.seal_replay.computed_digest_hex),
		 seal_digest_b);
	zassert_equal(run_passport(&fixture), -EBADMSG);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_DIGEST_MISMATCH) !=
		     0U);
	zassert_false(fixture.passport.seal_digest_consistent);
}

ZTEST(pqcp_deployment_assurance_passport, test_seal_replay_failure_blocks)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.seal_replay.passed = false;
	zassert_equal(run_passport(&fixture), -EBADMSG);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL_REPLAY) !=
		     0U);
	zassert_false(fixture.passport.seal_replay_passed);
}

ZTEST(pqcp_deployment_assurance_passport, test_seal_warn_blocks_for_product)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.seal.status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN;
	fixture.seal.warning_mask =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_NOT_PRODUCT_PASS;
	fixture.seal_replay.seal_status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN;
	zassert_equal(run_passport(&fixture), -EBADMSG);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL) != 0U);
}

ZTEST(pqcp_deployment_assurance_passport, test_seal_warn_warns_for_prototype)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			      &fixture.policy),
		      0);
	fixture.seal.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	fixture.seal_replay.profile =
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	fixture.seal_audit.profile =
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	fixture.seal.status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN;
	fixture.seal.warning_mask =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_NOT_PRODUCT_PASS;
	fixture.seal_replay.seal_status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN;
	zassert_equal(run_passport(&fixture), 0);
	zassert_equal(fixture.passport.status,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN);
	zassert_equal(fixture.passport.error_mask, 0U);
	zassert_true((fixture.passport.warning_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_NOT_PRODUCT_PASS) !=
		     0U);
	zassert_true((fixture.passport.warning_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_UPSTREAM_WARNINGS) !=
		     0U);
}

ZTEST(pqcp_deployment_assurance_passport, test_not_production_blocks_for_product)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.capability.production_allowed = false;
	zassert_equal(run_passport(&fixture), -EBADMSG);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_NOT_PRODUCTION) !=
		     0U);
	zassert_false(fixture.passport.production_allowed);

	fill_fixture(&fixture);
	fixture.capability.production_allowed = false;
	fixture.policy.require_production_allowed = false;
	zassert_equal(run_passport(&fixture), 0);
	zassert_equal(fixture.passport.status,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN);
	zassert_true((fixture.passport.warning_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_LOCAL_ONLY) !=
		     0U);
}

ZTEST(pqcp_deployment_assurance_passport, test_missing_capability_blocks)
{
	struct fixture fixture;
	const uint32_t missing =
		~PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT;

	fill_fixture(&fixture);
	fixture.capability.evidence_capabilities &= missing;
	fixture.seal.evidence_capabilities_all &= missing;
	fixture.seal_replay.evidence_capabilities_all &= missing;
	fixture.seal_audit.evidence_capabilities_all &= missing;
	zassert_equal(run_passport(&fixture), -EBADMSG);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_CAPABILITY_MISMATCH) !=
		     0U);
}

ZTEST(pqcp_deployment_assurance_passport, test_product_score_floor_blocks)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.seal.seal_score = 74U;
	fixture.seal.min_terminal_score = 74U;
	fixture.seal_replay.seal_score = 74U;
	fixture.seal_replay.min_terminal_score = 74U;
	fixture.seal_audit.min_seal_score = 74U;
	fixture.seal_audit.min_terminal_score = 74U;
	zassert_equal(run_passport(&fixture), -EBADMSG);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SCORE_FLOOR) !=
		     0U);
}

ZTEST(pqcp_deployment_assurance_passport, test_invalid_input_fails_cleanly)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(pqcp_deployment_assurance_passport_run(
			      NULL, &fixture.seal, &fixture.seal_replay,
			      &fixture.seal_audit, &fixture.policy,
			      &fixture.passport),
		      -EINVAL);
	zassert_equal(fixture.passport.status,
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_INVALID_INPUT) !=
		     0U);

	fill_fixture(&fixture);
	fixture.seal_audit.min_terminal_score = 101U;
	zassert_equal(run_passport(&fixture), -EINVAL);
	zassert_true((fixture.passport.error_mask &
		      PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_INVALID_INPUT) !=
		     0U);

	fill_fixture(&fixture);
	fixture.seal.schema_version = 99U;
	zassert_equal(run_passport(&fixture), -EINVAL);

	zassert_equal(pqcp_deployment_assurance_passport_run(
			      &fixture.capability, &fixture.seal,
			      &fixture.seal_replay, &fixture.seal_audit,
			      &fixture.policy, NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_assurance_passport, test_emit_rejects_invalid_passport)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(run_passport(&fixture), 0);

	zassert_equal(pqcp_deployment_assurance_passport_emit(NULL), -EINVAL);

	fixture.passport.warning_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_assurance_passport_emit(
			      &fixture.passport),
		      -EINVAL);

	zassert_equal(run_passport(&fixture), 0);
	fixture.passport.passport_score = 101U;
	zassert_equal(pqcp_deployment_assurance_passport_emit(
			      &fixture.passport),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_assurance_passport, NULL, NULL, NULL, NULL, NULL);
