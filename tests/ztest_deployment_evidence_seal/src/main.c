/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the firmware-native terminal deployment evidence seal.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_seal.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char top_b[] = "hybrid1024_87_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char nonce_b[] = "ffeeddccbbaa99887766554433221100";
static const char verdict_digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char verdict_digest_b[] =
	"1111111111111111111111111111111111111111111111111111111111111111";
static const char audit_digest_a[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char trace_a[] =
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char review_a[] =
	"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
static const char device_a[] =
	"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
static const char token_a[] =
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

struct fixture {
	struct pqcp_deployment_evidence_verdict verdict;
	struct pqcp_deployment_evidence_verdict_replay_result replay;
	struct pqcp_deployment_evidence_verdict_audit_report audit;
	struct pqcp_deployment_evidence_seal_policy policy;
	struct pqcp_deployment_evidence_seal seal;
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

static void fill_verdict(struct pqcp_deployment_evidence_verdict *verdict)
{
	memset(verdict, 0, sizeof(*verdict));
	verdict->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_SCHEMA_VERSION;
	verdict->status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	verdict->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	verdict->verdict_score = 87U;
	verdict->min_chain_score = 87U;
	verdict->stage_count = 16U;
	verdict->pass_count = 16U;
	verdict->consistency_checks = 7U;
	verdict->consistency_pass_count = 7U;
	verdict->evidence_capabilities_all = full_caps();
	verdict->evidence_capabilities_any = full_caps();
	verdict->top_consistent = true;
	verdict->nonce_consistent = true;
	verdict->trace_digest_consistent = true;
	verdict->review_packet_digest_consistent = true;
	verdict->device_packet_digest_consistent = true;
	verdict->token_digest_consistent = true;
	set_text(verdict->top_candidate_id, sizeof(verdict->top_candidate_id),
		 top_a);
	set_text(verdict->nonce_hex, sizeof(verdict->nonce_hex), nonce_a);
	set_text(verdict->trace_digest_hex, sizeof(verdict->trace_digest_hex),
		 trace_a);
	set_text(verdict->review_packet_digest_hex,
		 sizeof(verdict->review_packet_digest_hex), review_a);
	set_text(verdict->device_packet_digest_hex,
		 sizeof(verdict->device_packet_digest_hex), device_a);
	set_text(verdict->token_digest_hex, sizeof(verdict->token_digest_hex),
		 token_a);
	set_text(verdict->packet_audit_digest_hex,
		 sizeof(verdict->packet_audit_digest_hex), device_a);
	set_text(verdict->verdict_digest_hex,
		 sizeof(verdict->verdict_digest_hex), verdict_digest_a);
}

static void fill_replay(
	struct pqcp_deployment_evidence_verdict_replay_result *replay)
{
	memset(replay, 0, sizeof(*replay));
	replay->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_SCHEMA_VERSION;
	replay->lines_seen = 1U;
	replay->marker_mask =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_REQUIRED_MASK;
	replay->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE;
	replay->verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	replay->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	replay->verdict_score = 87U;
	replay->min_chain_score = 87U;
	replay->stage_count = 16U;
	replay->consistency_checks = 7U;
	replay->consistency_pass_count = 7U;
	replay->evidence_capabilities_all = full_caps();
	replay->evidence_capabilities_any = full_caps();
	replay->passed = true;
	set_text(replay->top_candidate_id, sizeof(replay->top_candidate_id),
		 top_a);
	set_text(replay->nonce_hex, sizeof(replay->nonce_hex), nonce_a);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex), verdict_digest_a);
}

static void fill_audit(
	struct pqcp_deployment_evidence_verdict_audit_report *audit)
{
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_SCHEMA_VERSION;
	audit->status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS;
	audit->result_count = 1U;
	audit->replay_pass_count = 1U;
	audit->verdict_pass_count = 1U;
	audit->unique_verdict_digest_count = 1U;
	audit->min_verdict_score = 87U;
	audit->max_verdict_score = 87U;
	audit->avg_verdict_score = 87U;
	audit->min_chain_score = 87U;
	audit->max_chain_score = 87U;
	audit->avg_chain_score = 87U;
	audit->evidence_capabilities_all = full_caps();
	audit->evidence_capabilities_any = full_caps();
	audit->stable_top_candidate = true;
	audit->stable_nonce = true;
	audit->stable_verdict_digest = true;
	audit->stable_capabilities = true;
	audit->stable_verdict_status = true;
	audit->stable_profile = true;
	audit->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	set_text(audit->top_candidate_id, sizeof(audit->top_candidate_id),
		 top_a);
	set_text(audit->nonce_hex, sizeof(audit->nonce_hex), nonce_a);
	set_text(audit->verdict_digest_hex, sizeof(audit->verdict_digest_hex),
		 verdict_digest_a);
	set_text(audit->audit_digest_hex, sizeof(audit->audit_digest_hex),
		 audit_digest_a);
}

static void fill_fixture(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fill_verdict(&fixture->verdict);
	fill_replay(&fixture->replay);
	fill_audit(&fixture->audit);
	zassert_equal(pqcp_deployment_evidence_seal_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &fixture->policy),
		      0);
}

static int run_seal(struct fixture *fixture)
{
	return pqcp_deployment_evidence_seal_run(
		&fixture->verdict, &fixture->replay, &fixture->audit,
		&fixture->policy, &fixture->seal);
}

ZTEST(pqcp_deployment_evidence_seal, test_status_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_seal_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS),
			  "PASS");
	zassert_str_equal(pqcp_deployment_evidence_seal_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN),
			  "WARN");
	zassert_str_equal(pqcp_deployment_evidence_seal_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL),
			  "FAIL");
	zassert_str_equal(pqcp_deployment_evidence_seal_status_str(42),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_evidence_seal, test_default_policies_are_profile_specific)
{
	struct pqcp_deployment_evidence_seal_policy policy;

	zassert_equal(pqcp_deployment_evidence_seal_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			      &policy),
		      0);
	zassert_false(policy.score_floor_blocks);
	zassert_false(policy.require_verdict_pass);
	zassert_false(policy.require_audit_pass);
	zassert_true(policy.require_replay_pass);
	zassert_true(policy.require_consistency);
	zassert_true(policy.require_chain_capability);

	zassert_equal(pqcp_deployment_evidence_seal_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);
	zassert_true(policy.score_floor_blocks);
	zassert_true(policy.require_verdict_pass);
	zassert_true(policy.require_audit_pass);
	zassert_equal(policy.min_seal_score, 75U);

	zassert_equal(pqcp_deployment_evidence_seal_default_policy(99, &policy),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_seal, test_terminal_chain_seals)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(run_seal(&fixture), 0);
	zassert_equal(fixture.seal.status, PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS);
	zassert_equal(fixture.seal.error_mask, 0U);
	zassert_equal(fixture.seal.warning_mask, 0U);
	zassert_equal(fixture.seal.seal_score, 87U);
	zassert_equal(fixture.seal.min_terminal_score, 87U);
	zassert_equal(fixture.seal.verdict_status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS);
	zassert_equal(fixture.seal.audit_status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS);
	zassert_equal(fixture.seal.audited_result_count, 1U);
	zassert_equal(fixture.seal.chain_stage_count, 16U);
	zassert_equal(fixture.seal.chain_consistency_checks, 7U);
	zassert_true(fixture.seal.replay_passed);
	zassert_true(fixture.seal.top_consistent);
	zassert_true(fixture.seal.nonce_consistent);
	zassert_true(fixture.seal.verdict_digest_consistent);
	zassert_true(fixture.seal.profile_consistent);
	zassert_true(fixture.seal.status_consistent);
	zassert_str_equal(fixture.seal.top_candidate_id, top_a);
	zassert_str_equal(fixture.seal.nonce_hex, nonce_a);
	zassert_str_equal(fixture.seal.verdict_digest_hex, verdict_digest_a);
	zassert_str_equal(fixture.seal.audit_digest_hex, audit_digest_a);
	zassert_true(fixture.seal.seal_digest_hex[0] != '\0');
	zassert_equal(pqcp_deployment_evidence_seal_emit(&fixture.seal), 0);
}

ZTEST(pqcp_deployment_evidence_seal, test_seal_digest_is_input_bound)
{
	struct fixture a;
	struct fixture b;

	fill_fixture(&a);
	fill_fixture(&b);
	zassert_equal(run_seal(&a), 0);
	zassert_equal(run_seal(&b), 0);
	zassert_str_equal(a.seal.seal_digest_hex, b.seal.seal_digest_hex);

	b.verdict.verdict_score = 86U;
	b.replay.verdict_score = 86U;
	b.audit.min_verdict_score = 86U;
	zassert_equal(run_seal(&b), 0);
	zassert_not_equal(strcmp(a.seal.seal_digest_hex,
				 b.seal.seal_digest_hex),
			  0);
}

ZTEST(pqcp_deployment_evidence_seal, test_top_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.replay.top_candidate_id,
		 sizeof(fixture.replay.top_candidate_id), top_b);
	zassert_equal(run_seal(&fixture), -EBADMSG);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_TOP_MISMATCH) != 0U);
	zassert_false(fixture.seal.top_consistent);
	zassert_str_equal(fixture.seal.top_candidate_id, "none");
}

ZTEST(pqcp_deployment_evidence_seal, test_nonce_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.audit.nonce_hex, sizeof(fixture.audit.nonce_hex),
		 nonce_b);
	zassert_equal(run_seal(&fixture), -EBADMSG);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_NONCE_MISMATCH) !=
		     0U);
	zassert_false(fixture.seal.nonce_consistent);
}

ZTEST(pqcp_deployment_evidence_seal, test_digest_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.replay.computed_digest_hex,
		 sizeof(fixture.replay.computed_digest_hex),
		 verdict_digest_b);
	zassert_equal(run_seal(&fixture), -EBADMSG);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_DIGEST_MISMATCH) !=
		     0U);
	zassert_false(fixture.seal.verdict_digest_consistent);
}

ZTEST(pqcp_deployment_evidence_seal, test_profile_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.audit.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
	zassert_equal(run_seal(&fixture), -EBADMSG);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_PROFILE_MISMATCH) !=
		     0U);
	zassert_false(fixture.seal.profile_consistent);
}

ZTEST(pqcp_deployment_evidence_seal, test_replay_failure_blocks)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.replay.passed = false;
	zassert_equal(run_seal(&fixture), -EBADMSG);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_REPLAY) != 0U);
	zassert_false(fixture.seal.replay_passed);
}

ZTEST(pqcp_deployment_evidence_seal, test_verdict_warn_blocks_for_product)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.verdict.status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN;
	fixture.verdict.warning_mask =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_LOCAL_ONLY;
	fixture.replay.verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN;
	zassert_equal(run_seal(&fixture), -EBADMSG);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_VERDICT) != 0U);
}

ZTEST(pqcp_deployment_evidence_seal, test_verdict_warn_warns_for_prototype)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(pqcp_deployment_evidence_seal_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			      &fixture.policy),
		      0);
	fixture.verdict.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	fixture.replay.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	fixture.audit.profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	fixture.verdict.status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN;
	fixture.verdict.warning_mask =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_LOCAL_ONLY;
	fixture.replay.verdict_status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN;
	zassert_equal(run_seal(&fixture), 0);
	zassert_equal(fixture.seal.status, PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN);
	zassert_equal(fixture.seal.error_mask, 0U);
	zassert_true((fixture.seal.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_NOT_PRODUCT_PASS) !=
		     0U);
	zassert_true((fixture.seal.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_UPSTREAM_WARNINGS) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_seal, test_missing_capability_blocks)
{
	struct fixture fixture;
	const uint32_t missing =
		~PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT;

	fill_fixture(&fixture);
	fixture.verdict.evidence_capabilities_all &= missing;
	fixture.replay.evidence_capabilities_all &= missing;
	fixture.audit.evidence_capabilities_all &= missing;
	zassert_equal(run_seal(&fixture), -EBADMSG);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_CAPABILITY) != 0U);
}

ZTEST(pqcp_deployment_evidence_seal, test_product_score_floor_blocks)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.verdict.verdict_score = 74U;
	fixture.verdict.min_chain_score = 74U;
	fixture.replay.verdict_score = 74U;
	fixture.replay.min_chain_score = 74U;
	fixture.audit.min_verdict_score = 74U;
	fixture.audit.min_chain_score = 74U;
	zassert_equal(run_seal(&fixture), -EBADMSG);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_SCORE_FLOOR) != 0U);
}

ZTEST(pqcp_deployment_evidence_seal, test_low_sample_count_warns)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.policy.min_audit_samples = 3U;
	zassert_equal(run_seal(&fixture), 0);
	zassert_equal(fixture.seal.status, PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN);
	zassert_true((fixture.seal.warning_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_LOW_SAMPLE_COUNT) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_seal, test_invalid_input_fails_cleanly)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(pqcp_deployment_evidence_seal_run(
			      NULL, &fixture.replay, &fixture.audit,
			      &fixture.policy, &fixture.seal),
		      -EINVAL);
	zassert_equal(fixture.seal.status, PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_INVALID_INPUT) != 0U);

	fill_fixture(&fixture);
	fixture.audit.min_chain_score = 101U;
	zassert_equal(run_seal(&fixture), -EINVAL);
	zassert_true((fixture.seal.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_INVALID_INPUT) != 0U);

	fill_fixture(&fixture);
	fixture.replay.schema_version = 99U;
	zassert_equal(run_seal(&fixture), -EINVAL);

	zassert_equal(pqcp_deployment_evidence_seal_run(
			      &fixture.verdict, &fixture.replay,
			      &fixture.audit, &fixture.policy, NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_seal, test_emit_rejects_invalid_seal)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(run_seal(&fixture), 0);

	zassert_equal(pqcp_deployment_evidence_seal_emit(NULL), -EINVAL);

	fixture.seal.warning_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_evidence_seal_emit(&fixture.seal),
		      -EINVAL);

	zassert_equal(run_seal(&fixture), 0);
	fixture.seal.seal_score = 101U;
	zassert_equal(pqcp_deployment_evidence_seal_emit(&fixture.seal),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_seal, NULL, NULL, NULL, NULL, NULL);
