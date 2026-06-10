/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for the firmware-native deployment evidence seal replay verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_seal_replay.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char verdict_digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char audit_digest_a[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct fixture {
	struct pqcp_deployment_evidence_verdict verdict;
	struct pqcp_deployment_evidence_verdict_replay_result verdict_replay;
	struct pqcp_deployment_evidence_verdict_audit_report verdict_audit;
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
		 verdict_digest_a);
	set_text(verdict->review_packet_digest_hex,
		 sizeof(verdict->review_packet_digest_hex), verdict_digest_a);
	set_text(verdict->device_packet_digest_hex,
		 sizeof(verdict->device_packet_digest_hex), verdict_digest_a);
	set_text(verdict->token_digest_hex, sizeof(verdict->token_digest_hex),
		 verdict_digest_a);
	set_text(verdict->packet_audit_digest_hex,
		 sizeof(verdict->packet_audit_digest_hex), verdict_digest_a);
	set_text(verdict->verdict_digest_hex,
		 sizeof(verdict->verdict_digest_hex), verdict_digest_a);
}

static void fill_verdict_replay(
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

static void fill_verdict_audit(
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

static void build_seal(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fill_verdict(&fixture->verdict);
	fill_verdict_replay(&fixture->verdict_replay);
	fill_verdict_audit(&fixture->verdict_audit);
	zassert_equal(pqcp_deployment_evidence_seal_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &fixture->policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_run(
			      &fixture->verdict, &fixture->verdict_replay,
			      &fixture->verdict_audit, &fixture->policy,
			      &fixture->seal),
		      0);
	zassert_equal(fixture->seal.status,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS);
}

static void format_marker_line(
	const struct pqcp_deployment_evidence_seal *seal,
	char *line,
	size_t line_size)
{
	int written = snprintk(
		line, line_size,
		"PQCP_DEPLOYMENT_EVIDENCE_SEAL schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x score=%u min_score=%u verdict_status=%s audit_status=%s replay_passed=%u audited_results=%u chain_stages=%u chain_consistency=%u evidence_all=0x%08x evidence_any=0x%08x top_consistent=%u nonce_consistent=%u digest_consistent=%u profile_consistent=%u status_consistent=%u top=%s nonce=%s verdict_digest=%s audit_digest=%s seal_digest=%s",
		seal->schema_version,
		pqcp_deployment_release_gate_profile_str(seal->profile),
		pqcp_deployment_evidence_seal_status_str(seal->status),
		seal->error_mask,
		seal->warning_mask,
		seal->seal_score,
		seal->min_terminal_score,
		pqcp_deployment_evidence_verdict_status_str(
			seal->verdict_status),
		pqcp_deployment_evidence_verdict_audit_status_str(
			seal->audit_status),
		seal->replay_passed ? 1U : 0U,
		seal->audited_result_count,
		seal->chain_stage_count,
		seal->chain_consistency_checks,
		seal->evidence_capabilities_all,
		seal->evidence_capabilities_any,
		seal->top_consistent ? 1U : 0U,
		seal->nonce_consistent ? 1U : 0U,
		seal->verdict_digest_consistent ? 1U : 0U,
		seal->profile_consistent ? 1U : 0U,
		seal->status_consistent ? 1U : 0U,
		seal->top_candidate_id,
		seal->nonce_hex,
		seal->verdict_digest_hex,
		seal->audit_digest_hex,
		seal->seal_digest_hex);

	zassert_true(written > 0);
	zassert_true((size_t)written < line_size);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_error_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_seal_replay_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE),
			  "none");
	zassert_str_equal(pqcp_deployment_evidence_seal_replay_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DIGEST_MISMATCH),
			  "digest_mismatch");
	zassert_str_equal(pqcp_deployment_evidence_seal_replay_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DUPLICATE_MARKER),
			  "duplicate_marker");
	zassert_str_equal(pqcp_deployment_evidence_seal_replay_error_str(
				  PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MISSING_REQUIRED),
			  "missing_required");
	zassert_str_equal(pqcp_deployment_evidence_seal_replay_error_str(99),
			  "unknown");
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_struct_verify_passes)
{
	struct fixture fixture;
	struct pqcp_deployment_evidence_seal_replay_result result;

	build_seal(&fixture);
	zassert_equal(pqcp_deployment_evidence_seal_replay_verify(
			      &fixture.seal, &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE);
	zassert_equal(result.seal_status, PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS);
	zassert_equal(result.profile,
		      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT);
	zassert_equal(result.chain_stage_count, 16U);
	zassert_str_equal(result.top_candidate_id, top_a);
	zassert_str_equal(result.nonce_hex, nonce_a);
	zassert_str_equal(result.computed_digest_hex,
			  fixture.seal.seal_digest_hex);
	zassert_equal(pqcp_deployment_evidence_seal_replay_emit_result(
			      &result),
		      0);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_struct_verify_detects_tamper)
{
	struct fixture fixture;
	struct pqcp_deployment_evidence_seal_replay_result result;

	build_seal(&fixture);
	fixture.seal.seal_score = fixture.seal.seal_score > 0U ?
		fixture.seal.seal_score - 1U : 1U;
	zassert_equal(pqcp_deployment_evidence_seal_replay_verify(
			      &fixture.seal, &result),
		      -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DIGEST_MISMATCH);
	zassert_equal(pqcp_deployment_evidence_seal_replay_emit_result(
			      &result),
		      -EBADMSG);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_marker_line_replays)
{
	struct fixture fixture;
	struct pqcp_deployment_evidence_seal_replay_state state;
	struct pqcp_deployment_evidence_seal_replay_result result;
	char line[1024];

	build_seal(&fixture);
	format_marker_line(&fixture.seal, line, sizeof(line));

	zassert_equal(pqcp_deployment_evidence_seal_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_finish(
			      &state, &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.lines_seen, 1U);
	zassert_equal(result.marker_mask,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_REQUIRED_MASK);
	zassert_str_equal(result.computed_digest_hex,
			  fixture.seal.seal_digest_hex);
	zassert_equal(pqcp_deployment_evidence_seal_replay_emit_result(
			      &result),
		      0);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_noise_lines_are_ignored)
{
	struct fixture fixture;
	struct pqcp_deployment_evidence_seal_replay_state state;
	struct pqcp_deployment_evidence_seal_replay_result result;
	char line[1024];

	build_seal(&fixture);
	format_marker_line(&fixture.seal, line, sizeof(line));

	zassert_equal(pqcp_deployment_evidence_seal_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state, "BOOT banner"),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state,
			      "PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY schema=1"),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state,
			      "PQCP_DEPLOYMENT_EVIDENCE_VERDICT schema=1 status=PASS"),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_finish(
			      &state, &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.lines_seen, 1U);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_tampered_line_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_evidence_seal_replay_state state;
	struct pqcp_deployment_evidence_seal_replay_result result;
	char line[1024];
	char *score_field;

	build_seal(&fixture);
	format_marker_line(&fixture.seal, line, sizeof(line));

	/* Bump the reported score without recomputing the bound digest. */
	score_field = strstr(line, " score=");
	zassert_not_null(score_field);
	score_field[7] = score_field[7] == '9' ? '8' : '9';

	zassert_equal(pqcp_deployment_evidence_seal_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_finish(
			      &state, &result),
		      -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DIGEST_MISMATCH);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_duplicate_marker_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_evidence_seal_replay_state state;
	struct pqcp_deployment_evidence_seal_replay_result result;
	char line[1024];

	build_seal(&fixture);
	format_marker_line(&fixture.seal, line, sizeof(line));

	zassert_equal(pqcp_deployment_evidence_seal_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state, line),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state, line),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_replay_finish(
			      &state, &result),
		      -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DUPLICATE_MARKER);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_missing_marker_fails)
{
	struct pqcp_deployment_evidence_seal_replay_state state;
	struct pqcp_deployment_evidence_seal_replay_result result;

	zassert_equal(pqcp_deployment_evidence_seal_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_finish(
			      &state, &result),
		      -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MISSING_REQUIRED);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_malformed_marker_fails)
{
	struct pqcp_deployment_evidence_seal_replay_state state;
	struct pqcp_deployment_evidence_seal_replay_result result;

	zassert_equal(pqcp_deployment_evidence_seal_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state,
			      "PQCP_DEPLOYMENT_EVIDENCE_SEAL schema=1 status=PASS"),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_replay_finish(
			      &state, &result),
		      -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MALFORMED_FIELD);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_unknown_mask_bits_fail)
{
	struct fixture fixture;
	struct pqcp_deployment_evidence_seal_replay_result result;

	build_seal(&fixture);
	fixture.seal.warning_mask |= 0x80000000U;
	zassert_equal(pqcp_deployment_evidence_seal_replay_verify(
			      &fixture.seal, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MASK_RANGE);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_status_inconsistency_fails)
{
	struct fixture fixture;
	struct pqcp_deployment_evidence_seal_replay_result result;

	build_seal(&fixture);
	fixture.seal.status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL;
	zassert_equal(pqcp_deployment_evidence_seal_replay_verify(
			      &fixture.seal, &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_STATUS_MISMATCH);
}

ZTEST(pqcp_deployment_evidence_seal_replay, test_invalid_arguments_rejected)
{
	struct fixture fixture;
	struct pqcp_deployment_evidence_seal_replay_state state;
	struct pqcp_deployment_evidence_seal_replay_result result;

	build_seal(&fixture);
	zassert_equal(pqcp_deployment_evidence_seal_replay_init(NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      &state, NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_replay_ingest_line(
			      NULL, "x"),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_replay_finish(
			      NULL, &result),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_replay_finish(
			      &state, NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_replay_verify(
			      NULL, &result),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_replay_verify(
			      &fixture.seal, NULL),
		      -EINVAL);
	zassert_equal(pqcp_deployment_evidence_seal_replay_emit_result(NULL),
		      -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_evidence_seal_replay, NULL, NULL, NULL, NULL,
	    NULL);
