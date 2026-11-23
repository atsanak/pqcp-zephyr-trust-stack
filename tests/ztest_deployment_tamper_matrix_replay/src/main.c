/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the tamper matrix replay verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_tamper_matrix_replay.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char verdict_digest_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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

struct chain_fixture {
	struct pqcp_deployment_evidence_verdict verdict;
	struct pqcp_deployment_evidence_verdict_replay_result verdict_replay;
	struct pqcp_deployment_evidence_verdict_audit_report verdict_audit;
	struct pqcp_deployment_evidence_seal_policy seal_policy;
	struct pqcp_deployment_evidence_seal seal;
	struct pqcp_deployment_evidence_seal_replay_result seal_replay;
	struct pqcp_deployment_evidence_seal_audit_policy seal_audit_policy;
	struct pqcp_deployment_evidence_seal_audit_report seal_audit;
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_assurance_passport_policy passport_policy;
	struct pqcp_deployment_assurance_passport passport;
};

static struct chain_fixture chain;
static struct pqcp_deployment_tamper_matrix_workspace workspace;
static struct pqcp_deployment_tamper_cell cells[
	PQCP_DEPLOYMENT_TAMPER_MATRIX_MAX_CELLS];
static struct pqcp_deployment_tamper_matrix_report report;
static char marker_line[1280];

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

static void build_matrix(void)
{
	struct pqcp_deployment_tamper_matrix_policy policy;

	memset(&chain, 0, sizeof(chain));
	fill_verdict(&chain.verdict);
	fill_verdict_replay(&chain.verdict_replay);
	fill_verdict_audit(&chain.verdict_audit);
	zassert_equal(pqcp_deployment_evidence_seal_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &chain.seal_policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_run(
			      &chain.verdict, &chain.verdict_replay,
			      &chain.verdict_audit, &chain.seal_policy,
			      &chain.seal),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_verify(
			      &chain.seal, &chain.seal_replay),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_audit_default_policy(
			      &chain.seal_audit_policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_audit_run(
			      &chain.seal_replay, 1U,
			      &chain.seal_audit_policy, &chain.seal_audit),
		      0);
	fill_capability(&chain.capability);
	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &chain.passport_policy),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_run(
			      &chain.capability, &chain.seal,
			      &chain.seal_replay, &chain.seal_audit,
			      &chain.passport_policy, &chain.passport),
		      0);

	zassert_equal(pqcp_deployment_tamper_matrix_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);
	policy.stage_mask = PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_SEAL_BIT |
			    PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_PASSPORT_BIT;
	zassert_equal(pqcp_deployment_tamper_matrix_run(
			      NULL, &chain.seal, &chain.passport, &policy,
			      &workspace, cells, ARRAY_SIZE(cells), &report),
		      0);
}

/* Mirror of the PQCP_DEPLOYMENT_TAMPER_MATRIX emit layout, so the marker
 * ingestion path can be exercised against a transcript-shaped line.
 */
static void render_matrix_marker(
	const struct pqcp_deployment_tamper_matrix_report *src,
	char *out, size_t out_size)
{
	int written = snprintk(
		out, out_size,
		"PQCP_DEPLOYMENT_TAMPER_MATRIX schema=%u profile=product status=%s errors=0x%08x warnings=0x%08x stage_mask=0x%02x cells=%u controls=%u attacks=%u detected=%u missed=%u controls_passed=%u coverage_permille=%u verdict_class_mask=0x%08x seal_class_mask=0x%08x passport_class_mask=0x%08x top=%s nonce=%s verdict_digest=%s seal_digest=%s passport_digest=%s matrix_digest=%s",
		src->schema_version,
		pqcp_deployment_tamper_matrix_status_str(src->status),
		src->error_mask,
		src->warning_mask,
		src->stage_mask,
		src->cell_count,
		src->control_count,
		src->attack_count,
		src->detected_count,
		src->missed_count,
		src->control_pass_count,
		src->coverage_permille,
		src->verdict_class_mask,
		src->seal_class_mask,
		src->passport_class_mask,
		src->top_candidate_id,
		src->nonce_hex,
		src->verdict_digest_hex,
		src->seal_digest_hex,
		src->passport_digest_hex,
		src->matrix_digest_hex);

	zassert_true(written > 0 && (size_t)written < out_size);
}

ZTEST(pqcp_deployment_tamper_matrix_replay, test_struct_verify_passes)
{
	struct pqcp_deployment_tamper_matrix_replay_result result;

	build_matrix();
	zassert_equal(pqcp_deployment_tamper_matrix_replay_verify(&report,
								  &result),
		      0);
	zassert_true(result.passed);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE);
	zassert_str_equal(result.computed_digest_hex,
			  report.matrix_digest_hex);
	zassert_equal(result.coverage_permille, 1000U);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_emit_result(
			      &result),
		      0);
}

ZTEST(pqcp_deployment_tamper_matrix_replay, test_struct_tampering_is_detected)
{
	struct pqcp_deployment_tamper_matrix_replay_result result;

	build_matrix();
	report.detected_count -= 1U;
	report.missed_count += 1U;
	zassert_equal(pqcp_deployment_tamper_matrix_replay_verify(&report,
								  &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_COUNT_MISMATCH);

	build_matrix();
	report.coverage_permille = 999U;
	zassert_equal(pqcp_deployment_tamper_matrix_replay_verify(&report,
								  &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_COVERAGE_MISMATCH);

	build_matrix();
	report.matrix_digest_hex[0] =
		report.matrix_digest_hex[0] == '0' ? '1' : '0';
	zassert_equal(pqcp_deployment_tamper_matrix_replay_verify(&report,
								  &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DIGEST_MISMATCH);

	build_matrix();
	report.schema_version = 99U;
	zassert_equal(pqcp_deployment_tamper_matrix_replay_verify(&report,
								  &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_BAD_SCHEMA);

	build_matrix();
	report.status = PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS;
	zassert_equal(pqcp_deployment_tamper_matrix_replay_verify(&report,
								  &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_STATUS_MISMATCH);
}

ZTEST(pqcp_deployment_tamper_matrix_replay, test_marker_ingest_round_trips)
{
	static struct pqcp_deployment_tamper_matrix_replay_state state;
	struct pqcp_deployment_tamper_matrix_replay_result result;

	build_matrix();
	render_matrix_marker(&report, marker_line, sizeof(marker_line));

	zassert_equal(pqcp_deployment_tamper_matrix_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_ingest_line(
			      &state, "unrelated line"),
		      0);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_ingest_line(
			      &state, marker_line),
		      0);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_finish(&state,
								  &result),
		      0);
	zassert_true(result.passed);
	zassert_str_equal(result.computed_digest_hex,
			  report.matrix_digest_hex);
	zassert_str_equal(result.passport_digest_hex,
			  report.passport_digest_hex);
}

ZTEST(pqcp_deployment_tamper_matrix_replay, test_marker_ingest_negative_paths)
{
	static struct pqcp_deployment_tamper_matrix_replay_state state;
	struct pqcp_deployment_tamper_matrix_replay_result result;

	build_matrix();
	render_matrix_marker(&report, marker_line, sizeof(marker_line));

	/* Duplicate matrix marker. */
	zassert_equal(pqcp_deployment_tamper_matrix_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_ingest_line(
			      &state, marker_line),
		      0);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_ingest_line(
			      &state, marker_line),
		      -EINVAL);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_finish(&state,
								  &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DUPLICATE_MARKER);

	/* Missing matrix marker. */
	zassert_equal(pqcp_deployment_tamper_matrix_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_finish(&state,
								  &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MISSING_REQUIRED);

	/* Tampered digest inside the marker text. */
	render_matrix_marker(&report, marker_line, sizeof(marker_line));
	marker_line[strlen(marker_line) - 1U] =
		marker_line[strlen(marker_line) - 1U] == '0' ? '1' : '0';
	zassert_equal(pqcp_deployment_tamper_matrix_replay_init(&state), 0);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_ingest_line(
			      &state, marker_line),
		      0);
	zassert_equal(pqcp_deployment_tamper_matrix_replay_finish(&state,
								  &result),
		      -EBADMSG);
	zassert_equal(result.first_error,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DIGEST_MISMATCH);
}

ZTEST_SUITE(pqcp_deployment_tamper_matrix_replay, NULL, NULL, NULL, NULL,
	    NULL);
