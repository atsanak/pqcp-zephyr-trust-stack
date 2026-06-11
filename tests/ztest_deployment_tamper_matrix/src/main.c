/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tests for the adversarial evidence tamper detection matrix.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_tamper_matrix.h>

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

static void build_chain(struct chain_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fill_verdict(&fixture->verdict);
	fill_verdict_replay(&fixture->verdict_replay);
	fill_verdict_audit(&fixture->verdict_audit);
	zassert_equal(pqcp_deployment_evidence_seal_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &fixture->seal_policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_run(
			      &fixture->verdict, &fixture->verdict_replay,
			      &fixture->verdict_audit, &fixture->seal_policy,
			      &fixture->seal),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_replay_verify(
			      &fixture->seal, &fixture->seal_replay),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_audit_default_policy(
			      &fixture->seal_audit_policy),
		      0);
	zassert_equal(pqcp_deployment_evidence_seal_audit_run(
			      &fixture->seal_replay, 1U,
			      &fixture->seal_audit_policy,
			      &fixture->seal_audit),
		      0);
	fill_capability(&fixture->capability);
	zassert_equal(pqcp_deployment_assurance_passport_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &fixture->passport_policy),
		      0);
	zassert_equal(pqcp_deployment_assurance_passport_run(
			      &fixture->capability, &fixture->seal,
			      &fixture->seal_replay, &fixture->seal_audit,
			      &fixture->passport_policy, &fixture->passport),
		      0);
}

ZTEST(pqcp_deployment_tamper_matrix, test_stage_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_tamper_stage_str(
				  PQCP_DEPLOYMENT_TAMPER_STAGE_VERDICT),
			  "verdict");
	zassert_str_equal(pqcp_deployment_tamper_stage_str(
				  PQCP_DEPLOYMENT_TAMPER_STAGE_SEAL),
			  "seal");
	zassert_str_equal(pqcp_deployment_tamper_stage_str(
				  PQCP_DEPLOYMENT_TAMPER_STAGE_PASSPORT),
			  "passport");
	zassert_str_equal(pqcp_deployment_tamper_stage_str(99), "unknown");
	zassert_str_equal(pqcp_deployment_tamper_matrix_status_str(
				  PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS),
			  "PASS");
	zassert_str_equal(pqcp_deployment_tamper_matrix_status_str(99),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_tamper_matrix, test_default_policy_is_strict)
{
	struct pqcp_deployment_tamper_matrix_policy policy;

	zassert_equal(pqcp_deployment_tamper_matrix_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);
	zassert_equal(policy.stage_mask,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_KNOWN_MASK);
	zassert_equal(policy.min_coverage_permille, 1000U);
	zassert_true(policy.require_full_detection);
	zassert_true(policy.require_controls_pass);
	zassert_true(policy.coverage_floor_blocks);

	zassert_equal(pqcp_deployment_tamper_matrix_default_policy(99,
								   &policy),
		      -EINVAL);
	zassert_equal(pqcp_deployment_tamper_matrix_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_tamper_matrix, test_genuine_chain_full_detection)
{
	struct pqcp_deployment_tamper_matrix_policy policy;

	build_chain(&chain);
	zassert_equal(pqcp_deployment_tamper_matrix_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);
	/* The fixture verdict carries a placeholder digest, so attack only
	 * the genuinely-digested seal and passport stages.
	 */
	policy.stage_mask = PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_SEAL_BIT |
			    PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_PASSPORT_BIT;

	zassert_equal(pqcp_deployment_tamper_matrix_run(
			      NULL, &chain.seal, &chain.passport, &policy,
			      &workspace, cells, ARRAY_SIZE(cells), &report),
		      0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_TAMPER_MATRIX_WARN);
	zassert_equal(report.error_mask, 0U);
	zassert_equal(report.warning_mask,
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_PARTIAL_STAGES);
	zassert_equal(report.cell_count,
		      2U * PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT);
	zassert_equal(report.control_count, 2U);
	zassert_equal(report.attack_count,
		      2U * (PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT - 1U));
	zassert_equal(report.detected_count, report.attack_count);
	zassert_equal(report.missed_count, 0U);
	zassert_equal(report.control_pass_count, 2U);
	zassert_equal(report.coverage_permille, 1000U);
	zassert_equal(report.verdict_class_mask, 0U);
	zassert_equal(report.seal_class_mask,
		      (1U << PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT) - 1U);
	zassert_equal(report.passport_class_mask,
		      (1U << PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT) - 1U);
	zassert_str_equal(report.seal_digest_hex,
			  chain.seal.seal_digest_hex);
	zassert_str_equal(report.passport_digest_hex,
			  chain.passport.passport_digest_hex);
	zassert_str_equal(report.top_candidate_id, top_a);
	zassert_str_equal(report.nonce_hex, nonce_a);

	/* Every cell emit must accept its own shape. */
	for (size_t i = 0U; i < report.cell_count; ++i) {
		zassert_true(cells[i].ok);
		zassert_equal(pqcp_deployment_tamper_cell_emit(&cells[i]), 0);
	}
	zassert_equal(pqcp_deployment_tamper_matrix_emit(&report), 0);
}

ZTEST(pqcp_deployment_tamper_matrix, test_corrupt_control_fails_matrix)
{
	struct pqcp_deployment_tamper_matrix_policy policy;

	build_chain(&chain);
	/* Corrupt the seal digest: the control cell must now fail because
	 * the unmodified marker no longer replays, proving the controls are
	 * real and a reject-everything verifier cannot fake coverage.
	 */
	chain.seal.seal_digest_hex[0] =
		chain.seal.seal_digest_hex[0] == '0' ? '1' : '0';

	zassert_equal(pqcp_deployment_tamper_matrix_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);
	policy.stage_mask = PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_SEAL_BIT;

	zassert_equal(pqcp_deployment_tamper_matrix_run(
			      NULL, &chain.seal, NULL, &policy, &workspace,
			      cells, ARRAY_SIZE(cells), &report),
		      -EBADMSG);
	zassert_equal(report.status, PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_CONTROL_FAILED) !=
		     0U);
	zassert_equal(report.control_pass_count, 0U);
}

ZTEST(pqcp_deployment_tamper_matrix, test_invalid_inputs_are_rejected)
{
	struct pqcp_deployment_tamper_matrix_policy policy;

	build_chain(&chain);
	zassert_equal(pqcp_deployment_tamper_matrix_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);

	/* Selected stage with NULL input. */
	zassert_equal(pqcp_deployment_tamper_matrix_run(
			      NULL, &chain.seal, &chain.passport, &policy,
			      &workspace, cells, ARRAY_SIZE(cells), &report),
		      -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_INVALID_INPUT) !=
		     0U);

	/* Empty stage mask. */
	policy.stage_mask = 0U;
	zassert_equal(pqcp_deployment_tamper_matrix_run(
			      &chain.verdict, &chain.seal, &chain.passport,
			      &policy, &workspace, cells, ARRAY_SIZE(cells),
			      &report),
		      -EINVAL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_NO_STAGES) != 0U);

	/* Cell array too small. */
	zassert_equal(pqcp_deployment_tamper_matrix_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);
	zassert_equal(pqcp_deployment_tamper_matrix_run(
			      &chain.verdict, &chain.seal, &chain.passport,
			      &policy, &workspace, cells, 4U, &report),
		      -EINVAL);

	/* NULL report. */
	zassert_equal(pqcp_deployment_tamper_matrix_run(
			      &chain.verdict, &chain.seal, &chain.passport,
			      &policy, &workspace, cells, ARRAY_SIZE(cells),
			      NULL),
		      -EINVAL);
}

ZTEST(pqcp_deployment_tamper_matrix, test_emit_rejects_tampered_report)
{
	struct pqcp_deployment_tamper_matrix_policy policy;

	build_chain(&chain);
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

	zassert_equal(pqcp_deployment_tamper_matrix_emit(NULL), -EINVAL);

	report.coverage_permille = 1001U;
	zassert_equal(pqcp_deployment_tamper_matrix_emit(&report), -EINVAL);

	report.coverage_permille = 1000U;
	report.warning_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_tamper_matrix_emit(&report), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_tamper_matrix, NULL, NULL, NULL, NULL, NULL);
