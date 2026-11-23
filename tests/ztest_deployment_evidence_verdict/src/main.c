/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the firmware-native deployment evidence verdict.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_evidence_verdict.h>

static const char top_a[] = "hybrid768_65_campaign";
static const char top_b[] = "hybrid1024_87_campaign";
static const char nonce_a[] = "00112233445566778899aabbccddeeff";
static const char nonce_b[] = "ffeeddccbbaa99887766554433221100";
static const char trace_a[] =
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char trace_b[] =
	"1111111111111111111111111111111111111111111111111111111111111111";
static const char review_a[] =
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char review_b[] =
	"2222222222222222222222222222222222222222222222222222222222222222";
static const char device_a[] =
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char device_b[] =
	"3333333333333333333333333333333333333333333333333333333333333333";
static const char token_a[] =
	"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
static const char token_b[] =
	"4444444444444444444444444444444444444444444444444444444444444444";
static const char audit_a[] =
	"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

struct fixture {
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_pipeline_result pipeline;
	struct pqcp_deployment_budget_report budget;
	struct pqcp_deployment_experiment_plan experiments;
	struct pqcp_deployment_review_packet review_packet;
	struct pqcp_deployment_review_verifier_result review_replay;
	struct pqcp_deployment_review_audit_report review_audit;
	struct pqcp_deployment_release_gate_report release_gate;
	struct pqcp_deployment_device_token device_token;
	struct pqcp_deployment_device_token_verification token_verify;
	struct pqcp_deployment_device_token_replay_result token_replay;
	struct pqcp_deployment_device_token_audit_report token_audit;
	struct pqcp_deployment_device_gate_report device_gate;
	struct pqcp_deployment_device_packet device_packet;
	struct pqcp_deployment_device_packet_replay_result packet_replay;
	struct pqcp_deployment_device_packet_audit_report packet_audit;
	struct pqcp_deployment_evidence_verdict_policy policy;
	struct pqcp_deployment_evidence_verdict verdict;
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

static void fill_pipeline(struct pqcp_deployment_pipeline_result *pipeline)
{
	memset(pipeline, 0, sizeof(*pipeline));
	pipeline->schema_version = PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION;
	pipeline->candidate_count = 4U;
	pipeline->gap_count = 0U;
	pipeline->top_candidate_id = top_a;
	pipeline->top_candidate_score = 92U;
	pipeline->recommendation_ready = true;
	pipeline->replay_passed = true;
	pipeline->appraisal_passed = true;
	pipeline->claims_passed = true;
	pipeline->trace_digest.schema_version =
		PQCP_DEPLOYMENT_TRACE_BUILDER_SCHEMA_VERSION;
	pipeline->trace_digest.line_count = 12U;
	pipeline->trace_digest.byte_count = 1600U;
	pipeline->trace_digest.passed = true;
	set_text(pipeline->trace_digest.digest_hex,
		 sizeof(pipeline->trace_digest.digest_hex), trace_a);
	pipeline->passed = true;
}

static void fill_budget(struct pqcp_deployment_budget_report *budget)
{
	memset(budget, 0, sizeof(*budget));
	budget->schema_version = PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION;
	budget->profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT;
	budget->status = PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	budget->candidate_count = 4U;
	budget->pass_count = 1U;
	budget->top_candidate_id = top_a;
	budget->top_status = PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	budget->top_minimum_headroom_permille = 120;
	budget->top_margin_score = 90U;
	budget->pipeline_readiness_score = 91U;
	budget->claim_score = 88U;
	budget->pipeline_passed = true;
	budget->replay_passed = true;
	budget->appraisal_passed = true;
	budget->claims_passed = true;
}

static void fill_experiments(
	struct pqcp_deployment_experiment_plan *experiments)
{
	memset(experiments, 0, sizeof(*experiments));
	experiments->schema_version =
		PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION;
	experiments->status = PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS;
	experiments->top_candidate_id = top_a;
	experiments->budget_status = PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	experiments->pipeline_passed = true;
	experiments->replay_passed = true;
	experiments->appraisal_passed = true;
	experiments->claims_passed = true;
}

static void fill_review_packet(
	struct pqcp_deployment_review_packet *packet)
{
	memset(packet, 0, sizeof(*packet));
	packet->schema_version = PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION;
	packet->status = PQCP_DEPLOYMENT_REVIEW_PACKET_PASS;
	packet->line_count = 4U;
	packet->byte_count = 900U;
	packet->candidate_count = 4U;
	packet->top_candidate_id = top_a;
	packet->readiness_score = 91U;
	packet->claim_score = 88U;
	packet->review_score = 89U;
	packet->pipeline_passed = true;
	packet->replay_passed = true;
	packet->budget_passed = true;
	packet->experiment_plan_passed = true;
	set_text(packet->trace_digest_hex, sizeof(packet->trace_digest_hex),
		 trace_a);
	set_text(packet->packet_digest_hex, sizeof(packet->packet_digest_hex),
		 review_a);
}

static void fill_review_replay(
	struct pqcp_deployment_review_verifier_result *replay)
{
	memset(replay, 0, sizeof(*replay));
	replay->schema_version = PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION;
	replay->lines_seen = 5U;
	replay->marker_mask = PQCP_DEPLOYMENT_REVIEW_VERIFIER_REQUIRED_MASK;
	replay->fact_lines = 4U;
	replay->fact_bytes = 900U;
	replay->candidate_count = 4U;
	replay->readiness_score = 91U;
	replay->claim_score = 88U;
	replay->review_score = 89U;
	replay->first_error = PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_NONE;
	replay->packet_status = PQCP_DEPLOYMENT_REVIEW_PACKET_PASS;
	replay->passed = true;
	set_text(replay->top_candidate_id, sizeof(replay->top_candidate_id),
		 top_a);
	set_text(replay->trace_digest_hex, sizeof(replay->trace_digest_hex),
		 trace_a);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex), review_a);
}

static void fill_review_audit(
	struct pqcp_deployment_review_audit_report *audit)
{
	memset(audit, 0, sizeof(*audit));
	audit->schema_version = PQCP_DEPLOYMENT_REVIEW_AUDIT_SCHEMA_VERSION;
	audit->status = PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS;
	audit->result_count = 1U;
	audit->replay_pass_count = 1U;
	audit->packet_pass_count = 1U;
	audit->unique_packet_digest_count = 1U;
	audit->min_readiness_score = 91U;
	audit->min_claim_score = 88U;
	audit->min_review_score = 89U;
	audit->max_review_score = 89U;
	audit->avg_review_score = 89U;
	audit->stable_top_candidate = true;
	audit->stable_trace_digest = true;
	audit->stable_packet_digest = true;
	set_text(audit->top_candidate_id, sizeof(audit->top_candidate_id),
		 top_a);
	set_text(audit->trace_digest_hex, sizeof(audit->trace_digest_hex),
		 trace_a);
	set_text(audit->packet_digest_hex, sizeof(audit->packet_digest_hex),
		 review_a);
}

static void fill_release_gate(
	struct pqcp_deployment_release_gate_report *gate)
{
	memset(gate, 0, sizeof(*gate));
	gate->schema_version = PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION;
	gate->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	gate->status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	gate->candidate_count = 4U;
	gate->readiness_score = 91U;
	gate->claim_score = 88U;
	gate->review_score = 89U;
	gate->gate_score = 87U;
	gate->top_consistent = true;
	gate->digest_bound = true;
	gate->pipeline_passed = true;
	gate->budget_passed = true;
	gate->experiment_plan_passed = true;
	gate->packet_passed = true;
	gate->replay_passed = true;
	gate->audit_passed = true;
	set_text(gate->top_candidate_id, sizeof(gate->top_candidate_id), top_a);
	set_text(gate->trace_digest_hex, sizeof(gate->trace_digest_hex),
		 trace_a);
	set_text(gate->packet_digest_hex, sizeof(gate->packet_digest_hex),
		 review_a);
}

static void fill_device_token(struct pqcp_deployment_device_token *token)
{
	memset(token, 0, sizeof(*token));
	token->schema_version = PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION;
	token->status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	token->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	token->evidence_capabilities = full_caps();
	token->capability_readiness_score = 96U;
	token->gate_score = 87U;
	token->gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	token->capability_policy_passed = true;
	token->production_allowed = true;
	token->native_provider = true;
	token->gate_digest_bound = true;
	set_text(token->nonce_hex, sizeof(token->nonce_hex), nonce_a);
	set_text(token->top_candidate_id, sizeof(token->top_candidate_id),
		 top_a);
	set_text(token->trace_digest_hex, sizeof(token->trace_digest_hex),
		 trace_a);
	set_text(token->packet_digest_hex, sizeof(token->packet_digest_hex),
		 review_a);
	set_text(token->token_digest_hex, sizeof(token->token_digest_hex),
		 token_a);
}

static void fill_token_verify(
	struct pqcp_deployment_device_token_verification *verify)
{
	memset(verify, 0, sizeof(*verify));
	verify->schema_version = PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION;
	verify->passed = true;
	verify->expected_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	verify->observed_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	set_text(verify->expected_digest_hex,
		 sizeof(verify->expected_digest_hex), token_a);
	set_text(verify->observed_digest_hex,
		 sizeof(verify->observed_digest_hex), token_a);
}

static void fill_token_replay(
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
	replay->capability_readiness_score = 96U;
	replay->gate_score = 87U;
	set_text(replay->top_candidate_id, sizeof(replay->top_candidate_id),
		 top_a);
	set_text(replay->nonce_hex, sizeof(replay->nonce_hex), nonce_a);
	set_text(replay->token_digest_hex, sizeof(replay->token_digest_hex),
		 token_a);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex), token_a);
}

static void fill_token_audit(
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
	audit->min_capability_readiness_score = 96U;
	audit->min_gate_score = 87U;
	audit->max_gate_score = 87U;
	audit->avg_gate_score = 87U;
	audit->stable_nonce = true;
	audit->stable_top_candidate = true;
	audit->stable_token_digest = true;
	audit->stable_gate_status = true;
	set_text(audit->nonce_hex, sizeof(audit->nonce_hex), nonce_a);
	set_text(audit->top_candidate_id, sizeof(audit->top_candidate_id),
		 top_a);
	set_text(audit->token_digest_hex, sizeof(audit->token_digest_hex),
		 token_a);
}

static void fill_device_gate(struct pqcp_deployment_device_gate_report *gate)
{
	memset(gate, 0, sizeof(*gate));
	gate->schema_version = PQCP_DEPLOYMENT_DEVICE_GATE_SCHEMA_VERSION;
	gate->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	gate->status = PQCP_DEPLOYMENT_DEVICE_GATE_PASS;
	gate->evidence_capabilities = full_caps();
	gate->capability_readiness_score = 96U;
	gate->release_gate_score = 87U;
	gate->audit_min_gate_score = 87U;
	gate->release_gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	gate->token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	gate->audit_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS;
	gate->capability_policy_passed = true;
	gate->production_allowed = true;
	gate->native_provider = true;
	gate->verification_passed = true;
	gate->replay_passed = true;
	gate->top_consistent = true;
	gate->nonce_consistent = true;
	gate->token_digest_consistent = true;
	gate->release_digest_consistent = true;
	set_text(gate->top_candidate_id, sizeof(gate->top_candidate_id),
		 top_a);
	set_text(gate->nonce_hex, sizeof(gate->nonce_hex), nonce_a);
	set_text(gate->trace_digest_hex, sizeof(gate->trace_digest_hex),
		 trace_a);
	set_text(gate->packet_digest_hex, sizeof(gate->packet_digest_hex),
		 review_a);
	set_text(gate->token_digest_hex, sizeof(gate->token_digest_hex),
		 token_a);
}

static void fill_device_packet(
	struct pqcp_deployment_device_packet *packet)
{
	memset(packet, 0, sizeof(*packet));
	packet->schema_version = PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION;
	packet->status = PQCP_DEPLOYMENT_DEVICE_PACKET_PASS;
	packet->line_count = 6U;
	packet->byte_count = 1200U;
	packet->evidence_capabilities = full_caps();
	packet->capability_readiness_score = 96U;
	packet->release_gate_score = 87U;
	packet->audit_min_gate_score = 87U;
	packet->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
	packet->release_gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
	packet->token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
	packet->audit_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS;
	packet->device_gate_status = PQCP_DEPLOYMENT_DEVICE_GATE_PASS;
	packet->capability_policy_passed = true;
	packet->production_allowed = true;
	packet->native_provider = true;
	packet->verification_passed = true;
	packet->replay_passed = true;
	packet->top_consistent = true;
	packet->nonce_consistent = true;
	packet->token_digest_consistent = true;
	packet->release_digest_consistent = true;
	set_text(packet->top_candidate_id, sizeof(packet->top_candidate_id),
		 top_a);
	set_text(packet->nonce_hex, sizeof(packet->nonce_hex), nonce_a);
	set_text(packet->trace_digest_hex, sizeof(packet->trace_digest_hex),
		 trace_a);
	set_text(packet->packet_digest_hex, sizeof(packet->packet_digest_hex),
		 review_a);
	set_text(packet->token_digest_hex, sizeof(packet->token_digest_hex),
		 token_a);
	set_text(packet->device_packet_digest_hex,
		 sizeof(packet->device_packet_digest_hex), device_a);
}

static void fill_packet_replay(
	struct pqcp_deployment_device_packet_replay_result *replay)
{
	memset(replay, 0, sizeof(*replay));
	replay->schema_version =
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_SCHEMA_VERSION;
	replay->lines_seen = 7U;
	replay->marker_mask = PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_REQUIRED_MASK;
	replay->fact_lines = 6U;
	replay->fact_bytes = 1200U;
	replay->evidence_capabilities = full_caps();
	replay->capability_readiness_score = 96U;
	replay->release_gate_score = 87U;
	replay->audit_gate_score = 87U;
	replay->first_error =
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONE;
	replay->packet_status = PQCP_DEPLOYMENT_DEVICE_PACKET_PASS;
	replay->passed = true;
	set_text(replay->top_candidate_id, sizeof(replay->top_candidate_id),
		 top_a);
	set_text(replay->nonce_hex, sizeof(replay->nonce_hex), nonce_a);
	set_text(replay->computed_digest_hex,
		 sizeof(replay->computed_digest_hex), device_a);
}

static void fill_packet_audit(
	struct pqcp_deployment_device_packet_audit_report *audit)
{
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_SCHEMA_VERSION;
	audit->status = PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS;
	audit->result_count = 1U;
	audit->replay_pass_count = 1U;
	audit->packet_pass_count = 1U;
	audit->unique_packet_digest_count = 1U;
	audit->min_capability_readiness_score = 96U;
	audit->min_release_gate_score = 87U;
	audit->max_release_gate_score = 87U;
	audit->avg_release_gate_score = 87U;
	audit->min_audit_gate_score = 87U;
	audit->max_audit_gate_score = 87U;
	audit->avg_audit_gate_score = 87U;
	audit->evidence_capabilities_all = full_caps();
	audit->evidence_capabilities_any = full_caps();
	audit->stable_top_candidate = true;
	audit->stable_nonce = true;
	audit->stable_packet_digest = true;
	audit->stable_capabilities = true;
	audit->stable_packet_status = true;
	set_text(audit->top_candidate_id, sizeof(audit->top_candidate_id),
		 top_a);
	set_text(audit->nonce_hex, sizeof(audit->nonce_hex), nonce_a);
	set_text(audit->packet_digest_hex, sizeof(audit->packet_digest_hex),
		 device_a);
	set_text(audit->audit_digest_hex, sizeof(audit->audit_digest_hex),
		 audit_a);
}

static void fill_fixture(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fill_capability(&fixture->capability);
	fill_pipeline(&fixture->pipeline);
	fill_budget(&fixture->budget);
	fill_experiments(&fixture->experiments);
	fill_review_packet(&fixture->review_packet);
	fill_review_replay(&fixture->review_replay);
	fill_review_audit(&fixture->review_audit);
	fill_release_gate(&fixture->release_gate);
	fill_device_token(&fixture->device_token);
	fill_token_verify(&fixture->token_verify);
	fill_token_replay(&fixture->token_replay);
	fill_token_audit(&fixture->token_audit);
	fill_device_gate(&fixture->device_gate);
	fill_device_packet(&fixture->device_packet);
	fill_packet_replay(&fixture->packet_replay);
	fill_packet_audit(&fixture->packet_audit);
	zassert_equal(pqcp_deployment_evidence_verdict_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &fixture->policy),
		      0);
}

static int evaluate(struct fixture *fixture)
{
	return pqcp_deployment_evidence_verdict_evaluate(
		&fixture->capability, &fixture->pipeline, &fixture->budget,
		&fixture->experiments, &fixture->review_packet,
		&fixture->review_replay, &fixture->review_audit,
		&fixture->release_gate, &fixture->device_token,
		&fixture->token_verify, &fixture->token_replay,
		&fixture->token_audit, &fixture->device_gate,
		&fixture->device_packet, &fixture->packet_replay,
		&fixture->packet_audit, &fixture->policy,
		&fixture->verdict);
}

ZTEST(pqcp_deployment_evidence_verdict, test_status_tokens_are_stable)
{
	zassert_str_equal(pqcp_deployment_evidence_verdict_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS),
			  "PASS");
	zassert_str_equal(pqcp_deployment_evidence_verdict_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN),
			  "WARN");
	zassert_str_equal(pqcp_deployment_evidence_verdict_status_str(
				  PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL),
			  "FAIL");
	zassert_str_equal(pqcp_deployment_evidence_verdict_status_str(42),
			  "UNKNOWN");
}

ZTEST(pqcp_deployment_evidence_verdict, test_default_policies_are_profile_specific)
{
	struct pqcp_deployment_evidence_verdict_policy policy;

	zassert_equal(pqcp_deployment_evidence_verdict_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			      &policy),
		      0);
	zassert_equal(policy.profile,
		      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE);
	zassert_false(policy.score_floor_blocks);
	zassert_false(policy.require_release_gate_pass);

	zassert_equal(pqcp_deployment_evidence_verdict_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);
	zassert_true(policy.score_floor_blocks);
	zassert_true(policy.require_release_gate_pass);
	zassert_true(policy.require_device_token_pass);
	zassert_true(policy.require_device_packet_audit_pass);
	zassert_equal(pqcp_deployment_evidence_verdict_default_policy(99,
								      &policy),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_verdict, test_full_chain_passes)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(evaluate(&fixture), 0);
	zassert_equal(fixture.verdict.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS);
	zassert_equal(fixture.verdict.stage_count, 16U);
	zassert_equal(fixture.verdict.pass_count, 16U);
	zassert_equal(fixture.verdict.fail_count, 0U);
	zassert_equal(fixture.verdict.consistency_checks, 7U);
	zassert_equal(fixture.verdict.consistency_pass_count, 7U);
	zassert_true(fixture.verdict.top_consistent);
	zassert_true(fixture.verdict.nonce_consistent);
	zassert_true(fixture.verdict.trace_digest_consistent);
	zassert_true(fixture.verdict.review_packet_digest_consistent);
	zassert_true(fixture.verdict.device_packet_digest_consistent);
	zassert_true(fixture.verdict.token_digest_consistent);
	zassert_str_equal(fixture.verdict.top_candidate_id, top_a);
	zassert_str_equal(fixture.verdict.nonce_hex, nonce_a);
	zassert_str_equal(fixture.verdict.trace_digest_hex, trace_a);
	zassert_str_equal(fixture.verdict.review_packet_digest_hex, review_a);
	zassert_str_equal(fixture.verdict.device_packet_digest_hex, device_a);
	zassert_str_equal(fixture.verdict.token_digest_hex, token_a);
	zassert_true(fixture.verdict.verdict_digest_hex[0] != '\0');
	zassert_equal(pqcp_deployment_evidence_verdict_emit(
			      &fixture.verdict),
		      0);
}

ZTEST(pqcp_deployment_evidence_verdict, test_digest_is_stable_and_input_bound)
{
	struct fixture a;
	struct fixture b;

	fill_fixture(&a);
	fill_fixture(&b);
	zassert_equal(evaluate(&a), 0);
	zassert_equal(evaluate(&b), 0);
	zassert_str_equal(a.verdict.verdict_digest_hex,
			  b.verdict.verdict_digest_hex);

	b.release_gate.gate_score = 86U;
	b.device_token.gate_score = 86U;
	b.token_replay.gate_score = 86U;
	b.token_audit.min_gate_score = 86U;
	b.device_gate.release_gate_score = 86U;
	b.device_packet.release_gate_score = 86U;
	b.packet_replay.release_gate_score = 86U;
	b.packet_audit.min_release_gate_score = 86U;
	zassert_equal(evaluate(&b), 0);
	zassert_not_equal(strcmp(a.verdict.verdict_digest_hex,
				 b.verdict.verdict_digest_hex),
			  0);
}

ZTEST(pqcp_deployment_evidence_verdict, test_top_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.device_packet.top_candidate_id,
		 sizeof(fixture.device_packet.top_candidate_id), top_b);
	zassert_equal(evaluate(&fixture), -EBADMSG);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOP_MISMATCH) !=
		     0U);
	zassert_false(fixture.verdict.top_consistent);
}

ZTEST(pqcp_deployment_evidence_verdict, test_nonce_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.packet_audit.nonce_hex,
		 sizeof(fixture.packet_audit.nonce_hex), nonce_b);
	zassert_equal(evaluate(&fixture), -EBADMSG);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_NONCE_MISMATCH) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict, test_trace_digest_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.release_gate.trace_digest_hex,
		 sizeof(fixture.release_gate.trace_digest_hex), trace_b);
	zassert_equal(evaluate(&fixture), -EBADMSG);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TRACE_DIGEST) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict, test_review_digest_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.device_token.packet_digest_hex,
		 sizeof(fixture.device_token.packet_digest_hex), review_b);
	zassert_equal(evaluate(&fixture), -EBADMSG);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_DIGEST) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict, test_device_digest_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.packet_replay.computed_digest_hex,
		 sizeof(fixture.packet_replay.computed_digest_hex), device_b);
	zassert_equal(evaluate(&fixture), -EBADMSG);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_DIGEST) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict, test_token_digest_mismatch_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	set_text(fixture.token_verify.observed_digest_hex,
		 sizeof(fixture.token_verify.observed_digest_hex), token_b);
	zassert_equal(evaluate(&fixture), -EBADMSG);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOKEN_DIGEST) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict, test_missing_verdict_capability_fails)
{
	struct fixture fixture;
	const uint32_t missing =
		~PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT;

	fill_fixture(&fixture);
	fixture.capability.evidence_capabilities &= missing;
	fixture.device_token.evidence_capabilities &= missing;
	fixture.device_gate.evidence_capabilities &= missing;
	fixture.device_packet.evidence_capabilities &= missing;
	fixture.packet_replay.evidence_capabilities &= missing;
	fixture.packet_audit.evidence_capabilities_all &= missing;
	fixture.packet_audit.evidence_capabilities_any &= missing;
	zassert_equal(evaluate(&fixture), -EBADMSG);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_CAPABILITY_MISMATCH) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict, test_release_warning_can_be_nonblocking)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(pqcp_deployment_evidence_verdict_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			      &fixture.policy),
		      0);
	fixture.release_gate.status = PQCP_DEPLOYMENT_RELEASE_GATE_WARN;
	fixture.device_token.gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_WARN;
	fixture.token_replay.gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_WARN;
	fixture.device_gate.release_gate_status =
		PQCP_DEPLOYMENT_RELEASE_GATE_WARN;
	fixture.device_packet.release_gate_status =
		PQCP_DEPLOYMENT_RELEASE_GATE_WARN;
	zassert_equal(evaluate(&fixture), 0);
	zassert_equal(fixture.verdict.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN);
	zassert_equal(fixture.verdict.error_mask, 0U);
	zassert_true(fixture.verdict.warn_count > 0U);
}

ZTEST(pqcp_deployment_evidence_verdict, test_product_score_floor_fails)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	fixture.capability.evidence_readiness_score = 74U;
	fixture.device_token.capability_readiness_score = 74U;
	fixture.token_replay.capability_readiness_score = 74U;
	fixture.token_audit.min_capability_readiness_score = 74U;
	fixture.device_gate.capability_readiness_score = 74U;
	fixture.device_packet.capability_readiness_score = 74U;
	fixture.packet_replay.capability_readiness_score = 74U;
	fixture.packet_audit.min_capability_readiness_score = 74U;
	zassert_equal(evaluate(&fixture), -EBADMSG);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_SCORE_FLOOR) !=
		     0U);
}

ZTEST(pqcp_deployment_evidence_verdict, test_emit_rejects_unknown_masks)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(evaluate(&fixture), 0);
	fixture.verdict.warning_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_evidence_verdict_emit(
			      &fixture.verdict),
		      -EINVAL);
}

ZTEST(pqcp_deployment_evidence_verdict, test_invalid_input_fails_cleanly)
{
	struct fixture fixture;

	fill_fixture(&fixture);
	zassert_equal(pqcp_deployment_evidence_verdict_evaluate(
			      NULL, &fixture.pipeline, &fixture.budget,
			      &fixture.experiments, &fixture.review_packet,
			      &fixture.review_replay, &fixture.review_audit,
			      &fixture.release_gate, &fixture.device_token,
			      &fixture.token_verify, &fixture.token_replay,
			      &fixture.token_audit, &fixture.device_gate,
			      &fixture.device_packet, &fixture.packet_replay,
			      &fixture.packet_audit, &fixture.policy,
			      &fixture.verdict),
		      -EINVAL);
	zassert_equal(fixture.verdict.status,
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_INVALID_INPUT) !=
		     0U);

	fill_fixture(&fixture);
	fixture.packet_audit.min_audit_gate_score = 101U;
	zassert_equal(evaluate(&fixture), -EINVAL);
	zassert_true((fixture.verdict.error_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_INVALID_INPUT) !=
		     0U);
}

ZTEST_SUITE(pqcp_deployment_evidence_verdict, NULL, NULL, NULL, NULL, NULL);
