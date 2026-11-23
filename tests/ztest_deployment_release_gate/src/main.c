/*
 * SPDX-License-Identifier: MIT
 */

#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_release_gate.h>

static const char trace_digest[] =
	"4b4bb88a348a502d14463d286ae65e56d1e7404fc94ee8980ff5359df65ee05e";
static const char packet_digest[] =
	"863c3f8ab7b174d111c5b497449e0d6f47e556b43aabef93c7caa7616f4416c3";

static void fill_pass_inputs(
	struct pqcp_deployment_pipeline_result *pipeline,
	struct pqcp_deployment_budget_report *budget,
	struct pqcp_deployment_experiment_plan *experiments,
	struct pqcp_deployment_review_packet *packet,
	struct pqcp_deployment_review_verifier_result *replay,
	struct pqcp_deployment_review_audit_report *audit)
{
	memset(pipeline, 0, sizeof(*pipeline));
	memset(budget, 0, sizeof(*budget));
	memset(experiments, 0, sizeof(*experiments));
	memset(packet, 0, sizeof(*packet));
	memset(replay, 0, sizeof(*replay));
	memset(audit, 0, sizeof(*audit));

	pipeline->schema_version = PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION;
	pipeline->candidate_count = 3U;
	pipeline->gap_count = 0U;
	pipeline->top_candidate_id = "mlkem768_m7";
	pipeline->top_candidate_score = 92U;
	pipeline->recommendation_ready = true;
	pipeline->replay_passed = true;
	pipeline->appraisal_passed = true;
	pipeline->claims_passed = true;
	pipeline->passed = true;
	pipeline->appraisal.readiness_score = 100U;
	pipeline->claim_matrix.average_score = 94U;
	(void)snprintk(pipeline->trace_digest.digest_hex,
		       sizeof(pipeline->trace_digest.digest_hex), "%s",
		       trace_digest);

	budget->schema_version = PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION;
	budget->profile = PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT;
	budget->status = PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	budget->candidate_count = 3U;
	budget->pass_count = 3U;
	budget->top_candidate_id = "mlkem768_m7";
	budget->top_status = PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	budget->top_margin_score = 95U;
	budget->pipeline_readiness_score = 100U;
	budget->claim_score = 94U;
	budget->pipeline_passed = true;
	budget->replay_passed = true;
	budget->appraisal_passed = true;
	budget->claims_passed = true;

	experiments->schema_version =
		PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION;
	experiments->status = PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS;
	experiments->top_candidate_id = "mlkem768_m7";
	experiments->budget_status = PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	experiments->pipeline_passed = true;
	experiments->replay_passed = true;
	experiments->appraisal_passed = true;
	experiments->claims_passed = true;

	packet->schema_version = PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION;
	packet->status = PQCP_DEPLOYMENT_REVIEW_PACKET_PASS;
	packet->line_count = 4U;
	packet->byte_count = 805U;
	packet->candidate_count = 3U;
	packet->top_candidate_id = "mlkem768_m7";
	packet->readiness_score = 100U;
	packet->claim_score = 94U;
	packet->review_score = 100U;
	packet->pipeline_passed = true;
	packet->replay_passed = true;
	packet->budget_passed = true;
	packet->experiment_plan_passed = true;
	(void)snprintk(packet->trace_digest_hex,
		       sizeof(packet->trace_digest_hex), "%s", trace_digest);
	(void)snprintk(packet->packet_digest_hex,
		       sizeof(packet->packet_digest_hex), "%s", packet_digest);

	replay->schema_version =
		PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION;
	replay->lines_seen = 5U;
	replay->marker_mask = PQCP_DEPLOYMENT_REVIEW_VERIFIER_REQUIRED_MASK;
	replay->fact_lines = 4U;
	replay->fact_bytes = 805U;
	replay->candidate_count = 3U;
	replay->readiness_score = 100U;
	replay->claim_score = 94U;
	replay->review_score = 100U;
	replay->packet_status = PQCP_DEPLOYMENT_REVIEW_PACKET_PASS;
	replay->passed = true;
	(void)snprintk(replay->top_candidate_id,
		       sizeof(replay->top_candidate_id), "%s",
		       "mlkem768_m7");
	(void)snprintk(replay->trace_digest_hex,
		       sizeof(replay->trace_digest_hex), "%s", trace_digest);
	(void)snprintk(replay->computed_digest_hex,
		       sizeof(replay->computed_digest_hex), "%s",
		       packet_digest);

	audit->schema_version = PQCP_DEPLOYMENT_REVIEW_AUDIT_SCHEMA_VERSION;
	audit->status = PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS;
	audit->result_count = 1U;
	audit->replay_pass_count = 1U;
	audit->packet_pass_count = 1U;
	audit->unique_packet_digest_count = 1U;
	audit->min_readiness_score = 100U;
	audit->min_claim_score = 94U;
	audit->min_review_score = 100U;
	audit->max_review_score = 100U;
	audit->avg_review_score = 100U;
	audit->stable_top_candidate = true;
	audit->stable_trace_digest = true;
	audit->stable_packet_digest = true;
	(void)snprintk(audit->top_candidate_id,
		       sizeof(audit->top_candidate_id), "%s", "mlkem768_m7");
	(void)snprintk(audit->trace_digest_hex,
		       sizeof(audit->trace_digest_hex), "%s", trace_digest);
	(void)snprintk(audit->packet_digest_hex,
		       sizeof(audit->packet_digest_hex), "%s", packet_digest);
}

static int evaluate_with_profile(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_pipeline_result *pipeline,
	struct pqcp_deployment_budget_report *budget,
	struct pqcp_deployment_experiment_plan *experiments,
	struct pqcp_deployment_review_packet *packet,
	struct pqcp_deployment_review_verifier_result *replay,
	struct pqcp_deployment_review_audit_report *audit,
	struct pqcp_deployment_release_gate_report *report)
{
	struct pqcp_deployment_release_gate_policy policy;

	zassert_equal(pqcp_deployment_release_gate_default_policy(profile,
								  &policy),
		      0);
	return pqcp_deployment_release_gate_evaluate(
		pipeline, budget, experiments, packet, replay, audit, &policy,
		report);
}

ZTEST(pqcp_deployment_release_gate, test_product_gate_passes_clean_inputs)
{
	struct pqcp_deployment_pipeline_result pipeline;
	struct pqcp_deployment_budget_report budget;
	struct pqcp_deployment_experiment_plan experiments;
	struct pqcp_deployment_review_packet packet;
	struct pqcp_deployment_review_verifier_result replay;
	struct pqcp_deployment_review_audit_report audit;
	struct pqcp_deployment_release_gate_report report;

	fill_pass_inputs(&pipeline, &budget, &experiments, &packet, &replay,
			 &audit);
	zassert_equal(evaluate_with_profile(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &pipeline, &budget, &experiments, &packet,
			      &replay, &audit, &report),
		      0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_RELEASE_GATE_PASS);
	zassert_equal(report.gate_score, 94U);
	zassert_true(report.digest_bound);
	zassert_true(report.top_consistent);
	zassert_equal(pqcp_deployment_release_gate_emit(&report), 0);
}

ZTEST(pqcp_deployment_release_gate, test_product_gate_fails_open_experiments)
{
	struct pqcp_deployment_pipeline_result pipeline;
	struct pqcp_deployment_budget_report budget;
	struct pqcp_deployment_experiment_plan experiments;
	struct pqcp_deployment_review_packet packet;
	struct pqcp_deployment_review_verifier_result replay;
	struct pqcp_deployment_review_audit_report audit;
	struct pqcp_deployment_release_gate_report report;

	fill_pass_inputs(&pipeline, &budget, &experiments, &packet, &replay,
			 &audit);
	experiments.status = PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL;
	experiments.row_count = 2U;
	experiments.blocking_count = 1U;
	zassert_equal(evaluate_with_profile(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &pipeline, &budget, &experiments, &packet,
			      &replay, &audit, &report),
		      -EBADMSG);
	zassert_equal(report.status, PQCP_DEPLOYMENT_RELEASE_GATE_FAIL);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_EXPERIMENTS) != 0U);
}

ZTEST(pqcp_deployment_release_gate, test_paper_gate_warns_for_packet_failure)
{
	struct pqcp_deployment_pipeline_result pipeline;
	struct pqcp_deployment_budget_report budget;
	struct pqcp_deployment_experiment_plan experiments;
	struct pqcp_deployment_review_packet packet;
	struct pqcp_deployment_review_verifier_result replay;
	struct pqcp_deployment_review_audit_report audit;
	struct pqcp_deployment_release_gate_report report;

	fill_pass_inputs(&pipeline, &budget, &experiments, &packet, &replay,
			 &audit);
	packet.status = PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
	packet.review_score = 65U;
	replay.packet_status = PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
	audit.status = PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN;
	audit.packet_fail_count = 1U;
	audit.packet_pass_count = 0U;
	audit.warning_mask =
		PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_NOT_PASS;
	zassert_equal(evaluate_with_profile(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER,
			      &pipeline, &budget, &experiments, &packet,
			      &replay, &audit, &report),
		      0);
	zassert_equal(report.status, PQCP_DEPLOYMENT_RELEASE_GATE_WARN);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_PACKET) != 0U);
	zassert_true((report.warning_mask &
		      PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_AUDIT) != 0U);
}

ZTEST(pqcp_deployment_release_gate, test_partner_gate_requires_packet_pass)
{
	struct pqcp_deployment_pipeline_result pipeline;
	struct pqcp_deployment_budget_report budget;
	struct pqcp_deployment_experiment_plan experiments;
	struct pqcp_deployment_review_packet packet;
	struct pqcp_deployment_review_verifier_result replay;
	struct pqcp_deployment_review_audit_report audit;
	struct pqcp_deployment_release_gate_report report;

	fill_pass_inputs(&pipeline, &budget, &experiments, &packet, &replay,
			 &audit);
	packet.status = PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
	zassert_equal(evaluate_with_profile(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER,
			      &pipeline, &budget, &experiments, &packet,
			      &replay, &audit, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_PACKET) != 0U);
}

ZTEST(pqcp_deployment_release_gate, test_top_mismatch_fails)
{
	struct pqcp_deployment_pipeline_result pipeline;
	struct pqcp_deployment_budget_report budget;
	struct pqcp_deployment_experiment_plan experiments;
	struct pqcp_deployment_review_packet packet;
	struct pqcp_deployment_review_verifier_result replay;
	struct pqcp_deployment_review_audit_report audit;
	struct pqcp_deployment_release_gate_report report;

	fill_pass_inputs(&pipeline, &budget, &experiments, &packet, &replay,
			 &audit);
	budget.top_candidate_id = "other_candidate";
	zassert_equal(evaluate_with_profile(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &pipeline, &budget, &experiments, &packet,
			      &replay, &audit, &report),
		      -EBADMSG);
	zassert_false(report.top_consistent);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_TOP_MISMATCH) != 0U);
}

ZTEST(pqcp_deployment_release_gate, test_digest_mismatch_fails)
{
	struct pqcp_deployment_pipeline_result pipeline;
	struct pqcp_deployment_budget_report budget;
	struct pqcp_deployment_experiment_plan experiments;
	struct pqcp_deployment_review_packet packet;
	struct pqcp_deployment_review_verifier_result replay;
	struct pqcp_deployment_review_audit_report audit;
	struct pqcp_deployment_release_gate_report report;

	fill_pass_inputs(&pipeline, &budget, &experiments, &packet, &replay,
			 &audit);
	(void)snprintk(replay.computed_digest_hex,
		       sizeof(replay.computed_digest_hex), "%s",
		       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	zassert_equal(evaluate_with_profile(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &pipeline, &budget, &experiments, &packet,
			      &replay, &audit, &report),
		      -EBADMSG);
	zassert_false(report.digest_bound);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_DIGEST_MISMATCH) !=
		     0U);
}

ZTEST(pqcp_deployment_release_gate, test_score_floor_fails_for_product)
{
	struct pqcp_deployment_pipeline_result pipeline;
	struct pqcp_deployment_budget_report budget;
	struct pqcp_deployment_experiment_plan experiments;
	struct pqcp_deployment_review_packet packet;
	struct pqcp_deployment_review_verifier_result replay;
	struct pqcp_deployment_review_audit_report audit;
	struct pqcp_deployment_release_gate_report report;

	fill_pass_inputs(&pipeline, &budget, &experiments, &packet, &replay,
			 &audit);
	pipeline.appraisal.readiness_score = 79U;
	packet.readiness_score = 79U;
	replay.readiness_score = 79U;
	audit.min_readiness_score = 79U;
	zassert_equal(evaluate_with_profile(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &pipeline, &budget, &experiments, &packet,
			      &replay, &audit, &report),
		      -EBADMSG);
	zassert_true((report.error_mask &
		      PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_SCORE_FLOOR) != 0U);
}

ZTEST(pqcp_deployment_release_gate, test_invalid_input_fails)
{
	struct pqcp_deployment_release_gate_policy policy;
	struct pqcp_deployment_release_gate_report report;

	zassert_equal(pqcp_deployment_release_gate_default_policy(
			      PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT,
			      &policy),
		      0);
	zassert_equal(pqcp_deployment_release_gate_evaluate(
			      NULL, NULL, NULL, NULL, NULL, NULL, &policy,
			      &report),
		      -EINVAL);
	zassert_equal(report.status, PQCP_DEPLOYMENT_RELEASE_GATE_FAIL);
	zassert_equal(report.error_mask,
		      PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_INVALID_INPUT);
}

ZTEST(pqcp_deployment_release_gate, test_tokens_are_stable)
{
	zassert_mem_equal(
		pqcp_deployment_release_gate_profile_str(
			PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE),
		"prototype", strlen("prototype"));
	zassert_mem_equal(
		pqcp_deployment_release_gate_profile_str(
			PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER),
		"partner", strlen("partner"));
	zassert_mem_equal(
		pqcp_deployment_release_gate_status_str(
			PQCP_DEPLOYMENT_RELEASE_GATE_PASS),
		"PASS", strlen("PASS"));
	zassert_mem_equal(
		pqcp_deployment_release_gate_status_str(
			PQCP_DEPLOYMENT_RELEASE_GATE_FAIL),
		"FAIL", strlen("FAIL"));
}

ZTEST_SUITE(pqcp_deployment_release_gate, NULL, NULL, NULL, NULL, NULL);
