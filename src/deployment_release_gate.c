/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native deployment release gate evaluation.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_release_gate.h>

static bool text_present(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool profile_valid(enum pqcp_deployment_release_gate_profile profile)
{
	return profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
}

static bool status_valid(enum pqcp_deployment_release_gate_status status)
{
	return status == PQCP_DEPLOYMENT_RELEASE_GATE_PASS ||
	       status == PQCP_DEPLOYMENT_RELEASE_GATE_WARN ||
	       status == PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
}

const char *pqcp_deployment_release_gate_status_str(
	enum pqcp_deployment_release_gate_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_RELEASE_GATE_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_RELEASE_GATE_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_deployment_release_gate_profile_str(
	enum pqcp_deployment_release_gate_profile profile)
{
	switch (profile) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE:
		return "prototype";
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER:
		return "paper";
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT:
		return "product";
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER:
		return "partner";
	default:
		return "unknown";
	}
}

int pqcp_deployment_release_gate_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_release_gate_policy *policy)
{
	if (policy == NULL || !profile_valid(profile)) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->require_replay_pass = true;
	policy->require_digest_binding = true;

	switch (profile) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE:
		policy->min_readiness_score = 50U;
		policy->min_claim_score = 50U;
		policy->min_review_score = 40U;
		policy->max_blocking_experiments = 32U;
		policy->max_total_experiments = 32U;
		policy->require_audit_pass = false;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER:
		policy->min_readiness_score = 70U;
		policy->min_claim_score = 65U;
		policy->min_review_score = 60U;
		policy->max_blocking_experiments = 8U;
		policy->max_total_experiments = 16U;
		policy->require_pipeline_pass = true;
		policy->require_audit_pass = false;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT:
		policy->min_readiness_score = 80U;
		policy->min_claim_score = 75U;
		policy->min_review_score = 70U;
		policy->max_blocking_experiments = 0U;
		policy->max_total_experiments = 4U;
		policy->score_floor_blocks = true;
		policy->require_pipeline_pass = true;
		policy->require_budget_pass = true;
		policy->require_experiment_plan_pass = true;
		policy->require_audit_pass = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER:
		policy->min_readiness_score = 85U;
		policy->min_claim_score = 80U;
		policy->min_review_score = 75U;
		policy->max_blocking_experiments = 0U;
		policy->max_total_experiments = 0U;
		policy->score_floor_blocks = true;
		policy->require_pipeline_pass = true;
		policy->require_budget_pass = true;
		policy->require_experiment_plan_pass = true;
		policy->require_packet_pass = true;
		policy->require_audit_pass = true;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static bool policy_valid(
	const struct pqcp_deployment_release_gate_policy *policy)
{
	return policy != NULL &&
	       profile_valid(policy->profile) &&
	       policy->min_readiness_score <= 100U &&
	       policy->min_claim_score <= 100U &&
	       policy->min_review_score <= 100U &&
	       policy->max_blocking_experiments <=
		       PQCP_DEPLOYMENT_EXPERIMENT_PLAN_MAX_ROWS &&
	       policy->max_total_experiments <=
		       PQCP_DEPLOYMENT_EXPERIMENT_PLAN_MAX_ROWS;
}

static bool schemas_valid(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const struct pqcp_deployment_review_packet *packet,
	const struct pqcp_deployment_review_verifier_result *replay,
	const struct pqcp_deployment_review_audit_report *audit)
{
	return pipeline != NULL && budget != NULL && experiments != NULL &&
	       packet != NULL && replay != NULL && audit != NULL &&
	       pipeline->schema_version == PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION &&
	       budget->schema_version == PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION &&
	       experiments->schema_version ==
		       PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION &&
	       packet->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION &&
	       replay->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION &&
	       audit->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_AUDIT_SCHEMA_VERSION &&
	       text_present(pipeline->top_candidate_id) &&
	       text_present(budget->top_candidate_id) &&
	       text_present(experiments->top_candidate_id) &&
	       packet->top_candidate_id != NULL &&
	       text_present(replay->top_candidate_id) &&
	       text_present(audit->top_candidate_id) &&
	       text_present(packet->trace_digest_hex) &&
	       text_present(packet->packet_digest_hex) &&
	       text_present(replay->trace_digest_hex) &&
	       text_present(replay->computed_digest_hex) &&
	       text_present(audit->trace_digest_hex) &&
	       text_present(audit->packet_digest_hex) &&
	       pipeline->candidate_count != 0U &&
	       budget->candidate_count == pipeline->candidate_count &&
	       packet->candidate_count == pipeline->candidate_count &&
	       replay->candidate_count == pipeline->candidate_count &&
	       audit->result_count != 0U;
}

static void report_invalid(
	struct pqcp_deployment_release_gate_report *report,
	enum pqcp_deployment_release_gate_profile profile)
{
	if (report == NULL) {
		return;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION;
	report->profile = profile_valid(profile) ? profile :
		PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	report->status = PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
	report->error_mask = PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_INVALID_INPUT;
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s", "none");
}

static bool top_ids_consistent(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const struct pqcp_deployment_review_packet *packet,
	const struct pqcp_deployment_review_verifier_result *replay,
	const struct pqcp_deployment_review_audit_report *audit)
{
	const char *top = pipeline->top_candidate_id;

	return strcmp(top, budget->top_candidate_id) == 0 &&
	       strcmp(top, experiments->top_candidate_id) == 0 &&
	       strcmp(top, packet->top_candidate_id) == 0 &&
	       strcmp(top, replay->top_candidate_id) == 0 &&
	       strcmp(top, audit->top_candidate_id) == 0;
}

static bool digest_binding_consistent(
	const struct pqcp_deployment_review_packet *packet,
	const struct pqcp_deployment_review_verifier_result *replay,
	const struct pqcp_deployment_review_audit_report *audit)
{
	return strcmp(packet->trace_digest_hex, replay->trace_digest_hex) == 0 &&
	       strcmp(packet->trace_digest_hex, audit->trace_digest_hex) == 0 &&
	       strcmp(packet->packet_digest_hex,
		      replay->computed_digest_hex) == 0 &&
	       strcmp(packet->packet_digest_hex, audit->packet_digest_hex) == 0;
}

static uint32_t min3(uint32_t a, uint32_t b, uint32_t c)
{
	uint32_t min = a < b ? a : b;

	return min < c ? min : c;
}

static uint32_t compute_gate_score(
	const struct pqcp_deployment_release_gate_report *report)
{
	uint32_t base = min3(report->readiness_score, report->claim_score,
			     report->review_score);
	uint32_t penalty = 0U;

	if (!report->pipeline_passed) {
		penalty += 12U;
	}
	if (!report->budget_passed) {
		penalty += 12U;
	}
	if (!report->experiment_plan_passed) {
		penalty += 10U;
	}
	if (!report->packet_passed) {
		penalty += 8U;
	}
	if (!report->replay_passed) {
		penalty += 20U;
	}
	if (!report->audit_passed) {
		penalty += 8U;
	}
	if (!report->top_consistent || !report->digest_bound) {
		penalty += 25U;
	}
	if (report->blocking_experiment_count > 0U) {
		penalty += report->blocking_experiment_count > 10U ?
			20U : report->blocking_experiment_count * 2U;
	}

	return penalty >= base ? 0U : base - penalty;
}

static enum pqcp_deployment_release_gate_status compute_status(
	uint32_t errors,
	uint32_t warnings)
{
	if (errors != 0U) {
		return PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
	}
	if (warnings != 0U) {
		return PQCP_DEPLOYMENT_RELEASE_GATE_WARN;
	}

	return PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
}

static void fill_report_summary(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const struct pqcp_deployment_review_packet *packet,
	const struct pqcp_deployment_review_verifier_result *replay,
	const struct pqcp_deployment_review_audit_report *audit,
	const struct pqcp_deployment_release_gate_policy *policy,
	struct pqcp_deployment_release_gate_report *report)
{
	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION;
	report->profile = policy->profile;
	report->candidate_count = pipeline->candidate_count;
	report->gap_count = pipeline->gap_count;
	report->blocking_experiment_count = experiments->blocking_count;
	report->experiment_count = experiments->row_count;
	report->readiness_score = pipeline->appraisal.readiness_score;
	report->claim_score = pipeline->claim_matrix.average_score;
	report->review_score = packet->review_score;
	report->pipeline_passed = pipeline->passed;
	report->budget_passed =
		budget->status == PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	report->experiment_plan_passed =
		experiments->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS;
	report->packet_passed =
		packet->status == PQCP_DEPLOYMENT_REVIEW_PACKET_PASS;
	report->replay_passed = replay->passed;
	report->audit_passed =
		audit->status == PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS;
	report->top_consistent = top_ids_consistent(
		pipeline, budget, experiments, packet, replay, audit);
	report->digest_bound = digest_binding_consistent(packet, replay, audit);
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s",
		       pipeline->top_candidate_id);
	(void)snprintk(report->trace_digest_hex,
		       sizeof(report->trace_digest_hex), "%s",
		       packet->trace_digest_hex);
	(void)snprintk(report->packet_digest_hex,
		       sizeof(report->packet_digest_hex), "%s",
		       packet->packet_digest_hex);
}

static void apply_hard_policy(
	const struct pqcp_deployment_release_gate_policy *policy,
	struct pqcp_deployment_release_gate_report *report)
{
	if (!report->top_consistent) {
		report->error_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_TOP_MISMATCH;
	}
	if (policy->require_digest_binding && !report->digest_bound) {
		report->error_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_DIGEST_MISMATCH;
	}
	if (policy->require_pipeline_pass && !report->pipeline_passed) {
		report->error_mask |= PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_PIPELINE;
	}
	if (policy->require_budget_pass && !report->budget_passed) {
		report->error_mask |= PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_BUDGET;
	}
	if (policy->require_experiment_plan_pass &&
	    !report->experiment_plan_passed) {
		report->error_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_EXPERIMENTS;
	}
	if (report->blocking_experiment_count >
	    policy->max_blocking_experiments ||
	    report->experiment_count > policy->max_total_experiments) {
		report->error_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_EXPERIMENTS;
	}
	if (policy->require_packet_pass && !report->packet_passed) {
		report->error_mask |= PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_PACKET;
	}
	if (policy->require_replay_pass && !report->replay_passed) {
		report->error_mask |= PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_REPLAY;
	}
	if (policy->require_audit_pass && !report->audit_passed) {
		report->error_mask |= PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_AUDIT;
	}
	if ((report->readiness_score < policy->min_readiness_score ||
	     report->claim_score < policy->min_claim_score ||
	     report->review_score < policy->min_review_score) &&
	    policy->score_floor_blocks) {
		report->error_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_SCORE_FLOOR;
	}
}

static void apply_warnings(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const struct pqcp_deployment_review_packet *packet,
	const struct pqcp_deployment_review_audit_report *audit,
	const struct pqcp_deployment_release_gate_policy *policy,
	struct pqcp_deployment_release_gate_report *report)
{
	if (!pipeline->passed || pipeline->gap_count != 0U) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_PIPELINE_GAPS;
	}
	if (budget->status != PQCP_DEPLOYMENT_BUDGET_STATUS_PASS) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_BUDGET;
	}
	if (experiments->row_count != 0U) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_EXPERIMENTS;
	}
	if (packet->status != PQCP_DEPLOYMENT_REVIEW_PACKET_PASS) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_PACKET;
	}
	if (audit->status == PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_AUDIT;
	}
	if ((audit->warning_mask &
	     PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_NOT_PASS) != 0U) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_REVIEW_LIMITED;
	}
	if ((report->readiness_score < policy->min_readiness_score ||
	     report->claim_score < policy->min_claim_score ||
	     report->review_score < policy->min_review_score) &&
	    !policy->score_floor_blocks) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_SCORE_FLOOR;
	}
}

int pqcp_deployment_release_gate_evaluate(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const struct pqcp_deployment_review_packet *packet,
	const struct pqcp_deployment_review_verifier_result *replay,
	const struct pqcp_deployment_review_audit_report *audit,
	const struct pqcp_deployment_release_gate_policy *policy,
	struct pqcp_deployment_release_gate_report *report)
{
	if (report == NULL) {
		return -EINVAL;
	}
	if (!policy_valid(policy) ||
	    !schemas_valid(pipeline, budget, experiments, packet, replay,
			   audit)) {
		report_invalid(report,
			       policy != NULL ? policy->profile :
			       PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE);
		return -EINVAL;
	}

	fill_report_summary(pipeline, budget, experiments, packet, replay, audit,
			    policy, report);
	apply_hard_policy(policy, report);
	apply_warnings(pipeline, budget, experiments, packet, audit, policy,
		       report);
	report->gate_score = compute_gate_score(report);
	report->status = compute_status(report->error_mask,
					report->warning_mask);

	return report->status == PQCP_DEPLOYMENT_RELEASE_GATE_FAIL ?
		-EBADMSG : 0;
}

static bool report_valid(
	const struct pqcp_deployment_release_gate_report *report)
{
	return report != NULL &&
	       report->schema_version ==
		       PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION &&
	       profile_valid(report->profile) &&
	       status_valid(report->status) &&
	       report->candidate_count != 0U &&
	       report->readiness_score <= 100U &&
	       report->claim_score <= 100U &&
	       report->review_score <= 100U &&
	       report->gate_score <= 100U &&
	       text_present(report->top_candidate_id) &&
	       text_present(report->trace_digest_hex) &&
	       text_present(report->packet_digest_hex) &&
	       (report->error_mask &
		~PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_KNOWN_MASK) == 0U &&
	       (report->warning_mask &
		~PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_KNOWN_MASK) == 0U;
}

int pqcp_deployment_release_gate_emit(
	const struct pqcp_deployment_release_gate_report *report)
{
	if (!report_valid(report)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_RELEASE_GATE schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x candidates=%u gaps=%u experiments=%u blocking=%u readiness=%u claim_score=%u review_score=%u gate_score=%u top_consistent=%u digest_bound=%u pipeline=%s budget=%s experiment_plan=%s packet=%s replay=%s audit=%s top=%s trace_digest=%s packet_digest=%s\n",
	       report->schema_version,
	       pqcp_deployment_release_gate_profile_str(report->profile),
	       pqcp_deployment_release_gate_status_str(report->status),
	       report->error_mask,
	       report->warning_mask,
	       report->candidate_count,
	       report->gap_count,
	       report->experiment_count,
	       report->blocking_experiment_count,
	       report->readiness_score,
	       report->claim_score,
	       report->review_score,
	       report->gate_score,
	       report->top_consistent ? 1U : 0U,
	       report->digest_bound ? 1U : 0U,
	       report->pipeline_passed ? "PASS" : "FAIL",
	       report->budget_passed ? "PASS" : "FAIL",
	       report->experiment_plan_passed ? "PASS" : "FAIL",
	       report->packet_passed ? "PASS" : "FAIL",
	       report->replay_passed ? "PASS" : "FAIL",
	       report->audit_passed ? "PASS" : "FAIL",
	       report->top_candidate_id,
	       report->trace_digest_hex,
	       report->packet_digest_hex);

	return report->status == PQCP_DEPLOYMENT_RELEASE_GATE_FAIL ?
		-EBADMSG : 0;
}
