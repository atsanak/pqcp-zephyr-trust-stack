/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native deployment budget and evidence verdicts.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_budget.h>

static bool profile_valid(enum pqcp_deployment_appraisal_profile profile)
{
	return profile >= PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB &&
	       profile <= PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW;
}

static bool status_valid(enum pqcp_deployment_budget_status status)
{
	return status >= PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL &&
	       status <= PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
}

const char *pqcp_deployment_budget_status_str(
	enum pqcp_deployment_budget_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_BUDGET_STATUS_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_BUDGET_STATUS_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

static uint32_t base_required_evidence(
	enum pqcp_deployment_appraisal_profile profile)
{
	switch (profile) {
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB:
		return PQCP_DEPLOYMENT_EVIDENCE_KAT |
		       PQCP_DEPLOYMENT_EVIDENCE_PROVIDER;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PAPER:
		return PQCP_DEPLOYMENT_EVIDENCE_KAT |
		       PQCP_DEPLOYMENT_EVIDENCE_ACVP |
		       PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
		       PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		       PQCP_DEPLOYMENT_EVIDENCE_BASELINE |
		       PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		       PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		       PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
		       PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
		       PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT:
		return PQCP_DEPLOYMENT_EVIDENCE_KAT |
		       PQCP_DEPLOYMENT_EVIDENCE_ACVP |
		       PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
		       PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		       PQCP_DEPLOYMENT_EVIDENCE_BASELINE |
		       PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		       PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		       PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
		       PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
		       PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW:
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW:
		return PQCP_DEPLOYMENT_EVIDENCE_KAT |
		       PQCP_DEPLOYMENT_EVIDENCE_ACVP |
		       PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
		       PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		       PQCP_DEPLOYMENT_EVIDENCE_BASELINE |
		       PQCP_DEPLOYMENT_EVIDENCE_HARDWARE |
		       PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		       PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		       PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
		       PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
		       PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	default:
		return 0U;
	}
}

int pqcp_deployment_budget_default_policy(
	enum pqcp_deployment_appraisal_profile profile,
	struct pqcp_deployment_budget_policy *policy)
{
	if (!profile_valid(profile) || policy == NULL) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->required_evidence_mask = base_required_evidence(profile);

	switch (profile) {
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB:
		policy->min_headroom_permille = 0U;
		policy->min_confidence = 30U;
		policy->min_score = 30U;
		policy->require_complete_measurements = false;
		policy->require_required_evidence = false;
		policy->require_pipeline_pass = false;
		break;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PAPER:
		policy->min_headroom_permille = 50U;
		policy->min_confidence = 55U;
		policy->min_score = 55U;
		policy->require_complete_measurements = true;
		policy->require_required_evidence = true;
		policy->require_pipeline_pass = false;
		break;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT:
		policy->min_headroom_permille = 100U;
		policy->min_confidence = 70U;
		policy->min_score = 65U;
		policy->require_complete_measurements = true;
		policy->require_required_evidence = true;
		policy->require_pipeline_pass = true;
		break;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW:
		policy->min_headroom_permille = 150U;
		policy->min_confidence = 75U;
		policy->min_score = 70U;
		policy->require_complete_measurements = true;
		policy->require_required_evidence = true;
		policy->require_pipeline_pass = true;
		policy->require_hardware_evidence = true;
		policy->require_independent_evidence = true;
		break;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW:
		policy->min_headroom_permille = 200U;
		policy->min_confidence = 80U;
		policy->min_score = 75U;
		policy->require_complete_measurements = true;
		policy->require_required_evidence = true;
		policy->require_pipeline_pass = true;
		policy->require_hardware_evidence = true;
		policy->require_independent_evidence = true;
		break;
	default:
		return -EINVAL;
	}

	if (policy->require_hardware_evidence) {
		policy->required_evidence_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_HARDWARE;
	}

	return 0;
}

static bool policy_valid(const struct pqcp_deployment_budget_policy *policy)
{
	return policy != NULL &&
	       profile_valid(policy->profile) &&
	       policy->min_confidence <= 100U &&
	       policy->min_score <= 100U &&
	       (policy->required_evidence_mask &
		~PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK) == 0U;
}

static int32_t metric_headroom(
	const struct pqcp_deployment_candidate_robustness *robustness,
	uint32_t metric)
{
	switch (metric) {
	case PQCP_DEPLOYMENT_METRIC_LATENCY:
		return robustness->latency_headroom_permille;
	case PQCP_DEPLOYMENT_METRIC_RAM:
		return robustness->ram_headroom_permille;
	case PQCP_DEPLOYMENT_METRIC_STACK:
		return robustness->stack_headroom_permille;
	case PQCP_DEPLOYMENT_METRIC_HEAP:
		return robustness->heap_headroom_permille;
	case PQCP_DEPLOYMENT_METRIC_FLASH:
		return robustness->flash_headroom_permille;
	case PQCP_DEPLOYMENT_METRIC_ENERGY:
		return robustness->energy_headroom_permille;
	default:
		return PQCP_DEPLOYMENT_HEADROOM_UNKNOWN;
	}
}

static void evaluate_metric(
	const struct pqcp_deployment_candidate_robustness *robustness,
	const struct pqcp_deployment_budget_policy *policy,
	uint32_t metric,
	struct pqcp_deployment_budget_candidate *row)
{
	int32_t headroom;

	if ((robustness->configured_metric_mask & metric) == 0U) {
		return;
	}

	if ((robustness->missing_metric_mask & metric) != 0U ||
	    (robustness->measured_metric_mask & metric) == 0U) {
		row->metric_missing_mask |= metric;
		row->warning_mask |=
			PQCP_DEPLOYMENT_BUDGET_WARNING_PARTIAL_METRICS;
		if (policy->require_complete_measurements) {
			row->blocker_mask |=
				PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_MEASUREMENT;
		}
		return;
	}

	headroom = metric_headroom(robustness, metric);
	if (headroom == PQCP_DEPLOYMENT_HEADROOM_UNKNOWN) {
		row->metric_missing_mask |= metric;
		row->warning_mask |=
			PQCP_DEPLOYMENT_BUDGET_WARNING_PARTIAL_METRICS;
		if (policy->require_complete_measurements) {
			row->blocker_mask |=
				PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_MEASUREMENT;
		}
		return;
	}
	if (headroom < 0) {
		row->metric_fail_mask |= metric;
		row->blocker_mask |=
			PQCP_DEPLOYMENT_BUDGET_BLOCKER_OVER_BUDGET;
		return;
	}
	if ((uint32_t)headroom < policy->min_headroom_permille) {
		row->metric_warn_mask |= metric;
		row->warning_mask |= PQCP_DEPLOYMENT_BUDGET_WARNING_LOW_MARGIN;
		return;
	}

	row->metric_pass_mask |= metric;
}

static uint32_t metric_score_from_headroom(int32_t headroom)
{
	if (headroom == PQCP_DEPLOYMENT_HEADROOM_UNKNOWN || headroom <= 0) {
		return 0U;
	}
	if (headroom >= 500) {
		return 100U;
	}

	return (uint32_t)headroom / 5U;
}

static void evaluate_metrics(
	const struct pqcp_deployment_candidate_robustness *robustness,
	const struct pqcp_deployment_budget_policy *policy,
	struct pqcp_deployment_budget_candidate *row)
{
	static const uint32_t metrics[] = {
		PQCP_DEPLOYMENT_METRIC_LATENCY,
		PQCP_DEPLOYMENT_METRIC_RAM,
		PQCP_DEPLOYMENT_METRIC_STACK,
		PQCP_DEPLOYMENT_METRIC_HEAP,
		PQCP_DEPLOYMENT_METRIC_FLASH,
		PQCP_DEPLOYMENT_METRIC_ENERGY,
	};

	for (size_t i = 0U; i < sizeof(metrics) / sizeof(metrics[0]); ++i) {
		evaluate_metric(robustness, policy, metrics[i], row);
	}

	row->minimum_headroom_permille =
		robustness->minimum_headroom_permille;
	row->average_headroom_permille =
		robustness->average_headroom_permille;
	row->margin_score =
		metric_score_from_headroom(row->minimum_headroom_permille);
}

static void evaluate_evidence(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	const struct pqcp_deployment_budget_policy *policy,
	struct pqcp_deployment_budget_candidate *row)
{
	uint32_t required = policy->required_evidence_mask;

	if (scenario->require_hardware_evidence) {
		required |= PQCP_DEPLOYMENT_EVIDENCE_HARDWARE;
	}

	row->evidence_missing_mask = required & ~candidate->evidence_mask;

	if (row->evidence_missing_mask != 0U) {
		row->warning_mask |=
			PQCP_DEPLOYMENT_BUDGET_WARNING_PARTIAL_EVIDENCE;
		if (policy->require_required_evidence ||
		    (scenario->require_hardware_evidence &&
		     (row->evidence_missing_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_HARDWARE) != 0U)) {
			row->blocker_mask |=
				PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_EVIDENCE;
		}
	}

	if (policy->require_independent_evidence &&
	    !candidate->independent_evidence) {
		row->warning_mask |=
			PQCP_DEPLOYMENT_BUDGET_WARNING_PARTIAL_EVIDENCE;
		row->blocker_mask |=
			PQCP_DEPLOYMENT_BUDGET_BLOCKER_MISSING_EVIDENCE;
	}
}

static void evaluate_pipeline_status(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_policy *policy,
	struct pqcp_deployment_budget_candidate *row)
{
	if (pipeline->gap_count != 0U || !pipeline->passed) {
		row->warning_mask |=
			PQCP_DEPLOYMENT_BUDGET_WARNING_PIPELINE_GAPS;
	}

	if (policy->require_pipeline_pass && !pipeline->passed) {
		row->blocker_mask |=
			PQCP_DEPLOYMENT_BUDGET_BLOCKER_PIPELINE_FAILED;
	}
}

static void evaluate_candidate(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	const struct pqcp_deployment_candidate_result *advisor,
	const struct pqcp_deployment_candidate_robustness *robustness,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_policy *policy,
	struct pqcp_deployment_budget_candidate *row)
{
	memset(row, 0, sizeof(*row));
	row->schema_version = PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION;
	row->candidate_index = advisor->candidate_index;
	row->candidate_id = candidate->candidate_id;
	row->advisor_score = advisor->score;
	row->advisor_confidence = advisor->confidence;
	row->top_candidate = pipeline->top_candidate_id != NULL &&
			     strcmp(candidate->candidate_id,
				    pipeline->top_candidate_id) == 0;

	if (advisor->status == PQCP_DEPLOYMENT_RECOMMENDATION_REJECTED ||
	    advisor->blocker_mask != 0U || !advisor->feasible) {
		row->blocker_mask |=
			PQCP_DEPLOYMENT_BUDGET_BLOCKER_ADVISOR_REJECTED;
	}
	if (advisor->status == PQCP_DEPLOYMENT_RECOMMENDATION_CONDITIONAL) {
		row->warning_mask |=
			PQCP_DEPLOYMENT_BUDGET_WARNING_CONDITIONAL;
	}
	if (advisor->confidence < policy->min_confidence) {
		row->blocker_mask |= PQCP_DEPLOYMENT_BUDGET_BLOCKER_CONFIDENCE;
	}
	if (advisor->score < policy->min_score) {
		row->blocker_mask |= PQCP_DEPLOYMENT_BUDGET_BLOCKER_SCORE;
	}

	evaluate_metrics(robustness, policy, row);
	evaluate_evidence(scenario, candidate, policy, row);
	evaluate_pipeline_status(pipeline, policy, row);

	if (row->blocker_mask != 0U) {
		row->status = PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL;
	} else if (row->warning_mask != 0U) {
		row->status = PQCP_DEPLOYMENT_BUDGET_STATUS_WARN;
	} else {
		row->status = PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	}
}

static int validate_inputs(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_workspace *workspace,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_policy *policy,
	const struct pqcp_deployment_budget_candidate *rows,
	size_t row_capacity,
	const struct pqcp_deployment_budget_report *report)
{
	if (config == NULL || workspace == NULL || pipeline == NULL ||
	    !policy_valid(policy) || rows == NULL || report == NULL ||
	    pipeline->schema_version != PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION ||
	    pipeline->candidate_count == 0U ||
	    pipeline->candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES ||
	    pqcp_deployment_scenario_validate(config->scenario) != 0) {
		return -EINVAL;
	}
	if (row_capacity < pipeline->candidate_count) {
		return -ENOSPC;
	}

	return 0;
}

static void update_report_counts(
	const struct pqcp_deployment_budget_candidate *row,
	struct pqcp_deployment_budget_report *report)
{
	report->blocker_mask |= row->blocker_mask;
	report->warning_mask |= row->warning_mask;

	switch (row->status) {
	case PQCP_DEPLOYMENT_BUDGET_STATUS_PASS:
		report->pass_count++;
		break;
	case PQCP_DEPLOYMENT_BUDGET_STATUS_WARN:
		report->warn_count++;
		break;
	case PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL:
	default:
		report->fail_count++;
		break;
	}

	if (row->top_candidate) {
		report->top_candidate_id = row->candidate_id;
		report->top_status = row->status;
		report->top_minimum_headroom_permille =
			row->minimum_headroom_permille;
		report->top_margin_score = row->margin_score;
	}
}

static void finalize_report(struct pqcp_deployment_budget_report *report)
{
	if (report->fail_count != 0U || report->blocker_mask != 0U) {
		report->status = PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL;
	} else if (report->warn_count != 0U || report->warning_mask != 0U) {
		report->status = PQCP_DEPLOYMENT_BUDGET_STATUS_WARN;
	} else {
		report->status = PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	}
}

int pqcp_deployment_budget_evaluate(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_workspace *workspace,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_policy *policy,
	struct pqcp_deployment_budget_candidate *rows,
	size_t row_capacity,
	struct pqcp_deployment_budget_report *report)
{
	int ret = validate_inputs(config, workspace, pipeline, policy, rows,
				  row_capacity, report);

	if (ret != 0) {
		if (report != NULL) {
			memset(report, 0, sizeof(*report));
			report->schema_version =
				PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION;
			report->status = PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL;
			report->blocker_mask =
				PQCP_DEPLOYMENT_BUDGET_BLOCKER_INVALID_INPUT;
			report->top_candidate_id = "none";
		}
		return ret;
	}

	memset(rows, 0, sizeof(rows[0]) * pipeline->candidate_count);
	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION;
	report->profile = policy->profile;
	report->candidate_count = pipeline->candidate_count;
	report->required_margin_permille = policy->min_headroom_permille;
	report->top_candidate_id = "none";
	report->top_status = PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL;
	report->top_minimum_headroom_permille =
		PQCP_DEPLOYMENT_HEADROOM_UNKNOWN;
	report->pipeline_readiness_score = pipeline->appraisal.readiness_score;
	report->claim_score = pipeline->claim_matrix.average_score;
	report->pipeline_passed = pipeline->passed;
	report->replay_passed = pipeline->replay_passed;
	report->appraisal_passed = pipeline->appraisal_passed;
	report->claims_passed = pipeline->claims_passed;

	for (size_t i = 0U; i < pipeline->candidate_count; ++i) {
		const struct pqcp_deployment_candidate *candidate =
			&workspace->candidates[i];
		const struct pqcp_deployment_candidate_result *advisor =
			&workspace->results[i];
		const struct pqcp_deployment_candidate_robustness *robustness =
			&workspace->robustness[i];

		if (candidate->candidate_id == NULL ||
		    advisor->candidate_id == NULL ||
		    robustness->candidate_id == NULL ||
		    strcmp(candidate->candidate_id, advisor->candidate_id) != 0 ||
		    strcmp(candidate->candidate_id,
			   robustness->candidate_id) != 0) {
			rows[i].schema_version =
				PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION;
			rows[i].candidate_index = (uint32_t)i;
			rows[i].candidate_id = candidate->candidate_id != NULL ?
				candidate->candidate_id : "invalid";
			rows[i].status = PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL;
			rows[i].blocker_mask =
				PQCP_DEPLOYMENT_BUDGET_BLOCKER_INVALID_INPUT;
		} else {
			evaluate_candidate(config->scenario, candidate, advisor,
					   robustness, pipeline, policy,
					   &rows[i]);
		}
		update_report_counts(&rows[i], report);
	}

	finalize_report(report);
	return 0;
}

static bool row_valid(const struct pqcp_deployment_budget_candidate *row)
{
	return row != NULL &&
	       row->schema_version == PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION &&
	       row->candidate_id != NULL &&
	       status_valid(row->status) &&
	       row->advisor_score <= 100U &&
	       row->advisor_confidence <= 100U &&
	       row->margin_score <= 100U &&
	       (row->blocker_mask &
		~PQCP_DEPLOYMENT_BUDGET_BLOCKER_KNOWN_MASK) == 0U &&
	       (row->warning_mask &
		~PQCP_DEPLOYMENT_BUDGET_WARNING_KNOWN_MASK) == 0U &&
	       (row->metric_pass_mask & ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) ==
		       0U &&
	       (row->metric_warn_mask & ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) ==
		       0U &&
	       (row->metric_fail_mask & ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) ==
		       0U &&
	       (row->metric_missing_mask & ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) ==
		       0U &&
	       (row->evidence_missing_mask &
		~PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK) == 0U;
}

int pqcp_deployment_budget_candidate_emit(
	const struct pqcp_deployment_budget_candidate *row)
{
	if (!row_valid(row)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_BUDGET_CANDIDATE schema=%u index=%u id=%s status=%s blockers=0x%08x warnings=0x%08x metric_pass=0x%08x metric_warn=0x%08x metric_fail=0x%08x metric_missing=0x%08x evidence_missing=0x%08x min_headroom_permille=%d avg_headroom_permille=%d margin_score=%u advisor_score=%u confidence=%u top=%u\n",
	       row->schema_version,
	       row->candidate_index,
	       row->candidate_id,
	       pqcp_deployment_budget_status_str(row->status),
	       row->blocker_mask,
	       row->warning_mask,
	       row->metric_pass_mask,
	       row->metric_warn_mask,
	       row->metric_fail_mask,
	       row->metric_missing_mask,
	       row->evidence_missing_mask,
	       row->minimum_headroom_permille,
	       row->average_headroom_permille,
	       row->margin_score,
	       row->advisor_score,
	       row->advisor_confidence,
	       row->top_candidate ? 1U : 0U);

	return row->status == PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL ?
		-EBADMSG : 0;
}

static bool report_valid(const struct pqcp_deployment_budget_report *report)
{
	return report != NULL &&
	       report->schema_version == PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION &&
	       profile_valid(report->profile) &&
	       status_valid(report->status) &&
	       status_valid(report->top_status) &&
	       report->top_candidate_id != NULL &&
	       report->pass_count + report->warn_count + report->fail_count ==
		       report->candidate_count &&
	       report->pipeline_readiness_score <= 100U &&
	       report->claim_score <= 100U &&
	       report->top_margin_score <= 100U &&
	       (report->blocker_mask &
		~PQCP_DEPLOYMENT_BUDGET_BLOCKER_KNOWN_MASK) == 0U &&
	       (report->warning_mask &
		~PQCP_DEPLOYMENT_BUDGET_WARNING_KNOWN_MASK) == 0U;
}

int pqcp_deployment_budget_report_emit(
	const struct pqcp_deployment_budget_report *report)
{
	if (!report_valid(report)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_BUDGET_REPORT schema=%u status=%s profile=%s candidates=%u pass=%u warn=%u fail=%u blockers=0x%08x warnings=0x%08x top=%s top_status=%s top_min_headroom_permille=%d required_margin_permille=%u top_margin_score=%u readiness=%u claim_score=%u pipeline=%s replay=%s appraisal=%s claims=%s\n",
	       report->schema_version,
	       pqcp_deployment_budget_status_str(report->status),
	       pqcp_deployment_appraisal_profile_str(report->profile),
	       report->candidate_count,
	       report->pass_count,
	       report->warn_count,
	       report->fail_count,
	       report->blocker_mask,
	       report->warning_mask,
	       report->top_candidate_id,
	       pqcp_deployment_budget_status_str(report->top_status),
	       report->top_minimum_headroom_permille,
	       report->required_margin_permille,
	       report->top_margin_score,
	       report->pipeline_readiness_score,
	       report->claim_score,
	       report->pipeline_passed ? "PASS" : "FAIL",
	       report->replay_passed ? "PASS" : "FAIL",
	       report->appraisal_passed ? "PASS" : "FAIL",
	       report->claims_passed ? "PASS" : "FAIL");

	return report->status == PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL ?
		-EBADMSG : 0;
}
