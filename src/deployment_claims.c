/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deployment claim support matrix.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/deployment_claims.h>

struct claim_definition {
	enum pqcp_deployment_claim_id id;
	const char *token;
};

static const struct claim_definition claim_definitions[] = {
	{
		PQCP_DEPLOYMENT_CLAIM_FEASIBLE_RECOMMENDATION,
		"claim.deployment.feasible_recommendation",
	},
	{
		PQCP_DEPLOYMENT_CLAIM_REPLAYABLE_EVIDENCE,
		"claim.deployment.replayable_evidence",
	},
	{
		PQCP_DEPLOYMENT_CLAIM_REPRODUCIBLE_CAMPAIGN,
		"claim.deployment.reproducible_campaign",
	},
	{
		PQCP_DEPLOYMENT_CLAIM_ROBUST_RECOMMENDATION,
		"claim.deployment.robust_recommendation",
	},
	{
		PQCP_DEPLOYMENT_CLAIM_PROFILE_APPRAISAL,
		"claim.deployment.profile_appraisal",
	},
	{
		PQCP_DEPLOYMENT_CLAIM_GAP_FREE_REVIEW,
		"claim.deployment.gap_free_review",
	},
};

static bool support_valid(enum pqcp_deployment_claim_support support)
{
	return support >= PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED &&
	       support <= PQCP_DEPLOYMENT_CLAIM_SUPPORTED;
}

static bool risk_valid(enum pqcp_deployment_claim_risk risk)
{
	return risk >= PQCP_DEPLOYMENT_CLAIM_RISK_HIGH &&
	       risk <= PQCP_DEPLOYMENT_CLAIM_RISK_LOW;
}

static bool claim_id_valid(enum pqcp_deployment_claim_id claim_id)
{
	return claim_id >= PQCP_DEPLOYMENT_CLAIM_FEASIBLE_RECOMMENDATION &&
	       claim_id <= PQCP_DEPLOYMENT_CLAIM_GAP_FREE_REVIEW;
}

static uint32_t bit_count(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += value & 1U;
		value >>= 1U;
	}

	return count;
}

static bool advisor_present(
	const struct pqcp_deployment_claim_inputs *inputs)
{
	return inputs->advisor_report != NULL &&
	       inputs->advisor_report->schema_version ==
		       PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION;
}

static bool robustness_present(
	const struct pqcp_deployment_claim_inputs *inputs)
{
	return inputs->robustness_report != NULL &&
	       inputs->robustness_report->schema_version ==
		       PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION;
}

static bool transcript_present(
	const struct pqcp_deployment_claim_inputs *inputs)
{
	return inputs->transcript_result != NULL &&
	       inputs->transcript_result->schema_version ==
		       PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION;
}

static bool appraisal_present(
	const struct pqcp_deployment_claim_inputs *inputs)
{
	return inputs->appraisal != NULL &&
	       inputs->appraisal->schema_version ==
		       PQCP_DEPLOYMENT_APPRAISAL_SCHEMA_VERSION;
}

static uint32_t input_evidence_mask(
	const struct pqcp_deployment_claim_inputs *inputs)
{
	uint32_t evidence = 0U;

	if (advisor_present(inputs)) {
		evidence |= PQCP_DEPLOYMENT_CLAIM_EVIDENCE_ADVISOR;
	}
	if (robustness_present(inputs)) {
		evidence |= PQCP_DEPLOYMENT_CLAIM_EVIDENCE_ROBUSTNESS;
	}
	if (transcript_present(inputs)) {
		evidence |= PQCP_DEPLOYMENT_CLAIM_EVIDENCE_TRANSCRIPT;
		if ((inputs->transcript_result->marker_mask &
		     PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN) != 0U) {
			evidence |= PQCP_DEPLOYMENT_CLAIM_EVIDENCE_CAMPAIGN;
		}
	}
	if (appraisal_present(inputs)) {
		evidence |= PQCP_DEPLOYMENT_CLAIM_EVIDENCE_APPRAISAL;
	}

	return evidence;
}

const char *pqcp_deployment_claim_id_str(
	enum pqcp_deployment_claim_id claim_id)
{
	for (size_t i = 0U; i < ARRAY_SIZE(claim_definitions); ++i) {
		if (claim_definitions[i].id == claim_id) {
			return claim_definitions[i].token;
		}
	}

	return "claim.deployment.unknown";
}

const char *pqcp_deployment_claim_support_str(
	enum pqcp_deployment_claim_support support)
{
	switch (support) {
	case PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED:
		return "UNSUPPORTED";
	case PQCP_DEPLOYMENT_CLAIM_PARTIAL:
		return "PARTIAL";
	case PQCP_DEPLOYMENT_CLAIM_SUPPORTED:
		return "SUPPORTED";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_deployment_claim_risk_str(
	enum pqcp_deployment_claim_risk risk)
{
	switch (risk) {
	case PQCP_DEPLOYMENT_CLAIM_RISK_HIGH:
		return "HIGH";
	case PQCP_DEPLOYMENT_CLAIM_RISK_MEDIUM:
		return "MEDIUM";
	case PQCP_DEPLOYMENT_CLAIM_RISK_LOW:
		return "LOW";
	default:
		return "UNKNOWN";
	}
}

static uint32_t required_base_markers(void)
{
	return PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_SCENARIO |
	       PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CANDIDATE |
	       PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_DECISION;
}

static uint32_t required_campaign_markers(void)
{
	return PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN |
	       PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN_METRIC;
}

static uint32_t required_robustness_markers(void)
{
	return PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUST_CANDIDATE |
	       PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUSTNESS;
}

static enum pqcp_deployment_claim_support support_from_blockers(
	uint32_t blockers,
	uint32_t warnings)
{
	if (blockers == 0U && warnings == 0U) {
		return PQCP_DEPLOYMENT_CLAIM_SUPPORTED;
	}
	if (blockers == 0U) {
		return PQCP_DEPLOYMENT_CLAIM_PARTIAL;
	}
	return PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED;
}

static enum pqcp_deployment_claim_risk risk_from_support(
	enum pqcp_deployment_claim_support support,
	uint32_t warnings)
{
	if (support == PQCP_DEPLOYMENT_CLAIM_SUPPORTED) {
		return warnings == 0U ?
			PQCP_DEPLOYMENT_CLAIM_RISK_LOW :
			PQCP_DEPLOYMENT_CLAIM_RISK_MEDIUM;
	}
	if (support == PQCP_DEPLOYMENT_CLAIM_PARTIAL) {
		return PQCP_DEPLOYMENT_CLAIM_RISK_MEDIUM;
	}
	return PQCP_DEPLOYMENT_CLAIM_RISK_HIGH;
}

static uint32_t score_from_masks(
	enum pqcp_deployment_claim_support support,
	uint32_t blockers,
	uint32_t warnings)
{
	uint32_t base;
	uint32_t penalty;

	switch (support) {
	case PQCP_DEPLOYMENT_CLAIM_SUPPORTED:
		base = 100U;
		break;
	case PQCP_DEPLOYMENT_CLAIM_PARTIAL:
		base = 70U;
		break;
	case PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED:
	default:
		base = 35U;
		break;
	}

	penalty = (bit_count(blockers) * 12U) + (bit_count(warnings) * 4U);
	return penalty >= base ? 0U : base - penalty;
}

static void fill_row(
	struct pqcp_deployment_claim_row *row,
	enum pqcp_deployment_claim_id claim_id,
	uint32_t evidence_mask,
	uint32_t blockers,
	uint32_t warnings)
{
	enum pqcp_deployment_claim_support support =
		support_from_blockers(blockers, warnings);

	*row = (struct pqcp_deployment_claim_row) {
		.schema_version = PQCP_DEPLOYMENT_CLAIMS_SCHEMA_VERSION,
		.claim_id = claim_id,
		.claim_token = pqcp_deployment_claim_id_str(claim_id),
		.support = support,
		.risk = risk_from_support(support, warnings),
		.evidence_mask = evidence_mask,
		.blocker_mask = blockers,
		.warning_mask = warnings,
		.score = score_from_masks(support, blockers, warnings),
	};
}

static void evaluate_feasible_recommendation(
	const struct pqcp_deployment_claim_inputs *inputs,
	uint32_t evidence,
	struct pqcp_deployment_claim_row *row)
{
	uint32_t blockers = 0U;
	uint32_t warnings = 0U;
	const struct pqcp_deployment_report *report = inputs->advisor_report;

	if (!advisor_present(inputs)) {
		blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_MISSING_INPUT;
	} else {
		if (report->feasible_count == 0U) {
			blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_NO_FEASIBLE;
		}
		if (report->accepted_count == 0U) {
			blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_NO_ACCEPTED;
		}
		if (report->conditional_count != 0U) {
			warnings |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_CONDITIONAL;
		}
	}

	fill_row(row, PQCP_DEPLOYMENT_CLAIM_FEASIBLE_RECOMMENDATION,
		 evidence, blockers, warnings);
}

static void evaluate_replayable_evidence(
	const struct pqcp_deployment_claim_inputs *inputs,
	uint32_t evidence,
	struct pqcp_deployment_claim_row *row)
{
	uint32_t blockers = 0U;
	const struct pqcp_deployment_transcript_result *result =
		inputs->transcript_result;

	if (!transcript_present(inputs)) {
		blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_MISSING_INPUT;
	} else {
		if (!result->passed ||
		    result->first_error != PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE) {
			blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_REPLAY_FAILED;
		}
		if ((result->marker_mask & required_base_markers()) !=
		    required_base_markers()) {
			blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_MARKER_MISSING;
		}
	}

	fill_row(row, PQCP_DEPLOYMENT_CLAIM_REPLAYABLE_EVIDENCE,
		 evidence, blockers, 0U);
}

static void evaluate_reproducible_campaign(
	const struct pqcp_deployment_claim_inputs *inputs,
	uint32_t evidence,
	struct pqcp_deployment_claim_row *row)
{
	uint32_t blockers = 0U;
	uint32_t warnings = 0U;
	const struct pqcp_deployment_transcript_result *result =
		inputs->transcript_result;

	if (!transcript_present(inputs)) {
		blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_MISSING_INPUT;
	} else {
		if ((result->marker_mask & required_campaign_markers()) !=
		    required_campaign_markers() ||
		    result->campaign_observations <
			    PQCP_DEPLOYMENT_CAMPAIGN_DEFAULT_MIN_SAMPLES) {
			blockers |=
				PQCP_DEPLOYMENT_CLAIM_BLOCKER_CAMPAIGN_MISSING;
		}
		if (result->campaign_quality_mask != 0U) {
			warnings |=
				PQCP_DEPLOYMENT_CLAIM_BLOCKER_CAMPAIGN_QUALITY;
		}
	}

	fill_row(row, PQCP_DEPLOYMENT_CLAIM_REPRODUCIBLE_CAMPAIGN,
		 evidence, blockers, warnings);
}

static void evaluate_robust_recommendation(
	const struct pqcp_deployment_claim_inputs *inputs,
	uint32_t evidence,
	struct pqcp_deployment_claim_row *row)
{
	uint32_t blockers = 0U;
	uint32_t warnings = 0U;
	const struct pqcp_deployment_robustness_report *report =
		inputs->robustness_report;
	const struct pqcp_deployment_transcript_result *transcript =
		inputs->transcript_result;

	if (!robustness_present(inputs)) {
		blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_MISSING_INPUT;
	} else {
		if (report->top_candidate_index == UINT32_MAX ||
		    !report->recommendation_robust) {
			blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_NOT_ROBUST;
		}
		if (!report->recommendation_stable) {
			warnings |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_CONDITIONAL;
		}
	}
	if (!transcript_present(inputs) ||
	    (transcript->marker_mask & required_robustness_markers()) !=
		    required_robustness_markers()) {
		blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_MARKER_MISSING;
	}

	fill_row(row, PQCP_DEPLOYMENT_CLAIM_ROBUST_RECOMMENDATION,
		 evidence, blockers, warnings);
}

static void evaluate_profile_appraisal(
	const struct pqcp_deployment_claim_inputs *inputs,
	uint32_t evidence,
	struct pqcp_deployment_claim_row *row)
{
	uint32_t blockers = 0U;
	uint32_t warnings = 0U;
	const struct pqcp_deployment_appraisal *appraisal = inputs->appraisal;

	if (!appraisal_present(inputs)) {
		blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_MISSING_INPUT;
	} else {
		if (!appraisal->passed) {
			blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_APPRAISAL_FAILED;
		}
		if (appraisal->warning_mask != 0U ||
		    appraisal->readiness_score < 90U) {
			warnings |= appraisal->warning_mask |
				    PQCP_DEPLOYMENT_CLAIM_BLOCKER_CONDITIONAL;
		}
	}

	fill_row(row, PQCP_DEPLOYMENT_CLAIM_PROFILE_APPRAISAL,
		 evidence, blockers, warnings);
}

static bool strict_review_profile(
	enum pqcp_deployment_appraisal_profile profile)
{
	return profile == PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW ||
	       profile == PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW;
}

static void evaluate_gap_free_review(
	const struct pqcp_deployment_claim_inputs *inputs,
	uint32_t evidence,
	struct pqcp_deployment_claim_row *row)
{
	uint32_t blockers = 0U;
	uint32_t warnings = 0U;
	const struct pqcp_deployment_appraisal *appraisal = inputs->appraisal;

	if (!appraisal_present(inputs)) {
		blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_MISSING_INPUT;
	} else {
		if (!appraisal->passed) {
			blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_APPRAISAL_FAILED;
		}
		if (appraisal->gap_count != 0U) {
			blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_OPEN_GAPS;
		}
		if (appraisal->conditional_count != 0U) {
			blockers |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_CONDITIONAL;
		}
		if (!strict_review_profile(appraisal->profile)) {
			warnings |= PQCP_DEPLOYMENT_CLAIM_BLOCKER_CONDITIONAL;
		}
	}

	fill_row(row, PQCP_DEPLOYMENT_CLAIM_GAP_FREE_REVIEW,
		 evidence, blockers, warnings);
}

static int validate_inputs(
	const struct pqcp_deployment_claim_inputs *inputs)
{
	if (inputs == NULL) {
		return -EINVAL;
	}
	if (inputs->advisor_report != NULL &&
	    inputs->advisor_report->schema_version !=
		    PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION) {
		return -EINVAL;
	}
	if (inputs->robustness_report != NULL &&
	    inputs->robustness_report->schema_version !=
		    PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION) {
		return -EINVAL;
	}
	if (inputs->transcript_result != NULL &&
	    inputs->transcript_result->schema_version !=
		    PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION) {
		return -EINVAL;
	}
	if (inputs->appraisal != NULL &&
	    inputs->appraisal->schema_version !=
		    PQCP_DEPLOYMENT_APPRAISAL_SCHEMA_VERSION) {
		return -EINVAL;
	}

	return 0;
}

static int claim_row_validate(const struct pqcp_deployment_claim_row *row)
{
	if (row == NULL ||
	    row->schema_version != PQCP_DEPLOYMENT_CLAIMS_SCHEMA_VERSION ||
	    !claim_id_valid(row->claim_id) ||
	    row->claim_token == NULL ||
	    strcmp(row->claim_token,
		   pqcp_deployment_claim_id_str(row->claim_id)) != 0 ||
	    !support_valid(row->support) ||
	    !risk_valid(row->risk) ||
	    (row->evidence_mask &
	     ~PQCP_DEPLOYMENT_CLAIM_EVIDENCE_KNOWN_MASK) != 0U ||
	    (row->blocker_mask &
	     ~PQCP_DEPLOYMENT_CLAIM_BLOCKER_KNOWN_MASK) != 0U ||
	    (row->warning_mask &
	     ~PQCP_DEPLOYMENT_CLAIM_BLOCKER_KNOWN_MASK) != 0U ||
	    row->score > 100U) {
		return -EINVAL;
	}
	if ((row->blocker_mask != 0U) !=
	    (row->support == PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED)) {
		return -EBADMSG;
	}
	if ((row->risk == PQCP_DEPLOYMENT_CLAIM_RISK_HIGH) !=
	    (row->support == PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED)) {
		return -EBADMSG;
	}

	return 0;
}

static void summarize_matrix(
	const struct pqcp_deployment_claim_row *rows,
	size_t row_count,
	struct pqcp_deployment_claim_matrix *matrix)
{
	uint32_t score_sum = 0U;

	*matrix = (struct pqcp_deployment_claim_matrix) {
		.schema_version = PQCP_DEPLOYMENT_CLAIMS_SCHEMA_VERSION,
		.claim_count = (uint32_t)row_count,
	};

	for (size_t i = 0U; i < row_count; ++i) {
		score_sum += rows[i].score;
		switch (rows[i].support) {
		case PQCP_DEPLOYMENT_CLAIM_SUPPORTED:
			matrix->supported_count++;
			break;
		case PQCP_DEPLOYMENT_CLAIM_PARTIAL:
			matrix->partial_count++;
			break;
		case PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED:
		default:
			matrix->unsupported_count++;
			break;
		}
		switch (rows[i].risk) {
		case PQCP_DEPLOYMENT_CLAIM_RISK_HIGH:
			matrix->high_risk_count++;
			break;
		case PQCP_DEPLOYMENT_CLAIM_RISK_MEDIUM:
			matrix->medium_risk_count++;
			break;
		case PQCP_DEPLOYMENT_CLAIM_RISK_LOW:
		default:
			break;
		}
	}

	matrix->average_score = row_count == 0U ?
		0U : score_sum / (uint32_t)row_count;
	matrix->passed = matrix->unsupported_count == 0U &&
			 matrix->high_risk_count == 0U;
}

int pqcp_deployment_claims_evaluate(
	const struct pqcp_deployment_claim_inputs *inputs,
	struct pqcp_deployment_claim_row *rows,
	size_t row_capacity,
	struct pqcp_deployment_claim_matrix *matrix)
{
	uint32_t evidence;

	if (validate_inputs(inputs) != 0 || rows == NULL || matrix == NULL ||
	    row_capacity < ARRAY_SIZE(claim_definitions)) {
		return row_capacity < ARRAY_SIZE(claim_definitions) ?
			-ENOSPC : -EINVAL;
	}

	evidence = input_evidence_mask(inputs);
	evaluate_feasible_recommendation(inputs, evidence, &rows[0]);
	evaluate_replayable_evidence(inputs, evidence, &rows[1]);
	evaluate_reproducible_campaign(inputs, evidence, &rows[2]);
	evaluate_robust_recommendation(inputs, evidence, &rows[3]);
	evaluate_profile_appraisal(inputs, evidence, &rows[4]);
	evaluate_gap_free_review(inputs, evidence, &rows[5]);

	for (size_t i = 0U; i < ARRAY_SIZE(claim_definitions); ++i) {
		int ret = claim_row_validate(&rows[i]);

		if (ret != 0) {
			return ret;
		}
	}
	summarize_matrix(rows, ARRAY_SIZE(claim_definitions), matrix);

	return 0;
}

int pqcp_deployment_claim_row_emit(
	const struct pqcp_deployment_claim_row *row)
{
	if (claim_row_validate(row) != 0) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_CLAIM schema=%u id=%s support=%s risk=%s score=%u evidence=0x%08x blockers=0x%08x warnings=0x%08x\n",
	       row->schema_version,
	       row->claim_token,
	       pqcp_deployment_claim_support_str(row->support),
	       pqcp_deployment_claim_risk_str(row->risk),
	       row->score,
	       row->evidence_mask,
	       row->blocker_mask,
	       row->warning_mask);

	return row->support == PQCP_DEPLOYMENT_CLAIM_UNSUPPORTED ? -ENODATA : 0;
}

int pqcp_deployment_claim_matrix_emit(
	const struct pqcp_deployment_claim_matrix *matrix)
{
	if (matrix == NULL ||
	    matrix->schema_version != PQCP_DEPLOYMENT_CLAIMS_SCHEMA_VERSION ||
	    matrix->claim_count != PQCP_DEPLOYMENT_CLAIMS_MAX_ROWS ||
	    matrix->supported_count + matrix->partial_count +
		    matrix->unsupported_count != matrix->claim_count ||
	    matrix->high_risk_count > matrix->claim_count ||
	    matrix->medium_risk_count > matrix->claim_count ||
	    matrix->average_score > 100U ||
	    matrix->passed != (matrix->unsupported_count == 0U &&
			       matrix->high_risk_count == 0U)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_CLAIM_MATRIX schema=%u status=%s claims=%u supported=%u partial=%u unsupported=%u high_risk=%u medium_risk=%u average_score=%u\n",
	       matrix->schema_version,
	       matrix->passed ? "PASS" : "FAIL",
	       matrix->claim_count,
	       matrix->supported_count,
	       matrix->partial_count,
	       matrix->unsupported_count,
	       matrix->high_risk_count,
	       matrix->medium_risk_count,
	       matrix->average_score);

	return matrix->passed ? 0 : -ENODATA;
}
