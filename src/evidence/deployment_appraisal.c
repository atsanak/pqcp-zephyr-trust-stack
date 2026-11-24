/*
 * SPDX-License-Identifier: MIT
 *
 * Deployment evidence appraisal.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_appraisal.h>

static uint32_t bit_count(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += value & 1U;
		value >>= 1U;
	}

	return count;
}

static uint32_t readiness_score(uint32_t blockers, uint32_t warnings)
{
	uint32_t penalty = bit_count(blockers) * 20U +
			   bit_count(warnings) * 4U;

	return penalty >= 100U ? 0U : 100U - penalty;
}

static bool profile_valid(enum pqcp_deployment_appraisal_profile profile)
{
	return profile >= PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB &&
	       profile <= PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW;
}

static uint32_t base_required_markers(void)
{
	return PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_SCENARIO |
	       PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CANDIDATE |
	       PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_DECISION;
}

static uint32_t robustness_markers(void)
{
	return PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUST_CANDIDATE |
	       PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUSTNESS;
}

static uint32_t campaign_markers(void)
{
	return PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN |
	       PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN_METRIC;
}

const char *pqcp_deployment_appraisal_profile_str(
	enum pqcp_deployment_appraisal_profile profile)
{
	switch (profile) {
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB:
		return "lab";
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PAPER:
		return "paper";
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT:
		return "product";
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW:
		return "partner_review";
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW:
		return "hardware_review";
	default:
		return "unknown";
	}
}

int pqcp_deployment_appraisal_default_policy(
	enum pqcp_deployment_appraisal_profile profile,
	struct pqcp_deployment_appraisal_policy *policy)
{
	if (policy == NULL || !profile_valid(profile)) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->required_markers = base_required_markers();
	policy->min_candidates = 1U;
	policy->min_feasible = 1U;
	policy->min_accepted = 0U;
	policy->min_campaign_observations = 0U;
	policy->max_gap_count = UINT32_MAX;
	policy->allow_conditional = true;

	switch (profile) {
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB:
		break;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PAPER:
		policy->required_markers |= robustness_markers() |
					    campaign_markers();
		policy->min_candidates = 2U;
		policy->min_accepted = 1U;
		policy->min_campaign_observations = 5U;
		policy->max_gap_count = 8U;
		policy->require_campaign = true;
		policy->require_clean_campaign = true;
		policy->require_robustness = true;
		break;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PRODUCT:
		policy->required_markers |= robustness_markers() |
					    campaign_markers();
		policy->min_candidates = 2U;
		policy->min_feasible = 1U;
		policy->min_accepted = 1U;
		policy->min_campaign_observations = 5U;
		policy->max_gap_count = 3U;
		policy->require_campaign = true;
		policy->require_clean_campaign = true;
		policy->require_robustness = true;
		break;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_PARTNER_REVIEW:
		policy->required_markers |= robustness_markers() |
					    campaign_markers();
		policy->min_candidates = 2U;
		policy->min_feasible = 1U;
		policy->min_accepted = 1U;
		policy->min_campaign_observations = 5U;
		policy->max_gap_count = 0U;
		policy->require_campaign = true;
		policy->require_clean_campaign = true;
		policy->require_robustness = true;
		policy->allow_conditional = false;
		break;
	case PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW:
		policy->required_markers |= robustness_markers() |
					    campaign_markers();
		policy->min_candidates = 3U;
		policy->min_feasible = 1U;
		policy->min_accepted = 1U;
		policy->min_campaign_observations = 5U;
		policy->max_gap_count = 0U;
		policy->require_campaign = true;
		policy->require_clean_campaign = true;
		policy->require_robustness = true;
		policy->allow_conditional = false;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int policy_validate(
	const struct pqcp_deployment_appraisal_policy *policy)
{
	if (policy == NULL || !profile_valid(policy->profile) ||
	    (policy->required_markers &
	     ~PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_KNOWN_MASK) != 0U) {
		return -EINVAL;
	}
	if (policy->require_campaign &&
	    (policy->required_markers & campaign_markers()) !=
		    campaign_markers()) {
		return -EINVAL;
	}
	if (policy->require_robustness &&
	    (policy->required_markers & robustness_markers()) !=
		    robustness_markers()) {
		return -EINVAL;
	}

	return 0;
}

static uint32_t evaluate_blockers(
	const struct pqcp_deployment_transcript_result *replay,
	const struct pqcp_deployment_appraisal_policy *policy)
{
	uint32_t blockers = 0U;

	if (replay->schema_version !=
	    PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION ||
	    !replay->passed ||
	    replay->first_error != PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_REPLAY_FAILED;
	}
	if ((replay->marker_mask & policy->required_markers) !=
	    policy->required_markers) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_MISSING_MARKERS;
	}
	if (replay->candidate_count < policy->min_candidates) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CANDIDATE_COUNT;
	}
	if (replay->feasible_count < policy->min_feasible) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_FEASIBLE_COUNT;
	}
	if (replay->accepted_count < policy->min_accepted) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_ACCEPTED_COUNT;
	}
	if (policy->require_campaign &&
	    (replay->marker_mask & campaign_markers()) != campaign_markers()) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_REQUIRED;
	}
	if (policy->min_campaign_observations != 0U &&
	    replay->campaign_observations <
		    policy->min_campaign_observations) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_SAMPLES;
	}
	if (policy->require_clean_campaign &&
	    replay->campaign_quality_mask != 0U) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CAMPAIGN_QUALITY;
	}
	if (policy->require_robustness &&
	    (replay->marker_mask & robustness_markers()) !=
		    robustness_markers()) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_ROBUSTNESS_REQUIRED;
	}
	if (policy->max_gap_count != UINT32_MAX &&
	    replay->gap_count > policy->max_gap_count) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_OPEN_GAPS;
	}
	if (!policy->allow_conditional && replay->conditional_count != 0U) {
		blockers |= PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_CONDITIONAL;
	}

	return blockers;
}

static uint32_t evaluate_warnings(
	const struct pqcp_deployment_transcript_result *replay,
	const struct pqcp_deployment_appraisal_policy *policy)
{
	uint32_t warnings = 0U;

	if (replay->conditional_count != 0U) {
		warnings |= PQCP_DEPLOYMENT_APPRAISAL_WARNING_CONDITIONAL;
	}
	if (replay->rejected_count != 0U) {
		warnings |= PQCP_DEPLOYMENT_APPRAISAL_WARNING_REJECTED;
	}
	if (replay->gap_count != 0U) {
		warnings |= PQCP_DEPLOYMENT_APPRAISAL_WARNING_OPEN_GAPS;
	}
	if (!policy->require_campaign &&
	    (replay->marker_mask & campaign_markers()) != campaign_markers()) {
		warnings |= PQCP_DEPLOYMENT_APPRAISAL_WARNING_NO_CAMPAIGN;
	}
	if (!policy->require_robustness &&
	    (replay->marker_mask & robustness_markers()) !=
		    robustness_markers()) {
		warnings |= PQCP_DEPLOYMENT_APPRAISAL_WARNING_NO_ROBUSTNESS;
	}
	if (replay->feasible_count == 1U) {
		warnings |= PQCP_DEPLOYMENT_APPRAISAL_WARNING_SINGLE_FEASIBLE;
	}

	return warnings;
}

int pqcp_deployment_appraisal_evaluate(
	const struct pqcp_deployment_transcript_result *replay,
	const struct pqcp_deployment_appraisal_policy *policy,
	struct pqcp_deployment_appraisal *appraisal)
{
	uint32_t blockers;
	uint32_t warnings;

	if (replay == NULL || appraisal == NULL ||
	    policy_validate(policy) != 0) {
		return -EINVAL;
	}

	blockers = evaluate_blockers(replay, policy);
	warnings = evaluate_warnings(replay, policy);

	*appraisal = (struct pqcp_deployment_appraisal) {
		.schema_version = PQCP_DEPLOYMENT_APPRAISAL_SCHEMA_VERSION,
		.profile = policy->profile,
		.blocker_mask = blockers,
		.warning_mask = warnings,
		.marker_mask = replay->marker_mask,
		.candidate_count = replay->candidate_count,
		.feasible_count = replay->feasible_count,
		.accepted_count = replay->accepted_count,
		.conditional_count = replay->conditional_count,
		.gap_count = replay->gap_count,
		.campaign_observations = replay->campaign_observations,
		.readiness_score = readiness_score(blockers, warnings),
		.passed = blockers == 0U,
	};

	return 0;
}

int pqcp_deployment_appraisal_emit(
	const struct pqcp_deployment_appraisal *appraisal)
{
	if (appraisal == NULL ||
	    appraisal->schema_version !=
		    PQCP_DEPLOYMENT_APPRAISAL_SCHEMA_VERSION ||
	    !profile_valid(appraisal->profile) ||
	    appraisal->readiness_score > 100U ||
	    appraisal->passed != (appraisal->blocker_mask == 0U) ||
	    (appraisal->marker_mask &
	     ~PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_KNOWN_MASK) != 0U ||
	    (appraisal->blocker_mask &
	     ~PQCP_DEPLOYMENT_APPRAISAL_BLOCKER_KNOWN_MASK) != 0U ||
	    (appraisal->warning_mask &
	     ~PQCP_DEPLOYMENT_APPRAISAL_WARNING_KNOWN_MASK) != 0U) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_APPRAISAL schema=%u profile=%s status=%s blockers=0x%08x warnings=0x%08x readiness=%u markers=0x%08x candidates=%u feasible=%u accepted=%u conditional=%u gaps=%u campaign_observations=%u\n",
	       appraisal->schema_version,
	       pqcp_deployment_appraisal_profile_str(appraisal->profile),
	       appraisal->passed ? "PASS" : "FAIL",
	       appraisal->blocker_mask,
	       appraisal->warning_mask,
	       appraisal->readiness_score,
	       appraisal->marker_mask,
	       appraisal->candidate_count,
	       appraisal->feasible_count,
	       appraisal->accepted_count,
	       appraisal->conditional_count,
	       appraisal->gap_count,
	       appraisal->campaign_observations);

	return appraisal->passed ? 0 : -EPERM;
}
