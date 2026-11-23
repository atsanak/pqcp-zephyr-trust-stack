/*
 * SPDX-License-Identifier: MIT
 *
 * Policy appraisal for firmware fleet deployment evidence.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_fleet_policy.h>

#define FLEET_POLICY_DOMAIN UINT64_C(0x5051435046504f4c)

static void set_text(char *destination, size_t capacity, const char *source)
{
	if (destination == NULL || capacity == 0U) {
		return;
	}
	if (source == NULL) {
		destination[0] = '\0';
		return;
	}
	(void)snprintk(destination, capacity, "%s", source);
}

static uint32_t percent(uint32_t numerator, uint32_t denominator)
{
	if (denominator == 0U) {
		return 0U;
	}
	return (uint32_t)(((uint64_t)numerator * 100U) / denominator);
}

static uint32_t clamp_subtract(uint32_t value, uint32_t penalty)
{
	return penalty >= value ? 0U : value - penalty;
}

static bool profile_valid(enum pqcp_deployment_fleet_policy_profile profile)
{
	return profile >= PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE &&
	       profile <= PQCP_DEPLOYMENT_FLEET_POLICY_HARDWARE;
}

static bool policy_valid(const struct pqcp_deployment_fleet_policy *policy)
{
	return policy != NULL && profile_valid(policy->profile) &&
	       policy->min_devices != 0U &&
	       policy->min_devices <=
		       PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_DEVICES &&
	       policy->min_candidate_quorum_percent <= 100U &&
	       policy->min_profile_quorum_percent <= 100U &&
	       policy->min_board_quorum_percent <= 100U &&
	       policy->min_signature_percent <= 100U &&
	       policy->min_production_percent <= 100U &&
	       policy->min_average_score <= 100U &&
	       policy->max_outlier_percent <= 100U;
}

static bool consensus_shape_valid(
	const struct pqcp_deployment_fleet_consensus_report *consensus)
{
	return consensus != NULL &&
	       consensus->schema_version ==
		       PQCP_DEPLOYMENT_FLEET_CONSENSUS_SCHEMA_VERSION &&
	       consensus->device_count != 0U &&
	       consensus->device_count <=
		       PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_DEVICES &&
	       consensus->accepted_count <= consensus->device_count &&
	       consensus->rejected_count <= consensus->device_count &&
	       consensus->accepted_count + consensus->rejected_count <=
		       consensus->device_count &&
	       consensus->average_score <= 100U &&
	       consensus->candidate_quorum_percent <= 100U &&
	       consensus->profile_quorum_percent <= 100U &&
	       consensus->board_quorum_percent <= 100U &&
	       consensus->consensus_candidate_id[0] != '\0' &&
	       consensus->consensus_board[0] != '\0' &&
	       pqcp_deployment_evidence_codec_is_lower_hex(
		       consensus->fleet_digest_hex,
		       PQCP_DEPLOYMENT_FLEET_CONSENSUS_DIGEST_HEX_CHARS) &&
	       (consensus->error_mask &
		~PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_KNOWN_MASK) == 0U &&
	       (consensus->warning_mask &
		~PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_KNOWN_MASK) == 0U;
}

static void apply_quorum(
	const struct pqcp_deployment_fleet_consensus_report *consensus,
	const struct pqcp_deployment_fleet_policy *policy,
	struct pqcp_deployment_fleet_policy_result *result)
{
	bool candidate_low =
		consensus->candidate_quorum_percent <
		policy->min_candidate_quorum_percent;
	bool profile_low =
		consensus->profile_quorum_percent <
		policy->min_profile_quorum_percent;
	bool board_low =
		consensus->board_quorum_percent <
		policy->min_board_quorum_percent;

	if (candidate_low) {
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_RESOLVE_CANDIDATE_DRIFT;
	}
	if (profile_low) {
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_RESOLVE_PROFILE_DRIFT;
	}
	if (board_low) {
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_RESOLVE_BOARD_DRIFT;
	}
	if (candidate_low || profile_low || board_low) {
		if (policy->quorum_floor_blocks) {
			if (candidate_low) {
				result->blocker_mask |=
					PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_CANDIDATE_QUORUM;
			}
			if (profile_low) {
				result->blocker_mask |=
					PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_PROFILE_QUORUM;
			}
			if (board_low) {
				result->blocker_mask |=
					PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_BOARD_QUORUM;
			}
		} else {
			result->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_LOW_QUORUM;
		}
	}
}

static void apply_coverage(
	const struct pqcp_deployment_fleet_consensus_report *consensus,
	const struct pqcp_deployment_fleet_policy *policy,
	struct pqcp_deployment_fleet_policy_result *result)
{
	result->signature_percent = percent(
		consensus->signature_count, consensus->accepted_count);
	result->production_percent = percent(
		consensus->production_count, consensus->accepted_count);
	if (result->signature_percent < policy->min_signature_percent) {
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_SIGN_PASSPORTS;
		if (policy->signature_floor_blocks) {
			result->blocker_mask |=
				PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_SIGNATURE_COVERAGE;
		} else {
			result->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_UNSIGNED;
		}
	}
	if (result->production_percent < policy->min_production_percent) {
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_PROMOTE_PRODUCTION;
		if (policy->production_floor_blocks) {
			result->blocker_mask |=
				PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_PRODUCTION_COVERAGE;
		} else {
			result->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_NON_PRODUCTION;
		}
	}
}

static void apply_failure_limits(
	const struct pqcp_deployment_fleet_consensus_report *consensus,
	const struct pqcp_deployment_fleet_policy *policy,
	struct pqcp_deployment_fleet_policy_result *result)
{
	uint32_t replay_failures =
		consensus->device_count - consensus->replay_pass_count;

	if (policy->require_no_passport_failures &&
	    consensus->passport_fail_count >
		    policy->max_passport_failures) {
		result->blocker_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_PASSPORT_FAILURES;
		result->warning_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_FAILURE_HISTORY;
	}
	if (policy->require_no_audit_failures &&
	    consensus->audit_fail_count > policy->max_audit_failures) {
		result->blocker_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_AUDIT_FAILURES;
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_REAUDIT_DEVICE;
	}
	if (policy->require_no_replay_failures &&
	    replay_failures > policy->max_replay_failures) {
		result->blocker_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_REPLAY_FAILURES;
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_REPLAY_FAILED_DEVICE;
	}
	if (consensus->passport_fail_count != 0U ||
	    consensus->audit_fail_count != 0U ||
	    replay_failures != 0U) {
		result->warning_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_FAILURE_HISTORY;
	}
}

static void apply_score_and_outliers(
	const struct pqcp_deployment_fleet_consensus_report *consensus,
	const struct pqcp_deployment_fleet_policy *policy,
	struct pqcp_deployment_fleet_policy_result *result)
{
	result->outlier_percent = percent(
		consensus->outlier_count, consensus->device_count);
	if (result->outlier_percent > policy->max_outlier_percent) {
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_INVESTIGATE_OUTLIERS;
		if (policy->outlier_floor_blocks) {
			result->blocker_mask |=
				PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_OUTLIERS;
		} else {
			result->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_OUTLIERS;
		}
	}
	if (consensus->average_score < policy->min_average_score) {
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_REPEAT_BENCHMARKS;
		if (policy->score_floor_blocks) {
			result->blocker_mask |=
				PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_SCORE_FLOOR;
		} else {
			result->warning_mask |=
				PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_LOW_SCORE;
		}
	}
}

static uint32_t readiness_score(
	const struct pqcp_deployment_fleet_consensus_report *consensus,
	const struct pqcp_deployment_fleet_policy_result *result)
{
	uint32_t score = 100U;

	score = clamp_subtract(
		score, result->blocker_mask != 0U ? 45U : 0U);
	score = clamp_subtract(
		score, result->warning_mask != 0U ? 10U : 0U);
	score = clamp_subtract(
		score, 100U - result->candidate_quorum_percent);
	score = clamp_subtract(
		score, (100U - result->profile_quorum_percent) / 2U);
	score = clamp_subtract(
		score, (100U - result->signature_percent) / 4U);
	score = clamp_subtract(
		score, (100U - result->production_percent) / 4U);
	score = clamp_subtract(score, result->outlier_percent / 2U);
	if (consensus->average_score < score) {
		score = (score + consensus->average_score) / 2U;
	}
	return score;
}

static uint32_t reviewer_risk(
	const struct pqcp_deployment_fleet_policy_result *result)
{
	uint32_t risk = 100U - result->readiness_score;
	uint32_t blockers = 0U;
	uint32_t warnings = 0U;

	for (uint32_t mask = result->blocker_mask; mask != 0U;
	     mask >>= 1U) {
		blockers += mask & 1U;
	}
	for (uint32_t mask = result->warning_mask; mask != 0U;
	     mask >>= 1U) {
		warnings += mask & 1U;
	}
	risk += blockers * 6U + warnings * 2U;
	return risk > 100U ? 100U : risk;
}

static uint32_t evidence_grade(
	const struct pqcp_deployment_fleet_policy_result *result)
{
	if (result->status == PQCP_DEPLOYMENT_FLEET_POLICY_FAIL) {
		return 0U;
	}
	if (result->readiness_score >= 90U &&
	    result->signature_percent == 100U &&
	    result->production_percent == 100U) {
		return 4U;
	}
	if (result->readiness_score >= 80U) {
		return 3U;
	}
	if (result->readiness_score >= 65U) {
		return 2U;
	}
	return 1U;
}

static int digest_result(
	const struct pqcp_deployment_fleet_policy_result *result,
	char output[PQCP_DEPLOYMENT_FLEET_POLICY_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (result == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, FLEET_POLICY_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->profile);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->blocker_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->action_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->readiness_score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->reviewer_risk_score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->evidence_grade);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->device_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->accepted_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->signature_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->production_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->candidate_quorum_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->profile_quorum_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->board_quorum_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->outlier_percent);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->average_score);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->consensus_digest_bound);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->candidate_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->board);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->deployment_profile);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->consensus_digest_hex);
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

const char *pqcp_deployment_fleet_policy_profile_str(
	enum pqcp_deployment_fleet_policy_profile profile)
{
	switch (profile) {
	case PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE:
		return "prototype";
	case PQCP_DEPLOYMENT_FLEET_POLICY_PAPER:
		return "paper";
	case PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT:
		return "product";
	case PQCP_DEPLOYMENT_FLEET_POLICY_PARTNER:
		return "partner";
	case PQCP_DEPLOYMENT_FLEET_POLICY_HARDWARE:
		return "hardware";
	default:
		return "unknown";
	}
}

const char *pqcp_deployment_fleet_policy_status_str(
	enum pqcp_deployment_fleet_policy_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_FLEET_POLICY_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_FLEET_POLICY_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_FLEET_POLICY_FAIL:
	default:
		return "FAIL";
	}
}

int pqcp_deployment_fleet_policy_default(
	enum pqcp_deployment_fleet_policy_profile profile,
	struct pqcp_deployment_fleet_policy *policy)
{
	if (policy == NULL || !profile_valid(profile)) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->min_devices = profile == PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE ?
				      1U :
			      profile == PQCP_DEPLOYMENT_FLEET_POLICY_PAPER ?
				      3U :
			      profile == PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT ?
				      5U : 3U;
	policy->min_candidate_quorum_percent =
		profile == PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE ? 50U :
		profile == PQCP_DEPLOYMENT_FLEET_POLICY_PAPER ? 67U : 80U;
	policy->min_profile_quorum_percent =
		profile == PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE ? 50U :
		profile == PQCP_DEPLOYMENT_FLEET_POLICY_PAPER ? 67U : 100U;
	policy->min_board_quorum_percent =
		profile == PQCP_DEPLOYMENT_FLEET_POLICY_HARDWARE ? 100U : 50U;
	policy->min_signature_percent =
		profile <= PQCP_DEPLOYMENT_FLEET_POLICY_PAPER ? 0U : 80U;
	policy->min_production_percent =
		profile <= PQCP_DEPLOYMENT_FLEET_POLICY_PAPER ? 0U : 80U;
	policy->min_average_score =
		profile == PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE ? 50U :
		profile == PQCP_DEPLOYMENT_FLEET_POLICY_PAPER ? 70U : 80U;
	policy->max_outlier_percent =
		profile == PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE ? 50U :
		profile == PQCP_DEPLOYMENT_FLEET_POLICY_PAPER ? 34U : 20U;
	policy->max_passport_failures =
		profile <= PQCP_DEPLOYMENT_FLEET_POLICY_PAPER ? 1U : 0U;
	policy->max_audit_failures = 0U;
	policy->max_replay_failures = 0U;
	policy->require_consensus_pass =
		profile >= PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT;
	policy->require_no_passport_failures =
		profile >= PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT;
	policy->require_no_audit_failures = true;
	policy->require_no_replay_failures = true;
	policy->quorum_floor_blocks =
		profile >= PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT;
	policy->signature_floor_blocks =
		profile >= PQCP_DEPLOYMENT_FLEET_POLICY_PARTNER;
	policy->production_floor_blocks =
		profile >= PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT;
	policy->score_floor_blocks =
		profile >= PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT;
	policy->outlier_floor_blocks =
		profile >= PQCP_DEPLOYMENT_FLEET_POLICY_PARTNER;
	return 0;
}

int pqcp_deployment_fleet_policy_evaluate(
	const struct pqcp_deployment_fleet_consensus_report *consensus,
	const struct pqcp_deployment_fleet_policy *policy,
	struct pqcp_deployment_fleet_policy_result *result)
{
	int ret;

	if (result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->schema_version = PQCP_DEPLOYMENT_FLEET_POLICY_SCHEMA_VERSION;
	result->status = PQCP_DEPLOYMENT_FLEET_POLICY_FAIL;
	if (!policy_valid(policy) || !consensus_shape_valid(consensus)) {
		result->blocker_mask =
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_INVALID_INPUT;
		return -EINVAL;
	}
	result->profile = policy->profile;
	result->device_count = consensus->device_count;
	result->accepted_count = consensus->accepted_count;
	result->candidate_quorum_percent =
		consensus->candidate_quorum_percent;
	result->profile_quorum_percent =
		consensus->profile_quorum_percent;
	result->board_quorum_percent = consensus->board_quorum_percent;
	result->average_score = consensus->average_score;
	result->deployment_profile = consensus->consensus_profile;
	result->consensus_digest_bound = true;
	set_text(result->candidate_id, sizeof(result->candidate_id),
		  consensus->consensus_candidate_id);
	set_text(result->board, sizeof(result->board),
		  consensus->consensus_board);
	set_text(result->consensus_digest_hex,
		  sizeof(result->consensus_digest_hex),
		  consensus->fleet_digest_hex);
	if (consensus->accepted_count < policy->min_devices) {
		result->blocker_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_DEVICE_COUNT;
		result->action_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_ADD_DEVICES;
	}
	if (policy->require_consensus_pass &&
	    consensus->status != PQCP_DEPLOYMENT_FLEET_CONSENSUS_PASS) {
		result->blocker_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_CONSENSUS_FAIL;
	} else if (consensus->status ==
		   PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARN) {
		result->warning_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_CONSENSUS_WARN;
	}
	apply_quorum(consensus, policy, result);
	apply_coverage(consensus, policy, result);
	apply_failure_limits(consensus, policy, result);
	apply_score_and_outliers(consensus, policy, result);
	if (consensus->distinct_boards > 1U) {
		result->warning_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_HETEROGENEOUS_BOARD;
	}
	result->status = result->blocker_mask != 0U ?
				 PQCP_DEPLOYMENT_FLEET_POLICY_FAIL :
			 result->warning_mask != 0U ?
				 PQCP_DEPLOYMENT_FLEET_POLICY_WARN :
				 PQCP_DEPLOYMENT_FLEET_POLICY_PASS;
	result->readiness_score = readiness_score(consensus, result);
	result->reviewer_risk_score = reviewer_risk(result);
	result->evidence_grade = evidence_grade(result);
	ret = digest_result(result, result->policy_digest_hex);
	if (ret != 0) {
		result->blocker_mask |=
			PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_INVALID_INPUT;
		result->status = PQCP_DEPLOYMENT_FLEET_POLICY_FAIL;
		return ret;
	}
	return result->status == PQCP_DEPLOYMENT_FLEET_POLICY_FAIL ?
		       -EBADMSG : 0;
}

int pqcp_deployment_fleet_policy_emit(
	const struct pqcp_deployment_fleet_policy_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_FLEET_POLICY_SCHEMA_VERSION ||
	    !profile_valid(result->profile) ||
	    (result->blocker_mask &
	     ~PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_KNOWN_MASK) != 0U ||
	    (result->warning_mask &
	     ~PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_KNOWN_MASK) != 0U ||
	    (result->action_mask &
	     ~PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_KNOWN_MASK) != 0U) {
		return -EINVAL;
	}
	printk("PQCP_DEPLOYMENT_FLEET_POLICY schema=%u profile=%s status=%s "
	       "blockers=0x%08x warnings=0x%08x actions=0x%08x "
	       "readiness=%u reviewer_risk=%u evidence_grade=%u devices=%u "
	       "accepted=%u signature_percent=%u production_percent=%u "
	       "candidate_quorum=%u profile_quorum=%u board_quorum=%u "
	       "outlier_percent=%u average_score=%u digest_bound=%u "
	       "deployment_profile=%u candidate=%s board=%s "
	       "consensus_digest=%s policy_digest=%s\n",
	       result->schema_version,
	       pqcp_deployment_fleet_policy_profile_str(result->profile),
	       pqcp_deployment_fleet_policy_status_str(result->status),
	       result->blocker_mask, result->warning_mask,
	       result->action_mask, result->readiness_score,
	       result->reviewer_risk_score, result->evidence_grade,
	       result->device_count, result->accepted_count,
	       result->signature_percent, result->production_percent,
	       result->candidate_quorum_percent,
	       result->profile_quorum_percent,
	       result->board_quorum_percent,
	       result->outlier_percent, result->average_score,
	       result->consensus_digest_bound ? 1U : 0U,
	       (uint32_t)result->deployment_profile,
	       result->candidate_id, result->board,
	       result->consensus_digest_hex, result->policy_digest_hex);
	return 0;
}
