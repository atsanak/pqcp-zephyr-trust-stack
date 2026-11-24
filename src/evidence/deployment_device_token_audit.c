/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware-native deployment device-token replay audit aggregation.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_device_token_audit.h>

static bool text_present(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool token_status_valid(
	enum pqcp_deployment_device_token_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;
}

static bool gate_status_valid(enum pqcp_deployment_release_gate_status status)
{
	return status == PQCP_DEPLOYMENT_RELEASE_GATE_PASS ||
	       status == PQCP_DEPLOYMENT_RELEASE_GATE_WARN ||
	       status == PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
}

static bool result_schema_valid(
	const struct pqcp_deployment_device_token_replay_result *result)
{
	return result->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION &&
	       result->lines_seen != 0U &&
	       result->marker_mask ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK &&
	       token_status_valid(result->token_status) &&
	       gate_status_valid(result->gate_status) &&
	       text_present(result->top_candidate_id) &&
	       text_present(result->nonce_hex) &&
	       text_present(result->token_digest_hex) &&
	       text_present(result->computed_digest_hex);
}

static bool result_scores_valid(
	const struct pqcp_deployment_device_token_replay_result *result)
{
	return result->capability_readiness_score <= 100U &&
	       result->gate_score <= 100U;
}

static bool status_valid(
	enum pqcp_deployment_device_token_audit_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL;
}

const char *pqcp_deployment_device_token_audit_status_str(
	enum pqcp_deployment_device_token_audit_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

int pqcp_deployment_device_token_audit_default_policy(
	struct pqcp_deployment_device_token_audit_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->minimum_results = 1U;
	policy->capability_score_warn_floor = 70U;
	policy->gate_score_warn_floor = 60U;
	policy->require_replay_pass = true;
	policy->require_token_pass = false;
	policy->require_gate_pass = false;
	policy->require_stable_nonce = true;
	policy->require_stable_top = true;
	policy->require_stable_token_digest = true;
	policy->require_stable_gate_status = false;

	return 0;
}

static bool policy_valid(
	const struct pqcp_deployment_device_token_audit_policy *policy)
{
	return policy != NULL &&
	       policy->minimum_results <=
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_MAX_RESULTS &&
	       policy->capability_score_warn_floor <= 100U &&
	       policy->gate_score_warn_floor <= 100U;
}

static enum pqcp_deployment_device_token_audit_status compute_status(
	uint32_t errors,
	uint32_t warnings)
{
	if (errors != 0U) {
		return PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL;
	}
	if (warnings != 0U) {
		return PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN;
	}

	return PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS;
}

static void report_invalid(
	struct pqcp_deployment_device_token_audit_report *report,
	uint32_t error_mask)
{
	if (report == NULL) {
		return;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_SCHEMA_VERSION;
	report->status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL;
	report->error_mask = error_mask;
	report->min_capability_readiness_score = 100U;
	report->min_gate_score = 100U;
	report->stable_nonce = true;
	report->stable_top_candidate = true;
	report->stable_token_digest = true;
	report->stable_gate_status = true;
	(void)snprintk(report->nonce_hex, sizeof(report->nonce_hex), "%s",
		       "00000000000000000000000000000000");
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s", "none");
}

static uint32_t count_unique_token_digests(
	const struct pqcp_deployment_device_token_replay_result *results,
	size_t count)
{
	uint32_t unique = 0U;

	for (size_t i = 0U; i < count; ++i) {
		bool seen = false;

		for (size_t j = 0U; j < i; ++j) {
			if (strcmp(results[i].token_digest_hex,
				   results[j].token_digest_hex) == 0) {
				seen = true;
				break;
			}
		}
		if (!seen) {
			unique++;
		}
	}

	return unique;
}

static void copy_representative(
	struct pqcp_deployment_device_token_audit_report *report,
	const struct pqcp_deployment_device_token_replay_result *result)
{
	(void)snprintk(report->nonce_hex, sizeof(report->nonce_hex), "%s",
		       result->nonce_hex);
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s",
		       result->top_candidate_id);
	(void)snprintk(report->token_digest_hex,
		       sizeof(report->token_digest_hex), "%s",
		       result->token_digest_hex);
}

static void accumulate_replay_counts(
	struct pqcp_deployment_device_token_audit_report *report,
	const struct pqcp_deployment_device_token_replay_result *result)
{
	if (result->passed) {
		report->replay_pass_count++;
	} else {
		report->replay_fail_count++;
	}

	switch (result->token_status) {
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS:
		report->token_pass_count++;
		break;
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN:
		report->token_warn_count++;
		break;
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL:
	default:
		report->token_fail_count++;
		break;
	}

	switch (result->gate_status) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PASS:
		report->gate_pass_count++;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_WARN:
		report->gate_warn_count++;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_FAIL:
	default:
		report->gate_fail_count++;
		break;
	}
}

static void accumulate_scores(
	struct pqcp_deployment_device_token_audit_report *report,
	const struct pqcp_deployment_device_token_replay_result *result,
	uint32_t *gate_score_sum)
{
	if (result->capability_readiness_score <
	    report->min_capability_readiness_score) {
		report->min_capability_readiness_score =
			result->capability_readiness_score;
	}
	if (result->gate_score < report->min_gate_score) {
		report->min_gate_score = result->gate_score;
	}
	if (result->gate_score > report->max_gate_score) {
		report->max_gate_score = result->gate_score;
	}
	*gate_score_sum += result->gate_score;
}

static void accumulate_stability(
	struct pqcp_deployment_device_token_audit_report *report,
	const struct pqcp_deployment_device_token_replay_result *first,
	const struct pqcp_deployment_device_token_replay_result *current)
{
	if (strcmp(first->nonce_hex, current->nonce_hex) != 0) {
		report->stable_nonce = false;
	}
	if (strcmp(first->top_candidate_id, current->top_candidate_id) != 0) {
		report->stable_top_candidate = false;
	}
	if (strcmp(first->token_digest_hex, current->token_digest_hex) != 0) {
		report->stable_token_digest = false;
	}
	if (first->gate_status != current->gate_status) {
		report->stable_gate_status = false;
	}
}

static void apply_policy(
	struct pqcp_deployment_device_token_audit_report *report,
	const struct pqcp_deployment_device_token_audit_policy *policy)
{
	if (report->result_count < policy->minimum_results) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_SAMPLE_COUNT;
	}
	if (policy->require_replay_pass && report->replay_fail_count != 0U) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_REPLAY_FAILED;
	}
	if (!report->stable_nonce) {
		if (policy->require_stable_nonce) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_NONCE_DRIFT;
		}
	}
	if (!report->stable_top_candidate) {
		if (policy->require_stable_top) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOP_DRIFT;
		}
	}
	if (!report->stable_token_digest) {
		if (policy->require_stable_token_digest) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOKEN_DIGEST_DRIFT;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_TOKEN_DIVERSITY;
		}
	}
	if (!report->stable_gate_status &&
	    policy->require_stable_gate_status) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_GATE_STATUS_DRIFT;
	}
	if (policy->require_token_pass && report->token_pass_count !=
	    report->result_count) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_TOKEN_STATUS;
	} else if (report->token_warn_count != 0U ||
		   report->token_fail_count != 0U) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_TOKEN_NOT_PASS;
	}
	if (policy->require_gate_pass && report->gate_pass_count !=
	    report->result_count) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_GATE_STATUS;
	} else if (report->gate_warn_count != 0U ||
		   report->gate_fail_count != 0U) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_GATE_NOT_PASS;
	}
	if (report->min_capability_readiness_score <
	    policy->capability_score_warn_floor) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_CAPABILITY_SCORE;
	}
	if (report->min_gate_score < policy->gate_score_warn_floor) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_LOW_GATE_SCORE;
	}
}

int pqcp_deployment_device_token_audit_run(
	const struct pqcp_deployment_device_token_replay_result *results,
	size_t result_count,
	const struct pqcp_deployment_device_token_audit_policy *policy,
	struct pqcp_deployment_device_token_audit_report *report)
{
	uint32_t gate_score_sum = 0U;

	if (report == NULL) {
		return -EINVAL;
	}
	if (!policy_valid(policy) || results == NULL ||
	    result_count > PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_MAX_RESULTS) {
		report_invalid(report,
			       PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if (result_count == 0U) {
		report_invalid(report,
			       PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_NO_RESULTS);
		return -EINVAL;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_SCHEMA_VERSION;
	report->result_count = (uint32_t)result_count;
	report->min_capability_readiness_score = 100U;
	report->min_gate_score = 100U;
	report->stable_nonce = true;
	report->stable_top_candidate = true;
	report->stable_token_digest = true;
	report->stable_gate_status = true;
	copy_representative(report, &results[0]);

	for (size_t i = 0U; i < result_count; ++i) {
		if (!result_schema_valid(&results[i])) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_MALFORMED_RESULT;
			continue;
		}
		if (!result_scores_valid(&results[i])) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_SCORE_RANGE;
			continue;
		}
		accumulate_replay_counts(report, &results[i]);
		accumulate_scores(report, &results[i], &gate_score_sum);
		accumulate_stability(report, &results[0], &results[i]);
	}

	report->unique_token_digest_count =
		count_unique_token_digests(results, result_count);
	report->avg_gate_score = report->result_count != 0U ?
		gate_score_sum / report->result_count : 0U;

	apply_policy(report, policy);
	report->status = compute_status(report->error_mask,
					report->warning_mask);

	return report->status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_device_token_audit_emit(
	const struct pqcp_deployment_device_token_audit_report *report)
{
	if (report == NULL ||
	    report->schema_version !=
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_SCHEMA_VERSION ||
	    !status_valid(report->status) ||
	    (report->error_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_KNOWN_MASK) != 0U ||
	    (report->warning_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_KNOWN_MASK) != 0U ||
	    report->min_capability_readiness_score > 100U ||
	    report->min_gate_score > 100U ||
	    report->max_gate_score > 100U ||
	    report->avg_gate_score > 100U ||
	    !text_present(report->nonce_hex) ||
	    !text_present(report->top_candidate_id) ||
	    !text_present(report->token_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT schema=%u status=%s errors=0x%08x warnings=0x%08x results=%u replay_pass=%u replay_fail=%u token_pass=%u token_warn=%u token_fail=%u gate_pass=%u gate_warn=%u gate_fail=%u unique_tokens=%u stable_nonce=%u stable_top=%u stable_token=%u stable_gate_status=%u min_cap_readiness=%u min_gate_score=%u max_gate_score=%u avg_gate_score=%u nonce=%s top=%s token_digest=%s\n",
	       report->schema_version,
	       pqcp_deployment_device_token_audit_status_str(report->status),
	       report->error_mask,
	       report->warning_mask,
	       report->result_count,
	       report->replay_pass_count,
	       report->replay_fail_count,
	       report->token_pass_count,
	       report->token_warn_count,
	       report->token_fail_count,
	       report->gate_pass_count,
	       report->gate_warn_count,
	       report->gate_fail_count,
	       report->unique_token_digest_count,
	       report->stable_nonce ? 1U : 0U,
	       report->stable_top_candidate ? 1U : 0U,
	       report->stable_token_digest ? 1U : 0U,
	       report->stable_gate_status ? 1U : 0U,
	       report->min_capability_readiness_score,
	       report->min_gate_score,
	       report->max_gate_score,
	       report->avg_gate_score,
	       report->nonce_hex,
	       report->top_candidate_id,
	       report->token_digest_hex);

	return report->status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL ?
		-EBADMSG : 0;
}
