/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native deployment review audit aggregation.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_review_audit.h>

static bool text_present(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool result_schema_valid(
	const struct pqcp_deployment_review_verifier_result *result)
{
	return result->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION &&
	       result->lines_seen != 0U &&
	       result->readiness_score <= 100U &&
	       result->claim_score <= 100U &&
	       result->review_score <= 100U &&
	       text_present(result->top_candidate_id) &&
	       text_present(result->trace_digest_hex) &&
	       text_present(result->computed_digest_hex);
}

static bool status_valid(enum pqcp_deployment_review_audit_status status)
{
	return status == PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL;
}

const char *pqcp_deployment_review_audit_status_str(
	enum pqcp_deployment_review_audit_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

int pqcp_deployment_review_audit_default_policy(
	struct pqcp_deployment_review_audit_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->minimum_results = 1U;
	policy->review_score_warn_floor = 70U;
	policy->claim_score_warn_floor = 70U;
	policy->require_replay_pass = true;
	policy->require_packet_pass = false;
	policy->require_stable_top = true;
	policy->require_stable_trace_digest = true;
	policy->require_stable_packet_digest = false;

	return 0;
}

static bool policy_valid(
	const struct pqcp_deployment_review_audit_policy *policy)
{
	return policy != NULL &&
	       policy->minimum_results <=
		       PQCP_DEPLOYMENT_REVIEW_AUDIT_MAX_RESULTS &&
	       policy->review_score_warn_floor <= 100U &&
	       policy->claim_score_warn_floor <= 100U;
}

static enum pqcp_deployment_review_audit_status compute_status(
	uint32_t errors,
	uint32_t warnings)
{
	if (errors != 0U) {
		return PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL;
	}
	if (warnings != 0U) {
		return PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN;
	}

	return PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS;
}

static void report_invalid(struct pqcp_deployment_review_audit_report *report,
			   uint32_t error_mask)
{
	if (report == NULL) {
		return;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_DEPLOYMENT_REVIEW_AUDIT_SCHEMA_VERSION;
	report->status = PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL;
	report->error_mask = error_mask;
	report->min_readiness_score = 100U;
	report->min_claim_score = 100U;
	report->min_review_score = 100U;
	report->stable_top_candidate = true;
	report->stable_trace_digest = true;
	report->stable_packet_digest = true;
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s", "none");
}

static uint32_t count_unique_packet_digests(
	const struct pqcp_deployment_review_verifier_result *results,
	size_t count)
{
	uint32_t unique = 0U;

	for (size_t i = 0U; i < count; ++i) {
		bool seen = false;

		for (size_t j = 0U; j < i; ++j) {
			if (strcmp(results[i].computed_digest_hex,
				   results[j].computed_digest_hex) == 0) {
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
	struct pqcp_deployment_review_audit_report *report,
	const struct pqcp_deployment_review_verifier_result *result)
{
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s",
		       result->top_candidate_id);
	(void)snprintk(report->trace_digest_hex,
		       sizeof(report->trace_digest_hex), "%s",
		       result->trace_digest_hex);
	(void)snprintk(report->packet_digest_hex,
		       sizeof(report->packet_digest_hex), "%s",
		       result->computed_digest_hex);
}

static void accumulate_status_counts(
	struct pqcp_deployment_review_audit_report *report,
	const struct pqcp_deployment_review_verifier_result *result)
{
	if (result->passed) {
		report->replay_pass_count++;
	} else {
		report->replay_fail_count++;
	}

	switch (result->packet_status) {
	case PQCP_DEPLOYMENT_REVIEW_PACKET_PASS:
		report->packet_pass_count++;
		break;
	case PQCP_DEPLOYMENT_REVIEW_PACKET_WARN:
		report->packet_warn_count++;
		break;
	case PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL:
	default:
		report->packet_fail_count++;
		break;
	}
}

static void accumulate_scores(
	struct pqcp_deployment_review_audit_report *report,
	const struct pqcp_deployment_review_verifier_result *result,
	uint32_t *review_score_sum)
{
	if (result->readiness_score < report->min_readiness_score) {
		report->min_readiness_score = result->readiness_score;
	}
	if (result->claim_score < report->min_claim_score) {
		report->min_claim_score = result->claim_score;
	}
	if (result->review_score < report->min_review_score) {
		report->min_review_score = result->review_score;
	}
	if (result->review_score > report->max_review_score) {
		report->max_review_score = result->review_score;
	}
	*review_score_sum += result->review_score;
}

static void accumulate_stability(
	struct pqcp_deployment_review_audit_report *report,
	const struct pqcp_deployment_review_verifier_result *first,
	const struct pqcp_deployment_review_verifier_result *current)
{
	if (strcmp(first->top_candidate_id, current->top_candidate_id) != 0) {
		report->stable_top_candidate = false;
	}
	if (strcmp(first->trace_digest_hex, current->trace_digest_hex) != 0) {
		report->stable_trace_digest = false;
	}
	if (strcmp(first->computed_digest_hex,
		   current->computed_digest_hex) != 0) {
		report->stable_packet_digest = false;
	}
}

static void apply_policy(
	struct pqcp_deployment_review_audit_report *report,
	const struct pqcp_deployment_review_audit_policy *policy)
{
	if (report->result_count < policy->minimum_results) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_SAMPLE_COUNT;
	}
	if (policy->require_replay_pass && report->replay_fail_count != 0U) {
		report->error_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_REPLAY_FAILED;
	}
	if (policy->require_packet_pass &&
	    (report->packet_warn_count != 0U ||
	     report->packet_fail_count != 0U)) {
		report->error_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_PACKET_STATUS;
	} else if (!policy->require_packet_pass &&
		   (report->packet_warn_count != 0U ||
		    report->packet_fail_count != 0U)) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_NOT_PASS;
	}
	if (policy->require_stable_top &&
	    !report->stable_top_candidate) {
		report->error_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_TOP_DRIFT;
	}
	if (policy->require_stable_trace_digest &&
	    !report->stable_trace_digest) {
		report->error_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_TRACE_DIGEST_DRIFT;
	}
	if (policy->require_stable_packet_digest &&
	    !report->stable_packet_digest) {
		report->error_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_PACKET_DIGEST_DRIFT;
	} else if (!policy->require_stable_packet_digest &&
		   !report->stable_packet_digest) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_PACKET_DIVERSITY;
	}
	if (report->min_review_score < policy->review_score_warn_floor) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_REVIEW_SCORE;
	}
	if (report->min_claim_score < policy->claim_score_warn_floor) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_LOW_CLAIM_SCORE;
	}
}

int pqcp_deployment_review_audit_run(
	const struct pqcp_deployment_review_verifier_result *results,
	size_t result_count,
	const struct pqcp_deployment_review_audit_policy *policy,
	struct pqcp_deployment_review_audit_report *report)
{
	uint32_t review_score_sum = 0U;

	if (report == NULL) {
		return -EINVAL;
	}
	if (results == NULL || !policy_valid(policy) ||
	    result_count > PQCP_DEPLOYMENT_REVIEW_AUDIT_MAX_RESULTS) {
		report_invalid(report,
			       PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if (result_count == 0U) {
		report_invalid(report,
			       PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_NO_RESULTS);
		return -ENODATA;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_DEPLOYMENT_REVIEW_AUDIT_SCHEMA_VERSION;
	report->result_count = (uint32_t)result_count;
	report->min_readiness_score = 100U;
	report->min_claim_score = 100U;
	report->min_review_score = 100U;
	report->stable_top_candidate = true;
	report->stable_trace_digest = true;
	report->stable_packet_digest = true;
	copy_representative(report, &results[0]);

	for (size_t i = 0U; i < result_count; ++i) {
		const struct pqcp_deployment_review_verifier_result *result =
			&results[i];

		if (!result_schema_valid(result)) {
			report->error_mask |=
				PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_SCORE_RANGE;
			continue;
		}
		accumulate_status_counts(report, result);
		accumulate_scores(report, result, &review_score_sum);
		accumulate_stability(report, &results[0], result);
	}

	report->unique_packet_digest_count =
		count_unique_packet_digests(results, result_count);
	report->avg_review_score = review_score_sum / (uint32_t)result_count;
	apply_policy(report, policy);
	report->status = compute_status(report->error_mask,
					report->warning_mask);

	return report->status == PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL ?
		-EBADMSG : 0;
}

static bool report_valid(
	const struct pqcp_deployment_review_audit_report *report)
{
	return report != NULL &&
	       report->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_AUDIT_SCHEMA_VERSION &&
	       status_valid(report->status) &&
	       report->result_count != 0U &&
	       report->replay_pass_count + report->replay_fail_count ==
		       report->result_count &&
	       report->packet_pass_count + report->packet_warn_count +
			       report->packet_fail_count ==
		       report->result_count &&
	       report->unique_packet_digest_count != 0U &&
	       report->unique_packet_digest_count <= report->result_count &&
	       report->min_readiness_score <= 100U &&
	       report->min_claim_score <= 100U &&
	       report->min_review_score <= 100U &&
	       report->max_review_score <= 100U &&
	       report->avg_review_score <= 100U &&
	       text_present(report->top_candidate_id) &&
	       text_present(report->trace_digest_hex) &&
	       text_present(report->packet_digest_hex) &&
	       (report->error_mask &
		~PQCP_DEPLOYMENT_REVIEW_AUDIT_ERROR_KNOWN_MASK) == 0U &&
	       (report->warning_mask &
		~PQCP_DEPLOYMENT_REVIEW_AUDIT_WARNING_KNOWN_MASK) == 0U;
}

int pqcp_deployment_review_audit_emit(
	const struct pqcp_deployment_review_audit_report *report)
{
	if (!report_valid(report)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_REVIEW_AUDIT schema=%u status=%s errors=0x%08x warnings=0x%08x results=%u replay_pass=%u replay_fail=%u packet_pass=%u packet_warn=%u packet_fail=%u unique_packets=%u stable_top=%u stable_trace=%u stable_packet=%u min_readiness=%u min_claim=%u min_review=%u max_review=%u avg_review=%u top=%s trace_digest=%s packet_digest=%s\n",
	       report->schema_version,
	       pqcp_deployment_review_audit_status_str(report->status),
	       report->error_mask,
	       report->warning_mask,
	       report->result_count,
	       report->replay_pass_count,
	       report->replay_fail_count,
	       report->packet_pass_count,
	       report->packet_warn_count,
	       report->packet_fail_count,
	       report->unique_packet_digest_count,
	       report->stable_top_candidate ? 1U : 0U,
	       report->stable_trace_digest ? 1U : 0U,
	       report->stable_packet_digest ? 1U : 0U,
	       report->min_readiness_score,
	       report->min_claim_score,
	       report->min_review_score,
	       report->max_review_score,
	       report->avg_review_score,
	       report->top_candidate_id,
	       report->trace_digest_hex,
	       report->packet_digest_hex);

	return report->status == PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL ?
		-EBADMSG : 0;
}
