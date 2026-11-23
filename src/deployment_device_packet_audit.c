/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware-native deployment device-packet replay audit aggregation.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_device_packet_audit.h>

static bool text_present(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool packet_status_valid(
	enum pqcp_deployment_device_packet_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_PACKET_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL;
}

static bool audit_status_valid(
	enum pqcp_deployment_device_packet_audit_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL;
}

static bool digest_text_valid(const char *value)
{
	if (value == NULL ||
	    strlen(value) != PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS) {
		return false;
	}

	for (size_t i = 0U;
	     i < PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS; ++i) {
		const char c = value[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}

	return true;
}

static bool nonce_text_valid(const char *value)
{
	if (value == NULL ||
	    strlen(value) != PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS) {
		return false;
	}

	for (size_t i = 0U;
	     i < PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS; ++i) {
		const char c = value[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}

	return true;
}

static bool result_schema_valid(
	const struct pqcp_deployment_device_packet_replay_result *result)
{
	return result->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_SCHEMA_VERSION &&
	       result->lines_seen != 0U &&
	       result->fact_lines != 0U &&
	       result->fact_bytes != 0U &&
	       result->marker_mask ==
		       PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_REQUIRED_MASK &&
	       result->first_error_line == 0U &&
	       result->first_error ==
		       PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONE &&
	       packet_status_valid(result->packet_status) &&
	       text_present(result->top_candidate_id) &&
	       nonce_text_valid(result->nonce_hex) &&
	       digest_text_valid(result->computed_digest_hex);
}

static bool result_scores_valid(
	const struct pqcp_deployment_device_packet_replay_result *result)
{
	return result->capability_readiness_score <= 100U &&
	       result->release_gate_score <= 100U &&
	       result->audit_gate_score <= 100U;
}

static bool result_has_required_capability(
	const struct pqcp_deployment_device_packet_replay_result *result)
{
	const uint32_t required_caps =
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET_REPLAY;

	return (result->evidence_capabilities & required_caps) == required_caps;
}

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0x5a7ef00d13dca55eULL;
	digest[1] = 0xc2b2ae3d27d4eb4fULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0x165667b19e3779f9ULL;
}

static uint64_t rotl64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= (uint64_t)value + 0x100000001b3ULL;
	digest[0] *= 0x100000001b3ULL;
	digest[1] += digest[0] ^ ((uint64_t)value << 5U);
	digest[1] = rotl64(digest[1], 17U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + digest[0] + 0xd6e8feb86659fd93ULL;
	digest[2] = rotl64(digest[2], 31U);
	digest[3] += digest[2] ^ (digest[1] >> 13U);
	digest[3] = rotl64(digest[3], 43U);
}

static void digest_update_text(uint64_t digest[4], const char *value)
{
	if (value == NULL) {
		value = "";
	}
	for (const char *p = value; *p != '\0'; ++p) {
		digest_update_byte(digest, (uint8_t)*p);
	}
	digest_update_byte(digest, (uint8_t)'|');
}

static void digest_update_u32(uint64_t digest[4], uint32_t value)
{
	for (uint32_t shift = 0U; shift < 32U; shift += 8U) {
		digest_update_byte(digest, (uint8_t)(value >> shift));
	}
}

static void digest_result(
	uint64_t digest[4],
	const struct pqcp_deployment_device_packet_replay_result *result)
{
	digest_update_u32(digest, result->schema_version);
	digest_update_u32(digest, result->lines_seen);
	digest_update_u32(digest, result->marker_mask);
	digest_update_u32(digest, result->fact_lines);
	digest_update_u32(digest, result->fact_bytes);
	digest_update_u32(digest, result->evidence_capabilities);
	digest_update_u32(digest, result->capability_readiness_score);
	digest_update_u32(digest, result->release_gate_score);
	digest_update_u32(digest, result->audit_gate_score);
	digest_update_u32(digest, (uint32_t)result->packet_status);
	digest_update_u32(digest, result->passed ? 1U : 0U);
	digest_update_text(digest, result->top_candidate_id);
	digest_update_text(digest, result->nonce_hex);
	digest_update_text(digest, result->computed_digest_hex);
}

static void digest_to_hex(
	const uint64_t digest[4],
	char out[PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(
		out,
		PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_DIGEST_HEX_CHARS + 1U,
		"%016llx%016llx%016llx%016llx",
		(unsigned long long)digest[0],
		(unsigned long long)digest[1],
		(unsigned long long)digest[2],
		(unsigned long long)digest[3]);
}

const char *pqcp_deployment_device_packet_audit_status_str(
	enum pqcp_deployment_device_packet_audit_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

int pqcp_deployment_device_packet_audit_default_policy(
	struct pqcp_deployment_device_packet_audit_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->minimum_results = 1U;
	policy->capability_score_warn_floor = 70U;
	policy->release_score_warn_floor = 60U;
	policy->audit_score_warn_floor = 60U;
	policy->require_replay_pass = true;
	policy->require_packet_pass = false;
	policy->require_stable_top = true;
	policy->require_stable_nonce = true;
	policy->require_stable_digest = true;
	policy->require_stable_capabilities = true;
	policy->require_stable_packet_status = false;
	policy->require_replay_capability = true;

	return 0;
}

static bool policy_valid(
	const struct pqcp_deployment_device_packet_audit_policy *policy)
{
	return policy != NULL &&
	       policy->minimum_results <=
		       PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_MAX_RESULTS &&
	       policy->capability_score_warn_floor <= 100U &&
	       policy->release_score_warn_floor <= 100U &&
	       policy->audit_score_warn_floor <= 100U;
}

static enum pqcp_deployment_device_packet_audit_status compute_status(
	uint32_t errors,
	uint32_t warnings)
{
	if (errors != 0U) {
		return PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL;
	}
	if (warnings != 0U) {
		return PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN;
	}

	return PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS;
}

static void copy_representative(
	struct pqcp_deployment_device_packet_audit_report *report,
	const struct pqcp_deployment_device_packet_replay_result *result)
{
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s",
		       result->top_candidate_id);
	(void)snprintk(report->nonce_hex, sizeof(report->nonce_hex), "%s",
		       result->nonce_hex);
	(void)snprintk(report->packet_digest_hex,
		       sizeof(report->packet_digest_hex), "%s",
		       result->computed_digest_hex);
}

static void report_invalid(
	struct pqcp_deployment_device_packet_audit_report *report,
	uint32_t error_mask)
{
	if (report == NULL) {
		return;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_SCHEMA_VERSION;
	report->status = PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL;
	report->error_mask = error_mask;
	report->min_capability_readiness_score = 100U;
	report->min_release_gate_score = 100U;
	report->min_audit_gate_score = 100U;
	report->stable_top_candidate = true;
	report->stable_nonce = true;
	report->stable_packet_digest = true;
	report->stable_capabilities = true;
	report->stable_packet_status = true;
	report->evidence_capabilities_all = UINT32_MAX;
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s", "none");
	(void)snprintk(report->nonce_hex, sizeof(report->nonce_hex), "%s",
		       "00000000000000000000000000000000");
	(void)snprintk(report->packet_digest_hex,
		       sizeof(report->packet_digest_hex), "%s",
		       "0000000000000000000000000000000000000000000000000000000000000000");
	(void)snprintk(report->audit_digest_hex,
		       sizeof(report->audit_digest_hex), "%s",
		       "0000000000000000000000000000000000000000000000000000000000000000");
}

static uint32_t count_unique_packet_digests(
	const struct pqcp_deployment_device_packet_replay_result *results,
	size_t count)
{
	uint32_t unique = 0U;

	for (size_t i = 0U; i < count; ++i) {
		bool seen = false;

		if (!digest_text_valid(results[i].computed_digest_hex)) {
			continue;
		}
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

static void accumulate_replay_counts(
	struct pqcp_deployment_device_packet_audit_report *report,
	const struct pqcp_deployment_device_packet_replay_result *result)
{
	if (result->passed) {
		report->replay_pass_count++;
	} else {
		report->replay_fail_count++;
	}

	switch (result->packet_status) {
	case PQCP_DEPLOYMENT_DEVICE_PACKET_PASS:
		report->packet_pass_count++;
		break;
	case PQCP_DEPLOYMENT_DEVICE_PACKET_WARN:
		report->packet_warn_count++;
		break;
	case PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL:
	default:
		report->packet_fail_count++;
		break;
	}
}

static void accumulate_scores(
	struct pqcp_deployment_device_packet_audit_report *report,
	const struct pqcp_deployment_device_packet_replay_result *result,
	uint32_t *release_score_sum,
	uint32_t *audit_score_sum)
{
	if (result->capability_readiness_score <
	    report->min_capability_readiness_score) {
		report->min_capability_readiness_score =
			result->capability_readiness_score;
	}
	if (result->release_gate_score < report->min_release_gate_score) {
		report->min_release_gate_score = result->release_gate_score;
	}
	if (result->release_gate_score > report->max_release_gate_score) {
		report->max_release_gate_score = result->release_gate_score;
	}
	if (result->audit_gate_score < report->min_audit_gate_score) {
		report->min_audit_gate_score = result->audit_gate_score;
	}
	if (result->audit_gate_score > report->max_audit_gate_score) {
		report->max_audit_gate_score = result->audit_gate_score;
	}

	*release_score_sum += result->release_gate_score;
	*audit_score_sum += result->audit_gate_score;
}

static void accumulate_capabilities(
	struct pqcp_deployment_device_packet_audit_report *report,
	const struct pqcp_deployment_device_packet_replay_result *result)
{
	report->evidence_capabilities_all &= result->evidence_capabilities;
	report->evidence_capabilities_any |= result->evidence_capabilities;
}

static void accumulate_stability(
	struct pqcp_deployment_device_packet_audit_report *report,
	const struct pqcp_deployment_device_packet_replay_result *first,
	const struct pqcp_deployment_device_packet_replay_result *current)
{
	if (strcmp(first->top_candidate_id, current->top_candidate_id) != 0) {
		report->stable_top_candidate = false;
	}
	if (strcmp(first->nonce_hex, current->nonce_hex) != 0) {
		report->stable_nonce = false;
	}
	if (strcmp(first->computed_digest_hex,
		   current->computed_digest_hex) != 0) {
		report->stable_packet_digest = false;
	}
	if (first->evidence_capabilities != current->evidence_capabilities) {
		report->stable_capabilities = false;
	}
	if (first->packet_status != current->packet_status) {
		report->stable_packet_status = false;
	}
}

static void apply_policy(
	struct pqcp_deployment_device_packet_audit_report *report,
	const struct pqcp_deployment_device_packet_audit_policy *policy)
{
	const uint32_t required_caps =
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET_REPLAY;

	if (report->result_count < policy->minimum_results) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_SAMPLE_COUNT;
	}
	if (policy->require_replay_pass && report->replay_fail_count != 0U) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_REPLAY_FAILED;
	}
	if (policy->require_packet_pass &&
	    report->packet_pass_count != report->result_count) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_PACKET_STATUS;
	} else if (report->packet_warn_count != 0U ||
		   report->packet_fail_count != 0U) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_PACKET_NOT_PASS;
	}
	if (!report->stable_top_candidate && policy->require_stable_top) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_TOP_DRIFT;
	}
	if (!report->stable_nonce && policy->require_stable_nonce) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_NONCE_DRIFT;
	}
	if (!report->stable_packet_digest) {
		if (policy->require_stable_digest) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_DIGEST_DRIFT;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_DIGEST_DIVERSITY;
		}
	}
	if (!report->stable_capabilities) {
		if (policy->require_stable_capabilities) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_CAPABILITY_DRIFT;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_CAPABILITY_DIVERSITY;
		}
	}
	if (!report->stable_packet_status &&
	    policy->require_stable_packet_status) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_STATUS_DRIFT;
	}
	if (policy->require_replay_capability &&
	    (report->evidence_capabilities_all & required_caps) !=
		    required_caps) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_MISSING_CAPABILITY;
	}
	if (report->min_capability_readiness_score <
	    policy->capability_score_warn_floor) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_CAPABILITY_SCORE;
	}
	if (report->min_release_gate_score <
	    policy->release_score_warn_floor) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_RELEASE_SCORE;
	}
	if (report->min_audit_gate_score < policy->audit_score_warn_floor) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_LOW_AUDIT_SCORE;
	}
}

int pqcp_deployment_device_packet_audit_run(
	const struct pqcp_deployment_device_packet_replay_result *results,
	size_t result_count,
	const struct pqcp_deployment_device_packet_audit_policy *policy,
	struct pqcp_deployment_device_packet_audit_report *report)
{
	uint32_t release_score_sum = 0U;
	uint32_t audit_score_sum = 0U;
	uint64_t digest[4];

	if (report == NULL) {
		return -EINVAL;
	}
	if (!policy_valid(policy) || results == NULL ||
	    result_count > PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_MAX_RESULTS) {
		report_invalid(report,
			       PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if (result_count == 0U) {
		report_invalid(report,
			       PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_NO_RESULTS);
		return -EINVAL;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_SCHEMA_VERSION;
	report->result_count = (uint32_t)result_count;
	report->min_capability_readiness_score = 100U;
	report->min_release_gate_score = 100U;
	report->min_audit_gate_score = 100U;
	report->evidence_capabilities_all = UINT32_MAX;
	report->stable_top_candidate = true;
	report->stable_nonce = true;
	report->stable_packet_digest = true;
	report->stable_capabilities = true;
	report->stable_packet_status = true;
	copy_representative(report, &results[0]);
	digest_init(digest);

	for (size_t i = 0U; i < result_count; ++i) {
		if (!result_schema_valid(&results[i])) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_MALFORMED_RESULT;
			continue;
		}
		if (!result_scores_valid(&results[i])) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_SCORE_RANGE;
			continue;
		}
		if (!result_has_required_capability(&results[i])) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_MISSING_CAPABILITY;
		}

		accumulate_replay_counts(report, &results[i]);
		accumulate_scores(report, &results[i], &release_score_sum,
				  &audit_score_sum);
		accumulate_capabilities(report, &results[i]);
		accumulate_stability(report, &results[0], &results[i]);
		digest_result(digest, &results[i]);
	}

	report->unique_packet_digest_count =
		count_unique_packet_digests(results, result_count);
	report->avg_release_gate_score = report->result_count != 0U ?
		release_score_sum / report->result_count : 0U;
	report->avg_audit_gate_score = report->result_count != 0U ?
		audit_score_sum / report->result_count : 0U;
	digest_to_hex(digest, report->audit_digest_hex);

	apply_policy(report, policy);
	report->status = compute_status(report->error_mask,
					report->warning_mask);

	return report->status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_device_packet_audit_emit(
	const struct pqcp_deployment_device_packet_audit_report *report)
{
	if (report == NULL ||
	    report->schema_version !=
		    PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_SCHEMA_VERSION ||
	    !audit_status_valid(report->status) ||
	    (report->error_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_ERROR_KNOWN_MASK) != 0U ||
	    (report->warning_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARNING_KNOWN_MASK) != 0U ||
	    report->min_capability_readiness_score > 100U ||
	    report->min_release_gate_score > 100U ||
	    report->max_release_gate_score > 100U ||
	    report->avg_release_gate_score > 100U ||
	    report->min_audit_gate_score > 100U ||
	    report->max_audit_gate_score > 100U ||
	    report->avg_audit_gate_score > 100U ||
	    !text_present(report->top_candidate_id) ||
	    !nonce_text_valid(report->nonce_hex) ||
	    !digest_text_valid(report->packet_digest_hex) ||
	    !digest_text_valid(report->audit_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT schema=%u status=%s errors=0x%08x warnings=0x%08x results=%u replay_pass=%u replay_fail=%u packet_pass=%u packet_warn=%u packet_fail=%u unique_packets=%u stable_top=%u stable_nonce=%u stable_digest=%u stable_caps=%u stable_status=%u evidence_all=0x%08x evidence_any=0x%08x min_cap_readiness=%u min_release_score=%u max_release_score=%u avg_release_score=%u min_audit_score=%u max_audit_score=%u avg_audit_score=%u top=%s nonce=%s packet_digest=%s audit_digest=%s\n",
	       report->schema_version,
	       pqcp_deployment_device_packet_audit_status_str(report->status),
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
	       report->stable_nonce ? 1U : 0U,
	       report->stable_packet_digest ? 1U : 0U,
	       report->stable_capabilities ? 1U : 0U,
	       report->stable_packet_status ? 1U : 0U,
	       report->evidence_capabilities_all,
	       report->evidence_capabilities_any,
	       report->min_capability_readiness_score,
	       report->min_release_gate_score,
	       report->max_release_gate_score,
	       report->avg_release_gate_score,
	       report->min_audit_gate_score,
	       report->max_audit_gate_score,
	       report->avg_audit_gate_score,
	       report->top_candidate_id,
	       report->nonce_hex,
	       report->packet_digest_hex,
	       report->audit_digest_hex);

	return report->status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL ?
		-EBADMSG : 0;
}
