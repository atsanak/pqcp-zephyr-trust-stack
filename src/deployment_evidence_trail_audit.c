/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deployment evidence trail replay audit aggregation.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_trail_audit.h>

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

static bool trail_status_valid(
	enum pqcp_deployment_evidence_trail_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL;
}

static bool audit_status_valid(
	enum pqcp_deployment_evidence_trail_audit_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_FAIL;
}

static bool is_lower_hex_len(const char *value, size_t expected_len)
{
	if (value == NULL || strlen(value) != expected_len) {
		return false;
	}
	for (size_t i = 0U; i < expected_len; ++i) {
		const char c = value[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}

	return true;
}

static bool nonce_valid(const char *value)
{
	return is_lower_hex_len(value,
				PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS);
}

static bool digest_valid(const char *value)
{
	return is_lower_hex_len(
		value, PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS);
}

static void set_text(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0U) {
		return;
	}
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
}

static void set_zero_digest(char *dst, size_t dst_size)
{
	set_text(dst, dst_size,
		 "0000000000000000000000000000000000000000000000000000000000000000");
}

static void set_zero_nonce(char *dst, size_t dst_size)
{
	set_text(dst, dst_size, "00000000000000000000000000000000");
}

/* ------------------------------------------------------------------ */
/* Audit digest                                                        */
/* ------------------------------------------------------------------ */

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0x2c1b3c6dc45e9ba7ULL;
	digest[1] = 0x90fb1721ce6d8a35ULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0xbb67ae8584caa73bULL;
}

static uint64_t rotl64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= (uint64_t)value + 0x100000001b3ULL;
	digest[0] *= 0x100000001b3ULL;
	digest[1] += digest[0] ^ ((uint64_t)value << 9U);
	digest[1] = rotl64(digest[1], 21U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + digest[0] + 0x94d049bb133111ebULL;
	digest[2] = rotl64(digest[2], 33U);
	digest[3] += digest[2] ^ (digest[1] >> 15U);
	digest[3] = rotl64(digest[3], 45U);
}

static void digest_update_u32(uint64_t digest[4], uint32_t value)
{
	for (uint32_t shift = 0U; shift < 32U; shift += 8U) {
		digest_update_byte(digest, (uint8_t)(value >> shift));
	}
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

static void digest_update_bool(uint64_t digest[4], bool value)
{
	digest_update_u32(digest, value ? 1U : 0U);
}

static void digest_to_hex(
	const uint64_t digest[4],
	char out[PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(
		out,
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_DIGEST_HEX_CHARS + 1U,
		"%016llx%016llx%016llx%016llx",
		(unsigned long long)digest[0],
		(unsigned long long)digest[1],
		(unsigned long long)digest[2],
		(unsigned long long)digest[3]);
}

static void compute_audit_digest(
	struct pqcp_deployment_evidence_trail_audit_report *report)
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest, report->schema_version);
	digest_update_u32(digest, (uint32_t)report->status);
	digest_update_u32(digest, report->error_mask);
	digest_update_u32(digest, report->warning_mask);
	digest_update_u32(digest, (uint32_t)report->profile);
	digest_update_u32(digest, report->result_count);
	digest_update_u32(digest, report->replay_pass_count);
	digest_update_u32(digest, report->replay_fail_count);
	digest_update_u32(digest, report->trail_pass_count);
	digest_update_u32(digest, report->trail_warn_count);
	digest_update_u32(digest, report->trail_fail_count);
	digest_update_u32(digest, report->entry_count);
	digest_update_u32(digest, report->observed_stage_mask);
	digest_update_bool(digest, report->stable_head_digest);
	digest_update_bool(digest, report->stable_entry_count);
	digest_update_bool(digest, report->stable_stages);
	digest_update_bool(digest, report->stable_profile);
	digest_update_bool(digest, report->stable_top_candidate);
	digest_update_bool(digest, report->stable_nonce);
	digest_update_text(digest, report->top_candidate_id);
	digest_update_text(digest, report->nonce_hex);
	digest_update_text(digest, report->head_digest_hex);
	digest_to_hex(digest, report->audit_digest_hex);
}

static void audit_invalid(
	struct pqcp_deployment_evidence_trail_audit_report *report,
	uint32_t error_mask)
{
	if (report == NULL) {
		return;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_SCHEMA_VERSION;
	report->status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_FAIL;
	report->error_mask = error_mask;
	report->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	set_text(report->top_candidate_id, sizeof(report->top_candidate_id),
		 "none");
	set_zero_nonce(report->nonce_hex, sizeof(report->nonce_hex));
	set_zero_digest(report->head_digest_hex,
			sizeof(report->head_digest_hex));
	compute_audit_digest(report);
}

static bool result_shape_valid(
	const struct pqcp_deployment_evidence_trail_replay_result *result)
{
	return result->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_SCHEMA_VERSION &&
	       trail_status_valid(result->trail_status) &&
	       profile_valid(result->profile) &&
	       result->entry_count <=
		       PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES &&
	       text_present(result->top_candidate_id) &&
	       nonce_valid(result->nonce_hex) &&
	       digest_valid(result->computed_head_digest_hex);
}

const char *pqcp_deployment_evidence_trail_audit_status_str(
	enum pqcp_deployment_evidence_trail_audit_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

int pqcp_deployment_evidence_trail_audit_default_policy(
	struct pqcp_deployment_evidence_trail_audit_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->minimum_results = 1U;
	policy->require_replay_pass = true;
	policy->require_stable_head = true;
	policy->require_stable_count = true;
	policy->require_stable_stages = true;
	policy->require_stable_profile = true;
	policy->require_stable_top = true;
	policy->require_stable_nonce = true;

	return 0;
}

int pqcp_deployment_evidence_trail_audit_run(
	const struct pqcp_deployment_evidence_trail_replay_result *results,
	size_t result_count,
	const struct pqcp_deployment_evidence_trail_audit_policy *policy,
	struct pqcp_deployment_evidence_trail_audit_report *report)
{
	if (report == NULL) {
		return -EINVAL;
	}
	if (results == NULL || policy == NULL ||
	    result_count >
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_MAX_RESULTS) {
		audit_invalid(report,
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if (result_count == 0U) {
		audit_invalid(report,
			      PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_NO_RESULTS);
		return -EINVAL;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_SCHEMA_VERSION;
	report->result_count = (uint32_t)result_count;
	report->stable_head_digest = true;
	report->stable_entry_count = true;
	report->stable_stages = true;
	report->stable_profile = true;
	report->stable_top_candidate = true;
	report->stable_nonce = true;
	report->profile = results[0].profile;
	report->entry_count = results[0].entry_count;
	report->observed_stage_mask = results[0].observed_stage_mask;
	set_text(report->top_candidate_id, sizeof(report->top_candidate_id),
		 results[0].top_candidate_id);
	set_text(report->nonce_hex, sizeof(report->nonce_hex),
		 results[0].nonce_hex);
	set_text(report->head_digest_hex, sizeof(report->head_digest_hex),
		 results[0].computed_head_digest_hex);

	for (size_t i = 0U; i < result_count; ++i) {
		const struct pqcp_deployment_evidence_trail_replay_result
			*result = &results[i];

		if (!result_shape_valid(result)) {
			report->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_MALFORMED_RESULT;
			continue;
		}

		if (result->passed) {
			report->replay_pass_count++;
		} else {
			report->replay_fail_count++;
			if (policy->require_replay_pass) {
				report->error_mask |=
					PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_REPLAY_FAILED;
			}
		}

		switch (result->trail_status) {
		case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS:
			report->trail_pass_count++;
			break;
		case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN:
			report->trail_warn_count++;
			break;
		case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL:
		default:
			report->trail_fail_count++;
			break;
		}

		if (policy->require_trail_pass &&
		    result->trail_status !=
			    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS) {
			report->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_TRAIL_STATUS;
		}

		if (strcmp(result->computed_head_digest_hex,
			   report->head_digest_hex) != 0) {
			report->stable_head_digest = false;
		}
		if (result->entry_count != report->entry_count) {
			report->stable_entry_count = false;
		}
		if (result->observed_stage_mask !=
		    report->observed_stage_mask) {
			report->stable_stages = false;
		}
		if (result->profile != report->profile) {
			report->stable_profile = false;
		}
		if (strcmp(result->top_candidate_id,
			   report->top_candidate_id) != 0) {
			report->stable_top_candidate = false;
		}
		if (strcmp(result->nonce_hex, report->nonce_hex) != 0) {
			report->stable_nonce = false;
		}
	}

	if (!report->stable_head_digest && policy->require_stable_head) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_HEAD_DRIFT;
	}
	if (!report->stable_entry_count && policy->require_stable_count) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_COUNT_DRIFT;
	}
	if (!report->stable_stages && policy->require_stable_stages) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_STAGE_DRIFT;
	}
	if (!report->stable_profile && policy->require_stable_profile) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_PROFILE_DRIFT;
	}
	if (!report->stable_top_candidate && policy->require_stable_top) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_TOP_DRIFT;
	}
	if (!report->stable_nonce && policy->require_stable_nonce) {
		report->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_NONCE_DRIFT;
	}

	if (report->result_count < policy->minimum_results) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARNING_LOW_SAMPLE_COUNT;
	}
	if (!policy->require_trail_pass &&
	    report->trail_pass_count != report->result_count) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARNING_TRAIL_NOT_PASS;
	}

	if (!report->stable_top_candidate) {
		set_text(report->top_candidate_id,
			 sizeof(report->top_candidate_id), "none");
	}
	if (!report->stable_nonce) {
		set_zero_nonce(report->nonce_hex, sizeof(report->nonce_hex));
	}
	if (!report->stable_head_digest) {
		set_zero_digest(report->head_digest_hex,
				sizeof(report->head_digest_hex));
	}

	if (report->error_mask != 0U) {
		report->status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_FAIL;
	} else if (report->warning_mask != 0U) {
		report->status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARN;
	} else {
		report->status = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_PASS;
	}

	compute_audit_digest(report);

	return report->status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_evidence_trail_audit_emit(
	const struct pqcp_deployment_evidence_trail_audit_report *report)
{
	if (report == NULL ||
	    report->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_SCHEMA_VERSION ||
	    !audit_status_valid(report->status) ||
	    !profile_valid(report->profile) ||
	    (report->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_ERROR_KNOWN_MASK) != 0U ||
	    (report->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_WARNING_KNOWN_MASK) !=
		    0U ||
	    report->entry_count >
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES ||
	    (report->observed_stage_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_KNOWN_MASK) != 0U ||
	    !text_present(report->top_candidate_id) ||
	    !nonce_valid(report->nonce_hex) ||
	    !digest_valid(report->head_digest_hex) ||
	    !is_lower_hex_len(
		    report->audit_digest_hex,
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_DIGEST_HEX_CHARS)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x results=%u replay_pass=%u replay_fail=%u trail_pass=%u trail_warn=%u trail_fail=%u entries=%u observed_stages=0x%02x stable_head=%u stable_count=%u stable_stages=%u stable_profile=%u stable_top=%u stable_nonce=%u top=%s nonce=%s head_digest=%s audit_digest=%s\n",
	       report->schema_version,
	       pqcp_deployment_release_gate_profile_str(report->profile),
	       pqcp_deployment_evidence_trail_audit_status_str(
		       report->status),
	       report->error_mask,
	       report->warning_mask,
	       report->result_count,
	       report->replay_pass_count,
	       report->replay_fail_count,
	       report->trail_pass_count,
	       report->trail_warn_count,
	       report->trail_fail_count,
	       report->entry_count,
	       report->observed_stage_mask,
	       report->stable_head_digest ? 1U : 0U,
	       report->stable_entry_count ? 1U : 0U,
	       report->stable_stages ? 1U : 0U,
	       report->stable_profile ? 1U : 0U,
	       report->stable_top_candidate ? 1U : 0U,
	       report->stable_nonce ? 1U : 0U,
	       report->top_candidate_id,
	       report->nonce_hex,
	       report->head_digest_hex,
	       report->audit_digest_hex);

	return report->status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT_FAIL ?
		-EBADMSG : 0;
}
