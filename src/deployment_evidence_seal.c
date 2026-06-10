/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native terminal deployment evidence seal.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_seal.h>

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

static bool seal_status_valid(enum pqcp_deployment_evidence_seal_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL;
}

static bool verdict_status_valid(
	enum pqcp_deployment_evidence_verdict_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL;
}

static bool audit_status_valid(
	enum pqcp_deployment_evidence_verdict_audit_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_FAIL;
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
		value, PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS);
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

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0x8c5fb1e94d2a7c63ULL;
	digest[1] = 0x27220a95fe4d1ce1ULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0xd6e8feb86659fd93ULL;
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
	char out[PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(
		out,
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U,
		"%016llx%016llx%016llx%016llx",
		(unsigned long long)digest[0],
		(unsigned long long)digest[1],
		(unsigned long long)digest[2],
		(unsigned long long)digest[3]);
}

static void compute_seal_digest(struct pqcp_deployment_evidence_seal *seal)
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest, seal->schema_version);
	digest_update_u32(digest, (uint32_t)seal->status);
	digest_update_u32(digest, seal->error_mask);
	digest_update_u32(digest, seal->warning_mask);
	digest_update_u32(digest, (uint32_t)seal->profile);
	digest_update_u32(digest, seal->seal_score);
	digest_update_u32(digest, seal->min_terminal_score);
	digest_update_u32(digest, (uint32_t)seal->verdict_status);
	digest_update_u32(digest, (uint32_t)seal->audit_status);
	digest_update_u32(digest, seal->audited_result_count);
	digest_update_u32(digest, seal->chain_stage_count);
	digest_update_u32(digest, seal->chain_consistency_checks);
	digest_update_u32(digest, seal->evidence_capabilities_all);
	digest_update_u32(digest, seal->evidence_capabilities_any);
	digest_update_bool(digest, seal->replay_passed);
	digest_update_bool(digest, seal->top_consistent);
	digest_update_bool(digest, seal->nonce_consistent);
	digest_update_bool(digest, seal->verdict_digest_consistent);
	digest_update_bool(digest, seal->profile_consistent);
	digest_update_bool(digest, seal->status_consistent);
	digest_update_text(digest, seal->top_candidate_id);
	digest_update_text(digest, seal->nonce_hex);
	digest_update_text(digest, seal->verdict_digest_hex);
	digest_update_text(digest, seal->audit_digest_hex);
	digest_to_hex(digest, seal->seal_digest_hex);
}

static void seal_invalid(struct pqcp_deployment_evidence_seal *seal,
			 enum pqcp_deployment_release_gate_profile profile,
			 uint32_t error_mask)
{
	if (seal == NULL) {
		return;
	}

	memset(seal, 0, sizeof(*seal));
	seal->schema_version = PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION;
	seal->status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL;
	seal->error_mask = error_mask;
	seal->profile = profile;
	set_text(seal->top_candidate_id, sizeof(seal->top_candidate_id),
		 "none");
	set_zero_nonce(seal->nonce_hex, sizeof(seal->nonce_hex));
	set_zero_digest(seal->verdict_digest_hex,
			sizeof(seal->verdict_digest_hex));
	set_zero_digest(seal->audit_digest_hex,
			sizeof(seal->audit_digest_hex));
	set_zero_digest(seal->seal_digest_hex, sizeof(seal->seal_digest_hex));
}

static bool input_shapes_valid(
	const struct pqcp_deployment_evidence_verdict *verdict,
	const struct pqcp_deployment_evidence_verdict_replay_result *replay,
	const struct pqcp_deployment_evidence_verdict_audit_report *audit,
	const struct pqcp_deployment_evidence_seal_policy *policy)
{
	return verdict->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_VERDICT_SCHEMA_VERSION &&
	       replay->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_SCHEMA_VERSION &&
	       audit->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_SCHEMA_VERSION &&
	       verdict_status_valid(verdict->status) &&
	       verdict_status_valid(replay->verdict_status) &&
	       audit_status_valid(audit->status) &&
	       profile_valid(verdict->profile) &&
	       profile_valid(replay->profile) &&
	       profile_valid(audit->profile) &&
	       profile_valid(policy->profile) &&
	       policy->min_seal_score <= 100U &&
	       verdict->verdict_score <= 100U &&
	       verdict->min_chain_score <= 100U &&
	       replay->verdict_score <= 100U &&
	       replay->min_chain_score <= 100U &&
	       audit->min_verdict_score <= 100U &&
	       audit->min_chain_score <= 100U &&
	       text_present(verdict->top_candidate_id) &&
	       text_present(replay->top_candidate_id) &&
	       text_present(audit->top_candidate_id) &&
	       nonce_valid(verdict->nonce_hex) &&
	       nonce_valid(replay->nonce_hex) &&
	       nonce_valid(audit->nonce_hex) &&
	       digest_valid(verdict->verdict_digest_hex) &&
	       digest_valid(replay->computed_digest_hex) &&
	       digest_valid(audit->verdict_digest_hex) &&
	       digest_valid(audit->audit_digest_hex);
}

static uint32_t min_u32(uint32_t a, uint32_t b)
{
	return a < b ? a : b;
}

static uint32_t score_penalty(uint32_t score, uint32_t penalty)
{
	return penalty > score ? 0U : score - penalty;
}

const char *pqcp_deployment_evidence_seal_status_str(
	enum pqcp_deployment_evidence_seal_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

int pqcp_deployment_evidence_seal_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_evidence_seal_policy *policy)
{
	if (policy == NULL || !profile_valid(profile)) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->min_audit_samples = 1U;
	policy->require_replay_pass = true;
	policy->require_consistency = true;
	policy->require_chain_capability = true;

	switch (profile) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE:
		policy->min_seal_score = 50U;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER:
		policy->min_seal_score = 65U;
		policy->require_audit_pass = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT:
		policy->min_seal_score = 75U;
		policy->score_floor_blocks = true;
		policy->require_verdict_pass = true;
		policy->require_audit_pass = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER:
		policy->min_seal_score = 70U;
		policy->require_verdict_pass = true;
		policy->require_audit_pass = true;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int pqcp_deployment_evidence_seal_run(
	const struct pqcp_deployment_evidence_verdict *verdict,
	const struct pqcp_deployment_evidence_verdict_replay_result *replay,
	const struct pqcp_deployment_evidence_verdict_audit_report *audit,
	const struct pqcp_deployment_evidence_seal_policy *policy,
	struct pqcp_deployment_evidence_seal *seal)
{
	const uint32_t required_caps =
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT;
	uint32_t score;

	if (seal == NULL) {
		return -EINVAL;
	}
	if (verdict == NULL || replay == NULL || audit == NULL ||
	    policy == NULL || !profile_valid(policy->profile)) {
		seal_invalid(seal, policy != NULL ? policy->profile :
				   PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			     PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if (!input_shapes_valid(verdict, replay, audit, policy)) {
		seal_invalid(seal, policy->profile,
			     PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_INVALID_INPUT);
		return -EINVAL;
	}

	memset(seal, 0, sizeof(*seal));
	seal->schema_version = PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION;
	seal->profile = policy->profile;
	seal->verdict_status = verdict->status;
	seal->audit_status = audit->status;
	seal->audited_result_count = audit->result_count;
	seal->chain_stage_count = verdict->stage_count;
	seal->chain_consistency_checks = verdict->consistency_checks;
	seal->replay_passed = replay->passed;
	seal->evidence_capabilities_all =
		verdict->evidence_capabilities_all &
		replay->evidence_capabilities_all &
		audit->evidence_capabilities_all;
	seal->evidence_capabilities_any =
		verdict->evidence_capabilities_any |
		replay->evidence_capabilities_any |
		audit->evidence_capabilities_any;

	seal->top_consistent =
		strcmp(verdict->top_candidate_id, replay->top_candidate_id) == 0 &&
		strcmp(verdict->top_candidate_id, audit->top_candidate_id) == 0;
	seal->nonce_consistent =
		strcmp(verdict->nonce_hex, replay->nonce_hex) == 0 &&
		strcmp(verdict->nonce_hex, audit->nonce_hex) == 0;
	seal->verdict_digest_consistent =
		strcmp(verdict->verdict_digest_hex,
		       replay->computed_digest_hex) == 0 &&
		strcmp(verdict->verdict_digest_hex,
		       audit->verdict_digest_hex) == 0;
	seal->profile_consistent =
		verdict->profile == policy->profile &&
		replay->profile == policy->profile &&
		audit->profile == policy->profile;
	seal->status_consistent =
		verdict->status == replay->verdict_status;

	if (seal->top_consistent) {
		set_text(seal->top_candidate_id,
			 sizeof(seal->top_candidate_id),
			 verdict->top_candidate_id);
	} else {
		set_text(seal->top_candidate_id,
			 sizeof(seal->top_candidate_id), "none");
	}
	if (seal->nonce_consistent) {
		set_text(seal->nonce_hex, sizeof(seal->nonce_hex),
			 verdict->nonce_hex);
	} else {
		set_zero_nonce(seal->nonce_hex, sizeof(seal->nonce_hex));
	}
	if (seal->verdict_digest_consistent) {
		set_text(seal->verdict_digest_hex,
			 sizeof(seal->verdict_digest_hex),
			 verdict->verdict_digest_hex);
	} else {
		set_zero_digest(seal->verdict_digest_hex,
				sizeof(seal->verdict_digest_hex));
	}
	set_text(seal->audit_digest_hex, sizeof(seal->audit_digest_hex),
		 audit->audit_digest_hex);

	if (policy->require_verdict_pass &&
	    verdict->status != PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS) {
		seal->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_VERDICT;
	}
	if (policy->require_replay_pass && !replay->passed) {
		seal->error_mask |= PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_REPLAY;
	}
	if (policy->require_audit_pass &&
	    audit->status != PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS) {
		seal->error_mask |= PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_AUDIT;
	}
	if (policy->require_consistency) {
		if (!seal->top_consistent) {
			seal->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_TOP_MISMATCH;
		}
		if (!seal->nonce_consistent) {
			seal->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_NONCE_MISMATCH;
		}
		if (!seal->verdict_digest_consistent) {
			seal->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_DIGEST_MISMATCH;
		}
		if (!seal->profile_consistent) {
			seal->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_PROFILE_MISMATCH;
		}
		if (!seal->status_consistent) {
			seal->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_STATUS_MISMATCH;
		}
	}
	if (policy->require_chain_capability &&
	    (seal->evidence_capabilities_all & required_caps) !=
		    required_caps) {
		seal->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_CAPABILITY;
	}

	if (verdict->warning_mask != 0U || audit->warning_mask != 0U) {
		seal->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_UPSTREAM_WARNINGS;
	}
	if (verdict->status != PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS) {
		seal->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_NOT_PRODUCT_PASS;
	}
	if (audit->result_count < policy->min_audit_samples) {
		seal->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_LOW_SAMPLE_COUNT;
	}

	seal->min_terminal_score = verdict->verdict_score;
	seal->min_terminal_score = min_u32(seal->min_terminal_score,
					   verdict->min_chain_score);
	seal->min_terminal_score = min_u32(seal->min_terminal_score,
					   replay->verdict_score);
	seal->min_terminal_score = min_u32(seal->min_terminal_score,
					   audit->min_verdict_score);
	seal->min_terminal_score = min_u32(seal->min_terminal_score,
					   audit->min_chain_score);

	score = seal->min_terminal_score;
	if (verdict->status != PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS) {
		score = score_penalty(score, 10U);
	}
	if (audit->status != PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS) {
		score = score_penalty(score, 5U);
	}
	if (!replay->passed) {
		score = score_penalty(score, 20U);
	}
	if (!seal->top_consistent || !seal->nonce_consistent ||
	    !seal->verdict_digest_consistent || !seal->profile_consistent ||
	    !seal->status_consistent) {
		score = score_penalty(score, 15U);
	}
	seal->seal_score = score;

	if (seal->seal_score < policy->min_seal_score) {
		if (policy->score_floor_blocks) {
			seal->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_SCORE_FLOOR;
		} else {
			seal->warning_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_SCORE_FLOOR;
		}
	}

	if (seal->error_mask != 0U) {
		seal->status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL;
	} else if (seal->warning_mask != 0U) {
		seal->status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN;
	} else {
		seal->status = PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
	}

	compute_seal_digest(seal);

	return seal->status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_evidence_seal_emit(
	const struct pqcp_deployment_evidence_seal *seal)
{
	if (seal == NULL ||
	    seal->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION ||
	    !seal_status_valid(seal->status) ||
	    !profile_valid(seal->profile) ||
	    !verdict_status_valid(seal->verdict_status) ||
	    !audit_status_valid(seal->audit_status) ||
	    (seal->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_KNOWN_MASK) != 0U ||
	    (seal->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_KNOWN_MASK) != 0U ||
	    seal->seal_score > 100U ||
	    seal->min_terminal_score > 100U ||
	    !text_present(seal->top_candidate_id) ||
	    !nonce_valid(seal->nonce_hex) ||
	    !digest_valid(seal->verdict_digest_hex) ||
	    !digest_valid(seal->audit_digest_hex) ||
	    !digest_valid(seal->seal_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EVIDENCE_SEAL schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x score=%u min_score=%u verdict_status=%s audit_status=%s replay_passed=%u audited_results=%u chain_stages=%u chain_consistency=%u evidence_all=0x%08x evidence_any=0x%08x top_consistent=%u nonce_consistent=%u digest_consistent=%u profile_consistent=%u status_consistent=%u top=%s nonce=%s verdict_digest=%s audit_digest=%s seal_digest=%s\n",
	       seal->schema_version,
	       pqcp_deployment_release_gate_profile_str(seal->profile),
	       pqcp_deployment_evidence_seal_status_str(seal->status),
	       seal->error_mask,
	       seal->warning_mask,
	       seal->seal_score,
	       seal->min_terminal_score,
	       pqcp_deployment_evidence_verdict_status_str(
		       seal->verdict_status),
	       pqcp_deployment_evidence_verdict_audit_status_str(
		       seal->audit_status),
	       seal->replay_passed ? 1U : 0U,
	       seal->audited_result_count,
	       seal->chain_stage_count,
	       seal->chain_consistency_checks,
	       seal->evidence_capabilities_all,
	       seal->evidence_capabilities_any,
	       seal->top_consistent ? 1U : 0U,
	       seal->nonce_consistent ? 1U : 0U,
	       seal->verdict_digest_consistent ? 1U : 0U,
	       seal->profile_consistent ? 1U : 0U,
	       seal->status_consistent ? 1U : 0U,
	       seal->top_candidate_id,
	       seal->nonce_hex,
	       seal->verdict_digest_hex,
	       seal->audit_digest_hex,
	       seal->seal_digest_hex);

	return seal->status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL ?
		-EBADMSG : 0;
}
