/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware-native deployment assurance passport.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_assurance_passport.h>

static bool text_present(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool text_marker_safe(const char *value)
{
	if (!text_present(value)) {
		return false;
	}
	for (const char *p = value; *p != '\0'; ++p) {
		if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') {
			return false;
		}
	}

	return true;
}

static bool profile_valid(enum pqcp_deployment_release_gate_profile profile)
{
	return profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
}

static bool passport_status_valid(
	enum pqcp_deployment_assurance_passport_status status)
{
	return status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS ||
	       status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN ||
	       status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL;
}

static bool seal_status_valid(enum pqcp_deployment_evidence_seal_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL;
}

static bool seal_audit_status_valid(
	enum pqcp_deployment_evidence_seal_audit_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_FAIL;
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
		value, PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS);
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
	digest[0] = 0xb492b66fbe98f273ULL;
	digest[1] = 0x60642e2a34326f15ULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0x27d4eb2f165667c5ULL;
}

static uint64_t rotl64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= (uint64_t)value + 0x100000001b3ULL;
	digest[0] *= 0x100000001b3ULL;
	digest[1] += digest[0] ^ ((uint64_t)value << 11U);
	digest[1] = rotl64(digest[1], 27U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + digest[0] + 0x94d049bb133111ebULL;
	digest[2] = rotl64(digest[2], 39U);
	digest[3] += digest[2] ^ (digest[1] >> 7U);
	digest[3] = rotl64(digest[3], 51U);
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
	char out[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(
		out,
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U,
		"%016llx%016llx%016llx%016llx",
		(unsigned long long)digest[0],
		(unsigned long long)digest[1],
		(unsigned long long)digest[2],
		(unsigned long long)digest[3]);
}

static void compute_passport_digest(
	struct pqcp_deployment_assurance_passport *passport)
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest, passport->schema_version);
	digest_update_u32(digest, (uint32_t)passport->status);
	digest_update_u32(digest, passport->error_mask);
	digest_update_u32(digest, passport->warning_mask);
	digest_update_u32(digest, (uint32_t)passport->profile);
	digest_update_u32(digest, passport->passport_score);
	digest_update_u32(digest, passport->min_terminal_score);
	digest_update_u32(digest, passport->capability_readiness_score);
	digest_update_u32(digest, (uint32_t)passport->seal_status);
	digest_update_u32(digest, (uint32_t)passport->seal_audit_status);
	digest_update_u32(digest, passport->audited_result_count);
	digest_update_u32(digest, passport->chain_stage_count);
	digest_update_u32(digest, passport->evidence_capabilities_all);
	digest_update_u32(digest, passport->evidence_capabilities_any);
	digest_update_u32(digest, passport->mlkem_level_mask);
	digest_update_u32(digest, passport->mldsa_level_mask);
	digest_update_bool(digest, passport->seal_replay_passed);
	digest_update_bool(digest, passport->top_consistent);
	digest_update_bool(digest, passport->nonce_consistent);
	digest_update_bool(digest, passport->seal_digest_consistent);
	digest_update_bool(digest, passport->profile_consistent);
	digest_update_bool(digest, passport->production_allowed);
	digest_update_text(digest, passport->pqcp_version);
	digest_update_text(digest, passport->zephyr_version);
	digest_update_text(digest, passport->board);
	digest_update_text(digest, passport->top_candidate_id);
	digest_update_text(digest, passport->nonce_hex);
	digest_update_text(digest, passport->seal_digest_hex);
	digest_update_text(digest, passport->seal_audit_digest_hex);
	digest_to_hex(digest, passport->passport_digest_hex);
}

static void passport_invalid(
	struct pqcp_deployment_assurance_passport *passport,
	enum pqcp_deployment_release_gate_profile profile,
	uint32_t error_mask)
{
	if (passport == NULL) {
		return;
	}

	memset(passport, 0, sizeof(*passport));
	passport->schema_version =
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION;
	passport->status = PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL;
	passport->error_mask = error_mask;
	passport->profile = profile;
	set_text(passport->pqcp_version, sizeof(passport->pqcp_version),
		 "unknown");
	set_text(passport->zephyr_version, sizeof(passport->zephyr_version),
		 "unknown");
	set_text(passport->board, sizeof(passport->board), "unknown");
	set_text(passport->top_candidate_id,
		 sizeof(passport->top_candidate_id), "none");
	set_zero_nonce(passport->nonce_hex, sizeof(passport->nonce_hex));
	set_zero_digest(passport->seal_digest_hex,
			sizeof(passport->seal_digest_hex));
	set_zero_digest(passport->seal_audit_digest_hex,
			sizeof(passport->seal_audit_digest_hex));
	set_zero_digest(passport->passport_digest_hex,
			sizeof(passport->passport_digest_hex));
}

static bool input_shapes_valid(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_evidence_seal *seal,
	const struct pqcp_deployment_evidence_seal_replay_result *seal_replay,
	const struct pqcp_deployment_evidence_seal_audit_report *seal_audit,
	const struct pqcp_deployment_assurance_passport_policy *policy)
{
	return pqcp_capability_descriptor_validate(capability) == 0 &&
	       text_marker_safe(capability->pqcp_version) &&
	       text_marker_safe(capability->zephyr_version) &&
	       text_marker_safe(capability->board) &&
	       seal->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION &&
	       seal_replay->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_SCHEMA_VERSION &&
	       seal_audit->schema_version ==
		       PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_SCHEMA_VERSION &&
	       seal_status_valid(seal->status) &&
	       seal_status_valid(seal_replay->seal_status) &&
	       seal_audit_status_valid(seal_audit->status) &&
	       profile_valid(seal->profile) &&
	       profile_valid(seal_replay->profile) &&
	       profile_valid(seal_audit->profile) &&
	       profile_valid(policy->profile) &&
	       policy->min_passport_score <= 100U &&
	       capability->evidence_readiness_score <= 100U &&
	       seal->seal_score <= 100U &&
	       seal->min_terminal_score <= 100U &&
	       seal_replay->seal_score <= 100U &&
	       seal_replay->min_terminal_score <= 100U &&
	       seal_audit->min_seal_score <= 100U &&
	       seal_audit->min_terminal_score <= 100U &&
	       text_present(seal->top_candidate_id) &&
	       text_present(seal_replay->top_candidate_id) &&
	       text_present(seal_audit->top_candidate_id) &&
	       nonce_valid(seal->nonce_hex) &&
	       nonce_valid(seal_replay->nonce_hex) &&
	       nonce_valid(seal_audit->nonce_hex) &&
	       digest_valid(seal->seal_digest_hex) &&
	       digest_valid(seal_replay->computed_digest_hex) &&
	       digest_valid(seal_audit->seal_digest_hex) &&
	       digest_valid(seal_audit->audit_digest_hex);
}

static uint32_t min_u32(uint32_t a, uint32_t b)
{
	return a < b ? a : b;
}

static uint32_t score_penalty(uint32_t score, uint32_t penalty)
{
	return penalty > score ? 0U : score - penalty;
}

const char *pqcp_deployment_assurance_passport_status_str(
	enum pqcp_deployment_assurance_passport_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

int pqcp_deployment_assurance_passport_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_assurance_passport_policy *policy)
{
	if (policy == NULL || !profile_valid(profile)) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->require_seal_replay_pass = true;
	policy->require_consistency = true;
	policy->require_chain_capability = true;

	switch (profile) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE:
		policy->min_passport_score = 50U;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER:
		policy->min_passport_score = 65U;
		policy->require_seal_audit_pass = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT:
		policy->min_passport_score = 75U;
		policy->score_floor_blocks = true;
		policy->require_seal_pass = true;
		policy->require_seal_audit_pass = true;
		policy->require_production_allowed = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER:
		policy->min_passport_score = 70U;
		policy->require_seal_pass = true;
		policy->require_seal_audit_pass = true;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int pqcp_deployment_assurance_passport_run(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_evidence_seal *seal,
	const struct pqcp_deployment_evidence_seal_replay_result *seal_replay,
	const struct pqcp_deployment_evidence_seal_audit_report *seal_audit,
	const struct pqcp_deployment_assurance_passport_policy *policy,
	struct pqcp_deployment_assurance_passport *passport)
{
	const uint32_t required_caps =
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT;
	uint32_t score;

	if (passport == NULL) {
		return -EINVAL;
	}
	if (capability == NULL || seal == NULL || seal_replay == NULL ||
	    seal_audit == NULL || policy == NULL ||
	    !profile_valid(policy->profile)) {
		passport_invalid(passport, policy != NULL ? policy->profile :
				 PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
				 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if (!input_shapes_valid(capability, seal, seal_replay, seal_audit,
				policy)) {
		passport_invalid(passport, policy->profile,
				 PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_INVALID_INPUT);
		return -EINVAL;
	}

	memset(passport, 0, sizeof(*passport));
	passport->schema_version =
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION;
	passport->profile = policy->profile;
	passport->capability_readiness_score =
		capability->evidence_readiness_score;
	passport->seal_status = seal->status;
	passport->seal_audit_status = seal_audit->status;
	passport->audited_result_count = seal_audit->result_count;
	passport->chain_stage_count = seal->chain_stage_count;
	passport->mlkem_level_mask = capability->mlkem_level_mask;
	passport->mldsa_level_mask = capability->mldsa_level_mask;
	passport->seal_replay_passed = seal_replay->passed;
	passport->production_allowed = capability->production_allowed;
	passport->evidence_capabilities_all =
		capability->evidence_capabilities &
		seal->evidence_capabilities_all &
		seal_replay->evidence_capabilities_all &
		seal_audit->evidence_capabilities_all;
	passport->evidence_capabilities_any =
		capability->evidence_capabilities |
		seal->evidence_capabilities_any |
		seal_replay->evidence_capabilities_any |
		seal_audit->evidence_capabilities_any;

	set_text(passport->pqcp_version, sizeof(passport->pqcp_version),
		 capability->pqcp_version);
	set_text(passport->zephyr_version, sizeof(passport->zephyr_version),
		 capability->zephyr_version);
	set_text(passport->board, sizeof(passport->board), capability->board);

	passport->top_consistent =
		strcmp(seal->top_candidate_id,
		       seal_replay->top_candidate_id) == 0 &&
		strcmp(seal->top_candidate_id,
		       seal_audit->top_candidate_id) == 0;
	passport->nonce_consistent =
		strcmp(seal->nonce_hex, seal_replay->nonce_hex) == 0 &&
		strcmp(seal->nonce_hex, seal_audit->nonce_hex) == 0;
	passport->seal_digest_consistent =
		strcmp(seal->seal_digest_hex,
		       seal_replay->computed_digest_hex) == 0 &&
		strcmp(seal->seal_digest_hex,
		       seal_audit->seal_digest_hex) == 0;
	passport->profile_consistent =
		seal->profile == policy->profile &&
		seal_replay->profile == policy->profile &&
		seal_audit->profile == policy->profile;

	if (passport->top_consistent) {
		set_text(passport->top_candidate_id,
			 sizeof(passport->top_candidate_id),
			 seal->top_candidate_id);
	} else {
		set_text(passport->top_candidate_id,
			 sizeof(passport->top_candidate_id), "none");
	}
	if (passport->nonce_consistent) {
		set_text(passport->nonce_hex, sizeof(passport->nonce_hex),
			 seal->nonce_hex);
	} else {
		set_zero_nonce(passport->nonce_hex,
			       sizeof(passport->nonce_hex));
	}
	if (passport->seal_digest_consistent) {
		set_text(passport->seal_digest_hex,
			 sizeof(passport->seal_digest_hex),
			 seal->seal_digest_hex);
	} else {
		set_zero_digest(passport->seal_digest_hex,
				sizeof(passport->seal_digest_hex));
	}
	set_text(passport->seal_audit_digest_hex,
		 sizeof(passport->seal_audit_digest_hex),
		 seal_audit->audit_digest_hex);

	if (!capability->policy_passed) {
		passport->error_mask |=
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_CAPABILITY;
	}
	if (policy->require_seal_pass &&
	    seal->status != PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS) {
		passport->error_mask |=
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL;
	}
	if (policy->require_seal_replay_pass && !seal_replay->passed) {
		passport->error_mask |=
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL_REPLAY;
	}
	if (policy->require_seal_audit_pass &&
	    seal_audit->status != PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS) {
		passport->error_mask |=
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SEAL_AUDIT;
	}
	if (policy->require_consistency) {
		if (!passport->top_consistent) {
			passport->error_mask |=
				PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_TOP_MISMATCH;
		}
		if (!passport->nonce_consistent) {
			passport->error_mask |=
				PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_NONCE_MISMATCH;
		}
		if (!passport->seal_digest_consistent) {
			passport->error_mask |=
				PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_DIGEST_MISMATCH;
		}
		if (!passport->profile_consistent) {
			passport->error_mask |=
				PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_PROFILE_MISMATCH;
		}
	}
	if (policy->require_chain_capability &&
	    (passport->evidence_capabilities_all & required_caps) !=
		    required_caps) {
		passport->error_mask |=
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_CAPABILITY_MISMATCH;
	}
	if (!capability->production_allowed) {
		if (policy->require_production_allowed) {
			passport->error_mask |=
				PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_NOT_PRODUCTION;
		} else {
			passport->warning_mask |=
				PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_LOCAL_ONLY;
		}
	}

	if (seal->warning_mask != 0U || seal_audit->warning_mask != 0U) {
		passport->warning_mask |=
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_UPSTREAM_WARNINGS;
	}
	if (seal->status != PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS) {
		passport->warning_mask |=
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_NOT_PRODUCT_PASS;
	}

	passport->min_terminal_score = capability->evidence_readiness_score;
	passport->min_terminal_score = min_u32(passport->min_terminal_score,
					       seal->seal_score);
	passport->min_terminal_score = min_u32(passport->min_terminal_score,
					       seal->min_terminal_score);
	passport->min_terminal_score = min_u32(passport->min_terminal_score,
					       seal_replay->seal_score);
	passport->min_terminal_score = min_u32(passport->min_terminal_score,
					       seal_audit->min_seal_score);
	passport->min_terminal_score = min_u32(passport->min_terminal_score,
					       seal_audit->min_terminal_score);

	score = passport->min_terminal_score;
	if (seal->status != PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS) {
		score = score_penalty(score, 10U);
	}
	if (seal_audit->status != PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS) {
		score = score_penalty(score, 5U);
	}
	if (!seal_replay->passed) {
		score = score_penalty(score, 20U);
	}
	if (!passport->top_consistent || !passport->nonce_consistent ||
	    !passport->seal_digest_consistent ||
	    !passport->profile_consistent) {
		score = score_penalty(score, 15U);
	}
	if (!capability->production_allowed) {
		score = score_penalty(score, 5U);
	}
	passport->passport_score = score;

	if (passport->passport_score < policy->min_passport_score) {
		if (policy->score_floor_blocks) {
			passport->error_mask |=
				PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_SCORE_FLOOR;
		} else {
			passport->warning_mask |=
				PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_SCORE_FLOOR;
		}
	}

	if (passport->error_mask != 0U) {
		passport->status = PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL;
	} else if (passport->warning_mask != 0U) {
		passport->status = PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN;
	} else {
		passport->status = PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS;
	}

	compute_passport_digest(passport);

	return passport->status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_assurance_passport_emit(
	const struct pqcp_deployment_assurance_passport *passport)
{
	if (passport == NULL ||
	    passport->schema_version !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION ||
	    !passport_status_valid(passport->status) ||
	    !profile_valid(passport->profile) ||
	    !seal_status_valid(passport->seal_status) ||
	    !seal_audit_status_valid(passport->seal_audit_status) ||
	    (passport->error_mask &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_KNOWN_MASK) != 0U ||
	    (passport->warning_mask &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_KNOWN_MASK) != 0U ||
	    passport->passport_score > 100U ||
	    passport->min_terminal_score > 100U ||
	    passport->capability_readiness_score > 100U ||
	    !text_marker_safe(passport->pqcp_version) ||
	    !text_marker_safe(passport->zephyr_version) ||
	    !text_marker_safe(passport->board) ||
	    !text_present(passport->top_candidate_id) ||
	    !nonce_valid(passport->nonce_hex) ||
	    !digest_valid(passport->seal_digest_hex) ||
	    !digest_valid(passport->seal_audit_digest_hex) ||
	    !digest_valid(passport->passport_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_ASSURANCE_PASSPORT schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x score=%u min_score=%u capability_score=%u seal_status=%s seal_audit_status=%s seal_replay_passed=%u audited_results=%u chain_stages=%u evidence_all=0x%08x evidence_any=0x%08x mlkem_levels=0x%08x mldsa_levels=0x%08x top_consistent=%u nonce_consistent=%u digest_consistent=%u profile_consistent=%u production_allowed=%u pqcp_version=%s zephyr_version=%s board=%s top=%s nonce=%s seal_digest=%s seal_audit_digest=%s passport_digest=%s\n",
	       passport->schema_version,
	       pqcp_deployment_release_gate_profile_str(passport->profile),
	       pqcp_deployment_assurance_passport_status_str(passport->status),
	       passport->error_mask,
	       passport->warning_mask,
	       passport->passport_score,
	       passport->min_terminal_score,
	       passport->capability_readiness_score,
	       pqcp_deployment_evidence_seal_status_str(passport->seal_status),
	       pqcp_deployment_evidence_seal_audit_status_str(
		       passport->seal_audit_status),
	       passport->seal_replay_passed ? 1U : 0U,
	       passport->audited_result_count,
	       passport->chain_stage_count,
	       passport->evidence_capabilities_all,
	       passport->evidence_capabilities_any,
	       passport->mlkem_level_mask,
	       passport->mldsa_level_mask,
	       passport->top_consistent ? 1U : 0U,
	       passport->nonce_consistent ? 1U : 0U,
	       passport->seal_digest_consistent ? 1U : 0U,
	       passport->profile_consistent ? 1U : 0U,
	       passport->production_allowed ? 1U : 0U,
	       passport->pqcp_version,
	       passport->zephyr_version,
	       passport->board,
	       passport->top_candidate_id,
	       passport->nonce_hex,
	       passport->seal_digest_hex,
	       passport->seal_audit_digest_hex,
	       passport->passport_digest_hex);

	return passport->status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL ?
		-EBADMSG : 0;
}
