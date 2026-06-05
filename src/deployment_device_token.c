/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native deployment device evidence token.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_device_token.h>

static bool release_gate_profile_valid(
	enum pqcp_deployment_release_gate_profile profile)
{
	return profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
}

static bool release_gate_status_valid(
	enum pqcp_deployment_release_gate_status status)
{
	return status == PQCP_DEPLOYMENT_RELEASE_GATE_PASS ||
	       status == PQCP_DEPLOYMENT_RELEASE_GATE_WARN ||
	       status == PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
}

static bool token_status_valid(
	enum pqcp_deployment_device_token_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;
}

static bool has_text(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool is_hex_char(char c)
{
	return (c >= '0' && c <= '9') ||
	       (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

static bool is_hex_len(const char *value, size_t expected_len)
{
	if (value == NULL) {
		return false;
	}
	for (size_t i = 0U; i < expected_len; ++i) {
		if (!is_hex_char(value[i])) {
			return false;
		}
	}

	return value[expected_len] == '\0';
}

static bool nonce_valid(const char *nonce_hex)
{
	return is_hex_len(nonce_hex,
			  PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS);
}

static bool digest_valid(const char *digest_hex, size_t expected_len)
{
	return is_hex_len(digest_hex, expected_len);
}

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0x9ae16a3b2f90404fULL;
	digest[1] = 0xc949d7c7509e6557ULL;
	digest[2] = 0xff51afd7ed558ccdULL;
	digest[3] = 0xc4ceb9fe1a85ec53ULL;
}

static uint64_t rotl64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= value;
	digest[0] *= 0x100000001b3ULL;
	digest[1] ^= digest[0] + ((uint64_t)value << 21U);
	digest[1] = rotl64(digest[1], 19U) * 0x9e3779b185ebca87ULL;
	digest[2] += digest[1] ^ value ^ 0x517cc1b727220a95ULL;
	digest[2] = rotl64(digest[2], 33U);
	digest[3] ^= digest[2] + (digest[0] >> 11U);
	digest[3] = rotl64(digest[3], 47U);
}

static void digest_update_string(uint64_t digest[4], const char *value)
{
	for (const char *p = value; *p != '\0'; ++p) {
		digest_update_byte(digest, (uint8_t)*p);
	}
	digest_update_byte(digest, (uint8_t)'\n');
}

static void digest_to_hex(const uint64_t digest[4], char out[
			  PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(out, PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U,
		       "%016llx%016llx%016llx%016llx",
		       (unsigned long long)digest[0],
		       (unsigned long long)digest[1],
		       (unsigned long long)digest[2],
		       (unsigned long long)digest[3]);
}

static void build_canonical_line(
	const struct pqcp_deployment_device_token *token,
	char *line,
	size_t line_size)
{
	(void)snprintk(
		line, line_size,
		"PQCP_DEPLOYMENT_DEVICE_TOKEN_BODY schema=%u profile=%s nonce=%s status=%s errors=0x%08x warnings=0x%08x evidence=0x%08x cap_readiness=%u gate_score=%u gate_status=%s capability_policy=%u production_allowed=%u native_provider=%u gate_digest_bound=%u top=%s trace_digest=%s packet_digest=%s",
		token->schema_version,
		pqcp_deployment_release_gate_profile_str(token->profile),
		token->nonce_hex,
		pqcp_deployment_device_token_status_str(token->status),
		token->error_mask,
		token->warning_mask,
		token->evidence_capabilities,
		token->capability_readiness_score,
		token->gate_score,
		pqcp_deployment_release_gate_status_str(token->gate_status),
		token->capability_policy_passed ? 1U : 0U,
		token->production_allowed ? 1U : 0U,
		token->native_provider ? 1U : 0U,
		token->gate_digest_bound ? 1U : 0U,
		token->top_candidate_id,
		token->trace_digest_hex,
		token->packet_digest_hex);
}

static void compute_token_digest(
	struct pqcp_deployment_device_token *token)
{
	char line[768];
	uint64_t digest[4];

	digest_init(digest);
	build_canonical_line(token, line, sizeof(line));
	digest_update_string(digest, line);
	digest_to_hex(digest, token->token_digest_hex);
}

const char *pqcp_deployment_device_token_status_str(
	enum pqcp_deployment_device_token_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

int pqcp_deployment_device_token_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_device_token_policy *policy)
{
	if (policy == NULL || !release_gate_profile_valid(profile)) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->require_capability_policy_pass = true;
	policy->require_release_gate_capability = true;
	policy->require_device_token_capability = true;
	policy->require_gate_digest_binding = true;

	switch (profile) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE:
		policy->min_capability_readiness_score = 50U;
		policy->min_gate_score = 40U;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER:
		policy->min_capability_readiness_score = 70U;
		policy->min_gate_score = 60U;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT:
		policy->min_capability_readiness_score = 80U;
		policy->min_gate_score = 70U;
		policy->score_floor_blocks = true;
		policy->require_production_allowed = true;
		policy->require_native_provider = true;
		policy->require_gate_pass = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER:
		policy->min_capability_readiness_score = 85U;
		policy->min_gate_score = 75U;
		policy->score_floor_blocks = true;
		policy->require_production_allowed = true;
		policy->require_native_provider = true;
		policy->require_gate_pass = true;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static bool policy_valid(
	const struct pqcp_deployment_device_token_policy *policy)
{
	return policy != NULL &&
	       release_gate_profile_valid(policy->profile) &&
	       policy->min_capability_readiness_score <= 100U &&
	       policy->min_gate_score <= 100U;
}

static bool release_gate_valid(
	const struct pqcp_deployment_release_gate_report *release_gate)
{
	return release_gate != NULL &&
	       release_gate->schema_version ==
		       PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION &&
	       release_gate_profile_valid(release_gate->profile) &&
	       release_gate_status_valid(release_gate->status) &&
	       (release_gate->error_mask &
		~PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_KNOWN_MASK) == 0U &&
	       (release_gate->warning_mask &
		~PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_KNOWN_MASK) == 0U &&
	       release_gate->readiness_score <= 100U &&
	       release_gate->claim_score <= 100U &&
	       release_gate->review_score <= 100U &&
	       release_gate->gate_score <= 100U &&
	       has_text(release_gate->top_candidate_id) &&
	       digest_valid(release_gate->trace_digest_hex,
			    PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS) &&
	       digest_valid(release_gate->packet_digest_hex,
			    PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS);
}

static void copy_text(char *dst, size_t dst_size, const char *src)
{
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
}

static void add_policy_findings(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token_policy *policy,
	struct pqcp_deployment_device_token *token)
{
	const bool has_gate_cap =
		(capability->evidence_capabilities &
		 PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_RELEASE_GATE) != 0U;
	const bool has_token_cap =
		(capability->evidence_capabilities &
		 PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN) != 0U;
	const bool score_floor_met =
		capability->evidence_readiness_score >=
			policy->min_capability_readiness_score &&
		release_gate->gate_score >= policy->min_gate_score;

	if (policy->require_release_gate_capability && !has_gate_cap) {
		token->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_MISSING_GATE_CAP;
	}
	if (policy->require_device_token_capability && !has_token_cap) {
		token->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_MISSING_TOKEN_CAP;
	}
	if (policy->require_capability_policy_pass &&
	    !capability->policy_passed) {
		token->error_mask |= PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_POLICY;
	}
	if (policy->require_production_allowed &&
	    !capability->production_allowed) {
		token->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_PRODUCTION;
	} else if (!capability->production_allowed) {
		token->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_NOT_PRODUCTION;
	}
	if (policy->require_native_provider &&
	    capability->provider_summary !=
		    PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE) {
		token->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_PROVIDER;
	} else if (capability->provider_summary !=
		   PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE) {
		token->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_NON_NATIVE;
	}
	if (policy->require_gate_pass &&
	    release_gate->status != PQCP_DEPLOYMENT_RELEASE_GATE_PASS) {
		token->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_GATE_STATUS;
	} else if (release_gate->status ==
		   PQCP_DEPLOYMENT_RELEASE_GATE_WARN) {
		token->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_GATE_WARN;
	} else if (release_gate->status ==
		   PQCP_DEPLOYMENT_RELEASE_GATE_FAIL) {
		token->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_GATE_FAIL;
	}
	if (policy->require_gate_digest_binding &&
	    !release_gate->digest_bound) {
		token->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_GATE_DIGEST;
	}
	if (!score_floor_met) {
		if (policy->score_floor_blocks) {
			token->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_SCORE_FLOOR;
		} else {
			token->warning_mask |=
				PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_SCORE_FLOOR;
		}
	}
}

int pqcp_deployment_device_token_build(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const char *nonce_hex,
	const struct pqcp_deployment_device_token_policy *policy,
	struct pqcp_deployment_device_token *token)
{
	if (token == NULL) {
		return -EINVAL;
	}

	memset(token, 0, sizeof(*token));
	token->schema_version = PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION;
	token->status = PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;

	if (!policy_valid(policy)) {
		token->error_mask =
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_INVALID_INPUT;
		compute_token_digest(token);
		return -EINVAL;
	}

	token->profile = policy->profile;

	if (!nonce_valid(nonce_hex)) {
		token->error_mask =
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_BAD_NONCE;
		compute_token_digest(token);
		return -EINVAL;
	}
	copy_text(token->nonce_hex, sizeof(token->nonce_hex), nonce_hex);

	if (capability == NULL ||
	    pqcp_capability_descriptor_validate(capability) != 0) {
		token->error_mask =
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_CAPABILITY;
		compute_token_digest(token);
		return -EINVAL;
	}
	if (!release_gate_valid(release_gate)) {
		token->error_mask =
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_RELEASE_GATE;
		compute_token_digest(token);
		return -EINVAL;
	}
	if (release_gate->profile != policy->profile) {
		token->error_mask =
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_RELEASE_GATE;
		compute_token_digest(token);
		return -EINVAL;
	}

	token->evidence_capabilities = capability->evidence_capabilities;
	token->capability_readiness_score =
		capability->evidence_readiness_score;
	token->gate_score = release_gate->gate_score;
	token->gate_status = release_gate->status;
	token->capability_policy_passed = capability->policy_passed;
	token->production_allowed = capability->production_allowed;
	token->native_provider =
		capability->provider_summary ==
		PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	token->gate_digest_bound = release_gate->digest_bound;
	copy_text(token->top_candidate_id, sizeof(token->top_candidate_id),
		  release_gate->top_candidate_id);
	copy_text(token->trace_digest_hex, sizeof(token->trace_digest_hex),
		  release_gate->trace_digest_hex);
	copy_text(token->packet_digest_hex, sizeof(token->packet_digest_hex),
		  release_gate->packet_digest_hex);

	add_policy_findings(capability, release_gate, policy, token);
	token->status = token->error_mask != 0U ?
		PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL :
		(token->warning_mask != 0U ?
		 PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN :
		 PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS);
	compute_token_digest(token);

	return token->status == PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL ?
		-EBADMSG : 0;
}

static bool token_fields_valid(
	const struct pqcp_deployment_device_token *token)
{
	return token != NULL &&
	       token->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION &&
	       token_status_valid(token->status) &&
	       release_gate_profile_valid(token->profile) &&
	       (token->error_mask &
		~PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_KNOWN_MASK) == 0U &&
	       (token->warning_mask &
		~PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_KNOWN_MASK) == 0U &&
	       nonce_valid(token->nonce_hex) &&
	       token->capability_readiness_score <= 100U &&
	       token->gate_score <= 100U &&
	       release_gate_status_valid(token->gate_status) &&
	       has_text(token->top_candidate_id) &&
	       digest_valid(token->trace_digest_hex,
			    PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS) &&
	       digest_valid(token->packet_digest_hex,
			    PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS) &&
	       digest_valid(token->token_digest_hex,
			    PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS);
}

static bool tokens_match(
	const struct pqcp_deployment_device_token *a,
	const struct pqcp_deployment_device_token *b)
{
	return a->status == b->status &&
	       a->error_mask == b->error_mask &&
	       a->warning_mask == b->warning_mask &&
	       a->profile == b->profile &&
	       strcmp(a->nonce_hex, b->nonce_hex) == 0 &&
	       a->evidence_capabilities == b->evidence_capabilities &&
	       a->capability_readiness_score ==
		       b->capability_readiness_score &&
	       a->gate_score == b->gate_score &&
	       a->gate_status == b->gate_status &&
	       a->capability_policy_passed == b->capability_policy_passed &&
	       a->production_allowed == b->production_allowed &&
	       a->native_provider == b->native_provider &&
	       a->gate_digest_bound == b->gate_digest_bound &&
	       strcmp(a->top_candidate_id, b->top_candidate_id) == 0 &&
	       strcmp(a->trace_digest_hex, b->trace_digest_hex) == 0 &&
	       strcmp(a->packet_digest_hex, b->packet_digest_hex) == 0 &&
	       strcmp(a->token_digest_hex, b->token_digest_hex) == 0;
}

int pqcp_deployment_device_token_verify(
	const struct pqcp_deployment_device_token *observed,
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const char *nonce_hex,
	const struct pqcp_deployment_device_token_policy *policy,
	struct pqcp_deployment_device_token_verification *verification)
{
	struct pqcp_deployment_device_token expected;
	int ret;

	if (verification == NULL) {
		return -EINVAL;
	}

	memset(verification, 0, sizeof(*verification));
	verification->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION;

	if (!token_fields_valid(observed)) {
		verification->error_mask =
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_INVALID_INPUT;
		return -EINVAL;
	}

	ret = pqcp_deployment_device_token_build(
		capability, release_gate, nonce_hex, policy, &expected);
	verification->expected_status = expected.status;
	verification->observed_status = observed->status;
	copy_text(verification->expected_digest_hex,
		  sizeof(verification->expected_digest_hex),
		  expected.token_digest_hex);
	copy_text(verification->observed_digest_hex,
		  sizeof(verification->observed_digest_hex),
		  observed->token_digest_hex);
	if (ret != 0 && ret != -EBADMSG) {
		verification->error_mask =
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_INVALID_INPUT;
		return ret;
	}

	if (!tokens_match(observed, &expected)) {
		verification->error_mask =
			PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_TOKEN_MISMATCH;
		return -EBADMSG;
	}

	verification->passed = true;
	return 0;
}

int pqcp_deployment_device_token_emit(
	const struct pqcp_deployment_device_token *token)
{
	if (!token_fields_valid(token)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_DEVICE_TOKEN schema=%u profile=%s status=%s nonce=%s errors=0x%08x warnings=0x%08x evidence=0x%08x cap_readiness=%u gate_score=%u gate_status=%s capability_policy=%u production_allowed=%u native_provider=%u gate_digest_bound=%u top=%s trace_digest=%s packet_digest=%s token_digest=%s\n",
	       token->schema_version,
	       pqcp_deployment_release_gate_profile_str(token->profile),
	       pqcp_deployment_device_token_status_str(token->status),
	       token->nonce_hex,
	       token->error_mask,
	       token->warning_mask,
	       token->evidence_capabilities,
	       token->capability_readiness_score,
	       token->gate_score,
	       pqcp_deployment_release_gate_status_str(token->gate_status),
	       token->capability_policy_passed ? 1U : 0U,
	       token->production_allowed ? 1U : 0U,
	       token->native_provider ? 1U : 0U,
	       token->gate_digest_bound ? 1U : 0U,
	       token->top_candidate_id,
	       token->trace_digest_hex,
	       token->packet_digest_hex,
	       token->token_digest_hex);

	return token->status == PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_device_token_verification_emit(
	const struct pqcp_deployment_device_token_verification *verification)
{
	if (verification == NULL ||
	    verification->schema_version !=
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION ||
	    (verification->error_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_KNOWN_MASK) != 0U ||
	    !token_status_valid(verification->expected_status) ||
	    !token_status_valid(verification->observed_status) ||
	    !digest_valid(verification->expected_digest_hex,
			  PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS) ||
	    !digest_valid(verification->observed_digest_hex,
			  PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_DEVICE_TOKEN_VERIFY schema=%u status=%s errors=0x%08x expected_status=%s observed_status=%s expected_digest=%s observed_digest=%s\n",
	       verification->schema_version,
	       verification->passed ? "PASS" : "FAIL",
	       verification->error_mask,
	       pqcp_deployment_device_token_status_str(
		       verification->expected_status),
	       pqcp_deployment_device_token_status_str(
		       verification->observed_status),
	       verification->expected_digest_hex,
	       verification->observed_digest_hex);

	return verification->passed ? 0 : -EBADMSG;
}
