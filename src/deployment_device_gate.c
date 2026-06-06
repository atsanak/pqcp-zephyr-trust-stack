/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native deployment device-evidence gate.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_device_gate.h>

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

static bool audit_status_valid(
	enum pqcp_deployment_device_token_audit_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL;
}

static bool gate_status_valid(
	enum pqcp_deployment_device_gate_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_GATE_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_GATE_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_GATE_FAIL;
}

static enum pqcp_deployment_device_gate_status compute_status(
	uint32_t errors,
	uint32_t warnings)
{
	if (errors != 0U) {
		return PQCP_DEPLOYMENT_DEVICE_GATE_FAIL;
	}
	if (warnings != 0U) {
		return PQCP_DEPLOYMENT_DEVICE_GATE_WARN;
	}

	return PQCP_DEPLOYMENT_DEVICE_GATE_PASS;
}

static bool policy_valid(const struct pqcp_deployment_device_gate_policy *policy)
{
	return policy != NULL &&
	       profile_valid(policy->profile) &&
	       policy->min_capability_readiness_score <= 100U &&
	       policy->min_release_gate_score <= 100U &&
	       policy->min_audit_gate_score <= 100U;
}

static bool release_gate_valid(
	const struct pqcp_deployment_release_gate_report *release_gate)
{
	return release_gate != NULL &&
	       release_gate->schema_version ==
		       PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION &&
	       profile_valid(release_gate->profile) &&
	       release_gate_status_valid(release_gate->status) &&
	       (release_gate->error_mask &
		~PQCP_DEPLOYMENT_RELEASE_GATE_ERROR_KNOWN_MASK) == 0U &&
	       (release_gate->warning_mask &
		~PQCP_DEPLOYMENT_RELEASE_GATE_WARNING_KNOWN_MASK) == 0U &&
	       release_gate->readiness_score <= 100U &&
	       release_gate->claim_score <= 100U &&
	       release_gate->review_score <= 100U &&
	       release_gate->gate_score <= 100U &&
	       text_present(release_gate->top_candidate_id) &&
	       text_present(release_gate->trace_digest_hex) &&
	       text_present(release_gate->packet_digest_hex);
}

static bool token_valid(const struct pqcp_deployment_device_token *token)
{
	return token != NULL &&
	       token->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION &&
	       profile_valid(token->profile) &&
	       token_status_valid(token->status) &&
	       release_gate_status_valid(token->gate_status) &&
	       (token->error_mask &
		~PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_KNOWN_MASK) == 0U &&
	       (token->warning_mask &
		~PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_KNOWN_MASK) == 0U &&
	       token->capability_readiness_score <= 100U &&
	       token->gate_score <= 100U &&
	       text_present(token->nonce_hex) &&
	       text_present(token->top_candidate_id) &&
	       text_present(token->trace_digest_hex) &&
	       text_present(token->packet_digest_hex) &&
	       text_present(token->token_digest_hex);
}

static bool verification_valid(
	const struct pqcp_deployment_device_token_verification *verification)
{
	return verification != NULL &&
	       verification->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION &&
	       token_status_valid(verification->expected_status) &&
	       token_status_valid(verification->observed_status) &&
	       (verification->error_mask &
		~PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_KNOWN_MASK) == 0U &&
	       text_present(verification->expected_digest_hex) &&
	       text_present(verification->observed_digest_hex);
}

static bool replay_valid(
	const struct pqcp_deployment_device_token_replay_result *replay)
{
	return replay != NULL &&
	       replay->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION &&
	       replay->lines_seen != 0U &&
	       replay->marker_mask ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK &&
	       token_status_valid(replay->token_status) &&
	       release_gate_status_valid(replay->gate_status) &&
	       replay->capability_readiness_score <= 100U &&
	       replay->gate_score <= 100U &&
	       text_present(replay->top_candidate_id) &&
	       text_present(replay->nonce_hex) &&
	       text_present(replay->token_digest_hex) &&
	       text_present(replay->computed_digest_hex);
}

static bool audit_valid(
	const struct pqcp_deployment_device_token_audit_report *audit)
{
	return audit != NULL &&
	       audit->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_SCHEMA_VERSION &&
	       audit_status_valid(audit->status) &&
	       (audit->error_mask &
		~PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_ERROR_KNOWN_MASK) == 0U &&
	       (audit->warning_mask &
		~PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARNING_KNOWN_MASK) == 0U &&
	       audit->result_count != 0U &&
	       audit->min_capability_readiness_score <= 100U &&
	       audit->min_gate_score <= 100U &&
	       audit->max_gate_score <= 100U &&
	       audit->avg_gate_score <= 100U &&
	       text_present(audit->nonce_hex) &&
	       text_present(audit->top_candidate_id) &&
	       text_present(audit->token_digest_hex);
}

static void report_invalid(
	struct pqcp_deployment_device_gate_report *report,
	enum pqcp_deployment_release_gate_profile profile,
	uint32_t error_mask)
{
	if (report == NULL) {
		return;
	}

	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_DEPLOYMENT_DEVICE_GATE_SCHEMA_VERSION;
	report->profile = profile;
	report->status = PQCP_DEPLOYMENT_DEVICE_GATE_FAIL;
	report->error_mask = error_mask;
	report->release_gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
	report->token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;
	report->audit_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL;
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s", "none");
	(void)snprintk(report->nonce_hex, sizeof(report->nonce_hex), "%s",
		       "00000000000000000000000000000000");
	(void)snprintk(report->trace_digest_hex,
		       sizeof(report->trace_digest_hex), "%s", "none");
	(void)snprintk(report->packet_digest_hex,
		       sizeof(report->packet_digest_hex), "%s", "none");
	(void)snprintk(report->token_digest_hex,
		       sizeof(report->token_digest_hex), "%s", "none");
}

static void copy_report_fields(
	struct pqcp_deployment_device_gate_report *report,
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_policy *policy)
{
	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_DEPLOYMENT_DEVICE_GATE_SCHEMA_VERSION;
	report->profile = policy->profile;
	report->evidence_capabilities = capability->evidence_capabilities;
	report->capability_readiness_score =
		capability->evidence_readiness_score;
	report->release_gate_score = release_gate->gate_score;
	report->audit_min_gate_score = audit->min_gate_score;
	report->release_gate_status = release_gate->status;
	report->token_status = token->status;
	report->audit_status = audit->status;
	report->capability_policy_passed = capability->policy_passed;
	report->production_allowed = capability->production_allowed;
	report->native_provider =
		capability->provider_summary ==
		PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	report->verification_passed = verification->passed;
	report->replay_passed = replay->passed;
	(void)snprintk(report->top_candidate_id,
		       sizeof(report->top_candidate_id), "%s",
		       release_gate->top_candidate_id);
	(void)snprintk(report->nonce_hex, sizeof(report->nonce_hex), "%s",
		       token->nonce_hex);
	(void)snprintk(report->trace_digest_hex,
		       sizeof(report->trace_digest_hex), "%s",
		       release_gate->trace_digest_hex);
	(void)snprintk(report->packet_digest_hex,
		       sizeof(report->packet_digest_hex), "%s",
		       release_gate->packet_digest_hex);
	(void)snprintk(report->token_digest_hex,
		       sizeof(report->token_digest_hex), "%s",
		       token->token_digest_hex);
}

static void compute_consistency(
	struct pqcp_deployment_device_gate_report *report,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit)
{
	report->top_consistent =
		strcmp(release_gate->top_candidate_id,
		       token->top_candidate_id) == 0 &&
		strcmp(release_gate->top_candidate_id,
		       replay->top_candidate_id) == 0 &&
		strcmp(release_gate->top_candidate_id,
		       audit->top_candidate_id) == 0;
	report->nonce_consistent =
		strcmp(token->nonce_hex, replay->nonce_hex) == 0 &&
		strcmp(token->nonce_hex, audit->nonce_hex) == 0;
	report->token_digest_consistent =
		strcmp(token->token_digest_hex,
		       verification->expected_digest_hex) == 0 &&
		strcmp(token->token_digest_hex,
		       verification->observed_digest_hex) == 0 &&
		strcmp(token->token_digest_hex,
		       replay->token_digest_hex) == 0 &&
		strcmp(token->token_digest_hex,
		       replay->computed_digest_hex) == 0 &&
		strcmp(token->token_digest_hex,
		       audit->token_digest_hex) == 0;
	report->release_digest_consistent =
		strcmp(release_gate->trace_digest_hex,
		       token->trace_digest_hex) == 0 &&
		strcmp(release_gate->packet_digest_hex,
		       token->packet_digest_hex) == 0 &&
		release_gate->digest_bound && token->gate_digest_bound;
}

static void apply_capability_policy(
	struct pqcp_deployment_device_gate_report *report,
	const struct pqcp_deployment_device_gate_policy *policy)
{
	const bool has_audit_capability =
		(report->evidence_capabilities &
		 PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_TOKEN_AUDIT) != 0U;

	if (policy->require_capability_policy_pass &&
	    !report->capability_policy_passed) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_CAPABILITY;
	}
	if (policy->require_device_token_audit_capability &&
	    !has_audit_capability) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_MISSING_CAPABILITY;
	}
	if (!report->production_allowed) {
		if (policy->require_production_allowed) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PRODUCTION;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_NOT_PRODUCTION;
		}
	}
	if (!report->native_provider) {
		if (policy->require_native_provider) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PROVIDER;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_NON_NATIVE;
		}
	}
}

static void apply_status_policy(
	struct pqcp_deployment_device_gate_report *report,
	const struct pqcp_deployment_device_gate_policy *policy)
{
	if (report->release_gate_status != PQCP_DEPLOYMENT_RELEASE_GATE_PASS) {
		if (policy->require_release_gate_pass) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_RELEASE_GATE;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_RELEASE_GATE;
		}
	}
	if (report->token_status != PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS) {
		if (policy->require_token_pass) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOKEN;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_TOKEN;
		}
	}
	if (!report->verification_passed && policy->require_verification_pass) {
		report->error_mask |= PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_VERIFY;
	}
	if (!report->replay_passed && policy->require_replay_pass) {
		report->error_mask |= PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_REPLAY;
	}
	if (report->audit_status != PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS) {
		if (policy->require_audit_pass) {
			report->error_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_AUDIT;
		} else {
			report->warning_mask |=
				PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_AUDIT;
		}
	}
}

static void apply_consistency_policy(
	struct pqcp_deployment_device_gate_report *report,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_gate_policy *policy)
{
	if (release_gate->profile != policy->profile ||
	    token->profile != policy->profile) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_PROFILE_MISMATCH;
	}
	if (!report->top_consistent && policy->require_top_consistency) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOP_MISMATCH;
	}
	if (!report->nonce_consistent && policy->require_nonce_consistency) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_NONCE_MISMATCH;
	}
	if (!report->token_digest_consistent &&
	    policy->require_token_digest_consistency) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_TOKEN_DIGEST;
	}
	if (!report->release_digest_consistent &&
	    policy->require_release_digest_consistency) {
		report->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_RELEASE_DIGEST;
	}
}

static void apply_score_policy(
	struct pqcp_deployment_device_gate_report *report,
	const struct pqcp_deployment_device_gate_policy *policy)
{
	uint32_t score_error = 0U;

	if (report->capability_readiness_score <
	    policy->min_capability_readiness_score) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_CAPABILITY_SCORE;
		score_error = PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_SCORE_FLOOR;
	}
	if (report->release_gate_score < policy->min_release_gate_score) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_GATE_SCORE;
		score_error = PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_SCORE_FLOOR;
	}
	if (report->audit_min_gate_score < policy->min_audit_gate_score) {
		report->warning_mask |=
			PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_AUDIT_SCORE;
		score_error = PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_SCORE_FLOOR;
	}
	if (policy->score_floor_blocks && score_error != 0U) {
		report->error_mask |= score_error;
	}
}

const char *pqcp_deployment_device_gate_status_str(
	enum pqcp_deployment_device_gate_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_DEVICE_GATE_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_DEVICE_GATE_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_DEVICE_GATE_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

int pqcp_deployment_device_gate_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_device_gate_policy *policy)
{
	if (policy == NULL || !profile_valid(profile)) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->require_capability_policy_pass = true;
	policy->require_verification_pass = true;
	policy->require_replay_pass = true;
	policy->require_top_consistency = true;
	policy->require_nonce_consistency = true;
	policy->require_token_digest_consistency = true;
	policy->require_release_digest_consistency = true;
	policy->require_device_token_audit_capability = true;

	switch (profile) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE:
		policy->min_capability_readiness_score = 40U;
		policy->min_release_gate_score = 0U;
		policy->min_audit_gate_score = 0U;
		policy->require_release_gate_pass = false;
		policy->require_token_pass = false;
		policy->require_audit_pass = false;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER:
		policy->min_capability_readiness_score = 70U;
		policy->min_release_gate_score = 50U;
		policy->min_audit_gate_score = 50U;
		policy->require_release_gate_pass = false;
		policy->require_token_pass = false;
		policy->require_audit_pass = false;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT:
		policy->min_capability_readiness_score = 80U;
		policy->min_release_gate_score = 80U;
		policy->min_audit_gate_score = 80U;
		policy->score_floor_blocks = true;
		policy->require_production_allowed = true;
		policy->require_native_provider = true;
		policy->require_release_gate_pass = true;
		policy->require_token_pass = true;
		policy->require_audit_pass = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER:
		policy->min_capability_readiness_score = 75U;
		policy->min_release_gate_score = 60U;
		policy->min_audit_gate_score = 60U;
		policy->require_release_gate_pass = false;
		policy->require_token_pass = false;
		policy->require_audit_pass = false;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int pqcp_deployment_device_gate_evaluate(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_policy *policy,
	struct pqcp_deployment_device_gate_report *report)
{
	if (report == NULL) {
		return -EINVAL;
	}
	if (!policy_valid(policy) || capability == NULL ||
	    release_gate == NULL || token == NULL || verification == NULL ||
	    replay == NULL || audit == NULL) {
		report_invalid(report,
			       policy != NULL && profile_valid(policy->profile) ?
			       policy->profile :
			       PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
			       PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if (pqcp_capability_descriptor_validate(capability) != 0 ||
	    !release_gate_valid(release_gate) || !token_valid(token) ||
	    !verification_valid(verification) || !replay_valid(replay) ||
	    !audit_valid(audit)) {
		report_invalid(report, policy->profile,
			       PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_INVALID_INPUT);
		return -EINVAL;
	}

	copy_report_fields(report, capability, release_gate, token,
			   verification, replay, audit, policy);
	compute_consistency(report, release_gate, token, verification, replay,
			    audit);
	apply_capability_policy(report, policy);
	apply_status_policy(report, policy);
	apply_consistency_policy(report, release_gate, token, policy);
	apply_score_policy(report, policy);
	report->status = compute_status(report->error_mask,
					report->warning_mask);

	return report->status == PQCP_DEPLOYMENT_DEVICE_GATE_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_device_gate_emit(
	const struct pqcp_deployment_device_gate_report *report)
{
	if (report == NULL ||
	    report->schema_version !=
		    PQCP_DEPLOYMENT_DEVICE_GATE_SCHEMA_VERSION ||
	    !profile_valid(report->profile) ||
	    !gate_status_valid(report->status) ||
	    release_gate_status_valid(report->release_gate_status) == false ||
	    !token_status_valid(report->token_status) ||
	    !audit_status_valid(report->audit_status) ||
	    (report->error_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_KNOWN_MASK) != 0U ||
	    (report->warning_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_KNOWN_MASK) != 0U ||
	    report->capability_readiness_score > 100U ||
	    report->release_gate_score > 100U ||
	    report->audit_min_gate_score > 100U ||
	    !text_present(report->top_candidate_id) ||
	    !text_present(report->nonce_hex) ||
	    !text_present(report->trace_digest_hex) ||
	    !text_present(report->packet_digest_hex) ||
	    !text_present(report->token_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_DEVICE_GATE schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x evidence=0x%08x cap_readiness=%u release_gate_score=%u audit_gate_score=%u release=%s token=%s verify=%s replay=%s audit=%s capability_policy=%u production_allowed=%u native_provider=%u top_consistent=%u nonce_consistent=%u token_digest_consistent=%u release_digest_consistent=%u top=%s nonce=%s trace_digest=%s packet_digest=%s token_digest=%s\n",
	       report->schema_version,
	       pqcp_deployment_release_gate_profile_str(report->profile),
	       pqcp_deployment_device_gate_status_str(report->status),
	       report->error_mask,
	       report->warning_mask,
	       report->evidence_capabilities,
	       report->capability_readiness_score,
	       report->release_gate_score,
	       report->audit_min_gate_score,
	       pqcp_deployment_release_gate_status_str(
		       report->release_gate_status),
	       pqcp_deployment_device_token_status_str(report->token_status),
	       report->verification_passed ? "PASS" : "FAIL",
	       report->replay_passed ? "PASS" : "FAIL",
	       pqcp_deployment_device_token_audit_status_str(
		       report->audit_status),
	       report->capability_policy_passed ? 1U : 0U,
	       report->production_allowed ? 1U : 0U,
	       report->native_provider ? 1U : 0U,
	       report->top_consistent ? 1U : 0U,
	       report->nonce_consistent ? 1U : 0U,
	       report->token_digest_consistent ? 1U : 0U,
	       report->release_digest_consistent ? 1U : 0U,
	       report->top_candidate_id,
	       report->nonce_hex,
	       report->trace_digest_hex,
	       report->packet_digest_hex,
	       report->token_digest_hex);

	return report->status == PQCP_DEPLOYMENT_DEVICE_GATE_FAIL ?
		-EBADMSG : 0;
}
