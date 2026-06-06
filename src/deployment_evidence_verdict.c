/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native deployment evidence verdict.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_verdict.h>

enum stage_state {
	STAGE_FAIL = 0,
	STAGE_WARN,
	STAGE_PASS,
};

struct text_consistency {
	char value[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	bool seen;
	bool consistent;
};

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

static bool verdict_status_valid(
	enum pqcp_deployment_evidence_verdict_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL;
}

static bool budget_status_valid(enum pqcp_deployment_budget_status status)
{
	return status == PQCP_DEPLOYMENT_BUDGET_STATUS_PASS ||
	       status == PQCP_DEPLOYMENT_BUDGET_STATUS_WARN ||
	       status == PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL;
}

static bool experiment_status_valid(
	enum pqcp_deployment_experiment_plan_status status)
{
	return status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS ||
	       status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_WARN ||
	       status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL;
}

static bool review_packet_status_valid(
	enum pqcp_deployment_review_packet_status status)
{
	return status == PQCP_DEPLOYMENT_REVIEW_PACKET_PASS ||
	       status == PQCP_DEPLOYMENT_REVIEW_PACKET_WARN ||
	       status == PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
}

static bool review_audit_status_valid(
	enum pqcp_deployment_review_audit_status status)
{
	return status == PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_REVIEW_AUDIT_FAIL;
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

static bool token_audit_status_valid(
	enum pqcp_deployment_device_token_audit_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL;
}

static bool device_gate_status_valid(
	enum pqcp_deployment_device_gate_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_GATE_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_GATE_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_GATE_FAIL;
}

static bool device_packet_status_valid(
	enum pqcp_deployment_device_packet_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_PACKET_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL;
}

static bool packet_audit_status_valid(
	enum pqcp_deployment_device_packet_audit_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_FAIL;
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

static bool trace_digest_valid(const char *value)
{
	return is_lower_hex_len(value, PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS);
}

static bool review_digest_valid(const char *value)
{
	return is_lower_hex_len(
		value, PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS);
}

static bool device_digest_valid(const char *value)
{
	return is_lower_hex_len(
		value, PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS);
}

static bool token_digest_valid(const char *value)
{
	return is_lower_hex_len(
		value, PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS);
}

static bool nonce_valid(const char *value)
{
	return is_lower_hex_len(
		value, PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS);
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

static void text_consistency_init(struct text_consistency *check)
{
	memset(check, 0, sizeof(*check));
	check->consistent = true;
}

static void text_consistency_add(struct text_consistency *check,
				 const char *value,
				 bool valid)
{
	if (!valid || !text_present(value)) {
		check->consistent = false;
		return;
	}

	if (!check->seen) {
		set_text(check->value, sizeof(check->value), value);
		check->seen = true;
		return;
	}

	if (strcmp(check->value, value) != 0) {
		check->consistent = false;
	}
}

static bool text_consistency_passed(const struct text_consistency *check)
{
	return check->seen && check->consistent;
}

static enum stage_state bool_stage(bool passed)
{
	return passed ? STAGE_PASS : STAGE_FAIL;
}

static enum stage_state budget_stage(enum pqcp_deployment_budget_status status)
{
	return status == PQCP_DEPLOYMENT_BUDGET_STATUS_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_BUDGET_STATUS_WARN ? STAGE_WARN :
							      STAGE_FAIL;
}

static enum stage_state experiment_stage(
	enum pqcp_deployment_experiment_plan_status status)
{
	return status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_WARN ? STAGE_WARN :
							       STAGE_FAIL;
}

static enum stage_state review_packet_stage(
	enum pqcp_deployment_review_packet_status status)
{
	return status == PQCP_DEPLOYMENT_REVIEW_PACKET_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_REVIEW_PACKET_WARN ? STAGE_WARN :
							     STAGE_FAIL;
}

static enum stage_state review_audit_stage(
	enum pqcp_deployment_review_audit_status status)
{
	return status == PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_REVIEW_AUDIT_WARN ? STAGE_WARN :
							    STAGE_FAIL;
}

static enum stage_state release_gate_stage(
	enum pqcp_deployment_release_gate_status status)
{
	return status == PQCP_DEPLOYMENT_RELEASE_GATE_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_RELEASE_GATE_WARN ? STAGE_WARN :
							    STAGE_FAIL;
}

static enum stage_state token_stage(
	enum pqcp_deployment_device_token_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN ? STAGE_WARN :
							    STAGE_FAIL;
}

static enum stage_state token_audit_stage(
	enum pqcp_deployment_device_token_audit_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN ? STAGE_WARN :
								  STAGE_FAIL;
}

static enum stage_state device_gate_stage(
	enum pqcp_deployment_device_gate_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_GATE_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_DEVICE_GATE_WARN ? STAGE_WARN :
							   STAGE_FAIL;
}

static enum stage_state device_packet_stage(
	enum pqcp_deployment_device_packet_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_PACKET_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_WARN ? STAGE_WARN :
							     STAGE_FAIL;
}

static enum stage_state packet_audit_stage(
	enum pqcp_deployment_device_packet_audit_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS ? STAGE_PASS :
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_WARN ? STAGE_WARN :
								   STAGE_FAIL;
}

static void stage_add(struct pqcp_deployment_evidence_verdict *verdict,
		      enum stage_state state)
{
	verdict->stage_count++;
	switch (state) {
	case STAGE_PASS:
		verdict->pass_count++;
		break;
	case STAGE_WARN:
		verdict->warn_count++;
		break;
	case STAGE_FAIL:
	default:
		verdict->fail_count++;
		break;
	}
}

static void min_score_update(uint32_t *score, uint32_t value)
{
	if (value < *score) {
		*score = value;
	}
}

static uint32_t score_penalty(uint32_t score, uint32_t penalty)
{
	return penalty > score ? 0U : score - penalty;
}

static bool score_valid(uint32_t score)
{
	return score <= 100U;
}

static bool input_shapes_valid(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const struct pqcp_deployment_review_packet *review_packet,
	const struct pqcp_deployment_review_verifier_result *review_replay,
	const struct pqcp_deployment_review_audit_report *review_audit,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *device_token,
	const struct pqcp_deployment_device_token_verification *token_verify,
	const struct pqcp_deployment_device_token_replay_result *token_replay,
	const struct pqcp_deployment_device_token_audit_report *token_audit,
	const struct pqcp_deployment_device_gate_report *device_gate,
	const struct pqcp_deployment_device_packet *device_packet,
	const struct pqcp_deployment_device_packet_replay_result *packet_replay,
	const struct pqcp_deployment_device_packet_audit_report *packet_audit,
	const struct pqcp_deployment_evidence_verdict_policy *policy)
{
	return pqcp_capability_descriptor_validate(capability) == 0 &&
	       pipeline->schema_version == PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION &&
	       budget->schema_version == PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION &&
	       experiments->schema_version ==
		       PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION &&
	       review_packet->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION &&
	       review_replay->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION &&
	       review_audit->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_AUDIT_SCHEMA_VERSION &&
	       release_gate->schema_version ==
		       PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION &&
	       device_token->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION &&
	       token_verify->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION &&
	       token_replay->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION &&
	       token_audit->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_SCHEMA_VERSION &&
	       device_gate->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_GATE_SCHEMA_VERSION &&
	       device_packet->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION &&
	       packet_replay->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_SCHEMA_VERSION &&
	       packet_audit->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_SCHEMA_VERSION &&
	       budget_status_valid(budget->status) &&
	       experiment_status_valid(experiments->status) &&
	       review_packet_status_valid(review_packet->status) &&
	       review_audit_status_valid(review_audit->status) &&
	       release_gate_status_valid(release_gate->status) &&
	       token_status_valid(device_token->status) &&
	       token_status_valid(token_verify->expected_status) &&
	       token_status_valid(token_verify->observed_status) &&
	       token_status_valid(token_replay->token_status) &&
	       release_gate_status_valid(token_replay->gate_status) &&
	       token_audit_status_valid(token_audit->status) &&
	       device_gate_status_valid(device_gate->status) &&
	       device_packet_status_valid(device_packet->status) &&
	       device_packet_status_valid(packet_replay->packet_status) &&
	       packet_audit_status_valid(packet_audit->status) &&
	       profile_valid(policy->profile) &&
	       score_valid(policy->min_verdict_score) &&
	       score_valid(policy->min_release_gate_score) &&
	       score_valid(policy->min_review_score) &&
	       score_valid(policy->min_capability_readiness_score) &&
	       score_valid(pipeline->top_candidate_score) &&
	       score_valid(budget->top_margin_score) &&
	       score_valid(budget->pipeline_readiness_score) &&
	       score_valid(budget->claim_score) &&
	       score_valid(review_packet->readiness_score) &&
	       score_valid(review_packet->claim_score) &&
	       score_valid(review_packet->review_score) &&
	       score_valid(review_replay->readiness_score) &&
	       score_valid(review_replay->claim_score) &&
	       score_valid(review_replay->review_score) &&
	       score_valid(review_audit->min_readiness_score) &&
	       score_valid(review_audit->min_claim_score) &&
	       score_valid(review_audit->min_review_score) &&
	       score_valid(review_audit->max_review_score) &&
	       score_valid(review_audit->avg_review_score) &&
	       score_valid(release_gate->readiness_score) &&
	       score_valid(release_gate->claim_score) &&
	       score_valid(release_gate->review_score) &&
	       score_valid(release_gate->gate_score) &&
	       score_valid(device_token->capability_readiness_score) &&
	       score_valid(device_token->gate_score) &&
	       score_valid(token_replay->capability_readiness_score) &&
	       score_valid(token_replay->gate_score) &&
	       score_valid(token_audit->min_capability_readiness_score) &&
	       score_valid(token_audit->min_gate_score) &&
	       score_valid(token_audit->max_gate_score) &&
	       score_valid(token_audit->avg_gate_score) &&
	       score_valid(device_gate->capability_readiness_score) &&
	       score_valid(device_gate->release_gate_score) &&
	       score_valid(device_gate->audit_min_gate_score) &&
	       score_valid(device_packet->capability_readiness_score) &&
	       score_valid(device_packet->release_gate_score) &&
	       score_valid(device_packet->audit_min_gate_score) &&
	       score_valid(packet_replay->capability_readiness_score) &&
	       score_valid(packet_replay->release_gate_score) &&
	       score_valid(packet_replay->audit_gate_score) &&
	       score_valid(packet_audit->min_capability_readiness_score) &&
	       score_valid(packet_audit->min_release_gate_score) &&
	       score_valid(packet_audit->max_release_gate_score) &&
	       score_valid(packet_audit->avg_release_gate_score) &&
	       score_valid(packet_audit->min_audit_gate_score) &&
	       score_valid(packet_audit->max_audit_gate_score) &&
	       score_valid(packet_audit->avg_audit_gate_score);
}

static void verdict_invalid(
	struct pqcp_deployment_evidence_verdict *verdict,
	enum pqcp_deployment_release_gate_profile profile,
	uint32_t error_mask)
{
	if (verdict == NULL) {
		return;
	}

	memset(verdict, 0, sizeof(*verdict));
	verdict->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_SCHEMA_VERSION;
	verdict->status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL;
	verdict->error_mask = error_mask;
	verdict->profile = profile;
	verdict->min_chain_score = 0U;
	set_text(verdict->top_candidate_id, sizeof(verdict->top_candidate_id),
		 "none");
	set_zero_nonce(verdict->nonce_hex, sizeof(verdict->nonce_hex));
	set_zero_digest(verdict->trace_digest_hex,
			sizeof(verdict->trace_digest_hex));
	set_zero_digest(verdict->review_packet_digest_hex,
			sizeof(verdict->review_packet_digest_hex));
	set_zero_digest(verdict->device_packet_digest_hex,
			sizeof(verdict->device_packet_digest_hex));
	set_zero_digest(verdict->token_digest_hex,
			sizeof(verdict->token_digest_hex));
	set_zero_digest(verdict->packet_audit_digest_hex,
			sizeof(verdict->packet_audit_digest_hex));
	set_zero_digest(verdict->verdict_digest_hex,
			sizeof(verdict->verdict_digest_hex));
}

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0x4f1bbcdc59f3a0d7ULL;
	digest[1] = 0x9e3779b97f4a7c15ULL;
	digest[2] = 0xd6e8feb86659fd93ULL;
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
	digest[1] += digest[0] ^ ((uint64_t)value << 3U);
	digest[1] = rotl64(digest[1], 23U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + digest[0] + 0x94d049bb133111ebULL;
	digest[2] = rotl64(digest[2], 37U);
	digest[3] += digest[2] ^ (digest[1] >> 9U);
	digest[3] = rotl64(digest[3], 47U);
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
	char out[PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(
		out,
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U,
		"%016llx%016llx%016llx%016llx",
		(unsigned long long)digest[0],
		(unsigned long long)digest[1],
		(unsigned long long)digest[2],
		(unsigned long long)digest[3]);
}

static void compute_verdict_digest(
	struct pqcp_deployment_evidence_verdict *verdict)
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest, verdict->schema_version);
	digest_update_u32(digest, (uint32_t)verdict->status);
	digest_update_u32(digest, verdict->error_mask);
	digest_update_u32(digest, verdict->warning_mask);
	digest_update_u32(digest, (uint32_t)verdict->profile);
	digest_update_u32(digest, verdict->verdict_score);
	digest_update_u32(digest, verdict->min_chain_score);
	digest_update_u32(digest, verdict->stage_count);
	digest_update_u32(digest, verdict->pass_count);
	digest_update_u32(digest, verdict->warn_count);
	digest_update_u32(digest, verdict->fail_count);
	digest_update_u32(digest, verdict->consistency_checks);
	digest_update_u32(digest, verdict->consistency_pass_count);
	digest_update_u32(digest, verdict->evidence_capabilities_all);
	digest_update_u32(digest, verdict->evidence_capabilities_any);
	digest_update_bool(digest, verdict->top_consistent);
	digest_update_bool(digest, verdict->nonce_consistent);
	digest_update_bool(digest, verdict->trace_digest_consistent);
	digest_update_bool(digest, verdict->review_packet_digest_consistent);
	digest_update_bool(digest, verdict->device_packet_digest_consistent);
	digest_update_bool(digest, verdict->token_digest_consistent);
	digest_update_text(digest, verdict->top_candidate_id);
	digest_update_text(digest, verdict->nonce_hex);
	digest_update_text(digest, verdict->trace_digest_hex);
	digest_update_text(digest, verdict->review_packet_digest_hex);
	digest_update_text(digest, verdict->device_packet_digest_hex);
	digest_update_text(digest, verdict->token_digest_hex);
	digest_update_text(digest, verdict->packet_audit_digest_hex);
	digest_to_hex(digest, verdict->verdict_digest_hex);
}

static void consistency_count(
	struct pqcp_deployment_evidence_verdict *verdict,
	bool passed)
{
	verdict->consistency_checks++;
	if (passed) {
		verdict->consistency_pass_count++;
	}
}

static void apply_score_floor(
	struct pqcp_deployment_evidence_verdict *verdict,
	const struct pqcp_deployment_evidence_verdict_policy *policy)
{
	if (verdict->verdict_score < policy->min_verdict_score ||
	    verdict->min_chain_score < policy->min_verdict_score) {
		if (policy->score_floor_blocks) {
			verdict->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_SCORE_FLOOR;
		} else {
			verdict->warning_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_SCORE_FLOOR;
		}
	}
}

const char *pqcp_deployment_evidence_verdict_status_str(
	enum pqcp_deployment_evidence_verdict_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

int pqcp_deployment_evidence_verdict_default_policy(
	enum pqcp_deployment_release_gate_profile profile,
	struct pqcp_deployment_evidence_verdict_policy *policy)
{
	if (policy == NULL || !profile_valid(profile)) {
		return -EINVAL;
	}

	memset(policy, 0, sizeof(*policy));
	policy->profile = profile;
	policy->require_digest_consistency = true;
	policy->require_verdict_capability = true;
	policy->require_pipeline_pass = true;
	policy->require_planning_pass = true;
	policy->require_review_pass = true;

	switch (profile) {
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE:
		policy->min_verdict_score = 50U;
		policy->min_release_gate_score = 40U;
		policy->min_review_score = 40U;
		policy->min_capability_readiness_score = 50U;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER:
		policy->min_verdict_score = 65U;
		policy->min_release_gate_score = 60U;
		policy->min_review_score = 60U;
		policy->min_capability_readiness_score = 65U;
		policy->require_release_gate_pass = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT:
		policy->min_verdict_score = 75U;
		policy->min_release_gate_score = 70U;
		policy->min_review_score = 70U;
		policy->min_capability_readiness_score = 75U;
		policy->score_floor_blocks = true;
		policy->require_release_gate_pass = true;
		policy->require_device_token_pass = true;
		policy->require_device_gate_pass = true;
		policy->require_device_packet_pass = false;
		policy->require_device_packet_audit_pass = true;
		break;
	case PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER:
		policy->min_verdict_score = 70U;
		policy->min_release_gate_score = 65U;
		policy->min_review_score = 65U;
		policy->min_capability_readiness_score = 70U;
		policy->require_release_gate_pass = true;
		policy->require_device_token_pass = true;
		policy->require_device_gate_pass = true;
		policy->require_device_packet_audit_pass = true;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int pqcp_deployment_evidence_verdict_evaluate(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const struct pqcp_deployment_review_packet *review_packet,
	const struct pqcp_deployment_review_verifier_result *review_replay,
	const struct pqcp_deployment_review_audit_report *review_audit,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *device_token,
	const struct pqcp_deployment_device_token_verification *token_verify,
	const struct pqcp_deployment_device_token_replay_result *token_replay,
	const struct pqcp_deployment_device_token_audit_report *token_audit,
	const struct pqcp_deployment_device_gate_report *device_gate,
	const struct pqcp_deployment_device_packet *device_packet,
	const struct pqcp_deployment_device_packet_replay_result *packet_replay,
	const struct pqcp_deployment_device_packet_audit_report *packet_audit,
	const struct pqcp_deployment_evidence_verdict_policy *policy,
	struct pqcp_deployment_evidence_verdict *verdict)
{
	struct text_consistency top;
	struct text_consistency nonce;
	struct text_consistency trace_digest;
	struct text_consistency review_digest;
	struct text_consistency device_digest;
	struct text_consistency token_digest;
	uint32_t evidence_all;
	uint32_t evidence_any;
	uint32_t score;

	if (verdict == NULL) {
		return -EINVAL;
	}
	if (capability == NULL || pipeline == NULL || budget == NULL ||
	    experiments == NULL || review_packet == NULL ||
	    review_replay == NULL || review_audit == NULL ||
	    release_gate == NULL || device_token == NULL ||
	    token_verify == NULL || token_replay == NULL ||
	    token_audit == NULL || device_gate == NULL ||
	    device_packet == NULL || packet_replay == NULL ||
	    packet_audit == NULL || policy == NULL ||
	    !profile_valid(policy->profile)) {
		verdict_invalid(verdict, policy != NULL ? policy->profile :
				PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE,
				PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_INVALID_INPUT);
		return -EINVAL;
	}
	if (!input_shapes_valid(capability, pipeline, budget, experiments,
				review_packet, review_replay, review_audit,
				release_gate, device_token, token_verify,
				token_replay, token_audit, device_gate,
				device_packet, packet_replay, packet_audit,
				policy)) {
		verdict_invalid(verdict, policy->profile,
				PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_INVALID_INPUT);
		return -EINVAL;
	}

	memset(verdict, 0, sizeof(*verdict));
	verdict->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_SCHEMA_VERSION;
	verdict->profile = policy->profile;
	verdict->min_chain_score = 100U;
	verdict->evidence_capabilities_all = UINT32_MAX;

	stage_add(verdict, bool_stage(pqcp_capability_descriptor_validate(
					      capability) == 0 &&
				      capability->policy_passed));
	stage_add(verdict, bool_stage(pipeline->passed));
	stage_add(verdict, budget_stage(budget->status));
	stage_add(verdict, experiment_stage(experiments->status));
	stage_add(verdict, review_packet_stage(review_packet->status));
	stage_add(verdict, bool_stage(review_replay->passed));
	stage_add(verdict, review_audit_stage(review_audit->status));
	stage_add(verdict, release_gate_stage(release_gate->status));
	stage_add(verdict, token_stage(device_token->status));
	stage_add(verdict, bool_stage(token_verify->passed));
	stage_add(verdict, bool_stage(token_replay->passed));
	stage_add(verdict, token_audit_stage(token_audit->status));
	stage_add(verdict, device_gate_stage(device_gate->status));
	stage_add(verdict, device_packet_stage(device_packet->status));
	stage_add(verdict, bool_stage(packet_replay->passed));
	stage_add(verdict, packet_audit_stage(packet_audit->status));

	if (!capability->policy_passed ||
	    capability->evidence_readiness_score <
		    policy->min_capability_readiness_score) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_CAPABILITY;
	}
	if (policy->require_pipeline_pass && !pipeline->passed) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_PIPELINE;
	}
	if (policy->require_planning_pass &&
	    budget->status != PQCP_DEPLOYMENT_BUDGET_STATUS_PASS) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_BUDGET;
	}
	if (policy->require_planning_pass &&
	    experiments->status != PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_EXPERIMENTS;
	}
	if (policy->require_review_pass &&
	    review_packet->status != PQCP_DEPLOYMENT_REVIEW_PACKET_PASS) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_PACKET;
	}
	if (policy->require_review_pass && !review_replay->passed) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_REPLAY;
	}
	if (policy->require_review_pass &&
	    review_audit->status != PQCP_DEPLOYMENT_REVIEW_AUDIT_PASS) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_AUDIT;
	}
	if (policy->require_release_gate_pass &&
	    release_gate->status != PQCP_DEPLOYMENT_RELEASE_GATE_PASS) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_RELEASE_GATE;
	}
	if (policy->require_device_token_pass &&
	    (device_token->status != PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS ||
	     !token_verify->passed)) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_TOKEN;
	}
	if (policy->require_device_token_pass &&
	    (!token_replay->passed ||
	     token_audit->status != PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS)) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOKEN_REPLAY_AUDIT;
	}
	if (policy->require_device_gate_pass &&
	    device_gate->status != PQCP_DEPLOYMENT_DEVICE_GATE_PASS) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_GATE;
	}
	if (policy->require_device_packet_pass &&
	    device_packet->status != PQCP_DEPLOYMENT_DEVICE_PACKET_PASS) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_PACKET;
	} else if (device_packet->status !=
		   PQCP_DEPLOYMENT_DEVICE_PACKET_PASS) {
		verdict->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_DEVICE_PACKET;
	}
	if (policy->require_device_packet_audit_pass &&
	    (!packet_replay->passed ||
	     packet_audit->status !=
		     PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS)) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_PACKET_REPLAY_AUDIT;
	} else if (packet_audit->status !=
		   PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT_PASS) {
		verdict->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_PACKET_AUDIT;
	}

	if (budget->warning_mask != 0U || review_packet->warning_mask != 0U ||
	    review_audit->warning_mask != 0U ||
	    release_gate->warning_mask != 0U ||
	    device_token->warning_mask != 0U ||
	    token_audit->warning_mask != 0U ||
	    device_gate->warning_mask != 0U ||
	    device_packet->warning_mask != 0U ||
	    packet_audit->warning_mask != 0U) {
		verdict->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_UPSTREAM_WARNINGS;
	}
	if (verdict->fail_count != 0U) {
		verdict->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_NOT_PRODUCT_PASS;
	}
	if (!capability->production_allowed || !device_packet->production_allowed) {
		verdict->warning_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_LOCAL_ONLY;
	}

	text_consistency_init(&top);
	text_consistency_add(&top, pipeline->top_candidate_id,
			     text_present(pipeline->top_candidate_id));
	text_consistency_add(&top, budget->top_candidate_id,
			     text_present(budget->top_candidate_id));
	text_consistency_add(&top, experiments->top_candidate_id,
			     text_present(experiments->top_candidate_id));
	text_consistency_add(&top, review_packet->top_candidate_id,
			     text_present(review_packet->top_candidate_id));
	text_consistency_add(&top, review_replay->top_candidate_id,
			     text_present(review_replay->top_candidate_id));
	text_consistency_add(&top, review_audit->top_candidate_id,
			     text_present(review_audit->top_candidate_id));
	text_consistency_add(&top, release_gate->top_candidate_id,
			     text_present(release_gate->top_candidate_id));
	text_consistency_add(&top, device_token->top_candidate_id,
			     text_present(device_token->top_candidate_id));
	text_consistency_add(&top, token_replay->top_candidate_id,
			     text_present(token_replay->top_candidate_id));
	text_consistency_add(&top, token_audit->top_candidate_id,
			     text_present(token_audit->top_candidate_id));
	text_consistency_add(&top, device_gate->top_candidate_id,
			     text_present(device_gate->top_candidate_id));
	text_consistency_add(&top, device_packet->top_candidate_id,
			     text_present(device_packet->top_candidate_id));
	text_consistency_add(&top, packet_replay->top_candidate_id,
			     text_present(packet_replay->top_candidate_id));
	text_consistency_add(&top, packet_audit->top_candidate_id,
			     text_present(packet_audit->top_candidate_id));
	verdict->top_consistent = text_consistency_passed(&top);
	consistency_count(verdict, verdict->top_consistent);
	set_text(verdict->top_candidate_id, sizeof(verdict->top_candidate_id),
		 verdict->top_consistent ? top.value : "none");
	if (!verdict->top_consistent && policy->require_digest_consistency) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOP_MISMATCH;
	}

	text_consistency_init(&nonce);
	text_consistency_add(&nonce, device_token->nonce_hex,
			     nonce_valid(device_token->nonce_hex));
	text_consistency_add(&nonce, token_replay->nonce_hex,
			     nonce_valid(token_replay->nonce_hex));
	text_consistency_add(&nonce, token_audit->nonce_hex,
			     nonce_valid(token_audit->nonce_hex));
	text_consistency_add(&nonce, device_gate->nonce_hex,
			     nonce_valid(device_gate->nonce_hex));
	text_consistency_add(&nonce, device_packet->nonce_hex,
			     nonce_valid(device_packet->nonce_hex));
	text_consistency_add(&nonce, packet_replay->nonce_hex,
			     nonce_valid(packet_replay->nonce_hex));
	text_consistency_add(&nonce, packet_audit->nonce_hex,
			     nonce_valid(packet_audit->nonce_hex));
	verdict->nonce_consistent = text_consistency_passed(&nonce);
	consistency_count(verdict, verdict->nonce_consistent);
	if (verdict->nonce_consistent) {
		set_text(verdict->nonce_hex, sizeof(verdict->nonce_hex),
			 nonce.value);
	} else {
		set_zero_nonce(verdict->nonce_hex, sizeof(verdict->nonce_hex));
		if (policy->require_digest_consistency) {
			verdict->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_NONCE_MISMATCH;
		}
	}

	text_consistency_init(&trace_digest);
	text_consistency_add(&trace_digest, pipeline->trace_digest.digest_hex,
			     trace_digest_valid(
				     pipeline->trace_digest.digest_hex));
	text_consistency_add(&trace_digest, review_packet->trace_digest_hex,
			     trace_digest_valid(review_packet->trace_digest_hex));
	text_consistency_add(&trace_digest, review_replay->trace_digest_hex,
			     trace_digest_valid(review_replay->trace_digest_hex));
	text_consistency_add(&trace_digest, review_audit->trace_digest_hex,
			     trace_digest_valid(review_audit->trace_digest_hex));
	text_consistency_add(&trace_digest, release_gate->trace_digest_hex,
			     trace_digest_valid(release_gate->trace_digest_hex));
	text_consistency_add(&trace_digest, device_token->trace_digest_hex,
			     trace_digest_valid(device_token->trace_digest_hex));
	text_consistency_add(&trace_digest, device_gate->trace_digest_hex,
			     trace_digest_valid(device_gate->trace_digest_hex));
	text_consistency_add(&trace_digest, device_packet->trace_digest_hex,
			     trace_digest_valid(device_packet->trace_digest_hex));
	verdict->trace_digest_consistent =
		text_consistency_passed(&trace_digest);
	consistency_count(verdict, verdict->trace_digest_consistent);
	if (verdict->trace_digest_consistent) {
		set_text(verdict->trace_digest_hex,
			 sizeof(verdict->trace_digest_hex),
			 trace_digest.value);
	} else {
		set_zero_digest(verdict->trace_digest_hex,
				sizeof(verdict->trace_digest_hex));
		if (policy->require_digest_consistency) {
			verdict->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TRACE_DIGEST;
		}
	}

	text_consistency_init(&review_digest);
	text_consistency_add(&review_digest, review_packet->packet_digest_hex,
			     review_digest_valid(
				     review_packet->packet_digest_hex));
	text_consistency_add(&review_digest, review_replay->computed_digest_hex,
			     review_digest_valid(
				     review_replay->computed_digest_hex));
	text_consistency_add(&review_digest, review_audit->packet_digest_hex,
			     review_digest_valid(review_audit->packet_digest_hex));
	text_consistency_add(&review_digest, release_gate->packet_digest_hex,
			     review_digest_valid(release_gate->packet_digest_hex));
	text_consistency_add(&review_digest, device_token->packet_digest_hex,
			     review_digest_valid(device_token->packet_digest_hex));
	text_consistency_add(&review_digest, device_gate->packet_digest_hex,
			     review_digest_valid(device_gate->packet_digest_hex));
	text_consistency_add(&review_digest, device_packet->packet_digest_hex,
			     review_digest_valid(device_packet->packet_digest_hex));
	verdict->review_packet_digest_consistent =
		text_consistency_passed(&review_digest);
	consistency_count(verdict,
			  verdict->review_packet_digest_consistent);
	if (verdict->review_packet_digest_consistent) {
		set_text(verdict->review_packet_digest_hex,
			 sizeof(verdict->review_packet_digest_hex),
			 review_digest.value);
	} else {
		set_zero_digest(verdict->review_packet_digest_hex,
				sizeof(verdict->review_packet_digest_hex));
		if (policy->require_digest_consistency) {
			verdict->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_REVIEW_DIGEST;
		}
	}

	text_consistency_init(&device_digest);
	text_consistency_add(&device_digest,
			     device_packet->device_packet_digest_hex,
			     device_digest_valid(
				     device_packet->device_packet_digest_hex));
	text_consistency_add(&device_digest, packet_replay->computed_digest_hex,
			     device_digest_valid(
				     packet_replay->computed_digest_hex));
	text_consistency_add(&device_digest, packet_audit->packet_digest_hex,
			     device_digest_valid(packet_audit->packet_digest_hex));
	verdict->device_packet_digest_consistent =
		text_consistency_passed(&device_digest);
	consistency_count(verdict,
			  verdict->device_packet_digest_consistent);
	if (verdict->device_packet_digest_consistent) {
		set_text(verdict->device_packet_digest_hex,
			 sizeof(verdict->device_packet_digest_hex),
			 device_digest.value);
	} else {
		set_zero_digest(verdict->device_packet_digest_hex,
				sizeof(verdict->device_packet_digest_hex));
		if (policy->require_digest_consistency) {
			verdict->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_DEVICE_DIGEST;
		}
	}

	text_consistency_init(&token_digest);
	text_consistency_add(&token_digest, device_token->token_digest_hex,
			     token_digest_valid(device_token->token_digest_hex));
	text_consistency_add(&token_digest, token_verify->expected_digest_hex,
			     token_digest_valid(
				     token_verify->expected_digest_hex));
	text_consistency_add(&token_digest, token_verify->observed_digest_hex,
			     token_digest_valid(
				     token_verify->observed_digest_hex));
	text_consistency_add(&token_digest, token_replay->token_digest_hex,
			     token_digest_valid(token_replay->token_digest_hex));
	text_consistency_add(&token_digest, token_replay->computed_digest_hex,
			     token_digest_valid(
				     token_replay->computed_digest_hex));
	text_consistency_add(&token_digest, token_audit->token_digest_hex,
			     token_digest_valid(token_audit->token_digest_hex));
	text_consistency_add(&token_digest, device_gate->token_digest_hex,
			     token_digest_valid(device_gate->token_digest_hex));
	text_consistency_add(&token_digest, device_packet->token_digest_hex,
			     token_digest_valid(device_packet->token_digest_hex));
	verdict->token_digest_consistent =
		text_consistency_passed(&token_digest);
	consistency_count(verdict, verdict->token_digest_consistent);
	if (verdict->token_digest_consistent) {
		set_text(verdict->token_digest_hex,
			 sizeof(verdict->token_digest_hex),
			 token_digest.value);
	} else {
		set_zero_digest(verdict->token_digest_hex,
				sizeof(verdict->token_digest_hex));
		if (policy->require_digest_consistency) {
			verdict->error_mask |=
				PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_TOKEN_DIGEST;
		}
	}

	set_text(verdict->packet_audit_digest_hex,
		 sizeof(verdict->packet_audit_digest_hex),
		 packet_audit->audit_digest_hex);

	evidence_all = capability->evidence_capabilities;
	evidence_any = capability->evidence_capabilities;
	evidence_all &= device_token->evidence_capabilities;
	evidence_any |= device_token->evidence_capabilities;
	evidence_all &= device_gate->evidence_capabilities;
	evidence_any |= device_gate->evidence_capabilities;
	evidence_all &= device_packet->evidence_capabilities;
	evidence_any |= device_packet->evidence_capabilities;
	evidence_all &= packet_replay->evidence_capabilities;
	evidence_any |= packet_replay->evidence_capabilities;
	evidence_all &= packet_audit->evidence_capabilities_all;
	evidence_any |= packet_audit->evidence_capabilities_any;
	verdict->evidence_capabilities_all = evidence_all;
	verdict->evidence_capabilities_any = evidence_any;
	consistency_count(verdict, evidence_all != 0U);

	if (policy->require_verdict_capability &&
	    (evidence_all &
	     PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_EVIDENCE_VERDICT) == 0U) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_CAPABILITY_MISMATCH;
	}

	min_score_update(&verdict->min_chain_score,
			 capability->evidence_readiness_score);
	min_score_update(&verdict->min_chain_score,
			 pipeline->top_candidate_score);
	min_score_update(&verdict->min_chain_score,
			 budget->top_margin_score);
	min_score_update(&verdict->min_chain_score,
			 budget->pipeline_readiness_score);
	min_score_update(&verdict->min_chain_score, budget->claim_score);
	min_score_update(&verdict->min_chain_score,
			 review_packet->readiness_score);
	min_score_update(&verdict->min_chain_score,
			 review_packet->claim_score);
	min_score_update(&verdict->min_chain_score,
			 review_packet->review_score);
	min_score_update(&verdict->min_chain_score,
			 review_replay->readiness_score);
	min_score_update(&verdict->min_chain_score,
			 review_replay->claim_score);
	min_score_update(&verdict->min_chain_score,
			 review_replay->review_score);
	min_score_update(&verdict->min_chain_score,
			 review_audit->min_readiness_score);
	min_score_update(&verdict->min_chain_score,
			 review_audit->min_claim_score);
	min_score_update(&verdict->min_chain_score,
			 review_audit->min_review_score);
	min_score_update(&verdict->min_chain_score,
			 release_gate->gate_score);
	min_score_update(&verdict->min_chain_score,
			 device_token->capability_readiness_score);
	min_score_update(&verdict->min_chain_score, device_token->gate_score);
	min_score_update(&verdict->min_chain_score,
			 token_replay->capability_readiness_score);
	min_score_update(&verdict->min_chain_score, token_replay->gate_score);
	min_score_update(&verdict->min_chain_score,
			 token_audit->min_capability_readiness_score);
	min_score_update(&verdict->min_chain_score, token_audit->min_gate_score);
	min_score_update(&verdict->min_chain_score,
			 device_gate->capability_readiness_score);
	min_score_update(&verdict->min_chain_score,
			 device_gate->release_gate_score);
	min_score_update(&verdict->min_chain_score,
			 device_gate->audit_min_gate_score);
	min_score_update(&verdict->min_chain_score,
			 device_packet->capability_readiness_score);
	min_score_update(&verdict->min_chain_score,
			 device_packet->release_gate_score);
	min_score_update(&verdict->min_chain_score,
			 device_packet->audit_min_gate_score);
	min_score_update(&verdict->min_chain_score,
			 packet_replay->capability_readiness_score);
	min_score_update(&verdict->min_chain_score,
			 packet_replay->release_gate_score);
	min_score_update(&verdict->min_chain_score,
			 packet_replay->audit_gate_score);
	min_score_update(&verdict->min_chain_score,
			 packet_audit->min_capability_readiness_score);
	min_score_update(&verdict->min_chain_score,
			 packet_audit->min_release_gate_score);
	min_score_update(&verdict->min_chain_score,
			 packet_audit->min_audit_gate_score);

	score = verdict->min_chain_score;
	score = score_penalty(score, verdict->fail_count * 10U);
	score = score_penalty(score, verdict->warn_count * 3U);
	score = score_penalty(
		score,
		(verdict->consistency_checks - verdict->consistency_pass_count) *
			7U);
	verdict->verdict_score = score;
	apply_score_floor(verdict, policy);

	if (policy->require_all_pass && verdict->fail_count != 0U) {
		verdict->error_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_RELEASE_GATE;
	}

	if (verdict->error_mask != 0U) {
		verdict->status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL;
	} else if (verdict->warning_mask != 0U || verdict->warn_count != 0U) {
		verdict->status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN;
	} else {
		verdict->status = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
	}

	compute_verdict_digest(verdict);

	return verdict->status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL ?
		-EBADMSG : 0;
}

int pqcp_deployment_evidence_verdict_emit(
	const struct pqcp_deployment_evidence_verdict *verdict)
{
	if (verdict == NULL ||
	    verdict->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_VERDICT_SCHEMA_VERSION ||
	    !verdict_status_valid(verdict->status) ||
	    !profile_valid(verdict->profile) ||
	    (verdict->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_KNOWN_MASK) != 0U ||
	    (verdict->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_KNOWN_MASK) != 0U ||
	    verdict->verdict_score > 100U ||
	    verdict->min_chain_score > 100U ||
	    !text_present(verdict->top_candidate_id) ||
	    !nonce_valid(verdict->nonce_hex) ||
	    !trace_digest_valid(verdict->trace_digest_hex) ||
	    !review_digest_valid(verdict->review_packet_digest_hex) ||
	    !device_digest_valid(verdict->device_packet_digest_hex) ||
	    !token_digest_valid(verdict->token_digest_hex) ||
	    !device_digest_valid(verdict->packet_audit_digest_hex) ||
	    !device_digest_valid(verdict->verdict_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EVIDENCE_VERDICT schema=%u profile=%s status=%s errors=0x%08x warnings=0x%08x score=%u min_score=%u stages=%u pass=%u warn=%u fail=%u consistency=%u consistency_pass=%u evidence_all=0x%08x evidence_any=0x%08x top_consistent=%u nonce_consistent=%u trace_consistent=%u review_digest_consistent=%u device_digest_consistent=%u token_digest_consistent=%u top=%s nonce=%s trace_digest=%s review_digest=%s device_digest=%s token_digest=%s packet_audit_digest=%s verdict_digest=%s\n",
	       verdict->schema_version,
	       pqcp_deployment_release_gate_profile_str(verdict->profile),
	       pqcp_deployment_evidence_verdict_status_str(verdict->status),
	       verdict->error_mask,
	       verdict->warning_mask,
	       verdict->verdict_score,
	       verdict->min_chain_score,
	       verdict->stage_count,
	       verdict->pass_count,
	       verdict->warn_count,
	       verdict->fail_count,
	       verdict->consistency_checks,
	       verdict->consistency_pass_count,
	       verdict->evidence_capabilities_all,
	       verdict->evidence_capabilities_any,
	       verdict->top_consistent ? 1U : 0U,
	       verdict->nonce_consistent ? 1U : 0U,
	       verdict->trace_digest_consistent ? 1U : 0U,
	       verdict->review_packet_digest_consistent ? 1U : 0U,
	       verdict->device_packet_digest_consistent ? 1U : 0U,
	       verdict->token_digest_consistent ? 1U : 0U,
	       verdict->top_candidate_id,
	       verdict->nonce_hex,
	       verdict->trace_digest_hex,
	       verdict->review_packet_digest_hex,
	       verdict->device_packet_digest_hex,
	       verdict->token_digest_hex,
	       verdict->packet_audit_digest_hex,
	       verdict->verdict_digest_hex);

	return verdict->status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL ?
		-EBADMSG : 0;
}
