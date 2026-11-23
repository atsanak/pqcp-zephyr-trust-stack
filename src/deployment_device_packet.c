/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware-native deployment device evidence packet builder.
 */

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_device_packet.h>

struct device_packet_builder {
	char *buffer;
	size_t capacity;
	size_t length;
	uint32_t line_count;
	uint32_t error_mask;
	uint64_t digest[4];
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

static bool packet_status_valid(
	enum pqcp_deployment_device_packet_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_PACKET_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL;
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

static bool device_gate_status_valid(
	enum pqcp_deployment_device_gate_status status)
{
	return status == PQCP_DEPLOYMENT_DEVICE_GATE_PASS ||
	       status == PQCP_DEPLOYMENT_DEVICE_GATE_WARN ||
	       status == PQCP_DEPLOYMENT_DEVICE_GATE_FAIL;
}

const char *pqcp_deployment_device_packet_status_str(
	enum pqcp_deployment_device_packet_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_DEVICE_PACKET_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0xf6e8d91d2b6a8f45ULL;
	digest[1] = 0x94d049bb133111ebULL;
	digest[2] = 0x2545f4914f6cdd1dULL;
	digest[3] = 0x9e3779b97f4a7c15ULL;
}

static uint64_t rotl64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= (uint64_t)value + 0x100000001b3ULL;
	digest[0] *= 0x100000001b3ULL;
	digest[1] += digest[0] ^ ((uint64_t)value << 7U);
	digest[1] = rotl64(digest[1], 19U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + digest[0] + 0x165667b19e3779f9ULL;
	digest[2] = rotl64(digest[2], 29U);
	digest[3] += digest[2] ^ (digest[1] >> 11U);
	digest[3] = rotl64(digest[3], 41U);
}

static void digest_update_line(uint64_t digest[4], const char *line)
{
	for (const char *p = line; *p != '\0'; ++p) {
		digest_update_byte(digest, (uint8_t)*p);
	}
	digest_update_byte(digest, (uint8_t)'\n');
}

static void digest_to_hex(const uint64_t digest[4], char out[
			  PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(out,
		       PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS + 1U,
		       "%016llx%016llx%016llx%016llx",
		       (unsigned long long)digest[0],
		       (unsigned long long)digest[1],
		       (unsigned long long)digest[2],
		       (unsigned long long)digest[3]);
}

static int builder_init(struct device_packet_builder *builder,
			char *buffer,
			size_t capacity)
{
	if (builder == NULL || buffer == NULL || capacity < 2U) {
		return -EINVAL;
	}

	memset(builder, 0, sizeof(*builder));
	memset(buffer, 0, capacity);
	builder->buffer = buffer;
	builder->capacity = capacity;
	digest_init(builder->digest);

	return 0;
}

static int append_line(struct device_packet_builder *builder,
		       const char *fmt,
		       ...)
{
	char line[PQCP_DEPLOYMENT_DEVICE_PACKET_LINE_MAX];
	va_list args;
	size_t len;
	int written;

	if (builder == NULL || builder->buffer == NULL || fmt == NULL) {
		return -EINVAL;
	}

	va_start(args, fmt);
	written = vsnprintk(line, sizeof(line), fmt, args);
	va_end(args);
	if (written < 0 || written >= (int)sizeof(line)) {
		builder->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_OVERFLOW;
		return -ENOSPC;
	}

	len = strlen(line);
	if (len + 2U > builder->capacity - builder->length) {
		builder->error_mask |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_OVERFLOW;
		return -ENOSPC;
	}

	memcpy(&builder->buffer[builder->length], line, len);
	builder->length += len;
	builder->buffer[builder->length++] = '\n';
	builder->buffer[builder->length] = '\0';
	builder->line_count++;
	digest_update_line(builder->digest, line);

	return 0;
}

static bool strings_match(const char *a, const char *b)
{
	return text_present(a) && text_present(b) && strcmp(a, b) == 0;
}

static bool scores_valid(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_report *device_gate)
{
	return capability->evidence_readiness_score <= 100U &&
	       release_gate->gate_score <= 100U &&
	       token->capability_readiness_score <= 100U &&
	       token->gate_score <= 100U &&
	       replay->capability_readiness_score <= 100U &&
	       replay->gate_score <= 100U &&
	       audit->min_capability_readiness_score <= 100U &&
	       audit->min_gate_score <= 100U &&
	       audit->max_gate_score <= 100U &&
	       audit->avg_gate_score <= 100U &&
	       device_gate->capability_readiness_score <= 100U &&
	       device_gate->release_gate_score <= 100U &&
	       device_gate->audit_min_gate_score <= 100U;
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
	       (replay->marker_mask &
		~PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK) == 0U &&
	       token_status_valid(replay->token_status) &&
	       release_gate_status_valid(replay->gate_status) &&
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
	       text_present(audit->nonce_hex) &&
	       text_present(audit->top_candidate_id) &&
	       text_present(audit->token_digest_hex);
}

static bool device_gate_valid(
	const struct pqcp_deployment_device_gate_report *device_gate)
{
	return device_gate != NULL &&
	       device_gate->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_GATE_SCHEMA_VERSION &&
	       profile_valid(device_gate->profile) &&
	       device_gate_status_valid(device_gate->status) &&
	       release_gate_status_valid(device_gate->release_gate_status) &&
	       token_status_valid(device_gate->token_status) &&
	       audit_status_valid(device_gate->audit_status) &&
	       (device_gate->error_mask &
		~PQCP_DEPLOYMENT_DEVICE_GATE_ERROR_KNOWN_MASK) == 0U &&
	       (device_gate->warning_mask &
		~PQCP_DEPLOYMENT_DEVICE_GATE_WARNING_KNOWN_MASK) == 0U &&
	       text_present(device_gate->top_candidate_id) &&
	       text_present(device_gate->nonce_hex) &&
	       text_present(device_gate->trace_digest_hex) &&
	       text_present(device_gate->packet_digest_hex) &&
	       text_present(device_gate->token_digest_hex);
}

static void packet_invalid(struct pqcp_deployment_device_packet *packet,
			   uint32_t error_mask)
{
	if (packet == NULL) {
		return;
	}

	memset(packet, 0, sizeof(*packet));
	packet->schema_version = PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION;
	packet->status = PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL;
	packet->error_mask = error_mask;
	packet->profile = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
	packet->release_gate_status = PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
	packet->token_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;
	packet->audit_status = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL;
	packet->device_gate_status = PQCP_DEPLOYMENT_DEVICE_GATE_FAIL;
	(void)snprintk(packet->top_candidate_id,
		       sizeof(packet->top_candidate_id), "%s", "none");
	(void)snprintk(packet->nonce_hex, sizeof(packet->nonce_hex), "%s",
		       "00000000000000000000000000000000");
	(void)snprintk(packet->trace_digest_hex,
		       sizeof(packet->trace_digest_hex), "%s", "none");
	(void)snprintk(packet->packet_digest_hex,
		       sizeof(packet->packet_digest_hex), "%s", "none");
	(void)snprintk(packet->token_digest_hex,
		       sizeof(packet->token_digest_hex), "%s", "none");
	(void)snprintk(packet->device_packet_digest_hex,
		       sizeof(packet->device_packet_digest_hex), "%s", "none");
}

static int validate_inputs(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_report *device_gate,
	const char *buffer,
	size_t buffer_size,
	struct pqcp_deployment_device_packet *packet)
{
	if (capability == NULL || release_gate == NULL || token == NULL ||
	    verification == NULL || replay == NULL || audit == NULL ||
	    device_gate == NULL || buffer == NULL || packet == NULL ||
	    buffer_size < 2U ||
	    pqcp_capability_descriptor_validate(capability) != 0 ||
	    !release_gate_valid(release_gate) || !token_valid(token) ||
	    !verification_valid(verification) || !replay_valid(replay) ||
	    !audit_valid(audit) || !device_gate_valid(device_gate) ||
	    !scores_valid(capability, release_gate, token, replay, audit,
			  device_gate)) {
		packet_invalid(packet,
			       PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_INVALID_INPUT);
		return -EINVAL;
	}

	return 0;
}

static void copy_packet_fields(
	struct pqcp_deployment_device_packet *packet,
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_report *device_gate)
{
	memset(packet, 0, sizeof(*packet));
	packet->schema_version = PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION;
	packet->profile = device_gate->profile;
	packet->evidence_capabilities = capability->evidence_capabilities;
	packet->capability_readiness_score =
		capability->evidence_readiness_score;
	packet->release_gate_score = release_gate->gate_score;
	packet->audit_min_gate_score = audit->min_gate_score;
	packet->release_gate_status = release_gate->status;
	packet->token_status = token->status;
	packet->audit_status = audit->status;
	packet->device_gate_status = device_gate->status;
	packet->capability_policy_passed = capability->policy_passed;
	packet->production_allowed = capability->production_allowed;
	packet->native_provider =
		capability->provider_summary ==
		PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE;
	packet->verification_passed = verification->passed;
	packet->replay_passed = replay->passed;
	(void)snprintk(packet->top_candidate_id,
		       sizeof(packet->top_candidate_id), "%s",
		       device_gate->top_candidate_id);
	(void)snprintk(packet->nonce_hex, sizeof(packet->nonce_hex), "%s",
		       device_gate->nonce_hex);
	(void)snprintk(packet->trace_digest_hex,
		       sizeof(packet->trace_digest_hex), "%s",
		       device_gate->trace_digest_hex);
	(void)snprintk(packet->packet_digest_hex,
		       sizeof(packet->packet_digest_hex), "%s",
		       device_gate->packet_digest_hex);
	(void)snprintk(packet->token_digest_hex,
		       sizeof(packet->token_digest_hex), "%s",
		       device_gate->token_digest_hex);
}

static void compute_consistency(
	struct pqcp_deployment_device_packet *packet,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_report *device_gate)
{
	packet->top_consistent =
		strings_match(release_gate->top_candidate_id,
			      token->top_candidate_id) &&
		strings_match(release_gate->top_candidate_id,
			      replay->top_candidate_id) &&
		strings_match(release_gate->top_candidate_id,
			      audit->top_candidate_id) &&
		strings_match(release_gate->top_candidate_id,
			      device_gate->top_candidate_id) &&
		device_gate->top_consistent;
	packet->nonce_consistent =
		strings_match(token->nonce_hex, replay->nonce_hex) &&
		strings_match(token->nonce_hex, audit->nonce_hex) &&
		strings_match(token->nonce_hex, device_gate->nonce_hex) &&
		device_gate->nonce_consistent;
	packet->token_digest_consistent =
		strings_match(token->token_digest_hex,
			      verification->expected_digest_hex) &&
		strings_match(token->token_digest_hex,
			      verification->observed_digest_hex) &&
		strings_match(token->token_digest_hex,
			      replay->token_digest_hex) &&
		strings_match(token->token_digest_hex,
			      replay->computed_digest_hex) &&
		strings_match(token->token_digest_hex,
			      audit->token_digest_hex) &&
		strings_match(token->token_digest_hex,
			      device_gate->token_digest_hex) &&
		device_gate->token_digest_consistent;
	packet->release_digest_consistent =
		strings_match(release_gate->trace_digest_hex,
			      token->trace_digest_hex) &&
		strings_match(release_gate->packet_digest_hex,
			      token->packet_digest_hex) &&
		strings_match(release_gate->trace_digest_hex,
			      device_gate->trace_digest_hex) &&
		strings_match(release_gate->packet_digest_hex,
			      device_gate->packet_digest_hex) &&
		release_gate->digest_bound && token->gate_digest_bound &&
		device_gate->release_digest_consistent;
}

static uint32_t compute_errors(
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_report *device_gate,
	const struct pqcp_deployment_device_packet *packet)
{
	uint32_t errors = 0U;
	const bool has_packet_capability =
		(packet->evidence_capabilities &
		 PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET) != 0U;

	if (!has_packet_capability) {
		errors |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_MISSING_CAPABILITY;
	}
	if (release_gate->profile != token->profile ||
	    release_gate->profile != device_gate->profile ||
	    release_gate->profile != packet->profile) {
		errors |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_PROFILE_MISMATCH;
	}
	if (!packet->top_consistent) {
		errors |= PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_TOP_MISMATCH;
	}
	if (!packet->nonce_consistent) {
		errors |= PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_NONCE_MISMATCH;
	}
	if (!packet->token_digest_consistent) {
		errors |= PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_TOKEN_DIGEST;
	}
	if (!packet->release_digest_consistent) {
		errors |= PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_RELEASE_DIGEST;
	}
	if (device_gate->status == PQCP_DEPLOYMENT_DEVICE_GATE_FAIL) {
		errors |= PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_DEVICE_GATE;
	}
	if (!verification->passed || !replay->passed) {
		errors |= PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_REPLAY;
	}
	if (device_gate->release_gate_status != release_gate->status ||
	    device_gate->token_status != token->status ||
	    device_gate->audit_status != audit->status ||
	    replay->token_status != token->status ||
	    replay->gate_status != release_gate->status) {
		errors |=
			PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_STATUS_MISMATCH;
	}

	return errors;
}

static uint32_t compute_warnings(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_report *device_gate)
{
	uint32_t warnings = 0U;

	if (device_gate->status == PQCP_DEPLOYMENT_DEVICE_GATE_WARN) {
		warnings |= PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_DEVICE_GATE;
	}
	if (release_gate->status != PQCP_DEPLOYMENT_RELEASE_GATE_PASS) {
		warnings |= PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_RELEASE_GATE;
	}
	if (token->status != PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS) {
		warnings |= PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_TOKEN;
	}
	if (audit->status != PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS) {
		warnings |= PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_AUDIT;
	}
	if (!capability->production_allowed) {
		warnings |= PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_NOT_PRODUCTION;
	}
	if (capability->provider_summary !=
	    PQCP_CAPABILITY_PROVIDER_PQCP_NATIVE) {
		warnings |= PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_NON_NATIVE;
	}
	if (capability->evidence_readiness_score < 80U ||
	    release_gate->gate_score < 80U || audit->min_gate_score < 80U) {
		warnings |= PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_LOW_SCORE;
	}

	return warnings;
}

static enum pqcp_deployment_device_packet_status compute_status(
	uint32_t errors,
	uint32_t warnings)
{
	if (errors != 0U) {
		return PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL;
	}
	if (warnings != 0U) {
		return PQCP_DEPLOYMENT_DEVICE_PACKET_WARN;
	}

	return PQCP_DEPLOYMENT_DEVICE_PACKET_PASS;
}

static int append_facts(
	struct device_packet_builder *builder,
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_report *device_gate)
{
	int ret;

	ret = append_line(
		builder,
		"PQCP_DEPLOYMENT_DEVICE_FACT schema=%u field=capability profile=%s policy=%s production_allowed=%u provider=%s evidence=0x%08x readiness=%u",
		PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION,
		pqcp_firmware_policy_profile_str(capability->profile),
		capability->policy_passed ? "PASS" : "FAIL",
		capability->production_allowed ? 1U : 0U,
		pqcp_capability_provider_summary_str(
			capability->provider_summary),
		capability->evidence_capabilities,
		capability->evidence_readiness_score);
	if (ret != 0) {
		return ret;
	}

	ret = append_line(
		builder,
		"PQCP_DEPLOYMENT_DEVICE_FACT schema=%u field=release profile=%s status=%s errors=0x%08x warnings=0x%08x gate_score=%u top=%s trace_digest=%s packet_digest=%s",
		PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION,
		pqcp_deployment_release_gate_profile_str(release_gate->profile),
		pqcp_deployment_release_gate_status_str(release_gate->status),
		release_gate->error_mask,
		release_gate->warning_mask,
		release_gate->gate_score,
		release_gate->top_candidate_id,
		release_gate->trace_digest_hex,
		release_gate->packet_digest_hex);
	if (ret != 0) {
		return ret;
	}

	ret = append_line(
		builder,
		"PQCP_DEPLOYMENT_DEVICE_FACT schema=%u field=token profile=%s status=%s errors=0x%08x warnings=0x%08x nonce=%s cap_readiness=%u gate_score=%u top=%s token_digest=%s",
		PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION,
		pqcp_deployment_release_gate_profile_str(token->profile),
		pqcp_deployment_device_token_status_str(token->status),
		token->error_mask,
		token->warning_mask,
		token->nonce_hex,
		token->capability_readiness_score,
		token->gate_score,
		token->top_candidate_id,
		token->token_digest_hex);
	if (ret != 0) {
		return ret;
	}

	ret = append_line(
		builder,
		"PQCP_DEPLOYMENT_DEVICE_FACT schema=%u field=replay status=%s lines=%u markers=0x%08x token_status=%s gate_status=%s top=%s nonce=%s digest=%s computed=%s",
		PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION,
		replay->passed ? "PASS" : "FAIL",
		replay->lines_seen,
		replay->marker_mask,
		pqcp_deployment_device_token_status_str(replay->token_status),
		pqcp_deployment_release_gate_status_str(replay->gate_status),
		replay->top_candidate_id,
		replay->nonce_hex,
		replay->token_digest_hex,
		replay->computed_digest_hex);
	if (ret != 0) {
		return ret;
	}

	ret = append_line(
		builder,
		"PQCP_DEPLOYMENT_DEVICE_FACT schema=%u field=audit status=%s errors=0x%08x warnings=0x%08x results=%u replay_pass=%u replay_fail=%u unique_tokens=%u top=%s nonce=%s token_digest=%s",
		PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION,
		pqcp_deployment_device_token_audit_status_str(audit->status),
		audit->error_mask,
		audit->warning_mask,
		audit->result_count,
		audit->replay_pass_count,
		audit->replay_fail_count,
		audit->unique_token_digest_count,
		audit->top_candidate_id,
		audit->nonce_hex,
		audit->token_digest_hex);
	if (ret != 0) {
		return ret;
	}

	return append_line(
		builder,
		"PQCP_DEPLOYMENT_DEVICE_FACT schema=%u field=device_gate profile=%s status=%s errors=0x%08x warnings=0x%08x cap_readiness=%u release_gate_score=%u audit_gate_score=%u top=%s nonce=%s token_digest=%s verify=%s replay=%s",
		PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION,
		pqcp_deployment_release_gate_profile_str(device_gate->profile),
		pqcp_deployment_device_gate_status_str(device_gate->status),
		device_gate->error_mask,
		device_gate->warning_mask,
		device_gate->capability_readiness_score,
		device_gate->release_gate_score,
		device_gate->audit_min_gate_score,
		device_gate->top_candidate_id,
		device_gate->nonce_hex,
		device_gate->token_digest_hex,
		verification->passed ? "PASS" : "FAIL",
		replay->passed ? "PASS" : "FAIL");
}

int pqcp_deployment_device_packet_build(
	const struct pqcp_capability_descriptor *capability,
	const struct pqcp_deployment_release_gate_report *release_gate,
	const struct pqcp_deployment_device_token *token,
	const struct pqcp_deployment_device_token_verification *verification,
	const struct pqcp_deployment_device_token_replay_result *replay,
	const struct pqcp_deployment_device_token_audit_report *audit,
	const struct pqcp_deployment_device_gate_report *device_gate,
	char *buffer,
	size_t buffer_size,
	struct pqcp_deployment_device_packet *packet)
{
	struct device_packet_builder builder;
	uint32_t errors;
	uint32_t warnings;
	int ret;

	ret = validate_inputs(capability, release_gate, token, verification,
			      replay, audit, device_gate, buffer, buffer_size,
			      packet);
	if (ret != 0) {
		return ret;
	}

	copy_packet_fields(packet, capability, release_gate, token,
			   verification, replay, audit, device_gate);
	compute_consistency(packet, release_gate, token, verification, replay,
			    audit, device_gate);

	errors = compute_errors(release_gate, token, verification, replay, audit,
				device_gate, packet);
	warnings = compute_warnings(capability, release_gate, token, audit,
				    device_gate);

	ret = builder_init(&builder, buffer, buffer_size);
	if (ret != 0) {
		packet->error_mask =
			errors |
			PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_INVALID_INPUT;
		packet->status = PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL;
		return ret;
	}
	ret = append_facts(&builder, capability, release_gate, token,
			   verification, replay, audit, device_gate);
	if (ret != 0) {
		errors |= builder.error_mask;
	}

	packet->line_count = builder.line_count;
	packet->byte_count = builder.length > UINT32_MAX ?
		UINT32_MAX : (uint32_t)builder.length;
	packet->error_mask = errors;
	packet->warning_mask = warnings;
	packet->status = compute_status(errors, warnings);
	digest_to_hex(builder.digest, packet->device_packet_digest_hex);

	if (ret != 0) {
		return ret;
	}

	return errors != 0U ? -EBADMSG : 0;
}

static bool packet_valid(const struct pqcp_deployment_device_packet *packet)
{
	return packet != NULL &&
	       packet->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION &&
	       packet_status_valid(packet->status) &&
	       profile_valid(packet->profile) &&
	       release_gate_status_valid(packet->release_gate_status) &&
	       token_status_valid(packet->token_status) &&
	       audit_status_valid(packet->audit_status) &&
	       device_gate_status_valid(packet->device_gate_status) &&
	       (packet->error_mask &
		~PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_KNOWN_MASK) == 0U &&
	       (packet->warning_mask &
		~PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_KNOWN_MASK) == 0U &&
	       packet->capability_readiness_score <= 100U &&
	       packet->release_gate_score <= 100U &&
	       packet->audit_min_gate_score <= 100U &&
	       text_present(packet->top_candidate_id) &&
	       text_present(packet->nonce_hex) &&
	       text_present(packet->trace_digest_hex) &&
	       text_present(packet->packet_digest_hex) &&
	       text_present(packet->token_digest_hex) &&
	       text_present(packet->device_packet_digest_hex);
}

int pqcp_deployment_device_packet_emit_facts(
	const char *buffer,
	const struct pqcp_deployment_device_packet *packet)
{
	if (buffer == NULL || !packet_valid(packet)) {
		return -EINVAL;
	}
	if (packet->byte_count != strlen(buffer)) {
		return -EBADMSG;
	}

	printk("%s", buffer);
	return 0;
}

int pqcp_deployment_device_packet_emit(
	const struct pqcp_deployment_device_packet *packet)
{
	if (!packet_valid(packet)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_DEVICE_PACKET schema=%u status=%s errors=0x%08x warnings=0x%08x lines=%u bytes=%u evidence=0x%08x profile=%s cap_readiness=%u release_gate_score=%u audit_gate_score=%u device_gate=%s release=%s token=%s verify=%s replay=%s audit=%s top=%s nonce=%s trace_digest=%s packet_digest=%s token_digest=%s digest=%s\n",
	       packet->schema_version,
	       pqcp_deployment_device_packet_status_str(packet->status),
	       packet->error_mask,
	       packet->warning_mask,
	       packet->line_count,
	       packet->byte_count,
	       packet->evidence_capabilities,
	       pqcp_deployment_release_gate_profile_str(packet->profile),
	       packet->capability_readiness_score,
	       packet->release_gate_score,
	       packet->audit_min_gate_score,
	       pqcp_deployment_device_gate_status_str(
		       packet->device_gate_status),
	       pqcp_deployment_release_gate_status_str(
		       packet->release_gate_status),
	       pqcp_deployment_device_token_status_str(packet->token_status),
	       packet->verification_passed ? "PASS" : "FAIL",
	       packet->replay_passed ? "PASS" : "FAIL",
	       pqcp_deployment_device_token_audit_status_str(
		       packet->audit_status),
	       packet->top_candidate_id,
	       packet->nonce_hex,
	       packet->trace_digest_hex,
	       packet->packet_digest_hex,
	       packet->token_digest_hex,
	       packet->device_packet_digest_hex);

	return packet->status == PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL ?
		-EBADMSG : 0;
}
