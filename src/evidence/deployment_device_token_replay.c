/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware-native deployment device-token transcript replay verifier.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_device_token_replay.h>

#define FIELD_VALUE_MAX 160U
#define REPLAY_LINE_MAX 1024U

static bool starts_with(const char *value, const char *prefix)
{
	return strncmp(value, prefix, strlen(prefix)) == 0;
}

static bool has_text(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static int fail_once(
	struct pqcp_deployment_device_token_replay_state *state,
	enum pqcp_deployment_device_token_replay_error error)
{
	if (state != NULL &&
	    state->first_error ==
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONE) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}

	return -EBADMSG;
}

const char *pqcp_deployment_device_token_replay_error_str(
	enum pqcp_deployment_device_token_replay_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_DUPLICATE_MARKER:
		return "duplicate_marker";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MISSING_REQUIRED:
		return "missing_required";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_UNKNOWN_MARKER:
		return "unknown_marker";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONCE_MISMATCH:
		return "nonce_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_CAPABILITY_MISMATCH:
		return "capability_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_RELEASE_GATE_MISMATCH:
		return "release_gate_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH:
		return "token_digest_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_VERIFY_MISMATCH:
		return "verify_mismatch";
	default:
		return "unknown";
	}
}

static int clean_line(const char *input, char *out, size_t out_len)
{
	size_t len;

	if (input == NULL || out == NULL || out_len == 0U) {
		return -EINVAL;
	}

	len = strnlen(input, out_len);
	if (len == 0U || len >= out_len) {
		return -EINVAL;
	}
	while (len > 0U &&
	       (input[len - 1U] == '\n' || input[len - 1U] == '\r')) {
		len--;
	}
	if (len == 0U || len >= out_len) {
		return -EINVAL;
	}

	memcpy(out, input, len);
	out[len] = '\0';
	return 0;
}

static int field_value(const char *line, const char *key, char *out,
		       size_t out_len)
{
	size_t key_len;
	const char *p = line;

	if (line == NULL || key == NULL || out == NULL || out_len == 0U) {
		return -EINVAL;
	}
	key_len = strlen(key);

	while (*p != '\0') {
		if ((p == line || *(p - 1) == ' ') &&
		    strncmp(p, key, key_len) == 0 &&
		    p[key_len] == '=') {
			const char *value = p + key_len + 1U;
			size_t len = 0U;

			while (value[len] != '\0' && value[len] != ' ') {
				len++;
			}
			if (len == 0U || len >= out_len) {
				return -EINVAL;
			}
			memcpy(out, value, len);
			out[len] = '\0';
			return 0;
		}
		p++;
	}

	return -ENOENT;
}

static int get_field(const char *line, const char *key, char *out,
		     size_t out_len)
{
	return field_value(line, key, out, out_len) == 0 ? 0 : -EINVAL;
}

static int parse_u32_dec(const char *value, uint32_t *out)
{
	uint32_t result = 0U;

	if (value == NULL || out == NULL || *value == '\0') {
		return -EINVAL;
	}

	for (const char *p = value; *p != '\0'; ++p) {
		if (*p < '0' || *p > '9') {
			return -EINVAL;
		}
		if (result > (UINT32_MAX - (uint32_t)(*p - '0')) / 10U) {
			return -EINVAL;
		}
		result = (result * 10U) + (uint32_t)(*p - '0');
	}

	*out = result;
	return 0;
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}

	return -1;
}

static int parse_u32_hex(const char *value, uint32_t *out)
{
	uint32_t result = 0U;
	const char *p = value;

	if (value == NULL || out == NULL || *value == '\0') {
		return -EINVAL;
	}
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		p += 2;
		if (*p == '\0') {
			return -EINVAL;
		}
	}

	while (*p != '\0') {
		int nibble = hex_nibble(*p);

		if (nibble < 0 || result > (UINT32_MAX >> 4)) {
			return -EINVAL;
		}
		result = (result << 4) | (uint32_t)nibble;
		p++;
	}

	*out = result;
	return 0;
}

static int get_u32_dec(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_VALUE_MAX];

	return get_field(line, key, value, sizeof(value)) == 0 ?
		parse_u32_dec(value, out) : -EINVAL;
}

static int get_u32_hex(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_VALUE_MAX];

	return get_field(line, key, value, sizeof(value)) == 0 ?
		parse_u32_hex(value, out) : -EINVAL;
}

static int get_bool01(const char *line, const char *key, bool *out)
{
	uint32_t value;

	if (get_u32_dec(line, key, &value) != 0 || value > 1U) {
		return -EINVAL;
	}

	*out = value == 1U;
	return 0;
}

static bool is_hex_len(const char *value, size_t expected_len)
{
	if (value == NULL) {
		return false;
	}
	for (size_t i = 0U; i < expected_len; ++i) {
		if (hex_nibble(value[i]) < 0) {
			return false;
		}
	}

	return value[expected_len] == '\0';
}

static bool nonce_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS);
}

static bool token_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS);
}

static bool trace_digest_valid(const char *value)
{
	return is_hex_len(value, PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS);
}

static bool packet_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS);
}

static int parse_token_status(
	const char *value,
	enum pqcp_deployment_device_token_status *out)
{
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_TOKEN_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_TOKEN_FAIL;
		return 0;
	}

	return -EINVAL;
}

static int parse_gate_status(
	const char *value,
	enum pqcp_deployment_release_gate_status *out)
{
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_FAIL;
		return 0;
	}

	return -EINVAL;
}

static int parse_gate_profile(
	const char *value,
	enum pqcp_deployment_release_gate_profile *out)
{
	if (strcmp(value, "prototype") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE;
		return 0;
	}
	if (strcmp(value, "paper") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER;
		return 0;
	}
	if (strcmp(value, "product") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT;
		return 0;
	}
	if (strcmp(value, "partner") == 0) {
		*out = PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
		return 0;
	}

	return -EINVAL;
}

static void copy_text(char *dst, size_t dst_size, const char *src)
{
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
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
	const struct pqcp_deployment_device_token *token,
	char out[PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U])
{
	char line[768];
	uint64_t digest[4];

	digest_init(digest);
	build_canonical_line(token, line, sizeof(line));
	digest_update_string(digest, line);
	digest_to_hex(digest, out);
}

int pqcp_deployment_device_token_replay_init(
	struct pqcp_deployment_device_token_replay_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION;
	state->first_error =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONE;
	return 0;
}

static int reject_duplicate(
	struct pqcp_deployment_device_token_replay_state *state,
	uint32_t marker)
{
	if ((state->marker_mask & marker) != 0U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_DUPLICATE_MARKER);
	}
	state->marker_mask |= marker;
	return 0;
}

static int parse_capability(
	struct pqcp_deployment_device_token_replay_state *state,
	const char *line)
{
	char value[FIELD_VALUE_MAX];
	uint32_t schema;

	if (reject_duplicate(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_CAPABILITY) != 0) {
		return -EBADMSG;
	}
	if (get_u32_dec(line, "schema", &schema) != 0 ||
	    schema != PQCP_CAPABILITY_DESCRIPTOR_SCHEMA_VERSION ||
	    get_u32_hex(line, "evidence", &state->evidence_capabilities) != 0 ||
	    get_u32_dec(line, "readiness",
			&state->capability_readiness_score) != 0 ||
	    get_bool01(line, "production_allowed",
		       &state->production_allowed) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (get_field(line, "status", value, sizeof(value)) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (strcmp(value, "PASS") == 0) {
		state->capability_policy_passed = true;
	} else if (strcmp(value, "FAIL") == 0) {
		state->capability_policy_passed = false;
	} else {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (get_field(line, "provider", value, sizeof(value)) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}
	state->native_provider = strcmp(value, "pqcp_native") == 0;

	if (state->capability_readiness_score > 100U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}

	return 0;
}

static int parse_release_gate(
	struct pqcp_deployment_device_token_replay_state *state,
	const char *line)
{
	char value[FIELD_VALUE_MAX];
	uint32_t schema;

	if (reject_duplicate(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_RELEASE_GATE) !=
	    0) {
		return -EBADMSG;
	}
	if (get_u32_dec(line, "schema", &schema) != 0 ||
	    schema != PQCP_DEPLOYMENT_RELEASE_GATE_SCHEMA_VERSION ||
	    get_field(line, "profile", value, sizeof(value)) != 0 ||
	    parse_gate_profile(value, &state->gate_profile) != 0 ||
	    get_field(line, "status", value, sizeof(value)) != 0 ||
	    parse_gate_status(value, &state->gate_status) != 0 ||
	    get_u32_dec(line, "gate_score", &state->gate_score) != 0 ||
	    get_bool01(line, "digest_bound", &state->gate_digest_bound) != 0 ||
	    get_field(line, "top", state->gate_top_candidate_id,
		      sizeof(state->gate_top_candidate_id)) != 0 ||
	    get_field(line, "trace_digest", state->gate_trace_digest_hex,
		      sizeof(state->gate_trace_digest_hex)) != 0 ||
	    get_field(line, "packet_digest", state->gate_packet_digest_hex,
		      sizeof(state->gate_packet_digest_hex)) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (state->gate_score > 100U ||
	    !trace_digest_valid(state->gate_trace_digest_hex) ||
	    !packet_digest_valid(state->gate_packet_digest_hex) ||
	    !has_text(state->gate_top_candidate_id)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}

	return 0;
}

static int parse_token(
	struct pqcp_deployment_device_token_replay_state *state,
	const char *line)
{
	char value[FIELD_VALUE_MAX];
	uint32_t schema;

	if (reject_duplicate(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_TOKEN) != 0) {
		return -EBADMSG;
	}
	memset(&state->token, 0, sizeof(state->token));

	if (get_u32_dec(line, "schema", &schema) != 0 ||
	    schema != PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION ||
	    get_field(line, "profile", value, sizeof(value)) != 0 ||
	    parse_gate_profile(value, &state->token.profile) != 0 ||
	    get_field(line, "status", value, sizeof(value)) != 0 ||
	    parse_token_status(value, &state->token.status) != 0 ||
	    get_field(line, "nonce", state->token.nonce_hex,
		      sizeof(state->token.nonce_hex)) != 0 ||
	    get_u32_hex(line, "errors", &state->token.error_mask) != 0 ||
	    get_u32_hex(line, "warnings", &state->token.warning_mask) != 0 ||
	    get_u32_hex(line, "evidence",
			&state->token.evidence_capabilities) != 0 ||
	    get_u32_dec(line, "cap_readiness",
			&state->token.capability_readiness_score) != 0 ||
	    get_u32_dec(line, "gate_score", &state->token.gate_score) != 0 ||
	    get_field(line, "gate_status", value, sizeof(value)) != 0 ||
	    parse_gate_status(value, &state->token.gate_status) != 0 ||
	    get_bool01(line, "capability_policy",
		       &state->token.capability_policy_passed) != 0 ||
	    get_bool01(line, "production_allowed",
		       &state->token.production_allowed) != 0 ||
	    get_bool01(line, "native_provider",
		       &state->token.native_provider) != 0 ||
	    get_bool01(line, "gate_digest_bound",
		       &state->token.gate_digest_bound) != 0 ||
	    get_field(line, "top", state->token.top_candidate_id,
		      sizeof(state->token.top_candidate_id)) != 0 ||
	    get_field(line, "trace_digest", state->token.trace_digest_hex,
		      sizeof(state->token.trace_digest_hex)) != 0 ||
	    get_field(line, "packet_digest", state->token.packet_digest_hex,
		      sizeof(state->token.packet_digest_hex)) != 0 ||
	    get_field(line, "token_digest", state->token.token_digest_hex,
		      sizeof(state->token.token_digest_hex)) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}
	state->token.schema_version = schema;

	if (state->token.capability_readiness_score > 100U ||
	    state->token.gate_score > 100U ||
	    (state->token.error_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_KNOWN_MASK) != 0U ||
	    (state->token.warning_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_TOKEN_WARNING_KNOWN_MASK) != 0U ||
	    !nonce_valid(state->token.nonce_hex) ||
	    !trace_digest_valid(state->token.trace_digest_hex) ||
	    !packet_digest_valid(state->token.packet_digest_hex) ||
	    !token_digest_valid(state->token.token_digest_hex) ||
	    !has_text(state->token.top_candidate_id)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}

	return 0;
}

static int parse_verify(
	struct pqcp_deployment_device_token_replay_state *state,
	const char *line)
{
	char value[FIELD_VALUE_MAX];
	char status_value[FIELD_VALUE_MAX];
	uint32_t schema;
	bool marker_passed;

	if (reject_duplicate(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_MARKER_VERIFY) != 0) {
		return -EBADMSG;
	}
	if (get_u32_dec(line, "schema", &schema) != 0 ||
	    schema != PQCP_DEPLOYMENT_DEVICE_TOKEN_SCHEMA_VERSION ||
	    get_field(line, "status", status_value, sizeof(status_value)) != 0 ||
	    get_u32_hex(line, "errors", &state->verify_error_mask) != 0 ||
	    get_field(line, "expected_status", value, sizeof(value)) != 0 ||
	    parse_token_status(value, &state->verify_expected_status) != 0 ||
	    get_field(line, "observed_status", value, sizeof(value)) != 0 ||
	    parse_token_status(value, &state->verify_observed_status) != 0 ||
	    get_field(line, "expected_digest",
		      state->verify_expected_digest_hex,
		      sizeof(state->verify_expected_digest_hex)) != 0 ||
	    get_field(line, "observed_digest",
		      state->verify_observed_digest_hex,
		      sizeof(state->verify_observed_digest_hex)) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (strcmp(status_value, "PASS") == 0) {
		marker_passed = true;
	} else if (strcmp(status_value, "FAIL") == 0) {
		marker_passed = false;
	} else {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}
	state->verify_passed = marker_passed;
	if ((state->verify_error_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_TOKEN_ERROR_KNOWN_MASK) != 0U ||
	    !token_digest_valid(state->verify_expected_digest_hex) ||
	    !token_digest_valid(state->verify_observed_digest_hex)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MALFORMED_FIELD);
	}

	return 0;
}

int pqcp_deployment_device_token_replay_ingest_line(
	struct pqcp_deployment_device_token_replay_state *state,
	const char *line)
{
	char clean[REPLAY_LINE_MAX];

	if (state == NULL ||
	    state->schema_version !=
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION ||
	    line == NULL) {
		return -EINVAL;
	}
	if (clean_line(line, clean, sizeof(clean)) != 0) {
		return -EINVAL;
	}

	state->lines_seen++;
	if (!starts_with(clean, "PQCP_")) {
		return 0;
	}
	if (starts_with(clean, "PQCP_CAPABILITY_DESCRIPTOR ")) {
		return parse_capability(state, clean);
	}
	if (starts_with(clean, "PQCP_DEPLOYMENT_RELEASE_GATE ")) {
		return parse_release_gate(state, clean);
	}
	if (starts_with(clean, "PQCP_DEPLOYMENT_DEVICE_TOKEN ")) {
		return parse_token(state, clean);
	}
	if (starts_with(clean, "PQCP_DEPLOYMENT_DEVICE_TOKEN_VERIFY ")) {
		return parse_verify(state, clean);
	}
	if (starts_with(clean, "PQCP_DEPLOYMENT_DEVICE_TOKEN")) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_UNKNOWN_MARKER);
	}

	return 0;
}

static void populate_result(
	const struct pqcp_deployment_device_token_replay_state *state,
	struct pqcp_deployment_device_token_replay_result *result,
	const char *computed_digest)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION;
	result->lines_seen = state->lines_seen;
	result->marker_mask = state->marker_mask;
	result->first_error_line = state->first_error_line;
	result->first_error = state->first_error;
	result->token_status = state->token.status;
	result->gate_status = state->gate_status;
	result->capability_readiness_score =
		state->capability_readiness_score;
	result->gate_score = state->gate_score;
	copy_text(result->top_candidate_id,
		  sizeof(result->top_candidate_id),
		  state->token.top_candidate_id);
	copy_text(result->nonce_hex, sizeof(result->nonce_hex),
		  state->token.nonce_hex);
	copy_text(result->token_digest_hex, sizeof(result->token_digest_hex),
		  state->token.token_digest_hex);
	copy_text(result->computed_digest_hex,
		  sizeof(result->computed_digest_hex),
		  computed_digest != NULL ? computed_digest : "");
}

static int check_capability_matches_token(
	const struct pqcp_deployment_device_token_replay_state *state)
{
	if (state->token.evidence_capabilities !=
	    state->evidence_capabilities ||
	    state->token.capability_readiness_score !=
		    state->capability_readiness_score ||
	    state->token.capability_policy_passed !=
		    state->capability_policy_passed ||
	    state->token.production_allowed != state->production_allowed ||
	    state->token.native_provider != state->native_provider) {
		return -EBADMSG;
	}

	return 0;
}

static int check_release_gate_matches_token(
	const struct pqcp_deployment_device_token_replay_state *state)
{
	if (state->token.profile != state->gate_profile ||
	    state->token.gate_score != state->gate_score ||
	    state->token.gate_status != state->gate_status ||
	    state->token.gate_digest_bound != state->gate_digest_bound ||
	    strcmp(state->token.top_candidate_id,
		   state->gate_top_candidate_id) != 0 ||
	    strcmp(state->token.trace_digest_hex,
		   state->gate_trace_digest_hex) != 0 ||
	    strcmp(state->token.packet_digest_hex,
		   state->gate_packet_digest_hex) != 0) {
		return -EBADMSG;
	}

	return 0;
}

static int check_verify_matches_token(
	const struct pqcp_deployment_device_token_replay_state *state)
{
	if (!state->verify_passed || state->verify_error_mask != 0U ||
	    state->verify_expected_status != state->token.status ||
	    state->verify_observed_status != state->token.status ||
	    strcmp(state->verify_expected_digest_hex,
		   state->token.token_digest_hex) != 0 ||
	    strcmp(state->verify_observed_digest_hex,
		   state->token.token_digest_hex) != 0) {
		return -EBADMSG;
	}

	return 0;
}

int pqcp_deployment_device_token_replay_finish(
	struct pqcp_deployment_device_token_replay_state *state,
	const char *expected_nonce_hex,
	struct pqcp_deployment_device_token_replay_result *result)
{
	char computed_digest[
		PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U] = { 0 };
	int ret = 0;

	if (state == NULL || result == NULL ||
	    state->schema_version !=
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION) {
		return -EINVAL;
	}

	if (state->first_error !=
	    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONE) {
		populate_result(state, result, computed_digest);
		return -EBADMSG;
	}
	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK) !=
	    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK) {
		(void)fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_MISSING_REQUIRED);
		populate_result(state, result, computed_digest);
		return -EBADMSG;
	}
	if (expected_nonce_hex != NULL &&
	    (!nonce_valid(expected_nonce_hex) ||
	     strcmp(expected_nonce_hex, state->token.nonce_hex) != 0)) {
		(void)fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_NONCE_MISMATCH);
		populate_result(state, result, computed_digest);
		return -EBADMSG;
	}

	compute_token_digest(&state->token, computed_digest);
	if (strcmp(computed_digest, state->token.token_digest_hex) != 0) {
		(void)fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH);
		ret = -EBADMSG;
	} else if (check_capability_matches_token(state) != 0) {
		(void)fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_CAPABILITY_MISMATCH);
		ret = -EBADMSG;
	} else if (check_release_gate_matches_token(state) != 0) {
		(void)fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_RELEASE_GATE_MISMATCH);
		ret = -EBADMSG;
	} else if (check_verify_matches_token(state) != 0) {
		(void)fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_ERROR_VERIFY_MISMATCH);
		ret = -EBADMSG;
	}

	populate_result(state, result, computed_digest);
	result->passed = ret == 0;
	return ret;
}

int pqcp_deployment_device_token_replay_verify_transcript(
	const char *transcript,
	const char *expected_nonce_hex,
	struct pqcp_deployment_device_token_replay_result *result)
{
	struct pqcp_deployment_device_token_replay_state state;
	const char *line_start = transcript;
	int ret;

	if (transcript == NULL || result == NULL) {
		return -EINVAL;
	}

	ret = pqcp_deployment_device_token_replay_init(&state);
	if (ret != 0) {
		return ret;
	}

	while (*line_start != '\0') {
		const char *line_end = strchr(line_start, '\n');
		char line[REPLAY_LINE_MAX];
		size_t len;

		if (line_end == NULL) {
			line_end = line_start + strlen(line_start);
		}
		len = (size_t)(line_end - line_start);
		if (len >= sizeof(line)) {
			return -EINVAL;
		}
		if (len != 0U) {
			memcpy(line, line_start, len);
			line[len] = '\0';
			ret = pqcp_deployment_device_token_replay_ingest_line(
				&state, line);
			if (ret != 0) {
				break;
			}
		}
		if (*line_end == '\0') {
			break;
		}
		line_start = line_end + 1U;
	}

	return pqcp_deployment_device_token_replay_finish(
		&state, expected_nonce_hex, result);
}

int pqcp_deployment_device_token_replay_emit_result(
	const struct pqcp_deployment_device_token_replay_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_SCHEMA_VERSION ||
	    (result->marker_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK) != 0U ||
	    result->capability_readiness_score > 100U ||
	    result->gate_score > 100U ||
	    !token_digest_valid(result->token_digest_hex) ||
	    !token_digest_valid(result->computed_digest_hex) ||
	    !nonce_valid(result->nonce_hex) ||
	    !has_text(result->top_candidate_id)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY schema=%u status=%s error=%s line=%u markers=0x%08x lines=%u token_status=%s gate_status=%s cap_readiness=%u gate_score=%u top=%s nonce=%s digest=%s computed=%s\n",
	       result->schema_version,
	       result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_device_token_replay_error_str(
		       result->first_error),
	       result->first_error_line,
	       result->marker_mask,
	       result->lines_seen,
	       pqcp_deployment_device_token_status_str(result->token_status),
	       pqcp_deployment_release_gate_status_str(result->gate_status),
	       result->capability_readiness_score,
	       result->gate_score,
	       result->top_candidate_id,
	       result->nonce_hex,
	       result->token_digest_hex,
	       result->computed_digest_hex);

	return result->passed ? 0 : -EBADMSG;
}
