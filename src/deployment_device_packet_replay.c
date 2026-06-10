/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native deployment device-packet replay verifier.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_device_packet_replay.h>

#define FIELD_VALUE_MAX 192U
#define DEVICE_PACKET_REPLAY_LINE_MAX 1024U

static bool starts_with(const char *value, const char *prefix)
{
	return strncmp(value, prefix, strlen(prefix)) == 0;
}

static bool has_text(const char *value)
{
	return value != NULL && value[0] != '\0';
}

static bool provider_text_valid(const char *value)
{
	return strcmp(value, "disabled") == 0 ||
	       strcmp(value, "pqcp_native") == 0 ||
	       strcmp(value, "baseline_c") == 0 ||
	       strcmp(value, "mixed") == 0 ||
	       strcmp(value, "invalid") == 0;
}

static int fail_once(
	struct pqcp_deployment_device_packet_replay_state *state,
	enum pqcp_deployment_device_packet_replay_error error)
{
	if (state != NULL &&
	    state->first_error ==
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONE) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}

	return -EBADMSG;
}

const char *pqcp_deployment_device_packet_replay_error_str(
	enum pqcp_deployment_device_packet_replay_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_DUPLICATE_MARKER:
		return "duplicate_marker";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MISSING_REQUIRED:
		return "missing_required";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_UNKNOWN_MARKER:
		return "unknown_marker";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_DIGEST_MISMATCH:
		return "digest_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_BYTE_COUNT_MISMATCH:
		return "byte_count_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_LINE_COUNT_MISMATCH:
		return "line_count_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH:
		return "status_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_PROFILE_MISMATCH:
		return "profile_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOP_MISMATCH:
		return "top_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONCE_MISMATCH:
		return "nonce_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH:
		return "token_digest_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_RELEASE_DIGEST_MISMATCH:
		return "release_digest_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_CAPABILITY_MISMATCH:
		return "capability_mismatch";
	case PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH:
		return "score_mismatch";
	default:
		return "unknown";
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

static int parse_bool_status(const char *line, const char *key, bool *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	if (strcmp(value, "PASS") == 0) {
		*out = true;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = false;
		return 0;
	}

	return -EINVAL;
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

static bool trace_digest_valid(const char *value)
{
	return is_hex_len(value, PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS);
}

static bool review_packet_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS);
}

static bool token_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS);
}

static bool device_packet_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS);
}

static int parse_profile(
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

static int parse_profile_field(
	const char *line,
	const char *key,
	enum pqcp_deployment_release_gate_profile *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}

	return parse_profile(value, out);
}

static int parse_packet_status(
	const char *line,
	const char *key,
	enum pqcp_deployment_device_packet_status *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_PACKET_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_PACKET_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL;
		return 0;
	}

	return -EINVAL;
}

static int parse_release_status(
	const char *line,
	const char *key,
	enum pqcp_deployment_release_gate_status *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
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

static int parse_token_status(
	const char *line,
	const char *key,
	enum pqcp_deployment_device_token_status *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
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

static int parse_audit_status(
	const char *line,
	const char *key,
	enum pqcp_deployment_device_token_audit_status *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_FAIL;
		return 0;
	}

	return -EINVAL;
}

static int parse_device_gate_status(
	const char *line,
	const char *key,
	enum pqcp_deployment_device_gate_status *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_GATE_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_GATE_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_DEVICE_GATE_FAIL;
		return 0;
	}

	return -EINVAL;
}

static int verify_schema(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	uint32_t schema;

	if (get_u32_dec(line, "schema", &schema) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (schema != PQCP_DEPLOYMENT_DEVICE_PACKET_SCHEMA_VERSION) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_BAD_SCHEMA);
	}

	return 0;
}

static int ensure_single_marker(
	struct pqcp_deployment_device_packet_replay_state *state,
	uint32_t marker)
{
	if ((state->marker_mask & marker) != 0U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_DUPLICATE_MARKER);
	}

	state->marker_mask |= marker;
	return 0;
}

static int remember_profile(
	struct pqcp_deployment_device_packet_replay_state *state,
	enum pqcp_deployment_release_gate_profile profile)
{
	if (!state->profile_seen) {
		state->profile = profile;
		state->profile_seen = true;
		return 0;
	}

	return state->profile == profile ? 0 :
		fail_once(state,
			  PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_PROFILE_MISMATCH);
}

static int remember_u32(
	struct pqcp_deployment_device_packet_replay_state *state,
	bool *seen,
	uint32_t *slot,
	uint32_t value,
	enum pqcp_deployment_device_packet_replay_error error)
{
	if (seen == NULL || slot == NULL) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_INVALID_ARGUMENT);
	}
	if (!*seen) {
		*slot = value;
		*seen = true;
		return 0;
	}

	return *slot == value ? 0 : fail_once(state, error);
}

static int remember_text(
	struct pqcp_deployment_device_packet_replay_state *state,
	char *slot,
	size_t slot_size,
	const char *value,
	bool (*validator)(const char *),
	enum pqcp_deployment_device_packet_replay_error error)
{
	if (!has_text(value) || strlen(value) >= slot_size ||
	    (validator != NULL && !validator(value))) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (slot[0] == '\0') {
		(void)snprintk(slot, slot_size, "%s", value);
		return 0;
	}

	return strcmp(slot, value) == 0 ? 0 : fail_once(state, error);
}

static int remember_release_status(
	struct pqcp_deployment_device_packet_replay_state *state,
	enum pqcp_deployment_release_gate_status status)
{
	if (!state->release_status_seen) {
		state->release_status = status;
		state->release_status_seen = true;
		return 0;
	}

	return state->release_status == status ? 0 :
		fail_once(state,
			  PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH);
}

static int remember_token_status(
	struct pqcp_deployment_device_packet_replay_state *state,
	enum pqcp_deployment_device_token_status status)
{
	if (!state->token_status_seen) {
		state->token_status = status;
		state->token_status_seen = true;
		return 0;
	}

	return state->token_status == status ? 0 :
		fail_once(state,
			  PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH);
}

static int remember_audit_status(
	struct pqcp_deployment_device_packet_replay_state *state,
	enum pqcp_deployment_device_token_audit_status status)
{
	if (!state->audit_status_seen) {
		state->audit_status = status;
		state->audit_status_seen = true;
		return 0;
	}

	return state->audit_status == status ? 0 :
		fail_once(state,
			  PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH);
}

static int remember_device_gate_status(
	struct pqcp_deployment_device_packet_replay_state *state,
	enum pqcp_deployment_device_gate_status status)
{
	if (!state->device_gate_status_seen) {
		state->device_gate_status = status;
		state->device_gate_status_seen = true;
		return 0;
	}

	return state->device_gate_status == status ? 0 :
		fail_once(state,
			  PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH);
}

static int remember_bool(
	struct pqcp_deployment_device_packet_replay_state *state,
	bool *seen,
	bool *slot,
	bool value)
{
	if (!*seen) {
		*slot = value;
		*seen = true;
		return 0;
	}

	return *slot == value ? 0 :
		fail_once(state,
			  PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH);
}

static int ingest_fact_common(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	const size_t len = strlen(line);

	digest_update_line(state->digest_state, line);
	digest_to_hex(state->digest_state, state->computed_digest_hex);
	state->fact_lines++;
	if (UINT32_MAX - state->fact_bytes < len + 1U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_BYTE_COUNT_MISMATCH);
	}
	state->fact_bytes += (uint32_t)len + 1U;

	return 0;
}

static int ingest_capability_fact(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];
	char value[FIELD_VALUE_MAX];
	bool policy_passed;
	uint32_t evidence;
	uint32_t production_allowed;
	uint32_t readiness;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_CAPABILITY) !=
		    0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "capability") != 0 ||
		    parse_bool_status(line, "policy", &policy_passed) != 0 ||
		    get_field(line, "provider", value, sizeof(value)) != 0 ||
		    get_u32_hex(line, "evidence", &evidence) != 0 ||
		    get_u32_dec(line, "production_allowed",
				&production_allowed) != 0 ||
		    get_u32_dec(line, "readiness", &readiness) != 0 ||
		    readiness > 100U || production_allowed > 1U ||
		    !provider_text_valid(value)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (remember_bool(state, &state->capability_policy_seen,
			  &state->capability_policy_passed, policy_passed) != 0 ||
	    remember_u32(state, &state->production_allowed_seen,
			 &state->production_allowed, production_allowed,
			 PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH) !=
		    0 ||
	    remember_u32(
		    state, &state->evidence_seen,
		    &state->evidence_capabilities, evidence,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_CAPABILITY_MISMATCH) !=
		    0 ||
	    remember_u32(
		    state, &state->capability_score_seen,
		    &state->capability_readiness_score, readiness,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0) {
		return -EBADMSG;
	}

	return ingest_fact_common(state, line);
}

static int ingest_release_fact(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char trace[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	char packet[PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_release_gate_profile profile;
	enum pqcp_deployment_release_gate_status status;
	uint32_t score;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_RELEASE) != 0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "release") != 0 ||
	    parse_profile_field(line, "profile", &profile) != 0 ||
	    parse_release_status(line, "status", &status) != 0 ||
	    get_u32_dec(line, "gate_score", &score) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0 ||
	    get_field(line, "trace_digest", trace, sizeof(trace)) != 0 ||
	    get_field(line, "packet_digest", packet, sizeof(packet)) != 0 ||
	    score > 100U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (remember_profile(state, profile) != 0 ||
	    remember_release_status(state, status) != 0 ||
	    remember_u32(
		    state, &state->release_score_seen,
		    &state->release_gate_score, score,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->top_candidate_id,
		    sizeof(state->top_candidate_id), top, NULL,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOP_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->trace_digest_hex,
		    sizeof(state->trace_digest_hex), trace, trace_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_RELEASE_DIGEST_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->packet_digest_hex,
		    sizeof(state->packet_digest_hex), packet,
		    review_packet_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_RELEASE_DIGEST_MISMATCH) !=
		    0) {
		return -EBADMSG;
	}

	return ingest_fact_common(state, line);
}

static int ingest_token_fact(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char nonce[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	char digest[PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_release_gate_profile profile;
	enum pqcp_deployment_device_token_status status;
	uint32_t cap_score;
	uint32_t gate_score;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_TOKEN) != 0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "token") != 0 ||
	    parse_profile_field(line, "profile", &profile) != 0 ||
	    parse_token_status(line, "status", &status) != 0 ||
	    get_field(line, "nonce", nonce, sizeof(nonce)) != 0 ||
	    get_u32_dec(line, "cap_readiness", &cap_score) != 0 ||
	    get_u32_dec(line, "gate_score", &gate_score) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0 ||
	    get_field(line, "token_digest", digest, sizeof(digest)) != 0 ||
	    cap_score > 100U || gate_score > 100U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (remember_profile(state, profile) != 0 ||
	    remember_token_status(state, status) != 0 ||
	    remember_u32(
		    state, &state->capability_score_seen,
		    &state->capability_readiness_score, cap_score,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0 ||
	    remember_u32(
		    state, &state->release_score_seen,
		    &state->release_gate_score, gate_score,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->top_candidate_id,
		    sizeof(state->top_candidate_id), top, NULL,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOP_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->nonce_hex, sizeof(state->nonce_hex), nonce,
		    nonce_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONCE_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->token_digest_hex,
		    sizeof(state->token_digest_hex), digest, token_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH) !=
		    0) {
		return -EBADMSG;
	}

	return ingest_fact_common(state, line);
}

static int ingest_replay_fact(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char nonce[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	char digest[PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	char computed[PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_device_token_status token_status;
	enum pqcp_deployment_release_gate_status gate_status;
	bool replay_passed;
	uint32_t lines;
	uint32_t markers;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_REPLAY) != 0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "replay") != 0 ||
	    parse_bool_status(line, "status", &replay_passed) != 0 ||
	    get_u32_dec(line, "lines", &lines) != 0 ||
	    get_u32_hex(line, "markers", &markers) != 0 ||
	    parse_token_status(line, "token_status", &token_status) != 0 ||
	    parse_release_status(line, "gate_status", &gate_status) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0 ||
	    get_field(line, "nonce", nonce, sizeof(nonce)) != 0 ||
	    get_field(line, "digest", digest, sizeof(digest)) != 0 ||
	    get_field(line, "computed", computed, sizeof(computed)) != 0 ||
	    lines == 0U ||
	    markers != PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY_REQUIRED_MASK ||
	    !token_digest_valid(computed)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (remember_bool(state, &state->replay_seen, &state->replay_passed,
			  replay_passed) != 0 ||
	    remember_token_status(state, token_status) != 0 ||
	    remember_release_status(state, gate_status) != 0 ||
	    remember_text(
		    state, state->top_candidate_id,
		    sizeof(state->top_candidate_id), top, NULL,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOP_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->nonce_hex, sizeof(state->nonce_hex), nonce,
		    nonce_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONCE_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->token_digest_hex,
		    sizeof(state->token_digest_hex), digest, token_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->token_digest_hex,
		    sizeof(state->token_digest_hex), computed,
		    token_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH) !=
		    0) {
		return -EBADMSG;
	}

	return ingest_fact_common(state, line);
}

static int ingest_audit_fact(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char nonce[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	char digest[PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_device_token_audit_status status;
	uint32_t results;
	uint32_t replay_pass;
	uint32_t replay_fail;
	uint32_t unique_tokens;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_AUDIT) != 0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "audit") != 0 ||
	    parse_audit_status(line, "status", &status) != 0 ||
	    get_u32_dec(line, "results", &results) != 0 ||
	    get_u32_dec(line, "replay_pass", &replay_pass) != 0 ||
	    get_u32_dec(line, "replay_fail", &replay_fail) != 0 ||
	    get_u32_dec(line, "unique_tokens", &unique_tokens) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0 ||
	    get_field(line, "nonce", nonce, sizeof(nonce)) != 0 ||
	    get_field(line, "token_digest", digest, sizeof(digest)) != 0 ||
	    results == 0U || replay_pass + replay_fail != results ||
	    unique_tokens == 0U || unique_tokens > results) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (remember_audit_status(state, status) != 0 ||
	    remember_text(
		    state, state->top_candidate_id,
		    sizeof(state->top_candidate_id), top, NULL,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOP_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->nonce_hex, sizeof(state->nonce_hex), nonce,
		    nonce_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONCE_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->token_digest_hex,
		    sizeof(state->token_digest_hex), digest, token_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH) !=
		    0) {
		return -EBADMSG;
	}

	return ingest_fact_common(state, line);
}

static int ingest_device_gate_fact(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char nonce[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	char digest[PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_release_gate_profile profile;
	enum pqcp_deployment_device_gate_status status;
	bool verification;
	bool replay;
	uint32_t cap_score;
	uint32_t release_score;
	uint32_t audit_score;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_DEVICE_GATE) !=
		    0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "device_gate") != 0 ||
	    parse_profile_field(line, "profile", &profile) != 0 ||
	    parse_device_gate_status(line, "status", &status) != 0 ||
	    get_u32_dec(line, "cap_readiness", &cap_score) != 0 ||
	    get_u32_dec(line, "release_gate_score", &release_score) != 0 ||
	    get_u32_dec(line, "audit_gate_score", &audit_score) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0 ||
	    get_field(line, "nonce", nonce, sizeof(nonce)) != 0 ||
	    get_field(line, "token_digest", digest, sizeof(digest)) != 0 ||
	    parse_bool_status(line, "verify", &verification) != 0 ||
	    parse_bool_status(line, "replay", &replay) != 0 ||
	    cap_score > 100U || release_score > 100U || audit_score > 100U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (remember_profile(state, profile) != 0 ||
	    remember_device_gate_status(state, status) != 0 ||
	    remember_u32(
		    state, &state->capability_score_seen,
		    &state->capability_readiness_score, cap_score,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0 ||
	    remember_u32(
		    state, &state->release_score_seen,
		    &state->release_gate_score, release_score,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0 ||
	    remember_u32(
		    state, &state->audit_score_seen,
		    &state->audit_gate_score, audit_score,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0 ||
	    remember_bool(state, &state->verification_seen,
			  &state->verification_passed, verification) != 0 ||
	    remember_bool(state, &state->replay_seen, &state->replay_passed,
			  replay) != 0 ||
	    remember_text(
		    state, state->top_candidate_id,
		    sizeof(state->top_candidate_id), top, NULL,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOP_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->nonce_hex, sizeof(state->nonce_hex), nonce,
		    nonce_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONCE_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->token_digest_hex,
		    sizeof(state->token_digest_hex), digest, token_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH) !=
		    0) {
		return -EBADMSG;
	}

	return ingest_fact_common(state, line);
}

static int ingest_packet_marker(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char nonce[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	char trace[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	char packet[PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U];
	char token[PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_release_gate_profile profile;
	enum pqcp_deployment_release_gate_status release_status;
	enum pqcp_deployment_device_token_status token_status;
	enum pqcp_deployment_device_token_audit_status audit_status;
	enum pqcp_deployment_device_gate_status device_gate_status;
	bool verification;
	bool replay;
	uint32_t cap_score;
	uint32_t release_score;
	uint32_t audit_score;
	uint32_t evidence;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_MARKER_PACKET) != 0 ||
	    verify_schema(state, line) != 0 ||
	    parse_packet_status(line, "status", &state->packet_status) != 0 ||
	    get_u32_hex(line, "errors", &state->packet_error_mask) != 0 ||
	    get_u32_hex(line, "warnings", &state->packet_warning_mask) != 0 ||
	    get_u32_dec(line, "lines", &state->packet_line_count) != 0 ||
	    get_u32_dec(line, "bytes", &state->packet_byte_count) != 0 ||
	    get_u32_hex(line, "evidence", &evidence) != 0 ||
	    parse_profile_field(line, "profile", &profile) != 0 ||
	    get_u32_dec(line, "cap_readiness", &cap_score) != 0 ||
	    get_u32_dec(line, "release_gate_score", &release_score) != 0 ||
	    get_u32_dec(line, "audit_gate_score", &audit_score) != 0 ||
	    parse_device_gate_status(line, "device_gate",
				     &device_gate_status) != 0 ||
	    parse_release_status(line, "release", &release_status) != 0 ||
	    parse_token_status(line, "token", &token_status) != 0 ||
	    parse_bool_status(line, "verify", &verification) != 0 ||
	    parse_bool_status(line, "replay", &replay) != 0 ||
	    parse_audit_status(line, "audit", &audit_status) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0 ||
	    get_field(line, "nonce", nonce, sizeof(nonce)) != 0 ||
	    get_field(line, "trace_digest", trace, sizeof(trace)) != 0 ||
	    get_field(line, "packet_digest", packet, sizeof(packet)) != 0 ||
	    get_field(line, "token_digest", token, sizeof(token)) != 0 ||
	    get_field(line, "digest", state->packet_digest_observed_hex,
		      sizeof(state->packet_digest_observed_hex)) != 0 ||
	    cap_score > 100U || release_score > 100U ||
	    audit_score > 100U ||
	    (state->packet_error_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_PACKET_ERROR_KNOWN_MASK) != 0U ||
	    (state->packet_warning_mask &
	     ~PQCP_DEPLOYMENT_DEVICE_PACKET_WARNING_KNOWN_MASK) != 0U ||
	    !device_packet_digest_valid(state->packet_digest_observed_hex)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
	}
	if (remember_profile(state, profile) != 0 ||
	    remember_release_status(state, release_status) != 0 ||
	    remember_token_status(state, token_status) != 0 ||
	    remember_audit_status(state, audit_status) != 0 ||
	    remember_device_gate_status(state, device_gate_status) != 0 ||
	    remember_bool(state, &state->verification_seen,
			  &state->verification_passed, verification) != 0 ||
	    remember_bool(state, &state->replay_seen, &state->replay_passed,
			  replay) != 0 ||
	    remember_u32(
		    state, &state->evidence_seen,
		    &state->evidence_capabilities, evidence,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_CAPABILITY_MISMATCH) !=
		    0 ||
	    remember_u32(
		    state, &state->capability_score_seen,
		    &state->capability_readiness_score, cap_score,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0 ||
	    remember_u32(
		    state, &state->release_score_seen,
		    &state->release_gate_score, release_score,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0 ||
	    remember_u32(
		    state, &state->audit_score_seen,
		    &state->audit_gate_score, audit_score,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_SCORE_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->top_candidate_id,
		    sizeof(state->top_candidate_id), top, NULL,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOP_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->nonce_hex, sizeof(state->nonce_hex), nonce,
		    nonce_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONCE_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->trace_digest_hex,
		    sizeof(state->trace_digest_hex), trace, trace_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_RELEASE_DIGEST_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->packet_digest_hex,
		    sizeof(state->packet_digest_hex), packet,
		    review_packet_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_RELEASE_DIGEST_MISMATCH) !=
		    0 ||
	    remember_text(
		    state, state->token_digest_hex,
		    sizeof(state->token_digest_hex), token, token_digest_valid,
		    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_TOKEN_DIGEST_MISMATCH) !=
		    0) {
		return -EBADMSG;
	}

	return 0;
}

static void fill_result(
	const struct pqcp_deployment_device_packet_replay_state *state,
	struct pqcp_deployment_device_packet_replay_result *result,
	bool passed)
{
	if (state == NULL || result == NULL) {
		return;
	}

	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_SCHEMA_VERSION;
	result->lines_seen = state->lines_seen;
	result->marker_mask = state->marker_mask;
	result->fact_lines = state->fact_lines;
	result->fact_bytes = state->fact_bytes;
	result->evidence_capabilities = state->evidence_capabilities;
	result->capability_readiness_score =
		state->capability_readiness_score;
	result->release_gate_score = state->release_gate_score;
	result->audit_gate_score = state->audit_gate_score;
	result->first_error_line = state->first_error_line;
	result->first_error = state->first_error;
	result->packet_status = state->packet_status;
	result->passed = passed;
	(void)snprintk(result->top_candidate_id,
		       sizeof(result->top_candidate_id), "%s",
		       state->top_candidate_id);
	(void)snprintk(result->nonce_hex, sizeof(result->nonce_hex), "%s",
		       state->nonce_hex);
	(void)snprintk(result->computed_digest_hex,
		       sizeof(result->computed_digest_hex), "%s",
		       state->computed_digest_hex);
}

int pqcp_deployment_device_packet_replay_init(
	struct pqcp_deployment_device_packet_replay_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version =
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_SCHEMA_VERSION;
	state->first_error =
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONE;
	state->packet_status = PQCP_DEPLOYMENT_DEVICE_PACKET_FAIL;
	digest_init(state->digest_state);
	digest_to_hex(state->digest_state, state->computed_digest_hex);

	return 0;
}

int pqcp_deployment_device_packet_replay_ingest_line(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *line)
{
	char clean[DEVICE_PACKET_REPLAY_LINE_MAX];
	char field[FIELD_VALUE_MAX];

	if (state == NULL || line == NULL) {
		return -EINVAL;
	}
	if (clean_line(line, clean, sizeof(clean)) != 0) {
		state->lines_seen++;
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_INVALID_ARGUMENT);
	}

	state->lines_seen++;
	if (starts_with(clean, "PQCP_DEPLOYMENT_DEVICE_FACT ")) {
		if (get_field(clean, "field", field, sizeof(field)) != 0) {
			return fail_once(
				state,
				PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MALFORMED_FIELD);
		}
		if (strcmp(field, "capability") == 0) {
			return ingest_capability_fact(state, clean);
		}
		if (strcmp(field, "release") == 0) {
			return ingest_release_fact(state, clean);
		}
		if (strcmp(field, "token") == 0) {
			return ingest_token_fact(state, clean);
		}
		if (strcmp(field, "replay") == 0) {
			return ingest_replay_fact(state, clean);
		}
		if (strcmp(field, "audit") == 0) {
			return ingest_audit_fact(state, clean);
		}
		if (strcmp(field, "device_gate") == 0) {
			return ingest_device_gate_fact(state, clean);
		}
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_UNKNOWN_MARKER);
	}
	if (starts_with(clean, "PQCP_DEPLOYMENT_DEVICE_PACKET ")) {
		return ingest_packet_marker(state, clean);
	}

	return fail_once(
		state,
		PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_UNKNOWN_MARKER);
}

static enum pqcp_deployment_device_packet_status expected_packet_status(
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

static int finish_checks(
	struct pqcp_deployment_device_packet_replay_state *state)
{
	const uint32_t required_caps =
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET |
		PQCP_CAPABILITY_EVIDENCE_DEPLOYMENT_DEVICE_PACKET_REPLAY;

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_REQUIRED_MASK) !=
	    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_REQUIRED_MASK) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_MISSING_REQUIRED);
	}
	if (state->packet_line_count != state->fact_lines) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_LINE_COUNT_MISMATCH);
	}
	if (state->packet_byte_count != state->fact_bytes) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_BYTE_COUNT_MISMATCH);
	}
	if (strcmp(state->computed_digest_hex,
		   state->packet_digest_observed_hex) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_DIGEST_MISMATCH);
	}
	if (state->packet_status !=
	    expected_packet_status(state->packet_error_mask,
				   state->packet_warning_mask)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH);
	}
	if (state->packet_status == PQCP_DEPLOYMENT_DEVICE_PACKET_PASS &&
	    (state->device_gate_status != PQCP_DEPLOYMENT_DEVICE_GATE_PASS ||
	     state->release_status != PQCP_DEPLOYMENT_RELEASE_GATE_PASS ||
	     state->token_status != PQCP_DEPLOYMENT_DEVICE_TOKEN_PASS ||
	     state->audit_status != PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT_PASS ||
	     !state->verification_passed || !state->replay_passed)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_STATUS_MISMATCH);
	}
	if ((state->evidence_capabilities & required_caps) != required_caps) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_CAPABILITY_MISMATCH);
	}

	return 0;
}

int pqcp_deployment_device_packet_replay_finish(
	struct pqcp_deployment_device_packet_replay_state *state,
	struct pqcp_deployment_device_packet_replay_result *result)
{
	int ret;

	if (state == NULL || result == NULL) {
		return -EINVAL;
	}
	if (state->first_error !=
	    PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_ERROR_NONE) {
		fill_result(state, result, false);
		return -EBADMSG;
	}

	ret = finish_checks(state);
	fill_result(state, result, ret == 0);
	return ret == 0 ? 0 : -EBADMSG;
}

static int feed_fact_buffer(
	struct pqcp_deployment_device_packet_replay_state *state,
	const char *fact_buffer)
{
	const char *line_start = fact_buffer;
	char line[DEVICE_PACKET_REPLAY_LINE_MAX];

	if (fact_buffer == NULL) {
		return -EINVAL;
	}

	while (*line_start != '\0') {
		const char *line_end = strchr(line_start, '\n');
		size_t len = line_end == NULL ? strlen(line_start) :
						(size_t)(line_end - line_start);

		if (len != 0U) {
			if (len >= sizeof(line)) {
				return -EINVAL;
			}
			memcpy(line, line_start, len);
			line[len] = '\0';
			if (pqcp_deployment_device_packet_replay_ingest_line(
				    state, line) != 0) {
				return -EBADMSG;
			}
		}
		if (line_end == NULL) {
			break;
		}
		line_start = line_end + 1U;
	}

	return 0;
}

int pqcp_deployment_device_packet_replay_verify_packet(
	const char *fact_buffer,
	const struct pqcp_deployment_device_packet *packet,
	struct pqcp_deployment_device_packet_replay_result *result)
{
	struct pqcp_deployment_device_packet_replay_state state;
	char packet_line[DEVICE_PACKET_REPLAY_LINE_MAX];
	int written;
	int ret;

	if (fact_buffer == NULL || packet == NULL || result == NULL) {
		return -EINVAL;
	}

	ret = pqcp_deployment_device_packet_replay_init(&state);
	if (ret != 0) {
		return ret;
	}
	ret = feed_fact_buffer(&state, fact_buffer);
	if (ret != 0) {
		fill_result(&state, result, false);
		return ret;
	}

	written = snprintk(
		packet_line, sizeof(packet_line),
		"PQCP_DEPLOYMENT_DEVICE_PACKET schema=%u status=%s errors=0x%08x warnings=0x%08x lines=%u bytes=%u evidence=0x%08x profile=%s cap_readiness=%u release_gate_score=%u audit_gate_score=%u device_gate=%s release=%s token=%s verify=%s replay=%s audit=%s top=%s nonce=%s trace_digest=%s packet_digest=%s token_digest=%s digest=%s",
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
	if (written < 0 || written >= (int)sizeof(packet_line)) {
		fill_result(&state, result, false);
		return -ENOSPC;
	}
	ret = pqcp_deployment_device_packet_replay_ingest_line(&state,
							      packet_line);
	if (ret != 0) {
		fill_result(&state, result, false);
		return ret;
	}

	return pqcp_deployment_device_packet_replay_finish(&state, result);
}

static bool result_valid(
	const struct pqcp_deployment_device_packet_replay_result *result)
{
	return result != NULL &&
	       result->schema_version ==
		       PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY_SCHEMA_VERSION &&
	       result->lines_seen != 0U &&
	       result->top_candidate_id[0] != '\0' &&
	       result->nonce_hex[0] != '\0' &&
	       result->computed_digest_hex[0] != '\0' &&
	       result->capability_readiness_score <= 100U &&
	       result->release_gate_score <= 100U &&
	       result->audit_gate_score <= 100U;
}

int pqcp_deployment_device_packet_replay_emit_result(
	const struct pqcp_deployment_device_packet_replay_result *result)
{
	if (!result_valid(result)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY schema=%u status=%s error=%s line=%u markers=0x%08x lines=%u facts=%u bytes=%u evidence=0x%08x top=%s nonce=%s cap_readiness=%u release_gate_score=%u audit_gate_score=%u digest=%s packet_status=%s\n",
	       result->schema_version,
	       result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_device_packet_replay_error_str(
		       result->first_error),
	       result->first_error_line,
	       result->marker_mask,
	       result->lines_seen,
	       result->fact_lines,
	       result->fact_bytes,
	       result->evidence_capabilities,
	       result->top_candidate_id,
	       result->nonce_hex,
	       result->capability_readiness_score,
	       result->release_gate_score,
	       result->audit_gate_score,
	       result->computed_digest_hex,
	       pqcp_deployment_device_packet_status_str(
		       result->packet_status));

	return result->passed ? 0 : -EBADMSG;
}
