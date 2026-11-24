/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware-native deployment evidence seal replay verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_seal_replay.h>

#define FIELD_VALUE_MAX 96U
#define SEAL_REPLAY_LINE_MAX 1024U

#define SEAL_MARKER_PREFIX "PQCP_DEPLOYMENT_EVIDENCE_SEAL "

/* ------------------------------------------------------------------ */
/* Field tokenization helpers (mirrors deployment_evidence_verdict_replay) */
/* ------------------------------------------------------------------ */

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
		    strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
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

static int get_bool_flag(const char *line, const char *key, bool *out)
{
	uint32_t value;

	if (get_u32_dec(line, key, &value) != 0 || value > 1U) {
		return -EINVAL;
	}
	*out = value != 0U;
	return 0;
}

static int get_text(const char *line, const char *key, char *out,
		    size_t out_len)
{
	return get_field(line, key, out, out_len);
}

static bool is_hex_len(const char *value, size_t expected_len)
{
	if (value == NULL) {
		return false;
	}
	for (size_t i = 0U; i < expected_len; ++i) {
		const char c = value[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}

	return value[expected_len] == '\0';
}

static bool nonce_valid(const char *value)
{
	return is_hex_len(value, PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS);
}

static bool seal_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS);
}

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

static int parse_profile(const char *value,
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

static int parse_seal_status(const char *value,
			     enum pqcp_deployment_evidence_seal_status *out)
{
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL;
		return 0;
	}

	return -EINVAL;
}

static int parse_verdict_status(
	const char *value,
	enum pqcp_deployment_evidence_verdict_status *out)
{
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL;
		return 0;
	}

	return -EINVAL;
}

static int parse_audit_status(
	const char *value,
	enum pqcp_deployment_evidence_verdict_audit_status *out)
{
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT_FAIL;
		return 0;
	}

	return -EINVAL;
}

/* ------------------------------------------------------------------ */
/* Seal digest recomputation (identical to the seal generator)         */
/* ------------------------------------------------------------------ */

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

static void recompute_seal_digest(
	const struct pqcp_deployment_evidence_seal *seal,
	char out[PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U])
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
	digest_to_hex(digest, out);
}

/* ------------------------------------------------------------------ */
/* Seal structural validation                                          */
/* ------------------------------------------------------------------ */

static enum pqcp_deployment_evidence_seal_status expected_status(
	const struct pqcp_deployment_evidence_seal *seal)
{
	if (seal->error_mask != 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_FAIL;
	}
	if (seal->warning_mask != 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARN;
	}

	return PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
}

static enum pqcp_deployment_evidence_seal_replay_error validate_seal(
	const struct pqcp_deployment_evidence_seal *seal,
	char recomputed[PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U])
{
	if (seal->schema_version !=
	    PQCP_DEPLOYMENT_EVIDENCE_SEAL_SCHEMA_VERSION) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_BAD_SCHEMA;
	}
	if (!seal_status_valid(seal->status) ||
	    !verdict_status_valid(seal->verdict_status) ||
	    !audit_status_valid(seal->audit_status)) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_STATUS_MISMATCH;
	}
	if (!profile_valid(seal->profile)) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_PROFILE_MISMATCH;
	}
	if ((seal->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_SEAL_ERROR_KNOWN_MASK) != 0U ||
	    (seal->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_SEAL_WARNING_KNOWN_MASK) != 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MASK_RANGE;
	}
	if (seal->seal_score > 100U || seal->min_terminal_score > 100U) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_SCORE_RANGE;
	}
	if (seal->status != expected_status(seal)) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_STATUS_MISMATCH;
	}
	if (!text_present(seal->top_candidate_id) ||
	    !nonce_valid(seal->nonce_hex) ||
	    !seal_digest_valid(seal->verdict_digest_hex) ||
	    !seal_digest_valid(seal->audit_digest_hex) ||
	    !seal_digest_valid(seal->seal_digest_hex)) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MALFORMED_FIELD;
	}

	recompute_seal_digest(seal, recomputed);
	if (strcmp(recomputed, seal->seal_digest_hex) != 0) {
		return PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DIGEST_MISMATCH;
	}

	return PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE;
}

static void set_text(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0U) {
		return;
	}
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
}

static void build_result(
	const struct pqcp_deployment_evidence_seal *seal,
	const char *computed,
	uint32_t lines_seen,
	uint32_t marker_mask,
	uint32_t first_error_line,
	enum pqcp_deployment_evidence_seal_replay_error first_error,
	struct pqcp_deployment_evidence_seal_replay_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_SCHEMA_VERSION;
	result->lines_seen = lines_seen;
	result->marker_mask = marker_mask;
	result->first_error_line = first_error_line;
	result->first_error = first_error;
	result->seal_status = seal->status;
	result->seal_error_mask = seal->error_mask;
	result->seal_warning_mask = seal->warning_mask;
	result->profile = seal->profile;
	result->seal_score = seal->seal_score;
	result->min_terminal_score = seal->min_terminal_score;
	result->verdict_status = seal->verdict_status;
	result->audit_status = seal->audit_status;
	result->sealed_replay_passed = seal->replay_passed;
	result->audited_result_count = seal->audited_result_count;
	result->chain_stage_count = seal->chain_stage_count;
	result->chain_consistency_checks = seal->chain_consistency_checks;
	result->evidence_capabilities_all = seal->evidence_capabilities_all;
	result->evidence_capabilities_any = seal->evidence_capabilities_any;
	result->passed =
		first_error == PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE;
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 seal->top_candidate_id);
	set_text(result->nonce_hex, sizeof(result->nonce_hex),
		 seal->nonce_hex);
	set_text(result->verdict_digest_hex,
		 sizeof(result->verdict_digest_hex), seal->verdict_digest_hex);
	set_text(result->audit_digest_hex, sizeof(result->audit_digest_hex),
		 seal->audit_digest_hex);
	set_text(result->computed_digest_hex,
		 sizeof(result->computed_digest_hex), computed);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

const char *pqcp_deployment_evidence_seal_replay_error_str(
	enum pqcp_deployment_evidence_seal_replay_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DUPLICATE_MARKER:
		return "duplicate_marker";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MISSING_REQUIRED:
		return "missing_required";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_UNKNOWN_MARKER:
		return "unknown_marker";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DIGEST_MISMATCH:
		return "digest_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_STATUS_MISMATCH:
		return "status_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_PROFILE_MISMATCH:
		return "profile_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MASK_RANGE:
		return "mask_range";
	case PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_SCORE_RANGE:
		return "score_range";
	default:
		return "unknown";
	}
}

int pqcp_deployment_evidence_seal_replay_init(
	struct pqcp_deployment_evidence_seal_replay_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_SCHEMA_VERSION;
	state->first_error = PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE;
	return 0;
}

static void note_error(
	struct pqcp_deployment_evidence_seal_replay_state *state,
	enum pqcp_deployment_evidence_seal_replay_error error)
{
	if (state->first_error ==
	    PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}
}

static int parse_seal_marker(
	const char *line,
	struct pqcp_deployment_evidence_seal *seal,
	char observed_digest[PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U])
{
	char text[FIELD_VALUE_MAX];
	uint32_t replay_passed;

	memset(seal, 0, sizeof(*seal));

	if (get_u32_dec(line, "schema", &seal->schema_version) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "profile", text, sizeof(text)) != 0 ||
	    parse_profile(text, &seal->profile) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "status", text, sizeof(text)) != 0 ||
	    parse_seal_status(text, &seal->status) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "verdict_status", text, sizeof(text)) != 0 ||
	    parse_verdict_status(text, &seal->verdict_status) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "audit_status", text, sizeof(text)) != 0 ||
	    parse_audit_status(text, &seal->audit_status) != 0) {
		return -EINVAL;
	}
	if (get_u32_hex(line, "errors", &seal->error_mask) != 0 ||
	    get_u32_hex(line, "warnings", &seal->warning_mask) != 0 ||
	    get_u32_dec(line, "score", &seal->seal_score) != 0 ||
	    get_u32_dec(line, "min_score", &seal->min_terminal_score) != 0 ||
	    get_u32_dec(line, "replay_passed", &replay_passed) != 0 ||
	    replay_passed > 1U ||
	    get_u32_dec(line, "audited_results",
			&seal->audited_result_count) != 0 ||
	    get_u32_dec(line, "chain_stages", &seal->chain_stage_count) != 0 ||
	    get_u32_dec(line, "chain_consistency",
			&seal->chain_consistency_checks) != 0 ||
	    get_u32_hex(line, "evidence_all",
			&seal->evidence_capabilities_all) != 0 ||
	    get_u32_hex(line, "evidence_any",
			&seal->evidence_capabilities_any) != 0) {
		return -EINVAL;
	}
	seal->replay_passed = replay_passed != 0U;
	if (get_bool_flag(line, "top_consistent", &seal->top_consistent) != 0 ||
	    get_bool_flag(line, "nonce_consistent",
			  &seal->nonce_consistent) != 0 ||
	    get_bool_flag(line, "digest_consistent",
			  &seal->verdict_digest_consistent) != 0 ||
	    get_bool_flag(line, "profile_consistent",
			  &seal->profile_consistent) != 0 ||
	    get_bool_flag(line, "status_consistent",
			  &seal->status_consistent) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "top", seal->top_candidate_id,
		     sizeof(seal->top_candidate_id)) != 0 ||
	    get_text(line, "nonce", seal->nonce_hex,
		     sizeof(seal->nonce_hex)) != 0 ||
	    get_text(line, "verdict_digest", seal->verdict_digest_hex,
		     sizeof(seal->verdict_digest_hex)) != 0 ||
	    get_text(line, "audit_digest", seal->audit_digest_hex,
		     sizeof(seal->audit_digest_hex)) != 0 ||
	    get_text(line, "seal_digest", observed_digest,
		     PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U) != 0) {
		return -EINVAL;
	}

	set_text(seal->seal_digest_hex, sizeof(seal->seal_digest_hex),
		 observed_digest);
	return 0;
}

int pqcp_deployment_evidence_seal_replay_ingest_line(
	struct pqcp_deployment_evidence_seal_replay_state *state,
	const char *line)
{
	size_t len;

	if (state == NULL || line == NULL) {
		return -EINVAL;
	}

	len = strlen(line);
	if (len >= SEAL_REPLAY_LINE_MAX) {
		state->lines_seen++;
		note_error(state,
			   PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MALFORMED_FIELD);
		return -EINVAL;
	}

	if (strncmp(line, SEAL_MARKER_PREFIX,
		    strlen(SEAL_MARKER_PREFIX)) != 0) {
		/* Non-seal lines are ignored, not consumed as evidence. */
		return 0;
	}

	state->lines_seen++;

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_MARKER_SEAL) != 0U) {
		note_error(state,
			   PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_DUPLICATE_MARKER);
		return -EINVAL;
	}

	if (parse_seal_marker(line, &state->seal,
			      state->seal_digest_observed_hex) != 0) {
		note_error(state,
			   PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MALFORMED_FIELD);
		return -EINVAL;
	}

	state->marker_mask |= PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_MARKER_SEAL;
	return 0;
}

int pqcp_deployment_evidence_seal_replay_finish(
	struct pqcp_deployment_evidence_seal_replay_state *state,
	struct pqcp_deployment_evidence_seal_replay_result *result)
{
	char recomputed[PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_evidence_seal_replay_error error;

	if (state == NULL || result == NULL) {
		return -EINVAL;
	}

	if (state->first_error !=
	    PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE) {
		recompute_seal_digest(&state->seal, recomputed);
		build_result(&state->seal, recomputed, state->lines_seen,
			     state->marker_mask, state->first_error_line,
			     state->first_error, result);
		return -EBADMSG;
	}

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_REQUIRED_MASK) !=
	    PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_REQUIRED_MASK) {
		recompute_seal_digest(&state->seal, recomputed);
		build_result(&state->seal, recomputed, state->lines_seen,
			     state->marker_mask, state->lines_seen,
			     PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_MISSING_REQUIRED,
			     result);
		return -EBADMSG;
	}

	error = validate_seal(&state->seal, recomputed);
	build_result(&state->seal, recomputed, state->lines_seen,
		     state->marker_mask,
		     error == PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE ?
			     0U : state->lines_seen,
		     error, result);

	return error == PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_evidence_seal_replay_verify(
	const struct pqcp_deployment_evidence_seal *seal,
	struct pqcp_deployment_evidence_seal_replay_result *result)
{
	char recomputed[PQCP_DEPLOYMENT_EVIDENCE_SEAL_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_evidence_seal_replay_error error;

	if (seal == NULL || result == NULL) {
		return -EINVAL;
	}

	error = validate_seal(seal, recomputed);
	build_result(seal, recomputed, 1U,
		     PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_MARKER_SEAL,
		     error == PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE ?
			     0U : 1U,
		     error, result);

	return error == PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_evidence_seal_replay_emit_result(
	const struct pqcp_deployment_evidence_seal_replay_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY_SCHEMA_VERSION ||
	    !seal_status_valid(result->seal_status) ||
	    !profile_valid(result->profile) ||
	    result->seal_score > 100U || result->min_terminal_score > 100U ||
	    !text_present(result->top_candidate_id) ||
	    !nonce_valid(result->nonce_hex) ||
	    !seal_digest_valid(result->computed_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY schema=%u profile=%s status=%s passed=%s error=%s error_line=%u lines=%u markers=0x%08x errors=0x%08x warnings=0x%08x score=%u min_score=%u verdict_status=%s audit_status=%s sealed_replay_passed=%u audited_results=%u chain_stages=%u chain_consistency=%u evidence_all=0x%08x evidence_any=0x%08x top=%s nonce=%s computed_digest=%s\n",
	       result->schema_version,
	       pqcp_deployment_release_gate_profile_str(result->profile),
	       pqcp_deployment_evidence_seal_status_str(result->seal_status),
	       result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_evidence_seal_replay_error_str(
		       result->first_error),
	       result->first_error_line,
	       result->lines_seen,
	       result->marker_mask,
	       result->seal_error_mask,
	       result->seal_warning_mask,
	       result->seal_score,
	       result->min_terminal_score,
	       pqcp_deployment_evidence_verdict_status_str(
		       result->verdict_status),
	       pqcp_deployment_evidence_verdict_audit_status_str(
		       result->audit_status),
	       result->sealed_replay_passed ? 1U : 0U,
	       result->audited_result_count,
	       result->chain_stage_count,
	       result->chain_consistency_checks,
	       result->evidence_capabilities_all,
	       result->evidence_capabilities_any,
	       result->top_candidate_id,
	       result->nonce_hex,
	       result->computed_digest_hex);

	return result->passed ? 0 : -EBADMSG;
}
