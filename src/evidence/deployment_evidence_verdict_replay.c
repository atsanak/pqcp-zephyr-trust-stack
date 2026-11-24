/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware-native deployment evidence verdict replay verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_verdict_replay.h>

#define FIELD_VALUE_MAX 96U
#define VERDICT_REPLAY_LINE_MAX 1024U

#define VERDICT_MARKER_PREFIX "PQCP_DEPLOYMENT_EVIDENCE_VERDICT "

/* ------------------------------------------------------------------ */
/* Field tokenization helpers (mirrors deployment_device_packet_replay) */
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

static bool trace_digest_valid(const char *value)
{
	return is_hex_len(value, PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS);
}

static bool review_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS);
}

static bool device_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_DEVICE_PACKET_DIGEST_HEX_CHARS);
}

static bool token_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_DEVICE_TOKEN_DIGEST_HEX_CHARS);
}

static bool verdict_digest_valid(const char *value)
{
	return is_hex_len(value,
			  PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS);
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

static bool verdict_status_valid(
	enum pqcp_deployment_evidence_verdict_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL;
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

static int parse_status(const char *value,
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

/* ------------------------------------------------------------------ */
/* Verdict digest recomputation (identical to the verdict evaluator)   */
/* ------------------------------------------------------------------ */

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

static void recompute_verdict_digest(
	const struct pqcp_deployment_evidence_verdict *verdict,
	char out[PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U])
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
	digest_to_hex(digest, out);
}

/* ------------------------------------------------------------------ */
/* Verdict structural validation                                       */
/* ------------------------------------------------------------------ */

static enum pqcp_deployment_evidence_verdict_status expected_status(
	const struct pqcp_deployment_evidence_verdict *verdict)
{
	if (verdict->error_mask != 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_FAIL;
	}
	if (verdict->warning_mask != 0U || verdict->warn_count != 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARN;
	}

	return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_PASS;
}

static enum pqcp_deployment_evidence_verdict_replay_error validate_verdict(
	const struct pqcp_deployment_evidence_verdict *verdict,
	char recomputed[PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U])
{
	if (verdict->schema_version !=
	    PQCP_DEPLOYMENT_EVIDENCE_VERDICT_SCHEMA_VERSION) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_BAD_SCHEMA;
	}
	if (!verdict_status_valid(verdict->status)) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_STATUS_MISMATCH;
	}
	if (!profile_valid(verdict->profile)) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_PROFILE_MISMATCH;
	}
	if ((verdict->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_VERDICT_ERROR_KNOWN_MASK) != 0U ||
	    (verdict->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_VERDICT_WARNING_KNOWN_MASK) != 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MASK_RANGE;
	}
	if (verdict->verdict_score > 100U || verdict->min_chain_score > 100U) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_SCORE_RANGE;
	}
	if (verdict->pass_count + verdict->warn_count + verdict->fail_count !=
	    verdict->stage_count) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_STAGE_COUNT_MISMATCH;
	}
	if (verdict->consistency_pass_count > verdict->consistency_checks) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_CONSISTENCY_MISMATCH;
	}
	if (verdict->status != expected_status(verdict)) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_STATUS_MISMATCH;
	}
	if (!text_present(verdict->top_candidate_id) ||
	    !nonce_valid(verdict->nonce_hex) ||
	    !trace_digest_valid(verdict->trace_digest_hex) ||
	    !review_digest_valid(verdict->review_packet_digest_hex) ||
	    !device_digest_valid(verdict->device_packet_digest_hex) ||
	    !token_digest_valid(verdict->token_digest_hex) ||
	    !device_digest_valid(verdict->packet_audit_digest_hex) ||
	    !verdict_digest_valid(verdict->verdict_digest_hex)) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MALFORMED_FIELD;
	}

	recompute_verdict_digest(verdict, recomputed);
	if (strcmp(recomputed, verdict->verdict_digest_hex) != 0) {
		return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_DIGEST_MISMATCH;
	}

	return PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE;
}

static void set_text(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0U) {
		return;
	}
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
}

static void build_result(
	const struct pqcp_deployment_evidence_verdict *verdict,
	const char *computed,
	uint32_t lines_seen,
	uint32_t marker_mask,
	uint32_t first_error_line,
	enum pqcp_deployment_evidence_verdict_replay_error first_error,
	struct pqcp_deployment_evidence_verdict_replay_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_SCHEMA_VERSION;
	result->lines_seen = lines_seen;
	result->marker_mask = marker_mask;
	result->first_error_line = first_error_line;
	result->first_error = first_error;
	result->verdict_status = verdict->status;
	result->verdict_error_mask = verdict->error_mask;
	result->verdict_warning_mask = verdict->warning_mask;
	result->profile = verdict->profile;
	result->verdict_score = verdict->verdict_score;
	result->min_chain_score = verdict->min_chain_score;
	result->stage_count = verdict->stage_count;
	result->consistency_checks = verdict->consistency_checks;
	result->consistency_pass_count = verdict->consistency_pass_count;
	result->evidence_capabilities_all = verdict->evidence_capabilities_all;
	result->evidence_capabilities_any = verdict->evidence_capabilities_any;
	result->passed =
		first_error == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE;
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 verdict->top_candidate_id);
	set_text(result->nonce_hex, sizeof(result->nonce_hex),
		 verdict->nonce_hex);
	set_text(result->computed_digest_hex,
		 sizeof(result->computed_digest_hex), computed);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

const char *pqcp_deployment_evidence_verdict_replay_error_str(
	enum pqcp_deployment_evidence_verdict_replay_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_DUPLICATE_MARKER:
		return "duplicate_marker";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MISSING_REQUIRED:
		return "missing_required";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_UNKNOWN_MARKER:
		return "unknown_marker";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_DIGEST_MISMATCH:
		return "digest_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_STATUS_MISMATCH:
		return "status_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_PROFILE_MISMATCH:
		return "profile_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MASK_RANGE:
		return "mask_range";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_SCORE_RANGE:
		return "score_range";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_STAGE_COUNT_MISMATCH:
		return "stage_count_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_CONSISTENCY_MISMATCH:
		return "consistency_mismatch";
	default:
		return "unknown";
	}
}

int pqcp_deployment_evidence_verdict_replay_init(
	struct pqcp_deployment_evidence_verdict_replay_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_SCHEMA_VERSION;
	state->first_error = PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE;
	return 0;
}

static void note_error(
	struct pqcp_deployment_evidence_verdict_replay_state *state,
	enum pqcp_deployment_evidence_verdict_replay_error error)
{
	if (state->first_error ==
	    PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}
}

static int parse_verdict_marker(
	const char *line,
	struct pqcp_deployment_evidence_verdict *verdict,
	char observed_digest[PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U])
{
	char text[FIELD_VALUE_MAX];

	memset(verdict, 0, sizeof(*verdict));

	if (get_u32_dec(line, "schema", &verdict->schema_version) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "profile", text, sizeof(text)) != 0 ||
	    parse_profile(text, &verdict->profile) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "status", text, sizeof(text)) != 0 ||
	    parse_status(text, &verdict->status) != 0) {
		return -EINVAL;
	}
	if (get_u32_hex(line, "errors", &verdict->error_mask) != 0 ||
	    get_u32_hex(line, "warnings", &verdict->warning_mask) != 0 ||
	    get_u32_dec(line, "score", &verdict->verdict_score) != 0 ||
	    get_u32_dec(line, "min_score", &verdict->min_chain_score) != 0 ||
	    get_u32_dec(line, "stages", &verdict->stage_count) != 0 ||
	    get_u32_dec(line, "pass", &verdict->pass_count) != 0 ||
	    get_u32_dec(line, "warn", &verdict->warn_count) != 0 ||
	    get_u32_dec(line, "fail", &verdict->fail_count) != 0 ||
	    get_u32_dec(line, "consistency", &verdict->consistency_checks) != 0 ||
	    get_u32_dec(line, "consistency_pass",
			&verdict->consistency_pass_count) != 0 ||
	    get_u32_hex(line, "evidence_all",
			&verdict->evidence_capabilities_all) != 0 ||
	    get_u32_hex(line, "evidence_any",
			&verdict->evidence_capabilities_any) != 0) {
		return -EINVAL;
	}
	if (get_bool_flag(line, "top_consistent", &verdict->top_consistent) != 0 ||
	    get_bool_flag(line, "nonce_consistent",
			  &verdict->nonce_consistent) != 0 ||
	    get_bool_flag(line, "trace_consistent",
			  &verdict->trace_digest_consistent) != 0 ||
	    get_bool_flag(line, "review_digest_consistent",
			  &verdict->review_packet_digest_consistent) != 0 ||
	    get_bool_flag(line, "device_digest_consistent",
			  &verdict->device_packet_digest_consistent) != 0 ||
	    get_bool_flag(line, "token_digest_consistent",
			  &verdict->token_digest_consistent) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "top", verdict->top_candidate_id,
		     sizeof(verdict->top_candidate_id)) != 0 ||
	    get_text(line, "nonce", verdict->nonce_hex,
		     sizeof(verdict->nonce_hex)) != 0 ||
	    get_text(line, "trace_digest", verdict->trace_digest_hex,
		     sizeof(verdict->trace_digest_hex)) != 0 ||
	    get_text(line, "review_digest", verdict->review_packet_digest_hex,
		     sizeof(verdict->review_packet_digest_hex)) != 0 ||
	    get_text(line, "device_digest", verdict->device_packet_digest_hex,
		     sizeof(verdict->device_packet_digest_hex)) != 0 ||
	    get_text(line, "token_digest", verdict->token_digest_hex,
		     sizeof(verdict->token_digest_hex)) != 0 ||
	    get_text(line, "packet_audit_digest",
		     verdict->packet_audit_digest_hex,
		     sizeof(verdict->packet_audit_digest_hex)) != 0 ||
	    get_text(line, "verdict_digest", observed_digest,
		     PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U) != 0) {
		return -EINVAL;
	}

	set_text(verdict->verdict_digest_hex,
		 sizeof(verdict->verdict_digest_hex), observed_digest);
	return 0;
}

int pqcp_deployment_evidence_verdict_replay_ingest_line(
	struct pqcp_deployment_evidence_verdict_replay_state *state,
	const char *line)
{
	size_t len;

	if (state == NULL || line == NULL) {
		return -EINVAL;
	}

	len = strlen(line);
	if (len >= VERDICT_REPLAY_LINE_MAX) {
		state->lines_seen++;
		note_error(state,
			   PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MALFORMED_FIELD);
		return -EINVAL;
	}

	if (strncmp(line, VERDICT_MARKER_PREFIX,
		    strlen(VERDICT_MARKER_PREFIX)) != 0) {
		/* Non-verdict lines are ignored, not consumed as evidence. */
		return 0;
	}

	state->lines_seen++;

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_MARKER_VERDICT) != 0U) {
		note_error(state,
			   PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_DUPLICATE_MARKER);
		return -EINVAL;
	}

	if (parse_verdict_marker(line, &state->verdict,
				 state->verdict_digest_observed_hex) != 0) {
		note_error(state,
			   PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MALFORMED_FIELD);
		return -EINVAL;
	}

	state->marker_mask |=
		PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_MARKER_VERDICT;
	return 0;
}

int pqcp_deployment_evidence_verdict_replay_finish(
	struct pqcp_deployment_evidence_verdict_replay_state *state,
	struct pqcp_deployment_evidence_verdict_replay_result *result)
{
	char recomputed[PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_evidence_verdict_replay_error error;

	if (state == NULL || result == NULL) {
		return -EINVAL;
	}

	if (state->first_error !=
	    PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE) {
		recompute_verdict_digest(&state->verdict, recomputed);
		build_result(&state->verdict, recomputed, state->lines_seen,
			     state->marker_mask, state->first_error_line,
			     state->first_error, result);
		return -EBADMSG;
	}

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_REQUIRED_MASK) !=
	    PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_REQUIRED_MASK) {
		recompute_verdict_digest(&state->verdict, recomputed);
		build_result(&state->verdict, recomputed, state->lines_seen,
			     state->marker_mask, state->lines_seen,
			     PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_MISSING_REQUIRED,
			     result);
		return -EBADMSG;
	}

	error = validate_verdict(&state->verdict, recomputed);
	build_result(&state->verdict, recomputed, state->lines_seen,
		     state->marker_mask,
		     error == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE ?
			     0U : state->lines_seen,
		     error, result);

	return error == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_evidence_verdict_replay_verify(
	const struct pqcp_deployment_evidence_verdict *verdict,
	struct pqcp_deployment_evidence_verdict_replay_result *result)
{
	char recomputed[PQCP_DEPLOYMENT_EVIDENCE_VERDICT_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_evidence_verdict_replay_error error;

	if (verdict == NULL || result == NULL) {
		return -EINVAL;
	}

	error = validate_verdict(verdict, recomputed);
	build_result(verdict, recomputed, 1U,
		     PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_MARKER_VERDICT,
		     error == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE ?
			     0U : 1U,
		     error, result);

	return error == PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_evidence_verdict_replay_emit_result(
	const struct pqcp_deployment_evidence_verdict_replay_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY_SCHEMA_VERSION ||
	    !verdict_status_valid(result->verdict_status) ||
	    !profile_valid(result->profile) ||
	    result->verdict_score > 100U || result->min_chain_score > 100U ||
	    !text_present(result->top_candidate_id) ||
	    !nonce_valid(result->nonce_hex) ||
	    !verdict_digest_valid(result->computed_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY schema=%u profile=%s status=%s passed=%s error=%s error_line=%u lines=%u markers=0x%08x errors=0x%08x warnings=0x%08x score=%u min_score=%u stages=%u consistency=%u consistency_pass=%u evidence_all=0x%08x evidence_any=0x%08x top=%s nonce=%s computed_digest=%s\n",
	       result->schema_version,
	       pqcp_deployment_release_gate_profile_str(result->profile),
	       pqcp_deployment_evidence_verdict_status_str(result->verdict_status),
	       result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_evidence_verdict_replay_error_str(
		       result->first_error),
	       result->first_error_line,
	       result->lines_seen,
	       result->marker_mask,
	       result->verdict_error_mask,
	       result->verdict_warning_mask,
	       result->verdict_score,
	       result->min_chain_score,
	       result->stage_count,
	       result->consistency_checks,
	       result->consistency_pass_count,
	       result->evidence_capabilities_all,
	       result->evidence_capabilities_any,
	       result->top_candidate_id,
	       result->nonce_hex,
	       result->computed_digest_hex);

	return result->passed ? 0 : -EBADMSG;
}
