/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native deployment assurance passport replay verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_assurance_passport_replay.h>

#define FIELD_VALUE_MAX 96U
#define PASSPORT_REPLAY_LINE_MAX 1280U

#define PASSPORT_MARKER_PREFIX "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT "

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
		value, PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS);
}

static void set_text(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0U) {
		return;
	}
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
}

/* ------------------------------------------------------------------ */
/* Passport digest recomputation (identical to the passport generator) */
/* ------------------------------------------------------------------ */

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

static void recompute_passport_digest(
	const struct pqcp_deployment_assurance_passport *passport,
	char out[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U])
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
	digest_to_hex(digest, out);
}

static enum pqcp_deployment_assurance_passport_status expected_status(
	const struct pqcp_deployment_assurance_passport *passport)
{
	if (passport->error_mask != 0U) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL;
	}
	if (passport->warning_mask != 0U) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN;
	}

	return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS;
}

static enum pqcp_deployment_assurance_passport_replay_error validate_passport(
	const struct pqcp_deployment_assurance_passport *passport,
	char recomputed[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U])
{
	if (passport->schema_version !=
	    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_BAD_SCHEMA;
	}
	if (!passport_status_valid(passport->status) ||
	    !seal_status_valid(passport->seal_status) ||
	    !seal_audit_status_valid(passport->seal_audit_status)) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_STATUS_MISMATCH;
	}
	if (!profile_valid(passport->profile)) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_PROFILE_MISMATCH;
	}
	if ((passport->error_mask &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_KNOWN_MASK) != 0U ||
	    (passport->warning_mask &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_KNOWN_MASK) != 0U) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MASK_RANGE;
	}
	if (passport->passport_score > 100U ||
	    passport->min_terminal_score > 100U ||
	    passport->capability_readiness_score > 100U) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_SCORE_RANGE;
	}
	if (passport->status != expected_status(passport)) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_STATUS_MISMATCH;
	}
	if (!text_marker_safe(passport->pqcp_version) ||
	    !text_marker_safe(passport->zephyr_version) ||
	    !text_marker_safe(passport->board) ||
	    !text_present(passport->top_candidate_id) ||
	    !nonce_valid(passport->nonce_hex) ||
	    !digest_valid(passport->seal_digest_hex) ||
	    !digest_valid(passport->seal_audit_digest_hex) ||
	    !digest_valid(passport->passport_digest_hex)) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MALFORMED_FIELD;
	}

	recompute_passport_digest(passport, recomputed);
	if (strcmp(recomputed, passport->passport_digest_hex) != 0) {
		return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_DIGEST_MISMATCH;
	}

	return PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE;
}

static void build_result(
	const struct pqcp_deployment_assurance_passport *passport,
	const char *computed,
	enum pqcp_deployment_assurance_passport_replay_error first_error,
	struct pqcp_deployment_assurance_passport_replay_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_SCHEMA_VERSION;
	result->first_error = first_error;
	result->passport_status = passport->status;
	result->passport_error_mask = passport->error_mask;
	result->passport_warning_mask = passport->warning_mask;
	result->profile = passport->profile;
	result->passport_score = passport->passport_score;
	result->min_terminal_score = passport->min_terminal_score;
	result->evidence_capabilities_all =
		passport->evidence_capabilities_all;
	result->evidence_capabilities_any =
		passport->evidence_capabilities_any;
	result->passed = first_error ==
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE;
	set_text(result->board, sizeof(result->board),
		 text_present(passport->board) ? passport->board : "unknown");
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 text_present(passport->top_candidate_id) ?
			 passport->top_candidate_id : "none");
	set_text(result->nonce_hex, sizeof(result->nonce_hex),
		 passport->nonce_hex);
	set_text(result->computed_digest_hex,
		 sizeof(result->computed_digest_hex), computed);
}

const char *pqcp_deployment_assurance_passport_replay_error_str(
	enum pqcp_deployment_assurance_passport_replay_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_DIGEST_MISMATCH:
		return "digest_mismatch";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_STATUS_MISMATCH:
		return "status_mismatch";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_PROFILE_MISMATCH:
		return "profile_mismatch";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MASK_RANGE:
		return "mask_range";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_SCORE_RANGE:
		return "score_range";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_DUPLICATE_MARKER:
		return "duplicate_marker";
	case PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MISSING_REQUIRED:
		return "missing_required";
	default:
		return "unknown";
	}
}

/* ------------------------------------------------------------------ */
/* Passport marker line ingestion                                      */
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

	return field_value(line, key, value, sizeof(value)) == 0 ?
		parse_u32_dec(value, out) : -EINVAL;
}

static int get_u32_hex(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_VALUE_MAX];

	return field_value(line, key, value, sizeof(value)) == 0 ?
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
	return field_value(line, key, out, out_len) == 0 ? 0 : -EINVAL;
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

static int parse_tri_status(const char *value, uint32_t *out)
{
	if (strcmp(value, "PASS") == 0) {
		*out = 2U;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = 1U;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = 0U;
		return 0;
	}

	return -EINVAL;
}

static int parse_passport_marker(
	const char *line,
	struct pqcp_deployment_assurance_passport *passport,
	char observed_digest[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U])
{
	char text[FIELD_VALUE_MAX];
	uint32_t tri;

	memset(passport, 0, sizeof(*passport));

	if (get_u32_dec(line, "schema", &passport->schema_version) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "profile", text, sizeof(text)) != 0 ||
	    parse_profile(text, &passport->profile) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "status", text, sizeof(text)) != 0 ||
	    parse_tri_status(text, &tri) != 0) {
		return -EINVAL;
	}
	passport->status = (enum pqcp_deployment_assurance_passport_status)tri;
	if (get_text(line, "seal_status", text, sizeof(text)) != 0 ||
	    parse_tri_status(text, &tri) != 0) {
		return -EINVAL;
	}
	passport->seal_status = (enum pqcp_deployment_evidence_seal_status)tri;
	if (get_text(line, "seal_audit_status", text, sizeof(text)) != 0 ||
	    parse_tri_status(text, &tri) != 0) {
		return -EINVAL;
	}
	passport->seal_audit_status =
		(enum pqcp_deployment_evidence_seal_audit_status)tri;
	if (get_u32_hex(line, "errors", &passport->error_mask) != 0 ||
	    get_u32_hex(line, "warnings", &passport->warning_mask) != 0 ||
	    get_u32_dec(line, "score", &passport->passport_score) != 0 ||
	    get_u32_dec(line, "min_score",
			&passport->min_terminal_score) != 0 ||
	    get_u32_dec(line, "capability_score",
			&passport->capability_readiness_score) != 0 ||
	    get_u32_dec(line, "audited_results",
			&passport->audited_result_count) != 0 ||
	    get_u32_dec(line, "chain_stages",
			&passport->chain_stage_count) != 0 ||
	    get_u32_hex(line, "evidence_all",
			&passport->evidence_capabilities_all) != 0 ||
	    get_u32_hex(line, "evidence_any",
			&passport->evidence_capabilities_any) != 0 ||
	    get_u32_hex(line, "mlkem_levels",
			&passport->mlkem_level_mask) != 0 ||
	    get_u32_hex(line, "mldsa_levels",
			&passport->mldsa_level_mask) != 0) {
		return -EINVAL;
	}
	if (get_bool_flag(line, "seal_replay_passed",
			  &passport->seal_replay_passed) != 0 ||
	    get_bool_flag(line, "top_consistent",
			  &passport->top_consistent) != 0 ||
	    get_bool_flag(line, "nonce_consistent",
			  &passport->nonce_consistent) != 0 ||
	    get_bool_flag(line, "digest_consistent",
			  &passport->seal_digest_consistent) != 0 ||
	    get_bool_flag(line, "profile_consistent",
			  &passport->profile_consistent) != 0 ||
	    get_bool_flag(line, "production_allowed",
			  &passport->production_allowed) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "pqcp_version", passport->pqcp_version,
		     sizeof(passport->pqcp_version)) != 0 ||
	    get_text(line, "zephyr_version", passport->zephyr_version,
		     sizeof(passport->zephyr_version)) != 0 ||
	    get_text(line, "board", passport->board,
		     sizeof(passport->board)) != 0 ||
	    get_text(line, "top", passport->top_candidate_id,
		     sizeof(passport->top_candidate_id)) != 0 ||
	    get_text(line, "nonce", passport->nonce_hex,
		     sizeof(passport->nonce_hex)) != 0 ||
	    get_text(line, "seal_digest", passport->seal_digest_hex,
		     sizeof(passport->seal_digest_hex)) != 0 ||
	    get_text(line, "seal_audit_digest",
		     passport->seal_audit_digest_hex,
		     sizeof(passport->seal_audit_digest_hex)) != 0 ||
	    get_text(line, "passport_digest", observed_digest,
		     PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS +
			     1U) != 0) {
		return -EINVAL;
	}

	set_text(passport->passport_digest_hex,
		 sizeof(passport->passport_digest_hex), observed_digest);
	return 0;
}

static void note_error(
	struct pqcp_deployment_assurance_passport_replay_state *state,
	enum pqcp_deployment_assurance_passport_replay_error error)
{
	if (state->first_error ==
	    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}
}

int pqcp_deployment_assurance_passport_replay_init(
	struct pqcp_deployment_assurance_passport_replay_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version =
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_SCHEMA_VERSION;
	state->first_error =
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE;
	return 0;
}

int pqcp_deployment_assurance_passport_replay_ingest_line(
	struct pqcp_deployment_assurance_passport_replay_state *state,
	const char *line)
{
	size_t len;

	if (state == NULL || line == NULL) {
		return -EINVAL;
	}

	len = strlen(line);
	if (len >= PASSPORT_REPLAY_LINE_MAX) {
		state->lines_seen++;
		note_error(state,
			   PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MALFORMED_FIELD);
		return -EINVAL;
	}

	if (strncmp(line, PASSPORT_MARKER_PREFIX,
		    strlen(PASSPORT_MARKER_PREFIX)) != 0) {
		/* Non-passport lines are ignored, not consumed as evidence. */
		return 0;
	}

	state->lines_seen++;

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_MARKER_PASSPORT) !=
	    0U) {
		note_error(state,
			   PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_DUPLICATE_MARKER);
		return -EINVAL;
	}

	if (parse_passport_marker(line, &state->passport,
				  state->passport_digest_observed_hex) != 0) {
		note_error(state,
			   PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MALFORMED_FIELD);
		return -EINVAL;
	}

	state->marker_mask |=
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_MARKER_PASSPORT;
	return 0;
}

int pqcp_deployment_assurance_passport_replay_finish(
	struct pqcp_deployment_assurance_passport_replay_state *state,
	struct pqcp_deployment_assurance_passport_replay_result *result)
{
	char recomputed[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_assurance_passport_replay_error error;

	if (state == NULL || result == NULL) {
		return -EINVAL;
	}

	if (state->first_error !=
	    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE) {
		recompute_passport_digest(&state->passport, recomputed);
		build_result(&state->passport, recomputed, state->first_error,
			     result);
		return -EBADMSG;
	}

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_REQUIRED_MASK) !=
	    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_REQUIRED_MASK) {
		recompute_passport_digest(&state->passport, recomputed);
		build_result(&state->passport, recomputed,
			     PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_MISSING_REQUIRED,
			     result);
		return -EBADMSG;
	}

	error = validate_passport(&state->passport, recomputed);
	if (error != PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE) {
		recompute_passport_digest(&state->passport, recomputed);
	}
	build_result(&state->passport, recomputed, error, result);

	return error == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_assurance_passport_replay_verify(
	const struct pqcp_deployment_assurance_passport *passport,
	struct pqcp_deployment_assurance_passport_replay_result *result)
{
	char recomputed[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_assurance_passport_replay_error error;

	if (passport == NULL || result == NULL) {
		return -EINVAL;
	}

	error = validate_passport(passport, recomputed);
	if (error != PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE) {
		recompute_passport_digest(passport, recomputed);
	}
	build_result(passport, recomputed, error, result);

	return error == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_assurance_passport_replay_emit_result(
	const struct pqcp_deployment_assurance_passport_replay_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_SCHEMA_VERSION ||
	    !passport_status_valid(result->passport_status) ||
	    !profile_valid(result->profile) ||
	    result->passport_score > 100U ||
	    result->min_terminal_score > 100U ||
	    !text_present(result->board) ||
	    !text_present(result->top_candidate_id) ||
	    !nonce_valid(result->nonce_hex) ||
	    !digest_valid(result->computed_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY schema=%u profile=%s status=%s passed=%s error=%s errors=0x%08x warnings=0x%08x score=%u min_score=%u evidence_all=0x%08x evidence_any=0x%08x board=%s top=%s nonce=%s computed_digest=%s\n",
	       result->schema_version,
	       pqcp_deployment_release_gate_profile_str(result->profile),
	       pqcp_deployment_assurance_passport_status_str(
		       result->passport_status),
	       result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_assurance_passport_replay_error_str(
		       result->first_error),
	       result->passport_error_mask,
	       result->passport_warning_mask,
	       result->passport_score,
	       result->min_terminal_score,
	       result->evidence_capabilities_all,
	       result->evidence_capabilities_any,
	       result->board,
	       result->top_candidate_id,
	       result->nonce_hex,
	       result->computed_digest_hex);

	return result->passed ? 0 : -EBADMSG;
}
