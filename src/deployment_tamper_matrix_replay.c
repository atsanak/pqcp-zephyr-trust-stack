/*
 * SPDX-License-Identifier: MIT
 *
 * Tamper matrix replay verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_tamper_matrix_replay.h>

#define FIELD_VALUE_MAX 96U
#define MATRIX_REPLAY_LINE_MAX 1280U

#define MATRIX_MARKER_PREFIX "PQCP_DEPLOYMENT_TAMPER_MATRIX "

/* ------------------------------------------------------------------ */
/* Field tokenization helpers (mirrors deployment_evidence_seal_replay) */
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

static int get_text(const char *line, const char *key, char *out,
		    size_t out_len)
{
	return field_value(line, key, out, out_len) == 0 ? 0 : -EINVAL;
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
		value, PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS);
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

static bool matrix_status_valid(
	enum pqcp_deployment_tamper_matrix_status status)
{
	return status == PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS ||
	       status == PQCP_DEPLOYMENT_TAMPER_MATRIX_WARN ||
	       status == PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL;
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

static int parse_matrix_status(
	const char *value, enum pqcp_deployment_tamper_matrix_status *out)
{
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_TAMPER_MATRIX_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL;
		return 0;
	}

	return -EINVAL;
}

static void set_text(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0U) {
		return;
	}
	(void)snprintk(dst, dst_size, "%s", src != NULL ? src : "");
}

/* ------------------------------------------------------------------ */
/* Matrix digest recomputation (identical to the matrix generator)     */
/* ------------------------------------------------------------------ */

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0xa3c59dc1e7b40f25ULL;
	digest[1] = 0x51d0c8e7a9b3f6acULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0xc2b2ae3d27d4eb4fULL;
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

static void digest_to_hex(
	const uint64_t digest[4],
	char out[PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(
		out,
		PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U,
		"%016llx%016llx%016llx%016llx",
		(unsigned long long)digest[0],
		(unsigned long long)digest[1],
		(unsigned long long)digest[2],
		(unsigned long long)digest[3]);
}

static void recompute_matrix_digest(
	const struct pqcp_deployment_tamper_matrix_report *report,
	char out[PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U])
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest, report->schema_version);
	digest_update_u32(digest, (uint32_t)report->status);
	digest_update_u32(digest, report->error_mask);
	digest_update_u32(digest, report->warning_mask);
	digest_update_u32(digest, (uint32_t)report->profile);
	digest_update_u32(digest, report->stage_mask);
	digest_update_u32(digest, report->cell_count);
	digest_update_u32(digest, report->control_count);
	digest_update_u32(digest, report->attack_count);
	digest_update_u32(digest, report->detected_count);
	digest_update_u32(digest, report->missed_count);
	digest_update_u32(digest, report->control_pass_count);
	digest_update_u32(digest, report->coverage_permille);
	digest_update_u32(digest, report->verdict_class_mask);
	digest_update_u32(digest, report->seal_class_mask);
	digest_update_u32(digest, report->passport_class_mask);
	digest_update_text(digest, report->top_candidate_id);
	digest_update_text(digest, report->nonce_hex);
	digest_update_text(digest, report->verdict_digest_hex);
	digest_update_text(digest, report->seal_digest_hex);
	digest_update_text(digest, report->passport_digest_hex);
	digest_to_hex(digest, out);
}

/* ------------------------------------------------------------------ */
/* Matrix structural validation                                        */
/* ------------------------------------------------------------------ */

static uint32_t popcount_u32(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += value & 1U;
		value >>= 1U;
	}

	return count;
}

static enum pqcp_deployment_tamper_matrix_status expected_status(
	const struct pqcp_deployment_tamper_matrix_report *report)
{
	if (report->error_mask != 0U) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_FAIL;
	}
	if (report->warning_mask != 0U) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_WARN;
	}

	return PQCP_DEPLOYMENT_TAMPER_MATRIX_PASS;
}

static enum pqcp_deployment_tamper_matrix_replay_error validate_matrix(
	const struct pqcp_deployment_tamper_matrix_report *report,
	char recomputed[PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U])
{
	const uint32_t class_known_mask =
		(1U << PQCP_DEPLOYMENT_TAMPER_CLASS_COUNT) - 1U;
	uint32_t expected_coverage;
	uint32_t ok_bits;

	if (report->schema_version !=
	    PQCP_DEPLOYMENT_TAMPER_MATRIX_SCHEMA_VERSION) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_BAD_SCHEMA;
	}
	if (!matrix_status_valid(report->status)) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_STATUS_MISMATCH;
	}
	if (!profile_valid(report->profile)) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_PROFILE_MISMATCH;
	}
	if ((report->error_mask &
	     ~PQCP_DEPLOYMENT_TAMPER_MATRIX_ERROR_KNOWN_MASK) != 0U ||
	    (report->warning_mask &
	     ~PQCP_DEPLOYMENT_TAMPER_MATRIX_WARNING_KNOWN_MASK) != 0U ||
	    (report->stage_mask &
	     ~PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_KNOWN_MASK) != 0U ||
	    report->stage_mask == 0U ||
	    (report->verdict_class_mask & ~class_known_mask) != 0U ||
	    (report->seal_class_mask & ~class_known_mask) != 0U ||
	    (report->passport_class_mask & ~class_known_mask) != 0U) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MASK_RANGE;
	}
	if ((report->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_VERDICT_BIT) == 0U &&
	    report->verdict_class_mask != 0U) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MASK_RANGE;
	}
	if ((report->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_SEAL_BIT) == 0U &&
	    report->seal_class_mask != 0U) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MASK_RANGE;
	}
	if ((report->stage_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_STAGE_PASSPORT_BIT) == 0U &&
	    report->passport_class_mask != 0U) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MASK_RANGE;
	}
	if (report->cell_count !=
		    report->control_count + report->attack_count ||
	    report->detected_count + report->missed_count !=
		    report->attack_count ||
	    report->control_pass_count > report->control_count ||
	    report->cell_count > PQCP_DEPLOYMENT_TAMPER_MATRIX_MAX_CELLS) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_COUNT_MISMATCH;
	}
	ok_bits = popcount_u32(report->verdict_class_mask) +
		  popcount_u32(report->seal_class_mask) +
		  popcount_u32(report->passport_class_mask);
	if (ok_bits != report->detected_count + report->control_pass_count) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_COUNT_MISMATCH;
	}
	expected_coverage = report->attack_count == 0U ? 0U :
		(report->detected_count * 1000U) / report->attack_count;
	if (report->coverage_permille != expected_coverage ||
	    report->coverage_permille > 1000U) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_COVERAGE_MISMATCH;
	}
	if (report->status != expected_status(report)) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_STATUS_MISMATCH;
	}
	if (!text_present(report->top_candidate_id) ||
	    !nonce_valid(report->nonce_hex) ||
	    !digest_valid(report->verdict_digest_hex) ||
	    !digest_valid(report->seal_digest_hex) ||
	    !digest_valid(report->passport_digest_hex) ||
	    !digest_valid(report->matrix_digest_hex)) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MALFORMED_FIELD;
	}

	recompute_matrix_digest(report, recomputed);
	if (strcmp(recomputed, report->matrix_digest_hex) != 0) {
		return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DIGEST_MISMATCH;
	}

	return PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE;
}

static void build_result(
	const struct pqcp_deployment_tamper_matrix_report *report,
	const char *computed,
	uint32_t lines_seen,
	uint32_t marker_mask,
	uint32_t first_error_line,
	enum pqcp_deployment_tamper_matrix_replay_error first_error,
	struct pqcp_deployment_tamper_matrix_replay_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_SCHEMA_VERSION;
	result->lines_seen = lines_seen;
	result->marker_mask = marker_mask;
	result->first_error_line = first_error_line;
	result->first_error = first_error;
	result->matrix_status = report->status;
	result->matrix_error_mask = report->error_mask;
	result->matrix_warning_mask = report->warning_mask;
	result->profile = report->profile;
	result->stage_mask = report->stage_mask;
	result->cell_count = report->cell_count;
	result->attack_count = report->attack_count;
	result->detected_count = report->detected_count;
	result->missed_count = report->missed_count;
	result->control_pass_count = report->control_pass_count;
	result->coverage_permille = report->coverage_permille;
	result->passed = first_error ==
		PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE;
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 text_present(report->top_candidate_id) ?
			 report->top_candidate_id : "none");
	set_text(result->nonce_hex, sizeof(result->nonce_hex),
		 report->nonce_hex);
	set_text(result->passport_digest_hex,
		 sizeof(result->passport_digest_hex),
		 report->passport_digest_hex);
	set_text(result->computed_digest_hex,
		 sizeof(result->computed_digest_hex), computed);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

const char *pqcp_deployment_tamper_matrix_replay_error_str(
	enum pqcp_deployment_tamper_matrix_replay_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DUPLICATE_MARKER:
		return "duplicate_marker";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MISSING_REQUIRED:
		return "missing_required";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DIGEST_MISMATCH:
		return "digest_mismatch";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_STATUS_MISMATCH:
		return "status_mismatch";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_PROFILE_MISMATCH:
		return "profile_mismatch";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MASK_RANGE:
		return "mask_range";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_COUNT_MISMATCH:
		return "count_mismatch";
	case PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_COVERAGE_MISMATCH:
		return "coverage_mismatch";
	default:
		return "unknown";
	}
}

int pqcp_deployment_tamper_matrix_replay_init(
	struct pqcp_deployment_tamper_matrix_replay_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version =
		PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_SCHEMA_VERSION;
	state->first_error = PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE;
	return 0;
}

static void note_error(
	struct pqcp_deployment_tamper_matrix_replay_state *state,
	enum pqcp_deployment_tamper_matrix_replay_error error)
{
	if (state->first_error ==
	    PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}
}

static int parse_matrix_marker(
	const char *line,
	struct pqcp_deployment_tamper_matrix_report *report,
	char observed_digest[
		PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U])
{
	char text[FIELD_VALUE_MAX];

	memset(report, 0, sizeof(*report));

	if (get_u32_dec(line, "schema", &report->schema_version) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "profile", text, sizeof(text)) != 0 ||
	    parse_profile(text, &report->profile) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "status", text, sizeof(text)) != 0 ||
	    parse_matrix_status(text, &report->status) != 0) {
		return -EINVAL;
	}
	if (get_u32_hex(line, "errors", &report->error_mask) != 0 ||
	    get_u32_hex(line, "warnings", &report->warning_mask) != 0 ||
	    get_u32_hex(line, "stage_mask", &report->stage_mask) != 0 ||
	    get_u32_dec(line, "cells", &report->cell_count) != 0 ||
	    get_u32_dec(line, "controls", &report->control_count) != 0 ||
	    get_u32_dec(line, "attacks", &report->attack_count) != 0 ||
	    get_u32_dec(line, "detected", &report->detected_count) != 0 ||
	    get_u32_dec(line, "missed", &report->missed_count) != 0 ||
	    get_u32_dec(line, "controls_passed",
			&report->control_pass_count) != 0 ||
	    get_u32_dec(line, "coverage_permille",
			&report->coverage_permille) != 0 ||
	    get_u32_hex(line, "verdict_class_mask",
			&report->verdict_class_mask) != 0 ||
	    get_u32_hex(line, "seal_class_mask",
			&report->seal_class_mask) != 0 ||
	    get_u32_hex(line, "passport_class_mask",
			&report->passport_class_mask) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "top", report->top_candidate_id,
		     sizeof(report->top_candidate_id)) != 0 ||
	    get_text(line, "nonce", report->nonce_hex,
		     sizeof(report->nonce_hex)) != 0 ||
	    get_text(line, "verdict_digest", report->verdict_digest_hex,
		     sizeof(report->verdict_digest_hex)) != 0 ||
	    get_text(line, "seal_digest", report->seal_digest_hex,
		     sizeof(report->seal_digest_hex)) != 0 ||
	    get_text(line, "passport_digest", report->passport_digest_hex,
		     sizeof(report->passport_digest_hex)) != 0 ||
	    get_text(line, "matrix_digest", observed_digest,
		     PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U) !=
		    0) {
		return -EINVAL;
	}

	set_text(report->matrix_digest_hex, sizeof(report->matrix_digest_hex),
		 observed_digest);
	return 0;
}

int pqcp_deployment_tamper_matrix_replay_ingest_line(
	struct pqcp_deployment_tamper_matrix_replay_state *state,
	const char *line)
{
	size_t len;

	if (state == NULL || line == NULL) {
		return -EINVAL;
	}

	len = strlen(line);
	if (len >= MATRIX_REPLAY_LINE_MAX) {
		state->lines_seen++;
		note_error(state,
			   PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MALFORMED_FIELD);
		return -EINVAL;
	}

	if (strncmp(line, MATRIX_MARKER_PREFIX,
		    strlen(MATRIX_MARKER_PREFIX)) != 0) {
		/* Non-matrix lines are ignored, not consumed as evidence. */
		return 0;
	}

	state->lines_seen++;

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_MARKER_MATRIX) != 0U) {
		note_error(state,
			   PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_DUPLICATE_MARKER);
		return -EINVAL;
	}

	if (parse_matrix_marker(line, &state->report,
				state->matrix_digest_observed_hex) != 0) {
		note_error(state,
			   PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MALFORMED_FIELD);
		return -EINVAL;
	}

	state->marker_mask |=
		PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_MARKER_MATRIX;
	return 0;
}

int pqcp_deployment_tamper_matrix_replay_finish(
	struct pqcp_deployment_tamper_matrix_replay_state *state,
	struct pqcp_deployment_tamper_matrix_replay_result *result)
{
	char recomputed[PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_tamper_matrix_replay_error error;

	if (state == NULL || result == NULL) {
		return -EINVAL;
	}

	if (state->first_error !=
	    PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE) {
		recompute_matrix_digest(&state->report, recomputed);
		build_result(&state->report, recomputed, state->lines_seen,
			     state->marker_mask, state->first_error_line,
			     state->first_error, result);
		return -EBADMSG;
	}

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_REQUIRED_MASK) !=
	    PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_REQUIRED_MASK) {
		recompute_matrix_digest(&state->report, recomputed);
		build_result(&state->report, recomputed, state->lines_seen,
			     state->marker_mask, state->lines_seen,
			     PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_MISSING_REQUIRED,
			     result);
		return -EBADMSG;
	}

	error = validate_matrix(&state->report, recomputed);
	if (error != PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE) {
		recompute_matrix_digest(&state->report, recomputed);
	}
	build_result(&state->report, recomputed, state->lines_seen,
		     state->marker_mask,
		     error == PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE ?
			     0U : state->lines_seen,
		     error, result);

	return error == PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_tamper_matrix_replay_verify(
	const struct pqcp_deployment_tamper_matrix_report *report,
	struct pqcp_deployment_tamper_matrix_replay_result *result)
{
	char recomputed[PQCP_DEPLOYMENT_TAMPER_MATRIX_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_tamper_matrix_replay_error error;

	if (report == NULL || result == NULL) {
		return -EINVAL;
	}

	error = validate_matrix(report, recomputed);
	if (error != PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE) {
		recompute_matrix_digest(report, recomputed);
	}
	build_result(report, recomputed, 1U,
		     PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_MARKER_MATRIX,
		     error == PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE ?
			     0U : 1U,
		     error, result);

	return error == PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_tamper_matrix_replay_emit_result(
	const struct pqcp_deployment_tamper_matrix_replay_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY_SCHEMA_VERSION ||
	    !matrix_status_valid(result->matrix_status) ||
	    !profile_valid(result->profile) ||
	    result->coverage_permille > 1000U ||
	    !text_present(result->top_candidate_id) ||
	    !nonce_valid(result->nonce_hex) ||
	    !digest_valid(result->computed_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY schema=%u profile=%s status=%s passed=%s error=%s error_line=%u lines=%u markers=0x%08x errors=0x%08x warnings=0x%08x stage_mask=0x%02x cells=%u attacks=%u detected=%u missed=%u controls_passed=%u coverage_permille=%u top=%s nonce=%s passport_digest=%s computed_digest=%s\n",
	       result->schema_version,
	       pqcp_deployment_release_gate_profile_str(result->profile),
	       pqcp_deployment_tamper_matrix_status_str(result->matrix_status),
	       result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_tamper_matrix_replay_error_str(
		       result->first_error),
	       result->first_error_line,
	       result->lines_seen,
	       result->marker_mask,
	       result->matrix_error_mask,
	       result->matrix_warning_mask,
	       result->stage_mask,
	       result->cell_count,
	       result->attack_count,
	       result->detected_count,
	       result->missed_count,
	       result->control_pass_count,
	       result->coverage_permille,
	       result->top_candidate_id,
	       result->nonce_hex,
	       result->passport_digest_hex,
	       result->computed_digest_hex);

	return result->passed ? 0 : -EBADMSG;
}
