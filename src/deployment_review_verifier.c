/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware-native deployment review packet verifier.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_review_verifier.h>

#define FIELD_VALUE_MAX 128U
#define REVIEW_LINE_MAX 768U

static bool starts_with(const char *value, const char *prefix)
{
	return strncmp(value, prefix, strlen(prefix)) == 0;
}

static int fail_once(struct pqcp_deployment_review_verifier_state *state,
		     enum pqcp_deployment_review_verifier_error error)
{
	if (state != NULL &&
	    state->first_error ==
		    PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_NONE) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}

	return -EBADMSG;
}

const char *pqcp_deployment_review_verifier_error_str(
	enum pqcp_deployment_review_verifier_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DUPLICATE_MARKER:
		return "duplicate_marker";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MISSING_REQUIRED:
		return "missing_required";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DIGEST_MISMATCH:
		return "digest_mismatch";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_BYTE_COUNT_MISMATCH:
		return "byte_count_mismatch";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_LINE_COUNT_MISMATCH:
		return "line_count_mismatch";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_TOP_MISMATCH:
		return "top_mismatch";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_STATUS_MISMATCH:
		return "status_mismatch";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_COUNT_MISMATCH:
		return "count_mismatch";
	case PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_UNKNOWN_MARKER:
		return "unknown_marker";
	default:
		return "unknown";
	}
}

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0x6c62272e07bb0142ULL;
	digest[1] = 0x62b821756295c58dULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0xc2b2ae3d27d4eb4fULL;
}

static uint64_t rotl64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= value;
	digest[0] *= 0x100000001b3ULL;
	digest[1] += digest[0] + ((uint64_t)value << 11U);
	digest[1] = rotl64(digest[1], 17U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + value + 0x165667b19e3779f9ULL;
	digest[2] = rotl64(digest[2], 31U);
	digest[3] += digest[2] ^ (digest[0] >> 9U);
	digest[3] = rotl64(digest[3], 43U);
}

static void digest_update_line(uint64_t digest[4], const char *line)
{
	for (const char *p = line; *p != '\0'; ++p) {
		digest_update_byte(digest, (uint8_t)*p);
	}
	digest_update_byte(digest, (uint8_t)'\n');
}

static void digest_to_hex(const uint64_t digest[4], char out[
			  PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(out,
		       PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U,
		       "%016llx%016llx%016llx%016llx",
		       (unsigned long long)digest[0],
		       (unsigned long long)digest[1],
		       (unsigned long long)digest[2],
		       (unsigned long long)digest[3]);
}

static bool hex_digest_valid(const char *value, size_t expected_len)
{
	if (value == NULL || strlen(value) != expected_len) {
		return false;
	}

	for (const char *p = value; *p != '\0'; ++p) {
		if (!((*p >= '0' && *p <= '9') ||
		      (*p >= 'a' && *p <= 'f'))) {
			return false;
		}
	}

	return true;
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
	const size_t key_len = strlen(key);
	const char *p = line;

	if (line == NULL || key == NULL || out == NULL || out_len == 0U) {
		return -EINVAL;
	}

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

static int get_field(const char *line, const char *key, char *out,
		     size_t out_len)
{
	return field_value(line, key, out, out_len) == 0 ? 0 : -EINVAL;
}

static int get_u32_dec(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}

	return parse_u32_dec(value, out);
}

static int get_u32_hex(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}

	return parse_u32_hex(value, out);
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

static int parse_packet_status(const char *line, const char *key,
			       enum pqcp_deployment_review_packet_status *out)
{
	char value[FIELD_VALUE_MAX];

	if (get_field(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_REVIEW_PACKET_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_REVIEW_PACKET_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
		return 0;
	}

	return -EINVAL;
}

static int ensure_single_marker(
	struct pqcp_deployment_review_verifier_state *state,
	uint32_t marker)
{
	if ((state->marker_mask & marker) != 0U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DUPLICATE_MARKER);
	}

	state->marker_mask |= marker;
	return 0;
}

static int verify_schema(
	struct pqcp_deployment_review_verifier_state *state,
	const char *line)
{
	uint32_t schema;

	if (get_u32_dec(line, "schema", &schema) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD);
	}
	if (schema != PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_BAD_SCHEMA);
	}

	return 0;
}

static int remember_top(
	struct pqcp_deployment_review_verifier_state *state,
	const char *candidate)
{
	if (candidate == NULL || candidate[0] == '\0' ||
	    strlen(candidate) >= sizeof(state->top_candidate_id)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD);
	}

	if (state->top_candidate_id[0] != '\0' &&
	    strcmp(state->top_candidate_id, candidate) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_TOP_MISMATCH);
	}

	(void)snprintk(state->top_candidate_id,
		       sizeof(state->top_candidate_id), "%s", candidate);
	return 0;
}

static int remember_count(uint32_t *slot, uint32_t value)
{
	if (*slot == 0U) {
		*slot = value;
		return 0;
	}

	return *slot == value ? 0 : -EBADMSG;
}

static int ingest_fact_common(
	struct pqcp_deployment_review_verifier_state *state,
	const char *line)
{
	const size_t len = strlen(line);

	digest_update_line(state->digest_state, line);
	digest_to_hex(state->digest_state, state->computed_digest_hex);
	state->fact_lines++;
	if (UINT32_MAX - state->fact_bytes < len + 1U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_BYTE_COUNT_MISMATCH);
	}
	state->fact_bytes += (uint32_t)len + 1U;

	return 0;
}

static int ingest_scenario_fact(
	struct pqcp_deployment_review_verifier_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_SCENARIO) != 0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "scenario") != 0 ||
	    get_field(line, "id", field, sizeof(field)) != 0 ||
	    get_field(line, "operation", field, sizeof(field)) != 0 ||
	    get_field(line, "target", field, sizeof(field)) != 0 ||
	    get_field(line, "evidence_level", field, sizeof(field)) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD);
	}

	return ingest_fact_common(state, line);
}

static int ingest_pipeline_fact(
	struct pqcp_deployment_review_verifier_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	bool status;
	uint32_t value;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_PIPELINE) != 0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "pipeline") != 0 ||
	    parse_bool_status(line, "status", &status) != 0 ||
	    get_u32_dec(line, "candidates", &value) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0 ||
	    get_u32_dec(line, "readiness", &state->readiness_score) != 0 ||
	    get_u32_dec(line, "claim_score", &state->claim_score) != 0 ||
	    get_field(line, "trace_digest", state->trace_digest_hex,
		      sizeof(state->trace_digest_hex)) != 0 ||
	    parse_bool_status(line, "replay", &state->replay_passed) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD);
	}
	if (value == 0U ||
	    remember_count(&state->candidate_count, value) != 0 ||
	    remember_top(state, top) != 0 ||
	    !hex_digest_valid(state->trace_digest_hex,
			      PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_COUNT_MISMATCH);
	}
	state->pipeline_passed = status;

	return ingest_fact_common(state, line);
}

static int ingest_budget_fact(
	struct pqcp_deployment_review_verifier_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];
	char status[FIELD_VALUE_MAX];
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	uint32_t value;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_BUDGET) != 0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "budget") != 0 ||
	    get_field(line, "status", status, sizeof(status)) != 0 ||
	    get_u32_dec(line, "candidates", &value) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD);
	}
	if (remember_count(&state->candidate_count, value) != 0 ||
	    remember_top(state, top) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_COUNT_MISMATCH);
	}
	if (strcmp(status, "PASS") == 0) {
		state->budget_passed = true;
	} else if (strcmp(status, "WARN") == 0 ||
		   strcmp(status, "FAIL") == 0) {
		state->budget_passed = false;
	} else {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_STATUS_MISMATCH);
	}

	return ingest_fact_common(state, line);
}

static int ingest_experiment_fact(
	struct pqcp_deployment_review_verifier_state *state,
	const char *line)
{
	char field[FIELD_VALUE_MAX];
	char status[FIELD_VALUE_MAX];
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_EXPERIMENTS) != 0 ||
	    verify_schema(state, line) != 0 ||
	    get_field(line, "field", field, sizeof(field)) != 0 ||
	    strcmp(field, "experiments") != 0 ||
	    get_field(line, "status", status, sizeof(status)) != 0 ||
	    get_u32_dec(line, "rows", &state->experiment_count) != 0 ||
	    get_u32_dec(line, "blocking", &state->blocking_count) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD);
	}
	if (state->blocking_count > state->experiment_count ||
	    remember_top(state, top) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_COUNT_MISMATCH);
	}
	if (strcmp(status, "PASS") == 0) {
		state->experiment_plan_passed = true;
	} else if (strcmp(status, "WARN") == 0 ||
		   strcmp(status, "FAIL") == 0) {
		state->experiment_plan_passed = false;
	} else {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_STATUS_MISMATCH);
	}

	return ingest_fact_common(state, line);
}

static int ingest_packet(
	struct pqcp_deployment_review_verifier_state *state,
	const char *line)
{
	char top[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char trace_digest[PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U];
	uint32_t candidates;
	uint32_t experiments;
	uint32_t blocking;
	uint32_t readiness;
	uint32_t claim_score;
	uint32_t review_score;
	bool pipeline;
	bool replay;
	bool budget;
	bool experiment_plan;

	if (ensure_single_marker(
		    state,
		    PQCP_DEPLOYMENT_REVIEW_VERIFIER_MARKER_PACKET) != 0 ||
	    verify_schema(state, line) != 0 ||
	    parse_packet_status(line, "status", &state->packet_status) != 0 ||
	    get_u32_hex(line, "errors", &state->packet_error_mask) != 0 ||
	    get_u32_hex(line, "warnings", &state->packet_warning_mask) != 0 ||
	    get_u32_dec(line, "lines", &state->packet_line_count) != 0 ||
	    get_u32_dec(line, "bytes", &state->packet_byte_count) != 0 ||
	    get_field(line, "digest", state->packet_digest_hex,
		      sizeof(state->packet_digest_hex)) != 0 ||
	    get_field(line, "trace_digest", trace_digest,
		      sizeof(trace_digest)) != 0 ||
	    get_field(line, "top", top, sizeof(top)) != 0 ||
	    get_u32_dec(line, "candidates", &candidates) != 0 ||
	    get_u32_dec(line, "experiments", &experiments) != 0 ||
	    get_u32_dec(line, "blocking", &blocking) != 0 ||
	    get_u32_dec(line, "readiness", &readiness) != 0 ||
	    get_u32_dec(line, "claim_score", &claim_score) != 0 ||
	    get_u32_dec(line, "review_score", &review_score) != 0 ||
	    parse_bool_status(line, "pipeline", &pipeline) != 0 ||
	    parse_bool_status(line, "replay", &replay) != 0 ||
	    parse_bool_status(line, "budget", &budget) != 0 ||
	    parse_bool_status(line, "experiment_plan", &experiment_plan) != 0 ||
	    remember_top(state, top) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD);
	}
	if (!hex_digest_valid(state->packet_digest_hex,
			      PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS) ||
	    !hex_digest_valid(trace_digest,
			      PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS) ||
	    review_score > 100U ||
	    readiness > 100U ||
	    claim_score > 100U ||
	    (state->packet_error_mask &
	     ~PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_KNOWN_MASK) != 0U ||
	    (state->packet_warning_mask &
	     ~PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_KNOWN_MASK) != 0U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD);
	}
	if (remember_count(&state->candidate_count, candidates) != 0 ||
	    state->experiment_count != experiments ||
	    state->blocking_count != blocking ||
	    state->readiness_score != readiness ||
	    state->claim_score != claim_score ||
	    strcmp(state->trace_digest_hex, trace_digest) != 0 ||
	    state->pipeline_passed != pipeline ||
	    state->replay_passed != replay ||
	    state->budget_passed != budget ||
	    state->experiment_plan_passed != experiment_plan) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_COUNT_MISMATCH);
	}
	state->review_score = review_score;

	return 0;
}

static void fill_result(
	const struct pqcp_deployment_review_verifier_state *state,
	struct pqcp_deployment_review_verifier_result *result,
	bool passed)
{
	if (state == NULL || result == NULL) {
		return;
	}

	memset(result, 0, sizeof(*result));
	result->schema_version = PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION;
	result->lines_seen = state->lines_seen;
	result->marker_mask = state->marker_mask;
	result->fact_lines = state->fact_lines;
	result->fact_bytes = state->fact_bytes;
	result->candidate_count = state->candidate_count;
	result->experiment_count = state->experiment_count;
	result->blocking_count = state->blocking_count;
	result->readiness_score = state->readiness_score;
	result->claim_score = state->claim_score;
	result->review_score = state->review_score;
	result->first_error_line = state->first_error_line;
	result->first_error = state->first_error;
	result->packet_status = state->packet_status;
	result->passed = passed;
	(void)snprintk(result->top_candidate_id,
		       sizeof(result->top_candidate_id), "%s",
		       state->top_candidate_id);
	(void)snprintk(result->trace_digest_hex,
		       sizeof(result->trace_digest_hex), "%s",
		       state->trace_digest_hex);
	(void)snprintk(result->computed_digest_hex,
		       sizeof(result->computed_digest_hex), "%s",
		       state->computed_digest_hex);
}

int pqcp_deployment_review_verifier_init(
	struct pqcp_deployment_review_verifier_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version = PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION;
	state->first_error = PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_NONE;
	state->packet_status = PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
	digest_init(state->digest_state);
	digest_to_hex(state->digest_state, state->computed_digest_hex);

	return 0;
}

int pqcp_deployment_review_verifier_ingest_line(
	struct pqcp_deployment_review_verifier_state *state,
	const char *line)
{
	char clean[REVIEW_LINE_MAX];
	char field[FIELD_VALUE_MAX];
	int ret;

	if (state == NULL || line == NULL) {
		return -EINVAL;
	}
	if (clean_line(line, clean, sizeof(clean)) != 0) {
		state->lines_seen++;
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_INVALID_ARGUMENT);
	}

	state->lines_seen++;
	if (starts_with(clean, "PQCP_DEPLOYMENT_REVIEW_FACT ")) {
		if (get_field(clean, "field", field, sizeof(field)) != 0) {
			return fail_once(
				state,
				PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MALFORMED_FIELD);
		}
		if (strcmp(field, "scenario") == 0) {
			ret = ingest_scenario_fact(state, clean);
		} else if (strcmp(field, "pipeline") == 0) {
			ret = ingest_pipeline_fact(state, clean);
		} else if (strcmp(field, "budget") == 0) {
			ret = ingest_budget_fact(state, clean);
		} else if (strcmp(field, "experiments") == 0) {
			ret = ingest_experiment_fact(state, clean);
		} else {
			ret = fail_once(
				state,
				PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_UNKNOWN_MARKER);
		}
		return ret;
	}
	if (starts_with(clean, "PQCP_DEPLOYMENT_REVIEW_PACKET ")) {
		return ingest_packet(state, clean);
	}

	return fail_once(
		state, PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_UNKNOWN_MARKER);
}

static int finish_checks(struct pqcp_deployment_review_verifier_state *state)
{
	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_REVIEW_VERIFIER_REQUIRED_MASK) !=
	    PQCP_DEPLOYMENT_REVIEW_VERIFIER_REQUIRED_MASK) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_MISSING_REQUIRED);
	}
	if (state->packet_status == PQCP_DEPLOYMENT_REVIEW_PACKET_PASS &&
	    (!state->pipeline_passed || !state->replay_passed ||
	     !state->budget_passed || !state->experiment_plan_passed ||
	     state->packet_error_mask != 0U)) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_STATUS_MISMATCH);
	}
	if (state->packet_status == PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL &&
	    state->pipeline_passed && state->budget_passed &&
	    state->experiment_plan_passed && state->packet_error_mask == 0U) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_STATUS_MISMATCH);
	}
	if (state->packet_line_count != state->fact_lines) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_LINE_COUNT_MISMATCH);
	}
	if (state->packet_byte_count != state->fact_bytes) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_BYTE_COUNT_MISMATCH);
	}
	if (strcmp(state->computed_digest_hex, state->packet_digest_hex) != 0) {
		return fail_once(
			state,
			PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_DIGEST_MISMATCH);
	}

	return 0;
}

int pqcp_deployment_review_verifier_finish(
	struct pqcp_deployment_review_verifier_state *state,
	struct pqcp_deployment_review_verifier_result *result)
{
	int ret;

	if (state == NULL || result == NULL) {
		return -EINVAL;
	}
	if (state->first_error !=
	    PQCP_DEPLOYMENT_REVIEW_VERIFIER_ERROR_NONE) {
		fill_result(state, result, false);
		return -EBADMSG;
	}

	ret = finish_checks(state);
	fill_result(state, result, ret == 0);
	return ret == 0 ? 0 : -EBADMSG;
}

static int feed_fact_buffer(
	struct pqcp_deployment_review_verifier_state *state,
	const char *fact_buffer)
{
	const char *line_start = fact_buffer;
	char line[REVIEW_LINE_MAX];

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
			if (pqcp_deployment_review_verifier_ingest_line(
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

int pqcp_deployment_review_verifier_verify_packet(
	const char *fact_buffer,
	const struct pqcp_deployment_review_packet *packet,
	struct pqcp_deployment_review_verifier_result *result)
{
	struct pqcp_deployment_review_verifier_state state;
	char packet_line[REVIEW_LINE_MAX];
	int written;
	int ret;

	if (fact_buffer == NULL || packet == NULL || result == NULL ||
	    packet->top_candidate_id == NULL) {
		return -EINVAL;
	}

	ret = pqcp_deployment_review_verifier_init(&state);
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
		"PQCP_DEPLOYMENT_REVIEW_PACKET schema=%u status=%s errors=0x%08x warnings=0x%08x lines=%u bytes=%u digest=%s trace_digest=%s top=%s candidates=%u experiments=%u blocking=%u readiness=%u claim_score=%u review_score=%u pipeline=%s replay=%s budget=%s experiment_plan=%s",
		packet->schema_version,
		pqcp_deployment_review_packet_status_str(packet->status),
		packet->error_mask,
		packet->warning_mask,
		packet->line_count,
		packet->byte_count,
		packet->packet_digest_hex,
		packet->trace_digest_hex,
		packet->top_candidate_id,
		packet->candidate_count,
		packet->experiment_count,
		packet->blocking_experiment_count,
		packet->readiness_score,
		packet->claim_score,
		packet->review_score,
		packet->pipeline_passed ? "PASS" : "FAIL",
		packet->replay_passed ? "PASS" : "FAIL",
		packet->budget_passed ? "PASS" : "FAIL",
		packet->experiment_plan_passed ? "PASS" : "FAIL");
	if (written < 0 || written >= (int)sizeof(packet_line)) {
		fill_result(&state, result, false);
		return -ENOSPC;
	}
	ret = pqcp_deployment_review_verifier_ingest_line(&state, packet_line);
	if (ret != 0) {
		fill_result(&state, result, false);
		return ret;
	}

	return pqcp_deployment_review_verifier_finish(&state, result);
}

static bool result_valid(
	const struct pqcp_deployment_review_verifier_result *result)
{
	return result != NULL &&
	       result->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_VERIFIER_SCHEMA_VERSION &&
	       result->lines_seen != 0U &&
	       result->top_candidate_id[0] != '\0' &&
	       result->computed_digest_hex[0] != '\0' &&
	       result->readiness_score <= 100U &&
	       result->claim_score <= 100U &&
	       result->review_score <= 100U;
}

int pqcp_deployment_review_verifier_emit_result(
	const struct pqcp_deployment_review_verifier_result *result)
{
	if (!result_valid(result)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_REVIEW_REPLAY schema=%u status=%s error=%s line=%u markers=0x%08x lines=%u facts=%u bytes=%u top=%s candidates=%u experiments=%u blocking=%u readiness=%u claim_score=%u review_score=%u digest=%s packet_status=%s\n",
	       result->schema_version,
	       result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_review_verifier_error_str(result->first_error),
	       result->first_error_line,
	       result->marker_mask,
	       result->lines_seen,
	       result->fact_lines,
	       result->fact_bytes,
	       result->top_candidate_id,
	       result->candidate_count,
	       result->experiment_count,
	       result->blocking_count,
	       result->readiness_score,
	       result->claim_score,
	       result->review_score,
	       result->computed_digest_hex,
	       pqcp_deployment_review_packet_status_str(result->packet_status));

	return result->passed ? 0 : -EBADMSG;
}
