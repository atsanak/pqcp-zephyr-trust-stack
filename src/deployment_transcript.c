/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deployment evidence transcript replay verifier.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/deployment_transcript.h>

#define FIELD_VALUE_MAX 96U

#define CAMPAIGN_METRIC_LATENCY (1U << 0)
#define CAMPAIGN_METRIC_CYCLES  (1U << 1)
#define CAMPAIGN_METRIC_RAM     (1U << 2)
#define CAMPAIGN_METRIC_STACK   (1U << 3)
#define CAMPAIGN_METRIC_HEAP    (1U << 4)
#define CAMPAIGN_METRIC_FLASH   (1U << 5)
#define CAMPAIGN_METRIC_ENERGY  (1U << 6)

#define CAMPAIGN_METRIC_KNOWN_MASK \
	(CAMPAIGN_METRIC_LATENCY | CAMPAIGN_METRIC_CYCLES | \
	 CAMPAIGN_METRIC_RAM | CAMPAIGN_METRIC_STACK | \
	 CAMPAIGN_METRIC_HEAP | CAMPAIGN_METRIC_FLASH | \
	 CAMPAIGN_METRIC_ENERGY)

static bool starts_with(const char *value, const char *prefix)
{
	return strncmp(value, prefix, strlen(prefix)) == 0;
}

static int transcript_fail(
	struct pqcp_deployment_transcript_state *state,
	enum pqcp_deployment_transcript_error error)
{
	if (state != NULL &&
	    state->first_error == PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}

	return -EBADMSG;
}

static int field_value(
	const char *line,
	const char *key,
	char *out,
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

			while (value[len] != '\0' &&
			       value[len] != ' ' &&
			       value[len] != '\r' &&
			       value[len] != '\n') {
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

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}

	return parse_u32_dec(value, out);
}

static int get_u32_hex(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_VALUE_MAX];

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}

	return parse_u32_hex(value, out);
}

static int get_field(
	const char *line,
	const char *key,
	char *out,
	size_t out_len)
{
	if (field_value(line, key, out, out_len) != 0) {
		return -EINVAL;
	}

	return 0;
}

static bool token_is_none(const char *token)
{
	return strcmp(token, "none") == 0;
}

static bool token_is_pass(const char *token)
{
	return strcmp(token, "PASS") == 0 ||
	       strcmp(token, "ROBUST") == 0 ||
	       strcmp(token, "ADEQUATE") == 0;
}

static uint32_t campaign_metric_for_name(const char *name)
{
	if (strcmp(name, "latency") == 0) {
		return CAMPAIGN_METRIC_LATENCY;
	}
	if (strcmp(name, "cycles") == 0) {
		return CAMPAIGN_METRIC_CYCLES;
	}
	if (strcmp(name, "ram") == 0) {
		return CAMPAIGN_METRIC_RAM;
	}
	if (strcmp(name, "stack") == 0) {
		return CAMPAIGN_METRIC_STACK;
	}
	if (strcmp(name, "heap") == 0) {
		return CAMPAIGN_METRIC_HEAP;
	}
	if (strcmp(name, "flash") == 0) {
		return CAMPAIGN_METRIC_FLASH;
	}
	if (strcmp(name, "energy") == 0) {
		return CAMPAIGN_METRIC_ENERGY;
	}

	return 0U;
}

static void fill_result(
	const struct pqcp_deployment_transcript_state *state,
	struct pqcp_deployment_transcript_result *result,
	bool passed)
{
	if (state == NULL || result == NULL) {
		return;
	}

	result->schema_version = PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION;
	result->lines_seen = state->lines_seen;
	result->marker_mask = state->marker_mask;
	result->candidate_count = state->candidate_count;
	result->accepted_count = state->accepted_count;
	result->conditional_count = state->conditional_count;
	result->rejected_count = state->rejected_count;
	result->feasible_count = state->decision_feasible_count;
	result->robustness_candidate_count = state->robustness_candidate_count;
	result->pareto_frontier_count = state->pareto_frontier_count;
	result->campaign_metric_count = state->campaign_metric_count;
	result->campaign_observations = state->campaign_observations;
	result->campaign_quality_mask = state->campaign_quality_mask;
	result->gap_count = state->gap_count;
	result->first_error_line = state->first_error_line;
	result->first_error = state->first_error;
	result->passed = passed;
}

const char *pqcp_deployment_transcript_error_str(
	enum pqcp_deployment_transcript_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_BAD_SEQUENCE:
		return "bad_sequence";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_DUPLICATE_SUMMARY:
		return "duplicate_summary";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_STATUS_FAIL:
		return "status_fail";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_COUNT_MISMATCH:
		return "count_mismatch";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_TOP_MISMATCH:
		return "top_mismatch";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_CAMPAIGN_MISMATCH:
		return "campaign_mismatch";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_ROBUSTNESS_MISMATCH:
		return "robustness_mismatch";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MISSING_REQUIRED:
		return "missing_required";
	case PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_UNKNOWN_STATUS:
		return "unknown_status";
	default:
		return "unknown";
	}
}

int pqcp_deployment_transcript_init(
	struct pqcp_deployment_transcript_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version = PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION;
	state->first_error = PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE;

	return 0;
}

static int ingest_scenario(
	struct pqcp_deployment_transcript_state *state,
	const char *line)
{
	uint32_t schema;

	if (state->scenario_seen) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_DUPLICATE_SUMMARY);
	}
	if (get_u32_dec(line, "schema", &schema) != 0 ||
	    schema != PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	state->scenario_seen = true;
	state->marker_mask |= PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_SCENARIO;

	return 0;
}

static int ingest_campaign_summary(
	struct pqcp_deployment_transcript_state *state,
	const char *line)
{
	uint32_t schema;
	uint32_t projected;

	if (state->campaign_seen) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_DUPLICATE_SUMMARY);
	}
	if (get_u32_dec(line, "schema", &schema) != 0 ||
	    schema != PQCP_DEPLOYMENT_CAMPAIGN_SCHEMA_VERSION ||
	    get_u32_dec(line, "observations", &state->campaign_observations) != 0 ||
	    get_u32_dec(line, "successful", &state->campaign_successful) != 0 ||
	    get_u32_dec(line, "failed", &state->campaign_failed) != 0 ||
	    get_u32_hex(line, "quality", &state->campaign_quality_mask) != 0 ||
	    get_u32_dec(line, "projected", &projected) != 0 ||
	    get_field(line, "candidate", state->campaign_candidate,
		      sizeof(state->campaign_candidate)) != 0 ||
	    projected > 1U ||
	    state->campaign_successful + state->campaign_failed !=
		    state->campaign_observations) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if (state->campaign_quality_mask != 0U || projected == 0U) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_STATUS_FAIL);
	}

	/* projected is bounded to {0,1} and the == 0U case returned above. */
	state->campaign_projected = true;
	state->campaign_seen = true;
	state->marker_mask |= PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN;

	return 0;
}

static int ingest_campaign_metric(
	struct pqcp_deployment_transcript_state *state,
	const char *line)
{
	char metric[FIELD_VALUE_MAX];
	uint32_t count;
	uint32_t missing;
	uint32_t bit;

	if (!state->campaign_seen) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	}
	if (get_field(line, "metric", metric, sizeof(metric)) != 0 ||
	    get_u32_dec(line, "count", &count) != 0 ||
	    get_u32_dec(line, "missing", &missing) != 0) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	bit = campaign_metric_for_name(metric);
	if (bit == 0U || (state->campaign_metric_mask & bit) != 0U ||
	    count + missing > state->campaign_successful) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_CAMPAIGN_MISMATCH);
	}

	state->campaign_metric_mask |= bit;
	state->campaign_metric_count++;
	state->marker_mask |= PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN_METRIC;

	return 0;
}

static int ingest_candidate(
	struct pqcp_deployment_transcript_state *state,
	const char *line)
{
	char id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char status[FIELD_VALUE_MAX];
	uint32_t rank;

	if (!state->scenario_seen) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	}
	if (get_field(line, "id", id, sizeof(id)) != 0 ||
	    get_field(line, "status", status, sizeof(status)) != 0 ||
	    get_u32_dec(line, "rank", &rank) != 0) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}

	if (strcmp(status, "ACCEPTED") == 0) {
		state->accepted_count++;
	} else if (strcmp(status, "CONDITIONAL") == 0) {
		state->conditional_count++;
	} else if (strcmp(status, "REJECTED") == 0) {
		state->rejected_count++;
	} else {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_UNKNOWN_STATUS);
	}

	if (state->decision_seen && strcmp(id, state->decision_top) == 0) {
		state->decision_top_seen = true;
	}
	if (rank == 1U && state->rank_one_candidate[0] == '\0') {
		memcpy(state->rank_one_candidate, id, sizeof(state->rank_one_candidate));
	}
	if (state->campaign_seen &&
	    strcmp(id, state->campaign_candidate) == 0) {
		state->campaign_candidate_seen = true;
	}

	state->candidate_count++;
	state->marker_mask |= PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CANDIDATE;

	return 0;
}

static int ingest_decision(
	struct pqcp_deployment_transcript_state *state,
	const char *line)
{
	uint32_t schema;
	char status[FIELD_VALUE_MAX];

	if (state->decision_seen || !state->scenario_seen) {
		return transcript_fail(
			state, state->decision_seen ?
			PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_DUPLICATE_SUMMARY :
			PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	}
	if (get_u32_dec(line, "schema", &schema) != 0 ||
	    schema != PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION ||
	    get_field(line, "status", status, sizeof(status)) != 0 ||
	    get_u32_dec(line, "candidates", &state->decision_candidate_count) != 0 ||
	    get_u32_dec(line, "feasible", &state->decision_feasible_count) != 0 ||
	    get_u32_dec(line, "accepted", &state->decision_accepted_count) != 0 ||
	    get_u32_dec(line, "conditional",
			&state->decision_conditional_count) != 0 ||
	    get_u32_dec(line, "rejected", &state->decision_rejected_count) != 0 ||
	    get_field(line, "top", state->decision_top,
		      sizeof(state->decision_top)) != 0) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if (strcmp(status, "PASS") != 0) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_STATUS_FAIL);
	}
	if (!token_is_none(state->decision_top)) {
		state->decision_top_seen = false;
	}

	state->decision_seen = true;
	state->marker_mask |= PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_DECISION;

	return 0;
}

static int ingest_robust_candidate(
	struct pqcp_deployment_transcript_state *state,
	const char *line)
{
	char id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char status[FIELD_VALUE_MAX];
	uint32_t pareto;

	if (!state->scenario_seen) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	}
	if (get_field(line, "id", id, sizeof(id)) != 0 ||
	    get_field(line, "status", status, sizeof(status)) != 0 ||
	    get_u32_dec(line, "pareto", &pareto) != 0 ||
	    pareto > 1U) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if (strcmp(status, "REJECTED") != 0 &&
	    strcmp(status, "FRAGILE") != 0 &&
	    strcmp(status, "ADEQUATE") != 0 &&
	    strcmp(status, "ROBUST") != 0) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_UNKNOWN_STATUS);
	}

	if (pareto == 1U) {
		state->pareto_frontier_count++;
	}
	if (state->robustness_seen &&
	    strcmp(id, state->robustness_top) == 0) {
		state->robustness_top_seen = true;
	}

	state->robustness_candidate_count++;
	state->marker_mask |=
		PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUST_CANDIDATE;

	return 0;
}

static int ingest_robustness_summary(
	struct pqcp_deployment_transcript_state *state,
	const char *line)
{
	uint32_t schema;
	char status[FIELD_VALUE_MAX];

	if (state->robustness_seen || !state->scenario_seen) {
		return transcript_fail(
			state, state->robustness_seen ?
			PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_DUPLICATE_SUMMARY :
			PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	}
	if (get_u32_dec(line, "schema", &schema) != 0 ||
	    schema != PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION ||
	    get_field(line, "status", status, sizeof(status)) != 0 ||
	    get_u32_dec(line, "candidates",
			&state->robustness_candidate_total) != 0 ||
	    get_u32_dec(line, "feasible", &state->robustness_feasible_count) != 0 ||
	    get_u32_dec(line, "frontier", &state->robustness_frontier_count) != 0 ||
	    get_field(line, "top", state->robustness_top,
		      sizeof(state->robustness_top)) != 0) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}
	if (!token_is_pass(status)) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_STATUS_FAIL);
	}
	if (!token_is_none(state->robustness_top)) {
		state->robustness_top_seen = false;
	}

	state->robustness_seen = true;
	state->marker_mask |= PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUSTNESS;

	return 0;
}

static int ingest_gap(
	struct pqcp_deployment_transcript_state *state,
	const char *line)
{
	uint32_t priority;
	char candidate[PQCP_DEPLOYMENT_ID_MAX_CHARS];

	if (!state->decision_seen) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	}
	if (get_u32_dec(line, "priority", &priority) != 0 ||
	    get_field(line, "candidate", candidate, sizeof(candidate)) != 0 ||
	    priority == 0U) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MALFORMED_FIELD);
	}

	state->gap_count++;
	state->marker_mask |= PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_GAP;

	return 0;
}

int pqcp_deployment_transcript_ingest_line(
	struct pqcp_deployment_transcript_state *state,
	const char *line)
{
	if (state == NULL || line == NULL ||
	    state->schema_version != PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION) {
		return -EINVAL;
	}

	state->lines_seen++;
	if (state->first_error != PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE) {
		return -EBADMSG;
	}

	if (starts_with(line, "PQCP_DEPLOYMENT_SCENARIO ")) {
		return ingest_scenario(state, line);
	}
	if (starts_with(line, "PQCP_DEPLOYMENT_CAMPAIGN_SUMMARY ")) {
		return ingest_campaign_summary(state, line);
	}
	if (starts_with(line, "PQCP_DEPLOYMENT_CAMPAIGN_METRIC ")) {
		return ingest_campaign_metric(state, line);
	}
	if (starts_with(line, "PQCP_DEPLOYMENT_CANDIDATE ")) {
		return ingest_candidate(state, line);
	}
	if (starts_with(line, "PQCP_DEPLOYMENT_DECISION ")) {
		return ingest_decision(state, line);
	}
	if (starts_with(line, "PQCP_DEPLOYMENT_ROBUSTNESS_CANDIDATE ")) {
		return ingest_robust_candidate(state, line);
	}
	if (starts_with(line, "PQCP_DEPLOYMENT_ROBUSTNESS ")) {
		return ingest_robustness_summary(state, line);
	}
	if (starts_with(line, "PQCP_DEPLOYMENT_GAP ")) {
		return ingest_gap(state, line);
	}

	return 0;
}

static int verify_finish(
	struct pqcp_deployment_transcript_state *state)
{
	uint32_t feasible_count = state->accepted_count + state->conditional_count;

	if (!state->scenario_seen || !state->decision_seen ||
	    !state->robustness_seen) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MISSING_REQUIRED);
	}
	if (state->decision_candidate_count != state->candidate_count ||
	    state->decision_feasible_count != feasible_count ||
	    state->decision_accepted_count != state->accepted_count ||
	    state->decision_conditional_count != state->conditional_count ||
	    state->decision_rejected_count != state->rejected_count) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_COUNT_MISMATCH);
	}
	if (!token_is_none(state->decision_top) &&
	    !state->decision_top_seen &&
	    strcmp(state->decision_top, state->rank_one_candidate) != 0) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_TOP_MISMATCH);
	}
	if (state->robustness_candidate_total !=
	    state->robustness_candidate_count ||
	    state->robustness_feasible_count != feasible_count ||
	    state->robustness_frontier_count != state->pareto_frontier_count) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_ROBUSTNESS_MISMATCH);
	}
	if (!token_is_none(state->robustness_top) &&
	    strcmp(state->robustness_top, state->decision_top) != 0) {
		return transcript_fail(
			state, PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_TOP_MISMATCH);
	}
	if (state->campaign_seen) {
		if (state->campaign_metric_mask != CAMPAIGN_METRIC_KNOWN_MASK ||
		    state->campaign_metric_count != 7U ||
		    !state->campaign_candidate_seen) {
			return transcript_fail(
				state,
				PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_CAMPAIGN_MISMATCH);
		}
	}

	return 0;
}

int pqcp_deployment_transcript_finish(
	struct pqcp_deployment_transcript_state *state,
	struct pqcp_deployment_transcript_result *result)
{
	int ret;

	if (state == NULL ||
	    state->schema_version != PQCP_DEPLOYMENT_TRANSCRIPT_SCHEMA_VERSION) {
		return -EINVAL;
	}

	if (state->first_error != PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE) {
		fill_result(state, result, false);
		return -EBADMSG;
	}

	ret = verify_finish(state);
	if (ret != 0) {
		fill_result(state, result, false);
		return ret;
	}

	fill_result(state, result, true);
	return 0;
}
