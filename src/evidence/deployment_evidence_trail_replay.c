/*
 * SPDX-License-Identifier: MIT
 *
 * Deployment evidence trail replay verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_trail_replay.h>

#define FIELD_VALUE_MAX 96U
#define TRAIL_REPLAY_LINE_MAX 1024U

#define TRAIL_ENTRY_MARKER_PREFIX "PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ENTRY "
#define TRAIL_HEAD_MARKER_PREFIX "PQCP_DEPLOYMENT_EVIDENCE_TRAIL "

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
		value, PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS);
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

static bool trail_status_valid(
	enum pqcp_deployment_evidence_trail_status status)
{
	return status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN ||
	       status == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL;
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

static int parse_trail_status(
	const char *value, enum pqcp_deployment_evidence_trail_status *out)
{
	if (strcmp(value, "PASS") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS;
		return 0;
	}
	if (strcmp(value, "WARN") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN;
		return 0;
	}
	if (strcmp(value, "FAIL") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL;
		return 0;
	}

	return -EINVAL;
}

static int parse_trail_stage(
	const char *value, enum pqcp_deployment_evidence_trail_stage *out)
{
	if (strcmp(value, "verdict") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_VERDICT;
		return 0;
	}
	if (strcmp(value, "seal") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL;
		return 0;
	}
	if (strcmp(value, "seal_audit") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_SEAL_AUDIT;
		return 0;
	}
	if (strcmp(value, "passport") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_PASSPORT;
		return 0;
	}
	if (strcmp(value, "tamper_matrix") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_TAMPER_MATRIX;
		return 0;
	}
	if (strcmp(value, "custom") == 0) {
		*out = PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_CUSTOM;
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
/* Link digest recomputation (identical to the trail generator)        */
/* ------------------------------------------------------------------ */

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0xe7037ed1a0b428dbULL;
	digest[1] = 0x8ebc6af09c88c6e3ULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0x589965cc75374cc3ULL;
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
	char out[PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(
		out,
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U,
		"%016llx%016llx%016llx%016llx",
		(unsigned long long)digest[0],
		(unsigned long long)digest[1],
		(unsigned long long)digest[2],
		(unsigned long long)digest[3]);
}

static void compute_genesis_link(
	enum pqcp_deployment_release_gate_profile profile,
	const char *top_candidate_id,
	const char *nonce_hex,
	char out[PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U])
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest,
			  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION);
	digest_update_text(digest, "genesis");
	digest_update_u32(digest, (uint32_t)profile);
	digest_update_text(digest, top_candidate_id);
	digest_update_text(digest, nonce_hex);
	digest_to_hex(digest, out);
}

static void compute_entry_link(
	const char *previous_link_hex,
	uint32_t sequence,
	enum pqcp_deployment_evidence_trail_stage stage,
	const char *digest_hex,
	char out[PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U])
{
	uint64_t digest[4];

	digest_init(digest);
	digest_update_u32(digest,
			  PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION);
	digest_update_text(digest, "link");
	digest_update_text(digest, previous_link_hex);
	digest_update_u32(digest, sequence);
	digest_update_text(digest,
			   pqcp_deployment_evidence_trail_stage_str(stage));
	digest_update_text(digest, digest_hex);
	digest_to_hex(digest, out);
}

/* ------------------------------------------------------------------ */
/* Trail chain validation                                              */
/* ------------------------------------------------------------------ */

static enum pqcp_deployment_evidence_trail_status expected_status(
	const struct pqcp_deployment_evidence_trail *trail)
{
	if (trail->error_mask != 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_FAIL;
	}
	if (trail->warning_mask != 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARN;
	}

	return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_PASS;
}

static enum pqcp_deployment_evidence_trail_replay_error validate_chain(
	const struct pqcp_deployment_evidence_trail *trail,
	const struct pqcp_deployment_evidence_trail_entry *entries,
	uint32_t entry_count,
	char computed_head[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U])
{
	char link[PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];
	uint32_t observed_stages = 0U;

	if (trail->schema_version !=
	    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_BAD_SCHEMA;
	}
	if (!trail_status_valid(trail->status)) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_STATUS_MISMATCH;
	}
	if (!profile_valid(trail->profile)) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD;
	}
	if ((trail->error_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ERROR_KNOWN_MASK) != 0U ||
	    (trail->warning_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_WARNING_KNOWN_MASK) != 0U ||
	    (trail->observed_stage_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_KNOWN_MASK) != 0U ||
	    (trail->required_stage_mask &
	     ~PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_KNOWN_MASK) != 0U) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MASK_RANGE;
	}
	if (!text_present(trail->top_candidate_id) ||
	    !nonce_valid(trail->nonce_hex) ||
	    !digest_valid(trail->head_digest_hex)) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD;
	}
	if (trail->entry_count != entry_count ||
	    entry_count == 0U ||
	    entry_count > PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_COUNT_MISMATCH;
	}
	if (trail->status != expected_status(trail)) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_STATUS_MISMATCH;
	}

	compute_genesis_link(trail->profile, trail->top_candidate_id,
			     trail->nonce_hex, link);

	for (uint32_t i = 0U; i < entry_count; ++i) {
		const struct pqcp_deployment_evidence_trail_entry *entry =
			&entries[i];
		char recomputed[
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];

		if (entry->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_SCHEMA_VERSION) {
			return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_BAD_SCHEMA;
		}
		if (entry->sequence != i) {
			return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_SEQUENCE_GAP;
		}
		if ((uint32_t)entry->stage >=
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_COUNT) {
			return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD;
		}
		if (!digest_valid(entry->digest_hex) ||
		    !digest_valid(entry->link_digest_hex)) {
			return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD;
		}

		compute_entry_link(link, entry->sequence, entry->stage,
				   entry->digest_hex, recomputed);
		if (strcmp(recomputed, entry->link_digest_hex) != 0) {
			return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_LINK_MISMATCH;
		}
		set_text(link, sizeof(link), recomputed);
		observed_stages |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_STAGE_BIT(entry->stage);
	}

	set_text(computed_head,
		 PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U, link);

	if (observed_stages != trail->observed_stage_mask) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_STAGE_MISMATCH;
	}
	if (strcmp(computed_head, trail->head_digest_hex) != 0) {
		return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_HEAD_MISMATCH;
	}

	return PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE;
}

static void build_result(
	const struct pqcp_deployment_evidence_trail *trail,
	const char *computed_head,
	uint32_t lines_seen,
	uint32_t marker_mask,
	uint32_t entry_count,
	uint32_t first_error_line,
	enum pqcp_deployment_evidence_trail_replay_error first_error,
	struct pqcp_deployment_evidence_trail_replay_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_SCHEMA_VERSION;
	result->lines_seen = lines_seen;
	result->marker_mask = marker_mask;
	result->first_error_line = first_error_line;
	result->first_error = first_error;
	result->trail_status = trail->status;
	result->trail_error_mask = trail->error_mask;
	result->trail_warning_mask = trail->warning_mask;
	result->profile = trail->profile;
	result->entry_count = entry_count;
	result->observed_stage_mask = trail->observed_stage_mask;
	result->passed = first_error ==
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE;
	set_text(result->top_candidate_id, sizeof(result->top_candidate_id),
		 text_present(trail->top_candidate_id) ?
			 trail->top_candidate_id : "none");
	set_text(result->nonce_hex, sizeof(result->nonce_hex),
		 nonce_valid(trail->nonce_hex) ? trail->nonce_hex :
			 "00000000000000000000000000000000");
	set_text(result->computed_head_digest_hex,
		 sizeof(result->computed_head_digest_hex),
		 text_present(computed_head) ? computed_head :
			 "0000000000000000000000000000000000000000000000000000000000000000");
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

const char *pqcp_deployment_evidence_trail_replay_error_str(
	enum pqcp_deployment_evidence_trail_replay_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD:
		return "malformed_field";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_DUPLICATE_MARKER:
		return "duplicate_marker";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MISSING_REQUIRED:
		return "missing_required";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_SEQUENCE_GAP:
		return "sequence_gap";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_ENTRY_OVERFLOW:
		return "entry_overflow";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_ENTRY_AFTER_HEAD:
		return "entry_after_head";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_LINK_MISMATCH:
		return "link_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_HEAD_MISMATCH:
		return "head_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_COUNT_MISMATCH:
		return "count_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_STAGE_MISMATCH:
		return "stage_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_STATUS_MISMATCH:
		return "status_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MASK_RANGE:
		return "mask_range";
	default:
		return "unknown";
	}
}

int pqcp_deployment_evidence_trail_replay_init(
	struct pqcp_deployment_evidence_trail_replay_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	state->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_SCHEMA_VERSION;
	state->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE;
	return 0;
}

static void note_error(
	struct pqcp_deployment_evidence_trail_replay_state *state,
	enum pqcp_deployment_evidence_trail_replay_error error)
{
	if (state->first_error ==
	    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE) {
		state->first_error = error;
		state->first_error_line = state->lines_seen;
	}
}

static int parse_entry_marker(
	const char *line,
	struct pqcp_deployment_evidence_trail_entry *entry)
{
	char text[FIELD_VALUE_MAX];

	memset(entry, 0, sizeof(*entry));

	if (get_u32_dec(line, "schema", &entry->schema_version) != 0 ||
	    get_u32_dec(line, "seq", &entry->sequence) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "stage", text, sizeof(text)) != 0 ||
	    parse_trail_stage(text, &entry->stage) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "digest", entry->digest_hex,
		     sizeof(entry->digest_hex)) != 0 ||
	    get_text(line, "link", entry->link_digest_hex,
		     sizeof(entry->link_digest_hex)) != 0) {
		return -EINVAL;
	}

	return 0;
}

static int parse_head_marker(
	const char *line,
	struct pqcp_deployment_evidence_trail *trail)
{
	char text[FIELD_VALUE_MAX];

	memset(trail, 0, sizeof(*trail));

	if (get_u32_dec(line, "schema", &trail->schema_version) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "profile", text, sizeof(text)) != 0 ||
	    parse_profile(text, &trail->profile) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "status", text, sizeof(text)) != 0 ||
	    parse_trail_status(text, &trail->status) != 0) {
		return -EINVAL;
	}
	if (get_u32_hex(line, "errors", &trail->error_mask) != 0 ||
	    get_u32_hex(line, "warnings", &trail->warning_mask) != 0 ||
	    get_u32_dec(line, "entries", &trail->entry_count) != 0 ||
	    get_u32_hex(line, "required_stages",
			&trail->required_stage_mask) != 0 ||
	    get_u32_hex(line, "observed_stages",
			&trail->observed_stage_mask) != 0) {
		return -EINVAL;
	}
	if (get_text(line, "top", trail->top_candidate_id,
		     sizeof(trail->top_candidate_id)) != 0 ||
	    get_text(line, "nonce", trail->nonce_hex,
		     sizeof(trail->nonce_hex)) != 0 ||
	    get_text(line, "head_digest", trail->head_digest_hex,
		     sizeof(trail->head_digest_hex)) != 0) {
		return -EINVAL;
	}

	return 0;
}

int pqcp_deployment_evidence_trail_replay_ingest_line(
	struct pqcp_deployment_evidence_trail_replay_state *state,
	const char *line)
{
	size_t len;

	if (state == NULL || line == NULL) {
		return -EINVAL;
	}

	len = strlen(line);
	if (len >= TRAIL_REPLAY_LINE_MAX) {
		state->lines_seen++;
		note_error(state,
			   PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD);
		return -EINVAL;
	}

	if (strncmp(line, TRAIL_ENTRY_MARKER_PREFIX,
		    strlen(TRAIL_ENTRY_MARKER_PREFIX)) == 0) {
		state->lines_seen++;

		if ((state->marker_mask &
		     PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_MARKER_HEAD) !=
		    0U) {
			note_error(state,
				   PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_ENTRY_AFTER_HEAD);
			return -EINVAL;
		}
		if (state->entries_seen >=
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES) {
			note_error(state,
				   PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_ENTRY_OVERFLOW);
			return -EINVAL;
		}
		if (parse_entry_marker(
			    line, &state->entries[state->entries_seen]) != 0) {
			note_error(state,
				   PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD);
			return -EINVAL;
		}
		if (state->entries[state->entries_seen].sequence !=
		    state->entries_seen) {
			note_error(state,
				   PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_SEQUENCE_GAP);
			return -EINVAL;
		}
		state->entries_seen++;
		state->marker_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_MARKER_ENTRY;
		return 0;
	}

	if (strncmp(line, TRAIL_HEAD_MARKER_PREFIX,
		    strlen(TRAIL_HEAD_MARKER_PREFIX)) == 0) {
		state->lines_seen++;

		if ((state->marker_mask &
		     PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_MARKER_HEAD) !=
		    0U) {
			note_error(state,
				   PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_DUPLICATE_MARKER);
			return -EINVAL;
		}
		if (parse_head_marker(line, &state->trail) != 0) {
			note_error(state,
				   PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MALFORMED_FIELD);
			return -EINVAL;
		}
		state->marker_mask |=
			PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_MARKER_HEAD;
		return 0;
	}

	/* Non-trail lines are ignored, not consumed as evidence. */
	return 0;
}

int pqcp_deployment_evidence_trail_replay_finish(
	struct pqcp_deployment_evidence_trail_replay_state *state,
	struct pqcp_deployment_evidence_trail_replay_result *result)
{
	char computed_head[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_evidence_trail_replay_error error;

	if (state == NULL || result == NULL) {
		return -EINVAL;
	}

	computed_head[0] = '\0';

	if (state->first_error !=
	    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE) {
		build_result(&state->trail, computed_head, state->lines_seen,
			     state->marker_mask, state->entries_seen,
			     state->first_error_line, state->first_error,
			     result);
		return -EBADMSG;
	}

	if ((state->marker_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_REQUIRED_MASK) !=
	    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_REQUIRED_MASK) {
		build_result(&state->trail, computed_head, state->lines_seen,
			     state->marker_mask, state->entries_seen,
			     state->lines_seen,
			     PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_MISSING_REQUIRED,
			     result);
		return -EBADMSG;
	}

	error = validate_chain(&state->trail, state->entries,
			       state->entries_seen, computed_head);
	build_result(&state->trail, computed_head, state->lines_seen,
		     state->marker_mask, state->entries_seen,
		     error == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE ?
			     0U : state->lines_seen,
		     error, result);

	return error == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_evidence_trail_replay_verify(
	const struct pqcp_deployment_evidence_trail *trail,
	const struct pqcp_deployment_evidence_trail_entry *entries,
	size_t entry_count,
	struct pqcp_deployment_evidence_trail_replay_result *result)
{
	char computed_head[
		PQCP_DEPLOYMENT_EVIDENCE_TRAIL_DIGEST_HEX_CHARS + 1U];
	enum pqcp_deployment_evidence_trail_replay_error error;

	if (trail == NULL || entries == NULL || result == NULL ||
	    entry_count > PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES) {
		return -EINVAL;
	}

	computed_head[0] = '\0';
	error = validate_chain(trail, entries, (uint32_t)entry_count,
			       computed_head);
	build_result(trail, computed_head, (uint32_t)entry_count + 1U,
		     PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_REQUIRED_MASK,
		     (uint32_t)entry_count,
		     error == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE ?
			     0U : (uint32_t)entry_count + 1U,
		     error, result);

	return error == PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_ERROR_NONE ?
		0 : -EBADMSG;
}

int pqcp_deployment_evidence_trail_replay_emit_result(
	const struct pqcp_deployment_evidence_trail_replay_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY_SCHEMA_VERSION ||
	    !trail_status_valid(result->trail_status) ||
	    !profile_valid(result->profile) ||
	    result->entry_count >
		    PQCP_DEPLOYMENT_EVIDENCE_TRAIL_MAX_ENTRIES ||
	    !text_present(result->top_candidate_id) ||
	    !nonce_valid(result->nonce_hex) ||
	    !digest_valid(result->computed_head_digest_hex)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY schema=%u profile=%s status=%s passed=%s error=%s error_line=%u lines=%u markers=0x%08x errors=0x%08x warnings=0x%08x entries=%u observed_stages=0x%02x top=%s nonce=%s computed_head=%s\n",
	       result->schema_version,
	       pqcp_deployment_release_gate_profile_str(result->profile),
	       pqcp_deployment_evidence_trail_status_str(
		       result->trail_status),
	       result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_evidence_trail_replay_error_str(
		       result->first_error),
	       result->first_error_line,
	       result->lines_seen,
	       result->marker_mask,
	       result->trail_error_mask,
	       result->trail_warning_mask,
	       result->entry_count,
	       result->observed_stage_mask,
	       result->top_candidate_id,
	       result->nonce_hex,
	       result->computed_head_digest_hex);

	return result->passed ? 0 : -EBADMSG;
}
