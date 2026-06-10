/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * pqcp-evidence-verify - host replay of firmware deployment evidence.
 *
 * Ingests one captured device transcript (QEMU or serial console log),
 * replays the terminal evidence chain markers with the UNMODIFIED firmware
 * verifier translation units, recomputes every digest, and cross-binds the
 * layers (verdict digest into seal, seal digest into passport). Exit code 0
 * means the transcript's terminal chain is internally consistent and
 * tamper-free; any parse failure, digest mismatch, or broken binding exits 1.
 *
 * No Zephyr toolchain, no python, no network: a reviewer needs only a C
 * compiler to independently check what a device claimed.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pqcp_zephyr/deployment_assurance_passport_replay.h>
#include <pqcp_zephyr/deployment_evidence_seal_replay.h>
#include <pqcp_zephyr/deployment_evidence_verdict_replay.h>

#define LINE_MAX_CHARS 4096U
#define FIELD_MAX_CHARS 96U

#define PASSPORT_MARKER_PREFIX "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT "

struct transcript_summary {
	unsigned long total_lines;
	unsigned long verdict_markers;
	unsigned long seal_markers;
	unsigned long passport_markers;
	bool verdict_passed;
	bool seal_passed;
	bool passport_passed;
	bool verdict_seal_bound;
	bool seal_passport_bound;
	struct pqcp_deployment_evidence_verdict_replay_result verdict;
	struct pqcp_deployment_evidence_seal_replay_result seal;
	struct pqcp_deployment_assurance_passport_replay_result passport;
};

/* ------------------------------------------------------------------ */
/* Passport marker line -> struct reconstruction                       */
/*                                                                      */
/* The passport replay verifier is struct-based; this is the host-side  */
/* line adapter. Field grammar matches the firmware emitters: space-    */
/* separated key=value tokens, keys anchored at start-of-line or after  */
/* a space. Digest recomputation stays in the firmware .c file.         */
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

static int get_u32_dec(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_MAX_CHARS];
	char *end = NULL;
	unsigned long parsed;

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	parsed = strtoul(value, &end, 10);
	if (end == NULL || *end != '\0' || parsed > UINT32_MAX) {
		return -EINVAL;
	}
	*out = (uint32_t)parsed;
	return 0;
}

static int get_u32_hex(const char *line, const char *key, uint32_t *out)
{
	char value[FIELD_MAX_CHARS];
	char *end = NULL;
	unsigned long parsed;

	if (field_value(line, key, value, sizeof(value)) != 0) {
		return -EINVAL;
	}
	parsed = strtoul(value, &end, 16);
	if (end == NULL || *end != '\0' || parsed > UINT32_MAX) {
		return -EINVAL;
	}
	*out = (uint32_t)parsed;
	return 0;
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
	struct pqcp_deployment_assurance_passport *passport)
{
	char text[FIELD_MAX_CHARS];
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
	    get_text(line, "passport_digest", passport->passport_digest_hex,
		     sizeof(passport->passport_digest_hex)) != 0) {
		return -EINVAL;
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* Transcript processing                                                */
/* ------------------------------------------------------------------ */

static void strip_line_endings(char *line)
{
	size_t len = strlen(line);

	while (len > 0U &&
	       (line[len - 1U] == '\n' || line[len - 1U] == '\r')) {
		line[--len] = '\0';
	}
}

static const char *bool_token(bool value)
{
	return value ? "true" : "false";
}

static int process_transcript(FILE *input, bool lenient,
			      struct transcript_summary *summary)
{
	static char line[LINE_MAX_CHARS];
	struct pqcp_deployment_evidence_verdict_replay_state verdict_state;
	struct pqcp_deployment_evidence_seal_replay_state seal_state;
	struct pqcp_deployment_assurance_passport passport;
	bool passport_parse_failed = false;
	int ret;

	memset(summary, 0, sizeof(*summary));
	if (pqcp_deployment_evidence_verdict_replay_init(&verdict_state) != 0 ||
	    pqcp_deployment_evidence_seal_replay_init(&seal_state) != 0) {
		return -EINVAL;
	}
	memset(&passport, 0, sizeof(passport));

	while (fgets(line, sizeof(line), input) != NULL) {
		summary->total_lines++;
		strip_line_endings(line);

		if (strncmp(line, PASSPORT_MARKER_PREFIX,
			    strlen(PASSPORT_MARKER_PREFIX)) == 0) {
			summary->passport_markers++;
			if (summary->passport_markers > 1U ||
			    parse_passport_marker(line, &passport) != 0) {
				passport_parse_failed = true;
			}
			continue;
		}

		/* Both replay state machines ignore non-matching lines. */
		(void)pqcp_deployment_evidence_verdict_replay_ingest_line(
			&verdict_state, line);
		(void)pqcp_deployment_evidence_seal_replay_ingest_line(
			&seal_state, line);
	}

	summary->verdict_markers = verdict_state.lines_seen;
	summary->seal_markers = seal_state.lines_seen;

	ret = pqcp_deployment_evidence_verdict_replay_finish(
		&verdict_state, &summary->verdict);
	summary->verdict_passed = ret == 0 && summary->verdict.passed;

	ret = pqcp_deployment_evidence_seal_replay_finish(
		&seal_state, &summary->seal);
	summary->seal_passed = ret == 0 && summary->seal.passed;

	if (summary->passport_markers == 1U && !passport_parse_failed) {
		ret = pqcp_deployment_assurance_passport_replay_verify(
			&passport, &summary->passport);
		summary->passport_passed = ret == 0 &&
			summary->passport.passed;
	} else {
		summary->passport_passed = false;
	}

	summary->verdict_seal_bound =
		summary->verdict_passed && summary->seal_passed &&
		strcmp(summary->seal.verdict_digest_hex,
		       summary->verdict.computed_digest_hex) == 0;
	summary->seal_passport_bound =
		summary->seal_passed && summary->passport_passed &&
		strcmp(passport.seal_digest_hex,
		       summary->seal.computed_digest_hex) == 0;

	if (lenient) {
		bool any_layer_present = summary->verdict_markers != 0U ||
			summary->seal_markers != 0U ||
			summary->passport_markers != 0U;
		bool verdict_ok = summary->verdict_markers == 0U ||
			summary->verdict_passed;
		bool seal_ok = summary->seal_markers == 0U ||
			summary->seal_passed;
		bool passport_ok = summary->passport_markers == 0U ||
			summary->passport_passed;
		bool binding_ok =
			(summary->verdict_markers == 0U ||
			 summary->seal_markers == 0U ||
			 summary->verdict_seal_bound) &&
			(summary->seal_markers == 0U ||
			 summary->passport_markers == 0U ||
			 summary->seal_passport_bound);

		return (any_layer_present && verdict_ok && seal_ok &&
			passport_ok && binding_ok) ? 0 : -EBADMSG;
	}

	return (summary->verdict_passed && summary->seal_passed &&
		summary->passport_passed && summary->verdict_seal_bound &&
		summary->seal_passport_bound) ? 0 : -EBADMSG;
}

/* ------------------------------------------------------------------ */
/* Reporting                                                            */
/* ------------------------------------------------------------------ */

static void print_summary(FILE *out, const struct transcript_summary *summary,
			  bool chain_ok)
{
	fprintf(out, "pqcp-evidence-verify: %s\n",
		chain_ok ? "CHAIN OK" : "CHAIN BROKEN");
	fprintf(out,
		"  lines=%lu verdict_markers=%lu seal_markers=%lu passport_markers=%lu\n",
		summary->total_lines, summary->verdict_markers,
		summary->seal_markers, summary->passport_markers);
	fprintf(out, "  verdict_replay=%s error=%s digest=%s\n",
		bool_token(summary->verdict_passed),
		pqcp_deployment_evidence_verdict_replay_error_str(
			summary->verdict.first_error),
		summary->verdict.computed_digest_hex);
	fprintf(out, "  seal_replay=%s error=%s digest=%s\n",
		bool_token(summary->seal_passed),
		pqcp_deployment_evidence_seal_replay_error_str(
			summary->seal.first_error),
		summary->seal.computed_digest_hex);
	fprintf(out, "  passport_replay=%s error=%s digest=%s\n",
		bool_token(summary->passport_passed),
		pqcp_deployment_assurance_passport_replay_error_str(
			summary->passport.first_error),
		summary->passport.computed_digest_hex);
	fprintf(out, "  verdict->seal_binding=%s seal->passport_binding=%s\n",
		bool_token(summary->verdict_seal_bound),
		bool_token(summary->seal_passport_bound));
}

static int write_json(const char *path,
		      const struct transcript_summary *summary,
		      bool chain_ok)
{
	FILE *out = fopen(path, "w");

	if (out == NULL) {
		return -EIO;
	}

	fprintf(out, "{\n");
	fprintf(out, "  \"schema_version\": 1,\n");
	fprintf(out, "  \"chain_ok\": %s,\n", bool_token(chain_ok));
	fprintf(out, "  \"total_lines\": %lu,\n", summary->total_lines);
	fprintf(out, "  \"verdict\": {\"markers\": %lu, \"passed\": %s, \"error\": \"%s\", \"computed_digest\": \"%s\"},\n",
		summary->verdict_markers,
		bool_token(summary->verdict_passed),
		pqcp_deployment_evidence_verdict_replay_error_str(
			summary->verdict.first_error),
		summary->verdict.computed_digest_hex);
	fprintf(out, "  \"seal\": {\"markers\": %lu, \"passed\": %s, \"error\": \"%s\", \"computed_digest\": \"%s\"},\n",
		summary->seal_markers,
		bool_token(summary->seal_passed),
		pqcp_deployment_evidence_seal_replay_error_str(
			summary->seal.first_error),
		summary->seal.computed_digest_hex);
	fprintf(out, "  \"passport\": {\"markers\": %lu, \"passed\": %s, \"error\": \"%s\", \"computed_digest\": \"%s\", \"board\": \"%s\"},\n",
		summary->passport_markers,
		bool_token(summary->passport_passed),
		pqcp_deployment_assurance_passport_replay_error_str(
			summary->passport.first_error),
		summary->passport.computed_digest_hex,
		summary->passport.board);
	fprintf(out, "  \"bindings\": {\"verdict_to_seal\": %s, \"seal_to_passport\": %s}\n",
		bool_token(summary->verdict_seal_bound),
		bool_token(summary->seal_passport_bound));
	fprintf(out, "}\n");

	return fclose(out) == 0 ? 0 : -EIO;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--lenient] [--quiet] [--json <path>] <transcript.log>\n"
		"\n"
		"Replays the firmware deployment evidence chain from a captured\n"
		"device transcript using the unmodified firmware verifier code.\n"
		"Exit 0: terminal chain consistent. Exit 1: missing, malformed,\n"
		"tampered, or unbound evidence. Exit 2: usage or I/O error.\n"
		"\n"
		"  --lenient  verify only the layers present instead of\n"
		"             requiring the full verdict+seal+passport chain\n"
		"  --quiet    suppress the human-readable summary\n"
		"  --json     also write a machine-readable JSON summary\n",
		argv0);
}

int main(int argc, char **argv)
{
	struct transcript_summary summary;
	const char *transcript_path = NULL;
	const char *json_path = NULL;
	bool lenient = false;
	bool quiet = false;
	bool chain_ok;
	FILE *input;
	int ret;

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--lenient") == 0) {
			lenient = true;
		} else if (strcmp(argv[i], "--quiet") == 0) {
			quiet = true;
		} else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
			json_path = argv[++i];
		} else if (strcmp(argv[i], "--help") == 0 ||
			   strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else if (argv[i][0] == '-') {
			usage(argv[0]);
			return 2;
		} else if (transcript_path == NULL) {
			transcript_path = argv[i];
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (transcript_path == NULL) {
		usage(argv[0]);
		return 2;
	}

	input = fopen(transcript_path, "r");
	if (input == NULL) {
		fprintf(stderr, "pqcp-evidence-verify: cannot open %s\n",
			transcript_path);
		return 2;
	}

	ret = process_transcript(input, lenient, &summary);
	(void)fclose(input);
	if (ret == -EINVAL) {
		fprintf(stderr, "pqcp-evidence-verify: internal init error\n");
		return 2;
	}
	chain_ok = ret == 0;

	if (!quiet) {
		print_summary(stdout, &summary, chain_ok);
	}
	if (json_path != NULL && write_json(json_path, &summary,
					    chain_ok) != 0) {
		fprintf(stderr, "pqcp-evidence-verify: cannot write %s\n",
			json_path);
		return 2;
	}

	return chain_ok ? 0 : 1;
}
