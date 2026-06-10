/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * pqcp-evidence-fuzz - deterministic mutational fuzzer for the evidence
 * grammar.
 *
 * The marker parsers consume attacker-visible serial text, which makes
 * them a security surface. This harness drives the UNMODIFIED firmware
 * replay-verifier parsers (verdict, seal), the host passport line adapter,
 * and the signature chunk reassembler with corpus lines mutated by a
 * seeded xorshift PRNG. Built with ASan+UBSan and
 * -fno-sanitize-recover=all, any memory error or UB aborts the run with a
 * nonzero exit; a clean run prints one stable PQCP_FUZZ PASS marker.
 *
 * Deliberately not libFuzzer: a self-contained C driver runs identically
 * on any host with a C compiler (Apple clang ships no fuzzer runtime),
 * and a fixed seed makes every run reproducible by construction.
 *
 * Coverage-guided: the target translation units are compiled with
 * -fsanitize-coverage=trace-pc-guard (clang) or trace-pc (gcc), and the
 * callbacks below maintain an edge map. Any mutated input that reaches a
 * never-before-seen edge is promoted into the in-memory corpus, so later
 * mutations explore progressively deeper parser states. The harness
 * itself is NOT instrumented, and the mldsa backend is deliberately left
 * uninstrumented so coverage pressure stays on the parsers under test.
 * Evolution is deterministic for a fixed seed and build.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pqcp_zephyr/deployment_evidence_seal_replay.h>
#include <pqcp_zephyr/deployment_evidence_verdict_replay.h>

#include "passport_parse.h"
#include "signature_check.h"

#define MAX_CORPUS_LINES 4096U
#define MAX_LINE_CHARS 4096U

static char corpus[MAX_CORPUS_LINES][MAX_LINE_CHARS];
static size_t corpus_lengths[MAX_CORPUS_LINES];
static size_t corpus_count;

static uint64_t rng_state;

/* ------------------------------------------------------------------ */
/* Edge coverage (SanitizerCoverage callbacks)                          */
/*                                                                      */
/* Only the target TUs are instrumented; these callbacks fire from      */
/* parser code. edge_seen is sized generously and ids saturate at the   */
/* array bound, so an oversized build degrades gracefully instead of    */
/* corrupting memory.                                                   */
/* ------------------------------------------------------------------ */

#define EDGE_MAP_SLOTS 262144U

static uint8_t edge_seen[EDGE_MAP_SLOTS];
static uint32_t edge_guards_total;
static uint32_t edges_covered;
static volatile int new_edge_this_run;

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
void __sanitizer_cov_trace_pc_guard(uint32_t *guard);
void __sanitizer_cov_trace_pc(void);

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
{
	static uint32_t next_id = 1U;

	if (start == stop || *start != 0U) {
		return;
	}
	for (uint32_t *guard = start; guard < stop; ++guard) {
		*guard = next_id < EDGE_MAP_SLOTS ? next_id++ : 0U;
	}
	edge_guards_total = next_id;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard)
{
	const uint32_t id = *guard;

	if (id == 0U || id >= EDGE_MAP_SLOTS) {
		return;
	}
	if (edge_seen[id] == 0U) {
		edge_seen[id] = 1U;
		edges_covered++;
		new_edge_this_run = 1;
	}
}

/* gcc fallback (-fsanitize-coverage=trace-pc): hash the call site. */
void __sanitizer_cov_trace_pc(void)
{
	const uintptr_t pc =
		(uintptr_t)__builtin_return_address(0);
	const uint32_t id = (uint32_t)((pc >> 4) % (EDGE_MAP_SLOTS - 1U)) + 1U;

	if (edge_seen[id] == 0U) {
		edge_seen[id] = 1U;
		edges_covered++;
		new_edge_this_run = 1;
	}
	if (edge_guards_total == 0U) {
		edge_guards_total = EDGE_MAP_SLOTS;
	}
}

static uint64_t rng_next(void)
{
	uint64_t x = rng_state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	rng_state = x;
	return x;
}

static uint32_t rng_below(uint32_t bound)
{
	return bound == 0U ? 0U : (uint32_t)(rng_next() % bound);
}

static int load_corpus(const char *path)
{
	static char line[MAX_LINE_CHARS];
	FILE *input = fopen(path, "r");

	if (input == NULL) {
		fprintf(stderr, "pqcp-evidence-fuzz: cannot open %s\n", path);
		return -1;
	}

	while (corpus_count < MAX_CORPUS_LINES &&
	       fgets(line, sizeof(line), input) != NULL) {
		size_t len = strlen(line);

		while (len > 0U &&
		       (line[len - 1U] == '\n' || line[len - 1U] == '\r')) {
			line[--len] = '\0';
		}
		if (len == 0U) {
			continue;
		}
		memcpy(corpus[corpus_count], line, len + 1U);
		corpus_lengths[corpus_count] = len;
		corpus_count++;
	}

	(void)fclose(input);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Mutators                                                             */
/* ------------------------------------------------------------------ */

static size_t mutate(char *buffer, size_t len)
{
	const uint32_t ops = 1U + rng_below(8U);

	for (uint32_t op = 0U; op < ops; ++op) {
		switch (rng_below(9U)) {
		case 0: /* flip one bit */
			if (len > 0U) {
				buffer[rng_below((uint32_t)len)] ^=
					(char)(1U << rng_below(8U));
			}
			break;
		case 1: /* overwrite one byte with anything */
			if (len > 0U) {
				buffer[rng_below((uint32_t)len)] =
					(char)rng_below(256U);
			}
			break;
		case 2: /* truncate */
			if (len > 0U) {
				len = rng_below((uint32_t)len);
			}
			break;
		case 3: /* delete a span */
			if (len > 2U) {
				uint32_t start = rng_below((uint32_t)len - 1U);
				uint32_t span = 1U + rng_below(
					(uint32_t)(len - start - 1U));

				memmove(&buffer[start], &buffer[start + span],
					len - start - span);
				len -= span;
			}
			break;
		case 4: /* duplicate a span at the end */
			if (len > 0U && len < MAX_LINE_CHARS - 64U) {
				uint32_t start = rng_below((uint32_t)len);
				uint32_t span = 1U + rng_below(63U);

				if (start + span > len) {
					span = (uint32_t)(len - start);
				}
				memcpy(&buffer[len], &buffer[start], span);
				len += span;
			}
			break;
		case 5: /* insert a random byte */
			if (len < MAX_LINE_CHARS - 2U) {
				uint32_t at = rng_below((uint32_t)len + 1U);

				memmove(&buffer[at + 1U], &buffer[at],
					len - at);
				buffer[at] = (char)rng_below(256U);
				len++;
			}
			break;
		case 6: /* swap a separator: space <-> '=' */
			if (len > 0U) {
				uint32_t at = rng_below((uint32_t)len);

				if (buffer[at] == ' ') {
					buffer[at] = '=';
				} else if (buffer[at] == '=') {
					buffer[at] = ' ';
				}
			}
			break;
		case 7: /* splice with a random corpus line */
			if (corpus_count > 0U) {
				uint32_t other = rng_below(
					(uint32_t)corpus_count);
				size_t cut = rng_below((uint32_t)len + 1U);
				size_t take = rng_below((uint32_t)
					corpus_lengths[other] + 1U);

				if (cut + take >= MAX_LINE_CHARS) {
					take = MAX_LINE_CHARS - 1U - cut;
				}
				memcpy(&buffer[cut], corpus[other], take);
				len = cut + take;
			}
			break;
		case 8: /* append a run of one repeated byte */
		default:
			if (len < MAX_LINE_CHARS - 2U) {
				uint32_t span = 1U + rng_below(255U);
				char fill = (char)rng_below(256U);

				if (len + span >= MAX_LINE_CHARS) {
					span = (uint32_t)(MAX_LINE_CHARS - 1U -
							  len);
				}
				memset(&buffer[len], fill, span);
				len += span;
			}
			break;
		}
	}

	/* Parsers receive C strings: no interior NULs, always terminated. */
	for (size_t i = 0U; i < len; ++i) {
		if (buffer[i] == '\0') {
			buffer[i] = ' ';
		}
	}
	buffer[len] = '\0';
	return len;
}

/* ------------------------------------------------------------------ */
/* Targets                                                              */
/* ------------------------------------------------------------------ */

static void exercise_verdict(const char *line)
{
	struct pqcp_deployment_evidence_verdict_replay_state state;
	struct pqcp_deployment_evidence_verdict_replay_result result;

	(void)pqcp_deployment_evidence_verdict_replay_init(&state);
	(void)pqcp_deployment_evidence_verdict_replay_ingest_line(&state,
								  line);
	if (rng_below(4U) == 0U) {
		/* Occasionally re-ingest to walk the duplicate path. */
		(void)pqcp_deployment_evidence_verdict_replay_ingest_line(
			&state, line);
	}
	(void)pqcp_deployment_evidence_verdict_replay_finish(&state, &result);
}

static void exercise_seal(const char *line)
{
	struct pqcp_deployment_evidence_seal_replay_state state;
	struct pqcp_deployment_evidence_seal_replay_result result;

	(void)pqcp_deployment_evidence_seal_replay_init(&state);
	(void)pqcp_deployment_evidence_seal_replay_ingest_line(&state, line);
	if (rng_below(4U) == 0U) {
		(void)pqcp_deployment_evidence_seal_replay_ingest_line(&state,
								       line);
	}
	(void)pqcp_deployment_evidence_seal_replay_finish(&state, &result);
}

static void exercise_passport(const char *line)
{
	struct pqcp_deployment_assurance_passport passport;

	(void)parse_passport_marker(line, &passport);
}

static void exercise_signature(const char *line)
{
	static const char digest[] =
		"00112233445566778899aabbccddeeff"
		"00112233445566778899aabbccddeeff";
	struct signature_capture capture;

	signature_capture_init(&capture);
	(void)signature_capture_ingest_line(&capture, line);
	if (rng_below(4U) == 0U) {
		(void)signature_capture_ingest_line(&capture, line);
	}
	if (signature_capture_complete(&capture)) {
		(void)signature_capture_verify(&capture, digest);
	}
}

static void exercise_all(const char *line)
{
	exercise_verdict(line);
	exercise_seal(line);
	exercise_passport(line);
	exercise_signature(line);
}

int main(int argc, char **argv)
{
	static char buffer[MAX_LINE_CHARS];
	unsigned long iterations = 100000UL;
	uint64_t seed = 0x9e3779b97f4a7c15ULL;
	int corpus_files = 0;

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
			iterations = strtoul(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
			seed = strtoull(argv[++i], NULL, 0);
		} else if (argv[i][0] == '-') {
			fprintf(stderr,
				"usage: %s [--iterations N] [--seed S] <corpus.log>...\n",
				argv[0]);
			return 2;
		} else {
			if (load_corpus(argv[i]) != 0) {
				return 2;
			}
			corpus_files++;
		}
	}

	if (corpus_files == 0 || corpus_count == 0U) {
		fprintf(stderr, "pqcp-evidence-fuzz: no corpus lines loaded\n");
		return 2;
	}

	rng_state = seed != 0U ? seed : 1U;

	/* Regression pass: every corpus line, unmutated. */
	for (size_t i = 0U; i < corpus_count; ++i) {
		exercise_all(corpus[i]);
	}

	/* Mutation pass with coverage-guided corpus evolution: inputs that
	 * reach a new edge are promoted so later mutations build on them.
	 */
	size_t seed_corpus_count = corpus_count;

	for (unsigned long i = 0UL; i < iterations; ++i) {
		uint32_t pick = rng_below((uint32_t)corpus_count);
		size_t len = corpus_lengths[pick];

		memcpy(buffer, corpus[pick], len + 1U);
		len = mutate(buffer, len);
		new_edge_this_run = 0;
		exercise_all(buffer);
		if (new_edge_this_run && corpus_count < MAX_CORPUS_LINES) {
			memcpy(corpus[corpus_count], buffer, len + 1U);
			corpus_lengths[corpus_count] = len;
			corpus_count++;
		}
	}

	printf("PQCP_FUZZ PASS targets=4 corpus_lines=%zu evolved=%zu edges_covered=%u edge_guards=%u iterations=%lu seed=0x%llx\n",
	       seed_corpus_count, corpus_count - seed_corpus_count,
	       edges_covered, edge_guards_total, iterations,
	       (unsigned long long)seed);
	return 0;
}
