/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Model-based stateful property testing harness for the edge security
 * state machines.
 *
 * A model is an abstract specification of one firmware module, written as
 * a small state machine that is deliberately independent of the module's
 * implementation. The harness drives a seeded pseudo-random operation
 * trace through the model and the real module in lock step; every op
 * returns a violation code (0 = conforming) and is followed by the
 * module's own audit, so there are two oracles per step.
 *
 * Violation codes: 0 none, 1 module audit failed (set by the harness),
 * >= 2 model property violations (owned by the model).
 *
 * Marker grammar (one line each, at the start of the line; this is a
 * contract with scripts/run_model_checks.py):
 *
 *   PQCP_MODEL_CHECK module=<m> seeds=<n> ops=<n> violations=<n> status=PASS|FAIL
 *   PQCP_MODEL_COUNTEREXAMPLE module=<m> seed=<hex16> violation=<code> ops=<n> trace=<hex>
 *   PQCP_MODEL_SUMMARY modules=4 traces=<n> ops=<n> violations=0 status=PASS
 *
 * <code> is a decimal integer. <hex> encodes the shrunk trace as 7 bytes
 * per op: kind, a, b, then dt as little-endian u32. <seed> reproduces the
 * unshrunk trace. The positive-control test prints PQCP_MODEL_CONTROL
 * lines instead, so it can never be mistaken for a module counterexample.
 *
 * A counterexample is followed by an advisory diagnostic line (not part of
 * the contract) naming the violated check:
 *
 *   PQCP_MODEL_NOTE module=<m> line=<n> check=<expression>
 */

#ifndef MODEL_HARNESS_H_
#define MODEL_HARNESS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MODEL_TRACE_MAX 64U
#define MODEL_VIOLATION_AUDIT 1
#define MODEL_MAX_COUNTEREXAMPLES 3U
#define MODEL_HEX_PER_OP 14U

/* Record which property fired, then return its violation code. */
extern const char *model_fail_check;
extern int model_fail_line;
#define MODEL_REQUIRE(cond, code)                                     \
	do {                                                          \
		if (!(cond)) {                                        \
			model_fail_check = #cond;                     \
			model_fail_line = __LINE__;                   \
			return (code);                                \
		}                                                     \
	} while (0)

struct model_op {
	uint8_t kind;
	uint8_t a;
	uint8_t b;
	uint32_t dt;
};

struct model_vtable {
	const char *name;
	/* Number of distinct op kinds the generator may produce. */
	uint8_t op_kinds;
	/* Rebuild both the model and the module under test from scratch. */
	void (*reset)(void);
	/* Apply one op to both; return 0 or a violation code >= 2. */
	int (*apply)(const struct model_op *op);
	/* The module's own audit; nonzero is violation code 1. May be NULL. */
	int (*audit)(void);
};

struct model_stats {
	uint32_t seeds;
	uint32_t ops;
	uint32_t violations;
};

uint64_t model_seed_for(uint32_t module_index, uint32_t index);

/* Deterministic: the same (vtable kinds, seed, max_len) gives the same trace. */
uint32_t model_generate(const struct model_vtable *vt, uint64_t seed,
			uint32_t max_len, struct model_op *trace);

/* Reset, then replay; returns the first violation code or 0. */
int model_run_trace(const struct model_vtable *vt,
		    const struct model_op *trace, uint32_t n,
		    uint32_t *applied);

/* ddmin over op indices; returns the 1-minimal length (trace shrunk in place). */
uint32_t model_shrink(const struct model_vtable *vt,
		      struct model_op *trace, uint32_t n, int code);

void model_trace_hex(const struct model_op *trace, uint32_t n, char *out,
		     size_t capacity);

/*
 * Run `seeds` seeded traces. Prints CHECK (and up to
 * MODEL_MAX_COUNTEREXAMPLES COUNTEREXAMPLE) markers when `emit` is set.
 * Returns the number of violating traces.
 */
uint32_t model_check(const struct model_vtable *vt, uint32_t module_index,
		     uint32_t seeds, bool emit, struct model_stats *stats);

#endif /* MODEL_HARNESS_H_ */
