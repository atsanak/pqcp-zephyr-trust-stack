/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Positive controls for the model harness. A checker that cannot fail
 * proves nothing, so these feed a deliberately broken fake module through
 * the real generator, oracle and shrinker and require a counterexample
 * that shrinks to the known minimal trace.
 */

#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include "model_harness.h"
#include <zephyr/ztest.h>

/*
 * Fake module: arm / disarm gate a counter. The planted defect is a
 * property violation (code 77) once `fake_threshold` increments landed
 * while armed. Disarm never resets the counter, so the unique 1-minimal
 * failing trace is [arm, inc x threshold].
 */
enum { FAKE_ARM, FAKE_INC, FAKE_DISARM, FAKE_NOP, FAKE_KINDS };
#define FAKE_VIOLATION 77

static uint32_t fake_hits;
static bool fake_armed;
static uint32_t fake_threshold;
static uint32_t fake_audit_limit;

static void fake_reset(void)
{
	fake_hits = 0U;
	fake_armed = false;
}

static int fake_apply(const struct model_op *op)
{
	switch (op->kind) {
	case FAKE_ARM:
		fake_armed = true;
		break;
	case FAKE_INC:
		if (fake_armed) {
			++fake_hits;
		}
		break;
	case FAKE_DISARM:
		fake_armed = false;
		break;
	default:
		break;
	}
	return fake_hits >= fake_threshold ? FAKE_VIOLATION : 0;
}

static int fake_audit(void)
{
	return fake_hits >= fake_audit_limit ? -1 : 0;
}

static const struct model_vtable fake_vt = {
	.name = "control",
	.op_kinds = FAKE_KINDS,
	.reset = fake_reset,
	.apply = fake_apply,
	.audit = fake_audit,
};

static void fake_configure(uint32_t threshold, uint32_t audit_limit)
{
	fake_threshold = threshold;
	fake_audit_limit = audit_limit;
}

#define OP(k, delta) { .kind = (k), .a = 0, .b = 0, .dt = (delta) }

static void assert_one_minimal(const struct model_op *trace, uint32_t n,
			       int code)
{
	struct model_op cut[MODEL_TRACE_MAX];

	zassert_equal(model_run_trace(&fake_vt, trace, n, NULL), code);
	for (uint32_t skip = 0U; skip < n; ++skip) {
		uint32_t m = 0U;

		for (uint32_t i = 0U; i < n; ++i) {
			if (i != skip) {
				cut[m++] = trace[i];
			}
		}
		zassert_not_equal(
			model_run_trace(&fake_vt, cut, m, NULL), code,
			"op %u of the shrunk trace is removable", skip);
	}
}

ZTEST(edge_model, test_control_hand_built_trace_shrinks)
{
	struct model_op trace[] = {
		OP(FAKE_NOP, 5), OP(FAKE_INC, 0), OP(FAKE_ARM, 3),
		OP(FAKE_DISARM, 0), OP(FAKE_INC, 9), OP(FAKE_ARM, 0),
		OP(FAKE_INC, 1), OP(FAKE_NOP, 0), OP(FAKE_INC, 2),
		OP(FAKE_DISARM, 7), OP(FAKE_ARM, 0), OP(FAKE_INC, 4),
		OP(FAKE_NOP, 0),
	};
	const uint32_t n = ARRAY_SIZE(trace);
	char hex[MODEL_TRACE_MAX * MODEL_HEX_PER_OP + 1U];
	uint32_t shrunk;

	fake_configure(3U, UINT32_MAX);
	zassert_equal(model_run_trace(&fake_vt, trace, n, NULL),
		      FAKE_VIOLATION, "the planted defect must be reachable");
	shrunk = model_shrink(&fake_vt, trace, n, FAKE_VIOLATION);
	zassert_equal(shrunk, 4U, "expected [arm, inc, inc, inc]");
	zassert_equal(trace[0].kind, FAKE_ARM);
	for (uint32_t i = 1U; i < shrunk; ++i) {
		zassert_equal(trace[i].kind, FAKE_INC);
	}
	assert_one_minimal(trace, shrunk, FAKE_VIOLATION);
	model_trace_hex(trace, shrunk, hex, sizeof(hex));
	zassert_equal(strlen(hex), shrunk * MODEL_HEX_PER_OP);
	printk("PQCP_MODEL_CONTROL module=control violation=%d "
	       "original_ops=%u shrunk_ops=%u trace=%s\n",
	       FAKE_VIOLATION, n, shrunk, hex);
}

ZTEST(edge_model, test_control_seeded_counterexamples_shrink)
{
	struct model_stats stats;
	uint32_t found = 0U;

	fake_configure(3U, UINT32_MAX);
	zassert_true(model_check(&fake_vt, 99U, MODEL_TRACE_MAX, false,
				 &stats) > 0U,
		     "oracle never fired on the broken fake");
	for (uint32_t i = 0U; i < 64U; ++i) {
		struct model_op trace[MODEL_TRACE_MAX];
		const uint32_t n = model_generate(
			&fake_vt, model_seed_for(99U, i), MODEL_TRACE_MAX,
			trace);
		uint32_t applied;
		const int code = model_run_trace(&fake_vt, trace, n,
						 &applied);

		if (code == 0) {
			continue;
		}
		++found;
		zassert_equal(code, FAKE_VIOLATION);
		zassert_equal(model_shrink(&fake_vt, trace, n, code), 4U);
		assert_one_minimal(trace, 4U, code);
	}
	zassert_true(found > 0U);
}

ZTEST(edge_model, test_control_audit_oracle_is_violation_one)
{
	struct model_op trace[MODEL_TRACE_MAX];
	uint32_t n;
	uint32_t found = 0U;

	/* The apply-side property never fires; only the audit does. */
	fake_configure(UINT32_MAX, 2U);
	for (uint32_t i = 0U; i < 64U && found == 0U; ++i) {
		n = model_generate(&fake_vt, model_seed_for(98U, i),
				   MODEL_TRACE_MAX, trace);
		if (model_run_trace(&fake_vt, trace, n, NULL) ==
		    MODEL_VIOLATION_AUDIT) {
			++found;
			zassert_equal(model_shrink(&fake_vt, trace, n,
						   MODEL_VIOLATION_AUDIT),
				      3U, "expected [arm, inc, inc]");
		}
	}
	zassert_equal(found, 1U, "audit oracle never fired");
}

ZTEST(edge_model, test_control_conforming_fake_passes)
{
	struct model_stats stats;

	fake_configure(UINT32_MAX, UINT32_MAX);
	zassert_equal(model_check(&fake_vt, 97U, MODEL_TRACE_MAX, false,
				  &stats), 0U);
	zassert_equal(stats.seeds, MODEL_TRACE_MAX);
	zassert_true(stats.ops > 0U);
}

ZTEST(edge_model, test_control_generation_is_deterministic)
{
	struct model_op first[MODEL_TRACE_MAX];
	struct model_op second[MODEL_TRACE_MAX];
	struct model_op other[MODEL_TRACE_MAX];
	char hex_a[MODEL_TRACE_MAX * MODEL_HEX_PER_OP + 1U];
	char hex_b[MODEL_TRACE_MAX * MODEL_HEX_PER_OP + 1U];
	uint32_t na;
	uint32_t nb;
	uint32_t nc;

	na = model_generate(&fake_vt, 0xC0FFEE1234ULL, MODEL_TRACE_MAX,
			    first);
	nb = model_generate(&fake_vt, 0xC0FFEE1234ULL, MODEL_TRACE_MAX,
			    second);
	zassert_equal(na, nb);
	model_trace_hex(first, na, hex_a, sizeof(hex_a));
	model_trace_hex(second, nb, hex_b, sizeof(hex_b));
	zassert_str_equal(hex_a, hex_b, "same seed, different trace");

	nc = model_generate(&fake_vt, 0xC0FFEE1235ULL, MODEL_TRACE_MAX,
			    other);
	model_trace_hex(other, nc, hex_b, sizeof(hex_b));
	zassert_not_equal(strcmp(hex_a, hex_b), 0,
			  "adjacent seeds produced one trace");
	zassert_equal(model_seed_for(1U, 5U), model_seed_for(1U, 5U));
	zassert_not_equal(model_seed_for(1U, 5U), model_seed_for(2U, 5U));
}
