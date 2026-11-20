/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Seeded trace generation, replay, delta-debugging shrinker and marker
 * output for the edge model checks. See model_harness.h for the grammar.
 */

#include <string.h>

#include <zephyr/sys/printk.h>

#include "model_harness.h"

const char *model_fail_check = "";
int model_fail_line;

#define MODEL_SEED_BASE 0x5051435046454D31ULL

static uint64_t splitmix64(uint64_t x)
{
	x += 0x9E3779B97F4A7C15ULL;
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
	x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
	return x ^ (x >> 31);
}

/* xorshift64*: tiny, fast and fully determined by its 64-bit state. */
static uint64_t xorshift_next(uint64_t *state)
{
	uint64_t x = *state;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*state = x;
	return x * 0x2545F4914F6CDD1DULL;
}

uint64_t model_seed_for(uint32_t module_index, uint32_t index)
{
	return splitmix64(MODEL_SEED_BASE ^
			  ((uint64_t)module_index << 32) ^ index);
}

uint32_t model_generate(const struct model_vtable *vt, uint64_t seed,
			uint32_t max_len, struct model_op *trace)
{
	uint64_t state = seed != 0U ? seed : 0x9E3779B97F4A7C15ULL;
	uint32_t length;

	if (max_len > MODEL_TRACE_MAX) {
		max_len = MODEL_TRACE_MAX;
	}
	length = max_len - (uint32_t)(xorshift_next(&state) %
				      (max_len / 2U + 1U));
	for (uint32_t i = 0U; i < length; ++i) {
		const uint64_t r = xorshift_next(&state);
		const uint64_t t = xorshift_next(&state);
		const uint32_t pick = (uint32_t)(t & 0xFFU);

		trace[i].kind = (uint8_t)((r >> 8) % vt->op_kinds);
		trace[i].a = (uint8_t)(r >> 16);
		trace[i].b = (uint8_t)(r >> 24);
		/* Half the ops add no time, so races between two ops at
		 * one instant are exercised; a few jump by seconds.
		 */
		if (pick < 128U) {
			trace[i].dt = 0U;
		} else if (pick < 205U) {
			trace[i].dt = (uint32_t)((t >> 8) % 60U);
		} else {
			trace[i].dt = (uint32_t)((t >> 8) % 4000U);
		}
	}
	return length;
}

int model_run_trace(const struct model_vtable *vt,
		    const struct model_op *trace, uint32_t n,
		    uint32_t *applied)
{
	int code = 0;
	uint32_t done = 0U;

	vt->reset();
	for (uint32_t i = 0U; i < n && code == 0; ++i) {
		code = vt->apply(&trace[i]);
		++done;
		if (code == 0 && vt->audit != NULL &&
		    vt->audit() != 0) {
			model_fail_check = "module audit";
			model_fail_line = 0;
			code = MODEL_VIOLATION_AUDIT;
		}
	}
	if (applied != NULL) {
		*applied = done;
	}
	return code;
}

uint32_t model_shrink(const struct model_vtable *vt,
		      struct model_op *trace, uint32_t n, int code)
{
	struct model_op candidate[MODEL_TRACE_MAX];
	uint32_t applied = 0U;
	uint32_t chunk;

	if (model_run_trace(vt, trace, n, &applied) != code) {
		return n;
	}
	/* Nothing after the first violating op can matter. */
	n = applied;
	chunk = n / 2U != 0U ? n / 2U : 1U;
	while (n > 1U) {
		bool progressed = false;
		uint32_t start = 0U;

		while (start < n) {
			const uint32_t len = (n - start < chunk) ?
					     n - start : chunk;
			uint32_t m = 0U;

			for (uint32_t i = 0U; i < n; ++i) {
				if (i < start || i >= start + len) {
					candidate[m++] = trace[i];
				}
			}
			if (m > 0U &&
			    model_run_trace(vt, candidate, m,
					    &applied) == code) {
				memcpy(trace, candidate,
				       m * sizeof(trace[0]));
				n = m;
				progressed = true;
			} else {
				start += len;
			}
		}
		if (!progressed) {
			if (chunk == 1U) {
				break;
			}
			chunk /= 2U;
		} else if (chunk > n) {
			chunk = n;
		}
	}
	return n;
}

void model_trace_hex(const struct model_op *trace, uint32_t n, char *out,
		     size_t capacity)
{
	static const char digits[] = "0123456789abcdef";
	size_t pos = 0U;

	for (uint32_t i = 0U; i < n && pos + MODEL_HEX_PER_OP + 1U <=
				     capacity; ++i) {
		const uint8_t bytes[7] = {
			trace[i].kind, trace[i].a, trace[i].b,
			(uint8_t)trace[i].dt,
			(uint8_t)(trace[i].dt >> 8),
			(uint8_t)(trace[i].dt >> 16),
			(uint8_t)(trace[i].dt >> 24),
		};

		for (size_t j = 0U; j < sizeof(bytes); ++j) {
			out[pos++] = digits[bytes[j] >> 4];
			out[pos++] = digits[bytes[j] & 0xFU];
		}
	}
	if (capacity > 0U) {
		out[pos] = '\0';
	}
}

uint32_t model_check(const struct model_vtable *vt, uint32_t module_index,
		     uint32_t seeds, bool emit, struct model_stats *stats)
{
	struct model_stats local = { 0 };
	uint32_t printed = 0U;

	for (uint32_t i = 0U; i < seeds; ++i) {
		struct model_op trace[MODEL_TRACE_MAX];
		const uint64_t seed = model_seed_for(module_index, i);
		const uint32_t length = model_generate(
			vt, seed, MODEL_TRACE_MAX, trace);
		uint32_t applied = 0U;
		const int code = model_run_trace(vt, trace, length,
						 &applied);

		++local.seeds;
		local.ops += applied;
		if (code == 0) {
			continue;
		}
		++local.violations;
		if (emit && printed < MODEL_MAX_COUNTEREXAMPLES) {
			char hex[MODEL_TRACE_MAX * MODEL_HEX_PER_OP + 1U];
			const uint32_t shrunk =
				model_shrink(vt, trace, length, code);

			model_trace_hex(trace, shrunk, hex, sizeof(hex));
			model_fail_check = "";
			model_fail_line = 0;
			(void)model_run_trace(vt, trace, shrunk, NULL);
			printk("PQCP_MODEL_COUNTEREXAMPLE module=%s "
			       "seed=%08x%08x violation=%d ops=%u "
			       "trace=%s\n",
			       vt->name, (uint32_t)(seed >> 32),
			       (uint32_t)seed, code, shrunk, hex);
			printk("PQCP_MODEL_NOTE module=%s line=%d check=%s\n",
			       vt->name, model_fail_line, model_fail_check);
			++printed;
		}
	}
	if (emit) {
		printk("PQCP_MODEL_CHECK module=%s seeds=%u ops=%u "
		       "violations=%u status=%s\n",
		       vt->name, local.seeds, local.ops, local.violations,
		       local.violations == 0U ? "PASS" : "FAIL");
	}
	if (stats != NULL) {
		*stats = local;
	}
	return local.violations;
}
