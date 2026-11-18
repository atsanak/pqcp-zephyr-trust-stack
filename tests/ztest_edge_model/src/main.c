/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Suite entry point: one test per modelled module plus the harness
 * controls. The suite teardown prints the final PQCP_MODEL_SUMMARY marker
 * once every module has run, whether or not it conformed.
 */

#include <psa/crypto.h>

#include <zephyr/sys/printk.h>

#include "model_modules.h"
#include "test_common.h"

struct model_totals {
	uint32_t modules;
	uint32_t traces;
	uint32_t ops;
	uint32_t violations;
};

static struct model_totals totals;

static void *suite_setup(void)
{
	zassert_equal(psa_crypto_init(), PSA_SUCCESS);
	return NULL;
}

static void suite_teardown(void *fixture)
{
	ARG_UNUSED(fixture);
	if (totals.modules != MODEL_MODULE_COUNT) {
		return;
	}
	printk("PQCP_MODEL_SUMMARY modules=%u traces=%u ops=%u "
	       "violations=%u status=%s\n",
	       totals.modules, totals.traces, totals.ops,
	       totals.violations,
	       totals.violations == 0U ? "PASS" : "FAIL");
}

ZTEST_SUITE(edge_model, NULL, suite_setup, NULL, NULL, suite_teardown);

/*
 * Run one module for MODEL_SEEDS traces, fail the case on any violation,
 * and require a second run to be bit-for-bit identical (determinism: the
 * same seeds drive the same traces to the same outcome).
 */
void model_run_module(const struct model_vtable *vt, uint32_t index)
{
	struct model_stats first;
	struct model_stats second;
	uint32_t violations;

	violations = model_check(vt, index, MODEL_SEEDS, true, &first);
	++totals.modules;
	totals.traces += first.seeds;
	totals.ops += first.ops;
	totals.violations += violations;
	zassert_equal(violations, 0U,
		      "model %s: %u violating trace(s)", vt->name,
		      violations);
	zassert_equal(model_check(vt, index, MODEL_SEEDS, false, &second),
		      0U);
	zassert_equal(second.ops, first.ops);
}

ZTEST(edge_model, test_principal_model)
{
	model_run_module(&model_principal_vt, MODEL_INDEX_PRINCIPAL);
}

ZTEST(edge_model, test_session_model)
{
	model_run_module(&model_session_vt, MODEL_INDEX_SESSION);
}
