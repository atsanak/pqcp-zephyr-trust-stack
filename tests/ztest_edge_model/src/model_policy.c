/*
 * SPDX-License-Identifier: MIT
 *
 * Abstract model of the policy distributor's epoch discipline
 * (edge_policy_distributor.c). The model keeps the history of epochs that
 * were ever active and the epoch of every bundle staged.
 *
 * Properties (violation codes):
 *   61 D1  the active epoch only changes by a successful promote (to the
 *          promoted bundle's epoch, strictly greater than before) or by a
 *          successful rollback (to an epoch that was active before and is
 *          not greater than the current one)
 *   62 D2  promoting a bundle whose epoch is not greater than the active
 *          epoch never succeeds (no rollback of policy via a stale bundle)
 *   63 D3  rolling back or retiring a bundle leaves every other bundle's
 *          content untouched (the harness audit catches digest breakage)
 *   64     an op returned something other than the specified result
 */

#include "model_modules.h"
#include "test_common.h"

#define BUNDLES 3U
#define ACKS 8U
#define KNOWN 16U

enum { D_EPOCH = 61, D_STALE = 62, D_ID = 63, D_RESULT = 64 };

enum { OP_STAGE, OP_ACK, OP_PROMOTE, OP_ROLLBACK, OP_WAIT };

static const uint8_t op_of[] = {
	OP_STAGE, OP_STAGE, OP_ACK, OP_ACK, OP_PROMOTE, OP_PROMOTE,
	OP_ROLLBACK, OP_WAIT,
};

static struct pqcp_edge_policy_bundle bstore[BUNDLES];
static struct pqcp_edge_policy_ack astore[ACKS];
static struct pqcp_edge_policy_distributor pd;
static uint8_t base_digest[PQCP_EDGE_DIGEST_BYTES];

struct known {
	uint64_t id;
	uint64_t epoch;
	uint8_t seed;
};
static uint64_t staged_total;

static struct known known[KNOWN];
static uint32_t nknown;
static uint64_t history[KNOWN * 2U];
static uint32_t nhistory;
static uint64_t now;

static void reset(void)
{
	memset(known, 0, sizeof(known));
	nknown = 0U;
	staged_total = 0U;
	nhistory = 0U;
	history[nhistory++] = 1U;
	now = T0;
	edge_digest(base_digest, 0x01U);
	zassert_equal(pqcp_edge_policy_distributor_init(
		&pd, bstore, ARRAY_SIZE(bstore), astore, ARRAY_SIZE(astore),
		1U, base_digest), 0);
}

static int audit(void)
{
	return pqcp_edge_policy_distributor_audit(&pd);
}

static bool was_active(uint64_t e)
{
	for (uint32_t i = 0U; i < nhistory; ++i) {
		if (history[i] == e) {
			return true;
		}
	}
	return false;
}

static const struct known *pick(const struct model_op *op)
{
	return nknown == 0U ? NULL : &known[op->a % nknown];
}

static int apply(const struct model_op *op)
{
	const uint64_t before = pd.active_policy_epoch;
	const struct known *k = pick(op);
	int rc;

	now += op->dt % 500U;
	switch (op_of[op->kind % ARRAY_SIZE(op_of)]) {
	case OP_STAGE: {
		uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
		struct pqcp_edge_policy_bundle *b = NULL;
		const uint64_t e = 1U + (op->a % 6U);

		edge_digest(digest, (uint8_t)(0x40U + op->b));
		if (pqcp_edge_policy_stage(&pd, digest, e, now, now,
					   now + 100000U, 1U, 2U, &b) == 0 &&
		    b != NULL) {
			/* ID1: ids are issued 1, 2, 3, ... in staging order. */
			++staged_total;
			MODEL_REQUIRE(b->bundle_id == staged_total, D_ID);
			if (nknown < KNOWN) {
				known[nknown].id = b->bundle_id;
				known[nknown].epoch = b->policy_epoch;
				known[nknown].seed = (uint8_t)(0x40U + op->b);
				++nknown;
			}
		}
		break;
	}
	case OP_ACK:
		if (k != NULL) {
			uint8_t digest[PQCP_EDGE_DIGEST_BYTES];

			/* Acknowledge with the digest the bundle carries, so
			 * promotion can really reach ACTIVE.
			 */
			edge_digest(digest, k->seed);
			(void)pqcp_edge_policy_acknowledge(
				&pd, k->id, op->b % 2U ? "ack-a" : "ack-b",
				digest, 0, now);
		}
		break;
	case OP_PROMOTE:
		if (k == NULL) {
			break;
		}
		rc = pqcp_edge_policy_promote(&pd, k->id, now);
		if (k->epoch <= before) {
			MODEL_REQUIRE(rc != 0, D_STALE);
		}
		if (rc == 0) {
			/* Promotion is staged (STAGED, CANARY, PROMOTED,
			 * ACTIVE): a step either leaves the active epoch
			 * alone or makes this strictly newer bundle active.
			 */
			MODEL_REQUIRE(pd.active_policy_epoch == before ||
				      (pd.active_policy_epoch == k->epoch &&
				       k->epoch > before), D_EPOCH);
			if (pd.active_policy_epoch != before) {
				history[nhistory++ % ARRAY_SIZE(history)] =
					k->epoch;
			}
		}
		break;
	case OP_ROLLBACK:
		if (k == NULL) {
			break;
		}
		if (pqcp_edge_policy_rollback(&pd, k->id, now) == 0 &&
		    pd.active_policy_epoch != before) {
			MODEL_REQUIRE(pd.active_policy_epoch < before &&
				      was_active(pd.active_policy_epoch),
				      D_EPOCH);
		}
		break;
	default:
		break;
	}
	/* Active epoch changes are only legal through promote/rollback. */
	if (op_of[op->kind % ARRAY_SIZE(op_of)] != OP_PROMOTE &&
	    op_of[op->kind % ARRAY_SIZE(op_of)] != OP_ROLLBACK) {
		MODEL_REQUIRE(pd.active_policy_epoch == before, D_EPOCH);
	}
	return 0;
}

const struct model_vtable model_policy_vt = {
	.name = "policy",
	.op_kinds = ARRAY_SIZE(op_of),
	.reset = reset,
	.apply = apply,
	.audit = audit,
};
