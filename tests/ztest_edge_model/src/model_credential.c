/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Abstract model of the credential cache's revocation semantics
 * (edge_credential_cache.c). The model is one set: ids that were
 * successfully revoked. Revocation is terminal: nothing that happens
 * afterwards (more puts, expiry ticks, time passing, slot pressure from
 * other credentials) may make a revoked id usable again.
 *
 * Properties (violation codes):
 *   41 C1  authorize never succeeds for a revoked id
 *   42 C2  put over a revoked id never succeeds
 *   43 C3  a put of a different id never evicts revocation state: the
 *          revoked id still fails authorize and put afterwards (checked by
 *          C1/C2 on later ops, so slot reuse of revoked records is caught)
 *   44     an op returned something other than the specified result
 */

#include "model_modules.h"
#include "test_common.h"

#define CAPACITY 2U
#define IDS 3U

enum { C_AUTH = 41, C_PUT = 42, C_RESULT = 44 };

enum { OP_PUT, OP_REVOKE, OP_AUTH, OP_TICK, OP_WAIT };

static const uint8_t op_of[] = {
	OP_PUT, OP_PUT, OP_PUT, OP_REVOKE, OP_REVOKE,
	OP_AUTH, OP_AUTH, OP_TICK, OP_WAIT,
};

static const char *const cids[IDS] = { "c0", "c1", "c2" };

static struct pqcp_edge_credential_record store[CAPACITY];
static struct pqcp_edge_credential_cache cache;
static bool revoked[IDS];
static uint32_t revoked_count;
static uint64_t epoch;
static uint64_t now;

static void reset(void)
{
	memset(revoked, 0, sizeof(revoked));
	revoked_count = 0U;
	epoch = 1U;
	now = T0;
	zassert_equal(pqcp_edge_credential_cache_init(
		&cache, store, ARRAY_SIZE(store)), 0);
}

static int audit(void)
{
	return pqcp_edge_credential_cache_audit(&cache);
}

static void fill(struct pqcp_edge_credential_record *c, uint32_t i)
{
	memset(c, 0, sizeof(*c));
	SETSTR(c->credential_id, cids[i]);
	SETSTR(c->principal_id, "p1");
	SETSTR(c->issuer_domain, "dom-a");
	c->issuance_epoch = epoch;
	c->policy_epoch = 2U;
	c->revocation_epoch = 3U;
	c->issued_at_ms = now;
	c->refresh_at_ms = now + 500U;
	c->expires_at_ms = now + 1000U;
	c->capabilities = 0x3U;
	edge_digest(c->public_key_digest, 0x11U);
	edge_digest(c->credential_digest, 0x12U);
}

static int apply(const struct model_op *op)
{
	const uint32_t i = op->a % IDS;

	now += op->dt % 700U;
	switch (op_of[op->kind % ARRAY_SIZE(op_of)]) {
	case OP_PUT: {
		struct pqcp_edge_credential_record c;
		int rc;

		++epoch;
		fill(&c, i);
		rc = pqcp_edge_credential_put(&cache, &c, now);
		if (revoked[i]) {
			MODEL_REQUIRE(rc != 0, C_PUT);
		} else if (revoked_count >= CAPACITY) {
			/* C3: every slot holds a tombstone; none is recycled. */
			MODEL_REQUIRE(rc != 0, C_PUT);
		}
		break;
	}
	case OP_REVOKE:
		if (pqcp_edge_credential_revoke(&cache, cids[i], 3U) == 0 &&
		    !revoked[i]) {
			revoked[i] = true;
			++revoked_count;
		}
		break;
	case OP_AUTH: {
		int rc = pqcp_edge_credential_authorize(
			&cache, cids[i], "p1", 0x1U, 2U, 1U, now);

		if (revoked[i]) {
			MODEL_REQUIRE(rc != 0, C_AUTH);
		}
		break;
	}
	case OP_TICK: {
		uint32_t changed = 0U;

		MODEL_REQUIRE(pqcp_edge_credential_tick(&cache, now,
							&changed) == 0,
			      C_RESULT);
		break;
	}
	default:
		break;
	}
	/* A revoked id must stay refused even after unrelated activity. */
	for (uint32_t k = 0U; k < IDS; ++k) {
		if (revoked[k]) {
			MODEL_REQUIRE(pqcp_edge_credential_authorize(
				&cache, cids[k], "p1", 0x1U, 2U, 1U, now) != 0,
				C_AUTH);
		}
	}
	return 0;
}

const struct model_vtable model_credential_vt = {
	.name = "credential",
	.op_kinds = ARRAY_SIZE(op_of),
	.reset = reset,
	.apply = apply,
	.audit = audit,
};
