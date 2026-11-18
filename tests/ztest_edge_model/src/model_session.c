/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Abstract model of the session registry's slot and quota accounting
 * (edge_session_registry.c) together with the principal directory it
 * charges.
 *
 * The model is a ledger: every session ever opened, whether it is still
 * live (not yet closed), and per principal how many are live. A session
 * holds a registry slot and a principal quota unit from a successful open
 * until its single successful close, and nothing else changes that.
 * Expiry, failures and rekeys alter a session's lifecycle state but never
 * its ledger entry.
 *
 * Properties (violation codes):
 *   21 S1  the directory's active_sessions equals the ledger's live count
 *          after every op, and the registry holds exactly one unreleased
 *          slot per live session
 *   22 S2  an open succeeds exactly when the principal is active, under
 *          its quota and the registry has fewer live sessions than slots,
 *          so slots of closed sessions must be reusable and never leak
 *   23 S3  closing an already closed session never succeeds and never
 *          changes any count
 *   24 ID1 the n-th successful open issues session id n (first id is 1)
 *   25 an op returned something other than the specified result
 */

#include "model_modules.h"
#include "test_common.h"

#define SLOTS 3U
#define PRINCIPALS 2U
#define QUOTA 2U
#define LIFETIME_MS 100000U

enum {
	S_COUNTS = 21,
	S_OPEN = 22,
	S_DOUBLE_CLOSE = 23,
	S_ID = 24,
	S_RESULT = 25,
};

enum {
	OP_OPEN,
	OP_CLOSE,
	OP_DEGRADE,
	OP_ACTIVATE,
	OP_ACCOUNT,
	OP_TICK,
};

/* Opens and closes dominate: slot pressure is where the defects live. */
static const uint8_t op_of[] = {
	OP_OPEN, OP_OPEN, OP_OPEN, OP_OPEN,
	OP_CLOSE, OP_CLOSE, OP_CLOSE, OP_CLOSE,
	OP_DEGRADE, OP_ACTIVATE, OP_ACCOUNT, OP_TICK,
};

static const char *const ids[PRINCIPALS] = { "sa", "sb" };

struct ledger_entry {
	uint64_t id;
	uint8_t principal;
	bool live;
};

static struct pqcp_edge_principal pstore[PRINCIPALS];
static struct pqcp_edge_principal_directory dir;
static struct pqcp_edge_session sstore[SLOTS];
static struct pqcp_edge_session_registry reg;
static uint8_t binding[PQCP_EDGE_DIGEST_BYTES];

static struct ledger_entry ledger[MODEL_TRACE_MAX];
static uint32_t issued;
static uint32_t live[PRINCIPALS];
static bool active[PRINCIPALS];
static uint32_t live_total;
static uint64_t next_id;
static uint64_t now;

static void reset(void)
{
	memset(ledger, 0, sizeof(ledger));
	memset(live, 0, sizeof(live));
	issued = 0U;
	live_total = 0U;
	next_id = 1U;
	now = T0;
	zassert_equal(pqcp_edge_principal_directory_init(
		&dir, pstore, ARRAY_SIZE(pstore)), 0);
	for (uint32_t i = 0U; i < PRINCIPALS; ++i) {
		struct pqcp_edge_principal p;

		edge_make_principal(&p, ids[i], CAP_ALL,
				    PQCP_EDGE_TRUST_ATTESTED,
				    T0 + 100000000ULL);
		p.maximum_sessions = QUOTA;
		zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), 0);
		active[i] = true;
	}
	zassert_equal(pqcp_edge_session_registry_init(
		&reg, sstore, ARRAY_SIZE(sstore)), 0);
	edge_digest(binding, 0x33U);
}

static int audit(void)
{
	int rc = pqcp_edge_session_registry_audit(&reg);

	return rc != 0 ? rc : pqcp_edge_principal_audit(&dir);
}

static struct pqcp_edge_route make_route(const char *principal_id)
{
	struct pqcp_edge_route r;

	memset(&r, 0, sizeof(r));
	r.schema_version = PQCP_EDGE_SCHEMA_VERSION;
	r.route_id = 1U;
	SETSTR(r.source_principal_id, principal_id);
	SETSTR(r.service_id, "svc");
	SETSTR(r.endpoint_id, "ep");
	SETSTR(r.source_zone, "zone-a");
	SETSTR(r.destination_zone, "zone-a");
	r.expires_at_ms = now + 1000000000ULL;
	r.occupied = true;
	return r;
}

static int check_counts(void)
{
	uint32_t unreleased = 0U;

	for (uint32_t i = 0U; i < PRINCIPALS; ++i) {
		struct pqcp_edge_principal *p = NULL;

		MODEL_REQUIRE(pqcp_edge_principal_find(&dir, ids[i], &p) ==
			      0 && p != NULL, S_RESULT);
		MODEL_REQUIRE(p->active_sessions == live[i], S_COUNTS);
	}
	for (uint32_t i = 0U; i < SLOTS; ++i) {
		if (sstore[i].occupied && !sstore[i].principal_released) {
			++unreleased;
		}
	}
	MODEL_REQUIRE(unreleased == live_total, S_COUNTS);
	return 0;
}

/* A session id the op names: an issued one, or an unknown one. */
static uint64_t target(const struct model_op *op, struct ledger_entry **entry)
{
	*entry = NULL;
	if (issued == 0U || (op->b & 0x80U) != 0U) {
		return 1000U + op->a;
	}
	*entry = &ledger[op->a % issued];
	return (*entry)->id;
}

static int apply(const struct model_op *op)
{
	now += op->dt;

	switch (op_of[op->kind % ARRAY_SIZE(op_of)]) {
	case OP_OPEN: {
		const uint32_t p = op->a % PRINCIPALS;
		struct pqcp_edge_route route = make_route(ids[p]);
		struct pqcp_edge_session *s = NULL;
		const int rc = pqcp_edge_session_open(
			&reg, &dir, &route, binding, true, now,
			LIFETIME_MS, &s);

		if (!active[p]) {
			/* A refused principal reports -EACCES, or -EDQUOT
			 * when it is also at quota; never success.
			 */
			MODEL_REQUIRE(rc == -EACCES || rc == -EDQUOT,
				      S_OPEN);
		} else if (live[p] >= QUOTA) {
			MODEL_REQUIRE(rc == -EDQUOT, S_OPEN);
		} else if (live_total >= SLOTS) {
			MODEL_REQUIRE(rc == -ENOSPC, S_OPEN);
		} else {
			MODEL_REQUIRE(rc == 0 && s != NULL, S_OPEN);
			MODEL_REQUIRE(s->session_id == next_id, S_ID);
			ledger[issued].id = next_id;
			ledger[issued].principal = (uint8_t)p;
			ledger[issued].live = true;
			++issued;
			++next_id;
			++live[p];
			++live_total;
		}
		break;
	}
	case OP_CLOSE: {
		struct ledger_entry *e;
		const uint64_t id = target(op, &e);
		const int result = (op->b & 1U) != 0U ? -EIO : 0;
		const int rc = pqcp_edge_session_close(&reg, &dir, id,
							result, now);

		if (e == NULL) {
			MODEL_REQUIRE(rc == -ENOENT, S_RESULT);
		} else if (e->live) {
			MODEL_REQUIRE(rc == 0, S_RESULT);
			e->live = false;
			--live[e->principal];
			--live_total;
		} else {
			/* Closed already: -EALREADY while its slot still
			 * remembers it, -ENOENT once the slot was reused.
			 */
			MODEL_REQUIRE(rc == -EALREADY || rc == -ENOENT,
				      S_DOUBLE_CLOSE);
		}
		break;
	}
	case OP_DEGRADE:
	case OP_ACTIVATE: {
		const uint32_t p = op->a % PRINCIPALS;
		const bool up = op_of[op->kind % ARRAY_SIZE(op_of)] ==
				OP_ACTIVATE;

		MODEL_REQUIRE(pqcp_edge_principal_observe(
			&dir, ids[p], up ? 0U : 700U,
			PQCP_EDGE_TRUST_AUTHENTICATED, true, now) == 0,
			S_RESULT);
		active[p] = up;
		break;
	}
	case OP_ACCOUNT: {
		struct ledger_entry *e;
		const uint64_t id = target(op, &e);

		/* Failure accounting may push a session to FAILED but must
		 * never release its slot or quota: only close does.
		 */
		(void)pqcp_edge_session_account(&reg, id, 10U, 10U, false,
						now);
		break;
	}
	default: {
		uint32_t changed = 0U;

		MODEL_REQUIRE(pqcp_edge_session_tick(&reg, now, &changed) ==
			      0, S_RESULT);
		break;
	}
	}
	return check_counts();
}

const struct model_vtable model_session_vt = {
	.name = "session",
	.op_kinds = ARRAY_SIZE(op_of),
	.reset = reset,
	.apply = apply,
	.audit = audit,
};
