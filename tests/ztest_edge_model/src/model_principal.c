/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Abstract model of the principal directory's quarantine and revocation
 * lifecycle (edge_identity_directory.c).
 *
 * The model tracks only what the specification promises per principal:
 * whether it is registered, whether it has been revoked (permanent), and
 * whether a quarantine is in force. A quarantine is IN FORCE while it was
 * imposed and its deadline (0 = indefinite) has not passed; being in force
 * is a function of time alone. Everything the module does to a principal
 * under quarantine, whatever the op, must preserve that.
 *
 * Properties (violation codes):
 *   11 P1  observe on an in-force quarantine is refused with -EACCES and
 *          changes nothing, whatever the credential expiry says
 *   12 P2  re-registration never changes state, deadline or risk of an
 *          in-force quarantine
 *   13 P3  tick never moves an in-force quarantine out of QUARANTINED
 *   14 P4  a revoked principal never becomes anything but REVOKED, and
 *          every op that would resurrect it is refused
 *   15 an op returned something other than the specified result
 *   16 the directory disagrees with the model about a principal
 */

#include <limits.h>

#include "model_modules.h"
#include "test_common.h"

#define PIDS 3U

enum {
	P_OBSERVE_HELD = 11,
	P_REREGISTER = 12,
	P_TICK = 13,
	P_REVOKED = 14,
	P_RESULT = 15,
	P_STATE = 16,
};

enum {
	OP_REGISTER,
	OP_REREGISTER,
	OP_OBSERVE,
	OP_QUARANTINE,
	OP_RELEASE,
	OP_REVOKE,
	OP_TICK,
	OP_ADVANCE,
	OP_KINDS,
};

static const char *const ids[PIDS] = { "xa", "yb", "zc" };

struct principal_model {
	bool registered;
	bool revoked;
	bool quarantined;
	uint64_t until;
	uint64_t expires;
	uint64_t revocation_epoch;
	uint32_t epoch;
};

struct principal_snapshot {
	bool held;
	enum pqcp_edge_principal_state state;
	uint64_t until;
	uint32_t risk;
};

static struct pqcp_edge_principal store[4];
static struct pqcp_edge_principal_directory dir;
static struct principal_model model[PIDS];
static uint64_t now;

static bool held(uint32_t i)
{
	return model[i].registered && !model[i].revoked &&
	       model[i].quarantined &&
	       (model[i].until == 0U || now < model[i].until);
}

static void reset(void)
{
	memset(model, 0, sizeof(model));
	now = T0;
	zassert_equal(pqcp_edge_principal_directory_init(
		&dir, store, ARRAY_SIZE(store)), 0);
}

static int audit(void)
{
	return pqcp_edge_principal_audit(&dir);
}

/*
 * Whole-directory invariants after every op. `code` names the property the
 * current op is responsible for when an in-force quarantine is disturbed.
 */
static int check_all(const struct principal_snapshot *before,
		     int exempt, int code)
{
	for (uint32_t i = 0U; i < PIDS; ++i) {
		struct pqcp_edge_principal *p = NULL;
		const int rc = pqcp_edge_principal_find(&dir, ids[i], &p);

		if (!model[i].registered) {
			MODEL_REQUIRE(rc == -ENOENT, P_STATE);
			continue;
		}
		MODEL_REQUIRE(rc == 0 && p != NULL, P_STATE);
		MODEL_REQUIRE(p->credential_expires_at_ms ==
			      model[i].expires, P_STATE);
		if (model[i].revoked) {
			MODEL_REQUIRE(p->state ==
				      PQCP_EDGE_PRINCIPAL_REVOKED,
				      P_REVOKED);
			continue;
		}
		MODEL_REQUIRE(p->state != PQCP_EDGE_PRINCIPAL_REVOKED,
			      P_STATE);
		if (held(i)) {
			MODEL_REQUIRE(p->state ==
				      PQCP_EDGE_PRINCIPAL_QUARANTINED &&
				      p->quarantine_until_ms ==
				      model[i].until, code);
		}
		if (before[i].held && (int)i != exempt) {
			MODEL_REQUIRE(p->state == before[i].state &&
				      p->quarantine_until_ms ==
				      before[i].until &&
				      p->risk_score == before[i].risk,
				      code);
		}
	}
	return 0;
}

static int apply(const struct model_op *op)
{
	const uint32_t i = op->a % PIDS;
	struct principal_model *pm = &model[i];
	struct principal_snapshot before[PIDS];
	int exempt = -1;
	int check_code = P_STATE;
	int rc;

	now += op->dt;
	for (uint32_t k = 0U; k < PIDS; ++k) {
		struct pqcp_edge_principal *p = NULL;

		before[k].held = held(k);
		if (before[k].held &&
		    pqcp_edge_principal_find(&dir, ids[k], &p) == 0) {
			before[k].state = p->state;
			before[k].until = p->quarantine_until_ms;
			before[k].risk = p->risk_score;
		}
	}

	switch (op->kind % OP_KINDS) {
	case OP_REGISTER:
	case OP_REREGISTER: {
		struct pqcp_edge_principal p;
		const uint32_t epoch = pm->registered ?
			pm->epoch + (op->kind % OP_KINDS == OP_REREGISTER) :
			1U;
		const uint64_t base =
			pm->registered && pm->expires > now ?
			pm->expires : now;
		const uint64_t expires =
			base + 300U + (uint64_t)(op->b % 16U) * 200U;

		edge_make_principal(&p, ids[i], CAP_ALL,
				    (op->b >> 4) & 1U ?
				    PQCP_EDGE_TRUST_ATTESTED :
				    PQCP_EDGE_TRUST_AUTHENTICATED,
				    expires);
		p.credential_epoch = epoch;
		rc = pqcp_edge_principal_register(&dir, &p, now);
		if (pm->revoked) {
			MODEL_REQUIRE(rc == -EKEYREJECTED, P_REVOKED);
		} else {
			MODEL_REQUIRE(rc == 0, P_RESULT);
			pm->registered = true;
			pm->expires = expires;
			pm->epoch = epoch;
		}
		check_code = P_REREGISTER;
		break;
	}
	case OP_OBSERVE: {
		static const uint32_t risks[4] = { 0U, 400U, 650U, 950U };
		const uint32_t risk = risks[op->b % 4U];
		const bool was_held = held(i);

		rc = pqcp_edge_principal_observe(
			&dir, ids[i], risk, PQCP_EDGE_TRUST_AUTHENTICATED,
			true, now);
		if (!pm->registered) {
			MODEL_REQUIRE(rc == -ENOENT, P_RESULT);
		} else if (pm->revoked) {
			MODEL_REQUIRE(rc == -EKEYREVOKED, P_REVOKED);
		} else if (was_held) {
			MODEL_REQUIRE(rc == -EACCES, P_OBSERVE_HELD);
		} else if (pm->expires <= now) {
			MODEL_REQUIRE(rc == -EKEYEXPIRED, P_RESULT);
			pm->quarantined = false;
		} else if (risk >= 900U) {
			MODEL_REQUIRE(rc == -EACCES, P_RESULT);
			pm->quarantined = true;
			pm->until = UINT64_MAX;
		} else {
			MODEL_REQUIRE(rc == 0, P_RESULT);
			pm->quarantined = false;
		}
		check_code = P_OBSERVE_HELD;
		break;
	}
	case OP_QUARANTINE: {
		uint64_t until;

		switch (op->b % 5U) {
		case 0:
			until = 0U;
			break;
		case 1:
			until = now + 50U + (uint64_t)(op->b >> 3) * 10U;
			break;
		case 2:
			until = UINT64_MAX;
			break;
		case 3:
			until = now;
			break;
		default:
			until = now + 1000U;
			break;
		}
		rc = pqcp_edge_principal_quarantine(&dir, ids[i], until);
		if (!pm->registered) {
			MODEL_REQUIRE(rc == -ENOENT, P_RESULT);
		} else if (pm->revoked) {
			MODEL_REQUIRE(rc == -EKEYREVOKED, P_REVOKED);
		} else {
			MODEL_REQUIRE(rc == 0, P_RESULT);
			pm->quarantined = true;
			pm->until = until;
		}
		exempt = (int)i;
		break;
	}
	case OP_RELEASE:
		rc = pqcp_edge_principal_release(&dir, ids[i], now);
		if (!pm->registered) {
			MODEL_REQUIRE(rc == -ENOENT, P_RESULT);
		} else if (pm->revoked) {
			MODEL_REQUIRE(rc == -EKEYREVOKED, P_REVOKED);
		} else if (!pm->quarantined) {
			MODEL_REQUIRE(rc == -EALREADY, P_RESULT);
		} else if (pm->expires <= now) {
			MODEL_REQUIRE(rc == -EKEYEXPIRED, P_RESULT);
		} else {
			MODEL_REQUIRE(rc == 0, P_RESULT);
			pm->quarantined = false;
		}
		exempt = (int)i;
		break;
	case OP_REVOKE: {
		const bool stale = pm->revocation_epoch > 0U &&
				   (op->b & 1U) != 0U;
		const uint64_t epoch = stale ? pm->revocation_epoch :
					       pm->revocation_epoch + 1U;

		rc = pqcp_edge_principal_revoke(&dir, ids[i], epoch, now);
		if (!pm->registered) {
			MODEL_REQUIRE(rc == -ENOENT, P_RESULT);
		} else if (stale) {
			MODEL_REQUIRE(rc == -ESTALE, P_RESULT);
		} else {
			MODEL_REQUIRE(rc == 0, P_RESULT);
			pm->revoked = true;
			pm->revocation_epoch = epoch;
		}
		exempt = (int)i;
		break;
	}
	case OP_TICK: {
		uint32_t changed = 0U;

		MODEL_REQUIRE(pqcp_edge_principal_tick(&dir, now,
						       &changed) == 0,
			      P_RESULT);
		for (uint32_t k = 0U; k < PIDS; ++k) {
			/* A finite deadline that has passed ends the
			 * quarantine; indefinite ones never lapse.
			 */
			if (model[k].registered && !model[k].revoked &&
			    model[k].quarantined &&
			    model[k].until != 0U &&
			    model[k].until != UINT64_MAX &&
			    now >= model[k].until) {
				model[k].quarantined = false;
			}
		}
		check_code = P_TICK;
		break;
	}
	default:
		break;
	}

	return check_all(before, exempt, check_code);
}

const struct model_vtable model_principal_vt = {
	.name = "principal",
	.op_kinds = OP_KINDS,
	.reset = reset,
	.apply = apply,
	.audit = audit,
};
