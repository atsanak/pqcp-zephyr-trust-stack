/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Identity, service registry, access policy, routing, sessions, traffic
 * governance and circuit breaking.
 */

#include "edge_security_internal.h"
#include "test_common.h"

/* ------------------------------------------------------------------ */
/* Principal directory                                                 */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_principal pstore[3];
static struct pqcp_edge_principal_directory dir;

static void dir_setup(void)
{
	zassert_equal(pqcp_edge_principal_directory_init(
		&dir, pstore, ARRAY_SIZE(pstore)), 0);
}

static struct pqcp_edge_principal *reg(
	const char *id, uint64_t caps,
	enum pqcp_edge_trust_level trust, uint64_t expires)
{
	struct pqcp_edge_principal p;
	struct pqcp_edge_principal *found = NULL;

	edge_make_principal(&p, id, caps, trust, expires);
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), 0);
	zassert_equal(pqcp_edge_principal_find(&dir, id, &found), 0);
	return found;
}

ZTEST(edge_security, test_principal_rejects_invalid_arguments)
{
	static struct pqcp_edge_principal_directory raw;
	struct pqcp_edge_principal p;
	struct pqcp_edge_principal *out = NULL;
	uint32_t changed = 0U;

	zassert_equal(pqcp_edge_principal_directory_init(
		NULL, pstore, 3U), -EINVAL);
	zassert_equal(pqcp_edge_principal_directory_init(
		&dir, NULL, 3U), -EINVAL);
	zassert_equal(pqcp_edge_principal_directory_init(
		&dir, pstore, 0U), -EINVAL);

	/* Every operation fails closed on an uninitialised directory. */
	memset(&raw, 0, sizeof(raw));
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 9999U);
	zassert_equal(pqcp_edge_principal_register(&raw, &p, T0), -EINVAL);
	zassert_equal(pqcp_edge_principal_observe(&raw, "p1", 0U,
		PQCP_EDGE_TRUST_OBSERVED, false, T0), -EINVAL);
	zassert_equal(pqcp_edge_principal_quarantine(&raw, "p1", 5U),
		      -EINVAL);
	zassert_equal(pqcp_edge_principal_release(&raw, "p1", T0), -EINVAL);
	zassert_equal(pqcp_edge_principal_revoke(&raw, "p1", 2U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_principal_find(&raw, "p1", &out), -EINVAL);
	zassert_equal(pqcp_edge_principal_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_principal_audit(&raw), -EINVAL);
	zassert_equal(pqcp_edge_principal_audit(NULL), -EINVAL);

	dir_setup();
	zassert_equal(pqcp_edge_principal_register(&dir, NULL, T0), -EINVAL);

	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 9999U);
	p.principal_id[0] = '\0';
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -EINVAL);
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 9999U);
	memset(p.identity_digest, 0, sizeof(p.identity_digest));
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -EINVAL);
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 9999U);
	p.maximum_sessions = 0U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -EINVAL);
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, T0);
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -EINVAL);
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 9999U);
	p.credential_epoch = 0U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -EINVAL);
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 9999U);
	p.policy_epoch = 0U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -EINVAL);
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 9999U);
	p.trust = (enum pqcp_edge_trust_level)99;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -EINVAL);
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 9999U);
	p.state = (enum pqcp_edge_principal_state)99;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -EINVAL);
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 9999U);
	memset(p.principal_id, 'x', sizeof(p.principal_id));
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -EINVAL);

	/* None of the rejections created an entry. */
	zassert_equal(pqcp_edge_principal_find(&dir, "p1", &out), -ENOENT);
	zassert_is_null(out);
	zassert_equal(dir.registration_count, 0U);

	zassert_equal(pqcp_edge_principal_observe(&dir, NULL, 0U,
		PQCP_EDGE_TRUST_OBSERVED, false, T0), -EINVAL);
	zassert_equal(pqcp_edge_principal_observe(&dir, "p1", 0U,
		(enum pqcp_edge_trust_level)77, false, T0), -EINVAL);
	zassert_equal(pqcp_edge_principal_observe(&dir, "ghost", 0U,
		PQCP_EDGE_TRUST_OBSERVED, false, T0), -ENOENT);
	zassert_equal(pqcp_edge_principal_quarantine(&dir, NULL, 5U),
		      -EINVAL);
	zassert_equal(pqcp_edge_principal_quarantine(&dir, "ghost", 5U),
		      -ENOENT);
	zassert_equal(pqcp_edge_principal_release(&dir, "ghost", T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_principal_revoke(&dir, "ghost", 0U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_principal_revoke(&dir, "ghost", 1U, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_principal_find(&dir, "p1", NULL), -EINVAL);
	zassert_equal(pqcp_edge_principal_tick(&dir, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_principal_audit(&dir), 0);
}

ZTEST(edge_security, test_principal_registration_normalizes_state)
{
	struct pqcp_edge_principal p;
	struct pqcp_edge_principal *found = NULL;
	uint32_t first_generation;

	dir_setup();
	edge_make_principal(&p, "p1", 3U, PQCP_EDGE_TRUST_UNTRUSTED, 50000U);
	p.state = PQCP_EDGE_PRINCIPAL_EMPTY;
	p.active_sessions = 3U;
	p.quarantine_until_ms = 99U;
	p.generation = 77U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), 0);
	zassert_equal(pqcp_edge_principal_find(&dir, "p1", &found), 0);
	zassert_equal(found->state, PQCP_EDGE_PRINCIPAL_ACTIVE);
	/* An unauthenticated caller can never self-assert elevated trust. */
	zassert_equal(found->trust, PQCP_EDGE_TRUST_AUTHENTICATED);
	zassert_true(found->generation != 0U);
	zassert_equal(found->active_sessions, 0U);
	zassert_equal(found->quarantine_until_ms, 0U);
	zassert_equal(found->registered_at_ms, T0);
	zassert_equal(found->schema_version, PQCP_EDGE_SCHEMA_VERSION);
	zassert_equal(dir.registration_count, 1U);

	first_generation = found->generation;
	found = reg("p2", 0U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	zassert_true(found->generation > first_generation);
	zassert_equal(found->trust, PQCP_EDGE_TRUST_ATTESTED);
	zassert_equal(pqcp_edge_principal_audit(&dir), 0);
}

ZTEST(edge_security, test_principal_reregistration_is_monotonic)
{
	struct pqcp_edge_principal p;
	struct pqcp_edge_principal before;
	struct pqcp_edge_principal *found;

	dir_setup();
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	p.credential_epoch = 2U;
	p.policy_epoch = 2U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), 0);
	zassert_equal(pqcp_edge_principal_find(&dir, "p1", &found), 0);
	before = *found;

	/* Epoch rollback is stale. */
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	p.credential_epoch = 1U;
	p.policy_epoch = 2U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0 + 5U),
		      -ESTALE);
	zassert_mem_equal(found, &before, sizeof(before));
	p.credential_epoch = 2U;
	p.policy_epoch = 1U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0 + 5U),
		      -ESTALE);
	zassert_mem_equal(found, &before, sizeof(before));

	/* Same epoch must not shorten credential lifetime. */
	p.policy_epoch = 2U;
	p.credential_expires_at_ms = 40000U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0 + 5U),
		      -EKEYEXPIRED);
	zassert_mem_equal(found, &before, sizeof(before));

	/* Immutable identity attributes cannot be rebound. */
	p.credential_expires_at_ms = 50000U;
	p.identity_digest[0] ^= 0xffU;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0 + 5U),
		      -EKEYREJECTED);
	zassert_mem_equal(found, &before, sizeof(before));
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	p.credential_epoch = 2U;
	p.policy_epoch = 2U;
	SETSTR(p.tenant_id, "tenant-b");
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0 + 5U),
		      -EKEYREJECTED);
	SETSTR(p.tenant_id, "tenant-a");
	SETSTR(p.trust_domain, "dom-b");
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0 + 5U),
		      -EKEYREJECTED);
	zassert_mem_equal(found, &before, sizeof(before));
	zassert_equal(dir.registration_count, 1U);
	zassert_equal(dir.rejection_count, 6U);

	/* A forward epoch preserves generation and registration time. */
	edge_make_principal(&p, "p1", 5U, PQCP_EDGE_TRUST_ATTESTED, 60000U);
	p.credential_epoch = 3U;
	p.policy_epoch = 2U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0 + 9U), 0);
	zassert_equal(found->generation, before.generation);
	zassert_equal(found->registered_at_ms, before.registered_at_ms);
	zassert_equal(found->last_seen_ms, T0 + 9U);
	zassert_equal(found->capabilities, 5U);
	zassert_equal(dir.registration_count, 2U);
	zassert_equal(pqcp_edge_principal_audit(&dir), 0);
}

ZTEST(edge_security, test_principal_capacity_exhaustion_keeps_entries)
{
	struct pqcp_edge_principal p;
	struct pqcp_edge_principal snapshot[3];
	struct pqcp_edge_principal *found;

	dir_setup();
	(void)reg("a", 1U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	(void)reg("b", 2U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	(void)reg("c", 3U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	memcpy(snapshot, pstore, sizeof(snapshot));

	edge_make_principal(&p, "d", 4U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), -ENOSPC);
	zassert_mem_equal(pstore, snapshot, sizeof(snapshot));
	zassert_equal(pqcp_edge_principal_find(&dir, "d", &found), -ENOENT);
	zassert_equal(dir.rejection_count, 1U);
	zassert_equal(pqcp_edge_principal_audit(&dir), 0);
}

ZTEST(edge_security, test_principal_observe_risk_ladder)
{
	struct pqcp_edge_principal *p;

	dir_setup();
	p = reg("p1", 0U, PQCP_EDGE_TRUST_AUTHENTICATED, 50000U);

	zassert_equal(pqcp_edge_principal_observe(&dir, "p1", 100U,
		PQCP_EDGE_TRUST_ATTESTED, true, T0 + 10U), 0);
	zassert_equal(p->state, PQCP_EDGE_PRINCIPAL_ACTIVE);
	zassert_equal(p->trust, PQCP_EDGE_TRUST_ATTESTED);
	zassert_equal(p->risk_score, 100U);
	zassert_equal(p->last_seen_ms, T0 + 10U);

	zassert_equal(pqcp_edge_principal_observe(&dir, "p1", 650U,
		PQCP_EDGE_TRUST_OBSERVED, true, T0 + 20U), 0);
	zassert_equal(p->state, PQCP_EDGE_PRINCIPAL_DEGRADED);
	zassert_equal(p->trust, PQCP_EDGE_TRUST_ATTESTED);

	zassert_equal(pqcp_edge_principal_observe(&dir, "p1", 800U,
		PQCP_EDGE_TRUST_OBSERVED, true, T0 + 30U), 0);
	zassert_equal(p->trust, PQCP_EDGE_TRUST_OBSERVED);

	/* Critical risk quarantines indefinitely and reports the denial. */
	zassert_equal(pqcp_edge_principal_observe(&dir, "p1", 950U,
		PQCP_EDGE_TRUST_ATTESTED, true, T0 + 40U), -EACCES);
	zassert_equal(p->state, PQCP_EDGE_PRINCIPAL_QUARANTINED);
	zassert_equal(p->quarantine_until_ms, UINT64_MAX);

	/* A quarantined principal cannot launder itself with a good report. */
	zassert_equal(pqcp_edge_principal_observe(&dir, "p1", 10U,
		PQCP_EDGE_TRUST_ATTESTED, true, T0 + 50U), -EACCES);
	zassert_equal(p->state, PQCP_EDGE_PRINCIPAL_QUARANTINED);
	zassert_equal(p->risk_score, 950U);
	zassert_equal(p->last_seen_ms, T0 + 40U);

	/* An operator release lands in DEGRADED with trust reset. */
	p->trust = PQCP_EDGE_TRUST_PRIVILEGED;
	zassert_equal(pqcp_edge_principal_release(&dir, "p1", T0 + 60U), 0);
	zassert_equal(p->state, PQCP_EDGE_PRINCIPAL_DEGRADED);
	zassert_equal(p->trust, PQCP_EDGE_TRUST_OBSERVED);
	zassert_equal(p->quarantine_until_ms, 0U);
	zassert_equal(pqcp_edge_principal_release(&dir, "p1", T0 + 61U),
		      -EALREADY);
}

ZTEST(edge_security, test_principal_expired_credential_degrades)
{
	struct pqcp_edge_principal *p;

	dir_setup();
	p = reg("p1", 0U, PQCP_EDGE_TRUST_ATTESTED, 2000U);
	zassert_equal(pqcp_edge_principal_observe(&dir, "p1", 0U,
		PQCP_EDGE_TRUST_ATTESTED, true, 3000U), -EKEYEXPIRED);
	zassert_equal(p->state, PQCP_EDGE_PRINCIPAL_DEGRADED);
	zassert_equal(p->trust, PQCP_EDGE_TRUST_OBSERVED);

	/* Quarantine cannot be released once the credential has lapsed. */
	zassert_equal(pqcp_edge_principal_quarantine(&dir, "p1", 9000U), 0);
	zassert_equal(pqcp_edge_principal_release(&dir, "p1", 3000U),
		      -EKEYEXPIRED);
	zassert_equal(p->state, PQCP_EDGE_PRINCIPAL_QUARANTINED);
}

ZTEST(edge_security, test_principal_revocation_is_terminal)
{
	struct pqcp_edge_principal p;
	struct pqcp_edge_principal *found;
	uint32_t changed = 99U;

	dir_setup();
	found = reg("p1", CAP_ALL, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	memset(found->attestation_digest, 0x5a,
	       sizeof(found->attestation_digest));

	zassert_equal(pqcp_edge_principal_revoke(&dir, "p1", 5U, T0 + 7U), 0);
	zassert_equal(found->state, PQCP_EDGE_PRINCIPAL_REVOKED);
	zassert_equal(found->capabilities, 0U);
	zassert_equal(found->trust, PQCP_EDGE_TRUST_UNTRUSTED);
	zassert_false(found->channel_bound);
	zassert_true(pqcp_edge_internal_all_zero(
		found->attestation_digest,
		sizeof(found->attestation_digest)));
	zassert_equal(found->revocation_epoch, 5U);
	zassert_equal(dir.revocation_count, 1U);

	/* Replayed or older revocation epochs are stale. */
	zassert_equal(pqcp_edge_principal_revoke(&dir, "p1", 5U, T0 + 8U),
		      -ESTALE);
	zassert_equal(pqcp_edge_principal_revoke(&dir, "p1", 4U, T0 + 8U),
		      -ESTALE);
	zassert_equal(dir.revocation_count, 1U);

	zassert_equal(pqcp_edge_principal_observe(&dir, "p1", 0U,
		PQCP_EDGE_TRUST_PRIVILEGED, true, T0 + 9U), -EKEYREVOKED);
	zassert_equal(pqcp_edge_principal_quarantine(&dir, "p1", 9U),
		      -EKEYREVOKED);
	zassert_equal(pqcp_edge_principal_release(&dir, "p1", T0 + 9U),
		      -EKEYREVOKED);
	zassert_equal(found->state, PQCP_EDGE_PRINCIPAL_REVOKED);

	/* Re-enrolment of a revoked identity is refused outright. */
	edge_make_principal(&p, "p1", CAP_ALL, PQCP_EDGE_TRUST_ATTESTED,
			    90000U);
	p.credential_epoch = 9U;
	p.policy_epoch = 9U;
	p.revocation_epoch = 9U;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0 + 10U),
		      -EKEYREJECTED);
	zassert_equal(found->state, PQCP_EDGE_PRINCIPAL_REVOKED);
	zassert_equal(pqcp_edge_principal_tick(&dir, 99999999U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(pqcp_edge_principal_audit(&dir), 0);

	/* Audit catches a revoked record that regained privilege. */
	found->capabilities = 1U;
	zassert_equal(pqcp_edge_principal_audit(&dir), -EKEYREJECTED);
}

ZTEST(edge_security, test_principal_tick_expires_and_releases)
{
	struct pqcp_edge_principal *p1;
	struct pqcp_edge_principal *p2;
	struct pqcp_edge_principal *p3;
	uint32_t changed = 0U;

	dir_setup();
	p1 = reg("p1", 0U, PQCP_EDGE_TRUST_ATTESTED, 2000U);
	p2 = reg("p2", 0U, PQCP_EDGE_TRUST_ATTESTED, 90000U);
	p3 = reg("p3", 0U, PQCP_EDGE_TRUST_ATTESTED, 90000U);
	zassert_equal(pqcp_edge_principal_quarantine(&dir, "p2", 3000U), 0);
	zassert_equal(pqcp_edge_principal_quarantine(&dir, "p3",
						     UINT64_MAX), 0);
	p1->channel_bound = true;

	zassert_equal(pqcp_edge_principal_tick(&dir, 2500U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(p1->state, PQCP_EDGE_PRINCIPAL_DEGRADED);
	zassert_equal(p1->trust, PQCP_EDGE_TRUST_OBSERVED);
	zassert_false(p1->channel_bound);
	zassert_equal(p2->state, PQCP_EDGE_PRINCIPAL_QUARANTINED);

	zassert_equal(pqcp_edge_principal_tick(&dir, 3500U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(p2->state, PQCP_EDGE_PRINCIPAL_DEGRADED);
	/* A permanent quarantine survives any amount of elapsed time. */
	zassert_equal(pqcp_edge_principal_tick(&dir, 80000U,
					       &changed), 0);
	zassert_equal(p3->state, PQCP_EDGE_PRINCIPAL_QUARANTINED);
}

ZTEST(edge_security, test_principal_audit_detects_corruption)
{
	struct pqcp_edge_principal *p;

	dir_setup();
	p = reg("p1", 0U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	zassert_equal(pqcp_edge_principal_audit(&dir), 0);

	p->active_sessions = p->maximum_sessions + 1U;
	zassert_equal(pqcp_edge_principal_audit(&dir), -EBADMSG);
	p->active_sessions = 0U;
	zassert_equal(pqcp_edge_principal_audit(&dir), 0);

	/* A duplicated identity in a second slot is detected. */
	pstore[1] = pstore[0];
	zassert_equal(pqcp_edge_principal_audit(&dir), -EEXIST);
	memset(&pstore[1], 0, sizeof(pstore[1]));

	p->schema_version = 99U;
	zassert_equal(pqcp_edge_principal_audit(&dir), -EBADMSG);
}

ZTEST(edge_security, test_principal_quarantine_survives_reregistration)
{
	struct pqcp_edge_principal p;
	struct pqcp_edge_principal *found;

	dir_setup();
	found = reg("p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 50000U);
	zassert_equal(pqcp_edge_principal_quarantine(&dir, "p1",
						     UINT64_MAX), 0);

	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 60000U);
	p.credential_epoch = 2U;
	(void)pqcp_edge_principal_register(&dir, &p, T0 + 5U);

	BUG_EXPECT(found->state == PQCP_EDGE_PRINCIPAL_QUARANTINED,
		   "edge_identity_directory.c pqcp_edge_principal_register: "
		   "re-registering a QUARANTINED principal with state=ACTIVE "
		   "overwrites the record and silently lifts the quarantine "
		   "(quarantine_until_ms and risk_score are taken from caller)");
	zassert_equal(found->state, PQCP_EDGE_PRINCIPAL_QUARANTINED);
}

ZTEST(edge_security, test_principal_quarantine_survives_credential_expiry)
{
	struct pqcp_edge_principal *p;
	uint32_t changed = 0U;

	dir_setup();
	p = reg("p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 2000U);
	zassert_equal(pqcp_edge_principal_quarantine(&dir, "p1",
						     UINT64_MAX), 0);
	zassert_equal(pqcp_edge_principal_tick(&dir, 3000U, &changed), 0);

	BUG_EXPECT(p->state == PQCP_EDGE_PRINCIPAL_QUARANTINED,
		   "edge_identity_directory.c pqcp_edge_principal_tick: a "
		   "permanently QUARANTINED principal whose credential "
		   "expires is demoted to DEGRADED, dropping the quarantine "
		   "(tick treats credential expiry before quarantine; the "
		   "same ordering exists in pqcp_edge_principal_observe)");
	zassert_equal(p->state, PQCP_EDGE_PRINCIPAL_QUARANTINED);
}

/* ------------------------------------------------------------------ */
/* Service registry                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_service sstore[2];
static struct pqcp_edge_endpoint estore[3];
static struct pqcp_edge_service_registry reg_svc;

static void svc_setup(void)
{
	zassert_equal(pqcp_edge_service_registry_init(
		&reg_svc, sstore, ARRAY_SIZE(sstore),
		estore, ARRAY_SIZE(estore)), 0);
}

static void add_service(const char *id, uint64_t lease)
{
	struct pqcp_edge_service s;

	edge_make_service(&s, id, lease);
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0), 0);
}

static void add_endpoint(const char *id, const char *service,
			 uint64_t lease)
{
	struct pqcp_edge_endpoint e;

	edge_make_endpoint(&e, id, service, lease);
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), 0);
}

ZTEST(edge_security, test_service_registry_rejects_invalid_arguments)
{
	static struct pqcp_edge_service_registry raw;
	struct pqcp_edge_service s;
	struct pqcp_edge_endpoint e;
	struct pqcp_edge_service *sp = NULL;
	struct pqcp_edge_endpoint *ep = NULL;
	uint32_t changed = 0U;

	zassert_equal(pqcp_edge_service_registry_init(
		NULL, sstore, 2U, estore, 3U), -EINVAL);
	zassert_equal(pqcp_edge_service_registry_init(
		&reg_svc, NULL, 2U, estore, 3U), -EINVAL);
	zassert_equal(pqcp_edge_service_registry_init(
		&reg_svc, sstore, 0U, estore, 3U), -EINVAL);
	zassert_equal(pqcp_edge_service_registry_init(
		&reg_svc, sstore, 2U, NULL, 3U), -EINVAL);
	zassert_equal(pqcp_edge_service_registry_init(
		&reg_svc, sstore, 2U, estore, 0U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	edge_make_service(&s, "s1", 9000U);
	edge_make_endpoint(&e, "e1", "s1", 9000U);
	zassert_equal(pqcp_edge_service_register(&raw, &s, T0), -EINVAL);
	zassert_equal(pqcp_edge_service_set_state(&raw, "s1",
		PQCP_EDGE_SERVICE_HEALTHY, T0), -EINVAL);
	zassert_equal(pqcp_edge_endpoint_register(&raw, &e, T0), -EINVAL);
	zassert_equal(pqcp_edge_endpoint_observe(&raw, "e1", true, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_endpoint_eject(&raw, "e1", 5U), -EINVAL);
	zassert_equal(pqcp_edge_endpoint_reserve(&raw, "e1"), -EINVAL);
	zassert_equal(pqcp_edge_endpoint_release(&raw, "e1"), -EINVAL);
	zassert_equal(pqcp_edge_service_find(&raw, "s1", &sp), -EINVAL);
	zassert_equal(pqcp_edge_endpoint_find(&raw, "e1", &ep), -EINVAL);
	zassert_equal(pqcp_edge_service_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_service_registry_audit(&raw), -EINVAL);

	svc_setup();
	zassert_equal(pqcp_edge_service_register(&reg_svc, NULL, T0),
		      -EINVAL);
	edge_make_service(&s, "s1", 9000U);
	s.service_id[0] = '\0';
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0), -EINVAL);
	edge_make_service(&s, "s1", 9000U);
	s.operation_mask = 0U;
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0), -EINVAL);
	edge_make_service(&s, "s1", 9000U);
	s.minimum_trust = 99U;
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0), -EINVAL);
	edge_make_service(&s, "s1", T0);
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0), -EINVAL);
	edge_make_service(&s, "s1", 9000U);
	s.policy_epoch = 0U;
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0), -EINVAL);
	edge_make_service(&s, "s1", 9000U);
	s.state = (enum pqcp_edge_service_state)42;
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0), -EINVAL);
	zassert_equal(pqcp_edge_service_find(&reg_svc, "s1", &sp), -ENOENT);
	zassert_equal(reg_svc.registration_count, 0U);

	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		PQCP_EDGE_SERVICE_EMPTY, T0), -EINVAL);
	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		(enum pqcp_edge_service_state)42, T0), -EINVAL);
	zassert_equal(pqcp_edge_service_set_state(&reg_svc, NULL,
		PQCP_EDGE_SERVICE_HEALTHY, T0), -EINVAL);
	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		PQCP_EDGE_SERVICE_HEALTHY, T0), -ENOENT);

	add_service("s1", 9000U);
	edge_make_endpoint(&e, "e1", "s1", 9000U);
	e.transport = PQCP_EDGE_TRANSPORT_NONE;
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), -EINVAL);
	e.transport = (enum pqcp_edge_transport)99;
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), -EINVAL);
	edge_make_endpoint(&e, "e1", "s1", 9000U);
	e.maximum_requests = 0U;
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), -EINVAL);
	edge_make_endpoint(&e, "e1", "s1", 9000U);
	e.weight = 0U;
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), -EINVAL);
	edge_make_endpoint(&e, "e1", "s1", T0);
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), -EINVAL);
	edge_make_endpoint(&e, "e1", "ghost", 9000U);
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), -ENOENT);
	zassert_equal(pqcp_edge_endpoint_find(&reg_svc, "e1", &ep), -ENOENT);

	zassert_equal(pqcp_edge_endpoint_observe(&reg_svc, NULL, true, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_endpoint_observe(&reg_svc, "e1", true, 1U, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_endpoint_eject(&reg_svc, "e1", 0U), -EINVAL);
	zassert_equal(pqcp_edge_endpoint_eject(&reg_svc, "e1", 5U), -ENOENT);
	zassert_equal(pqcp_edge_endpoint_reserve(&reg_svc, "e1"), -ENOENT);
	zassert_equal(pqcp_edge_endpoint_release(&reg_svc, "e1"), -ENOENT);
	zassert_equal(pqcp_edge_service_find(&reg_svc, "s1", NULL), -EINVAL);
	zassert_equal(pqcp_edge_endpoint_find(&reg_svc, "e1", NULL), -EINVAL);
	zassert_equal(pqcp_edge_service_tick(&reg_svc, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_service_registry_audit(&reg_svc), 0);
}

ZTEST(edge_security, test_service_lease_lifecycle)
{
	struct pqcp_edge_service *s = NULL;
	struct pqcp_edge_endpoint e;
	uint32_t changed = 0U;

	svc_setup();
	add_service("s1", 5000U);
	zassert_equal(pqcp_edge_service_find(&reg_svc, "s1", &s), 0);
	zassert_equal(s->state, PQCP_EDGE_SERVICE_REGISTERED);
	zassert_equal(s->endpoint_count, 0U);
	zassert_equal(s->registered_at_ms, T0);

	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		PQCP_EDGE_SERVICE_HEALTHY, 2000U), 0);
	zassert_equal(s->state, PQCP_EDGE_SERVICE_HEALTHY);

	/* A lapsed lease cannot be declared healthy; state is unchanged. */
	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		PQCP_EDGE_SERVICE_HEALTHY, 6000U), -ESTALE);
	zassert_equal(s->state, PQCP_EDGE_SERVICE_HEALTHY);

	zassert_equal(pqcp_edge_service_tick(&reg_svc, 6000U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(s->state, PQCP_EDGE_SERVICE_UNAVAILABLE);
	zassert_equal(reg_svc.expiry_count, 1U);
	zassert_equal(pqcp_edge_service_tick(&reg_svc, 6001U, &changed), 0);
	zassert_equal(changed, 0U);

	/* No new endpoints may attach to an unavailable service. */
	edge_make_endpoint(&e, "e1", "s1", 99000U);
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, 7000U),
		      -EHOSTDOWN);
	zassert_equal(s->endpoint_count, 0U);
}

ZTEST(edge_security, test_service_retirement_is_terminal)
{
	struct pqcp_edge_service s;
	struct pqcp_edge_endpoint e;
	struct pqcp_edge_endpoint *ep = NULL;
	struct pqcp_edge_service *sp = NULL;

	svc_setup();
	add_service("s1", 90000U);
	add_endpoint("e1", "s1", 90000U);
	add_endpoint("e2", "s1", 90000U);

	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		PQCP_EDGE_SERVICE_RETIRED, T0 + 1U), 0);
	zassert_equal(pqcp_edge_endpoint_find(&reg_svc, "e1", &ep), 0);
	zassert_equal(ep->state, PQCP_EDGE_ENDPOINT_DRAINING);
	zassert_equal(pqcp_edge_endpoint_find(&reg_svc, "e2", &ep), 0);
	zassert_equal(ep->state, PQCP_EDGE_ENDPOINT_DRAINING);

	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		PQCP_EDGE_SERVICE_REGISTERED, T0 + 2U), -EPERM);
	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		PQCP_EDGE_SERVICE_HEALTHY, T0 + 2U), -EPERM);
	/* Retiring twice is idempotent. */
	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		PQCP_EDGE_SERVICE_RETIRED, T0 + 3U), 0);

	edge_make_service(&s, "s1", 90000U);
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0 + 4U),
		      -EKEYREJECTED);
	edge_make_endpoint(&e, "e3", "s1", 90000U);
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0 + 4U),
		      -EHOSTDOWN);
	zassert_equal(pqcp_edge_service_find(&reg_svc, "s1", &sp), 0);
	zassert_equal(sp->state, PQCP_EDGE_SERVICE_RETIRED);
	zassert_equal(sp->endpoint_count, 2U);
}

ZTEST(edge_security, test_service_reregistration_cannot_hijack)
{
	struct pqcp_edge_service s;
	struct pqcp_edge_service before;
	struct pqcp_edge_service *found = NULL;

	svc_setup();
	edge_make_service(&s, "s1", 90000U);
	s.policy_epoch = 3U;
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0), 0);
	zassert_equal(pqcp_edge_service_find(&reg_svc, "s1", &found), 0);
	before = *found;

	SETSTR(s.owner_principal_id, "attacker");
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0 + 1U),
		      -EKEYREJECTED);
	zassert_mem_equal(found, &before, sizeof(before));
	edge_make_service(&s, "s1", 90000U);
	s.policy_epoch = 3U;
	SETSTR(s.trust_domain, "dom-evil");
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0 + 1U),
		      -EKEYREJECTED);
	zassert_mem_equal(found, &before, sizeof(before));
	edge_make_service(&s, "s1", 90000U);
	s.policy_epoch = 2U;
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0 + 1U),
		      -EKEYREJECTED);
	zassert_mem_equal(found, &before, sizeof(before));

	/* A compatible refresh extends the lease and keeps provenance. */
	edge_make_service(&s, "s1", 120000U);
	s.policy_epoch = 4U;
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0 + 5U), 0);
	zassert_equal(found->lease_expires_at_ms, 120000U);
	zassert_equal(found->generation, before.generation);
	zassert_equal(found->registered_at_ms, T0);
	zassert_equal(reg_svc.registration_count, 2U);
}

ZTEST(edge_security, test_service_capacity_exhaustion_keeps_entries)
{
	struct pqcp_edge_service s;
	struct pqcp_edge_endpoint e;
	struct pqcp_edge_service snap_s[2];
	struct pqcp_edge_endpoint snap_e[3];

	svc_setup();
	add_service("s1", 90000U);
	add_service("s2", 90000U);
	add_endpoint("e1", "s1", 90000U);
	add_endpoint("e2", "s1", 90000U);
	add_endpoint("e3", "s2", 90000U);
	memcpy(snap_s, sstore, sizeof(snap_s));
	memcpy(snap_e, estore, sizeof(snap_e));

	edge_make_service(&s, "s3", 90000U);
	zassert_equal(pqcp_edge_service_register(&reg_svc, &s, T0), -ENOSPC);
	edge_make_endpoint(&e, "e4", "s1", 90000U);
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), -ENOSPC);
	zassert_mem_equal(sstore, snap_s, sizeof(snap_s));
	zassert_mem_equal(estore, snap_e, sizeof(snap_e));

	/* An endpoint cannot be moved to a different transport or owner. */
	edge_make_endpoint(&e, "e1", "s1", 90000U);
	e.transport = PQCP_EDGE_TRANSPORT_UDP;
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0),
		      -EKEYREJECTED);
	edge_make_endpoint(&e, "e1", "s2", 90000U);
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0),
		      -EKEYREJECTED);
	edge_make_endpoint(&e, "e1", "s1", 90000U);
	SETSTR(e.principal_id, "other-owner");
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0),
		      -EKEYREJECTED);
	zassert_mem_equal(estore, snap_e, sizeof(snap_e));
	zassert_equal(pqcp_edge_service_registry_audit(&reg_svc), 0);
}

ZTEST(edge_security, test_endpoint_ejection_and_capacity_accounting)
{
	struct pqcp_edge_endpoint *e = NULL;
	uint32_t changed = 0U;

	svc_setup();
	add_service("s1", 900000U);
	add_endpoint("e1", "s1", 900000U);
	zassert_equal(pqcp_edge_endpoint_find(&reg_svc, "e1", &e), 0);
	zassert_equal(e->state, PQCP_EDGE_ENDPOINT_READY);

	for (uint32_t i = 1U; i <= 4U; ++i) {
		zassert_equal(pqcp_edge_endpoint_observe(&reg_svc, "e1", false,
			0U, 2000U + i), 0);
		zassert_equal(e->state, PQCP_EDGE_ENDPOINT_DEGRADED);
		zassert_equal(e->consecutive_failures, i);
	}
	/* Fifth consecutive failure ejects for a fixed 60 s. */
	zassert_equal(pqcp_edge_endpoint_observe(&reg_svc, "e1", false, 0U,
		3000U), 0);
	zassert_equal(e->state, PQCP_EDGE_ENDPOINT_EJECTED);
	zassert_equal(e->ejected_until_ms, 63000U);

	/* While ejected nothing is recorded and nothing can be reserved. */
	zassert_equal(pqcp_edge_endpoint_observe(&reg_svc, "e1", true, 1U,
		3010U), -EHOSTDOWN);
	zassert_equal(e->consecutive_failures, 5U);
	zassert_equal(pqcp_edge_endpoint_reserve(&reg_svc, "e1"), -EHOSTDOWN);
	zassert_equal(pqcp_edge_service_tick(&reg_svc, 62999U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(e->state, PQCP_EDGE_ENDPOINT_EJECTED);

	zassert_equal(pqcp_edge_service_tick(&reg_svc, 63000U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(e->state, PQCP_EDGE_ENDPOINT_PROBING);
	zassert_equal(e->consecutive_failures, 0U);
	/* Probing endpoints are not yet usable. */
	zassert_equal(pqcp_edge_endpoint_reserve(&reg_svc, "e1"), -EHOSTDOWN);

	zassert_equal(pqcp_edge_endpoint_observe(&reg_svc, "e1", true, 100U,
		63010U), 0);
	zassert_equal(e->state, PQCP_EDGE_ENDPOINT_READY);
	zassert_equal(e->latency_ewma_us, 100U);
	zassert_equal(pqcp_edge_endpoint_observe(&reg_svc, "e1", true, 900U,
		63020U), 0);
	zassert_equal(e->latency_ewma_us, 200U);

	for (uint32_t i = 0U; i < e->maximum_requests; ++i) {
		zassert_equal(pqcp_edge_endpoint_reserve(&reg_svc, "e1"), 0);
	}
	zassert_equal(pqcp_edge_endpoint_reserve(&reg_svc, "e1"), -EAGAIN);
	zassert_equal(e->active_requests, e->maximum_requests);
	for (uint32_t i = 0U; i < e->maximum_requests; ++i) {
		zassert_equal(pqcp_edge_endpoint_release(&reg_svc, "e1"), 0);
	}
	zassert_equal(pqcp_edge_endpoint_release(&reg_svc, "e1"), -EALREADY);
	zassert_equal(e->active_requests, 0U);
}

ZTEST(edge_security, test_endpoint_manual_eject_and_lease_expiry)
{
	struct pqcp_edge_endpoint *e = NULL;
	uint32_t changed = 0U;

	svc_setup();
	add_service("s1", 900000U);
	add_endpoint("e1", "s1", 20000U);
	add_endpoint("e2", "s1", 900000U);
	zassert_equal(pqcp_edge_endpoint_find(&reg_svc, "e1", &e), 0);

	zassert_equal(pqcp_edge_endpoint_eject(&reg_svc, "e1", UINT64_MAX), 0);
	zassert_equal(e->state, PQCP_EDGE_ENDPOINT_EJECTED);
	zassert_equal(pqcp_edge_service_tick(&reg_svc, 19000U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(e->state, PQCP_EDGE_ENDPOINT_EJECTED);

	/* Lease expiry moves the endpoint to DRAINING even when ejected. */
	zassert_equal(pqcp_edge_service_tick(&reg_svc, 21000U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(e->state, PQCP_EDGE_ENDPOINT_DRAINING);
	zassert_equal(reg_svc.expiry_count, 1U);

	/* Observing a different endpoint past its lease marks it stale. */
	zassert_equal(pqcp_edge_endpoint_find(&reg_svc, "e2", &e), 0);
	e->lease_expires_at_ms = 5000U;
	zassert_equal(pqcp_edge_endpoint_observe(&reg_svc, "e2", true, 1U,
		6000U), -ESTALE);
	zassert_equal(e->state, PQCP_EDGE_ENDPOINT_DRAINING);
	zassert_equal(e->latency_ewma_us, 0U);
}

ZTEST(edge_security, test_service_registry_audit_detects_corruption)
{
	struct pqcp_edge_service *s = NULL;
	struct pqcp_edge_endpoint *e = NULL;

	svc_setup();
	add_service("s1", 90000U);
	add_endpoint("e1", "s1", 90000U);
	zassert_equal(pqcp_edge_service_registry_audit(&reg_svc), 0);

	zassert_equal(pqcp_edge_service_find(&reg_svc, "s1", &s), 0);
	zassert_equal(pqcp_edge_endpoint_find(&reg_svc, "e1", &e), 0);
	s->endpoint_count = 5U;
	zassert_equal(pqcp_edge_service_registry_audit(&reg_svc), -EBADMSG);
	s->endpoint_count = 1U;

	e->active_requests = e->maximum_requests + 1U;
	zassert_equal(pqcp_edge_service_registry_audit(&reg_svc), -EBADMSG);
	e->active_requests = 0U;

	SETSTR(e->service_id, "orphan");
	zassert_equal(pqcp_edge_service_registry_audit(&reg_svc), -EBADMSG);
	SETSTR(e->service_id, "s1");

	estore[1] = estore[0];
	sstore[0].endpoint_count = 2U;
	zassert_equal(pqcp_edge_service_registry_audit(&reg_svc), -EEXIST);
}

/* ------------------------------------------------------------------ */
/* Access engine                                                       */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_access_rule rstore[3];
static struct pqcp_edge_access_engine engine;

static void access_setup(enum pqcp_edge_policy_effect fallback)
{
	zassert_equal(pqcp_edge_access_engine_init(
		&engine, rstore, ARRAY_SIZE(rstore), fallback), 0);
}

static void make_rule(struct pqcp_edge_access_rule *r, uint32_t id,
		      uint32_t priority,
		      enum pqcp_edge_policy_effect effect)
{
	memset(r, 0, sizeof(*r));
	r->rule_id = id;
	r->priority = priority;
	r->operation_mask = ALL_OPERATIONS;
	r->maximum_risk = 1000U;
	r->effect = effect;
	r->enabled = true;
}

static void make_ctx(struct pqcp_edge_access_context *c,
		     const struct pqcp_edge_principal *p,
		     const struct pqcp_edge_service *s,
		     enum pqcp_edge_operation op, uint64_t now)
{
	memset(c, 0, sizeof(*c));
	c->principal = p;
	c->service = s;
	c->operation = op;
	SETSTR(c->source_zone, "zone-a");
	SETSTR(c->destination_zone, "zone-a");
	c->now_ms = now;
	c->channel_identity_verified = true;
	c->attestation_fresh = true;
}

ZTEST(edge_security, test_access_rejects_invalid_arguments)
{
	static struct pqcp_edge_access_engine raw;
	struct pqcp_edge_access_rule r;
	struct pqcp_edge_principal p;
	struct pqcp_edge_service s;
	struct pqcp_edge_access_context c;
	struct pqcp_edge_access_decision d;

	zassert_equal(pqcp_edge_access_engine_init(
		NULL, rstore, 3U, PQCP_EDGE_POLICY_DENY), -EINVAL);
	zassert_equal(pqcp_edge_access_engine_init(
		&engine, NULL, 3U, PQCP_EDGE_POLICY_DENY), -EINVAL);
	zassert_equal(pqcp_edge_access_engine_init(
		&engine, rstore, 0U, PQCP_EDGE_POLICY_DENY), -EINVAL);
	zassert_equal(pqcp_edge_access_engine_init(
		&engine, rstore, 3U, PQCP_EDGE_POLICY_UNSET), -EINVAL);
	zassert_equal(pqcp_edge_access_engine_init(
		&engine, rstore, 3U, (enum pqcp_edge_policy_effect)9),
		-EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(pqcp_edge_access_rule_put(&raw, &r), -EINVAL);
	zassert_equal(pqcp_edge_access_rule_remove(&raw, 1U), -EINVAL);
	zassert_equal(pqcp_edge_access_engine_audit(&raw), -EINVAL);
	zassert_equal(pqcp_edge_access_engine_audit(NULL), -EINVAL);

	access_setup(PQCP_EDGE_POLICY_DENY);
	zassert_equal(pqcp_edge_access_rule_put(&engine, NULL), -EINVAL);
	zassert_equal(pqcp_edge_access_rule_remove(&engine, 0U), -EINVAL);
	zassert_equal(pqcp_edge_access_rule_remove(&engine, 7U), -ENOENT);

	make_rule(&r, 0U, 1U, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -EINVAL);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.operation_mask = 0U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -EINVAL);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_UNSET);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -EINVAL);
	make_rule(&r, 1U, 1U, (enum pqcp_edge_policy_effect)9);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -EINVAL);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.not_before_ms = 500U;
	r.not_after_ms = 100U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -EINVAL);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.required_capabilities = 0x3U;
	r.forbidden_capabilities = 0x2U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -EINVAL);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.minimum_trust = 99U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -EINVAL);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.enabled = false;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -EINVAL);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	memset(r.service_id, 'x', sizeof(r.service_id));
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -EINVAL);
	zassert_equal(engine.count, 0U);

	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 90000U);
	edge_make_service(&s, "s1", 90000U);
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_CONNECT, T0);
	zassert_equal(pqcp_edge_access_evaluate(NULL, &c, &d), -EINVAL);
	zassert_equal(pqcp_edge_access_evaluate(&engine, NULL, &d), -EINVAL);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, NULL), -EINVAL);
	c.operation = PQCP_EDGE_OPERATION_NONE;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EINVAL);
	c.operation = PQCP_EDGE_OPERATION_COUNT;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EINVAL);
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_CONNECT, T0);
	c.principal = NULL;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EINVAL);
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_CONNECT, T0);
	c.service = NULL;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EINVAL);
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_CONNECT, T0);
	c.source_zone[0] = '\0';
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EINVAL);
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_CONNECT, T0);
	c.destination_zone[0] = '\0';
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EINVAL);
	/* Invalid requests are not counted as policy decisions. */
	zassert_equal(engine.allow_count + engine.deny_count +
		      engine.challenge_count, 0U);
}

ZTEST(edge_security, test_access_default_effect_is_fail_closed)
{
	struct pqcp_edge_principal p;
	struct pqcp_edge_service s;
	struct pqcp_edge_access_context c;
	struct pqcp_edge_access_decision d;

	edge_make_principal(&p, "p1", CAP_ALL, PQCP_EDGE_TRUST_ATTESTED,
			    90000U);
	edge_make_service(&s, "s1", 90000U);
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_CONNECT, T0);

	access_setup(PQCP_EDGE_POLICY_DENY);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_DENY);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_DEFAULT);
	zassert_true(strlen(d.explanation) > 0U);
	zassert_equal(engine.deny_count, 1U);

	access_setup(PQCP_EDGE_POLICY_CHALLENGE);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EAGAIN);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_CHALLENGE);
	zassert_equal(engine.challenge_count, 1U);

	access_setup(PQCP_EDGE_POLICY_QUARANTINE);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_QUARANTINE);

	access_setup(PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_DEFAULT);
	zassert_equal(engine.allow_count, 1U);
}

ZTEST(edge_security, test_access_hard_guards_override_explicit_allow)
{
	struct pqcp_edge_access_rule r;
	struct pqcp_edge_principal base_p;
	struct pqcp_edge_service base_s;
	struct pqcp_edge_principal p;
	struct pqcp_edge_service s;
	struct pqcp_edge_access_context c;
	struct pqcp_edge_access_decision d;

	access_setup(PQCP_EDGE_POLICY_DENY);
	make_rule(&r, 1U, 100U, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);

	edge_make_principal(&base_p, "p1", CAP_ALL,
			    PQCP_EDGE_TRUST_ATTESTED, 90000U);
	edge_make_service(&base_s, "s1", 90000U);
	base_s.state = PQCP_EDGE_SERVICE_HEALTHY;

	/* Sanity: the baseline request is allowed by the explicit rule. */
	make_ctx(&c, &base_p, &base_s, PQCP_EDGE_OPERATION_READ, T0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_RULE);
	zassert_equal(d.rule_id, 1U);
	zassert_equal(d.rule_priority, 100U);

	p = base_p; s = base_s;
	p.state = PQCP_EDGE_PRINCIPAL_REVOKED;
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_READ, T0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d),
		      -EKEYREVOKED);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_DENY);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_REVOCATION);

	p = base_p;
	p.state = PQCP_EDGE_PRINCIPAL_QUARANTINED;
	p.quarantine_until_ms = T0 + 500U;
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_READ, T0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_QUARANTINE);
	zassert_equal(d.retry_after_ms, T0 + 500U);
	/* Once the quarantine window has elapsed the guard no longer fires. */
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_READ, T0 + 500U);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);

	p = base_p;
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_READ, 90000U);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d),
		      -EKEYEXPIRED);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_CHALLENGE);

	s = base_s;
	s.state = PQCP_EDGE_SERVICE_UNAVAILABLE;
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_READ, T0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EHOSTDOWN);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_SERVICE);
	s.state = PQCP_EDGE_SERVICE_DRAINING;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EHOSTDOWN);

	s = base_s;
	s.lease_expires_at_ms = T0;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -ESTALE);

	s = base_s;
	s.operation_mask &= ~PQCP_EDGE_OPERATION_BIT(PQCP_EDGE_OPERATION_READ);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -ENOTSUP);

	s = base_s;
	s.required_capabilities = 0x6U;
	p.capabilities = 0x2U;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_CAPABILITY);
	zassert_equal(d.missing_capabilities, 0x4U);

	p = base_p;
	s = base_s;
	s.minimum_trust = PQCP_EDGE_TRUST_PRIVILEGED;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EAGAIN);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_CHALLENGE);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_TRUST);

	s = base_s;
	s.maximum_risk = 100U;
	p.risk_score = 101U;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_RISK);

	p = base_p;
	s = base_s;
	s.require_channel_binding = true;
	p.channel_bound = false;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -ENOTCONN);
	p.channel_bound = true;
	c.channel_identity_verified = false;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -ENOTCONN);
	c.channel_identity_verified = true;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);

	s.require_attestation = true;
	c.attestation_fresh = false;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EAGAIN);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_CHALLENGE);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_ATTESTATION);
	c.attestation_fresh = true;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);
}

ZTEST(edge_security, test_access_rule_priority_and_scope)
{
	struct pqcp_edge_access_rule r;
	struct pqcp_edge_principal p;
	struct pqcp_edge_service s;
	struct pqcp_edge_access_context c;
	struct pqcp_edge_access_decision d;

	edge_make_principal(&p, "p1", CAP_ALL, PQCP_EDGE_TRUST_ATTESTED,
			    90000U);
	edge_make_service(&s, "s1", 90000U);
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_PUBLISH, T0);

	access_setup(PQCP_EDGE_POLICY_DENY);
	make_rule(&r, 10U, 1U, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	make_rule(&r, 20U, 5U, PQCP_EDGE_POLICY_DENY);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	/* Higher priority deny wins over lower priority allow. */
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.rule_id, 20U);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_RULE);

	/* Equal priority: the lower rule id wins deterministically. */
	make_rule(&r, 5U, 5U, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);
	zassert_equal(d.rule_id, 5U);

	/* Removing the winner exposes the next one; counts stay audited. */
	zassert_equal(pqcp_edge_access_rule_remove(&engine, 5U), 0);
	zassert_equal(pqcp_edge_access_rule_remove(&engine, 5U), -ENOENT);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.rule_id, 20U);
	zassert_equal(engine.count, 2U);
	zassert_equal(pqcp_edge_access_engine_audit(&engine), 0);

	/* Rules scoped to another service, operation, zone or time miss. */
	zassert_equal(pqcp_edge_access_rule_remove(&engine, 20U), 0);
	zassert_equal(pqcp_edge_access_rule_remove(&engine, 10U), 0);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	SETSTR(r.service_id, "other-service");
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_DEFAULT);

	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.operation_mask = PQCP_EDGE_OPERATION_BIT(PQCP_EDGE_OPERATION_READ);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_DEFAULT);

	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	SETSTR(r.source_zone, "zone-z");
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	SETSTR(r.source_domain, "dom-a");
	SETSTR(r.destination_domain, "dom-b");
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);

	/* Time-windowed rule: allowed inside, default deny outside. */
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.not_before_ms = 2000U;
	r.not_after_ms = 3000U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	c.now_ms = 1999U;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	c.now_ms = 2000U;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);
	c.now_ms = 3000U;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);
	c.now_ms = 3001U;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_DEFAULT);
}

ZTEST(edge_security, test_access_rule_conditions)
{
	struct pqcp_edge_access_rule r;
	struct pqcp_edge_principal p;
	struct pqcp_edge_service s;
	struct pqcp_edge_access_context c;
	struct pqcp_edge_access_decision d;

	edge_make_principal(&p, "p1", 0x6U, PQCP_EDGE_TRUST_AUTHENTICATED,
			    90000U);
	edge_make_service(&s, "s1", 90000U);
	make_ctx(&c, &p, &s, PQCP_EDGE_OPERATION_WRITE, T0);
	access_setup(PQCP_EDGE_POLICY_DENY);

	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.required_capabilities = 0x1U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.missing_capabilities, 0x1U);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_CAPABILITY);

	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.forbidden_capabilities = 0x4U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.forbidden_capabilities, 0x4U);

	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.minimum_trust = PQCP_EDGE_TRUST_ATTESTED;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EAGAIN);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_CHALLENGE);

	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.maximum_risk = 10U;
	p.risk_score = 11U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_DENY);
	/* A quarantine rule keeps the stronger effect when risk is exceeded. */
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_QUARANTINE);
	r.maximum_risk = 10U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_QUARANTINE);
	p.risk_score = 0U;

	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.maximum_concurrent = 2U;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	c.current_concurrent = 1U;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);
	c.current_concurrent = 2U;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EDQUOT);
	zassert_equal(d.reason, PQCP_EDGE_POLICY_REASON_QUOTA);

	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_ALLOW);
	r.require_channel_binding = true;
	r.require_attestation = true;
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	c.channel_identity_verified = false;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -ENOTCONN);
	c.channel_identity_verified = true;
	c.attestation_fresh = false;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EAGAIN);
	c.attestation_fresh = true;
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), 0);

	/* Explicit challenge and quarantine rules map to their own codes. */
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_CHALLENGE);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EAGAIN);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_CHALLENGE);
	make_rule(&r, 1U, 1U, PQCP_EDGE_POLICY_QUARANTINE);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(pqcp_edge_access_evaluate(&engine, &c, &d), -EACCES);
	zassert_equal(d.effect, PQCP_EDGE_POLICY_QUARANTINE);
}

ZTEST(edge_security, test_access_rule_capacity_and_replace)
{
	struct pqcp_edge_access_rule r;
	struct pqcp_edge_access_rule snap[3];
	uint64_t generation;

	access_setup(PQCP_EDGE_POLICY_DENY);
	for (uint32_t i = 1U; i <= 3U; ++i) {
		make_rule(&r, i, i, PQCP_EDGE_POLICY_ALLOW);
		zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	}
	zassert_equal(engine.count, 3U);
	memcpy(snap, rstore, sizeof(snap));
	generation = engine.generation;

	make_rule(&r, 4U, 4U, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), -ENOSPC);
	zassert_mem_equal(rstore, snap, sizeof(snap));
	zassert_equal(engine.count, 3U);
	zassert_equal(engine.generation, generation);

	/* Replacing an existing id does not consume capacity. */
	make_rule(&r, 2U, 9U, PQCP_EDGE_POLICY_DENY);
	zassert_equal(pqcp_edge_access_rule_put(&engine, &r), 0);
	zassert_equal(engine.count, 3U);
	zassert_true(engine.generation > generation);
	zassert_equal(pqcp_edge_access_engine_audit(&engine), 0);

	/* Audit catches tampering: duplicate ids and count drift. */
	rstore[2].rule_id = rstore[0].rule_id;
	zassert_equal(pqcp_edge_access_engine_audit(&engine), -EEXIST);
	rstore[2].rule_id = 3U;
	engine.count = 2U;
	zassert_equal(pqcp_edge_access_engine_audit(&engine), -EBADMSG);
	engine.count = 3U;
	rstore[1].operation_mask = 0U;
	zassert_equal(pqcp_edge_access_engine_audit(&engine), -EBADMSG);
}

/* ------------------------------------------------------------------ */
/* Route table                                                         */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_route rtstore[2];
static struct pqcp_edge_route_table rtable;

static void route_setup(void)
{
	svc_setup();
	zassert_equal(pqcp_edge_route_table_init(
		&rtable, rtstore, ARRAY_SIZE(rtstore)), 0);
	add_service("s1", 900000U);
}

static void add_ready_endpoint(const char *id, uint32_t latency,
			       uint32_t trust, uint32_t priority,
			       const char *zone)
{
	struct pqcp_edge_endpoint e;

	edge_make_endpoint(&e, id, "s1", 900000U);
	e.latency_ewma_us = latency;
	e.trust_score = trust;
	e.priority = priority;
	SETSTR(e.zone, zone);
	zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), 0);
}

static struct pqcp_edge_principal route_principal(void)
{
	struct pqcp_edge_principal p;

	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 900000U);
	return p;
}

ZTEST(edge_security, test_route_rejects_invalid_arguments)
{
	static struct pqcp_edge_route_table raw;
	struct pqcp_edge_principal p = route_principal();
	struct pqcp_edge_route *route = (struct pqcp_edge_route *)0x1;
	uint32_t expired = 0U;

	zassert_equal(pqcp_edge_route_table_init(NULL, rtstore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_route_table_init(&rtable, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_route_table_init(&rtable, rtstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	route_setup();
	zassert_equal(pqcp_edge_route_select(&raw, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 100U, &route), -EINVAL);
	zassert_equal(pqcp_edge_route_failover(&raw, &reg_svc, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_route_expire(&raw, T0, &expired), -EINVAL);
	zassert_equal(pqcp_edge_route_table_audit(&raw), -EINVAL);

	zassert_equal(pqcp_edge_route_select(&rtable, NULL, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 100U, &route), -EINVAL);
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, NULL, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 100U, &route), -EINVAL);
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, NULL,
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 100U, &route), -EINVAL);
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 100U, NULL), -EINVAL);
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		(enum pqcp_edge_route_strategy)9, T0, 100U, &route),
		-EINVAL);
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 0U, &route), -EINVAL);
	p.state = PQCP_EDGE_PRINCIPAL_DEGRADED;
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 100U, &route), -EINVAL);
	p.state = PQCP_EDGE_PRINCIPAL_QUARANTINED;
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 100U, &route), -EINVAL);
	zassert_equal(rtable.selection_count, 0U);

	zassert_equal(pqcp_edge_route_failover(&rtable, NULL, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_route_failover(&rtable, &reg_svc, 0U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_route_failover(&rtable, &reg_svc, 5U, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_route_expire(&rtable, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_route_table_audit(&rtable), 0);
}

ZTEST(edge_security, test_route_selection_fails_closed)
{
	struct pqcp_edge_principal p = route_principal();
	struct pqcp_edge_route *route = NULL;

	route_setup();
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "ghost",
		PQCP_EDGE_ROUTE_LOWEST_LATENCY, T0, 100U, &route), -ENOENT);
	zassert_is_null(route);

	/* No endpoint at all. */
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_LOWEST_LATENCY, T0, 100U, &route), -ENOENT);
	zassert_is_null(route);

	/* An endpoint that is merely probing is not routable. */
	{
		struct pqcp_edge_endpoint e;

		edge_make_endpoint(&e, "e1", "s1", 900000U);
		e.state = PQCP_EDGE_ENDPOINT_PROBING;
		zassert_equal(pqcp_edge_endpoint_register(&reg_svc, &e, T0), 0);
	}
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_LOWEST_LATENCY, T0, 100U, &route), -ENOENT);

	/* Principals whose risk exceeds the endpoint trust are excluded. */
	zassert_equal(pqcp_edge_endpoint_observe(&reg_svc, "e1", true, 5U,
		T0 + 1U), 0);
	p.risk_score = 2000U;
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_LOWEST_LATENCY, T0, 100U, &route), -ENOENT);
	p.risk_score = 0U;

	/* A service that is down yields -EHOSTDOWN, not a stale route. */
	zassert_equal(pqcp_edge_service_set_state(&reg_svc, "s1",
		PQCP_EDGE_SERVICE_UNAVAILABLE, T0), 0);
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_LOWEST_LATENCY, T0, 100U, &route), -EHOSTDOWN);
	zassert_is_null(route);
	zassert_equal(rtable.selection_count, 0U);
	zassert_equal(pqcp_edge_route_table_audit(&rtable), 0);
}

ZTEST(edge_security, test_route_strategies_pick_expected_endpoint)
{
	static struct pqcp_edge_route big[8];
	struct pqcp_edge_principal p = route_principal();
	struct pqcp_edge_route *route = NULL;
	struct pqcp_edge_route *first = NULL;
	struct pqcp_edge_endpoint *ep = NULL;
	char chosen[PQCP_EDGE_ID_MAX_CHARS];

	svc_setup();
	zassert_equal(pqcp_edge_route_table_init(
		&rtable, big, ARRAY_SIZE(big)), 0);
	add_service("s1", 900000U);
	add_ready_endpoint("e-slow", 800U, 900U, 1U, "zone-a");
	add_ready_endpoint("e-fast", 100U, 900U, 1U, "zone-a");
	add_ready_endpoint("e-far", 50U, 900U, 1U, "zone-b");

	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_LOWEST_LATENCY, T0, 1000U, &route), 0);
	zassert_str_equal(route->endpoint_id, "e-far");
	zassert_equal(route->strategy, PQCP_EDGE_ROUTE_LOWEST_LATENCY);
	zassert_equal(route->expires_at_ms, T0 + 1000U);
	zassert_str_equal(route->source_principal_id, "p1");
	zassert_str_equal(route->destination_zone, "zone-b");

	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_ZONE_AFFINITY, T0, 1000U, &route), 0);
	zassert_str_equal(route->endpoint_id, "e-fast");
	zassert_str_equal(route->destination_zone, "zone-a");

	zassert_equal(pqcp_edge_endpoint_find(&reg_svc, "e-slow", &ep), 0);
	ep->trust_score = 1000U;
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_HIGHEST_TRUST, T0, 1000U, &route), 0);
	zassert_str_equal(route->endpoint_id, "e-slow");

	/* Load shifts the least-loaded choice away from busy endpoints. */
	for (int i = 0; i < 3; ++i) {
		zassert_equal(pqcp_edge_endpoint_reserve(&reg_svc, "e-far"), 0);
		zassert_equal(pqcp_edge_endpoint_reserve(&reg_svc, "e-fast"),
			      0);
	}
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_LEAST_LOADED, T0, 1000U, &route), 0);
	zassert_str_equal(route->endpoint_id, "e-slow");

	/* Deterministic selection is a pure function of the inputs. */
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 1000U, &first), 0);
	strcpy(chosen, first->endpoint_id);
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0 + 1U, 1000U, &route), 0);
	zassert_str_equal(route->endpoint_id, chosen);
	zassert_true(route->route_id != first->route_id);

	/* A numerically better priority beats any score advantage. */
	ep->priority = 0U;
	ep->latency_ewma_us = 900000U;
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_LOWEST_LATENCY, T0, 1000U, &route), 0);
	zassert_str_equal(route->endpoint_id, "e-slow");
	zassert_equal(pqcp_edge_route_table_audit(&rtable), 0);
}

ZTEST(edge_security, test_route_failover_preserves_route_on_failure)
{
	struct pqcp_edge_principal p = route_principal();
	struct pqcp_edge_route *route = NULL;
	struct pqcp_edge_route snapshot;
	uint8_t old_digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t id;

	route_setup();
	add_ready_endpoint("e1", 100U, 900U, 1U, "zone-a");
	add_ready_endpoint("e2", 200U, 900U, 1U, "zone-a");
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_LOWEST_LATENCY, T0, 5000U, &route), 0);
	zassert_str_equal(route->endpoint_id, "e1");
	id = route->route_id;
	memcpy(old_digest, route->route_digest, sizeof(old_digest));

	zassert_equal(pqcp_edge_route_failover(&rtable, &reg_svc, id,
		T0 + 10U), 0);
	zassert_str_equal(route->endpoint_id, "e2");
	zassert_equal(route->failover_count, 1U);
	zassert_equal(rtable.failover_count, 1U);
	zassert_true(memcmp(old_digest, route->route_digest,
			    sizeof(old_digest)) != 0);
	zassert_equal(pqcp_edge_route_table_audit(&rtable), 0);

	/* With no alternative, the route is left exactly as it was. */
	zassert_equal(pqcp_edge_endpoint_eject(&reg_svc, "e1", UINT64_MAX), 0);
	snapshot = *route;
	zassert_equal(pqcp_edge_route_failover(&rtable, &reg_svc, id,
		T0 + 20U), -ENOENT);
	zassert_mem_equal(route, &snapshot, sizeof(snapshot));
	zassert_equal(rtable.failover_count, 1U);

	/* Expired routes cannot be failed over. */
	zassert_equal(pqcp_edge_route_failover(&rtable, &reg_svc, id,
		T0 + 5000U), -ESTALE);
	zassert_mem_equal(route, &snapshot, sizeof(snapshot));
}

ZTEST(edge_security, test_route_table_capacity_expiry_and_tamper)
{
	struct pqcp_edge_principal p = route_principal();
	struct pqcp_edge_route *r1 = NULL;
	struct pqcp_edge_route *r2 = NULL;
	struct pqcp_edge_route *r3 = NULL;
	struct pqcp_edge_route snap[2];
	uint32_t expired = 0U;

	route_setup();
	add_ready_endpoint("e1", 100U, 900U, 1U, "zone-a");
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 1000U, &r1), 0);
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0, 2000U, &r2), 0);
	memcpy(snap, rtstore, sizeof(snap));

	/* Table is full of live routes: refuse rather than evict. */
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0 + 500U, 1000U, &r3),
		-ENOSPC);
	zassert_is_null(r3);
	zassert_mem_equal(rtstore, snap, sizeof(snap));

	/* Once one has expired its slot is reusable. */
	zassert_equal(pqcp_edge_route_select(&rtable, &reg_svc, &p, "s1",
		PQCP_EDGE_ROUTE_DETERMINISTIC, T0 + 1000U, 5000U, &r3), 0);
	zassert_equal(r3, r1);
	zassert_true(r3->route_id > r2->route_id);

	zassert_equal(pqcp_edge_route_expire(&rtable, T0 + 2000U,
					     &expired), 0);
	zassert_equal(expired, 1U);
	zassert_false(r2->occupied);
	zassert_equal(pqcp_edge_route_table_audit(&rtable), 0);

	r3->score ^= 1U;
	zassert_equal(pqcp_edge_route_table_audit(&rtable), -EBADMSG);
	r3->score ^= 1U;
	rtstore[1] = rtstore[0];
	zassert_equal(pqcp_edge_route_table_audit(&rtable), -EEXIST);
}

/* ------------------------------------------------------------------ */
/* Session registry                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_session sess_store[2];
static struct pqcp_edge_session_registry sreg;
static uint8_t binding[PQCP_EDGE_DIGEST_BYTES];

static void session_setup(uint32_t max_sessions)
{
	struct pqcp_edge_principal p;

	dir_setup();
	edge_make_principal(&p, "p1", 1U, PQCP_EDGE_TRUST_ATTESTED, 900000U);
	p.maximum_sessions = max_sessions;
	zassert_equal(pqcp_edge_principal_register(&dir, &p, T0), 0);
	zassert_equal(pqcp_edge_session_registry_init(
		&sreg, sess_store, ARRAY_SIZE(sess_store)), 0);
	edge_digest(binding, 0x33U);
}

static struct pqcp_edge_route make_route(uint64_t expires)
{
	struct pqcp_edge_route r;

	memset(&r, 0, sizeof(r));
	r.schema_version = PQCP_EDGE_SCHEMA_VERSION;
	r.route_id = 1U;
	SETSTR(r.source_principal_id, "p1");
	SETSTR(r.service_id, "s1");
	SETSTR(r.endpoint_id, "e1");
	SETSTR(r.source_zone, "zone-a");
	SETSTR(r.destination_zone, "zone-a");
	r.expires_at_ms = expires;
	r.occupied = true;
	return r;
}

static struct pqcp_edge_session *open_session(uint64_t now,
					      uint64_t lifetime)
{
	struct pqcp_edge_route r = make_route(900000U);
	struct pqcp_edge_session *s = NULL;

	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, binding,
		true, now, lifetime, &s), 0);
	zassert_not_null(s);
	return s;
}

ZTEST(edge_security, test_session_rejects_invalid_arguments)
{
	static struct pqcp_edge_session_registry raw;
	struct pqcp_edge_route r = make_route(900000U);
	struct pqcp_edge_session *s = (struct pqcp_edge_session *)0x1;
	uint8_t zero[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	uint32_t changed = 0U;

	zassert_equal(pqcp_edge_session_registry_init(NULL, sess_store, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_session_registry_init(&sreg, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_session_registry_init(&sreg, sess_store, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	session_setup(2U);
	zassert_equal(pqcp_edge_session_open(&raw, &dir, &r, binding, true,
		T0, 100U, &s), -EINVAL);
	zassert_equal(pqcp_edge_session_account(&raw, 1U, 1U, 1U, true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_session_require_rekey(&raw, 1U, 2U), -EINVAL);
	zassert_equal(pqcp_edge_session_close(&raw, &dir, 1U, 0, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_session_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_session_registry_audit(&raw), -EINVAL);

	zassert_equal(pqcp_edge_session_open(&sreg, NULL, &r, binding, true,
		T0, 100U, &s), -EINVAL);
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, NULL, binding,
		true, T0, 100U, &s), -EINVAL);
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, NULL, true,
		T0, 100U, &s), -EINVAL);
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, zero, true,
		T0, 100U, &s), -EINVAL);
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, binding, true,
		T0, 0U, &s), -EINVAL);
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, binding, true,
		T0, 100U, NULL), -EINVAL);
	r.expires_at_ms = T0;
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, binding, true,
		T0, 100U, &s), -EINVAL);
	r = make_route(900000U);
	r.occupied = false;
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, binding, true,
		T0, 100U, &s), -EINVAL);
	zassert_equal(sreg.opened_count, 0U);

	zassert_equal(pqcp_edge_session_account(&sreg, 0U, 1U, 1U, true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_session_account(&sreg, 9U, 1U, 1U, true, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_session_require_rekey(&sreg, 0U, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_session_require_rekey(&sreg, 1U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_edge_session_require_rekey(&sreg, 9U, 2U),
		      -ENOENT);
	zassert_equal(pqcp_edge_session_close(&sreg, &dir, 0U, 0, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_session_close(&sreg, NULL, 1U, 0, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_session_close(&sreg, &dir, 9U, 0, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_session_tick(&sreg, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_session_registry_audit(&sreg), 0);
}

ZTEST(edge_security, test_session_open_enforces_principal_state_and_quota)
{
	struct pqcp_edge_route r = make_route(900000U);
	struct pqcp_edge_session *s = NULL;
	struct pqcp_edge_principal *p = NULL;

	session_setup(1U);
	zassert_equal(pqcp_edge_principal_find(&dir, "p1", &p), 0);

	s = open_session(T0, 5000U);
	zassert_equal(s->state, PQCP_EDGE_SESSION_ACTIVE);
	zassert_equal(s->key_epoch, 1U);
	zassert_equal(s->expires_at_ms, T0 + 5000U);
	zassert_true(s->mutually_authenticated);
	zassert_str_equal(s->principal_id, "p1");
	zassert_equal(p->active_sessions, 1U);

	/* Per-principal quota: refused without touching earlier state. */
	{
		struct pqcp_edge_session snap = *s;
		struct pqcp_edge_session *s2 = (struct pqcp_edge_session *)0x1;

		zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, binding,
			true, T0 + 1U, 5000U, &s2), -EDQUOT);
		zassert_is_null(s2);
		zassert_mem_equal(s, &snap, sizeof(snap));
		zassert_equal(p->active_sessions, 1U);
		zassert_equal(sreg.rejected_count, 1U);
	}

	/* Non-active principals cannot open sessions. */
	p->maximum_sessions = 4U;
	p->state = PQCP_EDGE_PRINCIPAL_DEGRADED;
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, binding, true,
		T0 + 1U, 5000U, &s), -EACCES);
	p->state = PQCP_EDGE_PRINCIPAL_ACTIVE;
	p->credential_expires_at_ms = T0 + 1U;
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, binding, true,
		T0 + 1U, 5000U, &s), -EACCES);
	p->credential_expires_at_ms = 900000U;
	SETSTR(r.source_principal_id, "ghost");
	zassert_equal(pqcp_edge_session_open(&sreg, &dir, &r, binding, true,
		T0 + 1U, 5000U, &s), -ENOENT);
	zassert_equal(p->active_sessions, 1U);
	zassert_equal(pqcp_edge_session_registry_audit(&sreg), 0);
}

ZTEST(edge_security, test_session_accounting_and_close)
{
	struct pqcp_edge_session *s;
	struct pqcp_edge_principal *p = NULL;

	session_setup(4U);
	zassert_equal(pqcp_edge_principal_find(&dir, "p1", &p), 0);
	s = open_session(T0, 5000U);

	zassert_equal(pqcp_edge_session_account(&sreg, s->session_id, 100U,
		40U, true, T0 + 10U), 0);
	zassert_equal(pqcp_edge_session_account(&sreg, s->session_id, 50U,
		10U, true, T0 + 20U), 0);
	zassert_equal(s->bytes_sent, 150U);
	zassert_equal(s->bytes_received, 50U);
	zassert_equal(s->request_count, 2U);
	zassert_equal(s->last_activity_ms, T0 + 20U);

	/* Failures are tracked and recover with successes. */
	zassert_equal(pqcp_edge_session_account(&sreg, s->session_id, 0U,
		0U, false, T0 + 30U), 0);
	zassert_equal(s->failures, 1U);
	zassert_equal(pqcp_edge_session_account(&sreg, s->session_id, 0U,
		0U, true, T0 + 31U), 0);
	zassert_equal(s->failures, 0U);

	zassert_equal(pqcp_edge_session_close(&sreg, &dir, s->session_id, 0,
		T0 + 40U), 0);
	zassert_equal(s->state, PQCP_EDGE_SESSION_CLOSED);
	zassert_equal(p->active_sessions, 0U);
	zassert_equal(sreg.closed_count, 1U);
	zassert_equal(pqcp_edge_session_close(&sreg, &dir, s->session_id, 0,
		T0 + 41U), -EALREADY);
	zassert_equal(sreg.closed_count, 1U);
	/* Accounting on a closed session is refused and changes nothing. */
	zassert_equal(pqcp_edge_session_account(&sreg, s->session_id, 9U,
		9U, true, T0 + 42U), -ENOTCONN);
	zassert_equal(s->bytes_sent, 150U);
}

ZTEST(edge_security, test_session_failure_budget_and_expiry)
{
	struct pqcp_edge_session *s;
	struct pqcp_edge_session *s2;

	session_setup(4U);
	s = open_session(T0, 5000U);
	for (uint32_t i = 0U; i < 5U; ++i) {
		zassert_equal(s->state, PQCP_EDGE_SESSION_ACTIVE);
		zassert_equal(pqcp_edge_session_account(&sreg, s->session_id,
			0U, 0U, false, T0 + i), 0);
	}
	zassert_equal(s->state, PQCP_EDGE_SESSION_FAILED);
	zassert_equal(pqcp_edge_session_account(&sreg, s->session_id, 1U,
		1U, true, T0 + 10U), -ENOTCONN);

	/* Expiry observed via accounting moves the session to DRAINING. */
	s2 = open_session(T0, 1000U);
	zassert_equal(pqcp_edge_session_account(&sreg, s2->session_id, 1U,
		1U, true, T0 + 1000U), -ETIMEDOUT);
	zassert_equal(s2->state, PQCP_EDGE_SESSION_DRAINING);
	zassert_equal(s2->bytes_sent, 0U);
	zassert_equal(pqcp_edge_session_account(&sreg, s2->session_id, 1U,
		1U, true, T0 + 1001U), -ENOTCONN);
}

ZTEST(edge_security, test_session_rekey_and_tick)
{
	struct pqcp_edge_session *s;
	uint32_t changed = 0U;

	session_setup(4U);
	s = open_session(T0, 500000U);

	zassert_equal(pqcp_edge_session_require_rekey(&sreg, s->session_id,
		1U), -ESTALE);
	zassert_equal(s->state, PQCP_EDGE_SESSION_ACTIVE);
	zassert_equal(s->key_epoch, 1U);
	zassert_equal(pqcp_edge_session_require_rekey(&sreg, s->session_id,
		2U), 0);
	zassert_equal(s->state, PQCP_EDGE_SESSION_REKEY_REQUIRED);
	zassert_equal(s->key_epoch, 2U);
	zassert_equal(pqcp_edge_session_require_rekey(&sreg, s->session_id,
		3U), -EALREADY);
	zassert_equal(s->key_epoch, 2U);
	/* Traffic is still accepted while the rekey is outstanding. */
	zassert_equal(pqcp_edge_session_account(&sreg, s->session_id, 1U,
		1U, true, T0 + 100U), 0);

	zassert_equal(pqcp_edge_session_tick(&sreg, T0 + 60000U,
					     &changed), 0);
	zassert_equal(changed, 0U);
	/* An unanswered rekey request fails the session. */
	zassert_equal(pqcp_edge_session_tick(&sreg, T0 + 60101U,
					     &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(s->state, PQCP_EDGE_SESSION_FAILED);

	s = open_session(T0 + 200000U, 1000U);
	zassert_equal(pqcp_edge_session_tick(&sreg, T0 + 201000U,
					     &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(s->state, PQCP_EDGE_SESSION_DRAINING);
}

ZTEST(edge_security, test_session_registry_audit_detects_corruption)
{
	struct pqcp_edge_session *s;

	session_setup(4U);
	s = open_session(T0, 5000U);
	zassert_equal(pqcp_edge_session_registry_audit(&sreg), 0);
	memset(s->binding_digest, 0, sizeof(s->binding_digest));
	zassert_equal(pqcp_edge_session_registry_audit(&sreg), -EBADMSG);
	edge_digest(s->binding_digest, 1U);
	sess_store[1] = sess_store[0];
	zassert_equal(pqcp_edge_session_registry_audit(&sreg), -EEXIST);
}

ZTEST(edge_security, test_session_double_close_keeps_principal_count)
{
	struct pqcp_edge_session *s1;
	struct pqcp_edge_principal *p = NULL;
	int ret;

	session_setup(4U);
	zassert_equal(pqcp_edge_principal_find(&dir, "p1", &p), 0);
	s1 = open_session(T0, 5000U);
	(void)open_session(T0 + 1U, 5000U);
	zassert_equal(p->active_sessions, 2U);

	zassert_equal(pqcp_edge_session_close(&sreg, &dir, s1->session_id,
		-EIO, T0 + 10U), 0);
	zassert_equal(s1->state, PQCP_EDGE_SESSION_FAILED);
	zassert_equal(p->active_sessions, 1U);

	ret = pqcp_edge_session_close(&sreg, &dir, s1->session_id, 0,
				      T0 + 11U);
	BUG_EXPECT(ret == -EALREADY && p->active_sessions == 1U,
		   "edge_session_registry.c pqcp_edge_session_close: closing "
		   "a session that is already FAILED is accepted and "
		   "decrements the principal's active_sessions a second time "
		   "(only CLOSED is treated as already-closed), so another "
		   "live session stops being counted against the quota");
	zassert_equal(ret, -EALREADY);
}

ZTEST(edge_security, test_session_closed_slots_are_reclaimable)
{
	struct pqcp_edge_session *s;
	struct pqcp_edge_route r = make_route(900000U);
	struct pqcp_edge_session *extra = NULL;
	int ret;

	session_setup(4U);
	for (int i = 0; i < 2; ++i) {
		s = open_session(T0 + i, 5000U);
		zassert_equal(pqcp_edge_session_close(&sreg, &dir,
			s->session_id, 0, T0 + 10U), 0);
	}
	ret = pqcp_edge_session_open(&sreg, &dir, &r, binding, true,
				     T0 + 20U, 5000U, &extra);
	BUG_EXPECT(ret == 0,
		   "edge_session_registry.c: CLOSED/FAILED sessions keep "
		   "occupied=true forever (neither pqcp_edge_session_close nor "
		   "pqcp_edge_session_tick frees the slot), so a registry of "
		   "capacity N permanently refuses new sessions with -ENOSPC "
		   "after N lifetime sessions");
	zassert_equal(ret, 0);
}

/* ------------------------------------------------------------------ */
/* Traffic governor                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_traffic_subject tstore[2];
static struct pqcp_edge_traffic_governor gov;

static struct pqcp_edge_traffic_policy good_traffic_policy(void)
{
	struct pqcp_edge_traffic_policy policy = {
		.request_rate_per_window = 3U,
		.byte_rate_per_window = 100U,
		.window_ms = 1000U,
		.maximum_concurrent = 2U,
		.burst_requests = 1U,
		.failure_penalty = 600U,
		.recovery_credit = 200U,
	};

	return policy;
}

static void traffic_setup(void)
{
	struct pqcp_edge_traffic_policy policy = good_traffic_policy();

	zassert_equal(pqcp_edge_traffic_governor_init(
		&gov, &policy, tstore, ARRAY_SIZE(tstore)), 0);
}

ZTEST(edge_security, test_traffic_rejects_invalid_arguments)
{
	static struct pqcp_edge_traffic_governor raw;
	struct pqcp_edge_traffic_policy policy = good_traffic_policy();
	struct pqcp_edge_traffic_policy bad;
	uint32_t refilled = 0U;
	char unterminated[PQCP_EDGE_ID_MAX_CHARS];

	zassert_equal(pqcp_edge_traffic_governor_init(
		NULL, &policy, tstore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_traffic_governor_init(
		&gov, NULL, tstore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_traffic_governor_init(
		&gov, &policy, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_traffic_governor_init(
		&gov, &policy, tstore, 0U), -EINVAL);
	bad = policy; bad.request_rate_per_window = 0U;
	zassert_equal(pqcp_edge_traffic_governor_init(
		&gov, &bad, tstore, 2U), -EINVAL);
	bad = policy; bad.byte_rate_per_window = 0U;
	zassert_equal(pqcp_edge_traffic_governor_init(
		&gov, &bad, tstore, 2U), -EINVAL);
	bad = policy; bad.window_ms = 0U;
	zassert_equal(pqcp_edge_traffic_governor_init(
		&gov, &bad, tstore, 2U), -EINVAL);
	bad = policy; bad.maximum_concurrent = 0U;
	zassert_equal(pqcp_edge_traffic_governor_init(
		&gov, &bad, tstore, 2U), -EINVAL);
	bad = policy; bad.burst_requests = 0U;
	zassert_equal(pqcp_edge_traffic_governor_init(
		&gov, &bad, tstore, 2U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_traffic_authorize(&raw, "p", "s", 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_traffic_complete(&raw, "p", "s", true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_traffic_block(&raw, "p", "s", 5U), -EINVAL);
	zassert_equal(pqcp_edge_traffic_tick(&raw, T0, &refilled), -EINVAL);
	zassert_equal(pqcp_edge_traffic_governor_audit(&raw), -EINVAL);

	traffic_setup();
	memset(unterminated, 'x', sizeof(unterminated));
	zassert_equal(pqcp_edge_traffic_authorize(&gov, NULL, "s", 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", NULL, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "", "s", 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, unterminated, "s",
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 0U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_traffic_complete(&gov, NULL, "s", true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_traffic_complete(&gov, "p", "s", true, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_traffic_block(&gov, "p", "s", 0U), -EINVAL);
	zassert_equal(pqcp_edge_traffic_block(&gov, "p", "s", 5U), -ENOENT);
	zassert_equal(pqcp_edge_traffic_tick(&gov, T0, NULL), -EINVAL);
	zassert_false(tstore[0].occupied);
	zassert_equal(pqcp_edge_traffic_governor_audit(&gov), 0);
}

ZTEST(edge_security, test_traffic_limits_and_refill)
{
	uint32_t refilled = 0U;

	traffic_setup();
	/* Initial budget: 4 requests (rate + burst) and 100 bytes. */
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 40U, T0), 0);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 40U, T0), 0);
	zassert_equal(tstore[0].concurrent, 2U);
	zassert_equal(tstore[0].request_tokens, 2U);
	zassert_equal(tstore[0].byte_tokens, 20U);

	/* Concurrency cap: refused without consuming tokens. */
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 1U, T0),
		      -EDQUOT);
	zassert_equal(tstore[0].request_tokens, 2U);
	zassert_equal(tstore[0].byte_tokens, 20U);
	zassert_equal(tstore[0].rejected_requests, 1U);
	zassert_equal(tstore[0].accepted_requests, 2U);

	zassert_equal(pqcp_edge_traffic_complete(&gov, "p", "s", true, T0),
		      0);
	zassert_equal(pqcp_edge_traffic_complete(&gov, "p", "s", true, T0),
		      0);
	zassert_equal(pqcp_edge_traffic_complete(&gov, "p", "s", true, T0),
		      -EALREADY);

	/* Byte budget exhausted (20 left) although requests remain. */
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 40U, T0),
		      -EAGAIN);
	zassert_equal(tstore[0].byte_tokens, 20U);
	zassert_equal(tstore[0].concurrent, 0U);

	/* Refill is clamped: bytes to the rate, requests to rate + burst. */
	zassert_equal(pqcp_edge_traffic_tick(&gov, T0 + 999U, &refilled), 0);
	zassert_equal(refilled, 0U);
	zassert_equal(pqcp_edge_traffic_tick(&gov, T0 + 5000U, &refilled), 0);
	zassert_equal(refilled, 1U);
	zassert_equal(tstore[0].byte_tokens, 100U);
	zassert_equal(tstore[0].request_tokens, 4U);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 100U,
		T0 + 5000U), 0);
	zassert_equal(pqcp_edge_traffic_governor_audit(&gov), 0);
}

ZTEST(edge_security, test_traffic_failures_block_then_decay)
{
	uint32_t refilled = 0U;

	traffic_setup();
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 1U, T0), 0);
	zassert_equal(pqcp_edge_traffic_complete(&gov, "p", "s", false, T0),
		      0);
	zassert_equal(tstore[0].failure_score, 600U);
	zassert_equal(tstore[0].blocked_until_ms, 0U);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 1U, T0), 0);
	zassert_equal(pqcp_edge_traffic_complete(&gov, "p", "s", false, T0),
		      0);
	zassert_equal(tstore[0].failure_score, 1200U);
	zassert_equal(tstore[0].blocked_until_ms, T0 + 1000U);

	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 1U,
		T0 + 999U), -EACCES);
	zassert_equal(pqcp_edge_traffic_tick(&gov, T0 + 1000U, &refilled), 0);
	zassert_equal(tstore[0].blocked_until_ms, 0U);
	zassert_equal(tstore[0].failure_score, 600U);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 1U,
		T0 + 1000U), 0);

	/* Success earns recovery credit and floors at zero. */
	zassert_equal(pqcp_edge_traffic_complete(&gov, "p", "s", true,
		T0 + 1001U), 0);
	zassert_equal(tstore[0].failure_score, 400U);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p", "s", 1U,
		T0 + 1002U), 0);
	zassert_equal(pqcp_edge_traffic_complete(&gov, "p", "s", true,
		T0 + 1003U), 0);
	zassert_equal(tstore[0].failure_score, 200U);
}

ZTEST(edge_security, test_traffic_explicit_block_and_capacity)
{
	traffic_setup();
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p1", "s", 1U, T0),
		      0);
	zassert_equal(pqcp_edge_traffic_block(&gov, "p1", "s", T0 + 5000U),
		      0);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p1", "s", 1U,
		T0 + 10U), -EACCES);
	/* Other principals are not affected by the block. */
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p2", "s", 1U,
		T0 + 10U), 0);
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p1", "s", 1U,
		T0 + 5000U), 0);

	/* Subject table is full: further identities are refused. */
	zassert_equal(pqcp_edge_traffic_authorize(&gov, "p3", "s", 1U,
		T0 + 10U), -ENOSPC);
	zassert_equal(pqcp_edge_traffic_governor_audit(&gov), 0);

	tstore[0].concurrent = 99U;
	zassert_equal(pqcp_edge_traffic_governor_audit(&gov), -EBADMSG);
	tstore[0].concurrent = 1U;
	tstore[1] = tstore[0];
	zassert_equal(pqcp_edge_traffic_governor_audit(&gov), -EEXIST);
}

/* ------------------------------------------------------------------ */
/* Circuit breaker                                                     */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_circuit cstore[2];
static struct pqcp_edge_circuit_breaker cb;

static void circuit_setup(void)
{
	struct pqcp_edge_circuit_policy policy = {
		.open_after_failures = 2U,
		.close_after_successes = 2U,
		.half_open_maximum = 2U,
		.base_retry_ms = 1000U,
		.maximum_retry_ms = 4000U,
	};

	zassert_equal(pqcp_edge_circuit_breaker_init(
		&cb, &policy, cstore, ARRAY_SIZE(cstore)), 0);
}

ZTEST(edge_security, test_circuit_rejects_invalid_arguments)
{
	static struct pqcp_edge_circuit_breaker raw;
	struct pqcp_edge_circuit_policy ok = {
		.open_after_failures = 2U, .close_after_successes = 2U,
		.half_open_maximum = 2U, .base_retry_ms = 1000U,
		.maximum_retry_ms = 4000U,
	};
	struct pqcp_edge_circuit_policy bad;
	uint32_t changed = 0U;
	char unterminated[PQCP_EDGE_ID_MAX_CHARS];

	zassert_equal(pqcp_edge_circuit_breaker_init(
		NULL, &ok, cstore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_circuit_breaker_init(
		&cb, NULL, cstore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_circuit_breaker_init(
		&cb, &ok, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_circuit_breaker_init(
		&cb, &ok, cstore, 0U), -EINVAL);
	bad = ok; bad.open_after_failures = 0U;
	zassert_equal(pqcp_edge_circuit_breaker_init(
		&cb, &bad, cstore, 2U), -EINVAL);
	bad = ok; bad.close_after_successes = 0U;
	zassert_equal(pqcp_edge_circuit_breaker_init(
		&cb, &bad, cstore, 2U), -EINVAL);
	bad = ok; bad.half_open_maximum = 0U;
	zassert_equal(pqcp_edge_circuit_breaker_init(
		&cb, &bad, cstore, 2U), -EINVAL);
	bad = ok; bad.base_retry_ms = 0U;
	zassert_equal(pqcp_edge_circuit_breaker_init(
		&cb, &bad, cstore, 2U), -EINVAL);
	bad = ok; bad.maximum_retry_ms = 999U;
	zassert_equal(pqcp_edge_circuit_breaker_init(
		&cb, &bad, cstore, 2U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_circuit_allow(&raw, "s", "e", T0), -EINVAL);
	zassert_equal(pqcp_edge_circuit_record(&raw, "s", "e", true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_circuit_isolate(&raw, "s", "e"), -EINVAL);
	zassert_equal(pqcp_edge_circuit_reset(&raw, "s", "e", T0), -EINVAL);
	zassert_equal(pqcp_edge_circuit_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_circuit_breaker_audit(&raw), -EINVAL);

	circuit_setup();
	memset(unterminated, 'x', sizeof(unterminated));
	zassert_equal(pqcp_edge_circuit_allow(&cb, NULL, "e", T0), -EINVAL);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", NULL, T0), -EINVAL);
	zassert_equal(pqcp_edge_circuit_allow(&cb, unterminated, "e", T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_circuit_record(&cb, NULL, "e", true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_circuit_record(&cb, "s", "e", true, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_circuit_isolate(&cb, "s", "e"), -ENOENT);
	zassert_equal(pqcp_edge_circuit_reset(&cb, "s", "e", T0), -ENOENT);
	zassert_equal(pqcp_edge_circuit_tick(&cb, T0, NULL), -EINVAL);
	zassert_false(cstore[0].occupied);
}

ZTEST(edge_security, test_circuit_trip_halfopen_and_recovery)
{
	uint32_t changed = 0U;

	circuit_setup();
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0), 0);
	zassert_equal(pqcp_edge_circuit_record(&cb, "s", "e", false, T0), 0);
	zassert_equal(cstore[0].state, PQCP_EDGE_CIRCUIT_CLOSED);
	zassert_equal(pqcp_edge_circuit_record(&cb, "s", "e", false, T0), 0);
	zassert_equal(cstore[0].state, PQCP_EDGE_CIRCUIT_OPEN);
	zassert_equal(cstore[0].retry_at_ms, T0 + 1000U);
	zassert_equal(cstore[0].total_opens, 1U);

	/* Open circuit fails fast until the retry deadline. */
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0 + 999U),
		      -EHOSTDOWN);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0 + 1000U), 0);
	zassert_equal(cstore[0].state, PQCP_EDGE_CIRCUIT_HALF_OPEN);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0 + 1001U), 0);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0 + 1002U),
		      -EAGAIN);

	/* A failed probe reopens with doubled backoff. */
	zassert_equal(pqcp_edge_circuit_record(&cb, "s", "e", false,
		T0 + 1003U), 0);
	zassert_equal(cstore[0].state, PQCP_EDGE_CIRCUIT_OPEN);
	zassert_equal(cstore[0].total_opens, 2U);
	zassert_equal(cstore[0].retry_at_ms, T0 + 1003U + 2000U);

	zassert_equal(pqcp_edge_circuit_tick(&cb, T0 + 2000U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(pqcp_edge_circuit_tick(&cb, T0 + 3003U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(cstore[0].state, PQCP_EDGE_CIRCUIT_HALF_OPEN);

	zassert_equal(pqcp_edge_circuit_record(&cb, "s", "e", true,
		T0 + 3004U), 0);
	zassert_equal(cstore[0].state, PQCP_EDGE_CIRCUIT_HALF_OPEN);
	zassert_equal(pqcp_edge_circuit_record(&cb, "s", "e", true,
		T0 + 3005U), 0);
	zassert_equal(cstore[0].state, PQCP_EDGE_CIRCUIT_CLOSED);
	zassert_equal(cstore[0].total_opens, 1U);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0 + 3006U), 0);
	zassert_equal(pqcp_edge_circuit_breaker_audit(&cb), 0);
}

ZTEST(edge_security, test_circuit_isolation_is_sticky_until_reset)
{
	uint32_t changed = 0U;

	circuit_setup();
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0), 0);
	zassert_equal(pqcp_edge_circuit_isolate(&cb, "s", "e"), 0);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0 + 1U),
		      -EACCES);
	zassert_equal(pqcp_edge_circuit_record(&cb, "s", "e", true, T0 + 1U),
		      -EACCES);
	zassert_equal(pqcp_edge_circuit_tick(&cb, T0 + 99999U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(cstore[0].state, PQCP_EDGE_CIRCUIT_ISOLATED);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0 + 99999U),
		      -EACCES);

	zassert_equal(pqcp_edge_circuit_reset(&cb, "s", "e", T0 + 100000U), 0);
	zassert_equal(cstore[0].state, PQCP_EDGE_CIRCUIT_CLOSED);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e", T0 + 100001U),
		      0);
}

ZTEST(edge_security, test_circuit_capacity_and_audit)
{
	circuit_setup();
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e1", T0), 0);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e2", T0), 0);
	/* New endpoints are refused once the table is full. */
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e3", T0), -ENOSPC);
	zassert_equal(pqcp_edge_circuit_allow(&cb, "s", "e1", T0 + 1U), 0);
	zassert_equal(pqcp_edge_circuit_breaker_audit(&cb), 0);

	/* Backoff is bounded by the policy maximum. */
	for (int i = 0; i < 8; ++i) {
		zassert_equal(pqcp_edge_circuit_record(&cb, "s", "e1", false,
			T0 + 10U + i), 0);
	}
	zassert_true(cstore[0].retry_at_ms <= T0 + 17U + 4000U);

	cstore[1].state = (enum pqcp_edge_circuit_state)9;
	zassert_equal(pqcp_edge_circuit_breaker_audit(&cb), -EBADMSG);
	cstore[1].state = PQCP_EDGE_CIRCUIT_CLOSED;
	cstore[1] = cstore[0];
	zassert_equal(pqcp_edge_circuit_breaker_audit(&cb), -EEXIST);
	cstore[1] = cstore[0];
	SETSTR(cstore[1].endpoint_id, "e2");
	cstore[0].state = PQCP_EDGE_CIRCUIT_OPEN;
	cstore[0].retry_at_ms = cstore[0].opened_at_ms;
	zassert_equal(pqcp_edge_circuit_breaker_audit(&cb), -EBADMSG);
}
