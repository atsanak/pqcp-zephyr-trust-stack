/*
 * SPDX-License-Identifier: MIT
 *
 * Governance plane: posture, attestation, policy distribution, rotation,
 * resource budgets, DLP, federation, credentials, isolation, provenance,
 * scheduling, SLOs and transactional configuration.
 */

#include "edge_security_internal.h"
#include "test_common.h"

/* ------------------------------------------------------------------ */
/* Posture engine                                                      */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_posture_report pstr[2];
static struct pqcp_edge_posture_engine pe;

static struct pqcp_edge_posture_policy posture_policy(void)
{
	struct pqcp_edge_posture_policy p = {
		.required_signal_mask = 0x7U,
		.quarantine_failure_mask = 0x1U,
		.challenge_failure_mask = 0x2U,
		.maximum_risk = 500U,
		.minimum_policy_epoch = 2U,
		.minimum_firmware_version = 5U,
		.maximum_age_ms = 1000U,
	};

	return p;
}

static void posture_setup(void)
{
	struct pqcp_edge_posture_policy p = posture_policy();

	zassert_equal(pqcp_edge_posture_engine_init(
		&pe, &p, pstr, ARRAY_SIZE(pstr)), 0);
}

static void make_report(struct pqcp_edge_posture_report *r, const char *id)
{
	memset(r, 0, sizeof(*r));
	SETSTR(r->principal_id, id);
	r->measured_at_ms = T0;
	r->expires_at_ms = T0 + 5000U;
	r->policy_epoch = 2U;
	r->firmware_version = 5U;
	r->signal_mask = 0x7U;
	r->risk_score = 100U;
	edge_digest(r->measurement_digest, 0x44U);
}

static int posture_eval(const char *id, uint64_t now,
			enum pqcp_edge_policy_effect *effect,
			uint32_t *failures, uint32_t *risk)
{
	return pqcp_edge_posture_evaluate(&pe, id, now, effect, failures,
					  risk);
}

ZTEST(edge_security, test_posture_rejects_invalid_arguments)
{
	static struct pqcp_edge_posture_engine raw;
	struct pqcp_edge_posture_policy p = posture_policy();
	struct pqcp_edge_posture_policy bad;
	struct pqcp_edge_posture_report r;
	enum pqcp_edge_policy_effect effect;
	uint32_t failures = 0U;
	uint32_t risk = 0U;
	uint32_t expired = 0U;

	zassert_equal(pqcp_edge_posture_engine_init(NULL, &p, pstr, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_posture_engine_init(&pe, NULL, pstr, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_posture_engine_init(&pe, &p, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_posture_engine_init(&pe, &p, pstr, 0U),
		      -EINVAL);
	bad = p; bad.required_signal_mask = 0U;
	zassert_equal(pqcp_edge_posture_engine_init(&pe, &bad, pstr, 2U),
		      -EINVAL);
	bad = p; bad.required_signal_mask = 1U << PQCP_EDGE_POSTURE_SIGNAL_COUNT;
	zassert_equal(pqcp_edge_posture_engine_init(&pe, &bad, pstr, 2U),
		      -EINVAL);
	bad = p; bad.quarantine_failure_mask = 1U << 20;
	zassert_equal(pqcp_edge_posture_engine_init(&pe, &bad, pstr, 2U),
		      -EINVAL);
	bad = p; bad.challenge_failure_mask = 1U << 20;
	zassert_equal(pqcp_edge_posture_engine_init(&pe, &bad, pstr, 2U),
		      -EINVAL);
	bad = p; bad.maximum_risk = 1001U;
	zassert_equal(pqcp_edge_posture_engine_init(&pe, &bad, pstr, 2U),
		      -EINVAL);
	bad = p; bad.minimum_policy_epoch = 0U;
	zassert_equal(pqcp_edge_posture_engine_init(&pe, &bad, pstr, 2U),
		      -EINVAL);
	bad = p; bad.maximum_age_ms = 0U;
	zassert_equal(pqcp_edge_posture_engine_init(&pe, &bad, pstr, 2U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_report(&r, "p1");
	zassert_equal(pqcp_edge_posture_submit(&raw, &r, T0), -EINVAL);
	zassert_equal(pqcp_edge_posture_evaluate(&raw, "p1", T0, &effect,
		&failures, &risk), -EINVAL);
	zassert_equal(pqcp_edge_posture_expire(&raw, T0, &expired), -EINVAL);
	zassert_equal(pqcp_edge_posture_engine_audit(&raw), -EINVAL);

	posture_setup();
#define BAD_REPORT(mut)                                                  \
	do {                                                             \
		make_report(&r, "p1");                                   \
		mut;                                                     \
		zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0),     \
			      -EINVAL, #mut);                            \
	} while (0)
	BAD_REPORT(r.principal_id[0] = '\0');
	BAD_REPORT(r.expires_at_ms = r.measured_at_ms);
	BAD_REPORT(r.policy_epoch = 0U);
	BAD_REPORT(r.signal_mask = 1U << 20);
	BAD_REPORT(r.failure_mask = 0x8U);
	BAD_REPORT(r.risk_score = 1001U);
	BAD_REPORT(memset(r.measurement_digest, 0,
			  sizeof(r.measurement_digest)));
	BAD_REPORT(r.measured_at_ms = T0 + 1U);
	BAD_REPORT(r.expires_at_ms = T0);
#undef BAD_REPORT
	zassert_equal(pqcp_edge_posture_submit(&pe, NULL, T0), -EINVAL);
	zassert_equal(pe.accepted_count, 0U);
	zassert_equal(pqcp_edge_posture_evaluate(&pe, NULL, T0, &effect,
		&failures, &risk), -EINVAL);
	zassert_equal(pqcp_edge_posture_evaluate(&pe, "p1", T0, NULL,
		&failures, &risk), -EINVAL);
	zassert_equal(pqcp_edge_posture_evaluate(&pe, "p1", T0, &effect,
		NULL, &risk), -EINVAL);
	zassert_equal(pqcp_edge_posture_evaluate(&pe, "p1", T0, &effect,
		&failures, NULL), -EINVAL);
	zassert_equal(pqcp_edge_posture_expire(&pe, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_posture_engine_audit(&pe), 0);
}

ZTEST(edge_security, test_posture_unknown_principal_gets_challenge)
{
	enum pqcp_edge_policy_effect effect = PQCP_EDGE_POLICY_ALLOW;
	uint32_t failures = 0U;
	uint32_t risk = 0U;

	posture_setup();
	zassert_equal(posture_eval("ghost", T0, &effect, &failures, &risk),
		      -ENOENT);
	zassert_equal(effect, PQCP_EDGE_POLICY_CHALLENGE);
	zassert_equal(failures, 0x7U);
	zassert_equal(risk, 1000U);
}

ZTEST(edge_security, test_posture_effect_ladder)
{
	struct pqcp_edge_posture_report r;
	enum pqcp_edge_policy_effect effect;
	uint32_t failures;
	uint32_t risk;

	posture_setup();
	make_report(&r, "p1");
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0), 0);
	zassert_equal(posture_eval("p1", T0 + 10U, &effect, &failures, &risk),
		      0);
	zassert_equal(effect, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(failures, 0U);
	zassert_equal(risk, 100U);

	/* Required signal missing but in no escalation mask: deny. */
	r.measured_at_ms = T0 + 20U;
	r.signal_mask = 0x3U;
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0 + 20U), 0);
	zassert_equal(posture_eval("p1", T0 + 30U, &effect, &failures, &risk),
		      -EACCES);
	zassert_equal(effect, PQCP_EDGE_POLICY_DENY);
	zassert_equal(failures, 0x4U);

	/* Critical failure (secure boot) quarantines. */
	r.measured_at_ms = T0 + 40U;
	r.signal_mask = 0x7U;
	r.failure_mask = 0x1U;
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0 + 40U), 0);
	zassert_equal(posture_eval("p1", T0 + 50U, &effect, &failures, &risk),
		      -EACCES);
	zassert_equal(effect, PQCP_EDGE_POLICY_QUARANTINE);

	/* Soft failure challenges; quarantine takes precedence over it. */
	r.measured_at_ms = T0 + 60U;
	r.failure_mask = 0x2U;
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0 + 60U), 0);
	zassert_equal(posture_eval("p1", T0 + 70U, &effect, &failures, &risk),
		      -EAGAIN);
	zassert_equal(effect, PQCP_EDGE_POLICY_CHALLENGE);
	r.measured_at_ms = T0 + 80U;
	r.failure_mask = 0x3U;
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0 + 80U), 0);
	zassert_equal(posture_eval("p1", T0 + 90U, &effect, &failures, &risk),
		      -EACCES);
	zassert_equal(effect, PQCP_EDGE_POLICY_QUARANTINE);

	/* High risk alone challenges. */
	r.measured_at_ms = T0 + 100U;
	r.failure_mask = 0U;
	r.risk_score = 501U;
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0 + 100U), 0);
	zassert_equal(posture_eval("p1", T0 + 110U, &effect, &failures,
		&risk), -EAGAIN);
	zassert_equal(effect, PQCP_EDGE_POLICY_CHALLENGE);
	zassert_equal(risk, 501U);
}

ZTEST(edge_security, test_posture_stale_evidence_is_challenged)
{
	struct pqcp_edge_posture_report r;
	enum pqcp_edge_policy_effect effect;
	uint32_t failures;
	uint32_t risk;

	posture_setup();
	make_report(&r, "p1");
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0), 0);
	/* Older than maximum_age_ms. */
	zassert_equal(posture_eval("p1", T0 + 1001U, &effect, &failures,
		&risk), -ESTALE);
	zassert_equal(effect, PQCP_EDGE_POLICY_CHALLENGE);
	zassert_equal(posture_eval("p1", T0 + 1000U, &effect, &failures,
		&risk), 0);
	/* Report expiry, firmware and policy epoch floors. */
	pstr[0].expires_at_ms = T0 + 500U;
	zassert_equal(posture_eval("p1", T0 + 500U, &effect, &failures,
		&risk), -ESTALE);
	pstr[0].expires_at_ms = T0 + 5000U;
	pstr[0].firmware_version = 4U;
	zassert_equal(posture_eval("p1", T0 + 10U, &effect, &failures,
		&risk), -ESTALE);
	pstr[0].firmware_version = 5U;
	pstr[0].policy_epoch = 1U;
	zassert_equal(posture_eval("p1", T0 + 10U, &effect, &failures,
		&risk), -ESTALE);
}

ZTEST(edge_security, test_posture_submission_monotonicity_capacity_and_audit)
{
	struct pqcp_edge_posture_report r;
	struct pqcp_edge_posture_report snap;
	uint32_t expired = 0U;

	posture_setup();
	make_report(&r, "p1");
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0), 0);
	snap = pstr[0];
	/* Replaying an equal or older measurement is refused. */
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0), -ESTALE);
	r.measured_at_ms = T0 - 1U;
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0), -ESTALE);
	zassert_mem_equal(&pstr[0], &snap, sizeof(snap));
	zassert_equal(pe.rejected_count, 2U);
	zassert_equal(pe.accepted_count, 1U);

	make_report(&r, "p2");
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0), 0);
	make_report(&r, "p3");
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0), -ENOSPC);
	zassert_equal(pe.rejected_count, 3U);

	zassert_equal(pqcp_edge_posture_expire(&pe, T0 + 4999U, &expired), 0);
	zassert_equal(expired, 0U);
	zassert_equal(pqcp_edge_posture_expire(&pe, T0 + 5000U, &expired), 0);
	zassert_equal(expired, 2U);
	zassert_equal(pqcp_edge_posture_engine_audit(&pe), 0);

	make_report(&r, "p1");
	zassert_equal(pqcp_edge_posture_submit(&pe, &r, T0), 0);
	pstr[0].risk_score = 5000U;
	zassert_equal(pqcp_edge_posture_engine_audit(&pe), -EBADMSG);
	pstr[0].risk_score = 100U;
	pstr[1] = pstr[0];
	zassert_equal(pqcp_edge_posture_engine_audit(&pe), -EEXIST);
}

/* ------------------------------------------------------------------ */
/* Attestation manager                                                 */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_attestation_record atstore[2];
static struct pqcp_edge_attestation_manager am;

static void attest_setup(void)
{
	zassert_equal(pqcp_edge_attestation_manager_init(
		&am, atstore, ARRAY_SIZE(atstore)), 0);
}

static struct pqcp_edge_attestation_record *challenge(
	const char *id, uint8_t nonce_seed, uint64_t now, uint64_t expires)
{
	uint8_t nonce[PQCP_EDGE_NONCE_BYTES];
	uint8_t binding[PQCP_EDGE_DIGEST_BYTES];
	struct pqcp_edge_attestation_record *r = NULL;

	memset(nonce, nonce_seed, sizeof(nonce));
	edge_digest(binding, 0x66U);
	zassert_equal(pqcp_edge_attestation_challenge(&am, id, nonce,
		binding, 0x7U, now, expires, &r), 0);
	return r;
}

ZTEST(edge_security, test_attestation_rejects_invalid_arguments)
{
	static struct pqcp_edge_attestation_manager raw;
	uint8_t nonce[PQCP_EDGE_NONCE_BYTES] = { 1 };
	uint8_t zero_nonce[PQCP_EDGE_NONCE_BYTES] = { 0 };
	uint8_t binding[PQCP_EDGE_DIGEST_BYTES];
	uint8_t zero[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	struct pqcp_edge_attestation_record *r = (void *)0x1;
	bool fresh = true;
	uint32_t expired = 0U;

	edge_digest(binding, 1U);
	zassert_equal(pqcp_edge_attestation_manager_init(NULL, atstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_attestation_manager_init(&am, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_attestation_manager_init(&am, atstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_attestation_challenge(&raw, "p", nonce,
		binding, 1U, T0, T0 + 10U, &r), -EINVAL);
	zassert_equal(pqcp_edge_attestation_submit(&raw, 1U, 1U, binding,
		binding, T0), -EINVAL);
	zassert_equal(pqcp_edge_attestation_is_fresh(&raw, "p", T0, &fresh),
		      -EINVAL);
	zassert_equal(pqcp_edge_attestation_expire(&raw, T0, &expired),
		      -EINVAL);
	zassert_equal(pqcp_edge_attestation_manager_audit(&raw), -EINVAL);

	attest_setup();
	zassert_equal(pqcp_edge_attestation_challenge(&am, NULL, nonce,
		binding, 1U, T0, T0 + 10U, &r), -EINVAL);
	zassert_equal(pqcp_edge_attestation_challenge(&am, "", nonce,
		binding, 1U, T0, T0 + 10U, &r), -EINVAL);
	zassert_equal(pqcp_edge_attestation_challenge(&am, "p", NULL,
		binding, 1U, T0, T0 + 10U, &r), -EINVAL);
	zassert_equal(pqcp_edge_attestation_challenge(&am, "p", zero_nonce,
		binding, 1U, T0, T0 + 10U, &r), -EINVAL);
	zassert_equal(pqcp_edge_attestation_challenge(&am, "p", nonce, NULL,
		1U, T0, T0 + 10U, &r), -EINVAL);
	zassert_equal(pqcp_edge_attestation_challenge(&am, "p", nonce, zero,
		1U, T0, T0 + 10U, &r), -EINVAL);
	zassert_equal(pqcp_edge_attestation_challenge(&am, "p", nonce,
		binding, 0U, T0, T0 + 10U, &r), -EINVAL);
	zassert_equal(pqcp_edge_attestation_challenge(&am, "p", nonce,
		binding, 1U, T0, T0, &r), -EINVAL);
	zassert_equal(pqcp_edge_attestation_challenge(&am, "p", nonce,
		binding, 1U, T0, T0 + 10U, NULL), -EINVAL);
	zassert_false(atstore[0].occupied);

	zassert_equal(pqcp_edge_attestation_submit(&am, 0U, 1U, binding,
		binding, T0), -EINVAL);
	zassert_equal(pqcp_edge_attestation_submit(&am, 1U, 1U, NULL,
		binding, T0), -EINVAL);
	zassert_equal(pqcp_edge_attestation_submit(&am, 1U, 1U, zero,
		binding, T0), -EINVAL);
	zassert_equal(pqcp_edge_attestation_submit(&am, 1U, 1U, binding,
		NULL, T0), -EINVAL);
	zassert_equal(pqcp_edge_attestation_submit(&am, 9U, 1U, binding,
		binding, T0), -ENOENT);
	zassert_equal(am.rejected_count, 1U);
	zassert_equal(pqcp_edge_attestation_is_fresh(&am, NULL, T0, &fresh),
		      -EINVAL);
	zassert_equal(pqcp_edge_attestation_is_fresh(&am, "p", T0, NULL),
		      -EINVAL);
	zassert_equal(pqcp_edge_attestation_is_fresh(&am, "p", T0, &fresh),
		      -ENOENT);
	zassert_false(fresh);
	zassert_equal(pqcp_edge_attestation_expire(&am, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_attestation_manager_audit(&am), 0);
}

ZTEST(edge_security, test_attestation_requires_matching_binding_and_posture)
{
	struct pqcp_edge_attestation_record *r;
	uint8_t binding[PQCP_EDGE_DIGEST_BYTES];
	uint8_t wrong[PQCP_EDGE_DIGEST_BYTES];
	uint8_t evidence[PQCP_EDGE_DIGEST_BYTES];
	bool fresh = false;

	attest_setup();
	edge_digest(binding, 0x66U);
	edge_digest(wrong, 0x67U);
	edge_digest(evidence, 0x70U);

	/* Nothing is trusted before a verified response. */
	r = challenge("p1", 0xa1U, T0, T0 + 1000U);
	zassert_equal(r->state, PQCP_EDGE_ATTESTATION_CHALLENGED);
	zassert_equal(pqcp_edge_attestation_is_fresh(&am, "p1", T0 + 1U,
		&fresh), -ENOENT);

	/* A response bound to the wrong channel is rejected for good. */
	zassert_equal(pqcp_edge_attestation_submit(&am, r->challenge_id,
		0x7U, evidence, wrong, T0 + 1U), -EKEYREJECTED);
	zassert_equal(r->state, PQCP_EDGE_ATTESTATION_REJECTED);
	zassert_equal(pqcp_edge_attestation_submit(&am, r->challenge_id,
		0x7U, evidence, binding, T0 + 2U), -EALREADY);
	zassert_equal(r->state, PQCP_EDGE_ATTESTATION_REJECTED);
	zassert_equal(pqcp_edge_attestation_is_fresh(&am, "p1", T0 + 3U,
		&fresh), -ENOENT);

	/* Insufficient posture is rejected even with a valid binding. */
	r = challenge("p1", 0xa2U, T0 + 10U, T0 + 1000U);
	zassert_equal(pqcp_edge_attestation_submit(&am, r->challenge_id,
		0x3U, evidence, binding, T0 + 11U), -EKEYREJECTED);
	zassert_equal(r->state, PQCP_EDGE_ATTESTATION_REJECTED);
	zassert_equal(am.verified_count, 0U);
	zassert_equal(am.rejected_count, 3U);
}

ZTEST(edge_security, test_attestation_success_freshness_and_replay)
{
	struct pqcp_edge_attestation_record *r;
	uint8_t binding[PQCP_EDGE_DIGEST_BYTES];
	uint8_t evidence[PQCP_EDGE_DIGEST_BYTES];
	uint8_t nonce[PQCP_EDGE_NONCE_BYTES];
	struct pqcp_edge_attestation_record *dup = (void *)0x1;
	bool fresh = false;
	uint32_t expired = 0U;

	attest_setup();
	edge_digest(binding, 0x66U);
	edge_digest(evidence, 0x70U);
	r = challenge("p1", 0xa1U, T0, T0 + 1000U);
	zassert_equal(pqcp_edge_attestation_submit(&am, r->challenge_id,
		0xffU, evidence, binding, T0 + 5U), 0);
	zassert_equal(r->state, PQCP_EDGE_ATTESTATION_VERIFIED);
	zassert_equal(r->verified_at_ms, T0 + 5U);
	zassert_equal(am.verified_count, 1U);
	zassert_equal(pqcp_edge_attestation_is_fresh(&am, "p1", T0 + 6U,
		&fresh), 0);
	zassert_true(fresh);
	zassert_equal(pqcp_edge_attestation_is_fresh(&am, "other", T0 + 6U,
		&fresh), -ENOENT);
	zassert_false(fresh);
	/* Attestation of one principal never vouches for another. */
	zassert_equal(pqcp_edge_attestation_is_fresh(&am, "p1", T0 + 1000U,
		&fresh), -ENOENT);

	/* A verified challenge cannot be answered twice. */
	zassert_equal(pqcp_edge_attestation_submit(&am, r->challenge_id,
		0xffU, evidence, binding, T0 + 7U), -EALREADY);
	/* Nonces are single use, even for another principal. */
	memset(nonce, 0xa1, sizeof(nonce));
	zassert_equal(pqcp_edge_attestation_challenge(&am, "p2", nonce,
		binding, 0x7U, T0 + 8U, T0 + 900U, &dup), -EALREADY);
	zassert_is_null(dup);
	zassert_equal(pqcp_edge_attestation_manager_audit(&am), 0);

	/* Late answers are refused and the challenge expires. */
	r = challenge("p3", 0xa3U, T0 + 10U, T0 + 20U);
	zassert_equal(pqcp_edge_attestation_submit(&am, r->challenge_id,
		0xffU, evidence, binding, T0 + 20U), -ETIMEDOUT);
	zassert_equal(r->state, PQCP_EDGE_ATTESTATION_EXPIRED);

	/* Capacity: both records live until expiry frees one. */
	{
		uint8_t n2[PQCP_EDGE_NONCE_BYTES];
		struct pqcp_edge_attestation_record *full = (void *)0x1;

		memset(n2, 0xa9, sizeof(n2));
		zassert_equal(pqcp_edge_attestation_expire(&am, T0 + 1000U,
			&expired), 0);
		zassert_equal(expired, 1U);
		/* The verified record itself expired now as well. */
		zassert_equal(pqcp_edge_attestation_is_fresh(&am, "p1",
			T0 + 1000U, &fresh), -ENOENT);
		zassert_equal(pqcp_edge_attestation_challenge(&am, "p4", n2,
			binding, 0x7U, T0 + 1001U, T0 + 2000U, &full), 0);
	}
	zassert_equal(pqcp_edge_attestation_manager_audit(&am), 0);
}

ZTEST(edge_security, test_attestation_capacity_exhaustion_and_audit)
{
	struct pqcp_edge_attestation_record *a;
	struct pqcp_edge_attestation_record *full = (void *)0x1;
	struct pqcp_edge_attestation_record snap[2];
	uint8_t n[PQCP_EDGE_NONCE_BYTES];
	uint8_t binding[PQCP_EDGE_DIGEST_BYTES];

	attest_setup();
	edge_digest(binding, 0x66U);
	a = challenge("p1", 0x01U, T0, T0 + 1000U);
	(void)challenge("p2", 0x02U, T0, T0 + 1000U);
	memcpy(snap, atstore, sizeof(snap));
	memset(n, 0x03, sizeof(n));
	zassert_equal(pqcp_edge_attestation_challenge(&am, "p3", n, binding,
		0x7U, T0, T0 + 1000U, &full), -ENOSPC);
	zassert_is_null(full);
	zassert_mem_equal(atstore, snap, sizeof(snap));

	a->required_posture_mask = 0U;
	zassert_equal(pqcp_edge_attestation_manager_audit(&am), -EBADMSG);
	a->required_posture_mask = 7U;
	memset(a->nonce, 0, sizeof(a->nonce));
	zassert_equal(pqcp_edge_attestation_manager_audit(&am), -EBADMSG);
}

/* ------------------------------------------------------------------ */
/* Policy distributor                                                  */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_policy_bundle pbs[2];
static struct pqcp_edge_policy_ack pack[3];
static struct pqcp_edge_policy_distributor pd;
static uint8_t active_digest[PQCP_EDGE_DIGEST_BYTES];

static void policy_setup(size_t bundles)
{
	edge_digest(active_digest, 0x01U);
	zassert_equal(pqcp_edge_policy_distributor_init(
		&pd, pbs, bundles, pack, ARRAY_SIZE(pack), 1U,
		active_digest), 0);
}

static struct pqcp_edge_policy_bundle *stage_bundle(uint64_t epoch,
						    uint8_t digest_seed,
						    uint32_t acks)
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	struct pqcp_edge_policy_bundle *b = NULL;

	edge_digest(digest, digest_seed);
	zassert_equal(pqcp_edge_policy_stage(&pd, digest, epoch, T0, T0,
		T0 + 100000U, acks, 2U, &b), 0);
	return b;
}

ZTEST(edge_security, test_policy_rejects_invalid_arguments)
{
	static struct pqcp_edge_policy_distributor raw;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t zero[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	struct pqcp_edge_policy_bundle *b = (void *)0x1;

	edge_digest(digest, 5U);
	zassert_equal(pqcp_edge_policy_distributor_init(NULL, pbs, 2U, pack,
		3U, 1U, digest), -EINVAL);
	zassert_equal(pqcp_edge_policy_distributor_init(&pd, NULL, 2U, pack,
		3U, 1U, digest), -EINVAL);
	zassert_equal(pqcp_edge_policy_distributor_init(&pd, pbs, 0U, pack,
		3U, 1U, digest), -EINVAL);
	zassert_equal(pqcp_edge_policy_distributor_init(&pd, pbs, 2U, NULL,
		3U, 1U, digest), -EINVAL);
	zassert_equal(pqcp_edge_policy_distributor_init(&pd, pbs, 2U, pack,
		0U, 1U, digest), -EINVAL);
	zassert_equal(pqcp_edge_policy_distributor_init(&pd, pbs, 2U, pack,
		3U, 0U, digest), -EINVAL);
	zassert_equal(pqcp_edge_policy_distributor_init(&pd, pbs, 2U, pack,
		3U, 1U, NULL), -EINVAL);
	zassert_equal(pqcp_edge_policy_distributor_init(&pd, pbs, 2U, pack,
		3U, 1U, zero), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_policy_stage(&raw, digest, 2U, T0, T0,
		T0 + 10U, 1U, 1U, &b), -EINVAL);
	zassert_equal(pqcp_edge_policy_acknowledge(&raw, 1U, "p", digest, 0,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_policy_promote(&raw, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_policy_rollback(&raw, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_policy_distributor_audit(&raw), -EINVAL);

	policy_setup(2U);
	zassert_equal(pqcp_edge_policy_stage(&pd, NULL, 2U, T0, T0, T0 + 10U,
		1U, 1U, &b), -EINVAL);
	zassert_equal(pqcp_edge_policy_stage(&pd, zero, 2U, T0, T0, T0 + 10U,
		1U, 1U, &b), -EINVAL);
	/* The new epoch must exceed the active one. */
	zassert_equal(pqcp_edge_policy_stage(&pd, digest, 1U, T0, T0,
		T0 + 10U, 1U, 1U, &b), -EINVAL);
	zassert_equal(pqcp_edge_policy_stage(&pd, digest, 0U, T0, T0,
		T0 + 10U, 1U, 1U, &b), -EINVAL);
	zassert_equal(pqcp_edge_policy_stage(&pd, digest, 2U, T0, T0 - 1U,
		T0 + 10U, 1U, 1U, &b), -EINVAL);
	zassert_equal(pqcp_edge_policy_stage(&pd, digest, 2U, T0, T0, T0,
		1U, 1U, &b), -EINVAL);
	zassert_equal(pqcp_edge_policy_stage(&pd, digest, 2U, T0, T0,
		T0 + 10U, 0U, 1U, &b), -EINVAL);
	zassert_equal(pqcp_edge_policy_stage(&pd, digest, 2U, T0, T0,
		T0 + 10U, 1U, 0U, &b), -EINVAL);
	zassert_equal(pqcp_edge_policy_stage(&pd, digest, 2U, T0, T0,
		T0 + 10U, 1U, 1U, NULL), -EINVAL);
	zassert_false(pbs[0].occupied);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, 0U, "p", digest, 0,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, 1U, "", digest, 0,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, 1U, "p", NULL, 0,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, 9U, "p", digest, 0,
		T0), -ENOENT);
	zassert_equal(pqcp_edge_policy_promote(&pd, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_policy_promote(&pd, 9U, T0), -ENOENT);
	zassert_equal(pqcp_edge_policy_rollback(&pd, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_policy_rollback(&pd, 9U, T0), -ENOENT);
	zassert_equal(pqcp_edge_policy_distributor_audit(&pd), 0);
}

ZTEST(edge_security, test_policy_staged_rollout_requires_acknowledgements)
{
	struct pqcp_edge_policy_bundle *b;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t other[PQCP_EDGE_DIGEST_BYTES];
	struct pqcp_edge_policy_bundle *dup = NULL;
	uint64_t id;

	policy_setup(2U);
	b = stage_bundle(5U, 0x55U, 2U);
	id = b->bundle_id;
	edge_digest(digest, 0x55U);
	edge_digest(other, 0x56U);
	zassert_equal(b->stage, PQCP_EDGE_POLICY_STAGE_STAGED);
	zassert_equal(b->previous_epoch, 1U);
	zassert_mem_equal(b->previous_digest, active_digest,
			  sizeof(active_digest));
	/* The same epoch cannot be staged twice. */
	{
		uint8_t again[PQCP_EDGE_DIGEST_BYTES];

		edge_digest(again, 0x99U);
		zassert_equal(pqcp_edge_policy_stage(&pd, again, 5U, T0, T0,
			T0 + 100000U, 2U, 2U, &dup), -EALREADY);
		zassert_equal(dup, b);
	}

	zassert_equal(pqcp_edge_policy_promote(&pd, id, T0), 0);
	zassert_equal(b->stage, PQCP_EDGE_POLICY_STAGE_CANARY);
	/* Canary needs the required number of successful acks. */
	zassert_equal(pqcp_edge_policy_promote(&pd, id, T0), -EAGAIN);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, id, "p1", digest, 0,
		T0 + 1U), 0);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, id, "p1", digest, 0,
		T0 + 1U), -EALREADY);
	zassert_equal(b->received_acks, 1U);
	zassert_equal(pqcp_edge_policy_promote(&pd, id, T0 + 2U), -EAGAIN);
	/* A device applying different content fails its ack. */
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, id, "p2", other, 0,
		T0 + 3U), -EBADMSG);
	zassert_equal(b->received_acks, 1U);
	zassert_equal(b->failure_count, 1U);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, id, "p3", digest, 0,
		T0 + 4U), 0);
	zassert_equal(pqcp_edge_policy_promote(&pd, id, T0 + 5U), 0);
	zassert_equal(b->stage, PQCP_EDGE_POLICY_STAGE_PROMOTED);
	zassert_equal(pd.active_policy_epoch, 1U);
	zassert_equal(pqcp_edge_policy_promote(&pd, id, T0 + 6U), 0);
	zassert_equal(b->stage, PQCP_EDGE_POLICY_STAGE_ACTIVE);
	zassert_equal(pd.active_policy_epoch, 5U);
	zassert_mem_equal(pd.active_digest, digest, sizeof(digest));
	zassert_equal(pqcp_edge_policy_promote(&pd, id, T0 + 7U), -EALREADY);
	zassert_equal(pd.promotion_count, 3U);
	zassert_equal(pqcp_edge_policy_distributor_audit(&pd), 0);
}

ZTEST(edge_security, test_policy_failure_budget_expiry_and_rollback)
{
	struct pqcp_edge_policy_bundle *b;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t other[PQCP_EDGE_DIGEST_BYTES];
	uint64_t id;

	policy_setup(2U);
	b = stage_bundle(5U, 0x55U, 1U);
	id = b->bundle_id;
	edge_digest(digest, 0x55U);
	edge_digest(other, 0x56U);
	zassert_equal(pqcp_edge_policy_promote(&pd, id, T0), 0);
	/* A device-reported failure is returned and counted. */
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, id, "p1", digest,
		-EIO, T0 + 1U), -EIO);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, id, "p2", other, 0,
		T0 + 2U), -EBADMSG);
	zassert_equal(b->failure_count, 2U);
	zassert_equal(b->received_acks, 0U);
	/* Too many failures freeze promotion. */
	zassert_equal(pqcp_edge_policy_promote(&pd, id, T0 + 3U), -EACCES);
	zassert_equal(b->stage, PQCP_EDGE_POLICY_STAGE_CANARY);

	/* Rollback abandons the bundle; the active policy is untouched. */
	zassert_equal(pqcp_edge_policy_rollback(&pd, id, T0 + 4U), 0);
	zassert_equal(b->stage, PQCP_EDGE_POLICY_STAGE_ROLLBACK);
	zassert_equal(pd.active_policy_epoch, 1U);
	zassert_equal(pd.rollback_count, 1U);
	zassert_equal(pqcp_edge_policy_rollback(&pd, id, T0 + 5U), -EPERM);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, id, "p3", digest, 0,
		T0 + 5U), -ESTALE);
	zassert_equal(pqcp_edge_policy_promote(&pd, id, T0 + 5U), -EACCES);

	/* Bundles expire: late acks and promotion are refused. */
	b = stage_bundle(6U, 0x57U, 1U);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, b->bundle_id, "p1",
		digest, 0, T0 + 100000U), -ESTALE);
	zassert_equal(pqcp_edge_policy_promote(&pd, b->bundle_id,
		T0 + 100000U), -EACCES);
}

ZTEST(edge_security, test_policy_audit_detects_bundle_tampering)
{
	struct pqcp_edge_policy_bundle *b;

	policy_setup(2U);
	b = stage_bundle(5U, 0x55U, 1U);
	zassert_equal(pqcp_edge_policy_distributor_audit(&pd), 0);
	b->required_acks = 9U;
	zassert_equal(pqcp_edge_policy_distributor_audit(&pd), -EBADMSG);
	b->required_acks = 1U;
	b->content_digest[0] ^= 1U;
	zassert_equal(pqcp_edge_policy_distributor_audit(&pd), -EBADMSG);
	b->content_digest[0] ^= 1U;
	zassert_equal(pqcp_edge_policy_distributor_audit(&pd), 0);
}

ZTEST(edge_security, test_policy_rollback_keeps_integrity_audit_clean)
{
	struct pqcp_edge_policy_bundle *b;
	int ret;

	policy_setup(2U);
	b = stage_bundle(5U, 0x55U, 1U);
	zassert_equal(pqcp_edge_policy_rollback(&pd, b->bundle_id, T0 + 4U),
		      0);
	ret = pqcp_edge_policy_distributor_audit(&pd);
	zassert_equal(ret, 0);
	zassert_equal(b->stage, PQCP_EDGE_POLICY_STAGE_ROLLBACK);
}

ZTEST(edge_security, test_policy_active_rollback_restores_previous_epoch)
{
	struct pqcp_edge_policy_bundle *b;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t id;

	policy_setup(2U);
	b = stage_bundle(5U, 0x55U, 1U);
	id = b->bundle_id;
	edge_digest(digest, 0x55U);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, id, "p1", digest, 0,
		T0), 0);
	for (int i = 0; i < 3; ++i) {
		zassert_equal(pqcp_edge_policy_promote(&pd, id, T0 + 1U + i),
			      0);
	}
	zassert_equal(pd.active_policy_epoch, 5U);
	zassert_equal(pqcp_edge_policy_rollback(&pd, id, T0 + 10U), 0);
	zassert_equal(pd.active_policy_epoch, 1U);
	zassert_mem_equal(pd.active_digest, active_digest,
			  sizeof(active_digest));
}

ZTEST(edge_security, test_policy_older_bundle_cannot_displace_newer_epoch)
{
	struct pqcp_edge_policy_bundle *a;
	struct pqcp_edge_policy_bundle *b;
	uint8_t da[PQCP_EDGE_DIGEST_BYTES];
	uint8_t db[PQCP_EDGE_DIGEST_BYTES];
	int ret = 0;

	policy_setup(2U);
	a = stage_bundle(5U, 0x55U, 1U);
	b = stage_bundle(6U, 0x56U, 1U);
	edge_digest(da, 0x55U);
	edge_digest(db, 0x56U);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, a->bundle_id, "p1",
		da, 0, T0), 0);
	zassert_equal(pqcp_edge_policy_acknowledge(&pd, b->bundle_id, "p1",
		db, 0, T0), 0);
	for (int i = 0; i < 3; ++i) {
		zassert_equal(pqcp_edge_policy_promote(&pd, b->bundle_id,
			T0 + 1U + i), 0);
	}
	zassert_equal(pd.active_policy_epoch, 6U);

	/* Now drive the older bundle through its pipeline. */
	for (int i = 0; i < 3 && ret == 0; ++i) {
		ret = pqcp_edge_policy_promote(&pd, a->bundle_id, T0 + 10U + i);
	}
	zassert_equal(ret, -ESTALE);
	zassert_equal(a->stage, PQCP_EDGE_POLICY_STAGE_STAGED);
	zassert_equal(b->stage, PQCP_EDGE_POLICY_STAGE_ACTIVE);
	zassert_equal(pd.active_policy_epoch, 6U);
	zassert_mem_equal(pd.active_digest, db, sizeof(db));
	zassert_equal(pqcp_edge_policy_distributor_audit(&pd), 0);
}

ZTEST(edge_security, test_policy_abandoned_bundles_release_capacity)
{
	struct pqcp_edge_policy_bundle *b;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret;

	policy_setup(1U);
	b = stage_bundle(5U, 0x55U, 1U);
	zassert_equal(pqcp_edge_policy_rollback(&pd, b->bundle_id, T0 + 1U),
		      0);
	edge_digest(digest, 0x56U);
	ret = pqcp_edge_policy_stage(&pd, digest, 6U, T0 + 2U, T0 + 2U,
		T0 + 100000U, 1U, 1U, &b);
	zassert_equal(ret, 0);
	zassert_equal(b->stage, PQCP_EDGE_POLICY_STAGE_STAGED);
	zassert_equal(pqcp_edge_policy_distributor_audit(&pd), 0);
	/* Repeated rollout/rollback cycles never exhaust the table. */
	for (uint64_t e = 7U; e < 12U; ++e) {
		zassert_equal(pqcp_edge_policy_rollback(&pd, b->bundle_id,
			T0 + 3U), 0);
		zassert_equal(pqcp_edge_policy_stage(&pd, digest, e,
			T0 + 4U, T0 + 4U, T0 + 100000U, 1U, 1U, &b), 0);
	}
}

/* ------------------------------------------------------------------ */
/* Rotation manager                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_secret_rotation rtn[1];
static struct pqcp_edge_rotation_manager rotm;

static struct pqcp_edge_secret_rotation *plan_rotation(uint32_t targets,
						       uint32_t failures)
{
	uint8_t cur[PQCP_EDGE_DIGEST_BYTES];
	uint8_t tgt[PQCP_EDGE_DIGEST_BYTES];
	struct pqcp_edge_secret_rotation *r = NULL;

	edge_digest(cur, 1U);
	edge_digest(tgt, 2U);
	zassert_equal(pqcp_edge_rotation_plan(&rotm, "kms-key", 1U, 2U, cur,
		tgt, targets, failures, T0, T0 + 1000U, T0 + 5000U, &r), 0);
	return r;
}

ZTEST(edge_security, test_rotation_rejects_invalid_arguments)
{
	static struct pqcp_edge_rotation_manager raw;
	uint8_t cur[PQCP_EDGE_DIGEST_BYTES];
	uint8_t tgt[PQCP_EDGE_DIGEST_BYTES];
	uint8_t zero[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	struct pqcp_edge_secret_rotation *r = (void *)0x1;
	uint32_t changed = 0U;

	edge_digest(cur, 1U);
	edge_digest(tgt, 2U);
	zassert_equal(pqcp_edge_rotation_manager_init(NULL, rtn, 1U),
		      -EINVAL);
	zassert_equal(pqcp_edge_rotation_manager_init(&rotm, NULL, 1U),
		      -EINVAL);
	zassert_equal(pqcp_edge_rotation_manager_init(&rotm, rtn, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_rotation_plan(&raw, "k", 1U, 2U, cur, tgt,
		1U, 1U, T0, T0 + 10U, T0 + 20U, &r), -EINVAL);
	zassert_equal(pqcp_edge_rotation_transition(&raw, 1U,
		PQCP_EDGE_ROTATION_GENERATING, T0), -EINVAL);
	zassert_equal(pqcp_edge_rotation_acknowledge(&raw, 1U, true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_rotation_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_rotation_manager_audit(&raw), -EINVAL);

	zassert_equal(pqcp_edge_rotation_manager_init(&rotm, rtn, 1U), 0);
#define BAD_PLAN(secret, ce, te, cd, td, tc, mf, ov, dl)                   \
	zassert_equal(pqcp_edge_rotation_plan(&rotm, secret, ce, te, cd,   \
		td, tc, mf, T0, ov, dl, &r), -EINVAL)
	BAD_PLAN(NULL, 1U, 2U, cur, tgt, 1U, 1U, T0 + 10U, T0 + 20U);
	BAD_PLAN("", 1U, 2U, cur, tgt, 1U, 1U, T0 + 10U, T0 + 20U);
	BAD_PLAN("k", 0U, 2U, cur, tgt, 1U, 1U, T0 + 10U, T0 + 20U);
	BAD_PLAN("k", 2U, 2U, cur, tgt, 1U, 1U, T0 + 10U, T0 + 20U);
	BAD_PLAN("k", 1U, 2U, NULL, tgt, 1U, 1U, T0 + 10U, T0 + 20U);
	BAD_PLAN("k", 1U, 2U, cur, NULL, 1U, 1U, T0 + 10U, T0 + 20U);
	BAD_PLAN("k", 1U, 2U, zero, tgt, 1U, 1U, T0 + 10U, T0 + 20U);
	BAD_PLAN("k", 1U, 2U, cur, zero, 1U, 1U, T0 + 10U, T0 + 20U);
	/* Rotating to an identical secret is meaningless. */
	BAD_PLAN("k", 1U, 2U, cur, cur, 1U, 1U, T0 + 10U, T0 + 20U);
	BAD_PLAN("k", 1U, 2U, cur, tgt, 0U, 1U, T0 + 10U, T0 + 20U);
	BAD_PLAN("k", 1U, 2U, cur, tgt, 1U, 0U, T0 + 10U, T0 + 20U);
	BAD_PLAN("k", 1U, 2U, cur, tgt, 1U, 1U, T0, T0 + 20U);
	BAD_PLAN("k", 1U, 2U, cur, tgt, 1U, 1U, T0 + 10U, T0 + 10U);
#undef BAD_PLAN
	zassert_equal(pqcp_edge_rotation_plan(&rotm, "k", 1U, 2U, cur, tgt,
		1U, 1U, T0, T0 + 10U, T0 + 20U, NULL), -EINVAL);
	zassert_false(rtn[0].occupied);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, 0U,
		PQCP_EDGE_ROTATION_GENERATING, T0), -EINVAL);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, 1U,
		PQCP_EDGE_ROTATION_EMPTY, T0), -EINVAL);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, 1U,
		(enum pqcp_edge_rotation_state)9, T0), -EINVAL);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, 9U,
		PQCP_EDGE_ROTATION_GENERATING, T0), -ENOENT);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, 0U, true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, 9U, true, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_rotation_tick(&rotm, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_rotation_manager_audit(&rotm), 0);
}

ZTEST(edge_security, test_rotation_full_cycle_with_overlap)
{
	struct pqcp_edge_secret_rotation *r;
	uint64_t id;

	zassert_equal(pqcp_edge_rotation_manager_init(&rotm, rtn, 1U), 0);
	r = plan_rotation(2U, 2U);
	id = r->rotation_id;
	zassert_equal(r->state, PQCP_EDGE_ROTATION_PLANNED);

	/* The pipeline cannot be shortcut. */
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_DISTRIBUTING, T0), -EPERM);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_COMPLETED, T0), -EPERM);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, id, true, T0),
		      -EALREADY);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_GENERATING, T0), 0);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_GENERATING, T0), -EALREADY);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_DISTRIBUTING, T0), 0);

	/* Overlap only starts once every target has answered. */
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_OVERLAP, T0 + 1U), -EAGAIN);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, id, true,
		T0 + 2U), 0);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_OVERLAP, T0 + 3U), -EAGAIN);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, id, true,
		T0 + 4U), 0);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, id, true,
		T0 + 5U), -EDQUOT);
	zassert_equal(r->acknowledged_count, 2U);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_OVERLAP, T0 + 6U), 0);

	/* The old secret stays valid for the whole overlap window. */
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_RETIRING, T0 + 999U), -EAGAIN);
	zassert_equal(r->state, PQCP_EDGE_ROTATION_OVERLAP);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_RETIRING, T0 + 1000U), 0);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_COMPLETED, T0 + 1001U), 0);
	zassert_equal(rotm.completed_count, 1U);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_FAILED, T0 + 1002U), -EPERM);
	zassert_equal(pqcp_edge_rotation_manager_audit(&rotm), 0);
}

ZTEST(edge_security, test_rotation_failure_budget_deadline_and_capacity)
{
	struct pqcp_edge_secret_rotation *r;
	struct pqcp_edge_secret_rotation *next = (void *)0x1;
	uint8_t cur[PQCP_EDGE_DIGEST_BYTES];
	uint8_t tgt[PQCP_EDGE_DIGEST_BYTES];
	uint32_t changed = 0U;
	uint64_t id;

	zassert_equal(pqcp_edge_rotation_manager_init(&rotm, rtn, 1U), 0);
	edge_digest(cur, 1U);
	edge_digest(tgt, 2U);
	r = plan_rotation(5U, 2U);
	id = r->rotation_id;
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_GENERATING, T0), 0);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_DISTRIBUTING, T0), 0);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, id, false,
		T0 + 1U), 0);
	zassert_equal(r->state, PQCP_EDGE_ROTATION_DISTRIBUTING);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, id, false,
		T0 + 2U), 0);
	zassert_equal(r->state, PQCP_EDGE_ROTATION_FAILED);
	zassert_equal(rotm.failed_count, 1U);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, id, true,
		T0 + 3U), -EALREADY);

	/* A failed rotation frees its slot for the next plan. */
	zassert_equal(pqcp_edge_rotation_plan(&rotm, "k2", 1U, 2U, cur, tgt,
		1U, 1U, T0 + 10U, T0 + 20U, T0 + 30U, &next), 0);
	zassert_equal(next, r);
	/* An in-progress plan blocks further plans. */
	{
		struct pqcp_edge_secret_rotation *third = (void *)0x1;

		zassert_equal(pqcp_edge_rotation_plan(&rotm, "k3", 1U, 2U,
			cur, tgt, 1U, 1U, T0 + 10U, T0 + 20U, T0 + 30U,
			&third), -ENOSPC);
		zassert_is_null(third);
	}
	/* Deadline: tick fails it; it never silently continues. */
	zassert_equal(pqcp_edge_rotation_tick(&rotm, T0 + 29U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(pqcp_edge_rotation_tick(&rotm, T0 + 30U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(next->state, PQCP_EDGE_ROTATION_FAILED);
	zassert_equal(rotm.failed_count, 2U);

	/* Tick advances an overlap window that has elapsed. */
	r = plan_rotation(1U, 1U);
	id = r->rotation_id;
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_GENERATING, T0), 0);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_DISTRIBUTING, T0), 0);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rotm, id, true,
		T0 + 1U), 0);
	zassert_equal(pqcp_edge_rotation_transition(&rotm, id,
		PQCP_EDGE_ROTATION_OVERLAP, T0 + 2U), 0);
	zassert_equal(pqcp_edge_rotation_tick(&rotm, T0 + 1000U, &changed),
		      0);
	zassert_equal(changed, 1U);
	zassert_equal(r->state, PQCP_EDGE_ROTATION_RETIRING);
	zassert_equal(pqcp_edge_rotation_manager_audit(&rotm), 0);
	r->acknowledged_count = 9U;
	zassert_equal(pqcp_edge_rotation_manager_audit(&rotm), -EBADMSG);
}

/* ------------------------------------------------------------------ */
/* Resource monitor                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_resource_budget rbstore[2];
static struct pqcp_edge_resource_monitor rmon;

static void make_budget(struct pqcp_edge_resource_budget *b, const char *id)
{
	memset(b, 0, sizeof(*b));
	SETSTR(b->subject_id, id);
	for (size_t i = 0U; i < PQCP_EDGE_RESOURCE_COUNT; ++i) {
		b->limit[i] = 100U;
		b->warning[i] = 80U;
	}
	b->window_started_ms = T0;
	b->window_ms = 1000U;
}

static void resource_setup(void)
{
	zassert_equal(pqcp_edge_resource_monitor_init(
		&rmon, rbstore, ARRAY_SIZE(rbstore)), 0);
}

ZTEST(edge_security, test_resource_rejects_invalid_arguments)
{
	static struct pqcp_edge_resource_monitor raw;
	struct pqcp_edge_resource_budget b;
	enum pqcp_edge_resource_action action;
	uint32_t reset = 0U;

	zassert_equal(pqcp_edge_resource_monitor_init(NULL, rbstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_resource_monitor_init(&rmon, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_resource_monitor_init(&rmon, rbstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_budget(&b, "dev");
	zassert_equal(pqcp_edge_resource_budget_put(&raw, &b), -EINVAL);
	zassert_equal(pqcp_edge_resource_reserve(&raw, "dev",
		PQCP_EDGE_RESOURCE_CPU_US, 1U, T0, &action), -EINVAL);
	zassert_equal(pqcp_edge_resource_release(&raw, "dev",
		PQCP_EDGE_RESOURCE_CPU_US, 1U), -EINVAL);
	zassert_equal(pqcp_edge_resource_tick(&raw, T0, &reset), -EINVAL);
	zassert_equal(pqcp_edge_resource_monitor_audit(&raw), -EINVAL);

	resource_setup();
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, NULL), -EINVAL);
	make_budget(&b, "dev"); b.subject_id[0] = '\0';
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), -EINVAL);
	make_budget(&b, "dev"); b.window_ms = 0U;
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), -EINVAL);
	make_budget(&b, "dev");
	b.limit[PQCP_EDGE_RESOURCE_CPU_US] = 0U;
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), -EINVAL);
	make_budget(&b, "dev");
	b.warning[PQCP_EDGE_RESOURCE_CPU_US] = 101U;
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), -EINVAL);
	make_budget(&b, "dev");
	b.used[PQCP_EDGE_RESOURCE_CPU_US] = 101U;
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), -EINVAL);
	zassert_false(rbstore[0].occupied);

	zassert_equal(pqcp_edge_resource_reserve(&rmon, NULL,
		PQCP_EDGE_RESOURCE_CPU_US, 1U, T0, &action), -EINVAL);
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev",
		PQCP_EDGE_RESOURCE_COUNT, 1U, T0, &action), -EINVAL);
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev",
		PQCP_EDGE_RESOURCE_CPU_US, 0U, T0, &action), -EINVAL);
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev",
		PQCP_EDGE_RESOURCE_CPU_US, 1U, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev",
		PQCP_EDGE_RESOURCE_CPU_US, 1U, T0, &action), -ENOENT);
	zassert_equal(pqcp_edge_resource_release(&rmon, NULL,
		PQCP_EDGE_RESOURCE_CPU_US, 1U), -EINVAL);
	zassert_equal(pqcp_edge_resource_release(&rmon, "dev",
		PQCP_EDGE_RESOURCE_COUNT, 1U), -EINVAL);
	zassert_equal(pqcp_edge_resource_release(&rmon, "dev",
		PQCP_EDGE_RESOURCE_CPU_US, 0U), -EINVAL);
	zassert_equal(pqcp_edge_resource_release(&rmon, "dev",
		PQCP_EDGE_RESOURCE_CPU_US, 1U), -ENOENT);
	zassert_equal(pqcp_edge_resource_tick(&rmon, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_resource_monitor_audit(&rmon), 0);
}

ZTEST(edge_security, test_resource_budget_enforcement_and_actions)
{
	struct pqcp_edge_resource_budget b;
	enum pqcp_edge_resource_action action = PQCP_EDGE_RESOURCE_ACTION_ISOLATE;
	const enum pqcp_edge_resource_type mem = PQCP_EDGE_RESOURCE_MEMORY_BYTES;
	const enum pqcp_edge_resource_type cpu = PQCP_EDGE_RESOURCE_CPU_US;

	resource_setup();
	make_budget(&b, "dev");
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), 0);

	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev", mem, 50U, T0,
		&action), 0);
	zassert_equal(action, PQCP_EDGE_RESOURCE_ACTION_NONE);
	/* Crossing the warning threshold throttles. */
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev", mem, 30U,
		T0 + 1U, &action), 0);
	zassert_equal(action, PQCP_EDGE_RESOURCE_ACTION_THROTTLE);
	/* Exactly at the limit is allowed but already requires compaction. */
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev", mem, 20U,
		T0 + 2U, &action), 0);
	zassert_equal(action, PQCP_EDGE_RESOURCE_ACTION_COMPACT);
	/* Beyond the limit is denied and never partially applied. */
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev", mem, 1U,
		T0 + 3U, &action), -EDQUOT);
	zassert_equal(action, PQCP_EDGE_RESOURCE_ACTION_COMPACT);
	zassert_equal(rbstore[0].used[mem], 100U);
	zassert_equal(rbstore[0].violation_count, 1U);
	zassert_equal(rmon.denial_count, 1U);
	zassert_equal(rmon.accounting_count, 3U);

	/* Non-storage resources shed load instead of compacting. */
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev", cpu, 101U,
		T0 + 4U, &action), -EDQUOT);
	zassert_equal(action, PQCP_EDGE_RESOURCE_ACTION_SHED);
	zassert_equal(rbstore[0].used[cpu], 0U);
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "dev", cpu,
		UINT64_MAX, T0 + 4U, &action), -EDQUOT);

	/* Releasing more than is held is an error; otherwise relax. */
	zassert_equal(pqcp_edge_resource_release(&rmon, "dev", mem, 101U),
		      -ERANGE);
	zassert_equal(rbstore[0].used[mem], 100U);
	zassert_equal(pqcp_edge_resource_release(&rmon, "dev", mem, 90U), 0);
	zassert_equal(rbstore[0].action, PQCP_EDGE_RESOURCE_ACTION_NONE);
	zassert_equal(pqcp_edge_resource_monitor_audit(&rmon), 0);
}

ZTEST(edge_security, test_resource_window_reset_update_and_capacity)
{
	struct pqcp_edge_resource_budget b;
	enum pqcp_edge_resource_action action;
	uint32_t reset = 0U;
	const enum pqcp_edge_resource_type net = PQCP_EDGE_RESOURCE_NETWORK_BYTES;

	resource_setup();
	make_budget(&b, "a");
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), 0);
	zassert_equal(pqcp_edge_resource_reserve(&rmon, "a", net, 90U, T0,
		&action), 0);
	zassert_equal(action, PQCP_EDGE_RESOURCE_ACTION_THROTTLE);

	/* Shrinking a budget below current usage is refused, untouched. */
	b.limit[net] = 50U;
	b.warning[net] = 40U;
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), -EDQUOT);
	zassert_equal(rbstore[0].limit[net], 100U);
	zassert_equal(rbstore[0].used[net], 90U);
	/* Growing preserves accumulated usage. */
	b.limit[net] = 200U;
	b.warning[net] = 150U;
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), 0);
	zassert_equal(rbstore[0].used[net], 90U);
	zassert_equal(rbstore[0].action, PQCP_EDGE_RESOURCE_ACTION_NONE);

	make_budget(&b, "b");
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), 0);
	make_budget(&b, "c");
	zassert_equal(pqcp_edge_resource_budget_put(&rmon, &b), -ENOSPC);

	/* The accounting window rolls over and forgets usage. */
	zassert_equal(pqcp_edge_resource_tick(&rmon, T0 + 999U, &reset), 0);
	zassert_equal(reset, 0U);
	zassert_equal(pqcp_edge_resource_tick(&rmon, T0 + 1000U, &reset), 0);
	zassert_equal(reset, 2U);
	zassert_equal(rbstore[0].used[net], 0U);
	zassert_equal(rbstore[0].window_started_ms, T0 + 1000U);

	rbstore[1].action = (enum pqcp_edge_resource_action)9;
	zassert_equal(pqcp_edge_resource_monitor_audit(&rmon), -EBADMSG);
}

/* ------------------------------------------------------------------ */
/* DLP engine                                                          */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_dlp_rule dlpstore[3];
static struct pqcp_edge_dlp_engine dlp;

static void dlp_setup(void)
{
	zassert_equal(pqcp_edge_dlp_engine_init(
		&dlp, dlpstore, ARRAY_SIZE(dlpstore)), 0);
}

static void make_dlp(struct pqcp_edge_dlp_rule *r, uint32_t id,
		     enum pqcp_edge_dlp_action action)
{
	memset(r, 0, sizeof(*r));
	r->rule_id = id;
	r->priority = 1U;
	SETSTR(r->classification, "secret");
	r->minimum_matches = 2U;
	r->byte_pattern = 'A';
	r->byte_mask = 0xffU;
	r->maximum_payload = 64U;
	r->action = action;
	r->enabled = true;
}

ZTEST(edge_security, test_dlp_rejects_invalid_arguments)
{
	static struct pqcp_edge_dlp_engine raw;
	struct pqcp_edge_dlp_rule r;
	struct pqcp_edge_dlp_decision d;
	const uint8_t payload[2] = { 'A', 'B' };

	zassert_equal(pqcp_edge_dlp_engine_init(NULL, dlpstore, 3U),
		      -EINVAL);
	zassert_equal(pqcp_edge_dlp_engine_init(&dlp, NULL, 3U), -EINVAL);
	zassert_equal(pqcp_edge_dlp_engine_init(&dlp, dlpstore, 0U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_dlp(&r, 1U, PQCP_EDGE_DLP_BLOCK);
	zassert_equal(pqcp_edge_dlp_rule_put(&raw, &r), -EINVAL);
	zassert_equal(pqcp_edge_dlp_rule_remove(&raw, 1U), -EINVAL);
	zassert_equal(pqcp_edge_dlp_scan(&raw, "secret", "dom", payload, 2U,
		false, &d), -EINVAL);
	zassert_equal(pqcp_edge_dlp_engine_audit(&raw), -EINVAL);

	dlp_setup();
	zassert_equal(pqcp_edge_dlp_rule_put(&dlp, NULL), -EINVAL);
#define BAD_DLP(mut)                                                    \
	do {                                                            \
		make_dlp(&r, 1U, PQCP_EDGE_DLP_BLOCK);                  \
		mut;                                                    \
		zassert_equal(pqcp_edge_dlp_rule_put(&dlp, &r),         \
			      -EINVAL, #mut);                           \
	} while (0)
	BAD_DLP(r.rule_id = 0U);
	BAD_DLP(r.classification[0] = '\0');
	BAD_DLP(r.minimum_matches = 0U);
	BAD_DLP(r.byte_mask = 0x100U);
	BAD_DLP(r.byte_pattern = 0x100U);
	BAD_DLP(r.maximum_payload = 0U);
	BAD_DLP(r.action = (enum pqcp_edge_dlp_action)9);
	BAD_DLP(r.enabled = false);
	BAD_DLP(memset(r.destination_domain, 'x',
		       sizeof(r.destination_domain)));
#undef BAD_DLP
	zassert_equal(dlp.count, 0U);
	zassert_equal(pqcp_edge_dlp_rule_remove(&dlp, 0U), -EINVAL);
	zassert_equal(pqcp_edge_dlp_rule_remove(&dlp, 7U), -ENOENT);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, NULL, "dom", payload, 2U,
		false, &d), -EINVAL);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", NULL, payload, 2U,
		false, &d), -EINVAL);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", NULL, 2U,
		false, &d), -EINVAL);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", payload, 0U,
		false, &d), -EINVAL);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", payload, 2U,
		false, NULL), -EINVAL);
	zassert_equal(dlp.scan_count, 0U);
	zassert_equal(pqcp_edge_dlp_engine_audit(&dlp), 0);
}

ZTEST(edge_security, test_dlp_scan_actions_and_scoping)
{
	struct pqcp_edge_dlp_rule r;
	struct pqcp_edge_dlp_decision d;
	const uint8_t clean[8] = { 'x', 'y', 'z', 'x', 'y', 'z', 'x', 'y' };
	const uint8_t one[8] = { 'A', 'y', 'z', 'x', 'y', 'z', 'x', 'y' };
	const uint8_t two[8] = { 'A', 'y', 'A', 'x', 'y', 'z', 'x', 'y' };

	dlp_setup();
	/* No rules: egress is allowed and explained. */
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", two,
		sizeof(two), false, &d), 0);
	zassert_equal(d.action, PQCP_EDGE_DLP_ALLOW);
	zassert_equal(d.scanned_bytes, sizeof(two));
	zassert_true(strlen(d.reason) > 0U);

	make_dlp(&r, 1U, PQCP_EDGE_DLP_BLOCK);
	zassert_equal(pqcp_edge_dlp_rule_put(&dlp, &r), 0);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", clean,
		sizeof(clean), false, &d), 0);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", one,
		sizeof(one), false, &d), 0);
	zassert_equal(d.action, PQCP_EDGE_DLP_ALLOW);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", two,
		sizeof(two), false, &d), -EACCES);
	zassert_equal(d.action, PQCP_EDGE_DLP_BLOCK);
	zassert_equal(d.rule_id, 1U);
	zassert_equal(d.match_count, 2U);
	/* Other classifications are not covered by the rule. */
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "public", "dom", two,
		sizeof(two), false, &d), 0);
	zassert_equal(dlp.scan_count, 5U);
	zassert_equal(dlp.block_count, 1U);

	/* Destination and encryption scoping. */
	make_dlp(&r, 2U, PQCP_EDGE_DLP_QUARANTINE);
	r.priority = 5U;
	SETSTR(r.destination_domain, "partner");
	zassert_equal(pqcp_edge_dlp_rule_put(&dlp, &r), 0);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", two,
		sizeof(two), false, &d), -EACCES);
	zassert_equal(d.rule_id, 1U);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "partner", two,
		sizeof(two), false, &d), -EKEYREJECTED);
	zassert_equal(d.action, PQCP_EDGE_DLP_QUARANTINE);
	zassert_equal(d.rule_id, 2U);
	zassert_equal(dlp.block_count, 3U);

	make_dlp(&r, 3U, PQCP_EDGE_DLP_REDACT);
	r.priority = 9U;
	r.encrypted_only = true;
	zassert_equal(pqcp_edge_dlp_rule_put(&dlp, &r), 0);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", two,
		sizeof(two), true, &d), -EAGAIN);
	zassert_equal(d.action, PQCP_EDGE_DLP_REDACT);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", two,
		sizeof(two), false, &d), -EACCES);
	/* Rule table full. */
	make_dlp(&r, 4U, PQCP_EDGE_DLP_BLOCK);
	zassert_equal(pqcp_edge_dlp_rule_put(&dlp, &r), -ENOSPC);
	zassert_equal(dlp.count, 3U);
}

ZTEST(edge_security, test_dlp_priority_mask_oversize_and_audit)
{
	struct pqcp_edge_dlp_rule r;
	struct pqcp_edge_dlp_decision d;
	uint8_t big[100];
	const uint8_t nibble[4] = { 0x41, 0x4f, 0x50, 0x00 };

	dlp_setup();
	/* Equal priority: the more severe action wins. */
	make_dlp(&r, 1U, PQCP_EDGE_DLP_REDACT);
	r.minimum_matches = 1U;
	zassert_equal(pqcp_edge_dlp_rule_put(&dlp, &r), 0);
	make_dlp(&r, 2U, PQCP_EDGE_DLP_QUARANTINE);
	r.minimum_matches = 1U;
	zassert_equal(pqcp_edge_dlp_rule_put(&dlp, &r), 0);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom",
		(const uint8_t *)"A", 1U, false, &d), -EKEYREJECTED);
	zassert_equal(d.rule_id, 2U);
	zassert_equal(pqcp_edge_dlp_rule_remove(&dlp, 2U), 0);
	zassert_equal(pqcp_edge_dlp_rule_remove(&dlp, 2U), -ENOENT);

	/* Bit masks match byte classes: 0x4? */
	make_dlp(&r, 1U, PQCP_EDGE_DLP_BLOCK);
	r.byte_pattern = 0x40U;
	r.byte_mask = 0xf0U;
	r.minimum_matches = 2U;
	zassert_equal(pqcp_edge_dlp_rule_put(&dlp, &r), 0);
	zassert_equal(dlp.count, 2U - 1U);
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", nibble,
		sizeof(nibble), false, &d), -EACCES);
	zassert_equal(d.match_count, 2U);

	/* Oversized payloads are treated as a match regardless of content. */
	memset(big, 'z', sizeof(big));
	zassert_equal(pqcp_edge_dlp_scan(&dlp, "secret", "dom", big,
		sizeof(big), false, &d), -EACCES);
	zassert_equal(d.match_count, 2U);
	zassert_equal(d.scanned_bytes, sizeof(big));

	zassert_equal(pqcp_edge_dlp_engine_audit(&dlp), 0);
	dlp.count = 5U;
	zassert_equal(pqcp_edge_dlp_engine_audit(&dlp), -EBADMSG);
	dlp.count = 1U;
	dlpstore[1] = dlpstore[0];
	dlp.count = 2U;
	zassert_equal(pqcp_edge_dlp_engine_audit(&dlp), -EEXIST);
	dlpstore[1] = dlpstore[0];
	dlpstore[1].rule_id = 9U;
	dlpstore[1].minimum_matches = 0U;
	zassert_equal(pqcp_edge_dlp_engine_audit(&dlp), -EBADMSG);
}

/* ------------------------------------------------------------------ */
/* Trust federation                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_trust_anchor tastore[2];
static struct pqcp_edge_federation_grant fgstore[2];
static struct pqcp_edge_trust_federation fed;

static void fed_setup(void)
{
	zassert_equal(pqcp_edge_trust_federation_init(
		&fed, tastore, ARRAY_SIZE(tastore), fgstore,
		ARRAY_SIZE(fgstore)), 0);
}

static void make_anchor(struct pqcp_edge_trust_anchor *a, const char *id)
{
	memset(a, 0, sizeof(*a));
	SETSTR(a->domain_id, id);
	a->policy_epoch = 2U;
	a->revocation_epoch = 2U;
	a->not_before_ms = T0;
	a->expires_at_ms = T0 + 10000U;
	a->maximum_risk = 600U;
	edge_digest(a->public_key_digest, (uint8_t)id[4]);
}

static struct pqcp_edge_federation_grant *issue_grant(uint64_t uses)
{
	struct pqcp_edge_federation_grant *g = NULL;

	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a", "dom-b",
		0x3U, PQCP_EDGE_OPERATION_BIT(PQCP_EDGE_OPERATION_READ), 500U,
		T0, T0 + 5000U, uses, &g), 0);
	return g;
}

static int fed_auth(enum pqcp_edge_operation op, uint64_t caps,
		    uint32_t risk, uint64_t pe, uint64_t re, uint64_t now)
{
	return pqcp_edge_federation_authorize(&fed, "dom-a", "dom-b", op,
					      caps, risk, pe, re, now);
}

ZTEST(edge_security, test_federation_rejects_invalid_arguments)
{
	static struct pqcp_edge_trust_federation raw;
	struct pqcp_edge_trust_anchor a;
	struct pqcp_edge_federation_grant *g = (void *)0x1;
	const uint64_t read = PQCP_EDGE_OPERATION_BIT(PQCP_EDGE_OPERATION_READ);

	zassert_equal(pqcp_edge_trust_federation_init(NULL, tastore, 2U,
		fgstore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_trust_federation_init(&fed, NULL, 2U,
		fgstore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_trust_federation_init(&fed, tastore, 0U,
		fgstore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_trust_federation_init(&fed, tastore, 2U,
		NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_trust_federation_init(&fed, tastore, 2U,
		fgstore, 0U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_anchor(&a, "dom-a");
	zassert_equal(pqcp_edge_trust_anchor_put(&raw, &a), -EINVAL);
	zassert_equal(pqcp_edge_federation_grant_issue(&raw, "dom-a", "dom-b",
		1U, read, 1U, T0, T0 + 10U, 1U, &g), -EINVAL);
	zassert_equal(pqcp_edge_federation_authorize(&raw, "dom-a", "dom-b",
		PQCP_EDGE_OPERATION_READ, 1U, 1U, 1U, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_federation_revoke(&raw, 1U), -EINVAL);
	zassert_equal(pqcp_edge_trust_federation_audit(&raw), -EINVAL);

	fed_setup();
	zassert_equal(pqcp_edge_trust_anchor_put(&fed, NULL), -EINVAL);
#define BAD_ANCHOR(mut)                                                 \
	do {                                                            \
		make_anchor(&a, "dom-a");                               \
		mut;                                                    \
		zassert_equal(pqcp_edge_trust_anchor_put(&fed, &a),     \
			      -EINVAL, #mut);                           \
	} while (0)
	BAD_ANCHOR(a.domain_id[0] = '\0');
	BAD_ANCHOR(a.policy_epoch = 0U);
	BAD_ANCHOR(a.revocation_epoch = 0U);
	BAD_ANCHOR(a.expires_at_ms = a.not_before_ms);
	BAD_ANCHOR(a.maximum_risk = 1001U);
	BAD_ANCHOR(memset(a.public_key_digest, 0,
			  sizeof(a.public_key_digest)));
#undef BAD_ANCHOR
	zassert_false(tastore[0].active);

	zassert_equal(pqcp_edge_federation_grant_issue(&fed, NULL, "dom-b",
		1U, read, 1U, T0, T0 + 10U, 1U, &g), -EINVAL);
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a", "dom-a",
		1U, read, 1U, T0, T0 + 10U, 1U, &g), -EINVAL);
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a", "dom-b",
		0U, read, 1U, T0, T0 + 10U, 1U, &g), -EINVAL);
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a", "dom-b",
		1U, 0U, 1U, T0, T0 + 10U, 1U, &g), -EINVAL);
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a", "dom-b",
		1U, read, 1001U, T0, T0 + 10U, 1U, &g), -EINVAL);
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a", "dom-b",
		1U, read, 1U, T0, T0, 1U, &g), -EINVAL);
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a", "dom-b",
		1U, read, 1U, T0, T0 + 10U, 0U, &g), -EINVAL);
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a", "dom-b",
		1U, read, 1U, T0, T0 + 10U, 1U, NULL), -EINVAL);
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a", "dom-b",
		1U, read, 1U, T0, T0 + 10U, 1U, &g), -ENOKEY);
	zassert_is_null(g);
	zassert_equal(pqcp_edge_federation_authorize(&fed, NULL, "dom-b",
		PQCP_EDGE_OPERATION_READ, 1U, 1U, 1U, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_federation_authorize(&fed, "dom-a", "dom-b",
		PQCP_EDGE_OPERATION_NONE, 1U, 1U, 1U, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_federation_authorize(&fed, "dom-a", "dom-b",
		PQCP_EDGE_OPERATION_COUNT, 1U, 1U, 1U, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_federation_authorize(&fed, "dom-a", "dom-b",
		PQCP_EDGE_OPERATION_READ, 1U, 1001U, 1U, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_federation_authorize(&fed, "dom-a", "dom-b",
		PQCP_EDGE_OPERATION_READ, 1U, 1U, 0U, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_federation_authorize(&fed, "dom-a", "dom-b",
		PQCP_EDGE_OPERATION_READ, 1U, 1U, 1U, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_federation_revoke(&fed, 0U), -EINVAL);
	zassert_equal(pqcp_edge_federation_revoke(&fed, 9U), -ENOENT);
	zassert_equal(pqcp_edge_trust_federation_audit(&fed), 0);
}

ZTEST(edge_security, test_federation_denies_by_default_and_attenuates)
{
	struct pqcp_edge_trust_anchor a;
	struct pqcp_edge_federation_grant *g;
	const enum pqcp_edge_operation read = PQCP_EDGE_OPERATION_READ;

	fed_setup();
	/* Unknown domains cannot authorize anything. */
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 1U), -ENOKEY);
	make_anchor(&a, "dom-a");
	zassert_equal(pqcp_edge_trust_anchor_put(&fed, &a), 0);
	make_anchor(&a, "dom-b");
	zassert_equal(pqcp_edge_trust_anchor_put(&fed, &a), 0);
	/* Anchors alone grant nothing: no grant, no access. */
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 1U), -EACCES);
	zassert_equal(fed.rejection_count, 2U);

	g = issue_grant(2U);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 1U), 0);
	zassert_equal(g->use_count, 1U);
	zassert_equal(fed.authorization_count, 1U);
	/* Operation, capabilities, risk and direction are attenuated. */
	zassert_equal(fed_auth(PQCP_EDGE_OPERATION_WRITE, 0x1U, 10U, 2U, 2U,
		T0 + 1U), -EACCES);
	zassert_equal(fed_auth(read, 0x4U, 10U, 2U, 2U, T0 + 1U), -EACCES);
	zassert_equal(fed_auth(read, 0x1U, 501U, 2U, 2U, T0 + 1U), -EACCES);
	zassert_equal(pqcp_edge_federation_authorize(&fed, "dom-b", "dom-a",
		read, 0x1U, 10U, 2U, 2U, T0 + 1U), -EACCES);
	zassert_equal(g->use_count, 1U);

	/* Anchor-level gates: risk ceiling, stale epochs, validity window. */
	zassert_equal(fed_auth(read, 0x1U, 601U, 2U, 2U, T0 + 1U),
		      -EKEYREJECTED);
	tastore[0].maximum_risk = 100U;
	zassert_equal(fed_auth(read, 0x1U, 101U, 2U, 2U, T0 + 1U),
		      -EKEYREJECTED);
	tastore[0].maximum_risk = 600U;
	zassert_equal(fed_auth(read, 0x1U, 10U, 1U, 2U, T0 + 1U),
		      -EKEYREJECTED);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 1U, T0 + 1U),
		      -EKEYREJECTED);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 - 1U),
		      -EKEYREJECTED);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 10000U),
		      -EKEYREJECTED);
	zassert_equal(g->use_count, 1U);
}

ZTEST(edge_security, test_federation_use_limits_revocation_and_capacity)
{
	struct pqcp_edge_trust_anchor a;
	struct pqcp_edge_federation_grant *g;
	struct pqcp_edge_federation_grant *g2;
	struct pqcp_edge_federation_grant *g3 = (void *)0x1;
	const enum pqcp_edge_operation read = PQCP_EDGE_OPERATION_READ;
	const uint64_t read_mask = PQCP_EDGE_OPERATION_BIT(read);

	fed_setup();
	make_anchor(&a, "dom-a");
	zassert_equal(pqcp_edge_trust_anchor_put(&fed, &a), 0);
	make_anchor(&a, "dom-b");
	zassert_equal(pqcp_edge_trust_anchor_put(&fed, &a), 0);
	g = issue_grant(2U);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 1U), 0);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 2U), 0);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 3U), -EACCES);
	zassert_equal(g->use_count, 2U);
	/* Grants lapse at their expiry. */
	g2 = issue_grant(5U);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 4999U), 0);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 5000U),
		      -EACCES);

	/* Table full (one exhausted, one live): refuse a third grant. */
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a",
		"dom-b", 0x1U, read_mask, 10U, T0, T0 + 9000U, 1U, &g3),
		-ENOSPC);
	zassert_is_null(g3);
	/* Revocation is immediate, one-way and frees the slot. */
	zassert_equal(pqcp_edge_federation_revoke(&fed, g2->grant_id), 0);
	zassert_equal(pqcp_edge_federation_revoke(&fed, g2->grant_id),
		      -EALREADY);
	zassert_equal(fed_auth(read, 0x1U, 10U, 2U, 2U, T0 + 10U),
		      -EACCES);
	zassert_equal(pqcp_edge_federation_grant_issue(&fed, "dom-a",
		"dom-b", 0x1U, read_mask, 10U, T0, T0 + 9000U, 1U, &g3), 0);
	zassert_equal(pqcp_edge_trust_federation_audit(&fed), 0);

	/* Anchors only move forward. */
	make_anchor(&a, "dom-a");
	a.policy_epoch = 1U;
	zassert_equal(pqcp_edge_trust_anchor_put(&fed, &a), -ESTALE);
	make_anchor(&a, "dom-a");
	a.revocation_epoch = 1U;
	zassert_equal(pqcp_edge_trust_anchor_put(&fed, &a), -ESTALE);
	zassert_equal(tastore[0].policy_epoch, 2U);
	make_anchor(&a, "dom-a");
	a.policy_epoch = 3U;
	zassert_equal(pqcp_edge_trust_anchor_put(&fed, &a), 0);
	zassert_equal(tastore[0].generation, 2U - 1U + 1U);
	/* Anchor table full. */
	make_anchor(&a, "dom-c");
	zassert_equal(pqcp_edge_trust_anchor_put(&fed, &a), -ENOSPC);

	g3->maximum_uses += 1U;
	zassert_equal(pqcp_edge_trust_federation_audit(&fed), -EBADMSG);
	g3->maximum_uses -= 1U;
	tastore[1].policy_epoch = 0U;
	zassert_equal(pqcp_edge_trust_federation_audit(&fed), -EBADMSG);
}

/* ------------------------------------------------------------------ */
/* Credential cache                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_credential_record crstore[2];
static struct pqcp_edge_credential_cache cc;

static void cred_setup(size_t n)
{
	zassert_equal(pqcp_edge_credential_cache_init(&cc, crstore, n), 0);
}

static void make_cred(struct pqcp_edge_credential_record *c, const char *id)
{
	memset(c, 0, sizeof(*c));
	SETSTR(c->credential_id, id);
	SETSTR(c->principal_id, "p1");
	SETSTR(c->issuer_domain, "dom-a");
	c->issuance_epoch = 1U;
	c->policy_epoch = 2U;
	c->revocation_epoch = 1U;
	c->issued_at_ms = T0;
	c->refresh_at_ms = T0 + 500U;
	c->expires_at_ms = T0 + 1000U;
	c->capabilities = 0x3U;
	edge_digest(c->public_key_digest, 0x11U);
	edge_digest(c->credential_digest, 0x12U);
}

ZTEST(edge_security, test_credential_rejects_invalid_arguments)
{
	static struct pqcp_edge_credential_cache raw;
	struct pqcp_edge_credential_record c;
	uint32_t changed = 0U;

	zassert_equal(pqcp_edge_credential_cache_init(NULL, crstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_credential_cache_init(&cc, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_credential_cache_init(&cc, crstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_cred(&c, "c1");
	zassert_equal(pqcp_edge_credential_put(&raw, &c, T0), -EINVAL);
	zassert_equal(pqcp_edge_credential_authorize(&raw, "c1", "p1", 1U,
		2U, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_credential_revoke(&raw, "c1", 2U), -EINVAL);
	zassert_equal(pqcp_edge_credential_tick(&raw, T0, &changed),
		      -EINVAL);
	zassert_equal(pqcp_edge_credential_cache_audit(&raw), -EINVAL);

	cred_setup(2U);
	zassert_equal(pqcp_edge_credential_put(&cc, NULL, T0), -EINVAL);
#define BAD_CRED(mut)                                                   \
	do {                                                            \
		make_cred(&c, "c1");                                    \
		mut;                                                    \
		zassert_equal(pqcp_edge_credential_put(&cc, &c, T0),    \
			      -EINVAL, #mut);                           \
	} while (0)
	BAD_CRED(c.credential_id[0] = '\0');
	BAD_CRED(c.principal_id[0] = '\0');
	BAD_CRED(c.issuer_domain[0] = '\0');
	BAD_CRED(c.issuance_epoch = 0U);
	BAD_CRED(c.policy_epoch = 0U);
	BAD_CRED(c.revocation_epoch = 0U);
	BAD_CRED(c.refresh_at_ms = c.issued_at_ms - 1U);
	BAD_CRED(c.expires_at_ms = c.refresh_at_ms);
	BAD_CRED(c.capabilities = 0U);
	BAD_CRED(memset(c.public_key_digest, 0, sizeof(c.public_key_digest)));
	BAD_CRED(memset(c.credential_digest, 0,
			sizeof(c.credential_digest)));
	BAD_CRED(c.issued_at_ms = T0 + 1U);
#undef BAD_CRED
	make_cred(&c, "c1");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0 + 1000U),
		      -EINVAL);
	zassert_false(crstore[0].occupied);
	zassert_equal(pqcp_edge_credential_authorize(&cc, NULL, "p1", 1U, 2U,
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", NULL, 1U, 2U,
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 0U, 2U,
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 1U, 0U,
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 1U, 2U,
		0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 1U, 2U,
		1U, T0), -ENOENT);
	zassert_equal(pqcp_edge_credential_revoke(&cc, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_credential_revoke(&cc, "c1", 0U), -EINVAL);
	zassert_equal(pqcp_edge_credential_revoke(&cc, "c1", 2U), -ENOENT);
	zassert_equal(pqcp_edge_credential_tick(&cc, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_credential_cache_audit(&cc), 0);
}

ZTEST(edge_security, test_credential_authorization_gates)
{
	struct pqcp_edge_credential_record c;
	uint32_t changed = 0U;

	cred_setup(2U);
	make_cred(&c, "c1");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), 0);
	zassert_equal(crstore[0].state, PQCP_EDGE_CREDENTIAL_ACTIVE);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 0x1U,
		2U, 1U, T0 + 1U), 0);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "other",
		0x1U, 2U, 1U, T0 + 1U), -EACCES);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 0x4U,
		2U, 1U, T0 + 1U), -EACCES);
	/* The relying party knows newer epochs than the credential. */
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 0x1U,
		3U, 1U, T0 + 1U), -ESTALE);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 0x1U,
		2U, 2U, T0 + 1U), -ESTALE);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 0x1U,
		2U, 1U, T0 + 1000U), -EKEYEXPIRED);
	zassert_equal(cc.rejection_count, 5U);

	/* Refresh window: still valid by time but must be renewed. */
	zassert_equal(pqcp_edge_credential_tick(&cc, T0 + 500U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(crstore[0].state,
		      PQCP_EDGE_CREDENTIAL_REFRESH_REQUIRED);
	zassert_equal(cc.refresh_count, 1U);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 0x1U,
		2U, 1U, T0 + 501U), -EAGAIN);
	zassert_equal(pqcp_edge_credential_tick(&cc, T0 + 1000U, &changed),
		      0);
	zassert_equal(crstore[0].state, PQCP_EDGE_CREDENTIAL_EXPIRED);
	zassert_equal(pqcp_edge_credential_tick(&cc, T0 + 1001U, &changed),
		      0);
	zassert_equal(changed, 0U);
}

ZTEST(edge_security, test_credential_monotonic_updates_and_revocation)
{
	struct pqcp_edge_credential_record c;
	uint32_t generation;

	cred_setup(2U);
	make_cred(&c, "c1");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), 0);
	generation = crstore[0].generation;
	/* Replays and rollbacks of the same credential id are refused. */
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0 + 1U), -ESTALE);
	c.issuance_epoch = 2U;
	c.policy_epoch = 1U;
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0 + 1U), -ESTALE);
	c.policy_epoch = 2U;
	c.revocation_epoch = 0U + 1U;
	SETSTR(c.principal_id, "p2");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0 + 1U), -ESTALE);
	SETSTR(c.principal_id, "p1");
	zassert_equal(cc.rejection_count, 3U);
	zassert_equal(crstore[0].issuance_epoch, 1U);
	/* A newer issuance supersedes it and keeps the generation. */
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0 + 1U), 0);
	zassert_equal(crstore[0].issuance_epoch, 2U);
	zassert_equal(crstore[0].generation, generation);

	/* Revocation epochs only move forward; the record stays valid. */
	zassert_equal(pqcp_edge_credential_revoke(&cc, "c1", 1U), -ESTALE);
	zassert_equal(crstore[0].state, PQCP_EDGE_CREDENTIAL_ACTIVE);
	zassert_equal(pqcp_edge_credential_revoke(&cc, "c1", 5U), 0);
	zassert_equal(crstore[0].state, PQCP_EDGE_CREDENTIAL_REVOKED);
	zassert_not_equal(crstore[0].capabilities, 0U);
	zassert_equal(pqcp_edge_credential_revoke(&cc, "c1", 5U), -ESTALE);
	/* A revoked credential never authorizes and reports the dedicated
	 * revocation error (not the capability mismatch).
	 */
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 0x1U,
		2U, 1U, T0 + 2U), -EKEYREVOKED);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1",
		CAP_ALL, 2U, 1U, T0 + 2U), -EKEYREVOKED);
}

ZTEST(edge_security, test_credential_audit_detects_corruption)
{
	struct pqcp_edge_credential_record c;

	cred_setup(2U);
	make_cred(&c, "c1");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), 0);
	zassert_equal(pqcp_edge_credential_cache_audit(&cc), 0);
	crstore[0].generation = 0U;
	zassert_equal(pqcp_edge_credential_cache_audit(&cc), -EBADMSG);
	crstore[0].generation = 1U;
	crstore[0].state = (enum pqcp_edge_credential_state)9;
	zassert_equal(pqcp_edge_credential_cache_audit(&cc), -EBADMSG);
	crstore[0].state = PQCP_EDGE_CREDENTIAL_ACTIVE;
	memset(crstore[0].credential_digest, 0,
	       sizeof(crstore[0].credential_digest));
	zassert_equal(pqcp_edge_credential_cache_audit(&cc), -EBADMSG);
}

ZTEST(edge_security, test_credential_revocation_keeps_integrity_audit_clean)
{
	struct pqcp_edge_credential_record c;
	int ret;

	cred_setup(2U);
	make_cred(&c, "c1");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), 0);
	zassert_equal(pqcp_edge_credential_revoke(&cc, "c1", 5U), 0);
	ret = pqcp_edge_credential_cache_audit(&cc);
	zassert_equal(ret, 0);
}

ZTEST(edge_security, test_credential_capacity_exhaustion)
{
	struct pqcp_edge_credential_record c;
	struct pqcp_edge_credential_record snap[2];

	cred_setup(2U);
	make_cred(&c, "c1");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), 0);
	make_cred(&c, "c2");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), 0);
	memcpy(snap, crstore, sizeof(snap));
	make_cred(&c, "c3");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), -ENOSPC);
	zassert_mem_equal(crstore, snap, sizeof(snap));
	zassert_equal(cc.rejection_count, 1U);
}

ZTEST(edge_security, test_credential_revocation_survives_slot_recycling)
{
	struct pqcp_edge_credential_record c;
	struct pqcp_edge_credential_record snap;

	cred_setup(2U);
	make_cred(&c, "c1");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), 0);
	zassert_equal(pqcp_edge_credential_revoke(&cc, "c1", 5U), 0);
	make_cred(&c, "c2");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), 0);
	/* The revoked slot is a tombstone: it is never handed out. */
	make_cred(&c, "c3");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), -ENOSPC);
	/* The revoked id cannot be re-admitted, even with newer epochs. */
	memcpy(&snap, &crstore[0], sizeof(snap));
	make_cred(&c, "c1");
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), -EKEYREVOKED);
	c.issuance_epoch = 9U;
	c.revocation_epoch = 9U;
	zassert_equal(pqcp_edge_credential_put(&cc, &c, T0), -EKEYREVOKED);
	zassert_mem_equal(&crstore[0], &snap, sizeof(snap));
	zassert_equal(crstore[0].state, PQCP_EDGE_CREDENTIAL_REVOKED);
	zassert_equal(pqcp_edge_credential_authorize(&cc, "c1", "p1", 0x1U,
		1U, 1U, T0 + 1U), -EKEYREVOKED);
	zassert_equal(pqcp_edge_credential_cache_audit(&cc), 0);
}

/* ------------------------------------------------------------------ */
/* Isolation manager                                                   */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_isolation_zone izstore[2];
static struct pqcp_edge_isolation_manager iz;

static void iso_setup(void)
{
	zassert_equal(pqcp_edge_isolation_manager_init(
		&iz, izstore, ARRAY_SIZE(izstore)), 0);
}

static void make_zone(struct pqcp_edge_isolation_zone *z, const char *id)
{
	memset(z, 0, sizeof(*z));
	SETSTR(z->zone_id, id);
	z->state = PQCP_EDGE_ISOLATION_OPEN;
	z->allowed_capabilities = 0xfU;
	z->allowed_operations = ALL_OPERATIONS;
	z->maximum_workloads = 2U;
}

ZTEST(edge_security, test_isolation_rejects_invalid_arguments)
{
	static struct pqcp_edge_isolation_manager raw;
	struct pqcp_edge_isolation_zone z;
	uint32_t changed = 0U;

	zassert_equal(pqcp_edge_isolation_manager_init(NULL, izstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_isolation_manager_init(&iz, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_isolation_manager_init(&iz, izstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_zone(&z, "z1");
	zassert_equal(pqcp_edge_isolation_zone_put(&raw, &z), -EINVAL);
	zassert_equal(pqcp_edge_isolation_transition(&raw, "z1",
		PQCP_EDGE_ISOLATION_RESTRICTED, 1U, T0, 0U), -EINVAL);
	zassert_equal(pqcp_edge_isolation_authorize(&raw, "z1",
		PQCP_EDGE_OPERATION_READ, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_isolation_reserve(&raw, "z1"), -EINVAL);
	zassert_equal(pqcp_edge_isolation_release(&raw, "z1"), -EINVAL);
	zassert_equal(pqcp_edge_isolation_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_isolation_manager_audit(&raw), -EINVAL);

	iso_setup();
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, NULL), -EINVAL);
	make_zone(&z, "z1"); z.zone_id[0] = '\0';
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EINVAL);
	make_zone(&z, "z1"); z.state = (enum pqcp_edge_isolation_state)9;
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EINVAL);
	make_zone(&z, "z1"); z.maximum_workloads = 0U;
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EINVAL);
	make_zone(&z, "z1"); z.active_workloads = 3U;
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EINVAL);
	make_zone(&z, "z1"); z.allowed_capabilities = 0U;
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EINVAL);
	make_zone(&z, "z1"); z.allowed_operations = 0U;
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EINVAL);
	make_zone(&z, "z1"); z.state = PQCP_EDGE_ISOLATION_FAILSAFE;
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EINVAL);
	make_zone(&z, "z1"); z.entered_at_ms = 10U; z.expires_at_ms = 10U;
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EINVAL);
	zassert_false(izstore[0].occupied);

	zassert_equal(pqcp_edge_isolation_transition(&iz, NULL,
		PQCP_EDGE_ISOLATION_RESTRICTED, 1U, T0, 0U), -EINVAL);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		(enum pqcp_edge_isolation_state)9, 1U, T0, 0U), -EINVAL);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_RESTRICTED, 1U, T0, T0), -EINVAL);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_RESTRICTED, 0U, T0, 0U), -EINVAL);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_RESTRICTED, 1U, T0, 0U), -ENOENT);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, NULL,
		PQCP_EDGE_OPERATION_READ, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_NONE, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_COUNT, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_READ, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_READ, 1U, T0), -ENOENT);
	zassert_equal(iz.denial_count, 1U);
	zassert_equal(pqcp_edge_isolation_reserve(&iz, NULL), -EINVAL);
	zassert_equal(pqcp_edge_isolation_reserve(&iz, "z1"), -ENOENT);
	zassert_equal(pqcp_edge_isolation_release(&iz, NULL), -EINVAL);
	zassert_equal(pqcp_edge_isolation_release(&iz, "z1"), -ENOENT);
	zassert_equal(pqcp_edge_isolation_manager_audit(&iz), 0);
}

ZTEST(edge_security, test_isolation_states_restrict_operations)
{
	struct pqcp_edge_isolation_zone z;
	const uint64_t caps = 0x3U;

	iso_setup();
	make_zone(&z, "z1");
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), 0);

	/* OPEN honours the zone's allow-lists only. */
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_ADMINISTER, caps, T0), 0);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_READ, 0x10U, T0), -EACCES);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_READ, 0xfU, T0), 0);

	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_RESTRICTED, 0x1U, T0 + 1U, 0U), 0);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_READ, caps, T0 + 2U), 0);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_ADMINISTER, caps, T0 + 2U), -EACCES);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_DELETE, caps, T0 + 2U), -EACCES);

	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_QUARANTINED, 0x2U, T0 + 3U, 0U), 0);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_READ, caps, T0 + 4U), -EACCES);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_PUBLISH, caps, T0 + 4U), -EACCES);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_ATTEST, caps, T0 + 4U), 0);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_RECOVER, caps, T0 + 4U), 0);
	zassert_equal(pqcp_edge_isolation_reserve(&iz, "z1"), -EACCES);

	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_FAILSAFE, 0x4U, T0 + 5U, 0U), 0);
	zassert_equal(izstore[0].allowed_operations, 0U);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_ATTEST, caps, T0 + 6U), -EACCES);
	/* FAILSAFE can only be left via QUARANTINE. */
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_OPEN, 0U, T0 + 7U, 0U), -EPERM);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_RESTRICTED, 1U, T0 + 7U, 0U), -EPERM);
	zassert_equal(izstore[0].state, PQCP_EDGE_ISOLATION_FAILSAFE);
	zassert_equal(iz.transition_count, 3U);
	zassert_true(iz.denial_count >= 6U);
}

ZTEST(edge_security, test_isolation_expiry_workloads_and_put_rules)
{
	struct pqcp_edge_isolation_zone z;
	uint32_t changed = 0U;

	iso_setup();
	make_zone(&z, "z1");
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), 0);
	make_zone(&z, "z2");
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), 0);
	make_zone(&z, "z3");
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -ENOSPC);

	/* Workload slots. */
	zassert_equal(pqcp_edge_isolation_reserve(&iz, "z1"), 0);
	zassert_equal(pqcp_edge_isolation_reserve(&iz, "z1"), 0);
	zassert_equal(pqcp_edge_isolation_reserve(&iz, "z1"), -ENOSPC);
	/* Zone definition changes are refused while workloads run. */
	make_zone(&z, "z1");
	z.active_workloads = 0U;
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EBUSY);
	zassert_equal(izstore[0].active_workloads, 2U);

	/* Timed restrictions lapse via tick; quarantine with workloads
	 * degrades to RESTRICTED instead of fully opening.
	 */
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_QUARANTINED, 0x1U, T0, T0 + 100U), 0);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z2",
		PQCP_EDGE_ISOLATION_RESTRICTED, 0x1U, T0, T0 + 100U), 0);
	zassert_equal(pqcp_edge_isolation_tick(&iz, T0 + 99U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(pqcp_edge_isolation_tick(&iz, T0 + 100U, &changed), 0);
	zassert_equal(changed, 2U);
	zassert_equal(izstore[0].state, PQCP_EDGE_ISOLATION_RESTRICTED);
	zassert_equal(izstore[1].state, PQCP_EDGE_ISOLATION_OPEN);
	zassert_equal(pqcp_edge_isolation_release(&iz, "z1"), 0);
	zassert_equal(pqcp_edge_isolation_release(&iz, "z1"), 0);
	zassert_equal(pqcp_edge_isolation_release(&iz, "z1"), -EALREADY);

	/* Authorization also notices expiry. */
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z2",
		PQCP_EDGE_ISOLATION_QUARANTINED, 0x1U, T0 + 200U,
		T0 + 300U), 0);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z2",
		PQCP_EDGE_OPERATION_READ, 0x1U, T0 + 299U), -EACCES);
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z2",
		PQCP_EDGE_OPERATION_READ, 0x1U, T0 + 300U), 0);
	zassert_equal(izstore[1].state, PQCP_EDGE_ISOLATION_OPEN);

	/* Invalid direct state jump through put is refused. */
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z2",
		PQCP_EDGE_ISOLATION_FAILSAFE, 0x1U, T0 + 400U, 0U), 0);
	make_zone(&z, "z2");
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), -EPERM);
	zassert_equal(izstore[1].state, PQCP_EDGE_ISOLATION_FAILSAFE);
	zassert_equal(pqcp_edge_isolation_tick(&iz, T0 + 99999U, NULL), 0);
	zassert_equal(izstore[1].state, PQCP_EDGE_ISOLATION_FAILSAFE);

	izstore[1] = izstore[0];
	zassert_equal(pqcp_edge_isolation_manager_audit(&iz), -EEXIST);
	SETSTR(izstore[1].zone_id, "zz");
	izstore[1].maximum_workloads = 0U;
	zassert_equal(pqcp_edge_isolation_manager_audit(&iz), -EBADMSG);
}

ZTEST(edge_security, test_isolation_recovery_from_failsafe_yields_consistent_zone)
{
	struct pqcp_edge_isolation_zone z;
	int ret;

	iso_setup();
	make_zone(&z, "z1");
	zassert_equal(pqcp_edge_isolation_zone_put(&iz, &z), 0);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_FAILSAFE, 0x1U, T0, 0U), 0);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_QUARANTINED, 0x1U, T0 + 1U, 0U), 0);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_RESTRICTED, 0x1U, T0 + 2U, 0U), 0);
	zassert_equal(pqcp_edge_isolation_transition(&iz, "z1",
		PQCP_EDGE_ISOLATION_OPEN, 0U, T0 + 3U, 0U), 0);
	ret = pqcp_edge_isolation_manager_audit(&iz);
	zassert_equal(ret, 0);
	zassert_equal(izstore[0].allowed_capabilities, 0xfU);
	zassert_equal(izstore[0].allowed_operations, ALL_OPERATIONS);
	/* The restored zone really admits requests again. */
	zassert_equal(pqcp_edge_isolation_authorize(&iz, "z1",
		PQCP_EDGE_OPERATION_READ, 0x1U, T0 + 4U), 0);
}

/* ------------------------------------------------------------------ */
/* Provenance ledger                                                   */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_provenance_record pvstore[3];
static struct pqcp_edge_provenance_ledger pv;

static void prov_setup(void)
{
	zassert_equal(pqcp_edge_provenance_ledger_init(
		&pv, pvstore, ARRAY_SIZE(pvstore)), 0);
}

static int prov_append(enum pqcp_edge_provenance_event event,
		       uint8_t in_seed, uint8_t out_seed, uint64_t now,
		       struct pqcp_edge_provenance_record *rec)
{
	uint8_t in[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	uint8_t out[PQCP_EDGE_DIGEST_BYTES] = { 0 };

	if (in_seed != 0U) {
		edge_digest(in, in_seed);
	}
	if (out_seed != 0U) {
		edge_digest(out, out_seed);
	}
	return pqcp_edge_provenance_append(&pv, "artifact", "actor", "edge-1",
		event, 1U, in, out, now, rec);
}

ZTEST(edge_security, test_provenance_rejects_invalid_arguments)
{
	static struct pqcp_edge_provenance_ledger raw;
	struct pqcp_edge_provenance_record rec;
	uint8_t d[PQCP_EDGE_DIGEST_BYTES];
	char unterminated[PQCP_EDGE_OBJECT_MAX_CHARS];

	edge_digest(d, 1U);
	zassert_equal(pqcp_edge_provenance_ledger_init(NULL, pvstore, 3U),
		      -EINVAL);
	zassert_equal(pqcp_edge_provenance_ledger_init(&pv, NULL, 3U),
		      -EINVAL);
	zassert_equal(pqcp_edge_provenance_ledger_init(&pv, pvstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_provenance_append(&raw, "a", "b", "c",
		PQCP_EDGE_PROVENANCE_STORED, 1U, d, d, T0, &rec), -EINVAL);
	zassert_equal(pqcp_edge_provenance_find(&raw, 1U, &rec), -EINVAL);
	zassert_equal(pqcp_edge_provenance_verify(&raw), -EINVAL);

	prov_setup();
	memset(unterminated, 'x', sizeof(unterminated));
	zassert_equal(pqcp_edge_provenance_append(&pv, NULL, "b", "c",
		PQCP_EDGE_PROVENANCE_STORED, 1U, d, d, T0, &rec), -EINVAL);
	zassert_equal(pqcp_edge_provenance_append(&pv, "a", NULL, "c",
		PQCP_EDGE_PROVENANCE_STORED, 1U, d, d, T0, &rec), -EINVAL);
	zassert_equal(pqcp_edge_provenance_append(&pv, "a", "b", NULL,
		PQCP_EDGE_PROVENANCE_STORED, 1U, d, d, T0, &rec), -EINVAL);
	zassert_equal(pqcp_edge_provenance_append(&pv, "a", "b", "c",
		(enum pqcp_edge_provenance_event)9, 1U, d, d, T0, &rec),
		-EINVAL);
	zassert_equal(pqcp_edge_provenance_append(&pv, "a", "b", "c",
		PQCP_EDGE_PROVENANCE_STORED, 0U, d, d, T0, &rec), -EINVAL);
	zassert_equal(pqcp_edge_provenance_append(&pv, "a", "b", "c",
		PQCP_EDGE_PROVENANCE_STORED, 1U, NULL, d, T0, &rec),
		-EINVAL);
	zassert_equal(pqcp_edge_provenance_append(&pv, "a", "b", "c",
		PQCP_EDGE_PROVENANCE_STORED, 1U, d, NULL, T0, &rec),
		-EINVAL);
	zassert_equal(pqcp_edge_provenance_append(&pv, "a", "b", "c",
		PQCP_EDGE_PROVENANCE_STORED, 1U, d, d, 0U, &rec), -EINVAL);
	zassert_equal(pqcp_edge_provenance_append(&pv, unterminated, "b",
		"c", PQCP_EDGE_PROVENANCE_STORED, 1U, d, d, T0, &rec),
		-ENAMETOOLONG);
	zassert_equal(pqcp_edge_provenance_append(&pv, "", "b", "c",
		PQCP_EDGE_PROVENANCE_STORED, 1U, d, d, T0, &rec),
		-ENAMETOOLONG);
	zassert_equal(pv.count, 0U);
	zassert_equal(pv.next_sequence, 1U);
	zassert_equal(pqcp_edge_provenance_find(&pv, 0U, &rec), -EINVAL);
	zassert_equal(pqcp_edge_provenance_find(&pv, 1U, NULL), -EINVAL);
	zassert_equal(pqcp_edge_provenance_find(&pv, 2U, &rec), -ENOENT);
	zassert_equal(pqcp_edge_provenance_verify(&pv), 0);
}

ZTEST(edge_security, test_provenance_event_digest_semantics)
{
	struct pqcp_edge_provenance_record rec;

	prov_setup();
	/* CREATED: no input, a produced output. */
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_CREATED, 1U, 2U, T0,
		&rec), -EINVAL);
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_CREATED, 0U, 0U, T0,
		&rec), -EINVAL);
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_CREATED, 0U, 2U, T0,
		&rec), 0);
	/* TRANSFORMED must change the content. */
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_TRANSFORMED, 2U, 2U,
		T0 + 1U, &rec), -EINVAL);
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_TRANSFORMED, 2U, 3U,
		T0 + 1U, &rec), 0);
	/* Transfers and storage need both digests. */
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_STORED, 3U, 0U,
		T0 + 2U, &rec), -EINVAL);
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_REPLICATED, 0U, 3U,
		T0 + 2U, &rec), -EINVAL);
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_TRANSMITTED, 3U, 3U,
		T0 + 2U, &rec), 0);
	/* DELETED: input present, no output. */
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_DELETED, 3U, 4U,
		T0 + 3U, &rec), -EINVAL);
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_DELETED, 0U, 0U,
		T0 + 3U, &rec), -EINVAL);
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_DELETED, 3U, 0U,
		T0 + 3U, &rec), 0);
	/* Rejected appends consume no sequence number. */
	zassert_equal(pv.count, 3U);
	zassert_equal(pqcp_edge_provenance_verify(&pv), 0);
}

ZTEST(edge_security, test_provenance_chain_wraparound_and_tamper_detection)
{
	struct pqcp_edge_provenance_record r1;
	struct pqcp_edge_provenance_record r2;
	struct pqcp_edge_provenance_record found;

	prov_setup();
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_CREATED, 0U, 2U, T0,
		&r1), 0);
	zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_STORED, 2U, 2U,
		T0 + 1U, &r2), 0);
	zassert_equal(r2.sequence, r1.sequence + 1U);
	zassert_true(pqcp_edge_internal_all_zero(r1.previous_digest,
		sizeof(r1.previous_digest)));
	zassert_mem_equal(r2.previous_digest, r1.record_digest,
			  sizeof(r1.record_digest));
	zassert_mem_equal(pv.chain_head, r2.record_digest,
			  sizeof(r2.record_digest));
	zassert_equal(pqcp_edge_provenance_find(&pv, r1.sequence, &found), 0);
	zassert_mem_equal(&found, &r1, sizeof(found));
	zassert_equal(pqcp_edge_provenance_verify(&pv), 0);

	/* Ring semantics: oldest entries are overwritten and counted. */
	for (uint64_t i = 2U; i < 5U; ++i) {
		zassert_equal(prov_append(PQCP_EDGE_PROVENANCE_STORED, 2U, 2U,
			T0 + i, NULL), 0);
	}
	zassert_equal(pv.count, 3U);
	zassert_equal(pv.dropped_count, 2U);
	zassert_equal(pqcp_edge_provenance_find(&pv, r1.sequence, &found),
		      -ENOENT);
	zassert_equal(pqcp_edge_provenance_verify(&pv), 0);

	/* Tampering with any record field is detected. */
	pvstore[1].timestamp_ms ^= 1U;
	zassert_equal(pqcp_edge_provenance_verify(&pv), -EBADMSG);
	pvstore[1].timestamp_ms ^= 1U;
	zassert_equal(pqcp_edge_provenance_verify(&pv), 0);
	/* Splicing in a record from another chain breaks the linkage. */
	pvstore[2].previous_digest[0] ^= 1U;
	zassert_true(pqcp_edge_provenance_verify(&pv) != 0);
	pvstore[2].previous_digest[0] ^= 1U;
	/* A missing record is a sequence gap. */
	{
		struct pqcp_edge_provenance_record saved = pvstore[0];

		pvstore[0].sequence += 5U;
		zassert_true(pqcp_edge_provenance_verify(&pv) != 0);
		pvstore[0] = saved;
	}
	pv.chain_head[0] ^= 1U;
	zassert_equal(pqcp_edge_provenance_verify(&pv), -EBADMSG);
	pv.chain_head[0] ^= 1U;
	zassert_equal(pqcp_edge_provenance_verify(&pv), 0);
}

/* ------------------------------------------------------------------ */
/* Workload scheduler                                                  */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_workload_job jbstore[3];
static struct pqcp_edge_workload_scheduler ws;

static void sched_setup(size_t n)
{
	zassert_equal(pqcp_edge_workload_scheduler_init(&ws, jbstore, n), 0);
}

static void make_job(struct pqcp_edge_workload_job *j, uint32_t priority,
		     uint32_t resources)
{
	memset(j, 0, sizeof(*j));
	SETSTR(j->principal_id, "p1");
	SETSTR(j->service_id, "svc");
	j->earliest_start_ms = T0;
	j->deadline_ms = T0 + 1000U;
	j->estimated_cost = 10U;
	j->priority = priority;
	j->required_resource_mask = resources;
	j->maximum_attempts = 2U;
}

ZTEST(edge_security, test_scheduler_rejects_invalid_arguments)
{
	static struct pqcp_edge_workload_scheduler raw;
	struct pqcp_edge_workload_job j;
	struct pqcp_edge_workload_job *out = (void *)0x1;
	uint32_t changed = 0U;

	zassert_equal(pqcp_edge_workload_scheduler_init(NULL, jbstore, 3U),
		      -EINVAL);
	zassert_equal(pqcp_edge_workload_scheduler_init(&ws, NULL, 3U),
		      -EINVAL);
	zassert_equal(pqcp_edge_workload_scheduler_init(&ws, jbstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_job(&j, 1U, 1U);
	zassert_equal(pqcp_edge_workload_submit(&raw, &j, T0, &out),
		      -EINVAL);
	zassert_equal(pqcp_edge_workload_next(&raw, T0, 1U, &out), -EINVAL);
	zassert_equal(pqcp_edge_workload_complete(&raw, 1U, 0, T0), -EINVAL);
	zassert_equal(pqcp_edge_workload_retry(&raw, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_workload_cancel(&raw, 1U), -EINVAL);
	zassert_equal(pqcp_edge_workload_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_workload_scheduler_audit(&raw), -EINVAL);

	sched_setup(3U);
	zassert_equal(pqcp_edge_workload_submit(&ws, NULL, T0, &out),
		      -EINVAL);
#define BAD_JOB(mut)                                                    \
	do {                                                            \
		make_job(&j, 1U, 1U);                                   \
		mut;                                                    \
		zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0,    \
			&out), -EINVAL, #mut);                          \
	} while (0)
	BAD_JOB(j.principal_id[0] = '\0');
	BAD_JOB(j.service_id[0] = '\0');
	BAD_JOB(j.deadline_ms = j.earliest_start_ms);
	BAD_JOB(j.estimated_cost = 0U);
	BAD_JOB(j.priority = 0U);
	BAD_JOB(j.required_resource_mask = 0U);
	BAD_JOB(j.maximum_attempts = 0U);
	BAD_JOB(j.attempts = 5U);
	BAD_JOB(j.deadline_ms = T0 - 1U; j.earliest_start_ms = 0U);
	BAD_JOB(j.submitted_at_ms = T0 + 1U);
	BAD_JOB(j.earliest_start_ms = T0 - 10U; j.submitted_at_ms = T0);
#undef BAD_JOB
	zassert_false(jbstore[0].occupied);
	zassert_equal(pqcp_edge_workload_next(&ws, T0, 0U, &out), -EINVAL);
	zassert_equal(pqcp_edge_workload_next(&ws, T0, 1U, NULL), -EINVAL);
	zassert_equal(pqcp_edge_workload_next(&ws, T0, 1U, &out), -EAGAIN);
	zassert_equal(pqcp_edge_workload_complete(&ws, 0U, 0, T0), -EINVAL);
	zassert_equal(pqcp_edge_workload_complete(&ws, 9U, 0, T0), -ENOENT);
	zassert_equal(pqcp_edge_workload_retry(&ws, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_workload_retry(&ws, 1U, 0U), -EINVAL);
	zassert_equal(pqcp_edge_workload_retry(&ws, 9U, T0), -ENOENT);
	zassert_equal(pqcp_edge_workload_cancel(&ws, 0U), -EINVAL);
	zassert_equal(pqcp_edge_workload_cancel(&ws, 9U), -ENOENT);
	zassert_equal(pqcp_edge_workload_tick(&ws, T0, NULL), 0);
	zassert_equal(pqcp_edge_workload_scheduler_audit(&ws), 0);
}

ZTEST(edge_security, test_scheduler_priority_and_resource_exclusion)
{
	struct pqcp_edge_workload_job j;
	struct pqcp_edge_workload_job *low = NULL;
	struct pqcp_edge_workload_job *high = NULL;
	struct pqcp_edge_workload_job *other = NULL;
	struct pqcp_edge_workload_job *run = NULL;

	sched_setup(3U);
	make_job(&j, 1U, 0x1U);
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0, &low), 0);
	make_job(&j, 9U, 0x1U);
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0, &high), 0);
	make_job(&j, 5U, 0x2U);
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0, &other), 0);
	zassert_equal(high->state, PQCP_EDGE_JOB_QUEUED);

	/* Nothing runs when the offered resources do not cover the job. */
	{
		struct pqcp_edge_workload_job *none = (void *)0x1;

		zassert_equal(pqcp_edge_workload_next(&ws, T0, 0x4U, &none),
			      -EAGAIN);
	}
	zassert_equal(pqcp_edge_workload_next(&ws, T0, 0x3U, &run), 0);
	zassert_equal(run, high);
	zassert_equal(run->state, PQCP_EDGE_JOB_RUNNING);
	zassert_equal(run->attempts, 1U);
	/* Resource 0x1 is held: the low-priority job must wait, but the
	 * job on a disjoint resource may run in parallel.
	 */
	zassert_equal(pqcp_edge_workload_next(&ws, T0, 0x3U, &run), 0);
	zassert_equal(run, other);
	zassert_equal(pqcp_edge_workload_next(&ws, T0, 0x3U, &run), -EAGAIN);
	zassert_equal(low->state, PQCP_EDGE_JOB_QUEUED);
	zassert_equal(ws.reserved_resource_mask, 0x3U);
	zassert_equal(pqcp_edge_workload_scheduler_audit(&ws), 0);

	zassert_equal(pqcp_edge_workload_complete(&ws, high->job_id, 0,
		T0 + 1U), 0);
	zassert_equal(high->state, PQCP_EDGE_JOB_COMPLETED);
	zassert_equal(ws.completed_count, 1U);
	zassert_equal(ws.reserved_resource_mask, 0x2U);
	zassert_equal(pqcp_edge_workload_complete(&ws, high->job_id, 0,
		T0 + 2U), -EPERM);
	zassert_equal(pqcp_edge_workload_next(&ws, T0 + 3U, 0x3U, &run), 0);
	zassert_equal(run, low);
}

ZTEST(edge_security, test_scheduler_retry_deadline_and_cancellation)
{
	struct pqcp_edge_workload_job j;
	struct pqcp_edge_workload_job *a = NULL;
	struct pqcp_edge_workload_job *run = NULL;
	uint32_t changed = 0U;

	sched_setup(3U);
	make_job(&j, 1U, 0x1U);
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0, &a), 0);
	zassert_equal(pqcp_edge_workload_next(&ws, T0, 0x1U, &run), 0);
	/* Failure with attempts left parks the job for retry. */
	zassert_equal(pqcp_edge_workload_complete(&ws, a->job_id, -EIO,
		T0 + 1U), 0);
	zassert_equal(a->state, PQCP_EDGE_JOB_RETRY_WAIT);
	zassert_equal(a->result, -EIO);
	zassert_equal(ws.reserved_resource_mask, 0U);
	zassert_equal(pqcp_edge_workload_next(&ws, T0 + 2U, 0x1U, &run),
		      -EAGAIN);
	zassert_equal(pqcp_edge_workload_retry(&ws, a->job_id, T0 + 50U), 0);
	zassert_equal(pqcp_edge_workload_retry(&ws, a->job_id, T0 + 50U),
		      -EPERM);
	zassert_equal(pqcp_edge_workload_next(&ws, T0 + 49U, 0x1U, &run),
		      -EAGAIN);
	zassert_equal(pqcp_edge_workload_next(&ws, T0 + 50U, 0x1U, &run), 0);
	zassert_equal(a->attempts, 2U);
	/* Attempts exhausted: terminal failure. */
	zassert_equal(pqcp_edge_workload_complete(&ws, a->job_id, -EIO,
		T0 + 51U), 0);
	zassert_equal(a->state, PQCP_EDGE_JOB_FAILED);
	zassert_equal(ws.failed_count, 1U);
	zassert_equal(pqcp_edge_workload_cancel(&ws, a->job_id), -EALREADY);

	/* Deadlines: next() and tick() fail overdue work. */
	make_job(&j, 1U, 0x1U);
	j.deadline_ms = T0 + 100U;
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0 + 60U, &a), 0);
	zassert_equal(pqcp_edge_workload_next(&ws, T0 + 100U, 0x1U, &run),
		      -EAGAIN);
	zassert_equal(a->state, PQCP_EDGE_JOB_FAILED);
	zassert_equal(a->result, -ETIMEDOUT);
	zassert_equal(ws.failed_count, 2U);

	make_job(&j, 1U, 0x1U);
	j.deadline_ms = T0 + 200U;
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0 + 110U, &a), 0);
	zassert_equal(pqcp_edge_workload_tick(&ws, T0 + 200U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(a->state, PQCP_EDGE_JOB_FAILED);

	/* A running job can be cancelled and releases its resources. */
	make_job(&j, 1U, 0x1U);
	j.deadline_ms = T0 + 9000U;
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0 + 300U, &a), 0);
	zassert_equal(pqcp_edge_workload_next(&ws, T0 + 300U, 0x1U, &run), 0);
	zassert_equal(ws.reserved_resource_mask, 0x1U);
	zassert_equal(pqcp_edge_workload_cancel(&ws, a->job_id), 0);
	zassert_equal(a->state, PQCP_EDGE_JOB_CANCELLED);
	zassert_equal(ws.reserved_resource_mask, 0U);
	zassert_equal(pqcp_edge_workload_scheduler_audit(&ws), 0);
}

ZTEST(edge_security, test_scheduler_ids_capacity_and_audit)
{
	struct pqcp_edge_workload_job j;
	struct pqcp_edge_workload_job *a = NULL;
	struct pqcp_edge_workload_job *b = NULL;
	struct pqcp_edge_workload_job *c = (void *)0x1;
	struct pqcp_edge_workload_job *run = NULL;
	struct pqcp_edge_workload_job snap;

	sched_setup(2U);
	make_job(&j, 1U, 0x1U);
	j.job_id = 77U;
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0, &a), 0);
	zassert_equal(a->job_id, 77U);
	/* Explicit duplicate ids among live jobs are refused. */
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0, &b), -EEXIST);
	/* Auto ids continue after explicit ones. */
	j.job_id = 0U;
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0, &b), 0);
	zassert_true(b->job_id > 77U);
	snap = *a;
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0, &c), -ENOSPC);
	zassert_mem_equal(a, &snap, sizeof(snap));

	/* Finished jobs are reclaimed for new work. */
	zassert_equal(pqcp_edge_workload_next(&ws, T0, 0x1U, &run), 0);
	zassert_equal(pqcp_edge_workload_complete(&ws, run->job_id, 0,
		T0 + 1U), 0);
	zassert_equal(pqcp_edge_workload_submit(&ws, &j, T0 + 2U, &c), 0);
	zassert_equal(pqcp_edge_workload_scheduler_audit(&ws), 0);

	/* Audit catches double-booked resources and bookkeeping drift. */
	jbstore[0].state = PQCP_EDGE_JOB_RUNNING;
	jbstore[1].state = PQCP_EDGE_JOB_RUNNING;
	jbstore[0].required_resource_mask = 0x1U;
	jbstore[1].required_resource_mask = 0x1U;
	ws.reserved_resource_mask = 0x1U;
	zassert_equal(pqcp_edge_workload_scheduler_audit(&ws), -EDEADLK);
	jbstore[1].state = PQCP_EDGE_JOB_QUEUED;
	ws.reserved_resource_mask = 0x2U;
	zassert_equal(pqcp_edge_workload_scheduler_audit(&ws), -EBADMSG);
	ws.reserved_resource_mask = 0x1U;
	jbstore[1].job_id = jbstore[0].job_id;
	zassert_equal(pqcp_edge_workload_scheduler_audit(&ws), -EEXIST);
	jbstore[1].job_id = 99U;
	jbstore[1].priority = 0U;
	zassert_equal(pqcp_edge_workload_scheduler_audit(&ws), -EBADMSG);
}

/* ------------------------------------------------------------------ */
/* SLA monitor                                                         */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_sla_objective slstore[2];
static struct pqcp_edge_sla_monitor sla;

static void sla_setup(void)
{
	zassert_equal(pqcp_edge_sla_monitor_init(
		&sla, slstore, ARRAY_SIZE(slstore)), 0);
}

static void make_sla(struct pqcp_edge_sla_objective *o, const char *id,
		     uint32_t min_success, uint32_t max_error)
{
	memset(o, 0, sizeof(*o));
	SETSTR(o->service_id, id);
	o->window_ms = 1000U;
	o->maximum_latency_us = 1000U;
	o->minimum_success_basis_points = min_success;
	o->maximum_error_basis_points = max_error;
}

ZTEST(edge_security, test_sla_rejects_invalid_arguments)
{
	static struct pqcp_edge_sla_monitor raw;
	struct pqcp_edge_sla_objective o;
	enum pqcp_edge_sla_state state;
	uint32_t reset = 0U;

	zassert_equal(pqcp_edge_sla_monitor_init(NULL, slstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_sla_monitor_init(&sla, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_sla_monitor_init(&sla, slstore, 0U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_sla(&o, "svc", 9000U, 1000U);
	zassert_equal(pqcp_edge_sla_objective_put(&raw, &o, T0), -EINVAL);
	zassert_equal(pqcp_edge_sla_record(&raw, "svc", true, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_sla_evaluate(&raw, "svc", T0, &state),
		      -EINVAL);
	zassert_equal(pqcp_edge_sla_tick(&raw, T0, &reset), -EINVAL);
	zassert_equal(pqcp_edge_sla_monitor_audit(&raw), -EINVAL);

	sla_setup();
	zassert_equal(pqcp_edge_sla_objective_put(&sla, NULL, T0), -EINVAL);
	make_sla(&o, "svc", 9000U, 1000U); o.service_id[0] = '\0';
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -EINVAL);
	make_sla(&o, "svc", 9000U, 1000U); o.window_ms = 0U;
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -EINVAL);
	make_sla(&o, "svc", 9000U, 1000U); o.maximum_latency_us = 0U;
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -EINVAL);
	make_sla(&o, "svc", 0U, 10000U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -EINVAL);
	make_sla(&o, "svc", 10001U, 1000U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -EINVAL);
	make_sla(&o, "svc", 9000U, 10001U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -EINVAL);
	/* The success floor and error ceiling must be compatible. */
	make_sla(&o, "svc", 9000U, 500U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -EINVAL);
	make_sla(&o, "svc", 9000U, 1000U); o.request_count = 1U;
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -EINVAL);
	make_sla(&o, "svc", 9000U, 1000U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, 0U), -EINVAL);
	make_sla(&o, "svc", 9000U, 1000U);
	o.window_started_ms = T0 + 5U;
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -EINVAL);
	zassert_false(slstore[0].occupied);

	zassert_equal(pqcp_edge_sla_record(&sla, NULL, true, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_sla_record(&sla, "svc", true, 1U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_edge_sla_record(&sla, "svc", true, 1U, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_sla_evaluate(&sla, NULL, T0, &state),
		      -EINVAL);
	zassert_equal(pqcp_edge_sla_evaluate(&sla, "svc", T0, NULL),
		      -EINVAL);
	zassert_equal(pqcp_edge_sla_evaluate(&sla, "svc", T0, &state),
		      -ENOENT);
	zassert_equal(pqcp_edge_sla_tick(&sla, T0, NULL), 0);
	zassert_equal(pqcp_edge_sla_monitor_audit(&sla), 0);
}

ZTEST(edge_security, test_sla_state_follows_observed_service_quality)
{
	struct pqcp_edge_sla_objective o;
	enum pqcp_edge_sla_state state;

	sla_setup();
	make_sla(&o, "svc", 9000U, 1000U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), 0);
	zassert_equal(slstore[0].window_started_ms, T0);
	zassert_equal(pqcp_edge_sla_evaluate(&sla, "svc", T0, &state), 0);
	zassert_equal(state, PQCP_EDGE_SLA_UNKNOWN);

	for (int i = 0; i < 10; ++i) {
		zassert_equal(pqcp_edge_sla_record(&sla, "svc", true, 100U,
			T0 + 1U + i), 0);
	}
	zassert_equal(pqcp_edge_sla_evaluate(&sla, "svc", T0 + 20U, &state),
		      0);
	zassert_equal(state, PQCP_EDGE_SLA_HEALTHY);

	/* One error in eleven: success is above the floor but close to it. */
	zassert_equal(pqcp_edge_sla_record(&sla, "svc", false, 100U,
		T0 + 30U), 0);
	zassert_equal(slstore[0].state, PQCP_EDGE_SLA_AT_RISK);
	zassert_equal(sla.breach_count, 0U);
	/* More errors breach once, then stay breached without recounting. */
	zassert_equal(pqcp_edge_sla_record(&sla, "svc", false, 100U,
		T0 + 31U), 0);
	zassert_equal(pqcp_edge_sla_record(&sla, "svc", false, 100U,
		T0 + 32U), 0);
	zassert_equal(slstore[0].state, PQCP_EDGE_SLA_BREACHED);
	zassert_equal(sla.breach_count, 1U);
	zassert_equal(pqcp_edge_sla_record(&sla, "svc", false, 100U,
		T0 + 33U), 0);
	zassert_equal(sla.breach_count, 1U);
	zassert_equal(pqcp_edge_sla_monitor_audit(&sla), 0);

	/* Window rollover forgets history. */
	zassert_equal(pqcp_edge_sla_evaluate(&sla, "svc", T0 + 1000U,
		&state), 0);
	zassert_equal(state, PQCP_EDGE_SLA_UNKNOWN);
	zassert_equal(slstore[0].request_count, 0U);
	zassert_equal(slstore[0].window_started_ms, T0 + 1000U);
}

ZTEST(edge_security, test_sla_latency_objectives_and_maintenance)
{
	struct pqcp_edge_sla_objective o;
	enum pqcp_edge_sla_state state;
	uint32_t reset = 0U;

	sla_setup();
	make_sla(&o, "svc", 9000U, 1000U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), 0);
	make_sla(&o, "other", 9000U, 1000U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), 0);
	make_sla(&o, "third", 9000U, 1000U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), -ENOSPC);

	/* Average latency over the objective breaches. */
	zassert_equal(pqcp_edge_sla_record(&sla, "svc", true, 1500U,
		T0 + 1U), 0);
	zassert_equal(pqcp_edge_sla_evaluate(&sla, "svc", T0 + 2U, &state),
		      0);
	zassert_equal(state, PQCP_EDGE_SLA_BREACHED);
	/* A single extreme outlier alone is enough as well. */
	zassert_equal(pqcp_edge_sla_record(&sla, "other", true, 4001U,
		T0 + 1U), 0);
	zassert_equal(slstore[1].state, PQCP_EDGE_SLA_BREACHED);

	/* Replacing an objective keeps its running window. */
	make_sla(&o, "svc", 9000U, 1000U);
	o.maximum_latency_us = 5000U;
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0 + 3U), 0);
	zassert_equal(slstore[0].request_count, 1U);
	zassert_equal(slstore[0].state, PQCP_EDGE_SLA_HEALTHY);

	zassert_equal(pqcp_edge_sla_tick(&sla, T0 + 999U, &reset), 0);
	zassert_equal(reset, 0U);
	zassert_equal(pqcp_edge_sla_tick(&sla, T0 + 1000U, &reset), 0);
	zassert_equal(reset, 2U);
	zassert_equal(slstore[0].request_count, 0U);
	zassert_equal(slstore[0].state, PQCP_EDGE_SLA_UNKNOWN);

	slstore[0].success_count = 5U;
	zassert_equal(pqcp_edge_sla_monitor_audit(&sla), -EBADMSG);
	slstore[0].success_count = 0U;
	slstore[1] = slstore[0];
	zassert_equal(pqcp_edge_sla_monitor_audit(&sla), -EEXIST);
}

ZTEST(edge_security, test_sla_ninety_nine_percent_objective_can_be_healthy)
{
	struct pqcp_edge_sla_objective o;
	enum pqcp_edge_sla_state state = PQCP_EDGE_SLA_UNKNOWN;

	sla_setup();
	make_sla(&o, "svc", 9900U, 100U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), 0);
	for (int i = 0; i < 100; ++i) {
		zassert_equal(pqcp_edge_sla_record(&sla, "svc", true, 100U,
			T0 + 1U), 0);
	}
	zassert_equal(pqcp_edge_sla_evaluate(&sla, "svc", T0 + 2U, &state),
		      0);
	zassert_equal(state, PQCP_EDGE_SLA_HEALTHY);

	/* A tight objective that is only just met is still flagged. */
	make_sla(&o, "svc2", 9900U, 100U);
	zassert_equal(pqcp_edge_sla_objective_put(&sla, &o, T0), 0);
	for (int i = 0; i < 99; ++i) {
		zassert_equal(pqcp_edge_sla_record(&sla, "svc2", true, 100U,
			T0 + 1U), 0);
	}
	zassert_equal(pqcp_edge_sla_record(&sla, "svc2", false, 100U,
		T0 + 1U), 0);
	zassert_equal(pqcp_edge_sla_evaluate(&sla, "svc2", T0 + 2U, &state),
		      0);
	zassert_equal(state, PQCP_EDGE_SLA_AT_RISK);
}

/* ------------------------------------------------------------------ */
/* Configuration manager                                               */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_config_transaction cfstore[2];
static struct pqcp_edge_config_manager cfg;
static uint8_t cf_a[PQCP_EDGE_DIGEST_BYTES];
static uint8_t cf_b[PQCP_EDGE_DIGEST_BYTES];
static uint8_t cf_c[PQCP_EDGE_DIGEST_BYTES];
static uint8_t cf_v[PQCP_EDGE_DIGEST_BYTES];

static void config_setup(void)
{
	edge_digest(cf_a, 0x10U);
	edge_digest(cf_b, 0x20U);
	edge_digest(cf_c, 0x30U);
	edge_digest(cf_v, 0x40U);
	zassert_equal(pqcp_edge_config_manager_init(
		&cfg, cfstore, ARRAY_SIZE(cfstore), 5U, cf_a), 0);
}

ZTEST(edge_security, test_config_rejects_invalid_arguments)
{
	static struct pqcp_edge_config_manager raw;
	uint8_t zero[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	struct pqcp_edge_config_transaction *t = (void *)0x1;
	uint32_t aborted = 0U;

	config_setup();
	zassert_equal(pqcp_edge_config_manager_init(NULL, cfstore, 2U, 5U,
		cf_a), -EINVAL);
	zassert_equal(pqcp_edge_config_manager_init(&cfg, NULL, 2U, 5U,
		cf_a), -EINVAL);
	zassert_equal(pqcp_edge_config_manager_init(&cfg, cfstore, 0U, 5U,
		cf_a), -EINVAL);
	zassert_equal(pqcp_edge_config_manager_init(&cfg, cfstore, 2U, 0U,
		cf_a), -EINVAL);
	zassert_equal(pqcp_edge_config_manager_init(&cfg, cfstore, 2U, 5U,
		NULL), -EINVAL);
	zassert_equal(pqcp_edge_config_manager_init(&cfg, cfstore, 2U, 5U,
		zero), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_config_prepare(&raw, 5U, 6U, cf_a, cf_b, T0,
		T0 + 10U, &t), -EINVAL);
	zassert_equal(pqcp_edge_config_validate(&raw, 1U, cf_v, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_config_commit(&raw, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_config_abort(&raw, 1U, -EIO), -EINVAL);
	zassert_equal(pqcp_edge_config_tick(&raw, T0, &aborted), -EINVAL);
	zassert_equal(pqcp_edge_config_manager_audit(&raw), -EINVAL);

	config_setup();
	zassert_equal(pqcp_edge_config_prepare(&cfg, 0U, 6U, cf_a, cf_b, T0,
		T0 + 10U, &t), -EINVAL);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 5U, cf_a, cf_b, T0,
		T0 + 10U, &t), -EINVAL);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, NULL, cf_b, T0,
		T0 + 10U, &t), -EINVAL);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, NULL, T0,
		T0 + 10U, &t), -EINVAL);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, zero, cf_b, T0,
		T0 + 10U, &t), -EINVAL);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, zero, T0,
		T0 + 10U, &t), -EINVAL);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, cf_a, T0,
		T0 + 10U, &t), -EINVAL);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, cf_b, 0U,
		T0 + 10U, &t), -EINVAL);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, cf_b, T0,
		T0, &t), -EINVAL);
	zassert_false(cfstore[0].occupied);
	zassert_equal(pqcp_edge_config_validate(&cfg, 0U, cf_v, T0), -EINVAL);
	zassert_equal(pqcp_edge_config_validate(&cfg, 1U, NULL, T0), -EINVAL);
	zassert_equal(pqcp_edge_config_validate(&cfg, 1U, zero, T0), -EINVAL);
	zassert_equal(pqcp_edge_config_validate(&cfg, 9U, cf_v, T0), -ENOENT);
	zassert_equal(pqcp_edge_config_commit(&cfg, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_config_commit(&cfg, 9U, T0), -ENOENT);
	zassert_equal(pqcp_edge_config_abort(&cfg, 0U, -EIO), -EINVAL);
	zassert_equal(pqcp_edge_config_abort(&cfg, 9U, -EIO), -ENOENT);
	zassert_equal(pqcp_edge_config_tick(&cfg, T0, NULL), 0);
	zassert_equal(pqcp_edge_config_manager_audit(&cfg), 0);
}

ZTEST(edge_security, test_config_two_phase_commit_is_generation_bound)
{
	struct pqcp_edge_config_transaction *t = NULL;
	uint64_t id;

	config_setup();
	/* Base must be the active generation and digest. */
	zassert_equal(pqcp_edge_config_prepare(&cfg, 4U, 6U, cf_a, cf_b, T0,
		T0 + 100U, &t), -ESTALE);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_c, cf_b, T0,
		T0 + 100U, &t), -ESTALE);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, cf_b, T0,
		T0 + 100U, &t), 0);
	id = t->transaction_id;
	zassert_equal(t->state, PQCP_EDGE_CONFIG_PREPARED);
	/* Only one pending transaction per target generation. */
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, cf_c, T0,
		T0 + 100U, NULL), -EINPROGRESS);

	/* Commit requires validation first. */
	zassert_equal(pqcp_edge_config_commit(&cfg, id, T0 + 1U), -EPERM);
	zassert_equal(cfg.active_generation, 5U);
	zassert_equal(pqcp_edge_config_validate(&cfg, id, cf_v, T0 + 2U), 0);
	zassert_equal(pqcp_edge_config_validate(&cfg, id, cf_v, T0 + 2U),
		      -EALREADY);
	zassert_equal(pqcp_edge_config_commit(&cfg, id, T0 + 3U), 0);
	zassert_equal(cfg.active_generation, 6U);
	zassert_mem_equal(cfg.active_digest, cf_b, sizeof(cf_b));
	zassert_equal(cfg.commit_count, 1U);
	zassert_equal(pqcp_edge_config_commit(&cfg, id, T0 + 4U), -EALREADY);
	zassert_equal(pqcp_edge_config_abort(&cfg, id, -EIO), -EALREADY);
	zassert_equal(pqcp_edge_config_validate(&cfg, id, cf_v, T0 + 4U),
		      -EPERM);
	zassert_equal(cfg.active_generation, 6U);
	/* The old base can no longer be used (no rollback by replay). */
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 7U, cf_a, cf_c, T0,
		T0 + 100U, &t), -ESTALE);
	zassert_equal(pqcp_edge_config_manager_audit(&cfg), 0);
}

ZTEST(edge_security, test_config_commit_aborts_competing_transactions)
{
	struct pqcp_edge_config_transaction *t1 = NULL;
	struct pqcp_edge_config_transaction *t2 = NULL;

	config_setup();
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, cf_b, T0,
		T0 + 100U, &t1), 0);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 7U, cf_a, cf_c, T0,
		T0 + 100U, &t2), 0);
	zassert_equal(pqcp_edge_config_validate(&cfg, t1->transaction_id,
		cf_v, T0 + 1U), 0);
	zassert_equal(pqcp_edge_config_validate(&cfg, t2->transaction_id,
		cf_v, T0 + 1U), 0);
	zassert_equal(pqcp_edge_config_commit(&cfg, t1->transaction_id,
		T0 + 2U), 0);
	/* The loser was prepared against a base that no longer exists. */
	zassert_equal(t2->state, PQCP_EDGE_CONFIG_ABORTED);
	zassert_equal(t2->result, -ESTALE);
	zassert_equal(cfg.abort_count, 1U);
	zassert_equal(pqcp_edge_config_commit(&cfg, t2->transaction_id,
		T0 + 3U), -EPERM);
	zassert_equal(cfg.active_generation, 6U);
	zassert_equal(pqcp_edge_config_manager_audit(&cfg), 0);
}

ZTEST(edge_security, test_config_expiry_abort_and_slot_reuse)
{
	struct pqcp_edge_config_transaction *t = NULL;
	struct pqcp_edge_config_transaction *u = NULL;
	struct pqcp_edge_config_transaction *v = (void *)0x1;
	uint32_t aborted = 0U;

	config_setup();
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, cf_b, T0,
		T0 + 100U, &t), 0);
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 7U, cf_a, cf_c, T0,
		T0 + 500U, &u), 0);
	/* Table full with pending work. */
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 8U, cf_a, cf_c, T0,
		T0 + 500U, &v), -ENOSPC);

	/* A late validate aborts rather than extends the transaction. */
	zassert_equal(pqcp_edge_config_validate(&cfg, t->transaction_id,
		cf_v, T0 + 100U), -ETIMEDOUT);
	zassert_equal(t->state, PQCP_EDGE_CONFIG_ABORTED);
	zassert_equal(t->result, -ETIMEDOUT);
	zassert_equal(pqcp_edge_config_tick(&cfg, T0 + 499U, &aborted), 0);
	zassert_equal(aborted, 0U);
	zassert_equal(pqcp_edge_config_tick(&cfg, T0 + 500U, &aborted), 0);
	zassert_equal(aborted, 1U);
	zassert_equal(u->state, PQCP_EDGE_CONFIG_ABORTED);
	zassert_equal(cfg.abort_count, 2U);
	zassert_equal(cfg.active_generation, 5U);

	/* Terminal slots are reused, oldest first. */
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, cf_b,
		T0 + 600U, T0 + 900U, &v), 0);
	zassert_equal(v, t);

	/* Expired validated transaction cannot be committed. */
	zassert_equal(pqcp_edge_config_validate(&cfg, v->transaction_id,
		cf_v, T0 + 601U), 0);
	zassert_equal(pqcp_edge_config_commit(&cfg, v->transaction_id,
		T0 + 900U), -ETIMEDOUT);
	zassert_equal(cfg.active_generation, 5U);
	zassert_equal(pqcp_edge_config_manager_audit(&cfg), 0);

	/* Explicit abort records the reason, default reason is cancelled. */
	zassert_equal(pqcp_edge_config_prepare(&cfg, 5U, 6U, cf_a, cf_b,
		T0 + 1000U, T0 + 2000U, &v), 0);
	zassert_equal(pqcp_edge_config_abort(&cfg, v->transaction_id, 0), 0);
	zassert_equal(v->result, -ECANCELED);
	zassert_equal(pqcp_edge_config_manager_audit(&cfg), 0);
	v->validation_digest[0] = 0U;
	v->state = PQCP_EDGE_CONFIG_VALIDATED;
	zassert_equal(pqcp_edge_config_manager_audit(&cfg), -EBADMSG);
	v->state = PQCP_EDGE_CONFIG_ABORTED;
	v->result = 0;
	zassert_equal(pqcp_edge_config_manager_audit(&cfg), -EBADMSG);
}
