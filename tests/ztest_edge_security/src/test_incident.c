/*
 * SPDX-License-Identifier: MIT
 *
 * Detection and response: signals, incidents, playbooks, evidence custody,
 * containment, continuity, anomaly scoring and recovery.
 */

#include "edge_security_internal.h"
#include "test_common.h"

/* ------------------------------------------------------------------ */
/* Signal engine                                                       */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_signal sgstore[2];
static struct pqcp_edge_signal_engine sg;

static void signal_setup(void)
{
	zassert_equal(pqcp_edge_signal_engine_init(
		&sg, sgstore, ARRAY_SIZE(sgstore)), 0);
}

static void make_signal(struct pqcp_edge_signal *s,
			enum pqcp_edge_signal_type type,
			enum pqcp_edge_incident_severity severity,
			const char *subject, uint8_t evidence_seed)
{
	memset(s, 0, sizeof(*s));
	s->type = type;
	s->severity = severity;
	SETSTR(s->source_id, "sensor-1");
	SETSTR(s->subject_id, subject);
	s->observed_at_ms = T0;
	s->policy_epoch = 1U;
	s->magnitude = 1U;
	s->confidence = 1000U;
	edge_digest(s->evidence_digest, evidence_seed);
}

ZTEST(edge_security, test_signal_rejects_invalid_arguments)
{
	static struct pqcp_edge_signal_engine raw;
	struct pqcp_edge_signal s;
	struct pqcp_edge_signal *acc = (void *)0x1;
	uint64_t ids[PQCP_EDGE_MAX_INCIDENT_SIGNALS];
	uint32_t risk = 0U;
	uint32_t count = 0U;
	uint32_t expired = 0U;
	enum pqcp_edge_incident_severity sev;

	zassert_equal(pqcp_edge_signal_engine_init(NULL, sgstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_signal_engine_init(&sg, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_signal_engine_init(&sg, sgstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_signal(&s, PQCP_EDGE_SIGNAL_REPLAY, PQCP_EDGE_INCIDENT_LOW,
		    "sub", 1U);
	zassert_equal(pqcp_edge_signal_submit(&raw, &s, T0, &acc), -EINVAL);
	zassert_equal(pqcp_edge_signal_acknowledge(&raw, 1U), -EINVAL);
	zassert_equal(pqcp_edge_signal_correlate(&raw, "sub", 0U, &risk, &sev,
		ids, &count), -EINVAL);
	zassert_equal(pqcp_edge_signal_expire(&raw, T0, &expired), -EINVAL);
	zassert_equal(pqcp_edge_signal_engine_audit(&raw), -EINVAL);

	signal_setup();
	zassert_equal(pqcp_edge_signal_submit(&sg, NULL, T0, &acc), -EINVAL);
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0, NULL), -EINVAL);
#define BAD_SIG(mut)                                                    \
	do {                                                            \
		make_signal(&s, PQCP_EDGE_SIGNAL_REPLAY,                \
			    PQCP_EDGE_INCIDENT_LOW, "sub", 1U);         \
		mut;                                                    \
		zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0,      \
			&acc), -EINVAL, #mut);                          \
	} while (0)
	BAD_SIG(s.type = PQCP_EDGE_SIGNAL_COUNT);
	BAD_SIG(s.type = (enum pqcp_edge_signal_type)-1);
	BAD_SIG(s.severity = (enum pqcp_edge_incident_severity)9);
	BAD_SIG(s.source_id[0] = '\0');
	BAD_SIG(s.subject_id[0] = '\0');
	BAD_SIG(s.policy_epoch = 0U);
	BAD_SIG(s.magnitude = 0U);
	BAD_SIG(s.confidence = 1001U);
	BAD_SIG(memset(s.evidence_digest, 0, sizeof(s.evidence_digest)));
	BAD_SIG(s.observed_at_ms = T0 + 1U);
#undef BAD_SIG
	zassert_equal(sg.accepted_count, 0U);
	zassert_equal(pqcp_edge_signal_acknowledge(&sg, 0U), -EINVAL);
	zassert_equal(pqcp_edge_signal_acknowledge(&sg, 9U), -ENOENT);
	zassert_equal(pqcp_edge_signal_correlate(&sg, NULL, 0U, &risk, &sev,
		ids, &count), -EINVAL);
	zassert_equal(pqcp_edge_signal_correlate(&sg, "sub", 0U, NULL, &sev,
		ids, &count), -EINVAL);
	zassert_equal(pqcp_edge_signal_correlate(&sg, "sub", 0U, &risk, NULL,
		ids, &count), -EINVAL);
	zassert_equal(pqcp_edge_signal_correlate(&sg, "sub", 0U, &risk, &sev,
		NULL, &count), -EINVAL);
	zassert_equal(pqcp_edge_signal_correlate(&sg, "sub", 0U, &risk, &sev,
		ids, NULL), -EINVAL);
	zassert_equal(pqcp_edge_signal_expire(&sg, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_signal_engine_audit(&sg), 0);
}

ZTEST(edge_security, test_signal_deduplication_and_capacity)
{
	struct pqcp_edge_signal s;
	struct pqcp_edge_signal *a = NULL;
	struct pqcp_edge_signal *b = NULL;
	struct pqcp_edge_signal *c = NULL;
	struct pqcp_edge_signal snap;
	uint32_t expired = 0U;

	signal_setup();
	make_signal(&s, PQCP_EDGE_SIGNAL_REPLAY, PQCP_EDGE_INCIDENT_LOW,
		    "sub", 1U);
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0, &a), 0);
	zassert_true(a->signal_id != 0U);
	zassert_equal(a->observed_at_ms, T0);

	/* Same fingerprint: folded into the existing signal. */
	s.severity = PQCP_EDGE_INCIDENT_HIGH;
	s.magnitude = 3U;
	s.confidence = 500U;
	zassert_equal(pqcp_edge_signal_acknowledge(&sg, a->signal_id), 0);
	zassert_equal(pqcp_edge_signal_acknowledge(&sg, a->signal_id),
		      -EALREADY);
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0 + 5U, &b),
		      -EALREADY);
	zassert_equal(b, a);
	zassert_equal(a->severity, PQCP_EDGE_INCIDENT_HIGH);
	zassert_equal(a->magnitude, 4U);
	zassert_equal(a->confidence, 1000U);
	zassert_equal(a->observed_at_ms, T0 + 5U);
	/* A repeat re-arms acknowledgement so analysts see it again. */
	zassert_false(a->acknowledged);
	zassert_equal(sg.accepted_count, 1U);
	zassert_equal(sg.correlated_count, 1U);

	/* A lower severity repeat never downgrades. */
	s.severity = PQCP_EDGE_INCIDENT_INFORMATIONAL;
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0 + 6U, &b),
		      -EALREADY);
	zassert_equal(a->severity, PQCP_EDGE_INCIDENT_HIGH);

	/* A different source with the same evidence is a new signal. */
	make_signal(&s, PQCP_EDGE_SIGNAL_REPLAY, PQCP_EDGE_INCIDENT_LOW,
		    "sub", 1U);
	SETSTR(s.source_id, "sensor-2");
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0 + 7U, &b), 0);
	zassert_true(b->signal_id != a->signal_id);

	/* Full of unacknowledged signals: drop and count, never overwrite. */
	snap = *a;
	make_signal(&s, PQCP_EDGE_SIGNAL_KEY_FAILURE, PQCP_EDGE_INCIDENT_LOW,
		    "other", 9U);
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0 + 8U, &c),
		      -ENOSPC);
	zassert_is_null(c);
	zassert_equal(sg.dropped_count, 1U);
	zassert_mem_equal(a, &snap, sizeof(snap));

	/* Acknowledged signals are reclaimable, oldest first. */
	zassert_equal(pqcp_edge_signal_acknowledge(&sg, b->signal_id), 0);
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0 + 9U, &c), 0);
	zassert_equal(c, b);
	zassert_equal(pqcp_edge_signal_expire(&sg, T0 + 100U, &expired), 0);
	zassert_equal(expired, 0U);
	zassert_equal(pqcp_edge_signal_engine_audit(&sg), 0);
}

ZTEST(edge_security, test_signal_correlation_scoring)
{
	static struct pqcp_edge_signal big[20];
	static struct pqcp_edge_signal_engine big_engine;
	struct pqcp_edge_signal s;
	struct pqcp_edge_signal *acc = NULL;
	uint64_t ids[PQCP_EDGE_MAX_INCIDENT_SIGNALS];
	uint32_t risk = 7U;
	uint32_t count = 7U;
	enum pqcp_edge_incident_severity sev;

	signal_setup();
	zassert_equal(pqcp_edge_signal_correlate(&sg, "sub", 0U, &risk, &sev,
		ids, &count), -ENOENT);
	zassert_equal(risk, 0U);
	zassert_equal(count, 0U);

	/* (HIGH 250 + INTEGRITY 200) * magnitude 2 * confidence 50% = 450. */
	make_signal(&s, PQCP_EDGE_SIGNAL_INTEGRITY_FAILURE,
		    PQCP_EDGE_INCIDENT_HIGH, "sub", 1U);
	s.magnitude = 2U;
	s.confidence = 500U;
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0, &acc), 0);
	zassert_equal(pqcp_edge_signal_correlate(&sg, "sub", 0U, &risk, &sev,
		ids, &count), 0);
	zassert_equal(risk, 450U);
	zassert_equal(sev, PQCP_EDGE_INCIDENT_HIGH);
	zassert_equal(count, 1U);
	zassert_equal(ids[0], acc->signal_id);

	/* (LOW 40 + OPERATOR_ALERT 150) * 1 * 100% = 190, added later. */
	make_signal(&s, PQCP_EDGE_SIGNAL_OPERATOR_ALERT,
		    PQCP_EDGE_INCIDENT_LOW, "sub", 2U);
	s.observed_at_ms = T0 + 100U;
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0 + 100U, &acc), 0);
	zassert_equal(pqcp_edge_signal_correlate(&sg, "sub", 0U, &risk, &sev,
		ids, &count), 0);
	zassert_equal(risk, 640U);
	zassert_equal(count, 2U);
	/* The time window and subject filter are honoured. */
	zassert_equal(pqcp_edge_signal_correlate(&sg, "sub", T0 + 50U, &risk,
		&sev, ids, &count), 0);
	zassert_equal(risk, 190U);
	zassert_equal(sev, PQCP_EDGE_INCIDENT_LOW);
	zassert_equal(pqcp_edge_signal_correlate(&sg, "elsewhere", 0U, &risk,
		&sev, ids, &count), -ENOENT);

	/* Scores saturate at 1000 and report at most 16 signal ids. */
	zassert_equal(pqcp_edge_signal_engine_init(
		&big_engine, big, ARRAY_SIZE(big)), 0);
	for (uint8_t i = 0U; i < 20U; ++i) {
		make_signal(&s, PQCP_EDGE_SIGNAL_KEY_FAILURE,
			    PQCP_EDGE_INCIDENT_CRITICAL, "victim", i + 1U);
		s.magnitude = 10U;
		zassert_equal(pqcp_edge_signal_submit(&big_engine, &s, T0,
			&acc), 0);
	}
	zassert_equal(pqcp_edge_signal_correlate(&big_engine, "victim", 0U,
		&risk, &sev, ids, &count), 0);
	zassert_equal(risk, 1000U);
	zassert_equal(sev, PQCP_EDGE_INCIDENT_CRITICAL);
	zassert_equal(count, PQCP_EDGE_MAX_INCIDENT_SIGNALS);
}

ZTEST(edge_security, test_signal_expire_and_audit)
{
	struct pqcp_edge_signal s;
	struct pqcp_edge_signal *a = NULL;
	struct pqcp_edge_signal *b = NULL;
	uint32_t expired = 0U;

	signal_setup();
	make_signal(&s, PQCP_EDGE_SIGNAL_REPLAY, PQCP_EDGE_INCIDENT_LOW,
		    "sub", 1U);
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0, &a), 0);
	make_signal(&s, PQCP_EDGE_SIGNAL_REPLAY, PQCP_EDGE_INCIDENT_LOW,
		    "sub", 2U);
	zassert_equal(pqcp_edge_signal_submit(&sg, &s, T0, &b), 0);
	zassert_equal(pqcp_edge_signal_acknowledge(&sg, a->signal_id), 0);

	/* Only acknowledged, old signals are removed. */
	zassert_equal(pqcp_edge_signal_expire(&sg, T0, &expired), 0);
	zassert_equal(expired, 0U);
	zassert_equal(pqcp_edge_signal_expire(&sg, T0 + 1U, &expired), 0);
	zassert_equal(expired, 1U);
	zassert_false(sgstore[0].occupied);
	zassert_true(sgstore[1].occupied);
	zassert_equal(pqcp_edge_signal_engine_audit(&sg), 0);

	sgstore[1].magnitude = 0U;
	zassert_equal(pqcp_edge_signal_engine_audit(&sg), -EBADMSG);
	sgstore[1].magnitude = 1U;
	sgstore[0] = sgstore[1];
	zassert_equal(pqcp_edge_signal_engine_audit(&sg), -EEXIST);
}

/* ------------------------------------------------------------------ */
/* Incident manager                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_incident instore[2];
static struct pqcp_edge_incident_manager im;

static void incident_setup(void)
{
	zassert_equal(pqcp_edge_incident_manager_init(
		&im, instore, ARRAY_SIZE(instore)), 0);
}

static struct pqcp_edge_incident *open_incident(
	enum pqcp_edge_incident_severity severity, uint64_t now)
{
	const uint64_t ids[2] = { 11U, 12U };
	struct pqcp_edge_incident *inc = NULL;

	zassert_equal(pqcp_edge_incident_open(&im, "title", "subject",
		"owner", severity, 300U, ids, 2U, now, &inc), 0);
	return inc;
}

ZTEST(edge_security, test_incident_rejects_invalid_arguments)
{
	static struct pqcp_edge_incident_manager raw;
	struct pqcp_edge_incident *inc = (void *)0x1;
	const uint64_t ids[2] = { 1U, 2U };
	const uint64_t zero_id[1] = { 0U };
	const uint64_t dup_ids[2] = { 5U, 5U };
	uint64_t many[PQCP_EDGE_MAX_INCIDENT_SIGNALS + 1U] = { 1U };

	zassert_equal(pqcp_edge_incident_manager_init(NULL, instore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_incident_manager_init(&im, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_incident_manager_init(&im, instore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_incident_open(&raw, "t", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, ids, 2U, T0, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_add_signal(&raw, 1U, 1U, 1U,
		PQCP_EDGE_INCIDENT_LOW, T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_transition(&raw, 1U,
		PQCP_EDGE_INCIDENT_TRIAGED, T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_assign(&raw, 1U, "o", T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_find(&raw, 1U, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_manager_audit(&raw), -EINVAL);

	incident_setup();
	zassert_equal(pqcp_edge_incident_open(&im, NULL, "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, ids, 2U, T0, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_open(&im, "", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, ids, 2U, T0, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_open(&im, "t", NULL, "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, ids, 2U, T0, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "",
		PQCP_EDGE_INCIDENT_LOW, 1U, ids, 2U, T0, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "o",
		(enum pqcp_edge_incident_severity)9, 1U, ids, 2U, T0, &inc),
		-EINVAL);
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1001U, ids, 2U, T0, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, NULL, 2U, T0, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, many,
		PQCP_EDGE_MAX_INCIDENT_SIGNALS + 1U, T0, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, ids, 2U, T0, NULL), -EINVAL);
	/* Bad signal ids are rejected without consuming a slot. */
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, zero_id, 1U, T0, &inc), -EINVAL);
	zassert_is_null(inc);
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, dup_ids, 2U, T0, &inc), -EINVAL);
	zassert_false(instore[0].occupied);
	zassert_equal(im.opened_count, 0U);

	zassert_equal(pqcp_edge_incident_add_signal(&im, 0U, 1U, 1U,
		PQCP_EDGE_INCIDENT_LOW, T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_add_signal(&im, 1U, 0U, 1U,
		PQCP_EDGE_INCIDENT_LOW, T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_add_signal(&im, 1U, 1U, 1001U,
		PQCP_EDGE_INCIDENT_LOW, T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_add_signal(&im, 1U, 1U, 1U,
		(enum pqcp_edge_incident_severity)9, T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_add_signal(&im, 9U, 1U, 1U,
		PQCP_EDGE_INCIDENT_LOW, T0), -ENOENT);
	zassert_equal(pqcp_edge_incident_transition(&im, 0U,
		PQCP_EDGE_INCIDENT_TRIAGED, T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_transition(&im, 1U,
		PQCP_EDGE_INCIDENT_EMPTY, T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_transition(&im, 1U,
		(enum pqcp_edge_incident_state)9, T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_transition(&im, 9U,
		PQCP_EDGE_INCIDENT_TRIAGED, T0), -ENOENT);
	zassert_equal(pqcp_edge_incident_assign(&im, 0U, "o", T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_assign(&im, 1U, "", T0), -EINVAL);
	zassert_equal(pqcp_edge_incident_assign(&im, 9U, "o", T0), -ENOENT);
	zassert_equal(pqcp_edge_incident_find(&im, 0U, &inc), -EINVAL);
	zassert_equal(pqcp_edge_incident_find(&im, 1U, NULL), -EINVAL);
	zassert_equal(pqcp_edge_incident_find(&im, 9U, &inc), -ENOENT);
	zassert_is_null(inc);
	zassert_equal(pqcp_edge_incident_manager_audit(&im), 0);
}

ZTEST(edge_security, test_incident_lifecycle_state_machine)
{
	struct pqcp_edge_incident *inc;
	uint64_t id;
	struct pqcp_edge_incident snap;

	incident_setup();
	inc = open_incident(PQCP_EDGE_INCIDENT_HIGH, T0);
	id = inc->incident_id;
	zassert_equal(inc->state, PQCP_EDGE_INCIDENT_OPEN);
	zassert_equal(inc->signal_count, 2U);
	zassert_equal(inc->risk_score, 300U);
	zassert_equal(pqcp_edge_incident_manager_audit(&im), 0);

	/* Illegal jumps are refused and leave the record untouched. */
	snap = *inc;
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_RESOLVED, T0 + 1U), -EPERM);
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_MONITORING, T0 + 1U), -EPERM);
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_OPEN, T0 + 1U), -EALREADY);
	/* A high-severity incident cannot be closed without resolution. */
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_CLOSED, T0 + 1U), -EPERM);
	zassert_mem_equal(inc, &snap, sizeof(snap));

	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_TRIAGED, T0 + 2U), 0);
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_CONTAINING, T0 + 3U), 0);
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_REMEDIATING, T0 + 4U), 0);
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_MONITORING, T0 + 5U), 0);
	/* Resolution needs recorded remediation. */
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_RESOLVED, T0 + 6U), -EAGAIN);
	zassert_equal(inc->state, PQCP_EDGE_INCIDENT_MONITORING);
	inc->remediation_mask = 0x1U;
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_RESOLVED, T0 + 7U), 0);
	zassert_equal(im.resolved_count, 1U);
	zassert_equal(inc->resolved_at_ms, T0 + 7U);
	zassert_equal(pqcp_edge_incident_manager_audit(&im), 0);
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_CLOSED, T0 + 8U), 0);

	/* CLOSED is terminal. */
	zassert_equal(pqcp_edge_incident_transition(&im, id,
		PQCP_EDGE_INCIDENT_OPEN, T0 + 9U), -EPERM);
	zassert_equal(pqcp_edge_incident_add_signal(&im, id, 77U, 10U,
		PQCP_EDGE_INCIDENT_LOW, T0 + 9U), -EPERM);
	zassert_equal(pqcp_edge_incident_assign(&im, id, "new-owner",
		T0 + 9U), -EPERM);
	zassert_str_equal(inc->owner_id, "owner");
}

ZTEST(edge_security, test_incident_signals_assignment_and_capacity)
{
	struct pqcp_edge_incident *a;
	struct pqcp_edge_incident *b;
	struct pqcp_edge_incident *c = (void *)0x1;
	const uint64_t ids[1] = { 1U };
	uint8_t old_digest[PQCP_EDGE_DIGEST_BYTES];
	struct pqcp_edge_incident snap[2];

	incident_setup();
	a = open_incident(PQCP_EDGE_INCIDENT_LOW, T0);
	memcpy(old_digest, a->incident_digest, sizeof(old_digest));
	zassert_equal(pqcp_edge_incident_add_signal(&im, a->incident_id, 13U,
		700U, PQCP_EDGE_INCIDENT_CRITICAL, T0 + 1U), 0);
	zassert_equal(a->signal_count, 3U);
	zassert_equal(a->severity, PQCP_EDGE_INCIDENT_CRITICAL);
	zassert_equal(a->risk_score, 700U);
	zassert_true(memcmp(old_digest, a->incident_digest,
			    sizeof(old_digest)) != 0);
	/* Severity and risk only ratchet upwards. */
	zassert_equal(pqcp_edge_incident_add_signal(&im, a->incident_id, 14U,
		10U, PQCP_EDGE_INCIDENT_INFORMATIONAL, T0 + 2U), 0);
	zassert_equal(a->severity, PQCP_EDGE_INCIDENT_CRITICAL);
	zassert_equal(a->risk_score, 700U);
	zassert_equal(pqcp_edge_incident_add_signal(&im, a->incident_id, 14U,
		10U, PQCP_EDGE_INCIDENT_LOW, T0 + 3U), -EALREADY);
	zassert_equal(a->signal_count, 4U);

	/* Fill the signal list; the overflow leaves the record unchanged. */
	for (uint64_t sid = 100U; a->signal_count <
	     PQCP_EDGE_MAX_INCIDENT_SIGNALS; ++sid) {
		zassert_equal(pqcp_edge_incident_add_signal(&im,
			a->incident_id, sid, 1U, PQCP_EDGE_INCIDENT_LOW,
			T0 + 4U), 0);
	}
	snap[0] = *a;
	zassert_equal(pqcp_edge_incident_add_signal(&im, a->incident_id,
		999U, 1U, PQCP_EDGE_INCIDENT_LOW, T0 + 5U), -ENOSPC);
	zassert_mem_equal(a, &snap[0], sizeof(snap[0]));

	zassert_equal(pqcp_edge_incident_assign(&im, a->incident_id,
		"analyst", T0 + 6U), 0);
	zassert_str_equal(a->owner_id, "analyst");
	zassert_equal(a->updated_at_ms, T0 + 6U);
	zassert_equal(pqcp_edge_incident_manager_audit(&im), 0);

	/* Capacity: refuse while both are live, reuse a closed slot. */
	b = open_incident(PQCP_EDGE_INCIDENT_LOW, T0 + 10U);
	memcpy(snap, instore, sizeof(snap));
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, ids, 1U, T0 + 11U, &c), -ENOSPC);
	zassert_is_null(c);
	zassert_mem_equal(instore, snap, sizeof(snap));
	zassert_equal(pqcp_edge_incident_transition(&im, b->incident_id,
		PQCP_EDGE_INCIDENT_CLOSED, T0 + 12U), 0);
	zassert_equal(pqcp_edge_incident_open(&im, "t", "s", "o",
		PQCP_EDGE_INCIDENT_LOW, 1U, ids, 1U, T0 + 13U, &c), 0);
	zassert_equal(c, b);
	zassert_equal(pqcp_edge_incident_find(&im, a->incident_id, &c), 0);
	zassert_equal(c, a);
}

ZTEST(edge_security, test_incident_audit_detects_tampering)
{
	struct pqcp_edge_incident *inc;

	incident_setup();
	inc = open_incident(PQCP_EDGE_INCIDENT_LOW, T0);
	zassert_equal(pqcp_edge_incident_manager_audit(&im), 0);
	/* Any field covered by the digest cannot be changed silently. */
	inc->risk_score = 900U;
	zassert_equal(pqcp_edge_incident_manager_audit(&im), -EBADMSG);
	inc->risk_score = 300U;
	inc->signal_ids[1] = 5U;
	zassert_equal(pqcp_edge_incident_manager_audit(&im), -EBADMSG);
	inc->signal_ids[1] = 12U;
	inc->updated_at_ms = T0 - 1U;
	zassert_equal(pqcp_edge_incident_manager_audit(&im), -EBADMSG);
	inc->updated_at_ms = T0;
	zassert_equal(pqcp_edge_incident_manager_audit(&im), 0);
	/* Duplicate signal ids that still hash correctly are caught. */
	inc->signal_ids[1] = inc->signal_ids[0];
	zassert_equal(pqcp_edge_internal_incident_digest(inc,
		inc->incident_digest), 0);
	zassert_equal(pqcp_edge_incident_manager_audit(&im), -EEXIST);
}

/* ------------------------------------------------------------------ */
/* Playbook engine                                                     */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_playbook pbstore[1];
static struct pqcp_edge_playbook_engine pb;

static void playbook_setup(void)
{
	zassert_equal(pqcp_edge_playbook_engine_init(
		&pb, pbstore, ARRAY_SIZE(pbstore)), 0);
}

static struct pqcp_edge_playbook_step mk_step(
	uint32_t id, enum pqcp_edge_playbook_action action, uint32_t deps,
	uint32_t attempts, bool mandatory)
{
	struct pqcp_edge_playbook_step s;

	memset(&s, 0, sizeof(s));
	s.step_id = id;
	s.action = action;
	s.dependency_mask = deps;
	s.maximum_attempts = attempts;
	s.mandatory = mandatory;
	return s;
}

ZTEST(edge_security, test_playbook_rejects_invalid_arguments)
{
	static struct pqcp_edge_playbook_engine raw;
	struct pqcp_edge_playbook_step steps[3];
	struct pqcp_edge_playbook_step many[PQCP_EDGE_MAX_PLAYBOOK_STEPS + 1U];
	struct pqcp_edge_playbook *p = (void *)0x1;
	struct pqcp_edge_playbook_step *s = (void *)0x1;

	zassert_equal(pqcp_edge_playbook_engine_init(NULL, pbstore, 1U),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_engine_init(&pb, NULL, 1U),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_engine_init(&pb, pbstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	steps[0] = mk_step(1U, PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR, 0U, 1U,
			   false);
	zassert_equal(pqcp_edge_playbook_start(&raw, 1U, steps, 1U, T0, &p),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_next(&raw, 1U, T0, &s), -EINVAL);
	zassert_equal(pqcp_edge_playbook_complete_step(&raw, 1U, 1U, 0, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_retry_step(&raw, 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_engine_audit(&raw), -EINVAL);

	playbook_setup();
	zassert_equal(pqcp_edge_playbook_start(&pb, 0U, steps, 1U, T0, &p),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, NULL, 1U, T0, &p),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, steps, 0U, T0, &p),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, steps, 1U, T0, NULL),
		      -EINVAL);
	memset(many, 0, sizeof(many));
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, many,
		PQCP_EDGE_MAX_PLAYBOOK_STEPS + 1U, T0, &p), -EINVAL);

	steps[0] = mk_step(0U, PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR, 0U, 1U,
			   false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, steps, 1U, T0, &p),
		      -EINVAL);
	steps[0] = mk_step(1U, PQCP_EDGE_PLAYBOOK_NONE, 0U, 1U, false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, steps, 1U, T0, &p),
		      -EINVAL);
	steps[0] = mk_step(1U, (enum pqcp_edge_playbook_action)99, 0U, 1U,
			   false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, steps, 1U, T0, &p),
		      -EINVAL);
	steps[0] = mk_step(1U, PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR, 0U, 0U,
			   false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, steps, 1U, T0, &p),
		      -EINVAL);
	/* Dependencies must reference existing steps, never the step itself. */
	steps[0] = mk_step(1U, PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR, 0x2U, 1U,
			   false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, steps, 1U, T0, &p),
		      -EINVAL);
	steps[0] = mk_step(1U, PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR, 0x1U, 1U,
			   false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, steps, 1U, T0, &p),
		      -EINVAL);
	/* Duplicate step ids. */
	steps[0] = mk_step(4U, PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR, 0U, 1U,
			   false);
	steps[1] = mk_step(4U, PQCP_EDGE_PLAYBOOK_BLOCK_PRINCIPAL, 0U, 1U,
			   false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 1U, steps, 2U, T0, &p),
		      -EEXIST);
	zassert_false(pbstore[0].occupied);

	zassert_equal(pqcp_edge_playbook_next(&pb, 0U, T0, &s), -EINVAL);
	zassert_equal(pqcp_edge_playbook_next(&pb, 1U, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_playbook_next(&pb, 9U, T0, &s), -ENOENT);
	zassert_is_null(s);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, 0U, 1U, 0, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, 1U, 0U, 0, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, 9U, 1U, 0, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_playbook_retry_step(&pb, 0U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_retry_step(&pb, 1U, 0U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_playbook_retry_step(&pb, 9U, 1U, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_playbook_engine_audit(&pb), 0);
}

ZTEST(edge_security, test_playbook_executes_in_dependency_order)
{
	struct pqcp_edge_playbook_step steps[3];
	struct pqcp_edge_playbook *p = NULL;
	struct pqcp_edge_playbook_step *s = NULL;
	uint64_t exec;

	playbook_setup();
	steps[0] = mk_step(10U, PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR, 0U, 1U,
			   false);
	steps[1] = mk_step(20U, PQCP_EDGE_PLAYBOOK_BLOCK_PRINCIPAL, 0x1U,
			   1U, true);
	steps[2] = mk_step(30U, PQCP_EDGE_PLAYBOOK_CAPTURE_EVIDENCE, 0U, 1U,
			   false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 5U, steps, 3U, T0, &p), 0);
	exec = p->execution_id;
	zassert_true(p->active);
	zassert_equal(p->steps[0].state, PQCP_EDGE_PLAYBOOK_STEP_READY);
	zassert_equal(p->steps[1].state, PQCP_EDGE_PLAYBOOK_STEP_PENDING);

	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0, &s), 0);
	zassert_equal(s->step_id, 10U);
	zassert_equal(s->state, PQCP_EDGE_PLAYBOOK_STEP_RUNNING);
	zassert_equal(s->attempts, 1U);
	/* The dependent step is held back until its prerequisite succeeds. */
	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0, &s), 0);
	zassert_equal(s->step_id, 30U);
	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0, &s), -EAGAIN);
	zassert_is_null(s);
	zassert_equal(p->steps[1].state, PQCP_EDGE_PLAYBOOK_STEP_PENDING);

	zassert_equal(pqcp_edge_playbook_complete_step(&pb, exec, 10U, 0,
		T0 + 1U), 0);
	zassert_equal(p->completed_mask, 0x1U);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, exec, 10U, 0,
		T0 + 1U), -EALREADY);
	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0 + 1U, &s), 0);
	zassert_equal(s->step_id, 20U);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, exec, 20U, 0,
		T0 + 2U), 0);
	zassert_true(p->active);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, exec, 30U, 0,
		T0 + 3U), 0);
	zassert_false(p->active);
	zassert_equal(p->completed_at_ms, T0 + 3U);
	zassert_equal(pb.completed_count, 1U);
	zassert_equal(pb.failed_count, 0U);
	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0 + 4U, &s),
		      -EALREADY);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, exec, 99U, 0,
		T0 + 4U), -ENOENT);
	zassert_equal(pqcp_edge_playbook_engine_audit(&pb), 0);
}

ZTEST(edge_security, test_playbook_mandatory_first_retry_and_failure)
{
	struct pqcp_edge_playbook_step steps[2];
	struct pqcp_edge_playbook *p = NULL;
	struct pqcp_edge_playbook_step *s = NULL;
	uint64_t exec;

	playbook_setup();
	steps[0] = mk_step(5U, PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR, 0U, 1U,
			   false);
	steps[1] = mk_step(9U, PQCP_EDGE_PLAYBOOK_ROTATE_KEYS, 0U, 2U, true);
	zassert_equal(pqcp_edge_playbook_start(&pb, 5U, steps, 2U, T0, &p), 0);
	exec = p->execution_id;

	/* Mandatory work is scheduled ahead of lower step ids. */
	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0, &s), 0);
	zassert_equal(s->step_id, 9U);
	/* Failure with attempts left schedules a backed-off retry. */
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, exec, 9U, -EIO,
		T0 + 10U), 0);
	zassert_equal(s->state, PQCP_EDGE_PLAYBOOK_STEP_READY);
	zassert_equal(s->retry_at_ms, T0 + 10U + 250U);
	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0 + 11U, &s), 0);
	zassert_equal(s->step_id, 5U);
	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0 + 11U, &s),
		      -EAGAIN);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, exec, 5U, 0,
		T0 + 12U), 0);

	/* Operator may pull the retry forward. */
	zassert_equal(pqcp_edge_playbook_retry_step(&pb, exec, 9U, T0 + 20U),
		      0);
	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0 + 19U, &s),
		      -EAGAIN);
	zassert_equal(pqcp_edge_playbook_next(&pb, exec, T0 + 20U, &s), 0);
	zassert_equal(s->attempts, 2U);
	/* Retrying a running step is refused. */
	zassert_equal(pqcp_edge_playbook_retry_step(&pb, exec, 9U, T0 + 30U),
		      -EALREADY);
	/* Out of attempts: terminal failure of a mandatory step. */
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, exec, 9U, -EIO,
		T0 + 21U), 0);
	zassert_equal(s->state, PQCP_EDGE_PLAYBOOK_STEP_FAILED);
	zassert_equal(p->failed_mask, 0x2U);
	zassert_false(p->active);
	zassert_equal(pb.failed_count, 1U);
	zassert_equal(pb.completed_count, 0U);
	zassert_equal(pqcp_edge_playbook_retry_step(&pb, exec, 9U, T0 + 30U),
		      -EOVERFLOW);
	zassert_equal(s->state, PQCP_EDGE_PLAYBOOK_STEP_FAILED);
	zassert_equal(pqcp_edge_playbook_engine_audit(&pb), 0);
}

ZTEST(edge_security, test_playbook_capacity_and_audit)
{
	struct pqcp_edge_playbook_step step;
	struct pqcp_edge_playbook *p = NULL;
	struct pqcp_edge_playbook *p2 = (void *)0x1;
	struct pqcp_edge_playbook_step *s = NULL;
	struct pqcp_edge_playbook snap;

	playbook_setup();
	step = mk_step(1U, PQCP_EDGE_PLAYBOOK_VERIFY_INTEGRITY, 0U, 1U,
		       false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 5U, &step, 1U, T0, &p),
		      0);
	snap = *p;
	/* A running playbook is never evicted. */
	zassert_equal(pqcp_edge_playbook_start(&pb, 6U, &step, 1U, T0 + 1U,
		&p2), -ENOSPC);
	zassert_is_null(p2);
	zassert_mem_equal(p, &snap, sizeof(snap));

	zassert_equal(pqcp_edge_playbook_next(&pb, p->execution_id, T0, &s),
		      0);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, p->execution_id,
		1U, 0, T0 + 2U), 0);
	/* A finished playbook's slot is reusable. */
	zassert_equal(pqcp_edge_playbook_start(&pb, 6U, &step, 1U, T0 + 3U,
		&p2), 0);
	zassert_equal(p2->incident_id, 6U);
	zassert_equal(pqcp_edge_playbook_engine_audit(&pb), 0);

	p2->steps[0].attempts = 5U;
	zassert_equal(pqcp_edge_playbook_engine_audit(&pb), -EBADMSG);
	p2->steps[0].attempts = 0U;
	p2->active = false;
	zassert_equal(pqcp_edge_playbook_engine_audit(&pb), -EBADMSG);
	p2->active = true;
	p2->completed_at_ms = T0;
	zassert_equal(pqcp_edge_playbook_engine_audit(&pb), -EBADMSG);
}

ZTEST(edge_security, test_playbook_failed_step_does_not_strand_dependents)
{
	struct pqcp_edge_playbook_step steps[2];
	struct pqcp_edge_playbook *p = NULL;
	struct pqcp_edge_playbook_step *s = NULL;

	playbook_setup();
	steps[0] = mk_step(1U, PQCP_EDGE_PLAYBOOK_ENTER_RECOVERY, 0U, 1U,
			   true);
	steps[1] = mk_step(2U, PQCP_EDGE_PLAYBOOK_RESTORE_SERVICE, 0x1U, 1U,
			   false);
	zassert_equal(pqcp_edge_playbook_start(&pb, 5U, steps, 2U, T0, &p), 0);
	zassert_equal(pqcp_edge_playbook_next(&pb, p->execution_id, T0, &s),
		      0);
	zassert_equal(pqcp_edge_playbook_complete_step(&pb, p->execution_id,
		1U, -EIO, T0 + 1U), 0);
	zassert_equal(p->steps[0].state, PQCP_EDGE_PLAYBOOK_STEP_FAILED);

	zassert_equal(p->steps[1].state, PQCP_EDGE_PLAYBOOK_STEP_SKIPPED);
	zassert_false(p->active);
	zassert_equal(pb.failed_count, 1U);
	zassert_equal(pb.completed_count, 0U);
	zassert_equal(pqcp_edge_playbook_engine_audit(&pb), 0);
	/* The slot is released for the next playbook. */
	zassert_equal(pqcp_edge_playbook_start(&pb, 6U, steps, 2U, T0 + 2U,
					       &p), 0);
}

/* ------------------------------------------------------------------ */
/* Evidence store                                                      */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_evidence evstore[2];
static struct pqcp_edge_evidence_store es;

static void evidence_setup(void)
{
	zassert_equal(pqcp_edge_evidence_store_init(
		&es, evstore, ARRAY_SIZE(evstore)), 0);
}

ZTEST(edge_security, test_evidence_rejects_invalid_arguments)
{
	static struct pqcp_edge_evidence_store raw;
	static uint8_t big[PQCP_EDGE_EVIDENCE_MAX_BYTES + 1U];
	const uint8_t payload[4] = { 1, 2, 3, 4 };
	struct pqcp_edge_evidence *e = (void *)0x1;
	uint8_t out[8];
	size_t length = 5U;
	uint32_t expired = 0U;

	zassert_equal(pqcp_edge_evidence_store_init(NULL, evstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_evidence_store_init(&es, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_evidence_store_init(&es, evstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_evidence_capture(&raw, 1U, "s", "c", payload,
		4U, T0, T0 + 10U, &e), -EINVAL);
	zassert_equal(pqcp_edge_evidence_seal(&raw, 1U), -EINVAL);
	zassert_equal(pqcp_edge_evidence_export(&raw, 1U, out, 8U, &length),
		      -EINVAL);
	zassert_equal(pqcp_edge_evidence_expire(&raw, T0, &expired),
		      -EINVAL);
	zassert_equal(pqcp_edge_evidence_store_audit(&raw), -EINVAL);

	evidence_setup();
	zassert_equal(pqcp_edge_evidence_capture(&es, 0U, "s", "c", payload,
		4U, T0, T0 + 10U, &e), -EINVAL);
	zassert_equal(pqcp_edge_evidence_capture(&es, 1U, NULL, "c", payload,
		4U, T0, T0 + 10U, &e), -EINVAL);
	zassert_equal(pqcp_edge_evidence_capture(&es, 1U, "s", "", payload,
		4U, T0, T0 + 10U, &e), -EINVAL);
	zassert_equal(pqcp_edge_evidence_capture(&es, 1U, "s", "c", NULL, 4U,
		T0, T0 + 10U, &e), -EINVAL);
	zassert_equal(pqcp_edge_evidence_capture(&es, 1U, "s", "c", payload,
		0U, T0, T0 + 10U, &e), -EINVAL);
	zassert_equal(pqcp_edge_evidence_capture(&es, 1U, "s", "c", big,
		sizeof(big), T0, T0 + 10U, &e), -EINVAL);
	zassert_equal(pqcp_edge_evidence_capture(&es, 1U, "s", "c", payload,
		4U, T0, T0, &e), -EINVAL);
	zassert_equal(pqcp_edge_evidence_capture(&es, 1U, "s", "c", payload,
		4U, T0, T0 + 10U, NULL), -EINVAL);
	zassert_equal(es.capture_count, 0U);
	zassert_true(pqcp_edge_internal_all_zero(es.chain_head,
		sizeof(es.chain_head)));
	zassert_equal(pqcp_edge_evidence_seal(&es, 0U), -EINVAL);
	zassert_equal(pqcp_edge_evidence_seal(&es, 9U), -ENOENT);
	zassert_equal(pqcp_edge_evidence_export(&es, 0U, out, 8U, &length),
		      -EINVAL);
	zassert_equal(pqcp_edge_evidence_export(&es, 1U, NULL, 8U, &length),
		      -EINVAL);
	zassert_equal(pqcp_edge_evidence_export(&es, 1U, out, 8U, NULL),
		      -EINVAL);
	zassert_equal(pqcp_edge_evidence_export(&es, 9U, out, 8U, &length),
		      -ENOENT);
	zassert_equal(pqcp_edge_evidence_expire(&es, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_evidence_store_audit(&es), 0);
}

ZTEST(edge_security, test_evidence_custody_seal_export_and_expiry)
{
	const uint8_t payload[6] = { 'l', 'o', 'g', 'd', 'a', 't' };
	struct pqcp_edge_evidence *e1 = NULL;
	struct pqcp_edge_evidence *e2 = NULL;
	struct pqcp_edge_evidence *e3 = (void *)0x1;
	uint8_t out[16];
	size_t length = 99U;
	uint32_t expired = 0U;

	evidence_setup();
	zassert_equal(pqcp_edge_evidence_capture(&es, 5U, "agent", "syslog",
		payload, sizeof(payload), T0, T0 + 100U, &e1), 0);
	zassert_equal(pqcp_edge_evidence_capture(&es, 5U, "agent", "netflow",
		payload, sizeof(payload), T0 + 1U, T0 + 1000U, &e2), 0);
	/* Evidence chain: each item commits to its predecessor. */
	zassert_true(pqcp_edge_internal_all_zero(e1->previous_digest,
		sizeof(e1->previous_digest)));
	zassert_mem_equal(e2->previous_digest, e1->evidence_digest,
			  PQCP_EDGE_DIGEST_BYTES);
	zassert_mem_equal(es.chain_head, e2->evidence_digest,
			  PQCP_EDGE_DIGEST_BYTES);
	zassert_equal(es.capture_count, 2U);

	/* Unsealed evidence cannot leave custody. */
	zassert_equal(pqcp_edge_evidence_export(&es, e1->evidence_id, out,
		sizeof(out), &length), -EAGAIN);
	zassert_equal(length, 0U);
	zassert_equal(pqcp_edge_evidence_seal(&es, e1->evidence_id), 0);
	zassert_equal(pqcp_edge_evidence_seal(&es, e1->evidence_id),
		      -EALREADY);
	zassert_equal(pqcp_edge_evidence_export(&es, e1->evidence_id, out, 3U,
		&length), -ENOBUFS);
	zassert_equal(length, 0U);
	zassert_equal(pqcp_edge_evidence_export(&es, e1->evidence_id, out,
		sizeof(out), &length), 0);
	zassert_equal(length, sizeof(payload));
	zassert_mem_equal(out, payload, sizeof(payload));

	/* Full: refuse rather than overwrite custody records. */
	zassert_equal(pqcp_edge_evidence_capture(&es, 5U, "agent", "x",
		payload, sizeof(payload), T0 + 2U, T0 + 50U, &e3), -ENOSPC);
	zassert_is_null(e3);

	/* Sealed evidence survives expiry; unsealed expired evidence is
	 * securely erased.
	 */
	zassert_equal(pqcp_edge_evidence_expire(&es, T0 + 500U, &expired), 0);
	zassert_equal(expired, 0U);
	zassert_equal(pqcp_edge_evidence_expire(&es, T0 + 1000U, &expired),
		      0);
	zassert_equal(expired, 1U);
	zassert_true(pqcp_edge_internal_all_zero((const uint8_t *)&evstore[1],
		sizeof(evstore[1])));
	zassert_equal(pqcp_edge_evidence_expire(&es, T0 + 5000U, &expired),
		      0);
	zassert_equal(expired, 0U);
	zassert_true(evstore[0].occupied);
	zassert_equal(pqcp_edge_evidence_store_audit(&es), 0);
}

ZTEST(edge_security, test_evidence_audit_detects_tampering)
{
	const uint8_t payload[4] = { 9, 8, 7, 6 };
	struct pqcp_edge_evidence *e = NULL;

	evidence_setup();
	zassert_equal(pqcp_edge_evidence_capture(&es, 5U, "agent", "syslog",
		payload, sizeof(payload), T0, T0 + 100U, &e), 0);
	zassert_equal(pqcp_edge_evidence_store_audit(&es), 0);
	e->payload[0] ^= 1U;
	zassert_equal(pqcp_edge_evidence_store_audit(&es), -EBADMSG);
	e->payload[0] ^= 1U;
	e->incident_id = 6U;
	zassert_equal(pqcp_edge_evidence_store_audit(&es), -EBADMSG);
	e->incident_id = 5U;
	SETSTR(e->source_id, "forged");
	zassert_equal(pqcp_edge_evidence_store_audit(&es), -EBADMSG);
	SETSTR(e->source_id, "agent");
	zassert_equal(pqcp_edge_evidence_store_audit(&es), 0);
}

/* ------------------------------------------------------------------ */
/* Containment                                                         */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_containment cnstore[2];
static struct pqcp_edge_containment_manager cm;

static void containment_setup(void)
{
	zassert_equal(pqcp_edge_containment_manager_init(
		&cm, cnstore, ARRAY_SIZE(cnstore)), 0);
}

ZTEST(edge_security, test_containment_rejects_invalid_arguments)
{
	static struct pqcp_edge_containment_manager raw;
	struct pqcp_edge_containment *c = (void *)0x1;
	uint32_t released = 0U;

	zassert_equal(pqcp_edge_containment_manager_init(NULL, cnstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_containment_manager_init(&cm, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_containment_manager_init(&cm, cnstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_containment_apply(&raw, 1U, "s", 1U, T0,
		T0 + 10U, &c), -EINVAL);
	zassert_equal(pqcp_edge_containment_record_action(&raw, 1U, 1U, 0),
		      -EINVAL);
	zassert_equal(pqcp_edge_containment_release(&raw, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_containment_tick(&raw, T0, &released),
		      -EINVAL);
	zassert_equal(pqcp_edge_containment_manager_audit(&raw), -EINVAL);

	containment_setup();
	zassert_equal(pqcp_edge_containment_apply(&cm, 0U, "s", 1U, T0,
		T0 + 10U, &c), -EINVAL);
	zassert_equal(pqcp_edge_containment_apply(&cm, 1U, NULL, 1U, T0,
		T0 + 10U, &c), -EINVAL);
	zassert_equal(pqcp_edge_containment_apply(&cm, 1U, "s", 0U, T0,
		T0 + 10U, &c), -EINVAL);
	zassert_equal(pqcp_edge_containment_apply(&cm, 1U, "s", 1U, T0, T0,
		&c), -EINVAL);
	zassert_equal(pqcp_edge_containment_apply(&cm, 1U, "s", 1U, T0,
		T0 + 10U, NULL), -EINVAL);
	zassert_equal(cm.applied_count, 0U);
	zassert_equal(pqcp_edge_containment_record_action(&cm, 0U, 1U, 0),
		      -EINVAL);
	zassert_equal(pqcp_edge_containment_record_action(&cm, 1U, 0U, 0),
		      -EINVAL);
	zassert_equal(pqcp_edge_containment_record_action(&cm, 1U, 3U, 0),
		      -EINVAL);
	zassert_equal(pqcp_edge_containment_record_action(&cm, 9U, 1U, 0),
		      -ENOENT);
	zassert_equal(pqcp_edge_containment_release(&cm, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_containment_release(&cm, 9U, T0), -ENOENT);
	zassert_equal(pqcp_edge_containment_tick(&cm, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_containment_manager_audit(&cm), 0);
}

ZTEST(edge_security, test_containment_action_tracking_release_and_expiry)
{
	struct pqcp_edge_containment *c1 = NULL;
	struct pqcp_edge_containment *c2 = NULL;
	struct pqcp_edge_containment *c3 = (void *)0x1;
	uint32_t released = 0U;

	containment_setup();
	zassert_equal(pqcp_edge_containment_apply(&cm, 5U, "dev-1", 0x5U, T0,
		T0 + 100U, &c1), 0);
	zassert_true(c1->active);
	/* Only actions that were part of the containment can be recorded. */
	zassert_equal(pqcp_edge_containment_record_action(&cm,
		c1->containment_id, 0x2U, 0), -EACCES);
	zassert_equal(pqcp_edge_containment_record_action(&cm,
		c1->containment_id, 0x1U, 0), 0);
	zassert_equal(pqcp_edge_containment_record_action(&cm,
		c1->containment_id, 0x4U, -EIO), 0);
	zassert_equal(c1->applied_mask, 0x1U);
	zassert_equal(c1->failed_mask, 0x4U);
	/* A later success clears the failure for that action. */
	zassert_equal(pqcp_edge_containment_record_action(&cm,
		c1->containment_id, 0x4U, 0), 0);
	zassert_equal(c1->applied_mask, 0x5U);
	zassert_equal(c1->failed_mask, 0x0U);

	zassert_equal(pqcp_edge_containment_apply(&cm, 6U, "dev-2", 0x1U,
		T0, T0 + 10U, &c2), 0);
	/* Table full of active containments. */
	zassert_equal(pqcp_edge_containment_apply(&cm, 7U, "dev-3", 0x1U,
		T0, T0 + 10U, &c3), -ENOSPC);
	zassert_is_null(c3);

	zassert_equal(pqcp_edge_containment_tick(&cm, T0 + 10U, &released),
		      0);
	zassert_equal(released, 1U);
	zassert_false(c2->active);
	zassert_equal(c2->released_at_ms, T0 + 10U);
	zassert_true(c1->active);
	zassert_equal(pqcp_edge_containment_record_action(&cm,
		c2->containment_id, 0x1U, 0), -EACCES);

	zassert_equal(pqcp_edge_containment_release(&cm, c1->containment_id,
		T0 + 20U), 0);
	zassert_equal(pqcp_edge_containment_release(&cm, c1->containment_id,
		T0 + 21U), -EALREADY);
	zassert_equal(cm.released_count, 2U);
	zassert_equal(c1->released_at_ms, T0 + 20U);
	zassert_equal(pqcp_edge_containment_manager_audit(&cm), 0);
	/* Released slots are reusable. */
	zassert_equal(pqcp_edge_containment_apply(&cm, 7U, "dev-3", 0x1U,
		T0 + 30U, T0 + 40U, &c3), 0);
}

ZTEST(edge_security, test_containment_audit_detects_corruption)
{
	struct pqcp_edge_containment *c = NULL;

	containment_setup();
	zassert_equal(pqcp_edge_containment_apply(&cm, 5U, "dev-1", 0x3U, T0,
		T0 + 100U, &c), 0);
	c->applied_mask = 0x8U;
	zassert_equal(pqcp_edge_containment_manager_audit(&cm), -EBADMSG);
	c->applied_mask = 0U;
	c->failed_mask = 0x4U;
	zassert_equal(pqcp_edge_containment_manager_audit(&cm), -EBADMSG);
	c->failed_mask = 0U;
	c->active = false;
	zassert_equal(pqcp_edge_containment_manager_audit(&cm), -EBADMSG);
	c->active = true;
	zassert_equal(pqcp_edge_containment_manager_audit(&cm), 0);
}

/* ------------------------------------------------------------------ */
/* Continuity                                                          */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_continuity_service ctstore[2];
static struct pqcp_edge_continuity_manager ct;

static void continuity_setup(void)
{
	zassert_equal(pqcp_edge_continuity_manager_init(
		&ct, ctstore, ARRAY_SIZE(ctstore)), 0);
}

static struct pqcp_edge_continuity_service mk_cont(const char *id)
{
	struct pqcp_edge_continuity_service s;

	memset(&s, 0, sizeof(s));
	SETSTR(s.service_id, id);
	s.mode = PQCP_EDGE_CONTINUITY_NORMAL;
	s.minimum_endpoints = 2U;
	s.dependency_mask = 0x3U;
	return s;
}

ZTEST(edge_security, test_continuity_rejects_invalid_arguments)
{
	static struct pqcp_edge_continuity_manager raw;
	struct pqcp_edge_continuity_service s = mk_cont("svc");
	enum pqcp_edge_continuity_mode mode;

	zassert_equal(pqcp_edge_continuity_manager_init(NULL, ctstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_continuity_manager_init(&ct, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_continuity_manager_init(&ct, ctstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_continuity_register(&raw, &s), -EINVAL);
	zassert_equal(pqcp_edge_continuity_observe(&raw, "svc", 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_continuity_set_mode(&raw, "svc",
		PQCP_EDGE_CONTINUITY_DEGRADED, T0), -EINVAL);
	zassert_equal(pqcp_edge_continuity_evaluate(&raw, T0, &mode),
		      -EINVAL);
	zassert_equal(pqcp_edge_continuity_manager_audit(&raw), -EINVAL);

	continuity_setup();
	zassert_equal(pqcp_edge_continuity_register(&ct, NULL), -EINVAL);
	s.service_id[0] = '\0';
	zassert_equal(pqcp_edge_continuity_register(&ct, &s), -EINVAL);
	s = mk_cont("svc");
	s.mode = (enum pqcp_edge_continuity_mode)9;
	zassert_equal(pqcp_edge_continuity_register(&ct, &s), -EINVAL);
	s = mk_cont("svc");
	s.minimum_endpoints = 0U;
	zassert_equal(pqcp_edge_continuity_register(&ct, &s), -EINVAL);
	zassert_false(ctstore[0].occupied);
	zassert_equal(pqcp_edge_continuity_observe(&ct, NULL, 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 1U, 1U, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_continuity_set_mode(&ct, NULL,
		PQCP_EDGE_CONTINUITY_DEGRADED, T0), -EINVAL);
	zassert_equal(pqcp_edge_continuity_set_mode(&ct, "svc",
		(enum pqcp_edge_continuity_mode)9, T0), -EINVAL);
	zassert_equal(pqcp_edge_continuity_set_mode(&ct, "svc",
		PQCP_EDGE_CONTINUITY_DEGRADED, T0), -ENOENT);
	zassert_equal(pqcp_edge_continuity_evaluate(&ct, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_continuity_manager_audit(&ct), 0);
}

ZTEST(edge_security, test_continuity_mode_derivation)
{
	struct pqcp_edge_continuity_service s = mk_cont("svc");

	continuity_setup();
	zassert_equal(pqcp_edge_continuity_register(&ct, &s), 0);

	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 2U, 0x3U, T0),
		      0);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_NORMAL);
	zassert_equal(ct.transition_count, 0U);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 1U, 0x3U,
		T0 + 1U), 0);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_DEGRADED);
	zassert_equal(ctstore[0].entered_at_ms, T0 + 1U);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 2U, 0x1U,
		T0 + 2U), 0);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_ISOLATED);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 0U, 0x3U,
		T0 + 3U), 0);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_RECOVERY);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 0U, 0x1U,
		T0 + 4U), 0);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_FAILSAFE);
	/* Dependencies outside the declared mask are ignored. */
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 2U, 0xffU,
		T0 + 5U), 0);
	zassert_equal(ctstore[0].satisfied_dependencies, 0x3U);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_NORMAL);
	zassert_equal(ct.transition_count, 5U);
	zassert_equal(pqcp_edge_continuity_manager_audit(&ct), 0);
}

ZTEST(edge_security, test_continuity_set_mode_and_global_evaluation)
{
	struct pqcp_edge_continuity_service a = mk_cont("a");
	struct pqcp_edge_continuity_service b = mk_cont("b");
	enum pqcp_edge_continuity_mode mode = PQCP_EDGE_CONTINUITY_FAILSAFE;
	struct pqcp_edge_continuity_service c = mk_cont("c");

	continuity_setup();
	zassert_equal(pqcp_edge_continuity_register(&ct, &a), 0);
	zassert_equal(pqcp_edge_continuity_register(&ct, &b), 0);
	zassert_equal(pqcp_edge_continuity_register(&ct, &c), -ENOSPC);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "a", 2U, 0x3U, T0),
		      0);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "b", 1U, 0x3U, T0),
		      0);

	zassert_equal(pqcp_edge_continuity_set_mode(&ct, "b",
		PQCP_EDGE_CONTINUITY_DEGRADED, T0 + 1U), -EALREADY);
	/* Returning to NORMAL needs the evidence to support it. */
	zassert_equal(pqcp_edge_continuity_set_mode(&ct, "b",
		PQCP_EDGE_CONTINUITY_NORMAL, T0 + 1U), -EAGAIN);
	zassert_equal(ctstore[1].mode, PQCP_EDGE_CONTINUITY_DEGRADED);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "b", 2U, 0x3U,
		T0 + 2U), 0);
	zassert_equal(ctstore[1].mode, PQCP_EDGE_CONTINUITY_NORMAL);

	zassert_equal(pqcp_edge_continuity_observe(&ct, "b", 1U, 0x3U,
		T0 + 3U), 0);
	zassert_equal(pqcp_edge_continuity_evaluate(&ct, T0 + 4U, &mode), 0);
	zassert_equal(mode, PQCP_EDGE_CONTINUITY_DEGRADED);
	zassert_equal(ct.global_mode, PQCP_EDGE_CONTINUITY_DEGRADED);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "a", 0U, 0x0U,
		T0 + 5U), 0);
	zassert_equal(pqcp_edge_continuity_evaluate(&ct, T0 + 6U, &mode), 0);
	zassert_equal(mode, PQCP_EDGE_CONTINUITY_FAILSAFE);

	ctstore[0].satisfied_dependencies = 0x8U;
	zassert_equal(pqcp_edge_continuity_manager_audit(&ct), -EBADMSG);
	ctstore[0].satisfied_dependencies = 0U;
	ctstore[1] = ctstore[0];
	zassert_equal(pqcp_edge_continuity_manager_audit(&ct), -EEXIST);
}

ZTEST(edge_security, test_continuity_failsafe_escalation_is_latched)
{
	struct pqcp_edge_continuity_service s = mk_cont("svc");
	enum pqcp_edge_continuity_mode mode;

	continuity_setup();
	s.maximum_duration_ms = 100U;
	zassert_equal(pqcp_edge_continuity_register(&ct, &s), 0);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 1U, 0x3U, T0),
		      0);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_DEGRADED);

	/* Degraded for longer than allowed: escalate to FAILSAFE. */
	zassert_equal(pqcp_edge_continuity_evaluate(&ct, T0 + 101U, &mode),
		      0);
	zassert_equal(mode, PQCP_EDGE_CONTINUITY_FAILSAFE);
	/* A second evaluation must not silently walk the escalation back. */
	zassert_equal(pqcp_edge_continuity_evaluate(&ct, T0 + 102U, &mode),
		      0);
	zassert_equal(mode, PQCP_EDGE_CONTINUITY_FAILSAFE);
	/* Fresh healthy observations do not clear the latch either. */
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 2U, 0x3U,
		T0 + 103U), 0);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_FAILSAFE);
	zassert_equal(pqcp_edge_continuity_evaluate(&ct, T0 + 104U, &mode),
		      0);
	zassert_equal(mode, PQCP_EDGE_CONTINUITY_FAILSAFE);
	/* The operator releases it explicitly once evidence supports it. */
	zassert_equal(pqcp_edge_continuity_set_mode(&ct, "svc",
		PQCP_EDGE_CONTINUITY_NORMAL, T0 + 105U), 0);
	zassert_equal(pqcp_edge_continuity_evaluate(&ct, T0 + 106U, &mode),
		      0);
	zassert_equal(mode, PQCP_EDGE_CONTINUITY_NORMAL);
}

ZTEST(edge_security, test_continuity_operator_override_survives_evaluation)
{
	struct pqcp_edge_continuity_service s = mk_cont("svc");
	enum pqcp_edge_continuity_mode mode;

	continuity_setup();
	zassert_equal(pqcp_edge_continuity_register(&ct, &s), 0);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 2U, 0x3U, T0),
		      0);
	zassert_equal(pqcp_edge_continuity_set_mode(&ct, "svc",
		PQCP_EDGE_CONTINUITY_ISOLATED, T0 + 1U), 0);
	zassert_equal(pqcp_edge_continuity_evaluate(&ct, T0 + 2U, &mode), 0);
	zassert_equal(mode, PQCP_EDGE_CONTINUITY_ISOLATED);
	/* Nor does a new observation. */
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 2U, 0x3U,
		T0 + 3U), 0);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_ISOLATED);
	/* Operator returns to NORMAL; derivation resumes. */
	zassert_equal(pqcp_edge_continuity_set_mode(&ct, "svc",
		PQCP_EDGE_CONTINUITY_NORMAL, T0 + 4U), 0);
	zassert_equal(pqcp_edge_continuity_observe(&ct, "svc", 1U, 0x3U,
		T0 + 5U), 0);
	zassert_equal(ctstore[0].mode, PQCP_EDGE_CONTINUITY_DEGRADED);
}

/* ------------------------------------------------------------------ */
/* Anomaly engine                                                      */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_anomaly_baseline anstore[2];
static struct pqcp_edge_anomaly_engine an;

static void anomaly_setup(void)
{
	zassert_equal(pqcp_edge_anomaly_engine_init(
		&an, anstore, ARRAY_SIZE(anstore)), 0);
}

ZTEST(edge_security, test_anomaly_rejects_invalid_arguments)
{
	static struct pqcp_edge_anomaly_engine raw;
	struct pqcp_edge_anomaly_result r;
	char unterminated[PQCP_EDGE_ID_MAX_CHARS];

	zassert_equal(pqcp_edge_anomaly_engine_init(NULL, anstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_anomaly_engine_init(&an, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_engine_init(&an, anstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_anomaly_observe(&raw, "s",
		PQCP_EDGE_METRIC_LATENCY_US, 1U, T0, 20000U, &r), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_reset(&raw, "s",
		PQCP_EDGE_METRIC_LATENCY_US), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_engine_audit(&raw), -EINVAL);

	anomaly_setup();
	memset(unterminated, 'x', sizeof(unterminated));
	zassert_equal(pqcp_edge_anomaly_observe(&an, NULL,
		PQCP_EDGE_METRIC_LATENCY_US, 1U, T0, 20000U, &r), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_observe(&an, "",
		PQCP_EDGE_METRIC_LATENCY_US, 1U, T0, 20000U, &r), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_observe(&an, unterminated,
		PQCP_EDGE_METRIC_LATENCY_US, 1U, T0, 20000U, &r), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_observe(&an, "s",
		PQCP_EDGE_METRIC_COUNT, 1U, T0, 20000U, &r), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_observe(&an, "s",
		(enum pqcp_edge_metric_type)-1, 1U, T0, 20000U, &r), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_observe(&an, "s",
		PQCP_EDGE_METRIC_LATENCY_US, 1U, T0, 9999U, &r), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_observe(&an, "s",
		PQCP_EDGE_METRIC_LATENCY_US, 1U, T0, 100001U, &r), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_observe(&an, "s",
		PQCP_EDGE_METRIC_LATENCY_US, 1U, T0, 20000U, NULL), -EINVAL);
	zassert_equal(an.observation_count, 0U);
	zassert_false(anstore[0].occupied);
	zassert_equal(pqcp_edge_anomaly_reset(&an, NULL,
		PQCP_EDGE_METRIC_LATENCY_US), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_reset(&an, "s",
		PQCP_EDGE_METRIC_COUNT), -EINVAL);
	zassert_equal(pqcp_edge_anomaly_reset(&an, "s",
		PQCP_EDGE_METRIC_LATENCY_US), -ENOENT);
	zassert_equal(pqcp_edge_anomaly_engine_audit(&an), 0);
}

ZTEST(edge_security, test_anomaly_learns_baseline_then_flags_outliers)
{
	struct pqcp_edge_anomaly_result r;

	anomaly_setup();
	/* The first eight samples only train the baseline. */
	for (uint32_t i = 0U; i < 8U; ++i) {
		zassert_equal(pqcp_edge_anomaly_observe(&an, "dev",
			PQCP_EDGE_METRIC_REQUEST_RATE, 100U, T0 + i, 30000U,
			&r), 0);
		zassert_false(r.anomalous);
		zassert_equal(r.threshold, 0U);
	}
	zassert_equal(anstore[0].sample_count, 8U);
	zassert_equal(anstore[0].mean, 100U);

	/* In-band sample is accepted. */
	zassert_equal(pqcp_edge_anomaly_observe(&an, "dev",
		PQCP_EDGE_METRIC_REQUEST_RATE, 100U, T0 + 8U, 30000U, &r), 0);
	zassert_false(r.anomalous);
	zassert_equal(r.expected, 100U);
	zassert_equal(r.distance, 0U);
	zassert_equal(r.threshold, 3U);
	zassert_equal(an.anomaly_count, 0U);

	/* A large spike is flagged with a saturated severity. */
	zassert_equal(pqcp_edge_anomaly_observe(&an, "dev",
		PQCP_EDGE_METRIC_REQUEST_RATE, 500U, T0 + 9U, 30000U, &r), 0);
	zassert_true(r.anomalous);
	zassert_equal(r.distance, 400U);
	zassert_equal(r.severity, 1000U);
	zassert_equal(an.anomaly_count, 1U);
	zassert_equal(an.observation_count, 10U);
	zassert_equal(anstore[0].maximum, 500U);
	zassert_equal(anstore[0].last_value, 500U);

	/* Baselines are per subject and per metric. */
	zassert_equal(pqcp_edge_anomaly_observe(&an, "dev",
		PQCP_EDGE_METRIC_ERROR_RATE, 500U, T0 + 10U, 30000U, &r), 0);
	zassert_false(r.anomalous);
	zassert_equal(pqcp_edge_anomaly_engine_audit(&an), 0);
}

ZTEST(edge_security, test_anomaly_reset_and_capacity)
{
	struct pqcp_edge_anomaly_result r;
	struct pqcp_edge_anomaly_baseline snap[2];

	anomaly_setup();
	zassert_equal(pqcp_edge_anomaly_observe(&an, "a",
		PQCP_EDGE_METRIC_LATENCY_US, 5U, T0, 20000U, &r), 0);
	zassert_equal(pqcp_edge_anomaly_observe(&an, "b",
		PQCP_EDGE_METRIC_LATENCY_US, 5U, T0, 20000U, &r), 0);
	memcpy(snap, anstore, sizeof(snap));
	zassert_equal(pqcp_edge_anomaly_observe(&an, "c",
		PQCP_EDGE_METRIC_LATENCY_US, 5U, T0, 20000U, &r), -ENOSPC);
	zassert_mem_equal(anstore, snap, sizeof(snap));
	zassert_equal(an.observation_count, 2U);

	zassert_equal(pqcp_edge_anomaly_reset(&an, "a",
		PQCP_EDGE_METRIC_LATENCY_US), 0);
	zassert_false(anstore[0].occupied);
	zassert_equal(pqcp_edge_anomaly_reset(&an, "a",
		PQCP_EDGE_METRIC_LATENCY_US), -ENOENT);
	zassert_equal(pqcp_edge_anomaly_observe(&an, "c",
		PQCP_EDGE_METRIC_LATENCY_US, 5U, T0, 20000U, &r), 0);

	anstore[1].minimum = anstore[1].maximum + 1U;
	zassert_equal(pqcp_edge_anomaly_engine_audit(&an), -EBADMSG);
	anstore[1].minimum = 5U;
	anstore[1].sensitivity_basis_points = 100U;
	zassert_equal(pqcp_edge_anomaly_engine_audit(&an), -EBADMSG);
}

/* ------------------------------------------------------------------ */
/* Recovery coordinator                                                */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_recovery_plan rcstore[2];
static struct pqcp_edge_recovery_coordinator rc;

static void recovery_setup(void)
{
	zassert_equal(pqcp_edge_recovery_coordinator_init(
		&rc, rcstore, ARRAY_SIZE(rcstore)), 0);
}

static struct pqcp_edge_recovery_plan *authorize_plan(uint32_t steps,
						      uint32_t max_failures,
						      uint64_t expires)
{
	uint8_t auth[PQCP_EDGE_DIGEST_BYTES];
	struct pqcp_edge_recovery_plan *p = NULL;

	edge_digest(auth, 0x77U);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 5U, "dev-1", steps,
		max_failures, auth, T0, expires, &p), 0);
	return p;
}

ZTEST(edge_security, test_recovery_rejects_invalid_arguments)
{
	static struct pqcp_edge_recovery_coordinator raw;
	struct pqcp_edge_recovery_plan *p = (void *)0x1;
	uint8_t auth[PQCP_EDGE_DIGEST_BYTES];
	uint8_t zero[PQCP_EDGE_DIGEST_BYTES] = { 0 };
	uint32_t failed = 0U;

	edge_digest(auth, 1U);
	zassert_equal(pqcp_edge_recovery_coordinator_init(NULL, rcstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_recovery_coordinator_init(&rc, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_recovery_coordinator_init(&rc, rcstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_recovery_authorize(&raw, 1U, "s", 1U, 1U,
		auth, T0, T0 + 10U, &p), -EINVAL);
	zassert_equal(pqcp_edge_recovery_advance(&raw, 1U,
		PQCP_EDGE_RECOVERY_CHECKPOINTING, T0), -EINVAL);
	zassert_equal(pqcp_edge_recovery_record_step(&raw, 1U, 0U, true,
		auth, T0), -EINVAL);
	zassert_equal(pqcp_edge_recovery_checkpoint(&raw, 1U, auth, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_recovery_tick(&raw, T0, &failed), -EINVAL);
	zassert_equal(pqcp_edge_recovery_coordinator_audit(&raw), -EINVAL);

	recovery_setup();
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 0U, "s", 1U, 1U, auth,
		T0, T0 + 10U, &p), -EINVAL);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 1U, NULL, 1U, 1U,
		auth, T0, T0 + 10U, &p), -EINVAL);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 1U, "s", 0U, 1U, auth,
		T0, T0 + 10U, &p), -EINVAL);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 1U, "s", 33U, 1U,
		auth, T0, T0 + 10U, &p), -EINVAL);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 1U, "s", 1U, 0U, auth,
		T0, T0 + 10U, &p), -EINVAL);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 1U, "s", 1U, 1U, NULL,
		T0, T0 + 10U, &p), -EINVAL);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 1U, "s", 1U, 1U, zero,
		T0, T0 + 10U, &p), -EINVAL);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 1U, "s", 1U, 1U, auth,
		T0, T0, &p), -EINVAL);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 1U, "s", 1U, 1U, auth,
		T0, T0 + 10U, NULL), -EINVAL);
	zassert_false(rcstore[0].occupied);

	zassert_equal(pqcp_edge_recovery_advance(&rc, 0U,
		PQCP_EDGE_RECOVERY_CHECKPOINTING, T0), -EINVAL);
	zassert_equal(pqcp_edge_recovery_advance(&rc, 1U,
		PQCP_EDGE_RECOVERY_IDLE, T0), -EINVAL);
	zassert_equal(pqcp_edge_recovery_advance(&rc, 1U,
		(enum pqcp_edge_recovery_phase)99, T0), -EINVAL);
	zassert_equal(pqcp_edge_recovery_advance(&rc, 9U,
		PQCP_EDGE_RECOVERY_CHECKPOINTING, T0), -ENOENT);
	zassert_equal(pqcp_edge_recovery_record_step(&rc, 0U, 0U, true, auth,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_recovery_record_step(&rc, 1U, 0U, true, NULL,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_recovery_record_step(&rc, 1U, 0U, true, zero,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_recovery_record_step(&rc, 9U, 0U, true, auth,
		T0), -ENOENT);
	zassert_equal(pqcp_edge_recovery_checkpoint(&rc, 0U, auth, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_recovery_checkpoint(&rc, 1U, NULL, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_recovery_checkpoint(&rc, 1U, zero, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_recovery_checkpoint(&rc, 9U, auth, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_recovery_tick(&rc, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_recovery_coordinator_audit(&rc), 0);
}

ZTEST(edge_security, test_recovery_full_flow_requires_checkpoint_and_all_steps)
{
	struct pqcp_edge_recovery_plan *p;
	uint8_t ckpt[PQCP_EDGE_DIGEST_BYTES];
	uint8_t ev[PQCP_EDGE_DIGEST_BYTES];
	uint8_t chain1[PQCP_EDGE_DIGEST_BYTES];
	uint64_t id;

	recovery_setup();
	edge_digest(ckpt, 0x10U);
	edge_digest(ev, 0x20U);
	p = authorize_plan(3U, 2U, T0 + 10000U);
	id = p->recovery_id;
	zassert_equal(p->phase, PQCP_EDGE_RECOVERY_AUTHORIZED);

	/* Phases cannot be skipped. */
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_ISOLATING, T0 + 1U), -EPERM);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_COMPLETE, T0 + 1U), -EPERM);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_AUTHORIZED, T0 + 1U), -EALREADY);
	zassert_equal(p->phase, PQCP_EDGE_RECOVERY_AUTHORIZED);
	/* A checkpoint is only accepted while checkpointing. */
	zassert_equal(pqcp_edge_recovery_checkpoint(&rc, id, ckpt, T0 + 2U),
		      -EPERM);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_CHECKPOINTING, T0 + 3U), 0);
	/* Isolation without a checkpoint is refused. */
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_ISOLATING, T0 + 4U), -EAGAIN);
	zassert_equal(p->phase, PQCP_EDGE_RECOVERY_CHECKPOINTING);
	zassert_equal(pqcp_edge_recovery_checkpoint(&rc, id, ckpt, T0 + 5U),
		      0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_ISOLATING, T0 + 6U), 0);

	/* Steps are bounded by the plan and cannot repeat. */
	zassert_equal(pqcp_edge_recovery_record_step(&rc, id, 3U, true, ev,
		T0 + 7U), -EINVAL);
	zassert_equal(pqcp_edge_recovery_record_step(&rc, id, 0U, true, ev,
		T0 + 7U), 0);
	memcpy(chain1, p->evidence_digest, sizeof(chain1));
	zassert_false(pqcp_edge_internal_all_zero(chain1, sizeof(chain1)));
	zassert_equal(pqcp_edge_recovery_record_step(&rc, id, 0U, true, ev,
		T0 + 8U), -EALREADY);
	zassert_mem_equal(p->evidence_digest, chain1, sizeof(chain1));
	zassert_equal(pqcp_edge_recovery_record_step(&rc, id, 1U, true, ev,
		T0 + 9U), 0);
	zassert_true(memcmp(p->evidence_digest, chain1, sizeof(chain1)) != 0);

	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_RESTORING, T0 + 10U), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_VALIDATING, T0 + 11U), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_REJOINING, T0 + 12U), 0);
	/* Step 2 is outstanding: completion is premature. */
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_COMPLETE, T0 + 13U), -EAGAIN);
	zassert_equal(p->phase, PQCP_EDGE_RECOVERY_REJOINING);
	zassert_equal(rc.completed_count, 0U);
	zassert_equal(pqcp_edge_recovery_record_step(&rc, id, 2U, true, ev,
		T0 + 14U), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_COMPLETE, T0 + 15U), 0);
	zassert_equal(rc.completed_count, 1U);
	zassert_equal(p->completed_steps, 0x7U);
	/* Terminal: no further steps or transitions. */
	zassert_equal(pqcp_edge_recovery_record_step(&rc, id, 2U, true, ev,
		T0 + 16U), -EINVAL);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_RESTORING, T0 + 16U), -EPERM);
	zassert_equal(pqcp_edge_recovery_coordinator_audit(&rc), 0);
}

ZTEST(edge_security, test_recovery_failure_budget_expiry_and_capacity)
{
	struct pqcp_edge_recovery_plan *p;
	struct pqcp_edge_recovery_plan *p2;
	struct pqcp_edge_recovery_plan *p3 = (void *)0x1;
	uint8_t ckpt[PQCP_EDGE_DIGEST_BYTES];
	uint8_t ev[PQCP_EDGE_DIGEST_BYTES];
	uint8_t auth[PQCP_EDGE_DIGEST_BYTES];
	uint32_t failed = 0U;

	recovery_setup();
	edge_digest(ckpt, 0x10U);
	edge_digest(ev, 0x20U);
	edge_digest(auth, 0x30U);
	p = authorize_plan(4U, 2U, T0 + 1000U);
	zassert_equal(pqcp_edge_recovery_advance(&rc, p->recovery_id,
		PQCP_EDGE_RECOVERY_CHECKPOINTING, T0 + 1U), 0);
	/* Recording steps before isolation is refused. */
	zassert_equal(pqcp_edge_recovery_record_step(&rc, p->recovery_id, 0U,
		true, ev, T0 + 2U), -EINVAL);
	zassert_equal(pqcp_edge_recovery_checkpoint(&rc, p->recovery_id, ckpt,
		T0 + 2U), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, p->recovery_id,
		PQCP_EDGE_RECOVERY_ISOLATING, T0 + 3U), 0);
	zassert_equal(pqcp_edge_recovery_record_step(&rc, p->recovery_id, 0U,
		false, ev, T0 + 4U), 0);
	zassert_equal(p->failed_steps, 0x1U);
	zassert_equal(p->phase, PQCP_EDGE_RECOVERY_ISOLATING);
	/* Second distinct failure exhausts the budget. */
	zassert_equal(pqcp_edge_recovery_record_step(&rc, p->recovery_id, 1U,
		false, ev, T0 + 5U), 0);
	zassert_equal(p->phase, PQCP_EDGE_RECOVERY_FAILED);
	zassert_equal(rc.failed_count, 1U);
	zassert_equal(pqcp_edge_recovery_record_step(&rc, p->recovery_id, 2U,
		true, ev, T0 + 6U), -EINVAL);

	/* Second plan: expiry detected on advance and by tick. */
	p2 = (void *)0x1;
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 6U, "dev-2", 1U, 1U,
		auth, T0, T0 + 50U, &p2), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, p2->recovery_id,
		PQCP_EDGE_RECOVERY_CHECKPOINTING, T0 + 50U), -ETIMEDOUT);
	zassert_equal(p2->phase, PQCP_EDGE_RECOVERY_FAILED);
	zassert_equal(rc.failed_count, 2U);

	/* Table full of live plans: refuse; finished ones are reclaimable. */
	recovery_setup();
	p = authorize_plan(1U, 1U, T0 + 100U);
	p2 = authorize_plan(1U, 1U, T0 + 200U);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 7U, "dev-3", 1U, 1U,
		auth, T0, T0 + 300U, &p3), -ENOSPC);
	zassert_is_null(p3);
	zassert_equal(pqcp_edge_recovery_tick(&rc, T0 + 100U, &failed), 0);
	zassert_equal(failed, 1U);
	zassert_equal(p->phase, PQCP_EDGE_RECOVERY_FAILED);
	zassert_equal(p2->phase, PQCP_EDGE_RECOVERY_AUTHORIZED);
	zassert_equal(pqcp_edge_recovery_tick(&rc, T0 + 100U, &failed), 0);
	zassert_equal(failed, 0U);
	zassert_equal(pqcp_edge_recovery_authorize(&rc, 7U, "dev-3", 1U, 1U,
		auth, T0 + 101U, T0 + 300U, &p3), 0);
	zassert_equal(p3, p);

	p3->completed_steps = 0x1U;
	p3->failed_steps = 0x1U;
	zassert_equal(pqcp_edge_recovery_coordinator_audit(&rc), -EBADMSG);
	p3->failed_steps = 0U;
	p3->completed_steps = 0x4U;
	zassert_equal(pqcp_edge_recovery_coordinator_audit(&rc), -EBADMSG);
}

ZTEST(edge_security, test_recovery_completed_plan_is_not_reopened_by_expiry)
{
	struct pqcp_edge_recovery_plan *p;
	uint8_t ckpt[PQCP_EDGE_DIGEST_BYTES];
	uint8_t ev[PQCP_EDGE_DIGEST_BYTES];
	uint64_t id;

	recovery_setup();
	edge_digest(ckpt, 0x10U);
	edge_digest(ev, 0x20U);
	p = authorize_plan(1U, 1U, T0 + 100U);
	id = p->recovery_id;
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_CHECKPOINTING, T0 + 1U), 0);
	zassert_equal(pqcp_edge_recovery_checkpoint(&rc, id, ckpt, T0 + 2U),
		      0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_ISOLATING, T0 + 3U), 0);
	zassert_equal(pqcp_edge_recovery_record_step(&rc, id, 0U, true, ev,
		T0 + 4U), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_RESTORING, T0 + 5U), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_VALIDATING, T0 + 6U), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_REJOINING, T0 + 7U), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_COMPLETE, T0 + 8U), 0);
	zassert_equal(p->phase, PQCP_EDGE_RECOVERY_COMPLETE);

	/* A stray call after the authorization window must not undo a
	 * finished recovery.
	 */
	(void)pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_COMPLETE, T0 + 500U);
	(void)pqcp_edge_recovery_advance(&rc, id,
		PQCP_EDGE_RECOVERY_FAILED, T0 + 501U);
	zassert_equal(p->phase, PQCP_EDGE_RECOVERY_COMPLETE);
	zassert_equal(rc.failed_count, 0U);
	zassert_equal(rc.completed_count, 1U);
}
