/*
 * SPDX-License-Identifier: MIT
 *
 * Composition root: runtime initialisation, end-to-end zero-trust
 * admission, compliance reporting and multi-module response flows.
 */

#include "edge_security_internal.h"
#include "test_common.h"

/* ------------------------------------------------------------------ */
/* Storage for a complete runtime (every array is statically sized)    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_principal s_principals[4];
static struct pqcp_edge_service s_services[2];
static struct pqcp_edge_endpoint s_endpoints[2];
static struct pqcp_edge_access_rule s_rules[4];
static struct pqcp_edge_route s_routes[2];
static struct pqcp_edge_session s_sessions[2];
static struct pqcp_edge_traffic_subject s_traffic[4];
static struct pqcp_edge_circuit s_circuits[2];
static struct pqcp_edge_message s_messages[3];
static struct pqcp_edge_replay_entry s_replay[2];
static struct pqcp_edge_reassembly s_reassembly[2];
static struct pqcp_edge_topic s_topics[2];
static struct pqcp_edge_subscription s_subscriptions[2];
static struct pqcp_edge_group s_groups[2];
static struct pqcp_edge_delivery s_deliveries[2];
static struct pqcp_edge_vault_object s_vault[3];
static struct pqcp_edge_vault_acl_entry s_acl[2];
static struct pqcp_edge_vault_version s_versions[2];
static struct pqcp_edge_vault_journal_entry s_journal[8];
static struct pqcp_edge_vault_lease s_leases[2];
static struct pqcp_edge_replica_record s_replicas[2];
static struct pqcp_edge_vault_snapshot s_snapshots[2];
static struct pqcp_edge_signal s_signals[4];
static struct pqcp_edge_incident s_incidents[2];
static struct pqcp_edge_playbook s_playbooks[1];
static struct pqcp_edge_evidence s_evidence[2];
static struct pqcp_edge_containment s_containments[2];
static struct pqcp_edge_continuity_service s_continuity[2];
static struct pqcp_edge_posture_report s_posture[2];
static struct pqcp_edge_attestation_record s_attestations[2];
static struct pqcp_edge_policy_bundle s_bundles[2];
static struct pqcp_edge_policy_ack s_acks[2];
static struct pqcp_edge_secret_rotation s_rotations[1];
static struct pqcp_edge_anomaly_baseline s_anomaly[2];
static struct pqcp_edge_resource_budget s_budgets[2];
static struct pqcp_edge_export_cursor s_cursors[2];
static struct pqcp_edge_recovery_plan s_recovery[1];
static struct pqcp_edge_dlp_rule s_dlp[2];
static struct pqcp_edge_trust_anchor s_anchors[2];
static struct pqcp_edge_federation_grant s_grants[2];
static struct pqcp_edge_credential_record s_credentials[2];
static struct pqcp_edge_isolation_zone s_zones[2];
static struct pqcp_edge_provenance_record s_provenance[4];
static struct pqcp_edge_workload_job s_jobs[2];
static struct pqcp_edge_sla_objective s_sla[2];
static struct pqcp_edge_config_transaction s_config[2];

static struct pqcp_edge_runtime rt;

#define SET_STORE(st, field, array)                                       \
	do {                                                              \
		(st)->field = (array);                                    \
	} while (0)

static void fill_storage(struct pqcp_edge_runtime_storage *st)
{
	memset(st, 0, sizeof(*st));
#define STORE(f, cap, arr) \
	do { st->f = arr; st->cap = ARRAY_SIZE(arr); } while (0)
	STORE(principals, principal_capacity, s_principals);
	STORE(services, service_capacity, s_services);
	STORE(endpoints, endpoint_capacity, s_endpoints);
	STORE(access_rules, access_rule_capacity, s_rules);
	STORE(routes, route_capacity, s_routes);
	STORE(sessions, session_capacity, s_sessions);
	STORE(traffic_subjects, traffic_subject_capacity, s_traffic);
	STORE(circuits, circuit_capacity, s_circuits);
	STORE(messages, message_capacity, s_messages);
	STORE(replay_entries, replay_capacity, s_replay);
	STORE(reassemblies, reassembly_capacity, s_reassembly);
	STORE(topics, topic_capacity, s_topics);
	STORE(subscriptions, subscription_capacity, s_subscriptions);
	STORE(groups, group_capacity, s_groups);
	STORE(deliveries, delivery_capacity, s_deliveries);
	STORE(vault_objects, vault_object_capacity, s_vault);
	STORE(vault_acl_entries, vault_acl_capacity, s_acl);
	STORE(vault_versions, vault_version_capacity, s_versions);
	STORE(vault_journal_entries, vault_journal_capacity, s_journal);
	STORE(vault_leases, vault_lease_capacity, s_leases);
	STORE(replicas, replica_capacity, s_replicas);
	STORE(snapshots, snapshot_capacity, s_snapshots);
	STORE(signals, signal_capacity, s_signals);
	STORE(incidents, incident_capacity, s_incidents);
	STORE(playbooks, playbook_capacity, s_playbooks);
	STORE(evidence, evidence_capacity, s_evidence);
	STORE(containments, containment_capacity, s_containments);
	STORE(continuity_services, continuity_capacity, s_continuity);
	STORE(posture_reports, posture_capacity, s_posture);
	STORE(attestations, attestation_capacity, s_attestations);
	STORE(policy_bundles, policy_bundle_capacity, s_bundles);
	STORE(policy_acks, policy_ack_capacity, s_acks);
	STORE(rotations, rotation_capacity, s_rotations);
	STORE(anomaly_baselines, anomaly_capacity, s_anomaly);
	STORE(resource_budgets, resource_budget_capacity, s_budgets);
	STORE(export_cursors, export_cursor_capacity, s_cursors);
	STORE(recovery_plans, recovery_plan_capacity, s_recovery);
	STORE(dlp_rules, dlp_rule_capacity, s_dlp);
	STORE(trust_anchors, trust_anchor_capacity, s_anchors);
	STORE(federation_grants, federation_grant_capacity, s_grants);
	STORE(credentials, credential_capacity, s_credentials);
	STORE(isolation_zones, isolation_capacity, s_zones);
	STORE(provenance_records, provenance_capacity, s_provenance);
	STORE(workload_jobs, workload_job_capacity, s_jobs);
	STORE(sla_objectives, sla_capacity, s_sla);
	STORE(config_transactions, config_transaction_capacity, s_config);
#undef STORE
}

#define RT_EPOCH 3U
#define POSTURE_ALL 0x33BU

static void rt_setup(void)
{
	struct pqcp_edge_runtime_storage st;

	fill_storage(&st);
	zassert_equal(pqcp_edge_runtime_init(&rt, &st, RT_EPOCH), 0);
}

/* Populate one admissible principal/service/endpoint/zone/posture/rule. */
static void rt_enroll(void)
{
	struct pqcp_edge_principal p;
	struct pqcp_edge_service s;
	struct pqcp_edge_endpoint e;
	struct pqcp_edge_isolation_zone z;
	struct pqcp_edge_posture_report r;
	struct pqcp_edge_access_rule rule;

	edge_make_principal(&p, "p1", 0x3U, PQCP_EDGE_TRUST_ATTESTED,
			    T0 + 1000000U);
	p.policy_epoch = RT_EPOCH;
	p.revocation_epoch = 1U;
	zassert_equal(pqcp_edge_principal_register(&rt.principals, &p, T0), 0);

	edge_make_service(&s, "svc", T0 + 1000000U);
	s.policy_epoch = RT_EPOCH;
	zassert_equal(pqcp_edge_service_register(&rt.services, &s, T0), 0);
	zassert_equal(pqcp_edge_service_set_state(&rt.services, "svc",
		PQCP_EDGE_SERVICE_HEALTHY, T0), 0);
	edge_make_endpoint(&e, "ep1", "svc", T0 + 1000000U);
	zassert_equal(pqcp_edge_endpoint_register(&rt.services, &e, T0), 0);

	memset(&z, 0, sizeof(z));
	SETSTR(z.zone_id, "zone-a");
	z.state = PQCP_EDGE_ISOLATION_OPEN;
	z.allowed_capabilities = 0xffU;
	z.allowed_operations = ALL_OPERATIONS;
	z.maximum_workloads = 4U;
	zassert_equal(pqcp_edge_isolation_zone_put(&rt.isolation, &z), 0);

	memset(&r, 0, sizeof(r));
	SETSTR(r.principal_id, "p1");
	r.measured_at_ms = T0;
	r.expires_at_ms = T0 + 1000000U;
	r.policy_epoch = RT_EPOCH;
	r.firmware_version = 1U;
	r.signal_mask = 0x3FFU;
	edge_digest(r.measurement_digest, 0x21U);
	zassert_equal(pqcp_edge_posture_submit(&rt.posture, &r, T0), 0);

	memset(&rule, 0, sizeof(rule));
	rule.rule_id = 1U;
	rule.priority = 1U;
	rule.operation_mask = ALL_OPERATIONS;
	rule.maximum_risk = 1000U;
	rule.effect = PQCP_EDGE_POLICY_ALLOW;
	rule.enabled = true;
	zassert_equal(pqcp_edge_access_rule_put(&rt.access, &rule), 0);
}

static struct pqcp_edge_admission_request base_request(uint64_t now)
{
	struct pqcp_edge_admission_request q;

	memset(&q, 0, sizeof(q));
	SETSTR(q.principal_id, "p1");
	SETSTR(q.service_id, "svc");
	SETSTR(q.endpoint_id, "ep1");
	q.operation = PQCP_EDGE_OPERATION_CONNECT;
	q.required_capabilities = 0x1U;
	q.request_bytes = 100U;
	q.revocation_epoch = 1U;
	q.now_ms = now;
	q.channel_identity_verified = true;
	q.reserve_traffic = true;
	return q;
}

static struct pqcp_edge_principal *principal(const char *id)
{
	struct pqcp_edge_principal *p = NULL;

	zassert_equal(pqcp_edge_principal_find(&rt.principals, id, &p), 0);
	return p;
}

/* ------------------------------------------------------------------ */
/* Runtime initialisation                                              */
/* ------------------------------------------------------------------ */

ZTEST(edge_security, test_runtime_init_rejects_invalid_storage)
{
	struct pqcp_edge_runtime_storage st;
	struct pqcp_edge_admission_request q = base_request(T0);
	struct pqcp_edge_admission_result res;
	struct pqcp_edge_compliance_summary sum;

	fill_storage(&st);
	zassert_equal(pqcp_edge_runtime_init(NULL, &st, RT_EPOCH), -EINVAL);
	zassert_equal(pqcp_edge_runtime_init(&rt, NULL, RT_EPOCH), -EINVAL);
	zassert_equal(pqcp_edge_runtime_init(&rt, &st, 0U), -EINVAL);

#define EXPECT_STORAGE_REJECTED(ptr, cap)                                   \
	do {                                                                \
		void *saved = (void *)st.ptr;                               \
		size_t saved_cap = st.cap;                                  \
		st.ptr = NULL;                                              \
		zassert_equal(pqcp_edge_runtime_init(&rt, &st, RT_EPOCH),   \
			      -EINVAL, #ptr " NULL");                       \
		st.ptr = saved;                                             \
		st.cap = 0U;                                                \
		zassert_equal(pqcp_edge_runtime_init(&rt, &st, RT_EPOCH),   \
			      -EINVAL, #cap " zero");                       \
		st.cap = saved_cap;                                         \
	} while (0)
	EXPECT_STORAGE_REJECTED(principals, principal_capacity);
	EXPECT_STORAGE_REJECTED(services, service_capacity);
	EXPECT_STORAGE_REJECTED(endpoints, endpoint_capacity);
	EXPECT_STORAGE_REJECTED(access_rules, access_rule_capacity);
	EXPECT_STORAGE_REJECTED(routes, route_capacity);
	EXPECT_STORAGE_REJECTED(sessions, session_capacity);
	EXPECT_STORAGE_REJECTED(traffic_subjects, traffic_subject_capacity);
	EXPECT_STORAGE_REJECTED(circuits, circuit_capacity);
	EXPECT_STORAGE_REJECTED(messages, message_capacity);
	EXPECT_STORAGE_REJECTED(replay_entries, replay_capacity);
	EXPECT_STORAGE_REJECTED(topics, topic_capacity);
	EXPECT_STORAGE_REJECTED(groups, group_capacity);
	EXPECT_STORAGE_REJECTED(vault_objects, vault_object_capacity);
	EXPECT_STORAGE_REJECTED(vault_journal_entries,
				vault_journal_capacity);
	EXPECT_STORAGE_REJECTED(incidents, incident_capacity);
	EXPECT_STORAGE_REJECTED(evidence, evidence_capacity);
	EXPECT_STORAGE_REJECTED(posture_reports, posture_capacity);
	EXPECT_STORAGE_REJECTED(policy_bundles, policy_bundle_capacity);
	EXPECT_STORAGE_REJECTED(credentials, credential_capacity);
	EXPECT_STORAGE_REJECTED(provenance_records, provenance_capacity);
	EXPECT_STORAGE_REJECTED(config_transactions,
				config_transaction_capacity);
#undef EXPECT_STORAGE_REJECTED

	/* A rejected initialisation never yields a usable runtime. */
	memset(&rt, 0, sizeof(rt));
	st.principals = NULL;
	zassert_equal(pqcp_edge_runtime_init(&rt, &st, RT_EPOCH), -EINVAL);
	zassert_false(rt.initialized);
	zassert_equal(pqcp_edge_runtime_tick(&rt, T0), -EINVAL);
	zassert_equal(pqcp_edge_runtime_advance_policy(&rt, 9U), -EINVAL);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EINVAL);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_runtime_audit(&rt), -EINVAL);
	zassert_equal(pqcp_edge_compliance_collect(&rt, T0, &sum), -EINVAL);
	zassert_equal(pqcp_edge_runtime_audit(NULL), -EINVAL);
}

ZTEST(edge_security, test_runtime_init_audit_tick_and_policy_advance)
{
	uint32_t tick_before;

	rt_setup();
	zassert_true(rt.initialized);
	zassert_equal(rt.policy_epoch, RT_EPOCH);
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
	/* The access engine starts as deny-by-default. */
	zassert_equal(rt.access.default_effect, PQCP_EDGE_POLICY_DENY);
	zassert_equal(rt.posture.policy.minimum_policy_epoch, RT_EPOCH);

	zassert_equal(pqcp_edge_runtime_tick(&rt, 0U), -EINVAL);
	tick_before = (uint32_t)rt.tick_count;
	zassert_equal(pqcp_edge_runtime_tick(&rt, T0), 0);
	zassert_equal(rt.tick_count, tick_before + 1U);

	/* Policy epochs only move forward and propagate to posture. */
	zassert_equal(pqcp_edge_runtime_advance_policy(&rt, 0U), -EINVAL);
	zassert_equal(pqcp_edge_runtime_advance_policy(&rt, RT_EPOCH),
		      -ESTALE);
	zassert_equal(pqcp_edge_runtime_advance_policy(&rt, RT_EPOCH - 1U),
		      -ESTALE);
	zassert_equal(rt.policy_epoch, RT_EPOCH);
	zassert_equal(pqcp_edge_runtime_advance_policy(&rt, RT_EPOCH + 4U),
		      0);
	zassert_equal(rt.policy_epoch, RT_EPOCH + 4U);
	zassert_equal(rt.posture.policy.minimum_policy_epoch, RT_EPOCH + 4U);
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);

	/* Audit notices subsystem corruption and epoch/posture drift. */
	rt.posture.policy.minimum_policy_epoch = RT_EPOCH;
	zassert_equal(pqcp_edge_runtime_audit(&rt), -ESTALE);
	rt.posture.policy.minimum_policy_epoch = RT_EPOCH + 4U;
	s_principals[0].state = PQCP_EDGE_PRINCIPAL_ACTIVE;
	s_principals[0].generation = 0U;
	zassert_equal(pqcp_edge_runtime_audit(&rt), -EBADMSG);
	memset(&s_principals[0], 0, sizeof(s_principals[0]));
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
	rt.schema_version = 99U;
	zassert_equal(pqcp_edge_runtime_audit(&rt), -EINVAL);
}

/* ------------------------------------------------------------------ */
/* Admission                                                           */
/* ------------------------------------------------------------------ */

ZTEST(edge_security, test_runtime_admission_rejects_invalid_requests)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;

	rt_setup();
	rt_enroll();
	q = base_request(T0 + 10U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, NULL, &res), -EINVAL);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, NULL), -EINVAL);
	zassert_equal(pqcp_edge_runtime_authorize(NULL, &q, &res), -EINVAL);

#define BAD_REQ(mut)                                                    \
	do {                                                            \
		q = base_request(T0 + 10U);                             \
		mut;                                                    \
		zassert_equal(pqcp_edge_runtime_authorize(&rt, &q,      \
			&res), -EINVAL, #mut);                          \
	} while (0)
	BAD_REQ(q.principal_id[0] = '\0');
	BAD_REQ(q.service_id[0] = '\0');
	BAD_REQ(q.operation = PQCP_EDGE_OPERATION_NONE);
	BAD_REQ(q.operation = PQCP_EDGE_OPERATION_COUNT);
	BAD_REQ(q.required_capabilities = 0U);
	BAD_REQ(q.revocation_epoch = 0U);
	BAD_REQ(q.now_ms = 0U);
	BAD_REQ(q.require_credential = true; q.credential_id[0] = '\0');
	BAD_REQ(memset(q.endpoint_id, 'x', sizeof(q.endpoint_id)));
#undef BAD_REQ
	/* Malformed input never reaches (or consumes) policy state. */
	zassert_equal(rt.access.allow_count + rt.access.deny_count +
		      rt.access.challenge_count, 0U);
	zassert_false(s_traffic[0].occupied);
}

ZTEST(edge_security, test_runtime_admission_allows_fully_authorized_request)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;
	struct pqcp_edge_endpoint *ep = NULL;

	rt_setup();
	rt_enroll();
	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		0U, T0 + 1U), 0);
	q = base_request(T0 + 10U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_true(res.admitted);
	zassert_equal(res.access.effect, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_RULE);
	zassert_equal(res.posture_effect, PQCP_EDGE_POLICY_ALLOW);
	zassert_equal(res.posture_failure_mask, 0U);
	zassert_equal(res.credential_result, 0);
	zassert_equal(res.isolation_result, 0);
	zassert_equal(res.circuit_result, 0);
	zassert_equal(res.traffic_result, 0);

	/* Traffic was reserved and must be released on completion. */
	zassert_true(s_traffic[0].occupied);
	zassert_equal(s_traffic[0].concurrent, 1U);
	zassert_equal(s_traffic[0].accepted_bytes, 100U);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 700U, T0 + 20U), 0);
	zassert_equal(s_traffic[0].concurrent, 0U);
	zassert_equal(pqcp_edge_endpoint_find(&rt.services, "ep1", &ep), 0);
	zassert_equal(ep->latency_ewma_us, 700U);
	zassert_equal(s_circuits[0].consecutive_failures, 0U);

	/* A second completion has nothing outstanding and reports it. */
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 700U, T0 + 21U), -EALREADY);
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
}

ZTEST(edge_security, test_runtime_admission_is_default_deny)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;

	rt_setup();
	rt_enroll();
	zassert_equal(pqcp_edge_access_rule_remove(&rt.access, 1U), 0);
	q = base_request(T0 + 10U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_false(res.admitted);
	zassert_equal(res.access.effect, PQCP_EDGE_POLICY_DENY);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_DEFAULT);
	zassert_true(strlen(res.access.explanation) > 0U);
	/* A denied request reserves nothing downstream. */
	zassert_false(s_traffic[0].occupied);
	zassert_false(s_circuits[0].occupied);

	/* An explicit challenge rule maps to -EAGAIN, not admission. */
	{
		struct pqcp_edge_access_rule rule;

		memset(&rule, 0, sizeof(rule));
		rule.rule_id = 2U;
		rule.priority = 1U;
		rule.operation_mask = ALL_OPERATIONS;
		rule.maximum_risk = 1000U;
		rule.effect = PQCP_EDGE_POLICY_CHALLENGE;
		rule.enabled = true;
		zassert_equal(pqcp_edge_access_rule_put(&rt.access, &rule), 0);
		zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res),
			      -EAGAIN);
		zassert_false(res.admitted);
		zassert_equal(res.access.effect, PQCP_EDGE_POLICY_CHALLENGE);
	}
	zassert_false(s_traffic[0].occupied);
}

ZTEST(edge_security, test_runtime_admission_subject_gates_fail_closed)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;
	struct pqcp_edge_principal *p;
	struct pqcp_edge_service *s = NULL;

	rt_setup();
	rt_enroll();
	p = principal("p1");

	q = base_request(T0 + 10U);
	SETSTR(q.principal_id, "ghost");
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -ENOENT);
	zassert_false(res.admitted);
	q = base_request(T0 + 10U);
	SETSTR(q.service_id, "ghost");
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -ENOENT);
	zassert_false(res.admitted);

	/* Capability the principal does not hold. */
	q = base_request(T0 + 10U);
	q.required_capabilities = 0x4U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_CAPABILITY);

	/* Quarantined and revoked principals never get in. */
	zassert_equal(pqcp_edge_principal_quarantine(&rt.principals, "p1",
		UINT64_MAX), 0);
	q = base_request(T0 + 10U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_false(res.admitted);
	p->state = PQCP_EDGE_PRINCIPAL_ACTIVE;
	zassert_equal(pqcp_edge_principal_revoke(&rt.principals, "p1", 9U,
		T0 + 11U), 0);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_false(res.admitted);

	/* Fresh principal for the remaining gates. */
	{
		struct pqcp_edge_principal np;

		edge_make_principal(&np, "p2", 0x3U,
				    PQCP_EDGE_TRUST_ATTESTED, T0 + 1000000U);
		np.policy_epoch = RT_EPOCH;
		np.revocation_epoch = 1U;
		zassert_equal(pqcp_edge_principal_register(&rt.principals,
			&np, T0), 0);
	}
	/* p2 has no posture report: posture is unknown, hence challenged. */
	q = base_request(T0 + 10U);
	SETSTR(q.principal_id, "p2");
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -ENOENT);
	zassert_false(res.admitted);
	zassert_equal(res.posture_effect, PQCP_EDGE_POLICY_CHALLENGE);
	p = principal("p2");

	/* The caller's revocation view is newer than the principal's. */
	q.revocation_epoch = 5U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res),
		      -EKEYREVOKED);
	/* Principal bound to an older policy epoch than the runtime. */
	q = base_request(T0 + 10U);
	SETSTR(q.principal_id, "p2");
	p->policy_epoch = RT_EPOCH - 1U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -ESTALE);
	p->policy_epoch = RT_EPOCH;

	/* Retired services are unreachable. */
	zassert_equal(pqcp_edge_service_find(&rt.services, "svc", &s), 0);
	zassert_equal(pqcp_edge_service_set_state(&rt.services, "svc",
		PQCP_EDGE_SERVICE_RETIRED, T0 + 12U), 0);
	q = base_request(T0 + 13U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_false(res.admitted);

	/* Not one of the denials above touched traffic state. */
	zassert_false(s_traffic[0].occupied);
	zassert_false(s_circuits[0].occupied);
}

ZTEST(edge_security, test_runtime_admission_isolation_and_posture_gates)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;

	rt_setup();
	rt_enroll();
	q = base_request(T0 + 10U);

	/* Quarantined zone: operational traffic is refused. */
	zassert_equal(pqcp_edge_isolation_transition(&rt.isolation, "zone-a",
		PQCP_EDGE_ISOLATION_QUARANTINED, 0x1U, T0 + 5U, 0U), 0);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_ZONE);
	zassert_false(res.admitted);
	zassert_equal(pqcp_edge_isolation_transition(&rt.isolation, "zone-a",
		PQCP_EDGE_ISOLATION_RESTRICTED, 0x1U, T0 + 6U, 0U), 0);
	/* ... and restricted zones still block administration. */
	q.operation = PQCP_EDGE_OPERATION_ADMINISTER;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_ZONE);
	q.operation = PQCP_EDGE_OPERATION_CONNECT;
	zassert_equal(pqcp_edge_isolation_transition(&rt.isolation, "zone-a",
		PQCP_EDGE_ISOLATION_OPEN, 0U, T0 + 7U, 0U), 0);

	/* Posture failures: secure boot lost -> quarantine -> denied. */
	s_posture[0].failure_mask = 0x1U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_equal(res.posture_failure_mask, 0x1U);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_ATTESTATION);
	/* Policy not current -> challenge. */
	s_posture[0].failure_mask = 0x8U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EAGAIN);
	zassert_equal(res.posture_effect, PQCP_EDGE_POLICY_CHALLENGE);
	zassert_false(res.admitted);
	/* Stale measurements are not trusted. */
	s_posture[0].failure_mask = 0U;
	q.now_ms = T0 + 400000U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -ESTALE);
	zassert_false(res.admitted);
	q.now_ms = T0 + 10U;
	/* Healthy posture re-admits. */
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_true(res.admitted);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 100U, T0 + 11U), 0);
}

ZTEST(edge_security, test_runtime_admission_reports_posture_quarantine_verdict)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;

	rt_setup();
	rt_enroll();
	q = base_request(T0 + 10U);
	s_posture[0].failure_mask = 0x1U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_false(res.admitted);
	zassert_equal(res.posture_effect, PQCP_EDGE_POLICY_QUARANTINE);
}

ZTEST(edge_security, test_runtime_admission_credential_and_attestation_gates)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;
	struct pqcp_edge_credential_record c;
	struct pqcp_edge_service *s = NULL;
	uint8_t nonce[PQCP_EDGE_NONCE_BYTES];
	uint8_t binding[PQCP_EDGE_DIGEST_BYTES];
	uint8_t evidence[PQCP_EDGE_DIGEST_BYTES];
	struct pqcp_edge_attestation_record *ar = NULL;

	rt_setup();
	rt_enroll();
	q = base_request(T0 + 10U);
	q.require_credential = true;
	SETSTR(q.credential_id, "cred-1");

	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -ENOENT);
	zassert_false(res.admitted);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_REVOCATION);

	memset(&c, 0, sizeof(c));
	SETSTR(c.credential_id, "cred-1");
	SETSTR(c.principal_id, "p1");
	SETSTR(c.issuer_domain, "dom-a");
	c.issuance_epoch = 1U;
	c.policy_epoch = RT_EPOCH;
	c.revocation_epoch = 1U;
	c.issued_at_ms = T0;
	c.refresh_at_ms = T0 + 100U;
	c.expires_at_ms = T0 + 1000U;
	c.capabilities = 0x1U;
	edge_digest(c.public_key_digest, 1U);
	edge_digest(c.credential_digest, 2U);
	zassert_equal(pqcp_edge_credential_put(&rt.credentials, &c, T0), 0);
	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		0U, T0 + 1U), 0);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 10U, T0 + 11U), 0);
	/* Credential needing refresh is not accepted. */
	q.now_ms = T0 + 100U;
	zassert_equal(pqcp_edge_credential_tick(&rt.credentials, T0 + 100U,
		&(uint32_t){ 0U }), 0);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EAGAIN);
	zassert_false(res.admitted);
	/* Revoking the credential closes the door permanently. */
	zassert_equal(pqcp_edge_credential_revoke(&rt.credentials, "cred-1",
		7U), 0);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res),
		      -EKEYREVOKED);
	zassert_false(res.admitted);
	/* The request's own capability check still holds without it. */
	q.require_credential = false;
	q.now_ms = T0 + 101U;

	/* Attestation-gated service. */
	zassert_equal(pqcp_edge_service_find(&rt.services, "svc", &s), 0);
	s->require_attestation = true;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -ENOENT);
	zassert_false(res.admitted);
	zassert_false(res.attestation_fresh);
	memset(nonce, 0x5a, sizeof(nonce));
	edge_digest(binding, 0x33U);
	edge_digest(evidence, 0x34U);
	zassert_equal(pqcp_edge_attestation_challenge(&rt.attestation, "p1",
		nonce, binding, 0x7U, T0 + 101U, T0 + 5000U, &ar), 0);
	zassert_equal(pqcp_edge_attestation_submit(&rt.attestation,
		ar->challenge_id, 0x7U, evidence, binding, T0 + 102U), 0);
	q.now_ms = T0 + 103U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_true(res.admitted);
	zassert_true(res.attestation_fresh);
	/* Attestation lapses with its challenge window. */
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 10U, T0 + 104U), 0);
	q.now_ms = T0 + 5000U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -ENOENT);
	zassert_false(res.admitted);
}

ZTEST(edge_security, test_runtime_admission_policy_epoch_advance_invalidates_old_identities)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;

	rt_setup();
	rt_enroll();
	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		0U, T0 + 1U), 0);
	q = base_request(T0 + 10U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 10U, T0 + 11U), 0);

	zassert_equal(pqcp_edge_runtime_advance_policy(&rt, RT_EPOCH + 1U),
		      0);
	/* Principal and service still carry the old epoch: refused. */
	q.now_ms = T0 + 12U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -ESTALE);
	zassert_false(res.admitted);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_REVOCATION);
}

ZTEST(edge_security, test_runtime_admission_circuit_and_traffic_enforcement)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;

	rt_setup();
	rt_enroll();
	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		0U, T0 + 1U), 0);
	q = base_request(T0 + 10U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 10U, T0 + 11U), 0);

	/* Isolated endpoint circuit. */
	zassert_equal(pqcp_edge_circuit_isolate(&rt.circuits, "svc", "ep1"),
		      0);
	q.now_ms = T0 + 12U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_false(res.admitted);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_SERVICE);
	zassert_equal(pqcp_edge_circuit_reset(&rt.circuits, "svc", "ep1",
		T0 + 13U), 0);

	/* Blocked traffic subject. */
	zassert_equal(pqcp_edge_traffic_block(&rt.traffic, "p1", "svc",
		T0 + 100000U), 0);
	q.now_ms = T0 + 14U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_false(res.admitted);
	zassert_equal(res.access.reason, PQCP_EDGE_POLICY_REASON_QUOTA);

	/* Requests may skip the traffic reservation explicitly. */
	q.reserve_traffic = false;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_true(res.admitted);
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
}

ZTEST(edge_security, test_runtime_complete_request_validates_and_records_failures)
{
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;
	struct pqcp_edge_endpoint *ep = NULL;
	char bad[PQCP_EDGE_ID_MAX_CHARS];

	rt_setup();
	rt_enroll();
	memset(bad, 'x', sizeof(bad));
	zassert_equal(pqcp_edge_runtime_complete_request(NULL, "p1", "svc",
		"ep1", true, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, NULL, "svc",
		"ep1", true, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", NULL,
		"ep1", true, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 1U, 0U), -EINVAL);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, bad, "svc",
		"ep1", true, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		bad, true, 1U, T0), -EINVAL);
	/* Unknown subjects surface the first underlying error. */
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		NULL, true, 1U, T0), -ENOENT);

	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		0U, T0 + 1U), 0);
	q = base_request(T0 + 10U);
	for (int i = 0; i < 5; ++i) {
		zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
		q.now_ms += 1U;
		zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1",
			"svc", "ep1", false, 10U, q.now_ms), 0);
		q.now_ms += 1U;
	}
	/* Five consecutive failures: endpoint ejected, circuit opened. */
	zassert_equal(pqcp_edge_endpoint_find(&rt.services, "ep1", &ep), 0);
	zassert_equal(ep->state, PQCP_EDGE_ENDPOINT_EJECTED);
	zassert_equal(s_circuits[0].state, PQCP_EDGE_CIRCUIT_OPEN);
	zassert_true(s_traffic[0].failure_score >= 500U);
	zassert_equal(s_traffic[0].concurrent, 0U);
	/* The next request is refused by the open circuit. */
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EHOSTDOWN);
	zassert_false(res.admitted);
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
}

/* ------------------------------------------------------------------ */
/* Compliance                                                          */
/* ------------------------------------------------------------------ */

static uint32_t expected_score(const struct pqcp_edge_compliance_summary *s)
{
	uint64_t penalty = s->integrity_failure_count * 1200U +
			   s->open_incident_count * 400U +
			   (s->policy_denial_count > 1000U ? 1000U :
			    s->policy_denial_count) +
			   (s->maximum_risk_score > 1000U ? 1000U :
			    s->maximum_risk_score);

	if (s->principal_count == 0U || s->service_count == 0U) {
		penalty += 500U;
	}
	return penalty >= 10000U ? 0U : (uint32_t)(10000U - penalty);
}

ZTEST(edge_security, test_runtime_compliance_collect_and_encode)
{
	struct pqcp_edge_compliance_summary sum;
	struct pqcp_edge_compliance_summary bad;
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;
	uint8_t out[160];
	size_t length = 0U;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	static const uint64_t ids[1] = { 5U };
	struct pqcp_edge_incident *inc = NULL;

	rt_setup();
	/* An empty runtime is penalised for lacking principals/services. */
	zassert_equal(pqcp_edge_compliance_collect(&rt, 0U, &sum), -EINVAL);
	zassert_equal(pqcp_edge_compliance_collect(&rt, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_compliance_collect(&rt, T0, &sum), 0);
	zassert_equal(sum.principal_count, 0U);
	zassert_equal(sum.service_count, 0U);
	zassert_equal(sum.compliance_score, expected_score(&sum));
	zassert_true(sum.compliance_score <= 9500U);

	rt_enroll();
	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		0U, T0 + 1U), 0);
	q = base_request(T0 + 10U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_equal(pqcp_edge_incident_open(&rt.incidents, "title", "p1",
		"soc", PQCP_EDGE_INCIDENT_LOW, 250U, ids, 1U, T0 + 20U, &inc),
		0);
	zassert_equal(pqcp_edge_compliance_collect(&rt, T0 + 30U, &sum), 0);
	zassert_equal(sum.schema_version, PQCP_EDGE_SCHEMA_VERSION);
	zassert_equal(sum.generated_at_ms, T0 + 30U);
	zassert_equal(sum.policy_epoch, RT_EPOCH);
	zassert_equal(sum.principal_count, 1U);
	zassert_equal(sum.service_count, 1U);
	zassert_equal(sum.active_session_count, 0U);
	zassert_equal(sum.open_incident_count, 1U);
	zassert_equal(sum.maximum_risk_score, 250U);
	zassert_equal(sum.integrity_failure_count, 0U);
	zassert_equal(sum.compliance_score, expected_score(&sum));

	/* Canonical encoding: fixed layout, digest bound to the content. */
	zassert_equal(pqcp_edge_compliance_encode(&sum, out, sizeof(out),
		&length), 0);
	zassert_equal(length, 124U);
	zassert_equal(pqcp_edge_internal_read_u32(out), 1U);
	zassert_equal(pqcp_edge_internal_read_u64(out + 4U), T0 + 30U);
	zassert_equal(pqcp_edge_internal_read_u64(out + 12U), RT_EPOCH);
	zassert_equal(pqcp_edge_internal_read_u64(out + 20U), 1U);
	zassert_equal(pqcp_edge_internal_sha256(out, 92U, digest), 0);
	zassert_mem_equal(out + 92U, digest, sizeof(digest));
	zassert_mem_equal(out + 92U, sum.state_digest, sizeof(digest));

	/* Collection is deterministic for an unchanged runtime. */
	{
		struct pqcp_edge_compliance_summary again;

		zassert_equal(pqcp_edge_compliance_collect(&rt, T0 + 30U,
			&again), 0);
		zassert_mem_equal(&sum, &again, sizeof(sum));
	}

	/* Encoding rejects inconsistent or undersized inputs. */
	zassert_equal(pqcp_edge_compliance_encode(NULL, out, sizeof(out),
		&length), -EINVAL);
	zassert_equal(pqcp_edge_compliance_encode(&sum, NULL, sizeof(out),
		&length), -EINVAL);
	zassert_equal(pqcp_edge_compliance_encode(&sum, out, sizeof(out),
		NULL), -EINVAL);
	zassert_equal(pqcp_edge_compliance_encode(&sum, out, 123U, &length),
		      -EINVAL);
	bad = sum; bad.schema_version = 2U;
	zassert_equal(pqcp_edge_compliance_encode(&bad, out, sizeof(out),
		&length), -EINVAL);
	bad = sum; bad.generated_at_ms = 0U;
	zassert_equal(pqcp_edge_compliance_encode(&bad, out, sizeof(out),
		&length), -EINVAL);
	bad = sum; bad.policy_epoch = 0U;
	zassert_equal(pqcp_edge_compliance_encode(&bad, out, sizeof(out),
		&length), -EINVAL);
	bad = sum; bad.compliance_score = 10001U;
	zassert_equal(pqcp_edge_compliance_encode(&bad, out, sizeof(out),
		&length), -EINVAL);
	bad = sum; memset(bad.state_digest, 0, sizeof(bad.state_digest));
	zassert_equal(pqcp_edge_compliance_encode(&bad, out, sizeof(out),
		&length), -EINVAL);
	/* A tampered figure no longer matches its digest and no output
	 * escapes.
	 */
	bad = sum; bad.compliance_score = 10000U;
	memset(out, 0x77, sizeof(out));
	zassert_equal(pqcp_edge_compliance_encode(&bad, out, sizeof(out),
		&length), -EBADMSG);
	zassert_true(pqcp_edge_internal_all_zero(out, 124U));
	bad = sum; bad.open_incident_count = 0U;
	zassert_equal(pqcp_edge_compliance_encode(&bad, out, sizeof(out),
		&length), -EBADMSG);
}

ZTEST(edge_security, test_runtime_compliance_counts_integrity_failures_and_denials)
{
	struct pqcp_edge_compliance_summary clean;
	struct pqcp_edge_compliance_summary dirty;
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;

	rt_setup();
	rt_enroll();
	zassert_equal(pqcp_edge_compliance_collect(&rt, T0, &clean), 0);
	zassert_equal(clean.integrity_failure_count, 0U);
	zassert_equal(clean.policy_denial_count, 0U);

	/* Denials feed the compliance denial counter. */
	zassert_equal(pqcp_edge_access_rule_remove(&rt.access, 1U), 0);
	q = base_request(T0 + 10U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_equal(pqcp_edge_compliance_collect(&rt, T0 + 11U, &dirty), 0);
	zassert_equal(dirty.policy_denial_count, 2U);
	zassert_equal(dirty.compliance_score, expected_score(&dirty));
	zassert_true(dirty.compliance_score < clean.compliance_score);

	/* A failing runtime audit costs a full integrity penalty. */
	s_principals[0].active_sessions = 99U;
	zassert_equal(pqcp_edge_runtime_audit(&rt), -EBADMSG);
	zassert_equal(pqcp_edge_compliance_collect(&rt, T0 + 12U, &dirty), 0);
	zassert_equal(dirty.integrity_failure_count, 1U);
	zassert_equal(dirty.compliance_score, expected_score(&dirty));
	zassert_true(dirty.compliance_score + 1200U <= clean.compliance_score);
	s_principals[0].active_sessions = 0U;
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
}

/* ------------------------------------------------------------------ */
/* End-to-end flows across subsystems                                  */
/* ------------------------------------------------------------------ */

ZTEST(edge_security, test_flow_signal_to_containment_and_recovery)
{
	struct pqcp_edge_signal sig;
	struct pqcp_edge_signal *accepted = NULL;
	uint64_t ids[PQCP_EDGE_MAX_INCIDENT_SIGNALS];
	uint32_t risk = 0U;
	uint32_t count = 0U;
	enum pqcp_edge_incident_severity severity;
	struct pqcp_edge_incident *inc = NULL;
	struct pqcp_edge_playbook *pb = NULL;
	struct pqcp_edge_playbook_step steps[2];
	struct pqcp_edge_playbook_step *step = NULL;
	struct pqcp_edge_containment *cn = NULL;
	struct pqcp_edge_evidence *ev = NULL;
	struct pqcp_edge_recovery_plan *plan = NULL;
	struct pqcp_edge_admission_request q;
	struct pqcp_edge_admission_result res;
	struct pqcp_edge_principal *p;
	uint8_t auth[PQCP_EDGE_DIGEST_BYTES];
	uint8_t ckpt[PQCP_EDGE_DIGEST_BYTES];
	uint8_t proof[PQCP_EDGE_DIGEST_BYTES];
	uint8_t d_in[PQCP_EDGE_DIGEST_BYTES];
	uint8_t d_out[PQCP_EDGE_DIGEST_BYTES];
	const uint8_t artefact[8] = { 'l', 'o', 'g', 'b', 'u', 'n', 'd', 'l' };

	rt_setup();
	rt_enroll();
	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		0U, T0 + 1U), 0);
	q = base_request(T0 + 10U);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 10U, T0 + 11U), 0);

	/* 1. Detection: signals correlate into a risk score. */
	memset(&sig, 0, sizeof(sig));
	sig.type = PQCP_EDGE_SIGNAL_AUTHENTICATION_FAILURE;
	sig.severity = PQCP_EDGE_INCIDENT_HIGH;
	SETSTR(sig.source_id, "ids-1");
	SETSTR(sig.subject_id, "p1");
	sig.observed_at_ms = T0 + 20U;
	sig.policy_epoch = RT_EPOCH;
	sig.magnitude = 2U;
	sig.confidence = 800U;
	edge_digest(sig.evidence_digest, 0x51U);
	zassert_equal(pqcp_edge_signal_submit(&rt.signals, &sig, T0 + 20U,
		&accepted), 0);
	zassert_equal(pqcp_edge_signal_correlate(&rt.signals, "p1", 0U, &risk,
		&severity, ids, &count), 0);
	/* (250 + 100) * 2 * 0.8 */
	zassert_equal(risk, 560U);
	zassert_equal(severity, PQCP_EDGE_INCIDENT_HIGH);
	zassert_equal(count, 1U);

	/* 2. Incident with evidence custody. */
	zassert_equal(pqcp_edge_incident_open(&rt.incidents, "credential "
		"stuffing", "p1", "soc", severity, risk, ids, count, T0 + 21U,
		&inc), 0);
	zassert_equal(pqcp_edge_incident_transition(&rt.incidents,
		inc->incident_id, PQCP_EDGE_INCIDENT_TRIAGED, T0 + 22U), 0);
	zassert_equal(pqcp_edge_incident_transition(&rt.incidents,
		inc->incident_id, PQCP_EDGE_INCIDENT_CONTAINING, T0 + 23U), 0);
	zassert_equal(pqcp_edge_evidence_capture(&rt.evidence,
		inc->incident_id, "ids-1", "auth-log", artefact,
		sizeof(artefact), T0 + 24U, T0 + 100000U, &ev), 0);
	zassert_equal(pqcp_edge_evidence_seal(&rt.evidence, ev->evidence_id),
		      0);

	/* 3. Containment via a playbook that blocks the principal. */
	steps[0] = (struct pqcp_edge_playbook_step){
		.step_id = 1U, .action = PQCP_EDGE_PLAYBOOK_BLOCK_PRINCIPAL,
		.maximum_attempts = 1U, .mandatory = true };
	steps[1] = (struct pqcp_edge_playbook_step){
		.step_id = 2U, .action = PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR,
		.dependency_mask = 0x1U, .maximum_attempts = 1U };
	zassert_equal(pqcp_edge_playbook_start(&rt.playbooks,
		inc->incident_id, steps, 2U, T0 + 25U, &pb), 0);
	zassert_equal(pqcp_edge_containment_apply(&rt.containment,
		inc->incident_id, "p1", 1U << PQCP_EDGE_PLAYBOOK_BLOCK_PRINCIPAL,
		T0 + 25U, T0 + 50000U, &cn), 0);
	zassert_equal(pqcp_edge_playbook_next(&rt.playbooks, pb->execution_id,
		T0 + 26U, &step), 0);
	zassert_equal(step->action, PQCP_EDGE_PLAYBOOK_BLOCK_PRINCIPAL);
	zassert_equal(pqcp_edge_principal_quarantine(&rt.principals, "p1",
		UINT64_MAX), 0);
	zassert_equal(pqcp_edge_containment_record_action(&rt.containment,
		cn->containment_id, 1U << PQCP_EDGE_PLAYBOOK_BLOCK_PRINCIPAL,
		0), 0);
	zassert_equal(pqcp_edge_playbook_complete_step(&rt.playbooks,
		pb->execution_id, 1U, 0, T0 + 27U), 0);
	zassert_equal(pqcp_edge_playbook_next(&rt.playbooks, pb->execution_id,
		T0 + 28U, &step), 0);
	zassert_equal(pqcp_edge_playbook_complete_step(&rt.playbooks,
		pb->execution_id, 2U, 0, T0 + 29U), 0);
	zassert_false(pb->active);

	/* Containment is effective: the principal can no longer connect. */
	q.now_ms = T0 + 30U;
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), -EACCES);
	zassert_false(res.admitted);
	zassert_equal(pqcp_edge_principal_observe(&rt.principals, "p1", 0U,
		PQCP_EDGE_TRUST_ATTESTED, true, T0 + 30U), -EACCES);

	/* 4. Recovery: authorized plan, evidence-chained steps. */
	edge_digest(auth, 0x61U);
	edge_digest(ckpt, 0x62U);
	edge_digest(proof, 0x63U);
	zassert_equal(pqcp_edge_recovery_authorize(&rt.recovery,
		inc->incident_id, "p1", 1U, 1U, auth, T0 + 31U, T0 + 90000U,
		&plan), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rt.recovery,
		plan->recovery_id, PQCP_EDGE_RECOVERY_CHECKPOINTING,
		T0 + 32U), 0);
	zassert_equal(pqcp_edge_recovery_checkpoint(&rt.recovery,
		plan->recovery_id, ckpt, T0 + 33U), 0);
	zassert_equal(pqcp_edge_recovery_advance(&rt.recovery,
		plan->recovery_id, PQCP_EDGE_RECOVERY_ISOLATING, T0 + 34U),
		0);
	zassert_equal(pqcp_edge_recovery_record_step(&rt.recovery,
		plan->recovery_id, 0U, true, proof, T0 + 35U), 0);
	for (enum pqcp_edge_recovery_phase ph = PQCP_EDGE_RECOVERY_RESTORING;
	     ph <= PQCP_EDGE_RECOVERY_COMPLETE; ++ph) {
		zassert_equal(pqcp_edge_recovery_advance(&rt.recovery,
			plan->recovery_id, ph, T0 + 36U + ph), 0);
	}
	zassert_equal(plan->phase, PQCP_EDGE_RECOVERY_COMPLETE);

	/* 5. Release, resolve, close, and record provenance. */
	zassert_equal(pqcp_edge_principal_release(&rt.principals, "p1",
		T0 + 50U), 0);
	p = principal("p1");
	zassert_equal(p->state, PQCP_EDGE_PRINCIPAL_DEGRADED);
	zassert_equal(pqcp_edge_containment_release(&rt.containment,
		cn->containment_id, T0 + 51U), 0);
	zassert_equal(pqcp_edge_incident_transition(&rt.incidents,
		inc->incident_id, PQCP_EDGE_INCIDENT_MONITORING, T0 + 52U), 0);
	inc->remediation_mask = 1U << PQCP_EDGE_PLAYBOOK_BLOCK_PRINCIPAL;
	zassert_equal(pqcp_edge_incident_transition(&rt.incidents,
		inc->incident_id, PQCP_EDGE_INCIDENT_RESOLVED, T0 + 53U), 0);
	zassert_equal(pqcp_edge_incident_transition(&rt.incidents,
		inc->incident_id, PQCP_EDGE_INCIDENT_CLOSED, T0 + 54U), 0);
	edge_digest(d_in, 0x71U);
	edge_digest(d_out, 0x72U);
	zassert_equal(pqcp_edge_provenance_append(&rt.provenance, "p1-state",
		"soc", "edge-1", PQCP_EDGE_PROVENANCE_TRANSFORMED, RT_EPOCH,
		d_in, d_out, T0 + 55U, NULL), 0);

	/* The recovered principal can work again (degraded, not trusted). */
	q.now_ms = T0 + 60U;
	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		0U, T0 + 56U), 0);
	zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
	zassert_true(res.admitted);
	zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1", "svc",
		"ep1", true, 10U, T0 + 61U), 0);
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
}

ZTEST(edge_security, test_flow_vault_lifecycle_with_audit_trail)
{
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_vault_object *obj = NULL;
	struct pqcp_edge_principal *p;
	struct pqcp_edge_vault_lease *lease = NULL;
	struct pqcp_edge_replica_record *rep = NULL;
	struct pqcp_edge_replica_record *next = NULL;
	struct pqcp_edge_vault_snapshot *snap = NULL;
	struct pqcp_edge_export_cursor *cur = NULL;
	struct pqcp_edge_export_batch batch;
	struct pqcp_edge_compliance_summary sum;
	uint8_t out[32];
	size_t length = 0U;
	const uint32_t read = PQCP_EDGE_VAULT_PERMISSION_READ;
	const uint8_t payload[1] = { 1 };
	uint64_t first_seq;

	rt_setup();
	rt_enroll();
	p = principal("p1");

	memset(&o, 0, sizeof(o));
	SETSTR(o.object_id, "secret-1");
	SETSTR(o.namespace_id, "ns");
	SETSTR(o.owner_id, "p1");
	SETSTR(o.classification, "restricted");
	o.version = 1U;
	o.policy_epoch = RT_EPOCH;
	o.permissions = PQCP_EDGE_VAULT_PERMISSION_READ |
			PQCP_EDGE_VAULT_PERMISSION_WRITE |
			PQCP_EDGE_VAULT_PERMISSION_REPLICATE;
	memcpy(o.value, "v1-value", 8U);
	o.value_length = 8U;
	zassert_equal(pqcp_edge_vault_create(&rt.vault, &o, T0 + 1U), 0);
	zassert_equal(pqcp_edge_vault_find(&rt.vault, "secret-1", &obj), 0);
	zassert_equal(pqcp_edge_vault_journal_append(&rt.journal,
		PQCP_EDGE_VAULT_JOURNAL_CREATE, "secret-1", "p1", 0, payload,
		1U, T0 + 1U), 0);
	first_seq = s_journal[0].sequence;

	/* The owner reads; a stranger without an ACL entry is denied. */
	zassert_equal(pqcp_edge_vault_acl_authorize(&rt.vault_acl, obj, p,
		read, true, T0 + 2U), 0);
	{
		struct pqcp_edge_principal stranger;

		edge_make_principal(&stranger, "p9", 0x1U,
				    PQCP_EDGE_TRUST_ATTESTED, T0 + 1000000U);
		zassert_equal(pqcp_edge_vault_acl_authorize(&rt.vault_acl, obj,
			&stranger, read, true, T0 + 2U), -EACCES);
	}
	zassert_equal(pqcp_edge_vault_read(&rt.vault, "secret-1", out,
		sizeof(out), &length, T0 + 3U), 0);
	zassert_equal(length, 8U);
	zassert_equal(pqcp_edge_vault_journal_append(&rt.journal,
		PQCP_EDGE_VAULT_JOURNAL_READ, "secret-1", "p1", 0, NULL,
		0U, T0 + 3U), 0);

	/* Version, update, restore. */
	zassert_equal(pqcp_edge_vault_version_capture(&rt.versions, obj,
		T0 + 4U, 100000U), 0);
	zassert_equal(pqcp_edge_vault_write(&rt.vault, "secret-1",
		(const uint8_t *)"v2-value", 8U, 1U, T0 + 5U), 0);
	zassert_equal(pqcp_edge_vault_journal_append(&rt.journal,
		PQCP_EDGE_VAULT_JOURNAL_UPDATE, "secret-1", "p1", 0, payload,
		1U, T0 + 5U), 0);
	zassert_equal(pqcp_edge_vault_version_restore(&rt.versions, &rt.vault,
		"secret-1", 1U, T0 + 6U), 0);
	zassert_equal(pqcp_edge_vault_read(&rt.vault, "secret-1", out,
		sizeof(out), &length, T0 + 7U), 0);
	zassert_mem_equal(out, "v1-value", 8U);

	/* Short-lived lease, bound to policy epoch. */
	zassert_equal(pqcp_edge_vault_lease_issue(&rt.leases, "secret-1",
		"p1", read, RT_EPOCH, T0 + 8U, T0 + 1000U, 1U, &lease), 0);
	zassert_equal(pqcp_edge_vault_lease_authorize(&rt.leases,
		lease->lease_id, "secret-1", "p1", read, RT_EPOCH, T0 + 9U),
		0);
	zassert_equal(pqcp_edge_vault_lease_authorize(&rt.leases,
		lease->lease_id, "secret-1", "p1", read, RT_EPOCH, T0 + 10U),
		-EDQUOT);
	zassert_equal(pqcp_edge_vault_lease_authorize(&rt.leases,
		lease->lease_id, "secret-1", "p1", read, RT_EPOCH + 1U,
		T0 + 10U), -ESTALE);

	/* Replication applies only with the exact object digest. */
	zassert_equal(pqcp_edge_replication_schedule(&rt.replication, obj,
		"peer-1", T0 + 11U, 3U, &rep), 0);
	zassert_equal(pqcp_edge_replication_next(&rt.replication, T0 + 12U,
		&next), 0);
	zassert_equal(pqcp_edge_replication_complete(&rt.replication,
		rep->replication_id, 0, obj->object_digest, T0 + 13U), 0);
	zassert_equal(rep->state, PQCP_EDGE_REPLICA_APPLIED);

	/* Snapshot ties store state to the journal head; export resumes. */
	zassert_equal(pqcp_edge_snapshot_capture(&rt.snapshots, &rt.vault,
		&rt.journal, T0 + 14U, &snap), 0);
	zassert_equal(snap->object_count, 1U);
	zassert_mem_equal(snap->journal_head, rt.journal.chain_head,
			  PQCP_EDGE_DIGEST_BYTES);
	zassert_equal(pqcp_edge_audit_export_open(&rt.exporter, "uplink",
		first_seq, T0 + 15U, 100000U, &cur), 0);
	zassert_equal(pqcp_edge_audit_export_batch(&rt.exporter, &rt.journal,
		cur->cursor_id, 10U, T0 + 16U, &batch), 0);
	zassert_equal(batch.record_count, 3U);
	zassert_equal(pqcp_edge_audit_export_acknowledge(&rt.exporter,
		cur->cursor_id, batch.last_sequence), 0);
	zassert_equal(pqcp_edge_audit_export_batch(&rt.exporter, &rt.journal,
		cur->cursor_id, 10U, T0 + 17U, &batch), -EAGAIN);

	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
	zassert_equal(pqcp_edge_compliance_collect(&rt, T0 + 20U, &sum), 0);
	zassert_equal(sum.vault_object_count, 1U);
	zassert_equal(sum.integrity_failure_count, 0U);
}

ZTEST(edge_security, test_flow_secure_messaging_pipeline)
{
	struct pqcp_edge_topic topic;
	struct pqcp_edge_principal pub;
	struct pqcp_edge_principal sub;
	struct pqcp_edge_subscription *subscription = NULL;
	struct pqcp_edge_message m;
	struct pqcp_edge_message *got = NULL;
	struct pqcp_edge_delivery *delivery = NULL;
	struct pqcp_edge_ratchet tx;
	struct pqcp_edge_ratchet rx;
	uint8_t root[PQCP_EDGE_KEY_BYTES];
	uint8_t tx_key[PQCP_EDGE_KEY_BYTES];
	uint8_t rx_key[PQCP_EDGE_KEY_BYTES];
	uint64_t epoch = 0U;
	uint64_t seq = 0U;
	bool replayed = true;

	rt_setup();
	edge_make_principal(&pub, "pub", 0x2U, PQCP_EDGE_TRUST_ATTESTED,
			    T0 + 1000000U);
	edge_make_principal(&sub, "sub", 0x4U, PQCP_EDGE_TRUST_ATTESTED,
			    T0 + 1000000U);
	memset(&topic, 0, sizeof(topic));
	SETSTR(topic.topic, "telemetry");
	SETSTR(topic.owner_id, "owner");
	topic.publish_capabilities = 0x2U;
	topic.subscribe_capabilities = 0x4U;
	topic.maximum_payload = 64U;
	topic.maximum_subscribers = 2U;
	topic.encrypted = true;
	zassert_equal(pqcp_edge_topic_create(&rt.topics, &topic), 0);
	zassert_equal(pqcp_edge_topic_subscribe(&rt.topics, "telemetry", &sub,
		T0, 100000U, 4U, &subscription), 0);
	/* The subscriber cannot publish, the publisher cannot subscribe. */
	zassert_equal(pqcp_edge_topic_authorize_publish(&rt.topics,
		"telemetry", &sub, 8U), -EACCES);
	zassert_equal(pqcp_edge_topic_subscribe(&rt.topics, "telemetry", &pub,
		T0, 100000U, 4U, &(struct pqcp_edge_subscription *){ NULL }),
		-EACCES);
	zassert_equal(pqcp_edge_topic_authorize_publish(&rt.topics,
		"telemetry", &pub, 8U), 0);

	/* Per-message key from a ratchet shared by both ends. */
	edge_key(root, 0x42U);
	zassert_equal(pqcp_edge_ratchet_init(&tx, "sub", root, true, T0), 0);
	zassert_equal(pqcp_edge_ratchet_init(&rx, "pub", root, false, T0), 0);
	zassert_equal(pqcp_edge_ratchet_next_send(&tx, tx_key, &epoch, &seq),
		      0);

	/* Replay protection then durable queueing. */
	zassert_equal(pqcp_edge_replay_accept(&rt.replay, "pub", epoch, seq,
		T0 + 1U), 0);
	memset(&m, 0, sizeof(m));
	memset(m.message_id, 0x21, sizeof(m.message_id));
	SETSTR(m.producer_id, "pub");
	SETSTR(m.consumer_id, "sub");
	SETSTR(m.topic, "telemetry");
	m.producer_epoch = epoch;
	m.sequence = seq;
	m.created_at_ms = T0 + 1U;
	m.expires_at_ms = T0 + 10000U;
	m.maximum_attempts = 3U;
	m.priority = PQCP_EDGE_MESSAGE_HIGH;
	m.guarantee = PQCP_EDGE_DELIVERY_EFFECTIVELY_ONCE;
	memcpy(m.payload, "reading=42", 10U);
	m.payload_length = 10U;
	m.encrypted = true;
	zassert_equal(pqcp_edge_message_submit(&rt.messages, &m, tx_key,
		T0 + 1U, &replayed), 0);
	zassert_false(replayed);
	/* A replayed frame is stopped by the replay guard... */
	zassert_equal(pqcp_edge_replay_accept(&rt.replay, "pub", epoch, seq,
		T0 + 2U), -EALREADY);
	/* ... and idempotently absorbed by the queue. */
	zassert_equal(pqcp_edge_message_submit(&rt.messages, &m, tx_key,
		T0 + 2U, &replayed), 0);
	zassert_true(replayed);
	zassert_equal(rt.messages.accepted_count, 1U);
	zassert_equal(pqcp_edge_message_queue_audit(&rt.messages, tx_key), 0);

	/* The receiver derives the same key and can authenticate it. */
	zassert_equal(pqcp_edge_ratchet_receive(&rx, epoch, seq, rx_key), 0);
	zassert_mem_equal(tx_key, rx_key, sizeof(tx_key));
	zassert_equal(pqcp_edge_message_queue_audit(&rt.messages, rx_key), 0);

	/* Delivery tracking with retry. */
	zassert_equal(pqcp_edge_message_next(&rt.messages, "sub",
		"telemetry", T0 + 3U, &got), 0);
	zassert_equal(pqcp_edge_delivery_dispatch(&rt.deliveries,
		got->message_id, subscription->subscription_id, T0 + 3U,
		T0 + 9000U, 3U, &delivery), 0);
	zassert_equal(pqcp_edge_delivery_complete(&rt.deliveries,
		delivery->delivery_id, -EIO, T0 + 4U), 0);
	zassert_equal(pqcp_edge_message_retry(&rt.messages, got->message_id,
		T0 + 150U, -EIO), 0);
	zassert_equal(pqcp_edge_delivery_tick(&rt.deliveries, T0 + 104U,
		&(uint32_t){ 0U }), 0);
	zassert_equal(delivery->state, PQCP_EDGE_MESSAGE_IN_FLIGHT);
	zassert_equal(pqcp_edge_message_tick(&rt.messages, T0 + 150U,
		&(uint32_t){ 0U }), 0);
	zassert_equal(pqcp_edge_message_next(&rt.messages, "sub",
		"telemetry", T0 + 150U, &got), 0);
	zassert_equal(pqcp_edge_delivery_complete(&rt.deliveries,
		delivery->delivery_id, 0, T0 + 151U), 0);
	zassert_equal(pqcp_edge_message_acknowledge(&rt.messages,
		got->message_id, T0 + 152U), 0);
	zassert_equal(pqcp_edge_topic_acknowledge(&rt.topics,
		subscription->subscription_id, seq), 0);
	zassert_equal(rt.messages.acknowledged_count, 1U);
	zassert_equal(rt.deliveries.success_count, 1U);
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
}

ZTEST(edge_security, test_flow_policy_rollout_rotation_and_config_commit)
{
	struct pqcp_edge_policy_bundle *b = NULL;
	struct pqcp_edge_secret_rotation *rot = NULL;
	struct pqcp_edge_config_transaction *tx = NULL;
	uint8_t content[PQCP_EDGE_DIGEST_BYTES];
	uint8_t cur[PQCP_EDGE_DIGEST_BYTES];
	uint8_t tgt[PQCP_EDGE_DIGEST_BYTES];
	uint8_t validation[PQCP_EDGE_DIGEST_BYTES];
	uint8_t gen_digest[PQCP_EDGE_DIGEST_BYTES];

	rt_setup();
	edge_digest(content, 0x81U);
	edge_digest(cur, 0x82U);
	edge_digest(tgt, 0x83U);
	edge_digest(validation, 0x84U);

	/* Staged policy rollout to the next epoch. */
	zassert_equal(pqcp_edge_policy_stage(&rt.policy, content,
		RT_EPOCH + 1U, T0, T0, T0 + 100000U, 1U, 1U, &b), 0);
	zassert_equal(pqcp_edge_policy_acknowledge(&rt.policy, b->bundle_id,
		"edge-1", content, 0, T0 + 1U), 0);
	for (int i = 0; i < 3; ++i) {
		zassert_equal(pqcp_edge_policy_promote(&rt.policy,
			b->bundle_id, T0 + 2U + i), 0);
	}
	zassert_equal(rt.policy.active_policy_epoch, RT_EPOCH + 1U);
	zassert_equal(pqcp_edge_runtime_advance_policy(&rt, RT_EPOCH + 1U),
		      0);

	/* Secret rotation with overlap. */
	zassert_equal(pqcp_edge_rotation_plan(&rt.rotation, "fleet-key", 1U,
		2U, cur, tgt, 1U, 1U, T0 + 10U, T0 + 500U, T0 + 5000U, &rot),
		0);
	zassert_equal(pqcp_edge_rotation_transition(&rt.rotation,
		rot->rotation_id, PQCP_EDGE_ROTATION_GENERATING, T0 + 11U), 0);
	zassert_equal(pqcp_edge_rotation_transition(&rt.rotation,
		rot->rotation_id, PQCP_EDGE_ROTATION_DISTRIBUTING, T0 + 12U),
		0);
	zassert_equal(pqcp_edge_rotation_acknowledge(&rt.rotation,
		rot->rotation_id, true, T0 + 13U), 0);
	zassert_equal(pqcp_edge_rotation_transition(&rt.rotation,
		rot->rotation_id, PQCP_EDGE_ROTATION_OVERLAP, T0 + 14U), 0);
	zassert_equal(pqcp_edge_rotation_tick(&rt.rotation, T0 + 500U,
		&(uint32_t){ 0U }), 0);
	zassert_equal(rot->state, PQCP_EDGE_ROTATION_RETIRING);
	zassert_equal(pqcp_edge_rotation_transition(&rt.rotation,
		rot->rotation_id, PQCP_EDGE_ROTATION_COMPLETED, T0 + 501U), 0);

	/* Configuration generation tracks the policy epoch it started at. */
	zassert_equal(pqcp_edge_internal_sha256(
		(const uint8_t *)"pqcp-edge-security-policy", 25U,
		gen_digest), 0);
	zassert_equal(rt.configuration.active_generation, RT_EPOCH);
	zassert_equal(pqcp_edge_config_prepare(&rt.configuration, RT_EPOCH,
		RT_EPOCH + 1U, rt.configuration.active_digest, tgt, T0 + 20U,
		T0 + 1000U, &tx), 0);
	zassert_equal(pqcp_edge_config_validate(&rt.configuration,
		tx->transaction_id, validation, T0 + 21U), 0);
	zassert_equal(pqcp_edge_config_commit(&rt.configuration,
		tx->transaction_id, T0 + 22U), 0);
	zassert_equal(rt.configuration.active_generation, RT_EPOCH + 1U);

	zassert_equal(pqcp_edge_runtime_tick(&rt, T0 + 600U), 0);
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
}

ZTEST(edge_security, test_flow_telemetry_governance_and_data_loss_prevention)
{
	struct pqcp_edge_anomaly_result ar;
	struct pqcp_edge_resource_budget budget;
	enum pqcp_edge_resource_action action;
	struct pqcp_edge_dlp_rule rule;
	struct pqcp_edge_dlp_decision dd;
	struct pqcp_edge_sla_objective sla;
	enum pqcp_edge_sla_state state;
	struct pqcp_edge_workload_job job;
	struct pqcp_edge_workload_job *accepted = NULL;
	struct pqcp_edge_workload_job *running = NULL;
	struct pqcp_edge_continuity_service cs;
	enum pqcp_edge_continuity_mode mode;
	struct pqcp_edge_trust_anchor anchor;
	enum pqcp_edge_operation read = PQCP_EDGE_OPERATION_READ;

	rt_setup();
	rt_enroll();
	/* Anomaly baseline learns normal traffic, flags the outlier. */
	for (uint32_t i = 0U; i < 9U; ++i) {
		zassert_equal(pqcp_edge_anomaly_observe(&rt.anomaly, "p1",
			PQCP_EDGE_METRIC_REQUEST_RATE, 100U, T0 + i, 30000U,
			&ar), 0);
		zassert_false(ar.anomalous);
	}
	zassert_equal(pqcp_edge_anomaly_observe(&rt.anomaly, "p1",
		PQCP_EDGE_METRIC_REQUEST_RATE, 900U, T0 + 10U, 30000U, &ar),
		0);
	zassert_true(ar.anomalous);

	/* Resource budget reacts to the burst. */
	memset(&budget, 0, sizeof(budget));
	SETSTR(budget.subject_id, "p1");
	for (size_t i = 0U; i < PQCP_EDGE_RESOURCE_COUNT; ++i) {
		budget.limit[i] = 1000U;
		budget.warning[i] = 800U;
	}
	budget.window_ms = 10000U;
	budget.window_started_ms = T0;
	zassert_equal(pqcp_edge_resource_budget_put(&rt.resources, &budget),
		      0);
	zassert_equal(pqcp_edge_resource_reserve(&rt.resources, "p1",
		PQCP_EDGE_RESOURCE_NETWORK_BYTES, 900U, T0 + 11U, &action), 0);
	zassert_equal(action, PQCP_EDGE_RESOURCE_ACTION_THROTTLE);
	zassert_equal(pqcp_edge_resource_reserve(&rt.resources, "p1",
		PQCP_EDGE_RESOURCE_NETWORK_BYTES, 200U, T0 + 12U, &action),
		-EDQUOT);

	/* DLP blocks exfiltration of classified payloads. */
	memset(&rule, 0, sizeof(rule));
	rule.rule_id = 1U;
	SETSTR(rule.classification, "pii");
	rule.minimum_matches = 3U;
	rule.byte_pattern = '#';
	rule.byte_mask = 0xffU;
	rule.maximum_payload = 128U;
	rule.action = PQCP_EDGE_DLP_BLOCK;
	rule.enabled = true;
	zassert_equal(pqcp_edge_dlp_rule_put(&rt.dlp, &rule), 0);
	zassert_equal(pqcp_edge_dlp_scan(&rt.dlp, "pii", "partner",
		(const uint8_t *)"id=###-##", 9U, false, &dd), -EACCES);
	zassert_equal(pqcp_edge_dlp_scan(&rt.dlp, "pii", "partner",
		(const uint8_t *)"id=none", 7U, false, &dd), 0);

	/* SLO monitor and continuity manager see the degradation. */
	memset(&sla, 0, sizeof(sla));
	SETSTR(sla.service_id, "svc");
	sla.window_ms = 10000U;
	sla.maximum_latency_us = 1000U;
	sla.minimum_success_basis_points = 9000U;
	sla.maximum_error_basis_points = 1000U;
	zassert_equal(pqcp_edge_sla_objective_put(&rt.sla, &sla, T0 + 13U), 0);
	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		0U, T0 + 14U), 0);
	for (int i = 0; i < 3; ++i) {
		struct pqcp_edge_admission_request q = base_request(T0 + 15U + i);
		struct pqcp_edge_admission_result res;

		zassert_equal(pqcp_edge_runtime_authorize(&rt, &q, &res), 0);
		zassert_equal(pqcp_edge_runtime_complete_request(&rt, "p1",
			"svc", "ep1", i == 0, 100U, T0 + 20U + i), 0);
	}
	zassert_equal(pqcp_edge_sla_evaluate(&rt.sla, "svc", T0 + 30U,
		&state), 0);
	zassert_equal(state, PQCP_EDGE_SLA_BREACHED);
	memset(&cs, 0, sizeof(cs));
	SETSTR(cs.service_id, "svc");
	cs.minimum_endpoints = 1U;
	zassert_equal(pqcp_edge_continuity_register(&rt.continuity, &cs), 0);
	zassert_equal(pqcp_edge_continuity_observe(&rt.continuity, "svc", 0U,
		0U, T0 + 31U), 0);
	zassert_equal(pqcp_edge_continuity_evaluate(&rt.continuity, T0 + 32U,
		&mode), 0);
	zassert_equal(mode, PQCP_EDGE_CONTINUITY_RECOVERY);

	/* Federation grants stay deny-by-default across domains. */
	memset(&anchor, 0, sizeof(anchor));
	SETSTR(anchor.domain_id, "dom-a");
	anchor.policy_epoch = RT_EPOCH;
	anchor.revocation_epoch = 1U;
	anchor.not_before_ms = T0;
	anchor.expires_at_ms = T0 + 100000U;
	anchor.maximum_risk = 500U;
	edge_digest(anchor.public_key_digest, 0x91U);
	zassert_equal(pqcp_edge_trust_anchor_put(&rt.federation, &anchor), 0);
	SETSTR(anchor.domain_id, "dom-b");
	edge_digest(anchor.public_key_digest, 0x92U);
	zassert_equal(pqcp_edge_trust_anchor_put(&rt.federation, &anchor), 0);
	zassert_equal(pqcp_edge_federation_authorize(&rt.federation, "dom-a",
		"dom-b", read, 0x1U, 10U, RT_EPOCH, 1U, T0 + 40U), -EACCES);

	/* Work scheduling is bound to resources. */
	memset(&job, 0, sizeof(job));
	SETSTR(job.principal_id, "p1");
	SETSTR(job.service_id, "svc");
	job.earliest_start_ms = T0 + 41U;
	job.deadline_ms = T0 + 9000U;
	job.estimated_cost = 5U;
	job.priority = 1U;
	job.required_resource_mask = 0x1U;
	job.maximum_attempts = 1U;
	zassert_equal(pqcp_edge_workload_submit(&rt.scheduler, &job, T0 + 41U,
		&accepted), 0);
	zassert_equal(pqcp_edge_workload_next(&rt.scheduler, T0 + 42U, 0x1U,
		&running), 0);
	zassert_equal(pqcp_edge_workload_complete(&rt.scheduler,
		running->job_id, 0, T0 + 43U), 0);

	/* Group membership and key rotation, then a clean audit. */
	{
		uint8_t k1[PQCP_EDGE_KEY_BYTES];
		uint8_t k2[PQCP_EDGE_KEY_BYTES];

		edge_key(k1, 1U);
		edge_key(k2, 2U);
		zassert_equal(pqcp_edge_group_create(&rt.groups, "fleet",
			"owner", k1, T0 + 44U), 0);
		zassert_equal(pqcp_edge_group_add_member(&rt.groups, "fleet",
			"p1", 0x1U, T0 + 45U), 0);
		zassert_equal(pqcp_edge_group_authorize(&rt.groups, "fleet",
			"p1", 0x1U), 0);
		zassert_equal(pqcp_edge_group_remove_member(&rt.groups,
			"fleet", "p1", T0 + 46U), 0);
		zassert_equal(pqcp_edge_group_rotate(&rt.groups, "fleet", k2,
			T0 + 47U), 0);
		zassert_equal(pqcp_edge_group_authorize(&rt.groups, "fleet",
			"p1", 0x1U), -EACCES);
	}
	zassert_equal(pqcp_edge_runtime_tick(&rt, T0 + 50U), 0);
}

ZTEST(edge_security, test_flow_fragmented_session_traffic_is_reassembled_and_routed)
{
	struct pqcp_edge_principal p;
	struct pqcp_edge_route *route = NULL;
	struct pqcp_edge_session *session = NULL;
	static struct pqcp_edge_fragment frags[3];
	static uint8_t payload[600];
	static uint8_t out[600];
	uint8_t id[PQCP_EDGE_MESSAGE_ID_BYTES];
	uint8_t binding[PQCP_EDGE_DIGEST_BYTES];
	bool complete = false;
	size_t length = 0U;

	rt_setup();
	rt_enroll();
	zassert_equal(pqcp_edge_endpoint_observe(&rt.services, "ep1", true,
		100U, T0 + 1U), 0);
	p = *principal("p1");
	zassert_equal(pqcp_edge_route_select(&rt.routes, &rt.services, &p,
		"svc", PQCP_EDGE_ROUTE_LOWEST_LATENCY, T0 + 2U, 10000U,
		&route), 0);
	zassert_str_equal(route->endpoint_id, "ep1");
	edge_digest(binding, 0x9aU);
	zassert_equal(pqcp_edge_session_open(&rt.sessions, &rt.principals,
		route, binding, true, T0 + 3U, 5000U, &session), 0);
	zassert_equal(principal("p1")->active_sessions, 1U);

	memset(id, 0x66, sizeof(id));
	for (size_t i = 0U; i < sizeof(payload); ++i) {
		payload[i] = (uint8_t)(i ^ 0x5aU);
	}
	for (uint16_t i = 0U; i < 3U; ++i) {
		zassert_equal(pqcp_edge_message_fragment(id, payload,
			sizeof(payload), i, &frags[i]), 0);
	}
	/* Out-of-order arrival, duplicate and all. */
	for (int idx = 2; idx >= 0; --idx) {
		int ret = pqcp_edge_fragment_accept(&rt.fragments,
			&frags[idx], out, sizeof(out), T0 + 4U, 1000U,
			&complete, &length);

		zassert_equal(ret, 0);
		if (idx == 1) {
			zassert_equal(pqcp_edge_fragment_accept(&rt.fragments,
				&frags[1], out, sizeof(out), T0 + 4U, 1000U,
				&complete, &length), -EALREADY);
		}
	}
	zassert_true(complete);
	zassert_equal(length, sizeof(payload));
	zassert_mem_equal(out, payload, sizeof(payload));
	zassert_equal(pqcp_edge_session_account(&rt.sessions,
		session->session_id, 0U, length, true, T0 + 5U), 0);
	zassert_equal(session->bytes_received, sizeof(payload));

	zassert_equal(pqcp_edge_session_close(&rt.sessions, &rt.principals,
		session->session_id, 0, T0 + 6U), 0);
	zassert_equal(principal("p1")->active_sessions, 0U);
	zassert_equal(pqcp_edge_route_expire(&rt.routes, T0 + 20000U,
		&(uint32_t){ 0U }), 0);
	zassert_equal(pqcp_edge_runtime_audit(&rt), 0);
}
