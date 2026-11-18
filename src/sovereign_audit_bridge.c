/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 * Typed source snapshots projected into one tenant-scoped audit vocabulary.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/crypto_broker.h>
#include <pqcp_zephyr/edge_security.h>
#include <pqcp_zephyr/fleet_journal.h>
#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"
#include "sovereign_audit_internal.h"
#include "sovereign_ceremony_internal.h"

#define AUDIT(name) PQCP_SOVEREIGN_AUDIT_##name
#define VALID_TEXT(object, member) pqcp_sovereign_audit_internal_text_valid( \
	(object)->member, sizeof((object)->member), false)

struct bridge_attribute {
	const char *key;
	uint64_t value;
};

static struct pqcp_sovereign_event_draft bridge_draft(
	const char *tenant, const char *realm, const char *source, const char *object,
	enum pqcp_sovereign_audit_event_class event_class, uint64_t observed, uint64_t ingested)
{
	return (struct pqcp_sovereign_event_draft){
		.tenant_id = tenant, .realm = realm, .source = source, .object = object,
		.event_class = event_class, .activity = AUDIT(ACTIVITY_UPDATE),
		.severity = AUDIT(SEVERITY_INFORMATIONAL), .outcome = AUDIT(OUTCOME_PENDING),
		.data_class = AUDIT(DATA_CONFIDENTIAL),
		.observed_at_ms = observed, .ingested_at_ms = ingested,
		.flags = AUDIT(EVENT_SECURITY_RELEVANT) | AUDIT(EVENT_REGULATORY),
	};
}

static bool object_valid(uint32_t schema, uint64_t id, bool occupied)
{
	return schema == PQCP_SOVEREIGN_SCHEMA_VERSION && id != 0U && occupied;
}

static bool lifecycle_valid(enum pqcp_sovereign_lifecycle_state state)
{
	return state >= PQCP_SOVEREIGN_LIFECYCLE_DRAFT && state <= PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
}

static bool nonzero_digest(const uint8_t *digest)
{
	return !pqcp_sovereign_audit_internal_all_zero(digest, AUDIT(DIGEST_BYTES));
}

static void result_outcome(struct pqcp_sovereign_event_draft *d, int result)
{
	d->result = result;
	d->outcome = result == 0 ? AUDIT(OUTCOME_SUCCESS) : AUDIT(OUTCOME_FAILURE);
	d->severity = result == 0 ? AUDIT(SEVERITY_INFORMATIONAL) : AUDIT(SEVERITY_HIGH);
}

static int bridge_finish(struct pqcp_sovereign_event *output,
	const struct pqcp_sovereign_event_draft *draft,
	const struct bridge_attribute *attributes, size_t count)
{
	struct pqcp_sovereign_event candidate;
	uint8_t normalized_digest[AUDIT(DIGEST_BYTES)];
	uint8_t id_digest[AUDIT(DIGEST_BYTES)];
	static const uint8_t domain[] = "PQCP-SOVEREIGN-BRIDGE-SNAPSHOT-V1";
	const uint8_t *parts[] = {domain, normalized_digest};
	const size_t lengths[] = {sizeof(domain) - 1U, sizeof(normalized_digest)};
	int ret;

	if (output == NULL) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_event_init(&candidate, draft);
	for (size_t i = 0U; ret == 0 && i < count; ++i) {
		ret = pqcp_sovereign_event_add_u64(&candidate, attributes[i].key, attributes[i].value, 0U);
	}
	if (ret == 0) {
		/* Normalize volatile ingestion time and use a synthetic sequence only
		 * to commit the full typed content. Restore the uncommitted draft
		 * before returning, so the real ledger assigns sequence and linkage.
		 */
		candidate.sequence = 1U;
		candidate.ingested_at_ms = candidate.observed_at_ms;
		ret = pqcp_sovereign_event_digest(&candidate, normalized_digest);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_audit_internal_sha256_parts(parts, lengths, ARRAY_SIZE(parts), id_digest);
	}
	if (ret == 0) {
		memcpy(candidate.event_id, id_digest, sizeof(candidate.event_id));
		candidate.sequence = 0U;
		candidate.ingested_at_ms = draft->ingested_at_ms;
		*output = candidate;
	}
	pqcp_runtime_secure_zero(&candidate, sizeof(candidate));
	pqcp_runtime_secure_zero(normalized_digest, sizeof(normalized_digest));
	pqcp_runtime_secure_zero(id_digest, sizeof(id_digest));
	return ret;
}

int pqcp_sovereign_audit_bridge_broker_receipt(
	const char *tenant, const char *realm, const char *source,
	const struct pqcp_crypto_broker_receipt *r, uint64_t ingested,
	struct pqcp_sovereign_event *event)
{
	if (r == NULL || r->schema_version != PQCP_CRYPTO_BROKER_SCHEMA_VERSION || r->sequence == 0U ||
	    r->accepted_at_ms == 0U || r->completed_at_ms < r->accepted_at_ms ||
	    r->operation <= PQCP_CRYPTO_BROKER_OPERATION_NONE || r->operation >= PQCP_CRYPTO_BROKER_OPERATION_COUNT ||
	    r->decision <= PQCP_CRYPTO_BROKER_DECISION_UNSET || r->decision > PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY ||
	    r->signature_length > sizeof(r->signature) ||
	    r->signed_receipt != (r->signature_length != 0U) || !nonzero_digest(r->receipt_digest) ||
	    (r->decision != PQCP_CRYPTO_BROKER_DECISION_ALLOW && r->result == 0)) {
		return -EINVAL;
	}
	struct pqcp_sovereign_event_draft d = bridge_draft(tenant, realm, source,
		"broker-receipt", AUDIT(CLASS_CRYPTO_OPERATION), r->completed_at_ms, ingested);
	const struct bridge_attribute attributes[] = {
		{"source_sequence", r->sequence}, {"operation", r->operation},
		{"decision", r->decision}, {"cost_units", r->cost_units},
		{"accepted_at_ms", r->accepted_at_ms}, {"signed_receipt", r->signed_receipt},
	};

	d.action = pqcp_crypto_broker_operation_str(r->operation);
	d.reason = pqcp_crypto_broker_decision_str(r->decision);
	d.activity = AUDIT(ACTIVITY_EXECUTE);
	d.correlation_id = r->sequence;
	d.actor_digest = r->principal_digest;
	d.subject_digest = r->request_digest;
	d.resource_digest = r->key_binding_digest;
	d.evidence_digest = r->output_digest;
	d.receipt_digest = r->receipt_digest;
	result_outcome(&d, r->result);
	if (r->decision != PQCP_CRYPTO_BROKER_DECISION_ALLOW) {
		d.outcome = AUDIT(OUTCOME_DENIED);
	}
	return bridge_finish(event, &d, attributes, ARRAY_SIZE(attributes));
}

int pqcp_sovereign_audit_bridge_fleet_journal(
	const char *tenant, const char *realm, const struct pqcp_fleet_journal_entry *e,
	uint64_t ingested, struct pqcp_sovereign_event *event)
{
	static const enum pqcp_sovereign_audit_severity severity[] = {
		AUDIT(SEVERITY_INFORMATIONAL), AUDIT(SEVERITY_INFORMATIONAL), AUDIT(SEVERITY_LOW),
		AUDIT(SEVERITY_MEDIUM), AUDIT(SEVERITY_HIGH), AUDIT(SEVERITY_CRITICAL),
	};
	int ret = pqcp_fleet_journal_entry_verify(e);

	if (ret != 0) {
		return ret;
	}
	struct pqcp_sovereign_event_draft d = bridge_draft(tenant, realm, e->component,
		e->subject, AUDIT(CLASS_FLEET_OPERATION), e->timestamp_ms, ingested);
	const struct bridge_attribute attributes[] = {
		{"source_sequence", e->sequence}, {"kind", e->kind}, {"reason_code", e->reason},
		{"source_flags", e->flags}, {"detail_length", e->detail_length},
	};

	d.action = pqcp_fleet_journal_kind_str(e->kind);
	d.activity = AUDIT(ACTIVITY_EXECUTE);
	d.correlation_id = e->correlation_id;
	d.policy_epoch = e->policy_epoch;
	d.revocation_epoch = e->revocation_epoch;
	d.evidence_digest = e->digest;
	d.receipt_digest = e->digest;
	result_outcome(&d, e->result);
	d.severity = severity[e->severity];
	if (e->kind == PQCP_FLEET_JOURNAL_POLICY_REJECTED ||
	    e->kind == PQCP_FLEET_JOURNAL_COMMAND_REJECTED ||
	    e->kind == PQCP_FLEET_JOURNAL_ATTESTATION_REJECTED) {
		d.activity = AUDIT(ACTIVITY_REJECT);
		d.outcome = AUDIT(OUTCOME_DENIED);
	}
	if (e->flags & PQCP_FLEET_JOURNAL_FLAG_RECOVERY_RELEVANT) {
		d.flags |= AUDIT(EVENT_RECOVERY_RELEVANT);
	}
	return bridge_finish(event, &d, attributes, ARRAY_SIZE(attributes));
}

int pqcp_sovereign_audit_bridge_edge_incident(
	const char *tenant, const char *realm, const struct pqcp_edge_incident *e,
	uint64_t ingested, struct pqcp_sovereign_event *event)
{
	if (e == NULL || !object_valid(e->schema_version, e->incident_id, e->occupied) ||
	    !VALID_TEXT(e, title) || !VALID_TEXT(e, owner_id) || !VALID_TEXT(e, subject_id) ||
	    (unsigned int)e->severity > PQCP_EDGE_INCIDENT_CRITICAL ||
	    e->state <= PQCP_EDGE_INCIDENT_EMPTY || e->state > PQCP_EDGE_INCIDENT_CLOSED ||
	    e->opened_at_ms == 0U || e->updated_at_ms < e->opened_at_ms ||
	    e->signal_count > ARRAY_SIZE(e->signal_ids) || e->risk_score > 1000U ||
	    !nonzero_digest(e->incident_digest) ||
	    (e->resolved_at_ms && (e->resolved_at_ms < e->opened_at_ms || e->resolved_at_ms > e->updated_at_ms))) {
		return -EINVAL;
	}
	struct pqcp_sovereign_event_draft d = bridge_draft(tenant, realm, "edge-incident",
		e->subject_id, AUDIT(CLASS_SECURITY_INCIDENT), e->updated_at_ms, ingested);
	const struct bridge_attribute attributes[] = {
		{"incident_id", e->incident_id}, {"state", e->state}, {"risk_score", e->risk_score},
		{"signal_count", e->signal_count}, {"containment_mask", e->containment_mask},
		{"remediation_mask", e->remediation_mask},
	};

	d.actor = e->owner_id;
	d.reason = e->title;
	d.action = "incident";
	d.correlation_id = e->incident_id;
	d.severity = (enum pqcp_sovereign_audit_severity)(e->severity + 1U);
	d.evidence_digest = e->incident_digest;
	if (e->state == PQCP_EDGE_INCIDENT_RESOLVED || e->state == PQCP_EDGE_INCIDENT_CLOSED) {
		if (e->resolved_at_ms == 0U) {
			return -EINVAL;
		}
		d.activity = AUDIT(ACTIVITY_COMPLETE);
		d.outcome = AUDIT(OUTCOME_SUCCESS);
	}
	return bridge_finish(event, &d, attributes, ARRAY_SIZE(attributes));
}

int pqcp_sovereign_audit_bridge_deployment(
	const char *tenant, const char *realm, const struct pqcp_sovereign_rollout *r,
	uint64_t ingested, struct pqcp_sovereign_event *event)
{
	if (r == NULL || !object_valid(r->schema_version, r->rollout_id, r->occupied) ||
	    !VALID_TEXT(r, artifact_id) || !VALID_TEXT(r, ring_id) || r->policy_epoch == 0U ||
	    r->planned_at_ms == 0U || r->deadline_ms <= r->planned_at_ms ||
	    (r->started_at_ms && r->started_at_ms < r->planned_at_ms) ||
	    r->state <= PQCP_SOVEREIGN_ROLLOUT_EMPTY || r->state > PQCP_SOVEREIGN_ROLLOUT_FAILED ||
	    r->target_count == 0U || r->batch_size == 0U || r->health_basis_points > 10000U ||
	    r->attempted_count > r->target_count ||
	    (uint64_t)r->success_count + r->failure_count + r->unavailable_count > r->attempted_count ||
	    !nonzero_digest(r->plan_digest)) {
		return -EINVAL;
	}
	struct pqcp_sovereign_event_draft d = bridge_draft(tenant, realm, "sovereign-rollout",
		r->artifact_id, AUDIT(CLASS_DEPLOYMENT), r->started_at_ms ? r->started_at_ms : r->planned_at_ms, ingested);
	const struct bridge_attribute attributes[] = {
		{"rollout_id", r->rollout_id}, {"state", r->state}, {"target_count", r->target_count},
		{"attempted_count", r->attempted_count}, {"success_count", r->success_count},
		{"failure_count", r->failure_count}, {"unavailable_count", r->unavailable_count},
		{"health_basis_points", r->health_basis_points},
	};

	d.actor = r->ring_id;
	d.action = "deploy";
	d.activity = AUDIT(ACTIVITY_DEPLOY);
	d.policy_epoch = r->policy_epoch;
	d.correlation_id = r->rollout_id;
	d.evidence_digest = r->plan_digest;
	d.result = r->result;
	if (r->state == PQCP_SOVEREIGN_ROLLOUT_COMPLETED) {
		if (r->result != 0 || r->attempted_count != r->target_count || r->health_basis_points < 5000U) {
			return -EINVAL;
		}
		d.outcome = AUDIT(OUTCOME_SUCCESS);
	} else if (r->state == PQCP_SOVEREIGN_ROLLOUT_FAILED) {
		d.outcome = AUDIT(OUTCOME_FAILURE);
		d.severity = AUDIT(SEVERITY_HIGH);
	} else if (r->state == PQCP_SOVEREIGN_ROLLOUT_ROLLING_BACK) {
		d.activity = AUDIT(ACTIVITY_ROLLBACK);
	}
	return bridge_finish(event, &d, attributes, ARRAY_SIZE(attributes));
}

int pqcp_sovereign_audit_bridge_ceremony(
	const char *tenant, const char *realm, const struct pqcp_sovereign_key_ceremony *c,
	uint64_t ingested, struct pqcp_sovereign_event *event)
{
	if (c == NULL || !object_valid(c->schema_version, c->ceremony_id, c->occupied) ||
	    !VALID_TEXT(c, key_id) || !VALID_TEXT(c, purpose) || c->opened_at_ms == 0U ||
	    c->expires_at_ms <= c->opened_at_ms || c->target_epoch < c->current_epoch || c->target_epoch == 0U ||
	    c->threshold == 0U || c->threshold > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    c->required_distinct_roles == 0U || c->required_distinct_roles > c->threshold ||
	    c->distinct_role_count > c->contribution_count || c->contribution_count > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    c->state <= PQCP_SOVEREIGN_CEREMONY_EMPTY || c->state > PQCP_SOVEREIGN_CEREMONY_ABORTED) {
		return -EINVAL;
	}
	enum pqcp_sovereign_ceremony_action action = pqcp_sovereign_ceremony_action_from_text(c->purpose);
	enum pqcp_sovereign_audit_activity activity;

	switch (action) {
	case PQCP_SOVEREIGN_CEREMONY_ACTION_GENERATE:
		if (c->current_epoch != 0U) {
			return -EINVAL;
		}
		activity = AUDIT(ACTIVITY_CREATE);
		break;
	case PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE:
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RECOVER:
		if (c->current_epoch == 0U || c->target_epoch <= c->current_epoch) {
			return -EINVAL;
		}
		activity = action == PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE ? AUDIT(ACTIVITY_ROTATE) : AUDIT(ACTIVITY_RECOVER);
		break;
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RETIRE:
	case PQCP_SOVEREIGN_CEREMONY_ACTION_DESTROY:
		if (c->current_epoch == 0U) {
			return -EINVAL;
		}
		activity = action == PQCP_SOVEREIGN_CEREMONY_ACTION_RETIRE ? AUDIT(ACTIVITY_REVOKE) : AUDIT(ACTIVITY_DESTROY);
		break;
	default:
		return -EINVAL;
	}
	if (!nonzero_digest(c->transcript_digest) ||
	    (c->state != PQCP_SOVEREIGN_CEREMONY_COMMITTED && nonzero_digest(c->committed_key_digest))) {
		return -EINVAL;
	}
	struct pqcp_sovereign_event_draft d = bridge_draft(tenant, realm, "sovereign-ceremony",
		c->key_id, AUDIT(CLASS_KEY_CEREMONY), c->opened_at_ms, ingested);
	const struct bridge_attribute attributes[] = {
		{"ceremony_id", c->ceremony_id}, {"state", c->state}, {"target_epoch", c->target_epoch},
		{"threshold", c->threshold}, {"contribution_count", c->contribution_count},
		{"distinct_role_count", c->distinct_role_count},
	};

	d.action = "key-ceremony";
	d.reason = c->purpose;
	d.activity = activity;
	d.correlation_id = c->ceremony_id;
	d.resource_digest = c->committed_key_digest;
	d.evidence_digest = c->transcript_digest;
	if (c->state == PQCP_SOVEREIGN_CEREMONY_COMMITTED) {
		if (c->contribution_count < c->threshold || c->distinct_role_count < c->required_distinct_roles ||
		    !nonzero_digest(c->transcript_digest) || !nonzero_digest(c->committed_key_digest)) {
			return -EINVAL;
		}
		d.outcome = AUDIT(OUTCOME_SUCCESS);
	} else if (c->state == PQCP_SOVEREIGN_CEREMONY_ABORTED) {
		d.outcome = AUDIT(OUTCOME_CANCELLED);
	}
	return bridge_finish(event, &d, attributes, ARRAY_SIZE(attributes));
}

int pqcp_sovereign_audit_bridge_privacy_budget(
	const char *realm, const struct pqcp_sovereign_privacy_budget *b, bool authorized,
	uint64_t observed, struct pqcp_sovereign_event *event)
{
	if (b == NULL || !object_valid(b->schema_version, b->generation, b->occupied) ||
	    !VALID_TEXT(b, budget_id) || !VALID_TEXT(b, tenant_id) || !VALID_TEXT(b, subject_scope) ||
	    !VALID_TEXT(b, purpose) || !lifecycle_valid(b->state) || b->window_started_ms == 0U ||
	    observed < b->window_started_ms || b->window_ms == 0U || b->policy_epoch == 0U ||
	    b->epsilon_limit_micros == 0U || b->delta_limit_nanos == 0U || b->query_limit == 0U ||
	    b->epsilon_used_micros > b->epsilon_limit_micros || b->delta_used_nanos > b->delta_limit_nanos ||
	    b->query_count > b->query_limit || (authorized && b->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE)) {
		return -EINVAL;
	}
	struct pqcp_sovereign_event_draft d = bridge_draft(b->tenant_id, realm, "sovereign-privacy",
		b->budget_id, AUDIT(CLASS_PRIVACY), observed, observed);
	const struct bridge_attribute attributes[] = {
		{"generation", b->generation}, {"state", b->state}, {"query_count", b->query_count},
		{"query_limit", b->query_limit}, {"epsilon_used_micros", b->epsilon_used_micros},
		{"epsilon_limit_micros", b->epsilon_limit_micros}, {"delta_used_nanos", b->delta_used_nanos},
		{"delta_limit_nanos", b->delta_limit_nanos}, {"window_started_ms", b->window_started_ms},
		{"window_ms", b->window_ms},
	};

	d.action = "privacy-budget";
	d.reason = b->purpose;
	d.activity = AUDIT(ACTIVITY_AUTHORIZE);
	d.outcome = authorized ? AUDIT(OUTCOME_SUCCESS) : AUDIT(OUTCOME_DENIED);
	d.result = authorized ? 0 : -EACCES;
	d.policy_epoch = b->policy_epoch;
	d.data_class = AUDIT(DATA_PERSONAL);
	d.flags |= AUDIT(EVENT_PRIVACY_RELEVANT);
	return bridge_finish(event, &d, attributes, ARRAY_SIZE(attributes));
}

int pqcp_sovereign_audit_bridge_erasure(
	const char *realm, const struct pqcp_sovereign_retention_record *r,
	uint64_t observed, struct pqcp_sovereign_event *event)
{
	if (r == NULL || !object_valid(r->schema_version, r->record_id, r->occupied) ||
	    !VALID_TEXT(r, tenant_id) || !VALID_TEXT(r, object_id) || !VALID_TEXT(r, purpose) ||
	    (unsigned int)r->data_class >= PQCP_SOVEREIGN_DATA_CLASS_COUNT ||
	    r->created_at_ms == 0U || observed < r->created_at_ms ||
	    (r->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE && r->state != PQCP_SOVEREIGN_LIFECYCLE_RETIRED) ||
	    (r->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE && r->deleted_at_ms != 0U) ||
	    (r->state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED && (r->deleted_at_ms < r->created_at_ms ||
		r->deleted_at_ms > observed || r->deleted_at_ms < r->legal_hold_until_ms))) {
		return -EINVAL;
	}
	struct pqcp_sovereign_event_draft d = bridge_draft(r->tenant_id, realm, "sovereign-retention",
		r->object_id, AUDIT(CLASS_PRIVACY), observed, observed);
	const struct bridge_attribute attributes[] = {
		{"record_id", r->record_id}, {"state", r->state}, {"created_at_ms", r->created_at_ms},
		{"deleted_at_ms", r->deleted_at_ms}, {"delete_after_ms", r->delete_after_ms},
		{"legal_hold_until_ms", r->legal_hold_until_ms},
	};

	d.action = "erasure";
	d.reason = r->purpose;
	d.activity = AUDIT(ACTIVITY_ERASE);
	d.outcome = r->state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ? AUDIT(OUTCOME_SUCCESS) : AUDIT(OUTCOME_PENDING);
	d.correlation_id = r->record_id;
	d.resource_digest = r->object_digest;
	d.data_class = (enum pqcp_sovereign_audit_data_class)r->data_class;
	d.flags |= AUDIT(EVENT_PRIVACY_RELEVANT);
	return bridge_finish(event, &d, attributes, ARRAY_SIZE(attributes));
}

int pqcp_sovereign_audit_bridge_recovery(
	const char *tenant, const char *realm, const struct pqcp_sovereign_recovery_request *r,
	uint64_t observed, struct pqcp_sovereign_event *event)
{
	if (r == NULL || !object_valid(r->schema_version, r->recovery_id, r->occupied) ||
	    !VALID_TEXT(r, subject_id) || !VALID_TEXT(r, action) || r->opened_at_ms == 0U ||
	    observed < r->opened_at_ms || r->expires_at_ms <= r->opened_at_ms || r->policy_epoch == 0U ||
	    r->threshold == 0U || r->threshold > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    r->required_distinct_roles == 0U || r->required_distinct_roles > r->threshold ||
	    r->approval_count > PQCP_SOVEREIGN_MAX_APPROVERS || r->rejection_count > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    r->distinct_role_count > r->approval_count || !nonzero_digest(r->authorization_digest) ||
	    r->state <= PQCP_SOVEREIGN_APPROVAL_EMPTY || r->state > PQCP_SOVEREIGN_APPROVAL_CANCELLED) {
		return -EINVAL;
	}
	struct pqcp_sovereign_event_draft d = bridge_draft(tenant, realm, "sovereign-recovery",
		r->subject_id, AUDIT(CLASS_RECOVERY), observed, observed);
	const struct bridge_attribute attributes[] = {
		{"recovery_id", r->recovery_id}, {"state", r->state}, {"threshold", r->threshold},
		{"approval_count", r->approval_count}, {"rejection_count", r->rejection_count},
		{"distinct_role_count", r->distinct_role_count}, {"required_distinct_roles", r->required_distinct_roles},
	};

	d.action = r->action;
	d.activity = AUDIT(ACTIVITY_AUTHORIZE);
	d.policy_epoch = r->policy_epoch;
	d.correlation_id = r->recovery_id;
	d.evidence_digest = r->authorization_digest;
	d.flags |= AUDIT(EVENT_RECOVERY_RELEVANT);
	switch (r->state) {
	case PQCP_SOVEREIGN_APPROVAL_SATISFIED:
		if (r->approval_count < r->threshold || r->distinct_role_count < r->required_distinct_roles) {
			return -EINVAL;
		}
		/* Authorization has no completion timestamp; a stale satisfied
		 * snapshot must not imply a currently usable recovery grant.
		 */
		d.outcome = observed >= r->expires_at_ms ? AUDIT(OUTCOME_EXPIRED) : AUDIT(OUTCOME_SUCCESS);
		break;
	case PQCP_SOVEREIGN_APPROVAL_OPEN:
		d.outcome = observed >= r->expires_at_ms ? AUDIT(OUTCOME_EXPIRED) : AUDIT(OUTCOME_PENDING);
		break;
	case PQCP_SOVEREIGN_APPROVAL_REJECTED:
		d.outcome = AUDIT(OUTCOME_DENIED);
		break;
	case PQCP_SOVEREIGN_APPROVAL_EXPIRED:
		d.outcome = AUDIT(OUTCOME_EXPIRED);
		break;
	case PQCP_SOVEREIGN_APPROVAL_CANCELLED:
		d.outcome = AUDIT(OUTCOME_CANCELLED);
		break;
	default:
		return -EINVAL;
	}
	return bridge_finish(event, &d, attributes, ARRAY_SIZE(attributes));
}

int pqcp_sovereign_audit_bridge_continuity(
	const char *tenant, const char *realm, const struct pqcp_sovereign_continuity_exercise *e,
	uint64_t observed, struct pqcp_sovereign_event *event)
{
	if (e == NULL || !object_valid(e->schema_version, e->exercise_id, e->occupied) ||
	    !VALID_TEXT(e, service_id) || !VALID_TEXT(e, scenario) || e->policy_epoch == 0U ||
	    e->planned_at_ms == 0U || observed < e->planned_at_ms ||
	    e->required_steps == 0U || e->required_steps > 32U || e->maximum_failures == 0U ||
	    e->maximum_failures > e->required_steps ||
	    e->recovery_time_objective_ms == 0U || e->recovery_point_objective_ms == 0U ||
	    (e->started_at_ms && (e->started_at_ms < e->planned_at_ms || e->started_at_ms > observed)) ||
	    (e->completed_at_ms && (e->started_at_ms == 0U || e->completed_at_ms < e->started_at_ms || e->completed_at_ms > observed))) {
		return -EINVAL;
	}
	uint32_t mask = e->required_steps == 32U ? UINT32_MAX : (1U << e->required_steps) - 1U;
	uint32_t failed = 0U;

	for (uint32_t bits = e->failed_steps; bits != 0U; bits >>= 1U) {
		failed += bits & 1U;
	}
	if (((e->completed_steps | e->failed_steps) & ~mask) || (e->completed_steps & e->failed_steps)) {
		return -EINVAL;
	}
	struct pqcp_sovereign_event_draft d = bridge_draft(tenant, realm, "sovereign-continuity",
		e->service_id, AUDIT(CLASS_CONTINUITY), observed, observed);
	const struct bridge_attribute attributes[] = {
		{"exercise_id", e->exercise_id}, {"state", e->state}, {"required_steps", e->required_steps},
		{"completed_steps", e->completed_steps}, {"failed_steps", e->failed_steps},
		{"maximum_failures", e->maximum_failures}, {"recovery_time_objective_ms", e->recovery_time_objective_ms},
		{"recovery_point_objective_ms", e->recovery_point_objective_ms},
		{"observed_recovery_time_ms", e->observed_recovery_time_ms}, {"observed_data_loss_ms", e->observed_data_loss_ms},
	};

	d.action = "continuity-exercise";
	d.reason = e->scenario;
	d.activity = AUDIT(ACTIVITY_RECOVER);
	d.policy_epoch = e->policy_epoch;
	d.correlation_id = e->exercise_id;
	d.evidence_digest = e->evidence_digest;
	d.flags |= AUDIT(EVENT_RECOVERY_RELEVANT);
	switch (e->state) {
	case PQCP_SOVEREIGN_LIFECYCLE_DRAFT:
		if (e->started_at_ms || e->completed_at_ms || e->completed_steps || e->failed_steps) {
			return -EINVAL;
		}
		break;
	case PQCP_SOVEREIGN_LIFECYCLE_ACTIVE:
		if (!e->started_at_ms || e->completed_at_ms) {
			return -EINVAL;
		}
		break;
	case PQCP_SOVEREIGN_LIFECYCLE_RETIRED:
		if (!e->completed_at_ms || !nonzero_digest(e->evidence_digest) ||
		    (e->completed_steps | e->failed_steps) != mask || failed >= e->maximum_failures ||
		    e->observed_recovery_time_ms > e->recovery_time_objective_ms ||
		    e->observed_data_loss_ms > e->recovery_point_objective_ms) {
			return -EINVAL;
		}
		d.outcome = AUDIT(OUTCOME_SUCCESS);
		d.activity = AUDIT(ACTIVITY_COMPLETE);
		break;
	case PQCP_SOVEREIGN_LIFECYCLE_REVOKED:
		if (!e->completed_at_ms || !nonzero_digest(e->evidence_digest)) {
			return -EINVAL;
		}
		d.outcome = AUDIT(OUTCOME_FAILURE);
		d.severity = AUDIT(SEVERITY_HIGH);
		break;
	default:
		return -EINVAL;
	}
	return bridge_finish(event, &d, attributes, ARRAY_SIZE(attributes));
}
