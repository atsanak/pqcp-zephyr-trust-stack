/*
 * SPDX-License-Identifier: MIT
 *
 * Session-aware PQC profile planning and pinning.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_SESSION_DOMAIN UINT64_C(0x4144505345535349)

static bool session_kind_valid(enum pqcp_adaptive_session_kind kind)
{
	return kind >= PQCP_ADAPTIVE_SESSION_KEM &&
	       kind <= PQCP_ADAPTIVE_SESSION_TELEMETRY;
}

static bool request_valid(
	const struct pqcp_adaptive_session_request *request)
{
	return request != NULL &&
	       request->schema_version ==
		       PQCP_ADAPTIVE_SCHEMA_VERSION &&
	       request->session_id != 0U &&
	       session_kind_valid(request->kind) &&
	       request->minimum_security_level > 0U &&
	       request->minimum_security_level <= 5U &&
	       (request->required_evidence_mask &
		~PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK) == 0U &&
	       (request->deadline_ms == 0U ||
		request->deadline_ms >= request->requested_at_ms);
}

static int table_digest(struct pqcp_adaptive_session_table *table)
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_SESSION_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, table->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, table->active_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, table->rejected_count);
	for (uint32_t index = 0U;
	     index < PQCP_ADAPTIVE_MAX_SESSIONS; ++index) {
		const struct pqcp_adaptive_session_entry *entry =
			&table->sessions[index];

		pqcp_deployment_evidence_digest_update_bool(
			&digest, entry->active);
		if (!entry->active) {
			continue;
		}
		pqcp_deployment_evidence_digest_update_u64(
			&digest, entry->session_id);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, (uint32_t)entry->kind);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, entry->opened_at_ms);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, entry->expires_at_ms);
		pqcp_deployment_evidence_digest_update_text(
			&digest, entry->profile_id);
	}
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, table->table_digest_hex);
}

static int plan_digest(
	const struct pqcp_adaptive_session_plan *plan,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_SESSION_DOMAIN ^ UINT64_C(0x50));
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)plan->status);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, plan->session_id);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->blocker_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->warning_mask);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, plan->projected_latency_us);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, plan->projected_energy_uj);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, plan->expires_at_ms);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, plan->transition_required);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, plan->profile_pinned);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, plan->hybrid);
	pqcp_deployment_evidence_digest_update_text(
		&digest, plan->selected_profile_id);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

static const struct pqcp_adaptive_candidate_score *find_score(
	const struct pqcp_adaptive_recommendation *recommendation,
	const char *profile_id)
{
	for (uint32_t index = 0U;
	     index < recommendation->evaluated_count; ++index) {
		if (strcmp(
			    recommendation->candidates[index].profile_id,
			    profile_id) == 0) {
			return &recommendation->candidates[index];
		}
	}
	return NULL;
}

static const struct pqcp_adaptive_profile *select_profile(
	const struct pqcp_adaptive_session_request *request,
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_recommendation *recommendation,
	const struct pqcp_adaptive_transition_controller *transition,
	bool *transition_required)
{
	const struct pqcp_adaptive_profile *active;
	const struct pqcp_adaptive_profile *recommended;
	uint32_t operation =
		pqcp_adaptive_internal_operation_for_session(
			request->kind);

	active = pqcp_adaptive_profile_registry_find(
		registry, transition->current_profile_id);
	recommended = pqcp_adaptive_profile_registry_find(
		registry, recommendation->recommended_profile_id);
	if (active != NULL && active->enabled &&
	    active->security_level >= request->minimum_security_level &&
	    (active->operation_mask & operation) == operation &&
	    (active->evidence_mask &
	     request->required_evidence_mask) ==
		    request->required_evidence_mask) {
		*transition_required = false;
		return active;
	}
	if (recommended != NULL && recommended->enabled &&
	    recommended->security_level >=
		    request->minimum_security_level &&
	    (recommended->operation_mask & operation) == operation &&
	    (recommended->evidence_mask &
	     request->required_evidence_mask) ==
		    request->required_evidence_mask) {
		*transition_required =
			strcmp(recommended->profile_id,
			       transition->current_profile_id) != 0;
		return recommended;
	}
	for (uint32_t index = 0U; index < registry->count; ++index) {
		const struct pqcp_adaptive_profile *profile =
			&registry->profiles[index];

		if (!profile->enabled ||
		    profile->security_level <
			    request->minimum_security_level ||
		    (profile->operation_mask & operation) != operation ||
		    (profile->evidence_mask &
		     request->required_evidence_mask) !=
			    request->required_evidence_mask) {
			continue;
		}
		*transition_required =
			strcmp(profile->profile_id,
			       transition->current_profile_id) != 0;
		return profile;
	}
	return NULL;
}

static void apply_request_semantics(
	const struct pqcp_adaptive_session_request *request,
	const struct pqcp_adaptive_profile *profile,
	struct pqcp_adaptive_session_plan *plan)
{
	if (request->require_authentication &&
	    profile->mldsa_level == 0U) {
		plan->blocker_mask |= PQCP_ADAPTIVE_BLOCK_OPERATION;
	}
	if (request->require_forward_secrecy &&
	    profile->mlkem_level == 0U) {
		plan->blocker_mask |= PQCP_ADAPTIVE_BLOCK_OPERATION;
	}
	if (request->kind == PQCP_ADAPTIVE_SESSION_HYBRID_TLS &&
	    profile->kind !=
		    PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE) {
		plan->blocker_mask |= PQCP_ADAPTIVE_BLOCK_OPERATION;
	}
	if (plan->transition_required &&
	    !request->allow_transition) {
		plan->blocker_mask |= PQCP_ADAPTIVE_BLOCK_POLICY;
	}
	if (request->deadline_ms != 0U &&
	    request->requested_at_ms +
		    plan->projected_latency_us / 1000U >
		    request->deadline_ms) {
		plan->blocker_mask |= PQCP_ADAPTIVE_BLOCK_LATENCY;
	}
	if (request->long_lived) {
		plan->profile_pinned = true;
		plan->warning_mask |=
			PQCP_ADAPTIVE_WARNING_PENDING_SESSIONS;
	}
}

int pqcp_adaptive_session_table_init(
	struct pqcp_adaptive_session_table *table)
{
	if (table == NULL) {
		return -EINVAL;
	}
	memset(table, 0, sizeof(*table));
	table->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	return table_digest(table);
}

int pqcp_adaptive_session_plan(
	const struct pqcp_adaptive_session_request *request,
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_recommendation *recommendation,
	const struct pqcp_adaptive_transition_controller *transition,
	struct pqcp_adaptive_session_plan *plan)
{
	const struct pqcp_adaptive_profile *profile;
	const struct pqcp_adaptive_candidate_score *score;
	bool transition_required = false;

	if (!request_valid(request) ||
	    pqcp_adaptive_profile_registry_validate(registry) != 0 ||
	    recommendation == NULL || transition == NULL ||
	    plan == NULL ||
	    recommendation->schema_version !=
		    PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    transition->schema_version !=
		    PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	memset(plan, 0, sizeof(*plan));
	plan->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	plan->session_id = request->session_id;
	plan->expires_at_ms = request->deadline_ms;
	profile = select_profile(
		request, registry, recommendation,
		transition, &transition_required);
	if (profile == NULL) {
		plan->status = PQCP_ADAPTIVE_STATUS_FAIL;
		plan->blocker_mask =
			PQCP_ADAPTIVE_BLOCK_OPERATION |
			PQCP_ADAPTIVE_BLOCK_SECURITY |
			PQCP_ADAPTIVE_BLOCK_EVIDENCE;
		pqcp_adaptive_internal_set_text(
			plan->selected_profile_id,
			sizeof(plan->selected_profile_id), "none");
		return plan_digest(plan, plan->plan_digest_hex);
	}
	plan->transition_required = transition_required;
	plan->hybrid =
		profile->kind ==
		PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE;
	pqcp_adaptive_internal_set_text(
		plan->selected_profile_id,
		sizeof(plan->selected_profile_id),
		profile->profile_id);
	score = find_score(recommendation, profile->profile_id);
	plan->projected_latency_us = score != NULL ?
		score->projected_latency_us :
		profile->nominal_latency_us;
	plan->projected_energy_uj = score != NULL ?
		score->projected_energy_uj :
		profile->energy_uj;
	apply_request_semantics(request, profile, plan);
	if (plan->blocker_mask != 0U) {
		plan->status = PQCP_ADAPTIVE_STATUS_FAIL;
	} else if (plan->warning_mask != 0U ||
		   plan->transition_required) {
		plan->status = PQCP_ADAPTIVE_STATUS_WARN;
	} else {
		plan->status = PQCP_ADAPTIVE_STATUS_PASS;
	}
	return plan_digest(plan, plan->plan_digest_hex);
}

static int find_session(
	const struct pqcp_adaptive_session_table *table,
	uint64_t session_id)
{
	for (uint32_t index = 0U;
	     index < PQCP_ADAPTIVE_MAX_SESSIONS; ++index) {
		if (table->sessions[index].active &&
		    table->sessions[index].session_id == session_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_session(
	const struct pqcp_adaptive_session_table *table)
{
	for (uint32_t index = 0U;
	     index < PQCP_ADAPTIVE_MAX_SESSIONS; ++index) {
		if (!table->sessions[index].active) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_adaptive_session_open(
	struct pqcp_adaptive_session_table *table,
	const struct pqcp_adaptive_session_plan *plan,
	enum pqcp_adaptive_session_kind kind,
	uint64_t opened_at_ms)
{
	struct pqcp_adaptive_session_entry *entry;
	int index;

	if (table == NULL || plan == NULL ||
	    table->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    plan->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    plan->status == PQCP_ADAPTIVE_STATUS_FAIL ||
	    !session_kind_valid(kind) ||
	    !pqcp_adaptive_internal_id_valid(
		    plan->selected_profile_id)) {
		return -EINVAL;
	}
	if (find_session(table, plan->session_id) >= 0) {
		table->rejected_count++;
		return -EEXIST;
	}
	index = free_session(table);
	if (index < 0) {
		table->rejected_count++;
		return -ENOSPC;
	}
	entry = &table->sessions[index];
	memset(entry, 0, sizeof(*entry));
	entry->active = true;
	entry->session_id = plan->session_id;
	entry->kind = kind;
	entry->opened_at_ms = opened_at_ms;
	entry->expires_at_ms = plan->expires_at_ms;
	pqcp_adaptive_internal_set_text(
		entry->profile_id, sizeof(entry->profile_id),
		plan->selected_profile_id);
	table->active_count++;
	return table_digest(table);
}

int pqcp_adaptive_session_close(
	struct pqcp_adaptive_session_table *table,
	uint64_t session_id)
{
	int index;

	if (table == NULL ||
	    table->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    session_id == 0U) {
		return -EINVAL;
	}
	index = find_session(table, session_id);
	if (index < 0) {
		return -ENOENT;
	}
	memset(&table->sessions[index], 0,
	       sizeof(table->sessions[index]));
	if (table->active_count != 0U) {
		table->active_count--;
	}
	return table_digest(table);
}

int pqcp_adaptive_session_expire(
	struct pqcp_adaptive_session_table *table,
	uint64_t now_ms)
{
	uint32_t expired = 0U;

	if (table == NULL ||
	    table->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	for (uint32_t index = 0U;
	     index < PQCP_ADAPTIVE_MAX_SESSIONS; ++index) {
		struct pqcp_adaptive_session_entry *entry =
			&table->sessions[index];

		if (!entry->active || entry->expires_at_ms == 0U ||
		    entry->expires_at_ms > now_ms) {
			continue;
		}
		memset(entry, 0, sizeof(*entry));
		expired++;
	}
	table->active_count =
		expired >= table->active_count ?
		0U : table->active_count - expired;
	if (table_digest(table) != 0) {
		return -EBADMSG;
	}
	return (int)expired;
}

bool pqcp_adaptive_session_profile_busy(
	const struct pqcp_adaptive_session_table *table,
	const char *profile_id)
{
	if (table == NULL ||
	    !pqcp_adaptive_internal_id_valid(profile_id)) {
		return false;
	}
	for (uint32_t index = 0U;
	     index < PQCP_ADAPTIVE_MAX_SESSIONS; ++index) {
		if (table->sessions[index].active &&
		    strcmp(table->sessions[index].profile_id,
			   profile_id) == 0) {
			return true;
		}
	}
	return false;
}

int pqcp_adaptive_session_emit(
	const struct pqcp_adaptive_session_plan *plan)
{
	if (plan == NULL ||
	    plan->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_SESSION schema=%u status=%s id=%llu profile=%s blockers=0x%08x warnings=0x%08x latency_us=%llu energy_uj=%llu expires_ms=%llu transition=%u pinned=%u hybrid=%u digest=%s\n",
	       plan->schema_version,
	       pqcp_adaptive_status_str(plan->status),
	       (unsigned long long)plan->session_id,
	       plan->selected_profile_id,
	       plan->blocker_mask,
	       plan->warning_mask,
	       (unsigned long long)plan->projected_latency_us,
	       (unsigned long long)plan->projected_energy_uj,
	       (unsigned long long)plan->expires_at_ms,
	       plan->transition_required ? 1U : 0U,
	       plan->profile_pinned ? 1U : 0U,
	       plan->hybrid ? 1U : 0U,
	       plan->plan_digest_hex);
	return 0;
}
