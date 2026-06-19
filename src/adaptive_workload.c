/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Multi-session workload admission and scheduling for adaptive PQC.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_WORKLOAD_DOMAIN UINT64_C(0x414450574f524b4c)

static bool workload_state_valid(enum pqcp_adaptive_workload_state state)
{
	return state >= PQCP_ADAPTIVE_WORKLOAD_QUEUED &&
	       state <= PQCP_ADAPTIVE_WORKLOAD_EXPIRED;
}

static bool workload_kind_valid(enum pqcp_adaptive_session_kind kind)
{
	return pqcp_adaptive_internal_operation_for_session(kind) != 0U;
}

static bool workload_item_valid(
	const struct pqcp_adaptive_workload_item *item)
{
	return item != NULL &&
	       item->request_id != 0U &&
	       workload_kind_valid(item->kind) &&
	       workload_state_valid(item->state) &&
	       item->submitted_at_ms != 0U &&
	       (item->deadline_ms == 0U ||
		item->deadline_ms >= item->submitted_at_ms) &&
	       item->estimated_latency_us != 0U &&
	       item->priority <= PQCP_ADAPTIVE_SCORE_MAX &&
	       item->minimum_security_level > 0U &&
	       item->minimum_security_level <= 5U &&
	       (item->required_evidence_mask &
		~PQCP_DEPLOYMENT_EVIDENCE_KNOWN_MASK) == 0U;
}

static int queue_digest(struct pqcp_adaptive_workload_queue *queue)
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_WORKLOAD_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, queue->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, queue->count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, queue->admitted_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, queue->rejected_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, queue->completed_count);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, queue->queued_latency_us);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, queue->queued_energy_uj);
	for (uint32_t index = 0U; index < queue->count; ++index) {
		const struct pqcp_adaptive_workload_item *item =
			&queue->items[index];

		pqcp_deployment_evidence_digest_update_u64(
			&digest, item->request_id);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, (uint32_t)item->kind);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, (uint32_t)item->state);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, item->submitted_at_ms);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, item->deadline_ms);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, item->estimated_latency_us);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, item->estimated_energy_uj);
		pqcp_deployment_evidence_digest_update_u64(
			&digest, item->payload_bytes);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, item->priority);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, item->minimum_security_level);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, item->required_evidence_mask);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, item->retry_count);
		pqcp_deployment_evidence_digest_update_bool(
			&digest, item->transition_allowed);
		pqcp_deployment_evidence_digest_update_bool(
			&digest, item->batchable);
		pqcp_deployment_evidence_digest_update_text(
			&digest, item->selected_profile_id);
	}
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, queue->queue_digest_hex);
}

static int plan_digest(
	const struct pqcp_adaptive_workload_plan *plan,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_WORKLOAD_DOMAIN ^ UINT64_C(0x50));
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)plan->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->considered_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->admitted_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->rejected_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->deferred_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->blocker_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->warning_mask);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, plan->planned_latency_us);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, plan->planned_energy_uj);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, plan->earliest_deadline_ms);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->required_operation_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, plan->minimum_security_level);
	pqcp_deployment_evidence_digest_update_text(
		&digest, plan->preferred_profile_id);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

static int find_item(
	const struct pqcp_adaptive_workload_queue *queue,
	uint64_t request_id)
{
	for (uint32_t index = 0U; index < queue->count; ++index) {
		if (queue->items[index].request_id == request_id) {
			return (int)index;
		}
	}
	return -1;
}

static void remove_item(
	struct pqcp_adaptive_workload_queue *queue,
	uint32_t index)
{
	for (uint32_t current = index;
	     current + 1U < queue->count; ++current) {
		queue->items[current] = queue->items[current + 1U];
	}
	if (queue->count != 0U) {
		memset(&queue->items[queue->count - 1U], 0,
		       sizeof(queue->items[0]));
		queue->count--;
	}
}

static void queue_recount(
	struct pqcp_adaptive_workload_queue *queue)
{
	uint32_t admitted = 0U;
	uint64_t latency = 0U;
	uint64_t energy = 0U;

	for (uint32_t index = 0U; index < queue->count; ++index) {
		const struct pqcp_adaptive_workload_item *item =
			&queue->items[index];

		if (item->state == PQCP_ADAPTIVE_WORKLOAD_ADMITTED ||
		    item->state == PQCP_ADAPTIVE_WORKLOAD_RUNNING) {
			admitted++;
		}
		if (item->state == PQCP_ADAPTIVE_WORKLOAD_QUEUED ||
		    item->state == PQCP_ADAPTIVE_WORKLOAD_ADMITTED) {
			latency =
				pqcp_adaptive_internal_saturating_add_u64(
					latency,
					item->estimated_latency_us);
			energy =
				pqcp_adaptive_internal_saturating_add_u64(
					energy,
					item->estimated_energy_uj);
		}
	}
	queue->admitted_count = admitted;
	queue->queued_latency_us = latency;
	queue->queued_energy_uj = energy;
}

static uint64_t scheduling_key(
	const struct pqcp_adaptive_workload_item *item,
	uint64_t now_ms)
{
	uint64_t deadline_component;
	uint64_t priority_component;
	uint64_t age_component;

	if (item->deadline_ms == 0U) {
		deadline_component = UINT64_C(1) << 52U;
	} else if (item->deadline_ms <= now_ms) {
		deadline_component = 0U;
	} else {
		deadline_component =
			item->deadline_ms - now_ms;
	}
	priority_component =
		(uint64_t)(PQCP_ADAPTIVE_SCORE_MAX - item->priority) <<
		40U;
	age_component = item->submitted_at_ms <= now_ms ?
		now_ms - item->submitted_at_ms : 0U;
	if (age_component > UINT32_MAX) {
		age_component = UINT32_MAX;
	}
	return deadline_component + priority_component -
	       (age_component < deadline_component ?
		age_component : 0U);
}

static void sort_queue(
	struct pqcp_adaptive_workload_queue *queue,
	uint64_t now_ms)
{
	for (uint32_t index = 1U; index < queue->count; ++index) {
		const struct pqcp_adaptive_workload_item value =
			queue->items[index];
		const uint64_t value_key =
			scheduling_key(&value, now_ms);
		uint32_t position = index;

		while (position > 0U &&
		       scheduling_key(
			       &queue->items[position - 1U],
			       now_ms) > value_key) {
			queue->items[position] =
				queue->items[position - 1U];
			position--;
		}
		queue->items[position] = value;
	}
}

static const struct pqcp_adaptive_profile *profile_for_item(
	const struct pqcp_adaptive_workload_item *item,
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_recommendation *recommendation)
{
	uint32_t operation =
		pqcp_adaptive_internal_operation_for_session(item->kind);
	const struct pqcp_adaptive_profile *recommended =
		pqcp_adaptive_profile_registry_find(
			registry,
			recommendation->recommended_profile_id);

	if (recommended != NULL && recommended->enabled &&
	    recommended->security_level >=
		    item->minimum_security_level &&
	    (recommended->operation_mask & operation) == operation &&
	    (recommended->evidence_mask &
	     item->required_evidence_mask) ==
		    item->required_evidence_mask) {
		return recommended;
	}
	for (uint32_t index = 0U; index < registry->count; ++index) {
		const struct pqcp_adaptive_profile *profile =
			&registry->profiles[index];

		if (profile->enabled &&
		    profile->security_level >=
			    item->minimum_security_level &&
		    (profile->operation_mask & operation) == operation &&
		    (profile->evidence_mask &
		     item->required_evidence_mask) ==
			    item->required_evidence_mask) {
			return profile;
		}
	}
	return NULL;
}

static bool latency_fits(
	uint64_t accumulated,
	const struct pqcp_adaptive_workload_item *item,
	const struct pqcp_adaptive_resource_limits *limits,
	uint64_t now_ms)
{
	uint64_t total =
		pqcp_adaptive_internal_saturating_add_u64(
			accumulated, item->estimated_latency_us);

	if (limits->latency_budget_us != 0U &&
	    total > limits->latency_budget_us) {
		return false;
	}
	if (item->deadline_ms != 0U) {
		uint64_t completion_ms =
			now_ms + (total + 999U) / 1000U;

		if (completion_ms > item->deadline_ms) {
			return false;
		}
	}
	return true;
}

static bool energy_fits(
	uint64_t accumulated,
	const struct pqcp_adaptive_workload_item *item,
	const struct pqcp_adaptive_resource_limits *limits)
{
	if (limits->energy_budget_uj == 0U) {
		return true;
	}
	return pqcp_adaptive_internal_saturating_add_u64(
			accumulated, item->estimated_energy_uj) <=
	       limits->energy_budget_uj;
}

static void update_plan_requirements(
	struct pqcp_adaptive_workload_plan *plan,
	const struct pqcp_adaptive_workload_item *item)
{
	plan->required_operation_mask |=
		pqcp_adaptive_internal_operation_for_session(item->kind);
	if (item->minimum_security_level >
	    plan->minimum_security_level) {
		plan->minimum_security_level =
			item->minimum_security_level;
	}
	if (item->deadline_ms != 0U &&
	    (plan->earliest_deadline_ms == 0U ||
	     item->deadline_ms < plan->earliest_deadline_ms)) {
		plan->earliest_deadline_ms = item->deadline_ms;
	}
}

int pqcp_adaptive_workload_init(
	struct pqcp_adaptive_workload_queue *queue)
{
	if (queue == NULL) {
		return -EINVAL;
	}
	memset(queue, 0, sizeof(*queue));
	queue->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	return queue_digest(queue);
}

int pqcp_adaptive_workload_submit(
	struct pqcp_adaptive_workload_queue *queue,
	const struct pqcp_adaptive_workload_item *item)
{
	struct pqcp_adaptive_workload_item normalized;

	if (queue == NULL ||
	    queue->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !workload_item_valid(item)) {
		return -EINVAL;
	}
	if (queue->count >= PQCP_ADAPTIVE_MAX_WORKLOAD_ITEMS) {
		queue->rejected_count++;
		return -ENOSPC;
	}
	if (find_item(queue, item->request_id) >= 0) {
		queue->rejected_count++;
		return -EEXIST;
	}
	normalized = *item;
	normalized.state = PQCP_ADAPTIVE_WORKLOAD_QUEUED;
	normalized.selected_profile_id[0] = '\0';
	queue->items[queue->count++] = normalized;
	queue_recount(queue);
	return queue_digest(queue);
}

int pqcp_adaptive_workload_cancel(
	struct pqcp_adaptive_workload_queue *queue,
	uint64_t request_id)
{
	int index;

	if (queue == NULL ||
	    queue->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    request_id == 0U) {
		return -EINVAL;
	}
	index = find_item(queue, request_id);
	if (index < 0) {
		return -ENOENT;
	}
	if (queue->items[index].state ==
	    PQCP_ADAPTIVE_WORKLOAD_RUNNING) {
		return -EBUSY;
	}
	remove_item(queue, (uint32_t)index);
	queue_recount(queue);
	return queue_digest(queue);
}

int pqcp_adaptive_workload_complete(
	struct pqcp_adaptive_workload_queue *queue,
	uint64_t request_id,
	bool success)
{
	int index;

	if (queue == NULL ||
	    queue->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    request_id == 0U) {
		return -EINVAL;
	}
	index = find_item(queue, request_id);
	if (index < 0) {
		return -ENOENT;
	}
	if (queue->items[index].state !=
		    PQCP_ADAPTIVE_WORKLOAD_ADMITTED &&
	    queue->items[index].state !=
		    PQCP_ADAPTIVE_WORKLOAD_RUNNING) {
		return -EPERM;
	}
	if (success) {
		queue->completed_count++;
		remove_item(queue, (uint32_t)index);
	} else {
		queue->items[index].state =
			PQCP_ADAPTIVE_WORKLOAD_QUEUED;
		queue->items[index].retry_count++;
		queue->items[index].selected_profile_id[0] = '\0';
	}
	queue_recount(queue);
	return queue_digest(queue);
}

int pqcp_adaptive_workload_plan(
	struct pqcp_adaptive_workload_queue *queue,
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_recommendation *recommendation,
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_resource_assessment *resources,
	uint64_t now_ms,
	struct pqcp_adaptive_workload_plan *plan)
{
	if (queue == NULL ||
	    queue->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    pqcp_adaptive_profile_registry_validate(registry) != 0 ||
	    recommendation == NULL || limits == NULL ||
	    resources == NULL || plan == NULL) {
		return -EINVAL;
	}
	memset(plan, 0, sizeof(*plan));
	plan->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	sort_queue(queue, now_ms);
	for (uint32_t index = 0U; index < queue->count; ++index) {
		struct pqcp_adaptive_workload_item *item =
			&queue->items[index];
		const struct pqcp_adaptive_profile *profile;

		if (item->state != PQCP_ADAPTIVE_WORKLOAD_QUEUED) {
			continue;
		}
		plan->considered_count++;
		if (item->deadline_ms != 0U &&
		    item->deadline_ms < now_ms) {
			item->state = PQCP_ADAPTIVE_WORKLOAD_EXPIRED;
			plan->rejected_count++;
			queue->rejected_count++;
			continue;
		}
		profile = profile_for_item(
			item, registry, recommendation);
		if (profile == NULL) {
			item->state = PQCP_ADAPTIVE_WORKLOAD_REJECTED;
			plan->rejected_count++;
			queue->rejected_count++;
			plan->blocker_mask |=
				PQCP_ADAPTIVE_BLOCK_OPERATION |
				PQCP_ADAPTIVE_BLOCK_SECURITY |
				PQCP_ADAPTIVE_BLOCK_EVIDENCE;
			continue;
		}
		if (!latency_fits(
			    plan->planned_latency_us,
			    item, limits, now_ms) ||
		    !energy_fits(
			    plan->planned_energy_uj,
			    item, limits)) {
			plan->deferred_count++;
			plan->warning_mask |=
				PQCP_ADAPTIVE_WARNING_FORECAST_PRESSURE;
			continue;
		}
		if (resources->overall_pressure >=
			    PQCP_ADAPTIVE_PRESSURE_HIGH &&
		    item->priority < 700U) {
			plan->deferred_count++;
			plan->warning_mask |=
				PQCP_ADAPTIVE_WARNING_FORECAST_PRESSURE;
			continue;
		}
		item->state = PQCP_ADAPTIVE_WORKLOAD_ADMITTED;
		pqcp_adaptive_internal_set_text(
			item->selected_profile_id,
			sizeof(item->selected_profile_id),
			profile->profile_id);
		plan->admitted_count++;
		plan->planned_latency_us =
			pqcp_adaptive_internal_saturating_add_u64(
				plan->planned_latency_us,
				item->estimated_latency_us);
		plan->planned_energy_uj =
			pqcp_adaptive_internal_saturating_add_u64(
				plan->planned_energy_uj,
				item->estimated_energy_uj);
		update_plan_requirements(plan, item);
		if (plan->preferred_profile_id[0] == '\0') {
			pqcp_adaptive_internal_set_text(
				plan->preferred_profile_id,
				sizeof(plan->preferred_profile_id),
				profile->profile_id);
		} else if (strcmp(
				   plan->preferred_profile_id,
				   profile->profile_id) != 0) {
			plan->warning_mask |=
				PQCP_ADAPTIVE_WARNING_PENDING_SESSIONS;
		}
	}
	queue_recount(queue);
	if (queue_digest(queue) != 0) {
		return -EBADMSG;
	}
	if (plan->admitted_count == 0U &&
	    plan->considered_count != 0U) {
		plan->status = PQCP_ADAPTIVE_STATUS_FAIL;
	} else if (plan->rejected_count != 0U ||
		   plan->deferred_count != 0U ||
		   plan->warning_mask != 0U) {
		plan->status = PQCP_ADAPTIVE_STATUS_WARN;
	} else {
		plan->status = PQCP_ADAPTIVE_STATUS_PASS;
	}
	if (plan->preferred_profile_id[0] == '\0') {
		pqcp_adaptive_internal_set_text(
			plan->preferred_profile_id,
			sizeof(plan->preferred_profile_id), "none");
	}
	return plan_digest(plan, plan->plan_digest_hex);
}

static const char *workload_state_str(
	enum pqcp_adaptive_workload_state state)
{
	switch (state) {
	case PQCP_ADAPTIVE_WORKLOAD_QUEUED:
		return "queued";
	case PQCP_ADAPTIVE_WORKLOAD_ADMITTED:
		return "admitted";
	case PQCP_ADAPTIVE_WORKLOAD_RUNNING:
		return "running";
	case PQCP_ADAPTIVE_WORKLOAD_COMPLETED:
		return "completed";
	case PQCP_ADAPTIVE_WORKLOAD_REJECTED:
		return "rejected";
	case PQCP_ADAPTIVE_WORKLOAD_EXPIRED:
		return "expired";
	default:
		return "invalid";
	}
}

int pqcp_adaptive_workload_emit(
	const struct pqcp_adaptive_workload_queue *queue,
	const struct pqcp_adaptive_workload_plan *plan)
{
	if (queue == NULL || plan == NULL ||
	    queue->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    plan->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	for (uint32_t index = 0U; index < queue->count; ++index) {
		const struct pqcp_adaptive_workload_item *item =
			&queue->items[index];

		printk("PQCP_ADAPTIVE_WORKLOAD_ITEM schema=%u index=%u request=%llu kind=%s state=%s submitted_ms=%llu deadline_ms=%llu latency_us=%llu energy_uj=%llu payload=%llu priority=%u security=%u evidence=0x%08x retries=%u transition=%u batchable=%u profile=%s\n",
		       queue->schema_version,
		       index,
		       (unsigned long long)item->request_id,
		       pqcp_adaptive_session_kind_str(item->kind),
		       workload_state_str(item->state),
		       (unsigned long long)item->submitted_at_ms,
		       (unsigned long long)item->deadline_ms,
		       (unsigned long long)item->estimated_latency_us,
		       (unsigned long long)item->estimated_energy_uj,
		       (unsigned long long)item->payload_bytes,
		       item->priority,
		       item->minimum_security_level,
		       item->required_evidence_mask,
		       item->retry_count,
		       item->transition_allowed ? 1U : 0U,
		       item->batchable ? 1U : 0U,
		       item->selected_profile_id[0] != '\0' ?
			       item->selected_profile_id : "none");
	}
	printk("PQCP_ADAPTIVE_WORKLOAD_PLAN schema=%u status=%s considered=%u admitted=%u rejected=%u deferred=%u blockers=0x%08x warnings=0x%08x latency_us=%llu energy_uj=%llu earliest_deadline_ms=%llu operations=0x%08x security=%u profile=%s plan_digest=%s queue_digest=%s\n",
	       plan->schema_version,
	       pqcp_adaptive_status_str(plan->status),
	       plan->considered_count,
	       plan->admitted_count,
	       plan->rejected_count,
	       plan->deferred_count,
	       plan->blocker_mask,
	       plan->warning_mask,
	       (unsigned long long)plan->planned_latency_us,
	       (unsigned long long)plan->planned_energy_uj,
	       (unsigned long long)plan->earliest_deadline_ms,
	       plan->required_operation_mask,
	       plan->minimum_security_level,
	       plan->preferred_profile_id,
	       plan->plan_digest_hex,
	       queue->queue_digest_hex);
	return 0;
}
