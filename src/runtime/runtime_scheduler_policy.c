/*
 * SPDX-License-Identifier: MIT
 *
 * Weighted deficit scheduler for bounded runtime jobs.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/runtime_operations.h>

static bool scheduler_class_valid(
	enum pqcp_runtime_scheduler_class scheduler_class)
{
	return scheduler_class >= PQCP_RUNTIME_SCHEDULER_CONTROL &&
	       scheduler_class < PQCP_RUNTIME_SCHEDULER_CLASS_COUNT;
}

static int scheduler_policy_validate(
	const struct pqcp_runtime_scheduler_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_RUNTIME_OPERATION_SCHEMA_VERSION ||
	    policy->tenant_quantum == 0U ||
	    policy->maximum_consecutive_dispatches == 0U ||
	    policy->retry_base_ms == 0U ||
	    policy->retry_max_ms < policy->retry_base_ms) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < PQCP_RUNTIME_SCHEDULER_CLASS_COUNT; ++index) {
		if (policy->class_weights[index] == 0U ||
		    policy->class_burst[index] == 0U) {
			return -EINVAL;
		}
	}
	return 0;
}

static struct pqcp_runtime_scheduler_tenant *find_tenant(
	struct pqcp_runtime_scheduler *scheduler,
	uint32_t tenant_id)
{
	for (size_t index = 0U;
	     index < scheduler->tenant_capacity; ++index) {
		struct pqcp_runtime_scheduler_tenant *tenant =
			&scheduler->tenants[index];

		if (tenant->enabled &&
		    tenant->tenant_id == tenant_id) {
			return tenant;
		}
	}
	return NULL;
}

static struct pqcp_runtime_scheduler_tenant *find_tenant_slot(
	struct pqcp_runtime_scheduler *scheduler,
	uint32_t tenant_id)
{
	struct pqcp_runtime_scheduler_tenant *empty = NULL;

	for (size_t index = 0U;
	     index < scheduler->tenant_capacity; ++index) {
		struct pqcp_runtime_scheduler_tenant *tenant =
			&scheduler->tenants[index];

		if (tenant->tenant_id == tenant_id &&
		    (tenant->enabled || tenant->weight != 0U)) {
			return tenant;
		}
		if (empty == NULL && !tenant->enabled &&
		    tenant->weight == 0U) {
			empty = tenant;
		}
	}
	return empty;
}

static uint64_t job_deadline(
	const struct pqcp_runtime_job *job)
{
	return job->deadline_ms;
}

static uint64_t saturating_add_u64(
	uint64_t left,
	uint64_t right)
{
	if (UINT64_MAX - left < right) {
		return UINT64_MAX;
	}
	return left + right;
}

static uint32_t saturating_add_u32(
	uint32_t left,
	uint32_t right)
{
	if (UINT32_MAX - left < right) {
		return UINT32_MAX;
	}
	return left + right;
}

static uint32_t class_credit(
	const struct pqcp_runtime_scheduler *scheduler,
	const struct pqcp_runtime_scheduler_entry *entry)
{
	const uint32_t weight =
		scheduler->policy.class_weights[
			entry->scheduler_class];
	const uint32_t burst =
		scheduler->policy.class_burst[
			entry->scheduler_class];
	uint64_t credit = (uint64_t)weight * burst;

	if (credit > UINT32_MAX) {
		credit = UINT32_MAX;
	}
	return (uint32_t)credit;
}

static bool deadline_missed(
	const struct pqcp_runtime_scheduler *scheduler,
	const struct pqcp_runtime_scheduler_entry *entry,
	uint64_t now_ms)
{
	if (entry->deadline_ms == 0U) {
		return false;
	}
	return now_ms >= entry->deadline_ms ||
	       entry->deadline_ms - now_ms <=
		       scheduler->policy.deadline_guard_ms;
}

static int remove_entry(
	struct pqcp_runtime_scheduler *scheduler,
	size_t slot,
	bool cancelled,
	bool expired)
{
	struct pqcp_runtime_scheduler_entry *entry;
	struct pqcp_runtime_scheduler_tenant *tenant;

	if (slot >= scheduler->capacity) {
		return -EINVAL;
	}
	entry = &scheduler->entries[slot];
	if (!entry->occupied) {
		return -ENOENT;
	}
	tenant = find_tenant(scheduler, entry->tenant_id);
	if (tenant != NULL && tenant->queued != 0U) {
		tenant->queued--;
	}
	memset(entry, 0, sizeof(*entry));
	if (scheduler->count != 0U) {
		scheduler->count--;
	}
	if (cancelled) {
		scheduler->cancelled++;
	}
	if (expired) {
		scheduler->expired++;
	}
	return 0;
}

static int eligible_score(
	const struct pqcp_runtime_scheduler *scheduler,
	const struct pqcp_runtime_scheduler_entry *entry,
	const struct pqcp_runtime_scheduler_tenant *tenant,
	uint64_t now_ms,
	uint64_t *score)
{
	uint64_t urgency = 0U;
	uint64_t age;
	uint64_t class_component;
	uint64_t fairness_component;

	if (!entry->occupied || entry->cancelled ||
	    entry->job == NULL || tenant == NULL ||
	    !tenant->enabled || entry->not_before_ms > now_ms) {
		return -EAGAIN;
	}
	if (tenant->deficit < entry->cost) {
		return -EDQUOT;
	}
	age = now_ms >= entry->enqueued_at_ms ?
		now_ms - entry->enqueued_at_ms : 0U;
	class_component =
		(uint64_t)(PQCP_RUNTIME_SCHEDULER_CLASS_COUNT -
			   entry->scheduler_class) *
		UINT64_C(1000000000);
	if (entry->deadline_ms != 0U) {
		if (entry->deadline_ms <= now_ms) {
			urgency = UINT64_C(2000000000);
		} else {
			const uint64_t remaining =
				entry->deadline_ms - now_ms;

			urgency = remaining < UINT64_C(1000000) ?
				UINT64_C(1000000000) - remaining :
				0U;
		}
	}
	fairness_component =
		scheduler->policy.enforce_owner_fairness &&
		scheduler->last_tenant_id == entry->tenant_id &&
		scheduler->consecutive_dispatches >=
			scheduler->policy.
				maximum_consecutive_dispatches ?
		0U : UINT64_C(500000000);
	*score = saturating_add_u64(
		class_component,
		saturating_add_u64(
			urgency,
			saturating_add_u64(
				age, fairness_component)));
	return 0;
}

int pqcp_runtime_scheduler_policy_default(
	struct pqcp_runtime_scheduler_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version =
		PQCP_RUNTIME_OPERATION_SCHEMA_VERSION;
	policy->class_weights[PQCP_RUNTIME_SCHEDULER_CONTROL] = 16U;
	policy->class_weights[PQCP_RUNTIME_SCHEDULER_INTERACTIVE] = 8U;
	policy->class_weights[PQCP_RUNTIME_SCHEDULER_DEFAULT] = 4U;
	policy->class_weights[PQCP_RUNTIME_SCHEDULER_BULK] = 2U;
	policy->class_weights[PQCP_RUNTIME_SCHEDULER_MAINTENANCE] = 1U;
	policy->class_burst[PQCP_RUNTIME_SCHEDULER_CONTROL] = 8U;
	policy->class_burst[PQCP_RUNTIME_SCHEDULER_INTERACTIVE] = 6U;
	policy->class_burst[PQCP_RUNTIME_SCHEDULER_DEFAULT] = 4U;
	policy->class_burst[PQCP_RUNTIME_SCHEDULER_BULK] = 2U;
	policy->class_burst[PQCP_RUNTIME_SCHEDULER_MAINTENANCE] = 1U;
	policy->tenant_quantum = 8U;
	policy->maximum_consecutive_dispatches = 4U;
	policy->deadline_guard_ms = 5U;
	policy->retry_base_ms = 10U;
	policy->retry_max_ms = 5000U;
	policy->expire_missed_deadlines = true;
	policy->enforce_owner_fairness = true;
	return 0;
}

int pqcp_runtime_scheduler_init(
	struct pqcp_runtime_scheduler *scheduler,
	const struct pqcp_runtime_scheduler_policy *policy,
	struct pqcp_runtime_scheduler_entry *entries,
	size_t capacity,
	struct pqcp_runtime_scheduler_tenant *tenants,
	size_t tenant_capacity)
{
	if (scheduler == NULL ||
	    scheduler_policy_validate(policy) != 0 ||
	    entries == NULL || capacity == 0U ||
	    tenants == NULL || tenant_capacity == 0U) {
		return -EINVAL;
	}
	memset(entries, 0, capacity * sizeof(*entries));
	memset(tenants, 0, tenant_capacity * sizeof(*tenants));
	memset(scheduler, 0, sizeof(*scheduler));
	scheduler->policy = *policy;
	scheduler->entries = entries;
	scheduler->capacity = capacity;
	scheduler->tenants = tenants;
	scheduler->tenant_capacity = tenant_capacity;
	scheduler->next_dispatch_sequence = 1U;
	k_mutex_init(&scheduler->lock);
	scheduler->initialized = true;
	return 0;
}

int pqcp_runtime_scheduler_configure_tenant(
	struct pqcp_runtime_scheduler *scheduler,
	uint32_t tenant_id,
	uint32_t weight,
	bool enabled)
{
	struct pqcp_runtime_scheduler_tenant *tenant;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    tenant_id == 0U || weight == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	tenant = find_tenant_slot(scheduler, tenant_id);
	if (tenant == NULL) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOSPC;
	}
	if (!enabled && (tenant->queued != 0U ||
			 tenant->in_flight != 0U)) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EBUSY;
	}
	tenant->tenant_id = tenant_id;
	tenant->weight = weight;
	tenant->enabled = enabled;
	if (enabled && tenant->deficit == 0U) {
		tenant->deficit =
			saturating_add_u32(
				scheduler->policy.tenant_quantum,
				weight);
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_runtime_scheduler_submit(
	struct pqcp_runtime_scheduler *scheduler,
	struct pqcp_runtime_job *job,
	enum pqcp_runtime_scheduler_class scheduler_class,
	uint32_t tenant_id,
	uint32_t cost,
	uint64_t not_before_ms)
{
	struct pqcp_runtime_scheduler_tenant *tenant;
	uint64_t now_ms;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    job == NULL || job->job_id == 0U ||
	    !scheduler_class_valid(scheduler_class) ||
	    tenant_id == 0U || cost == 0U) {
		return -EINVAL;
	}
	now_ms = k_uptime_get();
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	tenant = find_tenant(scheduler, tenant_id);
	if (tenant == NULL) {
		scheduler->rejected++;
		(void)k_mutex_unlock(&scheduler->lock);
		return -EDQUOT;
	}
	for (size_t index = 0U; index < scheduler->capacity; ++index) {
		const struct pqcp_runtime_scheduler_entry *entry =
			&scheduler->entries[index];

		if (entry->occupied && entry->job != NULL &&
		    entry->job->job_id == job->job_id) {
			(void)k_mutex_unlock(&scheduler->lock);
			return -EALREADY;
		}
	}
	for (size_t index = 0U; index < scheduler->capacity; ++index) {
		struct pqcp_runtime_scheduler_entry *entry =
			&scheduler->entries[index];

		if (entry->occupied) {
			continue;
		}
		memset(entry, 0, sizeof(*entry));
		entry->job = job;
		entry->scheduler_class = scheduler_class;
		entry->tenant_id = tenant_id;
		entry->cost = cost;
		entry->enqueued_at_ms = now_ms;
		entry->not_before_ms = not_before_ms;
		entry->deadline_ms = job_deadline(job);
		entry->occupied = true;
		tenant->queued++;
		scheduler->count++;
		job->status = PQCP_RUNTIME_STATUS_QUEUED;
		(void)k_mutex_unlock(&scheduler->lock);
		return 0;
	}
	scheduler->rejected++;
	(void)k_mutex_unlock(&scheduler->lock);
	return -ENOSPC;
}

static void replenish_tenants(
	struct pqcp_runtime_scheduler *scheduler)
{
	for (size_t index = 0U;
	     index < scheduler->tenant_capacity; ++index) {
		struct pqcp_runtime_scheduler_tenant *tenant =
			&scheduler->tenants[index];
		uint64_t increment;

		if (!tenant->enabled) {
			continue;
		}
		increment =
			(uint64_t)scheduler->policy.tenant_quantum *
			tenant->weight;
		tenant->deficit = saturating_add_u32(
			tenant->deficit,
			increment > UINT32_MAX ?
				UINT32_MAX : (uint32_t)increment);
	}
}

int pqcp_runtime_scheduler_select(
	struct pqcp_runtime_scheduler *scheduler,
	uint64_t now_ms,
	struct pqcp_runtime_scheduler_decision *decision)
{
	uint64_t best_score = 0U;
	size_t best_slot = SIZE_MAX;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    now_ms == 0U || decision == NULL) {
		return -EINVAL;
	}
	memset(decision, 0, sizeof(*decision));
	decision->reason = PQCP_RUNTIME_SCHEDULER_REASON_EMPTY;
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	replenish_tenants(scheduler);
	for (size_t index = 0U; index < scheduler->capacity; ++index) {
		struct pqcp_runtime_scheduler_entry *entry =
			&scheduler->entries[index];
		const struct pqcp_runtime_scheduler_tenant *tenant;
		uint64_t score;

		if (!entry->occupied) {
			continue;
		}
		if (entry->cancelled) {
			(void)remove_entry(
				scheduler, index, true, false);
			continue;
		}
		if (deadline_missed(scheduler, entry, now_ms) &&
		    scheduler->policy.expire_missed_deadlines) {
			if (entry->job != NULL) {
				entry->job->status =
					PQCP_RUNTIME_STATUS_FAILED;
				entry->job->result = -ETIMEDOUT;
			}
			(void)remove_entry(
				scheduler, index, false, true);
			continue;
		}
		tenant = find_tenant(
			scheduler, entry->tenant_id);
		ret = eligible_score(
			scheduler, entry, tenant, now_ms, &score);
		if (ret != 0) {
			if (ret == -EDQUOT) {
				decision->reason =
					PQCP_RUNTIME_SCHEDULER_REASON_QUOTA;
			} else if (entry->not_before_ms > now_ms) {
				decision->reason =
					PQCP_RUNTIME_SCHEDULER_REASON_NOT_BEFORE;
			}
			continue;
		}
		score = saturating_add_u64(
			score, class_credit(scheduler, entry));
		if (best_slot == SIZE_MAX || score > best_score ||
		    (score == best_score &&
		     entry->enqueued_at_ms <
			     scheduler->entries[
				     best_slot].enqueued_at_ms)) {
			best_score = score;
			best_slot = index;
		}
	}
	if (best_slot == SIZE_MAX) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EAGAIN;
	}
	{
		struct pqcp_runtime_scheduler_entry *entry =
			&scheduler->entries[best_slot];
		struct pqcp_runtime_scheduler_tenant *tenant =
			find_tenant(scheduler, entry->tenant_id);

		if (tenant == NULL || tenant->deficit < entry->cost) {
			(void)k_mutex_unlock(&scheduler->lock);
			return -EDQUOT;
		}
		tenant->deficit -= entry->cost;
		if (tenant->queued != 0U) {
			tenant->queued--;
		}
		tenant->in_flight++;
		tenant->dispatched++;
		entry->dispatch_sequence =
			scheduler->next_dispatch_sequence++;
		decision->job = entry->job;
		decision->reason =
			PQCP_RUNTIME_SCHEDULER_REASON_SELECTED;
		decision->selected_at_ms = now_ms;
		decision->waited_ms =
			now_ms >= entry->enqueued_at_ms ?
				now_ms - entry->enqueued_at_ms : 0U;
		decision->tenant_id = entry->tenant_id;
		decision->cost = entry->cost;
		decision->slot = best_slot;
		if (decision->job != NULL) {
			decision->job->status =
				PQCP_RUNTIME_STATUS_RUNNING;
		}
		if (scheduler->last_tenant_id ==
		    entry->tenant_id) {
			scheduler->consecutive_dispatches++;
		} else {
			scheduler->last_tenant_id =
				entry->tenant_id;
			scheduler->consecutive_dispatches = 1U;
		}
		scheduler->dispatched++;
		entry->occupied = false;
		scheduler->count--;
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_runtime_scheduler_complete(
	struct pqcp_runtime_scheduler *scheduler,
	const struct pqcp_runtime_scheduler_decision *decision,
	int result,
	uint64_t now_ms)
{
	struct pqcp_runtime_scheduler_tenant *tenant;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    decision == NULL || decision->job == NULL ||
	    decision->tenant_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	tenant = find_tenant(scheduler, decision->tenant_id);
	if (tenant == NULL || tenant->in_flight == 0U) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOENT;
	}
	tenant->in_flight--;
	if (result == 0) {
			tenant->completed++;
			decision->job->status =
				PQCP_RUNTIME_STATUS_COMPLETED;
	} else {
		tenant->failed++;
		decision->job->status =
			PQCP_RUNTIME_STATUS_FAILED;
	}
	decision->job->result = result;
	decision->job->measurement.completed_at_ms = now_ms;
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_runtime_scheduler_cancel(
	struct pqcp_runtime_scheduler *scheduler,
	uint64_t job_id)
{
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    job_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < scheduler->capacity; ++index) {
		struct pqcp_runtime_scheduler_entry *entry =
			&scheduler->entries[index];

		if (!entry->occupied || entry->job == NULL ||
		    entry->job->job_id != job_id) {
			continue;
		}
		entry->job->status =
			PQCP_RUNTIME_STATUS_CANCELLED;
		entry->job->result = -ECANCELED;
		ret = remove_entry(
			scheduler, index, true, false);
		(void)k_mutex_unlock(&scheduler->lock);
		return ret;
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return -ENOENT;
}

int pqcp_runtime_scheduler_audit(
	struct pqcp_runtime_scheduler *scheduler)
{
	size_t occupied = 0U;
	uint64_t queued_by_tenant = 0U;
	int ret;

	if (scheduler == NULL || !scheduler->initialized ||
	    scheduler_policy_validate(&scheduler->policy) != 0) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < scheduler->capacity; ++index) {
		const struct pqcp_runtime_scheduler_entry *entry =
			&scheduler->entries[index];

		if (!entry->occupied) {
			continue;
		}
		if (entry->job == NULL || entry->job->job_id == 0U ||
		    !scheduler_class_valid(
			    entry->scheduler_class) ||
		    entry->tenant_id == 0U ||
		    entry->cost == 0U) {
			(void)k_mutex_unlock(&scheduler->lock);
			return -EBADMSG;
		}
		occupied++;
	}
	for (size_t index = 0U;
	     index < scheduler->tenant_capacity; ++index) {
		const struct pqcp_runtime_scheduler_tenant *tenant =
			&scheduler->tenants[index];

		if (!tenant->enabled) {
			if (tenant->queued != 0U ||
			    tenant->in_flight != 0U) {
				(void)k_mutex_unlock(
					&scheduler->lock);
				return -EBADMSG;
			}
			continue;
		}
		if (tenant->tenant_id == 0U ||
		    tenant->weight == 0U) {
			(void)k_mutex_unlock(&scheduler->lock);
			return -EBADMSG;
		}
		queued_by_tenant += tenant->queued;
	}
	ret = occupied == scheduler->count &&
		      queued_by_tenant == scheduler->count ?
		0 : -EBADMSG;
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}
