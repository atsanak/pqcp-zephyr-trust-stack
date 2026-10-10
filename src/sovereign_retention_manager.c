/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Retention schedules, legal holds, and deletion eligibility tracking.
 */

#include "sovereign_privacy_internal.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

static bool retention_rule_valid(
	const struct pqcp_sovereign_retention_rule *rule)
{
	uint32_t valid_mask =
		(1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT) - 1U;

	return rule != NULL && rule->rule_id != 0U &&
	       pqcp_sovereign_privacy_text_valid(
		       rule->tenant_id, sizeof(rule->tenant_id)) &&
	       pqcp_sovereign_privacy_text_valid(
		       rule->purpose, sizeof(rule->purpose)) &&
	       rule->data_class_mask != 0U &&
	       (rule->data_class_mask & ~valid_mask) == 0U &&
	       rule->maximum_retention_ms != 0U &&
	       rule->maximum_retention_ms >=
		       rule->minimum_retention_ms &&
	       rule->deletion_method != 0U &&
	       rule->priority != 0U && rule->enabled;
}

static int retention_rule_index_locked(
	const struct pqcp_sovereign_retention_manager *manager,
	uint32_t rule_id)
{
	size_t index;

	for (index = 0U; index < manager->rule_capacity; ++index) {
		if (manager->rules[index].enabled &&
		    manager->rules[index].rule_id == rule_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_rule_index_locked(
	const struct pqcp_sovereign_retention_manager *manager)
{
	size_t index;

	for (index = 0U; index < manager->rule_capacity; ++index) {
		if (!manager->rules[index].enabled) {
			return (int)index;
		}
	}
	return -1;
}

static int retention_record_index_locked(
	const struct pqcp_sovereign_retention_manager *manager,
	uint64_t record_id)
{
	size_t index;

	for (index = 0U; index < manager->record_capacity; ++index) {
		if (manager->records[index].occupied &&
		    manager->records[index].record_id == record_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_record_index_locked(
	const struct pqcp_sovereign_retention_manager *manager)
{
	size_t index;

	for (index = 0U; index < manager->record_capacity; ++index) {
		if (!manager->records[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static const struct pqcp_sovereign_retention_rule *
select_rule_locked(
	const struct pqcp_sovereign_retention_manager *manager,
	const char *tenant_id,
	const char *purpose,
	enum pqcp_sovereign_data_class data_class)
{
	const struct pqcp_sovereign_retention_rule *selected = NULL;
	size_t index;

	for (index = 0U; index < manager->rule_capacity; ++index) {
		const struct pqcp_sovereign_retention_rule *rule =
			&manager->rules[index];

		if (!rule->enabled ||
		    strcmp(rule->tenant_id, tenant_id) != 0 ||
		    strcmp(rule->purpose, purpose) != 0 ||
		    (rule->data_class_mask &
		     (1U << (uint32_t)data_class)) == 0U) {
			continue;
		}
		if (selected == NULL ||
		    rule->priority > selected->priority ||
		    (rule->priority == selected->priority &&
		     rule->maximum_retention_ms <
			     selected->maximum_retention_ms) ||
		    (rule->priority == selected->priority &&
		     rule->maximum_retention_ms ==
			     selected->maximum_retention_ms &&
		     rule->rule_id < selected->rule_id)) {
			selected = rule;
		}
	}
	return selected;
}

static bool active_object_alias_locked(
	const struct pqcp_sovereign_retention_manager *manager,
	const char *tenant_id,
	const char *object_id)
{
	size_t index;

	for (index = 0U; index < manager->record_capacity; ++index) {
		const struct pqcp_sovereign_retention_record *record =
			&manager->records[index];

		if (record->occupied &&
		    record->state != PQCP_SOVEREIGN_LIFECYCLE_RETIRED &&
		    strcmp(record->tenant_id, tenant_id) == 0 &&
		    strcmp(record->object_id, object_id) == 0) {
			return true;
		}
	}
	return false;
}

static int checked_deadline(
	uint64_t start_ms,
	uint64_t duration_ms,
	uint64_t *deadline_ms)
{
	if (deadline_ms == NULL || duration_ms == 0U) {
		return -EINVAL;
	}
	if (duration_ms > UINT64_MAX - start_ms) {
		return -EOVERFLOW;
	}
	*deadline_ms = start_ms + duration_ms;
	return 0;
}

int pqcp_sovereign_retention_manager_init(
	struct pqcp_sovereign_retention_manager *manager,
	struct pqcp_sovereign_retention_rule *rules,
	size_t rule_capacity,
	struct pqcp_sovereign_retention_record *records,
	size_t record_capacity)
{
	if (manager == NULL || rules == NULL || rule_capacity == 0U ||
	    records == NULL || record_capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(rules, 0, rule_capacity * sizeof(*rules));
	memset(records, 0, record_capacity * sizeof(*records));
	manager->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	manager->rules = rules;
	manager->rule_capacity = rule_capacity;
	manager->records = records;
	manager->record_capacity = record_capacity;
	manager->next_record_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_retention_rule_put(
	struct pqcp_sovereign_retention_manager *manager,
	const struct pqcp_sovereign_retention_rule *rule)
{
	struct pqcp_sovereign_retention_rule candidate;
	int index;

	if (manager == NULL || !manager->initialized ||
	    !retention_rule_valid(rule)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = retention_rule_index_locked(manager, rule->rule_id);
	if (index < 0) {
		index = free_rule_index_locked(manager);
		if (index < 0) {
			k_mutex_unlock(&manager->lock);
			return -ENOSPC;
		}
	}
	candidate = *rule;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.enabled = true;
	manager->rules[index] = candidate;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_retention_track(
	struct pqcp_sovereign_retention_manager *manager,
	const char *object_id,
	const char *tenant_id,
	const char *purpose,
	enum pqcp_sovereign_data_class data_class,
	const uint8_t object_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_sovereign_retention_record **record)
{
	const struct pqcp_sovereign_retention_rule *rule;
	struct pqcp_sovereign_retention_record candidate;
	int index;
	uint64_t delete_after_ms;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    object_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    purpose, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_data_class_valid(data_class) ||
	    pqcp_sovereign_privacy_digest_zero(object_digest) ||
	    now_ms == 0U || record == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	if (active_object_alias_locked(
		    manager, tenant_id, object_id)) {
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	rule = select_rule_locked(
		manager, tenant_id, purpose, data_class);
	if (rule == NULL) {
		k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	ret = checked_deadline(
		now_ms, rule->maximum_retention_ms,
		&delete_after_ms);
	if (ret != 0) {
		k_mutex_unlock(&manager->lock);
		return ret;
	}
	index = free_record_index_locked(manager);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	if (manager->next_record_id == 0U ||
	    manager->next_record_id == UINT64_MAX) {
		k_mutex_unlock(&manager->lock);
		return -EOVERFLOW;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.record_id = manager->next_record_id++;
	ret = pqcp_sovereign_privacy_copy_text(
		candidate.object_id, sizeof(candidate.object_id),
		object_id);
	if (ret == 0) {
		ret = pqcp_sovereign_privacy_copy_text(
			candidate.tenant_id,
			sizeof(candidate.tenant_id), tenant_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_privacy_copy_text(
			candidate.purpose, sizeof(candidate.purpose),
			purpose);
	}
	if (ret != 0) {
		k_mutex_unlock(&manager->lock);
		return ret;
	}
	candidate.data_class = data_class;
	candidate.created_at_ms = now_ms;
	candidate.delete_after_ms = delete_after_ms;
	candidate.legal_hold_until_ms =
		rule->legal_hold_until_ms > now_ms ?
			rule->legal_hold_until_ms :
			0U;
	memcpy(candidate.object_digest, object_digest,
	       sizeof(candidate.object_digest));
	candidate.state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	candidate.occupied = true;
	manager->records[index] = candidate;
	*record = &manager->records[index];
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_retention_hold(
	struct pqcp_sovereign_retention_manager *manager,
	uint64_t record_id,
	uint64_t hold_until_ms)
{
	struct pqcp_sovereign_retention_record *record;
	int index;

	if (manager == NULL || !manager->initialized ||
	    record_id == 0U || hold_until_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = retention_record_index_locked(manager, record_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	record = &manager->records[index];
	if (record->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	if (hold_until_ms <= record->legal_hold_until_ms ||
	    hold_until_ms <= record->created_at_ms) {
		k_mutex_unlock(&manager->lock);
		return -ERANGE;
	}
	record->legal_hold_until_ms = hold_until_ms;
	k_mutex_unlock(&manager->lock);
	return 0;
}

static int minimum_retention_deadline_locked(
	const struct pqcp_sovereign_retention_manager *manager,
	const struct pqcp_sovereign_retention_record *record,
	uint64_t *deadline_ms)
{
	const struct pqcp_sovereign_retention_rule *rule;

	rule = select_rule_locked(
		manager, record->tenant_id, record->purpose,
		record->data_class);
	if (rule == NULL) {
		return -EACCES;
	}
	if (rule->minimum_retention_ms == 0U) {
		*deadline_ms = record->created_at_ms;
		return 0;
	}
	return checked_deadline(
		record->created_at_ms, rule->minimum_retention_ms,
		deadline_ms);
}

int pqcp_sovereign_retention_mark_deleted(
	struct pqcp_sovereign_retention_manager *manager,
	uint64_t record_id,
	uint64_t now_ms)
{
	struct pqcp_sovereign_retention_record *record;
	uint64_t minimum_deadline;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    record_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = retention_record_index_locked(manager, record_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	record = &manager->records[index];
	if (record->state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED) {
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	if (record->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	ret = minimum_retention_deadline_locked(
		manager, record, &minimum_deadline);
	if (ret != 0) {
		k_mutex_unlock(&manager->lock);
		return ret;
	}
	if (now_ms < minimum_deadline) {
		k_mutex_unlock(&manager->lock);
		return -EPERM;
	}
	if (record->legal_hold_until_ms > now_ms) {
		k_mutex_unlock(&manager->lock);
		return -EBUSY;
	}
	record->deleted_at_ms = now_ms;
	record->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_retention_due(
	struct pqcp_sovereign_retention_manager *manager,
	uint64_t now_ms,
	struct pqcp_sovereign_retention_record **record)
{
	struct pqcp_sovereign_retention_record *selected = NULL;
	size_t index;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || record == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U; index < manager->record_capacity;
	     ++index) {
		struct pqcp_sovereign_retention_record *candidate =
			&manager->records[index];

		if (!candidate->occupied ||
		    candidate->state !=
			    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    candidate->delete_after_ms > now_ms ||
		    candidate->legal_hold_until_ms > now_ms) {
			continue;
		}
		if (selected == NULL ||
		    candidate->delete_after_ms <
			    selected->delete_after_ms ||
		    (candidate->delete_after_ms ==
			     selected->delete_after_ms &&
		     candidate->record_id < selected->record_id)) {
			selected = candidate;
		}
	}
	if (selected == NULL) {
		k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	manager->deletion_due_count++;
	*record = selected;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_retention_manager_audit(
	struct pqcp_sovereign_retention_manager *manager)
{
	size_t index;
	size_t other;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    manager->rules == NULL || manager->rule_capacity == 0U ||
	    manager->records == NULL ||
	    manager->record_capacity == 0U ||
	    manager->next_record_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U;
	     index < manager->rule_capacity && ret == 0; ++index) {
		if (manager->rules[index].enabled &&
		    (manager->rules[index].schema_version !=
			     PQCP_SOVEREIGN_SCHEMA_VERSION ||
		     !retention_rule_valid(&manager->rules[index]))) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     manager->rules[index].enabled &&
		     other < manager->rule_capacity; ++other) {
			if (manager->rules[other].enabled &&
			    manager->rules[other].rule_id ==
				    manager->rules[index].rule_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	for (index = 0U;
	     index < manager->record_capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_retention_record *record =
			&manager->records[index];

		if (!record->occupied) {
			continue;
		}
		if (record->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    record->record_id == 0U ||
		    !pqcp_sovereign_privacy_text_valid(
			    record->object_id,
			    sizeof(record->object_id)) ||
		    !pqcp_sovereign_privacy_text_valid(
			    record->tenant_id,
			    sizeof(record->tenant_id)) ||
		    !pqcp_sovereign_privacy_text_valid(
			    record->purpose,
			    sizeof(record->purpose)) ||
		    !pqcp_sovereign_privacy_data_class_valid(
			    record->data_class) ||
		    record->delete_after_ms <= record->created_at_ms ||
		    pqcp_sovereign_privacy_digest_zero(
			    record->object_digest) ||
		    (record->state ==
			     PQCP_SOVEREIGN_LIFECYCLE_RETIRED &&
		     record->deleted_at_ms == 0U)) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < manager->record_capacity; ++other) {
			const struct pqcp_sovereign_retention_record *next =
				&manager->records[other];

			if (!next->occupied) {
				continue;
			}
			if (next->record_id == record->record_id ||
			    (record->state !=
				     PQCP_SOVEREIGN_LIFECYCLE_RETIRED &&
			     next->state !=
				     PQCP_SOVEREIGN_LIFECYCLE_RETIRED &&
			     strcmp(next->tenant_id,
				    record->tenant_id) == 0 &&
			     strcmp(next->object_id,
				    record->object_id) == 0)) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
