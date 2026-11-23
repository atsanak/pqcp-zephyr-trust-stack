/*
 * SPDX-License-Identifier: MIT
 *
 * Digest-bound asynchronous vault replication.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static int record_index(
	const struct pqcp_edge_replication_manager *manager,
	uint64_t replication_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->records[index].occupied &&
		    manager->records[index].replication_id ==
			    replication_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int duplicate_index(
	const struct pqcp_edge_replication_manager *manager,
	const char *object_id,
	const char *target_id,
	uint64_t object_version)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_edge_replica_record *record =
			&manager->records[index];

		if (record->occupied &&
		    record->object_version == object_version &&
		    strcmp(record->object_id, object_id) == 0 &&
		    strcmp(record->target_id, target_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_record_index(
	const struct pqcp_edge_replication_manager *manager)
{
	int recyclable = -1;
	uint64_t oldest = UINT64_MAX;

	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_edge_replica_record *record =
			&manager->records[index];

		if (!record->occupied) {
			return (int)index;
		}
		if ((record->state == PQCP_EDGE_REPLICA_APPLIED ||
		     /* A FAILED record that still owes retries is live. */
		     (record->state == PQCP_EDGE_REPLICA_FAILED &&
		      record->attempts >= record->maximum_attempts) ||
		     record->state == PQCP_EDGE_REPLICA_CONFLICT) &&
		    record->scheduled_at_ms < oldest) {
			oldest = record->scheduled_at_ms;
			recyclable = (int)index;
		}
	}
	return recyclable >= 0 ? recyclable : -ENOSPC;
}

int pqcp_edge_replication_manager_init(
	struct pqcp_edge_replication_manager *manager,
	struct pqcp_edge_replica_record *records,
	size_t capacity)
{
	if (manager == NULL || records == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(records, 0, capacity * sizeof(*records));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->records = records;
	manager->capacity = capacity;
	manager->next_replication_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_replication_schedule(
	struct pqcp_edge_replication_manager *manager,
	const struct pqcp_edge_vault_object *object,
	const char *target_id,
	uint64_t now_ms,
	uint32_t maximum_attempts,
	struct pqcp_edge_replica_record **record)
{
	struct pqcp_edge_replica_record candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    object == NULL || !object->occupied ||
	    !pqcp_edge_internal_text_valid(
		    target_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    maximum_attempts == 0U || record == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = duplicate_index(
		manager, object->object_id, target_id,
		object->version);
	if (index >= 0) {
		*record = &manager->records[index];
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	index = free_record_index(manager);
	if (index < 0) {
		*record = NULL;
		k_mutex_unlock(&manager->lock);
		return index;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.replication_id =
		pqcp_edge_internal_next_identifier(
			&manager->next_replication_id);
	ret = pqcp_edge_internal_copy_text(
		candidate.object_id,
		sizeof(candidate.object_id),
		object->object_id);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.target_id,
			sizeof(candidate.target_id),
			target_id);
	}
	if (ret == 0) {
		candidate.object_version = object->version;
		candidate.scheduled_at_ms = now_ms;
		candidate.maximum_attempts = maximum_attempts;
		candidate.state = PQCP_EDGE_REPLICA_PENDING;
		memcpy(candidate.object_digest,
		       object->object_digest,
		       sizeof(candidate.object_digest));
		candidate.occupied = true;
		manager->records[index] = candidate;
		*record = &manager->records[index];
	} else {
		*record = NULL;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_replication_next(
	struct pqcp_edge_replication_manager *manager,
	uint64_t now_ms,
	struct pqcp_edge_replica_record **record)
{
	struct pqcp_edge_replica_record *selected = NULL;

	if (manager == NULL || !manager->initialized ||
	    record == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_edge_replica_record *candidate =
			&manager->records[index];

		if (!candidate->occupied ||
		    (candidate->state !=
			     PQCP_EDGE_REPLICA_PENDING &&
		     candidate->state !=
			     PQCP_EDGE_REPLICA_FAILED) ||
		    candidate->retry_at_ms > now_ms ||
		    candidate->attempts >=
			    candidate->maximum_attempts) {
			continue;
		}
		if (selected == NULL ||
		    candidate->scheduled_at_ms <
			    selected->scheduled_at_ms ||
		    (candidate->scheduled_at_ms ==
			     selected->scheduled_at_ms &&
		     candidate->replication_id <
			     selected->replication_id)) {
			selected = candidate;
		}
	}
	if (selected == NULL) {
		*record = NULL;
		k_mutex_unlock(&manager->lock);
		return -EAGAIN;
	}
	selected->state = PQCP_EDGE_REPLICA_TRANSFERRING;
	++selected->attempts;
	*record = selected;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_replication_complete(
	struct pqcp_edge_replication_manager *manager,
	uint64_t replication_id,
	int result,
	const uint8_t applied_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_edge_replica_record *record;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    replication_id == 0U ||
	    (result == 0 && applied_digest == NULL)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = record_index(manager, replication_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	record = &manager->records[index];
	if (record->state != PQCP_EDGE_REPLICA_TRANSFERRING) {
		ret = -EALREADY;
		goto out;
	}
	record->completed_at_ms = now_ms;
	record->result = result;
	if (result == 0 &&
	    pqcp_edge_internal_equal(
		    record->object_digest, applied_digest,
		    sizeof(record->object_digest))) {
		record->state = PQCP_EDGE_REPLICA_APPLIED;
		++manager->success_count;
	} else if (result == 0) {
		record->state = PQCP_EDGE_REPLICA_CONFLICT;
		record->result = -EBADMSG;
		++manager->failure_count;
		ret = -EBADMSG;
	} else if (record->attempts >=
		   record->maximum_attempts) {
		record->state = PQCP_EDGE_REPLICA_FAILED;
		++manager->failure_count;
	} else {
		record->state = PQCP_EDGE_REPLICA_FAILED;
		record->retry_at_ms =
			pqcp_edge_internal_saturating_add_u64(
				now_ms,
				pqcp_edge_internal_backoff(
					250U, 60000U,
					record->attempts));
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_replication_retry(
	struct pqcp_edge_replication_manager *manager,
	uint64_t replication_id,
	uint64_t retry_at_ms)
{
	struct pqcp_edge_replica_record *record;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    replication_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = record_index(manager, replication_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	record = &manager->records[index];
	if (record->state != PQCP_EDGE_REPLICA_FAILED ||
	    record->attempts >= record->maximum_attempts) {
		ret = -EALREADY;
	} else {
		record->retry_at_ms = retry_at_ms;
		record->state = PQCP_EDGE_REPLICA_PENDING;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_edge_replication_manager_audit(
	struct pqcp_edge_replication_manager *manager)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->records == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_replica_record *record =
			&manager->records[index];

		if (!record->occupied) {
			continue;
		}
		if (record->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    record->replication_id == 0U ||
		    !pqcp_edge_internal_text_valid(
			    record->object_id,
			    sizeof(record->object_id)) ||
		    !pqcp_edge_internal_text_valid(
			    record->target_id,
			    sizeof(record->target_id)) ||
		    record->object_version == 0U ||
		    record->maximum_attempts == 0U ||
		    record->attempts >
			    record->maximum_attempts ||
		    record->state <= PQCP_EDGE_REPLICA_EMPTY ||
		    record->state > PQCP_EDGE_REPLICA_FAILED ||
		    pqcp_edge_internal_all_zero(
			    record->object_digest,
			    sizeof(record->object_digest))) {
			ret = -EBADMSG;
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
