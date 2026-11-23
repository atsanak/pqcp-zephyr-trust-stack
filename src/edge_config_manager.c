/*
 * SPDX-License-Identifier: MIT
 *
 * Generation-bound transactional configuration activation.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool state_valid(
	enum pqcp_edge_config_state state)
{
	return state >= PQCP_EDGE_CONFIG_PREPARED &&
	       state <= PQCP_EDGE_CONFIG_ABORTED;
}

static bool terminal_state(
	enum pqcp_edge_config_state state)
{
	return state == PQCP_EDGE_CONFIG_COMMITTED ||
	       state == PQCP_EDGE_CONFIG_ABORTED;
}

static int transaction_index(
	const struct pqcp_edge_config_manager *manager,
	uint64_t transaction_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->transactions[index].occupied &&
		    manager->transactions[index].
			    transaction_id ==
			    transaction_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_transaction_index(
	const struct pqcp_edge_config_manager *manager)
{
	int reusable = -1;
	uint64_t oldest = UINT64_MAX;

	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_edge_config_transaction *entry =
			&manager->transactions[index];

		if (!entry->occupied) {
			return (int)index;
		}
		if (terminal_state(entry->state) &&
		    entry->prepared_at_ms < oldest) {
			oldest = entry->prepared_at_ms;
			reusable = (int)index;
		}
	}
	return reusable >= 0 ? reusable : -ENOSPC;
}

static bool generation_pending(
	const struct pqcp_edge_config_manager *manager,
	uint64_t target_generation)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_edge_config_transaction *entry =
			&manager->transactions[index];

		if (entry->occupied &&
		    !terminal_state(entry->state) &&
		    entry->target_generation ==
			    target_generation) {
			return true;
		}
	}
	return false;
}

static bool transaction_shape_valid(
	const struct pqcp_edge_config_transaction *entry)
{
	if (entry == NULL ||
	    entry->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    entry->transaction_id == 0U ||
	    entry->base_generation == 0U ||
	    entry->target_generation <=
		    entry->base_generation ||
	    entry->prepared_at_ms == 0U ||
	    entry->expires_at_ms <=
		    entry->prepared_at_ms ||
	    !state_valid(entry->state) ||
	    pqcp_edge_internal_all_zero(
		    entry->base_digest,
		    sizeof(entry->base_digest)) ||
	    pqcp_edge_internal_all_zero(
		    entry->target_digest,
		    sizeof(entry->target_digest)) ||
	    pqcp_edge_internal_equal(
		    entry->base_digest,
		    entry->target_digest,
		    sizeof(entry->base_digest))) {
		return false;
	}
	if ((entry->state ==
		     PQCP_EDGE_CONFIG_VALIDATED ||
	     entry->state ==
		     PQCP_EDGE_CONFIG_COMMITTED) &&
	    pqcp_edge_internal_all_zero(
		    entry->validation_digest,
		    sizeof(entry->validation_digest))) {
		return false;
	}
	if (entry->state ==
		    PQCP_EDGE_CONFIG_COMMITTED &&
	    entry->result != 0) {
		return false;
	}
	if (entry->state ==
		    PQCP_EDGE_CONFIG_ABORTED &&
	    entry->result == 0) {
		return false;
	}
	return true;
}

static void abort_transaction(
	struct pqcp_edge_config_manager *manager,
	struct pqcp_edge_config_transaction *entry,
	int result)
{
	if (!terminal_state(entry->state)) {
		entry->state = PQCP_EDGE_CONFIG_ABORTED;
		entry->result = result == 0 ?
			-ECANCELED : result;
		++manager->abort_count;
	}
}

int pqcp_edge_config_manager_init(
	struct pqcp_edge_config_manager *manager,
	struct pqcp_edge_config_transaction *transactions,
	size_t capacity,
	uint64_t active_generation,
	const uint8_t active_digest[PQCP_EDGE_DIGEST_BYTES])
{
	if (manager == NULL || transactions == NULL ||
	    capacity == 0U || active_generation == 0U ||
	    active_digest == NULL ||
	    pqcp_edge_internal_all_zero(
		    active_digest,
		    PQCP_EDGE_DIGEST_BYTES)) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(transactions, 0,
	       capacity * sizeof(*transactions));
	manager->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	manager->transactions = transactions;
	manager->capacity = capacity;
	manager->next_transaction_id = 1U;
	manager->active_generation = active_generation;
	memcpy(manager->active_digest,
	       active_digest,
	       sizeof(manager->active_digest));
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_edge_config_prepare(
	struct pqcp_edge_config_manager *manager,
	uint64_t base_generation,
	uint64_t target_generation,
	const uint8_t base_digest[PQCP_EDGE_DIGEST_BYTES],
	const uint8_t target_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_config_transaction **transaction)
{
	struct pqcp_edge_config_transaction candidate;
	int index;

	if (manager == NULL || !manager->initialized ||
	    base_generation == 0U ||
	    target_generation <= base_generation ||
	    base_digest == NULL || target_digest == NULL ||
	    now_ms == 0U || expires_at_ms <= now_ms ||
	    pqcp_edge_internal_all_zero(
		    base_digest,
		    PQCP_EDGE_DIGEST_BYTES) ||
	    pqcp_edge_internal_all_zero(
		    target_digest,
		    PQCP_EDGE_DIGEST_BYTES) ||
	    pqcp_edge_internal_equal(
		    base_digest,
		    target_digest,
		    PQCP_EDGE_DIGEST_BYTES)) {
		return -EINVAL;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.base_generation = base_generation;
	candidate.target_generation = target_generation;
	candidate.prepared_at_ms = now_ms;
	candidate.expires_at_ms = expires_at_ms;
	candidate.state = PQCP_EDGE_CONFIG_PREPARED;
	memcpy(candidate.base_digest,
	       base_digest,
	       sizeof(candidate.base_digest));
	memcpy(candidate.target_digest,
	       target_digest,
	       sizeof(candidate.target_digest));
	candidate.occupied = true;
	k_mutex_lock(&manager->lock, K_FOREVER);
	if (base_generation !=
		    manager->active_generation ||
	    !pqcp_edge_internal_equal(
		    base_digest,
		    manager->active_digest,
		    sizeof(manager->active_digest))) {
		k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	if (generation_pending(manager,
			       target_generation)) {
		k_mutex_unlock(&manager->lock);
		return -EINPROGRESS;
	}
	index = free_transaction_index(manager);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	candidate.transaction_id =
		pqcp_edge_internal_next_identifier(
			&manager->next_transaction_id);
	manager->transactions[index] = candidate;
	if (transaction != NULL) {
		*transaction =
			&manager->transactions[index];
	}
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_config_validate(
	struct pqcp_edge_config_manager *manager,
	uint64_t transaction_id,
	const uint8_t validation_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_edge_config_transaction *entry;
	int index;

	if (manager == NULL || !manager->initialized ||
	    transaction_id == 0U ||
	    validation_digest == NULL ||
	    pqcp_edge_internal_all_zero(
		    validation_digest,
		    PQCP_EDGE_DIGEST_BYTES)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = transaction_index(
		manager, transaction_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	entry = &manager->transactions[index];
	if (entry->state !=
	    PQCP_EDGE_CONFIG_PREPARED) {
		k_mutex_unlock(&manager->lock);
		return entry->state ==
			       PQCP_EDGE_CONFIG_VALIDATED ?
			-EALREADY : -EPERM;
	}
	if (now_ms >= entry->expires_at_ms) {
		abort_transaction(manager, entry,
				  -ETIMEDOUT);
		k_mutex_unlock(&manager->lock);
		return -ETIMEDOUT;
	}
	if (entry->base_generation !=
		    manager->active_generation ||
	    !pqcp_edge_internal_equal(
		    entry->base_digest,
		    manager->active_digest,
		    sizeof(manager->active_digest))) {
		abort_transaction(manager, entry,
				  -ESTALE);
		k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	memcpy(entry->validation_digest,
	       validation_digest,
	       sizeof(entry->validation_digest));
	entry->state = PQCP_EDGE_CONFIG_VALIDATED;
	entry->result = 0;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_config_commit(
	struct pqcp_edge_config_manager *manager,
	uint64_t transaction_id,
	uint64_t now_ms)
{
	struct pqcp_edge_config_transaction *entry;
	int index;

	if (manager == NULL || !manager->initialized ||
	    transaction_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = transaction_index(
		manager, transaction_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	entry = &manager->transactions[index];
	if (entry->state !=
	    PQCP_EDGE_CONFIG_VALIDATED) {
		k_mutex_unlock(&manager->lock);
		return entry->state ==
			       PQCP_EDGE_CONFIG_COMMITTED ?
			-EALREADY : -EPERM;
	}
	if (now_ms >= entry->expires_at_ms) {
		abort_transaction(manager, entry,
				  -ETIMEDOUT);
		k_mutex_unlock(&manager->lock);
		return -ETIMEDOUT;
	}
	if (entry->base_generation !=
		    manager->active_generation ||
	    !pqcp_edge_internal_equal(
		    entry->base_digest,
		    manager->active_digest,
		    sizeof(manager->active_digest))) {
		abort_transaction(manager, entry,
				  -ESTALE);
		k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	manager->active_generation =
		entry->target_generation;
	memcpy(manager->active_digest,
	       entry->target_digest,
	       sizeof(manager->active_digest));
	entry->state = PQCP_EDGE_CONFIG_COMMITTED;
	entry->result = 0;
	++manager->commit_count;
	for (size_t other = 0U;
	     other < manager->capacity; ++other) {
		struct pqcp_edge_config_transaction *pending =
			&manager->transactions[other];

		if (other == (size_t)index ||
		    !pending->occupied ||
		    terminal_state(pending->state)) {
			continue;
		}
		abort_transaction(manager, pending,
				  -ESTALE);
	}
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_config_abort(
	struct pqcp_edge_config_manager *manager,
	uint64_t transaction_id,
	int result)
{
	int index;

	if (manager == NULL || !manager->initialized ||
	    transaction_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = transaction_index(
		manager, transaction_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return index;
	}
	if (terminal_state(
		    manager->transactions[index].state)) {
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	abort_transaction(
		manager,
		&manager->transactions[index],
		result);
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_edge_config_tick(
	struct pqcp_edge_config_manager *manager,
	uint64_t now_ms,
	uint32_t *aborted_count)
{
	uint32_t aborted = 0U;

	if (manager == NULL || !manager->initialized) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_edge_config_transaction *entry =
			&manager->transactions[index];

		if (!entry->occupied ||
		    terminal_state(entry->state) ||
		    now_ms < entry->expires_at_ms) {
			continue;
		}
		abort_transaction(manager, entry,
				  -ETIMEDOUT);
		++aborted;
	}
	k_mutex_unlock(&manager->lock);
	if (aborted_count != NULL) {
		*aborted_count = aborted;
	}
	return 0;
}

int pqcp_edge_config_manager_audit(
	struct pqcp_edge_config_manager *manager)
{
	uint64_t committed = 0U;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    manager->transactions == NULL ||
	    manager->capacity == 0U ||
	    manager->next_transaction_id == 0U ||
	    manager->active_generation == 0U ||
	    pqcp_edge_internal_all_zero(
		    manager->active_digest,
		    sizeof(manager->active_digest))) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_edge_config_transaction *entry =
			&manager->transactions[index];

		if (!entry->occupied) {
			continue;
		}
		if (!transaction_shape_valid(entry)) {
			ret = -EBADMSG;
			break;
		}
		if (entry->state ==
		    PQCP_EDGE_CONFIG_COMMITTED) {
			++committed;
			if (entry->target_generation >
			    manager->active_generation) {
				ret = -ESTALE;
				break;
			}
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->transactions[other].
				    occupied &&
			    manager->transactions[other].
				    transaction_id ==
				    entry->transaction_id) {
				ret = -EEXIST;
				break;
			}
			if (manager->transactions[other].
				    occupied &&
			    !terminal_state(entry->state) &&
			    !terminal_state(
				    manager->transactions[other].
					    state) &&
			    manager->transactions[other].
				    target_generation ==
				    entry->target_generation) {
				ret = -EINPROGRESS;
				break;
			}
		}
		if (ret != 0) {
			break;
		}
	}
	if (ret == 0 &&
	    committed > manager->commit_count) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
