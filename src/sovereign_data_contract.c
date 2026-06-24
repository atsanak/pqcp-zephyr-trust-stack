/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Data-sharing contracts with bounded volume, purpose, risk, and protection
 * requirements.
 */

#include "sovereign_privacy_internal.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

static bool contract_valid(
	const struct pqcp_sovereign_data_contract *contract,
	uint64_t now_ms)
{
	return contract != NULL &&
	       pqcp_sovereign_privacy_text_valid(
		       contract->provider_id,
		       sizeof(contract->provider_id)) &&
	       pqcp_sovereign_privacy_text_valid(
		       contract->consumer_id,
		       sizeof(contract->consumer_id)) &&
	       strcmp(contract->provider_id,
		      contract->consumer_id) != 0 &&
	       pqcp_sovereign_privacy_text_valid(
		       contract->dataset_id,
		       sizeof(contract->dataset_id)) &&
	       pqcp_sovereign_privacy_text_valid(
		       contract->purpose, sizeof(contract->purpose)) &&
	       pqcp_sovereign_privacy_text_valid(
		       contract->source_zone,
		       sizeof(contract->source_zone)) &&
	       pqcp_sovereign_privacy_text_valid(
		       contract->destination_zone,
		       sizeof(contract->destination_zone)) &&
	       pqcp_sovereign_privacy_data_class_valid(
		       contract->data_class) &&
	       contract->operation_mask != 0U &&
	       contract->policy_epoch != 0U &&
	       contract->effective_at_ms >= now_ms &&
	       contract->expires_at_ms > contract->effective_at_ms &&
	       contract->maximum_records != 0U &&
	       contract->records_used <= contract->maximum_records &&
	       contract->maximum_bytes != 0U &&
	       contract->bytes_used <= contract->maximum_bytes &&
	       contract->maximum_risk <= 1000U &&
	       !pqcp_sovereign_privacy_digest_zero(
		       contract->terms_digest) &&
	       contract->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
}

static ssize_t contract_index_locked(
	const struct pqcp_sovereign_data_contract_manager *manager,
	uint64_t contract_id)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		if (manager->contracts[index].occupied &&
		    manager->contracts[index].contract_id ==
			    contract_id) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static ssize_t free_contract_index_locked(
	const struct pqcp_sovereign_data_contract_manager *manager)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		if (!manager->contracts[index].occupied) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static bool contract_tuple_alias_locked(
	const struct pqcp_sovereign_data_contract_manager *manager,
	const struct pqcp_sovereign_data_contract *candidate,
	uint64_t ignored_contract_id)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		const struct pqcp_sovereign_data_contract *existing =
			&manager->contracts[index];

		if (!existing->occupied ||
		    existing->contract_id == ignored_contract_id ||
		    existing->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
			continue;
		}
		if (strcmp(existing->provider_id,
			   candidate->provider_id) == 0 &&
		    strcmp(existing->consumer_id,
			   candidate->consumer_id) == 0 &&
		    strcmp(existing->dataset_id,
			   candidate->dataset_id) == 0 &&
		    strcmp(existing->purpose, candidate->purpose) == 0 &&
		    existing->data_class == candidate->data_class &&
		    existing->expires_at_ms > candidate->effective_at_ms &&
		    candidate->expires_at_ms >
			    existing->effective_at_ms) {
			return true;
		}
	}
	return false;
}

int pqcp_sovereign_data_contract_manager_init(
	struct pqcp_sovereign_data_contract_manager *manager,
	struct pqcp_sovereign_data_contract *contracts,
	size_t capacity)
{
	if (manager == NULL || contracts == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(contracts, 0, capacity * sizeof(*contracts));
	manager->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	manager->contracts = contracts;
	manager->capacity = capacity;
	manager->next_contract_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_data_contract_put(
	struct pqcp_sovereign_data_contract_manager *manager,
	const struct pqcp_sovereign_data_contract *contract,
	uint64_t now_ms)
{
	struct pqcp_sovereign_data_contract candidate;
	const struct pqcp_sovereign_data_contract *existing = NULL;
	ssize_t index;

	if (manager == NULL || !manager->initialized ||
	    !contract_valid(contract, now_ms)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	if (contract->contract_id != 0U) {
		index = contract_index_locked(
			manager, contract->contract_id);
	} else {
		index = -1;
	}
	if (index >= 0) {
		existing = &manager->contracts[index];
		if (strcmp(existing->provider_id,
			   contract->provider_id) != 0 ||
		    strcmp(existing->consumer_id,
			   contract->consumer_id) != 0 ||
		    strcmp(existing->dataset_id,
			   contract->dataset_id) != 0 ||
		    existing->data_class != contract->data_class) {
			manager->denial_count++;
			k_mutex_unlock(&manager->lock);
			return -EACCES;
		}
		if (contract->policy_epoch <= existing->policy_epoch ||
		    contract->maximum_records <
			    existing->records_used ||
		    contract->maximum_bytes < existing->bytes_used) {
			manager->denial_count++;
			k_mutex_unlock(&manager->lock);
			return -ESTALE;
		}
	} else {
		index = free_contract_index_locked(manager);
		if (index < 0) {
			manager->denial_count++;
			k_mutex_unlock(&manager->lock);
			return -ENOSPC;
		}
	}
	if (contract_tuple_alias_locked(
		    manager, contract, contract->contract_id)) {
		manager->denial_count++;
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	candidate = *contract;
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	if (candidate.contract_id == 0U) {
		if (manager->next_contract_id == 0U ||
		    manager->next_contract_id == UINT64_MAX) {
			manager->denial_count++;
			k_mutex_unlock(&manager->lock);
			return -EOVERFLOW;
		}
		candidate.contract_id = manager->next_contract_id++;
		candidate.records_used = 0U;
		candidate.bytes_used = 0U;
	} else if (existing != NULL) {
		candidate.records_used = existing->records_used;
		candidate.bytes_used = existing->bytes_used;
	}
	candidate.state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	candidate.occupied = true;
	manager->contracts[index] = candidate;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_data_contract_authorize(
	struct pqcp_sovereign_data_contract_manager *manager,
	uint64_t contract_id,
	const char *provider_id,
	const char *consumer_id,
	const char *dataset_id,
	const char *purpose,
	enum pqcp_sovereign_operation operation,
	uint64_t records,
	uint64_t bytes,
	uint32_t risk_score,
	bool consent_valid,
	bool encrypted,
	uint64_t policy_epoch,
	uint64_t now_ms)
{
	struct pqcp_sovereign_data_contract *contract;
	ssize_t index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    contract_id == 0U ||
	    !pqcp_sovereign_privacy_text_valid(
		    provider_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    consumer_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    dataset_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    purpose, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_operation_valid(operation) ||
	    records == 0U || bytes == 0U || risk_score > 1000U ||
	    policy_epoch == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = contract_index_locked(manager, contract_id);
	if (index < 0) {
		ret = -ENOENT;
		goto out;
	}
	contract = &manager->contracts[index];
	if (contract->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
	    strcmp(contract->provider_id, provider_id) != 0 ||
	    strcmp(contract->consumer_id, consumer_id) != 0 ||
	    strcmp(contract->dataset_id, dataset_id) != 0 ||
	    strcmp(contract->purpose, purpose) != 0) {
		ret = -EACCES;
	} else if (contract->policy_epoch != policy_epoch) {
		ret = -ESTALE;
	} else if (now_ms < contract->effective_at_ms ||
		   now_ms >= contract->expires_at_ms) {
		ret = -ETIME;
	} else if ((contract->operation_mask &
		    PQCP_SOVEREIGN_BIT(operation)) == 0U) {
		ret = -EACCES;
	} else if (risk_score > contract->maximum_risk) {
		ret = -ERANGE;
	} else if (contract->require_consent && !consent_valid) {
		ret = -EACCES;
	} else if (contract->require_encryption && !encrypted) {
		ret = -EACCES;
	} else if (records >
		   contract->maximum_records - contract->records_used ||
		   bytes >
		   contract->maximum_bytes - contract->bytes_used) {
		ret = -EDQUOT;
	} else {
		contract->records_used += records;
		contract->bytes_used += bytes;
		manager->authorize_count++;
	}
out:
	if (ret != 0) {
		manager->denial_count++;
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_data_contract_revoke(
	struct pqcp_sovereign_data_contract_manager *manager,
	uint64_t contract_id)
{
	ssize_t index;

	if (manager == NULL || !manager->initialized ||
	    contract_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = contract_index_locked(manager, contract_id);
	if (index < 0) {
		k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	if (manager->contracts[index].state ==
	    PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
		k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	manager->contracts[index].state =
		PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_data_contract_tick(
	struct pqcp_sovereign_data_contract_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	size_t index;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U; index < manager->capacity; ++index) {
		struct pqcp_sovereign_data_contract *contract =
			&manager->contracts[index];

		if (!contract->occupied ||
		    contract->state !=
			    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    contract->expires_at_ms > now_ms) {
			continue;
		}
		contract->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		expired++;
	}
	*expired_count = expired;
	k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_sovereign_data_contract_manager_audit(
	struct pqcp_sovereign_data_contract_manager *manager)
{
	size_t index;
	size_t other;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    manager->contracts == NULL || manager->capacity == 0U ||
	    manager->next_contract_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (index = 0U; index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_data_contract *contract =
			&manager->contracts[index];

		if (!contract->occupied) {
			continue;
		}
		if (contract->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    contract->contract_id == 0U ||
		    !pqcp_sovereign_privacy_text_valid(
			    contract->provider_id,
			    sizeof(contract->provider_id)) ||
		    !pqcp_sovereign_privacy_text_valid(
			    contract->consumer_id,
			    sizeof(contract->consumer_id)) ||
		    strcmp(contract->provider_id,
			   contract->consumer_id) == 0 ||
		    contract->records_used >
			    contract->maximum_records ||
		    contract->bytes_used > contract->maximum_bytes ||
		    contract->expires_at_ms <=
			    contract->effective_at_ms ||
		    pqcp_sovereign_privacy_digest_zero(
			    contract->terms_digest)) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->contracts[other].occupied &&
			    manager->contracts[other].contract_id ==
				    contract->contract_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
