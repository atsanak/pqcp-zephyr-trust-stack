/*
 * SPDX-License-Identifier: MIT
 *
 * Tenant-scoped offline authority leases with epoch and operation bounds.
 */

#include "sovereign_continuity_internal.h"

static bool lease_state_valid(
	enum pqcp_sovereign_lease_state state)
{
	return state >= PQCP_SOVEREIGN_LEASE_PENDING &&
	       state <= PQCP_SOVEREIGN_LEASE_STALE;
}

static int lease_index(
	const struct pqcp_sovereign_authority_lease_manager *manager,
	const char *tenant_id,
	const char *lease_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_sovereign_authority_lease *lease =
			&manager->leases[index];

		if (lease->occupied &&
		    strcmp(lease->tenant_id, tenant_id) == 0 &&
		    strcmp(lease->lease_id, lease_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_lease_index(
	const struct pqcp_sovereign_authority_lease_manager *manager)
{
	int oldest_terminal = -1;
	uint64_t oldest_time = UINT64_MAX;

	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_sovereign_authority_lease *lease =
			&manager->leases[index];

		if (!lease->occupied) {
			return (int)index;
		}
		if ((lease->state ==
			     PQCP_SOVEREIGN_LEASE_EXHAUSTED ||
		     lease->state ==
			     PQCP_SOVEREIGN_LEASE_EXPIRED ||
		     lease->state ==
			     PQCP_SOVEREIGN_LEASE_REVOKED ||
		     lease->state ==
			     PQCP_SOVEREIGN_LEASE_STALE) &&
		    lease->issued_at_ms < oldest_time) {
			oldest_time = lease->issued_at_ms;
			oldest_terminal = (int)index;
		}
	}
	return oldest_terminal >= 0 ? oldest_terminal : -ENOSPC;
}

static int validate_lease(
	const struct pqcp_sovereign_authority_lease *lease)
{
	if (lease == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    lease->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    lease->principal_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    lease->lease_id) ||
	    lease->issued_at_ms == 0U ||
	    lease->valid_from_ms < lease->issued_at_ms ||
	    lease->expires_at_ms <= lease->valid_from_ms ||
	    lease->maximum_offline_ms == 0U ||
	    lease->maximum_offline_ms >
		    lease->expires_at_ms -
			    lease->valid_from_ms ||
	    lease->operation_limit == 0U ||
	    lease->operation_count >
		    lease->operation_limit ||
	    lease->operation_mask == 0U ||
	    (lease->operation_mask &
	     ~PQCP_SOVEREIGN_RECOVERY_OP_ALL) != 0U ||
	    lease->policy_epoch == 0U ||
	    lease->revocation_epoch == 0U ||
	    lease->fencing_epoch == 0U ||
	    lease->required_approval_count == 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    lease->plan_digest) ||
	    !pqcp_sovereign_continuity_digest_valid(
		    lease->quorum_authorization_digest)) {
		return -EINVAL;
	}
	return 0;
}

static int update_lease_digest(
	struct pqcp_sovereign_authority_lease_manager *manager,
	struct pqcp_sovereign_authority_lease *lease)
{
	int ret;

	ret = pqcp_sovereign_continuity_digest_lease(
		lease, lease->lease_digest);
	if (ret == 0) {
		memcpy(manager->tail_digest,
		       lease->lease_digest,
		       sizeof(manager->tail_digest));
	}
	return ret;
}

static bool offline_window_valid(
	const struct pqcp_sovereign_authority_lease *lease,
	const struct pqcp_sovereign_lease_use *use)
{
	if (use->disconnected_since_ms == 0U) {
		return true;
	}
	if (!lease->offline_permitted ||
	    use->disconnected_since_ms > use->now_ms) {
		return false;
	}
	return use->now_ms - use->disconnected_since_ms <=
	       lease->maximum_offline_ms;
}

int pqcp_sovereign_authority_lease_manager_init(
	struct pqcp_sovereign_authority_lease_manager *manager,
	struct pqcp_sovereign_authority_lease *leases,
	size_t capacity,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t fencing_epoch)
{
	if (manager == NULL || leases == NULL ||
	    capacity == 0U || policy_epoch == 0U ||
	    revocation_epoch == 0U ||
	    fencing_epoch == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(leases, 0, capacity * sizeof(*leases));
	manager->schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	manager->leases = leases;
	manager->capacity = capacity;
	manager->next_generation = 1U;
	manager->current_policy_epoch = policy_epoch;
	manager->current_revocation_epoch = revocation_epoch;
	manager->current_fencing_epoch = fencing_epoch;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_authority_lease_issue(
	struct pqcp_sovereign_authority_lease_manager *manager,
	const struct pqcp_sovereign_authority_lease *lease)
{
	struct pqcp_sovereign_authority_lease candidate;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized) {
		return -EINVAL;
	}
	ret = validate_lease(lease);
	if (ret != 0) {
		return ret;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	if (lease->policy_epoch !=
		    manager->current_policy_epoch ||
	    lease->revocation_epoch !=
		    manager->current_revocation_epoch ||
	    lease->fencing_epoch !=
		    manager->current_fencing_epoch) {
		manager->rejected_count =
			pqcp_sovereign_continuity_add_u64(
				manager->rejected_count, 1U);
		ret = -ESTALE;
		goto out;
	}
	index = lease_index(
		manager, lease->tenant_id, lease->lease_id);
	if (index >= 0) {
		ret = -EEXIST;
		goto reject;
	}
	if (index != -ENOENT) {
		ret = index;
		goto reject;
	}
	index = free_lease_index(manager);
	if (index < 0) {
		ret = index;
		goto reject;
	}
	candidate = *lease;
	candidate.schema_version =
		PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION;
	candidate.generation =
		pqcp_edge_internal_next_generation(
			&manager->next_generation);
	candidate.state = PQCP_SOVEREIGN_LEASE_PENDING;
	candidate.operation_count = 0U;
	candidate.last_used_at_ms = 0U;
	memcpy(candidate.previous_lease_digest,
	       manager->tail_digest,
	       sizeof(candidate.previous_lease_digest));
	candidate.occupied = true;
	ret = update_lease_digest(manager, &candidate);
	if (ret == 0) {
		manager->leases[index] = candidate;
	}
	goto out;
reject:
	manager->rejected_count =
		pqcp_sovereign_continuity_add_u64(
			manager->rejected_count, 1U);
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_authority_lease_activate(
	struct pqcp_sovereign_authority_lease_manager *manager,
	const char *tenant_id,
	const char *lease_id,
	uint32_t generation,
	uint64_t now_ms)
{
	struct pqcp_sovereign_authority_lease *lease;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(lease_id) ||
	    generation == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = lease_index(manager, tenant_id, lease_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	lease = &manager->leases[index];
	if (lease->generation != generation) {
		ret = -ESTALE;
	} else if (lease->state !=
		   PQCP_SOVEREIGN_LEASE_PENDING) {
		ret = lease->state ==
			      PQCP_SOVEREIGN_LEASE_ACTIVE ?
			-EALREADY : -EPERM;
	} else if (now_ms < lease->valid_from_ms) {
		ret = -EAGAIN;
	} else if (now_ms >= lease->expires_at_ms) {
		lease->state = PQCP_SOVEREIGN_LEASE_EXPIRED;
		ret = -ETIMEDOUT;
	} else if (lease->policy_epoch !=
			   manager->current_policy_epoch ||
		   lease->revocation_epoch !=
			   manager->current_revocation_epoch ||
		   lease->fencing_epoch !=
			   manager->current_fencing_epoch) {
		lease->state = PQCP_SOVEREIGN_LEASE_STALE;
		ret = -ESTALE;
	} else {
		lease->state = PQCP_SOVEREIGN_LEASE_ACTIVE;
		ret = update_lease_digest(manager, lease);
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_authority_lease_use(
	struct pqcp_sovereign_authority_lease_manager *manager,
	const struct pqcp_sovereign_lease_use *use)
{
	struct pqcp_sovereign_authority_lease *lease;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    use == NULL ||
	    !pqcp_sovereign_continuity_text_valid(
		    use->tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    use->principal_id) ||
	    !pqcp_sovereign_continuity_text_valid(
		    use->lease_id) ||
	    use->now_ms == 0U ||
	    use->policy_epoch == 0U ||
	    use->revocation_epoch == 0U ||
	    use->fencing_epoch == 0U ||
	    use->operation == 0U ||
	    (use->operation &
	     (use->operation - 1U)) != 0U ||
	    (use->operation &
	     ~PQCP_SOVEREIGN_RECOVERY_OP_ALL) != 0U ||
	    !pqcp_sovereign_continuity_digest_valid(
		    use->plan_digest) ||
	    !pqcp_sovereign_continuity_digest_valid(
		    use->authorization_digest)) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = lease_index(
		manager, use->tenant_id, use->lease_id);
	if (index < 0) {
		ret = index;
		goto reject;
	}
	lease = &manager->leases[index];
	if (lease->state != PQCP_SOVEREIGN_LEASE_ACTIVE) {
		ret = lease->state ==
			      PQCP_SOVEREIGN_LEASE_EXPIRED ?
			-ETIMEDOUT : -EACCES;
		goto reject;
	}
	if (strcmp(lease->principal_id,
		   use->principal_id) != 0) {
		ret = -EACCES;
		goto reject;
	}
	if (use->now_ms < lease->valid_from_ms ||
	    use->now_ms >= lease->expires_at_ms) {
		lease->state = PQCP_SOVEREIGN_LEASE_EXPIRED;
		ret = -ETIMEDOUT;
		goto reject;
	}
	if (use->policy_epoch !=
		    manager->current_policy_epoch ||
	    use->revocation_epoch !=
		    manager->current_revocation_epoch ||
	    use->fencing_epoch !=
		    manager->current_fencing_epoch ||
	    lease->policy_epoch != use->policy_epoch ||
	    lease->revocation_epoch != use->revocation_epoch ||
	    lease->fencing_epoch != use->fencing_epoch) {
		lease->state = PQCP_SOVEREIGN_LEASE_STALE;
		ret = -ESTALE;
		goto reject;
	}
	if ((lease->operation_mask & use->operation) == 0U) {
		ret = -EACCES;
		goto reject;
	}
	if (!pqcp_sovereign_continuity_digest_equal(
		    lease->plan_digest, use->plan_digest) ||
	    !pqcp_sovereign_continuity_digest_equal(
		    lease->quorum_authorization_digest,
		    use->authorization_digest)) {
		ret = -EKEYREJECTED;
		goto reject;
	}
	if (!offline_window_valid(lease, use)) {
		ret = -ETIME;
		goto reject;
	}
	if (lease->operation_count >=
	    lease->operation_limit) {
		lease->state =
			PQCP_SOVEREIGN_LEASE_EXHAUSTED;
		manager->exhausted_count =
			pqcp_sovereign_continuity_add_u64(
				manager->exhausted_count, 1U);
		ret = -EDQUOT;
		goto reject;
	}
	lease->operation_count =
		pqcp_sovereign_continuity_add_u64(
			lease->operation_count, 1U);
	lease->last_used_at_ms = use->now_ms;
	if (lease->operation_count ==
	    lease->operation_limit) {
		lease->state =
			PQCP_SOVEREIGN_LEASE_EXHAUSTED;
		manager->exhausted_count =
			pqcp_sovereign_continuity_add_u64(
				manager->exhausted_count, 1U);
	}
	ret = update_lease_digest(manager, lease);
	if (ret == 0) {
		manager->accepted_count =
			pqcp_sovereign_continuity_add_u64(
				manager->accepted_count, 1U);
	}
	goto out;
reject:
	manager->rejected_count =
		pqcp_sovereign_continuity_add_u64(
			manager->rejected_count, 1U);
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_authority_lease_revoke(
	struct pqcp_sovereign_authority_lease_manager *manager,
	const char *tenant_id,
	const char *lease_id,
	uint32_t generation,
	uint64_t now_ms)
{
	struct pqcp_sovereign_authority_lease *lease;
	int index;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    !pqcp_sovereign_continuity_text_valid(tenant_id) ||
	    !pqcp_sovereign_continuity_text_valid(lease_id) ||
	    generation == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	index = lease_index(manager, tenant_id, lease_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	lease = &manager->leases[index];
	if (lease->generation != generation) {
		ret = -ESTALE;
	} else if (lease->state ==
		   PQCP_SOVEREIGN_LEASE_REVOKED) {
		ret = -EALREADY;
	} else if (lease->state ==
		   PQCP_SOVEREIGN_LEASE_EXPIRED) {
		ret = -ETIMEDOUT;
	} else {
		lease->state = PQCP_SOVEREIGN_LEASE_REVOKED;
		lease->last_used_at_ms = now_ms;
		ret = update_lease_digest(manager, lease);
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_authority_lease_update_epochs(
	struct pqcp_sovereign_authority_lease_manager *manager,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t fencing_epoch)
{
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    policy_epoch == 0U || revocation_epoch == 0U ||
	    fencing_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	if (policy_epoch < manager->current_policy_epoch ||
	    revocation_epoch <
		    manager->current_revocation_epoch ||
	    fencing_epoch <
		    manager->current_fencing_epoch) {
		ret = -ESTALE;
		goto out;
	}
	manager->current_policy_epoch = policy_epoch;
	manager->current_revocation_epoch =
		revocation_epoch;
	manager->current_fencing_epoch = fencing_epoch;
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_sovereign_authority_lease *lease =
			&manager->leases[index];

		if (!lease->occupied ||
		    lease->state ==
			    PQCP_SOVEREIGN_LEASE_REVOKED ||
		    lease->state ==
			    PQCP_SOVEREIGN_LEASE_EXPIRED ||
		    lease->state ==
			    PQCP_SOVEREIGN_LEASE_EXHAUSTED) {
			continue;
		}
		if (lease->policy_epoch != policy_epoch ||
		    lease->revocation_epoch !=
			    revocation_epoch ||
		    lease->fencing_epoch != fencing_epoch) {
			lease->state =
				PQCP_SOVEREIGN_LEASE_STALE;
			ret = update_lease_digest(manager, lease);
			if (ret != 0) {
				break;
			}
		}
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_sovereign_authority_lease_expire(
	struct pqcp_sovereign_authority_lease_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_sovereign_authority_lease *lease =
			&manager->leases[index];

		if (!lease->occupied ||
		    lease->expires_at_ms > now_ms ||
		    lease->state ==
			    PQCP_SOVEREIGN_LEASE_EXPIRED ||
		    lease->state ==
			    PQCP_SOVEREIGN_LEASE_REVOKED) {
			continue;
		}
		lease->state = PQCP_SOVEREIGN_LEASE_EXPIRED;
		ret = update_lease_digest(manager, lease);
		if (ret != 0) {
			break;
		}
		++expired;
	}
	k_mutex_unlock(&manager->lock);
	*expired_count = expired;
	return ret;
}

int pqcp_sovereign_authority_lease_manager_audit(
	struct pqcp_sovereign_authority_lease_manager *manager)
{
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES];
	int ret = 0;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
	    manager->leases == NULL || manager->capacity == 0U ||
	    manager->current_policy_epoch == 0U ||
	    manager->current_revocation_epoch == 0U ||
	    manager->current_fencing_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&manager->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < manager->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_authority_lease *lease =
			&manager->leases[index];

		if (!lease->occupied) {
			continue;
		}
		if (lease->schema_version !=
			    PQCP_SOVEREIGN_CONTINUITY_SCHEMA_VERSION ||
		    lease->generation == 0U ||
		    validate_lease(lease) != 0 ||
		    !lease_state_valid(lease->state) ||
		    !pqcp_sovereign_continuity_digest_valid(
			    lease->lease_digest) ||
		    (lease->state ==
			     PQCP_SOVEREIGN_LEASE_ACTIVE &&
		     (lease->policy_epoch !=
			      manager->current_policy_epoch ||
		      lease->revocation_epoch !=
			      manager->current_revocation_epoch ||
		      lease->fencing_epoch !=
			      manager->current_fencing_epoch))) {
			ret = -EBADMSG;
			break;
		}
		ret = pqcp_sovereign_continuity_digest_lease(
			lease, digest);
		if (ret == 0 &&
		    !pqcp_sovereign_continuity_digest_equal(
			    digest, lease->lease_digest)) {
			ret = -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity && ret == 0;
		     ++other) {
			const struct pqcp_sovereign_authority_lease *peer =
				&manager->leases[other];

			if (peer->occupied &&
			    strcmp(lease->tenant_id,
				   peer->tenant_id) == 0 &&
			    strcmp(lease->lease_id,
				   peer->lease_id) == 0) {
				ret = -EEXIST;
			}
		}
	}
	k_mutex_unlock(&manager->lock);
	return ret;
}
