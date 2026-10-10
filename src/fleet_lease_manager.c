/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Epoch-bound offline authorization leases for disconnected devices.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>

#include "runtime_internal.h"

#define FLEET_LEASE_BODY_BYTES 128U

static bool operation_valid(
	enum pqcp_fleet_operation_type operation)
{
	return operation > PQCP_FLEET_OPERATION_NONE &&
	       operation < PQCP_FLEET_OPERATION_COUNT;
}

static size_t append_u32(
	uint8_t *output,
	size_t offset,
	uint32_t value)
{
	pqcp_runtime_internal_write_u32(output + offset, value);
	return offset + 4U;
}

static size_t append_u64(
	uint8_t *output,
	size_t offset,
	uint64_t value)
{
	pqcp_runtime_internal_write_u64(output + offset, value);
	return offset + 8U;
}

static int lease_digest(
	const struct pqcp_fleet_offline_lease *lease,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[FLEET_LEASE_BODY_BYTES];
	size_t offset = 0U;

	if (lease == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	memcpy(body + offset, "PQCP-FLEET-LEASE-V1", 19U);
	offset += 19U;
	offset = append_u32(
		body, offset, lease->schema_version);
	offset = append_u64(body, offset, lease->lease_id);
	offset = append_u64(
		body, offset, lease->issued_at_ms);
	offset = append_u64(
		body, offset, lease->valid_from_ms);
	offset = append_u64(
		body, offset, lease->expires_at_ms);
	offset = append_u64(
		body, offset, lease->maximum_offline_ms);
	offset = append_u64(
		body, offset, lease->operation_limit);
	offset = append_u32(
		body, offset, lease->capability_mask);
	offset = append_u32(
		body, offset, lease->operation_mask);
	offset = append_u64(
		body, offset, lease->policy_epoch);
	offset = append_u64(
		body, offset, lease->revocation_epoch);
	int ret = pqcp_runtime_internal_sha256(
		body, offset, digest);

	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int lease_validate(
	const struct pqcp_fleet_offline_lease *lease)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (lease == NULL ||
	    lease->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    lease->lease_id == 0U ||
	    lease->issued_at_ms == 0U ||
	    lease->valid_from_ms < lease->issued_at_ms ||
	    lease->expires_at_ms <= lease->valid_from_ms ||
	    lease->maximum_offline_ms == 0U ||
	    lease->maximum_offline_ms >
		    lease->expires_at_ms - lease->valid_from_ms ||
	    lease->operation_limit == 0U ||
	    lease->operation_count > lease->operation_limit ||
	    lease->capability_mask == 0U ||
	    lease->operation_mask == 0U) {
		return -EINVAL;
	}
	ret = lease_digest(lease, digest);
	if (ret == 0 &&
	    memcmp(digest, lease->lease_digest,
		   sizeof(digest)) != 0) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int lease_index(
	const struct pqcp_fleet_lease_manager *manager,
	uint64_t lease_id)
{
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		if (manager->leases[index].lease_id == lease_id &&
		    manager->leases[index].schema_version ==
			    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION) {
			return (int)index;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_lease_manager *manager)
{
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		if (manager->leases[index].schema_version == 0U ||
		    (!manager->leases[index].active &&
		     manager->leases[index].revoked)) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_fleet_lease_manager_init(
	struct pqcp_fleet_lease_manager *manager,
	struct pqcp_fleet_offline_lease *leases,
	size_t capacity)
{
	if (manager == NULL || leases == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(leases, 0, sizeof(*leases) * capacity);
	manager->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	manager->leases = leases;
	manager->capacity = capacity;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_fleet_lease_install(
	struct pqcp_fleet_lease_manager *manager,
	const struct pqcp_fleet_offline_lease *lease,
	uint64_t now_ms)
{
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    lease_validate(lease) != 0 || now_ms == 0U ||
	    now_ms < lease->issued_at_ms ||
	    now_ms >= lease->expires_at_ms ||
	    lease->policy_epoch <
		    manager->latest_policy_epoch ||
	    lease->revocation_epoch <
		    manager->latest_revocation_epoch ||
	    !lease->active || lease->revoked) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = lease_index(manager, lease->lease_id);
	if (index >= 0) {
		const struct pqcp_fleet_offline_lease *existing =
			&manager->leases[index];

		if (memcmp(existing->lease_digest,
			   lease->lease_digest,
			   sizeof(existing->lease_digest)) == 0) {
			(void)k_mutex_unlock(&manager->lock);
			return 0;
		}
		manager->rejected_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -EKEYREJECTED;
	}
	index = free_index(manager);
	if (index < 0) {
		manager->rejected_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	manager->leases[index] = *lease;
	manager->accepted_count++;
	if (lease->policy_epoch > manager->latest_policy_epoch) {
		manager->latest_policy_epoch =
			lease->policy_epoch;
	}
	if (lease->revocation_epoch >
	    manager->latest_revocation_epoch) {
		manager->latest_revocation_epoch =
			lease->revocation_epoch;
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_lease_authorize(
	struct pqcp_fleet_lease_manager *manager,
	uint64_t lease_id,
	enum pqcp_fleet_operation_type operation,
	uint32_t required_capabilities,
	uint64_t now_ms)
{
	struct pqcp_fleet_offline_lease *lease;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    lease_id == 0U || !operation_valid(operation) ||
	    required_capabilities == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = lease_index(manager, lease_id);
	if (index < 0) {
		manager->rejected_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	lease = &manager->leases[index];
	if (!lease->active || lease->revoked ||
	    now_ms < lease->valid_from_ms ||
	    now_ms >= lease->expires_at_ms ||
	    now_ms - lease->valid_from_ms >
		    lease->maximum_offline_ms ||
	    lease->policy_epoch <
		    manager->latest_policy_epoch ||
	    lease->revocation_epoch <
		    manager->latest_revocation_epoch ||
	    (lease->operation_mask &
	     PQCP_FLEET_OPERATION_BIT(operation)) == 0U ||
	    (lease->capability_mask &
	     required_capabilities) != required_capabilities ||
	    lease->operation_count >= lease->operation_limit) {
		manager->rejected_count++;
		if (now_ms >= lease->expires_at_ms ||
		    lease->operation_count >=
			    lease->operation_limit) {
			lease->active = false;
		}
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	lease->operation_count++;
	if (lease->operation_count >= lease->operation_limit) {
		lease->active = false;
	}
	manager->accepted_count++;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_lease_revoke(
	struct pqcp_fleet_lease_manager *manager,
	uint64_t lease_id)
{
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    lease_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = lease_index(manager, lease_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	if (manager->leases[index].revoked) {
		(void)k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	manager->leases[index].active = false;
	manager->leases[index].revoked = true;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_lease_advance_epochs(
	struct pqcp_fleet_lease_manager *manager,
	uint64_t policy_epoch,
	uint64_t revocation_epoch)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    policy_epoch < manager->latest_policy_epoch ||
	    revocation_epoch <
		    manager->latest_revocation_epoch) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	manager->latest_policy_epoch = policy_epoch;
	manager->latest_revocation_epoch = revocation_epoch;
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		struct pqcp_fleet_offline_lease *lease =
			&manager->leases[index];

		if (lease->schema_version == 0U ||
		    !lease->active) {
			continue;
		}
		if (lease->policy_epoch < policy_epoch ||
		    lease->revocation_epoch < revocation_epoch) {
			lease->active = false;
			lease->revoked = true;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_lease_expire(
	struct pqcp_fleet_lease_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		struct pqcp_fleet_offline_lease *lease =
			&manager->leases[index];

		if (lease->active &&
		    (now_ms >= lease->expires_at_ms ||
		     now_ms - lease->valid_from_ms >
			     lease->maximum_offline_ms)) {
			lease->active = false;
			expired++;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_fleet_lease_manager_audit(
	struct pqcp_fleet_lease_manager *manager)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    manager->leases == NULL || manager->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		const struct pqcp_fleet_offline_lease *lease =
			&manager->leases[index];

		if (lease->schema_version == 0U) {
			continue;
		}
		if (lease_validate(lease) != 0 ||
		    lease->policy_epoch >
			    manager->latest_policy_epoch ||
		    lease->revocation_epoch >
			    manager->latest_revocation_epoch ||
		    (lease->active && lease->revoked)) {
			(void)k_mutex_unlock(&manager->lock);
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->leases[other].schema_version != 0U &&
			    manager->leases[other].lease_id ==
				    lease->lease_id) {
				(void)k_mutex_unlock(&manager->lock);
				return -EEXIST;
			}
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}
