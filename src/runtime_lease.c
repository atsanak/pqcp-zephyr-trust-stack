/*
 * SPDX-License-Identifier: MIT
 *
 * Fixed-capacity key lease manager.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/runtime_lease.h>

#include "runtime_internal.h"

#define LEASE_REPORT_DOMAIN UINT64_C(0x505143504c534531)

static bool policy_valid(
	const struct pqcp_runtime_lease_policy *policy)
{
	return policy != NULL &&
	       policy->schema_version == PQCP_RUNTIME_SCHEMA_VERSION &&
	       policy->default_duration_ms != 0U &&
	       policy->maximum_duration_ms >=
		       policy->default_duration_ms &&
	       policy->renewal_window_ms <=
		       policy->maximum_duration_ms &&
	       policy->maximum_renewals != 0U &&
	       policy->maximum_uses != 0U;
}

int pqcp_runtime_lease_policy_default(
	struct pqcp_runtime_lease_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	*policy = (struct pqcp_runtime_lease_policy) {
		.schema_version = PQCP_RUNTIME_SCHEMA_VERSION,
		.default_duration_ms = 300000U,
		.maximum_duration_ms = 3600000U,
		.renewal_window_ms = 60000U,
		.maximum_renewals = 8U,
		.maximum_uses = 100000U,
		.destroy_key_on_expiry = true,
		.destroy_key_on_revoke = true,
		.require_same_owner = true,
	};
	return 0;
}

int pqcp_runtime_lease_manager_init(
	struct pqcp_runtime_lease_manager *manager,
	struct pqcp_runtime_key_store *key_store,
	struct pqcp_runtime_key_lease *leases,
	size_t capacity,
	const struct pqcp_runtime_lease_policy *policy)
{
	struct pqcp_runtime_lease_policy effective;

	if (manager == NULL || key_store == NULL ||
	    leases == NULL || capacity == 0U) {
		return -EINVAL;
	}
	if (policy == NULL) {
		if (pqcp_runtime_lease_policy_default(&effective) != 0) {
			return -EINVAL;
		}
		policy = &effective;
	}
	if (!policy_valid(policy) ||
	    pqcp_runtime_key_store_validate(key_store) != 0) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(leases, 0, sizeof(*leases) * capacity);
	manager->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	manager->key_store = key_store;
	manager->leases = leases;
	manager->capacity = capacity;
	manager->policy = *policy;
	manager->next_lease_id = 1U;
	k_mutex_init(&manager->lock);
	return 0;
}

static struct pqcp_runtime_key_lease *find_lease(
	struct pqcp_runtime_lease_manager *manager,
	uint64_t lease_id)
{
	for (size_t index = 0U; index < manager->capacity; ++index) {
		if (manager->leases[index].occupied &&
		    manager->leases[index].lease_id == lease_id) {
			return &manager->leases[index];
		}
	}
	return NULL;
}

static struct pqcp_runtime_key_lease *find_free(
	struct pqcp_runtime_lease_manager *manager)
{
	for (size_t index = 0U; index < manager->capacity; ++index) {
		if (!manager->leases[index].occupied) {
			return &manager->leases[index];
		}
	}
	return NULL;
}

static bool owner_matches(
	const struct pqcp_runtime_lease_manager *manager,
	const struct pqcp_runtime_key_lease *lease,
	const char *owner)
{
	return !manager->policy.require_same_owner ||
	       (owner != NULL &&
		strcmp(lease->owner, owner) == 0);
}

static uint64_t effective_duration(
	const struct pqcp_runtime_lease_policy *policy,
	uint64_t requested_duration_ms)
{
	uint64_t duration = requested_duration_ms != 0U ?
		requested_duration_ms : policy->default_duration_ms;

	return duration > policy->maximum_duration_ms ?
		policy->maximum_duration_ms : duration;
}

int pqcp_runtime_lease_issue(
	struct pqcp_runtime_lease_manager *manager,
	const struct pqcp_runtime_key_handle *key,
	const char *owner,
	uint32_t allowed_usage,
	uint64_t now_ms,
	uint64_t requested_duration_ms,
	struct pqcp_runtime_key_lease **lease)
{
	struct pqcp_runtime_key_metadata metadata;
	struct pqcp_runtime_key_lease *slot;
	uint64_t duration;
	int ret;

	if (manager == NULL || key == NULL || lease == NULL ||
	    !pqcp_runtime_key_handle_is_valid(key) ||
	    !pqcp_runtime_internal_text_valid(
		    owner, PQCP_RUNTIME_LEASE_OWNER_MAX_CHARS) ||
	    allowed_usage == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_key_store_metadata(
		manager->key_store, key, &metadata);
	if (ret != 0 || !metadata.active ||
	    (allowed_usage & ~metadata.usage) != 0U ||
	    (manager->policy.require_same_owner &&
	     strcmp(metadata.owner, owner) != 0)) {
		return ret != 0 ? ret : -EACCES;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	slot = find_free(manager);
	if (slot == NULL) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	duration = effective_duration(
		&manager->policy, requested_duration_ms);
	memset(slot, 0, sizeof(*slot));
	slot->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	slot->lease_id = manager->next_lease_id++;
	if (manager->next_lease_id == 0U) {
		manager->next_lease_id = 1U;
	}
	slot->key = *key;
	slot->state = PQCP_RUNTIME_LEASE_ACTIVE;
	slot->issued_at_ms = now_ms;
	slot->expires_at_ms = now_ms + duration;
	slot->allowed_usage = allowed_usage;
	slot->occupied = true;
	(void)pqcp_runtime_internal_copy_text(
		slot->owner, sizeof(slot->owner), owner);
	manager->issued_count++;
	*lease = slot;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

static int validate_live_lease(
	struct pqcp_runtime_lease_manager *manager,
	struct pqcp_runtime_key_lease *lease,
	const char *owner,
	uint32_t required_usage,
	uint64_t now_ms)
{
	struct pqcp_runtime_key_metadata metadata;
	int ret;

	if (lease == NULL || !lease->occupied ||
	    lease->state != PQCP_RUNTIME_LEASE_ACTIVE ||
	    !owner_matches(manager, lease, owner) ||
	    (required_usage & ~lease->allowed_usage) != 0U) {
		return -EACCES;
	}
	if (now_ms >= lease->expires_at_ms) {
		lease->state = PQCP_RUNTIME_LEASE_EXPIRED;
		return -ETIMEDOUT;
	}
	if (lease->use_count >= manager->policy.maximum_uses) {
		lease->state = PQCP_RUNTIME_LEASE_EXPIRING;
		return -EOVERFLOW;
	}
	ret = pqcp_runtime_key_store_metadata(
		manager->key_store, &lease->key, &metadata);
	if (ret != 0 || !metadata.active) {
		lease->state = PQCP_RUNTIME_LEASE_STALE;
		return ret != 0 ? ret : -ESTALE;
	}
	if (manager->policy.require_same_owner &&
	    strcmp(metadata.owner, lease->owner) != 0) {
		lease->state = PQCP_RUNTIME_LEASE_STALE;
		return -EACCES;
	}
	return 0;
}

int pqcp_runtime_lease_authorize(
	struct pqcp_runtime_lease_manager *manager,
	uint64_t lease_id,
	const char *owner,
	uint32_t required_usage,
	uint64_t now_ms,
	struct pqcp_runtime_key_handle *key)
{
	struct pqcp_runtime_key_lease *lease;
	int ret;

	if (manager == NULL || lease_id == 0U ||
	    required_usage == 0U || now_ms == 0U ||
	    key == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	lease = find_lease(manager, lease_id);
	ret = validate_live_lease(
		manager, lease, owner, required_usage, now_ms);
	if (ret == 0) {
		lease->use_count++;
		lease->last_used_at_ms = now_ms;
		*key = lease->key;
	}
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_runtime_lease_renew(
	struct pqcp_runtime_lease_manager *manager,
	uint64_t lease_id,
	const char *owner,
	uint64_t now_ms,
	uint64_t requested_duration_ms)
{
	struct pqcp_runtime_key_lease *lease;
	uint64_t duration;
	int ret;

	if (manager == NULL || lease_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	lease = find_lease(manager, lease_id);
	if (lease == NULL || !owner_matches(manager, lease, owner) ||
	    (lease->state != PQCP_RUNTIME_LEASE_ACTIVE &&
	     lease->state != PQCP_RUNTIME_LEASE_EXPIRING) ||
	    lease->renewal_count >= manager->policy.maximum_renewals ||
	    now_ms > lease->expires_at_ms ||
	    lease->expires_at_ms - now_ms >
		    manager->policy.renewal_window_ms) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	duration = effective_duration(
		&manager->policy, requested_duration_ms);
	lease->expires_at_ms = now_ms + duration;
	lease->renewal_count++;
	lease->state = PQCP_RUNTIME_LEASE_ACTIVE;
	manager->renewal_count++;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

static int destroy_for_terminal_state(
	struct pqcp_runtime_lease_manager *manager,
	struct pqcp_runtime_key_lease *lease,
	bool destroy)
{
	int ret = 0;

	if (destroy &&
	    pqcp_runtime_key_handle_is_valid(&lease->key)) {
		ret = pqcp_runtime_key_store_destroy(
			manager->key_store, &lease->key);
		if (ret == -ESTALE || ret == -ENOENT) {
			ret = 0;
		}
	}
	return ret;
}

int pqcp_runtime_lease_revoke(
	struct pqcp_runtime_lease_manager *manager,
	uint64_t lease_id,
	const char *owner,
	uint64_t now_ms)
{
	struct pqcp_runtime_key_lease *lease;
	int ret;

	if (manager == NULL || lease_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	lease = find_lease(manager, lease_id);
	if (lease == NULL || !owner_matches(manager, lease, owner) ||
	    lease->state == PQCP_RUNTIME_LEASE_REVOKED) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	lease->state = PQCP_RUNTIME_LEASE_REVOKED;
	lease->expires_at_ms = now_ms;
	ret = destroy_for_terminal_state(
		manager, lease,
		manager->policy.destroy_key_on_revoke);
	manager->revoked_count++;
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}

static int report_hash(
	const struct pqcp_runtime_lease_report *report,
	uint8_t output[PQCP_RUNTIME_DIGEST_BYTES])
{
	uint8_t buffer[80];
	size_t offset = 0U;

	memset(buffer, 0, sizeof(buffer));
	pqcp_runtime_internal_write_u64(
		buffer + offset, LEASE_REPORT_DOMAIN);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->capacity);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->active);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->expiring);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->expired);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->revoked);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->stale);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->destroyed_keys);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->failures);
	offset += 4U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, report->evaluated_at_ms);
	offset += 8U;
	return pqcp_runtime_internal_sha256(buffer, offset, output);
}

int pqcp_runtime_lease_reconcile(
	struct pqcp_runtime_lease_manager *manager,
	uint64_t now_ms,
	struct pqcp_runtime_lease_report *report)
{
	int ret;

	if (manager == NULL || report == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	report->capacity = (uint32_t)manager->capacity;
	report->evaluated_at_ms = now_ms;
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity; ++index) {
		struct pqcp_runtime_key_lease *lease =
			&manager->leases[index];

		if (!lease->occupied) {
			continue;
		}
		if (lease->state == PQCP_RUNTIME_LEASE_ACTIVE &&
		    now_ms >= lease->expires_at_ms) {
			lease->state = PQCP_RUNTIME_LEASE_EXPIRED;
			ret = destroy_for_terminal_state(
				manager, lease,
				manager->policy.destroy_key_on_expiry);
			if (ret == 0) {
				report->destroyed_keys++;
			} else {
				report->failures++;
			}
		} else if (lease->state ==
				   PQCP_RUNTIME_LEASE_ACTIVE &&
			   lease->expires_at_ms - now_ms <=
				   manager->policy.renewal_window_ms) {
			lease->state = PQCP_RUNTIME_LEASE_EXPIRING;
		}
		switch (lease->state) {
		case PQCP_RUNTIME_LEASE_ACTIVE:
			report->active++;
			break;
		case PQCP_RUNTIME_LEASE_EXPIRING:
			report->expiring++;
			break;
		case PQCP_RUNTIME_LEASE_EXPIRED:
			report->expired++;
			break;
		case PQCP_RUNTIME_LEASE_REVOKED:
			report->revoked++;
			break;
		case PQCP_RUNTIME_LEASE_STALE:
			report->stale++;
			break;
		default:
			report->failures++;
			break;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return report_hash(report, report->digest);
}

int pqcp_runtime_lease_manager_audit(
	struct pqcp_runtime_lease_manager *manager)
{
	int ret;

	if (manager == NULL ||
	    manager->schema_version != PQCP_RUNTIME_SCHEMA_VERSION ||
	    manager->key_store == NULL ||
	    manager->leases == NULL || manager->capacity == 0U ||
	    !policy_valid(&manager->policy)) {
		return -EBADMSG;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity; ++index) {
		const struct pqcp_runtime_key_lease *lease =
			&manager->leases[index];

		if (!lease->occupied) {
			continue;
		}
		if (lease->schema_version !=
			    PQCP_RUNTIME_SCHEMA_VERSION ||
		    lease->lease_id == 0U ||
		    !pqcp_runtime_key_handle_is_valid(&lease->key) ||
		    !pqcp_runtime_internal_text_valid(
			    lease->owner, sizeof(lease->owner)) ||
		    lease->issued_at_ms == 0U ||
		    lease->expires_at_ms < lease->issued_at_ms ||
		    lease->state < PQCP_RUNTIME_LEASE_ACTIVE ||
		    lease->state > PQCP_RUNTIME_LEASE_STALE) {
			(void)k_mutex_unlock(&manager->lock);
			return -EBADMSG;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_runtime_lease_report_verify(
	const struct pqcp_runtime_lease_report *report)
{
	uint8_t expected[PQCP_RUNTIME_DIGEST_BYTES];

	if (report == NULL ||
	    report->schema_version != PQCP_RUNTIME_SCHEMA_VERSION ||
	    report->capacity == 0U ||
	    report->active + report->expiring +
			    report->expired + report->revoked +
			    report->stale >
		    report->capacity ||
	    report_hash(report, expected) != 0 ||
	    memcmp(expected, report->digest, sizeof(expected)) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_lease_emit(
	const struct pqcp_runtime_lease_report *report)
{
	char digest_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];

	if (pqcp_runtime_lease_report_verify(report) != 0 ||
	    pqcp_runtime_internal_hex(
		    report->digest, sizeof(report->digest),
		    digest_hex, sizeof(digest_hex)) != 0) {
		return -EBADMSG;
	}
	printk("PQCP_RUNTIME_LEASES capacity=%u active=%u expiring=%u expired=%u revoked=%u stale=%u destroyed=%u failures=%u timestamp=%llu digest=%s\n",
	       report->capacity, report->active,
	       report->expiring, report->expired,
	       report->revoked, report->stale,
	       report->destroyed_keys, report->failures,
	       (unsigned long long)report->evaluated_at_ms,
	       digest_hex);
	return 0;
}
