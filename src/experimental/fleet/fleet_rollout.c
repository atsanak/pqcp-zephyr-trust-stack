/*
 * SPDX-License-Identifier: MIT
 *
 * Deterministic cohort assignment and measured rollout promotion.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>

#include "runtime_internal.h"

static bool state_valid(enum pqcp_fleet_rollout_state state)
{
	return state >= PQCP_FLEET_ROLLOUT_EMPTY &&
	       state <= PQCP_FLEET_ROLLOUT_ABORTED;
}

static bool seed_zero(
	const uint8_t seed[PQCP_FLEET_ROLLOUT_SEED_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_ROLLOUT_SEED_BYTES; ++index) {
		aggregate |= seed[index];
	}
	return aggregate == 0U;
}

static int campaign_validate(
	const struct pqcp_fleet_rollout_campaign *campaign)
{
	if (campaign == NULL ||
	    campaign->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    campaign->campaign_id == 0U ||
	    !pqcp_runtime_internal_text_valid(
		    campaign->component_id,
		    sizeof(campaign->component_id)) ||
	    campaign->target_version == 0U ||
	    campaign->cohort_percent_basis_points == 0U ||
	    campaign->cohort_percent_basis_points > 10000U ||
	    campaign->minimum_success_basis_points > 10000U ||
	    campaign->maximum_failure_basis_points > 10000U ||
	    campaign->minimum_success_basis_points +
		    campaign->maximum_failure_basis_points >
		    10000U ||
	    campaign->starts_at_ms == 0U ||
	    campaign->promotion_not_before_ms <
		    campaign->starts_at_ms ||
	    campaign->deadline_ms <=
		    campaign->promotion_not_before_ms ||
	    seed_zero(campaign->cohort_seed) ||
	    !state_valid(campaign->state) ||
	    campaign->state == PQCP_FLEET_ROLLOUT_EMPTY) {
		return -EINVAL;
	}
	if (campaign->successful_devices +
		    campaign->failed_devices +
		    campaign->pending_devices !=
	    campaign->assigned_devices) {
		return -EINVAL;
	}
	return 0;
}

static int campaign_index(
	const struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id)
{
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		if (manager->campaigns[index].occupied &&
		    manager->campaigns[index].campaign_id ==
			    campaign_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_rollout_manager *manager)
{
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		if (!manager->campaigns[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_fleet_rollout_manager_init(
	struct pqcp_fleet_rollout_manager *manager,
	struct pqcp_fleet_rollout_campaign *campaigns,
	size_t capacity)
{
	if (manager == NULL || campaigns == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(campaigns, 0, sizeof(*campaigns) * capacity);
	manager->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	manager->campaigns = campaigns;
	manager->capacity = capacity;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_fleet_rollout_create(
	struct pqcp_fleet_rollout_manager *manager,
	const struct pqcp_fleet_rollout_campaign *campaign)
{
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    campaign_validate(campaign) != 0 ||
	    campaign->state != PQCP_FLEET_ROLLOUT_PLANNED ||
	    campaign->assigned_devices != 0U ||
	    campaign->occupied) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (campaign_index(manager, campaign->campaign_id) >= 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -EEXIST;
	}
	index = free_index(manager);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	manager->campaigns[index] = *campaign;
	manager->campaigns[index].occupied = true;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

static int cohort_for_device(
	const struct pqcp_fleet_rollout_campaign *campaign,
	const char *device_id,
	uint32_t *cohort)
{
	const uint8_t *parts[3];
	size_t lengths[3];
	uint8_t version[8];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	const size_t device_length = strnlen(
		device_id, PQCP_FLEET_ID_MAX_CHARS);
	int ret;

	if (device_length == 0U ||
	    device_length >= PQCP_FLEET_ID_MAX_CHARS) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u64(
		version, campaign->target_version);
	parts[0] = campaign->cohort_seed;
	lengths[0] = sizeof(campaign->cohort_seed);
	parts[1] = (const uint8_t *)device_id;
	lengths[1] = device_length;
	parts[2] = version;
	lengths[2] = sizeof(version);
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, 3U, digest);
	if (ret == 0) {
		*cohort =
			pqcp_runtime_internal_read_u32(digest) %
			10000U;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_fleet_rollout_assign(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id,
	const char *device_id,
	bool *assigned,
	uint32_t *cohort_value)
{
	struct pqcp_fleet_rollout_campaign *campaign;
	uint32_t cohort;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    campaign_id == 0U || device_id == NULL ||
	    assigned == NULL || cohort_value == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = campaign_index(manager, campaign_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	campaign = &manager->campaigns[index];
	if (campaign->state != PQCP_FLEET_ROLLOUT_PLANNED &&
	    campaign->state != PQCP_FLEET_ROLLOUT_ACTIVE) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	ret = cohort_for_device(campaign, device_id, &cohort);
	if (ret == 0) {
		*cohort_value = cohort;
		*assigned =
			cohort <
			campaign->cohort_percent_basis_points;
		if (*assigned) {
			campaign->assigned_devices++;
			campaign->pending_devices++;
		}
		manager->decision_count++;
	}
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_fleet_rollout_record(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id,
	bool success)
{
	struct pqcp_fleet_rollout_campaign *campaign;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    campaign_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = campaign_index(manager, campaign_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	campaign = &manager->campaigns[index];
	if ((campaign->state != PQCP_FLEET_ROLLOUT_ACTIVE &&
	     campaign->state != PQCP_FLEET_ROLLOUT_DRAINING) ||
	    campaign->pending_devices == 0U) {
		(void)k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	campaign->pending_devices--;
	if (success) {
		campaign->successful_devices++;
	} else {
		campaign->failed_devices++;
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

static uint32_t basis_points(
	uint32_t numerator,
	uint32_t denominator)
{
	if (denominator == 0U) {
		return 0U;
	}
	return (uint32_t)(((uint64_t)numerator * 10000U) /
			  denominator);
}

int pqcp_fleet_rollout_tick(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || changed_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		struct pqcp_fleet_rollout_campaign *campaign =
			&manager->campaigns[index];
		uint32_t completed;
		uint32_t success_rate;
		uint32_t failure_rate;

		if (!campaign->occupied ||
		    campaign->state ==
			    PQCP_FLEET_ROLLOUT_COMPLETED ||
		    campaign->state ==
			    PQCP_FLEET_ROLLOUT_ABORTED ||
		    campaign->state ==
			    PQCP_FLEET_ROLLOUT_PAUSED) {
			continue;
		}
		if (now_ms >= campaign->deadline_ms) {
			campaign->state =
				PQCP_FLEET_ROLLOUT_ABORTED;
			changed++;
			continue;
		}
		if (campaign->state ==
			    PQCP_FLEET_ROLLOUT_PLANNED &&
		    now_ms >= campaign->starts_at_ms) {
			campaign->state =
				PQCP_FLEET_ROLLOUT_ACTIVE;
			changed++;
		}
		completed = campaign->successful_devices +
			    campaign->failed_devices;
		success_rate = basis_points(
			campaign->successful_devices, completed);
		failure_rate = basis_points(
			campaign->failed_devices, completed);
		if (campaign->state ==
			    PQCP_FLEET_ROLLOUT_ACTIVE &&
		    completed != 0U &&
		    now_ms >= campaign->promotion_not_before_ms) {
			if (failure_rate >
			    campaign->maximum_failure_basis_points) {
				campaign->state =
					PQCP_FLEET_ROLLOUT_ABORTED;
				changed++;
			} else if (success_rate >=
				   campaign->
					   minimum_success_basis_points) {
				campaign->state =
					PQCP_FLEET_ROLLOUT_PROMOTED;
				changed++;
			}
		}
		if (campaign->state ==
		    PQCP_FLEET_ROLLOUT_PROMOTED) {
			campaign->state =
				PQCP_FLEET_ROLLOUT_DRAINING;
			changed++;
		}
		if (campaign->state ==
			    PQCP_FLEET_ROLLOUT_DRAINING &&
		    campaign->pending_devices == 0U) {
			campaign->state =
				PQCP_FLEET_ROLLOUT_COMPLETED;
			changed++;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	*changed_count = changed;
	return 0;
}

static int set_pause_state(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id,
	bool paused)
{
	struct pqcp_fleet_rollout_campaign *campaign;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    campaign_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = campaign_index(manager, campaign_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	campaign = &manager->campaigns[index];
	if (paused) {
		if (campaign->state !=
			    PQCP_FLEET_ROLLOUT_ACTIVE) {
			ret = -EACCES;
		} else {
			campaign->state =
				PQCP_FLEET_ROLLOUT_PAUSED;
			ret = 0;
		}
	} else {
		if (campaign->state !=
			    PQCP_FLEET_ROLLOUT_PAUSED) {
			ret = -EACCES;
		} else {
			campaign->state =
				PQCP_FLEET_ROLLOUT_ACTIVE;
			ret = 0;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_fleet_rollout_pause(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id)
{
	return set_pause_state(manager, campaign_id, true);
}

int pqcp_fleet_rollout_resume(
	struct pqcp_fleet_rollout_manager *manager,
	uint64_t campaign_id)
{
	return set_pause_state(manager, campaign_id, false);
}

int pqcp_fleet_rollout_audit(
	struct pqcp_fleet_rollout_manager *manager)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    manager->campaigns == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		const struct pqcp_fleet_rollout_campaign *campaign =
			&manager->campaigns[index];

		if (!campaign->occupied) {
			continue;
		}
		if (campaign_validate(campaign) != 0) {
			(void)k_mutex_unlock(&manager->lock);
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->campaigns[other].occupied &&
			    manager->campaigns[other].campaign_id ==
				    campaign->campaign_id) {
				(void)k_mutex_unlock(&manager->lock);
				return -EEXIST;
			}
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}
