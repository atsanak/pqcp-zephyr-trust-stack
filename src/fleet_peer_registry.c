/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Gateway peer registry with monotonic trust and session admission.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>
#include <pqcp_zephyr/errno.h>

#include "runtime_internal.h"

static bool state_valid(enum pqcp_fleet_peer_state state)
{
	return state >= PQCP_FLEET_PEER_ACTIVE &&
	       state <= PQCP_FLEET_PEER_REVOKED;
}

static bool digest_zero(
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static int peer_validate(
	const struct pqcp_fleet_peer_record *peer)
{
	if (peer == NULL ||
	    peer->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    !pqcp_runtime_internal_text_valid(
		    peer->device_id, sizeof(peer->device_id)) ||
	    !pqcp_runtime_internal_text_valid(
		    peer->domain_id, sizeof(peer->domain_id)) ||
	    !pqcp_runtime_internal_text_valid(
		    peer->product_class,
		    sizeof(peer->product_class)) ||
	    digest_zero(peer->credential_fingerprint) ||
	    peer->credential_epoch == 0U ||
	    peer->first_seen_ms == 0U ||
	    peer->last_seen_ms < peer->first_seen_ms ||
	    peer->maximum_sessions == 0U ||
	    peer->active_sessions > peer->maximum_sessions ||
	    peer->trust_score > 1000U ||
	    !state_valid(peer->state)) {
		return -EINVAL;
	}
	return 0;
}

static int peer_index(
	const struct pqcp_fleet_peer_registry *registry,
	const char *device_id)
{
	for (size_t index = 0U; index < registry->capacity;
	     ++index) {
		if (registry->peers[index].state !=
			    PQCP_FLEET_PEER_EMPTY &&
		    strcmp(registry->peers[index].device_id,
			   device_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_peer_registry *registry)
{
	for (size_t index = 0U; index < registry->capacity;
	     ++index) {
		if (registry->peers[index].state ==
		    PQCP_FLEET_PEER_EMPTY) {
			return (int)index;
		}
	}
	return -1;
}

static uint32_t next_generation(
	struct pqcp_fleet_peer_registry *registry)
{
	registry->next_generation++;
	if (registry->next_generation == 0U) {
		registry->next_generation++;
	}
	return registry->next_generation;
}

int pqcp_fleet_peer_registry_init(
	struct pqcp_fleet_peer_registry *registry,
	struct pqcp_fleet_peer_record *peers,
	size_t capacity)
{
	if (registry == NULL || peers == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(peers, 0, sizeof(*peers) * capacity);
	registry->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	registry->peers = peers;
	registry->capacity = capacity;
	k_mutex_init(&registry->lock);
	registry->initialized = true;
	return 0;
}

int pqcp_fleet_peer_upsert(
	struct pqcp_fleet_peer_registry *registry,
	const struct pqcp_fleet_peer_record *peer,
	uint64_t now_ms)
{
	struct pqcp_fleet_peer_record *destination;
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    peer_validate(peer) != 0 || now_ms == 0U ||
	    peer->last_seen_ms > now_ms ||
	    peer->state == PQCP_FLEET_PEER_REVOKED) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = peer_index(registry, peer->device_id);
	if (index < 0) {
		index = free_index(registry);
		if (index < 0) {
			registry->rejection_count++;
			(void)k_mutex_unlock(&registry->lock);
			return -ENOSPC;
		}
		destination = &registry->peers[index];
		*destination = *peer;
		destination->generation =
			next_generation(registry);
		destination->active_sessions = 0U;
		registry->admission_count++;
		(void)k_mutex_unlock(&registry->lock);
		return 0;
	}
	destination = &registry->peers[index];
	if (destination->state == PQCP_FLEET_PEER_REVOKED ||
	    peer->credential_epoch <
		    destination->credential_epoch ||
	    peer->policy_epoch < destination->policy_epoch ||
	    peer->revocation_epoch <
		    destination->revocation_epoch) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return -ESTALE;
	}
	if (peer->credential_epoch ==
		    destination->credential_epoch &&
	    memcmp(peer->credential_fingerprint,
		   destination->credential_fingerprint,
		   PQCP_FLEET_DIGEST_BYTES) != 0) {
		destination->state =
			PQCP_FLEET_PEER_QUARANTINED;
		registry->quarantine_count++;
		(void)k_mutex_unlock(&registry->lock);
		return -EKEYREJECTED;
	}
	const uint32_t active_sessions =
		destination->active_sessions;
	const uint64_t first_seen = destination->first_seen_ms;
	const uint32_t generation = destination->generation;

	*destination = *peer;
	destination->active_sessions = active_sessions;
	destination->first_seen_ms = first_seen;
	destination->generation = generation;
	if (destination->active_sessions >
	    destination->maximum_sessions) {
		destination->state =
			PQCP_FLEET_PEER_DEGRADED;
	}
	(void)k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_fleet_peer_observe(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	bool success,
	uint64_t now_ms)
{
	struct pqcp_fleet_peer_record *peer;
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    device_id == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = peer_index(registry, device_id);
	if (index < 0) {
		(void)k_mutex_unlock(&registry->lock);
		return -ENOENT;
	}
	peer = &registry->peers[index];
	if (peer->state == PQCP_FLEET_PEER_REVOKED) {
		(void)k_mutex_unlock(&registry->lock);
		return -EKEYREVOKED;
	}
	peer->last_seen_ms = now_ms;
	if (success) {
		peer->consecutive_failures = 0U;
		if (peer->trust_score <= 990U) {
			peer->trust_score += 10U;
		} else {
			peer->trust_score = 1000U;
		}
		if (peer->state == PQCP_FLEET_PEER_DEGRADED &&
		    peer->trust_score >= 700U) {
			peer->state = PQCP_FLEET_PEER_ACTIVE;
		}
	} else {
		if (peer->consecutive_failures != UINT32_MAX) {
			peer->consecutive_failures++;
		}
		if (peer->trust_score >= 50U) {
			peer->trust_score -= 50U;
		} else {
			peer->trust_score = 0U;
		}
		if (peer->consecutive_failures >= 8U ||
		    peer->trust_score < 200U) {
			peer->state =
				PQCP_FLEET_PEER_QUARANTINED;
			peer->quarantine_until_ms =
				now_ms + 60000U;
			registry->quarantine_count++;
		} else if (peer->consecutive_failures >= 3U) {
			peer->state =
				PQCP_FLEET_PEER_DEGRADED;
		}
	}
	(void)k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_fleet_peer_open_session(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_peer_record *peer;
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    device_id == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = peer_index(registry, device_id);
	if (index < 0) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return -ENOENT;
	}
	peer = &registry->peers[index];
	if (peer->state == PQCP_FLEET_PEER_QUARANTINED &&
	    now_ms >= peer->quarantine_until_ms &&
	    peer->trust_score >= 500U) {
		peer->state = PQCP_FLEET_PEER_DEGRADED;
		peer->quarantine_until_ms = 0U;
	}
	if (peer->state != PQCP_FLEET_PEER_ACTIVE &&
	    peer->state != PQCP_FLEET_PEER_DEGRADED) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return -EACCES;
	}
	if (peer->active_sessions >= peer->maximum_sessions) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return -EDQUOT;
	}
	peer->active_sessions++;
	peer->last_seen_ms = now_ms;
	registry->admission_count++;
	(void)k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_fleet_peer_close_session(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id)
{
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    device_id == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = peer_index(registry, device_id);
	if (index < 0) {
		(void)k_mutex_unlock(&registry->lock);
		return -ENOENT;
	}
	if (registry->peers[index].active_sessions == 0U) {
		(void)k_mutex_unlock(&registry->lock);
		return -EALREADY;
	}
	registry->peers[index].active_sessions--;
	(void)k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_fleet_peer_quarantine(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	uint64_t until_ms)
{
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    device_id == NULL || until_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = peer_index(registry, device_id);
	if (index < 0) {
		(void)k_mutex_unlock(&registry->lock);
		return -ENOENT;
	}
	registry->peers[index].state =
		PQCP_FLEET_PEER_QUARANTINED;
	registry->peers[index].quarantine_until_ms = until_ms;
	registry->quarantine_count++;
	(void)k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_fleet_peer_release(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	uint64_t now_ms)
{
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    device_id == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = peer_index(registry, device_id);
	if (index < 0) {
		(void)k_mutex_unlock(&registry->lock);
		return -ENOENT;
	}
	struct pqcp_fleet_peer_record *peer =
		&registry->peers[index];

	if (peer->state != PQCP_FLEET_PEER_QUARANTINED ||
	    now_ms < peer->quarantine_until_ms ||
	    peer->trust_score < 500U) {
		(void)k_mutex_unlock(&registry->lock);
		return -EACCES;
	}
	peer->state = PQCP_FLEET_PEER_DEGRADED;
	peer->quarantine_until_ms = 0U;
	peer->consecutive_failures = 0U;
	(void)k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_fleet_peer_find(
	struct pqcp_fleet_peer_registry *registry,
	const char *device_id,
	struct pqcp_fleet_peer_record *peer)
{
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    device_id == NULL || peer == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = peer_index(registry, device_id);
	if (index >= 0) {
		*peer = registry->peers[index];
	}
	(void)k_mutex_unlock(&registry->lock);
	return index >= 0 ? 0 : -ENOENT;
}

int pqcp_fleet_peer_registry_audit(
	struct pqcp_fleet_peer_registry *registry)
{
	int ret;

	if (registry == NULL || !registry->initialized ||
	    registry->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    registry->peers == NULL || registry->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < registry->capacity;
	     ++index) {
		const struct pqcp_fleet_peer_record *peer =
			&registry->peers[index];

		if (peer->state == PQCP_FLEET_PEER_EMPTY) {
			continue;
		}
		if (peer_validate(peer) != 0 ||
		    peer->generation == 0U) {
			(void)k_mutex_unlock(&registry->lock);
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < registry->capacity; ++other) {
			if (registry->peers[other].state !=
				    PQCP_FLEET_PEER_EMPTY &&
			    strcmp(registry->peers[other].device_id,
				   peer->device_id) == 0) {
				(void)k_mutex_unlock(&registry->lock);
				return -EEXIST;
			}
		}
	}
	(void)k_mutex_unlock(&registry->lock);
	return 0;
}
