/*
 * SPDX-License-Identifier: MIT
 *
 * Explicit, evidence-chained fleet recovery state machine.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>

#include "runtime_internal.h"

static bool state_valid(enum pqcp_fleet_recovery_state state)
{
	return state >= PQCP_FLEET_RECOVERY_IDLE &&
	       state <= PQCP_FLEET_RECOVERY_LOCKED;
}

static bool reason_valid(enum pqcp_fleet_recovery_reason reason)
{
	return reason >
		       PQCP_FLEET_RECOVERY_REASON_NONE &&
	       reason <=
		       PQCP_FLEET_RECOVERY_OPERATOR_REQUEST;
}

static bool all_zero(const uint8_t *value, size_t length)
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate == 0U;
}

int pqcp_fleet_recovery_manager_init(
	struct pqcp_fleet_recovery_manager *manager,
	uint32_t maximum_attempts,
	uint32_t required_steps)
{
	if (manager == NULL || maximum_attempts == 0U ||
	    required_steps == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	manager->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	manager->state = PQCP_FLEET_RECOVERY_IDLE;
	manager->maximum_attempts = maximum_attempts;
	manager->required_steps = required_steps;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_fleet_recovery_authorize(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t session_id,
	enum pqcp_fleet_recovery_reason reason,
	const uint8_t authorization_digest[
		PQCP_FLEET_RECOVERY_AUTH_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    session_id == 0U || !reason_valid(reason) ||
	    authorization_digest == NULL ||
	    all_zero(authorization_digest,
		     PQCP_FLEET_RECOVERY_AUTH_BYTES) ||
	    now_ms == 0U || expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (manager->state == PQCP_FLEET_RECOVERY_LOCKED) {
		if (now_ms < manager->cooldown_until_ms) {
			(void)k_mutex_unlock(&manager->lock);
			return -EACCES;
		}
		manager->state = PQCP_FLEET_RECOVERY_IDLE;
		manager->attempt_count = 0U;
	}
	if (manager->state != PQCP_FLEET_RECOVERY_IDLE &&
	    manager->state != PQCP_FLEET_RECOVERY_COMPLETE) {
		(void)k_mutex_unlock(&manager->lock);
		return -EBUSY;
	}
	manager->state = PQCP_FLEET_RECOVERY_AUTHORIZED;
	manager->reason = reason;
	manager->session_id = session_id;
	manager->authorized_at_ms = now_ms;
	manager->expires_at_ms = expires_at_ms;
	manager->completed_steps = 0U;
	memset(manager->evidence_digest, 0,
	       sizeof(manager->evidence_digest));
	memcpy(manager->authorization_digest,
	       authorization_digest,
	       sizeof(manager->authorization_digest));
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_recovery_enter(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t now_ms)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (manager->state !=
	    PQCP_FLEET_RECOVERY_AUTHORIZED) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	if (now_ms > manager->expires_at_ms) {
		manager->state = PQCP_FLEET_RECOVERY_IDLE;
		(void)k_mutex_unlock(&manager->lock);
		return -ETIMEDOUT;
	}
	if (manager->attempt_count >= manager->maximum_attempts) {
		manager->state = PQCP_FLEET_RECOVERY_LOCKED;
		(void)k_mutex_unlock(&manager->lock);
		return -EDQUOT;
	}
	manager->attempt_count++;
	manager->state = PQCP_FLEET_RECOVERY_ACTIVE;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

static int evidence_chain(
	const struct pqcp_fleet_recovery_manager *manager,
	uint32_t step,
	const uint8_t *evidence,
	size_t evidence_length,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	const uint8_t *parts[4];
	size_t lengths[4];
	uint8_t step_encoded[4];
	uint8_t session_encoded[8];

	pqcp_runtime_internal_write_u32(step_encoded, step);
	pqcp_runtime_internal_write_u64(
		session_encoded, manager->session_id);
	parts[0] = manager->evidence_digest;
	lengths[0] = sizeof(manager->evidence_digest);
	parts[1] = session_encoded;
	lengths[1] = sizeof(session_encoded);
	parts[2] = step_encoded;
	lengths[2] = sizeof(step_encoded);
	parts[3] = evidence;
	lengths[3] = evidence_length;
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, 4U, digest);
}

int pqcp_fleet_recovery_step(
	struct pqcp_fleet_recovery_manager *manager,
	uint32_t step,
	const uint8_t *evidence,
	size_t evidence_length,
	uint64_t now_ms)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (manager == NULL || !manager->initialized ||
	    step == 0U || (step & (step - 1U)) != 0U ||
	    (evidence == NULL && evidence_length != 0U) ||
	    evidence_length == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (manager->state != PQCP_FLEET_RECOVERY_ACTIVE ||
	    (step & manager->required_steps) == 0U) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	if (now_ms > manager->expires_at_ms) {
		(void)k_mutex_unlock(&manager->lock);
		return -ETIMEDOUT;
	}
	if ((manager->completed_steps & step) != 0U) {
		(void)k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	ret = evidence_chain(
		manager, step, evidence, evidence_length, digest);
	if (ret == 0) {
		memcpy(manager->evidence_digest, digest,
		       sizeof(manager->evidence_digest));
		manager->completed_steps |= step;
	}
	(void)k_mutex_unlock(&manager->lock);
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_fleet_recovery_validate(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t now_ms)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (manager->state != PQCP_FLEET_RECOVERY_ACTIVE) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	if (now_ms > manager->expires_at_ms) {
		(void)k_mutex_unlock(&manager->lock);
		return -ETIMEDOUT;
	}
	if ((manager->completed_steps &
	     manager->required_steps) != manager->required_steps ||
	    all_zero(manager->evidence_digest,
		     sizeof(manager->evidence_digest))) {
		(void)k_mutex_unlock(&manager->lock);
		return -EINPROGRESS;
	}
	manager->state = PQCP_FLEET_RECOVERY_VALIDATING;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_recovery_complete(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t now_ms,
	uint64_t cooldown_ms)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || cooldown_ms == 0U ||
	    UINT64_MAX - now_ms < cooldown_ms) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (manager->state !=
	    PQCP_FLEET_RECOVERY_VALIDATING) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	manager->cooldown_until_ms = now_ms + cooldown_ms;
	manager->state = PQCP_FLEET_RECOVERY_COMPLETE;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_recovery_abort(
	struct pqcp_fleet_recovery_manager *manager,
	uint64_t now_ms,
	uint64_t cooldown_ms)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || cooldown_ms == 0U ||
	    UINT64_MAX - now_ms < cooldown_ms) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (manager->state == PQCP_FLEET_RECOVERY_IDLE ||
	    manager->state == PQCP_FLEET_RECOVERY_LOCKED) {
		(void)k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	manager->cooldown_until_ms = now_ms + cooldown_ms;
	if (manager->attempt_count >= manager->maximum_attempts) {
		manager->state = PQCP_FLEET_RECOVERY_LOCKED;
	} else {
		manager->state = PQCP_FLEET_RECOVERY_IDLE;
	}
	manager->session_id = 0U;
	manager->authorized_at_ms = 0U;
	manager->expires_at_ms = 0U;
	manager->completed_steps = 0U;
	memset(manager->authorization_digest, 0,
	       sizeof(manager->authorization_digest));
	memset(manager->evidence_digest, 0,
	       sizeof(manager->evidence_digest));
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_recovery_audit(
	struct pqcp_fleet_recovery_manager *manager)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    !state_valid(manager->state) ||
	    manager->maximum_attempts == 0U ||
	    manager->required_steps == 0U ||
	    manager->attempt_count > manager->maximum_attempts) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (manager->state != PQCP_FLEET_RECOVERY_IDLE &&
	    manager->state != PQCP_FLEET_RECOVERY_LOCKED &&
	    manager->state != PQCP_FLEET_RECOVERY_COMPLETE) {
		if (!reason_valid(manager->reason) ||
		    manager->session_id == 0U ||
		    manager->authorized_at_ms == 0U ||
		    manager->expires_at_ms <=
			    manager->authorized_at_ms ||
		    all_zero(manager->authorization_digest,
			     sizeof(manager->authorization_digest))) {
			(void)k_mutex_unlock(&manager->lock);
			return -EBADMSG;
		}
	}
	if ((manager->completed_steps &
	     ~manager->required_steps) != 0U ||
	    ((manager->state ==
		      PQCP_FLEET_RECOVERY_VALIDATING ||
	      manager->state ==
		      PQCP_FLEET_RECOVERY_EXITING ||
	      manager->state ==
		      PQCP_FLEET_RECOVERY_COMPLETE) &&
	     (manager->completed_steps &
	      manager->required_steps) != manager->required_steps)) {
		(void)k_mutex_unlock(&manager->lock);
		return -EBADMSG;
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}
