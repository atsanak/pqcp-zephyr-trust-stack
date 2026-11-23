/*
 * SPDX-License-Identifier: MIT
 *
 * Bounded identity and session rotation coordination.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_governance.h>

int pqcp_runtime_rotation_policy_default(
	struct pqcp_runtime_rotation_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	policy->identity_rotation_ms =
		UINT64_C(2592000000);
	policy->session_key_rotation_ms = 3600000U;
	policy->maximum_key_uses = 100000U;
	policy->maximum_rotations_per_tick = 2U;
	policy->rotate_on_failure = true;
	policy->drain_sessions_before_rotation = true;
	return 0;
}

static bool policy_valid(
	const struct pqcp_runtime_rotation_policy *policy)
{
	return policy != NULL &&
	       policy->schema_version ==
		       PQCP_RUNTIME_SCHEMA_VERSION &&
	       policy->identity_rotation_ms != 0U &&
	       policy->session_key_rotation_ms != 0U &&
	       policy->maximum_key_uses != 0U &&
	       policy->maximum_rotations_per_tick != 0U;
}

static bool identity_due(
	const struct pqcp_runtime_identity *identity,
	const struct pqcp_runtime_rotation_policy *policy,
	uint64_t now_ms)
{
	return identity->active && identity->local &&
	       !identity->rotation_pending &&
	       (identity->use_count >= policy->maximum_key_uses ||
		now_ms - identity->created_at_ms >=
			policy->identity_rotation_ms);
}

static bool session_due(
	const struct pqcp_runtime_session *session,
	const struct pqcp_runtime_rotation_policy *policy,
	uint64_t now_ms)
{
	return session->active && !session->draining &&
	       (session->failures != 0U ||
		now_ms - session->opened_at_ms >=
			policy->session_key_rotation_ms);
}

int pqcp_runtime_rotation_tick(
	const struct pqcp_runtime_rotation_policy *policy,
	struct pqcp_runtime_identity_store *identities,
	struct pqcp_runtime_session_manager *sessions,
	uint64_t now_ms,
	struct pqcp_runtime_rotation_report *report)
{
	uint32_t rotations = 0U;

	if (!policy_valid(policy) || identities == NULL ||
	    sessions == NULL || now_ms == 0U || report == NULL) {
		return -EINVAL;
	}
	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	report->timestamp_ms = now_ms;
	if (k_mutex_lock(&identities->lock, K_FOREVER) != 0) {
		return -EIO;
	}
	for (size_t index = 0U; index < identities->capacity; ++index) {
		const struct pqcp_runtime_identity *identity =
			&identities->identities[index];
		char id[PQCP_RUNTIME_IDENTITY_MAX_ID_CHARS];
		uint64_t expiry;

		if (!identity->active || !identity->local) {
			continue;
		}
		report->identities_checked++;
		if (!identity_due(identity, policy, now_ms) ||
		    rotations >= policy->maximum_rotations_per_tick) {
			continue;
		}
		(void)strncpy(id, identity->identity_id,
			      sizeof(id) - 1U);
		id[sizeof(id) - 1U] = '\0';
		expiry = identity->expires_at_ms != 0U ?
			now_ms + (identity->expires_at_ms -
				  identity->created_at_ms) :
			now_ms + policy->identity_rotation_ms;
		(void)k_mutex_unlock(&identities->lock);
		int ret = pqcp_runtime_identity_rotate_local(
			identities, id, now_ms, expiry);

		if (ret == 0) {
			report->identities_rotated++;
			rotations++;
		} else {
			report->failures++;
		}
		if (k_mutex_lock(
			    &identities->lock, K_FOREVER) != 0) {
			return -EIO;
		}
	}
	(void)k_mutex_unlock(&identities->lock);
	if (k_mutex_lock(&sessions->lock, K_FOREVER) != 0) {
		return -EIO;
	}
	for (size_t index = 0U; index < sessions->capacity; ++index) {
		struct pqcp_runtime_session *session =
			&sessions->sessions[index];

		if (!session->active) {
			continue;
		}
		report->sessions_checked++;
		if (session_due(session, policy, now_ms)) {
			session->draining = true;
			report->sessions_draining++;
		}
	}
	(void)k_mutex_unlock(&sessions->lock);
	return report->failures == 0U ? 0 : -EIO;
}
