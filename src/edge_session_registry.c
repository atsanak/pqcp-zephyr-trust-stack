/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bound service sessions to principal identity and route evidence.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool session_state_valid(
	enum pqcp_edge_session_state state)
{
	return state >= PQCP_EDGE_SESSION_EMPTY &&
	       state <= PQCP_EDGE_SESSION_FAILED;
}

static int session_index(
	const struct pqcp_edge_session_registry *registry,
	uint64_t session_id)
{
	for (size_t index = 0U;
	     index < registry->capacity; ++index) {
		if (registry->sessions[index].occupied &&
		    registry->sessions[index].session_id ==
			    session_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static bool session_reclaimable(
	const struct pqcp_edge_session *session)
{
	/* Finished sessions whose principal quota was already returned. */
	return session->occupied && session->principal_released &&
	       (session->state == PQCP_EDGE_SESSION_CLOSED ||
		session->state == PQCP_EDGE_SESSION_FAILED);
}

static int free_session_index(
	const struct pqcp_edge_session_registry *registry)
{
	int reclaim = -1;

	for (size_t index = 0U;
	     index < registry->capacity; ++index) {
		const struct pqcp_edge_session *session =
			&registry->sessions[index];

		if (!session->occupied) {
			return (int)index;
		}
		if (session_reclaimable(session) &&
		    (reclaim < 0 ||
		     session->last_activity_ms <
			     registry->sessions[reclaim].
				     last_activity_ms)) {
			reclaim = (int)index;
		}
	}
	return reclaim >= 0 ? reclaim : -ENOSPC;
}

static int principal_index_locked(
	const struct pqcp_edge_principal_directory *directory,
	const char *principal_id)
{
	for (size_t index = 0U;
	     index < directory->capacity; ++index) {
		if (directory->principals[index].state !=
			    PQCP_EDGE_PRINCIPAL_EMPTY &&
		    strcmp(
			    directory->principals[index].principal_id,
			    principal_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static bool binding_valid(
	const uint8_t binding[PQCP_EDGE_DIGEST_BYTES])
{
	return binding != NULL &&
	       !pqcp_edge_internal_all_zero(
		       binding, PQCP_EDGE_DIGEST_BYTES);
}

static bool session_valid(
	const struct pqcp_edge_session *session)
{
	return session != NULL && session->occupied &&
	       session->schema_version ==
		       PQCP_EDGE_SCHEMA_VERSION &&
	       session->session_id != 0U &&
	       session_state_valid(session->state) &&
	       session->state != PQCP_EDGE_SESSION_EMPTY &&
	       pqcp_edge_internal_text_valid(
		       session->principal_id,
		       sizeof(session->principal_id)) &&
	       pqcp_edge_internal_text_valid(
		       session->service_id,
		       sizeof(session->service_id)) &&
	       pqcp_edge_internal_text_valid(
		       session->endpoint_id,
		       sizeof(session->endpoint_id)) &&
	       binding_valid(session->binding_digest) &&
	       session->expires_at_ms >
		       session->opened_at_ms &&
	       session->last_activity_ms >=
		       session->opened_at_ms &&
	       session->maximum_failures != 0U;
}

int pqcp_edge_session_registry_init(
	struct pqcp_edge_session_registry *registry,
	struct pqcp_edge_session *sessions,
	size_t capacity)
{
	if (registry == NULL || sessions == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(sessions, 0, capacity * sizeof(*sessions));
	registry->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	registry->sessions = sessions;
	registry->capacity = capacity;
	registry->next_session_id = 1U;
	k_mutex_init(&registry->lock);
	registry->initialized = true;
	return 0;
}

int pqcp_edge_session_open(
	struct pqcp_edge_session_registry *registry,
	struct pqcp_edge_principal_directory *principals,
	const struct pqcp_edge_route *route,
	const uint8_t binding_digest[PQCP_EDGE_DIGEST_BYTES],
	bool mutually_authenticated,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	struct pqcp_edge_session **session)
{
	struct pqcp_edge_principal *principal;
	struct pqcp_edge_session candidate;
	int principal_slot;
	int slot;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    principals == NULL || !principals->initialized ||
	    route == NULL || !route->occupied ||
	    session == NULL || !binding_valid(binding_digest) ||
	    lifetime_ms == 0U || route->expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	k_mutex_lock(&principals->lock, K_FOREVER);
	principal_slot = principal_index_locked(
		principals, route->source_principal_id);
	if (principal_slot < 0) {
		ret = principal_slot;
		goto principal_out;
	}
	principal = &principals->principals[principal_slot];
	if (principal->state !=
		    PQCP_EDGE_PRINCIPAL_ACTIVE ||
	    principal->credential_expires_at_ms <= now_ms ||
	    principal->active_sessions >=
		    principal->maximum_sessions) {
		ret = principal->active_sessions >=
			    principal->maximum_sessions ?
			    -EDQUOT : -EACCES;
		goto principal_out;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	slot = free_session_index(registry);
	if (slot < 0) {
		ret = slot;
		goto registry_out;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.session_id =
		pqcp_edge_internal_next_identifier(
			&registry->next_session_id);
	ret = pqcp_edge_internal_copy_text(
		candidate.principal_id,
		sizeof(candidate.principal_id),
		route->source_principal_id);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.service_id,
			sizeof(candidate.service_id),
			route->service_id);
	}
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			candidate.endpoint_id,
			sizeof(candidate.endpoint_id),
			route->endpoint_id);
	}
	if (ret != 0) {
		goto registry_out;
	}
	candidate.opened_at_ms = now_ms;
	candidate.last_activity_ms = now_ms;
	candidate.expires_at_ms =
		pqcp_edge_internal_saturating_add_u64(
			now_ms, lifetime_ms);
	candidate.key_epoch = 1U;
	candidate.maximum_failures = 5U;
	candidate.state = PQCP_EDGE_SESSION_ACTIVE;
	memcpy(candidate.binding_digest, binding_digest,
	       sizeof(candidate.binding_digest));
	candidate.mutually_authenticated =
		mutually_authenticated;
	candidate.occupied = true;
	registry->sessions[slot] = candidate;
	++registry->opened_count;
	++principal->active_sessions;
	*session = &registry->sessions[slot];
registry_out:
	k_mutex_unlock(&registry->lock);
principal_out:
	k_mutex_unlock(&principals->lock);
	if (ret != 0) {
		*session = NULL;
		if (registry != NULL && registry->initialized) {
			++registry->rejected_count;
		}
	}
	return ret;
}

int pqcp_edge_session_account(
	struct pqcp_edge_session_registry *registry,
	uint64_t session_id,
	uint64_t bytes_sent,
	uint64_t bytes_received,
	bool success,
	uint64_t now_ms)
{
	struct pqcp_edge_session *session;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    session_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = session_index(registry, session_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	session = &registry->sessions[index];
	if (session->state != PQCP_EDGE_SESSION_ACTIVE &&
	    session->state !=
		    PQCP_EDGE_SESSION_REKEY_REQUIRED) {
		ret = -ENOTCONN;
		goto out;
	}
	if (session->expires_at_ms <= now_ms) {
		session->state = PQCP_EDGE_SESSION_DRAINING;
		ret = -ETIMEDOUT;
		goto out;
	}
	session->last_activity_ms = now_ms;
	session->bytes_sent =
		pqcp_edge_internal_saturating_add_u64(
			session->bytes_sent, bytes_sent);
	session->bytes_received =
		pqcp_edge_internal_saturating_add_u64(
			session->bytes_received, bytes_received);
	session->request_count =
		pqcp_edge_internal_saturating_add_u64(
			session->request_count, 1U);
	if (success) {
		if (session->failures != 0U) {
			--session->failures;
		}
	} else {
		session->failures =
			pqcp_edge_internal_saturating_add_u32(
				session->failures, 1U);
		if (session->failures >=
		    session->maximum_failures) {
			session->state =
				PQCP_EDGE_SESSION_FAILED;
		}
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_session_require_rekey(
	struct pqcp_edge_session_registry *registry,
	uint64_t session_id,
	uint64_t next_epoch)
{
	struct pqcp_edge_session *session;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    session_id == 0U || next_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = session_index(registry, session_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	session = &registry->sessions[index];
	if (session->state != PQCP_EDGE_SESSION_ACTIVE) {
		ret = -EALREADY;
	} else if (next_epoch <= session->key_epoch) {
		ret = -ESTALE;
	} else {
		session->key_epoch = next_epoch;
		session->state =
			PQCP_EDGE_SESSION_REKEY_REQUIRED;
	}
out:
	k_mutex_unlock(&registry->lock);
	return ret;
}

int pqcp_edge_session_close(
	struct pqcp_edge_session_registry *registry,
	struct pqcp_edge_principal_directory *principals,
	uint64_t session_id,
	int result,
	uint64_t now_ms)
{
	struct pqcp_edge_session *session;
	int principal_slot;
	int index;
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    principals == NULL || !principals->initialized ||
	    session_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&principals->lock, K_FOREVER);
	k_mutex_lock(&registry->lock, K_FOREVER);
	index = session_index(registry, session_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	session = &registry->sessions[index];
	if (session->state == PQCP_EDGE_SESSION_CLOSED ||
	    session->principal_released) {
		ret = -EALREADY;
		goto out;
	}
	principal_slot = principal_index_locked(
		principals, session->principal_id);
	if (principal_slot >= 0 &&
	    principals->principals[principal_slot].
		    active_sessions != 0U) {
		--principals->principals[principal_slot].
			active_sessions;
	}
	session->principal_released = true;
	session->state = result == 0 ?
		PQCP_EDGE_SESSION_CLOSED :
		PQCP_EDGE_SESSION_FAILED;
	session->last_activity_ms = now_ms;
	++registry->closed_count;
out:
	k_mutex_unlock(&registry->lock);
	k_mutex_unlock(&principals->lock);
	return ret;
}

int pqcp_edge_session_tick(
	struct pqcp_edge_session_registry *registry,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (registry == NULL || !registry->initialized ||
	    changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < registry->capacity; ++index) {
		struct pqcp_edge_session *session =
			&registry->sessions[index];

		if (!session->occupied ||
		    session->state ==
			    PQCP_EDGE_SESSION_CLOSED ||
		    session->state ==
			    PQCP_EDGE_SESSION_FAILED) {
			continue;
		}
		if (session->expires_at_ms <= now_ms) {
			session->state =
				PQCP_EDGE_SESSION_DRAINING;
			++changed;
		} else if (session->state ==
			   PQCP_EDGE_SESSION_REKEY_REQUIRED &&
			   session->last_activity_ms + 60000U <
				   now_ms) {
			session->state =
				PQCP_EDGE_SESSION_FAILED;
			++changed;
		}
	}
	k_mutex_unlock(&registry->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_edge_session_registry_audit(
	struct pqcp_edge_session_registry *registry)
{
	int ret = 0;

	if (registry == NULL || !registry->initialized ||
	    registry->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    registry->sessions == NULL ||
	    registry->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&registry->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < registry->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_session *session =
			&registry->sessions[index];

		if (!session->occupied) {
			continue;
		}
		if (!session_valid(session)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < registry->capacity; ++other) {
			if (registry->sessions[other].occupied &&
			    registry->sessions[other].session_id ==
				    session->session_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&registry->lock);
	return ret;
}
