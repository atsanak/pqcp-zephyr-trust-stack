/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Zero-trust principal inventory and lifecycle enforcement.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "edge_security_internal.h"

static bool trust_valid(enum pqcp_edge_trust_level trust)
{
	return trust >= PQCP_EDGE_TRUST_UNTRUSTED &&
	       trust <= PQCP_EDGE_TRUST_PRIVILEGED;
}

static bool state_valid(
	enum pqcp_edge_principal_state state)
{
	return state >= PQCP_EDGE_PRINCIPAL_EMPTY &&
	       state <= PQCP_EDGE_PRINCIPAL_REVOKED;
}

static bool principal_identity_valid(
	const struct pqcp_edge_principal *principal)
{
	if (principal == NULL ||
	    !pqcp_edge_internal_text_valid(
		    principal->principal_id,
		    sizeof(principal->principal_id)) ||
	    !pqcp_edge_internal_text_valid(
		    principal->tenant_id,
		    sizeof(principal->tenant_id)) ||
	    !pqcp_edge_internal_text_valid(
		    principal->trust_domain,
		    sizeof(principal->trust_domain)) ||
	    !pqcp_edge_internal_text_valid(
		    principal->zone,
		    sizeof(principal->zone)) ||
	    pqcp_edge_internal_all_zero(
		    principal->identity_digest,
		    sizeof(principal->identity_digest)) ||
	    principal->maximum_sessions == 0U ||
	    !trust_valid(principal->trust) ||
	    !state_valid(principal->state)) {
		return false;
	}
	return true;
}

static int principal_index(
	const struct pqcp_edge_principal_directory *directory,
	const char *principal_id)
{
	if (directory == NULL || principal_id == NULL) {
		return -EINVAL;
	}
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

static int free_principal_index(
	const struct pqcp_edge_principal_directory *directory)
{
	for (size_t index = 0U;
	     index < directory->capacity; ++index) {
		if (directory->principals[index].state ==
		    PQCP_EDGE_PRINCIPAL_EMPTY) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool immutable_identity_matches(
	const struct pqcp_edge_principal *current,
	const struct pqcp_edge_principal *candidate)
{
	return strcmp(
		       current->tenant_id,
		       candidate->tenant_id) == 0 &&
	       strcmp(
		       current->trust_domain,
		       candidate->trust_domain) == 0 &&
	       pqcp_edge_internal_equal(
		       current->identity_digest,
		       candidate->identity_digest,
		       sizeof(current->identity_digest));
}

static int validate_epoch_progression(
	const struct pqcp_edge_principal *current,
	const struct pqcp_edge_principal *candidate)
{
	if (candidate->credential_epoch <
		    current->credential_epoch ||
	    candidate->policy_epoch <
		    current->policy_epoch ||
	    candidate->revocation_epoch <
		    current->revocation_epoch) {
		return -ESTALE;
	}
	if (candidate->credential_epoch ==
		    current->credential_epoch &&
	    candidate->credential_expires_at_ms <
		    current->credential_expires_at_ms) {
		return -EKEYEXPIRED;
	}
	return 0;
}

static void normalize_principal(
	struct pqcp_edge_principal *principal,
	uint32_t generation,
	uint64_t now_ms)
{
	principal->schema_version = PQCP_EDGE_SCHEMA_VERSION;
	principal->generation = generation;
	principal->registered_at_ms = now_ms;
	principal->last_seen_ms = now_ms;
	principal->active_sessions = 0U;
	principal->quarantine_until_ms = 0U;
	if (principal->state == PQCP_EDGE_PRINCIPAL_EMPTY ||
	    principal->state == PQCP_EDGE_PRINCIPAL_REVOKED) {
		principal->state = PQCP_EDGE_PRINCIPAL_ACTIVE;
	}
	if (principal->trust == PQCP_EDGE_TRUST_UNTRUSTED) {
		principal->trust =
			PQCP_EDGE_TRUST_AUTHENTICATED;
	}
}

int pqcp_edge_principal_directory_init(
	struct pqcp_edge_principal_directory *directory,
	struct pqcp_edge_principal *principals,
	size_t capacity)
{
	if (directory == NULL || principals == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(directory, 0, sizeof(*directory));
	memset(principals, 0,
	       capacity * sizeof(*principals));
	directory->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	directory->principals = principals;
	directory->capacity = capacity;
	directory->next_generation = 1U;
	k_mutex_init(&directory->lock);
	directory->initialized = true;
	return 0;
}

int pqcp_edge_principal_register(
	struct pqcp_edge_principal_directory *directory,
	const struct pqcp_edge_principal *principal,
	uint64_t now_ms)
{
	struct pqcp_edge_principal candidate;
	int index;
	int ret = 0;

	if (directory == NULL || !directory->initialized ||
	    !principal_identity_valid(principal) ||
	    principal->credential_expires_at_ms <= now_ms ||
	    principal->credential_epoch == 0U ||
	    principal->policy_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&directory->lock, K_FOREVER);
	index = principal_index(
		directory, principal->principal_id);
	if (index >= 0) {
		struct pqcp_edge_principal *current =
			&directory->principals[index];

		if (current->state ==
			    PQCP_EDGE_PRINCIPAL_REVOKED ||
		    !immutable_identity_matches(
			    current, principal)) {
			ret = -EKEYREJECTED;
		} else {
			ret = validate_epoch_progression(
				current, principal);
		}
		if (ret == 0) {
			const uint32_t generation =
				current->generation;
			const uint64_t registered_at =
				current->registered_at_ms;
			const uint32_t active_sessions =
				current->active_sessions;

			candidate = *principal;
			candidate.schema_version =
				PQCP_EDGE_SCHEMA_VERSION;
			candidate.generation = generation;
			candidate.registered_at_ms =
				registered_at;
			candidate.last_seen_ms = now_ms;
			candidate.active_sessions =
				active_sessions;
			if (candidate.state ==
			    PQCP_EDGE_PRINCIPAL_EMPTY) {
				candidate.state =
					PQCP_EDGE_PRINCIPAL_ACTIVE;
			}
			*current = candidate;
			++directory->registration_count;
		}
	} else if (index == -ENOENT) {
		index = free_principal_index(directory);
		if (index < 0) {
			ret = index;
		} else {
			candidate = *principal;
			normalize_principal(
				&candidate,
				pqcp_edge_internal_next_generation(
					&directory->
						next_generation),
				now_ms);
			directory->principals[index] =
				candidate;
			++directory->registration_count;
		}
	} else {
		ret = index;
	}
	if (ret != 0) {
		++directory->rejection_count;
	}
	k_mutex_unlock(&directory->lock);
	return ret;
}

int pqcp_edge_principal_observe(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	uint32_t risk_score,
	enum pqcp_edge_trust_level trust,
	bool channel_bound,
	uint64_t now_ms)
{
	struct pqcp_edge_principal *principal;
	int index;
	int ret = 0;

	if (directory == NULL || !directory->initialized ||
	    principal_id == NULL || !trust_valid(trust)) {
		return -EINVAL;
	}
	k_mutex_lock(&directory->lock, K_FOREVER);
	index = principal_index(directory, principal_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	principal = &directory->principals[index];
	if (principal->state ==
	    PQCP_EDGE_PRINCIPAL_REVOKED) {
		ret = -EKEYREVOKED;
		goto out;
	}
	if (principal->credential_expires_at_ms <= now_ms) {
		principal->state =
			PQCP_EDGE_PRINCIPAL_DEGRADED;
		principal->trust =
			PQCP_EDGE_TRUST_OBSERVED;
		ret = -EKEYEXPIRED;
		goto out;
	}
	if (principal->state ==
		    PQCP_EDGE_PRINCIPAL_QUARANTINED &&
	    (principal->quarantine_until_ms == 0U ||
	     now_ms < principal->quarantine_until_ms)) {
		ret = -EACCES;
		goto out;
	}
	if (principal->state ==
		    PQCP_EDGE_PRINCIPAL_QUARANTINED &&
	    now_ms >= principal->quarantine_until_ms) {
		principal->quarantine_until_ms = 0U;
	}
	principal->last_seen_ms = now_ms;
	principal->risk_score = risk_score;
	principal->channel_bound = channel_bound;
	if (trust > principal->trust) {
		principal->trust = trust;
	} else if (risk_score > 750U &&
		   principal->trust >
			   PQCP_EDGE_TRUST_OBSERVED) {
		principal->trust =
			PQCP_EDGE_TRUST_OBSERVED;
	}
	if (risk_score >= 900U) {
		principal->state =
			PQCP_EDGE_PRINCIPAL_QUARANTINED;
		principal->quarantine_until_ms =
			UINT64_MAX;
		ret = -EACCES;
	} else if (risk_score >= 600U) {
		principal->state =
			PQCP_EDGE_PRINCIPAL_DEGRADED;
	} else {
		principal->state =
			PQCP_EDGE_PRINCIPAL_ACTIVE;
	}
out:
	k_mutex_unlock(&directory->lock);
	return ret;
}

int pqcp_edge_principal_quarantine(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	uint64_t until_ms)
{
	int index;
	int ret = 0;

	if (directory == NULL || !directory->initialized ||
	    principal_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&directory->lock, K_FOREVER);
	index = principal_index(directory, principal_id);
	if (index < 0) {
		ret = index;
	} else if (directory->principals[index].state ==
		   PQCP_EDGE_PRINCIPAL_REVOKED) {
		ret = -EKEYREVOKED;
	} else {
		directory->principals[index].state =
			PQCP_EDGE_PRINCIPAL_QUARANTINED;
		directory->principals[index].
			quarantine_until_ms = until_ms;
	}
	k_mutex_unlock(&directory->lock);
	return ret;
}

int pqcp_edge_principal_release(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	uint64_t now_ms)
{
	struct pqcp_edge_principal *principal;
	int index;
	int ret = 0;

	if (directory == NULL || !directory->initialized ||
	    principal_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&directory->lock, K_FOREVER);
	index = principal_index(directory, principal_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	principal = &directory->principals[index];
	if (principal->state ==
	    PQCP_EDGE_PRINCIPAL_REVOKED) {
		ret = -EKEYREVOKED;
	} else if (principal->state !=
		   PQCP_EDGE_PRINCIPAL_QUARANTINED) {
		ret = -EALREADY;
	} else if (principal->credential_expires_at_ms <=
		   now_ms) {
		ret = -EKEYEXPIRED;
	} else {
		principal->state =
			PQCP_EDGE_PRINCIPAL_DEGRADED;
		principal->quarantine_until_ms = 0U;
		if (principal->trust >
		    PQCP_EDGE_TRUST_OBSERVED) {
			principal->trust =
				PQCP_EDGE_TRUST_OBSERVED;
		}
	}
out:
	k_mutex_unlock(&directory->lock);
	return ret;
}

int pqcp_edge_principal_revoke(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	uint64_t revocation_epoch,
	uint64_t now_ms)
{
	struct pqcp_edge_principal *principal;
	int index;
	int ret = 0;

	if (directory == NULL || !directory->initialized ||
	    principal_id == NULL || revocation_epoch == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&directory->lock, K_FOREVER);
	index = principal_index(directory, principal_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	principal = &directory->principals[index];
	if (revocation_epoch <=
	    principal->revocation_epoch) {
		ret = -ESTALE;
		goto out;
	}
	principal->revocation_epoch = revocation_epoch;
	principal->state =
		PQCP_EDGE_PRINCIPAL_REVOKED;
	principal->trust = PQCP_EDGE_TRUST_UNTRUSTED;
	principal->capabilities = 0U;
	principal->channel_bound = false;
	principal->quarantine_until_ms = now_ms;
	pqcp_runtime_secure_zero(
		principal->attestation_digest,
		sizeof(principal->attestation_digest));
	++directory->revocation_count;
out:
	k_mutex_unlock(&directory->lock);
	return ret;
}

int pqcp_edge_principal_find(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	struct pqcp_edge_principal **principal)
{
	int index;
	int ret = 0;

	if (directory == NULL || !directory->initialized ||
	    principal_id == NULL || principal == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&directory->lock, K_FOREVER);
	index = principal_index(directory, principal_id);
	if (index < 0) {
		*principal = NULL;
		ret = index;
	} else {
		*principal = &directory->principals[index];
	}
	k_mutex_unlock(&directory->lock);
	return ret;
}

int pqcp_edge_principal_tick(
	struct pqcp_edge_principal_directory *directory,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (directory == NULL || !directory->initialized ||
	    changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&directory->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < directory->capacity; ++index) {
		struct pqcp_edge_principal *principal =
			&directory->principals[index];

		if (principal->state ==
		    PQCP_EDGE_PRINCIPAL_EMPTY) {
			continue;
		}
		if (principal->state ==
		    PQCP_EDGE_PRINCIPAL_REVOKED) {
			continue;
		}
		if (principal->credential_expires_at_ms <=
			    now_ms &&
		    principal->state !=
			    PQCP_EDGE_PRINCIPAL_DEGRADED) {
			principal->state =
				PQCP_EDGE_PRINCIPAL_DEGRADED;
			principal->trust =
				PQCP_EDGE_TRUST_OBSERVED;
			principal->channel_bound = false;
			++changed;
		}
		if (principal->state ==
			    PQCP_EDGE_PRINCIPAL_QUARANTINED &&
		    principal->quarantine_until_ms != 0U &&
		    principal->quarantine_until_ms !=
			    UINT64_MAX &&
		    now_ms >=
			    principal->quarantine_until_ms) {
			principal->state =
				PQCP_EDGE_PRINCIPAL_DEGRADED;
			principal->quarantine_until_ms = 0U;
			++changed;
		}
	}
	k_mutex_unlock(&directory->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_edge_principal_audit(
	struct pqcp_edge_principal_directory *directory)
{
	int ret = 0;

	if (directory == NULL || !directory->initialized ||
	    directory->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    directory->principals == NULL ||
	    directory->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&directory->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < directory->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_principal *principal =
			&directory->principals[index];

		if (principal->state ==
		    PQCP_EDGE_PRINCIPAL_EMPTY) {
			continue;
		}
		if (!principal_identity_valid(principal) ||
		    principal->schema_version !=
			    PQCP_EDGE_SCHEMA_VERSION ||
		    principal->generation == 0U ||
		    principal->credential_epoch == 0U ||
		    principal->policy_epoch == 0U ||
		    principal->active_sessions >
			    principal->maximum_sessions) {
			ret = -EBADMSG;
			break;
		}
		if (principal->state ==
			    PQCP_EDGE_PRINCIPAL_REVOKED &&
		    (principal->capabilities != 0U ||
		     principal->trust !=
			     PQCP_EDGE_TRUST_UNTRUSTED ||
		     principal->channel_bound)) {
			ret = -EKEYREJECTED;
			break;
		}
		for (size_t other = index + 1U;
		     other < directory->capacity; ++other) {
			if (directory->principals[other].state !=
				    PQCP_EDGE_PRINCIPAL_EMPTY &&
			    strcmp(
				    principal->principal_id,
				    directory->principals[other].
					    principal_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&directory->lock);
	return ret;
}
