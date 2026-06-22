/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Versioned approval authorities and high-risk action policies.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_approval.h>

static bool bytes_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static bool bytes_nonzero(
	const uint8_t *value,
	size_t length)
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate != 0U;
}

static uint64_t known_action_mask(void)
{
	uint64_t mask = 0U;

	for (uint32_t action = PQCP_FLEET_APPROVAL_ACTION_POLICY_ACTIVATE;
	     action < PQCP_FLEET_APPROVAL_ACTION_COUNT;
	     ++action) {
		mask |= UINT64_C(1) << action;
	}
	return mask;
}

static uint32_t known_role_mask(void)
{
	return PQCP_FLEET_APPROVAL_ROLE_SECURITY |
	       PQCP_FLEET_APPROVAL_ROLE_OPERATIONS |
	       PQCP_FLEET_APPROVAL_ROLE_COMPLIANCE |
	       PQCP_FLEET_APPROVAL_ROLE_VENDOR |
	       PQCP_FLEET_APPROVAL_ROLE_OWNER |
	       PQCP_FLEET_APPROVAL_ROLE_RECOVERY;
}

static uint32_t known_witness_role_mask(void)
{
	return PQCP_FLEET_TRANSPARENCY_WITNESS_OPERATOR |
	       PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR |
	       PQCP_FLEET_TRANSPARENCY_WITNESS_VENDOR |
	       PQCP_FLEET_TRANSPARENCY_WITNESS_REGULATOR |
	       PQCP_FLEET_TRANSPARENCY_WITNESS_DEVICE;
}

static bool authority_valid(
	const struct pqcp_fleet_approval_authority *authority)
{
	return authority != NULL &&
	       authority->schema_version ==
		       PQCP_FLEET_APPROVAL_SCHEMA_VERSION &&
	       authority->generation != 0U &&
	       authority->roles != 0U &&
	       (authority->roles & ~known_role_mask()) == 0U &&
	       authority->weight != 0U &&
	       authority->action_mask != 0U &&
	       (authority->action_mask & ~known_action_mask()) == 0U &&
	       authority->expires_at_ms > authority->not_before_ms &&
	       bytes_nonzero(
		       authority->authority_id,
		       sizeof(authority->authority_id)) &&
	       bytes_nonzero(
		       authority->key_id,
		       sizeof(authority->key_id)) &&
	       authority->state >=
		       PQCP_FLEET_APPROVAL_AUTHORITY_ACTIVE &&
	       authority->state <=
		       PQCP_FLEET_APPROVAL_AUTHORITY_REVOKED &&
	       (authority->state ==
			PQCP_FLEET_APPROVAL_AUTHORITY_REVOKED ?
			authority->revoked_at_ms != 0U :
			authority->revoked_at_ms == 0U);
}

static bool set_valid(
	const struct pqcp_fleet_approval_authority_set *set)
{
	return set != NULL && set->initialized &&
	       set->schema_version ==
		       PQCP_FLEET_APPROVAL_SCHEMA_VERSION &&
	       set->generation != 0U &&
	       set->policy_epoch != 0U &&
	       set->revocation_epoch != 0U &&
	       set->authorities != NULL && set->capacity != 0U &&
	       set->hash.digest != NULL &&
	       set->signatures.verify != NULL;
}

static int authority_index(
	const struct pqcp_fleet_approval_authority_set *set,
	const uint8_t authority_id[PQCP_FLEET_APPROVAL_ID_BYTES])
{
	for (size_t index = 0U; index < set->capacity; ++index) {
		if (set->authorities[index].state !=
			    PQCP_FLEET_APPROVAL_AUTHORITY_EMPTY &&
		    bytes_equal(
			    set->authorities[index].authority_id,
			    authority_id,
			    PQCP_FLEET_APPROVAL_ID_BYTES)) {
			return (int)index;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_approval_authority_set *set)
{
	for (size_t index = 0U; index < set->capacity; ++index) {
		if (set->authorities[index].state ==
		    PQCP_FLEET_APPROVAL_AUTHORITY_EMPTY) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_fleet_approval_authority_set_init(
	struct pqcp_fleet_approval_authority_set *set,
	struct pqcp_fleet_approval_authority *authorities,
	size_t capacity,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures)
{
	if (set == NULL || authorities == NULL ||
	    capacity == 0U || policy_epoch == 0U ||
	    revocation_epoch == 0U || hash == NULL ||
	    hash->digest == NULL || signatures == NULL ||
	    signatures->verify == NULL) {
		return -EINVAL;
	}
	memset(set, 0, sizeof(*set));
	memset(authorities, 0, capacity * sizeof(*authorities));
	set->schema_version = PQCP_FLEET_APPROVAL_SCHEMA_VERSION;
	set->generation = 1U;
	set->policy_epoch = policy_epoch;
	set->revocation_epoch = revocation_epoch;
	set->authorities = authorities;
	set->capacity = capacity;
	set->hash = *hash;
	set->signatures = *signatures;
	set->initialized = true;
	return 0;
}

int pqcp_fleet_approval_authority_upsert(
	struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_authority *authority)
{
	int index;

	if (!set_valid(set) || !authority_valid(authority)) {
		return -EINVAL;
	}
	if (set->generation == UINT64_MAX) {
		return -EOVERFLOW;
	}
	index = authority_index(set, authority->authority_id);
	if (index >= 0) {
		if (authority->generation <=
		    set->authorities[index].generation) {
			return -ESTALE;
		}
	} else {
		index = free_index(set);
		if (index < 0) {
			return -ENOSPC;
		}
	}
	set->authorities[index] = *authority;
	++set->generation;
	return 0;
}

int pqcp_fleet_approval_authority_revoke(
	struct pqcp_fleet_approval_authority_set *set,
	const uint8_t authority_id[PQCP_FLEET_APPROVAL_ID_BYTES],
	uint64_t revoked_at_ms)
{
	int index;

	if (!set_valid(set) || authority_id == NULL ||
	    revoked_at_ms == 0U) {
		return -EINVAL;
	}
	if (set->generation == UINT64_MAX ||
	    set->revocation_epoch == UINT64_MAX) {
		return -EOVERFLOW;
	}
	index = authority_index(set, authority_id);
	if (index < 0) {
		return -ENOENT;
	}
	if (set->authorities[index].state ==
	    PQCP_FLEET_APPROVAL_AUTHORITY_REVOKED) {
		return -EALREADY;
	}
	if (set->authorities[index].generation == UINT32_MAX) {
		return -EOVERFLOW;
	}
	set->authorities[index].state =
		PQCP_FLEET_APPROVAL_AUTHORITY_REVOKED;
	set->authorities[index].revoked_at_ms = revoked_at_ms;
	++set->authorities[index].generation;
	++set->revocation_epoch;
	++set->generation;
	return 0;
}

int pqcp_fleet_approval_authority_set_advance_epochs(
	struct pqcp_fleet_approval_authority_set *set,
	uint64_t policy_epoch,
	uint64_t revocation_epoch)
{
	if (!set_valid(set) ||
	    policy_epoch < set->policy_epoch ||
	    revocation_epoch < set->revocation_epoch ||
	    (policy_epoch == set->policy_epoch &&
	     revocation_epoch == set->revocation_epoch)) {
		return -EINVAL;
	}
	if (set->generation == UINT64_MAX) {
		return -EOVERFLOW;
	}
	set->policy_epoch = policy_epoch;
	set->revocation_epoch = revocation_epoch;
	++set->generation;
	return 0;
}

int pqcp_fleet_approval_authority_set_verify(
	const struct pqcp_fleet_approval_authority_set *set)
{
	if (!set_valid(set)) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < set->capacity; ++index) {
		const struct pqcp_fleet_approval_authority *authority =
			&set->authorities[index];

		if (authority->state ==
		    PQCP_FLEET_APPROVAL_AUTHORITY_EMPTY) {
			continue;
		}
		if (!authority_valid(authority)) {
			return -EILSEQ;
		}
		for (size_t other = index + 1U;
		     other < set->capacity;
		     ++other) {
			if (set->authorities[other].state !=
				    PQCP_FLEET_APPROVAL_AUTHORITY_EMPTY &&
			    bytes_equal(
				    authority->authority_id,
				    set->authorities[other].authority_id,
				    sizeof(authority->authority_id))) {
				return -EILSEQ;
			}
		}
	}
	return 0;
}

int pqcp_fleet_approval_policy_validate(
	const struct pqcp_fleet_approval_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_FLEET_APPROVAL_SCHEMA_VERSION ||
	    policy->generation == 0U ||
	    policy->minimum_approvals == 0U ||
	    policy->minimum_approvals >
		    PQCP_FLEET_APPROVAL_MAX_CERTIFICATE_VOTES ||
	    policy->minimum_weight == 0U ||
	    policy->policy_epoch == 0U ||
	    policy->revocation_epoch == 0U ||
	    policy->action_mask == 0U ||
	    (policy->action_mask & ~known_action_mask()) != 0U ||
	    policy->maximum_session_lifetime_ms == 0U ||
	    (policy->required_roles & ~known_role_mask()) != 0U ||
	    (policy->veto_roles & ~known_role_mask()) != 0U ||
	    !bytes_nonzero(policy->policy_id,
			   sizeof(policy->policy_id)) ||
	    !policy->enabled) {
		return -EINVAL;
	}
	if (policy->require_witnessed_checkpoint) {
		if (policy->minimum_witnesses == 0U ||
		    policy->minimum_witness_weight == 0U ||
		    (policy->required_witness_roles &
		     ~known_witness_role_mask()) != 0U) {
			return -EINVAL;
		}
	} else if (policy->minimum_witnesses != 0U ||
		   policy->minimum_witness_weight != 0U ||
		   policy->required_witness_roles != 0U) {
		return -EINVAL;
	}
	return 0;
}
