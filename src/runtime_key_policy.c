/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Runtime key policy evaluation.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_control.h>

#include "runtime_internal.h"

#define PQCP_RUNTIME_KEY_POLICY_REASON_FAMILY (1U << 0)
#define PQCP_RUNTIME_KEY_POLICY_REASON_USAGE (1U << 1)
#define PQCP_RUNTIME_KEY_POLICY_REASON_SECURITY (1U << 2)
#define PQCP_RUNTIME_KEY_POLICY_REASON_PERSISTENCE (1U << 3)
#define PQCP_RUNTIME_KEY_POLICY_REASON_LIFETIME (1U << 4)
#define PQCP_RUNTIME_KEY_POLICY_REASON_EXPIRY (1U << 5)
#define PQCP_RUNTIME_KEY_POLICY_REASON_OWNER (1U << 6)
#define PQCP_RUNTIME_KEY_POLICY_REASON_EXPORT (1U << 7)

static uint32_t family_bit(
	enum pqcp_runtime_key_family family)
{
	if (!pqcp_runtime_internal_key_family_valid(family)) {
		return 0U;
	}
	return 1U << ((uint32_t)family - 1U);
}

int pqcp_runtime_key_policy_default(
	struct pqcp_runtime_key_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	policy->maximum_volatile_lifetime_ms = 3600000U;
	policy->maximum_persistent_lifetime_ms =
		UINT64_C(31536000000);
	policy->maximum_uses = 1000000U;
	policy->allowed_family_mask =
		family_bit(PQCP_RUNTIME_KEY_MLKEM_PUBLIC) |
		family_bit(PQCP_RUNTIME_KEY_MLKEM_KEYPAIR) |
		family_bit(PQCP_RUNTIME_KEY_MLDSA_PUBLIC) |
		family_bit(PQCP_RUNTIME_KEY_MLDSA_KEYPAIR) |
		family_bit(PQCP_RUNTIME_KEY_SHARED_SECRET) |
		family_bit(PQCP_RUNTIME_KEY_AEAD);
	policy->allowed_usage_mask =
		PQCP_RUNTIME_USAGE_ENCAPSULATE |
		PQCP_RUNTIME_USAGE_DECAPSULATE |
		PQCP_RUNTIME_USAGE_SIGN |
		PQCP_RUNTIME_USAGE_VERIFY |
		PQCP_RUNTIME_USAGE_DERIVE |
		PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
		PQCP_RUNTIME_USAGE_DESTROY;
	policy->minimum_security_level = 1U;
	policy->allow_persistent =
		IS_ENABLED(CONFIG_PQCP_RUNTIME_KEY_STORE_PSA);
	policy->require_expiry = true;
	policy->require_owner = true;
	policy->allow_public_export = true;
	return pqcp_runtime_key_policy_validate(policy);
}

int pqcp_runtime_key_policy_validate(
	const struct pqcp_runtime_key_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    policy->maximum_volatile_lifetime_ms == 0U ||
	    policy->maximum_persistent_lifetime_ms == 0U ||
	    policy->maximum_persistent_lifetime_ms <
		    policy->maximum_volatile_lifetime_ms ||
	    policy->maximum_uses == 0U ||
	    policy->allowed_family_mask == 0U ||
	    policy->allowed_usage_mask == 0U ||
	    policy->minimum_security_level == 0U ||
	    policy->minimum_security_level > 5U) {
		return -EINVAL;
	}
	return 0;
}

static uint32_t request_security_level(
	const struct pqcp_runtime_key_request *request)
{
	switch (request->family) {
	case PQCP_RUNTIME_KEY_MLKEM_PUBLIC:
	case PQCP_RUNTIME_KEY_MLKEM_KEYPAIR:
		return pqcp_runtime_internal_security_level(
			request->level, 0U);
	case PQCP_RUNTIME_KEY_MLDSA_PUBLIC:
	case PQCP_RUNTIME_KEY_MLDSA_KEYPAIR:
		return pqcp_runtime_internal_security_level(
			0U, request->level);
	case PQCP_RUNTIME_KEY_SHARED_SECRET:
	case PQCP_RUNTIME_KEY_AEAD:
		return 3U;
	default:
		return 0U;
	}
}

int pqcp_runtime_key_policy_check(
	const struct pqcp_runtime_key_policy *policy,
	const struct pqcp_runtime_key_request *request,
	uint32_t *reason_mask)
{
	uint32_t reasons = 0U;

	if (pqcp_runtime_key_policy_validate(policy) != 0 ||
	    request == NULL || reason_mask == NULL) {
		return -EINVAL;
	}
	if ((policy->allowed_family_mask &
	     family_bit(request->family)) == 0U) {
		reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_FAMILY;
	}
	if (!pqcp_runtime_internal_usage_valid(request->usage) ||
	    (request->usage &
	     ~policy->allowed_usage_mask) != 0U) {
		reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_USAGE;
	}
	if (!pqcp_runtime_internal_level_valid(
		    request->family, request->level) ||
	    request_security_level(request) <
		    policy->minimum_security_level) {
		reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_SECURITY;
	}
	if (request->persistent && !policy->allow_persistent) {
		reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_PERSISTENCE;
	}
	if (request->now_ms == 0U) {
		reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_LIFETIME;
	} else if (request->expires_at_ms != 0U) {
		if (request->expires_at_ms <= request->now_ms) {
			reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_LIFETIME;
		} else {
			const uint64_t lifetime =
				request->expires_at_ms -
				request->now_ms;

			if ((!request->persistent &&
			     lifetime >
				     policy->
					     maximum_volatile_lifetime_ms) ||
			    (request->persistent &&
			     lifetime >
				     policy->
					     maximum_persistent_lifetime_ms)) {
				reasons |=
					PQCP_RUNTIME_KEY_POLICY_REASON_LIFETIME;
			}
		}
	} else if (policy->require_expiry) {
		reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_EXPIRY;
	}
	if (policy->require_owner &&
	    !pqcp_runtime_internal_owner_valid(request->owner)) {
		reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_OWNER;
	}
	if (request->exportable_public &&
	    !policy->allow_public_export) {
		reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_EXPORT;
	}
	if (!pqcp_runtime_internal_label_valid(request->label)) {
		reasons |= PQCP_RUNTIME_KEY_POLICY_REASON_OWNER;
	}
	*reason_mask = reasons;
	return reasons == 0U ? 0 : -EACCES;
}
