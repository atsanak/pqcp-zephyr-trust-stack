/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Policy-bound crypto broker lifecycle and capability management.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/crypto_broker.h>
#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/rng.h>

#include "crypto_broker_internal.h"
#include "runtime_internal.h"

static bool operation_valid(
	enum pqcp_crypto_broker_operation operation)
{
	return operation > PQCP_CRYPTO_BROKER_OPERATION_NONE &&
	       operation < PQCP_CRYPTO_BROKER_OPERATION_COUNT;
}

static bool principal_state_valid(
	enum pqcp_crypto_broker_principal_state state)
{
	return state >= PQCP_CRYPTO_BROKER_PRINCIPAL_EMPTY &&
	       state <= PQCP_CRYPTO_BROKER_PRINCIPAL_REVOKED;
}

static bool grant_state_valid(
	enum pqcp_crypto_broker_grant_state state)
{
	return state >= PQCP_CRYPTO_BROKER_GRANT_EMPTY &&
	       state <= PQCP_CRYPTO_BROKER_GRANT_REVOKED;
}

static bool capability_state_valid(
	enum pqcp_crypto_broker_capability_state state)
{
	return state >= PQCP_CRYPTO_BROKER_CAPABILITY_EMPTY &&
	       state <= PQCP_CRYPTO_BROKER_CAPABILITY_REVOKED;
}

static bool transaction_state_valid(
	enum pqcp_crypto_broker_transaction_state state)
{
	return state >= PQCP_CRYPTO_BROKER_TRANSACTION_EMPTY &&
	       state <= PQCP_CRYPTO_BROKER_TRANSACTION_FAILED;
}

static uint32_t operation_mask_all(void)
{
	uint32_t mask = 0U;

	for (uint32_t operation =
		     PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE;
	     operation < PQCP_CRYPTO_BROKER_OPERATION_COUNT;
	     ++operation) {
		mask |= PQCP_CRYPTO_BROKER_OPERATION_BIT(operation);
	}
	return mask;
}

static uint32_t family_mask_all(void)
{
	uint32_t mask = 0U;

	for (uint32_t family = PQCP_RUNTIME_KEY_MLKEM_KEYPAIR;
	     family <= PQCP_RUNTIME_KEY_AEAD; ++family) {
		mask |= PQCP_CRYPTO_BROKER_FAMILY_BIT(family);
	}
	return mask;
}

static uint32_t custody_mask_all(void)
{
	uint32_t mask = 0U;

	for (uint32_t custody = PQCP_RUNTIME_CUSTODY_SOFTWARE_OPAQUE;
	     custody <= PQCP_RUNTIME_CUSTODY_HARDWARE_BOUND;
	     ++custody) {
		mask |= PQCP_CRYPTO_BROKER_CUSTODY_BIT(custody);
	}
	return mask;
}

static int lock_broker(struct pqcp_crypto_broker *broker)
{
	if (broker == NULL || !broker->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&broker->lock, K_FOREVER);
}

static void unlock_broker(struct pqcp_crypto_broker *broker)
{
	(void)k_mutex_unlock(&broker->lock);
}

static bool storage_valid(
	const struct pqcp_crypto_broker_storage *storage)
{
	return storage != NULL &&
	       storage->principals != NULL &&
	       storage->principal_capacity != 0U &&
	       storage->grants != NULL &&
	       storage->grant_capacity != 0U &&
	       storage->capabilities != NULL &&
	       storage->capability_capacity != 0U &&
	       storage->transactions != NULL &&
	       storage->transaction_capacity >= 2U;
}

static bool config_valid(
	const struct pqcp_crypto_broker_config *config)
{
	if (config == NULL || config->executor == NULL ||
	    config->key_store == NULL ||
	    config->receipt_mac_key == NULL ||
	    config->receipt_mac_key_length < 16U ||
	    config->maximum_capability_lifetime_ms == 0U ||
	    config->transaction_retention_ms == 0U ||
	    config->maximum_cost_per_request == 0U ||
	    config->receipt_mode >
		    PQCP_CRYPTO_BROKER_RECEIPT_HMAC_AND_MLDSA) {
		return false;
	}
	if (config->receipt_mode ==
		    PQCP_CRYPTO_BROKER_RECEIPT_HMAC_AND_MLDSA &&
	    !pqcp_runtime_key_handle_is_valid(
		    &config->receipt_signing_key)) {
		return false;
	}
	return true;
}

bool pqcp_crypto_broker_internal_secure_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if ((left == NULL || right == NULL) && length != 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

bool pqcp_crypto_broker_internal_all_zero(
	const uint8_t *value,
	size_t length)
{
	uint8_t aggregate = 0U;

	if (value == NULL && length != 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate == 0U;
}

uint32_t pqcp_crypto_broker_internal_next_generation(
	uint32_t *generation)
{
	if (generation == NULL) {
		return 0U;
	}
	(*generation)++;
	if (*generation == 0U) {
		(*generation)++;
	}
	return *generation;
}

int pqcp_crypto_broker_internal_copy_id(
	char *destination,
	size_t capacity,
	const char *source)
{
	if (destination == NULL || source == NULL ||
	    capacity < 2U ||
	    strnlen(source, capacity) == 0U ||
	    strnlen(source, capacity) >= capacity) {
		return -EINVAL;
	}
	return pqcp_runtime_internal_copy_text(
		destination, capacity, source);
}

int pqcp_crypto_broker_internal_principal_index(
	const struct pqcp_crypto_broker *broker,
	const char *principal_id)
{
	if (broker == NULL || principal_id == NULL) {
		return -1;
	}
	for (size_t index = 0U;
	     index < broker->storage.principal_capacity;
	     ++index) {
		const struct pqcp_crypto_broker_principal *principal =
			&broker->storage.principals[index];

		if (principal->state !=
			    PQCP_CRYPTO_BROKER_PRINCIPAL_EMPTY &&
		    strcmp(principal->id, principal_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_crypto_broker_internal_grant_index(
	const struct pqcp_crypto_broker *broker,
	uint32_t grant_id)
{
	if (broker == NULL || grant_id == 0U) {
		return -1;
	}
	for (size_t index = 0U;
	     index < broker->storage.grant_capacity; ++index) {
		const struct pqcp_crypto_broker_grant *grant =
			&broker->storage.grants[index];

		if (grant->state !=
			    PQCP_CRYPTO_BROKER_GRANT_EMPTY &&
		    grant->grant_id == grant_id) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_crypto_broker_internal_capability_index(
	const struct pqcp_crypto_broker *broker,
	const uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES])
{
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
	int result = -1;

	if (broker == NULL || token == NULL ||
	    pqcp_crypto_broker_internal_all_zero(
		    token, PQCP_CRYPTO_BROKER_TOKEN_BYTES) ||
	    pqcp_runtime_internal_sha256(
		    token, PQCP_CRYPTO_BROKER_TOKEN_BYTES,
		    digest) != 0) {
		return -1;
	}
	for (size_t index = 0U;
	     index < broker->storage.capability_capacity;
	     ++index) {
		const struct pqcp_crypto_broker_capability *capability =
			&broker->storage.capabilities[index];

		if (capability->state !=
			    PQCP_CRYPTO_BROKER_CAPABILITY_EMPTY &&
		    pqcp_crypto_broker_internal_secure_equal(
			    capability->token_digest, digest,
			    sizeof(digest))) {
			result = (int)index;
			break;
		}
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return result;
}

int pqcp_crypto_broker_internal_transaction_index(
	const struct pqcp_crypto_broker *broker,
	uint32_t principal_index,
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES])
{
	if (broker == NULL || request_id == NULL ||
	    principal_index >=
		    broker->storage.principal_capacity) {
		return -1;
	}
	for (size_t index = 0U;
	     index < broker->storage.transaction_capacity;
	     ++index) {
		const struct pqcp_crypto_broker_transaction *transaction =
			&broker->storage.transactions[index];

		if (transaction->state !=
			    PQCP_CRYPTO_BROKER_TRANSACTION_EMPTY &&
		    transaction->principal_index == principal_index &&
		    pqcp_crypto_broker_internal_secure_equal(
			    transaction->request_id, request_id,
			    PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES)) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_crypto_broker_internal_free_principal(
	const struct pqcp_crypto_broker *broker)
{
	if (broker == NULL) {
		return -1;
	}
	for (size_t index = 0U;
	     index < broker->storage.principal_capacity;
	     ++index) {
		if (broker->storage.principals[index].state ==
		    PQCP_CRYPTO_BROKER_PRINCIPAL_EMPTY) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_crypto_broker_internal_free_grant(
	const struct pqcp_crypto_broker *broker)
{
	if (broker == NULL) {
		return -1;
	}
	for (size_t index = 0U;
	     index < broker->storage.grant_capacity; ++index) {
		if (broker->storage.grants[index].state ==
		    PQCP_CRYPTO_BROKER_GRANT_EMPTY) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_crypto_broker_internal_free_capability(
	const struct pqcp_crypto_broker *broker)
{
	if (broker == NULL) {
		return -1;
	}
	for (size_t index = 0U;
	     index < broker->storage.capability_capacity;
	     ++index) {
		if (broker->storage.capabilities[index].state ==
		    PQCP_CRYPTO_BROKER_CAPABILITY_EMPTY) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_crypto_broker_internal_free_transaction(
	const struct pqcp_crypto_broker *broker,
	uint64_t now_ms)
{
	int oldest_index = -1;
	uint64_t oldest_completed = UINT64_MAX;

	if (broker == NULL || now_ms == 0U) {
		return -1;
	}
	for (size_t index = 0U;
	     index < broker->storage.transaction_capacity;
	     ++index) {
		const struct pqcp_crypto_broker_transaction *transaction =
			&broker->storage.transactions[index];

		if (transaction->state ==
		    PQCP_CRYPTO_BROKER_TRANSACTION_EMPTY) {
			return (int)index;
		}
		if ((transaction->state ==
			     PQCP_CRYPTO_BROKER_TRANSACTION_COMPLETED ||
		     transaction->state ==
			     PQCP_CRYPTO_BROKER_TRANSACTION_CANCELLED ||
		     transaction->state ==
			     PQCP_CRYPTO_BROKER_TRANSACTION_FAILED) &&
		    transaction->completed_at_ms != 0U &&
		    transaction->completed_at_ms < oldest_completed &&
		    now_ms - transaction->completed_at_ms >=
			    broker->config.transaction_retention_ms) {
			oldest_completed =
				transaction->completed_at_ms;
			oldest_index = (int)index;
		}
	}
	return oldest_index;
}

const char *pqcp_crypto_broker_operation_str(
	enum pqcp_crypto_broker_operation operation)
{
	switch (operation) {
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE:
		return "key_generate";
	case PQCP_CRYPTO_BROKER_OPERATION_EXPORT_PUBLIC:
		return "export_public";
	case PQCP_CRYPTO_BROKER_OPERATION_SIGN:
		return "sign";
	case PQCP_CRYPTO_BROKER_OPERATION_VERIFY:
		return "verify";
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_ENCAPSULATE:
		return "kem_encapsulate";
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_DECAPSULATE:
		return "kem_decapsulate";
	case PQCP_CRYPTO_BROKER_OPERATION_HKDF_DERIVE:
		return "hkdf_derive";
	case PQCP_CRYPTO_BROKER_OPERATION_MAC:
		return "mac";
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_ENCRYPT:
		return "aead_encrypt";
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_DECRYPT:
		return "aead_decrypt";
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE:
		return "key_rotate";
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_DESTROY:
		return "key_destroy";
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_METADATA:
		return "key_metadata";
	default:
		return "none";
	}
}

const char *pqcp_crypto_broker_decision_str(
	enum pqcp_crypto_broker_decision decision)
{
	switch (decision) {
	case PQCP_CRYPTO_BROKER_DECISION_ALLOW:
		return "allow";
	case PQCP_CRYPTO_BROKER_DECISION_DENY_AUTHENTICATION:
		return "deny_authentication";
	case PQCP_CRYPTO_BROKER_DECISION_DENY_CAPABILITY:
		return "deny_capability";
	case PQCP_CRYPTO_BROKER_DECISION_DENY_GRANT:
		return "deny_grant";
	case PQCP_CRYPTO_BROKER_DECISION_DENY_QUOTA:
		return "deny_quota";
	case PQCP_CRYPTO_BROKER_DECISION_DENY_KEY_OWNERSHIP:
		return "deny_key_ownership";
	case PQCP_CRYPTO_BROKER_DECISION_DENY_CUSTODY:
		return "deny_custody";
	case PQCP_CRYPTO_BROKER_DECISION_DENY_DEADLINE:
		return "deny_deadline";
	case PQCP_CRYPTO_BROKER_DECISION_DENY_REPLAY:
		return "deny_replay";
	case PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY:
		return "deny_policy";
	default:
		return "unset";
	}
}

int pqcp_crypto_broker_init(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_config *config,
	const struct pqcp_crypto_broker_storage *storage)
{
	if (broker == NULL || !config_valid(config) ||
	    !storage_valid(storage) ||
	    pqcp_runtime_key_store_validate(
		    config->key_store) != 0) {
		return -EINVAL;
	}
	memset(broker, 0, sizeof(*broker));
	memset(storage->principals, 0,
	       sizeof(*storage->principals) *
		       storage->principal_capacity);
	memset(storage->grants, 0,
	       sizeof(*storage->grants) *
		       storage->grant_capacity);
	memset(storage->capabilities, 0,
	       sizeof(*storage->capabilities) *
		       storage->capability_capacity);
	memset(storage->transactions, 0,
	       sizeof(*storage->transactions) *
		       storage->transaction_capacity);
	broker->schema_version =
		PQCP_CRYPTO_BROKER_SCHEMA_VERSION;
	broker->config = *config;
	broker->storage = *storage;
	broker->next_receipt_sequence = 1U;
	broker->next_job_id = 1U;
	broker->next_grant_id = 1U;
	k_mutex_init(&broker->lock);
	broker->initialized = true;
	return pqcp_crypto_broker_audit(broker);
}

int pqcp_crypto_broker_internal_validate_quota(
	const struct pqcp_crypto_broker_quota *quota)
{
	if (quota == NULL ||
	    quota->maximum_active_keys == 0U ||
	    quota->maximum_inflight_requests == 0U ||
	    quota->maximum_operations_per_window == 0U ||
	    quota->maximum_input_bytes_per_window == 0U ||
	    quota->maximum_output_bytes_per_window == 0U ||
	    quota->maximum_cost_units_per_window == 0U ||
	    quota->window_ms == 0U) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_crypto_broker_register_principal(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	const char *tenant,
	const char *trust_domain,
	const uint8_t identity_digest[PQCP_RUNTIME_DIGEST_BYTES],
	const struct pqcp_crypto_broker_quota *quota,
	bool channel_identity_required,
	uint64_t now_ms)
{
	struct pqcp_crypto_broker_principal *principal;
	int index;
	int ret;

	if (principal_id == NULL || tenant == NULL ||
	    trust_domain == NULL || identity_digest == NULL ||
	    pqcp_crypto_broker_internal_all_zero(
		    identity_digest, PQCP_RUNTIME_DIGEST_BYTES) ||
	    pqcp_crypto_broker_internal_validate_quota(quota) != 0 ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_broker(broker);
	if (ret != 0) {
		return ret;
	}
	if (pqcp_crypto_broker_internal_principal_index(
		    broker, principal_id) >= 0) {
		unlock_broker(broker);
		return -EEXIST;
	}
	index = pqcp_crypto_broker_internal_free_principal(broker);
	if (index < 0) {
		unlock_broker(broker);
		return -ENOSPC;
	}
	principal = &broker->storage.principals[index];
	memset(principal, 0, sizeof(*principal));
	principal->schema_version =
		PQCP_CRYPTO_BROKER_SCHEMA_VERSION;
	principal->generation =
		pqcp_crypto_broker_internal_next_generation(
			&broker->next_principal_generation);
	ret = pqcp_crypto_broker_internal_copy_id(
		principal->id, sizeof(principal->id),
		principal_id);
	if (ret == 0) {
		ret = pqcp_crypto_broker_internal_copy_id(
			principal->tenant,
			sizeof(principal->tenant), tenant);
	}
	if (ret == 0) {
		ret = pqcp_crypto_broker_internal_copy_id(
			principal->trust_domain,
			sizeof(principal->trust_domain),
			trust_domain);
	}
	if (ret != 0) {
		memset(principal, 0, sizeof(*principal));
		unlock_broker(broker);
		return ret;
	}
	memcpy(principal->identity_digest, identity_digest,
	       sizeof(principal->identity_digest));
	principal->quota = *quota;
	principal->usage.window_started_ms = now_ms;
	principal->created_at_ms = now_ms;
	principal->state =
		PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE;
	principal->channel_identity_required =
		channel_identity_required;
	unlock_broker(broker);
	return 0;
}

static void revoke_principal_children(
	struct pqcp_crypto_broker *broker,
	uint32_t principal_index,
	uint64_t now_ms)
{
	for (size_t index = 0U;
	     index < broker->storage.grant_capacity; ++index) {
		struct pqcp_crypto_broker_grant *grant =
			&broker->storage.grants[index];

		if (grant->state !=
			    PQCP_CRYPTO_BROKER_GRANT_EMPTY &&
		    grant->principal_index == principal_index) {
			grant->state =
				PQCP_CRYPTO_BROKER_GRANT_REVOKED;
			grant->revoked_at_ms = now_ms;
		}
	}
	for (size_t index = 0U;
	     index < broker->storage.capability_capacity;
	     ++index) {
		struct pqcp_crypto_broker_capability *capability =
			&broker->storage.capabilities[index];

		if (capability->state !=
			    PQCP_CRYPTO_BROKER_CAPABILITY_EMPTY &&
		    capability->principal_index == principal_index) {
			capability->state =
				PQCP_CRYPTO_BROKER_CAPABILITY_REVOKED;
		}
	}
}

static int change_principal_state(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	enum pqcp_crypto_broker_principal_state target,
	uint64_t now_ms)
{
	struct pqcp_crypto_broker_principal *principal;
	int index;
	int ret;

	if (principal_id == NULL || now_ms == 0U ||
	    target < PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE ||
	    target > PQCP_CRYPTO_BROKER_PRINCIPAL_REVOKED) {
		return -EINVAL;
	}
	ret = lock_broker(broker);
	if (ret != 0) {
		return ret;
	}
	index = pqcp_crypto_broker_internal_principal_index(
		broker, principal_id);
	if (index < 0) {
		unlock_broker(broker);
		return -ENOENT;
	}
	principal = &broker->storage.principals[index];
	if (principal->state ==
	    PQCP_CRYPTO_BROKER_PRINCIPAL_REVOKED) {
		unlock_broker(broker);
		return -EKEYREVOKED;
	}
	switch (target) {
	case PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE:
		if (principal->state !=
		    PQCP_CRYPTO_BROKER_PRINCIPAL_SUSPENDED) {
			ret = -EALREADY;
			break;
		}
		principal->state =
			PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE;
		principal->suspended_at_ms = 0U;
		ret = 0;
		break;
	case PQCP_CRYPTO_BROKER_PRINCIPAL_SUSPENDED:
		if (principal->state !=
		    PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE) {
			ret = -EALREADY;
			break;
		}
		principal->state =
			PQCP_CRYPTO_BROKER_PRINCIPAL_SUSPENDED;
		principal->suspended_at_ms = now_ms;
		ret = 0;
		break;
	case PQCP_CRYPTO_BROKER_PRINCIPAL_REVOKED:
		principal->state =
			PQCP_CRYPTO_BROKER_PRINCIPAL_REVOKED;
		principal->revoked_at_ms = now_ms;
		revoke_principal_children(
			broker, (uint32_t)index, now_ms);
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	unlock_broker(broker);
	return ret;
}

int pqcp_crypto_broker_suspend_principal(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	uint64_t now_ms)
{
	return change_principal_state(
		broker, principal_id,
		PQCP_CRYPTO_BROKER_PRINCIPAL_SUSPENDED,
		now_ms);
}

int pqcp_crypto_broker_resume_principal(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	uint64_t now_ms)
{
	return change_principal_state(
		broker, principal_id,
		PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE,
		now_ms);
}

int pqcp_crypto_broker_revoke_principal(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	uint64_t now_ms)
{
	return change_principal_state(
		broker, principal_id,
		PQCP_CRYPTO_BROKER_PRINCIPAL_REVOKED,
		now_ms);
}

int pqcp_crypto_broker_internal_validate_grant_policy(
	const struct pqcp_crypto_broker_grant_policy *policy)
{
	if (policy == NULL || policy->operation_mask == 0U ||
	    (policy->operation_mask & ~operation_mask_all()) != 0U ||
	    policy->key_family_mask == 0U ||
	    (policy->key_family_mask & ~family_mask_all()) != 0U ||
	    !pqcp_runtime_internal_usage_valid(
		    policy->key_usage_mask) ||
	    policy->custody_mask == 0U ||
	    (policy->custody_mask & ~custody_mask_all()) != 0U ||
	    policy->maximum_input_bytes == 0U ||
	    policy->maximum_output_bytes == 0U ||
	    policy->maximum_input_bytes >
		    PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    policy->maximum_output_bytes >
		    PQCP_RUNTIME_MAX_OUTPUT_BYTES ||
	    policy->maximum_deadline_horizon_ms == 0U ||
	    policy->maximum_key_lifetime_ms == 0U ||
	    policy->cost_unit_limit == 0U) {
		return -EINVAL;
	}
	if (policy->allow_public_export &&
	    (policy->operation_mask &
	     PQCP_CRYPTO_BROKER_OPERATION_BIT(
		     PQCP_CRYPTO_BROKER_OPERATION_EXPORT_PUBLIC)) == 0U) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_crypto_broker_create_grant(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	const struct pqcp_crypto_broker_grant_policy *policy,
	uint64_t not_before_ms,
	uint64_t expires_at_ms,
	uint32_t maximum_uses,
	uint64_t now_ms,
	uint32_t *grant_id)
{
	struct pqcp_crypto_broker_grant *grant;
	int principal_index;
	int grant_index;
	int ret;

	if (principal_id == NULL ||
	    pqcp_crypto_broker_internal_validate_grant_policy(
		    policy) != 0 ||
	    now_ms == 0U || not_before_ms < now_ms ||
	    expires_at_ms <= not_before_ms ||
	    maximum_uses == 0U || grant_id == NULL) {
		return -EINVAL;
	}
	ret = lock_broker(broker);
	if (ret != 0) {
		return ret;
	}
	principal_index =
		pqcp_crypto_broker_internal_principal_index(
			broker, principal_id);
	if (principal_index < 0) {
		unlock_broker(broker);
		return -ENOENT;
	}
	if (broker->storage.principals[principal_index].state !=
	    PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE) {
		unlock_broker(broker);
		return -EACCES;
	}
	grant_index =
		pqcp_crypto_broker_internal_free_grant(broker);
	if (grant_index < 0) {
		unlock_broker(broker);
		return -ENOSPC;
	}
	grant = &broker->storage.grants[grant_index];
	memset(grant, 0, sizeof(*grant));
	grant->schema_version =
		PQCP_CRYPTO_BROKER_SCHEMA_VERSION;
	grant->grant_id = broker->next_grant_id++;
	if (grant->grant_id == 0U) {
		grant->grant_id = broker->next_grant_id++;
	}
	grant->generation =
		pqcp_crypto_broker_internal_next_generation(
			&broker->next_grant_generation);
	grant->principal_index = (uint32_t)principal_index;
	grant->policy = *policy;
	grant->not_before_ms = not_before_ms;
	grant->expires_at_ms = expires_at_ms;
	grant->maximum_uses = maximum_uses;
	grant->created_at_ms = now_ms;
	grant->state = PQCP_CRYPTO_BROKER_GRANT_ACTIVE;
	*grant_id = grant->grant_id;
	unlock_broker(broker);
	return 0;
}

static void revoke_grant_capabilities(
	struct pqcp_crypto_broker *broker,
	uint32_t grant_index)
{
	for (size_t index = 0U;
	     index < broker->storage.capability_capacity;
	     ++index) {
		struct pqcp_crypto_broker_capability *capability =
			&broker->storage.capabilities[index];

		if (capability->state !=
			    PQCP_CRYPTO_BROKER_CAPABILITY_EMPTY &&
		    capability->grant_index == grant_index) {
			capability->state =
				PQCP_CRYPTO_BROKER_CAPABILITY_REVOKED;
		}
	}
}

int pqcp_crypto_broker_revoke_grant(
	struct pqcp_crypto_broker *broker,
	uint32_t grant_id,
	uint64_t now_ms)
{
	struct pqcp_crypto_broker_grant *grant;
	int index;
	int ret;

	if (grant_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_broker(broker);
	if (ret != 0) {
		return ret;
	}
	index = pqcp_crypto_broker_internal_grant_index(
		broker, grant_id);
	if (index < 0) {
		unlock_broker(broker);
		return -ENOENT;
	}
	grant = &broker->storage.grants[index];
	if (grant->state ==
	    PQCP_CRYPTO_BROKER_GRANT_REVOKED) {
		unlock_broker(broker);
		return -EALREADY;
	}
	grant->state = PQCP_CRYPTO_BROKER_GRANT_REVOKED;
	grant->revoked_at_ms = now_ms;
	revoke_grant_capabilities(broker, (uint32_t)index);
	unlock_broker(broker);
	return 0;
}

static int unique_token(
	struct pqcp_crypto_broker *broker,
	uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES],
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES])
{
	for (size_t attempt = 0U; attempt < 8U; ++attempt) {
		if (pqcp_rng_get_bytes(
			    token, PQCP_CRYPTO_BROKER_TOKEN_BYTES) !=
		    PQCP_RNG_SUCCESS) {
			return -EIO;
		}
		if (pqcp_crypto_broker_internal_all_zero(
			    token, PQCP_CRYPTO_BROKER_TOKEN_BYTES)) {
			continue;
		}
		if (pqcp_runtime_internal_sha256(
			    token, PQCP_CRYPTO_BROKER_TOKEN_BYTES,
			    digest) != 0) {
			return -EIO;
		}
		bool collision = false;

		for (size_t index = 0U;
		     index < broker->storage.capability_capacity;
		     ++index) {
			const struct pqcp_crypto_broker_capability
				*capability =
					&broker->storage.capabilities[index];

			if (capability->state !=
				    PQCP_CRYPTO_BROKER_CAPABILITY_EMPTY &&
			    pqcp_crypto_broker_internal_secure_equal(
				    capability->token_digest, digest,
				    PQCP_RUNTIME_DIGEST_BYTES)) {
				collision = true;
				break;
			}
		}
		if (!collision) {
			return 0;
		}
	}
	pqcp_runtime_secure_zero(
		token, PQCP_CRYPTO_BROKER_TOKEN_BYTES);
	pqcp_runtime_secure_zero(
		digest, PQCP_RUNTIME_DIGEST_BYTES);
	return -EAGAIN;
}

static int issue_capability_locked(
	struct pqcp_crypto_broker *broker,
	uint32_t principal_index,
	uint32_t grant_index,
	const uint8_t parent_digest[PQCP_RUNTIME_DIGEST_BYTES],
	uint32_t operation_mask,
	uint32_t key_family_mask,
	uint32_t key_usage_mask,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint32_t maximum_uses,
	bool attenuated,
	uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES])
{
	struct pqcp_crypto_broker_capability *capability;
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
	int index;
	int ret;

	if (principal_index >=
		    broker->storage.principal_capacity ||
	    grant_index >= broker->storage.grant_capacity ||
	    operation_mask == 0U || key_family_mask == 0U ||
	    !pqcp_runtime_internal_usage_valid(key_usage_mask) ||
	    expires_at_ms <= now_ms || maximum_uses == 0U ||
	    expires_at_ms - now_ms >
		    broker->config.maximum_capability_lifetime_ms) {
		return -EINVAL;
	}
	index =
		pqcp_crypto_broker_internal_free_capability(broker);
	if (index < 0) {
		return -ENOSPC;
	}
	ret = unique_token(broker, token, digest);
	if (ret != 0) {
		return ret;
	}
	capability = &broker->storage.capabilities[index];
	memset(capability, 0, sizeof(*capability));
	capability->schema_version =
		PQCP_CRYPTO_BROKER_SCHEMA_VERSION;
	capability->generation =
		pqcp_crypto_broker_internal_next_generation(
			&broker->next_capability_generation);
	capability->principal_index = principal_index;
	capability->grant_index = grant_index;
	memcpy(capability->token_digest, digest,
	       sizeof(capability->token_digest));
	if (parent_digest != NULL) {
		memcpy(capability->parent_digest, parent_digest,
		       sizeof(capability->parent_digest));
	}
	capability->operation_mask = operation_mask;
	capability->key_family_mask = key_family_mask;
	capability->key_usage_mask = key_usage_mask;
	capability->issued_at_ms = now_ms;
	capability->expires_at_ms = expires_at_ms;
	capability->maximum_uses = maximum_uses;
	capability->state =
		PQCP_CRYPTO_BROKER_CAPABILITY_ACTIVE;
	capability->attenuated = attenuated;
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return 0;
}

int pqcp_crypto_broker_issue_capability(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	uint32_t grant_id,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint32_t maximum_uses,
	uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES])
{
	struct pqcp_crypto_broker_principal *principal;
	struct pqcp_crypto_broker_grant *grant;
	int principal_index;
	int grant_index;
	int ret;

	if (principal_id == NULL || grant_id == 0U ||
	    now_ms == 0U || token == NULL) {
		return -EINVAL;
	}
	ret = lock_broker(broker);
	if (ret != 0) {
		return ret;
	}
	principal_index =
		pqcp_crypto_broker_internal_principal_index(
			broker, principal_id);
	grant_index = pqcp_crypto_broker_internal_grant_index(
		broker, grant_id);
	if (principal_index < 0 || grant_index < 0) {
		unlock_broker(broker);
		return -ENOENT;
	}
	principal = &broker->storage.principals[principal_index];
	grant = &broker->storage.grants[grant_index];
	if (principal->state !=
		    PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE ||
	    grant->state != PQCP_CRYPTO_BROKER_GRANT_ACTIVE ||
	    grant->principal_index != (uint32_t)principal_index) {
		unlock_broker(broker);
		return -EACCES;
	}
	if (now_ms < grant->not_before_ms ||
	    now_ms >= grant->expires_at_ms ||
	    expires_at_ms > grant->expires_at_ms) {
		unlock_broker(broker);
		return -ETIMEDOUT;
	}
	ret = issue_capability_locked(
		broker, (uint32_t)principal_index,
		(uint32_t)grant_index, NULL,
		grant->policy.operation_mask,
		grant->policy.key_family_mask,
		grant->policy.key_usage_mask,
		now_ms, expires_at_ms, maximum_uses,
		false, token);
	unlock_broker(broker);
	return ret;
}

int pqcp_crypto_broker_attenuate_capability(
	struct pqcp_crypto_broker *broker,
	const uint8_t parent_token[PQCP_CRYPTO_BROKER_TOKEN_BYTES],
	uint32_t operation_mask,
	uint32_t key_family_mask,
	uint32_t key_usage_mask,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint32_t maximum_uses,
	uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES])
{
	struct pqcp_crypto_broker_capability *parent;
	int parent_index;
	int ret;

	if (parent_token == NULL || token == NULL ||
	    now_ms == 0U || operation_mask == 0U ||
	    key_family_mask == 0U ||
	    !pqcp_runtime_internal_usage_valid(key_usage_mask)) {
		return -EINVAL;
	}
	ret = lock_broker(broker);
	if (ret != 0) {
		return ret;
	}
	parent_index =
		pqcp_crypto_broker_internal_capability_index(
			broker, parent_token);
	if (parent_index < 0) {
		unlock_broker(broker);
		return -ENOENT;
	}
	parent = &broker->storage.capabilities[parent_index];
	if (parent->state !=
		    PQCP_CRYPTO_BROKER_CAPABILITY_ACTIVE ||
	    now_ms >= parent->expires_at_ms ||
	    expires_at_ms > parent->expires_at_ms ||
	    maximum_uses > parent->maximum_uses -
		    parent->use_count ||
	    (operation_mask & ~parent->operation_mask) != 0U ||
	    (key_family_mask & ~parent->key_family_mask) != 0U ||
	    (key_usage_mask & ~parent->key_usage_mask) != 0U) {
		unlock_broker(broker);
		return -EACCES;
	}
	ret = issue_capability_locked(
		broker, parent->principal_index,
		parent->grant_index, parent->token_digest,
		operation_mask, key_family_mask, key_usage_mask,
		now_ms, expires_at_ms, maximum_uses, true, token);
	unlock_broker(broker);
	return ret;
}

int pqcp_crypto_broker_revoke_capability(
	struct pqcp_crypto_broker *broker,
	const uint8_t token[PQCP_CRYPTO_BROKER_TOKEN_BYTES])
{
	int index;
	int ret;

	if (token == NULL) {
		return -EINVAL;
	}
	ret = lock_broker(broker);
	if (ret != 0) {
		return ret;
	}
	index =
		pqcp_crypto_broker_internal_capability_index(
			broker, token);
	if (index < 0) {
		unlock_broker(broker);
		return -ENOENT;
	}
	if (broker->storage.capabilities[index].state ==
	    PQCP_CRYPTO_BROKER_CAPABILITY_REVOKED) {
		unlock_broker(broker);
		return -EALREADY;
	}
	broker->storage.capabilities[index].state =
		PQCP_CRYPTO_BROKER_CAPABILITY_REVOKED;
	unlock_broker(broker);
	return 0;
}

static int audit_principal(
	const struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_principal *principal)
{
	if (principal->state ==
	    PQCP_CRYPTO_BROKER_PRINCIPAL_EMPTY) {
		return 0;
	}
	if (principal->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    principal->generation == 0U ||
	    !principal_state_valid(principal->state) ||
	    !pqcp_runtime_internal_text_valid(
		    principal->id, sizeof(principal->id)) ||
	    !pqcp_runtime_internal_text_valid(
		    principal->tenant,
		    sizeof(principal->tenant)) ||
	    !pqcp_runtime_internal_text_valid(
		    principal->trust_domain,
		    sizeof(principal->trust_domain)) ||
	    pqcp_crypto_broker_internal_all_zero(
		    principal->identity_digest,
		    sizeof(principal->identity_digest)) ||
	    pqcp_crypto_broker_internal_validate_quota(
		    &principal->quota) != 0 ||
	    principal->usage.inflight_requests >
		    principal->quota.maximum_inflight_requests ||
	    principal->usage.active_keys >
		    principal->quota.maximum_active_keys ||
	    principal->created_at_ms == 0U) {
		return -EBADMSG;
	}
	for (size_t index = 0U;
	     index < broker->storage.principal_capacity;
	     ++index) {
		const struct pqcp_crypto_broker_principal *other =
			&broker->storage.principals[index];

		if (other != principal &&
		    other->state !=
			    PQCP_CRYPTO_BROKER_PRINCIPAL_EMPTY &&
		    strcmp(other->id, principal->id) == 0) {
			return -EEXIST;
		}
	}
	return 0;
}

static int audit_grant(
	const struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_grant *grant)
{
	if (grant->state ==
	    PQCP_CRYPTO_BROKER_GRANT_EMPTY) {
		return 0;
	}
	if (grant->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    grant->grant_id == 0U || grant->generation == 0U ||
	    !grant_state_valid(grant->state) ||
	    grant->principal_index >=
		    broker->storage.principal_capacity ||
	    broker->storage.principals[grant->principal_index].state ==
		    PQCP_CRYPTO_BROKER_PRINCIPAL_EMPTY ||
	    pqcp_crypto_broker_internal_validate_grant_policy(
		    &grant->policy) != 0 ||
	    grant->not_before_ms == 0U ||
	    grant->expires_at_ms <= grant->not_before_ms ||
	    grant->maximum_uses == 0U ||
	    grant->use_count > grant->maximum_uses) {
		return -EBADMSG;
	}
	for (size_t index = 0U;
	     index < broker->storage.grant_capacity; ++index) {
		const struct pqcp_crypto_broker_grant *other =
			&broker->storage.grants[index];

		if (other != grant &&
		    other->state !=
			    PQCP_CRYPTO_BROKER_GRANT_EMPTY &&
		    other->grant_id == grant->grant_id) {
			return -EEXIST;
		}
	}
	return 0;
}

static int audit_capability(
	const struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_capability *capability)
{
	if (capability->state ==
	    PQCP_CRYPTO_BROKER_CAPABILITY_EMPTY) {
		return 0;
	}
	if (capability->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    capability->generation == 0U ||
	    !capability_state_valid(capability->state) ||
	    capability->principal_index >=
		    broker->storage.principal_capacity ||
	    capability->grant_index >=
		    broker->storage.grant_capacity ||
	    broker->storage.principals[
		    capability->principal_index].state ==
		    PQCP_CRYPTO_BROKER_PRINCIPAL_EMPTY ||
	    broker->storage.grants[
		    capability->grant_index].state ==
		    PQCP_CRYPTO_BROKER_GRANT_EMPTY ||
	    pqcp_crypto_broker_internal_all_zero(
		    capability->token_digest,
		    sizeof(capability->token_digest)) ||
	    capability->operation_mask == 0U ||
	    capability->key_family_mask == 0U ||
	    !pqcp_runtime_internal_usage_valid(
		    capability->key_usage_mask) ||
	    capability->issued_at_ms == 0U ||
	    capability->expires_at_ms <=
		    capability->issued_at_ms ||
	    capability->maximum_uses == 0U ||
	    capability->use_count >
		    capability->maximum_uses) {
		return -EBADMSG;
	}
	if (capability->attenuated &&
	    pqcp_crypto_broker_internal_all_zero(
		    capability->parent_digest,
		    sizeof(capability->parent_digest))) {
		return -EBADMSG;
	}
	return 0;
}

static int audit_transaction(
	const struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_transaction *transaction)
{
	if (transaction->state ==
	    PQCP_CRYPTO_BROKER_TRANSACTION_EMPTY) {
		return 0;
	}
	if (transaction->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    transaction->generation == 0U ||
	    !transaction_state_valid(transaction->state) ||
	    transaction->principal_index >=
		    broker->storage.principal_capacity ||
	    pqcp_crypto_broker_internal_all_zero(
		    transaction->request_id,
		    sizeof(transaction->request_id)) ||
	    pqcp_crypto_broker_internal_all_zero(
		    transaction->request_digest,
		    sizeof(transaction->request_digest)) ||
	    !operation_valid(transaction->operation) ||
	    transaction->accepted_at_ms == 0U ||
	    transaction->output_length >
		    sizeof(transaction->output)) {
		return -EBADMSG;
	}
	if ((transaction->state ==
		     PQCP_CRYPTO_BROKER_TRANSACTION_COMPLETED ||
	     transaction->state ==
		     PQCP_CRYPTO_BROKER_TRANSACTION_CANCELLED ||
	     transaction->state ==
		     PQCP_CRYPTO_BROKER_TRANSACTION_FAILED) &&
	    transaction->completed_at_ms <
		    transaction->accepted_at_ms) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_crypto_broker_audit(
	struct pqcp_crypto_broker *broker)
{
	int ret;

	if (broker == NULL || !broker->initialized ||
	    broker->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    !config_valid(&broker->config) ||
	    !storage_valid(&broker->storage) ||
	    broker->next_receipt_sequence == 0U ||
	    broker->next_job_id == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < broker->storage.principal_capacity;
	     ++index) {
		ret = audit_principal(
			broker,
			&broker->storage.principals[index]);
		if (ret != 0) {
			return ret;
		}
	}
	for (size_t index = 0U;
	     index < broker->storage.grant_capacity; ++index) {
		ret = audit_grant(
			broker, &broker->storage.grants[index]);
		if (ret != 0) {
			return ret;
		}
	}
	for (size_t index = 0U;
	     index < broker->storage.capability_capacity;
	     ++index) {
		ret = audit_capability(
			broker,
			&broker->storage.capabilities[index]);
		if (ret != 0) {
			return ret;
		}
	}
	for (size_t index = 0U;
	     index < broker->storage.transaction_capacity;
	     ++index) {
		ret = audit_transaction(
			broker,
			&broker->storage.transactions[index]);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}
