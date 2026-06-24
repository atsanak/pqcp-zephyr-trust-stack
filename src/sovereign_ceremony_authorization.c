/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Signed, role-separated ceremony authorization.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"
#include "sovereign_ceremony_internal.h"

#define APPROVAL_BODY_DOMAIN "pqcp-sovereign-signed-approval-v1"
#define APPROVAL_POLICY_DOMAIN "pqcp-sovereign-approval-policy-v1"
#define AUTHORIZATION_BODY_DOMAIN \
	"pqcp-sovereign-committed-authorization-v1"
#define APPROVAL_SET_DOMAIN "pqcp-sovereign-approval-set-v1"

bool pqcp_sovereign_internal_text_valid(
	const char *text,
	size_t capacity)
{
	size_t length;

	if (text == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(text, capacity);
	return length != 0U && length < capacity;
}

int pqcp_sovereign_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	size_t length;

	if (destination == NULL ||
	    !pqcp_sovereign_internal_text_valid(source, capacity)) {
		return -EINVAL;
	}
	length = strnlen(source, capacity);
	memset(destination, 0, capacity);
	memcpy(destination, source, length);
	return 0;
}

bool pqcp_sovereign_internal_digest_zero(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;
	size_t index;

	if (digest == NULL) {
		return true;
	}
	for (index = 0U; index < PQCP_SOVEREIGN_DIGEST_BYTES;
	     ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

bool pqcp_sovereign_internal_digest_equal(
	const uint8_t left[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t right[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t difference = 0U;
	size_t index;

	if (left == NULL || right == NULL) {
		return false;
	}
	for (index = 0U; index < PQCP_SOVEREIGN_DIGEST_BYTES;
	     ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

bool pqcp_sovereign_internal_u64_add(
	uint64_t left,
	uint64_t right,
	uint64_t *result)
{
	if (result == NULL || UINT64_MAX - left < right) {
		return false;
	}
	*result = left + right;
	return true;
}

bool pqcp_sovereign_internal_u32_add(
	uint32_t left,
	uint32_t right,
	uint32_t *result)
{
	if (result == NULL || UINT32_MAX - left < right) {
		return false;
	}
	*result = left + right;
	return true;
}

size_t pqcp_sovereign_internal_encode_u32(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	uint32_t value)
{
	if (output == NULL || offset > capacity ||
	    capacity - offset < sizeof(value)) {
		return 0U;
	}
	pqcp_runtime_internal_write_u32(&output[offset], value);
	return offset + sizeof(value);
}

size_t pqcp_sovereign_internal_encode_u64(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	uint64_t value)
{
	if (output == NULL || offset > capacity ||
	    capacity - offset < sizeof(value)) {
		return 0U;
	}
	pqcp_runtime_internal_write_u64(&output[offset], value);
	return offset + sizeof(value);
}

size_t pqcp_sovereign_internal_encode_bytes(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	const uint8_t *value,
	size_t value_length)
{
	size_t next;

	if (output == NULL ||
	    (value == NULL && value_length != 0U) ||
	    value_length > UINT32_MAX) {
		return 0U;
	}
	next = pqcp_sovereign_internal_encode_u32(
		output, capacity, offset, (uint32_t)value_length);
	if (next == 0U || next > capacity ||
	    capacity - next < value_length) {
		return 0U;
	}
	if (value_length != 0U) {
		memcpy(&output[next], value, value_length);
	}
	return next + value_length;
}

size_t pqcp_sovereign_internal_encode_text(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	const char *text,
	size_t maximum)
{
	size_t length;

	if (!pqcp_sovereign_internal_text_valid(text, maximum)) {
		return 0U;
	}
	length = strnlen(text, maximum);
	return pqcp_sovereign_internal_encode_bytes(
		output, capacity, offset,
		(const uint8_t *)text, length);
}

int pqcp_sovereign_internal_hash(
	const uint8_t *input,
	size_t input_length,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	if ((input == NULL && input_length != 0U) ||
	    digest == NULL) {
		return -EINVAL;
	}
	return pqcp_runtime_internal_sha256(
		input, input_length, digest);
}

int pqcp_sovereign_internal_hash_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t count,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	if (parts == NULL || lengths == NULL ||
	    count == 0U || digest == NULL) {
		return -EINVAL;
	}
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, count, digest);
}

const char *pqcp_sovereign_internal_action_text(
	enum pqcp_sovereign_ceremony_action action)
{
	switch (action) {
	case PQCP_SOVEREIGN_CEREMONY_ACTION_GENERATE:
		return "generate";
	case PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE:
		return "rotate";
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RETIRE:
		return "retire";
	case PQCP_SOVEREIGN_CEREMONY_ACTION_DESTROY:
		return "destroy";
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RECOVER:
		return "recovery";
	default:
		return "none";
	}
}

const char *pqcp_sovereign_internal_role_text(
	enum pqcp_sovereign_approval_role role)
{
	switch (role) {
	case PQCP_SOVEREIGN_APPROVAL_ROLE_SECURITY_OFFICER:
		return "security-officer";
	case PQCP_SOVEREIGN_APPROVAL_ROLE_KEY_CUSTODIAN:
		return "key-custodian";
	case PQCP_SOVEREIGN_APPROVAL_ROLE_POLICY_OWNER:
		return "policy-owner";
	case PQCP_SOVEREIGN_APPROVAL_ROLE_AUDITOR:
		return "auditor";
	case PQCP_SOVEREIGN_APPROVAL_ROLE_RECOVERY_OFFICER:
		return "recovery-officer";
	case PQCP_SOVEREIGN_APPROVAL_ROLE_PRIVACY_STEWARD:
		return "privacy-steward";
	default:
		return "none";
	}
}

enum pqcp_sovereign_ceremony_action
pqcp_sovereign_internal_action_from_text(const char *action)
{
	if (action == NULL) {
		return PQCP_SOVEREIGN_CEREMONY_ACTION_NONE;
	}
	if (strcmp(action, "generate") == 0 ||
	    strcmp(action, "key-generate") == 0) {
		return PQCP_SOVEREIGN_CEREMONY_ACTION_GENERATE;
	}
	if (strcmp(action, "rotate") == 0 ||
	    strcmp(action, "key-rotate") == 0) {
		return PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE;
	}
	if (strcmp(action, "retire") == 0 ||
	    strcmp(action, "key-retire") == 0) {
		return PQCP_SOVEREIGN_CEREMONY_ACTION_RETIRE;
	}
	if (strcmp(action, "destroy") == 0 ||
	    strcmp(action, "key-destroy") == 0) {
		return PQCP_SOVEREIGN_CEREMONY_ACTION_DESTROY;
	}
	if (strcmp(action, "recovery") == 0 ||
	    strcmp(action, "recover") == 0 ||
	    strcmp(action, "key-recovery") == 0) {
		return PQCP_SOVEREIGN_CEREMONY_ACTION_RECOVER;
	}
	return PQCP_SOVEREIGN_CEREMONY_ACTION_NONE;
}

static bool action_valid(enum pqcp_sovereign_ceremony_action action)
{
	return action > PQCP_SOVEREIGN_CEREMONY_ACTION_NONE &&
	       action < PQCP_SOVEREIGN_CEREMONY_ACTION_COUNT;
}

static bool role_valid(enum pqcp_sovereign_approval_role role)
{
	return role > PQCP_SOVEREIGN_APPROVAL_ROLE_NONE &&
	       role < PQCP_SOVEREIGN_APPROVAL_ROLE_COUNT;
}

static bool authorization_state_valid(
	enum pqcp_sovereign_authorization_state state)
{
	switch (state) {
	case PQCP_SOVEREIGN_AUTHORIZATION_EMPTY:
	case PQCP_SOVEREIGN_AUTHORIZATION_COLLECTING:
	case PQCP_SOVEREIGN_AUTHORIZATION_COMMITTED:
	case PQCP_SOVEREIGN_AUTHORIZATION_CONSUMED:
	case PQCP_SOVEREIGN_AUTHORIZATION_EXPIRED:
	case PQCP_SOVEREIGN_AUTHORIZATION_REVOKED:
		return true;
	default:
		return false;
	}
}

static bool policy_shape_valid(
	const struct pqcp_sovereign_approval_policy_internal *policy)
{
	const uint32_t known_roles =
		(PQCP_SOVEREIGN_APPROVAL_ROLE_BIT(
			PQCP_SOVEREIGN_APPROVAL_ROLE_COUNT) - 1U) &
		~PQCP_SOVEREIGN_APPROVAL_ROLE_BIT(
			PQCP_SOVEREIGN_APPROVAL_ROLE_NONE);

	if (policy == NULL || !policy->occupied ||
	    policy->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    !pqcp_sovereign_internal_text_valid(
		    policy->tenant_id, sizeof(policy->tenant_id)) ||
	    !action_valid(policy->action) ||
	    policy->required_capabilities == 0U ||
	    policy->allowed_role_mask == 0U ||
	    (policy->allowed_role_mask & ~known_roles) != 0U ||
	    policy->required_approvals == 0U ||
	    policy->required_approvals >
		    PQCP_SOVEREIGN_MAX_APPROVERS ||
	    policy->required_distinct_roles == 0U ||
	    policy->required_distinct_roles >
		    policy->required_approvals ||
	    policy->policy_epoch == 0U ||
	    policy->revocation_epoch == 0U ||
	    policy->not_before_ms == 0U ||
	    policy->expires_at_ms <= policy->not_before_ms ||
	    pqcp_sovereign_internal_digest_zero(
		    policy->target_digest) ||
	    pqcp_sovereign_internal_digest_zero(policy->nonce)) {
		return false;
	}
	return true;
}

static bool credential_shape_valid(
	const struct pqcp_sovereign_signer_credential_internal *credential)
{
	return credential != NULL &&
	       credential->occupied &&
	       credential->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       pqcp_sovereign_internal_text_valid(
		       credential->tenant_id,
		       sizeof(credential->tenant_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       credential->signer_id,
		       sizeof(credential->signer_id)) &&
	       role_valid(credential->role) &&
	       credential->capabilities != 0U &&
	       credential->credential_epoch != 0U &&
	       credential->revocation_epoch != 0U &&
	       credential->not_before_ms != 0U &&
	       credential->expires_at_ms >
		       credential->not_before_ms &&
	       pqcp_runtime_key_handle_is_valid(
		       &credential->verification_key) &&
	       (credential->verification_key.family ==
			PQCP_RUNTIME_KEY_MLDSA_PUBLIC ||
		credential->verification_key.family ==
			PQCP_RUNTIME_KEY_MLDSA_KEYPAIR) &&
	       !pqcp_sovereign_internal_digest_zero(
		       credential->identity_digest);
}

static bool signed_approval_shape_valid(
	const struct pqcp_sovereign_signed_approval_internal *approval)
{
	return approval != NULL &&
	       approval->occupied &&
	       approval->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       approval->authorization_id != 0U &&
	       pqcp_sovereign_internal_text_valid(
		       approval->tenant_id,
		       sizeof(approval->tenant_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       approval->signer_id,
		       sizeof(approval->signer_id)) &&
	       role_valid(approval->role) &&
	       action_valid(approval->action) &&
	       approval->capabilities != 0U &&
	       approval->credential_epoch != 0U &&
	       approval->policy_epoch != 0U &&
	       approval->revocation_epoch != 0U &&
	       approval->signed_at_ms != 0U &&
	       approval->not_before_ms != 0U &&
	       approval->expires_at_ms > approval->not_before_ms &&
	       !pqcp_sovereign_internal_digest_zero(
		       approval->target_digest) &&
	       !pqcp_sovereign_internal_digest_zero(
		       approval->nonce) &&
	       !pqcp_sovereign_internal_digest_zero(
		       approval->approval_digest) &&
	       approval->signature_length != 0U &&
	       approval->signature_length <=
		       sizeof(approval->signature);
}

int pqcp_sovereign_internal_approval_body(
	const struct pqcp_sovereign_signed_approval_internal *approval,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	size_t offset = 0U;

	if (approval == NULL || output == NULL ||
	    output_length == NULL ||
	    output_capacity <
		    PQCP_SOVEREIGN_CANONICAL_APPROVAL_BYTES) {
		return -EINVAL;
	}
	*output_length = 0U;
	memset(output, 0, output_capacity);
	offset = pqcp_sovereign_internal_encode_text(
		output, output_capacity, offset, APPROVAL_BODY_DOMAIN,
		sizeof(APPROVAL_BODY_DOMAIN));
	offset = pqcp_sovereign_internal_encode_u32(
		output, output_capacity, offset,
		approval->schema_version);
	offset = pqcp_sovereign_internal_encode_u64(
		output, output_capacity, offset,
		approval->authorization_id);
	offset = pqcp_sovereign_internal_encode_text(
		output, output_capacity, offset, approval->tenant_id,
		sizeof(approval->tenant_id));
	offset = pqcp_sovereign_internal_encode_text(
		output, output_capacity, offset, approval->signer_id,
		sizeof(approval->signer_id));
	offset = pqcp_sovereign_internal_encode_u32(
		output, output_capacity, offset,
		(uint32_t)approval->role);
	offset = pqcp_sovereign_internal_encode_u32(
		output, output_capacity, offset,
		(uint32_t)approval->action);
	offset = pqcp_sovereign_internal_encode_u64(
		output, output_capacity, offset,
		approval->capabilities);
	offset = pqcp_sovereign_internal_encode_u64(
		output, output_capacity, offset,
		approval->credential_epoch);
	offset = pqcp_sovereign_internal_encode_u64(
		output, output_capacity, offset,
		approval->policy_epoch);
	offset = pqcp_sovereign_internal_encode_u64(
		output, output_capacity, offset,
		approval->revocation_epoch);
	offset = pqcp_sovereign_internal_encode_u64(
		output, output_capacity, offset,
		approval->signed_at_ms);
	offset = pqcp_sovereign_internal_encode_u64(
		output, output_capacity, offset,
		approval->not_before_ms);
	offset = pqcp_sovereign_internal_encode_u64(
		output, output_capacity, offset,
		approval->expires_at_ms);
	offset = pqcp_sovereign_internal_encode_bytes(
		output, output_capacity, offset,
		approval->target_digest,
		sizeof(approval->target_digest));
	offset = pqcp_sovereign_internal_encode_bytes(
		output, output_capacity, offset, approval->nonce,
		sizeof(approval->nonce));
	offset = pqcp_sovereign_internal_encode_bytes(
		output, output_capacity, offset,
		approval->previous_authorization_digest,
		sizeof(approval->previous_authorization_digest));
	offset = pqcp_sovereign_internal_encode_u32(
		output, output_capacity, offset,
		approval->approve ? 1U : 0U);
	if (offset == 0U || offset > output_capacity) {
		pqcp_runtime_secure_zero(output, output_capacity);
		return -EOVERFLOW;
	}
	*output_length = offset;
	return 0;
}

int pqcp_sovereign_internal_approval_digest(
	const struct pqcp_sovereign_signed_approval_internal *approval,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_APPROVAL_BYTES];
	size_t length = 0U;
	int ret;

	ret = pqcp_sovereign_internal_approval_body(
		approval, body, sizeof(body), &length);
	if (ret == 0) {
		ret = pqcp_sovereign_internal_hash(
			body, length, digest);
	}
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_sovereign_internal_policy_digest(
	const struct pqcp_sovereign_approval_policy_internal *policy,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_APPROVAL_BYTES];
	size_t offset = 0U;
	int ret;

	if (policy == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_internal_encode_text(
		body, sizeof(body), offset, APPROVAL_POLICY_DOMAIN,
		sizeof(APPROVAL_POLICY_DOMAIN));
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset, policy->schema_version);
	offset = pqcp_sovereign_internal_encode_text(
		body, sizeof(body), offset, policy->tenant_id,
		sizeof(policy->tenant_id));
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset, (uint32_t)policy->action);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset,
		policy->required_capabilities);
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset, policy->allowed_role_mask);
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset, policy->required_approvals);
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset,
		policy->required_distinct_roles);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset, policy->policy_epoch);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset, policy->revocation_epoch);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset, policy->not_before_ms);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset, policy->expires_at_ms);
	offset = pqcp_sovereign_internal_encode_bytes(
		body, sizeof(body), offset, policy->target_digest,
		sizeof(policy->target_digest));
	offset = pqcp_sovereign_internal_encode_bytes(
		body, sizeof(body), offset, policy->nonce,
		sizeof(policy->nonce));
	offset = pqcp_sovereign_internal_encode_bytes(
		body, sizeof(body), offset,
		policy->previous_authorization_digest,
		sizeof(policy->previous_authorization_digest));
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_sovereign_internal_hash(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_sovereign_internal_authorization_digest(
	const struct pqcp_sovereign_committed_authorization_internal *authorization,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_AUTHORIZATION_BYTES];
	size_t offset = 0U;
	int ret;

	if (authorization == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_internal_encode_text(
		body, sizeof(body), offset, AUTHORIZATION_BODY_DOMAIN,
		sizeof(AUTHORIZATION_BODY_DOMAIN));
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset,
		authorization->schema_version);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset,
		authorization->authorization_id);
	offset = pqcp_sovereign_internal_encode_text(
		body, sizeof(body), offset, authorization->tenant_id,
		sizeof(authorization->tenant_id));
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset,
		(uint32_t)authorization->action);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset,
		authorization->policy_epoch);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset,
		authorization->revocation_epoch);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset,
		authorization->committed_at_ms);
	offset = pqcp_sovereign_internal_encode_u64(
		body, sizeof(body), offset,
		authorization->expires_at_ms);
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset,
		authorization->approval_count);
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset,
		authorization->distinct_role_count);
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset,
		authorization->signer_mask);
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset,
		authorization->role_mask);
	offset = pqcp_sovereign_internal_encode_u32(
		body, sizeof(body), offset,
		authorization->maximum_uses);
	offset = pqcp_sovereign_internal_encode_bytes(
		body, sizeof(body), offset,
		authorization->target_digest,
		sizeof(authorization->target_digest));
	offset = pqcp_sovereign_internal_encode_bytes(
		body, sizeof(body), offset, authorization->nonce,
		sizeof(authorization->nonce));
	offset = pqcp_sovereign_internal_encode_bytes(
		body, sizeof(body), offset,
		authorization->previous_authorization_digest,
		sizeof(authorization->previous_authorization_digest));
	offset = pqcp_sovereign_internal_encode_bytes(
		body, sizeof(body), offset,
		authorization->approvals_digest,
		sizeof(authorization->approvals_digest));
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_sovereign_internal_hash(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int lock_engine(
	struct pqcp_sovereign_authorization_engine_internal *engine)
{
	if (engine == NULL || !engine->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&engine->lock, K_FOREVER);
}

static void unlock_engine(
	struct pqcp_sovereign_authorization_engine_internal *engine)
{
	(void)k_mutex_unlock(&engine->lock);
}

static int authorization_slot_index_locked(
	const struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t authorization_id)
{
	size_t index;

	if (authorization_id == 0U) {
		return -EINVAL;
	}
	for (index = 0U; index < engine->capacity; ++index) {
		const struct pqcp_sovereign_authorization_slot_internal *slot =
			&engine->slots[index];

		if (slot->occupied &&
		    (slot->committed.authorization_id ==
			     authorization_id ||
		     (slot->committed.authorization_id == 0U &&
		      slot->approvals[0].authorization_id ==
			      authorization_id))) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static uint64_t slot_authorization_id(
	const struct pqcp_sovereign_authorization_slot_internal *slot)
{
	size_t index;

	if (slot->committed.authorization_id != 0U) {
		return slot->committed.authorization_id;
	}
	for (index = 0U; index < ARRAY_SIZE(slot->approvals);
	     ++index) {
		if (slot->approvals[index].occupied) {
			return slot->approvals[index].authorization_id;
		}
	}
	return 0U;
}

static int slot_index_by_id_locked(
	const struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t authorization_id)
{
	size_t index;

	for (index = 0U; index < engine->capacity; ++index) {
		if (engine->slots[index].occupied &&
		    slot_authorization_id(&engine->slots[index]) ==
			    authorization_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_authorization_slot_locked(
	const struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t now_ms)
{
	size_t index;

	for (index = 0U; index < engine->capacity; ++index) {
		if (!engine->slots[index].occupied) {
			return (int)index;
		}
	}
	for (index = 0U; index < engine->capacity; ++index) {
		const struct pqcp_sovereign_authorization_slot_internal *slot =
			&engine->slots[index];

		if ((slot->committed.state ==
			     PQCP_SOVEREIGN_AUTHORIZATION_EXPIRED ||
		     slot->committed.state ==
			     PQCP_SOVEREIGN_AUTHORIZATION_REVOKED ||
		     slot->committed.state ==
			     PQCP_SOVEREIGN_AUTHORIZATION_CONSUMED) &&
		    slot->policy.expires_at_ms <= now_ms) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int approval_index_by_signer(
	const struct pqcp_sovereign_authorization_slot_internal *slot,
	const char *signer_id)
{
	size_t index;

	for (index = 0U; index < ARRAY_SIZE(slot->approvals);
	     ++index) {
		if (slot->approvals[index].occupied &&
		    strcmp(slot->approvals[index].signer_id,
			   signer_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_approval_index(
	const struct pqcp_sovereign_authorization_slot_internal *slot)
{
	size_t index;

	for (index = 0U; index < ARRAY_SIZE(slot->approvals);
	     ++index) {
		if (!slot->approvals[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static uint32_t approval_role_mask(
	const struct pqcp_sovereign_authorization_slot_internal *slot)
{
	uint32_t mask = 0U;
	size_t index;

	for (index = 0U; index < ARRAY_SIZE(slot->approvals);
	     ++index) {
		const struct pqcp_sovereign_signed_approval_internal *approval =
			&slot->approvals[index];

		if (approval->occupied && approval->approve) {
			mask |= PQCP_SOVEREIGN_APPROVAL_ROLE_BIT(
				approval->role);
		}
	}
	return mask;
}

static uint32_t bit_count_u32(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += value & 1U;
		value >>= 1U;
	}
	return count;
}

static int approval_set_digest(
	const struct pqcp_sovereign_authorization_slot_internal *slot,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_AUTHORIZATION_BYTES];
	size_t offset = 0U;
	size_t index;
	int ret;

	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_internal_encode_text(
		body, sizeof(body), offset, APPROVAL_SET_DOMAIN,
		sizeof(APPROVAL_SET_DOMAIN));
	offset = pqcp_sovereign_internal_encode_bytes(
		body, sizeof(body), offset, slot->policy.policy_digest,
		sizeof(slot->policy.policy_digest));
	for (index = 0U; index < ARRAY_SIZE(slot->approvals);
	     ++index) {
		const struct pqcp_sovereign_signed_approval_internal *approval =
			&slot->approvals[index];

		if (!approval->occupied || !approval->approve) {
			continue;
		}
		offset = pqcp_sovereign_internal_encode_bytes(
			body, sizeof(body), offset,
			approval->approval_digest,
			sizeof(approval->approval_digest));
		if (offset == 0U) {
			pqcp_runtime_secure_zero(body, sizeof(body));
			return -EOVERFLOW;
		}
	}
	ret = pqcp_sovereign_internal_hash(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int verify_signed_approval(
	struct pqcp_runtime_key_store *key_store,
	const struct pqcp_sovereign_signer_credential_internal *credential,
	const struct pqcp_sovereign_signed_approval_internal *approval)
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_APPROVAL_BYTES];
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	size_t body_length = 0U;
	int ret;

	ret = pqcp_sovereign_internal_approval_body(
		approval, body, sizeof(body), &body_length);
	if (ret == 0) {
		ret = pqcp_sovereign_internal_hash(
			body, body_length, digest);
	}
	if (ret == 0 &&
	    !pqcp_sovereign_internal_digest_equal(
		    digest, approval->approval_digest)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_runtime_key_store_verify(
			key_store, &credential->verification_key,
			body, body_length,
			(const uint8_t *)PQCP_SOVEREIGN_APPROVAL_CONTEXT,
			strlen(PQCP_SOVEREIGN_APPROVAL_CONTEXT),
			approval->signature,
			approval->signature_length);
	}
	pqcp_runtime_secure_zero(body, sizeof(body));
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int validate_approval_binding(
	const struct pqcp_sovereign_approval_policy_internal *policy,
	const struct pqcp_sovereign_signer_credential_internal *credential,
	const struct pqcp_sovereign_signed_approval_internal *approval,
	uint64_t authorization_id,
	uint64_t now_ms)
{
	if (!credential_shape_valid(credential) ||
	    !signed_approval_shape_valid(approval)) {
		return -EINVAL;
	}
	if (credential->revoked) {
		return -EACCES;
	}
	if (strcmp(policy->tenant_id, credential->tenant_id) != 0 ||
	    strcmp(policy->tenant_id, approval->tenant_id) != 0 ||
	    strcmp(credential->signer_id, approval->signer_id) != 0) {
		return -EACCES;
	}
	if (approval->authorization_id != authorization_id ||
	    approval->action != policy->action ||
	    approval->role != credential->role ||
	    (policy->allowed_role_mask &
	     PQCP_SOVEREIGN_APPROVAL_ROLE_BIT(approval->role)) == 0U) {
		return -EACCES;
	}
	if ((credential->capabilities &
	     policy->required_capabilities) !=
		    policy->required_capabilities ||
	    (approval->capabilities &
	     policy->required_capabilities) !=
		    policy->required_capabilities ||
	    (approval->capabilities & credential->capabilities) !=
		    approval->capabilities) {
		return -EACCES;
	}
	if (credential->credential_epoch !=
		    approval->credential_epoch ||
	    credential->credential_epoch < policy->policy_epoch ||
	    approval->policy_epoch != policy->policy_epoch ||
	    credential->revocation_epoch !=
		    approval->revocation_epoch ||
	    approval->revocation_epoch !=
		    policy->revocation_epoch) {
		return -ESTALE;
	}
	if (now_ms < policy->not_before_ms ||
	    now_ms >= policy->expires_at_ms ||
	    now_ms < credential->not_before_ms ||
	    now_ms >= credential->expires_at_ms ||
	    now_ms < approval->not_before_ms ||
	    now_ms >= approval->expires_at_ms ||
	    approval->signed_at_ms < approval->not_before_ms ||
	    approval->signed_at_ms >= approval->expires_at_ms ||
	    approval->not_before_ms < policy->not_before_ms ||
	    approval->expires_at_ms > policy->expires_at_ms ||
	    approval->not_before_ms < credential->not_before_ms ||
	    approval->expires_at_ms > credential->expires_at_ms) {
		return -ETIMEDOUT;
	}
	if (!pqcp_sovereign_internal_digest_equal(
		    policy->target_digest,
		    approval->target_digest) ||
	    !pqcp_sovereign_internal_digest_equal(
		    policy->nonce, approval->nonce) ||
	    !pqcp_sovereign_internal_digest_equal(
		    policy->previous_authorization_digest,
		    approval->previous_authorization_digest)) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_sovereign_authorization_engine_init_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	struct pqcp_sovereign_authorization_slot_internal *slots,
	size_t capacity,
	struct pqcp_runtime_key_store *key_store)
{
	if (engine == NULL || slots == NULL || capacity == 0U ||
	    capacity > PQCP_SOVEREIGN_MAX_AUTHORIZATIONS ||
	    key_store == NULL) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	memset(slots, 0, capacity * sizeof(*slots));
	engine->slots = slots;
	engine->capacity = capacity;
	engine->next_authorization_id = 1U;
	engine->key_store = key_store;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

int pqcp_sovereign_authorization_open_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	const struct pqcp_sovereign_approval_policy_internal *policy,
	uint64_t now_ms,
	uint64_t *authorization_id)
{
	struct pqcp_sovereign_authorization_slot_internal staged;
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int slot;
	int ret;

	if (authorization_id == NULL ||
	    !policy_shape_valid(policy) ||
	    now_ms < policy->not_before_ms ||
	    now_ms >= policy->expires_at_ms) {
		return -EINVAL;
	}
	*authorization_id = 0U;
	ret = pqcp_sovereign_internal_policy_digest(
		policy, digest);
	if (ret != 0) {
		return ret;
	}
	if (!pqcp_sovereign_internal_digest_zero(
		    policy->policy_digest) &&
	    !pqcp_sovereign_internal_digest_equal(
		    policy->policy_digest, digest)) {
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return -EBADMSG;
	}
	ret = lock_engine(engine);
	if (ret != 0) {
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return ret;
	}
	if (engine->next_authorization_id == 0U ||
	    engine->next_authorization_id == UINT64_MAX) {
		unlock_engine(engine);
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return -EOVERFLOW;
	}
	slot = free_authorization_slot_locked(engine, now_ms);
	if (slot < 0) {
		unlock_engine(engine);
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return slot;
	}
	memset(&staged, 0, sizeof(staged));
	staged.policy = *policy;
	memcpy(staged.policy.policy_digest, digest,
	       sizeof(staged.policy.policy_digest));
	staged.opened_at_ms = now_ms;
	staged.occupied = true;
	staged.committed.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.committed.authorization_id =
		engine->next_authorization_id++;
	staged.committed.state =
		PQCP_SOVEREIGN_AUTHORIZATION_COLLECTING;
	staged.committed.occupied = true;
	engine->slots[slot] = staged;
	*authorization_id =
		staged.committed.authorization_id;
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	unlock_engine(engine);
	return 0;
}

int pqcp_sovereign_authorization_submit_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	const struct pqcp_sovereign_signer_credential_internal *credential,
	const struct pqcp_sovereign_signed_approval_internal *approval,
	uint64_t now_ms)
{
	struct pqcp_sovereign_authorization_slot_internal *slot;
	int slot_index;
	int approval_index;
	int ret;

	if (now_ms == 0U || credential == NULL ||
	    approval == NULL) {
		return -EINVAL;
	}
	ret = lock_engine(engine);
	if (ret != 0) {
		return ret;
	}
	slot_index = slot_index_by_id_locked(
		engine, approval->authorization_id);
	if (slot_index < 0) {
		engine->rejected_count++;
		unlock_engine(engine);
		return slot_index;
	}
	slot = &engine->slots[slot_index];
	if (slot->committed.state !=
	    PQCP_SOVEREIGN_AUTHORIZATION_COLLECTING) {
		engine->rejected_count++;
		unlock_engine(engine);
		return -EALREADY;
	}
	ret = validate_approval_binding(
		&slot->policy, credential, approval,
		slot->committed.authorization_id, now_ms);
	if (ret != 0) {
		engine->rejected_count++;
		unlock_engine(engine);
		return ret;
	}
	if (approval_index_by_signer(
		    slot, approval->signer_id) >= 0) {
		engine->replay_count++;
		unlock_engine(engine);
		return -EALREADY;
	}
	approval_index = free_approval_index(slot);
	if (approval_index < 0) {
		engine->rejected_count++;
		unlock_engine(engine);
		return approval_index;
	}
	ret = verify_signed_approval(
		engine->key_store, credential, approval);
	if (ret != 0) {
		engine->rejected_count++;
		unlock_engine(engine);
		return ret;
	}
	slot->approvals[approval_index] = *approval;
	if (approval->approve) {
		slot->approval_count++;
		slot->role_mask |=
			PQCP_SOVEREIGN_APPROVAL_ROLE_BIT(
				approval->role);
		slot->distinct_role_count =
			bit_count_u32(slot->role_mask);
	} else {
		slot->rejection_count++;
	}
	unlock_engine(engine);
	return 0;
}

static int committed_authorization_build(
	const struct pqcp_sovereign_authorization_slot_internal *slot,
	uint64_t now_ms,
	uint32_t maximum_uses,
	struct pqcp_sovereign_committed_authorization_internal *result)
{
	uint32_t signer_mask = 0U;
	size_t index;
	int ret;

	if (slot->approval_count <
		    slot->policy.required_approvals ||
	    slot->distinct_role_count <
		    slot->policy.required_distinct_roles ||
	    maximum_uses == 0U) {
		return -EACCES;
	}
	memset(result, 0, sizeof(*result));
	result->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	result->authorization_id =
		slot->committed.authorization_id;
	ret = pqcp_sovereign_internal_copy_text(
		result->tenant_id, sizeof(result->tenant_id),
		slot->policy.tenant_id);
	if (ret != 0) {
		return ret;
	}
	result->action = slot->policy.action;
	result->policy_epoch = slot->policy.policy_epoch;
	result->revocation_epoch = slot->policy.revocation_epoch;
	result->committed_at_ms = now_ms;
	result->expires_at_ms = slot->policy.expires_at_ms;
	result->approval_count = slot->approval_count;
	result->distinct_role_count = slot->distinct_role_count;
	result->role_mask = slot->role_mask;
	result->maximum_uses = maximum_uses;
	memcpy(result->target_digest, slot->policy.target_digest,
	       sizeof(result->target_digest));
	memcpy(result->nonce, slot->policy.nonce,
	       sizeof(result->nonce));
	memcpy(result->previous_authorization_digest,
	       slot->policy.previous_authorization_digest,
	       sizeof(result->previous_authorization_digest));
	for (index = 0U; index < ARRAY_SIZE(slot->approvals);
	     ++index) {
		if (slot->approvals[index].occupied &&
		    slot->approvals[index].approve) {
			signer_mask |= 1U << index;
		}
	}
	result->signer_mask = signer_mask;
	ret = approval_set_digest(slot, result->approvals_digest);
	if (ret != 0) {
		return ret;
	}
	result->state = PQCP_SOVEREIGN_AUTHORIZATION_COMMITTED;
	result->occupied = true;
	ret = pqcp_sovereign_internal_authorization_digest(
		result, result->authorization_digest);
	return ret;
}

int pqcp_sovereign_authorization_commit_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t authorization_id,
	uint64_t now_ms,
	uint32_t maximum_uses,
	struct pqcp_sovereign_committed_authorization_internal *authorization)
{
	struct pqcp_sovereign_authorization_slot_internal *slot;
	struct pqcp_sovereign_committed_authorization_internal staged;
	int index;
	int ret;

	if (authorization_id == 0U || now_ms == 0U ||
	    maximum_uses == 0U || authorization == NULL) {
		return -EINVAL;
	}
	memset(authorization, 0, sizeof(*authorization));
	ret = lock_engine(engine);
	if (ret != 0) {
		return ret;
	}
	index = slot_index_by_id_locked(engine, authorization_id);
	if (index < 0) {
		unlock_engine(engine);
		return index;
	}
	slot = &engine->slots[index];
	if (slot->committed.state !=
	    PQCP_SOVEREIGN_AUTHORIZATION_COLLECTING) {
		unlock_engine(engine);
		return -EALREADY;
	}
	if (now_ms < slot->policy.not_before_ms ||
	    now_ms >= slot->policy.expires_at_ms) {
		slot->committed.state =
			PQCP_SOVEREIGN_AUTHORIZATION_EXPIRED;
		unlock_engine(engine);
		return -ETIMEDOUT;
	}
	ret = committed_authorization_build(
		slot, now_ms, maximum_uses, &staged);
	if (ret != 0) {
		engine->rejected_count++;
		unlock_engine(engine);
		return ret;
	}
	slot->committed = staged;
	*authorization = staged;
	if (engine->committed_count != UINT64_MAX) {
		engine->committed_count++;
	}
	unlock_engine(engine);
	return 0;
}

int pqcp_sovereign_authorization_consume_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t authorization_id,
	const char *tenant_id,
	enum pqcp_sovereign_ceremony_action action,
	const uint8_t target_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms,
	struct pqcp_sovereign_committed_authorization_internal *authorization)
{
	struct pqcp_sovereign_committed_authorization_internal *committed;
	int index;
	int ret;

	if (authorization_id == 0U ||
	    !pqcp_sovereign_internal_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !action_valid(action) || target_digest == NULL ||
	    pqcp_sovereign_internal_digest_zero(target_digest) ||
	    policy_epoch == 0U || revocation_epoch == 0U ||
	    now_ms == 0U || authorization == NULL) {
		return -EINVAL;
	}
	memset(authorization, 0, sizeof(*authorization));
	ret = lock_engine(engine);
	if (ret != 0) {
		return ret;
	}
	index = slot_index_by_id_locked(engine, authorization_id);
	if (index < 0) {
		unlock_engine(engine);
		return index;
	}
	committed = &engine->slots[index].committed;
	if (committed->state !=
	    PQCP_SOVEREIGN_AUTHORIZATION_COMMITTED) {
		unlock_engine(engine);
		return committed->state ==
		       PQCP_SOVEREIGN_AUTHORIZATION_EXPIRED ?
		       -ETIMEDOUT : -EACCES;
	}
	if (now_ms < committed->committed_at_ms ||
	    now_ms >= committed->expires_at_ms) {
		committed->state =
			PQCP_SOVEREIGN_AUTHORIZATION_EXPIRED;
		unlock_engine(engine);
		return -ETIMEDOUT;
	}
	if (strcmp(committed->tenant_id, tenant_id) != 0 ||
	    committed->action != action ||
	    committed->policy_epoch != policy_epoch ||
	    committed->revocation_epoch != revocation_epoch ||
	    !pqcp_sovereign_internal_digest_equal(
		    committed->target_digest, target_digest)) {
		unlock_engine(engine);
		return -EACCES;
	}
	if (committed->use_count >= committed->maximum_uses) {
		committed->state =
			PQCP_SOVEREIGN_AUTHORIZATION_CONSUMED;
		unlock_engine(engine);
		return -EACCES;
	}
	committed->use_count++;
	*authorization = *committed;
	if (committed->use_count == committed->maximum_uses) {
		committed->state =
			PQCP_SOVEREIGN_AUTHORIZATION_CONSUMED;
	}
	unlock_engine(engine);
	return 0;
}

int pqcp_sovereign_authorization_revoke_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t authorization_id)
{
	int index;
	int ret;

	ret = lock_engine(engine);
	if (ret != 0) {
		return ret;
	}
	index = slot_index_by_id_locked(engine, authorization_id);
	if (index < 0) {
		unlock_engine(engine);
		return index;
	}
	if (engine->slots[index].committed.state ==
	    PQCP_SOVEREIGN_AUTHORIZATION_REVOKED) {
		unlock_engine(engine);
		return -EALREADY;
	}
	engine->slots[index].committed.state =
		PQCP_SOVEREIGN_AUTHORIZATION_REVOKED;
	unlock_engine(engine);
	return 0;
}

int pqcp_sovereign_authorization_tick_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t count = 0U;
	size_t index;
	int ret;

	if (now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	*expired_count = 0U;
	ret = lock_engine(engine);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < engine->capacity; ++index) {
		struct pqcp_sovereign_authorization_slot_internal *slot =
			&engine->slots[index];

		if (!slot->occupied ||
		    (slot->committed.state !=
			     PQCP_SOVEREIGN_AUTHORIZATION_COLLECTING &&
		     slot->committed.state !=
			     PQCP_SOVEREIGN_AUTHORIZATION_COMMITTED) ||
		    now_ms < slot->policy.expires_at_ms) {
			continue;
		}
		slot->committed.state =
			PQCP_SOVEREIGN_AUTHORIZATION_EXPIRED;
		if (count != UINT32_MAX) {
			count++;
		}
	}
	*expired_count = count;
	unlock_engine(engine);
	return 0;
}

static int audit_approval_slot(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	const struct pqcp_sovereign_authorization_slot_internal *slot)
{
	uint8_t expected[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint32_t approvals = 0U;
	uint32_t rejections = 0U;
	uint32_t role_mask = 0U;
	size_t left;
	size_t right;
	int ret;

	if (!slot->occupied || !policy_shape_valid(&slot->policy) ||
	    slot->opened_at_ms < slot->policy.not_before_ms ||
	    slot->opened_at_ms >= slot->policy.expires_at_ms ||
	    slot->committed.authorization_id == 0U ||
	    !authorization_state_valid(slot->committed.state)) {
		return -EBADMSG;
	}
	ret = pqcp_sovereign_internal_policy_digest(
		&slot->policy, expected);
	if (ret != 0 ||
	    !pqcp_sovereign_internal_digest_equal(
		    expected, slot->policy.policy_digest)) {
		pqcp_runtime_secure_zero(expected, sizeof(expected));
		return ret != 0 ? ret : -EBADMSG;
	}
	for (left = 0U; left < ARRAY_SIZE(slot->approvals);
	     ++left) {
		const struct pqcp_sovereign_signed_approval_internal *approval =
			&slot->approvals[left];

		if (!approval->occupied) {
			continue;
		}
		if (!signed_approval_shape_valid(approval) ||
		    approval->authorization_id !=
			    slot->committed.authorization_id ||
		    strcmp(approval->tenant_id,
			   slot->policy.tenant_id) != 0 ||
		    approval->action != slot->policy.action ||
		    approval->policy_epoch !=
			    slot->policy.policy_epoch ||
		    approval->revocation_epoch !=
			    slot->policy.revocation_epoch ||
		    !pqcp_sovereign_internal_digest_equal(
			    approval->target_digest,
			    slot->policy.target_digest) ||
		    !pqcp_sovereign_internal_digest_equal(
			    approval->nonce, slot->policy.nonce) ||
		    !pqcp_sovereign_internal_digest_equal(
			    approval->previous_authorization_digest,
			    slot->policy
				    .previous_authorization_digest)) {
			pqcp_runtime_secure_zero(expected, sizeof(expected));
			return -EBADMSG;
		}
		ret = pqcp_sovereign_internal_approval_digest(
			approval, expected);
		if (ret != 0 ||
		    !pqcp_sovereign_internal_digest_equal(
			    expected, approval->approval_digest)) {
			pqcp_runtime_secure_zero(expected, sizeof(expected));
			return ret != 0 ? ret : -EBADMSG;
		}
		for (right = left + 1U;
		     right < ARRAY_SIZE(slot->approvals); ++right) {
			if (slot->approvals[right].occupied &&
			    strcmp(slot->approvals[right].signer_id,
				   approval->signer_id) == 0) {
				pqcp_runtime_secure_zero(
					expected, sizeof(expected));
				return -EBADMSG;
			}
		}
		if (approval->approve) {
			approvals++;
			role_mask |=
				PQCP_SOVEREIGN_APPROVAL_ROLE_BIT(
					approval->role);
		} else {
			rejections++;
		}
	}
	if (approvals != slot->approval_count ||
	    rejections != slot->rejection_count ||
	    role_mask != slot->role_mask ||
	    bit_count_u32(role_mask) != slot->distinct_role_count) {
		pqcp_runtime_secure_zero(expected, sizeof(expected));
		return -EBADMSG;
	}
	if (slot->committed.state !=
	    PQCP_SOVEREIGN_AUTHORIZATION_COLLECTING) {
		uint8_t approval_digest[PQCP_SOVEREIGN_DIGEST_BYTES];

		ret = approval_set_digest(slot, approval_digest);
		if (ret != 0 ||
		    !pqcp_sovereign_internal_digest_equal(
			    approval_digest,
			    slot->committed.approvals_digest)) {
			pqcp_runtime_secure_zero(
				approval_digest, sizeof(approval_digest));
			pqcp_runtime_secure_zero(
				expected, sizeof(expected));
			return ret != 0 ? ret : -EBADMSG;
		}
		ret = pqcp_sovereign_internal_authorization_digest(
			&slot->committed, expected);
		pqcp_runtime_secure_zero(
			approval_digest, sizeof(approval_digest));
		if (ret != 0 ||
		    !pqcp_sovereign_internal_digest_equal(
			    expected,
			    slot->committed.authorization_digest)) {
			pqcp_runtime_secure_zero(
				expected, sizeof(expected));
			return ret != 0 ? ret : -EBADMSG;
		}
		if (slot->committed.approval_count != approvals ||
		    slot->committed.distinct_role_count !=
			    bit_count_u32(role_mask) ||
		    slot->committed.role_mask != role_mask ||
		    slot->committed.use_count >
			    slot->committed.maximum_uses) {
			pqcp_runtime_secure_zero(
				expected, sizeof(expected));
			return -EBADMSG;
		}
	}
	pqcp_runtime_secure_zero(expected, sizeof(expected));
	return 0;
}

int pqcp_sovereign_authorization_audit_internal(
	struct pqcp_sovereign_authorization_engine_internal *engine)
{
	uint64_t maximum_id = 0U;
	size_t left;
	size_t right;
	int ret;

	ret = lock_engine(engine);
	if (ret != 0) {
		return ret;
	}
	if (engine->slots == NULL || engine->capacity == 0U ||
	    engine->capacity > PQCP_SOVEREIGN_MAX_AUTHORIZATIONS ||
	    engine->next_authorization_id == 0U ||
	    engine->key_store == NULL) {
		unlock_engine(engine);
		return -EBADMSG;
	}
	for (left = 0U; left < engine->capacity; ++left) {
		uint64_t authorization_id;

		if (!engine->slots[left].occupied) {
			continue;
		}
		ret = audit_approval_slot(
			engine, &engine->slots[left]);
		if (ret != 0) {
			unlock_engine(engine);
			return ret;
		}
		authorization_id =
			slot_authorization_id(&engine->slots[left]);
		if (authorization_id > maximum_id) {
			maximum_id = authorization_id;
		}
		for (right = left + 1U;
		     right < engine->capacity; ++right) {
			if (engine->slots[right].occupied &&
			    slot_authorization_id(
				    &engine->slots[right]) ==
				    authorization_id) {
				unlock_engine(engine);
				return -EBADMSG;
			}
		}
	}
	if (maximum_id != 0U &&
	    engine->next_authorization_id <= maximum_id) {
		unlock_engine(engine);
		return -EBADMSG;
	}
	unlock_engine(engine);
	return 0;
}
