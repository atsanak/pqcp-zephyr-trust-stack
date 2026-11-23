/*
 * SPDX-License-Identifier: MIT
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

bool pqcp_sovereign_ceremony_text_valid(
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

int pqcp_sovereign_ceremony_copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	size_t length;

	if (destination == NULL ||
	    !pqcp_sovereign_ceremony_text_valid(source, capacity)) {
		return -EINVAL;
	}
	length = strnlen(source, capacity);
	memset(destination, 0, capacity);
	memcpy(destination, source, length);
	return 0;
}

bool pqcp_sovereign_ceremony_digest_zero(
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

bool pqcp_sovereign_ceremony_digest_equal(
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

bool pqcp_sovereign_ceremony_u64_add(
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

bool pqcp_sovereign_ceremony_u32_add(
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

size_t pqcp_sovereign_ceremony_encode_u32(
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

size_t pqcp_sovereign_ceremony_encode_u64(
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

size_t pqcp_sovereign_ceremony_encode_bytes(
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
	next = pqcp_sovereign_ceremony_encode_u32(
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

size_t pqcp_sovereign_ceremony_encode_text(
	uint8_t *output,
	size_t capacity,
	size_t offset,
	const char *text,
	size_t maximum)
{
	size_t length;

	if (!pqcp_sovereign_ceremony_text_valid(text, maximum)) {
		return 0U;
	}
	length = strnlen(text, maximum);
	return pqcp_sovereign_ceremony_encode_bytes(
		output, capacity, offset,
		(const uint8_t *)text, length);
}

int pqcp_sovereign_ceremony_hash(
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

int pqcp_sovereign_ceremony_hash_parts(
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

const char *pqcp_sovereign_ceremony_action_text(
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

const char *pqcp_sovereign_ceremony_role_text(
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
pqcp_sovereign_ceremony_action_from_text(const char *action)
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

static uint32_t bit_count_u32(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += value & 1U;
		value >>= 1U;
	}
	return count;
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
	    !pqcp_sovereign_ceremony_text_valid(
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
	    policy->required_distinct_roles >
		    bit_count_u32(policy->allowed_role_mask) ||
	    policy->policy_epoch == 0U ||
	    policy->revocation_epoch == 0U ||
	    policy->not_before_ms == 0U ||
	    policy->expires_at_ms <= policy->not_before_ms ||
	    pqcp_sovereign_ceremony_digest_zero(
		    policy->target_digest) ||
	    pqcp_sovereign_ceremony_digest_zero(policy->nonce)) {
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
	       pqcp_sovereign_ceremony_text_valid(
		       credential->tenant_id,
		       sizeof(credential->tenant_id)) &&
	       pqcp_sovereign_ceremony_text_valid(
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
	       !pqcp_sovereign_ceremony_digest_zero(
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
	       pqcp_sovereign_ceremony_text_valid(
		       approval->tenant_id,
		       sizeof(approval->tenant_id)) &&
	       pqcp_sovereign_ceremony_text_valid(
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
	       !pqcp_sovereign_ceremony_digest_zero(
		       approval->target_digest) &&
	       !pqcp_sovereign_ceremony_digest_zero(
		       approval->nonce) &&
	       !pqcp_sovereign_ceremony_digest_zero(
		       approval->approval_digest) &&
	       approval->signature_length != 0U &&
	       approval->signature_length <=
		       sizeof(approval->signature);
}

int pqcp_sovereign_ceremony_approval_body(
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
	offset = pqcp_sovereign_ceremony_encode_text(
		output, output_capacity, offset, APPROVAL_BODY_DOMAIN,
		sizeof(APPROVAL_BODY_DOMAIN));
	offset = pqcp_sovereign_ceremony_encode_u32(
		output, output_capacity, offset,
		approval->schema_version);
	offset = pqcp_sovereign_ceremony_encode_u64(
		output, output_capacity, offset,
		approval->authorization_id);
	offset = pqcp_sovereign_ceremony_encode_text(
		output, output_capacity, offset, approval->tenant_id,
		sizeof(approval->tenant_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		output, output_capacity, offset, approval->signer_id,
		sizeof(approval->signer_id));
	offset = pqcp_sovereign_ceremony_encode_u32(
		output, output_capacity, offset,
		(uint32_t)approval->role);
	offset = pqcp_sovereign_ceremony_encode_u32(
		output, output_capacity, offset,
		(uint32_t)approval->action);
	offset = pqcp_sovereign_ceremony_encode_u64(
		output, output_capacity, offset,
		approval->capabilities);
	offset = pqcp_sovereign_ceremony_encode_u64(
		output, output_capacity, offset,
		approval->credential_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		output, output_capacity, offset,
		approval->policy_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		output, output_capacity, offset,
		approval->revocation_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		output, output_capacity, offset,
		approval->signed_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		output, output_capacity, offset,
		approval->not_before_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		output, output_capacity, offset,
		approval->expires_at_ms);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		output, output_capacity, offset,
		approval->target_digest,
		sizeof(approval->target_digest));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		output, output_capacity, offset, approval->nonce,
		sizeof(approval->nonce));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		output, output_capacity, offset,
		approval->previous_authorization_digest,
		sizeof(approval->previous_authorization_digest));
	offset = pqcp_sovereign_ceremony_encode_u32(
		output, output_capacity, offset,
		approval->approve ? 1U : 0U);
	if (offset == 0U || offset > output_capacity) {
		pqcp_runtime_secure_zero(output, output_capacity);
		return -EOVERFLOW;
	}
	*output_length = offset;
	return 0;
}

int pqcp_sovereign_ceremony_approval_digest(
	const struct pqcp_sovereign_signed_approval_internal *approval,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_APPROVAL_BYTES];
	size_t length = 0U;
	int ret;

	ret = pqcp_sovereign_ceremony_approval_body(
		approval, body, sizeof(body), &length);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_hash(
			body, length, digest);
	}
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_sovereign_ceremony_policy_digest(
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
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, APPROVAL_POLICY_DOMAIN,
		sizeof(APPROVAL_POLICY_DOMAIN));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, policy->schema_version);
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, policy->tenant_id,
		sizeof(policy->tenant_id));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, (uint32_t)policy->action);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset,
		policy->required_capabilities);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, policy->allowed_role_mask);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, policy->required_approvals);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		policy->required_distinct_roles);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, policy->policy_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, policy->revocation_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, policy->not_before_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, policy->expires_at_ms);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, policy->target_digest,
		sizeof(policy->target_digest));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, policy->nonce,
		sizeof(policy->nonce));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		policy->previous_authorization_digest,
		sizeof(policy->previous_authorization_digest));
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_sovereign_ceremony_hash(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_sovereign_ceremony_authorization_digest(
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
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, AUTHORIZATION_BODY_DOMAIN,
		sizeof(AUTHORIZATION_BODY_DOMAIN));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		authorization->schema_version);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset,
		authorization->authorization_id);
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, authorization->tenant_id,
		sizeof(authorization->tenant_id));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		(uint32_t)authorization->action);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset,
		authorization->policy_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset,
		authorization->revocation_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset,
		authorization->committed_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset,
		authorization->expires_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		authorization->approval_count);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		authorization->distinct_role_count);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		authorization->signer_mask);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		authorization->role_mask);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		authorization->maximum_uses);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		authorization->target_digest,
		sizeof(authorization->target_digest));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, authorization->nonce,
		sizeof(authorization->nonce));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		authorization->previous_authorization_digest,
		sizeof(authorization->previous_authorization_digest));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		authorization->approvals_digest,
		sizeof(authorization->approvals_digest));
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_sovereign_ceremony_hash(body, offset, digest);
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

static int approval_set_digest(
	const struct pqcp_sovereign_authorization_slot_internal *slot,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_AUTHORIZATION_BYTES];
	char previous_signer[PQCP_SOVEREIGN_ID_MAX_CHARS];
	size_t offset = 0U;
	uint32_t ordinal;
	bool have_previous = false;
	int ret;

	memset(body, 0, sizeof(body));
	memset(previous_signer, 0, sizeof(previous_signer));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, APPROVAL_SET_DOMAIN,
		sizeof(APPROVAL_SET_DOMAIN));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, slot->policy.policy_digest,
		sizeof(slot->policy.policy_digest));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, slot->approval_count);
	for (ordinal = 0U; ordinal < slot->approval_count; ++ordinal) {
		const struct pqcp_sovereign_signed_approval_internal *selected =
			NULL;
		size_t index;

		for (index = 0U; index < ARRAY_SIZE(slot->approvals);
		     ++index) {
			const struct pqcp_sovereign_signed_approval_internal
				*candidate = &slot->approvals[index];

			if (!candidate->occupied || !candidate->approve ||
			    (have_previous &&
			     strcmp(candidate->signer_id,
				    previous_signer) <= 0) ||
			    (selected != NULL &&
			     strcmp(candidate->signer_id,
				    selected->signer_id) >= 0)) {
				continue;
			}
			selected = candidate;
		}
		if (selected == NULL) {
			ret = -EBADMSG;
			goto cleanup;
		}
		offset = pqcp_sovereign_ceremony_encode_bytes(
			body, sizeof(body), offset,
			selected->approval_digest,
			sizeof(selected->approval_digest));
		if (offset == 0U) {
			ret = -EOVERFLOW;
			goto cleanup;
		}
		ret = pqcp_sovereign_ceremony_copy_text(
			previous_signer, sizeof(previous_signer),
			selected->signer_id);
		if (ret != 0) {
			goto cleanup;
		}
		have_previous = true;
	}
	ret = pqcp_sovereign_ceremony_hash(body, offset, digest);

cleanup:
	pqcp_runtime_secure_zero(body, sizeof(body));
	pqcp_runtime_secure_zero(
		previous_signer, sizeof(previous_signer));
	return ret;
}

static int verify_signed_approval(
	struct pqcp_runtime_key_store *key_store,
	const struct pqcp_sovereign_signer_credential_internal *credential,
	const struct pqcp_sovereign_signed_approval_internal *approval,
	uint64_t now_ms)
{
	struct pqcp_runtime_key_metadata metadata;
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_APPROVAL_BYTES];
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	size_t body_length = 0U;
	int ret;

	ret = pqcp_runtime_key_store_metadata(
		key_store, &credential->verification_key, &metadata);
	if (ret != 0) {
		return ret;
	}
	if (!metadata.active ||
	    metadata.custody == PQCP_RUNTIME_CUSTODY_NONE ||
	    (metadata.usage & PQCP_RUNTIME_USAGE_VERIFY) == 0U ||
	    metadata.created_at_ms > now_ms ||
	    metadata.expires_at_ms <= now_ms ||
	    strcmp(metadata.owner, credential->tenant_id) != 0 ||
	    !pqcp_runtime_key_handle_equal(
		    &metadata.handle, &credential->verification_key)) {
		return -EKEYREJECTED;
	}
	ret = pqcp_sovereign_ceremony_approval_body(
		approval, body, sizeof(body), &body_length);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_hash(
			body, body_length, digest);
	}
	if (ret == 0 &&
	    !pqcp_sovereign_ceremony_digest_equal(
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
	if (!pqcp_sovereign_ceremony_digest_equal(
		    policy->target_digest,
		    approval->target_digest) ||
	    !pqcp_sovereign_ceremony_digest_equal(
		    policy->nonce, approval->nonce) ||
	    !pqcp_sovereign_ceremony_digest_equal(
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
	ret = pqcp_sovereign_ceremony_policy_digest(
		policy, digest);
	if (ret != 0) {
		return ret;
	}
	if (!pqcp_sovereign_ceremony_digest_zero(
		    policy->policy_digest) &&
	    !pqcp_sovereign_ceremony_digest_equal(
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
		engine->key_store, credential, approval, now_ms);
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
	ret = pqcp_sovereign_ceremony_copy_text(
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
	ret = pqcp_sovereign_ceremony_authorization_digest(
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
	    !pqcp_sovereign_ceremony_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !action_valid(action) || target_digest == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(target_digest) ||
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
	    !pqcp_sovereign_ceremony_digest_equal(
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
	    slot->committed.state ==
		    PQCP_SOVEREIGN_AUTHORIZATION_EMPTY ||
	    !authorization_state_valid(slot->committed.state)) {
		return -EBADMSG;
	}
	ret = pqcp_sovereign_ceremony_policy_digest(
		&slot->policy, expected);
	if (ret != 0 ||
	    !pqcp_sovereign_ceremony_digest_equal(
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
		    !pqcp_sovereign_ceremony_digest_equal(
			    approval->target_digest,
			    slot->policy.target_digest) ||
		    !pqcp_sovereign_ceremony_digest_equal(
			    approval->nonce, slot->policy.nonce) ||
		    !pqcp_sovereign_ceremony_digest_equal(
			    approval->previous_authorization_digest,
			    slot->policy
				    .previous_authorization_digest)) {
			pqcp_runtime_secure_zero(expected, sizeof(expected));
			return -EBADMSG;
		}
		ret = pqcp_sovereign_ceremony_approval_digest(
			approval, expected);
		if (ret != 0 ||
		    !pqcp_sovereign_ceremony_digest_equal(
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
	if (slot->committed.committed_at_ms == 0U) {
		if ((slot->committed.state !=
			     PQCP_SOVEREIGN_AUTHORIZATION_COLLECTING &&
		     slot->committed.state !=
			     PQCP_SOVEREIGN_AUTHORIZATION_EXPIRED &&
		     slot->committed.state !=
			     PQCP_SOVEREIGN_AUTHORIZATION_REVOKED) ||
		    slot->committed.expires_at_ms != 0U ||
		    slot->committed.approval_count != 0U ||
		    slot->committed.distinct_role_count != 0U ||
		    slot->committed.signer_mask != 0U ||
		    slot->committed.role_mask != 0U ||
		    slot->committed.use_count != 0U ||
		    slot->committed.maximum_uses != 0U ||
		    !pqcp_sovereign_ceremony_digest_zero(
			    slot->committed.approvals_digest) ||
		    !pqcp_sovereign_ceremony_digest_zero(
			    slot->committed.authorization_digest)) {
			pqcp_runtime_secure_zero(
				expected, sizeof(expected));
			return -EBADMSG;
		}
	} else {
		uint8_t approval_digest[PQCP_SOVEREIGN_DIGEST_BYTES];

		if (slot->committed.state ==
			    PQCP_SOVEREIGN_AUTHORIZATION_COLLECTING ||
		    slot->committed.committed_at_ms <
			    slot->opened_at_ms ||
		    slot->committed.expires_at_ms !=
			    slot->policy.expires_at_ms ||
		    strcmp(slot->committed.tenant_id,
			   slot->policy.tenant_id) != 0 ||
		    slot->committed.action != slot->policy.action ||
		    slot->committed.policy_epoch !=
			    slot->policy.policy_epoch ||
		    slot->committed.revocation_epoch !=
			    slot->policy.revocation_epoch ||
		    !pqcp_sovereign_ceremony_digest_equal(
			    slot->committed.target_digest,
			    slot->policy.target_digest) ||
		    !pqcp_sovereign_ceremony_digest_equal(
			    slot->committed.nonce,
			    slot->policy.nonce) ||
		    !pqcp_sovereign_ceremony_digest_equal(
			    slot->committed.previous_authorization_digest,
			    slot->policy.previous_authorization_digest)) {
			pqcp_runtime_secure_zero(
				expected, sizeof(expected));
			return -EBADMSG;
		}
		ret = approval_set_digest(slot, approval_digest);
		if (ret != 0 ||
		    !pqcp_sovereign_ceremony_digest_equal(
			    approval_digest,
			    slot->committed.approvals_digest)) {
			pqcp_runtime_secure_zero(
				approval_digest, sizeof(approval_digest));
			pqcp_runtime_secure_zero(
				expected, sizeof(expected));
			return ret != 0 ? ret : -EBADMSG;
		}
		ret = pqcp_sovereign_ceremony_authorization_digest(
			&slot->committed, expected);
		pqcp_runtime_secure_zero(
			approval_digest, sizeof(approval_digest));
		if (ret != 0 ||
		    !pqcp_sovereign_ceremony_digest_equal(
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

static int lock_executor(
	struct pqcp_sovereign_ceremony_executor_internal *executor)
{
	if (executor == NULL || !executor->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&executor->lock, K_FOREVER);
}

static void unlock_executor(
	struct pqcp_sovereign_ceremony_executor_internal *executor)
{
	(void)k_mutex_unlock(&executor->lock);
}

static int binding_index_by_ceremony_locked(
	const struct pqcp_sovereign_ceremony_executor_internal *executor,
	uint64_t ceremony_id)
{
	size_t index;

	for (index = 0U; index < executor->binding_capacity; ++index) {
		if (executor->bindings[index].occupied &&
		    executor->bindings[index].ceremony_id == ceremony_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int binding_index_by_authorization_locked(
	const struct pqcp_sovereign_ceremony_executor_internal *executor,
	uint64_t authorization_id)
{
	size_t index;

	for (index = 0U; index < executor->binding_capacity; ++index) {
		if (executor->bindings[index].occupied &&
		    executor->bindings[index].authorization_id ==
			    authorization_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_binding_index_locked(
	const struct pqcp_sovereign_ceremony_executor_internal *executor)
{
	size_t index;

	for (index = 0U; index < executor->binding_capacity; ++index) {
		if (!executor->bindings[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int ceremony_snapshot(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id,
	struct pqcp_sovereign_key_ceremony *ceremony)
{
	size_t index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    ceremony_id == 0U || ceremony == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < manager->ceremony_capacity; ++index) {
		if (manager->ceremonies[index].occupied &&
		    manager->ceremonies[index].ceremony_id ==
			    ceremony_id) {
			*ceremony = manager->ceremonies[index];
			(void)k_mutex_unlock(&manager->lock);
			return 0;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return -ENOENT;
}

static int authorization_snapshot(
	struct pqcp_sovereign_authorization_engine_internal *engine,
	uint64_t authorization_id,
	struct pqcp_sovereign_committed_authorization_internal *authorization)
{
	int index;
	int ret;

	if (authorization == NULL || authorization_id == 0U) {
		return -EINVAL;
	}
	ret = lock_engine(engine);
	if (ret != 0) {
		return ret;
	}
	index = slot_index_by_id_locked(engine, authorization_id);
	if (index < 0) {
		unlock_engine(engine);
		return index;
	}
	*authorization = engine->slots[index].committed;
	unlock_engine(engine);
	return 0;
}

static bool action_requires_current_key(
	enum pqcp_sovereign_ceremony_action action)
{
	return action == PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE ||
	       action == PQCP_SOVEREIGN_CEREMONY_ACTION_RETIRE ||
	       action == PQCP_SOVEREIGN_CEREMONY_ACTION_DESTROY;
}

static bool action_creates_key(
	enum pqcp_sovereign_ceremony_action action)
{
	return action == PQCP_SOVEREIGN_CEREMONY_ACTION_GENERATE ||
	       action == PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE ||
	       action == PQCP_SOVEREIGN_CEREMONY_ACTION_RECOVER;
}

static enum pqcp_crypto_broker_operation broker_operation_for_action(
	enum pqcp_sovereign_ceremony_action action)
{
	switch (action) {
	case PQCP_SOVEREIGN_CEREMONY_ACTION_GENERATE:
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RECOVER:
		return PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE;
	case PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE:
		return PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE;
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RETIRE:
	case PQCP_SOVEREIGN_CEREMONY_ACTION_DESTROY:
		return PQCP_CRYPTO_BROKER_OPERATION_KEY_DESTROY;
	default:
		return PQCP_CRYPTO_BROKER_OPERATION_NONE;
	}
}

static const char *custody_action_for_ceremony(
	enum pqcp_sovereign_ceremony_action action)
{
	switch (action) {
	case PQCP_SOVEREIGN_CEREMONY_ACTION_GENERATE:
		return "key-generated";
	case PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE:
		return "key-rotated";
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RETIRE:
		return "key-retired";
	case PQCP_SOVEREIGN_CEREMONY_ACTION_DESTROY:
		return "key-destroyed";
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RECOVER:
		return "key-recovered";
	default:
		return NULL;
	}
}

static int ceremony_request_id(
	const struct pqcp_sovereign_ceremony_binding_internal *binding,
	uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES])
{
	static const char domain[] =
		"pqcp-sovereign-ceremony-broker-request-v1";
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_AUTHORIZATION_BYTES];
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	size_t offset = 0U;
	uint8_t aggregate = 0U;
	size_t index;
	int ret;

	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, domain, sizeof(domain));
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->ceremony_id);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->authorization_id);
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, binding->tenant_id,
		sizeof(binding->tenant_id));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, (uint32_t)binding->action);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->created_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->expires_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->policy_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->revocation_epoch);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, binding->target_digest,
		sizeof(binding->target_digest));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		binding->authorization_digest,
		sizeof(binding->authorization_digest));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, binding->current_key.slot);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		binding->current_key.generation);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		(uint32_t)binding->current_key.backend);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		(uint32_t)binding->current_key.family);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, binding->current_key.level);
	if (offset == 0U) {
		ret = -EOVERFLOW;
		goto cleanup;
	}
	ret = pqcp_sovereign_ceremony_hash(body, offset, digest);
	if (ret != 0) {
		goto cleanup;
	}
	memcpy(request_id, digest,
	       PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES);
	for (index = 0U;
	     index < PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES; ++index) {
		aggregate |= request_id[index];
	}
	if (aggregate == 0U) {
		request_id[0] = 1U;
	}

cleanup:
	pqcp_runtime_secure_zero(body, sizeof(body));
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int ceremony_execution_evidence(
	const struct pqcp_sovereign_ceremony_binding_internal *binding,
	const struct pqcp_crypto_broker_response *response,
	const struct pqcp_runtime_key_handle *result_key,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	static const char domain[] =
		"pqcp-sovereign-ceremony-execution-v1";
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_AUTHORIZATION_BYTES];
	size_t offset = 0U;

	if (binding == NULL || response == NULL ||
	    result_key == NULL || digest == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(
		    response->receipt.receipt_digest)) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, domain, sizeof(domain));
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->ceremony_id);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->authorization_id);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, (uint32_t)binding->action);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->policy_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, binding->revocation_epoch);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, binding->target_digest,
		sizeof(binding->target_digest));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		binding->authorization_digest,
		sizeof(binding->authorization_digest));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		response->receipt.receipt_digest,
		sizeof(response->receipt.receipt_digest));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, result_key->slot);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, result_key->generation);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		(uint32_t)result_key->backend);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		(uint32_t)result_key->family);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, result_key->level);
	if (offset == 0U) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	int ret = pqcp_sovereign_ceremony_hash(body, offset, digest);

	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int binding_current_key_validate(
	struct pqcp_sovereign_ceremony_executor_internal *executor,
	const char *tenant_id,
	const struct pqcp_runtime_key_handle *current_key,
	uint64_t now_ms)
{
	struct pqcp_runtime_key_metadata metadata;
	int ret;

	ret = pqcp_runtime_key_store_metadata(
		executor->broker->config.key_store,
		current_key, &metadata);
	if (ret != 0) {
		return ret;
	}
	if (!metadata.active ||
	    metadata.custody == PQCP_RUNTIME_CUSTODY_NONE ||
	    metadata.expires_at_ms <= now_ms ||
	    strcmp(metadata.owner, tenant_id) != 0 ||
	    !pqcp_runtime_key_handle_equal(
		    &metadata.handle, current_key)) {
		return -EKEYREJECTED;
	}
	return 0;
}

int pqcp_sovereign_ceremony_executor_init_internal(
	struct pqcp_sovereign_ceremony_executor_internal *executor,
	struct pqcp_sovereign_key_ceremony_manager *manager,
	struct pqcp_sovereign_authorization_engine_internal *authorizations,
	struct pqcp_sovereign_custody_ledger *custody,
	struct pqcp_crypto_broker *broker,
	struct pqcp_sovereign_ceremony_binding_internal *bindings,
	size_t binding_capacity)
{
	if (executor == NULL || manager == NULL ||
	    !manager->initialized || authorizations == NULL ||
	    !authorizations->initialized || custody == NULL ||
	    !custody->initialized || broker == NULL ||
	    !broker->initialized || bindings == NULL ||
	    binding_capacity == 0U ||
	    binding_capacity >
		    PQCP_SOVEREIGN_MAX_CEREMONY_BINDINGS ||
	    broker->config.key_store == NULL ||
	    authorizations->key_store !=
		    broker->config.key_store) {
		return -EINVAL;
	}
	memset(executor, 0, sizeof(*executor));
	memset(bindings, 0, binding_capacity * sizeof(*bindings));
	executor->manager = manager;
	executor->authorizations = authorizations;
	executor->custody = custody;
	executor->broker = broker;
	executor->bindings = bindings;
	executor->binding_capacity = binding_capacity;
	k_mutex_init(&executor->lock);
	executor->initialized = true;
	return 0;
}

int pqcp_sovereign_ceremony_bind_internal(
	struct pqcp_sovereign_ceremony_executor_internal *executor,
	uint64_t ceremony_id,
	uint64_t authorization_id,
	const char *tenant_id,
	enum pqcp_sovereign_ceremony_action action,
	const struct pqcp_runtime_key_handle *current_key,
	const uint8_t target_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const char *principal_id,
	const uint8_t capability[PQCP_CRYPTO_BROKER_TOKEN_BYTES],
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms)
{
	struct pqcp_sovereign_ceremony_binding_internal staged;
	struct pqcp_sovereign_key_ceremony ceremony;
	struct pqcp_sovereign_committed_authorization_internal authorization;
	uint8_t expected_authorization_digest[
		PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t capability_aggregate = 0U;
	size_t index;
	int slot;
	int ret;

	if (ceremony_id == 0U || authorization_id == 0U ||
	    !pqcp_sovereign_ceremony_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !action_valid(action) ||
	    target_digest == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(target_digest) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    principal_id, PQCP_CRYPTO_BROKER_ID_MAX_CHARS) ||
	    capability == NULL || policy_epoch == 0U ||
	    revocation_epoch == 0U || now_ms == 0U ||
	    expires_at_ms <= now_ms ||
	    (action_requires_current_key(action) &&
	     (current_key == NULL ||
	      !pqcp_runtime_key_handle_is_valid(current_key))) ||
	    (!action_requires_current_key(action) &&
	     current_key != NULL &&
	     pqcp_runtime_key_handle_is_valid(current_key))) {
		return -EINVAL;
	}
	for (index = 0U; index < PQCP_CRYPTO_BROKER_TOKEN_BYTES;
	     ++index) {
		capability_aggregate |= capability[index];
	}
	if (capability_aggregate == 0U) {
		return -EINVAL;
	}
	ret = ceremony_snapshot(
		executor->manager, ceremony_id, &ceremony);
	if (ret != 0) {
		return ret;
	}
	if (ceremony.state != PQCP_SOVEREIGN_CEREMONY_COLLECTING &&
	    ceremony.state != PQCP_SOVEREIGN_CEREMONY_COMBINING) {
		return -EALREADY;
	}
	if (pqcp_sovereign_ceremony_action_from_text(
		    ceremony.purpose) != action ||
	    ceremony.expires_at_ms < expires_at_ms ||
	    ceremony.opened_at_ms > now_ms) {
		return -EACCES;
	}
	ret = authorization_snapshot(
		executor->authorizations, authorization_id,
		&authorization);
	if (ret != 0) {
		return ret;
	}
	if (authorization.state !=
		    PQCP_SOVEREIGN_AUTHORIZATION_COMMITTED ||
	    strcmp(authorization.tenant_id, tenant_id) != 0 ||
	    authorization.action != action ||
	    authorization.policy_epoch != policy_epoch ||
	    authorization.revocation_epoch != revocation_epoch ||
	    authorization.committed_at_ms > now_ms ||
	    authorization.expires_at_ms < expires_at_ms ||
	    authorization.use_count >= authorization.maximum_uses ||
	    !pqcp_sovereign_ceremony_digest_equal(
		    authorization.target_digest, target_digest)) {
		return -EACCES;
	}
	ret = pqcp_sovereign_ceremony_authorization_digest(
		&authorization, expected_authorization_digest);
	if (ret != 0 ||
	    !pqcp_sovereign_ceremony_digest_equal(
		    expected_authorization_digest,
		    authorization.authorization_digest)) {
		pqcp_runtime_secure_zero(
			expected_authorization_digest,
			sizeof(expected_authorization_digest));
		return ret != 0 ? ret : -EBADMSG;
	}
	if (action_requires_current_key(action)) {
		ret = binding_current_key_validate(
			executor, tenant_id, current_key, now_ms);
		if (ret != 0) {
			pqcp_runtime_secure_zero(
				expected_authorization_digest,
				sizeof(expected_authorization_digest));
			return ret;
		}
	}
	ret = lock_executor(executor);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			expected_authorization_digest,
			sizeof(expected_authorization_digest));
		return ret;
	}
	if (binding_index_by_ceremony_locked(
		    executor, ceremony_id) >= 0 ||
	    binding_index_by_authorization_locked(
		    executor, authorization_id) >= 0) {
		unlock_executor(executor);
		pqcp_runtime_secure_zero(
			expected_authorization_digest,
			sizeof(expected_authorization_digest));
		return -EALREADY;
	}
	slot = free_binding_index_locked(executor);
	if (slot < 0) {
		unlock_executor(executor);
		pqcp_runtime_secure_zero(
			expected_authorization_digest,
			sizeof(expected_authorization_digest));
		return slot;
	}
	memset(&staged, 0, sizeof(staged));
	staged.ceremony_id = ceremony_id;
	staged.authorization_id = authorization_id;
	staged.action = action;
	staged.created_at_ms = now_ms;
	staged.expires_at_ms = expires_at_ms;
	staged.policy_epoch = policy_epoch;
	staged.revocation_epoch = revocation_epoch;
	if (current_key != NULL) {
		staged.current_key = *current_key;
	}
	ret = pqcp_sovereign_ceremony_copy_text(
		staged.tenant_id, sizeof(staged.tenant_id), tenant_id);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.principal_id,
			sizeof(staged.principal_id), principal_id);
	}
	if (ret != 0) {
		unlock_executor(executor);
		pqcp_runtime_secure_zero(
			expected_authorization_digest,
			sizeof(expected_authorization_digest));
		return ret;
	}
	memcpy(staged.target_digest, target_digest,
	       sizeof(staged.target_digest));
	memcpy(staged.authorization_digest,
	       authorization.authorization_digest,
	       sizeof(staged.authorization_digest));
	memcpy(staged.capability, capability,
	       sizeof(staged.capability));
	staged.occupied = true;
	executor->bindings[slot] = staged;
	unlock_executor(executor);
	pqcp_runtime_secure_zero(
		expected_authorization_digest,
		sizeof(expected_authorization_digest));
	return 0;
}

static void ceremony_failure_record_locked(
	struct pqcp_sovereign_ceremony_executor_internal *executor,
	struct pqcp_sovereign_ceremony_binding_internal *binding,
	int result,
	uint64_t now_ms,
	const uint8_t receipt_digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	struct pqcp_sovereign_key_ceremony ceremony;
	const uint8_t *evidence = binding->authorization_digest;
	const char *key_id = "ceremony";
	uint64_t key_epoch = binding->policy_epoch;

	binding->terminal = true;
	binding->executed = false;
	binding->executed_at_ms = now_ms;
	binding->result = result != 0 ? result : -EIO;
	if (receipt_digest != NULL &&
	    !pqcp_sovereign_ceremony_digest_zero(receipt_digest)) {
		memcpy(binding->execution_receipt_digest,
		       receipt_digest,
		       sizeof(binding->execution_receipt_digest));
		evidence = receipt_digest;
	}
	if (executor->failure_count != UINT64_MAX) {
		executor->failure_count++;
	}
	if (ceremony_snapshot(
		    executor->manager, binding->ceremony_id,
		    &ceremony) == 0) {
		key_id = ceremony.key_id;
		key_epoch = ceremony.target_epoch;
	}
	(void)pqcp_sovereign_key_ceremony_abort(
		executor->manager, binding->ceremony_id);
	(void)pqcp_sovereign_custody_append(
		executor->custody, key_id,
		binding->principal_id, "ceremony-aborted",
		key_epoch, binding->policy_epoch,
		evidence, now_ms, NULL);
}

static int build_broker_request(
	const struct pqcp_sovereign_ceremony_binding_internal *binding,
	const struct pqcp_crypto_broker_key_spec *key_spec,
	struct pqcp_crypto_broker_request *request)
{
	enum pqcp_crypto_broker_operation operation =
		broker_operation_for_action(binding->action);
	int ret;

	if (operation == PQCP_CRYPTO_BROKER_OPERATION_NONE ||
	    (action_creates_key(binding->action) &&
	     key_spec == NULL)) {
		return -EINVAL;
	}
	memset(request, 0, sizeof(*request));
	request->schema_version =
		PQCP_CRYPTO_BROKER_SCHEMA_VERSION;
	ret = ceremony_request_id(binding, request->request_id);
	if (ret != 0) {
		return ret;
	}
	memcpy(request->capability, binding->capability,
	       sizeof(request->capability));
	ret = pqcp_sovereign_ceremony_copy_text(
		request->principal_id,
		sizeof(request->principal_id),
		binding->principal_id);
	if (ret != 0) {
		return ret;
	}
	request->operation = operation;
	request->submitted_at_ms = binding->created_at_ms;
	request->deadline_ms = binding->expires_at_ms;
	request->flags =
		PQCP_CRYPTO_BROKER_REQUEST_ZERO_OUTPUT_ON_FAILURE;
	if (action_creates_key(binding->action)) {
		request->key_spec = *key_spec;
		request->level = key_spec->level;
	}
	if (action_requires_current_key(binding->action)) {
		request->primary_key = binding->current_key;
		request->level = binding->current_key.level;
	}
	return 0;
}

int pqcp_sovereign_ceremony_execute_internal(
	struct pqcp_sovereign_ceremony_executor_internal *executor,
	uint64_t ceremony_id,
	const struct pqcp_crypto_broker_key_spec *key_spec,
	uint64_t now_ms,
	struct pqcp_runtime_key_handle *result_key)
{
	struct pqcp_sovereign_committed_authorization_internal authorization;
	struct pqcp_sovereign_ceremony_binding_internal *binding;
	struct pqcp_sovereign_key_ceremony ceremony;
	struct pqcp_crypto_broker_request request;
	struct pqcp_crypto_broker_response response;
	struct pqcp_runtime_key_handle committed_key = { 0 };
	const char *custody_action;
	int index;
	int ret;

	if (ceremony_id == 0U || now_ms == 0U ||
	    result_key == NULL) {
		return -EINVAL;
	}
	memset(result_key, 0, sizeof(*result_key));
	memset(&response, 0, sizeof(response));
	ret = lock_executor(executor);
	if (ret != 0) {
		return ret;
	}
	index = binding_index_by_ceremony_locked(
		executor, ceremony_id);
	if (index < 0) {
		unlock_executor(executor);
		return index;
	}
	binding = &executor->bindings[index];
	if (binding->terminal) {
		if (binding->executed) {
			*result_key = binding->committed_key;
		}
		ret = binding->result;
		unlock_executor(executor);
		return ret;
	}
	if (now_ms < binding->created_at_ms ||
	    now_ms >= binding->expires_at_ms) {
		ceremony_failure_record_locked(
			executor, binding, -ETIMEDOUT, now_ms, NULL);
		unlock_executor(executor);
		return -ETIMEDOUT;
	}
	ret = ceremony_snapshot(
		executor->manager, ceremony_id, &ceremony);
	if (ret != 0 ||
	    ceremony.state != PQCP_SOVEREIGN_CEREMONY_COMBINING ||
	    ceremony.contribution_count < ceremony.threshold ||
	    ceremony.distinct_role_count <
		    ceremony.required_distinct_roles ||
	    now_ms >= ceremony.expires_at_ms) {
		ret = ret != 0 ? ret :
		      now_ms >= ceremony.expires_at_ms ?
			      -ETIMEDOUT : -EACCES;
		ceremony_failure_record_locked(
			executor, binding, ret, now_ms, NULL);
		unlock_executor(executor);
		return ret;
	}
	ret = pqcp_sovereign_authorization_consume_internal(
		executor->authorizations,
		binding->authorization_id, binding->tenant_id,
		binding->action, binding->target_digest,
		binding->policy_epoch, binding->revocation_epoch,
		now_ms, &authorization);
	if (ret != 0 ||
	    !pqcp_sovereign_ceremony_digest_equal(
		    authorization.authorization_digest,
		    binding->authorization_digest)) {
		ret = ret != 0 ? ret : -EBADMSG;
		ceremony_failure_record_locked(
			executor, binding, ret, now_ms, NULL);
		unlock_executor(executor);
		return ret;
	}
	ret = build_broker_request(binding, key_spec, &request);
	if (ret != 0) {
		ceremony_failure_record_locked(
			executor, binding, ret, now_ms, NULL);
		unlock_executor(executor);
		return ret;
	}
	ret = pqcp_crypto_broker_execute(
		executor->broker, &request, &response);
	if (ret != 0 || response.result != 0 ||
	    response.receipt.operation != request.operation ||
	    response.receipt.result != 0 ||
	    memcmp(response.receipt.request_id,
		   request.request_id,
		   sizeof(request.request_id)) != 0 ||
	    pqcp_sovereign_ceremony_digest_zero(
		    response.receipt.receipt_digest)) {
		ret = ret != 0 ? ret :
		      response.result != 0 ? response.result : -EBADMSG;
		ceremony_failure_record_locked(
			executor, binding, ret, now_ms,
			response.receipt.receipt_digest);
		unlock_executor(executor);
		return ret;
	}
	ret = pqcp_crypto_broker_receipt_verify(
		executor->broker, &response.receipt);
	if (ret != 0) {
		ceremony_failure_record_locked(
			executor, binding, ret, now_ms,
			response.receipt.receipt_digest);
		unlock_executor(executor);
		return ret;
	}
	if (action_creates_key(binding->action)) {
		committed_key = response.primary_key;
		if (!pqcp_runtime_key_handle_is_valid(&committed_key) ||
		    !response.metadata.active ||
		    strcmp(response.metadata.owner,
			   binding->tenant_id) != 0 ||
		    !pqcp_runtime_key_handle_equal(
			    &response.metadata.handle,
			    &committed_key)) {
			if (pqcp_runtime_key_handle_is_valid(
				    &committed_key)) {
				(void)pqcp_runtime_key_store_destroy(
					executor->broker->config.key_store,
					&committed_key);
			}
			ret = -EKEYREJECTED;
			ceremony_failure_record_locked(
				executor, binding, ret, now_ms,
				response.receipt.receipt_digest);
			unlock_executor(executor);
			return ret;
		}
	}
	ret = ceremony_execution_evidence(
		binding, &response, &committed_key,
		binding->execution_evidence_digest);
	if (ret == 0) {
		custody_action = custody_action_for_ceremony(
			binding->action);
		ret = pqcp_sovereign_custody_append(
			executor->custody, ceremony.key_id,
			binding->principal_id, custody_action,
			ceremony.target_epoch, binding->policy_epoch,
			binding->execution_evidence_digest, now_ms, NULL);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_key_ceremony_commit(
			executor->manager, ceremony_id,
			binding->execution_evidence_digest, now_ms);
	}
	if (ret != 0) {
		if (action_creates_key(binding->action) &&
		    pqcp_runtime_key_handle_is_valid(&committed_key)) {
			(void)pqcp_runtime_key_store_destroy(
				executor->broker->config.key_store,
				&committed_key);
		}
		ceremony_failure_record_locked(
			executor, binding, ret, now_ms,
			response.receipt.receipt_digest);
		unlock_executor(executor);
		return ret;
	}
	binding->committed_key = committed_key;
	memcpy(binding->execution_receipt_digest,
	       response.receipt.receipt_digest,
	       sizeof(binding->execution_receipt_digest));
	binding->executed_at_ms = now_ms;
	binding->result = 0;
	binding->terminal = true;
	binding->executed = true;
	if (executor->execution_count != UINT64_MAX) {
		executor->execution_count++;
	}
	*result_key = committed_key;
	unlock_executor(executor);
	return 0;
}

static int audit_binding_locked(
	struct pqcp_sovereign_ceremony_executor_internal *executor,
	const struct pqcp_sovereign_ceremony_binding_internal *binding)
{
	struct pqcp_sovereign_committed_authorization_internal authorization;
	struct pqcp_sovereign_key_ceremony ceremony;
	uint8_t expected[PQCP_SOVEREIGN_DIGEST_BYTES];
	int ret;

	if (!binding->occupied || binding->ceremony_id == 0U ||
	    binding->authorization_id == 0U ||
	    !pqcp_sovereign_ceremony_text_valid(
		    binding->tenant_id, sizeof(binding->tenant_id)) ||
	    !action_valid(binding->action) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    binding->principal_id,
		    sizeof(binding->principal_id)) ||
	    binding->created_at_ms == 0U ||
	    binding->expires_at_ms <= binding->created_at_ms ||
	    binding->policy_epoch == 0U ||
	    binding->revocation_epoch == 0U ||
	    pqcp_sovereign_ceremony_digest_zero(
		    binding->target_digest) ||
	    pqcp_sovereign_ceremony_digest_zero(
		    binding->authorization_digest) ||
	    (action_requires_current_key(binding->action) &&
	     !pqcp_runtime_key_handle_is_valid(
		     &binding->current_key)) ||
	    (!action_requires_current_key(binding->action) &&
	     pqcp_runtime_key_handle_is_valid(
		     &binding->current_key))) {
		return -EBADMSG;
	}
	ret = ceremony_snapshot(
		executor->manager, binding->ceremony_id, &ceremony);
	if (ret != 0 ||
	    pqcp_sovereign_ceremony_action_from_text(
		    ceremony.purpose) != binding->action) {
		return ret != 0 ? ret : -EBADMSG;
	}
	ret = authorization_snapshot(
		executor->authorizations,
		binding->authorization_id, &authorization);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_ceremony_authorization_digest(
		&authorization, expected);
	if (ret != 0 ||
	    !pqcp_sovereign_ceremony_digest_equal(
		    expected, authorization.authorization_digest) ||
	    !pqcp_sovereign_ceremony_digest_equal(
		    expected, binding->authorization_digest) ||
	    strcmp(authorization.tenant_id,
		   binding->tenant_id) != 0 ||
	    authorization.action != binding->action ||
	    authorization.policy_epoch != binding->policy_epoch ||
	    authorization.revocation_epoch !=
		    binding->revocation_epoch ||
	    !pqcp_sovereign_ceremony_digest_equal(
		    authorization.target_digest,
		    binding->target_digest)) {
		pqcp_runtime_secure_zero(expected, sizeof(expected));
		return ret != 0 ? ret : -EBADMSG;
	}
	if (binding->terminal) {
		if (binding->executed_at_ms < binding->created_at_ms ||
		    binding->executed_at_ms >= binding->expires_at_ms ||
		    (binding->executed && binding->result != 0) ||
		    (!binding->executed && binding->result == 0)) {
			pqcp_runtime_secure_zero(expected, sizeof(expected));
			return -EBADMSG;
		}
		if (binding->executed) {
			if (ceremony.state !=
				    PQCP_SOVEREIGN_CEREMONY_COMMITTED ||
			    pqcp_sovereign_ceremony_digest_zero(
				    binding->execution_receipt_digest) ||
			    pqcp_sovereign_ceremony_digest_zero(
				    binding->execution_evidence_digest) ||
			    !pqcp_sovereign_ceremony_digest_equal(
				    ceremony.committed_key_digest,
				    binding->execution_evidence_digest) ||
			    (action_creates_key(binding->action) &&
			     !pqcp_runtime_key_handle_is_valid(
				     &binding->committed_key)) ||
			    (!action_creates_key(binding->action) &&
			     pqcp_runtime_key_handle_is_valid(
				     &binding->committed_key))) {
				pqcp_runtime_secure_zero(
					expected, sizeof(expected));
				return -EBADMSG;
			}
		} else if (ceremony.state !=
			   PQCP_SOVEREIGN_CEREMONY_ABORTED) {
			pqcp_runtime_secure_zero(expected, sizeof(expected));
			return -EBADMSG;
		}
	} else if (binding->executed ||
		   binding->executed_at_ms != 0U ||
		   binding->result != 0 ||
		   !pqcp_sovereign_ceremony_digest_zero(
			   binding->execution_receipt_digest) ||
		   !pqcp_sovereign_ceremony_digest_zero(
			   binding->execution_evidence_digest) ||
		   pqcp_runtime_key_handle_is_valid(
			   &binding->committed_key)) {
		pqcp_runtime_secure_zero(expected, sizeof(expected));
		return -EBADMSG;
	}
	pqcp_runtime_secure_zero(expected, sizeof(expected));
	return 0;
}

int pqcp_sovereign_ceremony_executor_audit_internal(
	struct pqcp_sovereign_ceremony_executor_internal *executor)
{
	size_t left;
	size_t right;
	int ret;

	ret = lock_executor(executor);
	if (ret != 0) {
		return ret;
	}
	if (executor->manager == NULL ||
	    !executor->manager->initialized ||
	    executor->authorizations == NULL ||
	    !executor->authorizations->initialized ||
	    executor->custody == NULL ||
	    !executor->custody->initialized ||
	    executor->broker == NULL ||
	    !executor->broker->initialized ||
	    executor->bindings == NULL ||
	    executor->binding_capacity == 0U ||
	    executor->binding_capacity >
		    PQCP_SOVEREIGN_MAX_CEREMONY_BINDINGS) {
		unlock_executor(executor);
		return -EBADMSG;
	}
	for (left = 0U; left < executor->binding_capacity; ++left) {
		if (!executor->bindings[left].occupied) {
			continue;
		}
		ret = audit_binding_locked(
			executor, &executor->bindings[left]);
		if (ret != 0) {
			unlock_executor(executor);
			return ret;
		}
		for (right = left + 1U;
		     right < executor->binding_capacity; ++right) {
			if (!executor->bindings[right].occupied) {
				continue;
			}
			if (executor->bindings[right].ceremony_id ==
				    executor->bindings[left].ceremony_id ||
			    executor->bindings[right].authorization_id ==
				    executor->bindings[left]
					    .authorization_id) {
				unlock_executor(executor);
				return -EBADMSG;
			}
		}
	}
	unlock_executor(executor);
	ret = pqcp_sovereign_authorization_audit_internal(
		executor->authorizations);
	if (ret == 0) {
		ret = pqcp_sovereign_key_ceremony_manager_audit(
			executor->manager);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_custody_verify(
			executor->custody);
	}
	if (ret == 0) {
		ret = pqcp_crypto_broker_audit(executor->broker);
	}
	return ret;
}
