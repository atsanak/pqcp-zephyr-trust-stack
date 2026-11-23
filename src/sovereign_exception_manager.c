/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free, fail-closed control exception lifecycle.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"
#include "sovereign_artifact_internal.h"

#define EXCEPTION_APPROVAL_DOMAIN \
	"pqcp-sovereign-exception-approval-v1"
#define EXCEPTION_CANONICAL_BYTES 512U
#define EXCEPTION_RISK_MAX 10000U

static int manager_lock(
	struct pqcp_sovereign_exception_manager *manager)
{
	if (manager == NULL || !manager->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&manager->lock, K_FOREVER);
}

static void manager_unlock(
	struct pqcp_sovereign_exception_manager *manager)
{
	(void)k_mutex_unlock(&manager->lock);
}

static bool digest_zero(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	return digest == NULL ||
	       pqcp_sovereign_internal_all_zero(
		       digest, PQCP_SOVEREIGN_DIGEST_BYTES);
}

static bool exception_state_valid(
	enum pqcp_sovereign_exception_state state)
{
	switch (state) {
	case PQCP_SOVEREIGN_EXCEPTION_REQUESTED:
	case PQCP_SOVEREIGN_EXCEPTION_APPROVED:
	case PQCP_SOVEREIGN_EXCEPTION_ACTIVE:
	case PQCP_SOVEREIGN_EXCEPTION_EXPIRED:
	case PQCP_SOVEREIGN_EXCEPTION_REVOKED:
		return true;
	default:
		return false;
	}
}

static bool exception_terminal(
	enum pqcp_sovereign_exception_state state)
{
	return state == PQCP_SOVEREIGN_EXCEPTION_EXPIRED ||
	       state == PQCP_SOVEREIGN_EXCEPTION_REVOKED;
}

static int exception_index_locked(
	const struct pqcp_sovereign_exception_manager *manager,
	uint64_t exception_id)
{
	size_t index;

	if (exception_id == 0U) {
		return -EINVAL;
	}
	for (index = 0U; index < manager->capacity; ++index) {
		if (manager->exceptions[index].occupied &&
		    manager->exceptions[index].exception_id ==
			    exception_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_exception_index_locked(
	const struct pqcp_sovereign_exception_manager *manager,
	uint64_t now_ms)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		if (!manager->exceptions[index].occupied) {
			return (int)index;
		}
	}
	for (index = 0U; index < manager->capacity; ++index) {
		const struct pqcp_sovereign_exception *entry =
			&manager->exceptions[index];

		if (exception_terminal(entry->state) &&
		    entry->expires_at_ms <= now_ms) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int matching_exception_index_locked(
	const struct pqcp_sovereign_exception_manager *manager,
	const char *subject_id,
	const char *control_id)
{
	size_t index;

	for (index = 0U; index < manager->capacity; ++index) {
		const struct pqcp_sovereign_exception *entry =
			&manager->exceptions[index];

		if (entry->occupied &&
		    strcmp(entry->subject_id, subject_id) == 0 &&
		    strcmp(entry->control_id, control_id) == 0 &&
		    !exception_terminal(entry->state)) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static size_t encode_u32(
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

static size_t encode_u64(
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

static size_t encode_bytes(
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
	next = encode_u32(
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

static size_t encode_text(
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
	return encode_bytes(
		output, capacity, offset,
		(const uint8_t *)text, length);
}

static int exception_approval_binding_digest(
	const struct pqcp_sovereign_exception *exception,
	uint64_t approved_at_ms,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[EXCEPTION_CANONICAL_BYTES];
	size_t offset = 0U;
	int ret;

	if (exception == NULL || approved_at_ms == 0U ||
	    digest == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	offset = encode_text(
		body, sizeof(body), offset,
		EXCEPTION_APPROVAL_DOMAIN,
		sizeof(EXCEPTION_APPROVAL_DOMAIN));
	offset = encode_u32(
		body, sizeof(body), offset,
		PQCP_SOVEREIGN_SCHEMA_VERSION);
	offset = encode_u64(
		body, sizeof(body), offset, exception->exception_id);
	offset = encode_text(
		body, sizeof(body), offset, exception->subject_id,
		sizeof(exception->subject_id));
	offset = encode_text(
		body, sizeof(body), offset, exception->control_id,
		sizeof(exception->control_id));
	offset = encode_text(
		body, sizeof(body), offset, exception->owner_id,
		sizeof(exception->owner_id));
	offset = encode_text(
		body, sizeof(body), offset, exception->justification,
		sizeof(exception->justification));
	offset = encode_u64(
		body, sizeof(body), offset,
		exception->requested_at_ms);
	offset = encode_u64(
		body, sizeof(body), offset, approved_at_ms);
	offset = encode_u64(
		body, sizeof(body), offset,
		exception->expires_at_ms);
	offset = encode_u64(
		body, sizeof(body), offset, exception->policy_epoch);
	offset = encode_u32(
		body, sizeof(body), offset, exception->residual_risk);
	offset = encode_u32(
		body, sizeof(body), offset,
		exception->compensating_control_mask);
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	ret = pqcp_runtime_internal_sha256(body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static bool exception_shape_valid(
	const struct pqcp_sovereign_exception *exception)
{
	if (exception == NULL || !exception->occupied ||
	    exception->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    exception->exception_id == 0U ||
	    !pqcp_sovereign_internal_text_valid(
		    exception->subject_id,
		    sizeof(exception->subject_id)) ||
	    !pqcp_sovereign_internal_text_valid(
		    exception->control_id,
		    sizeof(exception->control_id)) ||
	    !pqcp_sovereign_internal_text_valid(
		    exception->owner_id,
		    sizeof(exception->owner_id)) ||
	    !pqcp_sovereign_internal_text_valid(
		    exception->justification,
		    sizeof(exception->justification)) ||
	    exception->requested_at_ms == 0U ||
	    exception->expires_at_ms <= exception->requested_at_ms ||
	    exception->policy_epoch == 0U ||
	    exception->residual_risk > EXCEPTION_RISK_MAX ||
	    exception->compensating_control_mask == 0U ||
	    !exception_state_valid(exception->state)) {
		return false;
	}
	if (exception->approved_at_ms == 0U) {
		if (exception->state !=
			    PQCP_SOVEREIGN_EXCEPTION_REQUESTED &&
		    exception->state !=
			    PQCP_SOVEREIGN_EXCEPTION_EXPIRED &&
		    exception->state !=
			    PQCP_SOVEREIGN_EXCEPTION_REVOKED) {
			return false;
		}
		return digest_zero(exception->approval_digest);
	}
	if (exception->approved_at_ms <
		    exception->requested_at_ms ||
	    exception->approved_at_ms >=
		    exception->expires_at_ms ||
	    digest_zero(exception->approval_digest)) {
		return false;
	}
	return true;
}

int pqcp_sovereign_exception_manager_init(
	struct pqcp_sovereign_exception_manager *manager,
	struct pqcp_sovereign_exception *exceptions,
	size_t capacity)
{
	if (manager == NULL || exceptions == NULL ||
	    capacity == 0U || capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(exceptions, 0, capacity * sizeof(*exceptions));
	manager->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	manager->exceptions = exceptions;
	manager->capacity = capacity;
	manager->next_exception_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_exception_request(
	struct pqcp_sovereign_exception_manager *manager,
	const char *subject_id,
	const char *control_id,
	const char *owner_id,
	const char *justification,
	uint32_t residual_risk,
	uint32_t compensating_control_mask,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_exception **exception)
{
	struct pqcp_sovereign_exception staged;
	int index;
	int ret;

	if (exception == NULL) {
		return -EINVAL;
	}
	*exception = NULL;
	if (!pqcp_sovereign_internal_text_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    control_id, PQCP_SOVEREIGN_CONTROL_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    owner_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    justification, PQCP_SOVEREIGN_REASON_MAX_CHARS) ||
	    residual_risk > EXCEPTION_RISK_MAX ||
	    compensating_control_mask == 0U ||
	    policy_epoch == 0U || now_ms == 0U ||
	    expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	ret = manager_lock(manager);
	if (ret != 0) {
		return ret;
	}
	if (manager->next_exception_id == 0U ||
	    manager->next_exception_id == UINT64_MAX) {
		manager_unlock(manager);
		return -EOVERFLOW;
	}
	if (matching_exception_index_locked(
		    manager, subject_id, control_id) >= 0) {
		manager_unlock(manager);
		return -EALREADY;
	}
	index = free_exception_index_locked(manager, now_ms);
	if (index < 0) {
		manager_unlock(manager);
		return index;
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.exception_id = manager->next_exception_id++;
	ret = pqcp_sovereign_internal_copy_text(
		staged.subject_id, sizeof(staged.subject_id),
		subject_id);
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			staged.control_id, sizeof(staged.control_id),
			control_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			staged.owner_id, sizeof(staged.owner_id),
			owner_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			staged.justification,
			sizeof(staged.justification),
			justification);
	}
	if (ret != 0) {
		manager_unlock(manager);
		return ret;
	}
	staged.requested_at_ms = now_ms;
	staged.expires_at_ms = expires_at_ms;
	staged.policy_epoch = policy_epoch;
	staged.residual_risk = residual_risk;
	staged.compensating_control_mask =
		compensating_control_mask;
	staged.state = PQCP_SOVEREIGN_EXCEPTION_REQUESTED;
	staged.occupied = true;
	manager->exceptions[index] = staged;
	*exception = &manager->exceptions[index];
	manager_unlock(manager);
	return 0;
}

int pqcp_sovereign_exception_approve(
	struct pqcp_sovereign_exception_manager *manager,
	uint64_t exception_id,
	const uint8_t approval_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_sovereign_exception *exception;
	uint8_t binding[PQCP_SOVEREIGN_DIGEST_BYTES];
	int index;
	int ret;

	if (exception_id == 0U ||
	    digest_zero(approval_digest) || now_ms == 0U) {
		return -EINVAL;
	}
	ret = manager_lock(manager);
	if (ret != 0) {
		return ret;
	}
	index = exception_index_locked(manager, exception_id);
	if (index < 0) {
		manager_unlock(manager);
		return index;
	}
	exception = &manager->exceptions[index];
	if (exception->state !=
	    PQCP_SOVEREIGN_EXCEPTION_REQUESTED) {
		manager_unlock(manager);
		return -EALREADY;
	}
	if (now_ms < exception->requested_at_ms) {
		manager_unlock(manager);
		return -ETIME;
	}
	if (now_ms >= exception->expires_at_ms) {
		exception->state = PQCP_SOVEREIGN_EXCEPTION_EXPIRED;
		if (manager->expiry_count != UINT64_MAX) {
			manager->expiry_count++;
		}
		manager_unlock(manager);
		return -ETIMEDOUT;
	}
	ret = exception_approval_binding_digest(
		exception, now_ms, binding);
	if (ret != 0) {
		manager_unlock(manager);
		return ret;
	}
	if (!pqcp_sovereign_internal_equal(
		    binding, approval_digest, sizeof(binding))) {
		pqcp_runtime_secure_zero(binding, sizeof(binding));
		manager_unlock(manager);
		return -EKEYREJECTED;
	}
	exception->approved_at_ms = now_ms;
	memcpy(exception->approval_digest, approval_digest,
	       sizeof(exception->approval_digest));
	exception->state = PQCP_SOVEREIGN_EXCEPTION_ACTIVE;
	if (manager->approval_count != UINT64_MAX) {
		manager->approval_count++;
	}
	pqcp_runtime_secure_zero(binding, sizeof(binding));
	manager_unlock(manager);
	return 0;
}

int pqcp_sovereign_exception_authorize(
	struct pqcp_sovereign_exception_manager *manager,
	const char *subject_id,
	const char *control_id,
	uint32_t maximum_residual_risk,
	uint64_t policy_epoch,
	uint64_t now_ms)
{
	struct pqcp_sovereign_exception *selected = NULL;
	size_t index;
	int ret;

	if (!pqcp_sovereign_internal_text_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    control_id, PQCP_SOVEREIGN_CONTROL_MAX_CHARS) ||
	    maximum_residual_risk > EXCEPTION_RISK_MAX ||
	    policy_epoch == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = manager_lock(manager);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < manager->capacity; ++index) {
		struct pqcp_sovereign_exception *entry =
			&manager->exceptions[index];

		if (!entry->occupied ||
		    entry->state != PQCP_SOVEREIGN_EXCEPTION_ACTIVE ||
		    strcmp(entry->subject_id, subject_id) != 0 ||
		    strcmp(entry->control_id, control_id) != 0 ||
		    entry->policy_epoch != policy_epoch ||
		    entry->residual_risk > maximum_residual_risk ||
		    entry->compensating_control_mask == 0U ||
		    now_ms < entry->approved_at_ms) {
			continue;
		}
		if (now_ms >= entry->expires_at_ms) {
			entry->state =
				PQCP_SOVEREIGN_EXCEPTION_EXPIRED;
			if (manager->expiry_count != UINT64_MAX) {
				manager->expiry_count++;
			}
			continue;
		}
		if (selected == NULL ||
		    entry->residual_risk < selected->residual_risk ||
		    (entry->residual_risk ==
			     selected->residual_risk &&
		     entry->expires_at_ms <
			     selected->expires_at_ms) ||
		    (entry->residual_risk ==
			     selected->residual_risk &&
		     entry->expires_at_ms ==
			     selected->expires_at_ms &&
		     entry->exception_id <
			     selected->exception_id)) {
			selected = entry;
		}
	}
	if (selected == NULL) {
		manager_unlock(manager);
		return -EACCES;
	}
	manager_unlock(manager);
	return 0;
}

int pqcp_sovereign_exception_revoke(
	struct pqcp_sovereign_exception_manager *manager,
	uint64_t exception_id)
{
	struct pqcp_sovereign_exception *exception;
	int index;
	int ret;

	if (exception_id == 0U) {
		return -EINVAL;
	}
	ret = manager_lock(manager);
	if (ret != 0) {
		return ret;
	}
	index = exception_index_locked(manager, exception_id);
	if (index < 0) {
		manager_unlock(manager);
		return index;
	}
	exception = &manager->exceptions[index];
	if (exception->state ==
	    PQCP_SOVEREIGN_EXCEPTION_REVOKED) {
		manager_unlock(manager);
		return -EALREADY;
	}
	if (exception->state ==
	    PQCP_SOVEREIGN_EXCEPTION_EXPIRED) {
		manager_unlock(manager);
		return -ETIMEDOUT;
	}
	exception->state = PQCP_SOVEREIGN_EXCEPTION_REVOKED;
	manager_unlock(manager);
	return 0;
}

int pqcp_sovereign_exception_tick(
	struct pqcp_sovereign_exception_manager *manager,
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
	ret = manager_lock(manager);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < manager->capacity; ++index) {
		struct pqcp_sovereign_exception *exception =
			&manager->exceptions[index];

		if (!exception->occupied ||
		    exception_terminal(exception->state) ||
		    now_ms < exception->expires_at_ms) {
			continue;
		}
		exception->state =
			PQCP_SOVEREIGN_EXCEPTION_EXPIRED;
		if (count != UINT32_MAX) {
			count++;
		}
		if (manager->expiry_count != UINT64_MAX) {
			manager->expiry_count++;
		}
	}
	*expired_count = count;
	manager_unlock(manager);
	return 0;
}

int pqcp_sovereign_exception_manager_audit(
	struct pqcp_sovereign_exception_manager *manager)
{
	uint8_t binding[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint64_t maximum_id = 0U;
	uint64_t approved = 0U;
	uint64_t expired = 0U;
	size_t left;
	size_t right;
	int ret;

	ret = manager_lock(manager);
	if (ret != 0) {
		return ret;
	}
	if (manager->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    manager->exceptions == NULL ||
	    manager->capacity == 0U ||
	    manager->next_exception_id == 0U) {
		manager_unlock(manager);
		return -EBADMSG;
	}
	for (left = 0U; left < manager->capacity; ++left) {
		const struct pqcp_sovereign_exception *exception =
			&manager->exceptions[left];

		if (!exception->occupied) {
			continue;
		}
		if (!exception_shape_valid(exception)) {
			manager_unlock(manager);
			return -EBADMSG;
		}
		if (exception->exception_id > maximum_id) {
			maximum_id = exception->exception_id;
		}
		if (exception->approved_at_ms != 0U) {
			ret = exception_approval_binding_digest(
				exception, exception->approved_at_ms,
				binding);
			if (ret != 0 ||
			    !pqcp_sovereign_internal_equal(
				    binding,
				    exception->approval_digest,
				    sizeof(binding))) {
				pqcp_runtime_secure_zero(
					binding, sizeof(binding));
				manager_unlock(manager);
				return ret != 0 ? ret : -EBADMSG;
			}
			if (approved != UINT64_MAX) {
				approved++;
			}
		}
		if (exception->state ==
		    PQCP_SOVEREIGN_EXCEPTION_EXPIRED) {
			if (expired != UINT64_MAX) {
				expired++;
			}
		}
		for (right = left + 1U;
		     right < manager->capacity; ++right) {
			const struct pqcp_sovereign_exception *peer =
				&manager->exceptions[right];

			if (!peer->occupied) {
				continue;
			}
			if (peer->exception_id ==
				    exception->exception_id ||
			    (!exception_terminal(peer->state) &&
			     !exception_terminal(exception->state) &&
			     strcmp(peer->subject_id,
				    exception->subject_id) == 0 &&
			     strcmp(peer->control_id,
				    exception->control_id) == 0)) {
				pqcp_runtime_secure_zero(
					binding, sizeof(binding));
				manager_unlock(manager);
				return -EBADMSG;
			}
		}
	}
	pqcp_runtime_secure_zero(binding, sizeof(binding));
	if ((maximum_id != 0U &&
	     manager->next_exception_id <= maximum_id) ||
	    manager->approval_count < approved ||
	    manager->expiry_count < expired) {
		manager_unlock(manager);
		return -EBADMSG;
	}
	manager_unlock(manager);
	return 0;
}
