/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free sovereign key ceremony state machine.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"
#include "sovereign_ceremony_internal.h"

#define CEREMONY_DOMAIN "pqcp-sovereign-ceremony-state-v1"
#define CONTRIBUTION_DOMAIN "pqcp-sovereign-contribution-v1"
#define COMMIT_DOMAIN "pqcp-sovereign-ceremony-commit-v1"
#define ABORT_DOMAIN "pqcp-sovereign-ceremony-abort-v1"

static bool ceremony_state_valid(
	enum pqcp_sovereign_ceremony_state state)
{
	switch (state) {
	case PQCP_SOVEREIGN_CEREMONY_EMPTY:
	case PQCP_SOVEREIGN_CEREMONY_PLANNED:
	case PQCP_SOVEREIGN_CEREMONY_COLLECTING:
	case PQCP_SOVEREIGN_CEREMONY_COMBINING:
	case PQCP_SOVEREIGN_CEREMONY_COMMITTED:
	case PQCP_SOVEREIGN_CEREMONY_ABORTED:
		return true;
	default:
		return false;
	}
}

static bool ceremony_terminal(
	enum pqcp_sovereign_ceremony_state state)
{
	return state == PQCP_SOVEREIGN_CEREMONY_COMMITTED ||
	       state == PQCP_SOVEREIGN_CEREMONY_ABORTED;
}

static int lock_manager(
	struct pqcp_sovereign_key_ceremony_manager *manager)
{
	if (manager == NULL || !manager->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&manager->lock, K_FOREVER);
}

static void unlock_manager(
	struct pqcp_sovereign_key_ceremony_manager *manager)
{
	(void)k_mutex_unlock(&manager->lock);
}

static int ceremony_index_locked(
	const struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id)
{
	size_t index;

	if (ceremony_id == 0U) {
		return -EINVAL;
	}
	for (index = 0U; index < manager->ceremony_capacity;
	     ++index) {
		if (manager->ceremonies[index].occupied &&
		    manager->ceremonies[index].ceremony_id ==
			    ceremony_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_ceremony_index_locked(
	const struct pqcp_sovereign_key_ceremony_manager *manager)
{
	size_t index;

	for (index = 0U; index < manager->ceremony_capacity;
	     ++index) {
		if (!manager->ceremonies[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int free_contribution_index_locked(
	const struct pqcp_sovereign_key_ceremony_manager *manager)
{
	size_t index;

	for (index = 0U; index < manager->contribution_capacity;
	     ++index) {
		if (!manager->contributions[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int contribution_index_locked(
	const struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id,
	const char *custodian_id)
{
	size_t index;

	for (index = 0U; index < manager->contribution_capacity;
	     ++index) {
		const struct pqcp_sovereign_key_contribution *entry =
			&manager->contributions[index];

		if (entry->occupied &&
		    entry->ceremony_id == ceremony_id &&
		    strcmp(entry->custodian_id, custodian_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static bool contribution_role_seen_locked(
	const struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id,
	const char *role)
{
	size_t index;

	for (index = 0U; index < manager->contribution_capacity;
	     ++index) {
		const struct pqcp_sovereign_key_contribution *entry =
			&manager->contributions[index];

		if (entry->occupied &&
		    entry->verified &&
		    entry->ceremony_id == ceremony_id &&
		    strcmp(entry->role, role) == 0) {
			return true;
		}
	}
	return false;
}

static uint32_t contribution_count_locked(
	const struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id)
{
	uint32_t count = 0U;
	size_t index;

	for (index = 0U; index < manager->contribution_capacity;
	     ++index) {
		if (manager->contributions[index].occupied &&
		    manager->contributions[index].verified &&
		    manager->contributions[index].ceremony_id ==
			    ceremony_id &&
		    count != UINT32_MAX) {
			count++;
		}
	}
	return count;
}

static uint32_t distinct_role_count_locked(
	const struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id)
{
	uint32_t count = 0U;
	size_t index;
	size_t prior;

	for (index = 0U; index < manager->contribution_capacity;
	     ++index) {
		const struct pqcp_sovereign_key_contribution *entry =
			&manager->contributions[index];
		bool duplicate = false;

		if (!entry->occupied || !entry->verified ||
		    entry->ceremony_id != ceremony_id) {
			continue;
		}
		for (prior = 0U; prior < index; ++prior) {
			const struct pqcp_sovereign_key_contribution *seen =
				&manager->contributions[prior];

			if (seen->occupied && seen->verified &&
			    seen->ceremony_id == ceremony_id &&
			    strcmp(seen->role, entry->role) == 0) {
				duplicate = true;
				break;
			}
		}
		if (!duplicate && count != UINT32_MAX) {
			count++;
		}
	}
	return count;
}

static int ceremony_open_digest(
	const struct pqcp_sovereign_key_ceremony *ceremony,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_CEREMONY_BYTES];
	size_t offset = 0U;

	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, CEREMONY_DOMAIN,
		sizeof(CEREMONY_DOMAIN));
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, ceremony->schema_version);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, ceremony->ceremony_id);
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, ceremony->key_id,
		sizeof(ceremony->key_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, ceremony->purpose,
		sizeof(ceremony->purpose));
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, ceremony->current_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, ceremony->target_epoch);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, ceremony->opened_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, ceremony->expires_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, ceremony->threshold);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		ceremony->required_distinct_roles);
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	int ret = pqcp_sovereign_ceremony_hash(
		body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int contribution_event_digest(
	const struct pqcp_sovereign_key_ceremony *ceremony,
	const struct pqcp_sovereign_key_contribution *contribution,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_CEREMONY_BYTES];
	size_t offset = 0U;

	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, CONTRIBUTION_DOMAIN,
		sizeof(CONTRIBUTION_DOMAIN));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, ceremony->transcript_digest,
		sizeof(ceremony->transcript_digest));
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, contribution->ceremony_id);
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, contribution->custodian_id,
		sizeof(contribution->custodian_id));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, contribution->role,
		sizeof(contribution->role));
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset,
		contribution->submitted_at_ms);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset,
		contribution->credential_epoch);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		contribution->contribution_digest,
		sizeof(contribution->contribution_digest));
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset,
		contribution->proof_digest,
		sizeof(contribution->proof_digest));
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	int ret = pqcp_sovereign_ceremony_hash(
		body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int ceremony_terminal_digest(
	const struct pqcp_sovereign_key_ceremony *ceremony,
	const char *domain,
	const uint8_t key_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[PQCP_SOVEREIGN_CANONICAL_CEREMONY_BYTES];
	size_t offset = 0U;

	memset(body, 0, sizeof(body));
	offset = pqcp_sovereign_ceremony_encode_text(
		body, sizeof(body), offset, domain,
		PQCP_SOVEREIGN_LABEL_MAX_CHARS);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, ceremony->transcript_digest,
		sizeof(ceremony->transcript_digest));
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, ceremony->ceremony_id);
	offset = pqcp_sovereign_ceremony_encode_u64(
		body, sizeof(body), offset, ceremony->target_epoch);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset, ceremony->contribution_count);
	offset = pqcp_sovereign_ceremony_encode_u32(
		body, sizeof(body), offset,
		ceremony->distinct_role_count);
	offset = pqcp_sovereign_ceremony_encode_bytes(
		body, sizeof(body), offset, key_digest,
		PQCP_SOVEREIGN_DIGEST_BYTES);
	if (offset == 0U || offset > sizeof(body)) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return -EOVERFLOW;
	}
	int ret = pqcp_sovereign_ceremony_hash(
		body, offset, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static bool purpose_epoch_valid(
	const char *purpose,
	uint64_t current_epoch,
	uint64_t target_epoch)
{
	enum pqcp_sovereign_ceremony_action action =
		pqcp_sovereign_ceremony_action_from_text(purpose);

	switch (action) {
	case PQCP_SOVEREIGN_CEREMONY_ACTION_GENERATE:
		return current_epoch == 0U && target_epoch != 0U;
	case PQCP_SOVEREIGN_CEREMONY_ACTION_ROTATE:
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RECOVER:
		return current_epoch != 0U &&
		       target_epoch > current_epoch;
	case PQCP_SOVEREIGN_CEREMONY_ACTION_RETIRE:
	case PQCP_SOVEREIGN_CEREMONY_ACTION_DESTROY:
		return current_epoch != 0U &&
		       target_epoch >= current_epoch;
	default:
		return false;
	}
}

static bool ceremony_shape_valid(
	const struct pqcp_sovereign_key_ceremony *ceremony)
{
	if (ceremony == NULL || !ceremony->occupied ||
	    ceremony->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    ceremony->ceremony_id == 0U ||
	    !pqcp_sovereign_ceremony_text_valid(
		    ceremony->key_id, sizeof(ceremony->key_id)) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    ceremony->purpose, sizeof(ceremony->purpose)) ||
	    !purpose_epoch_valid(
		    ceremony->purpose, ceremony->current_epoch,
		    ceremony->target_epoch) ||
	    ceremony->opened_at_ms == 0U ||
	    ceremony->expires_at_ms <= ceremony->opened_at_ms ||
	    ceremony->threshold == 0U ||
	    ceremony->threshold > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    ceremony->required_distinct_roles == 0U ||
	    ceremony->required_distinct_roles > ceremony->threshold ||
	    ceremony->contribution_count >
		    PQCP_SOVEREIGN_MAX_APPROVERS ||
	    ceremony->distinct_role_count >
		    ceremony->contribution_count ||
	    pqcp_sovereign_ceremony_digest_zero(
		    ceremony->transcript_digest) ||
	    !ceremony_state_valid(ceremony->state)) {
		return false;
	}
	if (ceremony->state == PQCP_SOVEREIGN_CEREMONY_COMMITTED &&
	    (ceremony->contribution_count < ceremony->threshold ||
	     ceremony->distinct_role_count <
		     ceremony->required_distinct_roles ||
	     pqcp_sovereign_ceremony_digest_zero(
		     ceremony->committed_key_digest))) {
		return false;
	}
	if (ceremony->state != PQCP_SOVEREIGN_CEREMONY_COMMITTED &&
	    !pqcp_sovereign_ceremony_digest_zero(
		    ceremony->committed_key_digest)) {
		return false;
	}
	return true;
}

static bool contribution_shape_valid(
	const struct pqcp_sovereign_key_contribution *contribution)
{
	return contribution != NULL &&
	       contribution->occupied &&
	       contribution->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       contribution->ceremony_id != 0U &&
	       pqcp_sovereign_ceremony_text_valid(
		       contribution->custodian_id,
		       sizeof(contribution->custodian_id)) &&
	       pqcp_sovereign_ceremony_text_valid(
		       contribution->role,
		       sizeof(contribution->role)) &&
	       contribution->submitted_at_ms != 0U &&
	       contribution->credential_epoch != 0U &&
	       !pqcp_sovereign_ceremony_digest_zero(
		       contribution->contribution_digest) &&
	       !pqcp_sovereign_ceremony_digest_zero(
		       contribution->proof_digest) &&
	       contribution->verified;
}

int pqcp_sovereign_key_ceremony_manager_init(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	struct pqcp_sovereign_key_ceremony *ceremonies,
	size_t ceremony_capacity,
	struct pqcp_sovereign_key_contribution *contributions,
	size_t contribution_capacity)
{
	if (manager == NULL || ceremonies == NULL ||
	    ceremony_capacity == 0U ||
	    contributions == NULL ||
	    contribution_capacity == 0U ||
	    ceremony_capacity > UINT32_MAX ||
	    contribution_capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(ceremonies, 0,
	       ceremony_capacity * sizeof(*ceremonies));
	memset(contributions, 0,
	       contribution_capacity * sizeof(*contributions));
	manager->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	manager->ceremonies = ceremonies;
	manager->ceremony_capacity = ceremony_capacity;
	manager->contributions = contributions;
	manager->contribution_capacity = contribution_capacity;
	manager->next_ceremony_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_sovereign_key_ceremony_open(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	const char *key_id,
	const char *purpose,
	uint64_t current_epoch,
	uint64_t target_epoch,
	uint32_t threshold,
	uint32_t required_distinct_roles,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_key_ceremony **ceremony)
{
	struct pqcp_sovereign_key_ceremony staged;
	int slot;
	int ret;

	if (ceremony == NULL) {
		return -EINVAL;
	}
	*ceremony = NULL;
	if (!pqcp_sovereign_ceremony_text_valid(
		    key_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    purpose, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !purpose_epoch_valid(purpose, current_epoch, target_epoch) ||
	    threshold == 0U ||
	    threshold > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    required_distinct_roles == 0U ||
	    required_distinct_roles > threshold ||
	    now_ms == 0U || expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	ret = lock_manager(manager);
	if (ret != 0) {
		return ret;
	}
	if (manager->next_ceremony_id == 0U ||
	    manager->next_ceremony_id == UINT64_MAX) {
		unlock_manager(manager);
		return -EOVERFLOW;
	}
	slot = free_ceremony_index_locked(manager);
	if (slot < 0) {
		unlock_manager(manager);
		return slot;
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.ceremony_id = manager->next_ceremony_id++;
	ret = pqcp_sovereign_ceremony_copy_text(
		staged.key_id, sizeof(staged.key_id), key_id);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.purpose, sizeof(staged.purpose), purpose);
	}
	if (ret != 0) {
		unlock_manager(manager);
		return ret;
	}
	staged.current_epoch = current_epoch;
	staged.target_epoch = target_epoch;
	staged.opened_at_ms = now_ms;
	staged.expires_at_ms = expires_at_ms;
	staged.threshold = threshold;
	staged.required_distinct_roles = required_distinct_roles;
	staged.state = PQCP_SOVEREIGN_CEREMONY_COLLECTING;
	staged.occupied = true;
	ret = ceremony_open_digest(
		&staged, staged.transcript_digest);
	if (ret != 0) {
		unlock_manager(manager);
		return ret;
	}
	manager->ceremonies[slot] = staged;
	*ceremony = &manager->ceremonies[slot];
	unlock_manager(manager);
	return 0;
}

int pqcp_sovereign_key_ceremony_contribute(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id,
	const char *custodian_id,
	const char *role,
	uint64_t credential_epoch,
	const uint8_t contribution_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t proof_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_sovereign_key_ceremony *ceremony;
	struct pqcp_sovereign_key_contribution staged;
	uint8_t next_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	bool new_role;
	int ceremony_slot;
	int contribution_slot;
	int ret;

	if (ceremony_id == 0U ||
	    !pqcp_sovereign_ceremony_text_valid(
		    custodian_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    role, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    credential_epoch == 0U ||
	    contribution_digest == NULL ||
	    proof_digest == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(
		    contribution_digest) ||
	    pqcp_sovereign_ceremony_digest_zero(proof_digest) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_manager(manager);
	if (ret != 0) {
		return ret;
	}
	ceremony_slot = ceremony_index_locked(
		manager, ceremony_id);
	if (ceremony_slot < 0) {
		unlock_manager(manager);
		return ceremony_slot;
	}
	ceremony = &manager->ceremonies[ceremony_slot];
	if (ceremony->state !=
	    PQCP_SOVEREIGN_CEREMONY_COLLECTING) {
		unlock_manager(manager);
		return ceremony_terminal(ceremony->state) ?
		       -EALREADY : -EBUSY;
	}
	if (now_ms < ceremony->opened_at_ms) {
		unlock_manager(manager);
		return -EINVAL;
	}
	if (now_ms >= ceremony->expires_at_ms) {
		ceremony->state = PQCP_SOVEREIGN_CEREMONY_ABORTED;
		if (manager->aborted_count != UINT64_MAX) {
			manager->aborted_count++;
		}
		unlock_manager(manager);
		return -ETIMEDOUT;
	}
	if (credential_epoch < ceremony->target_epoch) {
		unlock_manager(manager);
		return -ESTALE;
	}
	if (contribution_index_locked(
		    manager, ceremony_id, custodian_id) >= 0) {
		unlock_manager(manager);
		return -EALREADY;
	}
	if (ceremony->contribution_count >=
	    PQCP_SOVEREIGN_MAX_APPROVERS) {
		unlock_manager(manager);
		return -ENOSPC;
	}
	contribution_slot =
		free_contribution_index_locked(manager);
	if (contribution_slot < 0) {
		unlock_manager(manager);
		return contribution_slot;
	}
	new_role = !contribution_role_seen_locked(
		manager, ceremony_id, role);
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.ceremony_id = ceremony_id;
	ret = pqcp_sovereign_ceremony_copy_text(
		staged.custodian_id,
		sizeof(staged.custodian_id), custodian_id);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.role, sizeof(staged.role), role);
	}
	if (ret != 0) {
		unlock_manager(manager);
		return ret;
	}
	staged.submitted_at_ms = now_ms;
	staged.credential_epoch = credential_epoch;
	memcpy(staged.contribution_digest, contribution_digest,
	       sizeof(staged.contribution_digest));
	memcpy(staged.proof_digest, proof_digest,
	       sizeof(staged.proof_digest));
	staged.verified = true;
	staged.occupied = true;
	ret = contribution_event_digest(
		ceremony, &staged, next_digest);
	if (ret != 0) {
		unlock_manager(manager);
		return ret;
	}
	manager->contributions[contribution_slot] = staged;
	ceremony->contribution_count++;
	if (new_role) {
		ceremony->distinct_role_count++;
	}
	memcpy(ceremony->transcript_digest, next_digest,
	       sizeof(ceremony->transcript_digest));
	if (ceremony->contribution_count >= ceremony->threshold &&
	    ceremony->distinct_role_count >=
		    ceremony->required_distinct_roles) {
		ceremony->state =
			PQCP_SOVEREIGN_CEREMONY_COMBINING;
	}
	pqcp_runtime_secure_zero(
		next_digest, sizeof(next_digest));
	unlock_manager(manager);
	return 0;
}

int pqcp_sovereign_key_ceremony_commit(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id,
	const uint8_t committed_key_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_sovereign_key_ceremony *ceremony;
	uint8_t next_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int index;
	int ret;

	if (ceremony_id == 0U ||
	    committed_key_digest == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(
		    committed_key_digest) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = lock_manager(manager);
	if (ret != 0) {
		return ret;
	}
	index = ceremony_index_locked(manager, ceremony_id);
	if (index < 0) {
		unlock_manager(manager);
		return index;
	}
	ceremony = &manager->ceremonies[index];
	if (ceremony->state !=
	    PQCP_SOVEREIGN_CEREMONY_COMBINING) {
		unlock_manager(manager);
		return ceremony_terminal(ceremony->state) ?
		       -EALREADY : -EACCES;
	}
	if (now_ms < ceremony->opened_at_ms ||
	    now_ms >= ceremony->expires_at_ms) {
		ceremony->state = PQCP_SOVEREIGN_CEREMONY_ABORTED;
		if (manager->aborted_count != UINT64_MAX) {
			manager->aborted_count++;
		}
		unlock_manager(manager);
		return -ETIMEDOUT;
	}
	if (ceremony->contribution_count < ceremony->threshold ||
	    ceremony->distinct_role_count <
		    ceremony->required_distinct_roles) {
		unlock_manager(manager);
		return -EACCES;
	}
	ret = ceremony_terminal_digest(
		ceremony, COMMIT_DOMAIN, committed_key_digest,
		next_digest);
	if (ret != 0) {
		unlock_manager(manager);
		return ret;
	}
	memcpy(ceremony->committed_key_digest,
	       committed_key_digest,
	       sizeof(ceremony->committed_key_digest));
	memcpy(ceremony->transcript_digest, next_digest,
	       sizeof(ceremony->transcript_digest));
	ceremony->state = PQCP_SOVEREIGN_CEREMONY_COMMITTED;
	if (manager->completed_count != UINT64_MAX) {
		manager->completed_count++;
	}
	pqcp_runtime_secure_zero(
		next_digest, sizeof(next_digest));
	unlock_manager(manager);
	return 0;
}

int pqcp_sovereign_key_ceremony_abort(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t ceremony_id)
{
	struct pqcp_sovereign_key_ceremony *ceremony;
	uint8_t zero_digest[PQCP_SOVEREIGN_DIGEST_BYTES] = { 0 };
	uint8_t next_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int index;
	int ret;

	ret = lock_manager(manager);
	if (ret != 0) {
		return ret;
	}
	index = ceremony_index_locked(manager, ceremony_id);
	if (index < 0) {
		unlock_manager(manager);
		return index;
	}
	ceremony = &manager->ceremonies[index];
	if (ceremony_terminal(ceremony->state)) {
		unlock_manager(manager);
		return -EALREADY;
	}
	ret = ceremony_terminal_digest(
		ceremony, ABORT_DOMAIN, zero_digest, next_digest);
	if (ret != 0) {
		unlock_manager(manager);
		return ret;
	}
	memcpy(ceremony->transcript_digest, next_digest,
	       sizeof(ceremony->transcript_digest));
	ceremony->state = PQCP_SOVEREIGN_CEREMONY_ABORTED;
	if (manager->aborted_count != UINT64_MAX) {
		manager->aborted_count++;
	}
	pqcp_runtime_secure_zero(
		next_digest, sizeof(next_digest));
	unlock_manager(manager);
	return 0;
}

int pqcp_sovereign_key_ceremony_tick(
	struct pqcp_sovereign_key_ceremony_manager *manager,
	uint64_t now_ms,
	uint32_t *aborted_count)
{
	uint8_t zero_digest[PQCP_SOVEREIGN_DIGEST_BYTES] = { 0 };
	uint8_t next_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint32_t count = 0U;
	size_t index;
	int ret;

	if (now_ms == 0U || aborted_count == NULL) {
		return -EINVAL;
	}
	*aborted_count = 0U;
	ret = lock_manager(manager);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < manager->ceremony_capacity;
	     ++index) {
		struct pqcp_sovereign_key_ceremony *ceremony =
			&manager->ceremonies[index];

		if (!ceremony->occupied ||
		    ceremony_terminal(ceremony->state) ||
		    now_ms < ceremony->expires_at_ms) {
			continue;
		}
		ret = ceremony_terminal_digest(
			ceremony, ABORT_DOMAIN, zero_digest,
			next_digest);
		if (ret != 0) {
			unlock_manager(manager);
			return ret;
		}
		memcpy(ceremony->transcript_digest, next_digest,
		       sizeof(ceremony->transcript_digest));
		ceremony->state =
			PQCP_SOVEREIGN_CEREMONY_ABORTED;
		if (count != UINT32_MAX) {
			count++;
		}
		if (manager->aborted_count != UINT64_MAX) {
			manager->aborted_count++;
		}
	}
	*aborted_count = count;
	pqcp_runtime_secure_zero(
		next_digest, sizeof(next_digest));
	unlock_manager(manager);
	return 0;
}

static int audit_contributions_locked(
	const struct pqcp_sovereign_key_ceremony_manager *manager,
	const struct pqcp_sovereign_key_ceremony *ceremony)
{
	uint32_t count = contribution_count_locked(
		manager, ceremony->ceremony_id);
	uint32_t roles = distinct_role_count_locked(
		manager, ceremony->ceremony_id);
	size_t left;
	size_t right;

	if (count != ceremony->contribution_count ||
	    roles != ceremony->distinct_role_count) {
		return -EBADMSG;
	}
	for (left = 0U; left < manager->contribution_capacity;
	     ++left) {
		const struct pqcp_sovereign_key_contribution *entry =
			&manager->contributions[left];

		if (!entry->occupied ||
		    entry->ceremony_id != ceremony->ceremony_id) {
			continue;
		}
		if (!contribution_shape_valid(entry) ||
		    entry->submitted_at_ms < ceremony->opened_at_ms ||
		    entry->submitted_at_ms >= ceremony->expires_at_ms ||
		    entry->credential_epoch < ceremony->target_epoch) {
			return -EBADMSG;
		}
		for (right = left + 1U;
		     right < manager->contribution_capacity; ++right) {
			const struct pqcp_sovereign_key_contribution *other =
				&manager->contributions[right];

			if (other->occupied &&
			    other->ceremony_id == ceremony->ceremony_id &&
			    strcmp(other->custodian_id,
				   entry->custodian_id) == 0) {
				return -EBADMSG;
			}
		}
	}
	return 0;
}

int pqcp_sovereign_key_ceremony_manager_audit(
	struct pqcp_sovereign_key_ceremony_manager *manager)
{
	uint64_t maximum_id = 0U;
	size_t left;
	size_t right;
	int ret;

	ret = lock_manager(manager);
	if (ret != 0) {
		return ret;
	}
	if (manager->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    manager->ceremonies == NULL ||
	    manager->ceremony_capacity == 0U ||
	    manager->contributions == NULL ||
	    manager->contribution_capacity == 0U ||
	    manager->next_ceremony_id == 0U) {
		unlock_manager(manager);
		return -EBADMSG;
	}
	for (left = 0U; left < manager->ceremony_capacity;
	     ++left) {
		const struct pqcp_sovereign_key_ceremony *ceremony =
			&manager->ceremonies[left];

		if (!ceremony->occupied) {
			continue;
		}
		if (!ceremony_shape_valid(ceremony)) {
			unlock_manager(manager);
			return -EBADMSG;
		}
		if (ceremony->ceremony_id > maximum_id) {
			maximum_id = ceremony->ceremony_id;
		}
		for (right = left + 1U;
		     right < manager->ceremony_capacity; ++right) {
			if (manager->ceremonies[right].occupied &&
			    manager->ceremonies[right].ceremony_id ==
				    ceremony->ceremony_id) {
				unlock_manager(manager);
				return -EBADMSG;
			}
		}
		ret = audit_contributions_locked(
			manager, ceremony);
		if (ret != 0) {
			unlock_manager(manager);
			return ret;
		}
	}
	for (left = 0U; left < manager->contribution_capacity;
	     ++left) {
		if (!manager->contributions[left].occupied) {
			continue;
		}
		if (!contribution_shape_valid(
			    &manager->contributions[left]) ||
		    ceremony_index_locked(
			    manager,
			    manager->contributions[left].ceremony_id) <
			    0) {
			unlock_manager(manager);
			return -EBADMSG;
		}
	}
	if (maximum_id != 0U &&
	    manager->next_ceremony_id <= maximum_id) {
		unlock_manager(manager);
		return -EBADMSG;
	}
	unlock_manager(manager);
	return 0;
}
