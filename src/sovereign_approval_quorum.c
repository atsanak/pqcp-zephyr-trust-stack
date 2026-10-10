/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free role-separated approval quorum.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"
#include "sovereign_ceremony_internal.h"

static bool approval_state_valid(enum pqcp_sovereign_approval_state state)
{
	switch (state) {
	case PQCP_SOVEREIGN_APPROVAL_EMPTY:
	case PQCP_SOVEREIGN_APPROVAL_OPEN:
	case PQCP_SOVEREIGN_APPROVAL_SATISFIED:
	case PQCP_SOVEREIGN_APPROVAL_REJECTED:
	case PQCP_SOVEREIGN_APPROVAL_EXPIRED:
	case PQCP_SOVEREIGN_APPROVAL_CANCELLED:
		return true;
	default:
		return false;
	}
}

static bool approval_terminal(enum pqcp_sovereign_approval_state state)
{
	return state == PQCP_SOVEREIGN_APPROVAL_SATISFIED ||
	       state == PQCP_SOVEREIGN_APPROVAL_REJECTED ||
	       state == PQCP_SOVEREIGN_APPROVAL_EXPIRED ||
	       state == PQCP_SOVEREIGN_APPROVAL_CANCELLED;
}

static bool approval_role_valid(const char *role)
{
	static const char *const roles[] = {
		"security-officer",
		"key-custodian",
		"policy-owner",
		"auditor",
		"recovery-officer",
		"privacy-steward",
	};
	size_t index;

	if (!pqcp_sovereign_ceremony_text_valid(
		    role, PQCP_SOVEREIGN_LABEL_MAX_CHARS)) {
		return false;
	}
	for (index = 0U; index < ARRAY_SIZE(roles); ++index) {
		if (strcmp(role, roles[index]) == 0) {
			return true;
		}
	}
	return false;
}

static bool request_shape_valid(
	const struct pqcp_sovereign_approval_request *request)
{
	if (request == NULL || !request->occupied ||
	    request->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    request->request_id == 0U ||
	    !pqcp_sovereign_ceremony_text_valid(
		    request->subject_id, sizeof(request->subject_id)) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    request->action, sizeof(request->action)) ||
	    request->required_capabilities == 0U ||
	    request->required_approvals == 0U ||
	    request->required_approvals > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    request->required_distinct_roles == 0U ||
	    request->required_distinct_roles >
		    request->required_approvals ||
	    request->opened_at_ms == 0U ||
	    request->expires_at_ms <= request->opened_at_ms ||
	    request->policy_epoch == 0U ||
	    pqcp_sovereign_ceremony_digest_zero(
		    request->subject_digest) ||
	    !approval_state_valid(request->state)) {
		return false;
	}
	if (request->approval_count > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    request->rejection_count > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    request->distinct_role_count > request->approval_count ||
	    request->distinct_role_count >
		    PQCP_SOVEREIGN_MAX_APPROVERS) {
		return false;
	}
	if (request->state == PQCP_SOVEREIGN_APPROVAL_SATISFIED &&
	    (request->approval_count < request->required_approvals ||
	     request->distinct_role_count <
		     request->required_distinct_roles)) {
		return false;
	}
	if (request->state == PQCP_SOVEREIGN_APPROVAL_OPEN &&
	    request->approval_count >= request->required_approvals &&
	    request->distinct_role_count >=
		    request->required_distinct_roles) {
		return false;
	}
	if (request->state == PQCP_SOVEREIGN_APPROVAL_REJECTED &&
	    request->approval_count >= request->required_approvals &&
	    request->distinct_role_count >=
		    request->required_distinct_roles) {
		return false;
	}
	return true;
}

static bool vote_shape_valid(
	const struct pqcp_sovereign_approval_vote *vote)
{
	return vote != NULL &&
	       vote->occupied &&
	       vote->schema_version == PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       vote->request_id != 0U &&
	       pqcp_sovereign_ceremony_text_valid(
		       vote->approver_id, sizeof(vote->approver_id)) &&
	       approval_role_valid(vote->role) &&
	       vote->capabilities != 0U &&
	       vote->voted_at_ms != 0U &&
	       vote->credential_epoch != 0U &&
	       !pqcp_sovereign_ceremony_digest_zero(vote->vote_digest);
}

static int lock_quorum(struct pqcp_sovereign_approval_quorum *quorum)
{
	if (quorum == NULL || !quorum->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&quorum->lock, K_FOREVER);
}

static void unlock_quorum(struct pqcp_sovereign_approval_quorum *quorum)
{
	(void)k_mutex_unlock(&quorum->lock);
}

static int request_index_locked(
	const struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id)
{
	size_t index;

	if (request_id == 0U) {
		return -EINVAL;
	}
	for (index = 0U; index < quorum->request_capacity; ++index) {
		const struct pqcp_sovereign_approval_request *candidate =
			&quorum->requests[index];

		if (candidate->occupied &&
		    candidate->request_id == request_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_request_index_locked(
	const struct pqcp_sovereign_approval_quorum *quorum)
{
	size_t index;

	for (index = 0U; index < quorum->request_capacity; ++index) {
		if (!quorum->requests[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int free_vote_index_locked(
	const struct pqcp_sovereign_approval_quorum *quorum)
{
	size_t index;

	for (index = 0U; index < quorum->vote_capacity; ++index) {
		if (!quorum->votes[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int vote_index_locked(
	const struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id,
	const char *approver_id)
{
	size_t index;

	for (index = 0U; index < quorum->vote_capacity; ++index) {
		const struct pqcp_sovereign_approval_vote *vote =
			&quorum->votes[index];

		if (vote->occupied &&
		    vote->request_id == request_id &&
		    strcmp(vote->approver_id, approver_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static bool role_seen_locked(
	const struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id,
	const char *role)
{
	size_t index;

	for (index = 0U; index < quorum->vote_capacity; ++index) {
		const struct pqcp_sovereign_approval_vote *vote =
			&quorum->votes[index];

		if (vote->occupied &&
		    vote->request_id == request_id &&
		    vote->approve &&
		    strcmp(vote->role, role) == 0) {
			return true;
		}
	}
	return false;
}

static uint32_t request_vote_count_locked(
	const struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id)
{
	uint32_t count = 0U;
	size_t index;

	for (index = 0U; index < quorum->vote_capacity; ++index) {
		if (quorum->votes[index].occupied &&
		    quorum->votes[index].request_id == request_id) {
			if (count != UINT32_MAX) {
				count++;
			}
		}
	}
	return count;
}

static uint32_t free_vote_count_locked(
	const struct pqcp_sovereign_approval_quorum *quorum)
{
	uint32_t count = 0U;
	size_t index;

	for (index = 0U; index < quorum->vote_capacity; ++index) {
		if (!quorum->votes[index].occupied &&
		    count != UINT32_MAX) {
			count++;
		}
	}
	return count;
}

static uint32_t request_approval_count_locked(
	const struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id)
{
	uint32_t count = 0U;
	size_t index;

	for (index = 0U; index < quorum->vote_capacity; ++index) {
		if (quorum->votes[index].occupied &&
		    quorum->votes[index].request_id == request_id &&
		    quorum->votes[index].approve) {
			if (count != UINT32_MAX) {
				count++;
			}
		}
	}
	return count;
}

static uint32_t request_rejection_count_locked(
	const struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id)
{
	uint32_t count = 0U;
	size_t index;

	for (index = 0U; index < quorum->vote_capacity; ++index) {
		if (quorum->votes[index].occupied &&
		    quorum->votes[index].request_id == request_id &&
		    !quorum->votes[index].approve) {
			if (count != UINT32_MAX) {
				count++;
			}
		}
	}
	return count;
}

static uint32_t request_distinct_role_count_locked(
	const struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id)
{
	uint32_t count = 0U;
	size_t index;
	size_t prior;

	for (index = 0U; index < quorum->vote_capacity; ++index) {
		const struct pqcp_sovereign_approval_vote *vote =
			&quorum->votes[index];
		bool duplicate = false;

		if (!vote->occupied ||
		    vote->request_id != request_id ||
		    !vote->approve) {
			continue;
		}
		for (prior = 0U; prior < index; ++prior) {
			const struct pqcp_sovereign_approval_vote *seen =
				&quorum->votes[prior];

			if (seen->occupied &&
			    seen->request_id == request_id &&
			    seen->approve &&
			    strcmp(seen->role, vote->role) == 0) {
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

static bool request_can_still_satisfy_locked(
	const struct pqcp_sovereign_approval_quorum *quorum,
	const struct pqcp_sovereign_approval_request *request)
{
	const uint32_t cast = request_vote_count_locked(
		quorum, request->request_id);
	const uint32_t approvals = request_approval_count_locked(
		quorum, request->request_id);
	const uint32_t distinct_roles =
		request_distinct_role_count_locked(
			quorum, request->request_id);
	uint32_t remaining = free_vote_count_locked(quorum);
	uint32_t request_slots;

	if (cast >= PQCP_SOVEREIGN_MAX_APPROVERS) {
		request_slots = 0U;
	} else {
		request_slots = PQCP_SOVEREIGN_MAX_APPROVERS - cast;
	}
	if (remaining > request_slots) {
		remaining = request_slots;
	}
	if (approvals < request->required_approvals &&
	    remaining < request->required_approvals - approvals) {
		return false;
	}
	if (distinct_roles < request->required_distinct_roles &&
	    remaining <
		    request->required_distinct_roles - distinct_roles) {
		return false;
	}
	return true;
}

static void refresh_request_locked(
	struct pqcp_sovereign_approval_quorum *quorum,
	struct pqcp_sovereign_approval_request *request)
{
	request->approval_count = request_approval_count_locked(
		quorum, request->request_id);
	request->rejection_count = request_rejection_count_locked(
		quorum, request->request_id);
	request->distinct_role_count =
		request_distinct_role_count_locked(
			quorum, request->request_id);
	if (request->approval_count >= request->required_approvals &&
	    request->distinct_role_count >=
		    request->required_distinct_roles) {
		request->state = PQCP_SOVEREIGN_APPROVAL_SATISFIED;
		if (quorum->satisfied_count != UINT64_MAX) {
			quorum->satisfied_count++;
		}
	} else if (!request_can_still_satisfy_locked(quorum, request)) {
		request->state = PQCP_SOVEREIGN_APPROVAL_REJECTED;
		if (quorum->rejected_count != UINT64_MAX) {
			quorum->rejected_count++;
		}
	}
}

static int validate_open_arguments(
	const char *subject_id,
	const char *action,
	uint64_t required_capabilities,
	uint32_t required_approvals,
	uint32_t required_distinct_roles,
	const uint8_t subject_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms)
{
	if (!pqcp_sovereign_ceremony_text_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    !pqcp_sovereign_ceremony_text_valid(
		    action, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    required_capabilities == 0U ||
	    required_approvals == 0U ||
	    required_approvals > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    required_distinct_roles == 0U ||
	    required_distinct_roles > required_approvals ||
	    subject_digest == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(subject_digest) ||
	    policy_epoch == 0U ||
	    now_ms == 0U ||
	    expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	return 0;
}

static int validate_vote_arguments(
	const char *approver_id,
	const char *role,
	uint64_t capabilities,
	uint64_t credential_epoch,
	const uint8_t vote_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms)
{
	if (!pqcp_sovereign_ceremony_text_valid(
		    approver_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !approval_role_valid(role) ||
	    capabilities == 0U ||
	    credential_epoch == 0U ||
	    vote_digest == NULL ||
	    pqcp_sovereign_ceremony_digest_zero(vote_digest) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_sovereign_approval_quorum_init(
	struct pqcp_sovereign_approval_quorum *quorum,
	struct pqcp_sovereign_approval_request *requests,
	size_t request_capacity,
	struct pqcp_sovereign_approval_vote *votes,
	size_t vote_capacity)
{
	if (quorum == NULL || requests == NULL ||
	    request_capacity == 0U ||
	    votes == NULL || vote_capacity == 0U ||
	    request_capacity > UINT32_MAX ||
	    vote_capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(quorum, 0, sizeof(*quorum));
	memset(requests, 0, request_capacity * sizeof(*requests));
	memset(votes, 0, vote_capacity * sizeof(*votes));
	quorum->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	quorum->requests = requests;
	quorum->request_capacity = request_capacity;
	quorum->votes = votes;
	quorum->vote_capacity = vote_capacity;
	quorum->next_request_id = 1U;
	k_mutex_init(&quorum->lock);
	quorum->initialized = true;
	return 0;
}

int pqcp_sovereign_approval_open(
	struct pqcp_sovereign_approval_quorum *quorum,
	const char *subject_id,
	const char *action,
	uint64_t required_capabilities,
	uint32_t required_approvals,
	uint32_t required_distinct_roles,
	const uint8_t subject_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_approval_request **request)
{
	struct pqcp_sovereign_approval_request staged;
	int slot;
	int ret;

	if (request == NULL) {
		return -EINVAL;
	}
	*request = NULL;
	ret = validate_open_arguments(
		subject_id, action, required_capabilities,
		required_approvals, required_distinct_roles,
		subject_digest, policy_epoch, now_ms,
		expires_at_ms);
	if (ret != 0) {
		return ret;
	}
	ret = lock_quorum(quorum);
	if (ret != 0) {
		return ret;
	}
	if (quorum->next_request_id == 0U ||
	    quorum->next_request_id == UINT64_MAX) {
		unlock_quorum(quorum);
		return -EOVERFLOW;
	}
	slot = free_request_index_locked(quorum);
	if (slot < 0) {
		unlock_quorum(quorum);
		return slot;
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.request_id = quorum->next_request_id++;
	ret = pqcp_sovereign_ceremony_copy_text(
		staged.subject_id, sizeof(staged.subject_id), subject_id);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.action, sizeof(staged.action), action);
	}
	if (ret != 0) {
		unlock_quorum(quorum);
		return ret;
	}
	staged.opened_at_ms = now_ms;
	staged.expires_at_ms = expires_at_ms;
	staged.policy_epoch = policy_epoch;
	staged.required_capabilities = required_capabilities;
	staged.required_approvals = required_approvals;
	staged.required_distinct_roles = required_distinct_roles;
	staged.state = PQCP_SOVEREIGN_APPROVAL_OPEN;
	memcpy(staged.subject_digest, subject_digest,
	       sizeof(staged.subject_digest));
	staged.occupied = true;
	quorum->requests[slot] = staged;
	*request = &quorum->requests[slot];
	unlock_quorum(quorum);
	return 0;
}

int pqcp_sovereign_approval_vote(
	struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id,
	const char *approver_id,
	const char *role,
	uint64_t capabilities,
	uint64_t credential_epoch,
	bool approve,
	const uint8_t vote_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_sovereign_approval_request *request;
	struct pqcp_sovereign_approval_vote staged;
	bool new_role;
	int request_slot;
	int vote_slot;
	int ret;

	ret = validate_vote_arguments(
		approver_id, role, capabilities, credential_epoch,
		vote_digest, now_ms);
	if (ret != 0 || request_id == 0U) {
		return ret != 0 ? ret : -EINVAL;
	}
	ret = lock_quorum(quorum);
	if (ret != 0) {
		return ret;
	}
	request_slot = request_index_locked(quorum, request_id);
	if (request_slot < 0) {
		unlock_quorum(quorum);
		return request_slot;
	}
	request = &quorum->requests[request_slot];
	if (request->state != PQCP_SOVEREIGN_APPROVAL_OPEN) {
		unlock_quorum(quorum);
		return approval_terminal(request->state) ?
		       -EALREADY : -EPERM;
	}
	if (now_ms < request->opened_at_ms) {
		unlock_quorum(quorum);
		return -EINVAL;
	}
	if (now_ms >= request->expires_at_ms) {
		request->state = PQCP_SOVEREIGN_APPROVAL_EXPIRED;
		unlock_quorum(quorum);
		return -ETIMEDOUT;
	}
	if ((capabilities & request->required_capabilities) !=
	    request->required_capabilities) {
		unlock_quorum(quorum);
		return -EACCES;
	}
	if (credential_epoch < request->policy_epoch) {
		unlock_quorum(quorum);
		return -ESTALE;
	}
	if (vote_index_locked(
		    quorum, request_id, approver_id) >= 0) {
		unlock_quorum(quorum);
		return -EALREADY;
	}
	if (request_vote_count_locked(quorum, request_id) >=
	    PQCP_SOVEREIGN_MAX_APPROVERS) {
		unlock_quorum(quorum);
		return -ENOSPC;
	}
	vote_slot = free_vote_index_locked(quorum);
	if (vote_slot < 0) {
		unlock_quorum(quorum);
		return vote_slot;
	}
	new_role = approve &&
		   !role_seen_locked(quorum, request_id, role);
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.request_id = request_id;
	ret = pqcp_sovereign_ceremony_copy_text(
		staged.approver_id, sizeof(staged.approver_id),
		approver_id);
	if (ret == 0) {
		ret = pqcp_sovereign_ceremony_copy_text(
			staged.role, sizeof(staged.role), role);
	}
	if (ret != 0) {
		unlock_quorum(quorum);
		return ret;
	}
	staged.capabilities = capabilities;
	staged.voted_at_ms = now_ms;
	staged.credential_epoch = credential_epoch;
	staged.approve = approve;
	memcpy(staged.vote_digest, vote_digest,
	       sizeof(staged.vote_digest));
	staged.occupied = true;
	quorum->votes[vote_slot] = staged;
	if (approve) {
		request->approval_count++;
		if (new_role) {
			request->distinct_role_count++;
		}
	} else {
		request->rejection_count++;
	}
	refresh_request_locked(quorum, request);
	unlock_quorum(quorum);
	return 0;
}

int pqcp_sovereign_approval_status(
	struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t request_id,
	enum pqcp_sovereign_approval_state *state,
	uint32_t *approvals,
	uint32_t *distinct_roles)
{
	const struct pqcp_sovereign_approval_request *request;
	int index;
	int ret;

	if (state == NULL || approvals == NULL ||
	    distinct_roles == NULL || request_id == 0U) {
		return -EINVAL;
	}
	ret = lock_quorum(quorum);
	if (ret != 0) {
		return ret;
	}
	index = request_index_locked(quorum, request_id);
	if (index < 0) {
		unlock_quorum(quorum);
		return index;
	}
	request = &quorum->requests[index];
	*state = request->state;
	*approvals = request->approval_count;
	*distinct_roles = request->distinct_role_count;
	unlock_quorum(quorum);
	return 0;
}

int pqcp_sovereign_approval_tick(
	struct pqcp_sovereign_approval_quorum *quorum,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t count = 0U;
	size_t index;
	int ret;

	if (expired_count == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	*expired_count = 0U;
	ret = lock_quorum(quorum);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < quorum->request_capacity; ++index) {
		struct pqcp_sovereign_approval_request *request =
			&quorum->requests[index];

		if (request->occupied &&
		    request->state == PQCP_SOVEREIGN_APPROVAL_OPEN &&
		    now_ms >= request->expires_at_ms) {
			request->state =
				PQCP_SOVEREIGN_APPROVAL_EXPIRED;
			if (count != UINT32_MAX) {
				count++;
			}
		}
	}
	*expired_count = count;
	unlock_quorum(quorum);
	return 0;
}

static int audit_request_votes_locked(
	const struct pqcp_sovereign_approval_quorum *quorum,
	const struct pqcp_sovereign_approval_request *request)
{
	uint32_t approvals;
	uint32_t rejections;
	uint32_t distinct_roles;
	size_t left;
	size_t right;

	approvals = request_approval_count_locked(
		quorum, request->request_id);
	rejections = request_rejection_count_locked(
		quorum, request->request_id);
	distinct_roles = request_distinct_role_count_locked(
		quorum, request->request_id);
	if (approvals != request->approval_count ||
	    rejections != request->rejection_count ||
	    distinct_roles != request->distinct_role_count) {
		return -EBADMSG;
	}
	for (left = 0U; left < quorum->vote_capacity; ++left) {
		const struct pqcp_sovereign_approval_vote *vote =
			&quorum->votes[left];

		if (!vote->occupied ||
		    vote->request_id != request->request_id) {
			continue;
		}
		if (!vote_shape_valid(vote) ||
		    (vote->capabilities &
		     request->required_capabilities) !=
			    request->required_capabilities ||
		    vote->credential_epoch < request->policy_epoch ||
		    vote->voted_at_ms < request->opened_at_ms ||
		    vote->voted_at_ms >= request->expires_at_ms) {
			return -EBADMSG;
		}
		for (right = left + 1U;
		     right < quorum->vote_capacity; ++right) {
			const struct pqcp_sovereign_approval_vote *other =
				&quorum->votes[right];

			if (other->occupied &&
			    other->request_id == request->request_id &&
			    strcmp(other->approver_id,
				   vote->approver_id) == 0) {
				return -EBADMSG;
			}
		}
	}
	return 0;
}

int pqcp_sovereign_approval_quorum_audit(
	struct pqcp_sovereign_approval_quorum *quorum)
{
	uint64_t maximum_id = 0U;
	size_t left;
	size_t right;
	int ret;

	ret = lock_quorum(quorum);
	if (ret != 0) {
		return ret;
	}
	if (quorum->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    quorum->requests == NULL ||
	    quorum->request_capacity == 0U ||
	    quorum->votes == NULL ||
	    quorum->vote_capacity == 0U ||
	    quorum->next_request_id == 0U) {
		unlock_quorum(quorum);
		return -EBADMSG;
	}
	for (left = 0U; left < quorum->request_capacity; ++left) {
		const struct pqcp_sovereign_approval_request *request =
			&quorum->requests[left];

		if (!request->occupied) {
			continue;
		}
		if (!request_shape_valid(request)) {
			unlock_quorum(quorum);
			return -EBADMSG;
		}
		if (request->request_id > maximum_id) {
			maximum_id = request->request_id;
		}
		for (right = left + 1U;
		     right < quorum->request_capacity; ++right) {
			if (quorum->requests[right].occupied &&
			    quorum->requests[right].request_id ==
				    request->request_id) {
				unlock_quorum(quorum);
				return -EBADMSG;
			}
		}
		ret = audit_request_votes_locked(quorum, request);
		if (ret != 0) {
			unlock_quorum(quorum);
			return ret;
		}
	}
	for (left = 0U; left < quorum->vote_capacity; ++left) {
		if (!quorum->votes[left].occupied) {
			continue;
		}
		if (!vote_shape_valid(&quorum->votes[left]) ||
		    request_index_locked(
			    quorum,
			    quorum->votes[left].request_id) < 0) {
			unlock_quorum(quorum);
			return -EBADMSG;
		}
	}
	if (maximum_id != 0U &&
	    quorum->next_request_id <= maximum_id) {
		unlock_quorum(quorum);
		return -EBADMSG;
	}
	unlock_quorum(quorum);
	return 0;
}
