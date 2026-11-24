/*
 * SPDX-License-Identifier: MIT
 *
 * Policy-fenced, role-separated recovery authorization quorum.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "runtime_internal.h"

static const uint8_t recovery_vote_domain[] =
	"pqcp.sovereign.recovery.vote.v1";

static bool digest_valid(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	if (digest == NULL) {
		return false;
	}
	for (size_t index = 0U;
	     index < PQCP_SOVEREIGN_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate != 0U;
}

static uint64_t add_u64(uint64_t left, uint64_t right)
{
	return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

static uint32_t add_u32(uint32_t left, uint32_t right)
{
	return UINT32_MAX - left < right ? UINT32_MAX : left + right;
}

static bool terminal_state(enum pqcp_sovereign_approval_state state)
{
	return state == PQCP_SOVEREIGN_APPROVAL_SATISFIED ||
	       state == PQCP_SOVEREIGN_APPROVAL_REJECTED ||
	       state == PQCP_SOVEREIGN_APPROVAL_EXPIRED ||
	       state == PQCP_SOVEREIGN_APPROVAL_CANCELLED;
}

static bool request_shape_valid(
	const struct pqcp_sovereign_recovery_request *request)
{
	if (request == NULL || !request->occupied ||
	    request->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    request->recovery_id == 0U ||
	    !pqcp_runtime_internal_text_valid(
		    request->subject_id, sizeof(request->subject_id)) ||
	    !pqcp_runtime_internal_text_valid(
		    request->action, sizeof(request->action)) ||
	    request->opened_at_ms == 0U ||
	    request->expires_at_ms <= request->opened_at_ms ||
	    request->policy_epoch == 0U ||
	    request->threshold == 0U ||
	    request->threshold > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    request->required_distinct_roles == 0U ||
	    request->required_distinct_roles > request->threshold ||
	    request->approval_count > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    request->rejection_count > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    request->distinct_role_count > request->approval_count ||
	    !digest_valid(request->authorization_digest)) {
		return false;
	}
	switch (request->state) {
	case PQCP_SOVEREIGN_APPROVAL_OPEN:
		return request->approval_count < request->threshold ||
		       request->distinct_role_count <
			       request->required_distinct_roles;
	case PQCP_SOVEREIGN_APPROVAL_SATISFIED:
		return request->approval_count >= request->threshold &&
		       request->distinct_role_count >=
			       request->required_distinct_roles;
	case PQCP_SOVEREIGN_APPROVAL_REJECTED:
	case PQCP_SOVEREIGN_APPROVAL_EXPIRED:
	case PQCP_SOVEREIGN_APPROVAL_CANCELLED:
		return true;
	default:
		return false;
	}
}

static bool vote_shape_valid(
	const struct pqcp_sovereign_recovery_vote *vote)
{
	return vote != NULL && vote->occupied &&
	       vote->schema_version == PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       vote->recovery_id != 0U &&
	       pqcp_runtime_internal_text_valid(
		       vote->operator_id, sizeof(vote->operator_id)) &&
	       pqcp_runtime_internal_text_valid(
		       vote->role, sizeof(vote->role)) &&
	       vote->voted_at_ms != 0U &&
	       vote->credential_epoch != 0U &&
	       digest_valid(vote->evidence_digest);
}

static int request_index_locked(
	const struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id)
{
	for (size_t index = 0U;
	     index < quorum->request_capacity; ++index) {
		if (quorum->requests[index].occupied &&
		    quorum->requests[index].recovery_id ==
			    recovery_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static void clear_request_votes_locked(
	struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id)
{
	for (size_t index = 0U; index < quorum->vote_capacity; ++index) {
		if (quorum->votes[index].occupied &&
		    quorum->votes[index].recovery_id == recovery_id) {
			memset(&quorum->votes[index], 0,
			       sizeof(quorum->votes[index]));
		}
	}
}

static int reusable_request_index_locked(
	struct pqcp_sovereign_recovery_quorum *quorum)
{
	int oldest = -1;
	uint64_t oldest_time = UINT64_MAX;

	for (size_t index = 0U;
	     index < quorum->request_capacity; ++index) {
		const struct pqcp_sovereign_recovery_request *request =
			&quorum->requests[index];

		if (!request->occupied) {
			return (int)index;
		}
		if (terminal_state(request->state) &&
		    request->expires_at_ms < oldest_time) {
			oldest = (int)index;
			oldest_time = request->expires_at_ms;
		}
	}
	if (oldest >= 0) {
		clear_request_votes_locked(
			quorum, quorum->requests[oldest].recovery_id);
	}
	return oldest >= 0 ? oldest : -ENOSPC;
}

static int free_vote_index_locked(
	const struct pqcp_sovereign_recovery_quorum *quorum)
{
	for (size_t index = 0U; index < quorum->vote_capacity; ++index) {
		if (!quorum->votes[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int operator_vote_index_locked(
	const struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id,
	const char *operator_id)
{
	for (size_t index = 0U; index < quorum->vote_capacity; ++index) {
		const struct pqcp_sovereign_recovery_vote *vote =
			&quorum->votes[index];

		if (vote->occupied &&
		    vote->recovery_id == recovery_id &&
		    strcmp(vote->operator_id, operator_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static uint32_t vote_count_locked(
	const struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id)
{
	uint32_t count = 0U;

	for (size_t index = 0U; index < quorum->vote_capacity; ++index) {
		if (quorum->votes[index].occupied &&
		    quorum->votes[index].recovery_id == recovery_id) {
			count = add_u32(count, 1U);
		}
	}
	return count;
}

static uint32_t approval_count_locked(
	const struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id)
{
	uint32_t count = 0U;

	for (size_t index = 0U; index < quorum->vote_capacity; ++index) {
		if (quorum->votes[index].occupied &&
		    quorum->votes[index].recovery_id == recovery_id &&
		    quorum->votes[index].approve) {
			count = add_u32(count, 1U);
		}
	}
	return count;
}

static uint32_t rejection_count_locked(
	const struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id)
{
	uint32_t count = 0U;

	for (size_t index = 0U; index < quorum->vote_capacity; ++index) {
		if (quorum->votes[index].occupied &&
		    quorum->votes[index].recovery_id == recovery_id &&
		    !quorum->votes[index].approve) {
			count = add_u32(count, 1U);
		}
	}
	return count;
}

static uint32_t distinct_role_count_locked(
	const struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id)
{
	uint32_t count = 0U;

	for (size_t index = 0U; index < quorum->vote_capacity; ++index) {
		const struct pqcp_sovereign_recovery_vote *vote =
			&quorum->votes[index];
		bool duplicate = false;

		if (!vote->occupied || !vote->approve ||
		    vote->recovery_id != recovery_id) {
			continue;
		}
		for (size_t prior = 0U; prior < index; ++prior) {
			const struct pqcp_sovereign_recovery_vote *seen =
				&quorum->votes[prior];

			if (seen->occupied && seen->approve &&
			    seen->recovery_id == recovery_id &&
			    strcmp(seen->role, vote->role) == 0) {
				duplicate = true;
				break;
			}
		}
		if (!duplicate) {
			count = add_u32(count, 1U);
		}
	}
	return count;
}

static uint32_t electorate_limit(
	const struct pqcp_sovereign_recovery_quorum *quorum)
{
	size_t limit = quorum->vote_capacity;

	if (limit > PQCP_SOVEREIGN_MAX_APPROVERS) {
		limit = PQCP_SOVEREIGN_MAX_APPROVERS;
	}
	return (uint32_t)limit;
}

static void refresh_request_locked(
	struct pqcp_sovereign_recovery_quorum *quorum,
	struct pqcp_sovereign_recovery_request *request)
{
	uint32_t votes;
	uint32_t remaining;
	uint32_t electorate;
	enum pqcp_sovereign_approval_state previous = request->state;

	request->approval_count = approval_count_locked(
		quorum, request->recovery_id);
	request->rejection_count = rejection_count_locked(
		quorum, request->recovery_id);
	request->distinct_role_count = distinct_role_count_locked(
		quorum, request->recovery_id);
	if (request->approval_count >= request->threshold &&
	    request->distinct_role_count >=
		    request->required_distinct_roles) {
		request->state = PQCP_SOVEREIGN_APPROVAL_SATISFIED;
		if (previous != PQCP_SOVEREIGN_APPROVAL_SATISFIED) {
			quorum->satisfied_count =
				add_u64(quorum->satisfied_count, 1U);
		}
		return;
	}
	votes = vote_count_locked(quorum, request->recovery_id);
	electorate = electorate_limit(quorum);
	remaining = votes >= electorate ? 0U : electorate - votes;
	if (request->approval_count + remaining <
		    request->threshold ||
	    request->distinct_role_count + remaining <
		    request->required_distinct_roles) {
		request->state = PQCP_SOVEREIGN_APPROVAL_REJECTED;
	}
}

static int next_recovery_id_locked(
	struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t *recovery_id)
{
	if (quorum->next_recovery_id == 0U ||
	    quorum->next_recovery_id == UINT64_MAX) {
		return -EOVERFLOW;
	}
	*recovery_id = quorum->next_recovery_id++;
	return 0;
}

static int fence_prior_requests_locked(
	struct pqcp_sovereign_recovery_quorum *quorum,
	const char *subject_id,
	const char *action,
	uint64_t policy_epoch,
	const uint8_t authorization_digest[
		PQCP_SOVEREIGN_DIGEST_BYTES],
	struct pqcp_sovereign_recovery_request **idempotent)
{
	*idempotent = NULL;
	for (size_t index = 0U;
	     index < quorum->request_capacity; ++index) {
		struct pqcp_sovereign_recovery_request *request =
			&quorum->requests[index];

		if (!request->occupied ||
		    strcmp(request->subject_id, subject_id) != 0 ||
		    strcmp(request->action, action) != 0) {
			continue;
		}
		if (request->policy_epoch == policy_epoch &&
		    memcmp(request->authorization_digest,
			   authorization_digest,
			   PQCP_SOVEREIGN_DIGEST_BYTES) == 0 &&
		    (request->state == PQCP_SOVEREIGN_APPROVAL_OPEN ||
		     request->state ==
			     PQCP_SOVEREIGN_APPROVAL_SATISFIED)) {
			*idempotent = request;
			return -EALREADY;
		}
		if (!terminal_state(request->state) ||
		    request->state ==
			    PQCP_SOVEREIGN_APPROVAL_SATISFIED) {
			if (request->policy_epoch >= policy_epoch) {
				return -ESTALE;
			}
			request->state =
				PQCP_SOVEREIGN_APPROVAL_CANCELLED;
		}
	}
	return 0;
}

static int bind_vote_evidence(
	const struct pqcp_sovereign_recovery_request *request,
	const char *operator_id,
	const char *role,
	uint64_t credential_epoch,
	uint64_t now_ms,
	bool approve,
	const uint8_t external[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t numeric[36];
	const uint8_t *parts[8];
	size_t lengths[8];

	pqcp_runtime_internal_write_u64(numeric, request->recovery_id);
	pqcp_runtime_internal_write_u64(
		numeric + 8U, request->policy_epoch);
	pqcp_runtime_internal_write_u64(
		numeric + 16U, credential_epoch);
	pqcp_runtime_internal_write_u64(numeric + 24U, now_ms);
	pqcp_runtime_internal_write_u32(
		numeric + 32U, approve ? 1U : 0U);
	parts[0] = recovery_vote_domain;
	lengths[0] = sizeof(recovery_vote_domain) - 1U;
	parts[1] = (const uint8_t *)request->subject_id;
	lengths[1] = strlen(request->subject_id);
	parts[2] = (const uint8_t *)request->action;
	lengths[2] = strlen(request->action);
	parts[3] = (const uint8_t *)operator_id;
	lengths[3] = strlen(operator_id);
	parts[4] = (const uint8_t *)role;
	lengths[4] = strlen(role);
	parts[5] = request->authorization_digest;
	lengths[5] = sizeof(request->authorization_digest);
	parts[6] = external;
	lengths[6] = PQCP_SOVEREIGN_DIGEST_BYTES;
	parts[7] = numeric;
	lengths[7] = sizeof(numeric);
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, 8U, output);
}

int pqcp_sovereign_recovery_quorum_init(
	struct pqcp_sovereign_recovery_quorum *quorum,
	struct pqcp_sovereign_recovery_request *requests,
	size_t request_capacity,
	struct pqcp_sovereign_recovery_vote *votes,
	size_t vote_capacity)
{
	if (quorum == NULL || requests == NULL ||
	    request_capacity == 0U || votes == NULL ||
	    vote_capacity == 0U ||
	    request_capacity > UINT32_MAX ||
	    vote_capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(quorum, 0, sizeof(*quorum));
	memset(requests, 0,
	       request_capacity * sizeof(requests[0]));
	memset(votes, 0, vote_capacity * sizeof(votes[0]));
	quorum->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	quorum->requests = requests;
	quorum->request_capacity = request_capacity;
	quorum->votes = votes;
	quorum->vote_capacity = vote_capacity;
	quorum->next_recovery_id = 1U;
	k_mutex_init(&quorum->lock);
	quorum->initialized = true;
	return 0;
}

int pqcp_sovereign_recovery_open(
	struct pqcp_sovereign_recovery_quorum *quorum,
	const char *subject_id,
	const char *action,
	uint32_t threshold,
	uint32_t required_distinct_roles,
	const uint8_t authorization_digest[
		PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_recovery_request **request)
{
	struct pqcp_sovereign_recovery_request candidate;
	struct pqcp_sovereign_recovery_request *existing;
	int slot;
	int ret;

	if (quorum == NULL || !quorum->initialized ||
	    request == NULL ||
	    !pqcp_runtime_internal_text_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    !pqcp_runtime_internal_text_valid(
		    action, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    threshold == 0U ||
	    threshold > PQCP_SOVEREIGN_MAX_APPROVERS ||
	    threshold > quorum->vote_capacity ||
	    required_distinct_roles == 0U ||
	    required_distinct_roles > threshold ||
	    !digest_valid(authorization_digest) ||
	    policy_epoch == 0U || now_ms == 0U ||
	    expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	*request = NULL;
	k_mutex_lock(&quorum->lock, K_FOREVER);
	ret = fence_prior_requests_locked(
		quorum, subject_id, action, policy_epoch,
		authorization_digest, &existing);
	if (ret != 0) {
		if (ret == -EALREADY) {
			*request = existing;
		}
		k_mutex_unlock(&quorum->lock);
		return ret;
	}
	slot = reusable_request_index_locked(quorum);
	if (slot < 0) {
		k_mutex_unlock(&quorum->lock);
		return slot;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	ret = next_recovery_id_locked(
		quorum, &candidate.recovery_id);
	if (ret == 0) {
		ret = pqcp_runtime_internal_copy_text(
			candidate.subject_id,
			sizeof(candidate.subject_id), subject_id);
	}
	if (ret == 0) {
		ret = pqcp_runtime_internal_copy_text(
			candidate.action,
			sizeof(candidate.action), action);
	}
	if (ret != 0) {
		k_mutex_unlock(&quorum->lock);
		return ret;
	}
	candidate.opened_at_ms = now_ms;
	candidate.expires_at_ms = expires_at_ms;
	candidate.policy_epoch = policy_epoch;
	candidate.threshold = threshold;
	candidate.required_distinct_roles =
		required_distinct_roles;
	memcpy(candidate.authorization_digest,
	       authorization_digest,
	       sizeof(candidate.authorization_digest));
	candidate.state = PQCP_SOVEREIGN_APPROVAL_OPEN;
	candidate.occupied = true;
	quorum->requests[slot] = candidate;
	*request = &quorum->requests[slot];
	k_mutex_unlock(&quorum->lock);
	return 0;
}

int pqcp_sovereign_recovery_vote(
	struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id,
	const char *operator_id,
	const char *role,
	uint64_t credential_epoch,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	bool approve,
	uint64_t now_ms)
{
	struct pqcp_sovereign_recovery_request *request;
	struct pqcp_sovereign_recovery_vote candidate;
	int request_slot;
	int vote_slot;
	int ret;

	if (quorum == NULL || !quorum->initialized ||
	    recovery_id == 0U ||
	    !pqcp_runtime_internal_text_valid(
		    operator_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_runtime_internal_text_valid(
		    role, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    credential_epoch == 0U ||
	    !digest_valid(evidence_digest) || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&quorum->lock, K_FOREVER);
	request_slot = request_index_locked(quorum, recovery_id);
	if (request_slot < 0) {
		ret = request_slot;
		goto out;
	}
	request = &quorum->requests[request_slot];
	if (request->state != PQCP_SOVEREIGN_APPROVAL_OPEN) {
		ret = terminal_state(request->state) ?
			-EALREADY : -EPERM;
		goto out;
	}
	if (now_ms < request->opened_at_ms) {
		ret = -ETIME;
		goto out;
	}
	if (now_ms >= request->expires_at_ms) {
		request->state = PQCP_SOVEREIGN_APPROVAL_EXPIRED;
		ret = -ETIMEDOUT;
		goto out;
	}
	if (credential_epoch < request->policy_epoch) {
		ret = -ESTALE;
		goto out;
	}
	if (operator_vote_index_locked(
		    quorum, recovery_id, operator_id) >= 0) {
		ret = -EALREADY;
		goto out;
	}
	if (vote_count_locked(quorum, recovery_id) >=
	    electorate_limit(quorum)) {
		ret = -ENOSPC;
		goto out;
	}
	vote_slot = free_vote_index_locked(quorum);
	if (vote_slot < 0) {
		ret = vote_slot;
		goto out;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.recovery_id = recovery_id;
	ret = pqcp_runtime_internal_copy_text(
		candidate.operator_id,
		sizeof(candidate.operator_id), operator_id);
	if (ret == 0) {
		ret = pqcp_runtime_internal_copy_text(
			candidate.role, sizeof(candidate.role), role);
	}
	if (ret == 0) {
		ret = bind_vote_evidence(
			request, operator_id, role,
			credential_epoch, now_ms, approve,
			evidence_digest, candidate.evidence_digest);
	}
	if (ret != 0) {
		goto out;
	}
	candidate.voted_at_ms = now_ms;
	candidate.credential_epoch = credential_epoch;
	candidate.approve = approve;
	candidate.occupied = true;
	quorum->votes[vote_slot] = candidate;
	refresh_request_locked(quorum, request);
out:
	k_mutex_unlock(&quorum->lock);
	return ret;
}

int pqcp_sovereign_recovery_authorize(
	struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t recovery_id,
	uint64_t policy_epoch,
	uint64_t now_ms)
{
	struct pqcp_sovereign_recovery_request *request;
	int index;
	int ret = 0;

	if (quorum == NULL || !quorum->initialized ||
	    recovery_id == 0U || policy_epoch == 0U ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&quorum->lock, K_FOREVER);
	index = request_index_locked(quorum, recovery_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	request = &quorum->requests[index];
	if (now_ms < request->opened_at_ms) {
		ret = -ETIME;
		goto out;
	}
	if (now_ms >= request->expires_at_ms) {
		if (request->state == PQCP_SOVEREIGN_APPROVAL_OPEN) {
			request->state =
				PQCP_SOVEREIGN_APPROVAL_EXPIRED;
		}
		ret = -ETIMEDOUT;
		goto out;
	}
	if (policy_epoch != request->policy_epoch) {
		ret = -ESTALE;
		goto out;
	}
	for (size_t other = 0U;
	     other < quorum->request_capacity; ++other) {
		const struct pqcp_sovereign_recovery_request *peer =
			&quorum->requests[other];

		if (peer->occupied &&
		    peer->recovery_id != request->recovery_id &&
		    strcmp(peer->subject_id,
			   request->subject_id) == 0 &&
		    strcmp(peer->action, request->action) == 0 &&
		    peer->policy_epoch > request->policy_epoch &&
		    peer->state !=
			    PQCP_SOVEREIGN_APPROVAL_CANCELLED) {
			request->state =
				PQCP_SOVEREIGN_APPROVAL_CANCELLED;
			ret = -ESTALE;
			goto out;
		}
	}
	if (request->state == PQCP_SOVEREIGN_APPROVAL_OPEN) {
		refresh_request_locked(quorum, request);
	}
	switch (request->state) {
	case PQCP_SOVEREIGN_APPROVAL_SATISFIED:
		ret = 0;
		break;
	case PQCP_SOVEREIGN_APPROVAL_REJECTED:
		ret = -EACCES;
		break;
	case PQCP_SOVEREIGN_APPROVAL_EXPIRED:
		ret = -ETIMEDOUT;
		break;
	case PQCP_SOVEREIGN_APPROVAL_CANCELLED:
		ret = -ESTALE;
		break;
	default:
		ret = -EAGAIN;
		break;
	}
out:
	k_mutex_unlock(&quorum->lock);
	return ret;
}

int pqcp_sovereign_recovery_quorum_tick(
	struct pqcp_sovereign_recovery_quorum *quorum,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;

	if (quorum == NULL || !quorum->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&quorum->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < quorum->request_capacity; ++index) {
		struct pqcp_sovereign_recovery_request *request =
			&quorum->requests[index];

		if (request->occupied &&
		    request->state == PQCP_SOVEREIGN_APPROVAL_OPEN &&
		    now_ms >= request->expires_at_ms) {
			request->state =
				PQCP_SOVEREIGN_APPROVAL_EXPIRED;
			expired = add_u32(expired, 1U);
		}
	}
	*expired_count = expired;
	k_mutex_unlock(&quorum->lock);
	return 0;
}

static int audit_request_votes_locked(
	const struct pqcp_sovereign_recovery_quorum *quorum,
	const struct pqcp_sovereign_recovery_request *request)
{
	uint32_t approvals = approval_count_locked(
		quorum, request->recovery_id);
	uint32_t rejections = rejection_count_locked(
		quorum, request->recovery_id);
	uint32_t roles = distinct_role_count_locked(
		quorum, request->recovery_id);

	if (approvals != request->approval_count ||
	    rejections != request->rejection_count ||
	    roles != request->distinct_role_count ||
	    approvals + rejections >
		    electorate_limit(quorum)) {
		return -EBADMSG;
	}
	for (size_t index = 0U; index < quorum->vote_capacity; ++index) {
		const struct pqcp_sovereign_recovery_vote *vote =
			&quorum->votes[index];

		if (!vote->occupied ||
		    vote->recovery_id != request->recovery_id) {
			continue;
		}
		if (!vote_shape_valid(vote) ||
		    vote->voted_at_ms < request->opened_at_ms ||
		    vote->voted_at_ms >= request->expires_at_ms ||
		    vote->credential_epoch < request->policy_epoch) {
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < quorum->vote_capacity; ++other) {
			const struct pqcp_sovereign_recovery_vote *peer =
				&quorum->votes[other];

			if (peer->occupied &&
			    peer->recovery_id == vote->recovery_id &&
			    strcmp(peer->operator_id,
				   vote->operator_id) == 0) {
				return -EEXIST;
			}
		}
	}
	return 0;
}

int pqcp_sovereign_recovery_quorum_audit(
	struct pqcp_sovereign_recovery_quorum *quorum)
{
	uint64_t maximum_id = 0U;
	uint64_t resident_satisfied = 0U;
	int ret = 0;

	if (quorum == NULL || !quorum->initialized ||
	    quorum->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    quorum->requests == NULL ||
	    quorum->request_capacity == 0U ||
	    quorum->votes == NULL ||
	    quorum->vote_capacity == 0U ||
	    quorum->next_recovery_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&quorum->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < quorum->request_capacity && ret == 0; ++index) {
		const struct pqcp_sovereign_recovery_request *request =
			&quorum->requests[index];

		if (!request->occupied) {
			continue;
		}
		if (!request_shape_valid(request) ||
		    request->threshold > electorate_limit(quorum)) {
			ret = -EBADMSG;
			break;
		}
		if (request->recovery_id > maximum_id) {
			maximum_id = request->recovery_id;
		}
		if (request->state ==
		    PQCP_SOVEREIGN_APPROVAL_SATISFIED) {
			resident_satisfied =
				add_u64(resident_satisfied, 1U);
		}
		ret = audit_request_votes_locked(quorum, request);
		for (size_t other = index + 1U;
		     other < quorum->request_capacity && ret == 0;
		     ++other) {
			const struct pqcp_sovereign_recovery_request *peer =
				&quorum->requests[other];

			if (!peer->occupied) {
				continue;
			}
			if (peer->recovery_id == request->recovery_id) {
				ret = -EEXIST;
				break;
			}
			if (strcmp(peer->subject_id,
				   request->subject_id) == 0 &&
			    strcmp(peer->action,
				   request->action) == 0 &&
			    !terminal_state(peer->state) &&
			    !terminal_state(request->state)) {
				ret = -EBUSY;
			}
		}
	}
	for (size_t index = 0U;
	     index < quorum->vote_capacity && ret == 0; ++index) {
		if (quorum->votes[index].occupied &&
		    (!vote_shape_valid(&quorum->votes[index]) ||
		     request_index_locked(
			     quorum,
			     quorum->votes[index].recovery_id) < 0)) {
			ret = -EBADMSG;
		}
	}
	if (ret == 0 && maximum_id != 0U &&
	    quorum->next_recovery_id <= maximum_id) {
		ret = -EBADMSG;
	}
	if (ret == 0 &&
	    quorum->satisfied_count < resident_satisfied) {
		ret = -EBADMSG;
	}
	k_mutex_unlock(&quorum->lock);
	return ret;
}
