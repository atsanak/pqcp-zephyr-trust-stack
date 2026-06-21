/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Per-principal and per-service admission control.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool policy_valid(
	const struct pqcp_edge_traffic_policy *policy)
{
	return policy != NULL &&
	       policy->request_rate_per_window != 0U &&
	       policy->byte_rate_per_window != 0U &&
	       policy->window_ms != 0U &&
	       policy->maximum_concurrent != 0U &&
	       policy->burst_requests != 0U;
}

static int subject_index(
	const struct pqcp_edge_traffic_governor *governor,
	const char *principal_id,
	const char *service_id)
{
	for (size_t index = 0U;
	     index < governor->capacity; ++index) {
		const struct pqcp_edge_traffic_subject *subject =
			&governor->subjects[index];

		if (subject->occupied &&
		    strcmp(subject->principal_id,
			   principal_id) == 0 &&
		    strcmp(subject->service_id,
			   service_id) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_subject_index(
	const struct pqcp_edge_traffic_governor *governor)
{
	for (size_t index = 0U;
	     index < governor->capacity; ++index) {
		if (!governor->subjects[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static void refill_subject(
	const struct pqcp_edge_traffic_policy *policy,
	struct pqcp_edge_traffic_subject *subject,
	uint64_t now_ms)
{
	uint64_t elapsed;
	uint64_t windows;
	uint64_t request_refill;
	uint64_t byte_refill;
	uint64_t maximum_requests;

	if (now_ms <= subject->window_started_ms) {
		return;
	}
	elapsed = now_ms - subject->window_started_ms;
	windows = elapsed / policy->window_ms;
	if (windows == 0U) {
		return;
	}
	request_refill =
		pqcp_edge_internal_saturating_add_u64(
			0U,
			policy->request_rate_per_window *
				windows);
	byte_refill =
		pqcp_edge_internal_saturating_add_u64(
			0U,
			policy->byte_rate_per_window *
				windows);
	maximum_requests =
		pqcp_edge_internal_saturating_add_u64(
			policy->request_rate_per_window,
			policy->burst_requests);
	subject->request_tokens =
		pqcp_edge_internal_saturating_add_u64(
			subject->request_tokens,
			request_refill);
	if (subject->request_tokens > maximum_requests) {
		subject->request_tokens = maximum_requests;
	}
	subject->byte_tokens =
		pqcp_edge_internal_saturating_add_u64(
			subject->byte_tokens, byte_refill);
	if (subject->byte_tokens >
	    policy->byte_rate_per_window) {
		subject->byte_tokens =
			policy->byte_rate_per_window;
	}
	subject->window_started_ms +=
		windows * policy->window_ms;
}

static int get_or_create_subject(
	struct pqcp_edge_traffic_governor *governor,
	const char *principal_id,
	const char *service_id,
	uint64_t now_ms)
{
	struct pqcp_edge_traffic_subject *subject;
	int index;
	int ret;

	index = subject_index(
		governor, principal_id, service_id);
	if (index >= 0) {
		return index;
	}
	if (index != -ENOENT) {
		return index;
	}
	index = free_subject_index(governor);
	if (index < 0) {
		return index;
	}
	subject = &governor->subjects[index];
	memset(subject, 0, sizeof(*subject));
	ret = pqcp_edge_internal_copy_text(
		subject->principal_id,
		sizeof(subject->principal_id),
		principal_id);
	if (ret == 0) {
		ret = pqcp_edge_internal_copy_text(
			subject->service_id,
			sizeof(subject->service_id),
			service_id);
	}
	if (ret != 0) {
		memset(subject, 0, sizeof(*subject));
		return ret;
	}
	subject->window_started_ms = now_ms;
	subject->request_tokens =
		pqcp_edge_internal_saturating_add_u64(
			governor->policy.
				request_rate_per_window,
			governor->policy.burst_requests);
	subject->byte_tokens =
		governor->policy.byte_rate_per_window;
	subject->occupied = true;
	return index;
}

int pqcp_edge_traffic_governor_init(
	struct pqcp_edge_traffic_governor *governor,
	const struct pqcp_edge_traffic_policy *policy,
	struct pqcp_edge_traffic_subject *subjects,
	size_t capacity)
{
	if (governor == NULL || !policy_valid(policy) ||
	    subjects == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(governor, 0, sizeof(*governor));
	memset(subjects, 0,
	       capacity * sizeof(*subjects));
	governor->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	governor->policy = *policy;
	governor->subjects = subjects;
	governor->capacity = capacity;
	k_mutex_init(&governor->lock);
	governor->initialized = true;
	return 0;
}

int pqcp_edge_traffic_authorize(
	struct pqcp_edge_traffic_governor *governor,
	const char *principal_id,
	const char *service_id,
	uint64_t bytes,
	uint64_t now_ms)
{
	struct pqcp_edge_traffic_subject *subject;
	int index;
	int ret = 0;

	if (governor == NULL || !governor->initialized ||
	    !pqcp_edge_internal_text_valid(
		    principal_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    service_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    bytes == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&governor->lock, K_FOREVER);
	index = get_or_create_subject(
		governor, principal_id, service_id, now_ms);
	if (index < 0) {
		ret = index;
		goto out;
	}
	subject = &governor->subjects[index];
	refill_subject(&governor->policy, subject, now_ms);
	if (subject->blocked_until_ms != 0U &&
	    now_ms < subject->blocked_until_ms) {
		ret = -EACCES;
	} else if (subject->concurrent >=
		   governor->policy.maximum_concurrent) {
		ret = -EDQUOT;
	} else if (subject->request_tokens == 0U ||
		   subject->byte_tokens < bytes) {
		ret = -EAGAIN;
	} else {
		--subject->request_tokens;
		subject->byte_tokens -= bytes;
		++subject->concurrent;
		++subject->accepted_requests;
		subject->accepted_bytes =
			pqcp_edge_internal_saturating_add_u64(
				subject->accepted_bytes,
				bytes);
	}
	if (ret != 0) {
		++subject->rejected_requests;
	}
out:
	k_mutex_unlock(&governor->lock);
	return ret;
}

int pqcp_edge_traffic_complete(
	struct pqcp_edge_traffic_governor *governor,
	const char *principal_id,
	const char *service_id,
	bool success,
	uint64_t now_ms)
{
	struct pqcp_edge_traffic_subject *subject;
	int index;
	int ret = 0;

	if (governor == NULL || !governor->initialized ||
	    principal_id == NULL || service_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&governor->lock, K_FOREVER);
	index = subject_index(
		governor, principal_id, service_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	subject = &governor->subjects[index];
	refill_subject(&governor->policy, subject, now_ms);
	if (subject->concurrent == 0U) {
		ret = -EALREADY;
		goto out;
	}
	--subject->concurrent;
	if (success) {
		if (subject->failure_score >
		    governor->policy.recovery_credit) {
			subject->failure_score -=
				governor->policy.recovery_credit;
		} else {
			subject->failure_score = 0U;
		}
	} else {
		subject->failure_score =
			pqcp_edge_internal_saturating_add_u32(
				subject->failure_score,
				governor->policy.failure_penalty);
		if (subject->failure_score >= 1000U) {
			subject->blocked_until_ms =
				pqcp_edge_internal_saturating_add_u64(
					now_ms,
					governor->policy.window_ms);
		}
	}
out:
	k_mutex_unlock(&governor->lock);
	return ret;
}

int pqcp_edge_traffic_block(
	struct pqcp_edge_traffic_governor *governor,
	const char *principal_id,
	const char *service_id,
	uint64_t until_ms)
{
	int index;
	int ret = 0;

	if (governor == NULL || !governor->initialized ||
	    principal_id == NULL || service_id == NULL ||
	    until_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&governor->lock, K_FOREVER);
	index = subject_index(
		governor, principal_id, service_id);
	if (index < 0) {
		ret = index;
	} else {
		governor->subjects[index].blocked_until_ms =
			until_ms;
	}
	k_mutex_unlock(&governor->lock);
	return ret;
}

int pqcp_edge_traffic_tick(
	struct pqcp_edge_traffic_governor *governor,
	uint64_t now_ms,
	uint32_t *refilled_count)
{
	uint32_t refilled = 0U;

	if (governor == NULL || !governor->initialized ||
	    refilled_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&governor->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < governor->capacity; ++index) {
		struct pqcp_edge_traffic_subject *subject =
			&governor->subjects[index];
		uint64_t requests;
		uint64_t bytes;

		if (!subject->occupied) {
			continue;
		}
		requests = subject->request_tokens;
		bytes = subject->byte_tokens;
		refill_subject(
			&governor->policy, subject, now_ms);
		if (requests != subject->request_tokens ||
		    bytes != subject->byte_tokens) {
			++refilled;
		}
		if (subject->blocked_until_ms != 0U &&
		    now_ms >= subject->blocked_until_ms) {
			subject->blocked_until_ms = 0U;
			subject->failure_score /=
				2U;
		}
	}
	k_mutex_unlock(&governor->lock);
	*refilled_count = refilled;
	return 0;
}

int pqcp_edge_traffic_governor_audit(
	struct pqcp_edge_traffic_governor *governor)
{
	int ret = 0;

	if (governor == NULL || !governor->initialized ||
	    governor->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    !policy_valid(&governor->policy) ||
	    governor->subjects == NULL ||
	    governor->capacity == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&governor->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < governor->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_traffic_subject *subject =
			&governor->subjects[index];

		if (!subject->occupied) {
			continue;
		}
		if (!pqcp_edge_internal_text_valid(
			    subject->principal_id,
			    sizeof(subject->principal_id)) ||
		    !pqcp_edge_internal_text_valid(
			    subject->service_id,
			    sizeof(subject->service_id)) ||
		    subject->concurrent >
			    governor->policy.maximum_concurrent) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < governor->capacity; ++other) {
			if (governor->subjects[other].occupied &&
			    strcmp(
				    subject->principal_id,
				    governor->subjects[other].
					    principal_id) == 0 &&
			    strcmp(
				    subject->service_id,
				    governor->subjects[other].
					    service_id) == 0) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&governor->lock);
	return ret;
}
