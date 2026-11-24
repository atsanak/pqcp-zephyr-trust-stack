/*
 * SPDX-License-Identifier: MIT
 *
 * Per-owner execution and session admission quotas.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_governance.h>

#include "runtime_internal.h"

static struct pqcp_runtime_admission_quota *find_quota(
	struct pqcp_runtime_admission *admission,
	const char *owner)
{
	for (size_t index = 0U; index < admission->capacity; ++index) {
		if (admission->quotas[index].active &&
		    strcmp(admission->quotas[index].owner,
			   owner) == 0) {
			return &admission->quotas[index];
		}
	}
	return NULL;
}

static struct pqcp_runtime_admission_quota *free_quota(
	struct pqcp_runtime_admission *admission)
{
	for (size_t index = 0U; index < admission->capacity; ++index) {
		if (!admission->quotas[index].active) {
			return &admission->quotas[index];
		}
	}
	return NULL;
}

static bool quota_valid(
	const struct pqcp_runtime_admission_quota *quota)
{
	return quota != NULL &&
	       quota->schema_version ==
		       PQCP_RUNTIME_SCHEMA_VERSION &&
	       pqcp_runtime_internal_owner_valid(quota->owner) &&
	       quota->maximum_concurrent_jobs != 0U &&
	       quota->maximum_sessions != 0U &&
	       quota->maximum_cycles_per_window != 0U &&
	       quota->maximum_bytes_per_window != 0U &&
	       quota->window_ms != 0U &&
	       quota->concurrent_jobs <=
		       quota->maximum_concurrent_jobs &&
	       quota->active_sessions <= quota->maximum_sessions;
}

int pqcp_runtime_admission_init(
	struct pqcp_runtime_admission *admission,
	struct pqcp_runtime_admission_quota *quotas,
	size_t capacity)
{
	if (admission == NULL || quotas == NULL ||
	    capacity == 0U ||
	    capacity > PQCP_RUNTIME_MAX_QUOTAS) {
		return -EINVAL;
	}
	memset(admission, 0, sizeof(*admission));
	memset(quotas, 0, sizeof(*quotas) * capacity);
	admission->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	admission->quotas = quotas;
	admission->capacity = capacity;
	k_mutex_init(&admission->lock);
	return 0;
}

int pqcp_runtime_admission_configure(
	struct pqcp_runtime_admission *admission,
	const struct pqcp_runtime_admission_quota *quota)
{
	struct pqcp_runtime_admission_quota *target;
	int ret;

	if (admission == NULL || !quota_valid(quota)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&admission->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	target = find_quota(admission, quota->owner);
	if (target == NULL) {
		target = free_quota(admission);
	}
	if (target == NULL) {
		(void)k_mutex_unlock(&admission->lock);
		return -ENOSPC;
	}
	if (target->active &&
	    (target->concurrent_jobs != 0U ||
	     target->active_sessions != 0U)) {
		(void)k_mutex_unlock(&admission->lock);
		return -EBUSY;
	}
	*target = *quota;
	target->active = true;
	(void)k_mutex_unlock(&admission->lock);
	return 0;
}

static void reset_window(
	struct pqcp_runtime_admission_quota *quota,
	uint64_t now_ms)
{
	if (quota->window_started_ms == 0U ||
	    now_ms - quota->window_started_ms >=
		    quota->window_ms) {
		quota->window_started_ms = now_ms;
		quota->cycles_used = 0U;
		quota->bytes_used = 0U;
	}
}

int pqcp_runtime_admission_job_begin(
	struct pqcp_runtime_admission *admission,
	const char *owner,
	uint64_t estimated_cycles,
	uint64_t estimated_bytes,
	uint64_t now_ms)
{
	struct pqcp_runtime_admission_quota *quota;
	int ret;

	if (admission == NULL ||
	    !pqcp_runtime_internal_owner_valid(owner) ||
	    estimated_cycles == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&admission->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	quota = find_quota(admission, owner);
	if (quota == NULL) {
		(void)k_mutex_unlock(&admission->lock);
		return -ENOENT;
	}
	reset_window(quota, now_ms);
	if (quota->concurrent_jobs >=
		    quota->maximum_concurrent_jobs ||
	    estimated_cycles >
		    quota->maximum_cycles_per_window -
			    quota->cycles_used ||
	    estimated_bytes >
		    quota->maximum_bytes_per_window -
			    quota->bytes_used) {
		quota->rejected_jobs++;
		(void)k_mutex_unlock(&admission->lock);
		return -EAGAIN;
	}
	quota->concurrent_jobs++;
	(void)k_mutex_unlock(&admission->lock);
	return 0;
}

int pqcp_runtime_admission_job_finish(
	struct pqcp_runtime_admission *admission,
	const char *owner,
	uint64_t actual_cycles,
	uint64_t actual_bytes,
	uint64_t now_ms)
{
	struct pqcp_runtime_admission_quota *quota;
	int ret;

	if (admission == NULL ||
	    !pqcp_runtime_internal_owner_valid(owner) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&admission->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	quota = find_quota(admission, owner);
	if (quota == NULL || quota->concurrent_jobs == 0U) {
		(void)k_mutex_unlock(&admission->lock);
		return quota == NULL ? -ENOENT : -EALREADY;
	}
	reset_window(quota, now_ms);
	quota->concurrent_jobs--;
	if (UINT64_MAX - quota->cycles_used < actual_cycles) {
		quota->cycles_used = UINT64_MAX;
	} else {
		quota->cycles_used += actual_cycles;
	}
	if (UINT64_MAX - quota->bytes_used < actual_bytes) {
		quota->bytes_used = UINT64_MAX;
	} else {
		quota->bytes_used += actual_bytes;
	}
	(void)k_mutex_unlock(&admission->lock);
	return 0;
}

int pqcp_runtime_admission_session_open(
	struct pqcp_runtime_admission *admission,
	const char *owner,
	uint64_t now_ms)
{
	struct pqcp_runtime_admission_quota *quota;
	int ret;

	if (admission == NULL ||
	    !pqcp_runtime_internal_owner_valid(owner) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&admission->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	quota = find_quota(admission, owner);
	if (quota == NULL) {
		(void)k_mutex_unlock(&admission->lock);
		return -ENOENT;
	}
	reset_window(quota, now_ms);
	if (quota->active_sessions >=
	    quota->maximum_sessions) {
		(void)k_mutex_unlock(&admission->lock);
		return -EAGAIN;
	}
	quota->active_sessions++;
	(void)k_mutex_unlock(&admission->lock);
	return 0;
}

int pqcp_runtime_admission_session_close(
	struct pqcp_runtime_admission *admission,
	const char *owner)
{
	struct pqcp_runtime_admission_quota *quota;
	int ret;

	if (admission == NULL ||
	    !pqcp_runtime_internal_owner_valid(owner)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&admission->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	quota = find_quota(admission, owner);
	if (quota == NULL || quota->active_sessions == 0U) {
		(void)k_mutex_unlock(&admission->lock);
		return quota == NULL ? -ENOENT : -EALREADY;
	}
	quota->active_sessions--;
	(void)k_mutex_unlock(&admission->lock);
	return 0;
}

int pqcp_runtime_admission_audit(
	struct pqcp_runtime_admission *admission)
{
	if (admission == NULL ||
	    admission->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    admission->quotas == NULL ||
	    admission->capacity == 0U) {
		return -EINVAL;
	}
	if (k_mutex_lock(&admission->lock, K_FOREVER) != 0) {
		return -EIO;
	}
	for (size_t index = 0U; index < admission->capacity; ++index) {
		if (!admission->quotas[index].active) {
			continue;
		}
		if (!quota_valid(&admission->quotas[index])) {
			(void)k_mutex_unlock(&admission->lock);
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < admission->capacity; ++other) {
			if (admission->quotas[other].active &&
			    strcmp(admission->quotas[index].owner,
				   admission->quotas[other].owner) == 0) {
				(void)k_mutex_unlock(&admission->lock);
				return -EBADMSG;
			}
		}
	}
	(void)k_mutex_unlock(&admission->lock);
	return 0;
}
