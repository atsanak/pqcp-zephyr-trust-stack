/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Session pinning and key lifecycle for the executable runtime.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_session.h>

#include "runtime_internal.h"

static struct pqcp_runtime_session *find_unlocked(
	struct pqcp_runtime_session_manager *manager,
	uint64_t session_id)
{
	for (size_t index = 0U; index < manager->capacity; ++index) {
		if (manager->sessions[index].active &&
		    manager->sessions[index].session_id ==
			    session_id) {
			return &manager->sessions[index];
		}
	}
	return NULL;
}

static struct pqcp_runtime_session *free_unlocked(
	struct pqcp_runtime_session_manager *manager)
{
	for (size_t index = 0U; index < manager->capacity; ++index) {
		if (!manager->sessions[index].active) {
			return &manager->sessions[index];
		}
	}
	return NULL;
}

static const struct pqcp_adaptive_profile *resolve_profile(
	const struct pqcp_runtime_session_manager *manager,
	const char *profile_id)
{
	if (manager->adaptive_control == NULL) {
		return NULL;
	}
	return pqcp_adaptive_profile_registry_find(
		&manager->adaptive_control->registry,
		profile_id);
}

static bool request_valid(
	const struct pqcp_runtime_session_request *request)
{
	return request != NULL &&
	       request->session_id != 0U &&
	       pqcp_runtime_internal_text_valid(
		       request->profile_id,
		       PQCP_RUNTIME_PROFILE_MAX_CHARS) &&
	       request->now_ms != 0U &&
	       (request->expires_at_ms == 0U ||
		request->expires_at_ms > request->now_ms);
}

static int generate_key(
	struct pqcp_runtime_session_manager *manager,
	struct pqcp_runtime_session *session,
	enum pqcp_runtime_job_type type,
	uint32_t level,
	const char *label,
	struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_job job;

	memset(&job, 0, sizeof(job));
	job.schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	job.job_id =
		(session->session_id << 8U) |
		(type & UINT64_C(0xff));
	if (job.job_id == 0U) {
		job.job_id = type;
	}
	job.session_id = session->session_id;
	job.type = type;
	job.priority = PQCP_RUNTIME_PRIORITY_CRITICAL;
	job.status = PQCP_RUNTIME_STATUS_IDLE;
	job.flags =
		PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS |
		PQCP_RUNTIME_JOB_FLAG_ZERO_OUTPUT_ON_FAILURE |
		PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION;
	job.level = level;
	job.key_request.level = level;
	job.key_request.now_ms =
		pqcp_runtime_internal_now_ms();
	job.key_request.expires_at_ms =
		session->expires_at_ms;
	job.key_request.owner = "session";
	job.key_request.label = label;
	job.key_request.exportable_public = true;
	if (type == PQCP_RUNTIME_JOB_MLKEM_KEYGEN) {
		job.key_request.family =
			PQCP_RUNTIME_KEY_MLKEM_KEYPAIR;
		job.key_request.usage =
			PQCP_RUNTIME_USAGE_ENCAPSULATE |
			PQCP_RUNTIME_USAGE_DECAPSULATE |
			PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
			PQCP_RUNTIME_USAGE_DESTROY;
	} else {
		job.key_request.family =
			PQCP_RUNTIME_KEY_MLDSA_KEYPAIR;
		job.key_request.usage =
			PQCP_RUNTIME_USAGE_SIGN |
			PQCP_RUNTIME_USAGE_VERIFY |
			PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
			PQCP_RUNTIME_USAGE_DESTROY;
	}
	(void)pqcp_runtime_internal_copy_text(
		job.profile_id, sizeof(job.profile_id),
		session->profile_id);
	int ret = pqcp_runtime_executor_submit(
		manager->executor, &job);

	if (ret != 0) {
		return ret;
	}
	*handle = job.primary_key;
	return pqcp_runtime_key_handle_is_valid(handle) ?
		0 : -EBADMSG;
}

int pqcp_runtime_session_manager_init(
	struct pqcp_runtime_session_manager *manager,
	struct pqcp_runtime_session *sessions,
	size_t capacity,
	struct pqcp_runtime_executor *executor,
	struct pqcp_adaptive_control_plane *adaptive_control)
{
	if (manager == NULL || sessions == NULL ||
	    capacity == 0U || executor == NULL) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(sessions, 0, sizeof(*sessions) * capacity);
	manager->schema_version =
		PQCP_RUNTIME_SCHEMA_VERSION;
	manager->sessions = sessions;
	manager->capacity = capacity;
	manager->executor = executor;
	manager->adaptive_control = adaptive_control;
	k_mutex_init(&manager->lock);
	return 0;
}

int pqcp_runtime_session_open(
	struct pqcp_runtime_session_manager *manager,
	const struct pqcp_runtime_session_request *request,
	struct pqcp_runtime_session **session)
{
	const struct pqcp_adaptive_profile *profile;
	struct pqcp_runtime_session *entry;
	int ret;

	if (manager == NULL || !request_valid(request) ||
	    session == NULL ||
	    manager->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (find_unlocked(manager, request->session_id) != NULL) {
		manager->rejected_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -EEXIST;
	}
	entry = free_unlocked(manager);
	if (entry == NULL) {
		manager->rejected_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	profile = resolve_profile(manager, request->profile_id);
	if (manager->adaptive_control != NULL &&
	    (profile == NULL || !profile->enabled)) {
		manager->rejected_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	memset(entry, 0, sizeof(*entry));
	entry->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	entry->session_id = request->session_id;
	entry->opened_at_ms = request->now_ms;
	entry->expires_at_ms = request->expires_at_ms;
	entry->protected_channel = request->protected_channel;
	entry->active = true;
	if (pqcp_runtime_internal_copy_text(
		    entry->profile_id, sizeof(entry->profile_id),
		    request->profile_id) != 0) {
		memset(entry, 0, sizeof(*entry));
		manager->rejected_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -EINVAL;
	}
	if (profile != NULL) {
		entry->mlkem_level = profile->mlkem_level;
		entry->mldsa_level = profile->mldsa_level;
	}
	manager->active_count++;
	manager->opened_count++;
	(void)k_mutex_unlock(&manager->lock);

	if (request->generate_kem_key) {
		if (entry->mlkem_level == 0U) {
			ret = -ENOTSUP;
			goto fail;
		}
		ret = generate_key(
			manager, entry,
			PQCP_RUNTIME_JOB_MLKEM_KEYGEN,
			entry->mlkem_level,
			"session-kem", &entry->kem_key);
		if (ret != 0) {
			goto fail;
		}
	}
	if (request->generate_signing_key) {
		if (entry->mldsa_level == 0U) {
			ret = -ENOTSUP;
			goto fail;
		}
		ret = generate_key(
			manager, entry,
			PQCP_RUNTIME_JOB_MLDSA_KEYGEN,
			entry->mldsa_level,
			"session-signing",
			&entry->signing_key);
		if (ret != 0) {
			goto fail;
		}
	}
	*session = entry;
	return 0;

fail:
	(void)pqcp_runtime_session_close(
		manager, request->session_id);
	return ret;
}

int pqcp_runtime_session_submit(
	struct pqcp_runtime_session_manager *manager,
	uint64_t session_id,
	struct pqcp_runtime_job *job)
{
	struct pqcp_runtime_session *session;
	int ret;

	if (manager == NULL || session_id == 0U ||
	    job == NULL || job->session_id != session_id) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	session = find_unlocked(manager, session_id);
	if (session == NULL || session->draining) {
		manager->rejected_count++;
		(void)k_mutex_unlock(&manager->lock);
		return session == NULL ? -ENOENT : -ESHUTDOWN;
	}
	if (session->expires_at_ms != 0U &&
	    session->expires_at_ms <=
		    pqcp_runtime_internal_now_ms()) {
		manager->rejected_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -EKEYEXPIRED;
	}
	job->session_id = session_id;
	(void)pqcp_runtime_internal_copy_text(
		job->profile_id, sizeof(job->profile_id),
		session->profile_id);
	session->jobs_submitted++;
	(void)k_mutex_unlock(&manager->lock);
	ret = pqcp_runtime_executor_submit(
		manager->executor, job);
	(void)k_mutex_lock(&manager->lock, K_FOREVER);
	session = find_unlocked(manager, session_id);
	if (session != NULL) {
		if (ret == 0 &&
		    (job->flags &
		     PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS) != 0U) {
			session->jobs_completed++;
			if (job->result != 0) {
				session->failures++;
			}
		} else if (ret != 0) {
			session->failures++;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_runtime_session_mark_draining(
	struct pqcp_runtime_session_manager *manager,
	const char *profile_id)
{
	uint32_t changed = 0U;
	int ret;

	if (manager == NULL ||
	    !pqcp_runtime_internal_text_valid(
		    profile_id, PQCP_RUNTIME_PROFILE_MAX_CHARS)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity; ++index) {
		struct pqcp_runtime_session *session =
			&manager->sessions[index];

		if (session->active &&
		    strcmp(session->profile_id, profile_id) == 0 &&
		    !session->draining) {
			session->draining = true;
			changed++;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return changed == 0U ? -ENOENT : (int)changed;
}

static void destroy_session_keys(
	struct pqcp_runtime_session_manager *manager,
	struct pqcp_runtime_session *session)
{
	if (pqcp_runtime_key_handle_is_valid(
		    &session->kem_key)) {
		(void)pqcp_runtime_key_store_destroy(
			manager->executor->key_store,
			&session->kem_key);
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &session->signing_key)) {
		(void)pqcp_runtime_key_store_destroy(
			manager->executor->key_store,
			&session->signing_key);
	}
}

int pqcp_runtime_session_close(
	struct pqcp_runtime_session_manager *manager,
	uint64_t session_id)
{
	struct pqcp_runtime_session copy;
	struct pqcp_runtime_session *session;
	int ret;

	if (manager == NULL || session_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	session = find_unlocked(manager, session_id);
	if (session == NULL) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	copy = *session;
	memset(session, 0, sizeof(*session));
	if (manager->active_count != 0U) {
		manager->active_count--;
	}
	manager->closed_count++;
	(void)k_mutex_unlock(&manager->lock);
	destroy_session_keys(manager, &copy);
	pqcp_runtime_secure_zero(&copy, sizeof(copy));
	return 0;
}

int pqcp_runtime_session_expire(
	struct pqcp_runtime_session_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint64_t ids[CONFIG_PQCP_RUNTIME_MAX_SESSIONS];
	uint32_t count = 0U;
	int ret;

	if (manager == NULL || now_ms == 0U ||
	    expired_count == NULL ||
	    manager->capacity >
		    CONFIG_PQCP_RUNTIME_MAX_SESSIONS) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity; ++index) {
		const struct pqcp_runtime_session *session =
			&manager->sessions[index];

		if (session->active &&
		    session->expires_at_ms != 0U &&
		    session->expires_at_ms <= now_ms) {
			ids[count++] = session->session_id;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	for (uint32_t index = 0U; index < count; ++index) {
		(void)pqcp_runtime_session_close(
			manager, ids[index]);
	}
	*expired_count = count;
	return 0;
}

struct pqcp_runtime_session *pqcp_runtime_session_find(
	struct pqcp_runtime_session_manager *manager,
	uint64_t session_id)
{
	struct pqcp_runtime_session *session;

	if (manager == NULL || session_id == 0U) {
		return NULL;
	}
	if (k_mutex_lock(&manager->lock, K_FOREVER) != 0) {
		return NULL;
	}
	session = find_unlocked(manager, session_id);
	(void)k_mutex_unlock(&manager->lock);
	return session;
}

static bool session_valid(
	const struct pqcp_runtime_session *session)
{
	if (!session->active) {
		return session->schema_version == 0U &&
		       session->session_id == 0U;
	}
	return session->schema_version ==
		       PQCP_RUNTIME_SCHEMA_VERSION &&
	       session->session_id != 0U &&
	       pqcp_runtime_internal_text_valid(
		       session->profile_id,
		       sizeof(session->profile_id)) &&
	       session->opened_at_ms != 0U &&
	       (session->expires_at_ms == 0U ||
		session->expires_at_ms >
			session->opened_at_ms) &&
	       session->jobs_completed <=
		       session->jobs_submitted &&
	       session->failures <= session->jobs_completed;
}

int pqcp_runtime_session_manager_audit(
	struct pqcp_runtime_session_manager *manager)
{
	uint32_t active = 0U;
	int ret;

	if (manager == NULL ||
	    manager->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    manager->sessions == NULL ||
	    manager->capacity == 0U ||
	    manager->executor == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity; ++index) {
		if (!session_valid(&manager->sessions[index])) {
			(void)k_mutex_unlock(&manager->lock);
			return -EBADMSG;
		}
		if (manager->sessions[index].active) {
			active++;
			for (size_t other = index + 1U;
			     other < manager->capacity; ++other) {
				if (manager->sessions[other].active &&
				    manager->sessions[other].session_id ==
					    manager->sessions[index]
						    .session_id) {
					(void)k_mutex_unlock(
						&manager->lock);
					return -EBADMSG;
				}
			}
		}
	}
	ret = active == manager->active_count &&
	      manager->closed_count <= manager->opened_count ?
		0 : -EBADMSG;
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}
