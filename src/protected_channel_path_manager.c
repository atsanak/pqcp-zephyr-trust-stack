/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Validated path selection and migration for protected channels.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel_operations.h>

static int path_policy_validate(
	const struct pqcp_channel_path_policy *policy)
{
	if (policy == NULL ||
	    policy->schema_version !=
		    PQCP_CHANNEL_OPERATION_SCHEMA_VERSION ||
	    policy->validation_timeout_ms == 0U ||
	    policy->idle_timeout_ms <
		    policy->validation_timeout_ms ||
	    policy->maximum_failures == 0U ||
	    policy->migration_hysteresis_bps > 10000U) {
		return -EINVAL;
	}
	return 0;
}

static struct pqcp_channel_path *path_find(
	struct pqcp_channel_path_manager *manager,
	uint32_t path_id)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_channel_path *path =
			&manager->paths[index];

		if (path->occupied &&
		    path->path_id == path_id) {
			return path;
		}
	}
	return NULL;
}

static struct pqcp_channel_path *path_free(
	struct pqcp_channel_path_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (!manager->paths[index].occupied ||
		    manager->paths[index].state ==
			    PQCP_CHANNEL_PATH_FAILED) {
			return &manager->paths[index];
		}
	}
	return NULL;
}

static int path_allocate_id(
	struct pqcp_channel_path_manager *manager,
	uint32_t *path_id)
{
	for (size_t attempt = 0U;
	     attempt <= manager->capacity; ++attempt) {
		uint32_t candidate =
			manager->next_path_id++;

		if (candidate == 0U) {
			candidate =
				manager->next_path_id++;
		}
		if (path_find(manager, candidate) == NULL) {
			*path_id = candidate;
			return 0;
		}
	}
	return -ENOSPC;
}

static bool path_usable(
	const struct pqcp_channel_path *path)
{
	return path->occupied &&
	       (path->state ==
			PQCP_CHANNEL_PATH_VALIDATED ||
		path->state ==
			PQCP_CHANNEL_PATH_ACTIVE);
}

static uint64_t path_score(
	const struct pqcp_channel_path *path)
{
	uint64_t score =
		path->smoothed_rtt_us == 0U ?
			UINT32_MAX :
			path->smoothed_rtt_us;
	uint64_t penalty =
		(uint64_t)path->priority * 1000U;

	if (UINT64_MAX - score < penalty) {
		return UINT64_MAX;
	}
	score += penalty;
	penalty =
		(uint64_t)path->failures * 100000U;
	return UINT64_MAX - score < penalty ?
		UINT64_MAX :
		score + penalty;
}

static bool path_improves(
	const struct pqcp_channel_path *current,
	const struct pqcp_channel_path *candidate,
	uint32_t hysteresis_bps)
{
	const uint64_t current_score =
		path_score(current);
	const uint64_t candidate_score =
		path_score(candidate);
	uint64_t required;

	if (candidate_score >= current_score) {
		return false;
	}
	if (hysteresis_bps == 0U ||
	    current_score == UINT64_MAX) {
		return true;
	}
	required =
		current_score >
			UINT64_MAX / hysteresis_bps ?
			UINT64_MAX / 10000U :
			(current_score *
			 hysteresis_bps) /
				10000U;
	return current_score - candidate_score >=
	       (required == 0U ? 1U : required);
}

static void path_update_rtt(
	struct pqcp_channel_path *path,
	uint64_t rtt_us)
{
	path->smoothed_rtt_us =
		path->smoothed_rtt_us == 0U ?
			rtt_us :
			(path->smoothed_rtt_us * 7U +
			 rtt_us) /
				8U;
}

static void path_mark_failed(
	struct pqcp_channel_path_manager *manager,
	struct pqcp_channel_path *path)
{
	if (path->failures < UINT32_MAX) {
		path->failures++;
	}
	path->state = PQCP_CHANNEL_PATH_FAILED;
	if (manager->active_path_id ==
	    path->path_id) {
		manager->active_path_id = 0U;
	}
}

static int path_expire(
	struct pqcp_channel_path_manager *manager,
	uint64_t now_ms)
{
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_channel_path *path =
			&manager->paths[index];

		if (!path->occupied) {
			continue;
		}
		if (now_ms < path->created_at_ms ||
		    now_ms < path->last_activity_ms) {
			return -EBADMSG;
		}
		if (path->state ==
			    PQCP_CHANNEL_PATH_PROBING &&
		    now_ms - path->created_at_ms >=
			    manager->policy.
				    validation_timeout_ms) {
			path_mark_failed(manager, path);
			continue;
		}
		if (path_usable(path) &&
		    now_ms - path->last_activity_ms >=
			    manager->policy.idle_timeout_ms) {
			path_mark_failed(manager, path);
		}
	}
	return 0;
}

static struct pqcp_channel_path *path_best(
	struct pqcp_channel_path_manager *manager)
{
	struct pqcp_channel_path *best = NULL;

	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		struct pqcp_channel_path *candidate =
			&manager->paths[index];

		if (!path_usable(candidate) ||
		    candidate->failures >=
			    manager->policy.maximum_failures) {
			continue;
		}
		if (best == NULL ||
		    path_score(candidate) <
			    path_score(best) ||
		    (path_score(candidate) ==
			     path_score(best) &&
		     candidate->path_id < best->path_id)) {
			best = candidate;
		}
	}
	return best;
}

static int path_activate(
	struct pqcp_channel_path_manager *manager,
	struct pqcp_channel_path *candidate)
{
	struct pqcp_channel_path *current = NULL;

	if (manager->active_path_id != 0U) {
		current = path_find(
			manager,
			manager->active_path_id);
		if (current == NULL) {
			return -EBADMSG;
		}
	}
	if (current == candidate) {
		candidate->state =
			PQCP_CHANNEL_PATH_ACTIVE;
		return 0;
	}
	if (current != NULL) {
		current->state =
			PQCP_CHANNEL_PATH_VALIDATED;
		manager->migrations++;
	}
	candidate->state =
		PQCP_CHANNEL_PATH_ACTIVE;
	manager->active_path_id =
		candidate->path_id;
	return 0;
}

int pqcp_channel_path_policy_default(
	struct pqcp_channel_path_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	policy->validation_timeout_ms = 5000U;
	policy->idle_timeout_ms = 60000U;
	policy->maximum_failures = 3U;
	policy->migration_hysteresis_bps = 1000U;
	policy->allow_automatic_migration = true;
	return 0;
}

int pqcp_channel_path_manager_init(
	struct pqcp_channel_path_manager *manager,
	const struct pqcp_channel_path_policy *policy,
	struct pqcp_channel_path *paths,
	size_t capacity)
{
	if (manager == NULL ||
	    path_policy_validate(policy) != 0 ||
	    paths == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(paths, 0, capacity * sizeof(*paths));
	manager->policy = *policy;
	manager->paths = paths;
	manager->capacity = capacity;
	manager->next_path_id = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_channel_path_begin_probe(
	struct pqcp_channel_path_manager *manager,
	uint64_t challenge,
	uint32_t priority,
	uint64_t now_ms,
	struct pqcp_channel_path **path)
{
	struct pqcp_channel_path *entry;
	uint32_t path_id;
	bool replacing;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    challenge == 0U || now_ms == 0U ||
	    path == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = path_expire(manager, now_ms);
	if (ret != 0) {
		goto out;
	}
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		if (manager->paths[index].occupied &&
		    manager->paths[index].state ==
			    PQCP_CHANNEL_PATH_PROBING &&
		    manager->paths[index].challenge ==
			    challenge) {
			ret = -EALREADY;
			goto out;
		}
	}
	entry = path_free(manager);
	if (entry == NULL) {
		ret = -ENOSPC;
		goto out;
	}
	replacing = entry->occupied;
	ret = path_allocate_id(manager, &path_id);
	if (ret != 0) {
		goto out;
	}
	memset(entry, 0, sizeof(*entry));
	entry->path_id = path_id;
	entry->state =
		PQCP_CHANNEL_PATH_PROBING;
	entry->challenge = challenge;
	entry->created_at_ms = now_ms;
	entry->last_activity_ms = now_ms;
	entry->priority = priority;
	entry->occupied = true;
	if (!replacing) {
		manager->count++;
	}
	*path = entry;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_channel_path_validate(
	struct pqcp_channel_path_manager *manager,
	uint32_t path_id,
	uint64_t challenge,
	uint64_t rtt_us,
	uint64_t now_ms)
{
	struct pqcp_channel_path *path;
	struct pqcp_channel_path *active = NULL;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    path_id == 0U || challenge == 0U ||
	    rtt_us == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	path = path_find(manager, path_id);
	if (path == NULL) {
		ret = -ENOENT;
		goto out;
	}
	if (path->state !=
	    PQCP_CHANNEL_PATH_PROBING) {
		ret = -EALREADY;
		goto out;
	}
	if (path->challenge != challenge) {
		path_mark_failed(manager, path);
		ret = -EKEYREJECTED;
		goto out;
	}
	if (now_ms < path->created_at_ms ||
	    now_ms - path->created_at_ms >
		    manager->policy.
			    validation_timeout_ms) {
		path_mark_failed(manager, path);
		ret = -ETIMEDOUT;
		goto out;
	}
	path->state =
		PQCP_CHANNEL_PATH_VALIDATED;
	path->challenge = 0U;
	path->validated_at_ms = now_ms;
	path->last_activity_ms = now_ms;
	path_update_rtt(path, rtt_us);
	if (manager->active_path_id != 0U) {
		active = path_find(
			manager,
			manager->active_path_id);
		if (active == NULL ||
		    active->state !=
			    PQCP_CHANNEL_PATH_ACTIVE) {
			ret = -EBADMSG;
			goto out;
		}
	}
	if (active == NULL ||
	    (manager->policy.allow_automatic_migration &&
	     path_improves(
		     active, path,
		     manager->policy.
			     migration_hysteresis_bps))) {
		ret = path_activate(manager, path);
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_channel_path_record_io(
	struct pqcp_channel_path_manager *manager,
	uint32_t path_id,
	uint64_t now_ms,
	size_t sent_bytes,
	size_t received_bytes)
{
	struct pqcp_channel_path *path;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    path_id == 0U || now_ms == 0U ||
	    (sent_bytes == 0U &&
	     received_bytes == 0U)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	path = path_find(manager, path_id);
	if (path == NULL) {
		ret = -ENOENT;
		goto out;
	}
	if (!path_usable(path)) {
		ret = -EHOSTUNREACH;
		goto out;
	}
	if (now_ms < path->last_activity_ms ||
	    UINT64_MAX - path->bytes_sent <
		    sent_bytes ||
	    UINT64_MAX - path->bytes_received <
		    received_bytes) {
		ret = -EOVERFLOW;
		goto out;
	}
	path->bytes_sent += sent_bytes;
	path->bytes_received += received_bytes;
	path->last_activity_ms = now_ms;
	ret = 0;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_channel_path_fail(
	struct pqcp_channel_path_manager *manager,
	uint32_t path_id,
	uint64_t now_ms)
{
	struct pqcp_channel_path *path;
	struct pqcp_channel_path *candidate;
	bool was_active;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    path_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	path = path_find(manager, path_id);
	if (path == NULL) {
		ret = -ENOENT;
		goto out;
	}
	if (path->state ==
	    PQCP_CHANNEL_PATH_FAILED) {
		ret = -EALREADY;
		goto out;
	}
	was_active =
		manager->active_path_id == path_id;
	path->last_activity_ms = now_ms;
	path_mark_failed(manager, path);
	if (!was_active) {
		ret = 0;
		goto out;
	}
	candidate = path_best(manager);
	if (candidate == NULL ||
	    !manager->policy.allow_automatic_migration) {
		manager->failed_migrations++;
		ret = -EHOSTUNREACH;
		goto out;
	}
	ret = path_activate(manager, candidate);
	if (ret != 0) {
		manager->failed_migrations++;
	}
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_channel_path_select(
	struct pqcp_channel_path_manager *manager,
	uint64_t now_ms,
	uint32_t *path_id)
{
	struct pqcp_channel_path *current = NULL;
	struct pqcp_channel_path *candidate;
	struct pqcp_channel_path *selected;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || path_id == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = path_expire(manager, now_ms);
	if (ret != 0) {
		goto out;
	}
	if (manager->active_path_id != 0U) {
		current = path_find(
			manager,
			manager->active_path_id);
	}
	candidate = path_best(manager);
	if (candidate == NULL) {
		ret = -EHOSTUNREACH;
		goto out;
	}
	selected = current;
	if (current == NULL ||
	    (candidate != current &&
	     manager->policy.allow_automatic_migration &&
	     path_improves(
		     current, candidate,
		     manager->policy.
			     migration_hysteresis_bps))) {
		ret = path_activate(manager, candidate);
		if (ret != 0) {
			manager->failed_migrations++;
			goto out;
		}
		selected = candidate;
	}
	if (selected == NULL) {
		ret = -EHOSTUNREACH;
		goto out;
	}
	*path_id = selected->path_id;
	ret = 0;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_channel_path_manager_audit(
	struct pqcp_channel_path_manager *manager)
{
	size_t occupied = 0U;
	size_t active = 0U;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    path_policy_validate(&manager->policy) != 0 ||
	    manager->paths == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < manager->capacity; ++index) {
		const struct pqcp_channel_path *path =
			&manager->paths[index];

		if (!path->occupied) {
			if (path->path_id != 0U ||
			    path->state !=
				    PQCP_CHANNEL_PATH_UNUSED) {
				ret = -EBADMSG;
				goto out;
			}
			continue;
		}
		occupied++;
		if (path->path_id == 0U ||
		    path->state <=
			    PQCP_CHANNEL_PATH_UNUSED ||
		    path->state >
			    PQCP_CHANNEL_PATH_FAILED ||
		    path->created_at_ms == 0U ||
		    path->last_activity_ms <
			    path->created_at_ms ||
		    (path->state ==
			     PQCP_CHANNEL_PATH_PROBING &&
		     path->challenge == 0U) ||
		    (path->state !=
			     PQCP_CHANNEL_PATH_PROBING &&
		     path->challenge != 0U) ||
		    (path_usable(path) &&
		     (path->validated_at_ms == 0U ||
		      path->smoothed_rtt_us == 0U))) {
			ret = -EBADMSG;
			goto out;
		}
		if (path->state ==
		    PQCP_CHANNEL_PATH_ACTIVE) {
			active++;
			if (manager->active_path_id !=
			    path->path_id) {
				ret = -EBADMSG;
				goto out;
			}
		}
		for (size_t prior = 0U;
		     prior < index; ++prior) {
			if (manager->paths[prior].occupied &&
			    manager->paths[prior].path_id ==
				    path->path_id) {
				ret = -EBADMSG;
				goto out;
			}
		}
	}
	if (occupied != manager->count ||
	    active > 1U ||
	    ((manager->active_path_id == 0U) !=
	     (active == 0U))) {
		ret = -EBADMSG;
		goto out;
	}
	ret = 0;
out:
	k_mutex_unlock(&manager->lock);
	return ret;
}
