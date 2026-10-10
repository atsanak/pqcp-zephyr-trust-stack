/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Multi-component firmware staging, probation, health, and rollback control.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_operations.h>

#include "runtime_internal.h"

static bool state_valid(enum pqcp_fleet_update_state state)
{
	return state >= PQCP_FLEET_UPDATE_IDLE &&
	       state <= PQCP_FLEET_UPDATE_FAILED;
}

static int component_index(
	const struct pqcp_fleet_update_manager *manager,
	const char *component_id)
{
	if (manager == NULL || component_id == NULL) {
		return -1;
	}
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		const struct pqcp_fleet_update_component *component =
			&manager->components[index];

		if (component->occupied &&
		    strcmp(component->component_id,
			   component_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int free_component_index(
	const struct pqcp_fleet_update_manager *manager)
{
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		if (!manager->components[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static bool digest_zero(
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static int component_validate(
	const struct pqcp_fleet_update_component *component)
{
	if (!component->occupied) {
		return 0;
	}
	if (component->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    !pqcp_runtime_internal_text_valid(
		    component->component_id,
		    sizeof(component->component_id)) ||
	    !state_valid(component->state) ||
	    component->current_version == 0U) {
		return -EBADMSG;
	}
	if (component->state != PQCP_FLEET_UPDATE_IDLE &&
	    component->state != PQCP_FLEET_UPDATE_COMMITTED &&
	    component->state != PQCP_FLEET_UPDATE_ROLLED_BACK &&
	    component->target_version == 0U) {
		return -EBADMSG;
	}
	if ((component->state == PQCP_FLEET_UPDATE_RECEIVING ||
	     component->state == PQCP_FLEET_UPDATE_STAGED ||
	     component->state == PQCP_FLEET_UPDATE_ACTIVATING ||
	     component->state == PQCP_FLEET_UPDATE_PROBATION) &&
	    (component->image_size == 0U ||
	     digest_zero(component->expected_digest))) {
		return -EBADMSG;
	}
	if (component->received_bytes >
	    component->image_size) {
		return -EBADMSG;
	}
	if (component->successful_health_checks >
		    component->required_health_checks &&
	    component->required_health_checks != 0U) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_fleet_update_manager_init(
	struct pqcp_fleet_update_manager *manager,
	struct pqcp_fleet_update_component *components,
	size_t capacity)
{
	if (manager == NULL || components == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(components, 0, sizeof(*components) * capacity);
	manager->schema_version =
		PQCP_FLEET_OPERATIONS_SCHEMA_VERSION;
	manager->components = components;
	manager->capacity = capacity;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_fleet_update_register_component(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	uint64_t current_version)
{
	struct pqcp_fleet_update_component *component;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    component_id == NULL || current_version == 0U ||
	    strnlen(component_id,
		    PQCP_FLEET_COMPONENT_MAX_CHARS) == 0U ||
	    strnlen(component_id,
		    PQCP_FLEET_COMPONENT_MAX_CHARS) >=
		    PQCP_FLEET_COMPONENT_MAX_CHARS) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = component_index(manager, component_id);
	if (index >= 0) {
		component = &manager->components[index];
		if (component->current_version != current_version) {
			(void)k_mutex_unlock(&manager->lock);
			return -EEXIST;
		}
		(void)k_mutex_unlock(&manager->lock);
		return 0;
	}
	index = free_component_index(manager);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	component = &manager->components[index];
	memset(component, 0, sizeof(*component));
	component->schema_version =
		PQCP_FLEET_OPERATIONS_SCHEMA_VERSION;
	ret = pqcp_runtime_internal_copy_text(
		component->component_id,
		sizeof(component->component_id), component_id);
	if (ret == 0) {
		component->state = PQCP_FLEET_UPDATE_IDLE;
		component->current_version = current_version;
		component->occupied = true;
	}
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_fleet_update_authorize(
	struct pqcp_fleet_update_manager *manager,
	const struct pqcp_fleet_update_manifest *manifest,
	uint64_t now_ms,
	uint64_t probation_ms,
	uint64_t rollback_window_ms,
	uint32_t required_health_checks)
{
	struct pqcp_fleet_update_component *component;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    manifest == NULL || now_ms == 0U ||
	    probation_ms == 0U || rollback_window_ms == 0U ||
	    required_health_checks == 0U ||
	    manifest->envelope.type !=
		    PQCP_FLEET_MESSAGE_UPDATE_MANIFEST ||
	    manifest->envelope.issued_at_ms > now_ms ||
	    manifest->envelope.expires_at_ms <= now_ms ||
	    manifest->version == 0U ||
	    manifest->image_size == 0U ||
	    digest_zero(manifest->image_digest)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = component_index(
		manager, manifest->component_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	component = &manager->components[index];
	if (component->state != PQCP_FLEET_UPDATE_IDLE &&
	    component->state != PQCP_FLEET_UPDATE_COMMITTED &&
	    component->state !=
		    PQCP_FLEET_UPDATE_ROLLED_BACK &&
	    component->state != PQCP_FLEET_UPDATE_FAILED) {
		(void)k_mutex_unlock(&manager->lock);
		return -EBUSY;
	}
	if (manifest->minimum_current_version >
		    component->current_version ||
	    manifest->version <= component->current_version) {
		(void)k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	component->state = PQCP_FLEET_UPDATE_AUTHORIZED;
	component->previous_version =
		component->current_version;
	component->target_version = manifest->version;
	component->image_size = manifest->image_size;
	component->received_bytes = 0U;
	component->activated_at_ms = 0U;
	component->probation_until_ms = probation_ms;
	component->rollback_deadline_ms =
		rollback_window_ms;
	component->flags = manifest->flags;
	component->failed_health_checks = 0U;
	component->required_health_checks =
		required_health_checks;
	component->successful_health_checks = 0U;
	memcpy(component->expected_digest,
	       manifest->image_digest,
	       sizeof(component->expected_digest));
	memset(component->received_digest, 0,
	       sizeof(component->received_digest));
	manager->authorized_count++;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

static int update_rolling_digest(
	struct pqcp_fleet_update_component *component,
	uint64_t offset,
	const uint8_t *block,
	size_t block_length)
{
	const uint8_t *parts[3];
	size_t lengths[3];
	uint8_t encoded_offset[8];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	pqcp_runtime_internal_write_u64(
		encoded_offset, offset);
	parts[0] = component->received_digest;
	lengths[0] = sizeof(component->received_digest);
	parts[1] = encoded_offset;
	lengths[1] = sizeof(encoded_offset);
	parts[2] = block;
	lengths[2] = block_length;
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, 3U, digest);
	if (ret == 0) {
		memcpy(component->received_digest, digest,
		       sizeof(component->received_digest));
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_fleet_update_record_block(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	uint64_t offset,
	const uint8_t *block,
	size_t block_length)
{
	struct pqcp_fleet_update_component *component;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    component_id == NULL || block == NULL ||
	    block_length == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = component_index(manager, component_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	component = &manager->components[index];
	if (component->state !=
		    PQCP_FLEET_UPDATE_AUTHORIZED &&
	    component->state !=
		    PQCP_FLEET_UPDATE_RECEIVING) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	if (offset != component->received_bytes ||
	    block_length >
		    component->image_size -
			    component->received_bytes) {
		(void)k_mutex_unlock(&manager->lock);
		return -ERANGE;
	}
	ret = update_rolling_digest(
		component, offset, block, block_length);
	if (ret == 0) {
		component->received_bytes += block_length;
		component->state =
			PQCP_FLEET_UPDATE_RECEIVING;
	}
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_fleet_update_finish_staging(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	struct pqcp_fleet_update_component *component;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    component_id == NULL || digest == NULL ||
	    digest_zero(digest)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = component_index(manager, component_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	component = &manager->components[index];
	if (component->state !=
		    PQCP_FLEET_UPDATE_RECEIVING ||
	    component->received_bytes != component->image_size) {
		(void)k_mutex_unlock(&manager->lock);
		return -EINPROGRESS;
	}
	if (memcmp(digest, component->expected_digest,
		   PQCP_FLEET_DIGEST_BYTES) != 0) {
		component->state = PQCP_FLEET_UPDATE_FAILED;
		manager->failed_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -EBADMSG;
	}
	memcpy(component->received_digest, digest,
	       sizeof(component->received_digest));
	component->state = PQCP_FLEET_UPDATE_STAGED;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_update_activate(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_update_component *component;
	uint64_t probation_duration;
	uint64_t rollback_duration;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    component_id == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = component_index(manager, component_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	component = &manager->components[index];
	if (component->state != PQCP_FLEET_UPDATE_STAGED) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	probation_duration = component->probation_until_ms;
	rollback_duration = component->rollback_deadline_ms;
	if (UINT64_MAX - now_ms < probation_duration ||
	    UINT64_MAX - now_ms < rollback_duration) {
		(void)k_mutex_unlock(&manager->lock);
		return -EOVERFLOW;
	}
	component->state = PQCP_FLEET_UPDATE_PROBATION;
	component->activated_at_ms = now_ms;
	component->probation_until_ms =
		now_ms + probation_duration;
	component->rollback_deadline_ms =
		now_ms + rollback_duration;
	component->current_version =
		component->target_version;
	manager->activated_count++;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_update_health(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	bool healthy,
	uint64_t now_ms)
{
	struct pqcp_fleet_update_component *component;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    component_id == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = component_index(manager, component_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	component = &manager->components[index];
	if (component->state != PQCP_FLEET_UPDATE_PROBATION) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	if (now_ms > component->rollback_deadline_ms) {
		component->state = PQCP_FLEET_UPDATE_FAILED;
		manager->failed_count++;
		(void)k_mutex_unlock(&manager->lock);
		return -ETIMEDOUT;
	}
	if (healthy) {
		if (component->successful_health_checks <
		    component->required_health_checks) {
			component->successful_health_checks++;
		}
		if (component->successful_health_checks >=
			    component->required_health_checks &&
		    now_ms >= component->probation_until_ms) {
			component->state =
				PQCP_FLEET_UPDATE_COMMITTED;
			component->previous_version = 0U;
			manager->committed_count++;
		}
	} else {
		component->failed_health_checks++;
		if (component->failed_health_checks >=
		    component->required_health_checks) {
			component->state =
				PQCP_FLEET_UPDATE_ROLLBACK_PENDING;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_update_request_rollback(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_update_component *component;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    component_id == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = component_index(manager, component_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	component = &manager->components[index];
	if (component->state != PQCP_FLEET_UPDATE_PROBATION &&
	    component->state != PQCP_FLEET_UPDATE_COMMITTED &&
	    component->state != PQCP_FLEET_UPDATE_FAILED) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	if (component->previous_version == 0U ||
	    now_ms > component->rollback_deadline_ms) {
		(void)k_mutex_unlock(&manager->lock);
		return -ETIMEDOUT;
	}
	component->state =
		PQCP_FLEET_UPDATE_ROLLBACK_PENDING;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_update_complete_rollback(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id)
{
	struct pqcp_fleet_update_component *component;
	int index;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    component_id == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = component_index(manager, component_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	component = &manager->components[index];
	if (component->state !=
	    PQCP_FLEET_UPDATE_ROLLBACK_PENDING) {
		(void)k_mutex_unlock(&manager->lock);
		return -EACCES;
	}
	component->current_version =
		component->previous_version;
	component->state = PQCP_FLEET_UPDATE_ROLLED_BACK;
	component->target_version = 0U;
	component->image_size = 0U;
	component->received_bytes = 0U;
	component->activated_at_ms = 0U;
	component->probation_until_ms = 0U;
	component->rollback_deadline_ms = 0U;
	component->flags = 0U;
	component->failed_health_checks = 0U;
	component->required_health_checks = 0U;
	component->successful_health_checks = 0U;
	memset(component->expected_digest, 0,
	       sizeof(component->expected_digest));
	memset(component->received_digest, 0,
	       sizeof(component->received_digest));
	component->previous_version = 0U;
	manager->rollback_count++;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_update_tick(
	struct pqcp_fleet_update_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;
	int ret;

	if (manager == NULL || !manager->initialized ||
	    now_ms == 0U || changed_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		struct pqcp_fleet_update_component *component =
			&manager->components[index];

		if (!component->occupied ||
		    component->state !=
			    PQCP_FLEET_UPDATE_PROBATION) {
			continue;
		}
		if (component->successful_health_checks >=
			    component->required_health_checks &&
		    now_ms >= component->probation_until_ms) {
			component->state =
				PQCP_FLEET_UPDATE_COMMITTED;
			component->previous_version = 0U;
			manager->committed_count++;
			changed++;
		} else if (now_ms >
			   component->rollback_deadline_ms) {
			component->state =
				PQCP_FLEET_UPDATE_ROLLBACK_PENDING;
			changed++;
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_fleet_update_manager_audit(
	struct pqcp_fleet_update_manager *manager)
{
	int ret;

	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    manager->components == NULL ||
	    manager->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < manager->capacity;
	     ++index) {
		const struct pqcp_fleet_update_component *component =
			&manager->components[index];

		if (component_validate(component) != 0) {
			(void)k_mutex_unlock(&manager->lock);
			return -EBADMSG;
		}
		if (!component->occupied) {
			continue;
		}
		for (size_t other = index + 1U;
		     other < manager->capacity; ++other) {
			if (manager->components[other].occupied &&
			    strcmp(
				    component->component_id,
				    manager->components[other].
					    component_id) == 0) {
				(void)k_mutex_unlock(
					&manager->lock);
				return -EEXIST;
			}
		}
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}
