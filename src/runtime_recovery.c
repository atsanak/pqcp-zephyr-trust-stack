/*
 * SPDX-License-Identifier: MIT
 *
 * Secret-free runtime recovery and key-reference reconciliation.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_control.h>

#include "runtime_internal.h"

static int validate_handle_reference(
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_key_handle *handle)
{
	struct pqcp_runtime_key_metadata metadata;

	if (!pqcp_runtime_key_handle_is_valid(handle)) {
		return 0;
	}
	return pqcp_runtime_key_store_metadata(
		controller->key_store, handle, &metadata);
}

int pqcp_runtime_recovery_validate_key_references(
	struct pqcp_runtime_controller *controller)
{
	uint32_t missing = 0U;

	if (controller == NULL || !controller->initialized) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < controller->sessions->capacity; ++index) {
		struct pqcp_runtime_session *session =
			&controller->sessions->sessions[index];

		if (!session->active) {
			continue;
		}
		if (validate_handle_reference(
			    controller, &session->kem_key) != 0) {
			memset(&session->kem_key, 0,
			       sizeof(session->kem_key));
			session->draining = true;
			missing++;
		}
		if (validate_handle_reference(
			    controller,
			    &session->signing_key) != 0) {
			memset(&session->signing_key, 0,
			       sizeof(session->signing_key));
			session->draining = true;
			missing++;
		}
	}
	return missing == 0U ? 0 : -ENOENT;
}

int pqcp_runtime_recovery_restore(
	struct pqcp_runtime_controller *controller,
	const uint8_t *snapshot,
	size_t snapshot_length,
	struct pqcp_runtime_session *session_storage,
	size_t session_capacity,
	struct pqcp_runtime_profile_state *profile_storage,
	size_t profile_capacity,
	struct pqcp_runtime_snapshot_info *info,
	uint64_t now_ms)
{
	uint32_t active = 0U;
	int ret;

	if (controller == NULL || !controller->initialized ||
	    snapshot == NULL || snapshot_length == 0U ||
	    session_storage == NULL || profile_storage == NULL ||
	    info == NULL || now_ms == 0U ||
	    session_storage !=
		    controller->sessions->sessions ||
	    session_capacity != controller->sessions->capacity ||
	    profile_storage !=
		    controller->executor->profile_states ||
	    profile_capacity !=
		    controller->executor->profile_state_capacity) {
		return -EINVAL;
	}
	if (controller->sessions->active_count != 0U ||
	    controller->executor->queue_count != 0U) {
		return -EBUSY;
	}
	ret = pqcp_runtime_snapshot_read(
		snapshot, snapshot_length,
		session_storage, session_capacity,
		profile_storage, profile_capacity, info);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < session_capacity; ++index) {
		struct pqcp_runtime_session *session =
			&session_storage[index];

		if (!session->active) {
			continue;
		}
		if (session->expires_at_ms != 0U &&
		    session->expires_at_ms <= now_ms) {
			memset(session, 0, sizeof(*session));
			continue;
		}
		session->draining = true;
		active++;
	}
	controller->sessions->active_count = active;
	controller->accepting_sessions = false;
	ret = pqcp_runtime_recovery_validate_key_references(
		controller);
	(void)pqcp_runtime_audit_append(
		controller->audit, PQCP_RUNTIME_AUDIT_RESTORE,
		now_ms, info->bytes_written, ret,
		ret == 0 ? 0U : 1U,
		"runtime", ret == 0 ?
			"snapshot-restored" :
			"snapshot-key-missing");
	return ret;
}
