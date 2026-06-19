/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP measured runtime sessions.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_SESSION_H_
#define PQCP_ZEPHYR_RUNTIME_SESSION_H_

#include <pqcp_zephyr/runtime_executor.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pqcp_runtime_session_manager {
	uint32_t schema_version;
	struct pqcp_runtime_session *sessions;
	size_t capacity;
	size_t active_count;
	uint64_t opened_count;
	uint64_t closed_count;
	uint64_t rejected_count;
	struct pqcp_runtime_executor *executor;
	struct pqcp_adaptive_control_plane *adaptive_control;
	struct k_mutex lock;
};

struct pqcp_runtime_session_request {
	uint64_t session_id;
	const char *profile_id;
	uint64_t now_ms;
	uint64_t expires_at_ms;
	bool generate_kem_key;
	bool generate_signing_key;
	bool protected_channel;
};

int pqcp_runtime_session_manager_init(
	struct pqcp_runtime_session_manager *manager,
	struct pqcp_runtime_session *sessions,
	size_t capacity,
	struct pqcp_runtime_executor *executor,
	struct pqcp_adaptive_control_plane *adaptive_control);
int pqcp_runtime_session_open(
	struct pqcp_runtime_session_manager *manager,
	const struct pqcp_runtime_session_request *request,
	struct pqcp_runtime_session **session);
int pqcp_runtime_session_submit(
	struct pqcp_runtime_session_manager *manager,
	uint64_t session_id,
	struct pqcp_runtime_job *job);
int pqcp_runtime_session_mark_draining(
	struct pqcp_runtime_session_manager *manager,
	const char *profile_id);
int pqcp_runtime_session_close(
	struct pqcp_runtime_session_manager *manager,
	uint64_t session_id);
int pqcp_runtime_session_expire(
	struct pqcp_runtime_session_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
struct pqcp_runtime_session *pqcp_runtime_session_find(
	struct pqcp_runtime_session_manager *manager,
	uint64_t session_id);
int pqcp_runtime_session_manager_audit(
	struct pqcp_runtime_session_manager *manager);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_SESSION_H_ */
