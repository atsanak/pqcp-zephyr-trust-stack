/*
 * SPDX-License-Identifier: MIT
 *
 * Runtime admission, rotation, circuit-breaking, and evidence summaries.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_GOVERNANCE_H_
#define PQCP_ZEPHYR_RUNTIME_GOVERNANCE_H_

#include <pqcp_zephyr/runtime_campaign.h>
#include <pqcp_zephyr/runtime_identity.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_MAX_QUOTAS 16U

struct pqcp_runtime_admission_quota {
	uint32_t schema_version;
	char owner[PQCP_RUNTIME_OWNER_MAX_CHARS];
	uint32_t maximum_concurrent_jobs;
	uint32_t maximum_sessions;
	uint64_t maximum_cycles_per_window;
	uint64_t maximum_bytes_per_window;
	uint64_t window_ms;
	uint64_t window_started_ms;
	uint64_t cycles_used;
	uint64_t bytes_used;
	uint32_t concurrent_jobs;
	uint32_t active_sessions;
	uint32_t rejected_jobs;
	bool active;
};

struct pqcp_runtime_admission {
	uint32_t schema_version;
	struct pqcp_runtime_admission_quota *quotas;
	size_t capacity;
	struct k_mutex lock;
};

struct pqcp_runtime_rotation_policy {
	uint32_t schema_version;
	uint64_t identity_rotation_ms;
	uint64_t session_key_rotation_ms;
	uint32_t maximum_key_uses;
	uint32_t maximum_rotations_per_tick;
	bool rotate_on_failure;
	bool drain_sessions_before_rotation;
};

struct pqcp_runtime_rotation_report {
	uint32_t schema_version;
	uint32_t identities_checked;
	uint32_t identities_rotated;
	uint32_t sessions_checked;
	uint32_t sessions_draining;
	uint32_t failures;
	uint64_t timestamp_ms;
};

struct pqcp_runtime_circuit {
	uint32_t schema_version;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	uint32_t failure_threshold;
	uint32_t recovery_success_threshold;
	uint64_t open_duration_ms;
	uint64_t opened_at_ms;
	uint32_t consecutive_failures;
	uint32_t consecutive_successes;
	uint64_t total_failures;
	uint64_t total_successes;
	bool open;
	bool half_open;
};

struct pqcp_runtime_evidence_summary {
	uint32_t schema_version;
	struct pqcp_runtime_capability capability;
	struct pqcp_runtime_health_report health;
	uint32_t active_sessions;
	uint32_t active_keys;
	uint32_t active_identities;
	uint64_t jobs_submitted;
	uint64_t jobs_completed;
	uint64_t jobs_failed;
	uint64_t audit_sequence;
	uint8_t audit_root[PQCP_RUNTIME_AUDIT_DIGEST_BYTES];
	uint8_t summary_digest[PQCP_RUNTIME_DIGEST_BYTES];
};

int pqcp_runtime_admission_init(
	struct pqcp_runtime_admission *admission,
	struct pqcp_runtime_admission_quota *quotas,
	size_t capacity);
int pqcp_runtime_admission_configure(
	struct pqcp_runtime_admission *admission,
	const struct pqcp_runtime_admission_quota *quota);
int pqcp_runtime_admission_job_begin(
	struct pqcp_runtime_admission *admission,
	const char *owner,
	uint64_t estimated_cycles,
	uint64_t estimated_bytes,
	uint64_t now_ms);
int pqcp_runtime_admission_job_finish(
	struct pqcp_runtime_admission *admission,
	const char *owner,
	uint64_t actual_cycles,
	uint64_t actual_bytes,
	uint64_t now_ms);
int pqcp_runtime_admission_session_open(
	struct pqcp_runtime_admission *admission,
	const char *owner,
	uint64_t now_ms);
int pqcp_runtime_admission_session_close(
	struct pqcp_runtime_admission *admission,
	const char *owner);
int pqcp_runtime_admission_audit(
	struct pqcp_runtime_admission *admission);

int pqcp_runtime_rotation_policy_default(
	struct pqcp_runtime_rotation_policy *policy);
int pqcp_runtime_rotation_tick(
	const struct pqcp_runtime_rotation_policy *policy,
	struct pqcp_runtime_identity_store *identities,
	struct pqcp_runtime_session_manager *sessions,
	uint64_t now_ms,
	struct pqcp_runtime_rotation_report *report);

int pqcp_runtime_circuit_init(
	struct pqcp_runtime_circuit *circuit,
	const char *profile_id,
	uint32_t failure_threshold,
	uint32_t recovery_success_threshold,
	uint64_t open_duration_ms);
int pqcp_runtime_circuit_record(
	struct pqcp_runtime_circuit *circuit,
	bool success,
	uint64_t now_ms);
bool pqcp_runtime_circuit_allow(
	struct pqcp_runtime_circuit *circuit,
	uint64_t now_ms);
int pqcp_runtime_circuit_apply_profile(
	const struct pqcp_runtime_circuit *circuit,
	struct pqcp_adaptive_profile_registry *registry);

int pqcp_runtime_evidence_summary_build(
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_identity_store *identities,
	struct pqcp_runtime_evidence_summary *summary);
int pqcp_runtime_evidence_summary_verify(
	const struct pqcp_runtime_evidence_summary *summary);
int pqcp_runtime_evidence_summary_emit(
	const struct pqcp_runtime_evidence_summary *summary);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_GOVERNANCE_H_ */
