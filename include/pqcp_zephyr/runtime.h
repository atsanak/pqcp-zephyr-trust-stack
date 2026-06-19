/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP executable runtime.
 *
 * Stability: experimental. The stable ML-KEM and ML-DSA APIs remain the
 * primitive boundary; this API adds allocation-free scheduling, key handles,
 * measurements, and session orchestration around those primitives.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_H_
#define PQCP_ZEPHYR_RUNTIME_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/adaptive_control.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/mlkem.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_SCHEMA_VERSION 1U
#define PQCP_RUNTIME_DIGEST_BYTES 32U
#define PQCP_RUNTIME_DIGEST_HEX_CHARS 64U
#define PQCP_RUNTIME_OWNER_MAX_CHARS 32U
#define PQCP_RUNTIME_LABEL_MAX_CHARS 32U
#define PQCP_RUNTIME_PROFILE_MAX_CHARS PQCP_ADAPTIVE_ID_MAX_CHARS
#define PQCP_RUNTIME_MAX_KEY_BYTES \
	(PQCP_MLDSA_PK_SIZE_MAX + PQCP_MLDSA_SK_SIZE_MAX)
#define PQCP_RUNTIME_MAX_PUBLIC_KEY_BYTES PQCP_MLDSA_PK_SIZE_MAX
#define PQCP_RUNTIME_MAX_INPUT_BYTES 8192U
#define PQCP_RUNTIME_MAX_OUTPUT_BYTES 8192U
#define PQCP_RUNTIME_MAX_CONTEXT_BYTES 255U
#define PQCP_RUNTIME_AEAD_KEY_BYTES 32U

enum pqcp_runtime_status {
	PQCP_RUNTIME_STATUS_IDLE = 0,
	PQCP_RUNTIME_STATUS_QUEUED,
	PQCP_RUNTIME_STATUS_RUNNING,
	PQCP_RUNTIME_STATUS_COMPLETED,
	PQCP_RUNTIME_STATUS_CANCELLED,
	PQCP_RUNTIME_STATUS_EXPIRED,
	PQCP_RUNTIME_STATUS_FAILED,
};

enum pqcp_runtime_metric_source {
	PQCP_RUNTIME_METRIC_UNKNOWN = 0,
	PQCP_RUNTIME_METRIC_BOOTSTRAP_PRIOR,
	PQCP_RUNTIME_METRIC_MEASURED,
	PQCP_RUNTIME_METRIC_CALIBRATED,
};

enum pqcp_runtime_key_family {
	PQCP_RUNTIME_KEY_NONE = 0,
	PQCP_RUNTIME_KEY_MLKEM_PUBLIC,
	PQCP_RUNTIME_KEY_MLKEM_KEYPAIR,
	PQCP_RUNTIME_KEY_MLDSA_PUBLIC,
	PQCP_RUNTIME_KEY_MLDSA_KEYPAIR,
	PQCP_RUNTIME_KEY_SHARED_SECRET,
	PQCP_RUNTIME_KEY_AEAD,
};

enum pqcp_runtime_key_backend {
	PQCP_RUNTIME_KEY_BACKEND_NONE = 0,
	PQCP_RUNTIME_KEY_BACKEND_VOLATILE,
	PQCP_RUNTIME_KEY_BACKEND_PSA_PERSISTENT,
};

enum pqcp_runtime_job_type {
	PQCP_RUNTIME_JOB_NONE = 0,
	PQCP_RUNTIME_JOB_MLKEM_KEYGEN,
	PQCP_RUNTIME_JOB_MLKEM_ENCAPSULATE,
	PQCP_RUNTIME_JOB_MLKEM_DECAPSULATE,
	PQCP_RUNTIME_JOB_MLDSA_KEYGEN,
	PQCP_RUNTIME_JOB_MLDSA_SIGN,
	PQCP_RUNTIME_JOB_MLDSA_VERIFY,
};

enum pqcp_runtime_job_priority {
	PQCP_RUNTIME_PRIORITY_BACKGROUND = 0,
	PQCP_RUNTIME_PRIORITY_NORMAL,
	PQCP_RUNTIME_PRIORITY_INTERACTIVE,
	PQCP_RUNTIME_PRIORITY_CRITICAL,
};

enum pqcp_runtime_key_usage {
	PQCP_RUNTIME_USAGE_NONE = 0U,
	PQCP_RUNTIME_USAGE_ENCAPSULATE = (1U << 0),
	PQCP_RUNTIME_USAGE_DECAPSULATE = (1U << 1),
	PQCP_RUNTIME_USAGE_SIGN = (1U << 2),
	PQCP_RUNTIME_USAGE_VERIFY = (1U << 3),
	PQCP_RUNTIME_USAGE_DERIVE = (1U << 4),
	PQCP_RUNTIME_USAGE_EXPORT_PUBLIC = (1U << 5),
	PQCP_RUNTIME_USAGE_DESTROY = (1U << 6),
};

struct pqcp_runtime_key_handle {
	uint32_t slot;
	uint32_t generation;
	enum pqcp_runtime_key_backend backend;
	enum pqcp_runtime_key_family family;
	uint32_t level;
};

struct pqcp_runtime_key_metadata {
	uint32_t schema_version;
	struct pqcp_runtime_key_handle handle;
	uint32_t usage;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint64_t last_used_at_ms;
	uint32_t use_count;
	uint32_t public_bytes;
	uint32_t secret_bytes;
	char owner[PQCP_RUNTIME_OWNER_MAX_CHARS];
	char label[PQCP_RUNTIME_LABEL_MAX_CHARS];
	bool active;
	bool persistent;
	bool exportable_public;
};

struct pqcp_runtime_key_request {
	enum pqcp_runtime_key_family family;
	uint32_t level;
	uint32_t usage;
	uint64_t now_ms;
	uint64_t expires_at_ms;
	const char *owner;
	const char *label;
	bool persistent;
	bool exportable_public;
};

struct pqcp_runtime_measurement {
	uint32_t schema_version;
	enum pqcp_runtime_job_type operation;
	uint64_t submitted_at_ms;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	uint64_t queue_delay_us;
	uint64_t latency_us;
	uint64_t cycles;
	uint64_t stack_used_bytes;
	uint64_t workspace_bytes;
	uint32_t input_bytes;
	uint32_t output_bytes;
	int result;
	bool success;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
};

struct pqcp_runtime_job {
	uint32_t schema_version;
	uint64_t job_id;
	uint64_t session_id;
	enum pqcp_runtime_job_type type;
	enum pqcp_runtime_job_priority priority;
	enum pqcp_runtime_status status;
	uint64_t submitted_at_ms;
	uint64_t deadline_ms;
	uint32_t flags;
	uint32_t level;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	struct pqcp_runtime_key_request key_request;
	struct pqcp_runtime_key_handle primary_key;
	struct pqcp_runtime_key_handle secondary_key;
	const uint8_t *input;
	size_t input_length;
	const uint8_t *aux_input;
	size_t aux_input_length;
	const uint8_t *context;
	size_t context_length;
	uint8_t *output;
	size_t output_capacity;
	size_t output_length;
	uint8_t *aux_output;
	size_t aux_output_capacity;
	size_t aux_output_length;
	int result;
	struct pqcp_runtime_measurement measurement;
	void (*completion)(struct pqcp_runtime_job *job, void *user);
	void *completion_user;
};

struct pqcp_runtime_capability {
	uint32_t schema_version;
	uint32_t mlkem_level_mask;
	uint32_t mldsa_level_mask;
	uint32_t operation_mask;
	uint32_t key_backend_mask;
	uint32_t max_jobs;
	uint32_t max_keys;
	uint32_t workspace_bytes;
	bool executable_runtime;
	bool adaptive_integration;
	bool protected_channel;
	bool mutual_authentication;
	bool psa_persistence_requested;
	bool psa_persistence_available;
};

struct pqcp_runtime_profile_state {
	uint32_t schema_version;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	enum pqcp_runtime_metric_source latency_source;
	enum pqcp_runtime_metric_source cycles_source;
	enum pqcp_runtime_metric_source memory_source;
	enum pqcp_runtime_metric_source energy_source;
	uint32_t observation_count;
	uint32_t successful_observations;
	uint32_t failed_observations;
	uint64_t latency_ewma_us;
	uint64_t cycles_ewma;
	uint64_t stack_high_watermark;
	uint64_t workspace_high_watermark;
	uint64_t last_observed_at_ms;
};

struct pqcp_runtime_session {
	uint32_t schema_version;
	uint64_t session_id;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	uint32_t mlkem_level;
	uint32_t mldsa_level;
	uint64_t opened_at_ms;
	uint64_t expires_at_ms;
	uint64_t jobs_submitted;
	uint64_t jobs_completed;
	uint64_t failures;
	struct pqcp_runtime_key_handle kem_key;
	struct pqcp_runtime_key_handle signing_key;
	bool active;
	bool draining;
	bool protected_channel;
};

struct pqcp_runtime_snapshot_info {
	uint32_t schema_version;
	uint32_t bytes_written;
	uint32_t session_count;
	uint32_t profile_count;
	uint32_t key_reference_count;
	char digest_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];
};

const char *pqcp_runtime_status_str(enum pqcp_runtime_status status);
const char *pqcp_runtime_metric_source_str(
	enum pqcp_runtime_metric_source source);
const char *pqcp_runtime_job_type_str(enum pqcp_runtime_job_type type);

int pqcp_runtime_capability_current(
	struct pqcp_runtime_capability *capability);
int pqcp_runtime_capability_validate(
	const struct pqcp_runtime_capability *capability);
int pqcp_runtime_capability_emit(
	const struct pqcp_runtime_capability *capability);

int pqcp_runtime_profile_registry_build(
	struct pqcp_adaptive_profile_registry *registry);
int pqcp_runtime_profile_state_init(
	struct pqcp_runtime_profile_state *state,
	const char *profile_id);
int pqcp_runtime_profile_state_observe(
	struct pqcp_runtime_profile_state *state,
	const struct pqcp_runtime_measurement *measurement);

int pqcp_runtime_snapshot_write(
	const struct pqcp_runtime_session *sessions,
	size_t session_capacity,
	const struct pqcp_runtime_profile_state *profiles,
	size_t profile_capacity,
	uint8_t *output,
	size_t output_capacity,
	struct pqcp_runtime_snapshot_info *info);
int pqcp_runtime_snapshot_read(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_runtime_session *sessions,
	size_t session_capacity,
	struct pqcp_runtime_profile_state *profiles,
	size_t profile_capacity,
	struct pqcp_runtime_snapshot_info *info);

void pqcp_runtime_secure_zero(void *buffer, size_t length);
bool pqcp_runtime_key_handle_is_valid(
	const struct pqcp_runtime_key_handle *handle);
bool pqcp_runtime_key_handle_equal(
	const struct pqcp_runtime_key_handle *left,
	const struct pqcp_runtime_key_handle *right);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_H_ */
