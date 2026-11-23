/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free fleet device operations plane.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_OPERATIONS_H_
#define PQCP_ZEPHYR_FLEET_OPERATIONS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_enrollment.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_OPERATIONS_SCHEMA_VERSION 1U
#define PQCP_FLEET_POLICY_REASON_MAX_CHARS 64U
#define PQCP_FLEET_COMPONENT_MAX_CHARS 32U
#define PQCP_FLEET_ACTOR_MAX_CHARS 32U
#define PQCP_FLEET_AUDIT_PAYLOAD_MAX_BYTES 96U
#define PQCP_FLEET_ATTESTATION_MAX_BYTES 4096U
#define PQCP_FLEET_UPDATE_BLOCK_BYTES 32U

enum pqcp_fleet_operation_type {
	PQCP_FLEET_OPERATION_NONE = 0,
	PQCP_FLEET_OPERATION_APPLY_POLICY,
	PQCP_FLEET_OPERATION_APPLY_REVOCATION,
	PQCP_FLEET_OPERATION_ROTATE_KEY,
	PQCP_FLEET_OPERATION_STAGE_UPDATE,
	PQCP_FLEET_OPERATION_ACTIVATE_UPDATE,
	PQCP_FLEET_OPERATION_ROLLBACK_UPDATE,
	PQCP_FLEET_OPERATION_COLLECT_ATTESTATION,
	PQCP_FLEET_OPERATION_ENTER_RECOVERY,
	PQCP_FLEET_OPERATION_EXIT_RECOVERY,
	PQCP_FLEET_OPERATION_DECOMMISSION,
	PQCP_FLEET_OPERATION_CUSTOM,
	PQCP_FLEET_OPERATION_COUNT,
};

#define PQCP_FLEET_OPERATION_BIT(operation) \
	(1U << (uint32_t)(operation))

enum pqcp_fleet_policy_effect {
	PQCP_FLEET_POLICY_EFFECT_NONE = 0,
	PQCP_FLEET_POLICY_EFFECT_ALLOW,
	PQCP_FLEET_POLICY_EFFECT_DENY,
	PQCP_FLEET_POLICY_EFFECT_REQUIRE_RECOVERY,
	PQCP_FLEET_POLICY_EFFECT_QUARANTINE,
};

enum pqcp_fleet_policy_reason {
	PQCP_FLEET_POLICY_REASON_NONE = 0,
	PQCP_FLEET_POLICY_REASON_RULE_MATCH,
	PQCP_FLEET_POLICY_REASON_DEFAULT,
	PQCP_FLEET_POLICY_REASON_REVOKED,
	PQCP_FLEET_POLICY_REASON_CREDENTIAL_EXPIRED,
	PQCP_FLEET_POLICY_REASON_CAPABILITY,
	PQCP_FLEET_POLICY_REASON_SECURITY_LEVEL,
	PQCP_FLEET_POLICY_REASON_CHANNEL_IDENTITY,
	PQCP_FLEET_POLICY_REASON_EPOCH,
	PQCP_FLEET_POLICY_REASON_RISK,
	PQCP_FLEET_POLICY_REASON_TIME_WINDOW,
	PQCP_FLEET_POLICY_REASON_DEVICE_STATE,
};

enum pqcp_fleet_command_state {
	PQCP_FLEET_COMMAND_STATE_EMPTY = 0,
	PQCP_FLEET_COMMAND_STATE_QUEUED,
	PQCP_FLEET_COMMAND_STATE_RUNNING,
	PQCP_FLEET_COMMAND_STATE_RETRY_WAIT,
	PQCP_FLEET_COMMAND_STATE_COMPLETED,
	PQCP_FLEET_COMMAND_STATE_REJECTED,
	PQCP_FLEET_COMMAND_STATE_CANCELLED,
	PQCP_FLEET_COMMAND_STATE_EXPIRED,
};

enum pqcp_fleet_command_flag {
	PQCP_FLEET_COMMAND_HIGH_PRIORITY = (1U << 0),
	PQCP_FLEET_COMMAND_IDEMPOTENT = (1U << 1),
	PQCP_FLEET_COMMAND_REQUIRE_ONLINE = (1U << 2),
	PQCP_FLEET_COMMAND_REQUIRE_CHANNEL_IDENTITY = (1U << 3),
	PQCP_FLEET_COMMAND_ALLOW_RECOVERY = (1U << 4),
};

enum pqcp_fleet_update_state {
	PQCP_FLEET_UPDATE_IDLE = 0,
	PQCP_FLEET_UPDATE_AUTHORIZED,
	PQCP_FLEET_UPDATE_RECEIVING,
	PQCP_FLEET_UPDATE_STAGED,
	PQCP_FLEET_UPDATE_ACTIVATING,
	PQCP_FLEET_UPDATE_PROBATION,
	PQCP_FLEET_UPDATE_COMMITTED,
	PQCP_FLEET_UPDATE_ROLLBACK_PENDING,
	PQCP_FLEET_UPDATE_ROLLED_BACK,
	PQCP_FLEET_UPDATE_FAILED,
};

enum pqcp_fleet_audit_event {
	PQCP_FLEET_AUDIT_NONE = 0,
	PQCP_FLEET_AUDIT_POLICY_DECISION,
	PQCP_FLEET_AUDIT_COMMAND_ACCEPTED,
	PQCP_FLEET_AUDIT_COMMAND_COMPLETED,
	PQCP_FLEET_AUDIT_COMMAND_REJECTED,
	PQCP_FLEET_AUDIT_UPDATE_AUTHORIZED,
	PQCP_FLEET_AUDIT_UPDATE_STAGED,
	PQCP_FLEET_AUDIT_UPDATE_ACTIVATED,
	PQCP_FLEET_AUDIT_UPDATE_ROLLED_BACK,
	PQCP_FLEET_AUDIT_ATTESTATION,
	PQCP_FLEET_AUDIT_RECONCILIATION,
	PQCP_FLEET_AUDIT_QUARANTINE,
	PQCP_FLEET_AUDIT_RECOVERY,
	PQCP_FLEET_AUDIT_DECOMMISSION,
	PQCP_FLEET_AUDIT_EVENT_COUNT,
};

enum pqcp_fleet_audit_severity {
	PQCP_FLEET_AUDIT_DEBUG = 0,
	PQCP_FLEET_AUDIT_INFO,
	PQCP_FLEET_AUDIT_NOTICE,
	PQCP_FLEET_AUDIT_WARNING,
	PQCP_FLEET_AUDIT_ERROR,
	PQCP_FLEET_AUDIT_CRITICAL,
};

enum pqcp_fleet_metric {
	PQCP_FLEET_METRIC_HANDSHAKE_US = 0,
	PQCP_FLEET_METRIC_OPERATION_US,
	PQCP_FLEET_METRIC_QUEUE_DELAY_US,
	PQCP_FLEET_METRIC_FAILURES,
	PQCP_FLEET_METRIC_RETRIES,
	PQCP_FLEET_METRIC_BYTES_SENT,
	PQCP_FLEET_METRIC_BYTES_RECEIVED,
	PQCP_FLEET_METRIC_STORAGE_PRESSURE,
	PQCP_FLEET_METRIC_MEMORY_PRESSURE,
	PQCP_FLEET_METRIC_RISK_SCORE,
	PQCP_FLEET_METRIC_COUNT,
};

enum pqcp_fleet_reconcile_action {
	PQCP_FLEET_RECONCILE_NONE = 0,
	PQCP_FLEET_RECONCILE_ACCEPT_REMOTE,
	PQCP_FLEET_RECONCILE_KEEP_LOCAL,
	PQCP_FLEET_RECONCILE_REQUEST_POLICY,
	PQCP_FLEET_RECONCILE_REQUEST_REVOCATION,
	PQCP_FLEET_RECONCILE_REQUEST_CREDENTIAL,
	PQCP_FLEET_RECONCILE_ROTATE_KEY,
	PQCP_FLEET_RECONCILE_ENTER_RECOVERY,
	PQCP_FLEET_RECONCILE_QUARANTINE,
	PQCP_FLEET_RECONCILE_DECOMMISSION,
};

enum pqcp_fleet_reconcile_reason {
	PQCP_FLEET_RECONCILE_REASON_POLICY_EPOCH = (1U << 0),
	PQCP_FLEET_RECONCILE_REASON_REVOCATION_EPOCH = (1U << 1),
	PQCP_FLEET_RECONCILE_REASON_CREDENTIAL_EPOCH = (1U << 2),
	PQCP_FLEET_RECONCILE_REASON_FIRMWARE_VERSION = (1U << 3),
	PQCP_FLEET_RECONCILE_REASON_COMMAND_SEQUENCE = (1U << 4),
	PQCP_FLEET_RECONCILE_REASON_AUDIT_CHAIN = (1U << 5),
	PQCP_FLEET_RECONCILE_REASON_DEVICE_STATE = (1U << 6),
	PQCP_FLEET_RECONCILE_REASON_CAPABILITIES = (1U << 7),
	PQCP_FLEET_RECONCILE_REASON_DIGEST_CONFLICT = (1U << 8),
};

struct pqcp_fleet_policy_rule {
	uint32_t rule_id;
	uint32_t priority;
	uint32_t operation_mask;
	uint32_t device_state_mask;
	uint32_t required_capabilities;
	uint32_t forbidden_capabilities;
	uint32_t minimum_security_level;
	uint32_t maximum_risk_score;
	uint64_t minimum_policy_epoch;
	uint64_t minimum_revocation_epoch;
	uint64_t not_before_ms;
	uint64_t not_after_ms;
	enum pqcp_fleet_policy_effect effect;
	bool require_channel_identity;
	bool require_online;
	bool enabled;
};

struct pqcp_fleet_policy_context {
	enum pqcp_fleet_operation_type operation;
	enum pqcp_fleet_device_state device_state;
	uint32_t capabilities;
	uint32_t security_level;
	uint32_t risk_score;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t credential_valid_until_ms;
	uint64_t now_ms;
	bool channel_identity_verified;
	bool online;
	bool revoked;
};

struct pqcp_fleet_policy_decision {
	enum pqcp_fleet_policy_effect effect;
	enum pqcp_fleet_policy_reason reason;
	uint32_t matched_rule_id;
	uint32_t matched_priority;
	uint32_t missing_capabilities;
	enum pqcp_fleet_audit_severity severity;
	char explanation[PQCP_FLEET_POLICY_REASON_MAX_CHARS];
};

struct pqcp_fleet_policy_engine {
	uint32_t schema_version;
	struct pqcp_fleet_policy_rule *rules;
	size_t capacity;
	size_t count;
	enum pqcp_fleet_policy_effect default_effect;
	uint64_t generation;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_fleet_command {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t command_id;
	uint64_t sequence;
	uint64_t submitted_at_ms;
	uint64_t deadline_ms;
	uint64_t retry_after_ms;
	enum pqcp_fleet_operation_type operation;
	enum pqcp_fleet_command_state state;
	uint32_t flags;
	uint32_t required_capabilities;
	uint32_t attempts;
	uint32_t maximum_attempts;
	int result;
	uint8_t idempotency_key[PQCP_FLEET_DIGEST_BYTES];
	uint8_t payload_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t result_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_command_queue {
	uint32_t schema_version;
	struct pqcp_fleet_command *commands;
	size_t capacity;
	uint32_t next_generation;
	uint64_t last_sequence;
	uint64_t accepted_count;
	uint64_t completed_count;
	uint64_t rejected_count;
	uint64_t replayed_count;
	uint64_t cancelled_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_fleet_update_component {
	uint32_t schema_version;
	char component_id[PQCP_FLEET_COMPONENT_MAX_CHARS];
	enum pqcp_fleet_update_state state;
	uint64_t current_version;
	uint64_t previous_version;
	uint64_t target_version;
	uint64_t image_size;
	uint64_t received_bytes;
	uint64_t activated_at_ms;
	uint64_t probation_until_ms;
	uint64_t rollback_deadline_ms;
	uint32_t flags;
	uint32_t failed_health_checks;
	uint32_t required_health_checks;
	uint32_t successful_health_checks;
	uint8_t expected_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t received_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_update_manager {
	uint32_t schema_version;
	struct pqcp_fleet_update_component *components;
	size_t capacity;
	uint64_t authorized_count;
	uint64_t activated_count;
	uint64_t committed_count;
	uint64_t rollback_count;
	uint64_t failed_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_fleet_audit_entry {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t timestamp_ms;
	enum pqcp_fleet_audit_event event;
	enum pqcp_fleet_audit_severity severity;
	uint64_t subject_id;
	int result;
	char actor[PQCP_FLEET_ACTOR_MAX_CHARS];
	uint8_t payload_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t entry_digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_audit_ledger {
	uint32_t schema_version;
	struct pqcp_fleet_audit_entry *entries;
	size_t capacity;
	size_t next_index;
	size_t count;
	uint64_t next_sequence;
	uint8_t chain_head[PQCP_FLEET_DIGEST_BYTES];
	uint64_t dropped_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_fleet_metric_sample {
	uint64_t timestamp_ms;
	uint64_t value;
};

struct pqcp_fleet_metric_window {
	struct pqcp_fleet_metric_sample *samples;
	size_t capacity;
	size_t next_index;
	size_t count;
	uint64_t minimum;
	uint64_t maximum;
	uint64_t sum;
	uint64_t ewma;
	uint32_t ewma_weight;
};

struct pqcp_fleet_telemetry {
	uint32_t schema_version;
	struct pqcp_fleet_metric_window
		windows[PQCP_FLEET_METRIC_COUNT];
	uint64_t generation;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_fleet_attestation_claims {
	uint32_t schema_version;
	char device_id[PQCP_FLEET_ID_MAX_CHARS];
	char product_class[PQCP_FLEET_PRODUCT_MAX_CHARS];
	char firmware_version[PQCP_FLEET_VERSION_MAX_CHARS];
	enum pqcp_fleet_device_state device_state;
	uint64_t boot_counter;
	uint64_t firmware_version_number;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t credential_issuance_epoch;
	uint64_t audit_sequence;
	uint32_t capabilities;
	uint32_t risk_score;
	uint32_t security_level;
	uint8_t hardware_id_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t audit_chain_head[PQCP_FLEET_DIGEST_BYTES];
	uint8_t nonce[PQCP_FLEET_NONCE_BYTES];
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
};

struct pqcp_fleet_attestation {
	struct pqcp_fleet_attestation_claims claims;
	uint8_t claims_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

struct pqcp_fleet_reconcile_state {
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t credential_epoch;
	uint64_t firmware_version;
	uint64_t command_sequence;
	uint64_t audit_sequence;
	enum pqcp_fleet_device_state device_state;
	uint32_t capabilities;
	uint8_t credential_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t policy_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t audit_chain_head[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_reconcile_result {
	enum pqcp_fleet_reconcile_action action;
	uint32_t reason_mask;
	uint64_t selected_policy_epoch;
	uint64_t selected_revocation_epoch;
	uint64_t selected_credential_epoch;
	uint64_t selected_firmware_version;
	bool conflict;
	bool security_critical;
};

struct pqcp_fleet_operations_storage {
	struct pqcp_fleet_policy_rule *policy_rules;
	size_t policy_rule_capacity;
	struct pqcp_fleet_command *commands;
	size_t command_capacity;
	struct pqcp_fleet_update_component *components;
	size_t component_capacity;
	struct pqcp_fleet_audit_entry *audit_entries;
	size_t audit_capacity;
	struct pqcp_fleet_metric_sample *metric_samples;
	size_t samples_per_metric;
};

struct pqcp_fleet_operations {
	uint32_t schema_version;
	struct pqcp_fleet_device *device;
	struct pqcp_fleet_policy_engine policy;
	struct pqcp_fleet_command_queue commands;
	struct pqcp_fleet_update_manager updates;
	struct pqcp_fleet_audit_ledger audit;
	struct pqcp_fleet_telemetry telemetry;
	uint32_t risk_score;
	uint32_t security_level;
	uint64_t tick_count;
	bool online;
	bool channel_identity_verified;
	bool quarantined;
	bool initialized;
};

int pqcp_fleet_policy_engine_init(
	struct pqcp_fleet_policy_engine *engine,
	struct pqcp_fleet_policy_rule *rules,
	size_t capacity,
	enum pqcp_fleet_policy_effect default_effect);
int pqcp_fleet_policy_rule_put(
	struct pqcp_fleet_policy_engine *engine,
	const struct pqcp_fleet_policy_rule *rule);
int pqcp_fleet_policy_rule_remove(
	struct pqcp_fleet_policy_engine *engine,
	uint32_t rule_id);
int pqcp_fleet_policy_evaluate(
	struct pqcp_fleet_policy_engine *engine,
	const struct pqcp_fleet_policy_context *context,
	struct pqcp_fleet_policy_decision *decision);
int pqcp_fleet_policy_engine_audit(
	struct pqcp_fleet_policy_engine *engine);

int pqcp_fleet_command_queue_init(
	struct pqcp_fleet_command_queue *queue,
	struct pqcp_fleet_command *commands,
	size_t capacity);
int pqcp_fleet_command_submit(
	struct pqcp_fleet_command_queue *queue,
	const struct pqcp_fleet_command *command,
	struct pqcp_fleet_command **accepted,
	bool *replayed);
int pqcp_fleet_command_next(
	struct pqcp_fleet_command_queue *queue,
	uint64_t now_ms,
	struct pqcp_fleet_command **command);
int pqcp_fleet_command_complete(
	struct pqcp_fleet_command_queue *queue,
	uint64_t command_id,
	int result,
	const uint8_t *result_data,
	size_t result_length,
	uint64_t now_ms);
int pqcp_fleet_command_retry(
	struct pqcp_fleet_command_queue *queue,
	uint64_t command_id,
	uint64_t retry_after_ms,
	int result);
int pqcp_fleet_command_cancel(
	struct pqcp_fleet_command_queue *queue,
	uint64_t command_id);
int pqcp_fleet_command_expire(
	struct pqcp_fleet_command_queue *queue,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_fleet_command_queue_audit(
	struct pqcp_fleet_command_queue *queue);

int pqcp_fleet_update_manager_init(
	struct pqcp_fleet_update_manager *manager,
	struct pqcp_fleet_update_component *components,
	size_t capacity);
int pqcp_fleet_update_register_component(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	uint64_t current_version);
int pqcp_fleet_update_authorize(
	struct pqcp_fleet_update_manager *manager,
	const struct pqcp_fleet_update_manifest *manifest,
	uint64_t now_ms,
	uint64_t probation_ms,
	uint64_t rollback_window_ms,
	uint32_t required_health_checks);
int pqcp_fleet_update_record_block(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	uint64_t offset,
	const uint8_t *block,
	size_t block_length);
int pqcp_fleet_update_finish_staging(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES]);
int pqcp_fleet_update_activate(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	uint64_t now_ms);
int pqcp_fleet_update_health(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	bool healthy,
	uint64_t now_ms);
int pqcp_fleet_update_request_rollback(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id,
	uint64_t now_ms);
int pqcp_fleet_update_complete_rollback(
	struct pqcp_fleet_update_manager *manager,
	const char *component_id);
int pqcp_fleet_update_tick(
	struct pqcp_fleet_update_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_fleet_update_manager_audit(
	struct pqcp_fleet_update_manager *manager);

int pqcp_fleet_audit_ledger_init(
	struct pqcp_fleet_audit_ledger *ledger,
	struct pqcp_fleet_audit_entry *entries,
	size_t capacity);
int pqcp_fleet_audit_append(
	struct pqcp_fleet_audit_ledger *ledger,
	enum pqcp_fleet_audit_event event,
	enum pqcp_fleet_audit_severity severity,
	const char *actor,
	uint64_t subject_id,
	int result,
	const uint8_t *payload,
	size_t payload_length,
	uint64_t now_ms,
	struct pqcp_fleet_audit_entry *entry);
int pqcp_fleet_audit_find(
	struct pqcp_fleet_audit_ledger *ledger,
	uint64_t sequence,
	struct pqcp_fleet_audit_entry *entry);
int pqcp_fleet_audit_verify(
	struct pqcp_fleet_audit_ledger *ledger);

int pqcp_fleet_telemetry_init(
	struct pqcp_fleet_telemetry *telemetry,
	struct pqcp_fleet_metric_sample *samples,
	size_t samples_per_metric);
int pqcp_fleet_telemetry_record(
	struct pqcp_fleet_telemetry *telemetry,
	enum pqcp_fleet_metric metric,
	uint64_t value,
	uint64_t now_ms);
int pqcp_fleet_telemetry_summary(
	struct pqcp_fleet_telemetry *telemetry,
	enum pqcp_fleet_metric metric,
	uint64_t *minimum,
	uint64_t *maximum,
	uint64_t *average,
	uint64_t *p95,
	uint64_t *ewma);
int pqcp_fleet_telemetry_prune(
	struct pqcp_fleet_telemetry *telemetry,
	uint64_t before_ms,
	uint32_t *pruned_count);
int pqcp_fleet_telemetry_audit(
	struct pqcp_fleet_telemetry *telemetry);

int pqcp_fleet_attestation_collect(
	const struct pqcp_fleet_device *device,
	const struct pqcp_fleet_audit_ledger *ledger,
	uint32_t risk_score,
	uint32_t security_level,
	const uint8_t nonce[PQCP_FLEET_NONCE_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_fleet_attestation *attestation);
int pqcp_fleet_attestation_sign(
	struct pqcp_fleet_attestation *attestation,
	const struct pqcp_fleet_signer *signer);
int pqcp_fleet_attestation_verify(
	const struct pqcp_fleet_attestation *attestation,
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint64_t now_ms);
int pqcp_fleet_attestation_encode(
	const struct pqcp_fleet_attestation *attestation,
	uint8_t *output,
	size_t capacity,
	size_t *length);
int pqcp_fleet_attestation_decode(
	const uint8_t *input,
	size_t length,
	struct pqcp_fleet_attestation *attestation);

int pqcp_fleet_reconcile(
	const struct pqcp_fleet_reconcile_state *local,
	const struct pqcp_fleet_reconcile_state *remote,
	struct pqcp_fleet_reconcile_result *result);

int pqcp_fleet_operations_init(
	struct pqcp_fleet_operations *operations,
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_operations_storage *storage,
	enum pqcp_fleet_policy_effect default_effect,
	uint32_t security_level);
int pqcp_fleet_operations_submit(
	struct pqcp_fleet_operations *operations,
	const struct pqcp_fleet_command *command,
	uint64_t now_ms,
	struct pqcp_fleet_policy_decision *decision,
	bool *replayed);
int pqcp_fleet_operations_tick(
	struct pqcp_fleet_operations *operations,
	uint64_t now_ms);
int pqcp_fleet_operations_set_connectivity(
	struct pqcp_fleet_operations *operations,
	bool online,
	bool channel_identity_verified);
int pqcp_fleet_operations_set_risk(
	struct pqcp_fleet_operations *operations,
	uint32_t risk_score,
	uint64_t now_ms);
int pqcp_fleet_operations_audit(
	struct pqcp_fleet_operations *operations,
	uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_OPERATIONS_H_ */
