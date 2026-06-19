/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Adaptive PQC deployment control plane
 *
 * Stability: experimental runtime API. This API operates only on PQC
 * implementations already compiled into the firmware image. It never loads
 * code dynamically and never changes the ML-KEM, ML-DSA, ACVP, or benchmark
 * wire formats.
 */

#ifndef PQCP_ZEPHYR_ADAPTIVE_CONTROL_H_
#define PQCP_ZEPHYR_ADAPTIVE_CONTROL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_advisor.h>
#include <pqcp_zephyr/deployment_evidence_codec.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_ADAPTIVE_SCHEMA_VERSION 1U
#define PQCP_ADAPTIVE_ID_MAX_CHARS 48U
#define PQCP_ADAPTIVE_MAX_PROFILES 16U
#define PQCP_ADAPTIVE_TELEMETRY_CAPACITY 32U
#define PQCP_ADAPTIVE_MAX_EVENTS 64U
#define PQCP_ADAPTIVE_MAX_SESSIONS 16U
#define PQCP_ADAPTIVE_MAX_PEERS 16U
#define PQCP_ADAPTIVE_MAX_RECOMMENDATIONS 16U
#define PQCP_ADAPTIVE_MAX_WORKLOAD_ITEMS 24U
#define PQCP_ADAPTIVE_SNAPSHOT_MAX_BYTES 16384U
#define PQCP_ADAPTIVE_DIGEST_HEX_CHARS 64U
#define PQCP_ADAPTIVE_SCORE_MAX 1000U

enum pqcp_adaptive_status {
	PQCP_ADAPTIVE_STATUS_FAIL = 0,
	PQCP_ADAPTIVE_STATUS_WARN,
	PQCP_ADAPTIVE_STATUS_PASS,
};

enum pqcp_adaptive_metric_source {
	PQCP_ADAPTIVE_METRIC_UNKNOWN = 0,
	PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
	PQCP_ADAPTIVE_METRIC_MEASURED,
	PQCP_ADAPTIVE_METRIC_CALIBRATED,
};

enum pqcp_adaptive_mode {
	PQCP_ADAPTIVE_MODE_SAFE = 0,
	PQCP_ADAPTIVE_MODE_CONSERVATIVE,
	PQCP_ADAPTIVE_MODE_BALANCED,
	PQCP_ADAPTIVE_MODE_PERFORMANCE,
	PQCP_ADAPTIVE_MODE_RECOVERY,
	PQCP_ADAPTIVE_MODE_LOCKDOWN,
};

enum pqcp_adaptive_pressure {
	PQCP_ADAPTIVE_PRESSURE_NONE = 0,
	PQCP_ADAPTIVE_PRESSURE_LOW,
	PQCP_ADAPTIVE_PRESSURE_MODERATE,
	PQCP_ADAPTIVE_PRESSURE_HIGH,
	PQCP_ADAPTIVE_PRESSURE_CRITICAL,
};

enum pqcp_adaptive_threat_level {
	PQCP_ADAPTIVE_THREAT_NOMINAL = 0,
	PQCP_ADAPTIVE_THREAT_ELEVATED,
	PQCP_ADAPTIVE_THREAT_HIGH,
	PQCP_ADAPTIVE_THREAT_SEVERE,
	PQCP_ADAPTIVE_THREAT_CRITICAL,
};

enum pqcp_adaptive_policy_profile {
	PQCP_ADAPTIVE_POLICY_SENSOR = 0,
	PQCP_ADAPTIVE_POLICY_GATEWAY,
	PQCP_ADAPTIVE_POLICY_FIRMWARE_UPDATE,
	PQCP_ADAPTIVE_POLICY_CRITICAL_INFRASTRUCTURE,
	PQCP_ADAPTIVE_POLICY_RESEARCH,
};

enum pqcp_adaptive_transition_state {
	PQCP_ADAPTIVE_TRANSITION_STABLE = 0,
	PQCP_ADAPTIVE_TRANSITION_PENDING,
	PQCP_ADAPTIVE_TRANSITION_PREPARING,
	PQCP_ADAPTIVE_TRANSITION_COMMITTING,
	PQCP_ADAPTIVE_TRANSITION_COOLDOWN,
	PQCP_ADAPTIVE_TRANSITION_ROLLBACK,
	PQCP_ADAPTIVE_TRANSITION_BLOCKED,
};

enum pqcp_adaptive_transition_reason {
	PQCP_ADAPTIVE_REASON_NONE = 0,
	PQCP_ADAPTIVE_REASON_INITIAL_SELECTION,
	PQCP_ADAPTIVE_REASON_THREAT_ESCALATION,
	PQCP_ADAPTIVE_REASON_RESOURCE_PRESSURE,
	PQCP_ADAPTIVE_REASON_LATENCY_PRESSURE,
	PQCP_ADAPTIVE_REASON_ENERGY_PRESSURE,
	PQCP_ADAPTIVE_REASON_POLICY_CHANGE,
	PQCP_ADAPTIVE_REASON_HARDWARE_RECOVERY,
	PQCP_ADAPTIVE_REASON_FLEET_CONSENSUS,
	PQCP_ADAPTIVE_REASON_MANUAL_OVERRIDE,
	PQCP_ADAPTIVE_REASON_ROLLBACK,
};

enum pqcp_adaptive_session_kind {
	PQCP_ADAPTIVE_SESSION_KEM = 0,
	PQCP_ADAPTIVE_SESSION_SIGNATURE,
	PQCP_ADAPTIVE_SESSION_HYBRID_TLS,
	PQCP_ADAPTIVE_SESSION_ONBOARDING,
	PQCP_ADAPTIVE_SESSION_RECONNECT,
	PQCP_ADAPTIVE_SESSION_FIRMWARE_UPDATE,
	PQCP_ADAPTIVE_SESSION_TELEMETRY,
};

enum pqcp_adaptive_event_type {
	PQCP_ADAPTIVE_EVENT_BOOT = 0,
	PQCP_ADAPTIVE_EVENT_TELEMETRY,
	PQCP_ADAPTIVE_EVENT_THREAT_CHANGE,
	PQCP_ADAPTIVE_EVENT_RECOMMENDATION,
	PQCP_ADAPTIVE_EVENT_TRANSITION_REQUEST,
	PQCP_ADAPTIVE_EVENT_TRANSITION_COMMIT,
	PQCP_ADAPTIVE_EVENT_TRANSITION_REJECT,
	PQCP_ADAPTIVE_EVENT_DOWNGRADE_REQUEST,
	PQCP_ADAPTIVE_EVENT_DOWNGRADE_APPROVED,
	PQCP_ADAPTIVE_EVENT_DOWNGRADE_REJECTED,
	PQCP_ADAPTIVE_EVENT_SESSION_OPEN,
	PQCP_ADAPTIVE_EVENT_SESSION_CLOSE,
	PQCP_ADAPTIVE_EVENT_SNAPSHOT,
	PQCP_ADAPTIVE_EVENT_FLEET_UPDATE,
	PQCP_ADAPTIVE_EVENT_FAULT,
};

enum pqcp_adaptive_workload_state {
	PQCP_ADAPTIVE_WORKLOAD_QUEUED = 0,
	PQCP_ADAPTIVE_WORKLOAD_ADMITTED,
	PQCP_ADAPTIVE_WORKLOAD_RUNNING,
	PQCP_ADAPTIVE_WORKLOAD_COMPLETED,
	PQCP_ADAPTIVE_WORKLOAD_REJECTED,
	PQCP_ADAPTIVE_WORKLOAD_EXPIRED,
};

enum pqcp_adaptive_resilience_action {
	PQCP_ADAPTIVE_RESILIENCE_CONTINUE = 0,
	PQCP_ADAPTIVE_RESILIENCE_DEGRADE_PERFORMANCE,
	PQCP_ADAPTIVE_RESILIENCE_PIN_PROFILE,
	PQCP_ADAPTIVE_RESILIENCE_ROLLBACK,
	PQCP_ADAPTIVE_RESILIENCE_RECOVERY,
	PQCP_ADAPTIVE_RESILIENCE_LOCKDOWN,
};

#define PQCP_ADAPTIVE_ANOMALY_LATENCY_SPIKE       (1U << 0)
#define PQCP_ADAPTIVE_ANOMALY_MEMORY_PRESSURE     (1U << 1)
#define PQCP_ADAPTIVE_ANOMALY_STACK_PRESSURE      (1U << 2)
#define PQCP_ADAPTIVE_ANOMALY_HEAP_PRESSURE       (1U << 3)
#define PQCP_ADAPTIVE_ANOMALY_ENERGY_SPIKE        (1U << 4)
#define PQCP_ADAPTIVE_ANOMALY_QUEUE_PRESSURE       (1U << 5)
#define PQCP_ADAPTIVE_ANOMALY_NETWORK_LOSS         (1U << 6)
#define PQCP_ADAPTIVE_ANOMALY_HANDSHAKE_FAILURES   (1U << 7)
#define PQCP_ADAPTIVE_ANOMALY_CLOCK_ROLLBACK       (1U << 8)
#define PQCP_ADAPTIVE_ANOMALY_SENSOR_RANGE         (1U << 9)
#define PQCP_ADAPTIVE_ANOMALY_KNOWN_MASK ((1U << 10) - 1U)

#define PQCP_ADAPTIVE_THREAT_AUTH_FAILURE          (1U << 0)
#define PQCP_ADAPTIVE_THREAT_REPLAY                (1U << 1)
#define PQCP_ADAPTIVE_THREAT_SIGNATURE_FAILURE     (1U << 2)
#define PQCP_ADAPTIVE_THREAT_ROLLBACK_ATTEMPT      (1U << 3)
#define PQCP_ADAPTIVE_THREAT_PHYSICAL_TAMPER       (1U << 4)
#define PQCP_ADAPTIVE_THREAT_REMOTE_ADVISORY       (1U << 5)
#define PQCP_ADAPTIVE_THREAT_PUBLIC_NETWORK        (1U << 6)
#define PQCP_ADAPTIVE_THREAT_SENSITIVE_DATA        (1U << 7)
#define PQCP_ADAPTIVE_THREAT_BEHAVIORAL_ANOMALY    (1U << 8)
#define PQCP_ADAPTIVE_THREAT_FLEET_DIVERGENCE      (1U << 9)
#define PQCP_ADAPTIVE_THREAT_KNOWN_MASK ((1U << 10) - 1U)

#define PQCP_ADAPTIVE_RESOURCE_LATENCY             (1U << 0)
#define PQCP_ADAPTIVE_RESOURCE_RAM                 (1U << 1)
#define PQCP_ADAPTIVE_RESOURCE_STACK               (1U << 2)
#define PQCP_ADAPTIVE_RESOURCE_HEAP                (1U << 3)
#define PQCP_ADAPTIVE_RESOURCE_FLASH               (1U << 4)
#define PQCP_ADAPTIVE_RESOURCE_ENERGY              (1U << 5)
#define PQCP_ADAPTIVE_RESOURCE_QUEUE               (1U << 6)
#define PQCP_ADAPTIVE_RESOURCE_THERMAL             (1U << 7)
#define PQCP_ADAPTIVE_RESOURCE_BATTERY             (1U << 8)
#define PQCP_ADAPTIVE_RESOURCE_KNOWN_MASK ((1U << 9) - 1U)

#define PQCP_ADAPTIVE_BLOCK_OPERATION              (1U << 0)
#define PQCP_ADAPTIVE_BLOCK_SECURITY               (1U << 1)
#define PQCP_ADAPTIVE_BLOCK_PROVIDER               (1U << 2)
#define PQCP_ADAPTIVE_BLOCK_POLICY                 (1U << 3)
#define PQCP_ADAPTIVE_BLOCK_LATENCY                (1U << 4)
#define PQCP_ADAPTIVE_BLOCK_RAM                    (1U << 5)
#define PQCP_ADAPTIVE_BLOCK_STACK                  (1U << 6)
#define PQCP_ADAPTIVE_BLOCK_HEAP                   (1U << 7)
#define PQCP_ADAPTIVE_BLOCK_FLASH                  (1U << 8)
#define PQCP_ADAPTIVE_BLOCK_ENERGY                 (1U << 9)
#define PQCP_ADAPTIVE_BLOCK_EVIDENCE               (1U << 10)
#define PQCP_ADAPTIVE_BLOCK_HARDWARE               (1U << 11)
#define PQCP_ADAPTIVE_BLOCK_DOWNGRADE              (1U << 12)
#define PQCP_ADAPTIVE_BLOCK_COOLDOWN               (1U << 13)
#define PQCP_ADAPTIVE_BLOCK_SESSION_CONFLICT       (1U << 14)
#define PQCP_ADAPTIVE_BLOCK_FLEET_POLICY           (1U << 15)
#define PQCP_ADAPTIVE_BLOCK_KNOWN_MASK ((1U << 16) - 1U)

#define PQCP_ADAPTIVE_WARNING_LOW_CONFIDENCE        (1U << 0)
#define PQCP_ADAPTIVE_WARNING_FORECAST_PRESSURE     (1U << 1)
#define PQCP_ADAPTIVE_WARNING_TELEMETRY_STALE       (1U << 2)
#define PQCP_ADAPTIVE_WARNING_EXTERNAL_EVIDENCE     (1U << 3)
#define PQCP_ADAPTIVE_WARNING_FLEET_MINORITY        (1U << 4)
#define PQCP_ADAPTIVE_WARNING_PENDING_SESSIONS      (1U << 5)
#define PQCP_ADAPTIVE_WARNING_TRANSITION_FLAP       (1U << 6)
#define PQCP_ADAPTIVE_WARNING_MANUAL_AUTHORIZATION  (1U << 7)
#define PQCP_ADAPTIVE_WARNING_DEGRADED_EVIDENCE     (1U << 8)
#define PQCP_ADAPTIVE_WARNING_KNOWN_MASK ((1U << 9) - 1U)

struct pqcp_adaptive_profile {
	uint32_t schema_version;
	char profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	enum pqcp_deployment_candidate_kind kind;
	uint32_t operation_mask;
	uint32_t security_level;
	uint32_t mlkem_level;
	uint32_t mldsa_level;
	uint64_t nominal_latency_us;
	uint64_t nominal_cycles;
	uint64_t ram_bytes;
	uint64_t stack_bytes;
	uint64_t heap_bytes;
	uint64_t flash_bytes;
	uint64_t energy_uj;
	enum pqcp_adaptive_metric_source latency_source;
	enum pqcp_adaptive_metric_source cycles_source;
	enum pqcp_adaptive_metric_source memory_source;
	enum pqcp_adaptive_metric_source energy_source;
	uint32_t observation_count;
	uint32_t evidence_mask;
	uint32_t priority;
	bool enabled;
	bool native_provider;
	bool production_allowed;
	bool hardware_validated;
	bool hybrid_required;
};

struct pqcp_adaptive_profile_registry {
	uint32_t schema_version;
	uint32_t count;
	uint32_t enabled_count;
	uint32_t native_count;
	uint32_t production_count;
	struct pqcp_adaptive_profile profiles[PQCP_ADAPTIVE_MAX_PROFILES];
	char registry_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_telemetry_sample {
	uint64_t timestamp_ms;
	uint64_t latency_us;
	uint64_t cycles;
	uint64_t free_ram_bytes;
	uint64_t stack_used_bytes;
	uint64_t heap_free_bytes;
	uint64_t energy_uj;
	uint32_t queue_depth;
	int32_t temperature_millic;
	uint32_t battery_permille;
	uint32_t network_loss_permille;
	uint32_t handshake_failures;
	uint32_t auth_failures;
	bool operation_succeeded;
};

struct pqcp_adaptive_telemetry_window {
	uint32_t schema_version;
	uint32_t capacity;
	uint32_t count;
	uint32_t head;
	uint64_t last_timestamp_ms;
	uint32_t rejected_samples;
	struct pqcp_adaptive_telemetry_sample
		samples[PQCP_ADAPTIVE_TELEMETRY_CAPACITY];
};

struct pqcp_adaptive_metric_summary {
	uint32_t count;
	uint64_t minimum;
	uint64_t maximum;
	uint64_t mean;
	uint64_t median;
	uint64_t p90;
	uint64_t p99;
	uint64_t mad;
	uint32_t coefficient_variation_bps;
	int64_t trend_per_sample;
};

struct pqcp_adaptive_telemetry_summary {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	uint32_t sample_count;
	uint32_t success_count;
	uint32_t failure_count;
	uint32_t anomaly_mask;
	enum pqcp_adaptive_pressure latency_pressure;
	enum pqcp_adaptive_pressure memory_pressure;
	enum pqcp_adaptive_pressure energy_pressure;
	struct pqcp_adaptive_metric_summary latency;
	struct pqcp_adaptive_metric_summary cycles;
	struct pqcp_adaptive_metric_summary energy;
	uint64_t minimum_free_ram_bytes;
	uint64_t maximum_stack_used_bytes;
	uint64_t minimum_heap_free_bytes;
	uint32_t maximum_queue_depth;
	uint32_t average_battery_permille;
	uint32_t average_network_loss_permille;
	uint32_t total_handshake_failures;
	uint32_t total_auth_failures;
	int32_t maximum_temperature_millic;
	uint64_t first_timestamp_ms;
	uint64_t last_timestamp_ms;
	char telemetry_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_forecast_policy {
	uint32_t horizon_samples;
	uint32_t minimum_samples;
	uint32_t confidence_floor;
	uint32_t latency_growth_limit_bps;
	uint32_t energy_growth_limit_bps;
	uint64_t reserve_ram_bytes;
	uint64_t reserve_heap_bytes;
};

struct pqcp_adaptive_forecast {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	uint32_t confidence;
	uint32_t warning_mask;
	uint32_t horizon_samples;
	uint64_t predicted_latency_us;
	uint64_t predicted_cycles;
	uint64_t predicted_energy_uj;
	uint64_t predicted_free_ram_bytes;
	uint64_t predicted_stack_used_bytes;
	uint64_t predicted_heap_free_bytes;
	uint32_t predicted_queue_depth;
	uint32_t predicted_battery_permille;
	int32_t predicted_temperature_millic;
	bool latency_limit_expected;
	bool ram_limit_expected;
	bool stack_limit_expected;
	bool heap_limit_expected;
	bool energy_limit_expected;
	char forecast_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_threat_signal {
	uint64_t timestamp_ms;
	uint32_t signal_mask;
	uint32_t auth_failures;
	uint32_t replay_events;
	uint32_t signature_failures;
	uint32_t rollback_attempts;
	uint32_t remote_advisory_level;
	uint32_t fleet_divergence_percent;
	uint32_t data_sensitivity;
	bool physical_tamper;
	bool public_network;
};

struct pqcp_adaptive_threat_policy {
	uint32_t auth_failure_weight;
	uint32_t replay_weight;
	uint32_t signature_failure_weight;
	uint32_t rollback_weight;
	uint32_t tamper_weight;
	uint32_t advisory_weight;
	uint32_t public_network_weight;
	uint32_t sensitive_data_weight;
	uint32_t anomaly_weight;
	uint32_t fleet_divergence_weight;
	uint32_t elevated_threshold;
	uint32_t high_threshold;
	uint32_t severe_threshold;
	uint32_t critical_threshold;
};

struct pqcp_adaptive_threat_assessment {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	enum pqcp_adaptive_threat_level level;
	uint32_t score;
	uint32_t reason_mask;
	uint32_t minimum_security_level;
	bool require_hybrid;
	bool require_signature;
	bool prohibit_downgrade;
	bool require_hardware_evidence;
	uint64_t assessed_at_ms;
	char threat_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_resource_limits {
	uint64_t latency_budget_us;
	uint64_t ram_capacity_bytes;
	uint64_t stack_capacity_bytes;
	uint64_t heap_capacity_bytes;
	uint64_t flash_capacity_bytes;
	uint64_t energy_budget_uj;
	uint32_t queue_capacity;
	int32_t maximum_temperature_millic;
	uint32_t minimum_battery_permille;
	uint32_t reserve_permille;
};

struct pqcp_adaptive_resource_assessment {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	uint32_t available_mask;
	uint32_t exhausted_mask;
	uint32_t warning_mask;
	enum pqcp_adaptive_pressure overall_pressure;
	uint64_t latency_headroom_us;
	uint64_t ram_headroom_bytes;
	uint64_t stack_headroom_bytes;
	uint64_t heap_headroom_bytes;
	uint64_t flash_headroom_bytes;
	uint64_t energy_headroom_uj;
	uint32_t queue_headroom;
	int32_t thermal_headroom_millic;
	uint32_t battery_headroom_permille;
	uint32_t minimum_headroom_permille;
	char resource_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_policy {
	uint32_t schema_version;
	enum pqcp_adaptive_policy_profile profile;
	enum pqcp_adaptive_mode default_mode;
	uint32_t minimum_security_level;
	uint32_t required_evidence_mask;
	uint32_t minimum_confidence;
	uint32_t minimum_improvement_score;
	uint32_t transition_confirmations;
	uint32_t cooldown_cycles;
	uint32_t maximum_transitions_per_hour;
	uint32_t fleet_quorum_percent;
	uint32_t weight_security;
	uint32_t weight_latency;
	uint32_t weight_memory;
	uint32_t weight_energy;
	uint32_t weight_evidence;
	uint32_t weight_stability;
	uint32_t risk_penalty;
	uint32_t missing_evidence_penalty;
	bool require_native_provider;
	bool require_production_allowed;
	bool require_hardware_evidence;
	bool allow_security_downgrade;
	bool allow_manual_override;
	bool require_fleet_consensus;
	bool fail_closed;
};

struct pqcp_adaptive_candidate_score {
	uint32_t profile_index;
	enum pqcp_adaptive_status status;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	uint32_t total_score;
	uint32_t security_score;
	uint32_t latency_score;
	uint32_t memory_score;
	uint32_t energy_score;
	uint32_t evidence_score;
	uint32_t stability_score;
	uint32_t confidence;
	uint32_t missing_evidence_mask;
	uint64_t projected_latency_us;
	uint64_t projected_ram_bytes;
	uint64_t projected_stack_bytes;
	uint64_t projected_heap_bytes;
	uint64_t projected_energy_uj;
	char profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
};

struct pqcp_adaptive_recommendation {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	uint32_t evaluated_count;
	uint32_t accepted_count;
	uint32_t rejected_count;
	uint32_t warning_mask;
	uint32_t top_index;
	uint32_t confidence;
	bool transition_recommended;
	char current_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char recommended_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	struct pqcp_adaptive_candidate_score
		candidates[PQCP_ADAPTIVE_MAX_RECOMMENDATIONS];
	char recommendation_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_downgrade_authorization {
	uint32_t schema_version;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint32_t minimum_security_level;
	uint32_t maximum_security_drop;
	uint32_t allowed_reason_mask;
	char device_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char from_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char to_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char nonce_hex[33];
	char authorization_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
	bool approved;
	bool consumed;
};

struct pqcp_adaptive_downgrade_result {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	uint32_t security_drop;
	bool downgrade;
	bool authorization_required;
	bool authorization_valid;
	bool consumed;
	char from_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char to_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char result_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_transition_controller {
	uint32_t schema_version;
	enum pqcp_adaptive_transition_state state;
	enum pqcp_adaptive_transition_reason pending_reason;
	uint32_t confirmation_count;
	uint32_t cooldown_remaining;
	uint32_t transition_count;
	uint32_t rejected_count;
	uint64_t hour_window_start_ms;
	uint64_t last_transition_ms;
	uint64_t pending_since_ms;
	char current_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char previous_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char pending_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char controller_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_transition_result {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	enum pqcp_adaptive_transition_state state;
	enum pqcp_adaptive_transition_reason reason;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	uint32_t confirmations;
	uint32_t cooldown_remaining;
	bool changed;
	bool rollback_available;
	char from_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char to_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char transition_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_session_request {
	uint32_t schema_version;
	uint64_t session_id;
	enum pqcp_adaptive_session_kind kind;
	uint64_t requested_at_ms;
	uint64_t deadline_ms;
	uint64_t payload_bytes;
	uint32_t minimum_security_level;
	uint32_t required_evidence_mask;
	bool long_lived;
	bool allow_transition;
	bool require_forward_secrecy;
	bool require_authentication;
};

struct pqcp_adaptive_session_plan {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	uint64_t session_id;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	uint64_t projected_latency_us;
	uint64_t projected_energy_uj;
	uint64_t expires_at_ms;
	bool transition_required;
	bool profile_pinned;
	bool hybrid;
	char selected_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char plan_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_session_entry {
	bool active;
	uint64_t session_id;
	enum pqcp_adaptive_session_kind kind;
	uint64_t opened_at_ms;
	uint64_t expires_at_ms;
	char profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
};

struct pqcp_adaptive_session_table {
	uint32_t schema_version;
	uint32_t active_count;
	uint32_t rejected_count;
	struct pqcp_adaptive_session_entry sessions[PQCP_ADAPTIVE_MAX_SESSIONS];
	char table_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_workload_item {
	uint64_t request_id;
	enum pqcp_adaptive_session_kind kind;
	enum pqcp_adaptive_workload_state state;
	uint64_t submitted_at_ms;
	uint64_t deadline_ms;
	uint64_t estimated_latency_us;
	uint64_t estimated_energy_uj;
	uint64_t payload_bytes;
	uint32_t priority;
	uint32_t minimum_security_level;
	uint32_t required_evidence_mask;
	uint32_t retry_count;
	bool transition_allowed;
	bool batchable;
	char selected_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
};

struct pqcp_adaptive_workload_queue {
	uint32_t schema_version;
	uint32_t count;
	uint32_t admitted_count;
	uint32_t rejected_count;
	uint32_t completed_count;
	uint64_t queued_latency_us;
	uint64_t queued_energy_uj;
	struct pqcp_adaptive_workload_item
		items[PQCP_ADAPTIVE_MAX_WORKLOAD_ITEMS];
	char queue_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_workload_plan {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	uint32_t considered_count;
	uint32_t admitted_count;
	uint32_t rejected_count;
	uint32_t deferred_count;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	uint64_t planned_latency_us;
	uint64_t planned_energy_uj;
	uint64_t earliest_deadline_ms;
	uint32_t required_operation_mask;
	uint32_t minimum_security_level;
	char preferred_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char plan_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_health_signal {
	uint64_t timestamp_ms;
	uint32_t consecutive_failures;
	uint32_t total_failures;
	uint32_t digest_failures;
	uint32_t replay_failures;
	uint32_t transition_failures;
	uint32_t session_failures;
	uint32_t watchdog_resets;
	uint32_t profile_fault_mask;
	bool state_corrupt;
	bool backend_unavailable;
	bool entropy_degraded;
};

struct pqcp_adaptive_resilience_policy {
	uint32_t warn_failure_count;
	uint32_t rollback_failure_count;
	uint32_t recovery_failure_count;
	uint32_t lockdown_failure_count;
	uint32_t maximum_profile_faults;
	uint32_t recovery_stability_cycles;
	bool fail_closed_on_state_corruption;
	bool fail_closed_on_backend_loss;
	bool prohibit_transition_on_entropy_degradation;
};

struct pqcp_adaptive_resilience_state {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	enum pqcp_adaptive_resilience_action action;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	uint32_t isolated_profile_mask;
	uint32_t stable_cycles;
	uint32_t incident_count;
	uint64_t last_incident_ms;
	bool transitions_permitted;
	bool sessions_permitted;
	bool recovery_required;
	char pinned_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char resilience_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_calibration_observation {
	uint64_t timestamp_ms;
	uint64_t latency_us;
	uint64_t cycles;
	uint64_t ram_bytes;
	uint64_t stack_bytes;
	uint64_t heap_bytes;
	uint64_t energy_uj;
	bool successful;
	char profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
};

struct pqcp_adaptive_profile_calibration {
	uint32_t schema_version;
	uint32_t sample_count;
	uint32_t accepted_count;
	uint32_t rejected_count;
	uint32_t confidence;
	uint64_t last_timestamp_ms;
	uint64_t latency_ewma_us;
	uint64_t cycles_ewma;
	uint64_t ram_high_watermark;
	uint64_t stack_high_watermark;
	uint64_t heap_high_watermark;
	uint64_t energy_ewma_uj;
	uint64_t latency_min_us;
	uint64_t latency_max_us;
	uint64_t energy_min_uj;
	uint64_t energy_max_uj;
	char profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char calibration_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_calibration_table {
	uint32_t schema_version;
	uint32_t count;
	uint32_t accepted_observations;
	uint32_t rejected_observations;
	struct pqcp_adaptive_profile_calibration
		profiles[PQCP_ADAPTIVE_MAX_PROFILES];
	char table_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_event {
	uint32_t schema_version;
	uint32_t sequence;
	enum pqcp_adaptive_event_type type;
	enum pqcp_adaptive_status status;
	uint64_t timestamp_ms;
	uint32_t reason_mask;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	uint32_t score;
	char profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char related_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char previous_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
	char event_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_event_log {
	uint32_t schema_version;
	uint32_t count;
	uint32_t head;
	uint32_t next_sequence;
	uint32_t dropped_events;
	struct pqcp_adaptive_event events[PQCP_ADAPTIVE_MAX_EVENTS];
	char root_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_peer_report {
	uint32_t schema_version;
	uint64_t observed_at_ms;
	uint32_t confidence;
	uint32_t security_level;
	uint32_t resource_pressure;
	uint32_t threat_level;
	bool production_allowed;
	char device_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char recommendation_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_fleet_state {
	uint32_t schema_version;
	uint32_t peer_count;
	uint32_t accepted_count;
	uint32_t rejected_count;
	uint32_t quorum_percent;
	uint32_t distinct_profiles;
	uint32_t average_confidence;
	bool quorum_reached;
	char consensus_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	struct pqcp_adaptive_peer_report peers[PQCP_ADAPTIVE_MAX_PEERS];
	char fleet_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_snapshot {
	uint32_t schema_version;
	uint32_t byte_count;
	uint32_t record_count;
	uint32_t flags;
	char snapshot_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_control_input {
	uint64_t now_ms;
	const struct pqcp_adaptive_telemetry_sample *telemetry;
	const struct pqcp_adaptive_threat_signal *threat_signal;
	const struct pqcp_adaptive_resource_limits *resource_limits;
	const struct pqcp_adaptive_downgrade_authorization *authorization;
	const struct pqcp_adaptive_fleet_state *fleet;
	const struct pqcp_adaptive_health_signal *health;
	uint32_t required_operation_mask;
	enum pqcp_adaptive_transition_reason reason;
	bool force_recommendation;
	bool commit_transition;
};

struct pqcp_adaptive_control_result {
	uint32_t schema_version;
	enum pqcp_adaptive_status status;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	enum pqcp_adaptive_mode mode;
	enum pqcp_adaptive_threat_level threat_level;
	enum pqcp_adaptive_pressure resource_pressure;
	uint32_t confidence;
	bool recommendation_changed;
	bool transition_committed;
	bool downgrade_authorized;
	char active_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char recommended_profile_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	char control_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_adaptive_control_plane {
	uint32_t schema_version;
	char device_id[PQCP_ADAPTIVE_ID_MAX_CHARS];
	enum pqcp_adaptive_mode mode;
	struct pqcp_adaptive_profile_registry registry;
	struct pqcp_adaptive_policy policy;
	struct pqcp_adaptive_telemetry_window telemetry;
	struct pqcp_adaptive_telemetry_summary telemetry_summary;
	struct pqcp_adaptive_forecast forecast;
	struct pqcp_adaptive_threat_assessment threat;
	struct pqcp_adaptive_resource_assessment resources;
	struct pqcp_adaptive_recommendation recommendation;
	struct pqcp_adaptive_transition_controller transition;
	struct pqcp_adaptive_session_table sessions;
	struct pqcp_adaptive_workload_queue workload;
	struct pqcp_adaptive_resilience_state resilience;
	struct pqcp_adaptive_event_log events;
	uint32_t cycle_count;
	uint32_t failure_count;
	char state_digest_hex[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
};

const char *pqcp_adaptive_status_str(enum pqcp_adaptive_status status);
const char *pqcp_adaptive_mode_str(enum pqcp_adaptive_mode mode);
const char *pqcp_adaptive_pressure_str(enum pqcp_adaptive_pressure pressure);
const char *pqcp_adaptive_threat_level_str(
	enum pqcp_adaptive_threat_level level);
const char *pqcp_adaptive_transition_state_str(
	enum pqcp_adaptive_transition_state state);
const char *pqcp_adaptive_transition_reason_str(
	enum pqcp_adaptive_transition_reason reason);
const char *pqcp_adaptive_session_kind_str(
	enum pqcp_adaptive_session_kind kind);
const char *pqcp_adaptive_event_type_str(enum pqcp_adaptive_event_type type);

int pqcp_adaptive_profile_registry_init(
	struct pqcp_adaptive_profile_registry *registry);
int pqcp_adaptive_profile_registry_add(
	struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_profile *profile);
int pqcp_adaptive_profile_registry_remove(
	struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id);
int pqcp_adaptive_profile_registry_enable(
	struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id,
	bool enabled);
const struct pqcp_adaptive_profile *pqcp_adaptive_profile_registry_find(
	const struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id);
int pqcp_adaptive_profile_registry_default(
	struct pqcp_adaptive_profile_registry *registry);
int pqcp_adaptive_profile_registry_validate(
	const struct pqcp_adaptive_profile_registry *registry);
int pqcp_adaptive_profile_registry_emit(
	const struct pqcp_adaptive_profile_registry *registry);

int pqcp_adaptive_telemetry_init(
	struct pqcp_adaptive_telemetry_window *window);
int pqcp_adaptive_telemetry_push(
	struct pqcp_adaptive_telemetry_window *window,
	const struct pqcp_adaptive_telemetry_sample *sample);
int pqcp_adaptive_telemetry_summarize(
	const struct pqcp_adaptive_telemetry_window *window,
	const struct pqcp_adaptive_resource_limits *limits,
	struct pqcp_adaptive_telemetry_summary *summary);
int pqcp_adaptive_telemetry_reset(
	struct pqcp_adaptive_telemetry_window *window);
int pqcp_adaptive_telemetry_emit(
	const struct pqcp_adaptive_telemetry_summary *summary);

int pqcp_adaptive_forecast_default_policy(
	struct pqcp_adaptive_forecast_policy *policy);
int pqcp_adaptive_forecast_run(
	const struct pqcp_adaptive_telemetry_window *window,
	const struct pqcp_adaptive_telemetry_summary *summary,
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_forecast_policy *policy,
	struct pqcp_adaptive_forecast *forecast);
int pqcp_adaptive_forecast_emit(
	const struct pqcp_adaptive_forecast *forecast);

int pqcp_adaptive_threat_default_policy(
	struct pqcp_adaptive_threat_policy *policy);
int pqcp_adaptive_threat_assess(
	const struct pqcp_adaptive_threat_signal *signal,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_threat_policy *policy,
	struct pqcp_adaptive_threat_assessment *assessment);
int pqcp_adaptive_threat_emit(
	const struct pqcp_adaptive_threat_assessment *assessment);

int pqcp_adaptive_resource_assess(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment);
int pqcp_adaptive_resource_profile_fits(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_resource_assessment *assessment,
	const struct pqcp_adaptive_profile *profile,
	uint32_t *blocker_mask,
	uint32_t *minimum_headroom_permille);
int pqcp_adaptive_resource_emit(
	const struct pqcp_adaptive_resource_assessment *assessment);

int pqcp_adaptive_policy_default(
	enum pqcp_adaptive_policy_profile profile,
	struct pqcp_adaptive_policy *policy);
int pqcp_adaptive_policy_validate(
	const struct pqcp_adaptive_policy *policy);
int pqcp_adaptive_policy_merge(
	const struct pqcp_adaptive_policy *base,
	const struct pqcp_adaptive_policy *override_policy,
	uint32_t override_mask,
	struct pqcp_adaptive_policy *result);
int pqcp_adaptive_policy_emit(const struct pqcp_adaptive_policy *policy);

int pqcp_adaptive_optimizer_run(
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_threat_assessment *threat,
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_resource_assessment *resources,
	const struct pqcp_adaptive_forecast *forecast,
	const struct pqcp_adaptive_fleet_state *fleet,
	uint32_t required_operation_mask,
	const char *current_profile_id,
	struct pqcp_adaptive_recommendation *recommendation);
int pqcp_adaptive_optimizer_emit(
	const struct pqcp_adaptive_recommendation *recommendation);

int pqcp_adaptive_downgrade_authorization_build(
	const char *device_id,
	const struct pqcp_adaptive_profile *from,
	const struct pqcp_adaptive_profile *to,
	enum pqcp_adaptive_transition_reason reason,
	uint64_t issued_at_ms,
	uint64_t expires_at_ms,
	const char *nonce_hex,
	struct pqcp_adaptive_downgrade_authorization *authorization);
int pqcp_adaptive_downgrade_evaluate(
	const struct pqcp_adaptive_profile *from,
	const struct pqcp_adaptive_profile *to,
	enum pqcp_adaptive_transition_reason reason,
	uint64_t now_ms,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_threat_assessment *threat,
	struct pqcp_adaptive_downgrade_authorization *authorization,
	struct pqcp_adaptive_downgrade_result *result);
int pqcp_adaptive_downgrade_emit(
	const struct pqcp_adaptive_downgrade_result *result);

int pqcp_adaptive_transition_init(
	struct pqcp_adaptive_transition_controller *controller,
	const char *initial_profile_id,
	uint64_t now_ms);
int pqcp_adaptive_transition_request(
	struct pqcp_adaptive_transition_controller *controller,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_recommendation *recommendation,
	enum pqcp_adaptive_transition_reason reason,
	uint64_t now_ms,
	struct pqcp_adaptive_transition_result *result);
int pqcp_adaptive_transition_commit(
	struct pqcp_adaptive_transition_controller *controller,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_downgrade_result *downgrade,
	uint64_t now_ms,
	struct pqcp_adaptive_transition_result *result);
int pqcp_adaptive_transition_tick(
	struct pqcp_adaptive_transition_controller *controller,
	uint64_t now_ms);
int pqcp_adaptive_transition_rollback(
	struct pqcp_adaptive_transition_controller *controller,
	uint64_t now_ms,
	struct pqcp_adaptive_transition_result *result);
int pqcp_adaptive_transition_emit(
	const struct pqcp_adaptive_transition_result *result);

int pqcp_adaptive_session_table_init(
	struct pqcp_adaptive_session_table *table);
int pqcp_adaptive_session_plan(
	const struct pqcp_adaptive_session_request *request,
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_recommendation *recommendation,
	const struct pqcp_adaptive_transition_controller *transition,
	struct pqcp_adaptive_session_plan *plan);
int pqcp_adaptive_session_open(
	struct pqcp_adaptive_session_table *table,
	const struct pqcp_adaptive_session_plan *plan,
	enum pqcp_adaptive_session_kind kind,
	uint64_t opened_at_ms);
int pqcp_adaptive_session_close(
	struct pqcp_adaptive_session_table *table,
	uint64_t session_id);
int pqcp_adaptive_session_expire(
	struct pqcp_adaptive_session_table *table,
	uint64_t now_ms);
bool pqcp_adaptive_session_profile_busy(
	const struct pqcp_adaptive_session_table *table,
	const char *profile_id);
int pqcp_adaptive_session_emit(
	const struct pqcp_adaptive_session_plan *plan);

int pqcp_adaptive_workload_init(
	struct pqcp_adaptive_workload_queue *queue);
int pqcp_adaptive_workload_submit(
	struct pqcp_adaptive_workload_queue *queue,
	const struct pqcp_adaptive_workload_item *item);
int pqcp_adaptive_workload_cancel(
	struct pqcp_adaptive_workload_queue *queue,
	uint64_t request_id);
int pqcp_adaptive_workload_complete(
	struct pqcp_adaptive_workload_queue *queue,
	uint64_t request_id,
	bool success);
int pqcp_adaptive_workload_plan(
	struct pqcp_adaptive_workload_queue *queue,
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_recommendation *recommendation,
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_resource_assessment *resources,
	uint64_t now_ms,
	struct pqcp_adaptive_workload_plan *plan);
int pqcp_adaptive_workload_emit(
	const struct pqcp_adaptive_workload_queue *queue,
	const struct pqcp_adaptive_workload_plan *plan);

int pqcp_adaptive_resilience_default_policy(
	struct pqcp_adaptive_resilience_policy *policy);
int pqcp_adaptive_resilience_init(
	struct pqcp_adaptive_resilience_state *state);
int pqcp_adaptive_resilience_evaluate(
	struct pqcp_adaptive_resilience_state *state,
	const struct pqcp_adaptive_resilience_policy *policy,
	const struct pqcp_adaptive_health_signal *signal,
	const struct pqcp_adaptive_transition_controller *transition,
	const struct pqcp_adaptive_profile_registry *registry);
bool pqcp_adaptive_resilience_profile_allowed(
	const struct pqcp_adaptive_resilience_state *state,
	const struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id);
int pqcp_adaptive_resilience_emit(
	const struct pqcp_adaptive_resilience_state *state);

int pqcp_adaptive_calibration_init(
	struct pqcp_adaptive_calibration_table *table);
int pqcp_adaptive_calibration_observe(
	struct pqcp_adaptive_calibration_table *table,
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_calibration_observation *observation);
int pqcp_adaptive_calibration_reset_profile(
	struct pqcp_adaptive_calibration_table *table,
	const char *profile_id);
int pqcp_adaptive_calibration_apply(
	const struct pqcp_adaptive_calibration_table *table,
	const struct pqcp_adaptive_profile *profile,
	uint32_t minimum_confidence,
	struct pqcp_adaptive_profile *calibrated_profile);
int pqcp_adaptive_calibration_validate(
	const struct pqcp_adaptive_calibration_table *table,
	const struct pqcp_adaptive_profile_registry *registry);
int pqcp_adaptive_calibration_emit(
	const struct pqcp_adaptive_calibration_table *table);

int pqcp_adaptive_event_log_init(struct pqcp_adaptive_event_log *log);
int pqcp_adaptive_event_log_append(
	struct pqcp_adaptive_event_log *log,
	enum pqcp_adaptive_event_type type,
	enum pqcp_adaptive_status status,
	uint64_t timestamp_ms,
	uint32_t reason_mask,
	uint32_t blocker_mask,
	uint32_t warning_mask,
	uint32_t score,
	const char *profile_id,
	const char *related_id);
const struct pqcp_adaptive_event *pqcp_adaptive_event_log_get(
	const struct pqcp_adaptive_event_log *log,
	uint32_t logical_index);
int pqcp_adaptive_event_log_verify(
	const struct pqcp_adaptive_event_log *log);
int pqcp_adaptive_event_log_reseal(
	struct pqcp_adaptive_event_log *log);
int pqcp_adaptive_event_log_emit(
	const struct pqcp_adaptive_event_log *log);

int pqcp_adaptive_fleet_init(struct pqcp_adaptive_fleet_state *fleet);
int pqcp_adaptive_fleet_update(
	struct pqcp_adaptive_fleet_state *fleet,
	const struct pqcp_adaptive_peer_report *peer,
	uint64_t now_ms,
	uint64_t maximum_age_ms,
	uint32_t required_quorum_percent);
int pqcp_adaptive_fleet_remove_stale(
	struct pqcp_adaptive_fleet_state *fleet,
	uint64_t now_ms,
	uint64_t maximum_age_ms,
	uint32_t required_quorum_percent);
int pqcp_adaptive_fleet_emit(
	const struct pqcp_adaptive_fleet_state *fleet);

int pqcp_adaptive_snapshot_encode(
	const struct pqcp_adaptive_control_plane *control,
	uint8_t *buffer,
	size_t capacity,
	struct pqcp_adaptive_snapshot *snapshot);
int pqcp_adaptive_snapshot_decode(
	const uint8_t *buffer,
	size_t length,
	struct pqcp_adaptive_control_plane *control,
	struct pqcp_adaptive_snapshot *snapshot);
int pqcp_adaptive_snapshot_emit(
	const struct pqcp_adaptive_snapshot *snapshot);

int pqcp_adaptive_control_init(
	struct pqcp_adaptive_control_plane *control,
	const char *device_id,
	enum pqcp_adaptive_policy_profile policy_profile,
	const char *initial_profile_id,
	uint64_t now_ms);
int pqcp_adaptive_control_cycle(
	struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_input *input,
	struct pqcp_adaptive_control_result *result);
int pqcp_adaptive_control_emit(
	const struct pqcp_adaptive_control_plane *control,
	const struct pqcp_adaptive_control_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_ADAPTIVE_CONTROL_H_ */
