/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free zero-trust edge security plane.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_EDGE_SECURITY_H_
#define PQCP_ZEPHYR_EDGE_SECURITY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_resilience.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_EDGE_SCHEMA_VERSION 1U
#define PQCP_EDGE_DIGEST_BYTES 32U
#define PQCP_EDGE_ID_MAX_CHARS 48U
#define PQCP_EDGE_NAME_MAX_CHARS 48U
#define PQCP_EDGE_DOMAIN_MAX_CHARS 32U
#define PQCP_EDGE_ZONE_MAX_CHARS 24U
#define PQCP_EDGE_LABEL_MAX_CHARS 48U
#define PQCP_EDGE_REASON_MAX_CHARS 96U
#define PQCP_EDGE_ADDRESS_MAX_CHARS 64U
#define PQCP_EDGE_PATH_MAX_CHARS 96U
#define PQCP_EDGE_TOPIC_MAX_CHARS 64U
#define PQCP_EDGE_OBJECT_MAX_CHARS 64U
#define PQCP_EDGE_ACTOR_MAX_CHARS 48U
#define PQCP_EDGE_MESSAGE_ID_BYTES 16U
#define PQCP_EDGE_NONCE_BYTES 16U
#define PQCP_EDGE_KEY_BYTES 32U
#define PQCP_EDGE_TAG_BYTES 32U
#define PQCP_EDGE_MESSAGE_PAYLOAD_MAX_BYTES 512U
#define PQCP_EDGE_FRAGMENT_PAYLOAD_MAX_BYTES 256U
#define PQCP_EDGE_VAULT_VALUE_MAX_BYTES 1024U
#define PQCP_EDGE_EVIDENCE_MAX_BYTES 512U
#define PQCP_EDGE_REPORT_MAX_BYTES 2048U
#define PQCP_EDGE_MAX_ROUTE_HOPS 8U
#define PQCP_EDGE_MAX_POLICY_CONDITIONS 8U
#define PQCP_EDGE_MAX_GROUP_MEMBERS 32U
#define PQCP_EDGE_MAX_PLAYBOOK_STEPS 16U
#define PQCP_EDGE_MAX_INCIDENT_SIGNALS 16U
#define PQCP_EDGE_MAX_REPLICA_TARGETS 8U

#define PQCP_EDGE_OPERATION_BIT(operation) \
	(1ULL << (uint64_t)(operation))
#define PQCP_EDGE_CAPABILITY_BIT(capability) \
	(1ULL << (uint64_t)(capability))

enum pqcp_edge_operation {
	PQCP_EDGE_OPERATION_NONE = 0,
	PQCP_EDGE_OPERATION_DISCOVER,
	PQCP_EDGE_OPERATION_CONNECT,
	PQCP_EDGE_OPERATION_PUBLISH,
	PQCP_EDGE_OPERATION_SUBSCRIBE,
	PQCP_EDGE_OPERATION_READ,
	PQCP_EDGE_OPERATION_WRITE,
	PQCP_EDGE_OPERATION_DELETE,
	PQCP_EDGE_OPERATION_ROTATE,
	PQCP_EDGE_OPERATION_ATTEST,
	PQCP_EDGE_OPERATION_ADMINISTER,
	PQCP_EDGE_OPERATION_RECOVER,
	PQCP_EDGE_OPERATION_REPLICATE,
	PQCP_EDGE_OPERATION_COUNT,
};

enum pqcp_edge_capability {
	PQCP_EDGE_CAPABILITY_DISCOVERY = 0,
	PQCP_EDGE_CAPABILITY_MESH_CLIENT,
	PQCP_EDGE_CAPABILITY_MESH_SERVER,
	PQCP_EDGE_CAPABILITY_MESSAGE_PUBLISHER,
	PQCP_EDGE_CAPABILITY_MESSAGE_SUBSCRIBER,
	PQCP_EDGE_CAPABILITY_VAULT_READER,
	PQCP_EDGE_CAPABILITY_VAULT_WRITER,
	PQCP_EDGE_CAPABILITY_INCIDENT_OPERATOR,
	PQCP_EDGE_CAPABILITY_RECOVERY_OPERATOR,
	PQCP_EDGE_CAPABILITY_POLICY_ADMIN,
	PQCP_EDGE_CAPABILITY_REPLICA,
	PQCP_EDGE_CAPABILITY_AUDITOR,
	PQCP_EDGE_CAPABILITY_COUNT,
};

enum pqcp_edge_trust_level {
	PQCP_EDGE_TRUST_UNTRUSTED = 0,
	PQCP_EDGE_TRUST_OBSERVED,
	PQCP_EDGE_TRUST_AUTHENTICATED,
	PQCP_EDGE_TRUST_ATTESTED,
	PQCP_EDGE_TRUST_PRIVILEGED,
};

enum pqcp_edge_principal_state {
	PQCP_EDGE_PRINCIPAL_EMPTY = 0,
	PQCP_EDGE_PRINCIPAL_ACTIVE,
	PQCP_EDGE_PRINCIPAL_DEGRADED,
	PQCP_EDGE_PRINCIPAL_QUARANTINED,
	PQCP_EDGE_PRINCIPAL_REVOKED,
};

enum pqcp_edge_service_state {
	PQCP_EDGE_SERVICE_EMPTY = 0,
	PQCP_EDGE_SERVICE_REGISTERED,
	PQCP_EDGE_SERVICE_HEALTHY,
	PQCP_EDGE_SERVICE_DRAINING,
	PQCP_EDGE_SERVICE_UNAVAILABLE,
	PQCP_EDGE_SERVICE_RETIRED,
};

enum pqcp_edge_endpoint_state {
	PQCP_EDGE_ENDPOINT_EMPTY = 0,
	PQCP_EDGE_ENDPOINT_PROBING,
	PQCP_EDGE_ENDPOINT_READY,
	PQCP_EDGE_ENDPOINT_DEGRADED,
	PQCP_EDGE_ENDPOINT_EJECTED,
	PQCP_EDGE_ENDPOINT_DRAINING,
};

enum pqcp_edge_transport {
	PQCP_EDGE_TRANSPORT_NONE = 0,
	PQCP_EDGE_TRANSPORT_LOCAL,
	PQCP_EDGE_TRANSPORT_TCP,
	PQCP_EDGE_TRANSPORT_UDP,
	PQCP_EDGE_TRANSPORT_BLE,
	PQCP_EDGE_TRANSPORT_SERIAL,
	PQCP_EDGE_TRANSPORT_CAN,
};

enum pqcp_edge_policy_effect {
	PQCP_EDGE_POLICY_UNSET = 0,
	PQCP_EDGE_POLICY_ALLOW,
	PQCP_EDGE_POLICY_DENY,
	PQCP_EDGE_POLICY_CHALLENGE,
	PQCP_EDGE_POLICY_QUARANTINE,
};

enum pqcp_edge_policy_reason {
	PQCP_EDGE_POLICY_REASON_NONE = 0,
	PQCP_EDGE_POLICY_REASON_RULE,
	PQCP_EDGE_POLICY_REASON_DEFAULT,
	PQCP_EDGE_POLICY_REASON_PRINCIPAL,
	PQCP_EDGE_POLICY_REASON_SERVICE,
	PQCP_EDGE_POLICY_REASON_CAPABILITY,
	PQCP_EDGE_POLICY_REASON_TRUST,
	PQCP_EDGE_POLICY_REASON_ZONE,
	PQCP_EDGE_POLICY_REASON_TIME,
	PQCP_EDGE_POLICY_REASON_RISK,
	PQCP_EDGE_POLICY_REASON_QUOTA,
	PQCP_EDGE_POLICY_REASON_ATTESTATION,
	PQCP_EDGE_POLICY_REASON_REVOCATION,
};

enum pqcp_edge_route_strategy {
	PQCP_EDGE_ROUTE_LOWEST_LATENCY = 0,
	PQCP_EDGE_ROUTE_LEAST_LOADED,
	PQCP_EDGE_ROUTE_HIGHEST_TRUST,
	PQCP_EDGE_ROUTE_ZONE_AFFINITY,
	PQCP_EDGE_ROUTE_DETERMINISTIC,
};

enum pqcp_edge_session_state {
	PQCP_EDGE_SESSION_EMPTY = 0,
	PQCP_EDGE_SESSION_AUTHORIZING,
	PQCP_EDGE_SESSION_ACTIVE,
	PQCP_EDGE_SESSION_REKEY_REQUIRED,
	PQCP_EDGE_SESSION_DRAINING,
	PQCP_EDGE_SESSION_CLOSED,
	PQCP_EDGE_SESSION_FAILED,
};

enum pqcp_edge_circuit_state {
	PQCP_EDGE_CIRCUIT_CLOSED = 0,
	PQCP_EDGE_CIRCUIT_OPEN,
	PQCP_EDGE_CIRCUIT_HALF_OPEN,
	PQCP_EDGE_CIRCUIT_ISOLATED,
};

struct pqcp_edge_principal {
	uint32_t schema_version;
	uint32_t generation;
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	char tenant_id[PQCP_EDGE_ID_MAX_CHARS];
	char trust_domain[PQCP_EDGE_DOMAIN_MAX_CHARS];
	char zone[PQCP_EDGE_ZONE_MAX_CHARS];
	uint8_t identity_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t attestation_digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t capabilities;
	uint64_t credential_epoch;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t registered_at_ms;
	uint64_t last_seen_ms;
	uint64_t credential_expires_at_ms;
	uint64_t quarantine_until_ms;
	uint32_t risk_score;
	uint32_t active_sessions;
	uint32_t maximum_sessions;
	enum pqcp_edge_trust_level trust;
	enum pqcp_edge_principal_state state;
	bool channel_bound;
};

struct pqcp_edge_principal_directory {
	uint32_t schema_version;
	struct pqcp_edge_principal *principals;
	size_t capacity;
	uint32_t next_generation;
	uint64_t registration_count;
	uint64_t rejection_count;
	uint64_t revocation_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_service {
	uint32_t schema_version;
	uint32_t generation;
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	char service_name[PQCP_EDGE_NAME_MAX_CHARS];
	char owner_principal_id[PQCP_EDGE_ID_MAX_CHARS];
	char trust_domain[PQCP_EDGE_DOMAIN_MAX_CHARS];
	char zone[PQCP_EDGE_ZONE_MAX_CHARS];
	uint64_t required_capabilities;
	uint64_t operation_mask;
	uint64_t policy_epoch;
	uint64_t registered_at_ms;
	uint64_t lease_expires_at_ms;
	uint32_t endpoint_count;
	uint32_t minimum_trust;
	uint32_t maximum_risk;
	enum pqcp_edge_service_state state;
	bool require_attestation;
	bool require_channel_binding;
};

struct pqcp_edge_endpoint {
	uint32_t schema_version;
	uint32_t generation;
	char endpoint_id[PQCP_EDGE_ID_MAX_CHARS];
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	char address[PQCP_EDGE_ADDRESS_MAX_CHARS];
	char zone[PQCP_EDGE_ZONE_MAX_CHARS];
	enum pqcp_edge_transport transport;
	enum pqcp_edge_endpoint_state state;
	uint64_t registered_at_ms;
	uint64_t last_probe_ms;
	uint64_t lease_expires_at_ms;
	uint64_t ejected_until_ms;
	uint32_t priority;
	uint32_t weight;
	uint32_t active_requests;
	uint32_t maximum_requests;
	uint32_t consecutive_failures;
	uint32_t latency_ewma_us;
	uint32_t trust_score;
};

struct pqcp_edge_service_registry {
	uint32_t schema_version;
	struct pqcp_edge_service *services;
	size_t service_capacity;
	struct pqcp_edge_endpoint *endpoints;
	size_t endpoint_capacity;
	uint32_t next_service_generation;
	uint32_t next_endpoint_generation;
	uint64_t registration_count;
	uint64_t expiry_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_access_rule {
	uint32_t schema_version;
	uint32_t rule_id;
	uint32_t priority;
	char source_domain[PQCP_EDGE_DOMAIN_MAX_CHARS];
	char destination_domain[PQCP_EDGE_DOMAIN_MAX_CHARS];
	char source_zone[PQCP_EDGE_ZONE_MAX_CHARS];
	char destination_zone[PQCP_EDGE_ZONE_MAX_CHARS];
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t operation_mask;
	uint64_t required_capabilities;
	uint64_t forbidden_capabilities;
	uint64_t not_before_ms;
	uint64_t not_after_ms;
	uint32_t minimum_trust;
	uint32_t maximum_risk;
	uint32_t maximum_concurrent;
	enum pqcp_edge_policy_effect effect;
	bool require_attestation;
	bool require_channel_binding;
	bool enabled;
};

struct pqcp_edge_access_context {
	const struct pqcp_edge_principal *principal;
	const struct pqcp_edge_service *service;
	enum pqcp_edge_operation operation;
	char source_zone[PQCP_EDGE_ZONE_MAX_CHARS];
	char destination_zone[PQCP_EDGE_ZONE_MAX_CHARS];
	uint64_t now_ms;
	uint32_t current_concurrent;
	bool channel_identity_verified;
	bool attestation_fresh;
};

struct pqcp_edge_access_decision {
	enum pqcp_edge_policy_effect effect;
	enum pqcp_edge_policy_reason reason;
	uint32_t rule_id;
	uint32_t rule_priority;
	uint64_t missing_capabilities;
	uint64_t forbidden_capabilities;
	uint64_t retry_after_ms;
	char explanation[PQCP_EDGE_REASON_MAX_CHARS];
};

struct pqcp_edge_access_engine {
	uint32_t schema_version;
	struct pqcp_edge_access_rule *rules;
	size_t capacity;
	size_t count;
	enum pqcp_edge_policy_effect default_effect;
	uint64_t generation;
	uint64_t allow_count;
	uint64_t deny_count;
	uint64_t challenge_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_route_candidate {
	uint32_t endpoint_index;
	uint32_t score;
	uint32_t estimated_latency_us;
	uint32_t estimated_load_basis_points;
	uint32_t trust_score;
	bool eligible;
};

struct pqcp_edge_route {
	uint32_t schema_version;
	uint64_t route_id;
	char source_principal_id[PQCP_EDGE_ID_MAX_CHARS];
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	char endpoint_id[PQCP_EDGE_ID_MAX_CHARS];
	char source_zone[PQCP_EDGE_ZONE_MAX_CHARS];
	char destination_zone[PQCP_EDGE_ZONE_MAX_CHARS];
	enum pqcp_edge_route_strategy strategy;
	uint64_t selected_at_ms;
	uint64_t expires_at_ms;
	uint32_t score;
	uint32_t failover_count;
	uint8_t route_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_route_table {
	uint32_t schema_version;
	struct pqcp_edge_route *routes;
	size_t capacity;
	uint64_t next_route_id;
	uint64_t selection_count;
	uint64_t failover_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_session {
	uint32_t schema_version;
	uint64_t session_id;
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	char endpoint_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t opened_at_ms;
	uint64_t last_activity_ms;
	uint64_t expires_at_ms;
	uint64_t key_epoch;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t request_count;
	uint32_t failures;
	uint32_t maximum_failures;
	enum pqcp_edge_session_state state;
	uint8_t binding_digest[PQCP_EDGE_DIGEST_BYTES];
	bool mutually_authenticated;
	/* The principal's active_sessions quota slot was given back. */
	bool principal_released;
	bool occupied;
};

struct pqcp_edge_session_registry {
	uint32_t schema_version;
	struct pqcp_edge_session *sessions;
	size_t capacity;
	uint64_t next_session_id;
	uint64_t opened_count;
	uint64_t closed_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_traffic_policy {
	uint64_t request_rate_per_window;
	uint64_t byte_rate_per_window;
	uint64_t window_ms;
	uint32_t maximum_concurrent;
	uint32_t burst_requests;
	uint32_t failure_penalty;
	uint32_t recovery_credit;
};

struct pqcp_edge_traffic_subject {
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t window_started_ms;
	uint64_t request_tokens;
	uint64_t byte_tokens;
	uint64_t accepted_requests;
	uint64_t rejected_requests;
	uint64_t accepted_bytes;
	uint32_t concurrent;
	uint32_t failure_score;
	uint64_t blocked_until_ms;
	bool occupied;
};

struct pqcp_edge_traffic_governor {
	uint32_t schema_version;
	struct pqcp_edge_traffic_policy policy;
	struct pqcp_edge_traffic_subject *subjects;
	size_t capacity;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_circuit {
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	char endpoint_id[PQCP_EDGE_ID_MAX_CHARS];
	enum pqcp_edge_circuit_state state;
	uint64_t opened_at_ms;
	uint64_t retry_at_ms;
	uint64_t last_transition_ms;
	uint32_t consecutive_successes;
	uint32_t consecutive_failures;
	uint32_t half_open_attempts;
	uint32_t total_opens;
	bool occupied;
};

struct pqcp_edge_circuit_policy {
	uint32_t open_after_failures;
	uint32_t close_after_successes;
	uint32_t half_open_maximum;
	uint64_t base_retry_ms;
	uint64_t maximum_retry_ms;
};

struct pqcp_edge_circuit_breaker {
	uint32_t schema_version;
	struct pqcp_edge_circuit_policy policy;
	struct pqcp_edge_circuit *circuits;
	size_t capacity;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_message_state {
	PQCP_EDGE_MESSAGE_EMPTY = 0,
	PQCP_EDGE_MESSAGE_ACCEPTED,
	PQCP_EDGE_MESSAGE_QUEUED,
	PQCP_EDGE_MESSAGE_IN_FLIGHT,
	PQCP_EDGE_MESSAGE_ACKNOWLEDGED,
	PQCP_EDGE_MESSAGE_RETRY_WAIT,
	PQCP_EDGE_MESSAGE_DEAD_LETTER,
	PQCP_EDGE_MESSAGE_EXPIRED,
	PQCP_EDGE_MESSAGE_CANCELLED,
};

enum pqcp_edge_delivery_guarantee {
	PQCP_EDGE_DELIVERY_AT_MOST_ONCE = 0,
	PQCP_EDGE_DELIVERY_AT_LEAST_ONCE,
	PQCP_EDGE_DELIVERY_EFFECTIVELY_ONCE,
};

enum pqcp_edge_message_priority {
	PQCP_EDGE_MESSAGE_BACKGROUND = 0,
	PQCP_EDGE_MESSAGE_NORMAL,
	PQCP_EDGE_MESSAGE_HIGH,
	PQCP_EDGE_MESSAGE_CRITICAL,
};

struct pqcp_edge_message {
	uint32_t schema_version;
	uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES];
	char producer_id[PQCP_EDGE_ID_MAX_CHARS];
	char consumer_id[PQCP_EDGE_ID_MAX_CHARS];
	char topic[PQCP_EDGE_TOPIC_MAX_CHARS];
	uint64_t producer_epoch;
	uint64_t sequence;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint64_t not_before_ms;
	uint32_t attempt_count;
	uint32_t maximum_attempts;
	enum pqcp_edge_message_priority priority;
	enum pqcp_edge_delivery_guarantee guarantee;
	enum pqcp_edge_message_state state;
	uint8_t payload[PQCP_EDGE_MESSAGE_PAYLOAD_MAX_BYTES];
	size_t payload_length;
	uint8_t payload_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t message_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t authentication_tag[PQCP_EDGE_TAG_BYTES];
	bool encrypted;
	bool occupied;
};

struct pqcp_edge_message_queue {
	uint32_t schema_version;
	struct pqcp_edge_message *messages;
	size_t capacity;
	uint64_t accepted_count;
	uint64_t acknowledged_count;
	uint64_t retried_count;
	uint64_t dead_letter_count;
	uint64_t expired_count;
	uint8_t chain_head[PQCP_EDGE_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_replay_entry {
	char producer_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t epoch;
	uint64_t highest_sequence;
	uint64_t window_bits;
	uint64_t updated_at_ms;
	bool occupied;
};

struct pqcp_edge_replay_guard {
	uint32_t schema_version;
	struct pqcp_edge_replay_entry *entries;
	size_t capacity;
	uint32_t window_size;
	uint64_t accepted_count;
	uint64_t replay_count;
	uint64_t stale_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_fragment {
	uint32_t schema_version;
	uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES];
	uint16_t fragment_index;
	uint16_t fragment_count;
	uint32_t total_length;
	uint32_t offset;
	uint8_t payload[PQCP_EDGE_FRAGMENT_PAYLOAD_MAX_BYTES];
	size_t payload_length;
	uint8_t payload_digest[PQCP_EDGE_DIGEST_BYTES];
};

struct pqcp_edge_reassembly {
	uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES];
	uint8_t *output;
	size_t output_capacity;
	size_t total_length;
	uint64_t received_bitmap;
	uint16_t fragment_count;
	uint16_t received_count;
	uint64_t expires_at_ms;
	bool occupied;
};

struct pqcp_edge_fragment_manager {
	uint32_t schema_version;
	struct pqcp_edge_reassembly *assemblies;
	size_t capacity;
	uint64_t completed_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_ratchet {
	uint32_t schema_version;
	char peer_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t send_epoch;
	uint64_t receive_epoch;
	uint64_t send_sequence;
	uint64_t receive_sequence;
	uint8_t send_chain_key[PQCP_EDGE_KEY_BYTES];
	uint8_t receive_chain_key[PQCP_EDGE_KEY_BYTES];
	uint8_t root_digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t last_rotated_ms;
	uint32_t skipped_messages;
	bool initiator;
	bool initialized;
};

struct pqcp_edge_topic {
	uint32_t schema_version;
	uint32_t generation;
	char topic[PQCP_EDGE_TOPIC_MAX_CHARS];
	char owner_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t publish_capabilities;
	uint64_t subscribe_capabilities;
	uint64_t retention_ms;
	uint32_t maximum_payload;
	uint32_t maximum_subscribers;
	uint32_t active_subscribers;
	uint64_t published_count;
	uint64_t delivered_count;
	bool encrypted;
	bool durable;
	bool occupied;
};

struct pqcp_edge_subscription {
	uint32_t schema_version;
	uint64_t subscription_id;
	char topic[PQCP_EDGE_TOPIC_MAX_CHARS];
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint64_t last_acknowledged_sequence;
	uint32_t inflight;
	uint32_t maximum_inflight;
	bool paused;
	bool occupied;
};

struct pqcp_edge_topic_registry {
	uint32_t schema_version;
	struct pqcp_edge_topic *topics;
	size_t topic_capacity;
	struct pqcp_edge_subscription *subscriptions;
	size_t subscription_capacity;
	uint32_t next_topic_generation;
	uint64_t next_subscription_id;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_group_member {
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t joined_epoch;
	uint64_t removed_epoch;
	uint64_t capabilities;
	bool active;
};

struct pqcp_edge_group {
	uint32_t schema_version;
	uint32_t generation;
	char group_id[PQCP_EDGE_ID_MAX_CHARS];
	char owner_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t epoch;
	uint64_t created_at_ms;
	uint64_t rotated_at_ms;
	uint8_t key_digest[PQCP_EDGE_DIGEST_BYTES];
	struct pqcp_edge_group_member members[
		PQCP_EDGE_MAX_GROUP_MEMBERS];
	uint32_t member_count;
	bool occupied;
};

struct pqcp_edge_group_manager {
	uint32_t schema_version;
	struct pqcp_edge_group *groups;
	size_t capacity;
	uint32_t next_generation;
	uint64_t membership_changes;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_delivery {
	uint32_t schema_version;
	uint64_t delivery_id;
	uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES];
	uint64_t subscription_id;
	uint64_t dispatched_at_ms;
	uint64_t deadline_ms;
	uint64_t retry_at_ms;
	uint32_t attempts;
	uint32_t maximum_attempts;
	int result;
	enum pqcp_edge_message_state state;
	bool occupied;
};

struct pqcp_edge_delivery_manager {
	uint32_t schema_version;
	struct pqcp_edge_delivery *deliveries;
	size_t capacity;
	uint64_t next_delivery_id;
	uint64_t dispatch_count;
	uint64_t success_count;
	uint64_t failure_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_vault_object_state {
	PQCP_EDGE_VAULT_EMPTY = 0,
	PQCP_EDGE_VAULT_ACTIVE,
	PQCP_EDGE_VAULT_SEALED,
	PQCP_EDGE_VAULT_TOMBSTONED,
	PQCP_EDGE_VAULT_QUARANTINED,
};

enum pqcp_edge_vault_permission {
	PQCP_EDGE_VAULT_PERMISSION_READ = (1U << 0),
	PQCP_EDGE_VAULT_PERMISSION_WRITE = (1U << 1),
	PQCP_EDGE_VAULT_PERMISSION_DELETE = (1U << 2),
	PQCP_EDGE_VAULT_PERMISSION_ROTATE = (1U << 3),
	PQCP_EDGE_VAULT_PERMISSION_SHARE = (1U << 4),
	PQCP_EDGE_VAULT_PERMISSION_REPLICATE = (1U << 5),
	PQCP_EDGE_VAULT_PERMISSION_AUDIT = (1U << 6),
};

struct pqcp_edge_vault_object {
	uint32_t schema_version;
	uint32_t generation;
	char object_id[PQCP_EDGE_OBJECT_MAX_CHARS];
	char namespace_id[PQCP_EDGE_ID_MAX_CHARS];
	char owner_id[PQCP_EDGE_ID_MAX_CHARS];
	char classification[PQCP_EDGE_LABEL_MAX_CHARS];
	uint64_t version;
	uint64_t created_at_ms;
	uint64_t updated_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint32_t permissions;
	enum pqcp_edge_vault_object_state state;
	uint8_t value[PQCP_EDGE_VAULT_VALUE_MAX_BYTES];
	size_t value_length;
	uint8_t value_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t object_digest[PQCP_EDGE_DIGEST_BYTES];
	bool encrypted;
	bool occupied;
};

struct pqcp_edge_vault_store {
	uint32_t schema_version;
	struct pqcp_edge_vault_object *objects;
	size_t capacity;
	uint32_t next_generation;
	uint64_t create_count;
	uint64_t update_count;
	uint64_t delete_count;
	uint64_t rejection_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_vault_acl_entry {
	uint32_t schema_version;
	uint32_t generation;
	char object_id[PQCP_EDGE_OBJECT_MAX_CHARS];
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	uint32_t permissions;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint64_t maximum_uses;
	uint64_t use_count;
	uint32_t maximum_risk;
	enum pqcp_edge_trust_level minimum_trust;
	bool require_attestation;
	bool occupied;
};

struct pqcp_edge_vault_acl {
	uint32_t schema_version;
	struct pqcp_edge_vault_acl_entry *entries;
	size_t capacity;
	uint32_t next_generation;
	uint64_t allow_count;
	uint64_t deny_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_vault_version {
	uint32_t schema_version;
	uint64_t version_id;
	char object_id[PQCP_EDGE_OBJECT_MAX_CHARS];
	uint64_t object_version;
	uint64_t created_at_ms;
	uint64_t expires_at_ms;
	uint8_t value[PQCP_EDGE_VAULT_VALUE_MAX_BYTES];
	size_t value_length;
	uint8_t value_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_vault_version_store {
	uint32_t schema_version;
	struct pqcp_edge_vault_version *versions;
	size_t capacity;
	uint64_t next_version_id;
	uint64_t captured_count;
	uint64_t pruned_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_vault_journal_event {
	PQCP_EDGE_VAULT_JOURNAL_CREATE = 0,
	PQCP_EDGE_VAULT_JOURNAL_UPDATE,
	PQCP_EDGE_VAULT_JOURNAL_READ,
	PQCP_EDGE_VAULT_JOURNAL_DELETE,
	PQCP_EDGE_VAULT_JOURNAL_ACL_CHANGE,
	PQCP_EDGE_VAULT_JOURNAL_LEASE,
	PQCP_EDGE_VAULT_JOURNAL_REPLICATION,
	PQCP_EDGE_VAULT_JOURNAL_SNAPSHOT,
	PQCP_EDGE_VAULT_JOURNAL_INTEGRITY_FAILURE,
};

struct pqcp_edge_vault_journal_entry {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t timestamp_ms;
	char object_id[PQCP_EDGE_OBJECT_MAX_CHARS];
	char actor_id[PQCP_EDGE_ACTOR_MAX_CHARS];
	enum pqcp_edge_vault_journal_event event;
	int result;
	uint8_t payload_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t entry_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_vault_journal {
	uint32_t schema_version;
	struct pqcp_edge_vault_journal_entry *entries;
	size_t capacity;
	size_t next_index;
	size_t count;
	uint64_t next_sequence;
	uint8_t chain_head[PQCP_EDGE_DIGEST_BYTES];
	uint64_t dropped_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_vault_lease {
	uint32_t schema_version;
	uint64_t lease_id;
	char object_id[PQCP_EDGE_OBJECT_MAX_CHARS];
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	uint32_t permissions;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t maximum_uses;
	uint64_t use_count;
	uint64_t policy_epoch;
	uint8_t lease_digest[PQCP_EDGE_DIGEST_BYTES];
	bool revoked;
	bool occupied;
};

struct pqcp_edge_vault_lease_manager {
	uint32_t schema_version;
	struct pqcp_edge_vault_lease *leases;
	size_t capacity;
	uint64_t next_lease_id;
	uint64_t issued_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_replica_state {
	PQCP_EDGE_REPLICA_EMPTY = 0,
	PQCP_EDGE_REPLICA_PENDING,
	PQCP_EDGE_REPLICA_TRANSFERRING,
	PQCP_EDGE_REPLICA_APPLIED,
	PQCP_EDGE_REPLICA_CONFLICT,
	PQCP_EDGE_REPLICA_FAILED,
};

struct pqcp_edge_replica_record {
	uint32_t schema_version;
	uint64_t replication_id;
	char object_id[PQCP_EDGE_OBJECT_MAX_CHARS];
	char target_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t object_version;
	uint64_t scheduled_at_ms;
	uint64_t completed_at_ms;
	uint64_t retry_at_ms;
	uint32_t attempts;
	uint32_t maximum_attempts;
	enum pqcp_edge_replica_state state;
	uint8_t object_digest[PQCP_EDGE_DIGEST_BYTES];
	int result;
	bool occupied;
};

struct pqcp_edge_replication_manager {
	uint32_t schema_version;
	struct pqcp_edge_replica_record *records;
	size_t capacity;
	uint64_t next_replication_id;
	uint64_t success_count;
	uint64_t failure_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_vault_snapshot {
	uint32_t schema_version;
	uint64_t snapshot_id;
	uint64_t created_at_ms;
	uint64_t object_count;
	uint64_t highest_object_version;
	uint8_t store_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t journal_head[PQCP_EDGE_DIGEST_BYTES];
	uint8_t snapshot_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_snapshot_manager {
	uint32_t schema_version;
	struct pqcp_edge_vault_snapshot *snapshots;
	size_t capacity;
	uint64_t next_snapshot_id;
	uint64_t captured_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_signal_type {
	PQCP_EDGE_SIGNAL_AUTHENTICATION_FAILURE = 0,
	PQCP_EDGE_SIGNAL_AUTHORIZATION_FAILURE,
	PQCP_EDGE_SIGNAL_REPLAY,
	PQCP_EDGE_SIGNAL_INTEGRITY_FAILURE,
	PQCP_EDGE_SIGNAL_KEY_FAILURE,
	PQCP_EDGE_SIGNAL_STORAGE_FAILURE,
	PQCP_EDGE_SIGNAL_ROUTE_ANOMALY,
	PQCP_EDGE_SIGNAL_TRAFFIC_ANOMALY,
	PQCP_EDGE_SIGNAL_ATTESTATION_FAILURE,
	PQCP_EDGE_SIGNAL_POLICY_VIOLATION,
	PQCP_EDGE_SIGNAL_UPDATE_FAILURE,
	PQCP_EDGE_SIGNAL_OPERATOR_ALERT,
	PQCP_EDGE_SIGNAL_COUNT,
};

enum pqcp_edge_incident_severity {
	PQCP_EDGE_INCIDENT_INFORMATIONAL = 0,
	PQCP_EDGE_INCIDENT_LOW,
	PQCP_EDGE_INCIDENT_MEDIUM,
	PQCP_EDGE_INCIDENT_HIGH,
	PQCP_EDGE_INCIDENT_CRITICAL,
};

enum pqcp_edge_incident_state {
	PQCP_EDGE_INCIDENT_EMPTY = 0,
	PQCP_EDGE_INCIDENT_OPEN,
	PQCP_EDGE_INCIDENT_TRIAGED,
	PQCP_EDGE_INCIDENT_CONTAINING,
	PQCP_EDGE_INCIDENT_REMEDIATING,
	PQCP_EDGE_INCIDENT_MONITORING,
	PQCP_EDGE_INCIDENT_RESOLVED,
	PQCP_EDGE_INCIDENT_CLOSED,
};

struct pqcp_edge_signal {
	uint32_t schema_version;
	uint64_t signal_id;
	enum pqcp_edge_signal_type type;
	enum pqcp_edge_incident_severity severity;
	char source_id[PQCP_EDGE_ID_MAX_CHARS];
	char subject_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t observed_at_ms;
	uint64_t policy_epoch;
	uint32_t magnitude;
	uint32_t confidence;
	uint8_t evidence_digest[PQCP_EDGE_DIGEST_BYTES];
	bool acknowledged;
	bool occupied;
};

struct pqcp_edge_signal_engine {
	uint32_t schema_version;
	struct pqcp_edge_signal *signals;
	size_t capacity;
	uint64_t next_signal_id;
	uint64_t accepted_count;
	uint64_t correlated_count;
	uint64_t dropped_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_incident {
	uint32_t schema_version;
	uint64_t incident_id;
	enum pqcp_edge_incident_severity severity;
	enum pqcp_edge_incident_state state;
	char title[PQCP_EDGE_REASON_MAX_CHARS];
	char subject_id[PQCP_EDGE_ID_MAX_CHARS];
	char owner_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t opened_at_ms;
	uint64_t updated_at_ms;
	uint64_t resolved_at_ms;
	uint64_t signal_ids[PQCP_EDGE_MAX_INCIDENT_SIGNALS];
	uint32_t signal_count;
	uint32_t risk_score;
	uint32_t containment_mask;
	uint32_t remediation_mask;
	uint8_t incident_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_incident_manager {
	uint32_t schema_version;
	struct pqcp_edge_incident *incidents;
	size_t capacity;
	uint64_t next_incident_id;
	uint64_t opened_count;
	uint64_t resolved_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_playbook_action {
	PQCP_EDGE_PLAYBOOK_NONE = 0,
	PQCP_EDGE_PLAYBOOK_BLOCK_PRINCIPAL,
	PQCP_EDGE_PLAYBOOK_EJECT_ENDPOINT,
	PQCP_EDGE_PLAYBOOK_REVOKE_LEASES,
	PQCP_EDGE_PLAYBOOK_ROTATE_KEYS,
	PQCP_EDGE_PLAYBOOK_SEAL_OBJECTS,
	PQCP_EDGE_PLAYBOOK_CAPTURE_EVIDENCE,
	PQCP_EDGE_PLAYBOOK_ENTER_RECOVERY,
	PQCP_EDGE_PLAYBOOK_NOTIFY_OPERATOR,
	PQCP_EDGE_PLAYBOOK_RESTORE_SERVICE,
	PQCP_EDGE_PLAYBOOK_VERIFY_INTEGRITY,
};

enum pqcp_edge_playbook_step_state {
	PQCP_EDGE_PLAYBOOK_STEP_PENDING = 0,
	PQCP_EDGE_PLAYBOOK_STEP_READY,
	PQCP_EDGE_PLAYBOOK_STEP_RUNNING,
	PQCP_EDGE_PLAYBOOK_STEP_SUCCEEDED,
	PQCP_EDGE_PLAYBOOK_STEP_FAILED,
	PQCP_EDGE_PLAYBOOK_STEP_SKIPPED,
};

struct pqcp_edge_playbook_step {
	uint32_t step_id;
	enum pqcp_edge_playbook_action action;
	enum pqcp_edge_playbook_step_state state;
	uint32_t dependency_mask;
	uint32_t maximum_attempts;
	uint32_t attempts;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	uint64_t retry_at_ms;
	int result;
	bool mandatory;
};

struct pqcp_edge_playbook {
	uint32_t schema_version;
	uint64_t execution_id;
	uint64_t incident_id;
	uint64_t started_at_ms;
	uint64_t completed_at_ms;
	struct pqcp_edge_playbook_step steps[
		PQCP_EDGE_MAX_PLAYBOOK_STEPS];
	uint32_t step_count;
	uint32_t completed_mask;
	uint32_t failed_mask;
	bool active;
	bool occupied;
};

struct pqcp_edge_playbook_engine {
	uint32_t schema_version;
	struct pqcp_edge_playbook *playbooks;
	size_t capacity;
	uint64_t next_execution_id;
	uint64_t completed_count;
	uint64_t failed_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_evidence {
	uint32_t schema_version;
	uint64_t evidence_id;
	uint64_t incident_id;
	char source_id[PQCP_EDGE_ID_MAX_CHARS];
	char classification[PQCP_EDGE_LABEL_MAX_CHARS];
	uint64_t captured_at_ms;
	uint64_t expires_at_ms;
	uint8_t payload[PQCP_EDGE_EVIDENCE_MAX_BYTES];
	size_t payload_length;
	uint8_t payload_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_EDGE_DIGEST_BYTES];
	bool sealed;
	bool occupied;
};

struct pqcp_edge_evidence_store {
	uint32_t schema_version;
	struct pqcp_edge_evidence *evidence;
	size_t capacity;
	uint64_t next_evidence_id;
	uint8_t chain_head[PQCP_EDGE_DIGEST_BYTES];
	uint64_t capture_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_containment {
	uint32_t schema_version;
	uint64_t containment_id;
	uint64_t incident_id;
	char subject_id[PQCP_EDGE_ID_MAX_CHARS];
	uint32_t action_mask;
	uint64_t applied_at_ms;
	uint64_t expires_at_ms;
	uint64_t released_at_ms;
	uint32_t applied_mask;
	uint32_t failed_mask;
	bool active;
	bool occupied;
};

struct pqcp_edge_containment_manager {
	uint32_t schema_version;
	struct pqcp_edge_containment *records;
	size_t capacity;
	uint64_t next_containment_id;
	uint64_t applied_count;
	uint64_t released_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_continuity_mode {
	PQCP_EDGE_CONTINUITY_NORMAL = 0,
	PQCP_EDGE_CONTINUITY_DEGRADED,
	PQCP_EDGE_CONTINUITY_ISOLATED,
	PQCP_EDGE_CONTINUITY_RECOVERY,
	PQCP_EDGE_CONTINUITY_FAILSAFE,
};

struct pqcp_edge_continuity_service {
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	enum pqcp_edge_continuity_mode mode;
	uint64_t entered_at_ms;
	uint64_t maximum_duration_ms;
	uint32_t minimum_endpoints;
	uint32_t available_endpoints;
	uint32_t priority;
	uint64_t dependency_mask;
	uint64_t satisfied_dependencies;
	/* Mode is held by an operator override or a latched FAILSAFE
	 * escalation; observe/evaluate must not re-derive it.
	 */
	bool mode_pinned;
	bool occupied;
};

struct pqcp_edge_continuity_manager {
	uint32_t schema_version;
	struct pqcp_edge_continuity_service *services;
	size_t capacity;
	enum pqcp_edge_continuity_mode global_mode;
	uint64_t transition_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_posture_signal {
	PQCP_EDGE_POSTURE_SECURE_BOOT = 0,
	PQCP_EDGE_POSTURE_DEBUG_LOCKED,
	PQCP_EDGE_POSTURE_FIRMWARE_CURRENT,
	PQCP_EDGE_POSTURE_POLICY_CURRENT,
	PQCP_EDGE_POSTURE_REVOCATION_CURRENT,
	PQCP_EDGE_POSTURE_STORAGE_INTEGRITY,
	PQCP_EDGE_POSTURE_TIME_TRUSTED,
	PQCP_EDGE_POSTURE_ENTROPY_HEALTHY,
	PQCP_EDGE_POSTURE_CHANNEL_BOUND,
	PQCP_EDGE_POSTURE_KEY_CUSTODY,
	PQCP_EDGE_POSTURE_SIGNAL_COUNT,
};

struct pqcp_edge_posture_report {
	uint32_t schema_version;
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t measured_at_ms;
	uint64_t expires_at_ms;
	uint64_t policy_epoch;
	uint64_t firmware_version;
	uint32_t signal_mask;
	uint32_t failure_mask;
	uint32_t risk_score;
	uint8_t measurement_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_posture_policy {
	uint32_t required_signal_mask;
	uint32_t quarantine_failure_mask;
	uint32_t challenge_failure_mask;
	uint32_t maximum_risk;
	uint64_t minimum_policy_epoch;
	uint64_t minimum_firmware_version;
	uint64_t maximum_age_ms;
};

struct pqcp_edge_posture_engine {
	uint32_t schema_version;
	struct pqcp_edge_posture_policy policy;
	struct pqcp_edge_posture_report *reports;
	size_t capacity;
	uint64_t accepted_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_attestation_state {
	PQCP_EDGE_ATTESTATION_EMPTY = 0,
	PQCP_EDGE_ATTESTATION_CHALLENGED,
	PQCP_EDGE_ATTESTATION_RECEIVED,
	PQCP_EDGE_ATTESTATION_VERIFIED,
	PQCP_EDGE_ATTESTATION_REJECTED,
	PQCP_EDGE_ATTESTATION_EXPIRED,
};

struct pqcp_edge_attestation_record {
	uint32_t schema_version;
	uint64_t challenge_id;
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	uint8_t nonce[PQCP_EDGE_NONCE_BYTES];
	uint8_t expected_binding[PQCP_EDGE_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t verified_at_ms;
	uint32_t required_posture_mask;
	uint32_t observed_posture_mask;
	enum pqcp_edge_attestation_state state;
	bool occupied;
};

struct pqcp_edge_attestation_manager {
	uint32_t schema_version;
	struct pqcp_edge_attestation_record *records;
	size_t capacity;
	uint64_t next_challenge_id;
	uint64_t verified_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_policy_stage {
	PQCP_EDGE_POLICY_STAGE_EMPTY = 0,
	PQCP_EDGE_POLICY_STAGE_DRAFT,
	PQCP_EDGE_POLICY_STAGE_STAGED,
	PQCP_EDGE_POLICY_STAGE_CANARY,
	PQCP_EDGE_POLICY_STAGE_PROMOTED,
	PQCP_EDGE_POLICY_STAGE_ACTIVE,
	PQCP_EDGE_POLICY_STAGE_ROLLBACK,
	PQCP_EDGE_POLICY_STAGE_RETIRED,
};

struct pqcp_edge_policy_bundle {
	uint32_t schema_version;
	uint64_t bundle_id;
	uint64_t policy_epoch;
	uint64_t previous_epoch;
	uint64_t created_at_ms;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint32_t required_acks;
	uint32_t received_acks;
	uint32_t failure_count;
	uint32_t maximum_failures;
	enum pqcp_edge_policy_stage stage;
	uint8_t content_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t bundle_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_policy_ack {
	uint64_t bundle_id;
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t acknowledged_at_ms;
	uint8_t applied_digest[PQCP_EDGE_DIGEST_BYTES];
	int result;
	bool occupied;
};

struct pqcp_edge_policy_distributor {
	uint32_t schema_version;
	struct pqcp_edge_policy_bundle *bundles;
	size_t bundle_capacity;
	struct pqcp_edge_policy_ack *acks;
	size_t ack_capacity;
	uint64_t next_bundle_id;
	uint64_t active_policy_epoch;
	uint8_t active_digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t promotion_count;
	uint64_t rollback_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_rotation_state {
	PQCP_EDGE_ROTATION_EMPTY = 0,
	PQCP_EDGE_ROTATION_PLANNED,
	PQCP_EDGE_ROTATION_GENERATING,
	PQCP_EDGE_ROTATION_DISTRIBUTING,
	PQCP_EDGE_ROTATION_OVERLAP,
	PQCP_EDGE_ROTATION_RETIRING,
	PQCP_EDGE_ROTATION_COMPLETED,
	PQCP_EDGE_ROTATION_FAILED,
};

struct pqcp_edge_secret_rotation {
	uint32_t schema_version;
	uint64_t rotation_id;
	char secret_id[PQCP_EDGE_OBJECT_MAX_CHARS];
	uint64_t current_epoch;
	uint64_t target_epoch;
	uint64_t started_at_ms;
	uint64_t overlap_until_ms;
	uint64_t deadline_ms;
	uint32_t target_count;
	uint32_t acknowledged_count;
	uint32_t failure_count;
	uint32_t maximum_failures;
	enum pqcp_edge_rotation_state state;
	uint8_t current_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t target_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_rotation_manager {
	uint32_t schema_version;
	struct pqcp_edge_secret_rotation *rotations;
	size_t capacity;
	uint64_t next_rotation_id;
	uint64_t completed_count;
	uint64_t failed_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_metric_type {
	PQCP_EDGE_METRIC_LATENCY_US = 0,
	PQCP_EDGE_METRIC_REQUEST_RATE,
	PQCP_EDGE_METRIC_ERROR_RATE,
	PQCP_EDGE_METRIC_BYTE_RATE,
	PQCP_EDGE_METRIC_AUTH_FAILURE_RATE,
	PQCP_EDGE_METRIC_REPLAY_RATE,
	PQCP_EDGE_METRIC_STORAGE_PRESSURE,
	PQCP_EDGE_METRIC_MEMORY_PRESSURE,
	PQCP_EDGE_METRIC_ENTROPY_FAILURE_RATE,
	PQCP_EDGE_METRIC_COUNT,
};

struct pqcp_edge_anomaly_baseline {
	char subject_id[PQCP_EDGE_ID_MAX_CHARS];
	enum pqcp_edge_metric_type metric;
	uint64_t sample_count;
	uint64_t mean;
	uint64_t deviation;
	uint64_t minimum;
	uint64_t maximum;
	uint64_t last_value;
	uint64_t last_observed_ms;
	uint32_t sensitivity_basis_points;
	bool occupied;
};

struct pqcp_edge_anomaly_result {
	bool anomalous;
	uint32_t severity;
	uint64_t distance;
	uint64_t threshold;
	uint64_t expected;
};

struct pqcp_edge_anomaly_engine {
	uint32_t schema_version;
	struct pqcp_edge_anomaly_baseline *baselines;
	size_t capacity;
	uint64_t observation_count;
	uint64_t anomaly_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_resource_type {
	PQCP_EDGE_RESOURCE_MEMORY_BYTES = 0,
	PQCP_EDGE_RESOURCE_STORAGE_BYTES,
	PQCP_EDGE_RESOURCE_CPU_US,
	PQCP_EDGE_RESOURCE_NETWORK_BYTES,
	PQCP_EDGE_RESOURCE_CRYPTO_OPS,
	PQCP_EDGE_RESOURCE_QUEUE_SLOTS,
	PQCP_EDGE_RESOURCE_COUNT,
};

enum pqcp_edge_resource_action {
	PQCP_EDGE_RESOURCE_ACTION_NONE = 0,
	PQCP_EDGE_RESOURCE_ACTION_THROTTLE,
	PQCP_EDGE_RESOURCE_ACTION_SHED,
	PQCP_EDGE_RESOURCE_ACTION_COMPACT,
	PQCP_EDGE_RESOURCE_ACTION_ISOLATE,
};

struct pqcp_edge_resource_budget {
	char subject_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t limit[PQCP_EDGE_RESOURCE_COUNT];
	uint64_t warning[PQCP_EDGE_RESOURCE_COUNT];
	uint64_t used[PQCP_EDGE_RESOURCE_COUNT];
	uint64_t window_started_ms;
	uint64_t window_ms;
	uint64_t violation_count;
	enum pqcp_edge_resource_action action;
	bool occupied;
};

struct pqcp_edge_resource_monitor {
	uint32_t schema_version;
	struct pqcp_edge_resource_budget *budgets;
	size_t capacity;
	uint64_t accounting_count;
	uint64_t denial_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_export_cursor {
	uint64_t cursor_id;
	uint64_t next_sequence;
	uint64_t acknowledged_sequence;
	uint64_t expires_at_ms;
	char consumer_id[PQCP_EDGE_ID_MAX_CHARS];
	bool occupied;
};

struct pqcp_edge_export_batch {
	uint64_t cursor_id;
	uint64_t first_sequence;
	uint64_t last_sequence;
	uint32_t record_count;
	uint8_t batch_digest[PQCP_EDGE_DIGEST_BYTES];
};

struct pqcp_edge_audit_exporter {
	uint32_t schema_version;
	struct pqcp_edge_export_cursor *cursors;
	size_t capacity;
	uint64_t next_cursor_id;
	uint64_t exported_records;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_recovery_phase {
	PQCP_EDGE_RECOVERY_IDLE = 0,
	PQCP_EDGE_RECOVERY_AUTHORIZED,
	PQCP_EDGE_RECOVERY_CHECKPOINTING,
	PQCP_EDGE_RECOVERY_ISOLATING,
	PQCP_EDGE_RECOVERY_RESTORING,
	PQCP_EDGE_RECOVERY_VALIDATING,
	PQCP_EDGE_RECOVERY_REJOINING,
	PQCP_EDGE_RECOVERY_COMPLETE,
	PQCP_EDGE_RECOVERY_FAILED,
};

struct pqcp_edge_recovery_plan {
	uint32_t schema_version;
	uint64_t recovery_id;
	uint64_t incident_id;
	char subject_id[PQCP_EDGE_ID_MAX_CHARS];
	enum pqcp_edge_recovery_phase phase;
	uint64_t authorized_at_ms;
	uint64_t expires_at_ms;
	uint64_t updated_at_ms;
	uint32_t required_steps;
	uint32_t completed_steps;
	uint32_t failed_steps;
	uint32_t maximum_failures;
	uint8_t authorization_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_recovery_coordinator {
	uint32_t schema_version;
	struct pqcp_edge_recovery_plan *plans;
	size_t capacity;
	uint64_t next_recovery_id;
	uint64_t completed_count;
	uint64_t failed_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_dlp_action {
	PQCP_EDGE_DLP_ALLOW = 0,
	PQCP_EDGE_DLP_REDACT,
	PQCP_EDGE_DLP_BLOCK,
	PQCP_EDGE_DLP_QUARANTINE,
};

struct pqcp_edge_dlp_rule {
	uint32_t rule_id;
	uint32_t priority;
	char classification[PQCP_EDGE_LABEL_MAX_CHARS];
	char destination_domain[PQCP_EDGE_DOMAIN_MAX_CHARS];
	uint32_t minimum_matches;
	uint32_t byte_pattern;
	uint32_t byte_mask;
	uint64_t maximum_payload;
	enum pqcp_edge_dlp_action action;
	bool encrypted_only;
	bool enabled;
};

struct pqcp_edge_dlp_decision {
	enum pqcp_edge_dlp_action action;
	uint32_t rule_id;
	uint32_t match_count;
	uint64_t scanned_bytes;
	char reason[PQCP_EDGE_REASON_MAX_CHARS];
};

struct pqcp_edge_dlp_engine {
	uint32_t schema_version;
	struct pqcp_edge_dlp_rule *rules;
	size_t capacity;
	size_t count;
	uint64_t scan_count;
	uint64_t block_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_trust_anchor {
	uint32_t generation;
	char domain_id[PQCP_EDGE_DOMAIN_MAX_CHARS];
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint32_t maximum_risk;
	uint8_t public_key_digest[PQCP_EDGE_DIGEST_BYTES];
	bool active;
};

struct pqcp_edge_federation_grant {
	uint64_t grant_id;
	char source_domain[PQCP_EDGE_DOMAIN_MAX_CHARS];
	char destination_domain[PQCP_EDGE_DOMAIN_MAX_CHARS];
	uint64_t capabilities;
	uint64_t operation_mask;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t maximum_uses;
	uint64_t use_count;
	uint32_t maximum_risk;
	uint8_t grant_digest[PQCP_EDGE_DIGEST_BYTES];
	bool revoked;
	bool occupied;
};

struct pqcp_edge_trust_federation {
	uint32_t schema_version;
	struct pqcp_edge_trust_anchor *anchors;
	size_t anchor_capacity;
	struct pqcp_edge_federation_grant *grants;
	size_t grant_capacity;
	uint32_t next_anchor_generation;
	uint64_t next_grant_id;
	uint64_t authorization_count;
	uint64_t rejection_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_credential_state {
	PQCP_EDGE_CREDENTIAL_EMPTY = 0,
	PQCP_EDGE_CREDENTIAL_ACTIVE,
	PQCP_EDGE_CREDENTIAL_REFRESH_REQUIRED,
	PQCP_EDGE_CREDENTIAL_EXPIRED,
	PQCP_EDGE_CREDENTIAL_REVOKED,
};

struct pqcp_edge_credential_record {
	uint32_t schema_version;
	uint32_t generation;
	char credential_id[PQCP_EDGE_ID_MAX_CHARS];
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	char issuer_domain[PQCP_EDGE_DOMAIN_MAX_CHARS];
	uint64_t issuance_epoch;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t issued_at_ms;
	uint64_t refresh_at_ms;
	uint64_t expires_at_ms;
	uint64_t capabilities;
	uint8_t public_key_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t credential_digest[PQCP_EDGE_DIGEST_BYTES];
	enum pqcp_edge_credential_state state;
	bool occupied;
};

struct pqcp_edge_credential_cache {
	uint32_t schema_version;
	struct pqcp_edge_credential_record *records;
	size_t capacity;
	uint32_t next_generation;
	uint64_t refresh_count;
	uint64_t rejection_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_isolation_state {
	PQCP_EDGE_ISOLATION_OPEN = 0,
	PQCP_EDGE_ISOLATION_RESTRICTED,
	PQCP_EDGE_ISOLATION_QUARANTINED,
	PQCP_EDGE_ISOLATION_FAILSAFE,
};

struct pqcp_edge_isolation_zone {
	char zone_id[PQCP_EDGE_ZONE_MAX_CHARS];
	enum pqcp_edge_isolation_state state;
	uint64_t allowed_capabilities;
	uint64_t allowed_operations;
	uint64_t entered_at_ms;
	uint64_t expires_at_ms;
	uint32_t reason_mask;
	uint32_t active_workloads;
	uint32_t maximum_workloads;
	/* Allow-lists in force before FAILSAFE zeroed them; restored when
	 * the zone leaves FAILSAFE. Meaningful only while FAILSAFE.
	 */
	uint64_t saved_allowed_capabilities;
	uint64_t saved_allowed_operations;
	bool occupied;
};

struct pqcp_edge_isolation_manager {
	uint32_t schema_version;
	struct pqcp_edge_isolation_zone *zones;
	size_t capacity;
	uint64_t transition_count;
	uint64_t denial_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_provenance_event {
	PQCP_EDGE_PROVENANCE_CREATED = 0,
	PQCP_EDGE_PROVENANCE_TRANSFORMED,
	PQCP_EDGE_PROVENANCE_TRANSMITTED,
	PQCP_EDGE_PROVENANCE_STORED,
	PQCP_EDGE_PROVENANCE_REPLICATED,
	PQCP_EDGE_PROVENANCE_REDACTED,
	PQCP_EDGE_PROVENANCE_DELETED,
};

struct pqcp_edge_provenance_record {
	uint32_t schema_version;
	uint64_t sequence;
	char artifact_id[PQCP_EDGE_OBJECT_MAX_CHARS];
	char actor_id[PQCP_EDGE_ACTOR_MAX_CHARS];
	char location_id[PQCP_EDGE_ID_MAX_CHARS];
	enum pqcp_edge_provenance_event event;
	uint64_t timestamp_ms;
	uint64_t policy_epoch;
	uint8_t input_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t output_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t previous_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t record_digest[PQCP_EDGE_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_edge_provenance_ledger {
	uint32_t schema_version;
	struct pqcp_edge_provenance_record *records;
	size_t capacity;
	size_t next_index;
	size_t count;
	uint64_t next_sequence;
	uint8_t chain_head[PQCP_EDGE_DIGEST_BYTES];
	uint64_t dropped_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_job_state {
	PQCP_EDGE_JOB_EMPTY = 0,
	PQCP_EDGE_JOB_QUEUED,
	PQCP_EDGE_JOB_RESERVED,
	PQCP_EDGE_JOB_RUNNING,
	PQCP_EDGE_JOB_RETRY_WAIT,
	PQCP_EDGE_JOB_COMPLETED,
	PQCP_EDGE_JOB_FAILED,
	PQCP_EDGE_JOB_CANCELLED,
};

struct pqcp_edge_workload_job {
	uint32_t schema_version;
	uint64_t job_id;
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t submitted_at_ms;
	uint64_t earliest_start_ms;
	uint64_t deadline_ms;
	uint64_t estimated_cost;
	uint32_t priority;
	uint32_t required_resource_mask;
	uint32_t attempts;
	uint32_t maximum_attempts;
	enum pqcp_edge_job_state state;
	int result;
	bool occupied;
};

struct pqcp_edge_workload_scheduler {
	uint32_t schema_version;
	struct pqcp_edge_workload_job *jobs;
	size_t capacity;
	uint64_t next_job_id;
	uint32_t reserved_resource_mask;
	uint64_t completed_count;
	uint64_t failed_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_sla_state {
	PQCP_EDGE_SLA_UNKNOWN = 0,
	PQCP_EDGE_SLA_HEALTHY,
	PQCP_EDGE_SLA_AT_RISK,
	PQCP_EDGE_SLA_BREACHED,
};

struct pqcp_edge_sla_objective {
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	uint64_t window_ms;
	uint64_t maximum_latency_us;
	uint32_t minimum_success_basis_points;
	uint32_t maximum_error_basis_points;
	uint64_t window_started_ms;
	uint64_t request_count;
	uint64_t success_count;
	uint64_t error_count;
	uint64_t latency_sum_us;
	uint64_t maximum_observed_latency_us;
	enum pqcp_edge_sla_state state;
	bool occupied;
};

struct pqcp_edge_sla_monitor {
	uint32_t schema_version;
	struct pqcp_edge_sla_objective *objectives;
	size_t capacity;
	uint64_t breach_count;
	struct k_mutex lock;
	bool initialized;
};

enum pqcp_edge_config_state {
	PQCP_EDGE_CONFIG_EMPTY = 0,
	PQCP_EDGE_CONFIG_PREPARED,
	PQCP_EDGE_CONFIG_VALIDATED,
	PQCP_EDGE_CONFIG_COMMITTED,
	PQCP_EDGE_CONFIG_ABORTED,
};

struct pqcp_edge_config_transaction {
	uint32_t schema_version;
	uint64_t transaction_id;
	uint64_t base_generation;
	uint64_t target_generation;
	uint64_t prepared_at_ms;
	uint64_t expires_at_ms;
	enum pqcp_edge_config_state state;
	uint8_t base_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t target_digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t validation_digest[PQCP_EDGE_DIGEST_BYTES];
	int result;
	bool occupied;
};

struct pqcp_edge_config_manager {
	uint32_t schema_version;
	struct pqcp_edge_config_transaction *transactions;
	size_t capacity;
	uint64_t next_transaction_id;
	uint64_t active_generation;
	uint8_t active_digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t commit_count;
	uint64_t abort_count;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_edge_compliance_summary {
	uint32_t schema_version;
	uint64_t generated_at_ms;
	uint64_t policy_epoch;
	uint64_t principal_count;
	uint64_t service_count;
	uint64_t active_session_count;
	uint64_t queued_message_count;
	uint64_t vault_object_count;
	uint64_t open_incident_count;
	uint64_t integrity_failure_count;
	uint64_t policy_denial_count;
	uint32_t maximum_risk_score;
	uint32_t compliance_score;
	uint8_t state_digest[PQCP_EDGE_DIGEST_BYTES];
};

struct pqcp_edge_runtime_storage {
	struct pqcp_edge_principal *principals;
	size_t principal_capacity;
	struct pqcp_edge_service *services;
	size_t service_capacity;
	struct pqcp_edge_endpoint *endpoints;
	size_t endpoint_capacity;
	struct pqcp_edge_access_rule *access_rules;
	size_t access_rule_capacity;
	struct pqcp_edge_route *routes;
	size_t route_capacity;
	struct pqcp_edge_session *sessions;
	size_t session_capacity;
	struct pqcp_edge_traffic_subject *traffic_subjects;
	size_t traffic_subject_capacity;
	struct pqcp_edge_circuit *circuits;
	size_t circuit_capacity;
	struct pqcp_edge_message *messages;
	size_t message_capacity;
	struct pqcp_edge_replay_entry *replay_entries;
	size_t replay_capacity;
	struct pqcp_edge_reassembly *reassemblies;
	size_t reassembly_capacity;
	struct pqcp_edge_topic *topics;
	size_t topic_capacity;
	struct pqcp_edge_subscription *subscriptions;
	size_t subscription_capacity;
	struct pqcp_edge_group *groups;
	size_t group_capacity;
	struct pqcp_edge_delivery *deliveries;
	size_t delivery_capacity;
	struct pqcp_edge_vault_object *vault_objects;
	size_t vault_object_capacity;
	struct pqcp_edge_vault_acl_entry *vault_acl_entries;
	size_t vault_acl_capacity;
	struct pqcp_edge_vault_version *vault_versions;
	size_t vault_version_capacity;
	struct pqcp_edge_vault_journal_entry *vault_journal_entries;
	size_t vault_journal_capacity;
	struct pqcp_edge_vault_lease *vault_leases;
	size_t vault_lease_capacity;
	struct pqcp_edge_replica_record *replicas;
	size_t replica_capacity;
	struct pqcp_edge_vault_snapshot *snapshots;
	size_t snapshot_capacity;
	struct pqcp_edge_signal *signals;
	size_t signal_capacity;
	struct pqcp_edge_incident *incidents;
	size_t incident_capacity;
	struct pqcp_edge_playbook *playbooks;
	size_t playbook_capacity;
	struct pqcp_edge_evidence *evidence;
	size_t evidence_capacity;
	struct pqcp_edge_containment *containments;
	size_t containment_capacity;
	struct pqcp_edge_continuity_service *continuity_services;
	size_t continuity_capacity;
	struct pqcp_edge_posture_report *posture_reports;
	size_t posture_capacity;
	struct pqcp_edge_attestation_record *attestations;
	size_t attestation_capacity;
	struct pqcp_edge_policy_bundle *policy_bundles;
	size_t policy_bundle_capacity;
	struct pqcp_edge_policy_ack *policy_acks;
	size_t policy_ack_capacity;
	struct pqcp_edge_secret_rotation *rotations;
	size_t rotation_capacity;
	struct pqcp_edge_anomaly_baseline *anomaly_baselines;
	size_t anomaly_capacity;
	struct pqcp_edge_resource_budget *resource_budgets;
	size_t resource_budget_capacity;
	struct pqcp_edge_export_cursor *export_cursors;
	size_t export_cursor_capacity;
	struct pqcp_edge_recovery_plan *recovery_plans;
	size_t recovery_plan_capacity;
	struct pqcp_edge_dlp_rule *dlp_rules;
	size_t dlp_rule_capacity;
	struct pqcp_edge_trust_anchor *trust_anchors;
	size_t trust_anchor_capacity;
	struct pqcp_edge_federation_grant *federation_grants;
	size_t federation_grant_capacity;
	struct pqcp_edge_credential_record *credentials;
	size_t credential_capacity;
	struct pqcp_edge_isolation_zone *isolation_zones;
	size_t isolation_capacity;
	struct pqcp_edge_provenance_record *provenance_records;
	size_t provenance_capacity;
	struct pqcp_edge_workload_job *workload_jobs;
	size_t workload_job_capacity;
	struct pqcp_edge_sla_objective *sla_objectives;
	size_t sla_capacity;
	struct pqcp_edge_config_transaction *config_transactions;
	size_t config_transaction_capacity;
};

struct pqcp_edge_runtime {
	uint32_t schema_version;
	struct pqcp_edge_principal_directory principals;
	struct pqcp_edge_service_registry services;
	struct pqcp_edge_access_engine access;
	struct pqcp_edge_route_table routes;
	struct pqcp_edge_session_registry sessions;
	struct pqcp_edge_traffic_governor traffic;
	struct pqcp_edge_circuit_breaker circuits;
	struct pqcp_edge_message_queue messages;
	struct pqcp_edge_replay_guard replay;
	struct pqcp_edge_fragment_manager fragments;
	struct pqcp_edge_topic_registry topics;
	struct pqcp_edge_group_manager groups;
	struct pqcp_edge_delivery_manager deliveries;
	struct pqcp_edge_vault_store vault;
	struct pqcp_edge_vault_acl vault_acl;
	struct pqcp_edge_vault_version_store versions;
	struct pqcp_edge_vault_journal journal;
	struct pqcp_edge_vault_lease_manager leases;
	struct pqcp_edge_replication_manager replication;
	struct pqcp_edge_snapshot_manager snapshots;
	struct pqcp_edge_signal_engine signals;
	struct pqcp_edge_incident_manager incidents;
	struct pqcp_edge_playbook_engine playbooks;
	struct pqcp_edge_evidence_store evidence;
	struct pqcp_edge_containment_manager containment;
	struct pqcp_edge_continuity_manager continuity;
	struct pqcp_edge_posture_engine posture;
	struct pqcp_edge_attestation_manager attestation;
	struct pqcp_edge_policy_distributor policy;
	struct pqcp_edge_rotation_manager rotation;
	struct pqcp_edge_anomaly_engine anomaly;
	struct pqcp_edge_resource_monitor resources;
	struct pqcp_edge_audit_exporter exporter;
	struct pqcp_edge_recovery_coordinator recovery;
	struct pqcp_edge_dlp_engine dlp;
	struct pqcp_edge_trust_federation federation;
	struct pqcp_edge_credential_cache credentials;
	struct pqcp_edge_isolation_manager isolation;
	struct pqcp_edge_provenance_ledger provenance;
	struct pqcp_edge_workload_scheduler scheduler;
	struct pqcp_edge_sla_monitor sla;
	struct pqcp_edge_config_manager configuration;
	uint64_t policy_epoch;
	uint64_t tick_count;
	bool initialized;
};

struct pqcp_edge_admission_request {
	char principal_id[PQCP_EDGE_ID_MAX_CHARS];
	char service_id[PQCP_EDGE_ID_MAX_CHARS];
	char credential_id[PQCP_EDGE_ID_MAX_CHARS];
	char endpoint_id[PQCP_EDGE_ID_MAX_CHARS];
	enum pqcp_edge_operation operation;
	uint64_t required_capabilities;
	uint64_t request_bytes;
	uint64_t revocation_epoch;
	uint64_t now_ms;
	uint32_t current_concurrent;
	bool channel_identity_verified;
	bool require_credential;
	bool reserve_traffic;
};

struct pqcp_edge_admission_result {
	struct pqcp_edge_access_decision access;
	enum pqcp_edge_policy_effect posture_effect;
	uint32_t posture_failure_mask;
	uint32_t posture_risk_score;
	int credential_result;
	int isolation_result;
	int attestation_result;
	int circuit_result;
	int traffic_result;
	bool attestation_fresh;
	bool admitted;
};

const char *pqcp_edge_operation_str(enum pqcp_edge_operation operation);
const char *pqcp_edge_incident_state_str(
	enum pqcp_edge_incident_state state);

int pqcp_edge_principal_directory_init(
	struct pqcp_edge_principal_directory *directory,
	struct pqcp_edge_principal *principals,
	size_t capacity);
int pqcp_edge_principal_register(
	struct pqcp_edge_principal_directory *directory,
	const struct pqcp_edge_principal *principal,
	uint64_t now_ms);
int pqcp_edge_principal_observe(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	uint32_t risk_score,
	enum pqcp_edge_trust_level trust,
	bool channel_bound,
	uint64_t now_ms);
int pqcp_edge_principal_quarantine(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	uint64_t until_ms);
int pqcp_edge_principal_release(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	uint64_t now_ms);
int pqcp_edge_principal_revoke(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	uint64_t revocation_epoch,
	uint64_t now_ms);
int pqcp_edge_principal_find(
	struct pqcp_edge_principal_directory *directory,
	const char *principal_id,
	struct pqcp_edge_principal **principal);
int pqcp_edge_principal_tick(
	struct pqcp_edge_principal_directory *directory,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_principal_audit(
	struct pqcp_edge_principal_directory *directory);

int pqcp_edge_service_registry_init(
	struct pqcp_edge_service_registry *registry,
	struct pqcp_edge_service *services,
	size_t service_capacity,
	struct pqcp_edge_endpoint *endpoints,
	size_t endpoint_capacity);
int pqcp_edge_service_register(
	struct pqcp_edge_service_registry *registry,
	const struct pqcp_edge_service *service,
	uint64_t now_ms);
int pqcp_edge_service_set_state(
	struct pqcp_edge_service_registry *registry,
	const char *service_id,
	enum pqcp_edge_service_state state,
	uint64_t now_ms);
int pqcp_edge_endpoint_register(
	struct pqcp_edge_service_registry *registry,
	const struct pqcp_edge_endpoint *endpoint,
	uint64_t now_ms);
int pqcp_edge_endpoint_observe(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id,
	bool success,
	uint32_t latency_us,
	uint64_t now_ms);
int pqcp_edge_endpoint_eject(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id,
	uint64_t until_ms);
int pqcp_edge_endpoint_reserve(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id);
int pqcp_edge_endpoint_release(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id);
int pqcp_edge_service_find(
	struct pqcp_edge_service_registry *registry,
	const char *service_id,
	struct pqcp_edge_service **service);
int pqcp_edge_endpoint_find(
	struct pqcp_edge_service_registry *registry,
	const char *endpoint_id,
	struct pqcp_edge_endpoint **endpoint);
int pqcp_edge_service_tick(
	struct pqcp_edge_service_registry *registry,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_service_registry_audit(
	struct pqcp_edge_service_registry *registry);

int pqcp_edge_access_engine_init(
	struct pqcp_edge_access_engine *engine,
	struct pqcp_edge_access_rule *rules,
	size_t capacity,
	enum pqcp_edge_policy_effect default_effect);
int pqcp_edge_access_rule_put(
	struct pqcp_edge_access_engine *engine,
	const struct pqcp_edge_access_rule *rule);
int pqcp_edge_access_rule_remove(
	struct pqcp_edge_access_engine *engine,
	uint32_t rule_id);
int pqcp_edge_access_evaluate(
	struct pqcp_edge_access_engine *engine,
	const struct pqcp_edge_access_context *context,
	struct pqcp_edge_access_decision *decision);
int pqcp_edge_access_engine_audit(
	struct pqcp_edge_access_engine *engine);

int pqcp_edge_route_table_init(
	struct pqcp_edge_route_table *table,
	struct pqcp_edge_route *routes,
	size_t capacity);
int pqcp_edge_route_select(
	struct pqcp_edge_route_table *table,
	struct pqcp_edge_service_registry *registry,
	const struct pqcp_edge_principal *principal,
	const char *service_id,
	enum pqcp_edge_route_strategy strategy,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	struct pqcp_edge_route **route);
int pqcp_edge_route_failover(
	struct pqcp_edge_route_table *table,
	struct pqcp_edge_service_registry *registry,
	uint64_t route_id,
	uint64_t now_ms);
int pqcp_edge_route_expire(
	struct pqcp_edge_route_table *table,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_edge_route_table_audit(
	struct pqcp_edge_route_table *table);

int pqcp_edge_session_registry_init(
	struct pqcp_edge_session_registry *registry,
	struct pqcp_edge_session *sessions,
	size_t capacity);
int pqcp_edge_session_open(
	struct pqcp_edge_session_registry *registry,
	struct pqcp_edge_principal_directory *principals,
	const struct pqcp_edge_route *route,
	const uint8_t binding_digest[PQCP_EDGE_DIGEST_BYTES],
	bool mutually_authenticated,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	struct pqcp_edge_session **session);
int pqcp_edge_session_account(
	struct pqcp_edge_session_registry *registry,
	uint64_t session_id,
	uint64_t bytes_sent,
	uint64_t bytes_received,
	bool success,
	uint64_t now_ms);
int pqcp_edge_session_require_rekey(
	struct pqcp_edge_session_registry *registry,
	uint64_t session_id,
	uint64_t next_epoch);
int pqcp_edge_session_close(
	struct pqcp_edge_session_registry *registry,
	struct pqcp_edge_principal_directory *principals,
	uint64_t session_id,
	int result,
	uint64_t now_ms);
int pqcp_edge_session_tick(
	struct pqcp_edge_session_registry *registry,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_session_registry_audit(
	struct pqcp_edge_session_registry *registry);

int pqcp_edge_traffic_governor_init(
	struct pqcp_edge_traffic_governor *governor,
	const struct pqcp_edge_traffic_policy *policy,
	struct pqcp_edge_traffic_subject *subjects,
	size_t capacity);
int pqcp_edge_traffic_authorize(
	struct pqcp_edge_traffic_governor *governor,
	const char *principal_id,
	const char *service_id,
	uint64_t bytes,
	uint64_t now_ms);
int pqcp_edge_traffic_complete(
	struct pqcp_edge_traffic_governor *governor,
	const char *principal_id,
	const char *service_id,
	bool success,
	uint64_t now_ms);
int pqcp_edge_traffic_block(
	struct pqcp_edge_traffic_governor *governor,
	const char *principal_id,
	const char *service_id,
	uint64_t until_ms);
int pqcp_edge_traffic_tick(
	struct pqcp_edge_traffic_governor *governor,
	uint64_t now_ms,
	uint32_t *refilled_count);
int pqcp_edge_traffic_governor_audit(
	struct pqcp_edge_traffic_governor *governor);

int pqcp_edge_circuit_breaker_init(
	struct pqcp_edge_circuit_breaker *breaker,
	const struct pqcp_edge_circuit_policy *policy,
	struct pqcp_edge_circuit *circuits,
	size_t capacity);
int pqcp_edge_circuit_allow(
	struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id,
	uint64_t now_ms);
int pqcp_edge_circuit_record(
	struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id,
	bool success,
	uint64_t now_ms);
int pqcp_edge_circuit_isolate(
	struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id);
int pqcp_edge_circuit_reset(
	struct pqcp_edge_circuit_breaker *breaker,
	const char *service_id,
	const char *endpoint_id,
	uint64_t now_ms);
int pqcp_edge_circuit_tick(
	struct pqcp_edge_circuit_breaker *breaker,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_circuit_breaker_audit(
	struct pqcp_edge_circuit_breaker *breaker);

int pqcp_edge_message_queue_init(
	struct pqcp_edge_message_queue *queue,
	struct pqcp_edge_message *messages,
	size_t capacity);
int pqcp_edge_message_submit(
	struct pqcp_edge_message_queue *queue,
	const struct pqcp_edge_message *message,
	const uint8_t authentication_key[PQCP_EDGE_KEY_BYTES],
	uint64_t now_ms,
	bool *replayed);
int pqcp_edge_message_next(
	struct pqcp_edge_message_queue *queue,
	const char *consumer_id,
	const char *topic,
	uint64_t now_ms,
	struct pqcp_edge_message **message);
int pqcp_edge_message_acknowledge(
	struct pqcp_edge_message_queue *queue,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES],
	uint64_t now_ms);
int pqcp_edge_message_retry(
	struct pqcp_edge_message_queue *queue,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES],
	uint64_t retry_at_ms,
	int result);
int pqcp_edge_message_cancel(
	struct pqcp_edge_message_queue *queue,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES]);
int pqcp_edge_message_tick(
	struct pqcp_edge_message_queue *queue,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_message_queue_audit(
	struct pqcp_edge_message_queue *queue,
	const uint8_t authentication_key[PQCP_EDGE_KEY_BYTES]);

int pqcp_edge_replay_guard_init(
	struct pqcp_edge_replay_guard *guard,
	struct pqcp_edge_replay_entry *entries,
	size_t capacity,
	uint32_t window_size);
int pqcp_edge_replay_accept(
	struct pqcp_edge_replay_guard *guard,
	const char *producer_id,
	uint64_t epoch,
	uint64_t sequence,
	uint64_t now_ms);
int pqcp_edge_replay_advance_epoch(
	struct pqcp_edge_replay_guard *guard,
	const char *producer_id,
	uint64_t epoch,
	uint64_t now_ms);
int pqcp_edge_replay_expire(
	struct pqcp_edge_replay_guard *guard,
	uint64_t before_ms,
	uint32_t *expired_count);
int pqcp_edge_replay_guard_audit(
	struct pqcp_edge_replay_guard *guard);

int pqcp_edge_fragment_manager_init(
	struct pqcp_edge_fragment_manager *manager,
	struct pqcp_edge_reassembly *assemblies,
	size_t capacity);
int pqcp_edge_message_fragment(
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES],
	const uint8_t *payload,
	size_t payload_length,
	uint16_t fragment_index,
	struct pqcp_edge_fragment *fragment);
int pqcp_edge_fragment_accept(
	struct pqcp_edge_fragment_manager *manager,
	const struct pqcp_edge_fragment *fragment,
	uint8_t *output,
	size_t output_capacity,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	bool *complete,
	size_t *message_length);
int pqcp_edge_fragment_expire(
	struct pqcp_edge_fragment_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_edge_fragment_manager_audit(
	struct pqcp_edge_fragment_manager *manager);

int pqcp_edge_ratchet_init(
	struct pqcp_edge_ratchet *ratchet,
	const char *peer_id,
	const uint8_t root_key[PQCP_EDGE_KEY_BYTES],
	bool initiator,
	uint64_t now_ms);
int pqcp_edge_ratchet_next_send(
	struct pqcp_edge_ratchet *ratchet,
	uint8_t message_key[PQCP_EDGE_KEY_BYTES],
	uint64_t *epoch,
	uint64_t *sequence);
int pqcp_edge_ratchet_receive(
	struct pqcp_edge_ratchet *ratchet,
	uint64_t epoch,
	uint64_t sequence,
	uint8_t message_key[PQCP_EDGE_KEY_BYTES]);
int pqcp_edge_ratchet_rotate(
	struct pqcp_edge_ratchet *ratchet,
	const uint8_t shared_secret[PQCP_EDGE_KEY_BYTES],
	uint64_t next_epoch,
	uint64_t now_ms);
int pqcp_edge_ratchet_audit(
	struct pqcp_edge_ratchet *ratchet);

int pqcp_edge_topic_registry_init(
	struct pqcp_edge_topic_registry *registry,
	struct pqcp_edge_topic *topics,
	size_t topic_capacity,
	struct pqcp_edge_subscription *subscriptions,
	size_t subscription_capacity);
int pqcp_edge_topic_create(
	struct pqcp_edge_topic_registry *registry,
	const struct pqcp_edge_topic *topic);
int pqcp_edge_topic_remove(
	struct pqcp_edge_topic_registry *registry,
	const char *topic);
int pqcp_edge_topic_authorize_publish(
	struct pqcp_edge_topic_registry *registry,
	const char *topic,
	const struct pqcp_edge_principal *principal,
	size_t payload_length);
int pqcp_edge_topic_subscribe(
	struct pqcp_edge_topic_registry *registry,
	const char *topic,
	const struct pqcp_edge_principal *principal,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	uint32_t maximum_inflight,
	struct pqcp_edge_subscription **subscription);
int pqcp_edge_topic_unsubscribe(
	struct pqcp_edge_topic_registry *registry,
	uint64_t subscription_id);
int pqcp_edge_topic_acknowledge(
	struct pqcp_edge_topic_registry *registry,
	uint64_t subscription_id,
	uint64_t sequence);
int pqcp_edge_topic_tick(
	struct pqcp_edge_topic_registry *registry,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_edge_topic_registry_audit(
	struct pqcp_edge_topic_registry *registry);

int pqcp_edge_group_manager_init(
	struct pqcp_edge_group_manager *manager,
	struct pqcp_edge_group *groups,
	size_t capacity);
int pqcp_edge_group_create(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const char *owner_id,
	const uint8_t key_material[PQCP_EDGE_KEY_BYTES],
	uint64_t now_ms);
int pqcp_edge_group_add_member(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const char *principal_id,
	uint64_t capabilities,
	uint64_t now_ms);
int pqcp_edge_group_remove_member(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const char *principal_id,
	uint64_t now_ms);
int pqcp_edge_group_rotate(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const uint8_t key_material[PQCP_EDGE_KEY_BYTES],
	uint64_t now_ms);
int pqcp_edge_group_authorize(
	struct pqcp_edge_group_manager *manager,
	const char *group_id,
	const char *principal_id,
	uint64_t required_capabilities);
int pqcp_edge_group_manager_audit(
	struct pqcp_edge_group_manager *manager);

int pqcp_edge_delivery_manager_init(
	struct pqcp_edge_delivery_manager *manager,
	struct pqcp_edge_delivery *deliveries,
	size_t capacity);
int pqcp_edge_delivery_dispatch(
	struct pqcp_edge_delivery_manager *manager,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES],
	uint64_t subscription_id,
	uint64_t now_ms,
	uint64_t deadline_ms,
	uint32_t maximum_attempts,
	struct pqcp_edge_delivery **delivery);
int pqcp_edge_delivery_complete(
	struct pqcp_edge_delivery_manager *manager,
	uint64_t delivery_id,
	int result,
	uint64_t now_ms);
int pqcp_edge_delivery_retry(
	struct pqcp_edge_delivery_manager *manager,
	uint64_t delivery_id,
	uint64_t retry_at_ms);
int pqcp_edge_delivery_tick(
	struct pqcp_edge_delivery_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_delivery_manager_audit(
	struct pqcp_edge_delivery_manager *manager);

int pqcp_edge_vault_store_init(
	struct pqcp_edge_vault_store *store,
	struct pqcp_edge_vault_object *objects,
	size_t capacity);
int pqcp_edge_vault_create(
	struct pqcp_edge_vault_store *store,
	const struct pqcp_edge_vault_object *object,
	uint64_t now_ms);
int pqcp_edge_vault_read(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	uint64_t now_ms);
int pqcp_edge_vault_write(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	const uint8_t *value,
	size_t value_length,
	uint64_t expected_version,
	uint64_t now_ms);
int pqcp_edge_vault_seal(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	uint64_t now_ms);
int pqcp_edge_vault_delete(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	uint64_t expected_version,
	uint64_t now_ms);
int pqcp_edge_vault_find(
	struct pqcp_edge_vault_store *store,
	const char *object_id,
	struct pqcp_edge_vault_object **object);
int pqcp_edge_vault_tick(
	struct pqcp_edge_vault_store *store,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_vault_store_audit(
	struct pqcp_edge_vault_store *store);

int pqcp_edge_vault_acl_init(
	struct pqcp_edge_vault_acl *acl,
	struct pqcp_edge_vault_acl_entry *entries,
	size_t capacity);
int pqcp_edge_vault_acl_put(
	struct pqcp_edge_vault_acl *acl,
	const struct pqcp_edge_vault_acl_entry *entry);
int pqcp_edge_vault_acl_remove(
	struct pqcp_edge_vault_acl *acl,
	const char *object_id,
	const char *principal_id);
int pqcp_edge_vault_acl_authorize(
	struct pqcp_edge_vault_acl *acl,
	const struct pqcp_edge_vault_object *object,
	const struct pqcp_edge_principal *principal,
	uint32_t permissions,
	bool attestation_fresh,
	uint64_t now_ms);
int pqcp_edge_vault_acl_expire(
	struct pqcp_edge_vault_acl *acl,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_edge_vault_acl_audit(
	struct pqcp_edge_vault_acl *acl);

int pqcp_edge_vault_version_store_init(
	struct pqcp_edge_vault_version_store *store,
	struct pqcp_edge_vault_version *versions,
	size_t capacity);
int pqcp_edge_vault_version_capture(
	struct pqcp_edge_vault_version_store *store,
	const struct pqcp_edge_vault_object *object,
	uint64_t now_ms,
	uint64_t retention_ms);
int pqcp_edge_vault_version_restore(
	struct pqcp_edge_vault_version_store *versions,
	struct pqcp_edge_vault_store *objects,
	const char *object_id,
	uint64_t object_version,
	uint64_t now_ms);
int pqcp_edge_vault_version_prune(
	struct pqcp_edge_vault_version_store *store,
	uint64_t now_ms,
	uint32_t *pruned_count);
int pqcp_edge_vault_version_store_audit(
	struct pqcp_edge_vault_version_store *store);

int pqcp_edge_vault_journal_init(
	struct pqcp_edge_vault_journal *journal,
	struct pqcp_edge_vault_journal_entry *entries,
	size_t capacity);
int pqcp_edge_vault_journal_append(
	struct pqcp_edge_vault_journal *journal,
	enum pqcp_edge_vault_journal_event event,
	const char *object_id,
	const char *actor_id,
	int result,
	const uint8_t *payload,
	size_t payload_length,
	uint64_t now_ms);
int pqcp_edge_vault_journal_find(
	struct pqcp_edge_vault_journal *journal,
	uint64_t sequence,
	struct pqcp_edge_vault_journal_entry *entry);
int pqcp_edge_vault_journal_verify(
	struct pqcp_edge_vault_journal *journal);

int pqcp_edge_vault_lease_manager_init(
	struct pqcp_edge_vault_lease_manager *manager,
	struct pqcp_edge_vault_lease *leases,
	size_t capacity);
int pqcp_edge_vault_lease_issue(
	struct pqcp_edge_vault_lease_manager *manager,
	const char *object_id,
	const char *principal_id,
	uint32_t permissions,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t maximum_uses,
	struct pqcp_edge_vault_lease **lease);
int pqcp_edge_vault_lease_authorize(
	struct pqcp_edge_vault_lease_manager *manager,
	uint64_t lease_id,
	const char *object_id,
	const char *principal_id,
	uint32_t permissions,
	uint64_t policy_epoch,
	uint64_t now_ms);
int pqcp_edge_vault_lease_revoke(
	struct pqcp_edge_vault_lease_manager *manager,
	uint64_t lease_id);
int pqcp_edge_vault_lease_expire(
	struct pqcp_edge_vault_lease_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_edge_vault_lease_manager_audit(
	struct pqcp_edge_vault_lease_manager *manager);

int pqcp_edge_replication_manager_init(
	struct pqcp_edge_replication_manager *manager,
	struct pqcp_edge_replica_record *records,
	size_t capacity);
int pqcp_edge_replication_schedule(
	struct pqcp_edge_replication_manager *manager,
	const struct pqcp_edge_vault_object *object,
	const char *target_id,
	uint64_t now_ms,
	uint32_t maximum_attempts,
	struct pqcp_edge_replica_record **record);
int pqcp_edge_replication_next(
	struct pqcp_edge_replication_manager *manager,
	uint64_t now_ms,
	struct pqcp_edge_replica_record **record);
int pqcp_edge_replication_complete(
	struct pqcp_edge_replication_manager *manager,
	uint64_t replication_id,
	int result,
	const uint8_t applied_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_edge_replication_retry(
	struct pqcp_edge_replication_manager *manager,
	uint64_t replication_id,
	uint64_t retry_at_ms);
int pqcp_edge_replication_manager_audit(
	struct pqcp_edge_replication_manager *manager);

int pqcp_edge_snapshot_manager_init(
	struct pqcp_edge_snapshot_manager *manager,
	struct pqcp_edge_vault_snapshot *snapshots,
	size_t capacity);
int pqcp_edge_snapshot_capture(
	struct pqcp_edge_snapshot_manager *manager,
	struct pqcp_edge_vault_store *store,
	struct pqcp_edge_vault_journal *journal,
	uint64_t now_ms,
	struct pqcp_edge_vault_snapshot **snapshot);
int pqcp_edge_snapshot_verify(
	struct pqcp_edge_snapshot_manager *manager,
	uint64_t snapshot_id);
int pqcp_edge_snapshot_manager_audit(
	struct pqcp_edge_snapshot_manager *manager);

int pqcp_edge_signal_engine_init(
	struct pqcp_edge_signal_engine *engine,
	struct pqcp_edge_signal *signals,
	size_t capacity);
int pqcp_edge_signal_submit(
	struct pqcp_edge_signal_engine *engine,
	const struct pqcp_edge_signal *signal,
	uint64_t now_ms,
	struct pqcp_edge_signal **accepted);
int pqcp_edge_signal_acknowledge(
	struct pqcp_edge_signal_engine *engine,
	uint64_t signal_id);
int pqcp_edge_signal_correlate(
	struct pqcp_edge_signal_engine *engine,
	const char *subject_id,
	uint64_t since_ms,
	uint32_t *risk_score,
	enum pqcp_edge_incident_severity *severity,
	uint64_t signal_ids[PQCP_EDGE_MAX_INCIDENT_SIGNALS],
	uint32_t *signal_count);
int pqcp_edge_signal_expire(
	struct pqcp_edge_signal_engine *engine,
	uint64_t before_ms,
	uint32_t *expired_count);
int pqcp_edge_signal_engine_audit(
	struct pqcp_edge_signal_engine *engine);

int pqcp_edge_incident_manager_init(
	struct pqcp_edge_incident_manager *manager,
	struct pqcp_edge_incident *incidents,
	size_t capacity);
int pqcp_edge_incident_open(
	struct pqcp_edge_incident_manager *manager,
	const char *title,
	const char *subject_id,
	const char *owner_id,
	enum pqcp_edge_incident_severity severity,
	uint32_t risk_score,
	const uint64_t *signal_ids,
	uint32_t signal_count,
	uint64_t now_ms,
	struct pqcp_edge_incident **incident);
int pqcp_edge_incident_add_signal(
	struct pqcp_edge_incident_manager *manager,
	uint64_t incident_id,
	uint64_t signal_id,
	uint32_t risk_score,
	enum pqcp_edge_incident_severity severity,
	uint64_t now_ms);
int pqcp_edge_incident_transition(
	struct pqcp_edge_incident_manager *manager,
	uint64_t incident_id,
	enum pqcp_edge_incident_state state,
	uint64_t now_ms);
int pqcp_edge_incident_assign(
	struct pqcp_edge_incident_manager *manager,
	uint64_t incident_id,
	const char *owner_id,
	uint64_t now_ms);
int pqcp_edge_incident_find(
	struct pqcp_edge_incident_manager *manager,
	uint64_t incident_id,
	struct pqcp_edge_incident **incident);
int pqcp_edge_incident_manager_audit(
	struct pqcp_edge_incident_manager *manager);

int pqcp_edge_playbook_engine_init(
	struct pqcp_edge_playbook_engine *engine,
	struct pqcp_edge_playbook *playbooks,
	size_t capacity);
int pqcp_edge_playbook_start(
	struct pqcp_edge_playbook_engine *engine,
	uint64_t incident_id,
	const struct pqcp_edge_playbook_step *steps,
	uint32_t step_count,
	uint64_t now_ms,
	struct pqcp_edge_playbook **playbook);
int pqcp_edge_playbook_next(
	struct pqcp_edge_playbook_engine *engine,
	uint64_t execution_id,
	uint64_t now_ms,
	struct pqcp_edge_playbook_step **step);
int pqcp_edge_playbook_complete_step(
	struct pqcp_edge_playbook_engine *engine,
	uint64_t execution_id,
	uint32_t step_id,
	int result,
	uint64_t now_ms);
int pqcp_edge_playbook_retry_step(
	struct pqcp_edge_playbook_engine *engine,
	uint64_t execution_id,
	uint32_t step_id,
	uint64_t retry_at_ms);
int pqcp_edge_playbook_engine_audit(
	struct pqcp_edge_playbook_engine *engine);

int pqcp_edge_evidence_store_init(
	struct pqcp_edge_evidence_store *store,
	struct pqcp_edge_evidence *evidence,
	size_t capacity);
int pqcp_edge_evidence_capture(
	struct pqcp_edge_evidence_store *store,
	uint64_t incident_id,
	const char *source_id,
	const char *classification,
	const uint8_t *payload,
	size_t payload_length,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_evidence **evidence);
int pqcp_edge_evidence_seal(
	struct pqcp_edge_evidence_store *store,
	uint64_t evidence_id);
int pqcp_edge_evidence_export(
	struct pqcp_edge_evidence_store *store,
	uint64_t evidence_id,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_edge_evidence_expire(
	struct pqcp_edge_evidence_store *store,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_edge_evidence_store_audit(
	struct pqcp_edge_evidence_store *store);

int pqcp_edge_containment_manager_init(
	struct pqcp_edge_containment_manager *manager,
	struct pqcp_edge_containment *records,
	size_t capacity);
int pqcp_edge_containment_apply(
	struct pqcp_edge_containment_manager *manager,
	uint64_t incident_id,
	const char *subject_id,
	uint32_t action_mask,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_containment **containment);
int pqcp_edge_containment_record_action(
	struct pqcp_edge_containment_manager *manager,
	uint64_t containment_id,
	uint32_t action,
	int result);
int pqcp_edge_containment_release(
	struct pqcp_edge_containment_manager *manager,
	uint64_t containment_id,
	uint64_t now_ms);
int pqcp_edge_containment_tick(
	struct pqcp_edge_containment_manager *manager,
	uint64_t now_ms,
	uint32_t *released_count);
int pqcp_edge_containment_manager_audit(
	struct pqcp_edge_containment_manager *manager);

int pqcp_edge_continuity_manager_init(
	struct pqcp_edge_continuity_manager *manager,
	struct pqcp_edge_continuity_service *services,
	size_t capacity);
int pqcp_edge_continuity_register(
	struct pqcp_edge_continuity_manager *manager,
	const struct pqcp_edge_continuity_service *service);
int pqcp_edge_continuity_observe(
	struct pqcp_edge_continuity_manager *manager,
	const char *service_id,
	uint32_t available_endpoints,
	uint64_t satisfied_dependencies,
	uint64_t now_ms);
int pqcp_edge_continuity_set_mode(
	struct pqcp_edge_continuity_manager *manager,
	const char *service_id,
	enum pqcp_edge_continuity_mode mode,
	uint64_t now_ms);
int pqcp_edge_continuity_evaluate(
	struct pqcp_edge_continuity_manager *manager,
	uint64_t now_ms,
	enum pqcp_edge_continuity_mode *mode);
int pqcp_edge_continuity_manager_audit(
	struct pqcp_edge_continuity_manager *manager);

int pqcp_edge_posture_engine_init(
	struct pqcp_edge_posture_engine *engine,
	const struct pqcp_edge_posture_policy *policy,
	struct pqcp_edge_posture_report *reports,
	size_t capacity);
int pqcp_edge_posture_submit(
	struct pqcp_edge_posture_engine *engine,
	const struct pqcp_edge_posture_report *report,
	uint64_t now_ms);
int pqcp_edge_posture_evaluate(
	struct pqcp_edge_posture_engine *engine,
	const char *principal_id,
	uint64_t now_ms,
	enum pqcp_edge_policy_effect *effect,
	uint32_t *failure_mask,
	uint32_t *risk_score);
int pqcp_edge_posture_expire(
	struct pqcp_edge_posture_engine *engine,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_edge_posture_engine_audit(
	struct pqcp_edge_posture_engine *engine);

int pqcp_edge_attestation_manager_init(
	struct pqcp_edge_attestation_manager *manager,
	struct pqcp_edge_attestation_record *records,
	size_t capacity);
int pqcp_edge_attestation_challenge(
	struct pqcp_edge_attestation_manager *manager,
	const char *principal_id,
	const uint8_t nonce[PQCP_EDGE_NONCE_BYTES],
	const uint8_t expected_binding[PQCP_EDGE_DIGEST_BYTES],
	uint32_t required_posture_mask,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_attestation_record **record);
int pqcp_edge_attestation_submit(
	struct pqcp_edge_attestation_manager *manager,
	uint64_t challenge_id,
	uint32_t observed_posture_mask,
	const uint8_t evidence_digest[PQCP_EDGE_DIGEST_BYTES],
	const uint8_t binding_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_edge_attestation_is_fresh(
	struct pqcp_edge_attestation_manager *manager,
	const char *principal_id,
	uint64_t now_ms,
	bool *fresh);
int pqcp_edge_attestation_expire(
	struct pqcp_edge_attestation_manager *manager,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_edge_attestation_manager_audit(
	struct pqcp_edge_attestation_manager *manager);

int pqcp_edge_policy_distributor_init(
	struct pqcp_edge_policy_distributor *distributor,
	struct pqcp_edge_policy_bundle *bundles,
	size_t bundle_capacity,
	struct pqcp_edge_policy_ack *acks,
	size_t ack_capacity,
	uint64_t active_policy_epoch,
	const uint8_t active_digest[PQCP_EDGE_DIGEST_BYTES]);
int pqcp_edge_policy_stage(
	struct pqcp_edge_policy_distributor *distributor,
	const uint8_t content_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t not_before_ms,
	uint64_t expires_at_ms,
	uint32_t required_acks,
	uint32_t maximum_failures,
	struct pqcp_edge_policy_bundle **bundle);
int pqcp_edge_policy_acknowledge(
	struct pqcp_edge_policy_distributor *distributor,
	uint64_t bundle_id,
	const char *principal_id,
	const uint8_t applied_digest[PQCP_EDGE_DIGEST_BYTES],
	int result,
	uint64_t now_ms);
int pqcp_edge_policy_promote(
	struct pqcp_edge_policy_distributor *distributor,
	uint64_t bundle_id,
	uint64_t now_ms);
int pqcp_edge_policy_rollback(
	struct pqcp_edge_policy_distributor *distributor,
	uint64_t bundle_id,
	uint64_t now_ms);
int pqcp_edge_policy_distributor_audit(
	struct pqcp_edge_policy_distributor *distributor);

int pqcp_edge_rotation_manager_init(
	struct pqcp_edge_rotation_manager *manager,
	struct pqcp_edge_secret_rotation *rotations,
	size_t capacity);
int pqcp_edge_rotation_plan(
	struct pqcp_edge_rotation_manager *manager,
	const char *secret_id,
	uint64_t current_epoch,
	uint64_t target_epoch,
	const uint8_t current_digest[PQCP_EDGE_DIGEST_BYTES],
	const uint8_t target_digest[PQCP_EDGE_DIGEST_BYTES],
	uint32_t target_count,
	uint32_t maximum_failures,
	uint64_t now_ms,
	uint64_t overlap_until_ms,
	uint64_t deadline_ms,
	struct pqcp_edge_secret_rotation **rotation);
int pqcp_edge_rotation_transition(
	struct pqcp_edge_rotation_manager *manager,
	uint64_t rotation_id,
	enum pqcp_edge_rotation_state state,
	uint64_t now_ms);
int pqcp_edge_rotation_acknowledge(
	struct pqcp_edge_rotation_manager *manager,
	uint64_t rotation_id,
	bool success,
	uint64_t now_ms);
int pqcp_edge_rotation_tick(
	struct pqcp_edge_rotation_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_rotation_manager_audit(
	struct pqcp_edge_rotation_manager *manager);

int pqcp_edge_anomaly_engine_init(
	struct pqcp_edge_anomaly_engine *engine,
	struct pqcp_edge_anomaly_baseline *baselines,
	size_t capacity);
int pqcp_edge_anomaly_observe(
	struct pqcp_edge_anomaly_engine *engine,
	const char *subject_id,
	enum pqcp_edge_metric_type metric,
	uint64_t value,
	uint64_t now_ms,
	uint32_t sensitivity_basis_points,
	struct pqcp_edge_anomaly_result *result);
int pqcp_edge_anomaly_reset(
	struct pqcp_edge_anomaly_engine *engine,
	const char *subject_id,
	enum pqcp_edge_metric_type metric);
int pqcp_edge_anomaly_engine_audit(
	struct pqcp_edge_anomaly_engine *engine);

int pqcp_edge_resource_monitor_init(
	struct pqcp_edge_resource_monitor *monitor,
	struct pqcp_edge_resource_budget *budgets,
	size_t capacity);
int pqcp_edge_resource_budget_put(
	struct pqcp_edge_resource_monitor *monitor,
	const struct pqcp_edge_resource_budget *budget);
int pqcp_edge_resource_reserve(
	struct pqcp_edge_resource_monitor *monitor,
	const char *subject_id,
	enum pqcp_edge_resource_type resource,
	uint64_t amount,
	uint64_t now_ms,
	enum pqcp_edge_resource_action *action);
int pqcp_edge_resource_release(
	struct pqcp_edge_resource_monitor *monitor,
	const char *subject_id,
	enum pqcp_edge_resource_type resource,
	uint64_t amount);
int pqcp_edge_resource_tick(
	struct pqcp_edge_resource_monitor *monitor,
	uint64_t now_ms,
	uint32_t *reset_count);
int pqcp_edge_resource_monitor_audit(
	struct pqcp_edge_resource_monitor *monitor);

int pqcp_edge_audit_exporter_init(
	struct pqcp_edge_audit_exporter *exporter,
	struct pqcp_edge_export_cursor *cursors,
	size_t capacity);
int pqcp_edge_audit_export_open(
	struct pqcp_edge_audit_exporter *exporter,
	const char *consumer_id,
	uint64_t first_sequence,
	uint64_t now_ms,
	uint64_t lifetime_ms,
	struct pqcp_edge_export_cursor **cursor);
/*
 * Export the next batch for a cursor. Returns 0 with a populated batch,
 * -EAGAIN when the cursor is caught up (no new records yet), and
 * -EOVERFLOW when the journal ring overwrote records the cursor had not
 * exported (audit gap). On -EOVERFLOW, batch->first_sequence and
 * batch->last_sequence give the inclusive range of lost sequences,
 * record_count is 0, and the cursor is NOT advanced: the consumer must
 * record the gap and explicitly skip it with
 * pqcp_edge_audit_export_acknowledge(cursor, batch->last_sequence).
 */
int pqcp_edge_audit_export_batch(
	struct pqcp_edge_audit_exporter *exporter,
	struct pqcp_edge_vault_journal *journal,
	uint64_t cursor_id,
	uint32_t maximum_records,
	uint64_t now_ms,
	struct pqcp_edge_export_batch *batch);
int pqcp_edge_audit_export_acknowledge(
	struct pqcp_edge_audit_exporter *exporter,
	uint64_t cursor_id,
	uint64_t sequence);
int pqcp_edge_audit_export_expire(
	struct pqcp_edge_audit_exporter *exporter,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_edge_audit_exporter_audit(
	struct pqcp_edge_audit_exporter *exporter);

int pqcp_edge_recovery_coordinator_init(
	struct pqcp_edge_recovery_coordinator *coordinator,
	struct pqcp_edge_recovery_plan *plans,
	size_t capacity);
int pqcp_edge_recovery_authorize(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t incident_id,
	const char *subject_id,
	uint32_t required_steps,
	uint32_t maximum_failures,
	const uint8_t authorization_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_recovery_plan **plan);
int pqcp_edge_recovery_advance(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t recovery_id,
	enum pqcp_edge_recovery_phase phase,
	uint64_t now_ms);
int pqcp_edge_recovery_record_step(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t recovery_id,
	uint32_t step,
	bool success,
	const uint8_t evidence[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_edge_recovery_checkpoint(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t recovery_id,
	const uint8_t checkpoint[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_edge_recovery_tick(
	struct pqcp_edge_recovery_coordinator *coordinator,
	uint64_t now_ms,
	uint32_t *failed_count);
int pqcp_edge_recovery_coordinator_audit(
	struct pqcp_edge_recovery_coordinator *coordinator);

int pqcp_edge_dlp_engine_init(
	struct pqcp_edge_dlp_engine *engine,
	struct pqcp_edge_dlp_rule *rules,
	size_t capacity);
int pqcp_edge_dlp_rule_put(
	struct pqcp_edge_dlp_engine *engine,
	const struct pqcp_edge_dlp_rule *rule);
int pqcp_edge_dlp_rule_remove(
	struct pqcp_edge_dlp_engine *engine,
	uint32_t rule_id);
int pqcp_edge_dlp_scan(
	struct pqcp_edge_dlp_engine *engine,
	const char *classification,
	const char *destination_domain,
	const uint8_t *payload,
	size_t payload_length,
	bool encrypted,
	struct pqcp_edge_dlp_decision *decision);
int pqcp_edge_dlp_engine_audit(
	struct pqcp_edge_dlp_engine *engine);

int pqcp_edge_trust_federation_init(
	struct pqcp_edge_trust_federation *federation,
	struct pqcp_edge_trust_anchor *anchors,
	size_t anchor_capacity,
	struct pqcp_edge_federation_grant *grants,
	size_t grant_capacity);
int pqcp_edge_trust_anchor_put(
	struct pqcp_edge_trust_federation *federation,
	const struct pqcp_edge_trust_anchor *anchor);
int pqcp_edge_federation_grant_issue(
	struct pqcp_edge_trust_federation *federation,
	const char *source_domain,
	const char *destination_domain,
	uint64_t capabilities,
	uint64_t operation_mask,
	uint32_t maximum_risk,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t maximum_uses,
	struct pqcp_edge_federation_grant **grant);
int pqcp_edge_federation_authorize(
	struct pqcp_edge_trust_federation *federation,
	const char *source_domain,
	const char *destination_domain,
	enum pqcp_edge_operation operation,
	uint64_t capabilities,
	uint32_t risk_score,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms);
int pqcp_edge_federation_revoke(
	struct pqcp_edge_trust_federation *federation,
	uint64_t grant_id);
int pqcp_edge_trust_federation_audit(
	struct pqcp_edge_trust_federation *federation);

int pqcp_edge_credential_cache_init(
	struct pqcp_edge_credential_cache *cache,
	struct pqcp_edge_credential_record *records,
	size_t capacity);
int pqcp_edge_credential_put(
	struct pqcp_edge_credential_cache *cache,
	const struct pqcp_edge_credential_record *record,
	uint64_t now_ms);
int pqcp_edge_credential_authorize(
	struct pqcp_edge_credential_cache *cache,
	const char *credential_id,
	const char *principal_id,
	uint64_t required_capabilities,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms);
int pqcp_edge_credential_revoke(
	struct pqcp_edge_credential_cache *cache,
	const char *credential_id,
	uint64_t revocation_epoch);
int pqcp_edge_credential_tick(
	struct pqcp_edge_credential_cache *cache,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_credential_cache_audit(
	struct pqcp_edge_credential_cache *cache);

int pqcp_edge_isolation_manager_init(
	struct pqcp_edge_isolation_manager *manager,
	struct pqcp_edge_isolation_zone *zones,
	size_t capacity);
int pqcp_edge_isolation_zone_put(
	struct pqcp_edge_isolation_manager *manager,
	const struct pqcp_edge_isolation_zone *zone);
int pqcp_edge_isolation_transition(
	struct pqcp_edge_isolation_manager *manager,
	const char *zone_id,
	enum pqcp_edge_isolation_state state,
	uint32_t reason_mask,
	uint64_t now_ms,
	uint64_t expires_at_ms);
int pqcp_edge_isolation_authorize(
	struct pqcp_edge_isolation_manager *manager,
	const char *zone_id,
	enum pqcp_edge_operation operation,
	uint64_t capabilities,
	uint64_t now_ms);
int pqcp_edge_isolation_reserve(
	struct pqcp_edge_isolation_manager *manager,
	const char *zone_id);
int pqcp_edge_isolation_release(
	struct pqcp_edge_isolation_manager *manager,
	const char *zone_id);
int pqcp_edge_isolation_tick(
	struct pqcp_edge_isolation_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_isolation_manager_audit(
	struct pqcp_edge_isolation_manager *manager);

int pqcp_edge_provenance_ledger_init(
	struct pqcp_edge_provenance_ledger *ledger,
	struct pqcp_edge_provenance_record *records,
	size_t capacity);
int pqcp_edge_provenance_append(
	struct pqcp_edge_provenance_ledger *ledger,
	const char *artifact_id,
	const char *actor_id,
	const char *location_id,
	enum pqcp_edge_provenance_event event,
	uint64_t policy_epoch,
	const uint8_t input_digest[PQCP_EDGE_DIGEST_BYTES],
	const uint8_t output_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_edge_provenance_record *record);
int pqcp_edge_provenance_find(
	struct pqcp_edge_provenance_ledger *ledger,
	uint64_t sequence,
	struct pqcp_edge_provenance_record *record);
int pqcp_edge_provenance_verify(
	struct pqcp_edge_provenance_ledger *ledger);

int pqcp_edge_workload_scheduler_init(
	struct pqcp_edge_workload_scheduler *scheduler,
	struct pqcp_edge_workload_job *jobs,
	size_t capacity);
int pqcp_edge_workload_submit(
	struct pqcp_edge_workload_scheduler *scheduler,
	const struct pqcp_edge_workload_job *job,
	uint64_t now_ms,
	struct pqcp_edge_workload_job **accepted);
int pqcp_edge_workload_next(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t now_ms,
	uint32_t available_resource_mask,
	struct pqcp_edge_workload_job **job);
int pqcp_edge_workload_complete(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t job_id,
	int result,
	uint64_t now_ms);
int pqcp_edge_workload_retry(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t job_id,
	uint64_t retry_at_ms);
int pqcp_edge_workload_cancel(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t job_id);
int pqcp_edge_workload_tick(
	struct pqcp_edge_workload_scheduler *scheduler,
	uint64_t now_ms,
	uint32_t *changed_count);
int pqcp_edge_workload_scheduler_audit(
	struct pqcp_edge_workload_scheduler *scheduler);

int pqcp_edge_sla_monitor_init(
	struct pqcp_edge_sla_monitor *monitor,
	struct pqcp_edge_sla_objective *objectives,
	size_t capacity);
int pqcp_edge_sla_objective_put(
	struct pqcp_edge_sla_monitor *monitor,
	const struct pqcp_edge_sla_objective *objective,
	uint64_t now_ms);
int pqcp_edge_sla_record(
	struct pqcp_edge_sla_monitor *monitor,
	const char *service_id,
	bool success,
	uint64_t latency_us,
	uint64_t now_ms);
int pqcp_edge_sla_evaluate(
	struct pqcp_edge_sla_monitor *monitor,
	const char *service_id,
	uint64_t now_ms,
	enum pqcp_edge_sla_state *state);
int pqcp_edge_sla_tick(
	struct pqcp_edge_sla_monitor *monitor,
	uint64_t now_ms,
	uint32_t *reset_count);
int pqcp_edge_sla_monitor_audit(
	struct pqcp_edge_sla_monitor *monitor);

int pqcp_edge_config_manager_init(
	struct pqcp_edge_config_manager *manager,
	struct pqcp_edge_config_transaction *transactions,
	size_t capacity,
	uint64_t active_generation,
	const uint8_t active_digest[PQCP_EDGE_DIGEST_BYTES]);
int pqcp_edge_config_prepare(
	struct pqcp_edge_config_manager *manager,
	uint64_t base_generation,
	uint64_t target_generation,
	const uint8_t base_digest[PQCP_EDGE_DIGEST_BYTES],
	const uint8_t target_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_edge_config_transaction **transaction);
int pqcp_edge_config_validate(
	struct pqcp_edge_config_manager *manager,
	uint64_t transaction_id,
	const uint8_t validation_digest[PQCP_EDGE_DIGEST_BYTES],
	uint64_t now_ms);
int pqcp_edge_config_commit(
	struct pqcp_edge_config_manager *manager,
	uint64_t transaction_id,
	uint64_t now_ms);
int pqcp_edge_config_abort(
	struct pqcp_edge_config_manager *manager,
	uint64_t transaction_id,
	int result);
int pqcp_edge_config_tick(
	struct pqcp_edge_config_manager *manager,
	uint64_t now_ms,
	uint32_t *aborted_count);
int pqcp_edge_config_manager_audit(
	struct pqcp_edge_config_manager *manager);

int pqcp_edge_compliance_collect(
	struct pqcp_edge_runtime *runtime,
	uint64_t now_ms,
	struct pqcp_edge_compliance_summary *summary);
int pqcp_edge_compliance_encode(
	const struct pqcp_edge_compliance_summary *summary,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);

int pqcp_edge_runtime_init(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_runtime_storage *storage,
	uint64_t policy_epoch);
int pqcp_edge_runtime_tick(
	struct pqcp_edge_runtime *runtime,
	uint64_t now_ms);
int pqcp_edge_runtime_advance_policy(
	struct pqcp_edge_runtime *runtime,
	uint64_t policy_epoch);
int pqcp_edge_runtime_authorize(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request,
	struct pqcp_edge_admission_result *result);
int pqcp_edge_runtime_complete_request(
	struct pqcp_edge_runtime *runtime,
	const char *principal_id,
	const char *service_id,
	const char *endpoint_id,
	bool success,
	uint64_t latency_us,
	uint64_t now_ms);
int pqcp_edge_runtime_audit(
	struct pqcp_edge_runtime *runtime);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_EDGE_SECURITY_H_ */
