/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free desired and reported state for fleet convergence.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_DESIRED_STATE_H_
#define PQCP_ZEPHYR_FLEET_DESIRED_STATE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_resilience.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_DESIRED_STATE_SCHEMA_VERSION 1U
#define PQCP_FLEET_RESOURCE_NAME_MAX_CHARS 48U
#define PQCP_FLEET_RESOURCE_PROFILE_MAX_CHARS 32U
#define PQCP_FLEET_RESOURCE_OWNER_COUNT 8U
#define PQCP_FLEET_STATE_ALL_FIELDS UINT64_MAX

enum pqcp_fleet_resource_kind {
	PQCP_FLEET_RESOURCE_NONE = 0,
	PQCP_FLEET_RESOURCE_IDENTITY,
	PQCP_FLEET_RESOURCE_POLICY,
	PQCP_FLEET_RESOURCE_REVOCATION,
	PQCP_FLEET_RESOURCE_FIRMWARE,
	PQCP_FLEET_RESOURCE_CHANNEL,
	PQCP_FLEET_RESOURCE_RECOVERY,
	PQCP_FLEET_RESOURCE_KIND_COUNT,
};

enum pqcp_fleet_field_owner {
	PQCP_FLEET_FIELD_OWNER_NONE = 0,
	PQCP_FLEET_FIELD_OWNER_REGISTRAR,
	PQCP_FLEET_FIELD_OWNER_SECURITY,
	PQCP_FLEET_FIELD_OWNER_FLEET,
	PQCP_FLEET_FIELD_OWNER_ROLLOUT,
	PQCP_FLEET_FIELD_OWNER_DEVICE,
	PQCP_FLEET_FIELD_OWNER_CHANNEL,
	PQCP_FLEET_FIELD_OWNER_RECOVERY,
	PQCP_FLEET_FIELD_OWNER_COUNT,
};

enum pqcp_fleet_state_origin {
	PQCP_FLEET_STATE_ORIGIN_NONE = 0,
	PQCP_FLEET_STATE_ORIGIN_DESIRED,
	PQCP_FLEET_STATE_ORIGIN_REPORTED,
	PQCP_FLEET_STATE_ORIGIN_RECONCILED,
	PQCP_FLEET_STATE_ORIGIN_RECOVERY,
};

enum pqcp_fleet_resource_flag {
	PQCP_FLEET_RESOURCE_PRESENT = (1U << 0),
	PQCP_FLEET_RESOURCE_TOMBSTONE = (1U << 1),
	PQCP_FLEET_RESOURCE_SECURITY_CRITICAL = (1U << 2),
	PQCP_FLEET_RESOURCE_IMMUTABLE = (1U << 3),
	PQCP_FLEET_RESOURCE_ALLOW_ROLLBACK = (1U << 4),
	PQCP_FLEET_RESOURCE_REQUIRE_ACK = (1U << 5),
	PQCP_FLEET_RESOURCE_QUARANTINED = (1U << 6),
	PQCP_FLEET_RESOURCE_DEGRADED = (1U << 7),
};

enum pqcp_fleet_identity_field {
	PQCP_FLEET_IDENTITY_FIELD_STATE = (UINT64_C(1) << 0),
	PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_EPOCH =
		(UINT64_C(1) << 1),
	PQCP_FLEET_IDENTITY_FIELD_KEY_EPOCH = (UINT64_C(1) << 2),
	PQCP_FLEET_IDENTITY_FIELD_VALID_FROM = (UINT64_C(1) << 3),
	PQCP_FLEET_IDENTITY_FIELD_VALID_UNTIL = (UINT64_C(1) << 4),
	PQCP_FLEET_IDENTITY_FIELD_CAPABILITIES =
		(UINT64_C(1) << 5),
	PQCP_FLEET_IDENTITY_FIELD_SECURITY_LEVEL =
		(UINT64_C(1) << 6),
	PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_DIGEST =
		(UINT64_C(1) << 7),
	PQCP_FLEET_IDENTITY_FIELD_KEY_DIGEST = (UINT64_C(1) << 8),
	PQCP_FLEET_IDENTITY_FIELD_HARDWARE_DIGEST =
		(UINT64_C(1) << 9),
};

enum pqcp_fleet_policy_state_field {
	PQCP_FLEET_POLICY_FIELD_EPOCH = (UINT64_C(1) << 0),
	PQCP_FLEET_POLICY_FIELD_FLAGS = (UINT64_C(1) << 1),
	PQCP_FLEET_POLICY_FIELD_MINIMUM_SECURITY =
		(UINT64_C(1) << 2),
	PQCP_FLEET_POLICY_FIELD_REQUIRED_CAPABILITIES =
		(UINT64_C(1) << 3),
	PQCP_FLEET_POLICY_FIELD_ALLOWED_MLKEM =
		(UINT64_C(1) << 4),
	PQCP_FLEET_POLICY_FIELD_ALLOWED_MLDSA =
		(UINT64_C(1) << 5),
	PQCP_FLEET_POLICY_FIELD_MAXIMUM_SESSIONS =
		(UINT64_C(1) << 6),
	PQCP_FLEET_POLICY_FIELD_MAXIMUM_JOBS =
		(UINT64_C(1) << 7),
	PQCP_FLEET_POLICY_FIELD_PROFILE = (UINT64_C(1) << 8),
	PQCP_FLEET_POLICY_FIELD_BUNDLE_DIGEST =
		(UINT64_C(1) << 9),
};

enum pqcp_fleet_revocation_state_field {
	PQCP_FLEET_REVOCATION_FIELD_EPOCH = (UINT64_C(1) << 0),
	PQCP_FLEET_REVOCATION_FIELD_EFFECTIVE_AT =
		(UINT64_C(1) << 1),
	PQCP_FLEET_REVOCATION_FIELD_REFRESH_DUE =
		(UINT64_C(1) << 2),
	PQCP_FLEET_REVOCATION_FIELD_OFFLINE_GRACE =
		(UINT64_C(1) << 3),
	PQCP_FLEET_REVOCATION_FIELD_REASON = (UINT64_C(1) << 4),
	PQCP_FLEET_REVOCATION_FIELD_REVOKED = (UINT64_C(1) << 5),
	PQCP_FLEET_REVOCATION_FIELD_QUARANTINE =
		(UINT64_C(1) << 6),
	PQCP_FLEET_REVOCATION_FIELD_INDEX_DIGEST =
		(UINT64_C(1) << 7),
};

enum pqcp_fleet_firmware_state_field {
	PQCP_FLEET_FIRMWARE_FIELD_VERSION = (UINT64_C(1) << 0),
	PQCP_FLEET_FIRMWARE_FIELD_ROLLBACK_FLOOR =
		(UINT64_C(1) << 1),
	PQCP_FLEET_FIRMWARE_FIELD_PREVIOUS_VERSION =
		(UINT64_C(1) << 2),
	PQCP_FLEET_FIRMWARE_FIELD_PHASE = (UINT64_C(1) << 3),
	PQCP_FLEET_FIRMWARE_FIELD_FLAGS = (UINT64_C(1) << 4),
	PQCP_FLEET_FIRMWARE_FIELD_HEALTH_EPOCH =
		(UINT64_C(1) << 5),
	PQCP_FLEET_FIRMWARE_FIELD_HEALTHY = (UINT64_C(1) << 6),
	PQCP_FLEET_FIRMWARE_FIELD_IMAGE_DIGEST =
		(UINT64_C(1) << 7),
	PQCP_FLEET_FIRMWARE_FIELD_RUNNING_DIGEST =
		(UINT64_C(1) << 8),
};

enum pqcp_fleet_channel_state_field {
	PQCP_FLEET_CHANNEL_FIELD_EPOCH = (UINT64_C(1) << 0),
	PQCP_FLEET_CHANNEL_FIELD_IDENTITY_EPOCH =
		(UINT64_C(1) << 1),
	PQCP_FLEET_CHANNEL_FIELD_POLICY_EPOCH =
		(UINT64_C(1) << 2),
	PQCP_FLEET_CHANNEL_FIELD_SESSION_GENERATION =
		(UINT64_C(1) << 3),
	PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_BYTES =
		(UINT64_C(1) << 4),
	PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_MS =
		(UINT64_C(1) << 5),
	PQCP_FLEET_CHANNEL_FIELD_PROFILE = (UINT64_C(1) << 6),
	PQCP_FLEET_CHANNEL_FIELD_ONLINE = (UINT64_C(1) << 7),
	PQCP_FLEET_CHANNEL_FIELD_AUTHENTICATED =
		(UINT64_C(1) << 8),
	PQCP_FLEET_CHANNEL_FIELD_REKEY_REQUIRED =
		(UINT64_C(1) << 9),
	PQCP_FLEET_CHANNEL_FIELD_PEER_DIGEST =
		(UINT64_C(1) << 10),
	PQCP_FLEET_CHANNEL_FIELD_TRANSCRIPT_DIGEST =
		(UINT64_C(1) << 11),
};

enum pqcp_fleet_recovery_state_field {
	PQCP_FLEET_RECOVERY_FIELD_EPOCH = (UINT64_C(1) << 0),
	PQCP_FLEET_RECOVERY_FIELD_SESSION_ID = (UINT64_C(1) << 1),
	PQCP_FLEET_RECOVERY_FIELD_STATE = (UINT64_C(1) << 2),
	PQCP_FLEET_RECOVERY_FIELD_REASON = (UINT64_C(1) << 3),
	PQCP_FLEET_RECOVERY_FIELD_BARRIER_GENERATION =
		(UINT64_C(1) << 4),
	PQCP_FLEET_RECOVERY_FIELD_EXPIRES_AT = (UINT64_C(1) << 5),
	PQCP_FLEET_RECOVERY_FIELD_REQUIRED_STEPS =
		(UINT64_C(1) << 6),
	PQCP_FLEET_RECOVERY_FIELD_COMPLETED_STEPS =
		(UINT64_C(1) << 7),
	PQCP_FLEET_RECOVERY_FIELD_AUTHORIZED =
		(UINT64_C(1) << 8),
	PQCP_FLEET_RECOVERY_FIELD_LOCKED = (UINT64_C(1) << 9),
	PQCP_FLEET_RECOVERY_FIELD_AUTHORIZATION_DIGEST =
		(UINT64_C(1) << 10),
	PQCP_FLEET_RECOVERY_FIELD_EVIDENCE_DIGEST =
		(UINT64_C(1) << 11),
};

enum pqcp_fleet_drift_class {
	PQCP_FLEET_DRIFT_NONE = 0,
	PQCP_FLEET_DRIFT_OBSERVED_MISSING,
	PQCP_FLEET_DRIFT_DESIRED_MISSING,
	PQCP_FLEET_DRIFT_OBSERVED_STALE,
	PQCP_FLEET_DRIFT_OBSERVED_AHEAD,
	PQCP_FLEET_DRIFT_VALUE_MISMATCH,
	PQCP_FLEET_DRIFT_DIGEST_CONFLICT,
	PQCP_FLEET_DRIFT_OWNERSHIP_CONFLICT,
	PQCP_FLEET_DRIFT_SECURITY_REGRESSION,
	PQCP_FLEET_DRIFT_ROLLBACK_REQUIRED,
	PQCP_FLEET_DRIFT_BLOCKED,
};

enum pqcp_fleet_drift_severity {
	PQCP_FLEET_DRIFT_SEVERITY_NONE = 0,
	PQCP_FLEET_DRIFT_SEVERITY_INFO,
	PQCP_FLEET_DRIFT_SEVERITY_NOTICE,
	PQCP_FLEET_DRIFT_SEVERITY_WARNING,
	PQCP_FLEET_DRIFT_SEVERITY_ERROR,
	PQCP_FLEET_DRIFT_SEVERITY_CRITICAL,
};

enum pqcp_fleet_drift_reason {
	PQCP_FLEET_DRIFT_REASON_GENERATION = (1U << 0),
	PQCP_FLEET_DRIFT_REASON_EPOCH = (1U << 1),
	PQCP_FLEET_DRIFT_REASON_FIELDS = (1U << 2),
	PQCP_FLEET_DRIFT_REASON_DIGEST = (1U << 3),
	PQCP_FLEET_DRIFT_REASON_OWNER = (1U << 4),
	PQCP_FLEET_DRIFT_REASON_SECURITY = (1U << 5),
	PQCP_FLEET_DRIFT_REASON_TOMBSTONE = (1U << 6),
	PQCP_FLEET_DRIFT_REASON_DEPENDENCY = (1U << 7),
};

enum pqcp_fleet_patch_flag {
	PQCP_FLEET_PATCH_CREATE = (1U << 0),
	PQCP_FLEET_PATCH_ALLOW_IDEMPOTENT = (1U << 1),
	PQCP_FLEET_PATCH_TRANSFER_OWNERSHIP = (1U << 2),
	PQCP_FLEET_PATCH_SECURITY_OVERRIDE = (1U << 3),
	PQCP_FLEET_PATCH_ALLOW_ROLLBACK = (1U << 4),
	PQCP_FLEET_PATCH_REPLACE = (1U << 5),
};

struct pqcp_fleet_resource_key {
	enum pqcp_fleet_resource_kind kind;
	uint64_t resource_id;
	char name[PQCP_FLEET_RESOURCE_NAME_MAX_CHARS];
};

struct pqcp_fleet_identity_state {
	enum pqcp_fleet_device_state device_state;
	uint64_t credential_epoch;
	uint64_t key_epoch;
	uint64_t valid_from_ms;
	uint64_t valid_until_ms;
	uint32_t capabilities;
	uint32_t security_level;
	uint8_t credential_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t key_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t hardware_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_policy_state {
	uint64_t policy_epoch;
	uint32_t flags;
	uint32_t minimum_security_level;
	uint32_t required_capabilities;
	uint32_t allowed_mlkem_mask;
	uint32_t allowed_mldsa_mask;
	uint32_t maximum_sessions;
	uint32_t maximum_jobs;
	char preferred_profile[PQCP_FLEET_RESOURCE_PROFILE_MAX_CHARS];
	uint8_t bundle_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_revocation_state {
	uint64_t revocation_epoch;
	uint64_t effective_at_ms;
	uint64_t refresh_due_ms;
	uint64_t offline_grace_ms;
	uint32_t reason;
	bool revoked;
	bool quarantine;
	uint8_t index_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_firmware_state {
	uint64_t version;
	uint64_t rollback_floor;
	uint64_t previous_version;
	enum pqcp_fleet_update_state phase;
	uint32_t flags;
	uint64_t health_epoch;
	bool healthy;
	uint8_t image_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t running_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_channel_state {
	uint64_t channel_epoch;
	uint64_t identity_epoch;
	uint64_t policy_epoch;
	uint64_t session_generation;
	uint64_t rekey_after_bytes;
	uint64_t rekey_after_ms;
	char profile[PQCP_FLEET_RESOURCE_PROFILE_MAX_CHARS];
	bool online;
	bool authenticated;
	bool rekey_required;
	uint8_t peer_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t transcript_digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_recovery_resource_state {
	uint64_t recovery_epoch;
	uint64_t session_id;
	enum pqcp_fleet_recovery_state state;
	enum pqcp_fleet_recovery_reason reason;
	uint64_t barrier_generation;
	uint64_t expires_at_ms;
	uint32_t required_steps;
	uint32_t completed_steps;
	bool authorized;
	bool locked;
	uint8_t authorization_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_FLEET_DIGEST_BYTES];
};

union pqcp_fleet_resource_value {
	struct pqcp_fleet_identity_state identity;
	struct pqcp_fleet_policy_state policy;
	struct pqcp_fleet_revocation_state revocation;
	struct pqcp_fleet_firmware_state firmware;
	struct pqcp_fleet_channel_state channel;
	struct pqcp_fleet_recovery_resource_state recovery;
};

struct pqcp_fleet_resource_state {
	uint32_t schema_version;
	struct pqcp_fleet_resource_key key;
	uint64_t generation;
	uint64_t epoch;
	uint64_t updated_at_ms;
	uint64_t field_mask;
	uint64_t owner_masks[PQCP_FLEET_FIELD_OWNER_COUNT];
	uint32_t flags;
	enum pqcp_fleet_state_origin origin;
	union pqcp_fleet_resource_value value;
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_state_slot {
	struct pqcp_fleet_resource_state resource;
	bool occupied;
};

struct pqcp_fleet_state_snapshot {
	uint32_t schema_version;
	struct pqcp_fleet_resource_state *resources;
	size_t capacity;
	size_t count;
	uint64_t generation;
	uint64_t maximum_epoch;
	uint64_t created_at_ms;
	enum pqcp_fleet_state_origin origin;
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	bool sealed;
};

struct pqcp_fleet_state_patch {
	struct pqcp_fleet_resource_state resource;
	enum pqcp_fleet_field_owner owner;
	uint64_t field_mask;
	uint64_t expected_generation;
	uint32_t flags;
};

struct pqcp_fleet_state_mutation {
	uint64_t previous_generation;
	uint64_t committed_generation;
	uint64_t changed_fields;
	uint64_t transferred_fields;
	uint8_t previous_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t committed_digest[PQCP_FLEET_DIGEST_BYTES];
	bool created;
	bool idempotent;
	bool tombstoned;
};

struct pqcp_fleet_drift {
	struct pqcp_fleet_resource_key key;
	enum pqcp_fleet_drift_class classification;
	enum pqcp_fleet_drift_severity severity;
	uint32_t reason_mask;
	uint64_t field_mask;
	uint64_t desired_generation;
	uint64_t observed_generation;
	uint64_t desired_epoch;
	uint64_t observed_epoch;
	uint8_t desired_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t observed_digest[PQCP_FLEET_DIGEST_BYTES];
	bool security_critical;
	bool requires_rollback;
};

struct pqcp_fleet_desired_state {
	uint32_t schema_version;
	struct pqcp_fleet_state_slot *desired;
	size_t desired_capacity;
	size_t desired_count;
	struct pqcp_fleet_state_slot *observed;
	size_t observed_capacity;
	size_t observed_count;
	uint64_t desired_generation;
	uint64_t observed_generation;
	uint64_t mutation_count;
	uint64_t rejected_count;
	struct k_mutex lock;
	bool initialized;
};

uint64_t pqcp_fleet_resource_supported_fields(
	enum pqcp_fleet_resource_kind kind);

int pqcp_fleet_resource_state_init(
	struct pqcp_fleet_resource_state *resource,
	enum pqcp_fleet_resource_kind kind,
	uint64_t resource_id,
	const char *name,
	enum pqcp_fleet_state_origin origin);

int pqcp_fleet_resource_set_owner(
	struct pqcp_fleet_resource_state *resource,
	enum pqcp_fleet_field_owner owner,
	uint64_t field_mask,
	bool transfer);

enum pqcp_fleet_field_owner pqcp_fleet_resource_field_owner(
	const struct pqcp_fleet_resource_state *resource,
	uint64_t field);

int pqcp_fleet_resource_digest(
	const struct pqcp_fleet_resource_state *resource,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES]);

int pqcp_fleet_resource_verify(
	const struct pqcp_fleet_resource_state *resource);

int pqcp_fleet_desired_state_init(
	struct pqcp_fleet_desired_state *model,
	struct pqcp_fleet_state_slot *desired,
	size_t desired_capacity,
	struct pqcp_fleet_state_slot *observed,
	size_t observed_capacity);

int pqcp_fleet_desired_apply(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_state_patch *patch,
	struct pqcp_fleet_state_mutation *mutation);

int pqcp_fleet_observed_apply(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_state_patch *patch,
	struct pqcp_fleet_state_mutation *mutation);

int pqcp_fleet_desired_tombstone(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_resource_key *key,
	enum pqcp_fleet_field_owner owner,
	uint64_t generation,
	uint64_t epoch,
	uint64_t now_ms,
	uint32_t patch_flags,
	struct pqcp_fleet_state_mutation *mutation);

int pqcp_fleet_observed_tombstone(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_resource_key *key,
	enum pqcp_fleet_field_owner owner,
	uint64_t generation,
	uint64_t epoch,
	uint64_t now_ms,
	uint32_t patch_flags,
	struct pqcp_fleet_state_mutation *mutation);

int pqcp_fleet_desired_get(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_resource_key *key,
	struct pqcp_fleet_resource_state *resource);

int pqcp_fleet_observed_get(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_resource_key *key,
	struct pqcp_fleet_resource_state *resource);

int pqcp_fleet_desired_snapshot(
	struct pqcp_fleet_desired_state *model,
	struct pqcp_fleet_state_snapshot *snapshot,
	uint64_t now_ms);

int pqcp_fleet_observed_snapshot(
	struct pqcp_fleet_desired_state *model,
	struct pqcp_fleet_state_snapshot *snapshot,
	uint64_t now_ms);

int pqcp_fleet_snapshot_digest(
	const struct pqcp_fleet_state_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES]);

int pqcp_fleet_snapshot_verify(
	const struct pqcp_fleet_state_snapshot *snapshot);

int pqcp_fleet_snapshot_find(
	const struct pqcp_fleet_state_snapshot *snapshot,
	const struct pqcp_fleet_resource_key *key,
	const struct pqcp_fleet_resource_state **resource);

int pqcp_fleet_resource_classify_drift(
	const struct pqcp_fleet_resource_state *desired,
	const struct pqcp_fleet_resource_state *observed,
	struct pqcp_fleet_drift *drift);

int pqcp_fleet_snapshot_classify_drift(
	const struct pqcp_fleet_state_snapshot *desired,
	const struct pqcp_fleet_state_snapshot *observed,
	struct pqcp_fleet_drift *drift,
	size_t drift_capacity,
	size_t *drift_count);

int pqcp_fleet_model_classify_drift(
	struct pqcp_fleet_desired_state *model,
	struct pqcp_fleet_drift *drift,
	size_t drift_capacity,
	size_t *drift_count);

int pqcp_fleet_desired_state_audit(
	struct pqcp_fleet_desired_state *model);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_DESIRED_STATE_H_ */
