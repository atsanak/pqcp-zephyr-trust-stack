/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free desired and reported state for fleet convergence.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_desired_state.h>

#include "fleet_internal.h"

#define RESOURCE_CANONICAL_BYTES 768U
#define SNAPSHOT_CHAIN_BYTES 160U

struct canonical_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

static bool kind_valid(enum pqcp_fleet_resource_kind kind)
{
	return kind > PQCP_FLEET_RESOURCE_NONE &&
	       kind < PQCP_FLEET_RESOURCE_KIND_COUNT;
}

static bool owner_valid(enum pqcp_fleet_field_owner owner)
{
	return owner > PQCP_FLEET_FIELD_OWNER_NONE &&
	       owner < PQCP_FLEET_FIELD_OWNER_COUNT;
}

static bool origin_valid(enum pqcp_fleet_state_origin origin)
{
	return origin > PQCP_FLEET_STATE_ORIGIN_NONE &&
	       origin <= PQCP_FLEET_STATE_ORIGIN_RECOVERY;
}

static bool update_state_valid(enum pqcp_fleet_update_state state)
{
	return state >= PQCP_FLEET_UPDATE_IDLE &&
	       state <= PQCP_FLEET_UPDATE_FAILED;
}

static bool device_state_valid(enum pqcp_fleet_device_state state)
{
	return state >= PQCP_FLEET_DEVICE_FACTORY &&
	       state <= PQCP_FLEET_DEVICE_DECOMMISSIONED;
}

static bool recovery_state_valid(enum pqcp_fleet_recovery_state state)
{
	return state >= PQCP_FLEET_RECOVERY_IDLE &&
	       state <= PQCP_FLEET_RECOVERY_LOCKED;
}

static bool recovery_reason_valid(enum pqcp_fleet_recovery_reason reason)
{
	return reason >= PQCP_FLEET_RECOVERY_REASON_NONE &&
	       reason <= PQCP_FLEET_RECOVERY_OPERATOR_REQUEST;
}

static bool text_valid(const char *text, size_t capacity)
{
	size_t length;

	if (text == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(text, capacity);
	return length > 0U && length < capacity;
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

static bool digest_equal(
	const uint8_t left[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t difference = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static bool size_array_valid(size_t count, size_t element_size)
{
	return element_size != 0U && count <= SIZE_MAX / element_size;
}

static void writer_init(
	struct canonical_writer *writer,
	uint8_t *buffer,
	size_t capacity)
{
	writer->buffer = buffer;
	writer->capacity = capacity;
	writer->offset = 0U;
	writer->error = 0;
}

static void writer_bytes(
	struct canonical_writer *writer,
	const uint8_t *value,
	size_t length)
{
	if (writer->error != 0) {
		return;
	}
	if ((value == NULL && length != 0U) ||
	    length > writer->capacity - writer->offset) {
		writer->error = -EOVERFLOW;
		return;
	}
	if (length != 0U) {
		memcpy(writer->buffer + writer->offset, value, length);
		writer->offset += length;
	}
}

static void writer_u8(
	struct canonical_writer *writer,
	uint8_t value)
{
	writer_bytes(writer, &value, sizeof(value));
}

static void writer_u32(
	struct canonical_writer *writer,
	uint32_t value)
{
	uint8_t encoded[4];

	encoded[0] = (uint8_t)(value >> 24);
	encoded[1] = (uint8_t)(value >> 16);
	encoded[2] = (uint8_t)(value >> 8);
	encoded[3] = (uint8_t)value;
	writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_u64(
	struct canonical_writer *writer,
	uint64_t value)
{
	uint8_t encoded[8];

	for (size_t index = 0U; index < sizeof(encoded); ++index) {
		encoded[sizeof(encoded) - 1U - index] =
			(uint8_t)(value >> (index * 8U));
	}
	writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_bool(
	struct canonical_writer *writer,
	bool value)
{
	writer_u8(writer, value ? 1U : 0U);
}

static void writer_text(
	struct canonical_writer *writer,
	const char *value,
	size_t capacity)
{
	size_t length = strnlen(value, capacity);

	writer_u32(writer, (uint32_t)length);
	writer_bytes(writer, (const uint8_t *)value, length);
}

uint64_t pqcp_fleet_resource_supported_fields(
	enum pqcp_fleet_resource_kind kind)
{
	switch (kind) {
	case PQCP_FLEET_RESOURCE_IDENTITY:
		return PQCP_FLEET_IDENTITY_FIELD_STATE |
		       PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_EPOCH |
		       PQCP_FLEET_IDENTITY_FIELD_KEY_EPOCH |
		       PQCP_FLEET_IDENTITY_FIELD_VALID_FROM |
		       PQCP_FLEET_IDENTITY_FIELD_VALID_UNTIL |
		       PQCP_FLEET_IDENTITY_FIELD_CAPABILITIES |
		       PQCP_FLEET_IDENTITY_FIELD_SECURITY_LEVEL |
		       PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_DIGEST |
		       PQCP_FLEET_IDENTITY_FIELD_KEY_DIGEST |
		       PQCP_FLEET_IDENTITY_FIELD_HARDWARE_DIGEST;
	case PQCP_FLEET_RESOURCE_POLICY:
		return PQCP_FLEET_POLICY_FIELD_EPOCH |
		       PQCP_FLEET_POLICY_FIELD_FLAGS |
		       PQCP_FLEET_POLICY_FIELD_MINIMUM_SECURITY |
		       PQCP_FLEET_POLICY_FIELD_REQUIRED_CAPABILITIES |
		       PQCP_FLEET_POLICY_FIELD_ALLOWED_MLKEM |
		       PQCP_FLEET_POLICY_FIELD_ALLOWED_MLDSA |
		       PQCP_FLEET_POLICY_FIELD_MAXIMUM_SESSIONS |
		       PQCP_FLEET_POLICY_FIELD_MAXIMUM_JOBS |
		       PQCP_FLEET_POLICY_FIELD_PROFILE |
		       PQCP_FLEET_POLICY_FIELD_BUNDLE_DIGEST;
	case PQCP_FLEET_RESOURCE_REVOCATION:
		return PQCP_FLEET_REVOCATION_FIELD_EPOCH |
		       PQCP_FLEET_REVOCATION_FIELD_EFFECTIVE_AT |
		       PQCP_FLEET_REVOCATION_FIELD_REFRESH_DUE |
		       PQCP_FLEET_REVOCATION_FIELD_OFFLINE_GRACE |
		       PQCP_FLEET_REVOCATION_FIELD_REASON |
		       PQCP_FLEET_REVOCATION_FIELD_REVOKED |
		       PQCP_FLEET_REVOCATION_FIELD_QUARANTINE |
		       PQCP_FLEET_REVOCATION_FIELD_INDEX_DIGEST;
	case PQCP_FLEET_RESOURCE_FIRMWARE:
		return PQCP_FLEET_FIRMWARE_FIELD_VERSION |
		       PQCP_FLEET_FIRMWARE_FIELD_ROLLBACK_FLOOR |
		       PQCP_FLEET_FIRMWARE_FIELD_PREVIOUS_VERSION |
		       PQCP_FLEET_FIRMWARE_FIELD_PHASE |
		       PQCP_FLEET_FIRMWARE_FIELD_FLAGS |
		       PQCP_FLEET_FIRMWARE_FIELD_HEALTH_EPOCH |
		       PQCP_FLEET_FIRMWARE_FIELD_HEALTHY |
		       PQCP_FLEET_FIRMWARE_FIELD_IMAGE_DIGEST |
		       PQCP_FLEET_FIRMWARE_FIELD_RUNNING_DIGEST;
	case PQCP_FLEET_RESOURCE_CHANNEL:
		return PQCP_FLEET_CHANNEL_FIELD_EPOCH |
		       PQCP_FLEET_CHANNEL_FIELD_IDENTITY_EPOCH |
		       PQCP_FLEET_CHANNEL_FIELD_POLICY_EPOCH |
		       PQCP_FLEET_CHANNEL_FIELD_SESSION_GENERATION |
		       PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_BYTES |
		       PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_MS |
		       PQCP_FLEET_CHANNEL_FIELD_PROFILE |
		       PQCP_FLEET_CHANNEL_FIELD_ONLINE |
		       PQCP_FLEET_CHANNEL_FIELD_AUTHENTICATED |
		       PQCP_FLEET_CHANNEL_FIELD_REKEY_REQUIRED |
		       PQCP_FLEET_CHANNEL_FIELD_PEER_DIGEST |
		       PQCP_FLEET_CHANNEL_FIELD_TRANSCRIPT_DIGEST;
	case PQCP_FLEET_RESOURCE_RECOVERY:
		return PQCP_FLEET_RECOVERY_FIELD_EPOCH |
		       PQCP_FLEET_RECOVERY_FIELD_SESSION_ID |
		       PQCP_FLEET_RECOVERY_FIELD_STATE |
		       PQCP_FLEET_RECOVERY_FIELD_REASON |
		       PQCP_FLEET_RECOVERY_FIELD_BARRIER_GENERATION |
		       PQCP_FLEET_RECOVERY_FIELD_EXPIRES_AT |
		       PQCP_FLEET_RECOVERY_FIELD_REQUIRED_STEPS |
		       PQCP_FLEET_RECOVERY_FIELD_COMPLETED_STEPS |
		       PQCP_FLEET_RECOVERY_FIELD_AUTHORIZED |
		       PQCP_FLEET_RECOVERY_FIELD_LOCKED |
		       PQCP_FLEET_RECOVERY_FIELD_AUTHORIZATION_DIGEST |
		       PQCP_FLEET_RECOVERY_FIELD_EVIDENCE_DIGEST;
	default:
		return 0U;
	}
}

static int key_validate(const struct pqcp_fleet_resource_key *key)
{
	if (key == NULL || !kind_valid(key->kind) ||
	    key->resource_id == 0U ||
	    !text_valid(key->name, sizeof(key->name))) {
		return -EINVAL;
	}
	return 0;
}

static int key_copy(
	struct pqcp_fleet_resource_key *destination,
	enum pqcp_fleet_resource_kind kind,
	uint64_t resource_id,
	const char *name)
{
	size_t length;

	if (destination == NULL || !kind_valid(kind) ||
	    resource_id == 0U || name == NULL) {
		return -EINVAL;
	}
	length = strnlen(name, sizeof(destination->name));
	if (length == 0U || length >= sizeof(destination->name)) {
		return -EINVAL;
	}
	memset(destination, 0, sizeof(*destination));
	destination->kind = kind;
	destination->resource_id = resource_id;
	memcpy(destination->name, name, length);
	destination->name[length] = '\0';
	return 0;
}

static int key_compare(
	const struct pqcp_fleet_resource_key *left,
	const struct pqcp_fleet_resource_key *right)
{
	if (left->kind < right->kind) {
		return -1;
	}
	if (left->kind > right->kind) {
		return 1;
	}
	if (left->resource_id < right->resource_id) {
		return -1;
	}
	if (left->resource_id > right->resource_id) {
		return 1;
	}
	return strcmp(left->name, right->name);
}

static bool key_equal(
	const struct pqcp_fleet_resource_key *left,
	const struct pqcp_fleet_resource_key *right)
{
	return key_compare(left, right) == 0;
}

int pqcp_fleet_resource_state_init(
	struct pqcp_fleet_resource_state *resource,
	enum pqcp_fleet_resource_kind kind,
	uint64_t resource_id,
	const char *name,
	enum pqcp_fleet_state_origin origin)
{
	int ret;

	if (resource == NULL || !origin_valid(origin)) {
		return -EINVAL;
	}
	memset(resource, 0, sizeof(*resource));
	ret = key_copy(&resource->key, kind, resource_id, name);
	if (ret != 0) {
		return ret;
	}
	resource->schema_version =
		PQCP_FLEET_DESIRED_STATE_SCHEMA_VERSION;
	resource->origin = origin;
	resource->flags = PQCP_FLEET_RESOURCE_PRESENT;
	return 0;
}

enum pqcp_fleet_field_owner pqcp_fleet_resource_field_owner(
	const struct pqcp_fleet_resource_state *resource,
	uint64_t field)
{
	if (resource == NULL || field == 0U ||
	    (field & (field - 1U)) != 0U ||
	    (field & resource->field_mask) == 0U) {
		return PQCP_FLEET_FIELD_OWNER_NONE;
	}
	for (enum pqcp_fleet_field_owner owner =
		     PQCP_FLEET_FIELD_OWNER_REGISTRAR;
	     owner < PQCP_FLEET_FIELD_OWNER_COUNT; ++owner) {
		if ((resource->owner_masks[owner] & field) != 0U) {
			return owner;
		}
	}
	return PQCP_FLEET_FIELD_OWNER_NONE;
}

int pqcp_fleet_resource_set_owner(
	struct pqcp_fleet_resource_state *resource,
	enum pqcp_fleet_field_owner owner,
	uint64_t field_mask,
	bool transfer)
{
	uint64_t supported;
	uint64_t conflicts = 0U;

	if (resource == NULL || !owner_valid(owner) ||
	    field_mask == 0U || !kind_valid(resource->key.kind)) {
		return -EINVAL;
	}
	supported = pqcp_fleet_resource_supported_fields(
		resource->key.kind);
	if ((field_mask & ~supported) != 0U) {
		return -EINVAL;
	}
	for (enum pqcp_fleet_field_owner candidate =
		     PQCP_FLEET_FIELD_OWNER_REGISTRAR;
	     candidate < PQCP_FLEET_FIELD_OWNER_COUNT; ++candidate) {
		if (candidate != owner) {
			conflicts |= resource->owner_masks[candidate] &
				field_mask;
		}
	}
	if (conflicts != 0U && !transfer) {
		return -EACCES;
	}
	for (enum pqcp_fleet_field_owner candidate =
		     PQCP_FLEET_FIELD_OWNER_REGISTRAR;
	     candidate < PQCP_FLEET_FIELD_OWNER_COUNT; ++candidate) {
		if (candidate != owner) {
			resource->owner_masks[candidate] &= ~field_mask;
		}
	}
	resource->owner_masks[owner] |= field_mask;
	resource->field_mask |= field_mask;
	return 0;
}

static int ownership_validate(
	const struct pqcp_fleet_resource_state *resource)
{
	uint64_t aggregate = 0U;

	if (resource->owner_masks[PQCP_FLEET_FIELD_OWNER_NONE] != 0U) {
		return -EBADMSG;
	}
	for (enum pqcp_fleet_field_owner owner =
		     PQCP_FLEET_FIELD_OWNER_REGISTRAR;
	     owner < PQCP_FLEET_FIELD_OWNER_COUNT; ++owner) {
		if ((aggregate & resource->owner_masks[owner]) != 0U) {
			return -EBADMSG;
		}
		aggregate |= resource->owner_masks[owner];
	}
	if (aggregate != resource->field_mask) {
		return -EBADMSG;
	}
	return 0;
}

static int identity_validate(
	const struct pqcp_fleet_resource_state *resource)
{
	const struct pqcp_fleet_identity_state *state =
		&resource->value.identity;
	const uint64_t fields = resource->field_mask;

	if ((fields & PQCP_FLEET_IDENTITY_FIELD_STATE) != 0U &&
	    !device_state_valid(state->device_state)) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_VALID_UNTIL) != 0U &&
	    state->valid_until_ms != 0U &&
	    (fields & PQCP_FLEET_IDENTITY_FIELD_VALID_FROM) != 0U &&
	    state->valid_until_ms <= state->valid_from_ms) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_SECURITY_LEVEL) != 0U &&
	    (state->security_level == 0U ||
	     state->security_level > 5U)) {
		return -EBADMSG;
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_DIGEST) != 0U &&
	    digest_zero(state->credential_digest)) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_KEY_DIGEST) != 0U &&
	    digest_zero(state->key_digest)) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_HARDWARE_DIGEST) != 0U &&
	    digest_zero(state->hardware_digest)) {
		return -EBADMSG;
	}
	return 0;
}

static int policy_validate(
	const struct pqcp_fleet_resource_state *resource)
{
	const struct pqcp_fleet_policy_state *state =
		&resource->value.policy;
	const uint64_t fields = resource->field_mask;

	if ((fields & PQCP_FLEET_POLICY_FIELD_MINIMUM_SECURITY) != 0U &&
	    (state->minimum_security_level == 0U ||
	     state->minimum_security_level > 5U)) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_PROFILE) != 0U &&
	    !text_valid(state->preferred_profile,
			sizeof(state->preferred_profile))) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_BUNDLE_DIGEST) != 0U &&
	    digest_zero(state->bundle_digest)) {
		return -EBADMSG;
	}
	return 0;
}

static int revocation_validate(
	const struct pqcp_fleet_resource_state *resource)
{
	const struct pqcp_fleet_revocation_state *state =
		&resource->value.revocation;
	const uint64_t fields = resource->field_mask;

	if ((fields & PQCP_FLEET_REVOCATION_FIELD_REFRESH_DUE) != 0U &&
	    (fields & PQCP_FLEET_REVOCATION_FIELD_EFFECTIVE_AT) != 0U &&
	    state->refresh_due_ms != 0U &&
	    state->refresh_due_ms < state->effective_at_ms) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_INDEX_DIGEST) != 0U &&
	    digest_zero(state->index_digest)) {
		return -EBADMSG;
	}
	return 0;
}

static int firmware_validate(
	const struct pqcp_fleet_resource_state *resource)
{
	const struct pqcp_fleet_firmware_state *state =
		&resource->value.firmware;
	const uint64_t fields = resource->field_mask;

	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_VERSION) != 0U &&
	    state->version == 0U) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_ROLLBACK_FLOOR) != 0U &&
	    (fields & PQCP_FLEET_FIRMWARE_FIELD_VERSION) != 0U &&
	    state->rollback_floor > state->version) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_PHASE) != 0U &&
	    !update_state_valid(state->phase)) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_IMAGE_DIGEST) != 0U &&
	    digest_zero(state->image_digest)) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_RUNNING_DIGEST) != 0U &&
	    digest_zero(state->running_digest)) {
		return -EBADMSG;
	}
	return 0;
}

static int channel_validate(
	const struct pqcp_fleet_resource_state *resource)
{
	const struct pqcp_fleet_channel_state *state =
		&resource->value.channel;
	const uint64_t fields = resource->field_mask;

	if ((fields & PQCP_FLEET_CHANNEL_FIELD_PROFILE) != 0U &&
	    !text_valid(state->profile, sizeof(state->profile))) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_CHANNEL_FIELD_AUTHENTICATED) != 0U &&
	    state->authenticated &&
	    (fields & PQCP_FLEET_CHANNEL_FIELD_ONLINE) != 0U &&
	    !state->online) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_CHANNEL_FIELD_PEER_DIGEST) != 0U &&
	    digest_zero(state->peer_digest)) {
		return -EBADMSG;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_TRANSCRIPT_DIGEST) != 0U &&
	    digest_zero(state->transcript_digest)) {
		return -EBADMSG;
	}
	return 0;
}

static int recovery_validate(
	const struct pqcp_fleet_resource_state *resource)
{
	const struct pqcp_fleet_recovery_resource_state *state =
		&resource->value.recovery;
	const uint64_t fields = resource->field_mask;

	if ((fields & PQCP_FLEET_RECOVERY_FIELD_STATE) != 0U &&
	    !recovery_state_valid(state->state)) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_REASON) != 0U &&
	    !recovery_reason_valid(state->reason)) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_COMPLETED_STEPS) != 0U &&
	    (fields & PQCP_FLEET_RECOVERY_FIELD_REQUIRED_STEPS) != 0U &&
	    (state->completed_steps & ~state->required_steps) != 0U) {
		return -EBADMSG;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_AUTHORIZATION_DIGEST) != 0U &&
	    digest_zero(state->authorization_digest)) {
		return -EBADMSG;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_EVIDENCE_DIGEST) != 0U &&
	    digest_zero(state->evidence_digest)) {
		return -EBADMSG;
	}
	return 0;
}

static int resource_shape_validate(
	const struct pqcp_fleet_resource_state *resource,
	bool committed)
{
	uint64_t supported;
	int ret;

	if (resource == NULL ||
	    resource->schema_version !=
		    PQCP_FLEET_DESIRED_STATE_SCHEMA_VERSION ||
	    key_validate(&resource->key) != 0 ||
	    !origin_valid(resource->origin)) {
		return -EINVAL;
	}
	supported = pqcp_fleet_resource_supported_fields(
		resource->key.kind);
	if (resource->field_mask == 0U ||
	    (resource->field_mask & ~supported) != 0U ||
	    (resource->flags & PQCP_FLEET_RESOURCE_PRESENT) == 0U) {
		return committed ? -EBADMSG : -EINVAL;
	}
	if (committed &&
	    (resource->generation == 0U ||
	     resource->updated_at_ms == 0U)) {
		return -EBADMSG;
	}
	ret = ownership_validate(resource);
	if (ret != 0) {
		return committed ? -EBADMSG : -EINVAL;
	}
	switch (resource->key.kind) {
	case PQCP_FLEET_RESOURCE_IDENTITY:
		ret = identity_validate(resource);
		break;
	case PQCP_FLEET_RESOURCE_POLICY:
		ret = policy_validate(resource);
		break;
	case PQCP_FLEET_RESOURCE_REVOCATION:
		ret = revocation_validate(resource);
		break;
	case PQCP_FLEET_RESOURCE_FIRMWARE:
		ret = firmware_validate(resource);
		break;
	case PQCP_FLEET_RESOURCE_CHANNEL:
		ret = channel_validate(resource);
		break;
	case PQCP_FLEET_RESOURCE_RECOVERY:
		ret = recovery_validate(resource);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static void write_identity(
	struct canonical_writer *writer,
	const struct pqcp_fleet_identity_state *state)
{
	writer_u32(writer, (uint32_t)state->device_state);
	writer_u64(writer, state->credential_epoch);
	writer_u64(writer, state->key_epoch);
	writer_u64(writer, state->valid_from_ms);
	writer_u64(writer, state->valid_until_ms);
	writer_u32(writer, state->capabilities);
	writer_u32(writer, state->security_level);
	writer_bytes(writer, state->credential_digest,
		     sizeof(state->credential_digest));
	writer_bytes(writer, state->key_digest,
		     sizeof(state->key_digest));
	writer_bytes(writer, state->hardware_digest,
		     sizeof(state->hardware_digest));
}

static void write_policy(
	struct canonical_writer *writer,
	const struct pqcp_fleet_policy_state *state)
{
	writer_u64(writer, state->policy_epoch);
	writer_u32(writer, state->flags);
	writer_u32(writer, state->minimum_security_level);
	writer_u32(writer, state->required_capabilities);
	writer_u32(writer, state->allowed_mlkem_mask);
	writer_u32(writer, state->allowed_mldsa_mask);
	writer_u32(writer, state->maximum_sessions);
	writer_u32(writer, state->maximum_jobs);
	writer_text(writer, state->preferred_profile,
		    sizeof(state->preferred_profile));
	writer_bytes(writer, state->bundle_digest,
		     sizeof(state->bundle_digest));
}

static void write_revocation(
	struct canonical_writer *writer,
	const struct pqcp_fleet_revocation_state *state)
{
	writer_u64(writer, state->revocation_epoch);
	writer_u64(writer, state->effective_at_ms);
	writer_u64(writer, state->refresh_due_ms);
	writer_u64(writer, state->offline_grace_ms);
	writer_u32(writer, state->reason);
	writer_bool(writer, state->revoked);
	writer_bool(writer, state->quarantine);
	writer_bytes(writer, state->index_digest,
		     sizeof(state->index_digest));
}

static void write_firmware(
	struct canonical_writer *writer,
	const struct pqcp_fleet_firmware_state *state)
{
	writer_u64(writer, state->version);
	writer_u64(writer, state->rollback_floor);
	writer_u64(writer, state->previous_version);
	writer_u32(writer, (uint32_t)state->phase);
	writer_u32(writer, state->flags);
	writer_u64(writer, state->health_epoch);
	writer_bool(writer, state->healthy);
	writer_bytes(writer, state->image_digest,
		     sizeof(state->image_digest));
	writer_bytes(writer, state->running_digest,
		     sizeof(state->running_digest));
}

static void write_channel(
	struct canonical_writer *writer,
	const struct pqcp_fleet_channel_state *state)
{
	writer_u64(writer, state->channel_epoch);
	writer_u64(writer, state->identity_epoch);
	writer_u64(writer, state->policy_epoch);
	writer_u64(writer, state->session_generation);
	writer_u64(writer, state->rekey_after_bytes);
	writer_u64(writer, state->rekey_after_ms);
	writer_text(writer, state->profile, sizeof(state->profile));
	writer_bool(writer, state->online);
	writer_bool(writer, state->authenticated);
	writer_bool(writer, state->rekey_required);
	writer_bytes(writer, state->peer_digest,
		     sizeof(state->peer_digest));
	writer_bytes(writer, state->transcript_digest,
		     sizeof(state->transcript_digest));
}

static void write_recovery(
	struct canonical_writer *writer,
	const struct pqcp_fleet_recovery_resource_state *state)
{
	writer_u64(writer, state->recovery_epoch);
	writer_u64(writer, state->session_id);
	writer_u32(writer, (uint32_t)state->state);
	writer_u32(writer, (uint32_t)state->reason);
	writer_u64(writer, state->barrier_generation);
	writer_u64(writer, state->expires_at_ms);
	writer_u32(writer, state->required_steps);
	writer_u32(writer, state->completed_steps);
	writer_bool(writer, state->authorized);
	writer_bool(writer, state->locked);
	writer_bytes(writer, state->authorization_digest,
		     sizeof(state->authorization_digest));
	writer_bytes(writer, state->evidence_digest,
		     sizeof(state->evidence_digest));
}

int pqcp_fleet_resource_digest(
	const struct pqcp_fleet_resource_state *resource,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t canonical[RESOURCE_CANONICAL_BYTES];
	struct canonical_writer writer;
	int ret;

	if (resource == NULL || digest == NULL ||
	    resource_shape_validate(resource, false) != 0) {
		return -EINVAL;
	}
	memset(canonical, 0, sizeof(canonical));
	writer_init(&writer, canonical, sizeof(canonical));
	writer_bytes(&writer,
		     (const uint8_t *)"PQCP-FLEET-RESOURCE-V1", 22U);
	writer_u32(&writer, resource->schema_version);
	writer_u32(&writer, (uint32_t)resource->key.kind);
	writer_u64(&writer, resource->key.resource_id);
	writer_text(&writer, resource->key.name,
		    sizeof(resource->key.name));
	writer_u64(&writer, resource->generation);
	writer_u64(&writer, resource->epoch);
	writer_u64(&writer, resource->updated_at_ms);
	writer_u64(&writer, resource->field_mask);
	for (size_t index = 0U;
	     index < PQCP_FLEET_FIELD_OWNER_COUNT; ++index) {
		writer_u64(&writer, resource->owner_masks[index]);
	}
	writer_u32(&writer, resource->flags);
	writer_u32(&writer, (uint32_t)resource->origin);
	switch (resource->key.kind) {
	case PQCP_FLEET_RESOURCE_IDENTITY:
		write_identity(&writer, &resource->value.identity);
		break;
	case PQCP_FLEET_RESOURCE_POLICY:
		write_policy(&writer, &resource->value.policy);
		break;
	case PQCP_FLEET_RESOURCE_REVOCATION:
		write_revocation(&writer, &resource->value.revocation);
		break;
	case PQCP_FLEET_RESOURCE_FIRMWARE:
		write_firmware(&writer, &resource->value.firmware);
		break;
	case PQCP_FLEET_RESOURCE_CHANNEL:
		write_channel(&writer, &resource->value.channel);
		break;
	case PQCP_FLEET_RESOURCE_RECOVERY:
		write_recovery(&writer, &resource->value.recovery);
		break;
	default:
		writer.error = -EINVAL;
		break;
	}
	ret = writer.error;
	if (ret == 0) {
		ret = pqcp_fleet_sha256(
			canonical, writer.offset, digest);
	}
	memset(canonical, 0, sizeof(canonical));
	return ret;
}

int pqcp_fleet_resource_verify(
	const struct pqcp_fleet_resource_state *resource)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	ret = resource_shape_validate(resource, true);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_fleet_resource_digest(resource, digest);
	if (ret == 0 && !digest_equal(digest, resource->digest)) {
		ret = -EBADMSG;
	}
	memset(digest, 0, sizeof(digest));
	return ret;
}

static int slot_find(
	const struct pqcp_fleet_state_slot *slots,
	size_t capacity,
	const struct pqcp_fleet_resource_key *key)
{
	for (size_t index = 0U; index < capacity; ++index) {
		if (slots[index].occupied &&
		    key_equal(&slots[index].resource.key, key)) {
			if (index > (size_t)INT_MAX) {
				return -EOVERFLOW;
			}
			return (int)index;
		}
	}
	return -ENOENT;
}

static int slot_free(
	const struct pqcp_fleet_state_slot *slots,
	size_t capacity)
{
	for (size_t index = 0U; index < capacity; ++index) {
		if (!slots[index].occupied) {
			if (index > (size_t)INT_MAX) {
				return -EOVERFLOW;
			}
			return (int)index;
		}
	}
	return -ENOSPC;
}

int pqcp_fleet_desired_state_init(
	struct pqcp_fleet_desired_state *model,
	struct pqcp_fleet_state_slot *desired,
	size_t desired_capacity,
	struct pqcp_fleet_state_slot *observed,
	size_t observed_capacity)
{
	if (model == NULL || desired == NULL ||
	    desired_capacity == 0U || observed == NULL ||
	    observed_capacity == 0U ||
	    !size_array_valid(desired_capacity, sizeof(*desired)) ||
	    !size_array_valid(observed_capacity, sizeof(*observed))) {
		return -EINVAL;
	}
	memset(model, 0, sizeof(*model));
	memset(desired, 0, desired_capacity * sizeof(*desired));
	memset(observed, 0, observed_capacity * sizeof(*observed));
	model->schema_version =
		PQCP_FLEET_DESIRED_STATE_SCHEMA_VERSION;
	model->desired = desired;
	model->desired_capacity = desired_capacity;
	model->observed = observed;
	model->observed_capacity = observed_capacity;
	k_mutex_init(&model->lock);
	model->initialized = true;
	return 0;
}

static void merge_identity(
	struct pqcp_fleet_identity_state *destination,
	const struct pqcp_fleet_identity_state *source,
	uint64_t fields)
{
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_STATE) != 0U) {
		destination->device_state = source->device_state;
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_EPOCH) != 0U) {
		destination->credential_epoch =
			source->credential_epoch;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_KEY_EPOCH) != 0U) {
		destination->key_epoch = source->key_epoch;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_VALID_FROM) != 0U) {
		destination->valid_from_ms = source->valid_from_ms;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_VALID_UNTIL) != 0U) {
		destination->valid_until_ms = source->valid_until_ms;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_CAPABILITIES) != 0U) {
		destination->capabilities = source->capabilities;
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_SECURITY_LEVEL) != 0U) {
		destination->security_level = source->security_level;
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_DIGEST) != 0U) {
		memcpy(destination->credential_digest,
		       source->credential_digest,
		       sizeof(destination->credential_digest));
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_KEY_DIGEST) != 0U) {
		memcpy(destination->key_digest, source->key_digest,
		       sizeof(destination->key_digest));
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_HARDWARE_DIGEST) != 0U) {
		memcpy(destination->hardware_digest,
		       source->hardware_digest,
		       sizeof(destination->hardware_digest));
	}
}

static void merge_policy(
	struct pqcp_fleet_policy_state *destination,
	const struct pqcp_fleet_policy_state *source,
	uint64_t fields)
{
	if ((fields & PQCP_FLEET_POLICY_FIELD_EPOCH) != 0U) {
		destination->policy_epoch = source->policy_epoch;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_FLAGS) != 0U) {
		destination->flags = source->flags;
	}
	if ((fields &
	     PQCP_FLEET_POLICY_FIELD_MINIMUM_SECURITY) != 0U) {
		destination->minimum_security_level =
			source->minimum_security_level;
	}
	if ((fields &
	     PQCP_FLEET_POLICY_FIELD_REQUIRED_CAPABILITIES) != 0U) {
		destination->required_capabilities =
			source->required_capabilities;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_ALLOWED_MLKEM) != 0U) {
		destination->allowed_mlkem_mask =
			source->allowed_mlkem_mask;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_ALLOWED_MLDSA) != 0U) {
		destination->allowed_mldsa_mask =
			source->allowed_mldsa_mask;
	}
	if ((fields &
	     PQCP_FLEET_POLICY_FIELD_MAXIMUM_SESSIONS) != 0U) {
		destination->maximum_sessions =
			source->maximum_sessions;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_MAXIMUM_JOBS) != 0U) {
		destination->maximum_jobs = source->maximum_jobs;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_PROFILE) != 0U) {
		memcpy(destination->preferred_profile,
		       source->preferred_profile,
		       sizeof(destination->preferred_profile));
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_BUNDLE_DIGEST) != 0U) {
		memcpy(destination->bundle_digest,
		       source->bundle_digest,
		       sizeof(destination->bundle_digest));
	}
}

static void merge_revocation(
	struct pqcp_fleet_revocation_state *destination,
	const struct pqcp_fleet_revocation_state *source,
	uint64_t fields)
{
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_EPOCH) != 0U) {
		destination->revocation_epoch =
			source->revocation_epoch;
	}
	if ((fields &
	     PQCP_FLEET_REVOCATION_FIELD_EFFECTIVE_AT) != 0U) {
		destination->effective_at_ms =
			source->effective_at_ms;
	}
	if ((fields &
	     PQCP_FLEET_REVOCATION_FIELD_REFRESH_DUE) != 0U) {
		destination->refresh_due_ms = source->refresh_due_ms;
	}
	if ((fields &
	     PQCP_FLEET_REVOCATION_FIELD_OFFLINE_GRACE) != 0U) {
		destination->offline_grace_ms =
			source->offline_grace_ms;
	}
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_REASON) != 0U) {
		destination->reason = source->reason;
	}
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_REVOKED) != 0U) {
		destination->revoked = source->revoked;
	}
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_QUARANTINE) != 0U) {
		destination->quarantine = source->quarantine;
	}
	if ((fields &
	     PQCP_FLEET_REVOCATION_FIELD_INDEX_DIGEST) != 0U) {
		memcpy(destination->index_digest,
		       source->index_digest,
		       sizeof(destination->index_digest));
	}
}

static void merge_firmware(
	struct pqcp_fleet_firmware_state *destination,
	const struct pqcp_fleet_firmware_state *source,
	uint64_t fields)
{
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_VERSION) != 0U) {
		destination->version = source->version;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_ROLLBACK_FLOOR) != 0U) {
		destination->rollback_floor = source->rollback_floor;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_PREVIOUS_VERSION) != 0U) {
		destination->previous_version =
			source->previous_version;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_PHASE) != 0U) {
		destination->phase = source->phase;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_FLAGS) != 0U) {
		destination->flags = source->flags;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_HEALTH_EPOCH) != 0U) {
		destination->health_epoch = source->health_epoch;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_HEALTHY) != 0U) {
		destination->healthy = source->healthy;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_IMAGE_DIGEST) != 0U) {
		memcpy(destination->image_digest,
		       source->image_digest,
		       sizeof(destination->image_digest));
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_RUNNING_DIGEST) != 0U) {
		memcpy(destination->running_digest,
		       source->running_digest,
		       sizeof(destination->running_digest));
	}
}

static void merge_channel(
	struct pqcp_fleet_channel_state *destination,
	const struct pqcp_fleet_channel_state *source,
	uint64_t fields)
{
	if ((fields & PQCP_FLEET_CHANNEL_FIELD_EPOCH) != 0U) {
		destination->channel_epoch = source->channel_epoch;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_IDENTITY_EPOCH) != 0U) {
		destination->identity_epoch = source->identity_epoch;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_POLICY_EPOCH) != 0U) {
		destination->policy_epoch = source->policy_epoch;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_SESSION_GENERATION) != 0U) {
		destination->session_generation =
			source->session_generation;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_BYTES) != 0U) {
		destination->rekey_after_bytes =
			source->rekey_after_bytes;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_MS) != 0U) {
		destination->rekey_after_ms =
			source->rekey_after_ms;
	}
	if ((fields & PQCP_FLEET_CHANNEL_FIELD_PROFILE) != 0U) {
		memcpy(destination->profile, source->profile,
		       sizeof(destination->profile));
	}
	if ((fields & PQCP_FLEET_CHANNEL_FIELD_ONLINE) != 0U) {
		destination->online = source->online;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_AUTHENTICATED) != 0U) {
		destination->authenticated = source->authenticated;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_REKEY_REQUIRED) != 0U) {
		destination->rekey_required = source->rekey_required;
	}
	if ((fields & PQCP_FLEET_CHANNEL_FIELD_PEER_DIGEST) != 0U) {
		memcpy(destination->peer_digest, source->peer_digest,
		       sizeof(destination->peer_digest));
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_TRANSCRIPT_DIGEST) != 0U) {
		memcpy(destination->transcript_digest,
		       source->transcript_digest,
		       sizeof(destination->transcript_digest));
	}
}

static void merge_recovery(
	struct pqcp_fleet_recovery_resource_state *destination,
	const struct pqcp_fleet_recovery_resource_state *source,
	uint64_t fields)
{
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_EPOCH) != 0U) {
		destination->recovery_epoch = source->recovery_epoch;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_SESSION_ID) != 0U) {
		destination->session_id = source->session_id;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_STATE) != 0U) {
		destination->state = source->state;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_REASON) != 0U) {
		destination->reason = source->reason;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_BARRIER_GENERATION) != 0U) {
		destination->barrier_generation =
			source->barrier_generation;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_EXPIRES_AT) != 0U) {
		destination->expires_at_ms = source->expires_at_ms;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_REQUIRED_STEPS) != 0U) {
		destination->required_steps = source->required_steps;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_COMPLETED_STEPS) != 0U) {
		destination->completed_steps = source->completed_steps;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_AUTHORIZED) != 0U) {
		destination->authorized = source->authorized;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_LOCKED) != 0U) {
		destination->locked = source->locked;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_AUTHORIZATION_DIGEST) != 0U) {
		memcpy(destination->authorization_digest,
		       source->authorization_digest,
		       sizeof(destination->authorization_digest));
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_EVIDENCE_DIGEST) != 0U) {
		memcpy(destination->evidence_digest,
		       source->evidence_digest,
		       sizeof(destination->evidence_digest));
	}
}

static void merge_value(
	struct pqcp_fleet_resource_state *destination,
	const struct pqcp_fleet_resource_state *source,
	uint64_t fields)
{
	switch (destination->key.kind) {
	case PQCP_FLEET_RESOURCE_IDENTITY:
		merge_identity(&destination->value.identity,
			       &source->value.identity, fields);
		break;
	case PQCP_FLEET_RESOURCE_POLICY:
		merge_policy(&destination->value.policy,
			     &source->value.policy, fields);
		break;
	case PQCP_FLEET_RESOURCE_REVOCATION:
		merge_revocation(&destination->value.revocation,
				 &source->value.revocation, fields);
		break;
	case PQCP_FLEET_RESOURCE_FIRMWARE:
		merge_firmware(&destination->value.firmware,
			       &source->value.firmware, fields);
		break;
	case PQCP_FLEET_RESOURCE_CHANNEL:
		merge_channel(&destination->value.channel,
			      &source->value.channel, fields);
		break;
	case PQCP_FLEET_RESOURCE_RECOVERY:
		merge_recovery(&destination->value.recovery,
			       &source->value.recovery, fields);
		break;
	default:
		break;
	}
}

static int identity_monotonic(
	const struct pqcp_fleet_resource_state *current,
	const struct pqcp_fleet_resource_state *candidate,
	uint64_t fields,
	uint32_t patch_flags)
{
	const struct pqcp_fleet_identity_state *old =
		&current->value.identity;
	const struct pqcp_fleet_identity_state *next =
		&candidate->value.identity;
	const bool override =
		(patch_flags & PQCP_FLEET_PATCH_SECURITY_OVERRIDE) != 0U;

	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_EPOCH) != 0U &&
	    next->credential_epoch < old->credential_epoch) {
		return -ESTALE;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_KEY_EPOCH) != 0U &&
	    next->key_epoch < old->key_epoch) {
		return -ESTALE;
	}
	if (!override &&
	    (fields & PQCP_FLEET_IDENTITY_FIELD_SECURITY_LEVEL) != 0U &&
	    next->security_level < old->security_level) {
		return -EACCES;
	}
	if (!override &&
	    (fields & PQCP_FLEET_IDENTITY_FIELD_STATE) != 0U &&
	    (old->device_state == PQCP_FLEET_DEVICE_REVOKED ||
	     old->device_state == PQCP_FLEET_DEVICE_DECOMMISSIONED) &&
	    next->device_state != old->device_state) {
		return -EACCES;
	}
	return 0;
}

static int policy_monotonic(
	const struct pqcp_fleet_resource_state *current,
	const struct pqcp_fleet_resource_state *candidate,
	uint64_t fields,
	uint32_t patch_flags)
{
	const struct pqcp_fleet_policy_state *old =
		&current->value.policy;
	const struct pqcp_fleet_policy_state *next =
		&candidate->value.policy;
	const bool override =
		(patch_flags & PQCP_FLEET_PATCH_SECURITY_OVERRIDE) != 0U;

	if ((fields & PQCP_FLEET_POLICY_FIELD_EPOCH) != 0U &&
	    next->policy_epoch < old->policy_epoch) {
		return -ESTALE;
	}
	if (!override &&
	    (fields &
	     PQCP_FLEET_POLICY_FIELD_MINIMUM_SECURITY) != 0U &&
	    next->minimum_security_level <
		    old->minimum_security_level) {
		return -EACCES;
	}
	if (!override &&
	    (fields & PQCP_FLEET_POLICY_FIELD_FLAGS) != 0U &&
	    (old->flags & PQCP_FLEET_POLICY_FORBID_DOWNGRADE) != 0U &&
	    (next->flags & PQCP_FLEET_POLICY_FORBID_DOWNGRADE) == 0U) {
		return -EACCES;
	}
	return 0;
}

static int revocation_monotonic(
	const struct pqcp_fleet_resource_state *current,
	const struct pqcp_fleet_resource_state *candidate,
	uint64_t fields,
	uint32_t patch_flags)
{
	const struct pqcp_fleet_revocation_state *old =
		&current->value.revocation;
	const struct pqcp_fleet_revocation_state *next =
		&candidate->value.revocation;
	const bool override =
		(patch_flags & PQCP_FLEET_PATCH_SECURITY_OVERRIDE) != 0U;

	if ((fields & PQCP_FLEET_REVOCATION_FIELD_EPOCH) != 0U &&
	    next->revocation_epoch < old->revocation_epoch) {
		return -ESTALE;
	}
	if (!override &&
	    (fields & PQCP_FLEET_REVOCATION_FIELD_REVOKED) != 0U &&
	    old->revoked && !next->revoked) {
		return -EACCES;
	}
	if (!override &&
	    (fields & PQCP_FLEET_REVOCATION_FIELD_QUARANTINE) != 0U &&
	    old->quarantine && !next->quarantine) {
		return -EACCES;
	}
	return 0;
}

static int firmware_monotonic(
	const struct pqcp_fleet_resource_state *current,
	const struct pqcp_fleet_resource_state *candidate,
	uint64_t fields,
	uint32_t patch_flags)
{
	const struct pqcp_fleet_firmware_state *old =
		&current->value.firmware;
	const struct pqcp_fleet_firmware_state *next =
		&candidate->value.firmware;
	const bool allow_rollback =
		(patch_flags & PQCP_FLEET_PATCH_ALLOW_ROLLBACK) != 0U ||
		(candidate->flags &
		 PQCP_FLEET_RESOURCE_ALLOW_ROLLBACK) != 0U;

	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_ROLLBACK_FLOOR) != 0U &&
	    next->rollback_floor < old->rollback_floor) {
		return -ESTALE;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_VERSION) != 0U &&
	    next->version < old->version &&
	    (!allow_rollback ||
	     next->version < old->rollback_floor)) {
		return -EACCES;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_HEALTH_EPOCH) != 0U &&
	    next->health_epoch < old->health_epoch) {
		return -ESTALE;
	}
	return 0;
}

static int channel_monotonic(
	const struct pqcp_fleet_resource_state *current,
	const struct pqcp_fleet_resource_state *candidate,
	uint64_t fields)
{
	const struct pqcp_fleet_channel_state *old =
		&current->value.channel;
	const struct pqcp_fleet_channel_state *next =
		&candidate->value.channel;

	if ((fields & PQCP_FLEET_CHANNEL_FIELD_EPOCH) != 0U &&
	    next->channel_epoch < old->channel_epoch) {
		return -ESTALE;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_IDENTITY_EPOCH) != 0U &&
	    next->identity_epoch < old->identity_epoch) {
		return -ESTALE;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_POLICY_EPOCH) != 0U &&
	    next->policy_epoch < old->policy_epoch) {
		return -ESTALE;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_SESSION_GENERATION) != 0U &&
	    next->session_generation < old->session_generation) {
		return -ESTALE;
	}
	return 0;
}

static int recovery_monotonic(
	const struct pqcp_fleet_resource_state *current,
	const struct pqcp_fleet_resource_state *candidate,
	uint64_t fields,
	uint32_t patch_flags)
{
	const struct pqcp_fleet_recovery_resource_state *old =
		&current->value.recovery;
	const struct pqcp_fleet_recovery_resource_state *next =
		&candidate->value.recovery;
	const bool override =
		(patch_flags & PQCP_FLEET_PATCH_SECURITY_OVERRIDE) != 0U;

	if ((fields & PQCP_FLEET_RECOVERY_FIELD_EPOCH) != 0U &&
	    next->recovery_epoch < old->recovery_epoch) {
		return -ESTALE;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_BARRIER_GENERATION) != 0U &&
	    next->barrier_generation < old->barrier_generation) {
		return -ESTALE;
	}
	if (!override &&
	    (fields & PQCP_FLEET_RECOVERY_FIELD_LOCKED) != 0U &&
	    old->locked && !next->locked) {
		return -EACCES;
	}
	return 0;
}

static int resource_monotonic(
	const struct pqcp_fleet_resource_state *current,
	const struct pqcp_fleet_resource_state *candidate,
	uint64_t fields,
	uint32_t patch_flags)
{
	if (candidate->epoch < current->epoch) {
		return -ESTALE;
	}
	if ((current->flags & PQCP_FLEET_RESOURCE_IMMUTABLE) != 0U &&
	    !digest_equal(current->digest, candidate->digest)) {
		return -EROFS;
	}
	if ((current->flags & PQCP_FLEET_RESOURCE_TOMBSTONE) != 0U &&
	    (candidate->flags & PQCP_FLEET_RESOURCE_TOMBSTONE) == 0U &&
	    (patch_flags & PQCP_FLEET_PATCH_SECURITY_OVERRIDE) == 0U) {
		return -EACCES;
	}
	switch (current->key.kind) {
	case PQCP_FLEET_RESOURCE_IDENTITY:
		return identity_monotonic(
			current, candidate, fields, patch_flags);
	case PQCP_FLEET_RESOURCE_POLICY:
		return policy_monotonic(
			current, candidate, fields, patch_flags);
	case PQCP_FLEET_RESOURCE_REVOCATION:
		return revocation_monotonic(
			current, candidate, fields, patch_flags);
	case PQCP_FLEET_RESOURCE_FIRMWARE:
		return firmware_monotonic(
			current, candidate, fields, patch_flags);
	case PQCP_FLEET_RESOURCE_CHANNEL:
		return channel_monotonic(current, candidate, fields);
	case PQCP_FLEET_RESOURCE_RECOVERY:
		return recovery_monotonic(
			current, candidate, fields, patch_flags);
	default:
		return -EINVAL;
	}
}

static uint64_t ownership_conflicts(
	const struct pqcp_fleet_resource_state *current,
	enum pqcp_fleet_field_owner owner,
	uint64_t fields)
{
	uint64_t conflicts = 0U;

	for (enum pqcp_fleet_field_owner candidate =
		     PQCP_FLEET_FIELD_OWNER_REGISTRAR;
	     candidate < PQCP_FLEET_FIELD_OWNER_COUNT; ++candidate) {
		if (candidate != owner) {
			conflicts |= current->owner_masks[candidate] &
				fields;
		}
	}
	return conflicts;
}

static int patch_validate(
	const struct pqcp_fleet_state_patch *patch,
	enum pqcp_fleet_state_origin origin)
{
	uint64_t supported;

	if (patch == NULL || !owner_valid(patch->owner) ||
	    patch->field_mask == 0U ||
	    patch->resource.origin != origin ||
	    patch->resource.generation == 0U ||
	    patch->resource.updated_at_ms == 0U ||
	    key_validate(&patch->resource.key) != 0) {
		return -EINVAL;
	}
	supported = pqcp_fleet_resource_supported_fields(
		patch->resource.key.kind);
	if ((patch->field_mask & ~supported) != 0U ||
	    (patch->resource.field_mask & patch->field_mask) !=
		    patch->field_mask ||
	    (patch->resource.flags &
	     PQCP_FLEET_RESOURCE_PRESENT) == 0U) {
		return -EINVAL;
	}
	return 0;
}

static int apply_locked(
	struct pqcp_fleet_desired_state *model,
	struct pqcp_fleet_state_slot *slots,
	size_t capacity,
	size_t *count,
	uint64_t *collection_generation,
	enum pqcp_fleet_state_origin origin,
	const struct pqcp_fleet_state_patch *patch,
	struct pqcp_fleet_state_mutation *mutation)
{
	struct pqcp_fleet_resource_state candidate;
	struct pqcp_fleet_resource_state *current = NULL;
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	uint64_t conflicts = 0U;
	int index;
	int ret;

	ret = patch_validate(patch, origin);
	if (ret != 0) {
		return ret;
	}
	if (mutation != NULL) {
		memset(mutation, 0, sizeof(*mutation));
	}
	index = slot_find(slots, capacity, &patch->resource.key);
	if (index < 0 && index != -ENOENT) {
		return index;
	}
	if (index == -ENOENT) {
		if ((patch->flags & PQCP_FLEET_PATCH_CREATE) == 0U) {
			return -ENOENT;
		}
		index = slot_free(slots, capacity);
		if (index < 0) {
			return index;
		}
		ret = pqcp_fleet_resource_state_init(
			&candidate, patch->resource.key.kind,
			patch->resource.key.resource_id,
			patch->resource.key.name, origin);
		if (ret != 0) {
			return ret;
		}
		candidate.flags = patch->resource.flags |
			PQCP_FLEET_RESOURCE_PRESENT;
	} else {
		current = &slots[index].resource;
		candidate = *current;
		if (patch->expected_generation != 0U &&
		    patch->expected_generation != current->generation) {
			return -EAGAIN;
		}
		if (patch->resource.generation <
		    current->generation) {
			return -ESTALE;
		}
		conflicts = ownership_conflicts(
			current, patch->owner, patch->field_mask);
		if (conflicts != 0U &&
		    (patch->flags &
		     PQCP_FLEET_PATCH_TRANSFER_OWNERSHIP) == 0U) {
			return -EACCES;
		}
		if ((patch->flags & PQCP_FLEET_PATCH_REPLACE) != 0U) {
			memset(&candidate.value, 0,
			       sizeof(candidate.value));
			memset(candidate.owner_masks, 0,
			       sizeof(candidate.owner_masks));
			candidate.field_mask = 0U;
		}
		candidate.flags = patch->resource.flags |
			PQCP_FLEET_RESOURCE_PRESENT;
	}
	candidate.generation = patch->resource.generation;
	candidate.epoch = patch->resource.epoch;
	candidate.updated_at_ms = patch->resource.updated_at_ms;
	candidate.origin = origin;
	merge_value(&candidate, &patch->resource,
		    patch->field_mask);
	ret = pqcp_fleet_resource_set_owner(
		&candidate, patch->owner, patch->field_mask,
		(patch->flags &
		 PQCP_FLEET_PATCH_TRANSFER_OWNERSHIP) != 0U);
	if (ret != 0) {
		return ret;
	}
	ret = resource_shape_validate(&candidate, false);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_fleet_resource_digest(&candidate, digest);
	if (ret != 0) {
		return ret;
	}
	memcpy(candidate.digest, digest, sizeof(candidate.digest));
	if (current != NULL) {
		if (candidate.generation == current->generation) {
			if ((patch->flags &
			     PQCP_FLEET_PATCH_ALLOW_IDEMPOTENT) != 0U &&
			    digest_equal(candidate.digest,
					 current->digest)) {
				if (mutation != NULL) {
					mutation->previous_generation =
						current->generation;
					mutation->committed_generation =
						current->generation;
					mutation->idempotent = true;
					memcpy(mutation->previous_digest,
					       current->digest,
					       sizeof(mutation->
						      previous_digest));
					memcpy(mutation->committed_digest,
					       current->digest,
					       sizeof(mutation->
						      committed_digest));
				}
				return 0;
			}
			return -EKEYREJECTED;
		}
		ret = resource_monotonic(
			current, &candidate, patch->field_mask,
			patch->flags);
		if (ret != 0) {
			return ret;
		}
	}
	if (*collection_generation == UINT64_MAX ||
	    model->mutation_count == UINT64_MAX) {
		return -EOVERFLOW;
	}
	if (mutation != NULL) {
		mutation->created = current == NULL;
		mutation->changed_fields = patch->field_mask;
		mutation->transferred_fields = conflicts;
		mutation->committed_generation =
			candidate.generation;
		mutation->tombstoned =
			(candidate.flags &
			 PQCP_FLEET_RESOURCE_TOMBSTONE) != 0U;
		memcpy(mutation->committed_digest, candidate.digest,
		       sizeof(mutation->committed_digest));
		if (current != NULL) {
			mutation->previous_generation =
				current->generation;
			memcpy(mutation->previous_digest,
			       current->digest,
			       sizeof(mutation->previous_digest));
		}
	}
	slots[index].resource = candidate;
	if (!slots[index].occupied) {
		slots[index].occupied = true;
		(*count)++;
	}
	(*collection_generation)++;
	model->mutation_count++;
	return 0;
}

static int apply_model(
	struct pqcp_fleet_desired_state *model,
	bool desired,
	const struct pqcp_fleet_state_patch *patch,
	struct pqcp_fleet_state_mutation *mutation)
{
	int ret;

	if (model == NULL || !model->initialized ||
	    model->schema_version !=
		    PQCP_FLEET_DESIRED_STATE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&model->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (desired) {
		ret = apply_locked(
			model, model->desired,
			model->desired_capacity,
			&model->desired_count,
			&model->desired_generation,
			PQCP_FLEET_STATE_ORIGIN_DESIRED,
			patch, mutation);
	} else {
		ret = apply_locked(
			model, model->observed,
			model->observed_capacity,
			&model->observed_count,
			&model->observed_generation,
			PQCP_FLEET_STATE_ORIGIN_REPORTED,
			patch, mutation);
	}
	if (ret != 0 && model->rejected_count != UINT64_MAX) {
		model->rejected_count++;
	}
	(void)k_mutex_unlock(&model->lock);
	return ret;
}

int pqcp_fleet_desired_apply(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_state_patch *patch,
	struct pqcp_fleet_state_mutation *mutation)
{
	return apply_model(model, true, patch, mutation);
}

int pqcp_fleet_observed_apply(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_state_patch *patch,
	struct pqcp_fleet_state_mutation *mutation)
{
	return apply_model(model, false, patch, mutation);
}

static int tombstone_model(
	struct pqcp_fleet_desired_state *model,
	bool desired,
	const struct pqcp_fleet_resource_key *key,
	enum pqcp_fleet_field_owner owner,
	uint64_t generation,
	uint64_t epoch,
	uint64_t now_ms,
	uint32_t patch_flags,
	struct pqcp_fleet_state_mutation *mutation)
{
	struct pqcp_fleet_state_patch patch;
	struct pqcp_fleet_state_slot *slots;
	size_t capacity;
	int index;
	int ret;

	if (model == NULL || !model->initialized ||
	    key_validate(key) != 0 || !owner_valid(owner) ||
	    generation == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&model->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	slots = desired ? model->desired : model->observed;
	capacity = desired ?
		model->desired_capacity : model->observed_capacity;
	index = slot_find(slots, capacity, key);
	if (index < 0) {
		(void)k_mutex_unlock(&model->lock);
		return index;
	}
	memset(&patch, 0, sizeof(patch));
	patch.resource = slots[index].resource;
	patch.resource.generation = generation;
	patch.resource.epoch = epoch;
	patch.resource.updated_at_ms = now_ms;
	patch.resource.flags |=
		PQCP_FLEET_RESOURCE_TOMBSTONE |
		PQCP_FLEET_RESOURCE_SECURITY_CRITICAL;
	patch.resource.origin = desired ?
		PQCP_FLEET_STATE_ORIGIN_DESIRED :
		PQCP_FLEET_STATE_ORIGIN_REPORTED;
	patch.owner = owner;
	patch.field_mask = patch.resource.field_mask;
	patch.expected_generation =
		slots[index].resource.generation;
	patch.flags = patch_flags |
		PQCP_FLEET_PATCH_TRANSFER_OWNERSHIP;
	if (desired) {
		ret = apply_locked(
			model, model->desired,
			model->desired_capacity,
			&model->desired_count,
			&model->desired_generation,
			PQCP_FLEET_STATE_ORIGIN_DESIRED,
			&patch, mutation);
	} else {
		ret = apply_locked(
			model, model->observed,
			model->observed_capacity,
			&model->observed_count,
			&model->observed_generation,
			PQCP_FLEET_STATE_ORIGIN_REPORTED,
			&patch, mutation);
	}
	if (ret != 0 && model->rejected_count != UINT64_MAX) {
		model->rejected_count++;
	}
	(void)k_mutex_unlock(&model->lock);
	return ret;
}

int pqcp_fleet_desired_tombstone(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_resource_key *key,
	enum pqcp_fleet_field_owner owner,
	uint64_t generation,
	uint64_t epoch,
	uint64_t now_ms,
	uint32_t patch_flags,
	struct pqcp_fleet_state_mutation *mutation)
{
	return tombstone_model(
		model, true, key, owner, generation, epoch,
		now_ms, patch_flags, mutation);
}

int pqcp_fleet_observed_tombstone(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_resource_key *key,
	enum pqcp_fleet_field_owner owner,
	uint64_t generation,
	uint64_t epoch,
	uint64_t now_ms,
	uint32_t patch_flags,
	struct pqcp_fleet_state_mutation *mutation)
{
	return tombstone_model(
		model, false, key, owner, generation, epoch,
		now_ms, patch_flags, mutation);
}

static int get_model(
	struct pqcp_fleet_desired_state *model,
	bool desired,
	const struct pqcp_fleet_resource_key *key,
	struct pqcp_fleet_resource_state *resource)
{
	const struct pqcp_fleet_state_slot *slots;
	size_t capacity;
	int index;
	int ret;

	if (model == NULL || !model->initialized ||
	    key_validate(key) != 0 || resource == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&model->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	slots = desired ? model->desired : model->observed;
	capacity = desired ?
		model->desired_capacity : model->observed_capacity;
	index = slot_find(slots, capacity, key);
	if (index >= 0) {
		*resource = slots[index].resource;
		ret = 0;
	} else {
		ret = index;
	}
	(void)k_mutex_unlock(&model->lock);
	return ret;
}

int pqcp_fleet_desired_get(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_resource_key *key,
	struct pqcp_fleet_resource_state *resource)
{
	return get_model(model, true, key, resource);
}

int pqcp_fleet_observed_get(
	struct pqcp_fleet_desired_state *model,
	const struct pqcp_fleet_resource_key *key,
	struct pqcp_fleet_resource_state *resource)
{
	return get_model(model, false, key, resource);
}

static void resource_sort(
	struct pqcp_fleet_resource_state *resources,
	size_t count)
{
	for (size_t index = 1U; index < count; ++index) {
		struct pqcp_fleet_resource_state selected =
			resources[index];
		size_t position = index;

		while (position > 0U &&
		       key_compare(&selected.key,
				   &resources[position - 1U].key) < 0) {
			resources[position] = resources[position - 1U];
			position--;
		}
		resources[position] = selected;
	}
}

int pqcp_fleet_snapshot_digest(
	const struct pqcp_fleet_state_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t chain[PQCP_FLEET_DIGEST_BYTES] = { 0 };
	uint8_t block[SNAPSHOT_CHAIN_BYTES];
	struct canonical_writer writer;
	int ret = 0;

	if (snapshot == NULL || digest == NULL ||
	    snapshot->schema_version !=
		    PQCP_FLEET_DESIRED_STATE_SCHEMA_VERSION ||
	    snapshot->resources == NULL ||
	    snapshot->count > snapshot->capacity ||
	    !origin_valid(snapshot->origin) ||
	    snapshot->created_at_ms == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < snapshot->count; ++index) {
		const struct pqcp_fleet_resource_state *resource =
			&snapshot->resources[index];

		if (pqcp_fleet_resource_verify(resource) != 0 ||
		    resource->origin != snapshot->origin ||
		    (index != 0U &&
		     key_compare(&snapshot->resources[index - 1U].key,
				 &resource->key) >= 0)) {
			return -EBADMSG;
		}
		memset(block, 0, sizeof(block));
		writer_init(&writer, block, sizeof(block));
		writer_bytes(
			&writer,
			(const uint8_t *)"PQCP-FLEET-SNAPSHOT-CHAIN-V1",
			28U);
		writer_u32(&writer, snapshot->schema_version);
		writer_u32(&writer, (uint32_t)snapshot->origin);
		writer_u64(&writer, snapshot->generation);
		writer_u64(&writer, snapshot->maximum_epoch);
		writer_u64(&writer, snapshot->created_at_ms);
		writer_u64(&writer, (uint64_t)snapshot->count);
		writer_u64(&writer, (uint64_t)index);
		writer_bytes(&writer, chain, sizeof(chain));
		writer_bytes(&writer, resource->digest,
			     sizeof(resource->digest));
		if (writer.error != 0) {
			return writer.error;
		}
		ret = pqcp_fleet_sha256(
			block, writer.offset, chain);
		if (ret != 0) {
			break;
		}
	}
	if (ret == 0 && snapshot->count == 0U) {
		memset(block, 0, sizeof(block));
		writer_init(&writer, block, sizeof(block));
		writer_bytes(
			&writer,
			(const uint8_t *)"PQCP-FLEET-SNAPSHOT-EMPTY-V1",
			28U);
		writer_u32(&writer, snapshot->schema_version);
		writer_u32(&writer, (uint32_t)snapshot->origin);
		writer_u64(&writer, snapshot->generation);
		writer_u64(&writer, snapshot->maximum_epoch);
		writer_u64(&writer, snapshot->created_at_ms);
		ret = writer.error;
		if (ret == 0) {
			ret = pqcp_fleet_sha256(
				block, writer.offset, chain);
		}
	}
	if (ret == 0) {
		memcpy(digest, chain, sizeof(chain));
	}
	memset(chain, 0, sizeof(chain));
	memset(block, 0, sizeof(block));
	return ret;
}

int pqcp_fleet_snapshot_verify(
	const struct pqcp_fleet_state_snapshot *snapshot)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	uint64_t maximum_epoch = 0U;
	int ret;

	if (snapshot == NULL || !snapshot->sealed) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < snapshot->count; ++index) {
		if (snapshot->resources[index].epoch > maximum_epoch) {
			maximum_epoch =
				snapshot->resources[index].epoch;
		}
	}
	if (maximum_epoch != snapshot->maximum_epoch) {
		return -EBADMSG;
	}
	ret = pqcp_fleet_snapshot_digest(snapshot, digest);
	if (ret == 0 &&
	    !digest_equal(digest, snapshot->digest)) {
		ret = -EBADMSG;
	}
	memset(digest, 0, sizeof(digest));
	return ret;
}

static int snapshot_model(
	struct pqcp_fleet_desired_state *model,
	bool desired,
	struct pqcp_fleet_state_snapshot *snapshot,
	uint64_t now_ms)
{
	const struct pqcp_fleet_state_slot *slots;
	size_t capacity;
	size_t required;
	size_t output = 0U;
	uint64_t maximum_epoch = 0U;
	int ret;

	if (model == NULL || !model->initialized ||
	    snapshot == NULL || snapshot->resources == NULL ||
	    snapshot->capacity == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&model->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	slots = desired ? model->desired : model->observed;
	capacity = desired ?
		model->desired_capacity : model->observed_capacity;
	required = desired ?
		model->desired_count : model->observed_count;
	if (snapshot->capacity < required) {
		(void)k_mutex_unlock(&model->lock);
		return -ENOSPC;
	}
	for (size_t index = 0U; index < capacity; ++index) {
		if (!slots[index].occupied) {
			continue;
		}
		snapshot->resources[output] = slots[index].resource;
		if (slots[index].resource.epoch > maximum_epoch) {
			maximum_epoch = slots[index].resource.epoch;
		}
		output++;
	}
	snapshot->schema_version =
		PQCP_FLEET_DESIRED_STATE_SCHEMA_VERSION;
	snapshot->count = output;
	snapshot->generation = desired ?
		model->desired_generation :
		model->observed_generation;
	snapshot->maximum_epoch = maximum_epoch;
	snapshot->created_at_ms = now_ms;
	snapshot->origin = desired ?
		PQCP_FLEET_STATE_ORIGIN_DESIRED :
		PQCP_FLEET_STATE_ORIGIN_REPORTED;
	snapshot->sealed = false;
	memset(snapshot->digest, 0, sizeof(snapshot->digest));
	(void)k_mutex_unlock(&model->lock);
	resource_sort(snapshot->resources, snapshot->count);
	ret = pqcp_fleet_snapshot_digest(
		snapshot, snapshot->digest);
	if (ret == 0) {
		snapshot->sealed = true;
	}
	return ret;
}

int pqcp_fleet_desired_snapshot(
	struct pqcp_fleet_desired_state *model,
	struct pqcp_fleet_state_snapshot *snapshot,
	uint64_t now_ms)
{
	return snapshot_model(model, true, snapshot, now_ms);
}

int pqcp_fleet_observed_snapshot(
	struct pqcp_fleet_desired_state *model,
	struct pqcp_fleet_state_snapshot *snapshot,
	uint64_t now_ms)
{
	return snapshot_model(model, false, snapshot, now_ms);
}

int pqcp_fleet_snapshot_find(
	const struct pqcp_fleet_state_snapshot *snapshot,
	const struct pqcp_fleet_resource_key *key,
	const struct pqcp_fleet_resource_state **resource)
{
	size_t low = 0U;
	size_t high;

	if (snapshot == NULL || key_validate(key) != 0 ||
	    resource == NULL ||
	    pqcp_fleet_snapshot_verify(snapshot) != 0) {
		return -EINVAL;
	}
	high = snapshot->count;
	while (low < high) {
		const size_t middle = low + (high - low) / 2U;
		const int comparison = key_compare(
			key, &snapshot->resources[middle].key);

		if (comparison == 0) {
			*resource = &snapshot->resources[middle];
			return 0;
		}
		if (comparison < 0) {
			high = middle;
		} else {
			low = middle + 1U;
		}
	}
	*resource = NULL;
	return -ENOENT;
}

static uint64_t identity_differences(
	const struct pqcp_fleet_identity_state *desired,
	const struct pqcp_fleet_identity_state *observed,
	uint64_t fields)
{
	uint64_t difference = 0U;

	if ((fields & PQCP_FLEET_IDENTITY_FIELD_STATE) != 0U &&
	    desired->device_state != observed->device_state) {
		difference |= PQCP_FLEET_IDENTITY_FIELD_STATE;
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_EPOCH) != 0U &&
	    desired->credential_epoch != observed->credential_epoch) {
		difference |=
			PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_EPOCH;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_KEY_EPOCH) != 0U &&
	    desired->key_epoch != observed->key_epoch) {
		difference |= PQCP_FLEET_IDENTITY_FIELD_KEY_EPOCH;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_VALID_FROM) != 0U &&
	    desired->valid_from_ms != observed->valid_from_ms) {
		difference |= PQCP_FLEET_IDENTITY_FIELD_VALID_FROM;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_VALID_UNTIL) != 0U &&
	    desired->valid_until_ms != observed->valid_until_ms) {
		difference |= PQCP_FLEET_IDENTITY_FIELD_VALID_UNTIL;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_CAPABILITIES) != 0U &&
	    desired->capabilities != observed->capabilities) {
		difference |= PQCP_FLEET_IDENTITY_FIELD_CAPABILITIES;
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_SECURITY_LEVEL) != 0U &&
	    desired->security_level != observed->security_level) {
		difference |=
			PQCP_FLEET_IDENTITY_FIELD_SECURITY_LEVEL;
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_DIGEST) != 0U &&
	    !digest_equal(desired->credential_digest,
			  observed->credential_digest)) {
		difference |=
			PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_DIGEST;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_KEY_DIGEST) != 0U &&
	    !digest_equal(desired->key_digest,
			  observed->key_digest)) {
		difference |= PQCP_FLEET_IDENTITY_FIELD_KEY_DIGEST;
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_HARDWARE_DIGEST) != 0U &&
	    !digest_equal(desired->hardware_digest,
			  observed->hardware_digest)) {
		difference |=
			PQCP_FLEET_IDENTITY_FIELD_HARDWARE_DIGEST;
	}
	return difference;
}

static uint64_t policy_differences(
	const struct pqcp_fleet_policy_state *desired,
	const struct pqcp_fleet_policy_state *observed,
	uint64_t fields)
{
	uint64_t difference = 0U;

	if ((fields & PQCP_FLEET_POLICY_FIELD_EPOCH) != 0U &&
	    desired->policy_epoch != observed->policy_epoch) {
		difference |= PQCP_FLEET_POLICY_FIELD_EPOCH;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_FLAGS) != 0U &&
	    desired->flags != observed->flags) {
		difference |= PQCP_FLEET_POLICY_FIELD_FLAGS;
	}
	if ((fields &
	     PQCP_FLEET_POLICY_FIELD_MINIMUM_SECURITY) != 0U &&
	    desired->minimum_security_level !=
		    observed->minimum_security_level) {
		difference |=
			PQCP_FLEET_POLICY_FIELD_MINIMUM_SECURITY;
	}
	if ((fields &
	     PQCP_FLEET_POLICY_FIELD_REQUIRED_CAPABILITIES) != 0U &&
	    desired->required_capabilities !=
		    observed->required_capabilities) {
		difference |=
			PQCP_FLEET_POLICY_FIELD_REQUIRED_CAPABILITIES;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_ALLOWED_MLKEM) != 0U &&
	    desired->allowed_mlkem_mask !=
		    observed->allowed_mlkem_mask) {
		difference |= PQCP_FLEET_POLICY_FIELD_ALLOWED_MLKEM;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_ALLOWED_MLDSA) != 0U &&
	    desired->allowed_mldsa_mask !=
		    observed->allowed_mldsa_mask) {
		difference |= PQCP_FLEET_POLICY_FIELD_ALLOWED_MLDSA;
	}
	if ((fields &
	     PQCP_FLEET_POLICY_FIELD_MAXIMUM_SESSIONS) != 0U &&
	    desired->maximum_sessions != observed->maximum_sessions) {
		difference |=
			PQCP_FLEET_POLICY_FIELD_MAXIMUM_SESSIONS;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_MAXIMUM_JOBS) != 0U &&
	    desired->maximum_jobs != observed->maximum_jobs) {
		difference |= PQCP_FLEET_POLICY_FIELD_MAXIMUM_JOBS;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_PROFILE) != 0U &&
	    strcmp(desired->preferred_profile,
		   observed->preferred_profile) != 0) {
		difference |= PQCP_FLEET_POLICY_FIELD_PROFILE;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_BUNDLE_DIGEST) != 0U &&
	    !digest_equal(desired->bundle_digest,
			  observed->bundle_digest)) {
		difference |= PQCP_FLEET_POLICY_FIELD_BUNDLE_DIGEST;
	}
	return difference;
}

static uint64_t revocation_differences(
	const struct pqcp_fleet_revocation_state *desired,
	const struct pqcp_fleet_revocation_state *observed,
	uint64_t fields)
{
	uint64_t difference = 0U;

	if ((fields & PQCP_FLEET_REVOCATION_FIELD_EPOCH) != 0U &&
	    desired->revocation_epoch != observed->revocation_epoch) {
		difference |= PQCP_FLEET_REVOCATION_FIELD_EPOCH;
	}
	if ((fields &
	     PQCP_FLEET_REVOCATION_FIELD_EFFECTIVE_AT) != 0U &&
	    desired->effective_at_ms != observed->effective_at_ms) {
		difference |=
			PQCP_FLEET_REVOCATION_FIELD_EFFECTIVE_AT;
	}
	if ((fields &
	     PQCP_FLEET_REVOCATION_FIELD_REFRESH_DUE) != 0U &&
	    desired->refresh_due_ms != observed->refresh_due_ms) {
		difference |=
			PQCP_FLEET_REVOCATION_FIELD_REFRESH_DUE;
	}
	if ((fields &
	     PQCP_FLEET_REVOCATION_FIELD_OFFLINE_GRACE) != 0U &&
	    desired->offline_grace_ms != observed->offline_grace_ms) {
		difference |=
			PQCP_FLEET_REVOCATION_FIELD_OFFLINE_GRACE;
	}
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_REASON) != 0U &&
	    desired->reason != observed->reason) {
		difference |= PQCP_FLEET_REVOCATION_FIELD_REASON;
	}
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_REVOKED) != 0U &&
	    desired->revoked != observed->revoked) {
		difference |= PQCP_FLEET_REVOCATION_FIELD_REVOKED;
	}
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_QUARANTINE) != 0U &&
	    desired->quarantine != observed->quarantine) {
		difference |= PQCP_FLEET_REVOCATION_FIELD_QUARANTINE;
	}
	if ((fields &
	     PQCP_FLEET_REVOCATION_FIELD_INDEX_DIGEST) != 0U &&
	    !digest_equal(desired->index_digest,
			  observed->index_digest)) {
		difference |=
			PQCP_FLEET_REVOCATION_FIELD_INDEX_DIGEST;
	}
	return difference;
}

static uint64_t firmware_differences(
	const struct pqcp_fleet_firmware_state *desired,
	const struct pqcp_fleet_firmware_state *observed,
	uint64_t fields)
{
	uint64_t difference = 0U;

	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_VERSION) != 0U &&
	    desired->version != observed->version) {
		difference |= PQCP_FLEET_FIRMWARE_FIELD_VERSION;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_ROLLBACK_FLOOR) != 0U &&
	    desired->rollback_floor != observed->rollback_floor) {
		difference |=
			PQCP_FLEET_FIRMWARE_FIELD_ROLLBACK_FLOOR;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_PREVIOUS_VERSION) != 0U &&
	    desired->previous_version != observed->previous_version) {
		difference |=
			PQCP_FLEET_FIRMWARE_FIELD_PREVIOUS_VERSION;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_PHASE) != 0U &&
	    desired->phase != observed->phase) {
		difference |= PQCP_FLEET_FIRMWARE_FIELD_PHASE;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_FLAGS) != 0U &&
	    desired->flags != observed->flags) {
		difference |= PQCP_FLEET_FIRMWARE_FIELD_FLAGS;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_HEALTH_EPOCH) != 0U &&
	    desired->health_epoch != observed->health_epoch) {
		difference |=
			PQCP_FLEET_FIRMWARE_FIELD_HEALTH_EPOCH;
	}
	if ((fields & PQCP_FLEET_FIRMWARE_FIELD_HEALTHY) != 0U &&
	    desired->healthy != observed->healthy) {
		difference |= PQCP_FLEET_FIRMWARE_FIELD_HEALTHY;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_IMAGE_DIGEST) != 0U &&
	    !digest_equal(desired->image_digest,
			  observed->image_digest)) {
		difference |= PQCP_FLEET_FIRMWARE_FIELD_IMAGE_DIGEST;
	}
	if ((fields &
	     PQCP_FLEET_FIRMWARE_FIELD_RUNNING_DIGEST) != 0U &&
	    !digest_equal(desired->running_digest,
			  observed->running_digest)) {
		difference |=
			PQCP_FLEET_FIRMWARE_FIELD_RUNNING_DIGEST;
	}
	return difference;
}

static uint64_t channel_differences(
	const struct pqcp_fleet_channel_state *desired,
	const struct pqcp_fleet_channel_state *observed,
	uint64_t fields)
{
	uint64_t difference = 0U;

	if ((fields & PQCP_FLEET_CHANNEL_FIELD_EPOCH) != 0U &&
	    desired->channel_epoch != observed->channel_epoch) {
		difference |= PQCP_FLEET_CHANNEL_FIELD_EPOCH;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_IDENTITY_EPOCH) != 0U &&
	    desired->identity_epoch != observed->identity_epoch) {
		difference |=
			PQCP_FLEET_CHANNEL_FIELD_IDENTITY_EPOCH;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_POLICY_EPOCH) != 0U &&
	    desired->policy_epoch != observed->policy_epoch) {
		difference |= PQCP_FLEET_CHANNEL_FIELD_POLICY_EPOCH;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_SESSION_GENERATION) != 0U &&
	    desired->session_generation !=
		    observed->session_generation) {
		difference |=
			PQCP_FLEET_CHANNEL_FIELD_SESSION_GENERATION;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_BYTES) != 0U &&
	    desired->rekey_after_bytes != observed->rekey_after_bytes) {
		difference |=
			PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_BYTES;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_MS) != 0U &&
	    desired->rekey_after_ms != observed->rekey_after_ms) {
		difference |=
			PQCP_FLEET_CHANNEL_FIELD_REKEY_AFTER_MS;
	}
	if ((fields & PQCP_FLEET_CHANNEL_FIELD_PROFILE) != 0U &&
	    strcmp(desired->profile, observed->profile) != 0) {
		difference |= PQCP_FLEET_CHANNEL_FIELD_PROFILE;
	}
	if ((fields & PQCP_FLEET_CHANNEL_FIELD_ONLINE) != 0U &&
	    desired->online != observed->online) {
		difference |= PQCP_FLEET_CHANNEL_FIELD_ONLINE;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_AUTHENTICATED) != 0U &&
	    desired->authenticated != observed->authenticated) {
		difference |= PQCP_FLEET_CHANNEL_FIELD_AUTHENTICATED;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_REKEY_REQUIRED) != 0U &&
	    desired->rekey_required != observed->rekey_required) {
		difference |=
			PQCP_FLEET_CHANNEL_FIELD_REKEY_REQUIRED;
	}
	if ((fields & PQCP_FLEET_CHANNEL_FIELD_PEER_DIGEST) != 0U &&
	    !digest_equal(desired->peer_digest,
			  observed->peer_digest)) {
		difference |= PQCP_FLEET_CHANNEL_FIELD_PEER_DIGEST;
	}
	if ((fields &
	     PQCP_FLEET_CHANNEL_FIELD_TRANSCRIPT_DIGEST) != 0U &&
	    !digest_equal(desired->transcript_digest,
			  observed->transcript_digest)) {
		difference |=
			PQCP_FLEET_CHANNEL_FIELD_TRANSCRIPT_DIGEST;
	}
	return difference;
}

static uint64_t recovery_differences(
	const struct pqcp_fleet_recovery_resource_state *desired,
	const struct pqcp_fleet_recovery_resource_state *observed,
	uint64_t fields)
{
	uint64_t difference = 0U;

	if ((fields & PQCP_FLEET_RECOVERY_FIELD_EPOCH) != 0U &&
	    desired->recovery_epoch != observed->recovery_epoch) {
		difference |= PQCP_FLEET_RECOVERY_FIELD_EPOCH;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_SESSION_ID) != 0U &&
	    desired->session_id != observed->session_id) {
		difference |= PQCP_FLEET_RECOVERY_FIELD_SESSION_ID;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_STATE) != 0U &&
	    desired->state != observed->state) {
		difference |= PQCP_FLEET_RECOVERY_FIELD_STATE;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_REASON) != 0U &&
	    desired->reason != observed->reason) {
		difference |= PQCP_FLEET_RECOVERY_FIELD_REASON;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_BARRIER_GENERATION) != 0U &&
	    desired->barrier_generation !=
		    observed->barrier_generation) {
		difference |=
			PQCP_FLEET_RECOVERY_FIELD_BARRIER_GENERATION;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_EXPIRES_AT) != 0U &&
	    desired->expires_at_ms != observed->expires_at_ms) {
		difference |= PQCP_FLEET_RECOVERY_FIELD_EXPIRES_AT;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_REQUIRED_STEPS) != 0U &&
	    desired->required_steps != observed->required_steps) {
		difference |= PQCP_FLEET_RECOVERY_FIELD_REQUIRED_STEPS;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_COMPLETED_STEPS) != 0U &&
	    desired->completed_steps != observed->completed_steps) {
		difference |=
			PQCP_FLEET_RECOVERY_FIELD_COMPLETED_STEPS;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_AUTHORIZED) != 0U &&
	    desired->authorized != observed->authorized) {
		difference |= PQCP_FLEET_RECOVERY_FIELD_AUTHORIZED;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_LOCKED) != 0U &&
	    desired->locked != observed->locked) {
		difference |= PQCP_FLEET_RECOVERY_FIELD_LOCKED;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_AUTHORIZATION_DIGEST) != 0U &&
	    !digest_equal(desired->authorization_digest,
			  observed->authorization_digest)) {
		difference |=
			PQCP_FLEET_RECOVERY_FIELD_AUTHORIZATION_DIGEST;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_EVIDENCE_DIGEST) != 0U &&
	    !digest_equal(desired->evidence_digest,
			  observed->evidence_digest)) {
		difference |=
			PQCP_FLEET_RECOVERY_FIELD_EVIDENCE_DIGEST;
	}
	return difference;
}

static uint64_t resource_differences(
	const struct pqcp_fleet_resource_state *desired,
	const struct pqcp_fleet_resource_state *observed)
{
	const uint64_t fields = desired->field_mask;

	switch (desired->key.kind) {
	case PQCP_FLEET_RESOURCE_IDENTITY:
		return identity_differences(
			&desired->value.identity,
			&observed->value.identity, fields);
	case PQCP_FLEET_RESOURCE_POLICY:
		return policy_differences(
			&desired->value.policy,
			&observed->value.policy, fields);
	case PQCP_FLEET_RESOURCE_REVOCATION:
		return revocation_differences(
			&desired->value.revocation,
			&observed->value.revocation, fields);
	case PQCP_FLEET_RESOURCE_FIRMWARE:
		return firmware_differences(
			&desired->value.firmware,
			&observed->value.firmware, fields);
	case PQCP_FLEET_RESOURCE_CHANNEL:
		return channel_differences(
			&desired->value.channel,
			&observed->value.channel, fields);
	case PQCP_FLEET_RESOURCE_RECOVERY:
		return recovery_differences(
			&desired->value.recovery,
			&observed->value.recovery, fields);
	default:
		return fields;
	}
}

static bool identity_security_regression(
	const struct pqcp_fleet_identity_state *desired,
	const struct pqcp_fleet_identity_state *observed,
	uint64_t fields)
{
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_EPOCH) != 0U &&
	    observed->credential_epoch > desired->credential_epoch) {
		return true;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_KEY_EPOCH) != 0U &&
	    observed->key_epoch > desired->key_epoch) {
		return true;
	}
	if ((fields &
	     PQCP_FLEET_IDENTITY_FIELD_SECURITY_LEVEL) != 0U &&
	    observed->security_level > desired->security_level) {
		return true;
	}
	if ((fields & PQCP_FLEET_IDENTITY_FIELD_STATE) != 0U &&
	    (observed->device_state == PQCP_FLEET_DEVICE_REVOKED ||
	     observed->device_state ==
		     PQCP_FLEET_DEVICE_DECOMMISSIONED) &&
	    desired->device_state != observed->device_state) {
		return true;
	}
	return false;
}

static bool policy_security_regression(
	const struct pqcp_fleet_policy_state *desired,
	const struct pqcp_fleet_policy_state *observed,
	uint64_t fields)
{
	if ((fields & PQCP_FLEET_POLICY_FIELD_EPOCH) != 0U &&
	    observed->policy_epoch > desired->policy_epoch) {
		return true;
	}
	if ((fields &
	     PQCP_FLEET_POLICY_FIELD_MINIMUM_SECURITY) != 0U &&
	    observed->minimum_security_level >
		    desired->minimum_security_level) {
		return true;
	}
	if ((fields & PQCP_FLEET_POLICY_FIELD_FLAGS) != 0U &&
	    (observed->flags & PQCP_FLEET_POLICY_LOCKDOWN) != 0U &&
	    (desired->flags & PQCP_FLEET_POLICY_LOCKDOWN) == 0U) {
		return true;
	}
	return false;
}

static bool revocation_security_regression(
	const struct pqcp_fleet_revocation_state *desired,
	const struct pqcp_fleet_revocation_state *observed,
	uint64_t fields)
{
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_EPOCH) != 0U &&
	    observed->revocation_epoch > desired->revocation_epoch) {
		return true;
	}
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_REVOKED) != 0U &&
	    observed->revoked && !desired->revoked) {
		return true;
	}
	if ((fields & PQCP_FLEET_REVOCATION_FIELD_QUARANTINE) != 0U &&
	    observed->quarantine && !desired->quarantine) {
		return true;
	}
	return false;
}

static bool firmware_rollback_required(
	const struct pqcp_fleet_firmware_state *desired,
	const struct pqcp_fleet_firmware_state *observed,
	uint64_t fields)
{
	return (fields & PQCP_FLEET_FIRMWARE_FIELD_VERSION) != 0U &&
	       observed->version > desired->version;
}

static bool recovery_security_regression(
	const struct pqcp_fleet_recovery_resource_state *desired,
	const struct pqcp_fleet_recovery_resource_state *observed,
	uint64_t fields)
{
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_EPOCH) != 0U &&
	    observed->recovery_epoch > desired->recovery_epoch) {
		return true;
	}
	if ((fields & PQCP_FLEET_RECOVERY_FIELD_LOCKED) != 0U &&
	    observed->locked && !desired->locked) {
		return true;
	}
	if ((fields &
	     PQCP_FLEET_RECOVERY_FIELD_BARRIER_GENERATION) != 0U &&
	    observed->barrier_generation >
		    desired->barrier_generation) {
		return true;
	}
	return false;
}

static bool security_regression(
	const struct pqcp_fleet_resource_state *desired,
	const struct pqcp_fleet_resource_state *observed,
	uint64_t fields)
{
	switch (desired->key.kind) {
	case PQCP_FLEET_RESOURCE_IDENTITY:
		return identity_security_regression(
			&desired->value.identity,
			&observed->value.identity, fields);
	case PQCP_FLEET_RESOURCE_POLICY:
		return policy_security_regression(
			&desired->value.policy,
			&observed->value.policy, fields);
	case PQCP_FLEET_RESOURCE_REVOCATION:
		return revocation_security_regression(
			&desired->value.revocation,
			&observed->value.revocation, fields);
	case PQCP_FLEET_RESOURCE_RECOVERY:
		return recovery_security_regression(
			&desired->value.recovery,
			&observed->value.recovery, fields);
	default:
		return false;
	}
}

static bool same_epoch_digest_conflict(
	const struct pqcp_fleet_resource_state *desired,
	const struct pqcp_fleet_resource_state *observed,
	uint64_t differences)
{
	uint64_t digest_fields = 0U;

	switch (desired->key.kind) {
	case PQCP_FLEET_RESOURCE_IDENTITY:
		digest_fields =
			PQCP_FLEET_IDENTITY_FIELD_CREDENTIAL_DIGEST |
			PQCP_FLEET_IDENTITY_FIELD_KEY_DIGEST |
			PQCP_FLEET_IDENTITY_FIELD_HARDWARE_DIGEST;
		break;
	case PQCP_FLEET_RESOURCE_POLICY:
		digest_fields =
			PQCP_FLEET_POLICY_FIELD_BUNDLE_DIGEST;
		break;
	case PQCP_FLEET_RESOURCE_REVOCATION:
		digest_fields =
			PQCP_FLEET_REVOCATION_FIELD_INDEX_DIGEST;
		break;
	case PQCP_FLEET_RESOURCE_FIRMWARE:
		digest_fields =
			PQCP_FLEET_FIRMWARE_FIELD_IMAGE_DIGEST |
			PQCP_FLEET_FIRMWARE_FIELD_RUNNING_DIGEST;
		break;
	case PQCP_FLEET_RESOURCE_CHANNEL:
		digest_fields =
			PQCP_FLEET_CHANNEL_FIELD_PEER_DIGEST |
			PQCP_FLEET_CHANNEL_FIELD_TRANSCRIPT_DIGEST;
		break;
	case PQCP_FLEET_RESOURCE_RECOVERY:
		digest_fields =
			PQCP_FLEET_RECOVERY_FIELD_AUTHORIZATION_DIGEST |
			PQCP_FLEET_RECOVERY_FIELD_EVIDENCE_DIGEST;
		break;
	default:
		break;
	}
	return desired->epoch == observed->epoch &&
	       (differences & digest_fields) != 0U;
}

static bool ownership_conflict(
	const struct pqcp_fleet_resource_state *desired,
	const struct pqcp_fleet_resource_state *observed)
{
	uint64_t fields =
		desired->field_mask & observed->field_mask;

	while (fields != 0U) {
		const uint64_t field = fields & (~fields + 1U);
		const enum pqcp_fleet_field_owner desired_owner =
			pqcp_fleet_resource_field_owner(
				desired, field);
		const enum pqcp_fleet_field_owner observed_owner =
			pqcp_fleet_resource_field_owner(
				observed, field);

		if (observed_owner != PQCP_FLEET_FIELD_OWNER_NONE &&
		    observed_owner != PQCP_FLEET_FIELD_OWNER_DEVICE &&
		    observed_owner != PQCP_FLEET_FIELD_OWNER_CHANNEL &&
		    observed_owner != PQCP_FLEET_FIELD_OWNER_RECOVERY &&
		    observed_owner != desired_owner) {
			return true;
		}
		fields &= ~field;
	}
	return false;
}

int pqcp_fleet_resource_classify_drift(
	const struct pqcp_fleet_resource_state *desired,
	const struct pqcp_fleet_resource_state *observed,
	struct pqcp_fleet_drift *drift)
{
	uint64_t differences;
	uint64_t missing_fields;

	if (drift == NULL ||
	    (desired == NULL && observed == NULL) ||
	    (desired != NULL &&
	     pqcp_fleet_resource_verify(desired) != 0) ||
	    (observed != NULL &&
	     pqcp_fleet_resource_verify(observed) != 0) ||
	    (desired != NULL && observed != NULL &&
	     !key_equal(&desired->key, &observed->key))) {
		return -EINVAL;
	}
	memset(drift, 0, sizeof(*drift));
	if (desired == NULL) {
		drift->key = observed->key;
		drift->classification =
			PQCP_FLEET_DRIFT_DESIRED_MISSING;
		drift->severity = PQCP_FLEET_DRIFT_SEVERITY_NOTICE;
		drift->reason_mask =
			PQCP_FLEET_DRIFT_REASON_GENERATION;
		drift->field_mask = observed->field_mask;
		drift->observed_generation = observed->generation;
		drift->observed_epoch = observed->epoch;
		memcpy(drift->observed_digest, observed->digest,
		       sizeof(drift->observed_digest));
		return 0;
	}
	drift->key = desired->key;
	drift->desired_generation = desired->generation;
	drift->desired_epoch = desired->epoch;
	memcpy(drift->desired_digest, desired->digest,
	       sizeof(drift->desired_digest));
	if (observed == NULL) {
		drift->classification =
			PQCP_FLEET_DRIFT_OBSERVED_MISSING;
		drift->severity =
			(desired->flags &
			 PQCP_FLEET_RESOURCE_SECURITY_CRITICAL) != 0U ?
				PQCP_FLEET_DRIFT_SEVERITY_CRITICAL :
				PQCP_FLEET_DRIFT_SEVERITY_WARNING;
		drift->reason_mask =
			PQCP_FLEET_DRIFT_REASON_GENERATION |
			PQCP_FLEET_DRIFT_REASON_FIELDS;
		drift->field_mask = desired->field_mask;
		drift->security_critical =
			(desired->flags &
			 PQCP_FLEET_RESOURCE_SECURITY_CRITICAL) != 0U;
		return 0;
	}
	drift->observed_generation = observed->generation;
	drift->observed_epoch = observed->epoch;
	memcpy(drift->observed_digest, observed->digest,
	       sizeof(drift->observed_digest));
	missing_fields =
		desired->field_mask & ~observed->field_mask;
	differences = resource_differences(desired, observed) |
		missing_fields;
	drift->field_mask = differences;
	if ((desired->flags & PQCP_FLEET_RESOURCE_TOMBSTONE) !=
	    (observed->flags & PQCP_FLEET_RESOURCE_TOMBSTONE)) {
		drift->reason_mask |=
			PQCP_FLEET_DRIFT_REASON_TOMBSTONE;
		differences |= desired->field_mask;
		drift->field_mask = differences;
	}
	if (differences == 0U &&
	    ((desired->flags & PQCP_FLEET_RESOURCE_TOMBSTONE) ==
	     (observed->flags & PQCP_FLEET_RESOURCE_TOMBSTONE))) {
		drift->classification = PQCP_FLEET_DRIFT_NONE;
		drift->severity = PQCP_FLEET_DRIFT_SEVERITY_NONE;
		return 0;
	}
	drift->reason_mask |= PQCP_FLEET_DRIFT_REASON_FIELDS;
	if (ownership_conflict(desired, observed)) {
		drift->classification =
			PQCP_FLEET_DRIFT_OWNERSHIP_CONFLICT;
		drift->severity =
			PQCP_FLEET_DRIFT_SEVERITY_CRITICAL;
		drift->reason_mask |=
			PQCP_FLEET_DRIFT_REASON_OWNER;
		drift->security_critical = true;
		return 0;
	}
	if (desired->generation != observed->generation) {
		drift->reason_mask |=
			PQCP_FLEET_DRIFT_REASON_GENERATION;
	}
	if (desired->epoch != observed->epoch) {
		drift->reason_mask |= PQCP_FLEET_DRIFT_REASON_EPOCH;
	}
	if (security_regression(desired, observed, differences)) {
		drift->classification =
			PQCP_FLEET_DRIFT_SECURITY_REGRESSION;
		drift->severity =
			PQCP_FLEET_DRIFT_SEVERITY_CRITICAL;
		drift->reason_mask |=
			PQCP_FLEET_DRIFT_REASON_SECURITY;
		drift->security_critical = true;
		return 0;
	}
	if (desired->key.kind == PQCP_FLEET_RESOURCE_FIRMWARE &&
	    firmware_rollback_required(
		    &desired->value.firmware,
		    &observed->value.firmware,
		    differences)) {
		drift->classification =
			PQCP_FLEET_DRIFT_ROLLBACK_REQUIRED;
		drift->severity = PQCP_FLEET_DRIFT_SEVERITY_ERROR;
		drift->requires_rollback = true;
		drift->security_critical =
			desired->value.firmware.version <
			observed->value.firmware.rollback_floor;
		if (drift->security_critical) {
			drift->classification =
				PQCP_FLEET_DRIFT_BLOCKED;
			drift->severity =
				PQCP_FLEET_DRIFT_SEVERITY_CRITICAL;
			drift->reason_mask |=
				PQCP_FLEET_DRIFT_REASON_SECURITY;
		}
		return 0;
	}
	if (same_epoch_digest_conflict(
		    desired, observed, differences)) {
		drift->classification =
			PQCP_FLEET_DRIFT_DIGEST_CONFLICT;
		drift->severity =
			PQCP_FLEET_DRIFT_SEVERITY_CRITICAL;
		drift->reason_mask |=
			PQCP_FLEET_DRIFT_REASON_DIGEST;
		drift->security_critical = true;
		return 0;
	}
	if (observed->epoch < desired->epoch) {
		drift->classification =
			PQCP_FLEET_DRIFT_OBSERVED_STALE;
		drift->severity = PQCP_FLEET_DRIFT_SEVERITY_WARNING;
	} else if (observed->epoch > desired->epoch) {
		drift->classification =
			PQCP_FLEET_DRIFT_OBSERVED_AHEAD;
		drift->severity = PQCP_FLEET_DRIFT_SEVERITY_ERROR;
	} else {
		drift->classification =
			PQCP_FLEET_DRIFT_VALUE_MISMATCH;
		drift->severity = PQCP_FLEET_DRIFT_SEVERITY_WARNING;
	}
	if ((desired->flags &
	     PQCP_FLEET_RESOURCE_SECURITY_CRITICAL) != 0U) {
		drift->security_critical = true;
		if (drift->severity <
		    PQCP_FLEET_DRIFT_SEVERITY_ERROR) {
			drift->severity =
				PQCP_FLEET_DRIFT_SEVERITY_ERROR;
		}
	}
	return 0;
}

int pqcp_fleet_snapshot_classify_drift(
	const struct pqcp_fleet_state_snapshot *desired,
	const struct pqcp_fleet_state_snapshot *observed,
	struct pqcp_fleet_drift *drift,
	size_t drift_capacity,
	size_t *drift_count)
{
	size_t desired_index = 0U;
	size_t observed_index = 0U;
	size_t produced = 0U;
	size_t required = 0U;
	int first_error = 0;

	if (desired == NULL || observed == NULL ||
	    drift == NULL || drift_capacity == 0U ||
	    drift_count == NULL ||
	    pqcp_fleet_snapshot_verify(desired) != 0 ||
	    pqcp_fleet_snapshot_verify(observed) != 0 ||
	    desired->origin != PQCP_FLEET_STATE_ORIGIN_DESIRED ||
	    observed->origin != PQCP_FLEET_STATE_ORIGIN_REPORTED) {
		return -EINVAL;
	}
	while (desired_index < desired->count ||
	       observed_index < observed->count) {
		const struct pqcp_fleet_resource_state *wanted = NULL;
		const struct pqcp_fleet_resource_state *actual = NULL;
		struct pqcp_fleet_drift classified;
		int comparison;
		int ret;

		if (desired_index >= desired->count) {
			actual = &observed->resources[observed_index++];
		} else if (observed_index >= observed->count) {
			wanted = &desired->resources[desired_index++];
		} else {
			comparison = key_compare(
				&desired->resources[desired_index].key,
				&observed->resources[observed_index].key);
			if (comparison == 0) {
				wanted =
					&desired->resources[desired_index++];
				actual =
					&observed->resources[observed_index++];
			} else if (comparison < 0) {
				wanted =
					&desired->resources[desired_index++];
			} else {
				actual =
					&observed->resources[observed_index++];
			}
		}
		ret = pqcp_fleet_resource_classify_drift(
			wanted, actual, &classified);
		if (ret != 0) {
			if (first_error == 0) {
				first_error = ret;
			}
			continue;
		}
		if (classified.classification == PQCP_FLEET_DRIFT_NONE) {
			continue;
		}
		if (produced < drift_capacity) {
			drift[produced] = classified;
			produced++;
		}
		required++;
	}
	*drift_count = required;
	if (first_error != 0) {
		return first_error;
	}
	return required > drift_capacity ? -ENOSPC : 0;
}

int pqcp_fleet_model_classify_drift(
	struct pqcp_fleet_desired_state *model,
	struct pqcp_fleet_drift *drift,
	size_t drift_capacity,
	size_t *drift_count)
{
	size_t produced = 0U;
	size_t required = 0U;
	int ret;

	if (model == NULL || !model->initialized ||
	    drift == NULL || drift_capacity == 0U ||
	    drift_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&model->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < model->desired_capacity; ++index) {
		const struct pqcp_fleet_resource_state *wanted;
		const struct pqcp_fleet_resource_state *actual = NULL;
		struct pqcp_fleet_drift classified;
		int observed_index;

		if (!model->desired[index].occupied) {
			continue;
		}
		wanted = &model->desired[index].resource;
		observed_index = slot_find(
			model->observed, model->observed_capacity,
			&wanted->key);
		if (observed_index >= 0) {
			actual =
				&model->observed[observed_index].resource;
		}
		ret = pqcp_fleet_resource_classify_drift(
			wanted, actual, &classified);
		if (ret != 0) {
			(void)k_mutex_unlock(&model->lock);
			return ret;
		}
		if (classified.classification == PQCP_FLEET_DRIFT_NONE) {
			continue;
		}
		if (produced < drift_capacity) {
			drift[produced++] = classified;
		}
		required++;
	}
	for (size_t index = 0U;
	     index < model->observed_capacity; ++index) {
		const struct pqcp_fleet_resource_state *actual;
		struct pqcp_fleet_drift classified;

		if (!model->observed[index].occupied) {
			continue;
		}
		actual = &model->observed[index].resource;
		if (slot_find(
			    model->desired, model->desired_capacity,
			    &actual->key) >= 0) {
			continue;
		}
		ret = pqcp_fleet_resource_classify_drift(
			NULL, actual, &classified);
		if (ret != 0) {
			(void)k_mutex_unlock(&model->lock);
			return ret;
		}
		if (produced < drift_capacity) {
			drift[produced++] = classified;
		}
		required++;
	}
	(void)k_mutex_unlock(&model->lock);
	*drift_count = required;
	return required > drift_capacity ? -ENOSPC : 0;
}

static int slots_audit(
	const struct pqcp_fleet_state_slot *slots,
	size_t capacity,
	size_t expected_count,
	enum pqcp_fleet_state_origin origin)
{
	size_t count = 0U;

	for (size_t index = 0U; index < capacity; ++index) {
		if (!slots[index].occupied) {
			continue;
		}
		count++;
		if (slots[index].resource.origin != origin ||
		    pqcp_fleet_resource_verify(
			    &slots[index].resource) != 0) {
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < capacity; ++other) {
			if (slots[other].occupied &&
			    key_equal(&slots[index].resource.key,
				      &slots[other].resource.key)) {
				return -EEXIST;
			}
		}
	}
	return count == expected_count ? 0 : -EBADMSG;
}

int pqcp_fleet_desired_state_audit(
	struct pqcp_fleet_desired_state *model)
{
	int ret;

	if (model == NULL || !model->initialized ||
	    model->schema_version !=
		    PQCP_FLEET_DESIRED_STATE_SCHEMA_VERSION ||
	    model->desired == NULL ||
	    model->desired_capacity == 0U ||
	    model->observed == NULL ||
	    model->observed_capacity == 0U ||
	    model->desired_count > model->desired_capacity ||
	    model->observed_count > model->observed_capacity) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&model->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = slots_audit(
		model->desired, model->desired_capacity,
		model->desired_count,
		PQCP_FLEET_STATE_ORIGIN_DESIRED);
	if (ret == 0) {
		ret = slots_audit(
			model->observed, model->observed_capacity,
			model->observed_count,
			PQCP_FLEET_STATE_ORIGIN_REPORTED);
	}
	(void)k_mutex_unlock(&model->lock);
	return ret;
}
