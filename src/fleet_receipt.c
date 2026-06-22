/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free authenticated fleet receipt correlation and quorum tracking.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_receipt.h>
#include <pqcp_zephyr/runtime.h>

#include "fleet_internal.h"

#define RECEIPT_MAC_DOMAIN "PQCP-FLEET-RECEIPT-MAC-V1"
#define RECEIPT_DIGEST_DOMAIN "PQCP-FLEET-RECEIPT-DIGEST-V1"
#define RECEIPT_TRACKER_DOMAIN "PQCP-FLEET-RECEIPT-TRACKER-V1"
#define RECEIPT_AGGREGATE_DOMAIN "PQCP-FLEET-RECEIPT-AGGREGATE-V1"
#define RECEIPT_SNAPSHOT_DOMAIN "PQCP-FLEET-RECEIPT-SNAPSHOT-V1"
#define RECEIPT_PACKET_ENCODED_MAX 512U
#define RECEIPT_TRACKER_ENCODED_MAX 320U
#define RECEIPT_SNAPSHOT_ENCODED_MAX 384U
#define RECEIPT_HASH_INPUT_MAX 192U
#define RECEIPT_HMAC_BLOCK_BYTES 64U
#define RECEIPT_MINIMUM_KEY_BYTES 16U

struct receipt_encoder {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

enum replay_result {
	REPLAY_RESULT_NEW = 0,
	REPLAY_RESULT_DUPLICATE,
	REPLAY_RESULT_TOO_OLD,
	REPLAY_RESULT_STALE_EPOCH,
};

static bool bytes_zero(const uint8_t *bytes, size_t length)
{
	uint8_t aggregate = 0U;

	if (bytes == NULL) {
		return true;
	}
	for (size_t index = 0U; index < length; ++index) {
		aggregate |= bytes[index];
	}
	return aggregate == 0U;
}

static bool constant_time_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if (left == NULL || right == NULL) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static bool digest_equal(
	const uint8_t left[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_DIGEST_BYTES])
{
	return constant_time_equal(
		left, right, PQCP_FLEET_DIGEST_BYTES);
}

static void saturating_increment_u64(uint64_t *value)
{
	if (value != NULL && *value != UINT64_MAX) {
		(*value)++;
	}
}

static void saturating_increment_u32(uint32_t *value)
{
	if (value != NULL && *value != UINT32_MAX) {
		(*value)++;
	}
}

static bool add_u64(uint64_t left, uint64_t right, uint64_t *result)
{
	if (result == NULL || right > UINT64_MAX - left) {
		return false;
	}
	*result = left + right;
	return true;
}

static bool size_array_valid(size_t count, size_t element_size)
{
	return element_size == 0U ||
	       count <= SIZE_MAX / element_size;
}

static void encoder_init(
	struct receipt_encoder *encoder,
	uint8_t *buffer,
	size_t capacity)
{
	if (encoder == NULL) {
		return;
	}
	encoder->buffer = buffer;
	encoder->capacity = capacity;
	encoder->offset = 0U;
	encoder->error = buffer == NULL ? -EINVAL : 0;
}

static void encoder_append(
	struct receipt_encoder *encoder,
	const void *value,
	size_t length)
{
	if (encoder == NULL || encoder->error != 0) {
		return;
	}
	if ((value == NULL && length != 0U) ||
	    length > encoder->capacity - encoder->offset) {
		encoder->error = -EOVERFLOW;
		return;
	}
	if (length != 0U) {
		memcpy(encoder->buffer + encoder->offset,
		       value, length);
		encoder->offset += length;
	}
}

static void encoder_u8(
	struct receipt_encoder *encoder,
	uint8_t value)
{
	encoder_append(encoder, &value, sizeof(value));
}

static void encoder_u32(
	struct receipt_encoder *encoder,
	uint32_t value)
{
	uint8_t encoded[4];

	encoded[0] = (uint8_t)(value >> 24U);
	encoded[1] = (uint8_t)(value >> 16U);
	encoded[2] = (uint8_t)(value >> 8U);
	encoded[3] = (uint8_t)value;
	encoder_append(encoder, encoded, sizeof(encoded));
}

static void encoder_i32(
	struct receipt_encoder *encoder,
	int32_t value)
{
	encoder_u32(encoder, (uint32_t)value);
}

static void encoder_u64(
	struct receipt_encoder *encoder,
	uint64_t value)
{
	uint8_t encoded[8];

	for (size_t index = 0U; index < sizeof(encoded); ++index) {
		encoded[index] =
			(uint8_t)(value >> (56U - index * 8U));
	}
	encoder_append(encoder, encoded, sizeof(encoded));
}

static void encoder_size(
	struct receipt_encoder *encoder,
	size_t value)
{
	encoder_u64(encoder, (uint64_t)value);
}

static bool text_character_valid(char value)
{
	return (value >= 'a' && value <= 'z') ||
	       (value >= 'A' && value <= 'Z') ||
	       (value >= '0' && value <= '9') ||
	       value == '-' || value == '_' || value == '.' ||
	       value == ':' || value == '/' || value == '@';
}

static bool text_valid(const char *text, size_t capacity)
{
	size_t length;

	if (text == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(text, capacity);
	if (length == 0U || length >= capacity) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		if (!text_character_valid(text[index])) {
			return false;
		}
	}
	return true;
}

static int copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	size_t length;

	if (destination == NULL ||
	    !text_valid(source, capacity)) {
		return -EINVAL;
	}
	length = strnlen(source, capacity);
	memset(destination, 0, capacity);
	memcpy(destination, source, length);
	return 0;
}

static bool kind_valid(enum pqcp_fleet_receipt_kind kind)
{
	return kind > PQCP_FLEET_RECEIPT_NONE &&
	       kind < PQCP_FLEET_RECEIPT_KIND_COUNT;
}

static bool status_valid(
	enum pqcp_fleet_receipt_status status)
{
	return status > PQCP_FLEET_RECEIPT_STATUS_NONE &&
	       status < PQCP_FLEET_RECEIPT_STATUS_COUNT;
}

static bool tracker_state_valid(
	enum pqcp_fleet_receipt_tracker_state state)
{
	return state >= PQCP_FLEET_RECEIPT_TRACKER_EMPTY &&
	       state < PQCP_FLEET_RECEIPT_TRACKER_STATE_COUNT;
}

bool pqcp_fleet_receipt_tracker_terminal(
	enum pqcp_fleet_receipt_tracker_state state)
{
	switch (state) {
	case PQCP_FLEET_RECEIPT_TRACKER_COMPLETE:
	case PQCP_FLEET_RECEIPT_TRACKER_FAILED:
	case PQCP_FLEET_RECEIPT_TRACKER_CANCELLED:
	case PQCP_FLEET_RECEIPT_TRACKER_EXPIRED:
	case PQCP_FLEET_RECEIPT_TRACKER_CONFLICT:
		return true;
	default:
		return false;
	}
}

static uint32_t known_tracker_flags(void)
{
	return PQCP_FLEET_RECEIPT_TRACK_REQUIRE_CHUNKS |
	       PQCP_FLEET_RECEIPT_TRACK_REQUIRE_APPLIED |
	       PQCP_FLEET_RECEIPT_TRACK_FAIL_REQUIRED_REJECTION |
	       PQCP_FLEET_RECEIPT_TRACK_FAIL_ANY_REJECTION |
	       PQCP_FLEET_RECEIPT_TRACK_RETAIN_TERMINAL_RECEIPTS |
	       PQCP_FLEET_RECEIPT_TRACK_STRICT_POLICY_EPOCH |
	       PQCP_FLEET_RECEIPT_TRACK_STRICT_REVOCATION_EPOCH |
	       PQCP_FLEET_RECEIPT_TRACK_HIGH_INTEGRITY;
}

static int packet_validate(
	const struct pqcp_fleet_receipt_packet *packet,
	bool require_auth_tag)
{
	if (packet == NULL ||
	    packet->schema_version !=
		    PQCP_FLEET_RECEIPT_SCHEMA_VERSION ||
	    !kind_valid(packet->kind) ||
	    !status_valid(packet->status) ||
	    packet->receipt_id == 0U ||
	    packet->receipt_epoch == 0U ||
	    packet->sequence == 0U ||
	    packet->artifact_id == 0U ||
	    packet->message_id == 0U ||
	    packet->correlation_id == 0U ||
	    packet->issued_at_ms == 0U ||
	    packet->expires_at_ms <= packet->issued_at_ms ||
	    packet->artifact_size == 0U ||
	    packet->acknowledged_bytes >
		    packet->artifact_size ||
	    !text_valid(
		    packet->peer_id,
		    sizeof(packet->peer_id)) ||
	    !text_valid(
		    packet->key_id,
		    sizeof(packet->key_id)) ||
	    bytes_zero(packet->nonce, sizeof(packet->nonce)) ||
	    bytes_zero(
		    packet->artifact_digest,
		    sizeof(packet->artifact_digest)) ||
	    (require_auth_tag &&
	     bytes_zero(
		     packet->auth_tag,
		     sizeof(packet->auth_tag)))) {
		return -EINVAL;
	}
	switch (packet->kind) {
	case PQCP_FLEET_RECEIPT_CHUNK:
		if (packet->chunk_count == 0U ||
		    packet->chunk_index >= packet->chunk_count ||
		    packet->chunk_length == 0U ||
		    packet->chunk_length >
			    packet->artifact_size ||
		    packet->acknowledged_bytes == 0U ||
		    bytes_zero(
			    packet->chunk_digest,
			    sizeof(packet->chunk_digest)) ||
		    packet->status ==
			    PQCP_FLEET_RECEIPT_STATUS_REJECTED ||
		    packet->status ==
			    PQCP_FLEET_RECEIPT_STATUS_FAILED) {
			return -EINVAL;
		}
		break;
	case PQCP_FLEET_RECEIPT_ARTIFACT:
	case PQCP_FLEET_RECEIPT_FINAL:
		if (packet->chunk_length != 0U ||
		    !bytes_zero(
			    packet->chunk_digest,
			    sizeof(packet->chunk_digest)) ||
		    packet->acknowledged_bytes !=
			    packet->artifact_size ||
		    packet->status ==
			    PQCP_FLEET_RECEIPT_STATUS_REJECTED ||
		    packet->status ==
			    PQCP_FLEET_RECEIPT_STATUS_FAILED) {
			return -EINVAL;
		}
		break;
	case PQCP_FLEET_RECEIPT_REJECTION:
		if (packet->status !=
			    PQCP_FLEET_RECEIPT_STATUS_REJECTED &&
		    packet->status !=
			    PQCP_FLEET_RECEIPT_STATUS_FAILED) {
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int encode_packet_body(
	const struct pqcp_fleet_receipt_packet *packet,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	struct receipt_encoder encoder;
	int ret;

	if (output == NULL || length == NULL) {
		return -EINVAL;
	}
	ret = packet_validate(packet, false);
	if (ret != 0) {
		return ret;
	}
	memset(output, 0, capacity);
	encoder_init(&encoder, output, capacity);
	encoder_append(
		&encoder, RECEIPT_MAC_DOMAIN,
		sizeof(RECEIPT_MAC_DOMAIN) - 1U);
	encoder_u32(&encoder, packet->schema_version);
	encoder_u32(&encoder, (uint32_t)packet->kind);
	encoder_u32(&encoder, (uint32_t)packet->status);
	encoder_u32(&encoder, packet->flags);
	encoder_u32(&encoder, packet->reason);
	encoder_i32(&encoder, packet->result);
	encoder_u64(&encoder, packet->receipt_id);
	encoder_u64(&encoder, packet->receipt_epoch);
	encoder_u64(&encoder, packet->sequence);
	encoder_u64(&encoder, packet->artifact_id);
	encoder_u64(&encoder, packet->message_id);
	encoder_u64(&encoder, packet->correlation_id);
	encoder_u64(&encoder, packet->policy_epoch);
	encoder_u64(&encoder, packet->revocation_epoch);
	encoder_u64(&encoder, packet->issued_at_ms);
	encoder_u64(&encoder, packet->expires_at_ms);
	encoder_u64(&encoder, packet->artifact_size);
	encoder_u64(&encoder, packet->acknowledged_bytes);
	encoder_u32(&encoder, packet->chunk_index);
	encoder_u32(&encoder, packet->chunk_count);
	encoder_u32(&encoder, packet->chunk_length);
	encoder_append(
		&encoder, packet->peer_id,
		sizeof(packet->peer_id));
	encoder_append(
		&encoder, packet->key_id,
		sizeof(packet->key_id));
	encoder_append(
		&encoder, packet->nonce,
		sizeof(packet->nonce));
	encoder_append(
		&encoder, packet->artifact_digest,
		sizeof(packet->artifact_digest));
	encoder_append(
		&encoder, packet->chunk_digest,
		sizeof(packet->chunk_digest));
	if (encoder.error != 0) {
		pqcp_runtime_secure_zero(output, capacity);
		return encoder.error;
	}
	*length = encoder.offset;
	return 0;
}

static int hmac_sha256(
	const uint8_t *key,
	size_t key_length,
	const uint8_t *message,
	size_t message_length,
	uint8_t output[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t key_block[RECEIPT_HMAC_BLOCK_BYTES];
	uint8_t inner_pad[RECEIPT_HMAC_BLOCK_BYTES];
	uint8_t outer_pad[RECEIPT_HMAC_BLOCK_BYTES];
	uint8_t inner_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t inner_input[
		RECEIPT_HMAC_BLOCK_BYTES +
		RECEIPT_PACKET_ENCODED_MAX];
	uint8_t outer_input[
		RECEIPT_HMAC_BLOCK_BYTES +
		PQCP_FLEET_DIGEST_BYTES];
	int ret = 0;

	if (key == NULL || output == NULL ||
	    key_length < RECEIPT_MINIMUM_KEY_BYTES ||
	    key_length > PQCP_FLEET_RECEIPT_KEY_MAX_BYTES ||
	    (message == NULL && message_length != 0U) ||
	    message_length > RECEIPT_PACKET_ENCODED_MAX) {
		return -EINVAL;
	}
	memset(key_block, 0, sizeof(key_block));
	memset(inner_pad, 0, sizeof(inner_pad));
	memset(outer_pad, 0, sizeof(outer_pad));
	memset(inner_digest, 0, sizeof(inner_digest));
	memset(inner_input, 0, sizeof(inner_input));
	memset(outer_input, 0, sizeof(outer_input));
	memcpy(key_block, key, key_length);
	for (size_t index = 0U;
	     index < RECEIPT_HMAC_BLOCK_BYTES; ++index) {
		inner_pad[index] = key_block[index] ^ 0x36U;
		outer_pad[index] = key_block[index] ^ 0x5cU;
	}
	memcpy(inner_input, inner_pad, sizeof(inner_pad));
	if (message_length != 0U) {
		memcpy(inner_input + sizeof(inner_pad),
		       message, message_length);
	}
	ret = pqcp_fleet_sha256(
		inner_input,
		sizeof(inner_pad) + message_length,
		inner_digest);
	if (ret == 0) {
		memcpy(outer_input, outer_pad, sizeof(outer_pad));
		memcpy(outer_input + sizeof(outer_pad),
		       inner_digest, sizeof(inner_digest));
		ret = pqcp_fleet_sha256(
			outer_input, sizeof(outer_input), output);
	}
	pqcp_runtime_secure_zero(
		key_block, sizeof(key_block));
	pqcp_runtime_secure_zero(
		inner_pad, sizeof(inner_pad));
	pqcp_runtime_secure_zero(
		outer_pad, sizeof(outer_pad));
	pqcp_runtime_secure_zero(
		inner_digest, sizeof(inner_digest));
	pqcp_runtime_secure_zero(
		inner_input, sizeof(inner_input));
	pqcp_runtime_secure_zero(
		outer_input, sizeof(outer_input));
	return ret;
}

int pqcp_fleet_receipt_authenticate(
	struct pqcp_fleet_receipt_packet *packet,
	const uint8_t *key,
	size_t key_length)
{
	uint8_t encoded[RECEIPT_PACKET_ENCODED_MAX];
	uint8_t tag[PQCP_FLEET_RECEIPT_AUTH_TAG_BYTES];
	size_t length = 0U;
	int ret;

	if (packet == NULL) {
		return -EINVAL;
	}
	memset(encoded, 0, sizeof(encoded));
	memset(tag, 0, sizeof(tag));
	ret = encode_packet_body(
		packet, encoded, sizeof(encoded), &length);
	if (ret == 0) {
		ret = hmac_sha256(
			key, key_length, encoded, length, tag);
	}
	if (ret == 0) {
		memcpy(packet->auth_tag, tag,
		       sizeof(packet->auth_tag));
	}
	pqcp_runtime_secure_zero(tag, sizeof(tag));
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

int pqcp_fleet_receipt_verify_auth(
	const struct pqcp_fleet_receipt_packet *packet,
	const uint8_t *key,
	size_t key_length)
{
	uint8_t encoded[RECEIPT_PACKET_ENCODED_MAX];
	uint8_t expected[PQCP_FLEET_RECEIPT_AUTH_TAG_BYTES];
	size_t length = 0U;
	int ret;

	ret = packet_validate(packet, true);
	if (ret != 0) {
		return ret;
	}
	memset(encoded, 0, sizeof(encoded));
	memset(expected, 0, sizeof(expected));
	ret = encode_packet_body(
		packet, encoded, sizeof(encoded), &length);
	if (ret == 0) {
		ret = hmac_sha256(
			key, key_length, encoded, length, expected);
	}
	if (ret == 0 &&
	    !constant_time_equal(
		    expected, packet->auth_tag,
		    sizeof(expected))) {
		ret = -EKEYREJECTED;
	}
	pqcp_runtime_secure_zero(expected, sizeof(expected));
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

int pqcp_fleet_receipt_digest(
	const struct pqcp_fleet_receipt_packet *packet,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[RECEIPT_PACKET_ENCODED_MAX];
	uint8_t body[RECEIPT_PACKET_ENCODED_MAX];
	struct receipt_encoder encoder;
	size_t body_length = 0U;
	int ret;

	if (digest == NULL) {
		return -EINVAL;
	}
	ret = packet_validate(packet, true);
	if (ret != 0) {
		return ret;
	}
	memset(encoded, 0, sizeof(encoded));
	memset(body, 0, sizeof(body));
	ret = encode_packet_body(
		packet, body, sizeof(body), &body_length);
	if (ret != 0) {
		goto out;
	}
	encoder_init(&encoder, encoded, sizeof(encoded));
	encoder_append(
		&encoder, RECEIPT_DIGEST_DOMAIN,
		sizeof(RECEIPT_DIGEST_DOMAIN) - 1U);
	encoder_append(&encoder, body, body_length);
	encoder_append(
		&encoder, packet->auth_tag,
		sizeof(packet->auth_tag));
	if (encoder.error != 0) {
		ret = encoder.error;
		goto out;
	}
	ret = pqcp_fleet_sha256(
		encoded, encoder.offset, digest);
out:
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int manager_validate(
	const struct pqcp_fleet_receipt_manager *manager)
{
	if (manager == NULL || !manager->initialized ||
	    manager->schema_version !=
		    PQCP_FLEET_RECEIPT_SCHEMA_VERSION ||
	    manager->peers == NULL ||
	    manager->peer_capacity == 0U ||
	    manager->trackers == NULL ||
	    manager->tracker_capacity == 0U ||
	    manager->acks == NULL ||
	    manager->ack_capacity == 0U ||
	    manager->receipts == NULL ||
	    manager->receipt_capacity == 0U ||
	    !size_array_valid(
		    manager->peer_capacity,
		    sizeof(*manager->peers)) ||
	    !size_array_valid(
		    manager->tracker_capacity,
		    sizeof(*manager->trackers)) ||
	    !size_array_valid(
		    manager->ack_capacity,
		    sizeof(*manager->acks)) ||
	    !size_array_valid(
		    manager->receipt_capacity,
		    sizeof(*manager->receipts)) ||
	    manager->peer_count > manager->peer_capacity ||
	    manager->tracker_count >
		    manager->tracker_capacity ||
	    manager->ack_count > manager->ack_capacity ||
	    manager->receipt_count >
		    manager->receipt_capacity ||
	    manager->receipt_head >=
		    manager->receipt_capacity ||
	    manager->next_peer_generation == 0U ||
	    manager->next_tracker_generation == 0U ||
	    manager->next_received_order == 0U) {
		return -EINVAL;
	}
	return 0;
}

static int peer_index(
	const struct pqcp_fleet_receipt_manager *manager,
	const char *peer_id)
{
	if (manager == NULL || peer_id == NULL) {
		return -1;
	}
	for (size_t index = 0U;
	     index < manager->peer_capacity; ++index) {
		if (manager->peers[index].occupied &&
		    strcmp(manager->peers[index].peer_id,
			   peer_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int free_peer_index(
	const struct pqcp_fleet_receipt_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->peer_capacity; ++index) {
		if (!manager->peers[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static int tracker_index_by_artifact(
	const struct pqcp_fleet_receipt_manager *manager,
	uint64_t artifact_id)
{
	if (manager == NULL || artifact_id == 0U) {
		return -1;
	}
	for (size_t index = 0U;
	     index < manager->tracker_capacity; ++index) {
		if (manager->trackers[index].occupied &&
		    manager->trackers[index].artifact_id ==
			    artifact_id) {
			return (int)index;
		}
	}
	return -1;
}

static int tracker_index_by_handle(
	const struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle)
{
	int index;

	if (handle.artifact_id == 0U ||
	    handle.generation == 0U) {
		return -1;
	}
	index = tracker_index_by_artifact(
		manager, handle.artifact_id);
	if (index < 0 ||
	    manager->trackers[index].generation !=
		    handle.generation) {
		return -1;
	}
	return index;
}

static int free_tracker_index(
	const struct pqcp_fleet_receipt_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->tracker_capacity; ++index) {
		if (!manager->trackers[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static int ack_index(
	const struct pqcp_fleet_receipt_manager *manager,
	uint64_t artifact_id,
	uint32_t tracker_generation,
	const char *peer_id)
{
	if (manager == NULL || artifact_id == 0U ||
	    tracker_generation == 0U || peer_id == NULL) {
		return -1;
	}
	for (size_t index = 0U;
	     index < manager->ack_capacity; ++index) {
		const struct pqcp_fleet_receipt_ack *ack =
			&manager->acks[index];

		if (ack->occupied &&
		    ack->artifact_id == artifact_id &&
		    ack->tracker_generation ==
			    tracker_generation &&
		    strcmp(ack->peer_id, peer_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int free_ack_index(
	const struct pqcp_fleet_receipt_manager *manager)
{
	for (size_t index = 0U;
	     index < manager->ack_capacity; ++index) {
		if (!manager->acks[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static uint32_t next_peer_generation(
	struct pqcp_fleet_receipt_manager *manager)
{
	uint32_t generation = manager->next_peer_generation;

	manager->next_peer_generation++;
	if (manager->next_peer_generation == 0U) {
		manager->next_peer_generation = 1U;
	}
	if (generation == 0U) {
		generation = manager->next_peer_generation++;
		if (manager->next_peer_generation == 0U) {
			manager->next_peer_generation = 1U;
		}
	}
	return generation;
}

static uint32_t next_tracker_generation(
	struct pqcp_fleet_receipt_manager *manager)
{
	uint32_t generation =
		manager->next_tracker_generation;

	manager->next_tracker_generation++;
	if (manager->next_tracker_generation == 0U) {
		manager->next_tracker_generation = 1U;
	}
	if (generation == 0U) {
		generation =
			manager->next_tracker_generation++;
		if (manager->next_tracker_generation == 0U) {
			manager->next_tracker_generation = 1U;
		}
	}
	return generation;
}

static int key_digest_compute(
	const uint8_t *key,
	size_t key_length,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	if (key == NULL ||
	    key_length < RECEIPT_MINIMUM_KEY_BYTES ||
	    key_length > PQCP_FLEET_RECEIPT_KEY_MAX_BYTES ||
	    digest == NULL) {
		return -EINVAL;
	}
	return pqcp_fleet_sha256(key, key_length, digest);
}

static int tracker_digest_compute(
	const struct pqcp_fleet_receipt_tracker *tracker,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[RECEIPT_TRACKER_ENCODED_MAX];
	struct receipt_encoder encoder;
	int ret;

	if (tracker == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(encoded, 0, sizeof(encoded));
	encoder_init(&encoder, encoded, sizeof(encoded));
	encoder_append(
		&encoder, RECEIPT_TRACKER_DOMAIN,
		sizeof(RECEIPT_TRACKER_DOMAIN) - 1U);
	encoder_u32(&encoder, tracker->schema_version);
	encoder_u32(&encoder, tracker->generation);
	encoder_u64(&encoder, tracker->artifact_id);
	encoder_u64(&encoder, tracker->message_id);
	encoder_u64(&encoder, tracker->correlation_id);
	encoder_u64(&encoder, tracker->receipt_epoch);
	encoder_u64(&encoder, tracker->policy_epoch);
	encoder_u64(&encoder, tracker->revocation_epoch);
	encoder_u64(&encoder, tracker->created_at_ms);
	encoder_u64(&encoder, tracker->expires_at_ms);
	encoder_u64(&encoder, tracker->completed_at_ms);
	encoder_u64(&encoder, tracker->artifact_size);
	encoder_u32(&encoder, tracker->chunk_count);
	encoder_u32(&encoder, tracker->quorum);
	encoder_u32(&encoder, tracker->flags);
	encoder_u32(&encoder, tracker->required_count);
	encoder_u32(&encoder, tracker->required_ack_count);
	encoder_u32(&encoder, tracker->acknowledged_count);
	encoder_u32(&encoder, tracker->rejected_count);
	encoder_u32(&encoder, tracker->failed_count);
	encoder_u32(&encoder, (uint32_t)tracker->state);
	encoder_i32(&encoder, tracker->terminal_result);
	encoder_u32(&encoder, tracker->terminal_reason);
	encoder_append(
		&encoder, tracker->artifact_digest,
		sizeof(tracker->artifact_digest));
	encoder_u8(&encoder, tracker->occupied ? 1U : 0U);
	if (encoder.error != 0) {
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return encoder.error;
	}
	ret = pqcp_fleet_sha256(
		encoded, encoder.offset, digest);
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static int tracker_digest_refresh(
	struct pqcp_fleet_receipt_tracker *tracker)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	ret = tracker_digest_compute(tracker, digest);
	if (ret == 0) {
		memcpy(tracker->tracker_digest, digest,
		       sizeof(tracker->tracker_digest));
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int peer_structure_validate(
	const struct pqcp_fleet_receipt_peer *peer)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (peer == NULL || !peer->occupied ||
	    peer->schema_version !=
		    PQCP_FLEET_RECEIPT_SCHEMA_VERSION ||
	    peer->generation == 0U ||
	    !text_valid(peer->peer_id, sizeof(peer->peer_id)) ||
	    !text_valid(peer->key_id, sizeof(peer->key_id)) ||
	    peer->key_length < RECEIPT_MINIMUM_KEY_BYTES ||
	    peer->key_length >
		    PQCP_FLEET_RECEIPT_KEY_MAX_BYTES ||
	    peer->key_epoch == 0U ||
	    peer->valid_from_ms == 0U ||
	    peer->valid_until_ms <= peer->valid_from_ms ||
	    peer->minimum_receipt_epoch == 0U) {
		return -EBADMSG;
	}
	if (peer->replay_initialized &&
	    (peer->replay_epoch <
		     peer->minimum_receipt_epoch ||
	     peer->replay_high_sequence == 0U ||
	     bytes_zero(
		     (const uint8_t *)peer->replay_bitmap,
		     sizeof(peer->replay_bitmap)))) {
		return -EBADMSG;
	}
	if (!peer->replay_initialized &&
	    (peer->replay_epoch != 0U ||
	     peer->replay_high_sequence != 0U ||
	     !bytes_zero(
		     (const uint8_t *)peer->replay_bitmap,
		     sizeof(peer->replay_bitmap)))) {
		return -EBADMSG;
	}
	ret = key_digest_compute(
		peer->key, peer->key_length, digest);
	if (ret == 0 &&
	    !digest_equal(digest, peer->key_digest)) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int tracker_structure_validate(
	const struct pqcp_fleet_receipt_tracker *tracker)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (tracker == NULL || !tracker->occupied ||
	    tracker->schema_version !=
		    PQCP_FLEET_RECEIPT_SCHEMA_VERSION ||
	    tracker->generation == 0U ||
	    tracker->artifact_id == 0U ||
	    tracker->message_id == 0U ||
	    tracker->correlation_id == 0U ||
	    tracker->receipt_epoch == 0U ||
	    tracker->created_at_ms == 0U ||
	    tracker->expires_at_ms <=
		    tracker->created_at_ms ||
	    tracker->artifact_size == 0U ||
	    tracker->chunk_count == 0U ||
	    tracker->quorum == 0U ||
	    (tracker->flags & ~known_tracker_flags()) != 0U ||
	    tracker->required_ack_count >
		    tracker->required_count ||
	    !tracker_state_valid(tracker->state) ||
	    tracker->state ==
		    PQCP_FLEET_RECEIPT_TRACKER_EMPTY ||
	    bytes_zero(
		    tracker->artifact_digest,
		    sizeof(tracker->artifact_digest))) {
		return -EBADMSG;
	}
	if ((tracker->flags &
	     PQCP_FLEET_RECEIPT_TRACK_STRICT_POLICY_EPOCH) != 0U &&
	    tracker->policy_epoch == 0U) {
		return -EBADMSG;
	}
	if ((tracker->flags &
	     PQCP_FLEET_RECEIPT_TRACK_STRICT_REVOCATION_EPOCH) != 0U &&
	    tracker->revocation_epoch == 0U) {
		return -EBADMSG;
	}
	if (pqcp_fleet_receipt_tracker_terminal(
		    tracker->state)) {
		if (tracker->completed_at_ms == 0U) {
			return -EBADMSG;
		}
	} else if (tracker->completed_at_ms != 0U) {
		return -EBADMSG;
	}
	if (tracker->state ==
		    PQCP_FLEET_RECEIPT_TRACKER_COMPLETE &&
	    (tracker->acknowledged_count < tracker->quorum ||
	     tracker->required_ack_count !=
		     tracker->required_count)) {
		return -EBADMSG;
	}
	if (tracker->state ==
		    PQCP_FLEET_RECEIPT_TRACKER_QUORUM &&
	    (tracker->acknowledged_count < tracker->quorum ||
	     tracker->required_ack_count ==
		     tracker->required_count)) {
		return -EBADMSG;
	}
	ret = tracker_digest_compute(tracker, digest);
	if (ret == 0 &&
	    !digest_equal(digest, tracker->tracker_digest)) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int track_request_validate(
	const struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_track_request *request)
{
	if (request == NULL ||
	    request->artifact_id == 0U ||
	    request->message_id == 0U ||
	    request->correlation_id == 0U ||
	    request->receipt_epoch == 0U ||
	    request->created_at_ms == 0U ||
	    request->expires_at_ms <=
		    request->created_at_ms ||
	    request->artifact_size == 0U ||
	    request->chunk_count == 0U ||
	    request->quorum == 0U ||
	    (request->flags & ~known_tracker_flags()) != 0U ||
	    bytes_zero(
		    request->artifact_digest,
		    sizeof(request->artifact_digest)) ||
	    request->policy_epoch <
		    manager->minimum_policy_epoch ||
	    request->revocation_epoch <
		    manager->minimum_revocation_epoch) {
		return -EINVAL;
	}
	if ((request->flags &
	     PQCP_FLEET_RECEIPT_TRACK_STRICT_POLICY_EPOCH) != 0U &&
	    request->policy_epoch == 0U) {
		return -EINVAL;
	}
	if ((request->flags &
	     PQCP_FLEET_RECEIPT_TRACK_STRICT_REVOCATION_EPOCH) != 0U &&
	    request->revocation_epoch == 0U) {
		return -EINVAL;
	}
	return 0;
}

static bool track_request_matches(
	const struct pqcp_fleet_receipt_tracker *tracker,
	const struct pqcp_fleet_receipt_track_request *request)
{
	return tracker->artifact_id == request->artifact_id &&
	       tracker->message_id == request->message_id &&
	       tracker->correlation_id ==
		       request->correlation_id &&
	       tracker->receipt_epoch == request->receipt_epoch &&
	       tracker->policy_epoch == request->policy_epoch &&
	       tracker->revocation_epoch ==
		       request->revocation_epoch &&
	       tracker->created_at_ms == request->created_at_ms &&
	       tracker->expires_at_ms == request->expires_at_ms &&
	       tracker->artifact_size == request->artifact_size &&
	       tracker->chunk_count == request->chunk_count &&
	       tracker->quorum == request->quorum &&
	       tracker->flags == request->flags &&
	       digest_equal(
		       tracker->artifact_digest,
		       request->artifact_digest);
}

static int duplicate_tracker_index(
	const struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_track_request *request,
	bool *exact)
{
	*exact = false;
	for (size_t index = 0U;
	     index < manager->tracker_capacity; ++index) {
		const struct pqcp_fleet_receipt_tracker *tracker =
			&manager->trackers[index];

		if (!tracker->occupied) {
			continue;
		}
		if (tracker->artifact_id ==
			    request->artifact_id ||
		    (tracker->message_id ==
			     request->message_id &&
		     tracker->correlation_id ==
			     request->correlation_id)) {
			*exact = track_request_matches(
				tracker, request);
			return (int)index;
		}
	}
	return -1;
}

static void replay_reset(
	struct pqcp_fleet_receipt_peer *peer,
	uint64_t receipt_epoch)
{
	peer->replay_epoch = receipt_epoch;
	peer->replay_high_sequence = 0U;
	memset(peer->replay_bitmap, 0,
	       sizeof(peer->replay_bitmap));
	peer->replay_initialized = false;
}

static bool replay_bit_get(
	const struct pqcp_fleet_receipt_peer *peer,
	uint32_t distance)
{
	uint32_t word = distance / 64U;
	uint32_t bit = distance % 64U;

	if (word >= PQCP_FLEET_RECEIPT_REPLAY_WORDS) {
		return false;
	}
	return (peer->replay_bitmap[word] &
		((uint64_t)1U << bit)) != 0U;
}

static void replay_shift_left(
	struct pqcp_fleet_receipt_peer *peer,
	uint32_t shift)
{
	uint64_t shifted[PQCP_FLEET_RECEIPT_REPLAY_WORDS];
	uint32_t word_shift = shift / 64U;
	uint32_t bit_shift = shift % 64U;

	memset(shifted, 0, sizeof(shifted));
	if (shift >= PQCP_FLEET_RECEIPT_REPLAY_BITS) {
		memset(peer->replay_bitmap, 0,
		       sizeof(peer->replay_bitmap));
		return;
	}
	for (size_t destination =
		     PQCP_FLEET_RECEIPT_REPLAY_WORDS;
	     destination > 0U; --destination) {
		size_t output_index = destination - 1U;

		if (output_index < word_shift) {
			continue;
		}
		size_t source_index =
			output_index - word_shift;
		shifted[output_index] |=
			peer->replay_bitmap[source_index] <<
			bit_shift;
		if (bit_shift != 0U && source_index > 0U) {
			shifted[output_index] |=
				peer->replay_bitmap[
					source_index - 1U] >>
				(64U - bit_shift);
		}
	}
	memcpy(peer->replay_bitmap, shifted,
	       sizeof(peer->replay_bitmap));
	pqcp_runtime_secure_zero(shifted, sizeof(shifted));
}

static enum replay_result replay_classify(
	const struct pqcp_fleet_receipt_peer *peer,
	uint64_t receipt_epoch,
	uint64_t sequence)
{
	uint64_t distance;

	if (peer->replay_initialized &&
	    receipt_epoch < peer->replay_epoch) {
		return REPLAY_RESULT_STALE_EPOCH;
	}
	if (!peer->replay_initialized ||
	    receipt_epoch > peer->replay_epoch) {
		return REPLAY_RESULT_NEW;
	}
	if (sequence > peer->replay_high_sequence) {
		return REPLAY_RESULT_NEW;
	}
	distance = peer->replay_high_sequence - sequence;
	if (distance >= PQCP_FLEET_RECEIPT_REPLAY_BITS) {
		return REPLAY_RESULT_TOO_OLD;
	}
	return replay_bit_get(peer, (uint32_t)distance) ?
		REPLAY_RESULT_DUPLICATE :
		REPLAY_RESULT_NEW;
}

static void replay_commit(
	struct pqcp_fleet_receipt_peer *peer,
	uint64_t receipt_epoch,
	uint64_t sequence)
{
	if (!peer->replay_initialized ||
	    receipt_epoch > peer->replay_epoch) {
		replay_reset(peer, receipt_epoch);
		peer->replay_high_sequence = sequence;
		peer->replay_bitmap[0] = 1U;
		peer->replay_initialized = true;
		return;
	}
	if (sequence > peer->replay_high_sequence) {
		uint64_t delta =
			sequence - peer->replay_high_sequence;

		replay_shift_left(
			peer,
			delta >= UINT32_MAX ?
				PQCP_FLEET_RECEIPT_REPLAY_BITS :
				(uint32_t)delta);
		peer->replay_high_sequence = sequence;
		peer->replay_bitmap[0] |= 1U;
		return;
	}
	uint64_t distance =
		peer->replay_high_sequence - sequence;

	if (distance < PQCP_FLEET_RECEIPT_REPLAY_BITS) {
		uint32_t word = (uint32_t)distance / 64U;
		uint32_t bit = (uint32_t)distance % 64U;

		peer->replay_bitmap[word] |=
			(uint64_t)1U << bit;
	}
}

static int retained_receipt_index(
	const struct pqcp_fleet_receipt_manager *manager,
	const char *peer_id,
	uint64_t receipt_epoch,
	uint64_t sequence)
{
	for (size_t logical = 0U;
	     logical < manager->receipt_count; ++logical) {
		size_t index =
			(manager->receipt_head + logical) %
			manager->receipt_capacity;
		const struct pqcp_fleet_receipt_record *record =
			&manager->receipts[index];

		if (record->occupied &&
		    record->receipt_epoch == receipt_epoch &&
		    record->sequence == sequence &&
		    strcmp(record->peer_id, peer_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static int append_receipt_record(
	struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_packet *packet,
	const uint8_t receipt_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms,
	int processing_result,
	bool authenticated,
	bool replay,
	bool collision)
{
	struct pqcp_fleet_receipt_record staged;
	size_t index;
	int ret;

	memset(&staged, 0, sizeof(staged));
	staged.schema_version =
		PQCP_FLEET_RECEIPT_SCHEMA_VERSION;
	staged.received_order =
		manager->next_received_order;
	if (manager->next_received_order != UINT64_MAX) {
		manager->next_received_order++;
	}
	staged.received_at_ms = now_ms;
	staged.receipt_id = packet->receipt_id;
	staged.receipt_epoch = packet->receipt_epoch;
	staged.sequence = packet->sequence;
	staged.artifact_id = packet->artifact_id;
	staged.message_id = packet->message_id;
	staged.correlation_id = packet->correlation_id;
	staged.kind = packet->kind;
	staged.status = packet->status;
	staged.processing_result = processing_result;
	staged.authenticated = authenticated;
	staged.replay = replay;
	staged.collision = collision;
	staged.occupied = true;
	ret = copy_text(
		staged.peer_id, sizeof(staged.peer_id),
		packet->peer_id);
	if (ret != 0) {
		pqcp_runtime_secure_zero(&staged, sizeof(staged));
		return ret;
	}
	memcpy(staged.receipt_digest, receipt_digest,
	       sizeof(staged.receipt_digest));
	if (manager->receipt_count <
	    manager->receipt_capacity) {
		index = (manager->receipt_head +
			 manager->receipt_count) %
			manager->receipt_capacity;
		manager->receipt_count++;
	} else {
		index = manager->receipt_head;
		manager->receipt_head =
			(manager->receipt_head + 1U) %
			manager->receipt_capacity;
		saturating_increment_u64(
			&manager->dropped_receipt_records);
	}
	pqcp_runtime_secure_zero(
		&manager->receipts[index],
		sizeof(manager->receipts[index]));
	manager->receipts[index] = staged;
	pqcp_runtime_secure_zero(&staged, sizeof(staged));
	return 0;
}

static int tracker_binding_validate(
	const struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_tracker *tracker,
	const struct pqcp_fleet_receipt_packet *packet,
	uint64_t now_ms)
{
	if (tracker->message_id != packet->message_id ||
	    tracker->correlation_id !=
		    packet->correlation_id ||
	    tracker->receipt_epoch != packet->receipt_epoch ||
	    tracker->artifact_size != packet->artifact_size ||
	    tracker->chunk_count != packet->chunk_count ||
	    !digest_equal(
		    tracker->artifact_digest,
		    packet->artifact_digest)) {
		return -EKEYREJECTED;
	}
	if (now_ms < tracker->created_at_ms ||
	    now_ms >= tracker->expires_at_ms ||
	    packet->issued_at_ms < tracker->created_at_ms ||
	    packet->issued_at_ms >= tracker->expires_at_ms ||
	    packet->expires_at_ms <= now_ms) {
		return -ETIMEDOUT;
	}
	if (packet->policy_epoch <
		    manager->minimum_policy_epoch ||
	    packet->revocation_epoch <
		    manager->minimum_revocation_epoch) {
		return -ESTALE;
	}
	if ((tracker->flags &
	     PQCP_FLEET_RECEIPT_TRACK_STRICT_POLICY_EPOCH) != 0U &&
	    packet->policy_epoch != tracker->policy_epoch) {
		return -ESTALE;
	}
	if ((tracker->flags &
	     PQCP_FLEET_RECEIPT_TRACK_STRICT_REVOCATION_EPOCH) != 0U &&
	    packet->revocation_epoch !=
		    tracker->revocation_epoch) {
		return -ESTALE;
	}
	return 0;
}

static int ack_allocate(
	struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_tracker *tracker,
	const char *peer_id,
	bool required,
	struct pqcp_fleet_receipt_ack **ack)
{
	int index = ack_index(
		manager, tracker->artifact_id,
		tracker->generation, peer_id);
	int ret;

	if (index >= 0) {
		*ack = &manager->acks[index];
		return 0;
	}
	index = free_ack_index(manager);
	if (index < 0) {
		return -ENOSPC;
	}
	struct pqcp_fleet_receipt_ack staged;

	memset(&staged, 0, sizeof(staged));
	staged.schema_version =
		PQCP_FLEET_RECEIPT_SCHEMA_VERSION;
	staged.tracker_generation = tracker->generation;
	staged.artifact_id = tracker->artifact_id;
	staged.required = required;
	staged.occupied = true;
	ret = copy_text(
		staged.peer_id, sizeof(staged.peer_id), peer_id);
	if (ret != 0) {
		pqcp_runtime_secure_zero(&staged, sizeof(staged));
		return ret;
	}
	manager->acks[index] = staged;
	manager->ack_count++;
	*ack = &manager->acks[index];
	pqcp_runtime_secure_zero(&staged, sizeof(staged));
	return 0;
}

static void tracker_set_terminal(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker *tracker,
	enum pqcp_fleet_receipt_tracker_state state,
	int result,
	uint32_t reason,
	uint64_t now_ms)
{
	if (pqcp_fleet_receipt_tracker_terminal(
		    tracker->state)) {
		return;
	}
	tracker->state = state;
	tracker->terminal_result = result;
	tracker->terminal_reason = reason;
	tracker->completed_at_ms = now_ms;
	switch (state) {
	case PQCP_FLEET_RECEIPT_TRACKER_COMPLETE:
		saturating_increment_u64(
			&manager->completed_count);
		break;
	case PQCP_FLEET_RECEIPT_TRACKER_FAILED:
	case PQCP_FLEET_RECEIPT_TRACKER_CONFLICT:
		saturating_increment_u64(
			&manager->failed_count);
		break;
	case PQCP_FLEET_RECEIPT_TRACKER_CANCELLED:
		saturating_increment_u64(
			&manager->cancelled_count);
		break;
	case PQCP_FLEET_RECEIPT_TRACKER_EXPIRED:
		saturating_increment_u64(
			&manager->expired_count);
		break;
	default:
		break;
	}
}

static void tracker_evaluate(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker *tracker,
	uint64_t now_ms)
{
	if (pqcp_fleet_receipt_tracker_terminal(
		    tracker->state)) {
		return;
	}
	if (tracker->acknowledged_count >= tracker->quorum) {
		if (tracker->required_ack_count ==
		    tracker->required_count) {
			tracker_set_terminal(
				manager, tracker,
				PQCP_FLEET_RECEIPT_TRACKER_COMPLETE,
				0, 0U, now_ms);
		} else {
			tracker->state =
				PQCP_FLEET_RECEIPT_TRACKER_QUORUM;
		}
	} else {
		tracker->state =
			PQCP_FLEET_RECEIPT_TRACKER_PENDING;
	}
}

static int apply_chunk_receipt(
	struct pqcp_fleet_receipt_ack *ack,
	const struct pqcp_fleet_receipt_tracker *tracker,
	const struct pqcp_fleet_receipt_packet *packet,
	bool *duplicate)
{
	uint64_t expected_bytes;

	if ((tracker->flags &
	     PQCP_FLEET_RECEIPT_TRACK_REQUIRE_CHUNKS) == 0U) {
		return -EACCES;
	}
	if (packet->chunk_count != tracker->chunk_count) {
		return -EKEYREJECTED;
	}
	if (packet->chunk_index < ack->next_chunk) {
		if (packet->chunk_index + 1U ==
			    ack->next_chunk &&
		    packet->acknowledged_bytes ==
			    ack->acknowledged_bytes &&
		    digest_equal(
			    packet->chunk_digest,
			    ack->last_chunk_digest)) {
			*duplicate = true;
			return 0;
		}
		return -ESTALE;
	}
	if (packet->chunk_index > ack->next_chunk) {
		return -EAGAIN;
	}
	if (!add_u64(
		    ack->acknowledged_bytes,
		    packet->chunk_length,
		    &expected_bytes) ||
	    expected_bytes > tracker->artifact_size ||
	    packet->acknowledged_bytes != expected_bytes) {
		return -ERANGE;
	}
	if (packet->chunk_index + 1U <
		    tracker->chunk_count &&
	    expected_bytes >= tracker->artifact_size) {
		return -ERANGE;
	}
	if (packet->chunk_index + 1U ==
		    tracker->chunk_count &&
	    expected_bytes != tracker->artifact_size) {
		return -ERANGE;
	}
	ack->acknowledged_bytes = expected_bytes;
	ack->next_chunk++;
	memcpy(ack->last_chunk_digest,
	       packet->chunk_digest,
	       sizeof(ack->last_chunk_digest));
	return 0;
}

static int apply_final_receipt(
	struct pqcp_fleet_receipt_ack *ack,
	const struct pqcp_fleet_receipt_tracker *tracker,
	const struct pqcp_fleet_receipt_packet *packet,
	bool *became_final,
	bool *duplicate)
{
	bool require_applied =
		(tracker->flags &
		 PQCP_FLEET_RECEIPT_TRACK_REQUIRE_APPLIED) != 0U;

	if ((tracker->flags &
	     PQCP_FLEET_RECEIPT_TRACK_REQUIRE_CHUNKS) != 0U &&
	    (ack->next_chunk != tracker->chunk_count ||
	     ack->acknowledged_bytes !=
		     tracker->artifact_size)) {
		return -EINPROGRESS;
	}
	if (packet->acknowledged_bytes !=
	    tracker->artifact_size) {
		return -ERANGE;
	}
	if (require_applied &&
	    packet->status !=
		    PQCP_FLEET_RECEIPT_STATUS_APPLIED) {
		return -EAGAIN;
	}
	if (require_applied &&
	    packet->kind != PQCP_FLEET_RECEIPT_FINAL) {
		return -EAGAIN;
	}
	if (ack->final_acknowledged) {
		*duplicate = true;
		return 0;
	}
	ack->acknowledged_bytes =
		tracker->artifact_size;
	ack->next_chunk = tracker->chunk_count;
	ack->final_acknowledged = true;
	ack->terminal_status = packet->status;
	ack->result = packet->result;
	ack->reason = packet->reason;
	*became_final = true;
	return 0;
}

static int apply_rejection_receipt(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker *tracker,
	struct pqcp_fleet_receipt_ack *ack,
	const struct pqcp_fleet_receipt_packet *packet,
	uint64_t now_ms)
{
	bool first_rejection =
		ack->terminal_status !=
			PQCP_FLEET_RECEIPT_STATUS_REJECTED &&
		ack->terminal_status !=
			PQCP_FLEET_RECEIPT_STATUS_FAILED;

	ack->terminal_status = packet->status;
	ack->result = packet->result;
	ack->reason = packet->reason;
	if (first_rejection) {
		if (packet->status ==
		    PQCP_FLEET_RECEIPT_STATUS_FAILED) {
			saturating_increment_u32(
				&tracker->failed_count);
		} else {
			saturating_increment_u32(
				&tracker->rejected_count);
		}
	}
	saturating_increment_u32(
		&ack->rejected_receipts);
	if ((tracker->flags &
	     PQCP_FLEET_RECEIPT_TRACK_FAIL_ANY_REJECTION) != 0U ||
	    (ack->required &&
	     (tracker->flags &
	      PQCP_FLEET_RECEIPT_TRACK_FAIL_REQUIRED_REJECTION) != 0U)) {
		tracker_set_terminal(
			manager, tracker,
			PQCP_FLEET_RECEIPT_TRACKER_FAILED,
			packet->result != 0 ?
				packet->result : -ECANCELED,
			packet->reason, now_ms);
	}
	return 0;
}

static int apply_receipt(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker *tracker,
	struct pqcp_fleet_receipt_ack *ack,
	const struct pqcp_fleet_receipt_packet *packet,
	const uint8_t receipt_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms,
	bool *duplicate)
{
	bool became_final = false;
	int ret;

	*duplicate = false;
	if (ack->last_receipt_id == packet->receipt_id) {
		if (digest_equal(
			    ack->last_receipt_digest,
			    receipt_digest)) {
			*duplicate = true;
			return 0;
		}
		return -EKEYREJECTED;
	}
	switch (packet->kind) {
	case PQCP_FLEET_RECEIPT_CHUNK:
		ret = apply_chunk_receipt(
			ack, tracker, packet, duplicate);
		break;
	case PQCP_FLEET_RECEIPT_ARTIFACT:
	case PQCP_FLEET_RECEIPT_FINAL:
		ret = apply_final_receipt(
			ack, tracker, packet,
			&became_final, duplicate);
		break;
	case PQCP_FLEET_RECEIPT_REJECTION:
		ret = apply_rejection_receipt(
			manager, tracker, ack, packet, now_ms);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	if (ret != 0) {
		return ret;
	}
	if (!*duplicate) {
		ack->last_receipt_id = packet->receipt_id;
		if (packet->sequence > ack->last_sequence) {
			ack->last_sequence = packet->sequence;
		}
		memcpy(ack->last_receipt_digest,
		       receipt_digest,
		       sizeof(ack->last_receipt_digest));
		saturating_increment_u32(
			&ack->accepted_receipts);
		if (became_final) {
			saturating_increment_u32(
				&tracker->acknowledged_count);
			if (ack->required) {
				saturating_increment_u32(
					&tracker->
						required_ack_count);
			}
		}
	}
	tracker_evaluate(manager, tracker, now_ms);
	return tracker_digest_refresh(tracker);
}

static void outcome_fill(
	const struct pqcp_fleet_receipt_tracker *tracker,
	const struct pqcp_fleet_receipt_ack *ack,
	bool authenticated,
	bool duplicate,
	bool replay,
	bool collision,
	struct pqcp_fleet_receipt_outcome *outcome)
{
	memset(outcome, 0, sizeof(*outcome));
	if (tracker != NULL) {
		outcome->tracker.artifact_id =
			tracker->artifact_id;
		outcome->tracker.generation =
			tracker->generation;
		outcome->tracker_state = tracker->state;
		outcome->acknowledged_count =
			tracker->acknowledged_count;
		outcome->required_ack_count =
			tracker->required_ack_count;
		outcome->required_count =
			tracker->required_count;
		outcome->quorum = tracker->quorum;
		outcome->quorum_reached =
			tracker->acknowledged_count >=
			tracker->quorum;
		outcome->complete =
			tracker->state ==
			PQCP_FLEET_RECEIPT_TRACKER_COMPLETE;
	}
	if (ack != NULL) {
		outcome->next_chunk = ack->next_chunk;
		outcome->acknowledged_bytes =
			ack->acknowledged_bytes;
	}
	outcome->authenticated = authenticated;
	outcome->duplicate = duplicate;
	outcome->replay = replay;
	outcome->collision = collision;
}

int pqcp_fleet_receipt_manager_init(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_peer *peers,
	size_t peer_capacity,
	struct pqcp_fleet_receipt_tracker *trackers,
	size_t tracker_capacity,
	struct pqcp_fleet_receipt_ack *acks,
	size_t ack_capacity,
	struct pqcp_fleet_receipt_record *receipts,
	size_t receipt_capacity)
{
	if (manager == NULL || peers == NULL ||
	    peer_capacity == 0U || trackers == NULL ||
	    tracker_capacity == 0U || acks == NULL ||
	    ack_capacity == 0U || receipts == NULL ||
	    receipt_capacity == 0U ||
	    !size_array_valid(peer_capacity, sizeof(*peers)) ||
	    !size_array_valid(
		    tracker_capacity, sizeof(*trackers)) ||
	    !size_array_valid(ack_capacity, sizeof(*acks)) ||
	    !size_array_valid(
		    receipt_capacity, sizeof(*receipts))) {
		return -EINVAL;
	}
	memset(manager, 0, sizeof(*manager));
	memset(peers, 0, sizeof(*peers) * peer_capacity);
	memset(trackers, 0,
	       sizeof(*trackers) * tracker_capacity);
	memset(acks, 0, sizeof(*acks) * ack_capacity);
	memset(receipts, 0,
	       sizeof(*receipts) * receipt_capacity);
	manager->schema_version =
		PQCP_FLEET_RECEIPT_SCHEMA_VERSION;
	manager->peers = peers;
	manager->peer_capacity = peer_capacity;
	manager->trackers = trackers;
	manager->tracker_capacity = tracker_capacity;
	manager->acks = acks;
	manager->ack_capacity = ack_capacity;
	manager->receipts = receipts;
	manager->receipt_capacity = receipt_capacity;
	manager->next_peer_generation = 1U;
	manager->next_tracker_generation = 1U;
	manager->next_received_order = 1U;
	manager->generation = 1U;
	k_mutex_init(&manager->lock);
	manager->initialized = true;
	return 0;
}

int pqcp_fleet_receipt_manager_deinit(
	struct pqcp_fleet_receipt_manager *manager)
{
	int ret;

	if (manager_validate(manager) != 0) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < manager->peer_capacity; ++index) {
		pqcp_runtime_secure_zero(
			&manager->peers[index],
			sizeof(manager->peers[index]));
	}
	for (size_t index = 0U;
	     index < manager->tracker_capacity; ++index) {
		pqcp_runtime_secure_zero(
			&manager->trackers[index],
			sizeof(manager->trackers[index]));
	}
	for (size_t index = 0U;
	     index < manager->ack_capacity; ++index) {
		pqcp_runtime_secure_zero(
			&manager->acks[index],
			sizeof(manager->acks[index]));
	}
	for (size_t index = 0U;
	     index < manager->receipt_capacity; ++index) {
		pqcp_runtime_secure_zero(
			&manager->receipts[index],
			sizeof(manager->receipts[index]));
	}
	manager->initialized = false;
	manager->peer_count = 0U;
	manager->tracker_count = 0U;
	manager->ack_count = 0U;
	manager->receipt_count = 0U;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

static bool peer_required_by_pending_tracker(
	const struct pqcp_fleet_receipt_manager *manager,
	const char *peer_id)
{
	for (size_t index = 0U;
	     index < manager->ack_capacity; ++index) {
		const struct pqcp_fleet_receipt_ack *ack =
			&manager->acks[index];
		int tracker_index;

		if (!ack->occupied || !ack->required ||
		    ack->final_acknowledged ||
		    strcmp(ack->peer_id, peer_id) != 0) {
			continue;
		}
		tracker_index = tracker_index_by_artifact(
			manager, ack->artifact_id);
		if (tracker_index >= 0 &&
		    manager->trackers[tracker_index].generation ==
			    ack->tracker_generation &&
		    !pqcp_fleet_receipt_tracker_terminal(
			    manager->trackers[tracker_index].state)) {
			return true;
		}
	}
	return false;
}

int pqcp_fleet_receipt_register_peer(
	struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_peer_registration *registration,
	uint64_t now_ms)
{
	struct pqcp_fleet_receipt_peer staged;
	uint8_t key_digest[PQCP_FLEET_DIGEST_BYTES];
	int index;
	int ret;

	if (manager_validate(manager) != 0 ||
	    registration == NULL ||
	    !text_valid(
		    registration->peer_id,
		    PQCP_FLEET_RECEIPT_PEER_MAX_CHARS) ||
	    !text_valid(
		    registration->key_id,
		    PQCP_FLEET_RECEIPT_KEY_ID_MAX_CHARS) ||
	    registration->key == NULL ||
	    registration->key_length <
		    RECEIPT_MINIMUM_KEY_BYTES ||
	    registration->key_length >
		    PQCP_FLEET_RECEIPT_KEY_MAX_BYTES ||
	    registration->key_epoch == 0U ||
	    registration->valid_from_ms == 0U ||
	    registration->valid_until_ms <=
		    registration->valid_from_ms ||
	    registration->minimum_receipt_epoch == 0U ||
	    now_ms < registration->valid_from_ms ||
	    now_ms >= registration->valid_until_ms) {
		return -EINVAL;
	}
	memset(&staged, 0, sizeof(staged));
	memset(key_digest, 0, sizeof(key_digest));
	ret = key_digest_compute(
		registration->key,
		registration->key_length,
		key_digest);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			key_digest, sizeof(key_digest));
		return ret;
	}
	index = peer_index(manager, registration->peer_id);
	if (index >= 0) {
		struct pqcp_fleet_receipt_peer *existing =
			&manager->peers[index];

		if (existing->key_epoch ==
			    registration->key_epoch &&
		    strcmp(existing->key_id,
			   registration->key_id) == 0 &&
		    digest_equal(
			    existing->key_digest,
			    key_digest)) {
			existing->valid_from_ms =
				registration->valid_from_ms;
			existing->valid_until_ms =
				registration->valid_until_ms;
			existing->minimum_receipt_epoch =
				registration->
					minimum_receipt_epoch;
			existing->enabled =
				registration->enabled;
			saturating_increment_u64(
				&manager->generation);
			(void)k_mutex_unlock(&manager->lock);
			pqcp_runtime_secure_zero(
				key_digest, sizeof(key_digest));
			return 0;
		}
		if (registration->key_epoch <=
		    existing->key_epoch) {
			(void)k_mutex_unlock(&manager->lock);
			pqcp_runtime_secure_zero(
				key_digest, sizeof(key_digest));
			return -EKEYREJECTED;
		}
		if (peer_required_by_pending_tracker(
			    manager, registration->peer_id)) {
			(void)k_mutex_unlock(&manager->lock);
			pqcp_runtime_secure_zero(
				key_digest, sizeof(key_digest));
			return -EBUSY;
		}
	} else {
		index = free_peer_index(manager);
		if (index < 0) {
			(void)k_mutex_unlock(&manager->lock);
			pqcp_runtime_secure_zero(
				key_digest, sizeof(key_digest));
			return -ENOSPC;
		}
	}
	staged.schema_version =
		PQCP_FLEET_RECEIPT_SCHEMA_VERSION;
	staged.generation = next_peer_generation(manager);
	staged.key_length = registration->key_length;
	staged.key_epoch = registration->key_epoch;
	staged.valid_from_ms = registration->valid_from_ms;
	staged.valid_until_ms = registration->valid_until_ms;
	staged.minimum_receipt_epoch =
		registration->minimum_receipt_epoch;
	staged.enabled = registration->enabled;
	staged.occupied = true;
	ret = copy_text(
		staged.peer_id, sizeof(staged.peer_id),
		registration->peer_id);
	if (ret == 0) {
		ret = copy_text(
			staged.key_id, sizeof(staged.key_id),
			registration->key_id);
	}
	if (ret == 0) {
		memcpy(staged.key, registration->key,
		       registration->key_length);
		memcpy(staged.key_digest, key_digest,
		       sizeof(staged.key_digest));
		if (manager->peers[index].occupied) {
			pqcp_runtime_secure_zero(
				&manager->peers[index],
				sizeof(manager->peers[index]));
		} else {
			manager->peer_count++;
		}
		manager->peers[index] = staged;
		saturating_increment_u64(
			&manager->generation);
	}
	(void)k_mutex_unlock(&manager->lock);
	pqcp_runtime_secure_zero(&staged, sizeof(staged));
	pqcp_runtime_secure_zero(
		key_digest, sizeof(key_digest));
	return ret;
}

int pqcp_fleet_receipt_unregister_peer(
	struct pqcp_fleet_receipt_manager *manager,
	const char *peer_id)
{
	int index;
	int ret;

	if (manager_validate(manager) != 0 ||
	    !text_valid(
		    peer_id,
		    PQCP_FLEET_RECEIPT_PEER_MAX_CHARS)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = peer_index(manager, peer_id);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	if (peer_required_by_pending_tracker(
		    manager, peer_id)) {
		(void)k_mutex_unlock(&manager->lock);
		return -EBUSY;
	}
	pqcp_runtime_secure_zero(
		&manager->peers[index],
		sizeof(manager->peers[index]));
	manager->peer_count--;
	saturating_increment_u64(&manager->generation);
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_receipt_advance_epochs(
	struct pqcp_fleet_receipt_manager *manager,
	uint64_t policy_epoch,
	uint64_t revocation_epoch)
{
	int ret;

	if (manager_validate(manager) != 0) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (policy_epoch < manager->minimum_policy_epoch ||
	    revocation_epoch <
		    manager->minimum_revocation_epoch) {
		(void)k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	manager->minimum_policy_epoch = policy_epoch;
	manager->minimum_revocation_epoch =
		revocation_epoch;
	saturating_increment_u64(&manager->generation);
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_receipt_track(
	struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_track_request *request,
	struct pqcp_fleet_receipt_tracker_handle *handle,
	bool *replayed)
{
	struct pqcp_fleet_receipt_tracker staged;
	bool exact;
	int duplicate_index;
	int index;
	int ret;

	if (manager_validate(manager) != 0 ||
	    request == NULL || handle == NULL ||
	    replayed == NULL) {
		return -EINVAL;
	}
	ret = track_request_validate(manager, request);
	if (ret != 0) {
		return ret;
	}
	memset(handle, 0, sizeof(*handle));
	*replayed = false;
	memset(&staged, 0, sizeof(staged));
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	duplicate_index = duplicate_tracker_index(
		manager, request, &exact);
	if (duplicate_index >= 0) {
		const struct pqcp_fleet_receipt_tracker *existing =
			&manager->trackers[duplicate_index];

		if (exact) {
			handle->artifact_id =
				existing->artifact_id;
			handle->generation =
				existing->generation;
			*replayed = true;
			(void)k_mutex_unlock(&manager->lock);
			return 0;
		}
		saturating_increment_u64(
			&manager->collision_count);
		(void)k_mutex_unlock(&manager->lock);
		return -EKEYREJECTED;
	}
	index = free_tracker_index(manager);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOSPC;
	}
	staged.schema_version =
		PQCP_FLEET_RECEIPT_SCHEMA_VERSION;
	staged.generation =
		next_tracker_generation(manager);
	staged.artifact_id = request->artifact_id;
	staged.message_id = request->message_id;
	staged.correlation_id = request->correlation_id;
	staged.receipt_epoch = request->receipt_epoch;
	staged.policy_epoch = request->policy_epoch;
	staged.revocation_epoch = request->revocation_epoch;
	staged.created_at_ms = request->created_at_ms;
	staged.expires_at_ms = request->expires_at_ms;
	staged.artifact_size = request->artifact_size;
	staged.chunk_count = request->chunk_count;
	staged.quorum = request->quorum;
	staged.flags = request->flags;
	staged.state = PQCP_FLEET_RECEIPT_TRACKER_PENDING;
	memcpy(staged.artifact_digest,
	       request->artifact_digest,
	       sizeof(staged.artifact_digest));
	staged.occupied = true;
	ret = tracker_digest_refresh(&staged);
	if (ret == 0) {
		manager->trackers[index] = staged;
		manager->tracker_count++;
		handle->artifact_id = staged.artifact_id;
		handle->generation = staged.generation;
		saturating_increment_u64(
			&manager->generation);
	}
	(void)k_mutex_unlock(&manager->lock);
	pqcp_runtime_secure_zero(&staged, sizeof(staged));
	return ret;
}

int pqcp_fleet_receipt_require_peer(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle,
	const char *peer_id)
{
	struct pqcp_fleet_receipt_tracker *tracker;
	struct pqcp_fleet_receipt_ack *ack;
	int tracker_index;
	int peer_position;
	int ret;

	if (manager_validate(manager) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U ||
	    !text_valid(
		    peer_id,
		    PQCP_FLEET_RECEIPT_PEER_MAX_CHARS)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	tracker_index = tracker_index_by_handle(
		manager, handle);
	peer_position = peer_index(manager, peer_id);
	if (tracker_index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	if (peer_position < 0 ||
	    !manager->peers[peer_position].enabled) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	tracker = &manager->trackers[tracker_index];
	if (pqcp_fleet_receipt_tracker_terminal(
		    tracker->state)) {
		(void)k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	ret = ack_allocate(
		manager, tracker, peer_id, true, &ack);
	if (ret != 0) {
		(void)k_mutex_unlock(&manager->lock);
		return ret;
	}
	if (!ack->required) {
		if (tracker->required_count == UINT32_MAX) {
			(void)k_mutex_unlock(&manager->lock);
			return -EOVERFLOW;
		}
		ack->required = true;
		tracker->required_count++;
		if (ack->final_acknowledged) {
			if (tracker->required_ack_count ==
			    UINT32_MAX) {
				(void)k_mutex_unlock(
					&manager->lock);
				return -EOVERFLOW;
			}
			tracker->required_ack_count++;
		}
	} else if (tracker->required_count == 0U) {
		tracker->required_count = 1U;
		if (ack->final_acknowledged) {
			tracker->required_ack_count = 1U;
		}
	}
	tracker_evaluate(
		manager, tracker, tracker->created_at_ms);
	ret = tracker_digest_refresh(tracker);
	if (ret == 0) {
		saturating_increment_u64(
			&manager->generation);
	}
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}

static int peer_packet_validate(
	const struct pqcp_fleet_receipt_peer *peer,
	const struct pqcp_fleet_receipt_packet *packet,
	uint64_t now_ms)
{
	if (!peer->enabled ||
	    strcmp(peer->key_id, packet->key_id) != 0 ||
	    now_ms < peer->valid_from_ms ||
	    now_ms >= peer->valid_until_ms ||
	    packet->issued_at_ms < peer->valid_from_ms ||
	    packet->issued_at_ms >= peer->valid_until_ms ||
	    packet->receipt_epoch <
		    peer->minimum_receipt_epoch) {
		return -EKEYEXPIRED;
	}
	if (packet->issued_at_ms > now_ms ||
	    packet->expires_at_ms <= now_ms) {
		return -ETIMEDOUT;
	}
	return 0;
}

int pqcp_fleet_receipt_ingest(
	struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_packet *packet,
	uint64_t now_ms,
	struct pqcp_fleet_receipt_outcome *outcome)
{
	struct pqcp_fleet_receipt_tracker *tracker = NULL;
	struct pqcp_fleet_receipt_peer *peer;
	struct pqcp_fleet_receipt_ack *ack = NULL;
	uint8_t receipt_digest[PQCP_FLEET_DIGEST_BYTES];
	enum replay_result replay_result;
	bool duplicate = false;
	bool collision = false;
	int retained_index;
	int tracker_position;
	int peer_position;
	int ret;

	if (manager_validate(manager) != 0 ||
	    packet_validate(packet, true) != 0 ||
	    now_ms == 0U || outcome == NULL) {
		return -EINVAL;
	}
	memset(outcome, 0, sizeof(*outcome));
	memset(receipt_digest, 0, sizeof(receipt_digest));
	ret = pqcp_fleet_receipt_digest(
		packet, receipt_digest);
	if (ret != 0) {
		return ret;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			receipt_digest, sizeof(receipt_digest));
		return ret;
	}
	peer_position = peer_index(manager, packet->peer_id);
	if (peer_position < 0) {
		ret = -ENOKEY;
		(void)append_receipt_record(
			manager, packet, receipt_digest,
			now_ms, ret, false, false, false);
		saturating_increment_u64(
			&manager->authentication_failure_count);
		outcome_fill(
			NULL, NULL, false, false,
			false, false, outcome);
		goto out;
	}
	peer = &manager->peers[peer_position];
	ret = peer_packet_validate(peer, packet, now_ms);
	if (ret == 0) {
		ret = pqcp_fleet_receipt_verify_auth(
			packet, peer->key, peer->key_length);
	}
	if (ret != 0) {
		saturating_increment_u64(
			&peer->authentication_failure_count);
		saturating_increment_u64(
			&manager->authentication_failure_count);
		(void)append_receipt_record(
			manager, packet, receipt_digest,
			now_ms, ret, false, false, false);
		outcome_fill(
			NULL, NULL, false, false,
			false, false, outcome);
		goto out;
	}
	saturating_increment_u64(&peer->accepted_count);
	saturating_increment_u64(
		&manager->authenticated_count);
	replay_result = replay_classify(
		peer, packet->receipt_epoch, packet->sequence);
	if (replay_result != REPLAY_RESULT_NEW) {
		retained_index = retained_receipt_index(
			manager, packet->peer_id,
			packet->receipt_epoch, packet->sequence);
		if (retained_index >= 0 &&
		    !digest_equal(
			    manager->receipts[retained_index].
				    receipt_digest,
			    receipt_digest)) {
			collision = true;
			ret = -EKEYREJECTED;
			saturating_increment_u64(
				&manager->collision_count);
		} else {
			ret = -EALREADY;
		}
		saturating_increment_u64(&peer->replay_count);
		saturating_increment_u64(
			&manager->replay_count);
		(void)append_receipt_record(
			manager, packet, receipt_digest,
			now_ms, ret, true, true, collision);
		outcome_fill(
			NULL, NULL, true, false,
			true, collision, outcome);
		goto out;
	}
	replay_commit(
		peer, packet->receipt_epoch, packet->sequence);
	tracker_position = tracker_index_by_artifact(
		manager, packet->artifact_id);
	if (tracker_position < 0) {
		ret = -ENOENT;
		saturating_increment_u64(
			&manager->binding_failure_count);
		saturating_increment_u64(
			&peer->rejected_count);
		(void)append_receipt_record(
			manager, packet, receipt_digest,
			now_ms, ret, true, false, false);
		outcome_fill(
			NULL, NULL, true, false,
			false, false, outcome);
		goto out;
	}
	tracker = &manager->trackers[tracker_position];
	if (pqcp_fleet_receipt_tracker_terminal(
		    tracker->state)) {
		ret = -EALREADY;
		(void)append_receipt_record(
			manager, packet, receipt_digest,
			now_ms, ret, true, false, false);
		outcome_fill(
			tracker, NULL, true, false,
			false, false, outcome);
		goto out;
	}
	ret = tracker_binding_validate(
		manager, tracker, packet, now_ms);
	if (ret != 0) {
		bool digest_conflict =
			!digest_equal(
				tracker->artifact_digest,
				packet->artifact_digest);

		saturating_increment_u64(
			&manager->binding_failure_count);
		saturating_increment_u64(
			&peer->rejected_count);
		if (digest_conflict ||
		    ((tracker->flags &
		      PQCP_FLEET_RECEIPT_TRACK_HIGH_INTEGRITY) != 0U &&
		     ret == -EKEYREJECTED)) {
			tracker_set_terminal(
				manager, tracker,
				PQCP_FLEET_RECEIPT_TRACKER_CONFLICT,
				-EKEYREJECTED, packet->reason,
				now_ms);
			(void)tracker_digest_refresh(tracker);
			saturating_increment_u64(
				&manager->collision_count);
			collision = true;
		}
		(void)append_receipt_record(
			manager, packet, receipt_digest,
			now_ms, ret, true, false, collision);
		outcome_fill(
			tracker, NULL, true, false,
			false, collision, outcome);
		goto out;
	}
	ret = ack_allocate(
		manager, tracker, packet->peer_id,
		false, &ack);
	if (ret != 0) {
		saturating_increment_u64(
			&manager->rejected_count);
		(void)append_receipt_record(
			manager, packet, receipt_digest,
			now_ms, ret, true, false, false);
		outcome_fill(
			tracker, NULL, true, false,
			false, false, outcome);
		goto out;
	}
	ret = apply_receipt(
		manager, tracker, ack, packet,
		receipt_digest, now_ms, &duplicate);
	if (ret == -EKEYREJECTED) {
		tracker_set_terminal(
			manager, tracker,
			PQCP_FLEET_RECEIPT_TRACKER_CONFLICT,
			ret, packet->reason, now_ms);
		(void)tracker_digest_refresh(tracker);
		collision = true;
		saturating_increment_u64(
			&manager->collision_count);
	}
	if (ret == 0) {
		saturating_increment_u64(
			&manager->accepted_count);
	} else {
		saturating_increment_u64(
			&manager->rejected_count);
		saturating_increment_u64(
			&peer->rejected_count);
	}
	(void)append_receipt_record(
		manager, packet, receipt_digest,
		now_ms, ret, true, false, collision);
	outcome_fill(
		tracker, ack, true, duplicate,
		false, collision, outcome);
	saturating_increment_u64(&manager->generation);
out:
	(void)k_mutex_unlock(&manager->lock);
	pqcp_runtime_secure_zero(
		receipt_digest, sizeof(receipt_digest));
	return ret;
}

int pqcp_fleet_receipt_cancel(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle,
	int result,
	uint32_t reason,
	uint64_t now_ms)
{
	struct pqcp_fleet_receipt_tracker *tracker;
	int index;
	int ret;

	if (manager_validate(manager) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U ||
	    result > 0 || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = tracker_index_by_handle(manager, handle);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	tracker = &manager->trackers[index];
	if (pqcp_fleet_receipt_tracker_terminal(
		    tracker->state)) {
		(void)k_mutex_unlock(&manager->lock);
		return -EALREADY;
	}
	tracker_set_terminal(
		manager, tracker,
		PQCP_FLEET_RECEIPT_TRACKER_CANCELLED,
		result == 0 ? -ECANCELED : result,
		reason, now_ms);
	ret = tracker_digest_refresh(tracker);
	if (ret == 0) {
		saturating_increment_u64(
			&manager->generation);
	}
	(void)k_mutex_unlock(&manager->lock);
	return ret;
}

int pqcp_fleet_receipt_tick(
	struct pqcp_fleet_receipt_manager *manager,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;
	int ret;

	if (manager_validate(manager) != 0 ||
	    now_ms == 0U || changed_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < manager->tracker_capacity; ++index) {
		struct pqcp_fleet_receipt_tracker *tracker =
			&manager->trackers[index];

		if (!tracker->occupied ||
		    pqcp_fleet_receipt_tracker_terminal(
			    tracker->state)) {
			continue;
		}
		if (tracker_structure_validate(tracker) != 0) {
			tracker_set_terminal(
				manager, tracker,
				PQCP_FLEET_RECEIPT_TRACKER_CONFLICT,
				-EBADMSG, 0U, now_ms);
			(void)tracker_digest_refresh(tracker);
			if (changed != UINT32_MAX) {
				changed++;
			}
			continue;
		}
		if (now_ms >= tracker->expires_at_ms ||
		    tracker->policy_epoch <
			    manager->minimum_policy_epoch ||
		    tracker->revocation_epoch <
			    manager->minimum_revocation_epoch) {
			tracker_set_terminal(
				manager, tracker,
				PQCP_FLEET_RECEIPT_TRACKER_EXPIRED,
				-ETIMEDOUT, 0U, now_ms);
			(void)tracker_digest_refresh(tracker);
			if (changed != UINT32_MAX) {
				changed++;
			}
		}
	}
	if (changed != 0U) {
		saturating_increment_u64(
			&manager->generation);
	}
	*changed_count = changed;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_receipt_get_tracker(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle,
	struct pqcp_fleet_receipt_tracker *tracker)
{
	int index;
	int ret;

	if (manager_validate(manager) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U ||
	    tracker == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = tracker_index_by_handle(manager, handle);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	*tracker = manager->trackers[index];
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_receipt_get_ack(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle,
	const char *peer_id,
	struct pqcp_fleet_receipt_ack *ack)
{
	int tracker_position;
	int ack_position;
	int ret;

	if (manager_validate(manager) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U ||
	    !text_valid(
		    peer_id,
		    PQCP_FLEET_RECEIPT_PEER_MAX_CHARS) ||
	    ack == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	tracker_position = tracker_index_by_handle(
		manager, handle);
	if (tracker_position < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	ack_position = ack_index(
		manager, handle.artifact_id,
		handle.generation, peer_id);
	if (ack_position < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ENOENT;
	}
	*ack = manager->acks[ack_position];
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

static size_t remove_tracker_acks(
	struct pqcp_fleet_receipt_manager *manager,
	uint64_t artifact_id,
	uint32_t generation)
{
	size_t removed = 0U;

	for (size_t index = 0U;
	     index < manager->ack_capacity; ++index) {
		struct pqcp_fleet_receipt_ack *ack =
			&manager->acks[index];

		if (ack->occupied &&
		    ack->artifact_id == artifact_id &&
		    ack->tracker_generation == generation) {
			pqcp_runtime_secure_zero(
				ack, sizeof(*ack));
			removed++;
		}
	}
	return removed;
}

int pqcp_fleet_receipt_remove_tracker(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_tracker_handle handle)
{
	struct pqcp_fleet_receipt_tracker *tracker;
	size_t removed_acks;
	int index;
	int ret;

	if (manager_validate(manager) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = tracker_index_by_handle(manager, handle);
	if (index < 0) {
		(void)k_mutex_unlock(&manager->lock);
		return -ESTALE;
	}
	tracker = &manager->trackers[index];
	if (!pqcp_fleet_receipt_tracker_terminal(
		    tracker->state)) {
		(void)k_mutex_unlock(&manager->lock);
		return -EBUSY;
	}
	removed_acks = remove_tracker_acks(
		manager, tracker->artifact_id,
		tracker->generation);
	if (removed_acks > manager->ack_count ||
	    manager->tracker_count == 0U) {
		(void)k_mutex_unlock(&manager->lock);
		return -EBADMSG;
	}
	manager->ack_count -= removed_acks;
	manager->tracker_count--;
	pqcp_runtime_secure_zero(tracker, sizeof(*tracker));
	saturating_increment_u64(&manager->generation);
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

int pqcp_fleet_receipt_prune_records(
	struct pqcp_fleet_receipt_manager *manager,
	size_t maximum_to_prune,
	uint64_t received_before_ms,
	size_t *pruned_count)
{
	size_t pruned = 0U;
	int ret;

	if (manager_validate(manager) != 0 ||
	    maximum_to_prune == 0U ||
	    received_before_ms == 0U ||
	    pruned_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	while (pruned < maximum_to_prune &&
	       manager->receipt_count != 0U) {
		struct pqcp_fleet_receipt_record *record =
			&manager->receipts[
				manager->receipt_head];

		if (!record->occupied ||
		    record->received_at_ms >=
			    received_before_ms) {
			break;
		}
		pqcp_runtime_secure_zero(
			record, sizeof(*record));
		manager->receipt_head =
			(manager->receipt_head + 1U) %
			manager->receipt_capacity;
		manager->receipt_count--;
		pruned++;
	}
	*pruned_count = pruned;
	if (pruned != 0U) {
		saturating_increment_u64(
			&manager->generation);
	}
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

static int aggregate_step(
	uint8_t state[PQCP_FLEET_DIGEST_BYTES],
	uint32_t type,
	size_t index,
	const uint8_t *data,
	size_t data_length)
{
	uint8_t encoded[RECEIPT_HASH_INPUT_MAX];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	struct receipt_encoder encoder;
	int ret;

	memset(encoded, 0, sizeof(encoded));
	memset(digest, 0, sizeof(digest));
	encoder_init(&encoder, encoded, sizeof(encoded));
	encoder_append(&encoder, state,
		       PQCP_FLEET_DIGEST_BYTES);
	encoder_u32(&encoder, type);
	encoder_size(&encoder, index);
	encoder_append(&encoder, data, data_length);
	if (encoder.error != 0) {
		ret = encoder.error;
		goto out;
	}
	ret = pqcp_fleet_sha256(
		encoded, encoder.offset, digest);
	if (ret == 0) {
		memcpy(state, digest,
		       PQCP_FLEET_DIGEST_BYTES);
	}
out:
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int aggregate_digest_compute(
	const struct pqcp_fleet_receipt_manager *manager,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t state[PQCP_FLEET_DIGEST_BYTES];
	uint8_t seed[RECEIPT_HASH_INPUT_MAX];
	struct receipt_encoder encoder;
	int ret;

	memset(state, 0, sizeof(state));
	memset(seed, 0, sizeof(seed));
	encoder_init(&encoder, seed, sizeof(seed));
	encoder_append(
		&encoder, RECEIPT_AGGREGATE_DOMAIN,
		sizeof(RECEIPT_AGGREGATE_DOMAIN) - 1U);
	encoder_u64(&encoder, manager->generation);
	encoder_size(&encoder, manager->peer_capacity);
	encoder_size(&encoder, manager->tracker_capacity);
	encoder_size(&encoder, manager->ack_capacity);
	encoder_size(&encoder, manager->receipt_capacity);
	if (encoder.error != 0) {
		ret = encoder.error;
		goto out;
	}
	ret = pqcp_fleet_sha256(
		seed, encoder.offset, state);
	if (ret != 0) {
		goto out;
	}
	for (size_t index = 0U;
	     index < manager->peer_capacity; ++index) {
		const struct pqcp_fleet_receipt_peer *peer =
			&manager->peers[index];
		uint8_t data[RECEIPT_HASH_INPUT_MAX];
		struct receipt_encoder item;

		if (!peer->occupied) {
			continue;
		}
		memset(data, 0, sizeof(data));
		encoder_init(&item, data, sizeof(data));
		encoder_append(
			&item, peer->peer_id,
			sizeof(peer->peer_id));
		encoder_append(
			&item, peer->key_id,
			sizeof(peer->key_id));
		encoder_append(
			&item, peer->key_digest,
			sizeof(peer->key_digest));
		encoder_u64(&item, peer->key_epoch);
		encoder_u64(&item, peer->replay_epoch);
		encoder_u64(
			&item, peer->replay_high_sequence);
		encoder_append(
			&item, peer->replay_bitmap,
			sizeof(peer->replay_bitmap));
		encoder_u8(&item, peer->enabled ? 1U : 0U);
		if (item.error != 0) {
			pqcp_runtime_secure_zero(
				data, sizeof(data));
			ret = item.error;
			goto out;
		}
		ret = aggregate_step(
			state, 1U, index, data, item.offset);
		pqcp_runtime_secure_zero(data, sizeof(data));
		if (ret != 0) {
			goto out;
		}
	}
	for (size_t index = 0U;
	     index < manager->tracker_capacity; ++index) {
		const struct pqcp_fleet_receipt_tracker *tracker =
			&manager->trackers[index];

		if (!tracker->occupied) {
			continue;
		}
		ret = aggregate_step(
			state, 2U, index,
			tracker->tracker_digest,
			sizeof(tracker->tracker_digest));
		if (ret != 0) {
			goto out;
		}
	}
	for (size_t index = 0U;
	     index < manager->ack_capacity; ++index) {
		const struct pqcp_fleet_receipt_ack *ack =
			&manager->acks[index];
		uint8_t data[RECEIPT_HASH_INPUT_MAX];
		struct receipt_encoder item;

		if (!ack->occupied) {
			continue;
		}
		memset(data, 0, sizeof(data));
		encoder_init(&item, data, sizeof(data));
		encoder_u32(
			&item, ack->tracker_generation);
		encoder_u64(&item, ack->artifact_id);
		encoder_append(
			&item, ack->peer_id,
			sizeof(ack->peer_id));
		encoder_u64(
			&item, ack->last_receipt_id);
		encoder_u64(&item, ack->last_sequence);
		encoder_u64(
			&item, ack->acknowledged_bytes);
		encoder_u32(&item, ack->next_chunk);
		encoder_u32(
			&item, ack->accepted_receipts);
		encoder_u32(
			&item, ack->rejected_receipts);
		encoder_u32(
			&item, (uint32_t)ack->terminal_status);
		encoder_i32(&item, ack->result);
		encoder_u32(&item, ack->reason);
		encoder_append(
			&item, ack->last_chunk_digest,
			sizeof(ack->last_chunk_digest));
		encoder_append(
			&item, ack->last_receipt_digest,
			sizeof(ack->last_receipt_digest));
		encoder_u8(&item, ack->required ? 1U : 0U);
		encoder_u8(
			&item,
			ack->final_acknowledged ? 1U : 0U);
		if (item.error != 0) {
			pqcp_runtime_secure_zero(
				data, sizeof(data));
			ret = item.error;
			goto out;
		}
		ret = aggregate_step(
			state, 3U, index, data, item.offset);
		pqcp_runtime_secure_zero(data, sizeof(data));
		if (ret != 0) {
			goto out;
		}
	}
	for (size_t logical = 0U;
	     logical < manager->receipt_count; ++logical) {
		size_t index =
			(manager->receipt_head + logical) %
			manager->receipt_capacity;
		const struct pqcp_fleet_receipt_record *record =
			&manager->receipts[index];

		if (!record->occupied) {
			continue;
		}
		ret = aggregate_step(
			state, 4U, index,
			record->receipt_digest,
			sizeof(record->receipt_digest));
		if (ret != 0) {
			goto out;
		}
	}
	memcpy(digest, state, sizeof(state));
	ret = 0;
out:
	pqcp_runtime_secure_zero(state, sizeof(state));
	pqcp_runtime_secure_zero(seed, sizeof(seed));
	return ret;
}

static int snapshot_digest_compute(
	const struct pqcp_fleet_receipt_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[RECEIPT_SNAPSHOT_ENCODED_MAX];
	struct receipt_encoder encoder;
	int ret;

	memset(encoded, 0, sizeof(encoded));
	encoder_init(&encoder, encoded, sizeof(encoded));
	encoder_append(
		&encoder, RECEIPT_SNAPSHOT_DOMAIN,
		sizeof(RECEIPT_SNAPSHOT_DOMAIN) - 1U);
	encoder_u32(&encoder, snapshot->schema_version);
	encoder_u64(&encoder, snapshot->generation);
	encoder_u64(
		&encoder, snapshot->minimum_policy_epoch);
	encoder_u64(
		&encoder, snapshot->minimum_revocation_epoch);
	encoder_u64(
		&encoder, snapshot->authenticated_count);
	encoder_u64(
		&encoder,
		snapshot->authentication_failure_count);
	encoder_u64(&encoder, snapshot->replay_count);
	encoder_u64(&encoder, snapshot->collision_count);
	encoder_u64(
		&encoder, snapshot->binding_failure_count);
	encoder_u64(&encoder, snapshot->accepted_count);
	encoder_u64(&encoder, snapshot->rejected_count);
	encoder_u64(&encoder, snapshot->expired_count);
	encoder_u64(&encoder, snapshot->completed_count);
	encoder_u64(&encoder, snapshot->failed_count);
	encoder_u64(
		&encoder, snapshot->dropped_receipt_records);
	encoder_size(&encoder, snapshot->peer_capacity);
	encoder_size(&encoder, snapshot->peer_count);
	encoder_size(&encoder, snapshot->tracker_capacity);
	encoder_size(&encoder, snapshot->tracker_count);
	encoder_size(&encoder, snapshot->ack_capacity);
	encoder_size(&encoder, snapshot->ack_count);
	encoder_size(&encoder, snapshot->receipt_capacity);
	encoder_size(&encoder, snapshot->receipt_count);
	encoder_size(&encoder, snapshot->pending_trackers);
	encoder_size(&encoder, snapshot->quorum_trackers);
	encoder_size(&encoder, snapshot->terminal_trackers);
	encoder_append(
		&encoder, snapshot->aggregate_digest,
		sizeof(snapshot->aggregate_digest));
	if (encoder.error != 0) {
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return encoder.error;
	}
	ret = pqcp_fleet_sha256(
		encoded, encoder.offset, digest);
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

int pqcp_fleet_receipt_snapshot(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_snapshot *snapshot)
{
	int ret;

	if (manager_validate(manager) != 0 ||
	    snapshot == NULL) {
		return -EINVAL;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	snapshot->schema_version =
		PQCP_FLEET_RECEIPT_SCHEMA_VERSION;
	snapshot->generation = manager->generation;
	snapshot->minimum_policy_epoch =
		manager->minimum_policy_epoch;
	snapshot->minimum_revocation_epoch =
		manager->minimum_revocation_epoch;
	snapshot->authenticated_count =
		manager->authenticated_count;
	snapshot->authentication_failure_count =
		manager->authentication_failure_count;
	snapshot->replay_count = manager->replay_count;
	snapshot->collision_count =
		manager->collision_count;
	snapshot->binding_failure_count =
		manager->binding_failure_count;
	snapshot->accepted_count =
		manager->accepted_count;
	snapshot->rejected_count =
		manager->rejected_count;
	snapshot->expired_count =
		manager->expired_count;
	snapshot->completed_count =
		manager->completed_count;
	snapshot->failed_count = manager->failed_count;
	snapshot->dropped_receipt_records =
		manager->dropped_receipt_records;
	snapshot->peer_capacity = manager->peer_capacity;
	snapshot->peer_count = manager->peer_count;
	snapshot->tracker_capacity =
		manager->tracker_capacity;
	snapshot->tracker_count = manager->tracker_count;
	snapshot->ack_capacity = manager->ack_capacity;
	snapshot->ack_count = manager->ack_count;
	snapshot->receipt_capacity =
		manager->receipt_capacity;
	snapshot->receipt_count = manager->receipt_count;
	for (size_t index = 0U;
	     index < manager->tracker_capacity; ++index) {
		const struct pqcp_fleet_receipt_tracker *tracker =
			&manager->trackers[index];

		if (!tracker->occupied) {
			continue;
		}
		if (tracker->state ==
		    PQCP_FLEET_RECEIPT_TRACKER_PENDING) {
			snapshot->pending_trackers++;
		} else if (tracker->state ==
			   PQCP_FLEET_RECEIPT_TRACKER_QUORUM) {
			snapshot->quorum_trackers++;
		} else if (
			pqcp_fleet_receipt_tracker_terminal(
				tracker->state)) {
			snapshot->terminal_trackers++;
		}
	}
	ret = aggregate_digest_compute(
		manager, snapshot->aggregate_digest);
	if (ret == 0) {
		ret = snapshot_digest_compute(
			snapshot, snapshot->snapshot_digest);
	}
	(void)k_mutex_unlock(&manager->lock);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			snapshot, sizeof(*snapshot));
	}
	return ret;
}

static void audit_mark(
	struct pqcp_fleet_receipt_audit *audit,
	uint32_t flag,
	size_t index,
	uint64_t artifact_id)
{
	audit->violation_mask |= flag;
	if (audit->first_bad_index == SIZE_MAX) {
		audit->first_bad_index = index;
		audit->first_bad_artifact_id = artifact_id;
	}
}

static bool ack_structure_valid(
	const struct pqcp_fleet_receipt_manager *manager,
	const struct pqcp_fleet_receipt_ack *ack)
{
	int tracker_position;
	const struct pqcp_fleet_receipt_tracker *tracker;

	if (!ack->occupied ||
	    ack->schema_version !=
		    PQCP_FLEET_RECEIPT_SCHEMA_VERSION ||
	    ack->tracker_generation == 0U ||
	    ack->artifact_id == 0U ||
	    !text_valid(ack->peer_id, sizeof(ack->peer_id)) ||
	    (ack->next_chunk == 0U &&
	     ack->acknowledged_bytes != 0U) ||
	    (ack->final_acknowledged &&
	     ack->terminal_status ==
		     PQCP_FLEET_RECEIPT_STATUS_NONE)) {
		return false;
	}
	tracker_position = tracker_index_by_artifact(
		manager, ack->artifact_id);
	if (tracker_position < 0) {
		return false;
	}
	tracker = &manager->trackers[tracker_position];
	if (tracker->generation !=
		    ack->tracker_generation ||
	    ack->next_chunk > tracker->chunk_count ||
	    ack->acknowledged_bytes >
		    tracker->artifact_size ||
	    (ack->final_acknowledged &&
	     (ack->next_chunk != tracker->chunk_count ||
	      ack->acknowledged_bytes !=
		      tracker->artifact_size))) {
		return false;
	}
	return true;
}

int pqcp_fleet_receipt_audit(
	struct pqcp_fleet_receipt_manager *manager,
	struct pqcp_fleet_receipt_audit *audit)
{
	size_t recomputed_peers = 0U;
	size_t recomputed_trackers = 0U;
	size_t recomputed_acks = 0U;
	size_t recomputed_receipts = 0U;
	int ret;

	if (manager == NULL || audit == NULL) {
		return -EINVAL;
	}
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_FLEET_RECEIPT_SCHEMA_VERSION;
	audit->first_bad_index = SIZE_MAX;
	if (manager_validate(manager) != 0) {
		audit_mark(
			audit,
			PQCP_FLEET_RECEIPT_AUDIT_MANAGER,
			0U, 0U);
		audit->consistent = false;
		return 0;
	}
	ret = k_mutex_lock(&manager->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < manager->peer_capacity; ++index) {
		const struct pqcp_fleet_receipt_peer *peer =
			&manager->peers[index];

		audit->inspected_peers++;
		if (!peer->occupied) {
			if (!bytes_zero(
				    (const uint8_t *)peer,
				    sizeof(*peer))) {
				audit_mark(
					audit,
					PQCP_FLEET_RECEIPT_AUDIT_STORAGE,
					index, 0U);
			}
			continue;
		}
		recomputed_peers++;
		if (peer_structure_validate(peer) != 0) {
			audit_mark(
				audit,
				PQCP_FLEET_RECEIPT_AUDIT_PEER |
				PQCP_FLEET_RECEIPT_AUDIT_KEY |
				PQCP_FLEET_RECEIPT_AUDIT_REPLAY,
				index, 0U);
		}
		for (size_t other = index + 1U;
		     other < manager->peer_capacity; ++other) {
			if (manager->peers[other].occupied &&
			    strcmp(peer->peer_id,
				   manager->peers[other].peer_id) ==
				    0) {
				audit_mark(
					audit,
					PQCP_FLEET_RECEIPT_AUDIT_DUPLICATE,
					index, 0U);
			}
		}
	}
	for (size_t index = 0U;
	     index < manager->tracker_capacity; ++index) {
		const struct pqcp_fleet_receipt_tracker *tracker =
			&manager->trackers[index];
		uint32_t ack_count = 0U;
		uint32_t required_count = 0U;
		uint32_t required_ack_count = 0U;

		audit->inspected_trackers++;
		if (!tracker->occupied) {
			if (!bytes_zero(
				    (const uint8_t *)tracker,
				    sizeof(*tracker))) {
				audit_mark(
					audit,
					PQCP_FLEET_RECEIPT_AUDIT_STORAGE,
					index, 0U);
			}
			continue;
		}
		recomputed_trackers++;
		if (tracker_structure_validate(tracker) != 0) {
			audit_mark(
				audit,
				PQCP_FLEET_RECEIPT_AUDIT_TRACKER |
				PQCP_FLEET_RECEIPT_AUDIT_BINDING |
				PQCP_FLEET_RECEIPT_AUDIT_QUORUM |
				PQCP_FLEET_RECEIPT_AUDIT_DIGEST,
				index, tracker->artifact_id);
		}
		for (size_t ack_position = 0U;
		     ack_position < manager->ack_capacity;
		     ++ack_position) {
			const struct pqcp_fleet_receipt_ack *ack =
				&manager->acks[ack_position];

			if (!ack->occupied ||
			    ack->artifact_id !=
				    tracker->artifact_id ||
			    ack->tracker_generation !=
				    tracker->generation) {
				continue;
			}
			if (ack->required) {
				required_count++;
			}
			if (ack->final_acknowledged) {
				ack_count++;
				if (ack->required) {
					required_ack_count++;
				}
			}
		}
		audit->recomputed_tracker_ack_count +=
			ack_count;
		audit->recomputed_required_ack_count +=
			required_ack_count;
		if (ack_count != tracker->acknowledged_count ||
		    required_count != tracker->required_count ||
		    required_ack_count !=
			    tracker->required_ack_count) {
			audit_mark(
				audit,
				PQCP_FLEET_RECEIPT_AUDIT_QUORUM |
				PQCP_FLEET_RECEIPT_AUDIT_COUNTER,
				index, tracker->artifact_id);
		}
		for (size_t other = index + 1U;
		     other < manager->tracker_capacity; ++other) {
			const struct pqcp_fleet_receipt_tracker
				*candidate =
				&manager->trackers[other];

			if (!candidate->occupied) {
				continue;
			}
			if (candidate->artifact_id ==
			    tracker->artifact_id) {
				audit->duplicate_artifact_id =
					tracker->artifact_id;
				audit_mark(
					audit,
					PQCP_FLEET_RECEIPT_AUDIT_DUPLICATE,
					index, tracker->artifact_id);
			}
			if (candidate->message_id ==
				    tracker->message_id &&
			    candidate->correlation_id ==
				    tracker->correlation_id) {
				audit_mark(
					audit,
					PQCP_FLEET_RECEIPT_AUDIT_DUPLICATE,
					index, tracker->artifact_id);
			}
		}
	}
	for (size_t index = 0U;
	     index < manager->ack_capacity; ++index) {
		const struct pqcp_fleet_receipt_ack *ack =
			&manager->acks[index];

		audit->inspected_acks++;
		if (!ack->occupied) {
			if (!bytes_zero(
				    (const uint8_t *)ack,
				    sizeof(*ack))) {
				audit_mark(
					audit,
					PQCP_FLEET_RECEIPT_AUDIT_STORAGE,
					index, 0U);
			}
			continue;
		}
		recomputed_acks++;
		if (!ack_structure_valid(manager, ack)) {
			audit_mark(
				audit,
				PQCP_FLEET_RECEIPT_AUDIT_ACK |
				PQCP_FLEET_RECEIPT_AUDIT_PROGRESS,
				index, ack->artifact_id);
		}
		for (size_t other = index + 1U;
		     other < manager->ack_capacity; ++other) {
			const struct pqcp_fleet_receipt_ack
				*candidate =
				&manager->acks[other];

			if (candidate->occupied &&
			    candidate->artifact_id ==
				    ack->artifact_id &&
			    candidate->tracker_generation ==
				    ack->tracker_generation &&
			    strcmp(candidate->peer_id,
				   ack->peer_id) == 0) {
				audit_mark(
					audit,
					PQCP_FLEET_RECEIPT_AUDIT_DUPLICATE,
					index, ack->artifact_id);
			}
		}
	}
	for (size_t logical = 0U;
	     logical < manager->receipt_count; ++logical) {
		size_t index =
			(manager->receipt_head + logical) %
			manager->receipt_capacity;
		const struct pqcp_fleet_receipt_record *record =
			&manager->receipts[index];

		audit->inspected_receipts++;
		if (!record->occupied ||
		    record->schema_version !=
			    PQCP_FLEET_RECEIPT_SCHEMA_VERSION ||
		    record->received_order == 0U ||
		    record->received_at_ms == 0U ||
		    record->receipt_id == 0U ||
		    record->receipt_epoch == 0U ||
		    record->sequence == 0U ||
		    record->artifact_id == 0U ||
		    !text_valid(
			    record->peer_id,
			    sizeof(record->peer_id)) ||
		    !kind_valid(record->kind) ||
		    !status_valid(record->status) ||
		    bytes_zero(
			    record->receipt_digest,
			    sizeof(record->receipt_digest))) {
			audit_mark(
				audit,
				PQCP_FLEET_RECEIPT_AUDIT_RECEIPT,
				index, record->artifact_id);
		} else {
			recomputed_receipts++;
		}
		for (size_t later = logical + 1U;
		     later < manager->receipt_count; ++later) {
			size_t other =
				(manager->receipt_head + later) %
				manager->receipt_capacity;
			const struct pqcp_fleet_receipt_record
				*candidate =
				&manager->receipts[other];

			if (candidate->occupied &&
			    candidate->receipt_id ==
				    record->receipt_id &&
			    strcmp(candidate->peer_id,
				   record->peer_id) == 0 &&
			    !digest_equal(
				    candidate->receipt_digest,
				    record->receipt_digest)) {
				audit->duplicate_receipt_id =
					record->receipt_id;
				audit_mark(
					audit,
					PQCP_FLEET_RECEIPT_AUDIT_DUPLICATE,
					index, record->artifact_id);
			}
		}
	}
	if (recomputed_peers != manager->peer_count ||
	    recomputed_trackers != manager->tracker_count ||
	    recomputed_acks != manager->ack_count ||
	    recomputed_receipts != manager->receipt_count) {
		audit_mark(
			audit,
			PQCP_FLEET_RECEIPT_AUDIT_COUNTER,
			0U, 0U);
	}
	ret = aggregate_digest_compute(
		manager, audit->aggregate_digest);
	if (ret != 0) {
		audit_mark(
			audit,
			PQCP_FLEET_RECEIPT_AUDIT_DIGEST,
			0U, 0U);
	}
	audit->consistent =
		audit->violation_mask == 0U;
	(void)k_mutex_unlock(&manager->lock);
	return 0;
}

const char *pqcp_fleet_receipt_kind_str(
	enum pqcp_fleet_receipt_kind kind)
{
	switch (kind) {
	case PQCP_FLEET_RECEIPT_NONE:
		return "none";
	case PQCP_FLEET_RECEIPT_CHUNK:
		return "chunk";
	case PQCP_FLEET_RECEIPT_ARTIFACT:
		return "artifact";
	case PQCP_FLEET_RECEIPT_FINAL:
		return "final";
	case PQCP_FLEET_RECEIPT_REJECTION:
		return "rejection";
	default:
		return "invalid";
	}
}

const char *pqcp_fleet_receipt_status_str(
	enum pqcp_fleet_receipt_status status)
{
	switch (status) {
	case PQCP_FLEET_RECEIPT_STATUS_NONE:
		return "none";
	case PQCP_FLEET_RECEIPT_STATUS_ACCEPTED:
		return "accepted";
	case PQCP_FLEET_RECEIPT_STATUS_STORED:
		return "stored";
	case PQCP_FLEET_RECEIPT_STATUS_APPLIED:
		return "applied";
	case PQCP_FLEET_RECEIPT_STATUS_REJECTED:
		return "rejected";
	case PQCP_FLEET_RECEIPT_STATUS_FAILED:
		return "failed";
	default:
		return "invalid";
	}
}

const char *pqcp_fleet_receipt_tracker_state_str(
	enum pqcp_fleet_receipt_tracker_state state)
{
	switch (state) {
	case PQCP_FLEET_RECEIPT_TRACKER_EMPTY:
		return "empty";
	case PQCP_FLEET_RECEIPT_TRACKER_PENDING:
		return "pending";
	case PQCP_FLEET_RECEIPT_TRACKER_QUORUM:
		return "quorum";
	case PQCP_FLEET_RECEIPT_TRACKER_COMPLETE:
		return "complete";
	case PQCP_FLEET_RECEIPT_TRACKER_FAILED:
		return "failed";
	case PQCP_FLEET_RECEIPT_TRACKER_CANCELLED:
		return "cancelled";
	case PQCP_FLEET_RECEIPT_TRACKER_EXPIRED:
		return "expired";
	case PQCP_FLEET_RECEIPT_TRACKER_CONFLICT:
		return "conflict";
	default:
		return "invalid";
	}
}
