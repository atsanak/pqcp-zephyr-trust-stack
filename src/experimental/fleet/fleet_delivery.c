/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free bounded fleet artifact delivery scheduler.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_delivery.h>
#include <pqcp_zephyr/runtime.h>

#include "fleet_internal.h"

#define DELIVERY_RECORD_DOMAIN "PQCP-FLEET-DELIVERY-RECORD-V1"
#define DELIVERY_PROGRESS_DOMAIN "PQCP-FLEET-DELIVERY-PROGRESS-V1"
#define DELIVERY_TOKEN_DOMAIN "PQCP-FLEET-DELIVERY-TOKEN-V1"
#define DELIVERY_JITTER_DOMAIN "PQCP-FLEET-DELIVERY-JITTER-V1"
#define DELIVERY_AGGREGATE_DOMAIN "PQCP-FLEET-DELIVERY-AGGREGATE-V1"
#define DELIVERY_SNAPSHOT_DOMAIN "PQCP-FLEET-DELIVERY-SNAPSHOT-V1"
#define DELIVERY_RECORD_ENCODED_MAX 512U
#define DELIVERY_SNAPSHOT_ENCODED_MAX 384U
#define DELIVERY_SMALL_HASH_INPUT_MAX 160U

struct delivery_encoder {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
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

static bool digest_equal(
	const uint8_t left[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t difference = 0U;

	if (left == NULL || right == NULL) {
		return false;
	}
	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static void saturating_increment_u64(uint64_t *value)
{
	if (value != NULL && *value != UINT64_MAX) {
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

static bool multiply_u64(
	uint64_t left,
	uint64_t right,
	uint64_t *result)
{
	if (result == NULL ||
	    (left != 0U && right > UINT64_MAX / left)) {
		return false;
	}
	*result = left * right;
	return true;
}

static bool size_array_valid(size_t count, size_t element_size)
{
	return element_size == 0U ||
	       count <= SIZE_MAX / element_size;
}

static uint64_t minimum_u64(uint64_t left, uint64_t right)
{
	return left < right ? left : right;
}

static void encoder_init(
	struct delivery_encoder *encoder,
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
	struct delivery_encoder *encoder,
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
	struct delivery_encoder *encoder,
	uint8_t value)
{
	encoder_append(encoder, &value, sizeof(value));
}

static void encoder_u16(
	struct delivery_encoder *encoder,
	uint16_t value)
{
	uint8_t encoded[2];

	encoded[0] = (uint8_t)(value >> 8U);
	encoded[1] = (uint8_t)value;
	encoder_append(encoder, encoded, sizeof(encoded));
}

static void encoder_u32(
	struct delivery_encoder *encoder,
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
	struct delivery_encoder *encoder,
	int32_t value)
{
	encoder_u32(encoder, (uint32_t)value);
}

static void encoder_u64(
	struct delivery_encoder *encoder,
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
	struct delivery_encoder *encoder,
	size_t value)
{
	encoder_u64(encoder, (uint64_t)value);
}

static uint64_t read_u64_be(const uint8_t input[8])
{
	uint64_t value = 0U;

	for (size_t index = 0U; index < 8U; ++index) {
		value = (value << 8U) | input[index];
	}
	return value;
}

static uint32_t known_flags(void)
{
	return PQCP_FLEET_DELIVERY_FLAG_IDEMPOTENT |
	       PQCP_FLEET_DELIVERY_FLAG_REQUIRE_POLICY_EPOCH |
	       PQCP_FLEET_DELIVERY_FLAG_REQUIRE_REVOCATION_EPOCH |
	       PQCP_FLEET_DELIVERY_FLAG_CANCEL_DEPENDENTS |
	       PQCP_FLEET_DELIVERY_FLAG_RETAIN_PROGRESS_ON_RETRY |
	       PQCP_FLEET_DELIVERY_FLAG_REQUIRE_FINAL_DIGEST |
	       PQCP_FLEET_DELIVERY_FLAG_ALLOW_ZERO_LENGTH |
	       PQCP_FLEET_DELIVERY_FLAG_HIGH_INTEGRITY;
}

static bool state_valid(enum pqcp_fleet_delivery_state state)
{
	return state >= PQCP_FLEET_DELIVERY_EMPTY &&
	       state < PQCP_FLEET_DELIVERY_STATE_COUNT;
}

static bool reason_valid(
	enum pqcp_fleet_delivery_terminal_reason reason)
{
	return reason >= PQCP_FLEET_DELIVERY_REASON_NONE &&
	       reason < PQCP_FLEET_DELIVERY_REASON_COUNT;
}

bool pqcp_fleet_delivery_state_terminal(
	enum pqcp_fleet_delivery_state state)
{
	switch (state) {
	case PQCP_FLEET_DELIVERY_DELIVERED:
	case PQCP_FLEET_DELIVERY_FAILED:
	case PQCP_FLEET_DELIVERY_CANCELLED:
	case PQCP_FLEET_DELIVERY_EXPIRED:
	case PQCP_FLEET_DELIVERY_DEPENDENCY_FAILED:
	case PQCP_FLEET_DELIVERY_CONFLICT:
		return true;
	default:
		return false;
	}
}

static int record_digest_compute(
	const struct pqcp_fleet_delivery_record *record,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[DELIVERY_RECORD_ENCODED_MAX];
	struct delivery_encoder encoder;
	int ret;

	if (record == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(encoded, 0, sizeof(encoded));
	encoder_init(&encoder, encoded, sizeof(encoded));
	encoder_append(
		&encoder, DELIVERY_RECORD_DOMAIN,
		sizeof(DELIVERY_RECORD_DOMAIN) - 1U);
	encoder_u32(&encoder, record->schema_version);
	encoder_u32(&encoder, record->generation);
	encoder_u64(&encoder, record->enqueue_sequence);
	encoder_u64(&encoder, record->artifact_id);
	encoder_u64(&encoder, record->message_id);
	encoder_u64(&encoder, record->correlation_id);
	encoder_u64(
		&encoder, record->dependency_artifact_id);
	encoder_u64(&encoder, record->policy_epoch);
	encoder_u64(&encoder, record->revocation_epoch);
	encoder_u64(&encoder, record->created_at_ms);
	encoder_u64(&encoder, record->not_before_ms);
	encoder_u64(&encoder, record->expires_at_ms);
	encoder_u64(&encoder, record->lease_duration_ms);
	encoder_u64(&encoder, record->base_backoff_ms);
	encoder_u64(&encoder, record->maximum_backoff_ms);
	encoder_u64(&encoder, record->next_attempt_ms);
	encoder_u64(&encoder, record->lease_acquired_at_ms);
	encoder_u64(&encoder, record->lease_expires_at_ms);
	encoder_u64(&encoder, record->last_progress_at_ms);
	encoder_u64(&encoder, record->terminal_at_ms);
	encoder_u64(&encoder, record->artifact_size);
	encoder_u64(&encoder, record->committed_bytes);
	encoder_u64(&encoder, record->worker_id);
	encoder_u64(&encoder, record->lease_token);
	encoder_u32(&encoder, record->chunk_size);
	encoder_u32(&encoder, record->chunk_count);
	encoder_u32(&encoder, record->next_chunk);
	encoder_u32(&encoder, record->attempts);
	encoder_u32(&encoder, record->maximum_attempts);
	encoder_u32(&encoder, record->jitter_basis_points);
	encoder_u16(&encoder, record->priority);
	encoder_u32(&encoder, record->flags);
	encoder_u32(&encoder, (uint32_t)record->state);
	encoder_u32(
		&encoder, (uint32_t)record->terminal_reason);
	encoder_i32(&encoder, record->last_error);
	encoder_append(
		&encoder, record->idempotency_key,
		sizeof(record->idempotency_key));
	encoder_append(
		&encoder, record->artifact_digest,
		sizeof(record->artifact_digest));
	encoder_append(
		&encoder, record->progress_digest,
		sizeof(record->progress_digest));
	encoder_u8(&encoder, record->occupied ? 1U : 0U);
	if (encoder.error != 0) {
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return encoder.error;
	}
	ret = pqcp_fleet_sha256(
		encoded, encoder.offset, digest);
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static int record_digest_refresh(
	struct pqcp_fleet_delivery_record *record)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (record == NULL) {
		return -EINVAL;
	}
	ret = record_digest_compute(record, digest);
	if (ret == 0) {
		memcpy(record->record_digest, digest,
		       sizeof(record->record_digest));
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int chunk_count_compute(
	uint64_t artifact_size,
	uint32_t chunk_size,
	uint32_t *chunk_count)
{
	uint64_t count;

	if (chunk_count == NULL || chunk_size == 0U) {
		return -EINVAL;
	}
	if (artifact_size == 0U) {
		*chunk_count = 0U;
		return 0;
	}
	count = artifact_size / chunk_size;
	if (artifact_size % chunk_size != 0U) {
		if (count == UINT64_MAX) {
			return -EOVERFLOW;
		}
		count++;
	}
	if (count > UINT32_MAX) {
		return -E2BIG;
	}
	*chunk_count = (uint32_t)count;
	return 0;
}

static int record_structure_validate(
	const struct pqcp_fleet_delivery_record *record)
{
	uint32_t expected_chunks;
	uint64_t minimum_bytes;
	uint64_t maximum_bytes;
	int ret;

	if (record == NULL || !record->occupied) {
		return -EINVAL;
	}
	if (record->schema_version !=
		    PQCP_FLEET_DELIVERY_SCHEMA_VERSION ||
	    record->generation == 0U ||
	    record->enqueue_sequence == 0U ||
	    record->artifact_id == 0U ||
	    record->message_id == 0U ||
	    record->correlation_id == 0U ||
	    record->created_at_ms == 0U ||
	    record->not_before_ms < record->created_at_ms ||
	    record->expires_at_ms <= record->created_at_ms ||
	    record->not_before_ms >= record->expires_at_ms ||
	    record->lease_duration_ms == 0U ||
	    record->base_backoff_ms == 0U ||
	    record->maximum_backoff_ms <
		    record->base_backoff_ms ||
	    record->chunk_size == 0U ||
	    record->maximum_attempts == 0U ||
	    record->attempts > record->maximum_attempts ||
	    record->jitter_basis_points >
		    PQCP_FLEET_DELIVERY_MAX_JITTER_BASIS_POINTS ||
	    record->priority >
		    PQCP_FLEET_DELIVERY_PRIORITY_MAX ||
	    (record->flags & ~known_flags()) != 0U ||
	    !state_valid(record->state) ||
	    record->state == PQCP_FLEET_DELIVERY_EMPTY ||
	    !reason_valid(record->terminal_reason) ||
	    bytes_zero(record->artifact_digest,
		       sizeof(record->artifact_digest)) ||
	    bytes_zero(record->idempotency_key,
		       sizeof(record->idempotency_key))) {
		return -EBADMSG;
	}
	if (record->dependency_artifact_id ==
	    record->artifact_id) {
		return -EBADMSG;
	}
	if (record->artifact_size == 0U &&
	    (record->flags &
	     PQCP_FLEET_DELIVERY_FLAG_ALLOW_ZERO_LENGTH) == 0U) {
		return -EBADMSG;
	}
	ret = chunk_count_compute(
		record->artifact_size,
		record->chunk_size,
		&expected_chunks);
	if (ret != 0 ||
	    expected_chunks != record->chunk_count ||
	    record->next_chunk > record->chunk_count ||
	    record->committed_bytes > record->artifact_size) {
		return -EBADMSG;
	}
	if (record->next_chunk == 0U) {
		minimum_bytes = 0U;
	} else if (!multiply_u64(
			   record->next_chunk - 1U,
			   record->chunk_size,
			   &minimum_bytes)) {
		return -EBADMSG;
	}
	if (!multiply_u64(
		    record->next_chunk,
		    record->chunk_size,
		    &maximum_bytes)) {
		maximum_bytes = UINT64_MAX;
	}
	maximum_bytes = minimum_u64(
		maximum_bytes, record->artifact_size);
	if (record->committed_bytes < minimum_bytes ||
	    record->committed_bytes > maximum_bytes) {
		return -EBADMSG;
	}
	if (record->next_chunk == 0U &&
	    !bytes_zero(record->progress_digest,
			sizeof(record->progress_digest))) {
		return -EBADMSG;
	}
	if (record->next_chunk != 0U &&
	    bytes_zero(record->progress_digest,
		       sizeof(record->progress_digest))) {
		return -EBADMSG;
	}
	if (record->state == PQCP_FLEET_DELIVERY_LEASED) {
		if (record->worker_id == 0U ||
		    record->lease_token == 0U ||
		    record->lease_acquired_at_ms == 0U ||
		    record->lease_expires_at_ms <=
			    record->lease_acquired_at_ms ||
		    record->lease_expires_at_ms >
			    record->expires_at_ms ||
		    record->attempts == 0U) {
			return -EBADMSG;
		}
	} else if (record->worker_id != 0U ||
		   record->lease_token != 0U ||
		   record->lease_acquired_at_ms != 0U ||
		   record->lease_expires_at_ms != 0U) {
		return -EBADMSG;
	}
	if (record->state ==
		    PQCP_FLEET_DELIVERY_RETRY_WAIT) {
		if (record->next_attempt_ms == 0U ||
		    record->next_attempt_ms >=
			    record->expires_at_ms) {
			return -EBADMSG;
		}
	} else if (record->next_attempt_ms != 0U) {
		return -EBADMSG;
	}
	if (pqcp_fleet_delivery_state_terminal(
		    record->state)) {
		if (record->terminal_reason ==
			    PQCP_FLEET_DELIVERY_REASON_NONE ||
		    record->terminal_at_ms == 0U) {
			return -EBADMSG;
		}
	} else if (record->terminal_reason !=
			   PQCP_FLEET_DELIVERY_REASON_NONE ||
		   record->terminal_at_ms != 0U) {
		return -EBADMSG;
	}
	if (record->state ==
		    PQCP_FLEET_DELIVERY_DELIVERED &&
	    (record->committed_bytes != record->artifact_size ||
	     record->next_chunk != record->chunk_count ||
	     record->terminal_reason !=
		     PQCP_FLEET_DELIVERY_REASON_COMPLETED)) {
		return -EBADMSG;
	}
	if (record->state ==
		    PQCP_FLEET_DELIVERY_WAITING_DEPENDENCY &&
	    record->dependency_artifact_id ==
		    PQCP_FLEET_DELIVERY_NO_DEPENDENCY) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_fleet_delivery_record_verify(
	const struct pqcp_fleet_delivery_record *record)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	ret = record_structure_validate(record);
	if (ret != 0) {
		return ret;
	}
	ret = record_digest_compute(record, digest);
	if (ret == 0 &&
	    !digest_equal(digest, record->record_digest)) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int scheduler_validate(
	const struct pqcp_fleet_delivery_scheduler *scheduler)
{
	if (scheduler == NULL || !scheduler->initialized ||
	    scheduler->schema_version !=
		    PQCP_FLEET_DELIVERY_SCHEMA_VERSION ||
	    scheduler->records == NULL ||
	    scheduler->capacity == 0U ||
	    !size_array_valid(
		    scheduler->capacity,
		    sizeof(*scheduler->records)) ||
	    scheduler->occupied_count > scheduler->capacity ||
	    scheduler->next_generation == 0U ||
	    scheduler->next_enqueue_sequence == 0U ||
	    scheduler->next_lease_nonce == 0U ||
	    scheduler->default_lease_ms == 0U ||
	    scheduler->maximum_lease_ms <
		    scheduler->default_lease_ms ||
	    scheduler->priority_aging_ms == 0U ||
	    scheduler->default_backoff_ms == 0U ||
	    scheduler->maximum_backoff_ms <
		    scheduler->default_backoff_ms ||
	    scheduler->default_maximum_attempts == 0U ||
	    scheduler->default_jitter_basis_points >
		    PQCP_FLEET_DELIVERY_MAX_JITTER_BASIS_POINTS) {
		return -EINVAL;
	}
	return 0;
}

static int record_index_by_artifact(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t artifact_id)
{
	if (scheduler == NULL || artifact_id == 0U) {
		return -1;
	}
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		if (scheduler->records[index].occupied &&
		    scheduler->records[index].artifact_id ==
			    artifact_id) {
			return (int)index;
		}
	}
	return -1;
}

static int record_index_by_handle(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle)
{
	int index;

	if (handle.artifact_id == 0U ||
	    handle.generation == 0U) {
		return -1;
	}
	index = record_index_by_artifact(
		scheduler, handle.artifact_id);
	if (index < 0 ||
	    scheduler->records[index].generation !=
		    handle.generation) {
		return -1;
	}
	return index;
}

static int free_record_index(
	const struct pqcp_fleet_delivery_scheduler *scheduler)
{
	if (scheduler == NULL) {
		return -1;
	}
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		if (!scheduler->records[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

static bool request_binding_matches(
	const struct pqcp_fleet_delivery_record *record,
	const struct pqcp_fleet_delivery_request *request)
{
	return record->artifact_id == request->artifact_id &&
	       record->message_id == request->message_id &&
	       record->correlation_id == request->correlation_id &&
	       record->dependency_artifact_id ==
		       request->dependency_artifact_id &&
	       record->policy_epoch == request->policy_epoch &&
	       record->revocation_epoch ==
		       request->revocation_epoch &&
	       record->artifact_size == request->artifact_size &&
	       digest_equal(
		       record->artifact_digest,
		       request->artifact_digest) &&
	       digest_equal(
		       record->idempotency_key,
		       request->idempotency_key);
}

static int duplicate_request_index(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_request *request,
	bool *exact,
	bool *collision)
{
	if (exact != NULL) {
		*exact = false;
	}
	if (collision != NULL) {
		*collision = false;
	}
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		const struct pqcp_fleet_delivery_record *record =
			&scheduler->records[index];
		bool same_identity;
		bool same_idempotency;

		if (!record->occupied) {
			continue;
		}
		same_identity =
			record->artifact_id ==
				request->artifact_id ||
			(record->message_id ==
				 request->message_id &&
			 record->correlation_id ==
				 request->correlation_id);
		same_idempotency = digest_equal(
			record->idempotency_key,
			request->idempotency_key);
		if (!same_identity && !same_idempotency) {
			continue;
		}
		if (request_binding_matches(record, request)) {
			if (exact != NULL) {
				*exact = true;
			}
		} else if (collision != NULL) {
			*collision = true;
		}
		return (int)index;
	}
	return -1;
}

static int request_validate(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_request *request,
	uint32_t *chunk_count)
{
	uint64_t lease_duration;
	uint64_t base_backoff;
	uint64_t maximum_backoff;
	uint32_t maximum_attempts;
	uint32_t jitter;
	int ret;

	if (scheduler == NULL || request == NULL ||
	    chunk_count == NULL ||
	    request->artifact_id == 0U ||
	    request->message_id == 0U ||
	    request->correlation_id == 0U ||
	    request->dependency_artifact_id ==
		    request->artifact_id ||
	    request->created_at_ms == 0U ||
	    request->not_before_ms <
		    request->created_at_ms ||
	    request->expires_at_ms <=
		    request->created_at_ms ||
	    request->not_before_ms >=
		    request->expires_at_ms ||
	    request->chunk_size == 0U ||
	    request->priority >
		    PQCP_FLEET_DELIVERY_PRIORITY_MAX ||
	    (request->flags & ~known_flags()) != 0U ||
	    bytes_zero(request->idempotency_key,
		       sizeof(request->idempotency_key)) ||
	    bytes_zero(request->artifact_digest,
		       sizeof(request->artifact_digest))) {
		return -EINVAL;
	}
	if (request->artifact_size == 0U &&
	    (request->flags &
	     PQCP_FLEET_DELIVERY_FLAG_ALLOW_ZERO_LENGTH) == 0U) {
		return -EINVAL;
	}
	if ((request->flags &
	     PQCP_FLEET_DELIVERY_FLAG_REQUIRE_POLICY_EPOCH) != 0U &&
	    request->policy_epoch == 0U) {
		return -EINVAL;
	}
	if ((request->flags &
	     PQCP_FLEET_DELIVERY_FLAG_REQUIRE_REVOCATION_EPOCH) != 0U &&
	    request->revocation_epoch == 0U) {
		return -EINVAL;
	}
	lease_duration = request->lease_duration_ms != 0U ?
		request->lease_duration_ms :
		scheduler->default_lease_ms;
	base_backoff = request->base_backoff_ms != 0U ?
		request->base_backoff_ms :
		scheduler->default_backoff_ms;
	maximum_backoff = request->maximum_backoff_ms != 0U ?
		request->maximum_backoff_ms :
		scheduler->maximum_backoff_ms;
	maximum_attempts = request->maximum_attempts != 0U ?
		request->maximum_attempts :
		scheduler->default_maximum_attempts;
	jitter = request->jitter_basis_points != 0U ?
		request->jitter_basis_points :
		scheduler->default_jitter_basis_points;
	if (lease_duration == 0U ||
	    lease_duration > scheduler->maximum_lease_ms ||
	    base_backoff == 0U ||
	    maximum_backoff < base_backoff ||
	    maximum_backoff >
		    scheduler->maximum_backoff_ms ||
	    maximum_attempts == 0U ||
	    jitter >
		    PQCP_FLEET_DELIVERY_MAX_JITTER_BASIS_POINTS) {
		return -EINVAL;
	}
	ret = chunk_count_compute(
		request->artifact_size,
		request->chunk_size,
		chunk_count);
	return ret;
}

static uint32_t next_generation(
	struct pqcp_fleet_delivery_scheduler *scheduler)
{
	uint32_t generation = scheduler->next_generation;

	scheduler->next_generation++;
	if (scheduler->next_generation == 0U) {
		scheduler->next_generation = 1U;
	}
	if (generation == 0U) {
		generation = scheduler->next_generation;
		scheduler->next_generation++;
		if (scheduler->next_generation == 0U) {
			scheduler->next_generation = 1U;
		}
	}
	return generation;
}

static uint64_t next_sequence(
	struct pqcp_fleet_delivery_scheduler *scheduler)
{
	uint64_t sequence = scheduler->next_enqueue_sequence;

	if (scheduler->next_enqueue_sequence != UINT64_MAX) {
		scheduler->next_enqueue_sequence++;
	}
	return sequence;
}

static bool dependency_chain_valid(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t artifact_id,
	uint64_t dependency_artifact_id)
{
	uint64_t current = dependency_artifact_id;

	for (size_t depth = 0U;
	     current != PQCP_FLEET_DELIVERY_NO_DEPENDENCY;
	     ++depth) {
		int index;

		if (depth >= scheduler->capacity ||
		    current == artifact_id) {
			return false;
		}
		index = record_index_by_artifact(
			scheduler, current);
		if (index < 0) {
			return false;
		}
		current = scheduler->records[index].
			dependency_artifact_id;
	}
	return true;
}

static bool dependency_delivered(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t dependency_artifact_id)
{
	int index;

	if (dependency_artifact_id ==
	    PQCP_FLEET_DELIVERY_NO_DEPENDENCY) {
		return true;
	}
	index = record_index_by_artifact(
		scheduler, dependency_artifact_id);
	return index >= 0 &&
	       scheduler->records[index].state ==
		       PQCP_FLEET_DELIVERY_DELIVERED;
}

static bool dependency_failed(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t dependency_artifact_id)
{
	int index;

	if (dependency_artifact_id ==
	    PQCP_FLEET_DELIVERY_NO_DEPENDENCY) {
		return false;
	}
	index = record_index_by_artifact(
		scheduler, dependency_artifact_id);
	if (index < 0) {
		return true;
	}
	return pqcp_fleet_delivery_state_terminal(
		       scheduler->records[index].state) &&
	       scheduler->records[index].state !=
		       PQCP_FLEET_DELIVERY_DELIVERED;
}

static void clear_lease(
	struct pqcp_fleet_delivery_record *record)
{
	record->worker_id = 0U;
	record->lease_token = 0U;
	record->lease_acquired_at_ms = 0U;
	record->lease_expires_at_ms = 0U;
}

static void clear_retry(
	struct pqcp_fleet_delivery_record *record)
{
	record->next_attempt_ms = 0U;
}

static int terminal_transition(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_record *record,
	enum pqcp_fleet_delivery_state state,
	enum pqcp_fleet_delivery_terminal_reason reason,
	int error,
	uint64_t now_ms)
{
	if (scheduler == NULL || record == NULL ||
	    !pqcp_fleet_delivery_state_terminal(state) ||
	    reason == PQCP_FLEET_DELIVERY_REASON_NONE ||
	    now_ms == 0U ||
	    pqcp_fleet_delivery_state_terminal(record->state)) {
		return -EINVAL;
	}
	clear_lease(record);
	clear_retry(record);
	record->state = state;
	record->terminal_reason = reason;
	record->last_error = error;
	record->terminal_at_ms = now_ms;
	switch (state) {
	case PQCP_FLEET_DELIVERY_DELIVERED:
		saturating_increment_u64(
			&scheduler->delivered_count);
		break;
	case PQCP_FLEET_DELIVERY_FAILED:
		saturating_increment_u64(
			&scheduler->failed_count);
		break;
	case PQCP_FLEET_DELIVERY_CANCELLED:
		saturating_increment_u64(
			&scheduler->cancelled_count);
		break;
	case PQCP_FLEET_DELIVERY_EXPIRED:
		saturating_increment_u64(
			&scheduler->expired_count);
		break;
	case PQCP_FLEET_DELIVERY_DEPENDENCY_FAILED:
		saturating_increment_u64(
			&scheduler->dependency_failed_count);
		break;
	case PQCP_FLEET_DELIVERY_CONFLICT:
		saturating_increment_u64(
			&scheduler->conflict_count);
		break;
	default:
		return -EINVAL;
	}
	saturating_increment_u64(&scheduler->generation);
	return record_digest_refresh(record);
}

static int progress_digest_update(
	struct pqcp_fleet_delivery_record *record,
	const struct pqcp_fleet_delivery_chunk *chunk,
	const uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[DELIVERY_SMALL_HASH_INPUT_MAX];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	struct delivery_encoder encoder;
	int ret;

	memset(encoded, 0, sizeof(encoded));
	encoder_init(&encoder, encoded, sizeof(encoded));
	encoder_append(
		&encoder, DELIVERY_PROGRESS_DOMAIN,
		sizeof(DELIVERY_PROGRESS_DOMAIN) - 1U);
	encoder_append(
		&encoder, record->progress_digest,
		sizeof(record->progress_digest));
	encoder_u64(&encoder, record->artifact_id);
	encoder_u32(&encoder, chunk->index);
	encoder_u64(&encoder, chunk->offset);
	encoder_u64(&encoder, chunk->length);
	encoder_append(
		&encoder, chunk_digest,
		PQCP_FLEET_DIGEST_BYTES);
	if (encoder.error != 0) {
		pqcp_runtime_secure_zero(encoded, sizeof(encoded));
		return encoder.error;
	}
	ret = pqcp_fleet_sha256(
		encoded, encoder.offset, digest);
	if (ret == 0) {
		memcpy(record->progress_digest, digest,
		       sizeof(record->progress_digest));
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static uint64_t deterministic_value(
	const char *domain,
	const struct pqcp_fleet_delivery_record *record,
	uint64_t nonce,
	uint32_t attempt)
{
	uint8_t encoded[DELIVERY_SMALL_HASH_INPUT_MAX];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	struct delivery_encoder encoder;
	uint64_t value = 0U;

	memset(encoded, 0, sizeof(encoded));
	memset(digest, 0, sizeof(digest));
	encoder_init(&encoder, encoded, sizeof(encoded));
	encoder_append(
		&encoder, domain, strnlen(domain, 64U));
	encoder_append(
		&encoder, record->artifact_digest,
		sizeof(record->artifact_digest));
	encoder_append(
		&encoder, record->idempotency_key,
		sizeof(record->idempotency_key));
	encoder_u64(&encoder, record->artifact_id);
	encoder_u64(&encoder, record->message_id);
	encoder_u64(&encoder, record->correlation_id);
	encoder_u64(&encoder, nonce);
	encoder_u32(&encoder, attempt);
	if (encoder.error == 0 &&
	    pqcp_fleet_sha256(
		    encoded, encoder.offset, digest) == 0) {
		value = read_u64_be(digest);
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return value;
}

static uint64_t backoff_without_jitter(
	const struct pqcp_fleet_delivery_record *record)
{
	uint64_t delay = record->base_backoff_ms;
	uint32_t shifts = record->attempts > 0U ?
		record->attempts - 1U : 0U;

	for (uint32_t shift = 0U; shift < shifts; ++shift) {
		if (delay >= record->maximum_backoff_ms ||
		    delay > UINT64_MAX / 2U) {
			return record->maximum_backoff_ms;
		}
		delay *= 2U;
		if (delay > record->maximum_backoff_ms) {
			delay = record->maximum_backoff_ms;
		}
	}
	return minimum_u64(
		delay, record->maximum_backoff_ms);
}

static uint64_t retry_delay(
	const struct pqcp_fleet_delivery_record *record)
{
	uint64_t delay = backoff_without_jitter(record);
	uint64_t jitter_range;
	uint64_t width;
	uint64_t random;
	uint64_t lower;

	if (record->jitter_basis_points == 0U) {
		return delay;
	}
	if (!multiply_u64(
		    delay, record->jitter_basis_points,
		    &jitter_range)) {
		jitter_range = UINT64_MAX;
	}
	jitter_range /= 10000U;
	if (jitter_range > delay) {
		jitter_range = delay;
	}
	lower = delay - jitter_range;
	if (jitter_range > (UINT64_MAX - 1U) / 2U) {
		width = UINT64_MAX;
	} else {
		width = jitter_range * 2U + 1U;
	}
	random = deterministic_value(
		DELIVERY_JITTER_DOMAIN,
		record,
		record->enqueue_sequence,
		record->attempts);
	if (width == 0U || width == UINT64_MAX) {
		return lower + minimum_u64(
			random, UINT64_MAX - lower);
	}
	return lower + random % width;
}

static int schedule_retry(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_record *record,
	int error,
	uint64_t now_ms)
{
	uint64_t delay;
	uint64_t next_attempt;

	clear_lease(record);
	record->last_error = error;
	if (record->attempts >= record->maximum_attempts) {
		return terminal_transition(
			scheduler, record,
			PQCP_FLEET_DELIVERY_FAILED,
			PQCP_FLEET_DELIVERY_REASON_ATTEMPTS_EXHAUSTED,
			error, now_ms);
	}
	delay = retry_delay(record);
	if (!add_u64(now_ms, delay, &next_attempt) ||
	    next_attempt >= record->expires_at_ms) {
		return terminal_transition(
			scheduler, record,
			PQCP_FLEET_DELIVERY_EXPIRED,
			PQCP_FLEET_DELIVERY_REASON_EXPIRED,
			-ETIMEDOUT, now_ms);
	}
	if ((record->flags &
	     PQCP_FLEET_DELIVERY_FLAG_RETAIN_PROGRESS_ON_RETRY) == 0U) {
		if (record->committed_bytes >
		    scheduler->committed_bytes) {
			return terminal_transition(
				scheduler, record,
				PQCP_FLEET_DELIVERY_CONFLICT,
				PQCP_FLEET_DELIVERY_REASON_INVARIANT_FAILURE,
				-EBADMSG, now_ms);
		}
		scheduler->committed_bytes -=
			record->committed_bytes;
		record->committed_bytes = 0U;
		record->next_chunk = 0U;
		memset(record->progress_digest, 0,
		       sizeof(record->progress_digest));
	}
	record->state = PQCP_FLEET_DELIVERY_RETRY_WAIT;
	record->next_attempt_ms = next_attempt;
	record->terminal_reason =
		PQCP_FLEET_DELIVERY_REASON_NONE;
	record->terminal_at_ms = 0U;
	saturating_increment_u64(&scheduler->retry_count);
	saturating_increment_u64(&scheduler->generation);
	return record_digest_refresh(record);
}

static bool epoch_stale(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_record *record)
{
	if ((record->flags &
	     PQCP_FLEET_DELIVERY_FLAG_REQUIRE_POLICY_EPOCH) != 0U &&
	    record->policy_epoch <
		    scheduler->latest_policy_epoch) {
		return true;
	}
	if ((record->flags &
	     PQCP_FLEET_DELIVERY_FLAG_REQUIRE_REVOCATION_EPOCH) != 0U &&
	    record->revocation_epoch <
		    scheduler->latest_revocation_epoch) {
		return true;
	}
	return false;
}

static int maintenance_record(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_record *record,
	uint64_t now_ms,
	bool *changed)
{
	int ret;

	*changed = false;
	if (!record->occupied ||
	    pqcp_fleet_delivery_state_terminal(record->state)) {
		return 0;
	}
	ret = pqcp_fleet_delivery_record_verify(record);
	if (ret != 0) {
		clear_lease(record);
		clear_retry(record);
		record->state = PQCP_FLEET_DELIVERY_CONFLICT;
		record->terminal_reason =
			PQCP_FLEET_DELIVERY_REASON_INVARIANT_FAILURE;
		record->last_error = -EBADMSG;
		record->terminal_at_ms = now_ms;
		saturating_increment_u64(
			&scheduler->conflict_count);
		saturating_increment_u64(&scheduler->generation);
		(void)record_digest_refresh(record);
		*changed = true;
		return 0;
	}
	if (now_ms >= record->expires_at_ms) {
		ret = terminal_transition(
			scheduler, record,
			PQCP_FLEET_DELIVERY_EXPIRED,
			PQCP_FLEET_DELIVERY_REASON_EXPIRED,
			-ETIMEDOUT, now_ms);
		*changed = ret == 0;
		return ret;
	}
	if (scheduler->expire_stale_epochs &&
	    epoch_stale(scheduler, record)) {
		ret = terminal_transition(
			scheduler, record,
			PQCP_FLEET_DELIVERY_EXPIRED,
			PQCP_FLEET_DELIVERY_REASON_EPOCH_STALE,
			-ESTALE, now_ms);
		if (ret == 0) {
			saturating_increment_u64(
				&scheduler->stale_epoch_count);
			*changed = true;
		}
		return ret;
	}
	if (record->state == PQCP_FLEET_DELIVERY_LEASED &&
	    now_ms >= record->lease_expires_at_ms) {
		saturating_increment_u64(
			&scheduler->lease_timeout_count);
		ret = schedule_retry(
			scheduler, record, -ETIMEDOUT, now_ms);
		*changed = ret == 0;
		return ret;
	}
	if (record->state ==
		    PQCP_FLEET_DELIVERY_WAITING_DEPENDENCY) {
		if (dependency_delivered(
			    scheduler,
			    record->dependency_artifact_id)) {
			record->state =
				PQCP_FLEET_DELIVERY_READY;
			saturating_increment_u64(
				&scheduler->generation);
			ret = record_digest_refresh(record);
			*changed = ret == 0;
			return ret;
		}
		if (dependency_failed(
			    scheduler,
			    record->dependency_artifact_id)) {
			ret = terminal_transition(
				scheduler, record,
				PQCP_FLEET_DELIVERY_DEPENDENCY_FAILED,
				PQCP_FLEET_DELIVERY_REASON_DEPENDENCY_TERMINAL,
				-ECANCELED, now_ms);
			*changed = ret == 0;
			return ret;
		}
	}
	if (record->state ==
		    PQCP_FLEET_DELIVERY_RETRY_WAIT &&
	    now_ms >= record->next_attempt_ms) {
		clear_retry(record);
		record->state = record->dependency_artifact_id !=
				PQCP_FLEET_DELIVERY_NO_DEPENDENCY &&
			!dependency_delivered(
				scheduler,
				record->dependency_artifact_id) ?
				PQCP_FLEET_DELIVERY_WAITING_DEPENDENCY :
				PQCP_FLEET_DELIVERY_READY;
		saturating_increment_u64(&scheduler->generation);
		ret = record_digest_refresh(record);
		*changed = ret == 0;
		return ret;
	}
	return 0;
}

static int maintenance_sweep(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed_total = 0U;
	bool progress = true;

	for (size_t pass = 0U;
	     pass < scheduler->capacity && progress; ++pass) {
		progress = false;
		for (size_t index = 0U;
		     index < scheduler->capacity; ++index) {
			bool changed;
			int ret = maintenance_record(
				scheduler,
				&scheduler->records[index],
				now_ms, &changed);

			if (ret != 0) {
				return ret;
			}
			if (changed) {
				if (changed_total != UINT32_MAX) {
					changed_total++;
				}
				progress = true;
			}
		}
	}
	if (changed_count != NULL) {
		*changed_count = changed_total;
	}
	return 0;
}

static uint16_t effective_priority(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_record *record,
	uint64_t now_ms)
{
	uint64_t age;
	uint64_t boost;
	uint64_t effective;

	if (now_ms <= record->created_at_ms) {
		return record->priority;
	}
	age = now_ms - record->created_at_ms;
	boost = age / scheduler->priority_aging_ms;
	effective = record->priority + boost;
	if (effective >
	    PQCP_FLEET_DELIVERY_PRIORITY_MAX) {
		effective =
			PQCP_FLEET_DELIVERY_PRIORITY_MAX;
	}
	return (uint16_t)effective;
}

static bool candidate_better(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_record *candidate,
	const struct pqcp_fleet_delivery_record *selected,
	uint64_t now_ms)
{
	uint16_t candidate_priority;
	uint16_t selected_priority;

	if (selected == NULL) {
		return true;
	}
	candidate_priority = effective_priority(
		scheduler, candidate, now_ms);
	selected_priority = effective_priority(
		scheduler, selected, now_ms);
	if (candidate_priority != selected_priority) {
		return candidate_priority > selected_priority;
	}
	if (candidate->expires_at_ms !=
	    selected->expires_at_ms) {
		return candidate->expires_at_ms <
		       selected->expires_at_ms;
	}
	if (candidate->not_before_ms !=
	    selected->not_before_ms) {
		return candidate->not_before_ms <
		       selected->not_before_ms;
	}
	return candidate->enqueue_sequence <
	       selected->enqueue_sequence;
}

static int selected_record_index(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t now_ms)
{
	const struct pqcp_fleet_delivery_record *selected = NULL;
	int selected_index = -1;

	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		const struct pqcp_fleet_delivery_record *record =
			&scheduler->records[index];

		if (!record->occupied ||
		    record->state != PQCP_FLEET_DELIVERY_READY ||
		    now_ms < record->not_before_ms ||
		    now_ms >= record->expires_at_ms ||
		    epoch_stale(scheduler, record) ||
		    !dependency_delivered(
			    scheduler,
			    record->dependency_artifact_id)) {
			continue;
		}
		if (candidate_better(
			    scheduler, record, selected, now_ms)) {
			selected = record;
			selected_index = (int)index;
		}
	}
	return selected_index;
}

static uint64_t lease_token_create(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_record *record)
{
	uint64_t nonce = scheduler->next_lease_nonce;
	uint64_t token;

	if (scheduler->next_lease_nonce != UINT64_MAX) {
		scheduler->next_lease_nonce++;
	}
	token = deterministic_value(
		DELIVERY_TOKEN_DOMAIN,
		record, nonce, record->attempts);
	if (token == 0U) {
		token = nonce ^ record->artifact_id ^
			((uint64_t)record->generation << 32U);
	}
	if (token == 0U) {
		token = 1U;
	}
	return token;
}

static int lease_record_validate(
	const struct pqcp_fleet_delivery_record *record,
	const struct pqcp_fleet_delivery_lease *lease,
	uint64_t now_ms)
{
	if (record == NULL || lease == NULL ||
	    record->state != PQCP_FLEET_DELIVERY_LEASED ||
	    lease->handle.artifact_id != record->artifact_id ||
	    lease->handle.generation != record->generation ||
	    lease->worker_id == 0U ||
	    lease->worker_id != record->worker_id ||
	    lease->token == 0U ||
	    lease->token != record->lease_token ||
	    lease->attempt != record->attempts ||
	    lease->acquired_at_ms !=
		    record->lease_acquired_at_ms ||
	    lease->expires_at_ms !=
		    record->lease_expires_at_ms ||
	    lease->next_chunk != record->next_chunk ||
	    now_ms < record->lease_acquired_at_ms ||
	    now_ms >= record->lease_expires_at_ms ||
	    now_ms >= record->expires_at_ms) {
		return -EACCES;
	}
	return 0;
}

static void lease_copy(
	const struct pqcp_fleet_delivery_record *record,
	struct pqcp_fleet_delivery_lease *lease)
{
	memset(lease, 0, sizeof(*lease));
	lease->handle.artifact_id = record->artifact_id;
	lease->handle.generation = record->generation;
	lease->worker_id = record->worker_id;
	lease->token = record->lease_token;
	lease->acquired_at_ms = record->lease_acquired_at_ms;
	lease->expires_at_ms = record->lease_expires_at_ms;
	lease->attempt = record->attempts;
	lease->next_chunk = record->next_chunk;
}

int pqcp_fleet_delivery_init(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_record *records,
	size_t capacity,
	const struct pqcp_fleet_delivery_config *config)
{
	struct pqcp_fleet_delivery_config selected = {
		.default_lease_ms =
			PQCP_FLEET_DELIVERY_DEFAULT_LEASE_MS,
		.maximum_lease_ms =
			PQCP_FLEET_DELIVERY_DEFAULT_MAX_LEASE_MS,
		.priority_aging_ms =
			PQCP_FLEET_DELIVERY_DEFAULT_AGING_MS,
		.default_backoff_ms =
			PQCP_FLEET_DELIVERY_DEFAULT_BACKOFF_MS,
		.maximum_backoff_ms =
			PQCP_FLEET_DELIVERY_DEFAULT_MAX_BACKOFF_MS,
		.default_maximum_attempts = 8U,
		.default_jitter_basis_points = 2000U,
		.expire_stale_epochs = true,
	};

	if (scheduler == NULL || records == NULL ||
	    capacity == 0U ||
	    !size_array_valid(capacity, sizeof(*records))) {
		return -EINVAL;
	}
	if (config != NULL) {
		selected = *config;
	}
	if (selected.default_lease_ms == 0U ||
	    selected.maximum_lease_ms <
		    selected.default_lease_ms ||
	    selected.priority_aging_ms == 0U ||
	    selected.default_backoff_ms == 0U ||
	    selected.maximum_backoff_ms <
		    selected.default_backoff_ms ||
	    selected.default_maximum_attempts == 0U ||
	    selected.default_jitter_basis_points >
		    PQCP_FLEET_DELIVERY_MAX_JITTER_BASIS_POINTS) {
		return -EINVAL;
	}
	memset(scheduler, 0, sizeof(*scheduler));
	memset(records, 0, sizeof(*records) * capacity);
	scheduler->schema_version =
		PQCP_FLEET_DELIVERY_SCHEMA_VERSION;
	scheduler->records = records;
	scheduler->capacity = capacity;
	scheduler->next_generation = 1U;
	scheduler->next_enqueue_sequence = 1U;
	scheduler->next_lease_nonce = 1U;
	scheduler->generation = 1U;
	scheduler->default_lease_ms =
		selected.default_lease_ms;
	scheduler->maximum_lease_ms =
		selected.maximum_lease_ms;
	scheduler->priority_aging_ms =
		selected.priority_aging_ms;
	scheduler->default_backoff_ms =
		selected.default_backoff_ms;
	scheduler->maximum_backoff_ms =
		selected.maximum_backoff_ms;
	scheduler->default_maximum_attempts =
		selected.default_maximum_attempts;
	scheduler->default_jitter_basis_points =
		selected.default_jitter_basis_points;
	scheduler->expire_stale_epochs =
		selected.expire_stale_epochs;
	k_mutex_init(&scheduler->lock);
	scheduler->initialized = true;
	return 0;
}

int pqcp_fleet_delivery_enqueue(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_request *request,
	struct pqcp_fleet_delivery_handle *handle,
	bool *replayed)
{
	struct pqcp_fleet_delivery_record staged;
	uint32_t chunk_count;
	bool exact;
	bool collision;
	int duplicate_index;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    request == NULL || handle == NULL ||
	    replayed == NULL) {
		return -EINVAL;
	}
	ret = request_validate(
		scheduler, request, &chunk_count);
	if (ret != 0) {
		return ret;
	}
	memset(handle, 0, sizeof(*handle));
	*replayed = false;
	memset(&staged, 0, sizeof(staged));
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	duplicate_index = duplicate_request_index(
		scheduler, request, &exact, &collision);
	if (duplicate_index >= 0) {
		struct pqcp_fleet_delivery_record *existing =
			&scheduler->records[duplicate_index];

		if (exact &&
		    (request->flags &
		     PQCP_FLEET_DELIVERY_FLAG_IDEMPOTENT) != 0U) {
			handle->artifact_id =
				existing->artifact_id;
			handle->generation =
				existing->generation;
			*replayed = true;
			saturating_increment_u64(
				&scheduler->replayed_count);
			(void)k_mutex_unlock(&scheduler->lock);
			return 0;
		}
		if (collision) {
			saturating_increment_u64(
				&scheduler->conflict_count);
		}
		saturating_increment_u64(
			&scheduler->rejected_count);
		(void)k_mutex_unlock(&scheduler->lock);
		return collision ? -EKEYREJECTED : -EEXIST;
	}
	if (request->dependency_artifact_id !=
		    PQCP_FLEET_DELIVERY_NO_DEPENDENCY &&
	    !dependency_chain_valid(
		    scheduler, request->artifact_id,
		    request->dependency_artifact_id)) {
		saturating_increment_u64(
			&scheduler->rejected_count);
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOENT;
	}
	index = free_record_index(scheduler);
	if (index < 0) {
		saturating_increment_u64(
			&scheduler->rejected_count);
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOSPC;
	}
	staged.schema_version =
		PQCP_FLEET_DELIVERY_SCHEMA_VERSION;
	staged.generation = next_generation(scheduler);
	staged.enqueue_sequence = next_sequence(scheduler);
	staged.artifact_id = request->artifact_id;
	staged.message_id = request->message_id;
	staged.correlation_id = request->correlation_id;
	staged.dependency_artifact_id =
		request->dependency_artifact_id;
	staged.policy_epoch = request->policy_epoch;
	staged.revocation_epoch = request->revocation_epoch;
	staged.created_at_ms = request->created_at_ms;
	staged.not_before_ms = request->not_before_ms;
	staged.expires_at_ms = request->expires_at_ms;
	staged.lease_duration_ms =
		request->lease_duration_ms != 0U ?
			request->lease_duration_ms :
			scheduler->default_lease_ms;
	staged.base_backoff_ms =
		request->base_backoff_ms != 0U ?
			request->base_backoff_ms :
			scheduler->default_backoff_ms;
	staged.maximum_backoff_ms =
		request->maximum_backoff_ms != 0U ?
			request->maximum_backoff_ms :
			scheduler->maximum_backoff_ms;
	staged.artifact_size = request->artifact_size;
	staged.chunk_size = request->chunk_size;
	staged.chunk_count = chunk_count;
	staged.maximum_attempts =
		request->maximum_attempts != 0U ?
			request->maximum_attempts :
			scheduler->default_maximum_attempts;
	staged.jitter_basis_points =
		request->jitter_basis_points != 0U ?
			request->jitter_basis_points :
			scheduler->default_jitter_basis_points;
	staged.priority = request->priority;
	staged.flags = request->flags;
	staged.state = request->dependency_artifact_id !=
			PQCP_FLEET_DELIVERY_NO_DEPENDENCY &&
		!dependency_delivered(
			scheduler,
			request->dependency_artifact_id) ?
			PQCP_FLEET_DELIVERY_WAITING_DEPENDENCY :
			PQCP_FLEET_DELIVERY_READY;
	staged.terminal_reason =
		PQCP_FLEET_DELIVERY_REASON_NONE;
	memcpy(staged.idempotency_key,
	       request->idempotency_key,
	       sizeof(staged.idempotency_key));
	memcpy(staged.artifact_digest,
	       request->artifact_digest,
	       sizeof(staged.artifact_digest));
	staged.occupied = true;
	ret = record_digest_refresh(&staged);
	if (ret == 0) {
		scheduler->records[index] = staged;
		scheduler->occupied_count++;
		saturating_increment_u64(
			&scheduler->enqueued_count);
		saturating_increment_u64(
			&scheduler->generation);
		handle->artifact_id = staged.artifact_id;
		handle->generation = staged.generation;
	}
	(void)k_mutex_unlock(&scheduler->lock);
	pqcp_runtime_secure_zero(&staged, sizeof(staged));
	return ret;
}

int pqcp_fleet_delivery_acquire(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t worker_id,
	uint64_t now_ms,
	struct pqcp_fleet_delivery_lease *lease)
{
	struct pqcp_fleet_delivery_record *record;
	uint64_t requested_expiry;
	uint64_t maximum_expiry;
	uint32_t changed;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    worker_id == 0U || now_ms == 0U ||
	    lease == NULL) {
		return -EINVAL;
	}
	memset(lease, 0, sizeof(*lease));
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = maintenance_sweep(
		scheduler, now_ms, &changed);
	if (ret != 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return ret;
	}
	index = selected_record_index(scheduler, now_ms);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EAGAIN;
	}
	record = &scheduler->records[index];
	if (record->attempts >= record->maximum_attempts) {
		ret = terminal_transition(
			scheduler, record,
			PQCP_FLEET_DELIVERY_FAILED,
			PQCP_FLEET_DELIVERY_REASON_ATTEMPTS_EXHAUSTED,
			-EAGAIN, now_ms);
		(void)k_mutex_unlock(&scheduler->lock);
		return ret == 0 ? -EAGAIN : ret;
	}
	if (!add_u64(
		    now_ms, record->lease_duration_ms,
		    &requested_expiry)) {
		requested_expiry = UINT64_MAX;
	}
	if (!add_u64(
		    now_ms, scheduler->maximum_lease_ms,
		    &maximum_expiry)) {
		maximum_expiry = UINT64_MAX;
	}
	record->attempts++;
	record->state = PQCP_FLEET_DELIVERY_LEASED;
	record->worker_id = worker_id;
	record->lease_acquired_at_ms = now_ms;
	record->lease_expires_at_ms = minimum_u64(
		record->expires_at_ms,
		minimum_u64(requested_expiry, maximum_expiry));
	record->lease_token =
		lease_token_create(scheduler, record);
	record->last_error = 0;
	clear_retry(record);
	if (record->lease_expires_at_ms <= now_ms) {
		ret = terminal_transition(
			scheduler, record,
			PQCP_FLEET_DELIVERY_EXPIRED,
			PQCP_FLEET_DELIVERY_REASON_EXPIRED,
			-ETIMEDOUT, now_ms);
		(void)k_mutex_unlock(&scheduler->lock);
		return ret == 0 ? -ETIMEDOUT : ret;
	}
	ret = record_digest_refresh(record);
	if (ret == 0) {
		lease_copy(record, lease);
		saturating_increment_u64(
			&scheduler->lease_count);
		saturating_increment_u64(
			&scheduler->generation);
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_next_chunk(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	uint64_t now_ms,
	struct pqcp_fleet_delivery_chunk *chunk)
{
	const struct pqcp_fleet_delivery_record *record;
	uint64_t remaining;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    lease == NULL || now_ms == 0U ||
	    chunk == NULL) {
		return -EINVAL;
	}
	memset(chunk, 0, sizeof(*chunk));
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(
		scheduler, lease->handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	record = &scheduler->records[index];
	ret = lease_record_validate(record, lease, now_ms);
	if (ret != 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return ret;
	}
	if (record->next_chunk >= record->chunk_count ||
	    record->committed_bytes >= record->artifact_size) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENODATA;
	}
	remaining = record->artifact_size -
		record->committed_bytes;
	chunk->handle = lease->handle;
	chunk->lease_token = lease->token;
	chunk->offset = record->committed_bytes;
	chunk->length = minimum_u64(
		remaining, record->chunk_size);
	chunk->index = record->next_chunk;
	chunk->count = record->chunk_count;
	chunk->final_chunk =
		chunk->index + 1U == chunk->count;
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

static int chunk_descriptor_validate(
	const struct pqcp_fleet_delivery_record *record,
	const struct pqcp_fleet_delivery_lease *lease,
	const struct pqcp_fleet_delivery_chunk *chunk)
{
	uint64_t remaining;
	uint64_t expected_length;

	if (record == NULL || lease == NULL || chunk == NULL ||
	    chunk->handle.artifact_id != record->artifact_id ||
	    chunk->handle.generation != record->generation ||
	    chunk->lease_token != lease->token ||
	    chunk->lease_token != record->lease_token ||
	    chunk->offset != record->committed_bytes ||
	    chunk->index != record->next_chunk ||
	    chunk->count != record->chunk_count ||
	    chunk->index >= chunk->count ||
	    chunk->length == 0U ||
	    record->committed_bytes >= record->artifact_size) {
		return -EINVAL;
	}
	remaining = record->artifact_size -
		record->committed_bytes;
	expected_length = minimum_u64(
		remaining, record->chunk_size);
	if (chunk->length != expected_length ||
	    chunk->final_chunk !=
		    (chunk->index + 1U == chunk->count)) {
		return -ERANGE;
	}
	return 0;
}

int pqcp_fleet_delivery_commit_chunk(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	const struct pqcp_fleet_delivery_chunk *chunk,
	const uint8_t chunk_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_fleet_delivery_record *record;
	uint64_t new_committed;
	uint64_t scheduler_committed;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    lease == NULL || chunk == NULL ||
	    chunk_digest == NULL ||
	    bytes_zero(chunk_digest,
		       PQCP_FLEET_DIGEST_BYTES) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(
		scheduler, lease->handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	record = &scheduler->records[index];
	ret = lease_record_validate(record, lease, now_ms);
	if (ret == 0) {
		ret = chunk_descriptor_validate(
			record, lease, chunk);
	}
	if (ret != 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return ret;
	}
	if (!add_u64(
		    record->committed_bytes, chunk->length,
		    &new_committed) ||
	    new_committed > record->artifact_size ||
	    !add_u64(
		    scheduler->committed_bytes,
		    chunk->length,
		    &scheduler_committed)) {
		(void)terminal_transition(
			scheduler, record,
			PQCP_FLEET_DELIVERY_CONFLICT,
			PQCP_FLEET_DELIVERY_REASON_INVARIANT_FAILURE,
			-EOVERFLOW, now_ms);
		(void)k_mutex_unlock(&scheduler->lock);
		return -EOVERFLOW;
	}
	ret = progress_digest_update(
		record, chunk, chunk_digest);
	if (ret == 0) {
		record->committed_bytes = new_committed;
		record->next_chunk++;
		record->last_progress_at_ms = now_ms;
		scheduler->committed_bytes =
			scheduler_committed;
		saturating_increment_u64(
			&scheduler->generation);
		ret = record_digest_refresh(record);
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_renew(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	uint64_t extension_ms,
	uint64_t now_ms,
	struct pqcp_fleet_delivery_lease *renewed)
{
	struct pqcp_fleet_delivery_record *record;
	uint64_t requested;
	uint64_t maximum;
	uint64_t selected;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    lease == NULL || extension_ms == 0U ||
	    now_ms == 0U || renewed == NULL) {
		return -EINVAL;
	}
	memset(renewed, 0, sizeof(*renewed));
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(
		scheduler, lease->handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	record = &scheduler->records[index];
	ret = lease_record_validate(record, lease, now_ms);
	if (ret != 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return ret;
	}
	if (!add_u64(
		    record->lease_expires_at_ms,
		    extension_ms, &requested)) {
		requested = UINT64_MAX;
	}
	if (!add_u64(
		    record->lease_acquired_at_ms,
		    scheduler->maximum_lease_ms,
		    &maximum)) {
		maximum = UINT64_MAX;
	}
	selected = minimum_u64(
		requested,
		minimum_u64(maximum, record->expires_at_ms));
	if (selected <= record->lease_expires_at_ms) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EALREADY;
	}
	record->lease_expires_at_ms = selected;
	ret = record_digest_refresh(record);
	if (ret == 0) {
		lease_copy(record, renewed);
		saturating_increment_u64(
			&scheduler->generation);
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_complete(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	const uint8_t artifact_digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t now_ms)
{
	struct pqcp_fleet_delivery_record *record;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    lease == NULL || artifact_digest == NULL ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(
		scheduler, lease->handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	record = &scheduler->records[index];
	ret = lease_record_validate(record, lease, now_ms);
	if (ret != 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return ret;
	}
	if (record->committed_bytes != record->artifact_size ||
	    record->next_chunk != record->chunk_count) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EINPROGRESS;
	}
	if (!digest_equal(
		    record->artifact_digest, artifact_digest)) {
		ret = terminal_transition(
			scheduler, record,
			PQCP_FLEET_DELIVERY_CONFLICT,
			PQCP_FLEET_DELIVERY_REASON_DIGEST_CONFLICT,
			-EKEYREJECTED, now_ms);
		(void)k_mutex_unlock(&scheduler->lock);
		return ret == 0 ? -EKEYREJECTED : ret;
	}
	ret = terminal_transition(
		scheduler, record,
		PQCP_FLEET_DELIVERY_DELIVERED,
		PQCP_FLEET_DELIVERY_REASON_COMPLETED,
		0, now_ms);
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_fail(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	int error,
	bool retryable,
	uint64_t now_ms)
{
	struct pqcp_fleet_delivery_record *record;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    lease == NULL || error >= 0 || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(
		scheduler, lease->handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	record = &scheduler->records[index];
	ret = lease_record_validate(record, lease, now_ms);
	if (ret == 0) {
		if (retryable) {
			ret = schedule_retry(
				scheduler, record, error, now_ms);
		} else {
			ret = terminal_transition(
				scheduler, record,
				PQCP_FLEET_DELIVERY_FAILED,
				PQCP_FLEET_DELIVERY_REASON_PERMANENT_FAILURE,
				error, now_ms);
		}
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_release(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_lease *lease,
	uint64_t now_ms)
{
	return pqcp_fleet_delivery_fail(
		scheduler, lease, -EAGAIN, true, now_ms);
}

int pqcp_fleet_delivery_cancel(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle,
	int reason,
	uint64_t now_ms)
{
	struct pqcp_fleet_delivery_record *record;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U ||
	    reason > 0 || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(scheduler, handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	record = &scheduler->records[index];
	if (pqcp_fleet_delivery_state_terminal(record->state)) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EALREADY;
	}
	ret = terminal_transition(
		scheduler, record,
		PQCP_FLEET_DELIVERY_CANCELLED,
		PQCP_FLEET_DELIVERY_REASON_CANCELLED_BY_CALLER,
		reason == 0 ? -ECANCELED : reason,
		now_ms);
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_reprioritize(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle,
	uint16_t priority)
{
	struct pqcp_fleet_delivery_record *record;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U ||
	    priority > PQCP_FLEET_DELIVERY_PRIORITY_MAX) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(scheduler, handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	record = &scheduler->records[index];
	if (pqcp_fleet_delivery_state_terminal(record->state)) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EALREADY;
	}
	if (record->priority == priority) {
		(void)k_mutex_unlock(&scheduler->lock);
		return 0;
	}
	record->priority = priority;
	saturating_increment_u64(&scheduler->generation);
	ret = record_digest_refresh(record);
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_reschedule(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle,
	uint64_t not_before_ms,
	uint64_t expires_at_ms)
{
	struct pqcp_fleet_delivery_record *record;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U ||
	    not_before_ms == 0U ||
	    expires_at_ms <= not_before_ms) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(scheduler, handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	record = &scheduler->records[index];
	if (pqcp_fleet_delivery_state_terminal(record->state) ||
	    record->state == PQCP_FLEET_DELIVERY_LEASED) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EBUSY;
	}
	if (not_before_ms < record->created_at_ms ||
	    expires_at_ms <= record->created_at_ms ||
	    (record->next_attempt_ms != 0U &&
	     record->next_attempt_ms >= expires_at_ms)) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ERANGE;
	}
	record->not_before_ms = not_before_ms;
	record->expires_at_ms = expires_at_ms;
	saturating_increment_u64(&scheduler->generation);
	ret = record_digest_refresh(record);
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_advance_epochs(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint64_t previous_expired;
	uint32_t changed;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (policy_epoch < scheduler->latest_policy_epoch ||
	    revocation_epoch <
		    scheduler->latest_revocation_epoch) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	previous_expired = scheduler->expired_count;
	scheduler->latest_policy_epoch = policy_epoch;
	scheduler->latest_revocation_epoch =
		revocation_epoch;
	ret = maintenance_sweep(
		scheduler, now_ms, &changed);
	if (ret == 0) {
		uint64_t difference =
			scheduler->expired_count -
			previous_expired;

		*expired_count = difference > UINT32_MAX ?
			UINT32_MAX : (uint32_t)difference;
		saturating_increment_u64(
			&scheduler->generation);
	}
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_tick(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    now_ms == 0U || changed_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = maintenance_sweep(
		scheduler, now_ms, changed_count);
	(void)k_mutex_unlock(&scheduler->lock);
	return ret;
}

int pqcp_fleet_delivery_get(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle,
	struct pqcp_fleet_delivery_record *record)
{
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U ||
	    record == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(scheduler, handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	*record = scheduler->records[index];
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

int pqcp_fleet_delivery_find(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t artifact_id,
	struct pqcp_fleet_delivery_record *record)
{
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    artifact_id == 0U || record == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_artifact(
		scheduler, artifact_id);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ENOENT;
	}
	*record = scheduler->records[index];
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

static bool record_has_dependents(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t artifact_id)
{
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		const struct pqcp_fleet_delivery_record *record =
			&scheduler->records[index];

		if (record->occupied &&
		    record->dependency_artifact_id ==
			    artifact_id) {
			return true;
		}
	}
	return false;
}

int pqcp_fleet_delivery_remove(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_handle handle)
{
	struct pqcp_fleet_delivery_record *record;
	int index;
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    handle.artifact_id == 0U ||
	    handle.generation == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_handle(scheduler, handle);
	if (index < 0) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -ESTALE;
	}
	record = &scheduler->records[index];
	if (!pqcp_fleet_delivery_state_terminal(record->state)) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EBUSY;
	}
	if (record_has_dependents(
		    scheduler, record->artifact_id)) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EBUSY;
	}
	if (record->committed_bytes >
	    scheduler->committed_bytes ||
	    scheduler->occupied_count == 0U) {
		(void)k_mutex_unlock(&scheduler->lock);
		return -EBADMSG;
	}
	scheduler->committed_bytes -=
		record->committed_bytes;
	scheduler->occupied_count--;
	pqcp_runtime_secure_zero(record, sizeof(*record));
	saturating_increment_u64(&scheduler->removed_count);
	saturating_increment_u64(&scheduler->generation);
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

static int aggregate_digest_compute(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t state[PQCP_FLEET_DIGEST_BYTES];
	uint8_t next[PQCP_FLEET_DIGEST_BYTES];
	uint8_t encoded[DELIVERY_SMALL_HASH_INPUT_MAX];
	struct delivery_encoder encoder;
	int ret;

	memset(state, 0, sizeof(state));
	memset(next, 0, sizeof(next));
	memset(encoded, 0, sizeof(encoded));
	encoder_init(&encoder, encoded, sizeof(encoded));
	encoder_append(
		&encoder, DELIVERY_AGGREGATE_DOMAIN,
		sizeof(DELIVERY_AGGREGATE_DOMAIN) - 1U);
	encoder_u64(&encoder, scheduler->generation);
	encoder_size(&encoder, scheduler->capacity);
	if (encoder.error != 0) {
		ret = encoder.error;
		goto out;
	}
	ret = pqcp_fleet_sha256(
		encoded, encoder.offset, state);
	if (ret != 0) {
		goto out;
	}
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		const struct pqcp_fleet_delivery_record *record =
			&scheduler->records[index];

		if (!record->occupied) {
			continue;
		}
		memset(encoded, 0, sizeof(encoded));
		encoder_init(
			&encoder, encoded, sizeof(encoded));
		encoder_append(
			&encoder, state, sizeof(state));
		encoder_size(&encoder, index);
		encoder_u64(&encoder, record->artifact_id);
		encoder_u32(&encoder, record->generation);
		encoder_append(
			&encoder, record->record_digest,
			sizeof(record->record_digest));
		if (encoder.error != 0) {
			ret = encoder.error;
			goto out;
		}
		ret = pqcp_fleet_sha256(
			encoded, encoder.offset, next);
		if (ret != 0) {
			goto out;
		}
		memcpy(state, next, sizeof(state));
		pqcp_runtime_secure_zero(next, sizeof(next));
	}
	memcpy(digest, state, sizeof(state));
	ret = 0;
out:
	pqcp_runtime_secure_zero(state, sizeof(state));
	pqcp_runtime_secure_zero(next, sizeof(next));
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static int snapshot_digest_compute(
	const struct pqcp_fleet_delivery_snapshot *snapshot,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t encoded[DELIVERY_SNAPSHOT_ENCODED_MAX];
	struct delivery_encoder encoder;
	int ret;

	memset(encoded, 0, sizeof(encoded));
	encoder_init(&encoder, encoded, sizeof(encoded));
	encoder_append(
		&encoder, DELIVERY_SNAPSHOT_DOMAIN,
		sizeof(DELIVERY_SNAPSHOT_DOMAIN) - 1U);
	encoder_u32(&encoder, snapshot->schema_version);
	encoder_u64(&encoder, snapshot->generation);
	encoder_u64(
		&encoder, snapshot->latest_policy_epoch);
	encoder_u64(
		&encoder, snapshot->latest_revocation_epoch);
	encoder_u64(&encoder, snapshot->enqueued_count);
	encoder_u64(&encoder, snapshot->replayed_count);
	encoder_u64(&encoder, snapshot->conflict_count);
	encoder_u64(&encoder, snapshot->lease_count);
	encoder_u64(&encoder, snapshot->retry_count);
	encoder_u64(&encoder, snapshot->delivered_count);
	encoder_u64(&encoder, snapshot->failed_count);
	encoder_u64(&encoder, snapshot->cancelled_count);
	encoder_u64(&encoder, snapshot->expired_count);
	encoder_u64(&encoder, snapshot->removed_count);
	encoder_u64(&encoder, snapshot->committed_bytes);
	encoder_u64(&encoder, snapshot->pending_bytes);
	encoder_u64(&encoder, snapshot->earliest_expiry_ms);
	encoder_u64(&encoder, snapshot->next_wakeup_ms);
	encoder_size(&encoder, snapshot->capacity);
	encoder_size(&encoder, snapshot->occupied_count);
	encoder_size(&encoder, snapshot->waiting_count);
	encoder_size(&encoder, snapshot->ready_count);
	encoder_size(&encoder, snapshot->leased_count);
	encoder_size(&encoder, snapshot->retry_wait_count);
	encoder_size(&encoder, snapshot->terminal_count);
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

int pqcp_fleet_delivery_snapshot(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	uint64_t now_ms,
	struct pqcp_fleet_delivery_snapshot *snapshot)
{
	int ret;

	if (scheduler_validate(scheduler) != 0 ||
	    now_ms == 0U || snapshot == NULL) {
		return -EINVAL;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	snapshot->schema_version =
		PQCP_FLEET_DELIVERY_SCHEMA_VERSION;
	snapshot->generation = scheduler->generation;
	snapshot->latest_policy_epoch =
		scheduler->latest_policy_epoch;
	snapshot->latest_revocation_epoch =
		scheduler->latest_revocation_epoch;
	snapshot->enqueued_count =
		scheduler->enqueued_count;
	snapshot->replayed_count =
		scheduler->replayed_count;
	snapshot->conflict_count =
		scheduler->conflict_count;
	snapshot->lease_count = scheduler->lease_count;
	snapshot->retry_count = scheduler->retry_count;
	snapshot->delivered_count =
		scheduler->delivered_count;
	snapshot->failed_count = scheduler->failed_count;
	snapshot->cancelled_count =
		scheduler->cancelled_count;
	snapshot->expired_count =
		scheduler->expired_count;
	snapshot->removed_count =
		scheduler->removed_count;
	snapshot->committed_bytes =
		scheduler->committed_bytes;
	snapshot->capacity = scheduler->capacity;
	snapshot->occupied_count =
		scheduler->occupied_count;
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		const struct pqcp_fleet_delivery_record *record =
			&scheduler->records[index];
		uint64_t pending;

		if (!record->occupied) {
			continue;
		}
		switch (record->state) {
		case PQCP_FLEET_DELIVERY_WAITING_DEPENDENCY:
			snapshot->waiting_count++;
			break;
		case PQCP_FLEET_DELIVERY_READY:
			snapshot->ready_count++;
			break;
		case PQCP_FLEET_DELIVERY_LEASED:
			snapshot->leased_count++;
			break;
		case PQCP_FLEET_DELIVERY_RETRY_WAIT:
			snapshot->retry_wait_count++;
			break;
		default:
			if (pqcp_fleet_delivery_state_terminal(
				    record->state)) {
				snapshot->terminal_count++;
			}
			break;
		}
		if (!pqcp_fleet_delivery_state_terminal(
			    record->state)) {
			pending = record->artifact_size -
				record->committed_bytes;
			if (pending >
			    UINT64_MAX - snapshot->pending_bytes) {
				ret = -EOVERFLOW;
				goto out;
			}
			snapshot->pending_bytes += pending;
			if (snapshot->earliest_expiry_ms == 0U ||
			    record->expires_at_ms <
				    snapshot->earliest_expiry_ms) {
				snapshot->earliest_expiry_ms =
					record->expires_at_ms;
			}
			if (record->state ==
				    PQCP_FLEET_DELIVERY_RETRY_WAIT &&
			    (snapshot->next_wakeup_ms == 0U ||
			     record->next_attempt_ms <
				     snapshot->next_wakeup_ms)) {
				snapshot->next_wakeup_ms =
					record->next_attempt_ms;
			}
			if (record->state ==
				    PQCP_FLEET_DELIVERY_LEASED &&
			    (snapshot->next_wakeup_ms == 0U ||
			     record->lease_expires_at_ms <
				     snapshot->next_wakeup_ms)) {
				snapshot->next_wakeup_ms =
					record->lease_expires_at_ms;
			}
			if (record->not_before_ms > now_ms &&
			    (snapshot->next_wakeup_ms == 0U ||
			     record->not_before_ms <
				     snapshot->next_wakeup_ms)) {
				snapshot->next_wakeup_ms =
					record->not_before_ms;
			}
		}
	}
	ret = aggregate_digest_compute(
		scheduler, snapshot->aggregate_digest);
	if (ret == 0) {
		ret = snapshot_digest_compute(
			snapshot, snapshot->snapshot_digest);
	}
out:
	(void)k_mutex_unlock(&scheduler->lock);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			snapshot, sizeof(*snapshot));
	}
	return ret;
}

static void audit_mark(
	struct pqcp_fleet_delivery_audit *audit,
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

static bool dependency_cycle_from(
	const struct pqcp_fleet_delivery_scheduler *scheduler,
	const struct pqcp_fleet_delivery_record *start)
{
	uint64_t slow = start->artifact_id;
	uint64_t fast = start->artifact_id;

	for (size_t depth = 0U;
	     depth <= scheduler->capacity; ++depth) {
		int slow_index;
		int fast_index;

		slow_index = record_index_by_artifact(
			scheduler, slow);
		if (slow_index < 0) {
			return false;
		}
		slow = scheduler->records[slow_index].
			dependency_artifact_id;
		if (slow == PQCP_FLEET_DELIVERY_NO_DEPENDENCY) {
			return false;
		}
		for (size_t step = 0U; step < 2U; ++step) {
			fast_index = record_index_by_artifact(
				scheduler, fast);
			if (fast_index < 0) {
				return false;
			}
			fast = scheduler->records[fast_index].
				dependency_artifact_id;
			if (fast ==
			    PQCP_FLEET_DELIVERY_NO_DEPENDENCY) {
				return false;
			}
		}
		if (slow == fast) {
			return true;
		}
	}
	return true;
}

int pqcp_fleet_delivery_audit(
	struct pqcp_fleet_delivery_scheduler *scheduler,
	struct pqcp_fleet_delivery_audit *audit)
{
	uint64_t committed_bytes = 0U;
	int ret;

	if (scheduler == NULL || audit == NULL) {
		return -EINVAL;
	}
	memset(audit, 0, sizeof(*audit));
	audit->schema_version =
		PQCP_FLEET_DELIVERY_SCHEMA_VERSION;
	audit->first_bad_index = SIZE_MAX;
	if (scheduler_validate(scheduler) != 0) {
		audit_mark(
			audit,
			PQCP_FLEET_DELIVERY_AUDIT_MANAGER,
			0U, 0U);
		audit->consistent = false;
		return 0;
	}
	ret = k_mutex_lock(&scheduler->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < scheduler->capacity; ++index) {
		const struct pqcp_fleet_delivery_record *record =
			&scheduler->records[index];

		audit->inspected_records++;
		if (!record->occupied) {
			if (!bytes_zero(
				    (const uint8_t *)record,
				    sizeof(*record))) {
				audit_mark(
					audit,
					PQCP_FLEET_DELIVERY_AUDIT_STORAGE,
					index, record->artifact_id);
			}
			continue;
		}
		audit->occupied_records++;
		if (record_structure_validate(record) != 0) {
			audit_mark(
				audit,
				PQCP_FLEET_DELIVERY_AUDIT_SCHEMA |
				PQCP_FLEET_DELIVERY_AUDIT_STATE |
				PQCP_FLEET_DELIVERY_AUDIT_TIME |
				PQCP_FLEET_DELIVERY_AUDIT_CHUNK |
				PQCP_FLEET_DELIVERY_AUDIT_LEASE |
				PQCP_FLEET_DELIVERY_AUDIT_RETRY |
				PQCP_FLEET_DELIVERY_AUDIT_TERMINAL,
				index, record->artifact_id);
		}
		if (pqcp_fleet_delivery_record_verify(record) != 0) {
			audit_mark(
				audit,
				PQCP_FLEET_DELIVERY_AUDIT_RECORD_HASH,
				index, record->artifact_id);
		}
		if (record->committed_bytes >
		    UINT64_MAX - committed_bytes) {
			audit_mark(
				audit,
				PQCP_FLEET_DELIVERY_AUDIT_OVERFLOW,
				index, record->artifact_id);
		} else {
			committed_bytes +=
				record->committed_bytes;
		}
		if (pqcp_fleet_delivery_state_terminal(
			    record->state)) {
			audit->terminal_records++;
		}
		switch (record->state) {
		case PQCP_FLEET_DELIVERY_DELIVERED:
			audit->recomputed_delivered_count++;
			break;
		case PQCP_FLEET_DELIVERY_FAILED:
		case PQCP_FLEET_DELIVERY_DEPENDENCY_FAILED:
		case PQCP_FLEET_DELIVERY_CONFLICT:
			audit->recomputed_failed_count++;
			break;
		case PQCP_FLEET_DELIVERY_CANCELLED:
			audit->recomputed_cancelled_count++;
			break;
		case PQCP_FLEET_DELIVERY_EXPIRED:
			audit->recomputed_expired_count++;
			break;
		default:
			break;
		}
		if (record->dependency_artifact_id !=
			    PQCP_FLEET_DELIVERY_NO_DEPENDENCY &&
		    record_index_by_artifact(
			    scheduler,
			    record->dependency_artifact_id) < 0) {
			audit_mark(
				audit,
				PQCP_FLEET_DELIVERY_AUDIT_DEPENDENCY,
				index, record->artifact_id);
		}
		if (dependency_cycle_from(scheduler, record)) {
			audit->dependency_cycle_artifact_id =
				record->artifact_id;
			audit_mark(
				audit,
				PQCP_FLEET_DELIVERY_AUDIT_DEPENDENCY,
				index, record->artifact_id);
		}
		for (size_t other = index + 1U;
		     other < scheduler->capacity; ++other) {
			const struct pqcp_fleet_delivery_record
				*candidate =
				&scheduler->records[other];

			if (!candidate->occupied) {
				continue;
			}
			if (candidate->artifact_id ==
			    record->artifact_id) {
				audit->duplicate_artifact_id =
					record->artifact_id;
				audit_mark(
					audit,
					PQCP_FLEET_DELIVERY_AUDIT_DUPLICATE,
					index, record->artifact_id);
			}
			if (candidate->message_id ==
				    record->message_id &&
			    candidate->correlation_id ==
				    record->correlation_id) {
				audit->duplicate_message_id =
					record->message_id;
				audit_mark(
					audit,
					PQCP_FLEET_DELIVERY_AUDIT_DUPLICATE,
					index, record->artifact_id);
			}
			if (digest_equal(
				    candidate->idempotency_key,
				    record->idempotency_key)) {
				audit_mark(
					audit,
					PQCP_FLEET_DELIVERY_AUDIT_DUPLICATE,
					index, record->artifact_id);
			}
		}
	}
	audit->recomputed_committed_bytes =
		committed_bytes;
	if (audit->occupied_records !=
		    scheduler->occupied_count ||
	    committed_bytes != scheduler->committed_bytes ||
	    audit->recomputed_delivered_count >
		    scheduler->delivered_count ||
	    audit->recomputed_cancelled_count >
		    scheduler->cancelled_count ||
	    audit->recomputed_expired_count >
		    scheduler->expired_count) {
		audit_mark(
			audit,
			PQCP_FLEET_DELIVERY_AUDIT_COUNTER,
			0U, 0U);
	}
	ret = aggregate_digest_compute(
		scheduler, audit->aggregate_digest);
	if (ret != 0) {
		audit_mark(
			audit,
			PQCP_FLEET_DELIVERY_AUDIT_DIGEST,
			0U, 0U);
	}
	audit->consistent =
		audit->violation_mask == 0U;
	(void)k_mutex_unlock(&scheduler->lock);
	return 0;
}

const char *pqcp_fleet_delivery_state_str(
	enum pqcp_fleet_delivery_state state)
{
	switch (state) {
	case PQCP_FLEET_DELIVERY_EMPTY:
		return "empty";
	case PQCP_FLEET_DELIVERY_WAITING_DEPENDENCY:
		return "waiting_dependency";
	case PQCP_FLEET_DELIVERY_READY:
		return "ready";
	case PQCP_FLEET_DELIVERY_LEASED:
		return "leased";
	case PQCP_FLEET_DELIVERY_RETRY_WAIT:
		return "retry_wait";
	case PQCP_FLEET_DELIVERY_DELIVERED:
		return "delivered";
	case PQCP_FLEET_DELIVERY_FAILED:
		return "failed";
	case PQCP_FLEET_DELIVERY_CANCELLED:
		return "cancelled";
	case PQCP_FLEET_DELIVERY_EXPIRED:
		return "expired";
	case PQCP_FLEET_DELIVERY_DEPENDENCY_FAILED:
		return "dependency_failed";
	case PQCP_FLEET_DELIVERY_CONFLICT:
		return "conflict";
	default:
		return "invalid";
	}
}

const char *pqcp_fleet_delivery_reason_str(
	enum pqcp_fleet_delivery_terminal_reason reason)
{
	switch (reason) {
	case PQCP_FLEET_DELIVERY_REASON_NONE:
		return "none";
	case PQCP_FLEET_DELIVERY_REASON_COMPLETED:
		return "completed";
	case PQCP_FLEET_DELIVERY_REASON_CANCELLED_BY_CALLER:
		return "cancelled_by_caller";
	case PQCP_FLEET_DELIVERY_REASON_EXPIRED:
		return "expired";
	case PQCP_FLEET_DELIVERY_REASON_ATTEMPTS_EXHAUSTED:
		return "attempts_exhausted";
	case PQCP_FLEET_DELIVERY_REASON_PERMANENT_FAILURE:
		return "permanent_failure";
	case PQCP_FLEET_DELIVERY_REASON_DEPENDENCY_TERMINAL:
		return "dependency_terminal";
	case PQCP_FLEET_DELIVERY_REASON_EPOCH_STALE:
		return "epoch_stale";
	case PQCP_FLEET_DELIVERY_REASON_DIGEST_CONFLICT:
		return "digest_conflict";
	case PQCP_FLEET_DELIVERY_REASON_INVARIANT_FAILURE:
		return "invariant_failure";
	case PQCP_FLEET_DELIVERY_REASON_REMOVED:
		return "removed";
	default:
		return "invalid";
	}
}
