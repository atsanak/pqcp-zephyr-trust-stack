/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Canonical encoding, digest, and validation helpers for evidence continuity.
 */

#include "evidence_continuity_internal.h"

#define CONTINUITY_HASH_PART_MAX_BYTES 512U
#define CONTINUITY_HASH_FRAME_BYTES \
	(PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES + 8U + \
	 CONTINUITY_HASH_PART_MAX_BYTES)

struct continuity_digest_builder {
	uint8_t state[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	int error;
};

static bool text_character_valid(char value)
{
	return (value >= 'a' && value <= 'z') ||
	       (value >= 'A' && value <= 'Z') ||
	       (value >= '0' && value <= '9') ||
	       value == '-' || value == '_' || value == '.' ||
	       value == ':' || value == '/' || value == '@';
}

bool pqcp_evidence_continuity_text_valid(
	const char *value,
	size_t capacity)
{
	size_t length;

	if (value == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(value, capacity);
	if (length == 0U || length >= capacity) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		if (!text_character_valid(value[index])) {
			return false;
		}
	}
	return true;
}

bool pqcp_evidence_continuity_digest_zero(
	const uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	uint8_t accumulator = 0U;

	if (digest == NULL) {
		return true;
	}
	for (size_t index = 0U;
	     index < PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES;
	     ++index) {
		accumulator |= digest[index];
	}
	return accumulator == 0U;
}

bool pqcp_evidence_continuity_digest_equal(
	const uint8_t left[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES],
	const uint8_t right[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	uint8_t difference = 0U;

	if (left == NULL || right == NULL) {
		return false;
	}
	for (size_t index = 0U;
	     index < PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES;
	     ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

bool pqcp_evidence_continuity_event_type_valid(
	enum pqcp_evidence_continuity_event_type type)
{
	return type > PQCP_EVIDENCE_CONTINUITY_EVENT_NONE &&
	       type < PQCP_EVIDENCE_CONTINUITY_EVENT_COUNT;
}

bool pqcp_evidence_continuity_severity_valid(
	enum pqcp_evidence_continuity_severity severity)
{
	return severity >=
		       PQCP_EVIDENCE_CONTINUITY_SEVERITY_DEBUG &&
	       severity <=
		       PQCP_EVIDENCE_CONTINUITY_SEVERITY_CRITICAL;
}

bool pqcp_evidence_continuity_anchor_state_valid(
	enum pqcp_evidence_continuity_anchor_state state)
{
	return state >= PQCP_EVIDENCE_CONTINUITY_ANCHOR_BOOTSTRAP &&
	       state <= PQCP_EVIDENCE_CONTINUITY_ANCHOR_QUARANTINED;
}

uint32_t pqcp_evidence_continuity_next_generation(
	uint32_t *generation)
{
	uint32_t next;

	if (generation == NULL) {
		return 0U;
	}
	next = *generation;
	if (next == 0U || next == UINT32_MAX) {
		next = 1U;
	}
	*generation = next + 1U;
	if (*generation == 0U) {
		*generation = 1U;
	}
	return next;
}

uint64_t pqcp_evidence_continuity_add_u64(
	uint64_t left,
	uint64_t right)
{
	return UINT64_MAX - left < right ?
		UINT64_MAX : left + right;
}

int pqcp_evidence_continuity_copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	size_t length;

	if (destination == NULL || capacity < 2U ||
	    !pqcp_evidence_continuity_text_valid(source, capacity)) {
		return -EINVAL;
	}
	length = strnlen(source, capacity);
	memset(destination, 0, capacity);
	memcpy(destination, source, length);
	return 0;
}

void pqcp_evidence_continuity_write_u32(
	uint8_t output[4],
	uint32_t value)
{
	output[0] = (uint8_t)(value >> 24U);
	output[1] = (uint8_t)(value >> 16U);
	output[2] = (uint8_t)(value >> 8U);
	output[3] = (uint8_t)value;
}

void pqcp_evidence_continuity_write_u64(
	uint8_t output[8],
	uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[index] =
			(uint8_t)(value >> (56U - index * 8U));
	}
}

uint32_t pqcp_evidence_continuity_read_u32(
	const uint8_t input[4])
{
	return ((uint32_t)input[0] << 24U) |
	       ((uint32_t)input[1] << 16U) |
	       ((uint32_t)input[2] << 8U) |
	       (uint32_t)input[3];
}

uint64_t pqcp_evidence_continuity_read_u64(
	const uint8_t input[8])
{
	uint64_t value = 0U;

	for (size_t index = 0U; index < 8U; ++index) {
		value = (value << 8U) | input[index];
	}
	return value;
}

void pqcp_evidence_continuity_secure_zero(
	void *memory,
	size_t length)
{
	volatile uint8_t *bytes = memory;

	if (bytes == NULL) {
		return;
	}
	while (length != 0U) {
		*bytes++ = 0U;
		--length;
	}
}

int pqcp_evidence_continuity_hash(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	return pqcp_fleet_sha256(input, input_length, output);
}

static void digest_builder_init(
	struct continuity_digest_builder *builder,
	const char *domain)
{
	size_t length;

	memset(builder, 0, sizeof(*builder));
	if (domain == NULL) {
		builder->error = -EINVAL;
		return;
	}
	length = strlen(domain);
	if (length == 0U ||
	    length > CONTINUITY_HASH_PART_MAX_BYTES) {
		builder->error = -EINVAL;
		return;
	}
	builder->error = pqcp_evidence_continuity_hash(
		(const uint8_t *)domain, length, builder->state);
}

static void digest_builder_add(
	struct continuity_digest_builder *builder,
	const void *value,
	size_t length)
{
	uint8_t frame[CONTINUITY_HASH_FRAME_BYTES];

	if (builder == NULL || builder->error != 0) {
		return;
	}
	if ((value == NULL && length != 0U) ||
	    length > CONTINUITY_HASH_PART_MAX_BYTES) {
		builder->error = -E2BIG;
		return;
	}
	memcpy(frame, builder->state, sizeof(builder->state));
	pqcp_evidence_continuity_write_u64(
		frame + sizeof(builder->state), length);
	if (length != 0U) {
		memcpy(frame + sizeof(builder->state) + 8U,
		       value, length);
	}
	builder->error = pqcp_evidence_continuity_hash(
		frame, sizeof(builder->state) + 8U + length,
		builder->state);
	pqcp_evidence_continuity_secure_zero(
		frame, sizeof(frame));
}

static void digest_builder_u32(
	struct continuity_digest_builder *builder,
	uint32_t value)
{
	uint8_t encoded[4];

	pqcp_evidence_continuity_write_u32(encoded, value);
	digest_builder_add(builder, encoded, sizeof(encoded));
}

static void digest_builder_i32(
	struct continuity_digest_builder *builder,
	int32_t value)
{
	digest_builder_u32(builder, (uint32_t)value);
}

static void digest_builder_u64(
	struct continuity_digest_builder *builder,
	uint64_t value)
{
	uint8_t encoded[8];

	pqcp_evidence_continuity_write_u64(encoded, value);
	digest_builder_add(builder, encoded, sizeof(encoded));
}

static void digest_builder_bool(
	struct continuity_digest_builder *builder,
	bool value)
{
	const uint8_t encoded = value ? 1U : 0U;

	digest_builder_add(builder, &encoded, sizeof(encoded));
}

static void digest_builder_text(
	struct continuity_digest_builder *builder,
	const char *value,
	size_t capacity)
{
	size_t length;

	if (value == NULL) {
		digest_builder_add(builder, NULL, 0U);
		return;
	}
	length = strnlen(value, capacity);
	if (length >= capacity) {
		builder->error = -EINVAL;
		return;
	}
	digest_builder_add(builder, value, length);
}

static int digest_builder_finish(
	struct continuity_digest_builder *builder,
	uint8_t output[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	if (builder == NULL || output == NULL) {
		return -EINVAL;
	}
	/* Read the error BEFORE the builder is zeroed. Returning builder->error
	 * after the wipe reported every hashing failure as success and left the
	 * output unwritten (fail-open). */
	int error = builder->error;

	if (error != 0) {
		pqcp_evidence_continuity_secure_zero(
			builder, sizeof(*builder));
		return error;
	}
	memcpy(output, builder->state, sizeof(builder->state));
	pqcp_evidence_continuity_secure_zero(
		builder, sizeof(*builder));
	return 0;
}

int pqcp_evidence_continuity_hash_parts(
	const char *domain,
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t count,
	uint8_t output[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	struct continuity_digest_builder builder;

	if (domain == NULL || output == NULL ||
	    (count != 0U && (parts == NULL || lengths == NULL))) {
		return -EINVAL;
	}
	digest_builder_init(&builder, domain);
	for (size_t index = 0U; index < count; ++index) {
		digest_builder_add(
			&builder, parts[index], lengths[index]);
	}
	return digest_builder_finish(&builder, output);
}

int pqcp_evidence_continuity_anchor_digest(
	const struct pqcp_evidence_continuity_anchor *anchor,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	struct continuity_digest_builder builder;

	if (anchor == NULL || digest == NULL) {
		return -EINVAL;
	}
	digest_builder_init(
		&builder, "PQCP-EVIDENCE-CONTINUITY-ANCHOR-V1");
	digest_builder_u32(&builder, anchor->schema_version);
	digest_builder_u32(&builder, anchor->generation);
	digest_builder_u32(&builder, (uint32_t)anchor->state);
	digest_builder_u32(&builder, anchor->flags);
	digest_builder_text(
		&builder, anchor->device_id, sizeof(anchor->device_id));
	digest_builder_text(
		&builder, anchor->domain_id, sizeof(anchor->domain_id));
	digest_builder_u64(&builder, anchor->monotonic_counter);
	digest_builder_u64(&builder, anchor->boot_epoch);
	digest_builder_u64(&builder, anchor->session_id);
	digest_builder_u64(&builder, anchor->first_event_sequence);
	digest_builder_u64(&builder, anchor->last_event_sequence);
	digest_builder_u64(
		&builder, anchor->latest_checkpoint_sequence);
	digest_builder_u64(&builder, anchor->created_at_ms);
	digest_builder_u64(&builder, anchor->updated_at_ms);
	digest_builder_u64(&builder, anchor->closed_at_ms);
	digest_builder_u64(&builder, anchor->policy_epoch);
	digest_builder_u64(&builder, anchor->firmware_epoch);
	digest_builder_u64(&builder, anchor->witness_epoch);
	digest_builder_u64(&builder, anchor->replication_epoch);
	digest_builder_u64(&builder, anchor->compaction_epoch);
	digest_builder_u64(&builder, anchor->recovery_epoch);
	digest_builder_add(
		&builder, anchor->device_digest,
		sizeof(anchor->device_digest));
	digest_builder_add(
		&builder, anchor->firmware_digest,
		sizeof(anchor->firmware_digest));
	digest_builder_add(
		&builder, anchor->policy_digest,
		sizeof(anchor->policy_digest));
	digest_builder_add(
		&builder, anchor->previous_anchor_digest,
		sizeof(anchor->previous_anchor_digest));
	digest_builder_add(
		&builder, anchor->journal_root,
		sizeof(anchor->journal_root));
	digest_builder_add(
		&builder, anchor->checkpoint_root,
		sizeof(anchor->checkpoint_root));
	digest_builder_add(
		&builder, anchor->witness_root,
		sizeof(anchor->witness_root));
	digest_builder_add(
		&builder, anchor->replication_root,
		sizeof(anchor->replication_root));
	digest_builder_add(
		&builder, anchor->compaction_root,
		sizeof(anchor->compaction_root));
	digest_builder_add(
		&builder, anchor->recovery_root,
		sizeof(anchor->recovery_root));
	digest_builder_bool(&builder, anchor->occupied);
	return digest_builder_finish(&builder, digest);
}

int pqcp_evidence_continuity_session_digest(
	const struct pqcp_evidence_continuity_boot_session *session,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	struct continuity_digest_builder builder;

	if (session == NULL || digest == NULL) {
		return -EINVAL;
	}
	digest_builder_init(
		&builder, "PQCP-EVIDENCE-CONTINUITY-SESSION-V1");
	digest_builder_u32(&builder, session->schema_version);
	digest_builder_u32(&builder, session->generation);
	digest_builder_u32(&builder, (uint32_t)session->state);
	digest_builder_u32(&builder, session->flags);
	digest_builder_text(
		&builder, session->device_id,
		sizeof(session->device_id));
	digest_builder_text(
		&builder, session->domain_id,
		sizeof(session->domain_id));
	digest_builder_u64(&builder, session->boot_epoch);
	digest_builder_u64(&builder, session->session_id);
	digest_builder_u64(&builder, session->opened_at_ms);
	digest_builder_u64(&builder, session->closed_at_ms);
	digest_builder_u64(&builder, session->first_event_sequence);
	digest_builder_u64(&builder, session->last_event_sequence);
	digest_builder_u64(&builder, session->event_count);
	digest_builder_u64(&builder, session->rejected_event_count);
	digest_builder_u64(&builder, session->policy_epoch);
	digest_builder_u64(&builder, session->firmware_epoch);
	digest_builder_add(
		&builder, session->boot_nonce_digest,
		sizeof(session->boot_nonce_digest));
	digest_builder_add(
		&builder, session->device_digest,
		sizeof(session->device_digest));
	digest_builder_add(
		&builder, session->firmware_digest,
		sizeof(session->firmware_digest));
	digest_builder_add(
		&builder, session->policy_digest,
		sizeof(session->policy_digest));
	digest_builder_add(
		&builder, session->inherited_anchor_digest,
		sizeof(session->inherited_anchor_digest));
	digest_builder_add(
		&builder, session->journal_root,
		sizeof(session->journal_root));
	digest_builder_add(
		&builder, session->terminal_evidence_digest,
		sizeof(session->terminal_evidence_digest));
	digest_builder_bool(&builder, session->require_witness);
	digest_builder_bool(&builder, session->require_replication);
	digest_builder_bool(&builder, session->occupied);
	return digest_builder_finish(&builder, digest);
}

int pqcp_evidence_continuity_event_digest(
	const struct pqcp_evidence_continuity_event *event,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	struct continuity_digest_builder builder;

	if (event == NULL || digest == NULL ||
	    event->detail_length > sizeof(event->detail)) {
		return -EINVAL;
	}
	digest_builder_init(
		&builder, "PQCP-EVIDENCE-CONTINUITY-EVENT-V1");
	digest_builder_u32(&builder, event->schema_version);
	digest_builder_u32(&builder, event->generation);
	digest_builder_u64(&builder, event->boot_epoch);
	digest_builder_u64(&builder, event->session_id);
	digest_builder_u64(&builder, event->sequence);
	digest_builder_u64(&builder, event->timestamp_ms);
	digest_builder_u64(&builder, event->correlation_id);
	digest_builder_u64(&builder, event->policy_epoch);
	digest_builder_u64(&builder, event->firmware_epoch);
	digest_builder_u32(&builder, (uint32_t)event->type);
	digest_builder_u32(&builder, (uint32_t)event->severity);
	digest_builder_u32(&builder, event->flags);
	digest_builder_i32(&builder, event->result);
	digest_builder_u32(&builder, event->reason);
	digest_builder_text(
		&builder, event->component,
		sizeof(event->component));
	digest_builder_text(
		&builder, event->subject,
		sizeof(event->subject));
	digest_builder_u32(&builder, event->detail_length);
	digest_builder_add(
		&builder, event->detail, event->detail_length);
	digest_builder_add(
		&builder, event->payload_digest,
		sizeof(event->payload_digest));
	digest_builder_add(
		&builder, event->previous_digest,
		sizeof(event->previous_digest));
	digest_builder_bool(&builder, event->occupied);
	return digest_builder_finish(&builder, digest);
}

int pqcp_evidence_continuity_checkpoint_digest(
	const struct pqcp_evidence_continuity_checkpoint *checkpoint,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	struct continuity_digest_builder builder;

	if (checkpoint == NULL || digest == NULL) {
		return -EINVAL;
	}
	digest_builder_init(
		&builder, "PQCP-EVIDENCE-CONTINUITY-CHECKPOINT-V1");
	digest_builder_u32(&builder, checkpoint->schema_version);
	digest_builder_u32(&builder, checkpoint->generation);
	digest_builder_u32(&builder, (uint32_t)checkpoint->state);
	digest_builder_u32(&builder, checkpoint->flags);
	digest_builder_text(
		&builder, checkpoint->device_id,
		sizeof(checkpoint->device_id));
	digest_builder_text(
		&builder, checkpoint->domain_id,
		sizeof(checkpoint->domain_id));
	digest_builder_u64(
		&builder, checkpoint->checkpoint_sequence);
	digest_builder_u64(&builder, checkpoint->boot_epoch);
	digest_builder_u64(&builder, checkpoint->session_id);
	digest_builder_u64(
		&builder, checkpoint->first_event_sequence);
	digest_builder_u64(
		&builder, checkpoint->last_event_sequence);
	digest_builder_u64(&builder, checkpoint->event_count);
	digest_builder_u64(&builder, checkpoint->created_at_ms);
	digest_builder_u64(&builder, checkpoint->sealed_at_ms);
	digest_builder_u64(&builder, checkpoint->policy_epoch);
	digest_builder_u64(&builder, checkpoint->firmware_epoch);
	digest_builder_u64(
		&builder, checkpoint->monotonic_counter);
	digest_builder_u32(
		&builder, checkpoint->security_event_count);
	digest_builder_u32(
		&builder, checkpoint->recovery_event_count);
	digest_builder_u32(
		&builder, checkpoint->witness_receipt_count);
	digest_builder_u32(
		&builder, checkpoint->replica_ack_count);
	digest_builder_add(
		&builder, checkpoint->previous_checkpoint_digest,
		sizeof(checkpoint->previous_checkpoint_digest));
	digest_builder_add(
		&builder, checkpoint->anchor_digest,
		sizeof(checkpoint->anchor_digest));
	digest_builder_add(
		&builder, checkpoint->event_root,
		sizeof(checkpoint->event_root));
	digest_builder_add(
		&builder, checkpoint->witness_root,
		sizeof(checkpoint->witness_root));
	digest_builder_add(
		&builder, checkpoint->replica_root,
		sizeof(checkpoint->replica_root));
	digest_builder_bool(&builder, checkpoint->occupied);
	return digest_builder_finish(&builder, digest);
}

int pqcp_evidence_continuity_receipt_digest(
	const struct pqcp_evidence_continuity_witness_receipt *receipt,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES])
{
	struct continuity_digest_builder builder;
	uint8_t signature_digest[
		PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];

	if (receipt == NULL || digest == NULL ||
	    receipt->signature_length > sizeof(receipt->signature)) {
		return -EINVAL;
	}
	if (pqcp_evidence_continuity_hash(
		    receipt->signature, receipt->signature_length,
		    signature_digest) != 0) {
		return -EIO;
	}
	digest_builder_init(
		&builder, "PQCP-EVIDENCE-CONTINUITY-RECEIPT-V1");
	digest_builder_u32(&builder, receipt->schema_version);
	digest_builder_u32(&builder, receipt->generation);
	digest_builder_u32(&builder, (uint32_t)receipt->status);
	digest_builder_text(
		&builder, receipt->witness_id,
		sizeof(receipt->witness_id));
	digest_builder_text(
		&builder, receipt->jurisdiction,
		sizeof(receipt->jurisdiction));
	digest_builder_text(
		&builder, receipt->failure_domain,
		sizeof(receipt->failure_domain));
	digest_builder_u64(&builder, receipt->receipt_sequence);
	digest_builder_u64(&builder, receipt->checkpoint_sequence);
	digest_builder_u64(&builder, receipt->monotonic_counter);
	digest_builder_u64(&builder, receipt->observed_at_ms);
	digest_builder_u64(&builder, receipt->expires_at_ms);
	digest_builder_u64(&builder, receipt->policy_epoch);
	digest_builder_u64(&builder, receipt->witness_epoch);
	digest_builder_u32(&builder, receipt->weight);
	digest_builder_u32(&builder, receipt->signature_length);
	digest_builder_add(
		&builder, receipt->challenge_digest,
		sizeof(receipt->challenge_digest));
	digest_builder_add(
		&builder, receipt->checkpoint_digest,
		sizeof(receipt->checkpoint_digest));
	digest_builder_add(
		&builder, receipt->previous_receipt_digest,
		sizeof(receipt->previous_receipt_digest));
	digest_builder_add(
		&builder, signature_digest, sizeof(signature_digest));
	digest_builder_bool(&builder, receipt->verified);
	digest_builder_bool(&builder, receipt->occupied);
	pqcp_evidence_continuity_secure_zero(
		signature_digest, sizeof(signature_digest));
	return digest_builder_finish(&builder, digest);
}

int pqcp_evidence_continuity_record_encode(
	const struct pqcp_evidence_continuity_record_header *header,
	const uint8_t *payload,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	size_t total;
	uint8_t calculated[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];

	if (header == NULL || output == NULL ||
	    output_length == NULL ||
	    (payload == NULL && header->payload_length != 0U)) {
		return -EINVAL;
	}
	total = PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES +
		header->payload_length;
	if (output_capacity < total) {
		return -ENOSPC;
	}
	if (pqcp_evidence_continuity_hash(
		    payload, header->payload_length, calculated) != 0 ||
	    !pqcp_evidence_continuity_digest_equal(
		    calculated, header->payload_digest)) {
		pqcp_evidence_continuity_secure_zero(
			calculated, sizeof(calculated));
		return -EBADMSG;
	}
	memset(output, 0, total);
	pqcp_evidence_continuity_write_u32(output, header->magic);
	pqcp_evidence_continuity_write_u32(
		output + 4U, header->schema_version);
	pqcp_evidence_continuity_write_u32(
		output + 8U, (uint32_t)header->object);
	pqcp_evidence_continuity_write_u32(
		output + 12U, header->slot);
	pqcp_evidence_continuity_write_u64(
		output + 16U, header->generation);
	pqcp_evidence_continuity_write_u64(
		output + 24U, header->monotonic_counter);
	pqcp_evidence_continuity_write_u32(
		output + 32U, header->payload_length);
	pqcp_evidence_continuity_write_u32(
		output + 36U, header->flags);
	memcpy(output + 40U, header->payload_digest,
	       sizeof(header->payload_digest));
	if (header->payload_length != 0U) {
		memcpy(output +
			       PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES,
		       payload, header->payload_length);
	}
	*output_length = total;
	pqcp_evidence_continuity_secure_zero(
		calculated, sizeof(calculated));
	return 0;
}

int pqcp_evidence_continuity_record_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_evidence_continuity_record_header *header,
	const uint8_t **payload)
{
	uint8_t calculated[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
	size_t expected;

	if (input == NULL || header == NULL || payload == NULL ||
	    input_length <
		    PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES) {
		return -EINVAL;
	}
	memset(header, 0, sizeof(*header));
	header->magic = pqcp_evidence_continuity_read_u32(input);
	header->schema_version =
		pqcp_evidence_continuity_read_u32(input + 4U);
	header->object =
		(enum pqcp_evidence_continuity_object)
			pqcp_evidence_continuity_read_u32(input + 8U);
	header->slot =
		pqcp_evidence_continuity_read_u32(input + 12U);
	header->generation =
		pqcp_evidence_continuity_read_u64(input + 16U);
	header->monotonic_counter =
		pqcp_evidence_continuity_read_u64(input + 24U);
	header->payload_length =
		pqcp_evidence_continuity_read_u32(input + 32U);
	header->flags =
		pqcp_evidence_continuity_read_u32(input + 36U);
	memcpy(header->payload_digest, input + 40U,
	       sizeof(header->payload_digest));
	expected = PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES +
		header->payload_length;
	if (header->magic !=
		    PQCP_EVIDENCE_CONTINUITY_RECORD_MAGIC ||
	    header->schema_version !=
		    PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION ||
	    header->object <=
		    PQCP_EVIDENCE_CONTINUITY_OBJECT_NONE ||
	    header->object >=
		    PQCP_EVIDENCE_CONTINUITY_OBJECT_COUNT ||
	    header->generation == 0U ||
	    (header->flags &
	     PQCP_EVIDENCE_CONTINUITY_RECORD_COMMITTED) == 0U ||
	    expected != input_length) {
		return -EBADMSG;
	}
	*payload = input +
		PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES;
	if (pqcp_evidence_continuity_hash(
		    *payload, header->payload_length,
		    calculated) != 0 ||
	    !pqcp_evidence_continuity_digest_equal(
		    calculated, header->payload_digest)) {
		pqcp_evidence_continuity_secure_zero(
			calculated, sizeof(calculated));
		return -EBADMSG;
	}
	pqcp_evidence_continuity_secure_zero(
		calculated, sizeof(calculated));
	return 0;
}

static int encode_record_header(
	const struct pqcp_evidence_continuity_record_header *header,
	uint8_t output[
		PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES])
{
	if (header == NULL || output == NULL) {
		return -EINVAL;
	}
	memset(
		output, 0,
		PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES);
	pqcp_evidence_continuity_write_u32(output, header->magic);
	pqcp_evidence_continuity_write_u32(
		output + 4U, header->schema_version);
	pqcp_evidence_continuity_write_u32(
		output + 8U, (uint32_t)header->object);
	pqcp_evidence_continuity_write_u32(
		output + 12U, header->slot);
	pqcp_evidence_continuity_write_u64(
		output + 16U, header->generation);
	pqcp_evidence_continuity_write_u64(
		output + 24U, header->monotonic_counter);
	pqcp_evidence_continuity_write_u32(
		output + 32U, header->payload_length);
	pqcp_evidence_continuity_write_u32(
		output + 36U, header->flags);
	memcpy(output + 40U, header->payload_digest,
	       sizeof(header->payload_digest));
	return 0;
}

int pqcp_evidence_continuity_store_record(
	const struct pqcp_evidence_continuity_store *store,
	enum pqcp_evidence_continuity_object object,
	uint32_t slot,
	uint64_t generation,
	uint64_t monotonic_counter,
	const uint8_t *payload,
	size_t payload_length)
{
	struct pqcp_evidence_continuity_record_header header;
	uint8_t encoded[
		PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES];
	int ret;

	if (store == NULL || store->write == NULL ||
	    store->erase == NULL || store->sync == NULL ||
	    object <= PQCP_EVIDENCE_CONTINUITY_OBJECT_NONE ||
	    object >= PQCP_EVIDENCE_CONTINUITY_OBJECT_COUNT ||
	    generation == 0U ||
	    (payload == NULL && payload_length != 0U) ||
	    payload_length > UINT32_MAX ||
	    (store->maximum_record_bytes != 0U &&
	     payload_length +
		     PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES >
		     store->maximum_record_bytes)) {
		return -EINVAL;
	}
	memset(&header, 0, sizeof(header));
	header.magic = PQCP_EVIDENCE_CONTINUITY_RECORD_MAGIC;
	header.schema_version =
		PQCP_EVIDENCE_CONTINUITY_SCHEMA_VERSION;
	header.object = object;
	header.slot = slot;
	header.generation = generation;
	header.monotonic_counter = monotonic_counter;
	header.payload_length = (uint32_t)payload_length;
	ret = pqcp_evidence_continuity_hash(
		payload, payload_length, header.payload_digest);
	if (ret != 0) {
		return ret;
	}
	ret = encode_record_header(&header, encoded);
	if (ret != 0) {
		goto out;
	}
	ret = store->erase(store->context, object, slot);
	if (ret != 0) {
		goto out;
	}
	ret = store->write(
		store->context, object, slot, 0U,
		encoded, sizeof(encoded));
	if (ret != 0) {
		goto out;
	}
	if (payload_length != 0U) {
		ret = store->write(
			store->context, object, slot,
			sizeof(encoded), payload, payload_length);
		if (ret != 0) {
			goto out;
		}
	}
	ret = store->sync(store->context);
	if (ret != 0) {
		goto out;
	}
	header.flags = PQCP_EVIDENCE_CONTINUITY_RECORD_COMMITTED;
	ret = encode_record_header(&header, encoded);
	if (ret != 0) {
		goto out;
	}
	ret = store->write(
		store->context, object, slot, 0U,
		encoded, sizeof(encoded));
	if (ret == 0) {
		ret = store->sync(store->context);
	}
out:
	pqcp_evidence_continuity_secure_zero(
		&header, sizeof(header));
	pqcp_evidence_continuity_secure_zero(
		encoded, sizeof(encoded));
	return ret;
}

int pqcp_evidence_continuity_load_record(
	const struct pqcp_evidence_continuity_store *store,
	enum pqcp_evidence_continuity_object object,
	uint32_t slot,
	uint8_t *buffer,
	size_t buffer_capacity,
	struct pqcp_evidence_continuity_record_header *header,
	const uint8_t **payload)
{
	size_t length = 0U;
	int ret;

	if (store == NULL || store->read == NULL ||
	    buffer == NULL ||
	    buffer_capacity <
		    PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES ||
	    header == NULL || payload == NULL) {
		return -EINVAL;
	}
	ret = store->read(
		store->context, object, slot, 0U,
		buffer, buffer_capacity, &length);
	if (ret != 0) {
		return ret;
	}
	/* Never trust the backend-reported length beyond the caller buffer. */
	if (length > buffer_capacity) {
		return -EBADMSG;
	}
	ret = pqcp_evidence_continuity_record_decode(
		buffer, length, header, payload);
	if (ret != 0) {
		return ret;
	}
	if (header->object != object || header->slot != slot) {
		return -EBADMSG;
	}
	return 0;
}
