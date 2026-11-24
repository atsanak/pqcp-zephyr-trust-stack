/*
 * SPDX-License-Identifier: MIT
 *
 * Canonical sovereign-channel frame codec.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_channel_internal.h"

static size_t bounded_text_length(const char *text, size_t capacity)
{
	if (text == NULL || capacity == 0U) {
		return 0U;
	}
	return strnlen(text, capacity);
}

bool pqcp_sovereign_channel_internal_all_zero(
	const uint8_t *value,
	size_t length)
{
	uint8_t aggregate = 0U;

	if (value == NULL && length != 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate == 0U;
}

bool pqcp_sovereign_channel_internal_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if ((left == NULL || right == NULL) && length != 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

bool pqcp_sovereign_channel_internal_frame_type_valid(
	enum pqcp_sovereign_channel_frame_type type)
{
	return type >= PQCP_SOVEREIGN_CHANNEL_FRAME_BEGIN &&
	       type <= PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW;
}

uint32_t pqcp_sovereign_channel_internal_allowed_flags(
	enum pqcp_sovereign_channel_frame_type type)
{
	switch (type) {
	case PQCP_SOVEREIGN_CHANNEL_FRAME_BEGIN:
		return PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CHUNK:
		return PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_COMMIT:
		return PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CANCEL:
		return PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RESULT:
		return PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_ACK |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_REPLAYED |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_CANCELLED;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_ERROR:
		return PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_RETRYABLE;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RECEIPT:
		return PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_ACK;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW:
		return PQCP_SOVEREIGN_CHANNEL_FLAG_ACK |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_ACCEPTED |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME |
		       PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL;
	default:
		return 0U;
	}
}

int pqcp_sovereign_channel_internal_copy_text(
	char *destination,
	size_t capacity,
	const uint8_t *source,
	size_t source_length)
{
	if (destination == NULL || capacity < 2U ||
	    source == NULL || source_length == 0U ||
	    source_length >= capacity) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < source_length; ++index) {
		if (source[index] == 0U) {
			return -EBADMSG;
		}
	}
	memcpy(destination, source, source_length);
	destination[source_length] = '\0';
	return 0;
}

static int writer_reserve(
	struct pqcp_sovereign_channel_wire_writer *writer,
	size_t length,
	uint8_t **output)
{
	if (writer == NULL || output == NULL ||
	    length > writer->capacity ||
	    writer->offset > writer->capacity - length) {
		return -ENOSPC;
	}
	*output = writer->output + writer->offset;
	writer->offset += length;
	return 0;
}

static int writer_field(
	struct pqcp_sovereign_channel_wire_writer *writer,
	uint16_t id,
	uint16_t flags,
	const uint8_t *value,
	size_t length)
{
	uint8_t *header;
	uint8_t *body;
	int ret;

	if (writer == NULL || id == 0U ||
	    id <= writer->last_field ||
	    (flags & ~PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) != 0U ||
	    (value == NULL && length != 0U) ||
	    length > UINT32_MAX ||
	    writer->field_count == UINT16_MAX) {
		return -EINVAL;
	}
	ret = writer_reserve(
		writer, PQCP_SOVEREIGN_CHANNEL_FIELD_HEADER_BYTES,
		&header);
	if (ret != 0) {
		return ret;
	}
	pqcp_runtime_internal_write_u16(header, id);
	pqcp_runtime_internal_write_u16(header + 2U, flags);
	pqcp_runtime_internal_write_u32(
		header + 4U, (uint32_t)length);
	ret = writer_reserve(writer, length, &body);
	if (ret != 0) {
		writer->offset -=
			PQCP_SOVEREIGN_CHANNEL_FIELD_HEADER_BYTES;
		return ret;
	}
	if (length != 0U) {
		memcpy(body, value, length);
	}
	writer->last_field = id;
	writer->field_count++;
	return 0;
}

static int writer_u32(
	struct pqcp_sovereign_channel_wire_writer *writer,
	uint16_t id,
	uint32_t value)
{
	uint8_t encoded[4];

	pqcp_runtime_internal_write_u32(encoded, value);
	return writer_field(
		writer, id,
		PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY,
		encoded, sizeof(encoded));
}

static int writer_u64(
	struct pqcp_sovereign_channel_wire_writer *writer,
	uint16_t id,
	uint64_t value)
{
	uint8_t encoded[8];

	pqcp_runtime_internal_write_u64(encoded, value);
	return writer_field(
		writer, id,
		PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY,
		encoded, sizeof(encoded));
}

static int writer_bytes(
	struct pqcp_sovereign_channel_wire_writer *writer,
	uint16_t id,
	const uint8_t *value,
	size_t length,
	bool mandatory)
{
	return writer_field(
		writer, id,
		mandatory ?
			PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY : 0U,
		value, length);
}

static int reader_next(
	struct pqcp_sovereign_channel_wire_reader *reader,
	struct pqcp_sovereign_channel_wire_field *field)
{
	const uint8_t *header;
	uint32_t length;

	if (reader == NULL || field == NULL ||
	    reader->remaining_fields == 0U ||
	    reader->offset > reader->length ||
	    reader->length - reader->offset <
		    PQCP_SOVEREIGN_CHANNEL_FIELD_HEADER_BYTES) {
		return -EBADMSG;
	}
	header = reader->input + reader->offset;
	field->id = pqcp_runtime_internal_read_u16(header);
	field->flags =
		pqcp_runtime_internal_read_u16(header + 2U);
	length = pqcp_runtime_internal_read_u32(header + 4U);
	if (field->id == 0U ||
	    field->id <= reader->last_field ||
	    (field->flags &
	     ~PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) != 0U) {
		return -EBADMSG;
	}
	reader->offset +=
		PQCP_SOVEREIGN_CHANNEL_FIELD_HEADER_BYTES;
	if (length > reader->length ||
	    reader->offset > reader->length - length) {
		return -EBADMSG;
	}
	field->length = length;
	field->value = reader->input + reader->offset;
	reader->offset += length;
	reader->remaining_fields--;
	reader->last_field = field->id;
	return 0;
}

static int field_u32(
	const struct pqcp_sovereign_channel_wire_field *field,
	uint32_t *value)
{
	if (field == NULL || value == NULL ||
	    field->length != 4U) {
		return -EBADMSG;
	}
	*value = pqcp_runtime_internal_read_u32(field->value);
	return 0;
}

static int field_u64(
	const struct pqcp_sovereign_channel_wire_field *field,
	uint64_t *value)
{
	if (field == NULL || value == NULL ||
	    field->length != 8U) {
		return -EBADMSG;
	}
	*value = pqcp_runtime_internal_read_u64(field->value);
	return 0;
}

static int encode_begin(
	struct pqcp_sovereign_channel_wire_writer *writer,
	const struct pqcp_sovereign_channel_frame *frame)
{
	const struct pqcp_sovereign_channel_begin *begin =
		&frame->body.begin;
	uint8_t handle[PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES];
	size_t principal_length;
	size_t tenant_length;
	size_t label_length;
	uint32_t options = 0U;
	int ret;

	principal_length = bounded_text_length(
		begin->principal_id, sizeof(begin->principal_id));
	tenant_length = bounded_text_length(
		begin->tenant_id, sizeof(begin->tenant_id));
	label_length = bounded_text_length(
		begin->key_spec.label,
		sizeof(begin->key_spec.label));
	if (principal_length == 0U ||
	    principal_length >= sizeof(begin->principal_id) ||
	    tenant_length == 0U ||
	    tenant_length >= sizeof(begin->tenant_id) ||
	    label_length >= sizeof(begin->key_spec.label) ||
	    begin->operation <=
		    PQCP_CRYPTO_BROKER_OPERATION_NONE ||
	    begin->operation >=
		    PQCP_CRYPTO_BROKER_OPERATION_COUNT ||
	    begin->submitted_at_ms == 0U ||
	    begin->deadline_ms < begin->submitted_at_ms ||
	    begin->input_length > PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    begin->aux_input_length >
		    PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    begin->context_length >
		    PQCP_RUNTIME_MAX_CONTEXT_BYTES ||
	    pqcp_sovereign_channel_internal_all_zero(
		    begin->capability,
		    sizeof(begin->capability)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    begin->content_digest,
		    sizeof(begin->content_digest))) {
		return -EINVAL;
	}
	if (begin->key_spec.persistent) {
		options |= PQCP_SOVEREIGN_CHANNEL_KEY_PERSISTENT;
	}
	if (begin->key_spec.exportable_public) {
		options |=
			PQCP_SOVEREIGN_CHANNEL_KEY_EXPORTABLE_PUBLIC;
	}
	ret = writer_bytes(
		writer, PQCP_SOVEREIGN_CHANNEL_FIELD_PRINCIPAL_ID,
		(const uint8_t *)begin->principal_id,
		principal_length, true);
	if (ret == 0) {
		ret = writer_bytes(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_TENANT_ID,
			(const uint8_t *)begin->tenant_id,
			tenant_length, true);
	}
	if (ret == 0) {
		ret = writer_bytes(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_CAPABILITY,
			begin->capability,
			sizeof(begin->capability), true);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_OPERATION,
			(uint32_t)begin->operation);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_SUBMITTED_AT,
			begin->submitted_at_ms);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_DEADLINE,
			begin->deadline_ms);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_REQUEST_FLAGS,
			begin->request_flags);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_LEVEL,
			begin->level);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_FAMILY,
			(uint32_t)begin->key_spec.family);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_LEVEL,
			begin->key_spec.level);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_USAGE,
			begin->key_spec.usage);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_EXPIRES_AT,
			begin->key_spec.expires_at_ms);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_OPTIONS,
			options);
	}
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_LABEL,
			(const uint8_t *)begin->key_spec.label,
			label_length, true);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_channel_internal_encode_handle(
			&begin->primary_key, handle);
	}
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_PRIMARY_KEY,
			handle, sizeof(handle), true);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_channel_internal_encode_handle(
			&begin->secondary_key, handle);
	}
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_SECONDARY_KEY,
			handle, sizeof(handle), true);
	}
	pqcp_runtime_secure_zero(handle, sizeof(handle));
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_INPUT_LENGTH,
			begin->input_length);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_AUX_LENGTH,
			begin->aux_input_length);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_CONTEXT_LENGTH,
			begin->context_length);
	}
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST,
			begin->content_digest,
			sizeof(begin->content_digest), true);
	}
	if (ret == 0 &&
	    (frame->flags &
	     PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME) != 0U) {
		if (!begin->has_resume_token ||
		    pqcp_sovereign_channel_internal_all_zero(
			    begin->resume_token,
			    sizeof(begin->resume_token))) {
			return -EINVAL;
		}
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_RESUME_TOKEN,
			begin->resume_token,
			sizeof(begin->resume_token), true);
	}
	return ret;
}

static int encode_chunk(
	struct pqcp_sovereign_channel_wire_writer *writer,
	const struct pqcp_sovereign_channel_chunk *chunk)
{
	int ret;

	if (chunk->data == NULL || chunk->data_length == 0U ||
	    chunk->data_length >
		    PQCP_SOVEREIGN_CHANNEL_MAX_FIELD_BYTES ||
	    pqcp_sovereign_channel_internal_all_zero(
		    chunk->rolling_digest,
		    sizeof(chunk->rolling_digest))) {
		return -EINVAL;
	}
	ret = writer_u64(
		writer, PQCP_SOVEREIGN_CHANNEL_FIELD_OFFSET,
		chunk->offset);
	if (ret == 0) {
		ret = writer_bytes(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_DATA,
			chunk->data, chunk->data_length, true);
	}
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_ROLLING_DIGEST,
			chunk->rolling_digest,
			sizeof(chunk->rolling_digest), true);
	}
	return ret;
}

static int encode_commit(
	struct pqcp_sovereign_channel_wire_writer *writer,
	const struct pqcp_sovereign_channel_commit *commit)
{
	int ret;

	if (pqcp_sovereign_channel_internal_all_zero(
		    commit->rolling_digest,
		    sizeof(commit->rolling_digest)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    commit->content_digest,
		    sizeof(commit->content_digest))) {
		return -EINVAL;
	}
	ret = writer_bytes(
		writer, PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST,
		commit->content_digest,
		sizeof(commit->content_digest), true);
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_ROLLING_DIGEST,
			commit->rolling_digest,
			sizeof(commit->rolling_digest), true);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_TOTAL_LENGTH,
			commit->total_length);
	}
	return ret;
}

static int encode_cancel(
	struct pqcp_sovereign_channel_wire_writer *writer,
	const struct pqcp_sovereign_channel_cancel *cancel)
{
	int ret;

	if (cancel->detail_length >
		    sizeof(cancel->detail)) {
		return -EINVAL;
	}
	ret = writer_u32(
		writer, PQCP_SOVEREIGN_CHANNEL_FIELD_ERROR_CODE,
		(uint32_t)(int32_t)cancel->error_code);
	if (ret == 0 && cancel->detail_length != 0U) {
		ret = writer_bytes(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_DETAIL,
			cancel->detail, cancel->detail_length, false);
	}
	return ret;
}

static int encode_result(
	struct pqcp_sovereign_channel_wire_writer *writer,
	const struct pqcp_sovereign_channel_frame *frame)
{
	const struct pqcp_sovereign_channel_result *result =
		&frame->body.result;
	uint8_t handle[PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES];
	uint8_t metadata[PQCP_SOVEREIGN_CHANNEL_METADATA_BYTES];
	bool acknowledgement =
		(frame->flags & PQCP_SOVEREIGN_CHANNEL_FLAG_ACK) != 0U;
	int ret;

	if (acknowledgement) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST,
			result->content_digest,
			sizeof(result->content_digest), true);
		if (ret == 0) {
			ret = writer_u64(
				writer,
				PQCP_SOVEREIGN_CHANNEL_FIELD_ACK_OFFSET,
				result->ack_offset);
		}
		return ret;
	}
	if ((result->data == NULL && result->data_length != 0U) ||
	    result->data_length >
		    PQCP_SOVEREIGN_CHANNEL_MAX_FIELD_BYTES ||
	    result->offset > result->total_length ||
	    result->data_length >
		    result->total_length - result->offset ||
	    pqcp_sovereign_channel_internal_all_zero(
		    result->content_digest,
		    sizeof(result->content_digest))) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_channel_internal_encode_handle(
		&result->primary_key, handle);
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_PRIMARY_KEY,
			handle, sizeof(handle), true);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_channel_internal_encode_handle(
			&result->secondary_key, handle);
	}
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_SECONDARY_KEY,
			handle, sizeof(handle), true);
	}
	pqcp_runtime_secure_zero(handle, sizeof(handle));
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST,
			result->content_digest,
			sizeof(result->content_digest), true);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_OFFSET,
			result->offset);
	}
	if (ret == 0 && result->data_length != 0U) {
		ret = writer_bytes(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_DATA,
			result->data, result->data_length, true);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_TOTAL_LENGTH,
			result->total_length);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_RESULT_CODE,
			(uint32_t)(int32_t)result->result_code);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_RESULT_FLAGS,
			result->result_flags);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_channel_internal_encode_metadata(
			&result->metadata, metadata);
	}
	if (ret == 0) {
		ret = writer_bytes(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_METADATA,
			metadata, sizeof(metadata), true);
	}
	pqcp_runtime_secure_zero(metadata, sizeof(metadata));
	return ret;
}

static int encode_error(
	struct pqcp_sovereign_channel_wire_writer *writer,
	const struct pqcp_sovereign_channel_error *error)
{
	int ret;

	if (error->stage <= PQCP_SOVEREIGN_CHANNEL_STAGE_NONE ||
	    error->stage > PQCP_SOVEREIGN_CHANNEL_STAGE_RESUME ||
	    error->detail_length > sizeof(error->detail)) {
		return -EINVAL;
	}
	ret = writer_u32(
		writer, PQCP_SOVEREIGN_CHANNEL_FIELD_ERROR_CODE,
		(uint32_t)(int32_t)error->error_code);
	if (ret == 0 && error->detail_length != 0U) {
		ret = writer_bytes(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_DETAIL,
			error->detail, error->detail_length, false);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_ERROR_STAGE,
			(uint32_t)error->stage);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_RETRY_AFTER,
			error->retry_after_ms);
	}
	return ret;
}

static int encode_receipt(
	struct pqcp_sovereign_channel_wire_writer *writer,
	const struct pqcp_sovereign_channel_frame *frame)
{
	const struct pqcp_sovereign_channel_receipt_frame *receipt =
		&frame->body.receipt;
	bool acknowledgement =
		(frame->flags & PQCP_SOVEREIGN_CHANNEL_FLAG_ACK) != 0U;
	int ret;

	if (acknowledgement) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST,
			receipt->content_digest,
			sizeof(receipt->content_digest), true);
		if (ret == 0) {
			ret = writer_u64(
				writer,
				PQCP_SOVEREIGN_CHANNEL_FIELD_ACK_OFFSET,
				receipt->ack_offset);
		}
		return ret;
	}
	if ((receipt->data == NULL &&
	     receipt->data_length != 0U) ||
	    receipt->data_length >
		    PQCP_SOVEREIGN_CHANNEL_MAX_FIELD_BYTES ||
	    receipt->offset > receipt->total_length ||
	    receipt->data_length >
		    receipt->total_length - receipt->offset ||
	    receipt->receipt_sequence == 0U ||
	    pqcp_sovereign_channel_internal_all_zero(
		    receipt->content_digest,
		    sizeof(receipt->content_digest)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    receipt->receipt_digest,
		    sizeof(receipt->receipt_digest))) {
		return -EINVAL;
	}
	ret = writer_bytes(
		writer, PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST,
		receipt->content_digest,
		sizeof(receipt->content_digest), true);
	if (ret == 0) {
		ret = writer_u64(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_OFFSET,
			receipt->offset);
	}
	if (ret == 0 && receipt->data_length != 0U) {
		ret = writer_bytes(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_DATA,
			receipt->data, receipt->data_length, true);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_TOTAL_LENGTH,
			receipt->total_length);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_RECEIPT_SEQUENCE,
			receipt->receipt_sequence);
	}
	if (ret == 0) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_RECEIPT_DIGEST,
			receipt->receipt_digest,
			sizeof(receipt->receipt_digest), true);
	}
	return ret;
}

static int encode_window(
	struct pqcp_sovereign_channel_wire_writer *writer,
	const struct pqcp_sovereign_channel_window *window)
{
	int ret = 0;

	if (window->kind < PQCP_SOVEREIGN_CHANNEL_WINDOW_CREDIT ||
	    window->kind >
		    PQCP_SOVEREIGN_CHANNEL_WINDOW_COMPLETE) {
		return -EINVAL;
	}
	if (window->has_resume_token) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_RESUME_TOKEN,
			window->resume_token,
			sizeof(window->resume_token), true);
	}
	if (ret == 0 && window->has_rolling_digest) {
		ret = writer_bytes(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_ROLLING_DIGEST,
			window->rolling_digest,
			sizeof(window->rolling_digest), true);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_ACK_OFFSET,
			window->ack_offset);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_CONNECTION_CREDIT,
			window->connection_credit);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_STREAM_CREDIT,
			window->stream_credit);
	}
	if (ret == 0) {
		ret = writer_u32(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_WINDOW_KIND,
			(uint32_t)window->kind);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer,
			PQCP_SOVEREIGN_CHANNEL_FIELD_SERVER_TIME,
			window->server_time_ms);
	}
	if (ret == 0) {
		ret = writer_u64(
			writer, PQCP_SOVEREIGN_CHANNEL_FIELD_EXPIRY,
			window->expires_at_ms);
	}
	return ret;
}

int pqcp_sovereign_channel_frame_encode(
	const struct pqcp_sovereign_channel_frame *frame,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_sovereign_channel_wire_writer writer;
	uint32_t payload_length;
	int ret;

	if (frame == NULL || output == NULL ||
	    output_length == NULL ||
	    output_capacity <
		    PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES ||
	    output_capacity >
		    PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES ||
	    frame->schema_version !=
		    PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION ||
	    !pqcp_sovereign_channel_internal_frame_type_valid(
		    frame->type) ||
	    (frame->flags &
	     ~pqcp_sovereign_channel_internal_allowed_flags(
		     frame->type)) != 0U ||
	    frame->sequence == UINT64_MAX ||
	    pqcp_sovereign_channel_internal_all_zero(
		    frame->transaction_id,
		    sizeof(frame->transaction_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    frame->request_id,
		    sizeof(frame->request_id))) {
		return -EINVAL;
	}
	memset(output, 0, output_capacity);
	memset(&writer, 0, sizeof(writer));
	writer.output = output;
	writer.capacity = output_capacity;
	writer.offset =
		PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES;
	switch (frame->type) {
	case PQCP_SOVEREIGN_CHANNEL_FRAME_BEGIN:
		ret = encode_begin(&writer, frame);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CHUNK:
		ret = encode_chunk(&writer, &frame->body.chunk);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_COMMIT:
		ret = encode_commit(&writer, &frame->body.commit);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CANCEL:
		ret = encode_cancel(&writer, &frame->body.cancel);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RESULT:
		ret = encode_result(&writer, frame);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_ERROR:
		ret = encode_error(&writer, &frame->body.error);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RECEIPT:
		ret = encode_receipt(&writer, frame);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW:
		ret = encode_window(&writer, &frame->body.window);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(output, output_capacity);
		return ret;
	}
	if (writer.offset >
		    PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES ||
	    writer.offset <
		    PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES) {
		pqcp_runtime_secure_zero(output, output_capacity);
		return -EMSGSIZE;
	}
	payload_length = (uint32_t)(
		writer.offset -
		PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES);
	pqcp_runtime_internal_write_u32(
		output, PQCP_SOVEREIGN_CHANNEL_MAGIC);
	pqcp_runtime_internal_write_u16(
		output + 4U,
		PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION);
	pqcp_runtime_internal_write_u16(
		output + 6U,
		PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES);
	pqcp_runtime_internal_write_u16(
		output + 8U, (uint16_t)frame->type);
	pqcp_runtime_internal_write_u16(
		output + 10U, writer.field_count);
	pqcp_runtime_internal_write_u32(
		output + 12U, frame->flags);
	pqcp_runtime_internal_write_u64(
		output + 16U, frame->sequence);
	memcpy(output + 24U, frame->transaction_id,
	       sizeof(frame->transaction_id));
	memcpy(output + 40U, frame->request_id,
	       sizeof(frame->request_id));
	pqcp_runtime_internal_write_u32(
		output + 56U, payload_length);
	pqcp_runtime_internal_write_u32(output + 60U, 0U);
	*output_length = writer.offset;
	return 0;
}

static int decode_begin_field(
	struct pqcp_sovereign_channel_begin *begin,
	const struct pqcp_sovereign_channel_wire_field *field,
	uint64_t *seen)
{
	uint32_t value;
	uint32_t options;
	int ret = 0;

	switch (field->id) {
	case PQCP_SOVEREIGN_CHANNEL_FIELD_PRINCIPAL_ID:
		ret = pqcp_sovereign_channel_internal_copy_text(
			begin->principal_id,
			sizeof(begin->principal_id),
			field->value, field->length);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_TENANT_ID:
		ret = pqcp_sovereign_channel_internal_copy_text(
			begin->tenant_id,
			sizeof(begin->tenant_id),
			field->value, field->length);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_CAPABILITY:
		if (field->length != sizeof(begin->capability)) {
			ret = -EBADMSG;
		} else {
			memcpy(begin->capability, field->value,
			       field->length);
		}
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_OPERATION:
		ret = field_u32(field, &value);
		if (ret == 0) {
			begin->operation =
				(enum pqcp_crypto_broker_operation)value;
		}
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_SUBMITTED_AT:
		ret = field_u64(field, &begin->submitted_at_ms);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_DEADLINE:
		ret = field_u64(field, &begin->deadline_ms);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_REQUEST_FLAGS:
		ret = field_u32(field, &begin->request_flags);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_LEVEL:
		ret = field_u32(field, &begin->level);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_FAMILY:
		ret = field_u32(field, &value);
		if (ret == 0) {
			begin->key_spec.family =
				(enum pqcp_runtime_key_family)value;
		}
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_LEVEL:
		ret = field_u32(field, &begin->key_spec.level);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_USAGE:
		ret = field_u32(field, &begin->key_spec.usage);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_EXPIRES_AT:
		ret = field_u64(
			field, &begin->key_spec.expires_at_ms);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_OPTIONS:
		ret = field_u32(field, &options);
		if (ret == 0 &&
		    (options &
		     ~(PQCP_SOVEREIGN_CHANNEL_KEY_PERSISTENT |
		       PQCP_SOVEREIGN_CHANNEL_KEY_EXPORTABLE_PUBLIC)) !=
			    0U) {
			ret = -EBADMSG;
		}
		if (ret == 0) {
			begin->key_spec.persistent =
				(options &
				 PQCP_SOVEREIGN_CHANNEL_KEY_PERSISTENT) !=
				0U;
			begin->key_spec.exportable_public =
				(options &
				 PQCP_SOVEREIGN_CHANNEL_KEY_EXPORTABLE_PUBLIC) !=
				0U;
		}
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_LABEL:
		if (field->length == 0U) {
			begin->key_spec.label[0] = '\0';
		} else {
			ret = pqcp_sovereign_channel_internal_copy_text(
				begin->key_spec.label,
				sizeof(begin->key_spec.label),
				field->value, field->length);
		}
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_PRIMARY_KEY:
		if (field->length !=
		    PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES) {
			ret = -EBADMSG;
		} else {
			ret =
				pqcp_sovereign_channel_internal_decode_handle(
					field->value,
					&begin->primary_key);
		}
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_SECONDARY_KEY:
		if (field->length !=
		    PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES) {
			ret = -EBADMSG;
		} else {
			ret =
				pqcp_sovereign_channel_internal_decode_handle(
					field->value,
					&begin->secondary_key);
		}
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_INPUT_LENGTH:
		ret = field_u32(field, &begin->input_length);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_AUX_LENGTH:
		ret = field_u32(
			field, &begin->aux_input_length);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_CONTEXT_LENGTH:
		ret = field_u32(field, &begin->context_length);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST:
		if (field->length !=
		    sizeof(begin->content_digest)) {
			ret = -EBADMSG;
		} else {
			memcpy(begin->content_digest,
			       field->value, field->length);
		}
		break;
	case PQCP_SOVEREIGN_CHANNEL_FIELD_RESUME_TOKEN:
		if (field->length !=
		    sizeof(begin->resume_token)) {
			ret = -EBADMSG;
		} else {
			memcpy(begin->resume_token,
			       field->value, field->length);
			begin->has_resume_token = true;
		}
		break;
	default:
		if ((field->flags &
		     PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) != 0U) {
			ret = -ENOTSUP;
		}
		return ret;
	}
	if (ret == 0 && field->id < 64U) {
		*seen |= UINT64_C(1) << field->id;
	}
	return ret;
}

static bool begin_required_fields(uint64_t seen, bool resume)
{
	uint64_t required = 0U;

	for (uint16_t id =
		     PQCP_SOVEREIGN_CHANNEL_FIELD_PRINCIPAL_ID;
	     id <= PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST;
	     ++id) {
		required |= UINT64_C(1) << id;
	}
	if (resume) {
		required |= UINT64_C(1) <<
			PQCP_SOVEREIGN_CHANNEL_FIELD_RESUME_TOKEN;
	}
	return (seen & required) == required;
}

static int decode_begin(
	struct pqcp_sovereign_channel_wire_reader *reader,
	struct pqcp_sovereign_channel_frame *frame)
{
	struct pqcp_sovereign_channel_wire_field field;
	uint64_t seen = 0U;
	bool resume =
		(frame->flags & PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME) != 0U;
	int ret;

	while (reader->remaining_fields != 0U) {
		ret = reader_next(reader, &field);
		if (ret != 0) {
			return ret;
		}
		ret = decode_begin_field(
			&frame->body.begin, &field, &seen);
		if (ret != 0) {
			return ret;
		}
	}
	if (!begin_required_fields(seen, resume) ||
	    frame->body.begin.operation <=
		    PQCP_CRYPTO_BROKER_OPERATION_NONE ||
	    frame->body.begin.operation >=
		    PQCP_CRYPTO_BROKER_OPERATION_COUNT ||
	    frame->body.begin.submitted_at_ms == 0U ||
	    frame->body.begin.deadline_ms <
		    frame->body.begin.submitted_at_ms ||
	    frame->body.begin.input_length >
		    PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    frame->body.begin.aux_input_length >
		    PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    frame->body.begin.context_length >
		    PQCP_RUNTIME_MAX_CONTEXT_BYTES ||
	    pqcp_sovereign_channel_internal_all_zero(
		    frame->body.begin.capability,
		    sizeof(frame->body.begin.capability)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    frame->body.begin.content_digest,
		    sizeof(frame->body.begin.content_digest))) {
		return -EBADMSG;
	}
	return 0;
}

static int decode_chunk(
	struct pqcp_sovereign_channel_wire_reader *reader,
	struct pqcp_sovereign_channel_chunk *chunk)
{
	struct pqcp_sovereign_channel_wire_field field;
	uint32_t seen = 0U;
	int ret;

	while (reader->remaining_fields != 0U) {
		ret = reader_next(reader, &field);
		if (ret != 0) {
			return ret;
		}
		switch (field.id) {
		case PQCP_SOVEREIGN_CHANNEL_FIELD_OFFSET:
			ret = field_u64(&field, &chunk->offset);
			seen |= 1U << 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_DATA:
			if (field.length == 0U ||
			    field.length >
				    PQCP_SOVEREIGN_CHANNEL_MAX_FIELD_BYTES) {
				ret = -EBADMSG;
			} else {
				chunk->data = field.value;
				chunk->data_length = field.length;
				seen |= 1U << 1;
				ret = 0;
			}
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_ROLLING_DIGEST:
			if (field.length !=
			    sizeof(chunk->rolling_digest)) {
				ret = -EBADMSG;
			} else {
				memcpy(chunk->rolling_digest,
				       field.value, field.length);
				seen |= 1U << 2;
				ret = 0;
			}
			break;
		default:
			ret = (field.flags &
			       PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) !=
				      0U ?
				-ENOTSUP : 0;
			break;
		}
		if (ret != 0) {
			return ret;
		}
	}
	return seen == 0x7U ? 0 : -EBADMSG;
}

static int decode_commit(
	struct pqcp_sovereign_channel_wire_reader *reader,
	struct pqcp_sovereign_channel_commit *commit)
{
	struct pqcp_sovereign_channel_wire_field field;
	uint32_t seen = 0U;
	int ret;

	while (reader->remaining_fields != 0U) {
		ret = reader_next(reader, &field);
		if (ret != 0) {
			return ret;
		}
		switch (field.id) {
		case PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST:
			if (field.length !=
			    sizeof(commit->content_digest)) {
				return -EBADMSG;
			}
			memcpy(commit->content_digest,
			       field.value, field.length);
			seen |= 1U << 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_ROLLING_DIGEST:
			if (field.length !=
			    sizeof(commit->rolling_digest)) {
				return -EBADMSG;
			}
			memcpy(commit->rolling_digest,
			       field.value, field.length);
			seen |= 1U << 1;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_TOTAL_LENGTH:
			ret = field_u64(
				&field, &commit->total_length);
			if (ret != 0) {
				return ret;
			}
			seen |= 1U << 2;
			break;
		default:
			if ((field.flags &
			     PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) !=
			    0U) {
				return -ENOTSUP;
			}
			break;
		}
	}
	return seen == 0x7U ? 0 : -EBADMSG;
}

static int decode_cancel(
	struct pqcp_sovereign_channel_wire_reader *reader,
	struct pqcp_sovereign_channel_cancel *cancel)
{
	struct pqcp_sovereign_channel_wire_field field;
	uint32_t value;
	bool code_seen = false;
	int ret;

	while (reader->remaining_fields != 0U) {
		ret = reader_next(reader, &field);
		if (ret != 0) {
			return ret;
		}
		switch (field.id) {
		case PQCP_SOVEREIGN_CHANNEL_FIELD_ERROR_CODE:
			ret = field_u32(&field, &value);
			if (ret != 0) {
				return ret;
			}
			cancel->error_code = (int32_t)value;
			code_seen = true;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_DETAIL:
			if (field.length > sizeof(cancel->detail)) {
				return -EBADMSG;
			}
			memcpy(cancel->detail, field.value, field.length);
			cancel->detail_length = field.length;
			break;
		default:
			if ((field.flags &
			     PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) !=
			    0U) {
				return -ENOTSUP;
			}
			break;
		}
	}
	return code_seen ? 0 : -EBADMSG;
}

static int decode_result(
	struct pqcp_sovereign_channel_wire_reader *reader,
	struct pqcp_sovereign_channel_frame *frame)
{
	struct pqcp_sovereign_channel_wire_field field;
	struct pqcp_sovereign_channel_result *result =
		&frame->body.result;
	bool acknowledgement =
		(frame->flags & PQCP_SOVEREIGN_CHANNEL_FLAG_ACK) != 0U;
	uint32_t value;
	uint32_t seen = 0U;
	int ret;

	while (reader->remaining_fields != 0U) {
		ret = reader_next(reader, &field);
		if (ret != 0) {
			return ret;
		}
		switch (field.id) {
		case PQCP_SOVEREIGN_CHANNEL_FIELD_PRIMARY_KEY:
			if (field.length !=
			    PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES) {
				return -EBADMSG;
			}
			ret =
				pqcp_sovereign_channel_internal_decode_handle(
					field.value,
					&result->primary_key);
			seen |= 1U << 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_SECONDARY_KEY:
			if (field.length !=
			    PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES) {
				return -EBADMSG;
			}
			ret =
				pqcp_sovereign_channel_internal_decode_handle(
					field.value,
					&result->secondary_key);
			seen |= 1U << 1;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST:
			if (field.length !=
			    sizeof(result->content_digest)) {
				return -EBADMSG;
			}
			memcpy(result->content_digest,
			       field.value, field.length);
			seen |= 1U << 2;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_OFFSET:
			ret = field_u64(&field, &result->offset);
			seen |= 1U << 3;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_DATA:
			if (field.length >
			    PQCP_SOVEREIGN_CHANNEL_MAX_FIELD_BYTES) {
				return -EBADMSG;
			}
			result->data = field.value;
			result->data_length = field.length;
			seen |= 1U << 4;
			ret = 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_TOTAL_LENGTH:
			ret = field_u64(
				&field, &result->total_length);
			seen |= 1U << 5;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_RESULT_CODE:
			ret = field_u32(&field, &value);
			result->result_code = (int32_t)value;
			seen |= 1U << 6;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_RESULT_FLAGS:
			ret = field_u32(
				&field, &result->result_flags);
			seen |= 1U << 7;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_METADATA:
			if (field.length !=
			    PQCP_SOVEREIGN_CHANNEL_METADATA_BYTES) {
				return -EBADMSG;
			}
			ret =
				pqcp_sovereign_channel_internal_decode_metadata(
					field.value,
					&result->metadata);
			seen |= 1U << 8;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_ACK_OFFSET:
			ret = field_u64(
				&field, &result->ack_offset);
			seen |= 1U << 9;
			break;
		default:
			ret = (field.flags &
			       PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) !=
				      0U ?
				-ENOTSUP : 0;
			break;
		}
		if (ret != 0) {
			return ret;
		}
	}
	if (acknowledgement) {
		return (seen & ((1U << 2) | (1U << 9))) ==
				       ((1U << 2) | (1U << 9)) ?
			0 : -EBADMSG;
	}
	if ((seen & 0x1efU) != 0x1efU ||
	    result->offset > result->total_length ||
	    result->data_length >
		    result->total_length - result->offset) {
		return -EBADMSG;
	}
	return 0;
}

static int decode_error(
	struct pqcp_sovereign_channel_wire_reader *reader,
	struct pqcp_sovereign_channel_error *error)
{
	struct pqcp_sovereign_channel_wire_field field;
	uint32_t value;
	uint32_t seen = 0U;
	int ret;

	while (reader->remaining_fields != 0U) {
		ret = reader_next(reader, &field);
		if (ret != 0) {
			return ret;
		}
		switch (field.id) {
		case PQCP_SOVEREIGN_CHANNEL_FIELD_ERROR_CODE:
			ret = field_u32(&field, &value);
			error->error_code = (int32_t)value;
			seen |= 1U << 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_DETAIL:
			if (field.length > sizeof(error->detail)) {
				return -EBADMSG;
			}
			memcpy(error->detail, field.value, field.length);
			error->detail_length = field.length;
			ret = 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_ERROR_STAGE:
			ret = field_u32(&field, &value);
			error->stage =
				(enum pqcp_sovereign_channel_error_stage)
					value;
			seen |= 1U << 1;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_RETRY_AFTER:
			ret = field_u64(
				&field, &error->retry_after_ms);
			seen |= 1U << 2;
			break;
		default:
			ret = (field.flags &
			       PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) !=
				      0U ?
				-ENOTSUP : 0;
			break;
		}
		if (ret != 0) {
			return ret;
		}
	}
	if (seen != 0x7U ||
	    error->stage <= PQCP_SOVEREIGN_CHANNEL_STAGE_NONE ||
	    error->stage > PQCP_SOVEREIGN_CHANNEL_STAGE_RESUME) {
		return -EBADMSG;
	}
	return 0;
}

static int decode_receipt(
	struct pqcp_sovereign_channel_wire_reader *reader,
	struct pqcp_sovereign_channel_frame *frame)
{
	struct pqcp_sovereign_channel_wire_field field;
	struct pqcp_sovereign_channel_receipt_frame *receipt =
		&frame->body.receipt;
	bool acknowledgement =
		(frame->flags & PQCP_SOVEREIGN_CHANNEL_FLAG_ACK) != 0U;
	uint32_t seen = 0U;
	int ret;

	while (reader->remaining_fields != 0U) {
		ret = reader_next(reader, &field);
		if (ret != 0) {
			return ret;
		}
		switch (field.id) {
		case PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST:
			if (field.length !=
			    sizeof(receipt->content_digest)) {
				return -EBADMSG;
			}
			memcpy(receipt->content_digest,
			       field.value, field.length);
			seen |= 1U << 0;
			ret = 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_OFFSET:
			ret = field_u64(&field, &receipt->offset);
			seen |= 1U << 1;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_DATA:
			receipt->data = field.value;
			receipt->data_length = field.length;
			seen |= 1U << 2;
			ret = 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_TOTAL_LENGTH:
			ret = field_u64(
				&field, &receipt->total_length);
			seen |= 1U << 3;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_ACK_OFFSET:
			ret = field_u64(
				&field, &receipt->ack_offset);
			seen |= 1U << 4;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_RECEIPT_SEQUENCE:
			ret = field_u64(
				&field, &receipt->receipt_sequence);
			seen |= 1U << 5;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_RECEIPT_DIGEST:
			if (field.length !=
			    sizeof(receipt->receipt_digest)) {
				return -EBADMSG;
			}
			memcpy(receipt->receipt_digest,
			       field.value, field.length);
			seen |= 1U << 6;
			ret = 0;
			break;
		default:
			ret = (field.flags &
			       PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) !=
				      0U ?
				-ENOTSUP : 0;
			break;
		}
		if (ret != 0) {
			return ret;
		}
	}
	if (acknowledgement) {
		return (seen & ((1U << 0) | (1U << 4))) ==
				       ((1U << 0) | (1U << 4)) ?
			0 : -EBADMSG;
	}
	if ((seen & 0x6fU) != 0x6fU ||
	    receipt->receipt_sequence == 0U ||
	    receipt->offset > receipt->total_length ||
	    receipt->data_length >
		    receipt->total_length - receipt->offset) {
		return -EBADMSG;
	}
	return 0;
}

static int decode_window(
	struct pqcp_sovereign_channel_wire_reader *reader,
	struct pqcp_sovereign_channel_window *window)
{
	struct pqcp_sovereign_channel_wire_field field;
	uint32_t value;
	uint32_t seen = 0U;
	int ret;

	while (reader->remaining_fields != 0U) {
		ret = reader_next(reader, &field);
		if (ret != 0) {
			return ret;
		}
		switch (field.id) {
		case PQCP_SOVEREIGN_CHANNEL_FIELD_RESUME_TOKEN:
			if (field.length !=
			    sizeof(window->resume_token)) {
				return -EBADMSG;
			}
			memcpy(window->resume_token,
			       field.value, field.length);
			window->has_resume_token = true;
			ret = 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_ROLLING_DIGEST:
			if (field.length !=
			    sizeof(window->rolling_digest)) {
				return -EBADMSG;
			}
			memcpy(window->rolling_digest,
			       field.value, field.length);
			window->has_rolling_digest = true;
			ret = 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_ACK_OFFSET:
			ret = field_u64(&field, &window->ack_offset);
			seen |= 1U << 0;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_CONNECTION_CREDIT:
			ret = field_u32(
				&field, &window->connection_credit);
			seen |= 1U << 1;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_STREAM_CREDIT:
			ret = field_u32(
				&field, &window->stream_credit);
			seen |= 1U << 2;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_WINDOW_KIND:
			ret = field_u32(&field, &value);
			window->kind =
				(enum pqcp_sovereign_channel_window_kind)
					value;
			seen |= 1U << 3;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_SERVER_TIME:
			ret = field_u64(
				&field, &window->server_time_ms);
			seen |= 1U << 4;
			break;
		case PQCP_SOVEREIGN_CHANNEL_FIELD_EXPIRY:
			ret = field_u64(
				&field, &window->expires_at_ms);
			seen |= 1U << 5;
			break;
		default:
			ret = (field.flags &
			       PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY) !=
				      0U ?
				-ENOTSUP : 0;
			break;
		}
		if (ret != 0) {
			return ret;
		}
	}
	if (seen != 0x3fU ||
	    window->kind < PQCP_SOVEREIGN_CHANNEL_WINDOW_CREDIT ||
	    window->kind >
		    PQCP_SOVEREIGN_CHANNEL_WINDOW_COMPLETE) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_sovereign_channel_frame_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_sovereign_channel_frame *frame)
{
	struct pqcp_sovereign_channel_wire_reader reader;
	uint32_t magic;
	uint16_t schema_version;
	uint16_t header_bytes;
	uint16_t type;
	uint16_t field_count;
	uint32_t payload_length;
	uint32_t reserved;
	int ret;

	if (input == NULL || frame == NULL ||
	    input_length <
		    PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES ||
	    input_length >
		    PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES) {
		return -EINVAL;
	}
	magic = pqcp_runtime_internal_read_u32(input);
	schema_version =
		pqcp_runtime_internal_read_u16(input + 4U);
	header_bytes =
		pqcp_runtime_internal_read_u16(input + 6U);
	type = pqcp_runtime_internal_read_u16(input + 8U);
	field_count =
		pqcp_runtime_internal_read_u16(input + 10U);
	payload_length =
		pqcp_runtime_internal_read_u32(input + 56U);
	reserved =
		pqcp_runtime_internal_read_u32(input + 60U);
	if (magic != PQCP_SOVEREIGN_CHANNEL_MAGIC ||
	    schema_version !=
		    PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION ||
	    header_bytes !=
		    PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES ||
	    !pqcp_sovereign_channel_internal_frame_type_valid(
		    (enum pqcp_sovereign_channel_frame_type)type) ||
	    field_count == 0U || reserved != 0U ||
	    payload_length !=
		    input_length -
			    PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES) {
		return -EBADMSG;
	}
	memset(frame, 0, sizeof(*frame));
	frame->schema_version = schema_version;
	frame->type =
		(enum pqcp_sovereign_channel_frame_type)type;
	frame->flags =
		pqcp_runtime_internal_read_u32(input + 12U);
	frame->sequence =
		pqcp_runtime_internal_read_u64(input + 16U);
	memcpy(frame->transaction_id, input + 24U,
	       sizeof(frame->transaction_id));
	memcpy(frame->request_id, input + 40U,
	       sizeof(frame->request_id));
	if ((frame->flags &
	     ~pqcp_sovereign_channel_internal_allowed_flags(
		     frame->type)) != 0U ||
	    pqcp_sovereign_channel_internal_all_zero(
		    frame->transaction_id,
		    sizeof(frame->transaction_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    frame->request_id,
		    sizeof(frame->request_id))) {
		return -EBADMSG;
	}
	memset(&reader, 0, sizeof(reader));
	reader.input = input;
	reader.length = input_length;
	reader.offset =
		PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES;
	reader.remaining_fields = field_count;
	switch (frame->type) {
	case PQCP_SOVEREIGN_CHANNEL_FRAME_BEGIN:
		ret = decode_begin(&reader, frame);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CHUNK:
		ret = decode_chunk(&reader, &frame->body.chunk);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_COMMIT:
		ret = decode_commit(&reader, &frame->body.commit);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CANCEL:
		ret = decode_cancel(&reader, &frame->body.cancel);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RESULT:
		ret = decode_result(&reader, frame);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_ERROR:
		ret = decode_error(&reader, &frame->body.error);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RECEIPT:
		ret = decode_receipt(&reader, frame);
		break;
	case PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW:
		ret = decode_window(&reader, &frame->body.window);
		break;
	default:
		ret = -EBADMSG;
		break;
	}
	if (ret != 0) {
		memset(frame, 0, sizeof(*frame));
		return ret;
	}
	if (reader.remaining_fields != 0U ||
	    reader.offset != reader.length) {
		memset(frame, 0, sizeof(*frame));
		return -EBADMSG;
	}
	return 0;
}

int pqcp_sovereign_channel_internal_encode_handle(
	const struct pqcp_runtime_key_handle *handle,
	uint8_t output[PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES])
{
	if (handle == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u32(output, handle->slot);
	pqcp_runtime_internal_write_u32(
		output + 4U, handle->generation);
	pqcp_runtime_internal_write_u32(
		output + 8U, (uint32_t)handle->backend);
	pqcp_runtime_internal_write_u32(
		output + 12U, (uint32_t)handle->family);
	pqcp_runtime_internal_write_u32(
		output + 16U, handle->level);
	return 0;
}

int pqcp_sovereign_channel_internal_decode_handle(
	const uint8_t input[PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES],
	struct pqcp_runtime_key_handle *handle)
{
	if (input == NULL || handle == NULL) {
		return -EINVAL;
	}
	memset(handle, 0, sizeof(*handle));
	handle->slot = pqcp_runtime_internal_read_u32(input);
	handle->generation =
		pqcp_runtime_internal_read_u32(input + 4U);
	handle->backend =
		(enum pqcp_runtime_key_backend)
			pqcp_runtime_internal_read_u32(input + 8U);
	handle->family =
		(enum pqcp_runtime_key_family)
			pqcp_runtime_internal_read_u32(input + 12U);
	handle->level =
		pqcp_runtime_internal_read_u32(input + 16U);
	if (handle->slot == 0U && handle->generation == 0U &&
	    handle->backend == PQCP_RUNTIME_KEY_BACKEND_NONE &&
	    handle->family == PQCP_RUNTIME_KEY_NONE &&
	    handle->level == 0U) {
		return 0;
	}
	if (!pqcp_runtime_key_handle_is_valid(handle)) {
		memset(handle, 0, sizeof(*handle));
		return -EBADMSG;
	}
	return 0;
}

int pqcp_sovereign_channel_internal_encode_metadata(
	const struct pqcp_runtime_key_metadata *metadata,
	uint8_t output[PQCP_SOVEREIGN_CHANNEL_METADATA_BYTES])
{
	size_t offset = 0U;
	uint8_t handle[PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES];
	uint32_t flags = 0U;
	int ret;

	if (metadata == NULL || output == NULL) {
		return -EINVAL;
	}
	memset(output, 0, PQCP_SOVEREIGN_CHANNEL_METADATA_BYTES);
	ret = pqcp_sovereign_channel_internal_encode_handle(
		&metadata->handle, handle);
	if (ret != 0) {
		return ret;
	}
	pqcp_runtime_internal_write_u32(
		output + offset, metadata->schema_version);
	offset += 4U;
	memcpy(output + offset, handle, sizeof(handle));
	offset += sizeof(handle);
	pqcp_runtime_secure_zero(handle, sizeof(handle));
	pqcp_runtime_internal_write_u32(
		output + offset, metadata->usage);
	offset += 4U;
	pqcp_runtime_internal_write_u64(
		output + offset, metadata->created_at_ms);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		output + offset, metadata->expires_at_ms);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		output + offset, metadata->last_used_at_ms);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		output + offset, metadata->use_count);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		output + offset, metadata->public_bytes);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		output + offset, metadata->secret_bytes);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		output + offset, (uint32_t)metadata->custody);
	offset += 4U;
	memcpy(output + offset, metadata->owner,
	       sizeof(metadata->owner));
	offset += sizeof(metadata->owner);
	memcpy(output + offset, metadata->label,
	       sizeof(metadata->label));
	offset += sizeof(metadata->label);
	if (metadata->active) {
		flags |= 1U << 0;
	}
	if (metadata->persistent) {
		flags |= 1U << 1;
	}
	if (metadata->exportable_public) {
		flags |= 1U << 2;
	}
	pqcp_runtime_internal_write_u32(
		output + offset, flags);
	offset += 4U;
	return offset <= PQCP_SOVEREIGN_CHANNEL_METADATA_BYTES ?
		0 : -EOVERFLOW;
}

int pqcp_sovereign_channel_internal_decode_metadata(
	const uint8_t input[PQCP_SOVEREIGN_CHANNEL_METADATA_BYTES],
	struct pqcp_runtime_key_metadata *metadata)
{
	size_t offset = 0U;
	uint32_t flags;
	int ret;

	if (input == NULL || metadata == NULL) {
		return -EINVAL;
	}
	memset(metadata, 0, sizeof(*metadata));
	metadata->schema_version =
		pqcp_runtime_internal_read_u32(input + offset);
	offset += 4U;
	ret = pqcp_sovereign_channel_internal_decode_handle(
		input + offset, &metadata->handle);
	if (ret != 0) {
		return ret;
	}
	offset += PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES;
	metadata->usage =
		pqcp_runtime_internal_read_u32(input + offset);
	offset += 4U;
	metadata->created_at_ms =
		pqcp_runtime_internal_read_u64(input + offset);
	offset += 8U;
	metadata->expires_at_ms =
		pqcp_runtime_internal_read_u64(input + offset);
	offset += 8U;
	metadata->last_used_at_ms =
		pqcp_runtime_internal_read_u64(input + offset);
	offset += 8U;
	metadata->use_count =
		pqcp_runtime_internal_read_u32(input + offset);
	offset += 4U;
	metadata->public_bytes =
		pqcp_runtime_internal_read_u32(input + offset);
	offset += 4U;
	metadata->secret_bytes =
		pqcp_runtime_internal_read_u32(input + offset);
	offset += 4U;
	metadata->custody =
		(enum pqcp_runtime_key_custody)
			pqcp_runtime_internal_read_u32(input + offset);
	offset += 4U;
	memcpy(metadata->owner, input + offset,
	       sizeof(metadata->owner));
	metadata->owner[sizeof(metadata->owner) - 1U] = '\0';
	offset += sizeof(metadata->owner);
	memcpy(metadata->label, input + offset,
	       sizeof(metadata->label));
	metadata->label[sizeof(metadata->label) - 1U] = '\0';
	offset += sizeof(metadata->label);
	flags = pqcp_runtime_internal_read_u32(input + offset);
	if ((flags & ~0x7U) != 0U) {
		memset(metadata, 0, sizeof(*metadata));
		return -EBADMSG;
	}
	metadata->active = (flags & (1U << 0)) != 0U;
	metadata->persistent = (flags & (1U << 1)) != 0U;
	metadata->exportable_public =
		(flags & (1U << 2)) != 0U;
	return 0;
}

const char *pqcp_sovereign_channel_frame_type_str(
	enum pqcp_sovereign_channel_frame_type type)
{
	switch (type) {
	case PQCP_SOVEREIGN_CHANNEL_FRAME_BEGIN:
		return "begin";
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CHUNK:
		return "chunk";
	case PQCP_SOVEREIGN_CHANNEL_FRAME_COMMIT:
		return "commit";
	case PQCP_SOVEREIGN_CHANNEL_FRAME_CANCEL:
		return "cancel";
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RESULT:
		return "result";
	case PQCP_SOVEREIGN_CHANNEL_FRAME_ERROR:
		return "error";
	case PQCP_SOVEREIGN_CHANNEL_FRAME_RECEIPT:
		return "receipt";
	case PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW:
		return "window";
	default:
		return "none";
	}
}

const char *pqcp_sovereign_channel_server_state_str(
	enum pqcp_sovereign_channel_server_state state)
{
	switch (state) {
	case PQCP_SOVEREIGN_CHANNEL_SERVER_EMPTY:
		return "empty";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_RECEIVING:
		return "receiving";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_READY:
		return "ready";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_EXECUTING:
		return "executing";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RESULT:
		return "sending_result";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RECEIPT:
		return "sending_receipt";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_WAITING_ACK:
		return "waiting_ack";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED:
		return "disconnected";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_COMPLETED:
		return "completed";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_CANCELLED:
		return "cancelled";
	case PQCP_SOVEREIGN_CHANNEL_SERVER_FAILED:
		return "failed";
	default:
		return "invalid";
	}
}

const char *pqcp_sovereign_channel_client_state_str(
	enum pqcp_sovereign_channel_client_state state)
{
	switch (state) {
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_EMPTY:
		return "empty";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_BEGIN_SENT:
		return "begin_sent";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_SENDING:
		return "sending";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_COMMIT_SENT:
		return "commit_sent";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_WAITING_RESULT:
		return "waiting_result";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_RECEIVING_RESULT:
		return "receiving_result";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_RECEIVING_RECEIPT:
		return "receiving_receipt";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_DISCONNECTED:
		return "disconnected";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_COMPLETED:
		return "completed";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_CANCELLED:
		return "cancelled";
	case PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED:
		return "failed";
	default:
		return "invalid";
	}
}
