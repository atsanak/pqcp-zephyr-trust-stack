/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Ordered request and response assembly for sovereign-channel transactions.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_channel_internal.h"

#define SOVEREIGN_BODY_DOMAIN "PQCP-SOVEREIGN-CHANNEL-BODY-V1"
#define SOVEREIGN_ROLL_DOMAIN "PQCP-SOVEREIGN-CHANNEL-ROLL-V1"

static int checked_total(
	uint32_t input_length,
	uint32_t aux_length,
	uint32_t context_length,
	uint64_t *total)
{
	uint64_t value;

	if (total == NULL ||
	    input_length > PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    aux_length > PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    context_length > PQCP_RUNTIME_MAX_CONTEXT_BYTES) {
		return -EINVAL;
	}
	value = (uint64_t)input_length +
		(uint64_t)aux_length;
	if (value > UINT64_MAX - context_length) {
		return -EOVERFLOW;
	}
	value += context_length;
	if (value > PQCP_SOVEREIGN_CHANNEL_MAX_BODY_BYTES) {
		return -E2BIG;
	}
	*total = value;
	return 0;
}

int pqcp_sovereign_channel_internal_hash_body(
	const uint8_t *input,
	size_t input_length,
	const uint8_t *aux_input,
	size_t aux_input_length,
	const uint8_t *context,
	size_t context_length,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	const uint8_t *parts[7];
	size_t lengths[7];
	uint8_t encoded_lengths[24];

	if (digest == NULL ||
	    (input == NULL && input_length != 0U) ||
	    (aux_input == NULL && aux_input_length != 0U) ||
	    (context == NULL && context_length != 0U) ||
	    input_length > PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    aux_input_length > PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    context_length > PQCP_RUNTIME_MAX_CONTEXT_BYTES) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u64(
		encoded_lengths, input_length);
	pqcp_runtime_internal_write_u64(
		encoded_lengths + 8U, aux_input_length);
	pqcp_runtime_internal_write_u64(
		encoded_lengths + 16U, context_length);
	parts[0] = (const uint8_t *)SOVEREIGN_BODY_DOMAIN;
	lengths[0] = sizeof(SOVEREIGN_BODY_DOMAIN) - 1U;
	parts[1] = encoded_lengths;
	lengths[1] = sizeof(encoded_lengths);
	parts[2] = input;
	lengths[2] = input_length;
	parts[3] = (const uint8_t *)"\x01";
	lengths[3] = 1U;
	parts[4] = aux_input;
	lengths[4] = aux_input_length;
	parts[5] = (const uint8_t *)"\x02";
	lengths[5] = 1U;
	parts[6] = context;
	lengths[6] = context_length;
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, 7U, digest);
}

int pqcp_sovereign_channel_internal_seed_digest(
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	uint32_t input_length,
	uint32_t aux_length,
	uint32_t context_length,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	const uint8_t *parts[4];
	size_t lengths[4];
	uint8_t encoded_lengths[12];
	uint64_t total;
	int ret;

	if (transaction_id == NULL || request_id == NULL ||
	    digest == NULL ||
	    pqcp_sovereign_channel_internal_all_zero(
		    transaction_id,
		    PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    request_id,
		    PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES)) {
		return -EINVAL;
	}
	ret = checked_total(
		input_length, aux_length, context_length,
		&total);
	if (ret != 0) {
		return ret;
	}
	(void)total;
	pqcp_runtime_internal_write_u32(
		encoded_lengths, input_length);
	pqcp_runtime_internal_write_u32(
		encoded_lengths + 4U, aux_length);
	pqcp_runtime_internal_write_u32(
		encoded_lengths + 8U, context_length);
	parts[0] = (const uint8_t *)SOVEREIGN_ROLL_DOMAIN;
	lengths[0] = sizeof(SOVEREIGN_ROLL_DOMAIN) - 1U;
	parts[1] = transaction_id;
	lengths[1] =
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES;
	parts[2] = request_id;
	lengths[2] = PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES;
	parts[3] = encoded_lengths;
	lengths[3] = sizeof(encoded_lengths);
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, 4U, digest);
}

int pqcp_sovereign_channel_internal_roll_digest(
	const uint8_t previous[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES],
	uint64_t offset,
	const uint8_t *data,
	size_t data_length,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	const uint8_t *parts[4];
	size_t lengths[4];
	uint8_t descriptor[12];

	if (previous == NULL || data == NULL ||
	    data_length == 0U || data_length > UINT32_MAX ||
	    digest == NULL ||
	    pqcp_sovereign_channel_internal_all_zero(
		    previous,
		    PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES)) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u64(descriptor, offset);
	pqcp_runtime_internal_write_u32(
		descriptor + 8U, (uint32_t)data_length);
	parts[0] = (const uint8_t *)SOVEREIGN_ROLL_DOMAIN;
	lengths[0] = sizeof(SOVEREIGN_ROLL_DOMAIN) - 1U;
	parts[1] = previous;
	lengths[1] = PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES;
	parts[2] = descriptor;
	lengths[2] = sizeof(descriptor);
	parts[3] = data;
	lengths[3] = data_length;
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, 4U, digest);
}

static int validate_buffers(
	const struct pqcp_sovereign_channel_begin *begin,
	uint8_t *input,
	size_t input_capacity,
	uint8_t *aux_input,
	size_t aux_input_capacity,
	uint8_t *context,
	size_t context_capacity)
{
	if (begin == NULL ||
	    (begin->input_length != 0U &&
	     (input == NULL ||
	      input_capacity < begin->input_length)) ||
	    (begin->aux_input_length != 0U &&
	     (aux_input == NULL ||
	      aux_input_capacity < begin->aux_input_length)) ||
	    (begin->context_length != 0U &&
	     (context == NULL ||
	      context_capacity < begin->context_length))) {
		return -ENOBUFS;
	}
	if (begin->input_length > PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    begin->aux_input_length >
		    PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    begin->context_length >
		    PQCP_RUNTIME_MAX_CONTEXT_BYTES) {
		return -E2BIG;
	}
	return 0;
}

int pqcp_sovereign_channel_request_assembler_init(
	struct pqcp_sovereign_channel_request_assembler *assembler,
	const struct pqcp_sovereign_channel_begin *begin,
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	uint8_t *input,
	size_t input_capacity,
	uint8_t *aux_input,
	size_t aux_input_capacity,
	uint8_t *context,
	size_t context_capacity)
{
	uint64_t total;
	int ret;

	if (assembler == NULL || transaction_id == NULL ||
	    request_id == NULL ||
	    pqcp_sovereign_channel_internal_all_zero(
		    transaction_id,
		    PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    request_id,
		    PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    begin != NULL ? begin->content_digest : NULL,
		    PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES)) {
		return -EINVAL;
	}
	ret = validate_buffers(
		begin, input, input_capacity,
		aux_input, aux_input_capacity,
		context, context_capacity);
	if (ret != 0) {
		return ret;
	}
	ret = checked_total(
		begin->input_length,
		begin->aux_input_length,
		begin->context_length,
		&total);
	if (ret != 0) {
		return ret;
	}
	memset(assembler, 0, sizeof(*assembler));
	assembler->input = input;
	assembler->input_capacity = input_capacity;
	assembler->aux_input = aux_input;
	assembler->aux_input_capacity = aux_input_capacity;
	assembler->context = context;
	assembler->context_capacity = context_capacity;
	assembler->expected_input_length =
		begin->input_length;
	assembler->expected_aux_length =
		begin->aux_input_length;
	assembler->expected_context_length =
		begin->context_length;
	assembler->expected_total_length = total;
	memcpy(assembler->transaction_id, transaction_id,
	       sizeof(assembler->transaction_id));
	memcpy(assembler->request_id, request_id,
	       sizeof(assembler->request_id));
	memcpy(assembler->expected_content_digest,
	       begin->content_digest,
	       sizeof(assembler->expected_content_digest));
	ret = pqcp_sovereign_channel_internal_seed_digest(
		transaction_id, request_id,
		begin->input_length,
		begin->aux_input_length,
		begin->context_length,
		assembler->rolling_digest);
	if (ret != 0) {
		memset(assembler, 0, sizeof(*assembler));
		return ret;
	}
	if (input != NULL && input_capacity != 0U) {
		memset(input, 0, input_capacity);
	}
	if (aux_input != NULL && aux_input_capacity != 0U) {
		memset(aux_input, 0, aux_input_capacity);
	}
	if (context != NULL && context_capacity != 0U) {
		memset(context, 0, context_capacity);
	}
	assembler->initialized = true;
	return 0;
}

static int copy_segment(
	uint8_t *destination,
	size_t destination_length,
	uint64_t segment_start,
	uint64_t chunk_start,
	const uint8_t *chunk,
	size_t chunk_length)
{
	uint64_t segment_end;
	uint64_t chunk_end;
	uint64_t overlap_start;
	uint64_t overlap_end;
	size_t source_offset;
	size_t destination_offset;
	size_t copy_length;

	if (destination_length == 0U) {
		return 0;
	}
	if (destination == NULL || chunk == NULL ||
	    segment_start > UINT64_MAX - destination_length ||
	    chunk_start > UINT64_MAX - chunk_length) {
		return -EOVERFLOW;
	}
	segment_end = segment_start + destination_length;
	chunk_end = chunk_start + chunk_length;
	if (chunk_end <= segment_start ||
	    chunk_start >= segment_end) {
		return 0;
	}
	overlap_start = chunk_start > segment_start ?
		chunk_start : segment_start;
	overlap_end = chunk_end < segment_end ?
		chunk_end : segment_end;
	source_offset = (size_t)(overlap_start - chunk_start);
	destination_offset =
		(size_t)(overlap_start - segment_start);
	copy_length = (size_t)(overlap_end - overlap_start);
	if (destination_offset > destination_length ||
	    copy_length >
		    destination_length - destination_offset ||
	    source_offset > chunk_length ||
	    copy_length > chunk_length - source_offset) {
		return -EOVERFLOW;
	}
	memcpy(destination + destination_offset,
	       chunk + source_offset, copy_length);
	return 0;
}

static int copy_chunk(
	struct pqcp_sovereign_channel_request_assembler *assembler,
	const struct pqcp_sovereign_channel_chunk *chunk)
{
	uint64_t aux_start =
		assembler->expected_input_length;
	uint64_t context_start =
		aux_start + assembler->expected_aux_length;
	int ret;

	ret = copy_segment(
		assembler->input,
		assembler->expected_input_length,
		0U, chunk->offset,
		chunk->data, chunk->data_length);
	if (ret == 0) {
		ret = copy_segment(
			assembler->aux_input,
			assembler->expected_aux_length,
			aux_start, chunk->offset,
			chunk->data, chunk->data_length);
	}
	if (ret == 0) {
		ret = copy_segment(
			assembler->context,
			assembler->expected_context_length,
			context_start, chunk->offset,
			chunk->data, chunk->data_length);
	}
	return ret;
}

int pqcp_sovereign_channel_request_assembler_append(
	struct pqcp_sovereign_channel_request_assembler *assembler,
	const struct pqcp_sovereign_channel_chunk *chunk)
{
	uint8_t next_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	int ret;

	if (assembler == NULL || !assembler->initialized ||
	    assembler->committed || chunk == NULL ||
	    chunk->data == NULL || chunk->data_length == 0U ||
	    chunk->offset != assembler->received_length ||
	    chunk->data_length >
		    PQCP_SOVEREIGN_CHANNEL_MAX_FIELD_BYTES ||
	    chunk->offset > assembler->expected_total_length ||
	    chunk->data_length >
		    assembler->expected_total_length -
			    chunk->offset) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_channel_internal_roll_digest(
		assembler->rolling_digest, chunk->offset,
		chunk->data, chunk->data_length,
		next_digest);
	if (ret != 0) {
		return ret;
	}
	if (!pqcp_sovereign_channel_internal_equal(
		    next_digest, chunk->rolling_digest,
		    sizeof(next_digest))) {
		pqcp_runtime_secure_zero(
			next_digest, sizeof(next_digest));
		return -EKEYREJECTED;
	}
	ret = copy_chunk(assembler, chunk);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			next_digest, sizeof(next_digest));
		return ret;
	}
	memcpy(assembler->rolling_digest, next_digest,
	       sizeof(assembler->rolling_digest));
	pqcp_runtime_secure_zero(
		next_digest, sizeof(next_digest));
	assembler->received_length += chunk->data_length;
	return 0;
}

int pqcp_sovereign_channel_request_assembler_commit(
	struct pqcp_sovereign_channel_request_assembler *assembler,
	const struct pqcp_sovereign_channel_commit *commit)
{
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	int ret;

	if (assembler == NULL || !assembler->initialized ||
	    assembler->committed || commit == NULL ||
	    commit->total_length !=
		    assembler->expected_total_length ||
	    assembler->received_length !=
		    assembler->expected_total_length ||
	    !pqcp_sovereign_channel_internal_equal(
		    commit->rolling_digest,
		    assembler->rolling_digest,
		    sizeof(assembler->rolling_digest)) ||
	    !pqcp_sovereign_channel_internal_equal(
		    commit->content_digest,
		    assembler->expected_content_digest,
		    sizeof(assembler->expected_content_digest))) {
		return -EBADMSG;
	}
	ret = pqcp_sovereign_channel_internal_hash_body(
		assembler->input,
		assembler->expected_input_length,
		assembler->aux_input,
		assembler->expected_aux_length,
		assembler->context,
		assembler->expected_context_length,
		digest);
	if (ret != 0) {
		return ret;
	}
	if (!pqcp_sovereign_channel_internal_equal(
		    digest,
		    assembler->expected_content_digest,
		    sizeof(digest))) {
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return -EKEYREJECTED;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	assembler->committed = true;
	return 0;
}

int pqcp_sovereign_channel_request_assembler_reset(
	struct pqcp_sovereign_channel_request_assembler *assembler)
{
	uint8_t *input;
	size_t input_capacity;
	uint8_t *aux_input;
	size_t aux_input_capacity;
	uint8_t *context;
	size_t context_capacity;

	if (assembler == NULL) {
		return -EINVAL;
	}
	input = assembler->input;
	input_capacity = assembler->input_capacity;
	aux_input = assembler->aux_input;
	aux_input_capacity = assembler->aux_input_capacity;
	context = assembler->context;
	context_capacity = assembler->context_capacity;
	if (input != NULL && input_capacity != 0U) {
		pqcp_runtime_secure_zero(input, input_capacity);
	}
	if (aux_input != NULL && aux_input_capacity != 0U) {
		pqcp_runtime_secure_zero(
			aux_input, aux_input_capacity);
	}
	if (context != NULL && context_capacity != 0U) {
		pqcp_runtime_secure_zero(context, context_capacity);
	}
	pqcp_runtime_secure_zero(assembler, sizeof(*assembler));
	return 0;
}

int pqcp_sovereign_channel_request_assembler_audit(
	const struct pqcp_sovereign_channel_request_assembler *assembler)
{
	uint64_t total;
	int ret;

	if (assembler == NULL || !assembler->initialized ||
	    pqcp_sovereign_channel_internal_all_zero(
		    assembler->transaction_id,
		    sizeof(assembler->transaction_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    assembler->request_id,
		    sizeof(assembler->request_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    assembler->expected_content_digest,
		    sizeof(assembler->expected_content_digest)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    assembler->rolling_digest,
		    sizeof(assembler->rolling_digest))) {
		return -EINVAL;
	}
	ret = checked_total(
		assembler->expected_input_length,
		assembler->expected_aux_length,
		assembler->expected_context_length,
		&total);
	if (ret != 0 ||
	    total != assembler->expected_total_length ||
	    assembler->received_length >
		    assembler->expected_total_length ||
	    (assembler->committed &&
	     assembler->received_length !=
		     assembler->expected_total_length)) {
		return -EBADMSG;
	}
	return validate_buffers(
		&(struct pqcp_sovereign_channel_begin){
			.input_length =
				assembler->expected_input_length,
			.aux_input_length =
				assembler->expected_aux_length,
			.context_length =
				assembler->expected_context_length,
		},
		assembler->input, assembler->input_capacity,
		assembler->aux_input,
		assembler->aux_input_capacity,
		assembler->context,
		assembler->context_capacity);
}

int pqcp_sovereign_channel_blob_assembler_init(
	struct pqcp_sovereign_channel_blob_assembler *assembler,
	uint8_t *output,
	size_t output_capacity,
	uint64_t expected_length,
	const uint8_t expected_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	if (assembler == NULL ||
	    (expected_length != 0U &&
	     (output == NULL ||
	      expected_length > output_capacity)) ||
	    expected_digest == NULL ||
	    pqcp_sovereign_channel_internal_all_zero(
		    expected_digest,
		    PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES)) {
		return -EINVAL;
	}
	memset(assembler, 0, sizeof(*assembler));
	assembler->output = output;
	assembler->output_capacity = output_capacity;
	assembler->expected_length = expected_length;
	memcpy(assembler->expected_digest, expected_digest,
	       sizeof(assembler->expected_digest));
	if (output != NULL && output_capacity != 0U) {
		memset(output, 0, output_capacity);
	}
	assembler->initialized = true;
	if (expected_length == 0U) {
		uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];

		if (pqcp_runtime_internal_sha256(
			    NULL, 0U, digest) != 0 ||
		    !pqcp_sovereign_channel_internal_equal(
			    digest, expected_digest,
			    sizeof(digest))) {
			pqcp_runtime_secure_zero(
				digest, sizeof(digest));
			memset(assembler, 0, sizeof(*assembler));
			return -EKEYREJECTED;
		}
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		assembler->completed = true;
	}
	return 0;
}

int pqcp_sovereign_channel_blob_assembler_append(
	struct pqcp_sovereign_channel_blob_assembler *assembler,
	uint64_t offset,
	const uint8_t *data,
	size_t data_length,
	bool final)
{
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	int ret;

	if (assembler == NULL || !assembler->initialized ||
	    assembler->completed || data == NULL ||
	    data_length == 0U ||
	    offset != assembler->received_length ||
	    offset > assembler->expected_length ||
	    data_length >
		    assembler->expected_length - offset ||
	    offset > assembler->output_capacity ||
	    data_length >
		    assembler->output_capacity - (size_t)offset) {
		return -EINVAL;
	}
	memcpy(assembler->output + (size_t)offset,
	       data, data_length);
	assembler->received_length += data_length;
	if (!final) {
		if (assembler->received_length ==
		    assembler->expected_length) {
			pqcp_runtime_secure_zero(
				assembler->output,
				assembler->output_capacity);
			assembler->received_length = 0U;
			return -EBADMSG;
		}
		return 0;
	}
	if (assembler->received_length !=
	    assembler->expected_length) {
		return -EBADMSG;
	}
	ret = pqcp_runtime_internal_sha256(
		assembler->output,
		(size_t)assembler->expected_length,
		digest);
	if (ret != 0) {
		return ret;
	}
	if (!pqcp_sovereign_channel_internal_equal(
		    digest, assembler->expected_digest,
		    sizeof(digest))) {
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		pqcp_runtime_secure_zero(
			assembler->output,
			assembler->output_capacity);
		assembler->received_length = 0U;
		return -EKEYREJECTED;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	assembler->completed = true;
	return 0;
}

int pqcp_sovereign_channel_blob_assembler_audit(
	const struct pqcp_sovereign_channel_blob_assembler *assembler)
{
	if (assembler == NULL || !assembler->initialized ||
	    assembler->expected_length >
		    assembler->output_capacity ||
	    assembler->received_length >
		    assembler->expected_length ||
	    (assembler->expected_length != 0U &&
	     assembler->output == NULL) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    assembler->expected_digest,
		    sizeof(assembler->expected_digest)) ||
	    (assembler->completed &&
	     assembler->received_length !=
		     assembler->expected_length)) {
		return -EBADMSG;
	}
	return 0;
}

uint32_t pqcp_sovereign_channel_internal_next_generation(
	uint32_t *generation)
{
	if (generation == NULL) {
		return 0U;
	}
	(*generation)++;
	if (*generation == 0U) {
		(*generation)++;
	}
	return *generation;
}

int pqcp_sovereign_channel_internal_receipt_digest(
	const uint8_t *receipt,
	size_t receipt_length,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	if ((receipt == NULL && receipt_length != 0U) ||
	    digest == NULL ||
	    receipt_length >
		    PQCP_SOVEREIGN_CHANNEL_RECEIPT_MAX_BYTES) {
		return -EINVAL;
	}
	return pqcp_runtime_internal_sha256(
		receipt, receipt_length, digest);
}
