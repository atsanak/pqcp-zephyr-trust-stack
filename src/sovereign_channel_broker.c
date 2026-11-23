/*
 * SPDX-License-Identifier: MIT
 *
 * Authenticated identity and crypto-broker adapters.
 */

#include <errno.h>
#include <string.h>

#include "crypto_broker_internal.h"
#include "runtime_internal.h"
#include "sovereign_channel_internal.h"

#define SOVEREIGN_RECEIPT_MAGIC 0x53524350U
#define SOVEREIGN_RECEIPT_FIXED_BYTES 328U

static int broker_request_from_wire(
	const struct pqcp_sovereign_channel_begin *begin,
	const struct pqcp_sovereign_channel_request_assembler *assembler,
	struct pqcp_crypto_broker_request *request)
{
	if (begin == NULL || assembler == NULL ||
	    !assembler->initialized || !assembler->committed ||
	    request == NULL ||
	    assembler->expected_input_length !=
		    begin->input_length ||
	    assembler->expected_aux_length !=
		    begin->aux_input_length ||
	    assembler->expected_context_length !=
		    begin->context_length ||
	    !pqcp_sovereign_channel_internal_equal(
		    assembler->expected_content_digest,
		    begin->content_digest,
		    sizeof(begin->content_digest))) {
		return -EINVAL;
	}
	memset(request, 0, sizeof(*request));
	request->schema_version =
		PQCP_CRYPTO_BROKER_SCHEMA_VERSION;
	memcpy(request->request_id, assembler->request_id,
	       sizeof(request->request_id));
	memcpy(request->capability, begin->capability,
	       sizeof(request->capability));
	memcpy(request->principal_id, begin->principal_id,
	       sizeof(request->principal_id));
	request->principal_id[
		sizeof(request->principal_id) - 1U] = '\0';
	request->operation = begin->operation;
	request->submitted_at_ms = begin->submitted_at_ms;
	request->deadline_ms = begin->deadline_ms;
	request->flags = begin->request_flags |
		PQCP_CRYPTO_BROKER_REQUEST_CHANNEL_AUTHENTICATED;
	request->level = begin->level;
	request->key_spec = begin->key_spec;
	request->primary_key = begin->primary_key;
	request->secondary_key = begin->secondary_key;
	request->input = assembler->input;
	request->input_length =
		assembler->expected_input_length;
	request->aux_input = assembler->aux_input;
	request->aux_input_length =
		assembler->expected_aux_length;
	request->context = assembler->context;
	request->context_length =
		assembler->expected_context_length;
	return 0;
}

int pqcp_sovereign_channel_identity_digest(
	const struct pqcp_channel *channel,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	if (channel == NULL || digest == NULL ||
	    channel->state != PQCP_CHANNEL_STATE_ESTABLISHED ||
	    !channel->established || !channel->peer_authenticated ||
	    channel->config.peer_identity_public_length == 0U ||
	    channel->config.peer_identity_public_length >
		    sizeof(channel->config.peer_identity_public)) {
		return -EACCES;
	}
	return pqcp_runtime_internal_sha256(
		channel->config.peer_identity_public,
		channel->config.peer_identity_public_length,
		digest);
}

int pqcp_sovereign_channel_broker_bind_identity(
	struct pqcp_crypto_broker *broker,
	const uint8_t identity_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES],
	const char *principal_id,
	const char *tenant_id)
{
	int ret;

	if (broker == NULL || !broker->initialized ||
	    identity_digest == NULL || principal_id == NULL ||
	    tenant_id == NULL ||
	    pqcp_sovereign_channel_internal_all_zero(
		    identity_digest,
		    PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES) ||
	    strnlen(principal_id,
		    PQCP_CRYPTO_BROKER_ID_MAX_CHARS) == 0U ||
	    strnlen(principal_id,
		    PQCP_CRYPTO_BROKER_ID_MAX_CHARS) >=
		    PQCP_CRYPTO_BROKER_ID_MAX_CHARS ||
	    strnlen(tenant_id,
		    PQCP_CRYPTO_BROKER_TENANT_MAX_CHARS) == 0U ||
	    strnlen(tenant_id,
		    PQCP_CRYPTO_BROKER_TENANT_MAX_CHARS) >=
		    PQCP_CRYPTO_BROKER_TENANT_MAX_CHARS) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&broker->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = -ENOENT;
	for (size_t index = 0U;
	     index < broker->storage.principal_capacity;
	     ++index) {
		const struct pqcp_crypto_broker_principal *principal =
			&broker->storage.principals[index];

		if (principal->state ==
			    PQCP_CRYPTO_BROKER_PRINCIPAL_EMPTY ||
		    strcmp(principal->id, principal_id) != 0) {
			continue;
		}
		if (principal->state !=
			    PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE ||
		    strcmp(principal->tenant, tenant_id) != 0 ||
		    !pqcp_sovereign_channel_internal_equal(
			    principal->identity_digest,
			    identity_digest,
			    sizeof(principal->identity_digest))) {
			ret = -EACCES;
		} else {
			ret = 0;
		}
		break;
	}
	(void)k_mutex_unlock(&broker->lock);
	return ret;
}

int pqcp_sovereign_channel_broker_execute(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_sovereign_channel_begin *begin,
	const struct pqcp_sovereign_channel_request_assembler *assembler,
	struct pqcp_crypto_broker_response *response)
{
	struct pqcp_crypto_broker_request request;
	int ret;

	if (broker == NULL || !broker->initialized ||
	    response == NULL) {
		return -EINVAL;
	}
	ret = broker_request_from_wire(
		begin, assembler, &request);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_crypto_broker_execute(
		broker, &request, response);
	pqcp_runtime_secure_zero(&request, sizeof(request));
	return ret;
}

int pqcp_sovereign_channel_broker_cancel(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	const uint8_t request_id[
		PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	uint64_t now_ms)
{
	if (broker == NULL || !broker->initialized ||
	    principal_id == NULL || request_id == NULL ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	return pqcp_crypto_broker_cancel(
		broker, principal_id, request_id, now_ms);
}

int pqcp_sovereign_channel_internal_broker_request_digest(
	const struct pqcp_sovereign_channel_begin *begin,
	const struct pqcp_sovereign_channel_request_assembler *assembler,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES])
{
	struct pqcp_crypto_broker_request request;
	int ret;

	if (digest == NULL) {
		return -EINVAL;
	}
	ret = broker_request_from_wire(
		begin, assembler, &request);
	if (ret == 0) {
		ret = pqcp_crypto_broker_internal_request_digest(
			&request, digest);
	}
	pqcp_runtime_secure_zero(&request, sizeof(request));
	return ret;
}

static void receipt_write_bytes(
	uint8_t *output,
	size_t *offset,
	const uint8_t *value,
	size_t length)
{
	memcpy(output + *offset, value, length);
	*offset += length;
}

static void receipt_write_u32(
	uint8_t *output,
	size_t *offset,
	uint32_t value)
{
	pqcp_runtime_internal_write_u32(
		output + *offset, value);
	*offset += 4U;
}

static void receipt_write_u64(
	uint8_t *output,
	size_t *offset,
	uint64_t value)
{
	pqcp_runtime_internal_write_u64(
		output + *offset, value);
	*offset += 8U;
}

int pqcp_sovereign_channel_receipt_encode(
	const struct pqcp_crypto_broker_receipt *receipt,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	size_t required;
	size_t offset = 0U;
	uint32_t flags = 0U;

	if (receipt == NULL || output == NULL ||
	    output_length == NULL ||
	    receipt->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    receipt->sequence == 0U ||
	    receipt->operation <=
		    PQCP_CRYPTO_BROKER_OPERATION_NONE ||
	    receipt->operation >=
		    PQCP_CRYPTO_BROKER_OPERATION_COUNT ||
	    receipt->decision <=
		    PQCP_CRYPTO_BROKER_DECISION_UNSET ||
	    receipt->decision >
		    PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY ||
	    receipt->signature_length >
		    sizeof(receipt->signature) ||
	    (receipt->signed_receipt &&
	     receipt->signature_length == 0U) ||
	    (!receipt->signed_receipt &&
	     receipt->signature_length != 0U)) {
		return -EINVAL;
	}
	required = SOVEREIGN_RECEIPT_FIXED_BYTES +
		receipt->signature_length;
	if (required > output_capacity ||
	    required >
		    PQCP_SOVEREIGN_CHANNEL_RECEIPT_MAX_BYTES) {
		return -ENOSPC;
	}
	memset(output, 0, required);
	receipt_write_u32(
		output, &offset, SOVEREIGN_RECEIPT_MAGIC);
	receipt_write_u32(
		output, &offset,
		PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION);
	receipt_write_u32(
		output, &offset, (uint32_t)required);
	receipt_write_u32(
		output, &offset, receipt->schema_version);
	receipt_write_u64(
		output, &offset, receipt->sequence);
	receipt_write_bytes(
		output, &offset, receipt->request_id,
		sizeof(receipt->request_id));
	receipt_write_bytes(
		output, &offset, receipt->request_digest,
		sizeof(receipt->request_digest));
	receipt_write_bytes(
		output, &offset, receipt->principal_digest,
		sizeof(receipt->principal_digest));
	receipt_write_bytes(
		output, &offset, receipt->authorization_digest,
		sizeof(receipt->authorization_digest));
	receipt_write_bytes(
		output, &offset, receipt->key_binding_digest,
		sizeof(receipt->key_binding_digest));
	receipt_write_bytes(
		output, &offset, receipt->output_digest,
		sizeof(receipt->output_digest));
	receipt_write_bytes(
		output, &offset,
		receipt->previous_receipt_digest,
		sizeof(receipt->previous_receipt_digest));
	receipt_write_bytes(
		output, &offset, receipt->receipt_digest,
		sizeof(receipt->receipt_digest));
	receipt_write_bytes(
		output, &offset, receipt->mac,
		sizeof(receipt->mac));
	receipt_write_u32(
		output, &offset,
		(uint32_t)receipt->signature_length);
	receipt_write_u64(
		output, &offset, receipt->accepted_at_ms);
	receipt_write_u64(
		output, &offset, receipt->completed_at_ms);
	receipt_write_u64(
		output, &offset, receipt->cost_units);
	receipt_write_u32(
		output, &offset, (uint32_t)receipt->operation);
	receipt_write_u32(
		output, &offset, (uint32_t)receipt->decision);
	receipt_write_u32(
		output, &offset,
		(uint32_t)(int32_t)receipt->result);
	if (receipt->signed_receipt) {
		flags |= 1U;
	}
	receipt_write_u32(output, &offset, flags);
	if (offset > SOVEREIGN_RECEIPT_FIXED_BYTES) {
		pqcp_runtime_secure_zero(output, required);
		return -EOVERFLOW;
	}
	offset = SOVEREIGN_RECEIPT_FIXED_BYTES;
	if (receipt->signature_length != 0U) {
		receipt_write_bytes(
			output, &offset, receipt->signature,
			receipt->signature_length);
	}
	if (offset != required) {
		pqcp_runtime_secure_zero(output, required);
		return -EOVERFLOW;
	}
	*output_length = required;
	return 0;
}

static int receipt_read_bytes(
	const uint8_t *input,
	size_t input_length,
	size_t *offset,
	uint8_t *output,
	size_t length)
{
	if (input == NULL || offset == NULL ||
	    output == NULL || *offset > input_length ||
	    length > input_length - *offset) {
		return -EBADMSG;
	}
	memcpy(output, input + *offset, length);
	*offset += length;
	return 0;
}

static int receipt_read_u32(
	const uint8_t *input,
	size_t input_length,
	size_t *offset,
	uint32_t *value)
{
	if (input == NULL || offset == NULL ||
	    value == NULL || *offset > input_length ||
	    4U > input_length - *offset) {
		return -EBADMSG;
	}
	*value = pqcp_runtime_internal_read_u32(
		input + *offset);
	*offset += 4U;
	return 0;
}

static int receipt_read_u64(
	const uint8_t *input,
	size_t input_length,
	size_t *offset,
	uint64_t *value)
{
	if (input == NULL || offset == NULL ||
	    value == NULL || *offset > input_length ||
	    8U > input_length - *offset) {
		return -EBADMSG;
	}
	*value = pqcp_runtime_internal_read_u64(
		input + *offset);
	*offset += 8U;
	return 0;
}

int pqcp_sovereign_channel_receipt_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_crypto_broker_receipt *receipt)
{
	size_t offset = 0U;
	uint32_t magic = 0U;
	uint32_t wire_schema = 0U;
	uint32_t encoded_length = 0U;
	uint32_t signature_length;
	uint32_t operation;
	uint32_t decision;
	uint32_t result;
	uint32_t flags;
	int ret;

	if (input == NULL || receipt == NULL ||
	    input_length < SOVEREIGN_RECEIPT_FIXED_BYTES ||
	    input_length >
		    PQCP_SOVEREIGN_CHANNEL_RECEIPT_MAX_BYTES) {
		return -EINVAL;
	}
	memset(receipt, 0, sizeof(*receipt));
	ret = receipt_read_u32(
		input, input_length, &offset, &magic);
	if (ret == 0) {
		ret = receipt_read_u32(
			input, input_length, &offset,
			&wire_schema);
	}
	if (ret == 0) {
		ret = receipt_read_u32(
			input, input_length, &offset,
			&encoded_length);
	}
	if (ret != 0 ||
	    magic != SOVEREIGN_RECEIPT_MAGIC ||
	    wire_schema !=
		    PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION ||
	    encoded_length != input_length) {
		return -EBADMSG;
	}
	ret = receipt_read_u32(
		input, input_length, &offset,
		&receipt->schema_version);
	if (ret == 0) {
		ret = receipt_read_u64(
			input, input_length, &offset,
			&receipt->sequence);
	}
	if (ret == 0) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->request_id,
			sizeof(receipt->request_id));
	}
	if (ret == 0) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->request_digest,
			sizeof(receipt->request_digest));
	}
	if (ret == 0) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->principal_digest,
			sizeof(receipt->principal_digest));
	}
	if (ret == 0) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->authorization_digest,
			sizeof(receipt->authorization_digest));
	}
	if (ret == 0) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->key_binding_digest,
			sizeof(receipt->key_binding_digest));
	}
	if (ret == 0) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->output_digest,
			sizeof(receipt->output_digest));
	}
	if (ret == 0) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->previous_receipt_digest,
			sizeof(receipt->previous_receipt_digest));
	}
	if (ret == 0) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->receipt_digest,
			sizeof(receipt->receipt_digest));
	}
	if (ret == 0) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->mac,
			sizeof(receipt->mac));
	}
	if (ret == 0) {
		ret = receipt_read_u32(
			input, input_length, &offset,
			&signature_length);
	}
	if (ret == 0) {
		ret = receipt_read_u64(
			input, input_length, &offset,
			&receipt->accepted_at_ms);
	}
	if (ret == 0) {
		ret = receipt_read_u64(
			input, input_length, &offset,
			&receipt->completed_at_ms);
	}
	if (ret == 0) {
		ret = receipt_read_u64(
			input, input_length, &offset,
			&receipt->cost_units);
	}
	if (ret == 0) {
		ret = receipt_read_u32(
			input, input_length, &offset, &operation);
	}
	if (ret == 0) {
		ret = receipt_read_u32(
			input, input_length, &offset, &decision);
	}
	if (ret == 0) {
		ret = receipt_read_u32(
			input, input_length, &offset, &result);
	}
	if (ret == 0) {
		ret = receipt_read_u32(
			input, input_length, &offset, &flags);
	}
	if (ret != 0 || offset > SOVEREIGN_RECEIPT_FIXED_BYTES ||
	    signature_length > sizeof(receipt->signature) ||
	    SOVEREIGN_RECEIPT_FIXED_BYTES +
			    signature_length !=
		    input_length ||
	    (flags & ~1U) != 0U) {
		memset(receipt, 0, sizeof(*receipt));
		return -EBADMSG;
	}
	offset = SOVEREIGN_RECEIPT_FIXED_BYTES;
	if (signature_length != 0U) {
		ret = receipt_read_bytes(
			input, input_length, &offset,
			receipt->signature, signature_length);
		if (ret != 0) {
			memset(receipt, 0, sizeof(*receipt));
			return ret;
		}
	}
	receipt->signature_length = signature_length;
	receipt->operation =
		(enum pqcp_crypto_broker_operation)operation;
	receipt->decision =
		(enum pqcp_crypto_broker_decision)decision;
	receipt->result = (int32_t)result;
	receipt->signed_receipt = (flags & 1U) != 0U;
	if (offset != input_length ||
	    receipt->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    receipt->sequence == 0U ||
	    receipt->operation <=
		    PQCP_CRYPTO_BROKER_OPERATION_NONE ||
	    receipt->operation >=
		    PQCP_CRYPTO_BROKER_OPERATION_COUNT ||
	    receipt->decision <=
		    PQCP_CRYPTO_BROKER_DECISION_UNSET ||
	    receipt->decision >
		    PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY ||
	    receipt->signed_receipt !=
		    (signature_length != 0U)) {
		pqcp_runtime_secure_zero(
			receipt, sizeof(*receipt));
		return -EBADMSG;
	}
	return 0;
}
