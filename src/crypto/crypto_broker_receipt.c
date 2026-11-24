/*
 * SPDX-License-Identifier: MIT
 *
 * Cryptographically chained execution receipts for the PQC crypto broker.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/crypto_broker.h>
#include <pqcp_zephyr/errno.h>

#include "crypto_broker_internal.h"
#include "runtime_internal.h"

#define BROKER_PRINCIPAL_BINDING_BYTES 192U
#define BROKER_AUTHORIZATION_BINDING_BYTES 128U
#define BROKER_KEY_BINDING_BYTES 160U
#define BROKER_RECEIPT_MAC_INPUT_BYTES \
	(sizeof(PQCP_CRYPTO_BROKER_RECEIPT_CONTEXT) - 1U + \
	 PQCP_RUNTIME_DIGEST_BYTES)

static size_t append_u32(
	uint8_t *output,
	size_t offset,
	uint32_t value)
{
	pqcp_runtime_internal_write_u32(output + offset, value);
	return offset + 4U;
}

static size_t append_i32(
	uint8_t *output,
	size_t offset,
	int32_t value)
{
	pqcp_runtime_internal_write_u32(
		output + offset, (uint32_t)value);
	return offset + 4U;
}

static size_t append_u64(
	uint8_t *output,
	size_t offset,
	uint64_t value)
{
	pqcp_runtime_internal_write_u64(output + offset, value);
	return offset + 8U;
}

static size_t append_handle(
	uint8_t *output,
	size_t offset,
	const struct pqcp_runtime_key_handle *handle)
{
	offset = append_u32(output, offset, handle->slot);
	offset = append_u32(output, offset, handle->generation);
	offset = append_u32(
		output, offset, (uint32_t)handle->backend);
	offset = append_u32(
		output, offset, (uint32_t)handle->family);
	offset = append_u32(output, offset, handle->level);
	return offset;
}

static int principal_digest(
	const struct pqcp_crypto_broker_principal *principal,
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES])
{
	uint8_t encoded[BROKER_PRINCIPAL_BINDING_BYTES];
	size_t id_length;
	size_t tenant_length;
	size_t domain_length;
	size_t offset = 0U;

	if (principal == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(encoded, 0, sizeof(encoded));
	memcpy(encoded + offset,
	       "PQCP-BROKER-PRINCIPAL-V1", 24U);
	offset += 24U;
	id_length = strnlen(
		principal->id, sizeof(principal->id));
	tenant_length = strnlen(
		principal->tenant, sizeof(principal->tenant));
	domain_length = strnlen(
		principal->trust_domain,
		sizeof(principal->trust_domain));
	encoded[offset++] = (uint8_t)id_length;
	memcpy(encoded + offset, principal->id, id_length);
	offset += id_length;
	encoded[offset++] = (uint8_t)tenant_length;
	memcpy(encoded + offset, principal->tenant,
	       tenant_length);
	offset += tenant_length;
	encoded[offset++] = (uint8_t)domain_length;
	memcpy(encoded + offset, principal->trust_domain,
	       domain_length);
	offset += domain_length;
	memcpy(encoded + offset, principal->identity_digest,
	       sizeof(principal->identity_digest));
	offset += sizeof(principal->identity_digest);
	offset = append_u32(
		encoded, offset, principal->generation);
	offset = append_u32(
		encoded, offset, (uint32_t)principal->state);
	if (offset > sizeof(encoded)) {
		pqcp_runtime_secure_zero(
			encoded, sizeof(encoded));
		return -EOVERFLOW;
	}
	int ret = pqcp_runtime_internal_sha256(
		encoded, offset, digest);

	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static int authorization_digest(
	const struct pqcp_crypto_broker_authorization *authorization,
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES])
{
	uint8_t encoded[BROKER_AUTHORIZATION_BINDING_BYTES];
	size_t reason_length;
	size_t offset = 0U;

	if (authorization == NULL || digest == NULL) {
		return -EINVAL;
	}
	memset(encoded, 0, sizeof(encoded));
	memcpy(encoded + offset,
	       "PQCP-BROKER-AUTHORIZATION-V1", 28U);
	offset += 28U;
	offset = append_u32(
		encoded, offset,
		authorization->principal_index);
	offset = append_u32(
		encoded, offset,
		authorization->grant_index);
	offset = append_u32(
		encoded, offset,
		authorization->capability_index);
	offset = append_u32(
		encoded, offset,
		(uint32_t)authorization->decision);
	offset = append_u64(
		encoded, offset, authorization->cost_units);
	reason_length = strnlen(
		authorization->reason,
		sizeof(authorization->reason));
	encoded[offset++] = (uint8_t)reason_length;
	memcpy(encoded + offset, authorization->reason,
	       reason_length);
	offset += reason_length;
	if (offset > sizeof(encoded)) {
		pqcp_runtime_secure_zero(
			encoded, sizeof(encoded));
		return -EOVERFLOW;
	}
	int ret = pqcp_runtime_internal_sha256(
		encoded, offset, digest);

	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

static int key_binding_digest(
	const struct pqcp_crypto_broker_request *request,
	const struct pqcp_crypto_broker_transaction *transaction,
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES])
{
	uint8_t encoded[BROKER_KEY_BINDING_BYTES];
	size_t offset = 0U;

	if (request == NULL || transaction == NULL ||
	    digest == NULL) {
		return -EINVAL;
	}
	memset(encoded, 0, sizeof(encoded));
	memcpy(encoded + offset,
	       "PQCP-BROKER-KEY-BINDING-V1", 26U);
	offset += 26U;
	offset = append_handle(
		encoded, offset, &request->primary_key);
	offset = append_handle(
		encoded, offset, &request->secondary_key);
	offset = append_handle(
		encoded, offset, &transaction->primary_key);
	offset = append_handle(
		encoded, offset, &transaction->secondary_key);
	offset = append_u32(
		encoded, offset,
		(uint32_t)request->key_spec.family);
	offset = append_u32(
		encoded, offset, request->key_spec.level);
	offset = append_u32(
		encoded, offset, request->key_spec.usage);
	offset = append_u64(
		encoded, offset,
		request->key_spec.expires_at_ms);
	offset = append_u32(
		encoded, offset,
		(uint32_t)transaction->metadata.custody);
	if (offset > sizeof(encoded)) {
		pqcp_runtime_secure_zero(
			encoded, sizeof(encoded));
		return -EOVERFLOW;
	}
	int ret = pqcp_runtime_internal_sha256(
		encoded, offset, digest);

	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

size_t pqcp_crypto_broker_internal_receipt_body(
	const struct pqcp_crypto_broker_receipt *receipt,
	uint8_t output[PQCP_CRYPTO_BROKER_RECEIPT_BODY_MAX_BYTES])
{
	size_t offset = 0U;

	if (receipt == NULL || output == NULL ||
	    receipt->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    receipt->sequence == 0U) {
		return 0U;
	}
	memset(output, 0,
	       PQCP_CRYPTO_BROKER_RECEIPT_BODY_MAX_BYTES);
	memcpy(output + offset,
	       "PQCP-BROKER-RECEIPT-V1", 22U);
	offset += 22U;
	offset = append_u32(
		output, offset, receipt->schema_version);
	offset = append_u64(
		output, offset, receipt->sequence);
	memcpy(output + offset, receipt->request_id,
	       sizeof(receipt->request_id));
	offset += sizeof(receipt->request_id);
	memcpy(output + offset, receipt->request_digest,
	       sizeof(receipt->request_digest));
	offset += sizeof(receipt->request_digest);
	memcpy(output + offset, receipt->principal_digest,
	       sizeof(receipt->principal_digest));
	offset += sizeof(receipt->principal_digest);
	memcpy(output + offset,
	       receipt->authorization_digest,
	       sizeof(receipt->authorization_digest));
	offset += sizeof(receipt->authorization_digest);
	memcpy(output + offset, receipt->key_binding_digest,
	       sizeof(receipt->key_binding_digest));
	offset += sizeof(receipt->key_binding_digest);
	memcpy(output + offset, receipt->output_digest,
	       sizeof(receipt->output_digest));
	offset += sizeof(receipt->output_digest);
	memcpy(output + offset,
	       receipt->previous_receipt_digest,
	       sizeof(receipt->previous_receipt_digest));
	offset += sizeof(receipt->previous_receipt_digest);
	offset = append_u64(
		output, offset, receipt->accepted_at_ms);
	offset = append_u64(
		output, offset, receipt->completed_at_ms);
	offset = append_u64(
		output, offset, receipt->cost_units);
	offset = append_u32(
		output, offset,
		(uint32_t)receipt->operation);
	offset = append_u32(
		output, offset,
		(uint32_t)receipt->decision);
	offset = append_i32(
		output, offset, receipt->result);
	output[offset++] = receipt->signed_receipt ? 1U : 0U;
	if (offset >
	    PQCP_CRYPTO_BROKER_RECEIPT_BODY_MAX_BYTES) {
		pqcp_runtime_secure_zero(
			output,
			PQCP_CRYPTO_BROKER_RECEIPT_BODY_MAX_BYTES);
		return 0U;
	}
	return offset;
}

static int receipt_mac(
	const struct pqcp_crypto_broker_config *config,
	const uint8_t receipt_digest[PQCP_RUNTIME_DIGEST_BYTES],
	uint8_t mac[PQCP_CRYPTO_BROKER_RECEIPT_MAC_BYTES])
{
	uint8_t input[BROKER_RECEIPT_MAC_INPUT_BYTES];
	size_t offset = 0U;
	int ret;

	memcpy(input + offset,
	       PQCP_CRYPTO_BROKER_RECEIPT_CONTEXT,
	       sizeof(PQCP_CRYPTO_BROKER_RECEIPT_CONTEXT) - 1U);
	offset +=
		sizeof(PQCP_CRYPTO_BROKER_RECEIPT_CONTEXT) - 1U;
	memcpy(input + offset, receipt_digest,
	       PQCP_RUNTIME_DIGEST_BYTES);
	offset += PQCP_RUNTIME_DIGEST_BYTES;
	ret = pqcp_runtime_internal_hmac_sha256(
		config->receipt_mac_key,
		config->receipt_mac_key_length,
		input, offset, mac);
	pqcp_runtime_secure_zero(input, sizeof(input));
	return ret;
}

static bool signed_receipt_required(
	const struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const struct pqcp_crypto_broker_authorization *authorization)
{
	if (broker->config.receipt_mode ==
	    PQCP_CRYPTO_BROKER_RECEIPT_HMAC_AND_MLDSA) {
		return true;
	}
	if ((request->flags &
	     PQCP_CRYPTO_BROKER_REQUEST_REQUIRE_SIGNED_RECEIPT) !=
	    0U) {
		return true;
	}
	return broker->storage.grants[
		authorization->grant_index].policy.require_signed_receipt;
}

int pqcp_crypto_broker_internal_create_receipt(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const struct pqcp_crypto_broker_authorization *authorization,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	struct pqcp_crypto_broker_receipt *receipt =
		&response->receipt;
	const struct pqcp_crypto_broker_principal *principal;
	uint8_t body[PQCP_CRYPTO_BROKER_RECEIPT_BODY_MAX_BYTES];
	size_t body_length;
	size_t signature_length = 0U;
	int ret;

	if (broker == NULL || request == NULL ||
	    authorization == NULL || transaction == NULL ||
	    response == NULL ||
	    authorization->principal_index >=
		    broker->storage.principal_capacity ||
	    authorization->grant_index >=
		    broker->storage.grant_capacity) {
		return -EINVAL;
	}
	principal = &broker->storage.principals[
		authorization->principal_index];
	memset(receipt, 0, sizeof(*receipt));
	receipt->schema_version =
		PQCP_CRYPTO_BROKER_SCHEMA_VERSION;
	receipt->sequence = broker->next_receipt_sequence++;
	if (receipt->sequence == 0U) {
		receipt->sequence =
			broker->next_receipt_sequence++;
	}
	memcpy(receipt->request_id, request->request_id,
	       sizeof(receipt->request_id));
	memcpy(receipt->request_digest,
	       transaction->request_digest,
	       sizeof(receipt->request_digest));
	ret = principal_digest(
		principal, receipt->principal_digest);
	if (ret == 0) {
		ret = authorization_digest(
			authorization,
			receipt->authorization_digest);
	}
	if (ret == 0) {
		ret = key_binding_digest(
			request, transaction,
			receipt->key_binding_digest);
	}
	if (ret == 0) {
		ret = pqcp_runtime_internal_sha256(
			transaction->output,
			transaction->output_length,
			receipt->output_digest);
	}
	if (ret != 0) {
		goto cleanup;
	}
	memcpy(receipt->previous_receipt_digest,
	       broker->receipt_chain_head,
	       sizeof(receipt->previous_receipt_digest));
	receipt->accepted_at_ms =
		transaction->accepted_at_ms;
	receipt->completed_at_ms =
		transaction->completed_at_ms;
	receipt->cost_units = authorization->cost_units;
	receipt->operation = request->operation;
	receipt->decision = authorization->decision;
	receipt->result = transaction->result;
	receipt->signed_receipt =
		signed_receipt_required(
			broker, request, authorization);
	body_length =
		pqcp_crypto_broker_internal_receipt_body(
			receipt, body);
	if (body_length == 0U) {
		ret = -EOVERFLOW;
		goto cleanup;
	}
	ret = pqcp_runtime_internal_sha256(
		body, body_length, receipt->receipt_digest);
	if (ret == 0) {
		ret = receipt_mac(
			&broker->config,
			receipt->receipt_digest, receipt->mac);
	}
	if (ret == 0 && receipt->signed_receipt) {
		if (!pqcp_runtime_key_handle_is_valid(
			    &broker->config.receipt_signing_key)) {
			ret = -ENOKEY;
		} else {
			ret = pqcp_runtime_key_store_sign(
				broker->config.key_store,
				&broker->config.receipt_signing_key,
				receipt->receipt_digest,
				sizeof(receipt->receipt_digest),
				(const uint8_t *)
					PQCP_CRYPTO_BROKER_RECEIPT_CONTEXT,
				sizeof(PQCP_CRYPTO_BROKER_RECEIPT_CONTEXT) -
					1U,
				receipt->signature,
				sizeof(receipt->signature),
				&signature_length);
			receipt->signature_length =
				signature_length;
		}
	}
	if (ret == 0) {
		memcpy(broker->receipt_chain_head,
		       receipt->receipt_digest,
		       sizeof(broker->receipt_chain_head));
		transaction->receipt = *receipt;
	}

cleanup:
	pqcp_runtime_secure_zero(body, sizeof(body));
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			receipt, sizeof(*receipt));
	}
	return ret;
}

int pqcp_crypto_broker_receipt_verify(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_receipt *receipt)
{
	uint8_t body[PQCP_CRYPTO_BROKER_RECEIPT_BODY_MAX_BYTES];
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t expected_mac[PQCP_RUNTIME_DIGEST_BYTES];
	size_t body_length;
	int ret;

	if (broker == NULL || !broker->initialized ||
	    receipt == NULL ||
	    receipt->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    receipt->sequence == 0U ||
	    receipt->completed_at_ms <
		    receipt->accepted_at_ms ||
	    receipt->operation <=
		    PQCP_CRYPTO_BROKER_OPERATION_NONE ||
	    receipt->operation >=
		    PQCP_CRYPTO_BROKER_OPERATION_COUNT ||
	    receipt->decision <=
		    PQCP_CRYPTO_BROKER_DECISION_UNSET ||
	    receipt->decision >
		    PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY) {
		return -EINVAL;
	}
	body_length =
		pqcp_crypto_broker_internal_receipt_body(
			receipt, body);
	if (body_length == 0U) {
		return -EBADMSG;
	}
	ret = pqcp_runtime_internal_sha256(
		body, body_length, digest);
	if (ret == 0 &&
	    !pqcp_crypto_broker_internal_secure_equal(
		    digest, receipt->receipt_digest,
		    sizeof(digest))) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = receipt_mac(
			&broker->config, digest, expected_mac);
	}
	if (ret == 0 &&
	    !pqcp_crypto_broker_internal_secure_equal(
		    expected_mac, receipt->mac,
		    sizeof(expected_mac))) {
		ret = -EKEYREJECTED;
	}
	if (ret == 0 && receipt->signed_receipt) {
		if (receipt->signature_length == 0U ||
		    receipt->signature_length >
			    sizeof(receipt->signature) ||
		    !pqcp_runtime_key_handle_is_valid(
			    &broker->config.receipt_signing_key)) {
			ret = -EBADMSG;
		} else {
			ret = pqcp_runtime_key_store_verify(
				broker->config.key_store,
				&broker->config.receipt_signing_key,
				receipt->receipt_digest,
				sizeof(receipt->receipt_digest),
				(const uint8_t *)
					PQCP_CRYPTO_BROKER_RECEIPT_CONTEXT,
				sizeof(PQCP_CRYPTO_BROKER_RECEIPT_CONTEXT) -
					1U,
				receipt->signature,
				receipt->signature_length);
		}
	}
	pqcp_runtime_secure_zero(body, sizeof(body));
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	pqcp_runtime_secure_zero(
		expected_mac, sizeof(expected_mac));
	return ret;
}
