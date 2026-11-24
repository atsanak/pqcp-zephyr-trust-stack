/*
 * SPDX-License-Identifier: MIT
 *
 * HMAC-bound bounded resumption for sovereign broker transactions.
 */

#include <errno.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_channel_internal.h"

#define SOVEREIGN_RESUME_DOMAIN "PQCP-SOVEREIGN-RESUME-V1"
#define SOVEREIGN_RESUME_CLAIM_BYTES 200U

static bool claim_valid(
	const struct pqcp_sovereign_channel_resume_claim *claim)
{
	if (claim == NULL ||
	    claim->schema_version !=
		    PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION ||
	    claim->generation == 0U ||
	    claim->issued_at_ms == 0U ||
	    claim->expires_at_ms < claim->issued_at_ms ||
	    pqcp_sovereign_channel_internal_all_zero(
		    claim->transaction_id,
		    sizeof(claim->transaction_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    claim->request_id,
		    sizeof(claim->request_id)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    claim->identity_digest,
		    sizeof(claim->identity_digest)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    claim->capability_digest,
		    sizeof(claim->capability_digest)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    claim->request_digest,
		    sizeof(claim->request_digest))) {
		return false;
	}
	return true;
}

static int encode_claim(
	const struct pqcp_sovereign_channel_resume_claim *claim,
	uint8_t output[SOVEREIGN_RESUME_CLAIM_BYTES])
{
	size_t offset = 0U;

	if (!claim_valid(claim) || output == NULL) {
		return -EINVAL;
	}
	memset(output, 0, SOVEREIGN_RESUME_CLAIM_BYTES);
	memcpy(output + offset, SOVEREIGN_RESUME_DOMAIN,
	       sizeof(SOVEREIGN_RESUME_DOMAIN) - 1U);
	offset += sizeof(SOVEREIGN_RESUME_DOMAIN) - 1U;
	pqcp_runtime_internal_write_u32(
		output + offset, claim->schema_version);
	offset += 4U;
	memcpy(output + offset, claim->transaction_id,
	       sizeof(claim->transaction_id));
	offset += sizeof(claim->transaction_id);
	memcpy(output + offset, claim->request_id,
	       sizeof(claim->request_id));
	offset += sizeof(claim->request_id);
	memcpy(output + offset, claim->identity_digest,
	       sizeof(claim->identity_digest));
	offset += sizeof(claim->identity_digest);
	memcpy(output + offset, claim->capability_digest,
	       sizeof(claim->capability_digest));
	offset += sizeof(claim->capability_digest);
	memcpy(output + offset, claim->request_digest,
	       sizeof(claim->request_digest));
	offset += sizeof(claim->request_digest);
	pqcp_runtime_internal_write_u64(
		output + offset, claim->received_offset);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		output + offset, claim->result_ack_offset);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		output + offset, claim->receipt_ack_offset);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		output + offset, claim->issued_at_ms);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		output + offset, claim->expires_at_ms);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		output + offset, claim->generation);
	offset += 4U;
	if (offset > SOVEREIGN_RESUME_CLAIM_BYTES) {
		pqcp_runtime_secure_zero(
			output, SOVEREIGN_RESUME_CLAIM_BYTES);
		return -EOVERFLOW;
	}
	return 0;
}

int pqcp_sovereign_channel_resume_token_issue(
	const uint8_t *secret,
	size_t secret_length,
	const struct pqcp_sovereign_channel_resume_claim *claim,
	uint8_t token[PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES])
{
	uint8_t encoded[SOVEREIGN_RESUME_CLAIM_BYTES];
	int ret;

	if (secret == NULL || secret_length < 16U ||
	    claim == NULL || token == NULL) {
		return -EINVAL;
	}
	ret = encode_claim(claim, encoded);
	if (ret == 0) {
		ret = pqcp_runtime_internal_hmac_sha256(
			secret, secret_length,
			encoded, sizeof(encoded), token);
	}
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			token,
			PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES);
	}
	return ret;
}

int pqcp_sovereign_channel_resume_token_verify(
	const uint8_t *secret,
	size_t secret_length,
	const struct pqcp_sovereign_channel_resume_claim *claim,
	const uint8_t token[PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES],
	uint64_t now_ms)
{
	uint8_t expected[PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES];
	int ret;

	if (secret == NULL || secret_length < 16U ||
	    !claim_valid(claim) || token == NULL ||
	    now_ms == 0U ||
	    now_ms < claim->issued_at_ms ||
	    now_ms > claim->expires_at_ms ||
	    pqcp_sovereign_channel_internal_all_zero(
		    token,
		    PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES)) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_channel_resume_token_issue(
		secret, secret_length, claim, expected);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_channel_internal_equal(
		expected, token, sizeof(expected)) ?
		0 : -EKEYREJECTED;
	pqcp_runtime_secure_zero(expected, sizeof(expected));
	return ret;
}

int pqcp_sovereign_channel_resume_claim_from_slot(
	const struct pqcp_sovereign_channel_server_slot *slot,
	struct pqcp_sovereign_channel_resume_claim *claim)
{
	if (slot == NULL || !slot->occupied ||
	    slot->generation == 0U || claim == NULL ||
	    slot->created_at_ms == 0U ||
	    slot->expires_at_ms < slot->created_at_ms ||
	    slot->assembler.received_length >
		    slot->assembler.expected_total_length ||
	    slot->result_ack_offset >
		    slot->response.output_length ||
	    slot->receipt_ack_offset >
		    slot->receipt_length ||
	    pqcp_sovereign_channel_internal_all_zero(
		    slot->identity_digest,
		    sizeof(slot->identity_digest)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    slot->capability_digest,
		    sizeof(slot->capability_digest)) ||
	    pqcp_sovereign_channel_internal_all_zero(
		    slot->request_digest,
		    sizeof(slot->request_digest))) {
		return -EINVAL;
	}
	memset(claim, 0, sizeof(*claim));
	claim->schema_version =
		PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION;
	memcpy(claim->transaction_id, slot->transaction_id,
	       sizeof(claim->transaction_id));
	memcpy(claim->request_id, slot->request_id,
	       sizeof(claim->request_id));
	memcpy(claim->identity_digest, slot->identity_digest,
	       sizeof(claim->identity_digest));
	memcpy(claim->capability_digest,
	       slot->capability_digest,
	       sizeof(claim->capability_digest));
	memcpy(claim->request_digest, slot->request_digest,
	       sizeof(claim->request_digest));
	claim->received_offset =
		slot->assembler.received_length;
	claim->result_ack_offset = slot->result_ack_offset;
	claim->receipt_ack_offset =
		slot->receipt_ack_offset;
	claim->issued_at_ms = slot->created_at_ms;
	claim->expires_at_ms = slot->expires_at_ms;
	claim->generation = slot->generation;
	return 0;
}
