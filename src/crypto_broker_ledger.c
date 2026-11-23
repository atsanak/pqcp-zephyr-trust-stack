/*
 * SPDX-License-Identifier: MIT
 *
 * Broker transaction replay and receipt-chain ledger helpers.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/crypto_broker.h>

#include "crypto_broker_internal.h"
#include "runtime_internal.h"

static bool terminal_state(
	enum pqcp_crypto_broker_transaction_state state)
{
	return state ==
		       PQCP_CRYPTO_BROKER_TRANSACTION_COMPLETED ||
	       state ==
		       PQCP_CRYPTO_BROKER_TRANSACTION_CANCELLED ||
	       state ==
		       PQCP_CRYPTO_BROKER_TRANSACTION_FAILED;
}

int pqcp_crypto_broker_internal_copy_transaction_response(
	const struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	uint8_t *caller_output;
	size_t caller_capacity;

	if (transaction == NULL || response == NULL ||
	    !terminal_state(transaction->state) ||
	    transaction->output_length >
		    sizeof(transaction->output)) {
		return -EINVAL;
	}
	caller_output = response->output;
	caller_capacity = response->output_capacity;
	if (transaction->output_length != 0U &&
	    (caller_output == NULL ||
	     caller_capacity < transaction->output_length)) {
		return -ENOSPC;
	}
	memset(response, 0, sizeof(*response));
	response->output = caller_output;
	response->output_capacity = caller_capacity;
	response->result = transaction->result;
	response->cancelled =
		transaction->state ==
			PQCP_CRYPTO_BROKER_TRANSACTION_CANCELLED;
	response->primary_key = transaction->primary_key;
	response->secondary_key = transaction->secondary_key;
	response->metadata = transaction->metadata;
	response->receipt = transaction->receipt;
	if (transaction->output_length != 0U) {
		memcpy(response->output, transaction->output,
		       transaction->output_length);
		response->output_length =
			transaction->output_length;
	}
	return 0;
}

static int receipt_digest_verify(
	const struct pqcp_crypto_broker_receipt *receipt)
{
	uint8_t body[PQCP_CRYPTO_BROKER_RECEIPT_BODY_MAX_BYTES];
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
	size_t body_length;
	int ret;

	if (receipt == NULL ||
	    receipt->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    receipt->sequence == 0U ||
	    pqcp_crypto_broker_internal_all_zero(
		    receipt->request_id,
		    sizeof(receipt->request_id)) ||
	    receipt->completed_at_ms <
		    receipt->accepted_at_ms) {
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
	pqcp_runtime_secure_zero(body, sizeof(body));
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int next_receipt_index(
	const struct pqcp_crypto_broker_transaction *transactions,
	size_t transaction_count,
	uint64_t after_sequence)
{
	uint64_t selected_sequence = UINT64_MAX;
	int selected = -1;

	for (size_t index = 0U; index < transaction_count; ++index) {
		const struct pqcp_crypto_broker_transaction *transaction =
			&transactions[index];
		const uint64_t sequence =
			transaction->receipt.sequence;

		if (!terminal_state(transaction->state) ||
		    sequence == 0U || sequence <= after_sequence) {
			continue;
		}
		if (sequence < selected_sequence) {
			selected_sequence = sequence;
			selected = (int)index;
		}
	}
	return selected;
}

int pqcp_crypto_broker_receipt_chain_verify(
	const struct pqcp_crypto_broker_transaction *transactions,
	size_t transaction_count,
	uint8_t chain_head[PQCP_RUNTIME_DIGEST_BYTES])
{
	uint8_t previous[PQCP_RUNTIME_DIGEST_BYTES] = { 0 };
	uint64_t previous_sequence = 0U;
	size_t verified = 0U;
	int index;
	int ret;

	if ((transactions == NULL && transaction_count != 0U) ||
	    chain_head == NULL) {
		return -EINVAL;
	}
	for (;;) {
		index = next_receipt_index(
			transactions, transaction_count,
			previous_sequence);
		if (index < 0) {
			break;
		}
		const struct pqcp_crypto_broker_receipt *receipt =
			&transactions[index].receipt;

		if (verified == 0U &&
		    !pqcp_crypto_broker_internal_all_zero(
			    receipt->previous_receipt_digest,
			    sizeof(receipt->previous_receipt_digest))) {
			pqcp_runtime_secure_zero(
				previous, sizeof(previous));
			return -EBADMSG;
		}
		if (verified != 0U &&
		    !pqcp_crypto_broker_internal_secure_equal(
			    receipt->previous_receipt_digest,
			    previous, sizeof(previous))) {
			pqcp_runtime_secure_zero(
				previous, sizeof(previous));
			return -EBADMSG;
		}
		ret = receipt_digest_verify(receipt);
		if (ret != 0) {
			pqcp_runtime_secure_zero(
				previous, sizeof(previous));
			return ret;
		}
		memcpy(previous, receipt->receipt_digest,
		       sizeof(previous));
		previous_sequence = receipt->sequence;
		verified++;
		if (verified > transaction_count) {
			pqcp_runtime_secure_zero(
				previous, sizeof(previous));
			return -ELOOP;
		}
	}
	if (verified == 0U) {
		memset(chain_head, 0,
		       PQCP_RUNTIME_DIGEST_BYTES);
	} else {
		memcpy(chain_head, previous,
		       PQCP_RUNTIME_DIGEST_BYTES);
	}
	pqcp_runtime_secure_zero(previous, sizeof(previous));
	return 0;
}
