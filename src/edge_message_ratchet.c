/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Symmetric hash ratchet for forward-evolving message keys.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

#define RATCHET_SEND_LABEL "pqcp-edge-send-v1"
#define RATCHET_RECEIVE_LABEL "pqcp-edge-receive-v1"
#define RATCHET_MESSAGE_LABEL "pqcp-edge-message-v1"
#define RATCHET_CHAIN_LABEL "pqcp-edge-chain-v1"
#define RATCHET_ROOT_LABEL "pqcp-edge-root-v1"

static int derive_labeled_key(
	const uint8_t chain_key[PQCP_EDGE_KEY_BYTES],
	const char *label,
	uint64_t epoch,
	uint64_t sequence,
	uint8_t output[PQCP_EDGE_KEY_BYTES])
{
	uint8_t info[64];
	size_t label_length;
	size_t offset = 0U;

	if (chain_key == NULL || label == NULL ||
	    output == NULL) {
		return -EINVAL;
	}
	label_length = strlen(label);
	if (label_length + 16U > sizeof(info)) {
		return -E2BIG;
	}
	memcpy(info + offset, label, label_length);
	offset += label_length;
	pqcp_edge_internal_write_u64(
		info + offset, epoch);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		info + offset, sequence);
	offset += 8U;
	return pqcp_edge_internal_hkdf(
		chain_key, chain_key,
		info, offset, output);
}

static int advance_chain(
	uint8_t chain_key[PQCP_EDGE_KEY_BYTES],
	uint64_t epoch,
	uint64_t sequence)
{
	uint8_t next[PQCP_EDGE_KEY_BYTES];
	int ret;

	ret = derive_labeled_key(
		chain_key, RATCHET_CHAIN_LABEL,
		epoch, sequence, next);
	if (ret == 0) {
		memcpy(chain_key, next, sizeof(next));
	}
	pqcp_runtime_secure_zero(next, sizeof(next));
	return ret;
}

int pqcp_edge_ratchet_init(
	struct pqcp_edge_ratchet *ratchet,
	const char *peer_id,
	const uint8_t root_key[PQCP_EDGE_KEY_BYTES],
	bool initiator,
	uint64_t now_ms)
{
	uint8_t initiator_send[PQCP_EDGE_KEY_BYTES];
	uint8_t initiator_receive[PQCP_EDGE_KEY_BYTES];
	int ret;

	if (ratchet == NULL ||
	    !pqcp_edge_internal_text_valid(
		    peer_id, PQCP_EDGE_ID_MAX_CHARS) ||
	    root_key == NULL ||
	    pqcp_edge_internal_all_zero(
		    root_key, PQCP_EDGE_KEY_BYTES)) {
		return -EINVAL;
	}
	memset(ratchet, 0, sizeof(*ratchet));
	ret = pqcp_edge_internal_copy_text(
		ratchet->peer_id,
		sizeof(ratchet->peer_id), peer_id);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_internal_hkdf(
		root_key, root_key,
		(const uint8_t *)RATCHET_SEND_LABEL,
		strlen(RATCHET_SEND_LABEL),
		initiator_send);
	if (ret == 0) {
		ret = pqcp_edge_internal_hkdf(
			root_key, root_key,
			(const uint8_t *)RATCHET_RECEIVE_LABEL,
			strlen(RATCHET_RECEIVE_LABEL),
			initiator_receive);
	}
	if (ret == 0) {
		ret = pqcp_edge_internal_sha256(
			root_key, PQCP_EDGE_KEY_BYTES,
			ratchet->root_digest);
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			initiator_send,
			sizeof(initiator_send));
		pqcp_runtime_secure_zero(
			initiator_receive,
			sizeof(initiator_receive));
		return ret;
	}
	if (initiator) {
		memcpy(ratchet->send_chain_key,
		       initiator_send,
		       sizeof(initiator_send));
		memcpy(ratchet->receive_chain_key,
		       initiator_receive,
		       sizeof(initiator_receive));
	} else {
		memcpy(ratchet->send_chain_key,
		       initiator_receive,
		       sizeof(initiator_receive));
		memcpy(ratchet->receive_chain_key,
		       initiator_send,
		       sizeof(initiator_send));
	}
	ratchet->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	ratchet->initiator = initiator;
	ratchet->send_epoch = 1U;
	ratchet->receive_epoch = 1U;
	ratchet->last_rotated_ms = now_ms;
	ratchet->initialized = true;
	pqcp_runtime_secure_zero(
		initiator_send, sizeof(initiator_send));
	pqcp_runtime_secure_zero(
		initiator_receive, sizeof(initiator_receive));
	return 0;
}

int pqcp_edge_ratchet_next_send(
	struct pqcp_edge_ratchet *ratchet,
	uint8_t message_key[PQCP_EDGE_KEY_BYTES],
	uint64_t *epoch,
	uint64_t *sequence)
{
	uint64_t next_sequence;
	int ret;

	if (ratchet == NULL || !ratchet->initialized ||
	    message_key == NULL || epoch == NULL ||
	    sequence == NULL) {
		return -EINVAL;
	}
	if (ratchet->send_sequence == UINT64_MAX) {
		return -EOVERFLOW;
	}
	next_sequence = ratchet->send_sequence + 1U;
	ret = derive_labeled_key(
		ratchet->send_chain_key,
		RATCHET_MESSAGE_LABEL,
		ratchet->send_epoch, next_sequence,
		message_key);
	if (ret == 0) {
		ret = advance_chain(
			ratchet->send_chain_key,
			ratchet->send_epoch, next_sequence);
	}
	if (ret == 0) {
		ratchet->send_sequence = next_sequence;
		*epoch = ratchet->send_epoch;
		*sequence = next_sequence;
	}
	return ret;
}

int pqcp_edge_ratchet_receive(
	struct pqcp_edge_ratchet *ratchet,
	uint64_t epoch,
	uint64_t sequence,
	uint8_t message_key[PQCP_EDGE_KEY_BYTES])
{
	uint8_t chain[PQCP_EDGE_KEY_BYTES];
	uint8_t candidate[PQCP_EDGE_KEY_BYTES];
	uint64_t current;
	int ret = 0;

	if (ratchet == NULL || !ratchet->initialized ||
	    message_key == NULL || epoch == 0U ||
	    sequence == 0U) {
		return -EINVAL;
	}
	if (epoch < ratchet->receive_epoch ||
	    (epoch == ratchet->receive_epoch &&
	     sequence <= ratchet->receive_sequence)) {
		return -EALREADY;
	}
	if (epoch != ratchet->receive_epoch) {
		return -ESTALE;
	}
	if (sequence - ratchet->receive_sequence > 64U) {
		return -ERANGE;
	}
	memcpy(chain, ratchet->receive_chain_key,
	       sizeof(chain));
	current = ratchet->receive_sequence;
	while (current < sequence && ret == 0) {
		++current;
		ret = derive_labeled_key(
			chain, RATCHET_MESSAGE_LABEL,
			epoch, current, candidate);
		if (ret == 0) {
			ret = advance_chain(
				chain, epoch, current);
		}
		if (current != sequence && ret == 0) {
			ratchet->skipped_messages =
				pqcp_edge_internal_saturating_add_u32(
					ratchet->
						skipped_messages,
					1U);
		}
	}
	if (ret == 0) {
		memcpy(message_key, candidate,
		       sizeof(candidate));
		memcpy(ratchet->receive_chain_key, chain,
		       sizeof(chain));
		ratchet->receive_sequence = sequence;
	}
	pqcp_runtime_secure_zero(chain, sizeof(chain));
	pqcp_runtime_secure_zero(
		candidate, sizeof(candidate));
	return ret;
}

int pqcp_edge_ratchet_rotate(
	struct pqcp_edge_ratchet *ratchet,
	const uint8_t shared_secret[PQCP_EDGE_KEY_BYTES],
	uint64_t next_epoch,
	uint64_t now_ms)
{
	uint8_t root[PQCP_EDGE_KEY_BYTES];
	uint8_t send[PQCP_EDGE_KEY_BYTES];
	uint8_t receive[PQCP_EDGE_KEY_BYTES];
	const uint8_t *parts[2];
	size_t lengths[2];
	int ret;

	if (ratchet == NULL || !ratchet->initialized ||
	    shared_secret == NULL ||
	    pqcp_edge_internal_all_zero(
		    shared_secret, PQCP_EDGE_KEY_BYTES) ||
	    next_epoch <= ratchet->send_epoch ||
	    next_epoch <= ratchet->receive_epoch) {
		return -EINVAL;
	}
	parts[0] = ratchet->root_digest;
	lengths[0] = sizeof(ratchet->root_digest);
	parts[1] = shared_secret;
	lengths[1] = PQCP_EDGE_KEY_BYTES;
	ret = pqcp_edge_internal_sha256_parts(
		parts, lengths, 2U, root);
	if (ret == 0) {
		/*
		 * Direction labels are role dependent, mirroring init():
		 * the initiator's send chain is the responder's receive
		 * chain and vice versa.
		 */
		ret = derive_labeled_key(
			root,
			ratchet->initiator ? RATCHET_SEND_LABEL :
					     RATCHET_RECEIVE_LABEL,
			next_epoch, 0U, send);
	}
	if (ret == 0) {
		ret = derive_labeled_key(
			root,
			ratchet->initiator ? RATCHET_RECEIVE_LABEL :
					     RATCHET_SEND_LABEL,
			next_epoch, 0U, receive);
	}
	if (ret == 0) {
		memcpy(ratchet->send_chain_key,
		       send, sizeof(send));
		memcpy(ratchet->receive_chain_key,
		       receive, sizeof(receive));
		ret = pqcp_edge_internal_sha256(
			root, sizeof(root),
			ratchet->root_digest);
	}
	if (ret == 0) {
		ratchet->send_epoch = next_epoch;
		ratchet->receive_epoch = next_epoch;
		ratchet->send_sequence = 0U;
		ratchet->receive_sequence = 0U;
		ratchet->skipped_messages = 0U;
		ratchet->last_rotated_ms = now_ms;
	}
	pqcp_runtime_secure_zero(root, sizeof(root));
	pqcp_runtime_secure_zero(send, sizeof(send));
	pqcp_runtime_secure_zero(receive, sizeof(receive));
	return ret;
}

int pqcp_edge_ratchet_audit(
	struct pqcp_edge_ratchet *ratchet)
{
	if (ratchet == NULL || !ratchet->initialized ||
	    ratchet->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    !pqcp_edge_internal_text_valid(
		    ratchet->peer_id,
		    sizeof(ratchet->peer_id)) ||
	    ratchet->send_epoch == 0U ||
	    ratchet->receive_epoch == 0U ||
	    pqcp_edge_internal_all_zero(
		    ratchet->send_chain_key,
		    sizeof(ratchet->send_chain_key)) ||
	    pqcp_edge_internal_all_zero(
		    ratchet->receive_chain_key,
		    sizeof(ratchet->receive_chain_key)) ||
	    pqcp_edge_internal_all_zero(
		    ratchet->root_digest,
		    sizeof(ratchet->root_digest))) {
		return -EBADMSG;
	}
	return 0;
}
