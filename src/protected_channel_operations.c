/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Operational coordinator for control messages, liveness, and key epochs.
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>

#include <pqcp_zephyr/protected_channel_operations.h>

#include "runtime_internal.h"

static enum pqcp_channel_policy_state initial_policy_state(
	const struct pqcp_channel *channel)
{
	switch (channel->state) {
	case PQCP_CHANNEL_STATE_ESTABLISHED:
		return PQCP_CHANNEL_POLICY_ESTABLISHED;
	case PQCP_CHANNEL_STATE_CLOSING:
		return PQCP_CHANNEL_POLICY_CLOSING;
	case PQCP_CHANNEL_STATE_CLOSED:
		return PQCP_CHANNEL_POLICY_CLOSED;
	case PQCP_CHANNEL_STATE_FAILED:
		return PQCP_CHANNEL_POLICY_FAILED;
	default:
		return PQCP_CHANNEL_POLICY_NEW;
	}
}

static int send_control_locked(
	struct pqcp_channel_operations *operations,
	struct pqcp_channel_control_message *message,
	uint64_t now_ms)
{
	uint8_t encoded[
		PQCP_CHANNEL_CONTROL_MAX_BYTES + 128U];
	size_t encoded_length = 0U;
	struct pqcp_channel_policy_decision decision;
	int ret;

	if (message->schema_version == 0U) {
		message->schema_version =
			PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	}
	if (message->message_id == 0U) {
		message->message_id =
			operations->next_control_id++;
	}
	if (message->timestamp_ms == 0U) {
		message->timestamp_ms = now_ms;
	}
	ret = pqcp_channel_policy_lookup(
		operations->state, message->kind, &decision);
	if (ret != 0) {
		return ret;
	}
	if (decision.action ==
	    PQCP_CHANNEL_POLICY_DENY) {
		return decision.error;
	}
	ret = pqcp_channel_control_encode(
		message, encoded, sizeof(encoded),
		&encoded_length);
	if (ret == 0) {
		ret = pqcp_channel_send(
			operations->channel,
			encoded, encoded_length);
	}
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	if (ret != 0) {
		operations->failures++;
		if (decision.action ==
		    PQCP_CHANNEL_POLICY_CLOSE_ON_FAILURE) {
			operations->state =
				PQCP_CHANNEL_POLICY_FAILED;
		}
		return ret;
	}
	operations->state = decision.next_state;
	operations->controls_sent++;
	(void)pqcp_channel_peer_record_io(
		operations->peer, now_ms,
		encoded_length, 0U);
	return 0;
}

static int handle_control_locked(
	struct pqcp_channel_operations *operations,
	const struct pqcp_channel_control_message *message,
	uint64_t now_ms)
{
	struct pqcp_channel_policy_decision decision;
	int ret;

	ret = pqcp_channel_policy_lookup(
		operations->state, message->kind, &decision);
	if (ret != 0) {
		return ret;
	}
	if (decision.action ==
	    PQCP_CHANNEL_POLICY_DENY) {
		operations->failures++;
		return decision.error;
	}
	switch (message->kind) {
	case PQCP_CHANNEL_CONTROL_KEEPALIVE:
		{
			struct pqcp_channel_control_message ack = {
				.kind =
					PQCP_CHANNEL_CONTROL_KEEPALIVE_ACK,
				.epoch = message->epoch,
				.value = message->value,
			};

			ret = send_control_locked(
				operations, &ack, now_ms);
		}
		break;
	case PQCP_CHANNEL_CONTROL_KEEPALIVE_ACK:
		ret = pqcp_channel_peer_probe_ack(
			operations->peer,
			&operations->peer_policy, now_ms);
		break;
	case PQCP_CHANNEL_CONTROL_PEER_DRAIN:
		operations->peer->status =
			PQCP_CHANNEL_PEER_DRAINING;
		ret = 0;
		break;
	case PQCP_CHANNEL_CONTROL_GOAWAY:
		operations->peer->status =
			PQCP_CHANNEL_PEER_DRAINING;
		ret = 0;
		break;
	case PQCP_CHANNEL_CONTROL_REKEY_ABORT:
		ret = pqcp_channel_rekey_abort(
			operations->rekey);
		break;
	case PQCP_CHANNEL_CONTROL_ERROR:
		operations->state =
			PQCP_CHANNEL_POLICY_FAILED;
		ret = -ECONNABORTED;
		break;
	default:
		ret = 0;
		break;
	}
	if (ret == 0) {
		operations->state = decision.next_state;
	}
	return ret;
}

int pqcp_channel_operations_init(
	struct pqcp_channel_operations *operations,
	struct pqcp_channel *channel,
	struct pqcp_channel_multiplexer *multiplexer,
	struct pqcp_channel_flow_controller *flow,
	struct pqcp_channel_rekey_context *rekey,
	struct pqcp_channel_resumption_store *resumption,
	struct pqcp_channel_peer_health *peer,
	const struct pqcp_channel_peer_policy *peer_policy,
	uint64_t now_ms)
{
	if (operations == NULL || channel == NULL ||
	    !channel->established ||
	    multiplexer == NULL ||
	    !multiplexer->initialized || flow == NULL ||
	    !flow->initialized || rekey == NULL ||
	    resumption == NULL || !resumption->initialized ||
	    peer == NULL ||
	    pqcp_channel_peer_health_audit(
		    peer, peer_policy) != 0 ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	memset(operations, 0, sizeof(*operations));
	operations->channel = channel;
	operations->multiplexer = multiplexer;
	operations->flow = flow;
	operations->rekey = rekey;
	operations->resumption = resumption;
	operations->peer = peer;
	operations->peer_policy = *peer_policy;
	operations->state = initial_policy_state(channel);
	operations->epoch_started_at_ms = now_ms;
	operations->next_control_id = 1U;
	memset(rekey, 0, sizeof(*rekey));
	rekey->schema_version =
		PQCP_CHANNEL_OPERATION_SCHEMA_VERSION;
	rekey->state = PQCP_CHANNEL_REKEY_IDLE;
	rekey->current_epoch = 1U;
	k_mutex_init(&operations->lock);
	operations->initialized = true;
	return 0;
}

int pqcp_channel_operations_send_control(
	struct pqcp_channel_operations *operations,
	struct pqcp_channel_control_message *message,
	uint64_t now_ms)
{
	int ret;

	if (operations == NULL || !operations->initialized ||
	    message == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&operations->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = send_control_locked(
		operations, message, now_ms);
	(void)k_mutex_unlock(&operations->lock);
	return ret;
}

int pqcp_channel_operations_receive_control(
	struct pqcp_channel_operations *operations,
	struct pqcp_channel_control_message *message,
	uint64_t now_ms)
{
	uint8_t encoded[
		PQCP_CHANNEL_CONTROL_MAX_BYTES + 128U];
	size_t encoded_length = 0U;
	int ret;

	if (operations == NULL || !operations->initialized ||
	    message == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = pqcp_channel_receive(
		operations->channel, encoded,
		sizeof(encoded), &encoded_length);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_control_decode(
		encoded, encoded_length, message);
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	if (ret != 0) {
		operations->failures++;
		return ret;
	}
	ret = k_mutex_lock(&operations->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	operations->controls_received++;
	(void)pqcp_channel_peer_record_io(
		operations->peer, now_ms, 0U,
		encoded_length);
	ret = handle_control_locked(
		operations, message, now_ms);
	if (ret != 0) {
		operations->failures++;
	}
	(void)k_mutex_unlock(&operations->lock);
	return ret;
}

static int maybe_send_keepalive(
	struct pqcp_channel_operations *operations,
	uint64_t now_ms)
{
	struct pqcp_channel_control_message message = {
		.kind = PQCP_CHANNEL_CONTROL_KEEPALIVE,
		.epoch = operations->rekey->current_epoch,
		.value = (uint32_t)(
			operations->peer->probes_sent + 1U),
	};
	int ret;

	if (!pqcp_channel_peer_probe_due(
		    operations->peer,
		    &operations->peer_policy, now_ms)) {
		return 0;
	}
	if (operations->peer->probe_outstanding) {
		return pqcp_channel_peer_tick(
			operations->peer,
			&operations->peer_policy, now_ms);
	}
	ret = send_control_locked(
		operations, &message, now_ms);
	if (ret == 0) {
		ret = pqcp_channel_peer_probe_sent(
			operations->peer, now_ms);
	}
	return ret;
}

static int maybe_prepare_rekey(
	struct pqcp_channel_operations *operations,
	const struct pqcp_channel_rekey_policy *policy,
	uint64_t now_ms)
{
	uint8_t salt[PQCP_CHANNEL_REKEY_SALT_BYTES];
	struct pqcp_channel_control_message message;
	psa_status_t status;
	int ret;

	if (!pqcp_channel_rekey_due(
		    operations->channel, policy, now_ms,
		    operations->epoch_started_at_ms) ||
	    (operations->rekey->state !=
		     PQCP_CHANNEL_REKEY_IDLE &&
	     operations->rekey->state !=
		     PQCP_CHANNEL_REKEY_COMMITTED &&
	     operations->rekey->state !=
		     PQCP_CHANNEL_REKEY_ABORTED)) {
		return 0;
	}
	status = psa_generate_random(salt, sizeof(salt));
	if (status != PSA_SUCCESS) {
		return -EIO;
	}
	ret = pqcp_channel_rekey_prepare(
		operations->channel, policy,
		operations->rekey, now_ms,
		operations->rekey->current_epoch + 1U,
		salt, true);
	if (ret == 0) {
		memset(&message, 0, sizeof(message));
		message.kind =
			PQCP_CHANNEL_CONTROL_REKEY_PREPARE;
		message.epoch =
			operations->rekey->pending_epoch;
		memcpy(message.payload,
		       operations->rekey->salt,
		       sizeof(operations->rekey->salt));
		memcpy(message.payload +
			       sizeof(operations->rekey->salt),
		       operations->rekey->confirmation,
		       sizeof(operations->rekey->confirmation));
		message.payload_length =
			sizeof(operations->rekey->salt) +
			sizeof(operations->rekey->confirmation);
		ret = send_control_locked(
			operations, &message, now_ms);
	}
	pqcp_runtime_secure_zero(salt, sizeof(salt));
	return ret;
}

int pqcp_channel_operations_tick(
	struct pqcp_channel_operations *operations,
	const struct pqcp_channel_rekey_policy *rekey_policy,
	uint64_t now_ms)
{
	int first_error = 0;
	int ret;

	if (operations == NULL || !operations->initialized ||
	    rekey_policy == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&operations->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_peer_tick(
		operations->peer,
		&operations->peer_policy, now_ms);
	if (ret != 0) {
		first_error = ret;
	}
	ret = maybe_send_keepalive(operations, now_ms);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	ret = maybe_prepare_rekey(
		operations, rekey_policy, now_ms);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	if (operations->peer->status ==
	    PQCP_CHANNEL_PEER_UNREACHABLE) {
		operations->state =
			PQCP_CHANNEL_POLICY_FAILED;
		if (first_error == 0) {
			first_error = -ETIMEDOUT;
		}
	}
	if (first_error != 0) {
		operations->failures++;
	}
	(void)k_mutex_unlock(&operations->lock);
	return first_error;
}

int pqcp_channel_operations_audit(
	struct pqcp_channel_operations *operations)
{
	int ret;

	if (operations == NULL || !operations->initialized ||
	    operations->channel == NULL ||
	    operations->multiplexer == NULL ||
	    operations->flow == NULL ||
	    operations->rekey == NULL ||
	    operations->resumption == NULL ||
	    operations->peer == NULL ||
	    operations->state < PQCP_CHANNEL_POLICY_NEW ||
	    operations->state >
		    PQCP_CHANNEL_POLICY_TERMINATED ||
	    operations->epoch_started_at_ms == 0U ||
	    operations->next_control_id == 0U) {
		return -EINVAL;
	}
	ret = pqcp_channel_audit(operations->channel);
	if (ret == 0) {
		ret = pqcp_channel_multiplexer_audit(
			operations->multiplexer);
	}
	if (ret == 0) {
		ret = pqcp_channel_flow_audit(
			operations->flow);
	}
	if (ret == 0) {
		ret = pqcp_channel_rekey_audit(
			operations->channel,
			operations->rekey);
	}
	if (ret == 0) {
		ret = pqcp_channel_resumption_store_audit(
			operations->resumption);
	}
	if (ret == 0) {
		ret = pqcp_channel_peer_health_audit(
			operations->peer,
			&operations->peer_policy);
	}
	if (ret == 0) {
		ret = pqcp_channel_policy_catalog_audit();
	}
	return ret;
}
