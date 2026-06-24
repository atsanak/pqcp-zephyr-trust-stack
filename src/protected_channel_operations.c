/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Operational coordinator for control messages, liveness, and key epochs.
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>

#include <pqcp_zephyr/protected_channel_operations.h>

#include "protected_channel_internal.h"
#include "runtime_internal.h"

#define REKEY_PREPARE_PAYLOAD_BYTES \
	(PQCP_CHANNEL_REKEY_SALT_BYTES + PQCP_CHANNEL_FINISHED_BYTES)
#define REKEY_CONFIRM_PAYLOAD_BYTES PQCP_CHANNEL_FINISHED_BYTES

enum rekey_commit_phase {
	REKEY_COMMIT_PHASE_NONE = 0,
	REKEY_COMMIT_PHASE_REQUEST = 1,
	REKEY_COMMIT_PHASE_ACK = 2,
	REKEY_COMMIT_PHASE_ACTIVATE = 3,
	REKEY_COMMIT_PHASE_CONFIRM = 4,
};

enum rekey_wait_phase {
	REKEY_WAIT_NONE = 0,
	REKEY_WAIT_ACCEPT,
	REKEY_WAIT_REQUEST,
	REKEY_WAIT_ACK,
	REKEY_WAIT_ACTIVATE,
	REKEY_WAIT_CONFIRM,
};

static int send_control_locked(
	struct pqcp_channel_operations *operations,
	struct pqcp_channel_control_message *message,
	uint64_t now_ms);

static bool secure_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static enum pqcp_channel_role peer_role(
	enum pqcp_channel_role role)
{
	return role == PQCP_CHANNEL_ROLE_CLIENT ?
		PQCP_CHANNEL_ROLE_SERVER :
		PQCP_CHANNEL_ROLE_CLIENT;
}

static void set_application_barrier(
	struct pqcp_channel_operations *operations,
	bool blocked)
{
	if (operations != NULL &&
	    operations->channel != NULL) {
		operations->channel->application_send_blocked =
			blocked;
	}
}

static void clear_rekey_progress(
	struct pqcp_channel_operations *operations)
{
	operations->rekey_phase = REKEY_WAIT_NONE;
	operations->rekey_last_send_ms = 0U;
	operations->rekey_retries = 0U;
}

static uint64_t rekey_retry_interval_ms(
	const struct pqcp_channel_rekey_policy *policy)
{
	uint64_t interval;

	if (policy == NULL) {
		return 1000U;
	}
	interval = policy->minimum_interval_ms;
	if (interval == 0U) {
		interval = 1000U;
	}
	if (policy->handshake_timeout_ms != 0U) {
		const uint64_t quarter =
			policy->handshake_timeout_ms / 4U;

		if (quarter != 0U && interval > quarter) {
			interval = quarter;
		}
	}
	return interval < 100U ? 100U : interval;
}

static void rekey_established_locked(
	struct pqcp_channel_operations *operations,
	uint64_t now_ms)
{
	operations->state =
		PQCP_CHANNEL_POLICY_ESTABLISHED;
	operations->epoch_started_at_ms = now_ms;
	operations->epoch_started_bytes =
		operations->channel->application_bytes_sent +
		operations->channel->application_bytes_received;
	set_application_barrier(operations, false);
	clear_rekey_progress(operations);
}

static int send_rekey_abort_locked(
	struct pqcp_channel_operations *operations,
	uint64_t epoch,
	uint32_t error,
	uint64_t now_ms)
{
	struct pqcp_channel_control_message abort = {
		.kind = PQCP_CHANNEL_CONTROL_REKEY_ABORT,
		.epoch = epoch,
		.error = error,
	};

	return send_control_locked(
		operations, &abort, now_ms);
}

static int resend_rekey_phase_locked(
	struct pqcp_channel_operations *operations,
	uint64_t now_ms)
{
	struct pqcp_channel_control_message message;

	if (operations == NULL ||
	    operations->rekey == NULL ||
	    operations->rekey->pending_epoch == 0U) {
		return -EINVAL;
	}
	memset(&message, 0, sizeof(message));
	message.epoch = operations->rekey->pending_epoch;
	switch (operations->rekey_phase) {
	case REKEY_WAIT_ACCEPT:
		message.kind =
			PQCP_CHANNEL_CONTROL_REKEY_PREPARE;
		memcpy(message.payload,
		       operations->rekey->salt,
		       sizeof(operations->rekey->salt));
		memcpy(message.payload +
			       sizeof(operations->rekey->salt),
		       operations->rekey->confirmation,
		       sizeof(operations->rekey->confirmation));
		message.payload_length =
			REKEY_PREPARE_PAYLOAD_BYTES;
		break;
	case REKEY_WAIT_REQUEST:
		message.kind =
			PQCP_CHANNEL_CONTROL_REKEY_ACCEPT;
		memcpy(message.payload,
		       operations->rekey->confirmation,
		       sizeof(operations->rekey->confirmation));
		message.payload_length =
			REKEY_CONFIRM_PAYLOAD_BYTES;
		break;
	case REKEY_WAIT_ACK:
		message.kind =
			PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
		message.value =
			REKEY_COMMIT_PHASE_REQUEST;
		memcpy(message.payload,
		       operations->rekey->confirmation,
		       sizeof(operations->rekey->confirmation));
		message.payload_length =
			REKEY_CONFIRM_PAYLOAD_BYTES;
		break;
	case REKEY_WAIT_ACTIVATE:
		message.kind =
			PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
		message.value = REKEY_COMMIT_PHASE_ACK;
		memcpy(message.payload,
		       operations->rekey->confirmation,
		       sizeof(operations->rekey->confirmation));
		message.payload_length =
			REKEY_CONFIRM_PAYLOAD_BYTES;
		break;
	case REKEY_WAIT_CONFIRM:
		message.kind =
			PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
		message.value =
			REKEY_COMMIT_PHASE_ACTIVATE;
		memcpy(message.payload,
		       operations->rekey->confirmation,
		       sizeof(operations->rekey->confirmation));
		message.payload_length =
			REKEY_CONFIRM_PAYLOAD_BYTES;
		break;
	default:
		return 0;
	}
	return send_control_locked(
		operations, &message, now_ms);
}

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
			ret = pqcp_channel_internal_send_application(
				operations->channel, encoded,
				encoded_length, true);
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
	struct pqcp_channel_control_message reply;
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
		memset(&reply, 0, sizeof(reply));
		reply.kind =
			PQCP_CHANNEL_CONTROL_KEEPALIVE_ACK;
		reply.epoch = message->epoch;
		reply.value = message->value;
		ret = send_control_locked(
			operations, &reply, now_ms);
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
	case PQCP_CHANNEL_CONTROL_REKEY_PREPARE:
		if (message->payload_length !=
			    REKEY_PREPARE_PAYLOAD_BYTES ||
		    message->epoch <=
			    operations->rekey->current_epoch) {
			return -EBADMSG;
		}
		if (!operations->rekey->initiator &&
		    operations->rekey_phase ==
			    REKEY_WAIT_REQUEST &&
		    operations->rekey->pending_epoch ==
			    message->epoch &&
		    secure_equal(
			    operations->rekey->salt,
			    message->payload,
			    PQCP_CHANNEL_REKEY_SALT_BYTES) &&
		    secure_equal(
			    operations->rekey
				    ->expected_peer_confirmation,
			    message->payload +
				    PQCP_CHANNEL_REKEY_SALT_BYTES,
			    PQCP_CHANNEL_FINISHED_BYTES)) {
			memset(&reply, 0, sizeof(reply));
			reply.kind =
				PQCP_CHANNEL_CONTROL_REKEY_ACCEPT;
			reply.epoch = message->epoch;
			memcpy(reply.payload,
			       operations->rekey->confirmation,
			       PQCP_CHANNEL_FINISHED_BYTES);
			reply.payload_length =
				REKEY_CONFIRM_PAYLOAD_BYTES;
			ret = send_control_locked(
				operations, &reply, now_ms);
			if (ret == 0) {
				operations->rekey_last_send_ms =
					now_ms;
				operations->rekey_retries++;
			}
			return ret;
		}
		if ((operations->rekey->state ==
			     PQCP_CHANNEL_REKEY_PREPARED ||
		     operations->rekey->state ==
			     PQCP_CHANNEL_REKEY_ACCEPTED) &&
		    operations->rekey->initiator &&
		    operations->rekey->pending_epoch ==
			    message->epoch &&
		    operations->rekey->initiator_role ==
			    PQCP_CHANNEL_ROLE_SERVER &&
		    !operations->rekey
			     ->local_direction_committed) {
			(void)pqcp_channel_rekey_abort(
				operations->rekey);
			rekey_established_locked(
				operations, now_ms);
		} else if (operations->rekey->state !=
				       PQCP_CHANNEL_REKEY_IDLE &&
			   operations->rekey->state !=
				       PQCP_CHANNEL_REKEY_ABORTED &&
			   operations->rekey->state !=
				       PQCP_CHANNEL_REKEY_COMMITTED) {
			ret = send_rekey_abort_locked(
				operations, message->epoch,
				(uint32_t)EBUSY, now_ms);
			return ret == 0 ? 0 : ret;
		}
		set_application_barrier(operations, true);
		ret = pqcp_channel_rekey_prepare(
			operations->channel,
			&operations->rekey_policy,
			operations->rekey, now_ms,
			message->epoch, message->payload,
			false);
		if (ret == 0) {
			ret = pqcp_channel_rekey_accept(
				operations->channel,
				operations->rekey,
				message->payload +
					PQCP_CHANNEL_REKEY_SALT_BYTES,
				now_ms);
		}
		if (ret != 0) {
			(void)pqcp_channel_rekey_abort(
				operations->rekey);
			rekey_established_locked(
				operations, now_ms);
			return ret;
		}
		memset(&reply, 0, sizeof(reply));
		reply.kind =
			PQCP_CHANNEL_CONTROL_REKEY_ACCEPT;
		reply.epoch = message->epoch;
		memcpy(reply.payload,
		       operations->rekey->confirmation,
		       PQCP_CHANNEL_FINISHED_BYTES);
		reply.payload_length =
			REKEY_CONFIRM_PAYLOAD_BYTES;
		operations->state =
			PQCP_CHANNEL_POLICY_REKEY_PREPARED;
		ret = send_control_locked(
			operations, &reply, now_ms);
		if (ret == 0) {
			operations->rekey_phase =
				REKEY_WAIT_REQUEST;
			operations->rekey_last_send_ms = now_ms;
			operations->rekey_retries = 0U;
		} else {
			(void)pqcp_channel_rekey_abort(
				operations->rekey);
			rekey_established_locked(
				operations, now_ms);
		}
		return ret;
	case PQCP_CHANNEL_CONTROL_REKEY_ACCEPT:
		if (message->payload_length !=
			    REKEY_CONFIRM_PAYLOAD_BYTES) {
			return -EBADMSG;
		}
		if (operations->rekey->initiator &&
		    operations->rekey_phase ==
			    REKEY_WAIT_ACK &&
		    operations->rekey->pending_epoch ==
			    message->epoch &&
		    secure_equal(
			    operations->rekey
				    ->expected_peer_confirmation,
			    message->payload,
			    PQCP_CHANNEL_FINISHED_BYTES)) {
			memset(&reply, 0, sizeof(reply));
			reply.kind =
				PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
			reply.epoch = message->epoch;
			reply.value =
				REKEY_COMMIT_PHASE_REQUEST;
			memcpy(reply.payload,
			       operations->rekey->confirmation,
			       PQCP_CHANNEL_FINISHED_BYTES);
			reply.payload_length =
				REKEY_CONFIRM_PAYLOAD_BYTES;
			ret = send_control_locked(
				operations, &reply, now_ms);
			if (ret == 0) {
				operations->rekey_last_send_ms =
					now_ms;
				operations->rekey_retries++;
			}
			return ret;
		}
		if (!operations->rekey->initiator ||
		    operations->rekey_phase !=
			    REKEY_WAIT_ACCEPT ||
		    operations->rekey->pending_epoch !=
			    message->epoch) {
			return -EBADMSG;
		}
		ret = pqcp_channel_rekey_accept(
			operations->channel,
			operations->rekey,
			message->payload, now_ms);
		if (ret != 0) {
			(void)pqcp_channel_rekey_abort(
				operations->rekey);
			rekey_established_locked(
				operations, now_ms);
			return ret;
		}
		memset(&reply, 0, sizeof(reply));
		reply.kind =
			PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
		reply.epoch = message->epoch;
		reply.value = REKEY_COMMIT_PHASE_REQUEST;
		memcpy(reply.payload,
		       operations->rekey->confirmation,
		       PQCP_CHANNEL_FINISHED_BYTES);
		reply.payload_length =
			REKEY_CONFIRM_PAYLOAD_BYTES;
		operations->state =
			PQCP_CHANNEL_POLICY_REKEY_COMMITTING;
		ret = send_control_locked(
			operations, &reply, now_ms);
		if (ret == 0) {
			operations->rekey_phase =
				REKEY_WAIT_ACK;
			operations->rekey_last_send_ms = now_ms;
			operations->rekey_retries = 0U;
		} else {
			(void)pqcp_channel_rekey_abort(
				operations->rekey);
			rekey_established_locked(
				operations, now_ms);
		}
		return ret;
	case PQCP_CHANNEL_CONTROL_REKEY_COMMIT:
		if (message->payload_length !=
			    REKEY_CONFIRM_PAYLOAD_BYTES) {
			return -EBADMSG;
		}
		switch (message->value) {
		case REKEY_COMMIT_PHASE_REQUEST:
			if (!operations->rekey->initiator &&
			    operations->rekey_phase ==
				    REKEY_WAIT_ACTIVATE &&
			    operations->rekey->pending_epoch ==
				    message->epoch &&
			    secure_equal(
				    operations->rekey
					    ->expected_peer_confirmation,
				    message->payload,
				    PQCP_CHANNEL_FINISHED_BYTES)) {
				memset(&reply, 0, sizeof(reply));
				reply.kind =
					PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
				reply.epoch = message->epoch;
				reply.value =
					REKEY_COMMIT_PHASE_ACK;
				memcpy(reply.payload,
				       operations->rekey
					       ->confirmation,
				       PQCP_CHANNEL_FINISHED_BYTES);
				reply.payload_length =
					REKEY_CONFIRM_PAYLOAD_BYTES;
				ret = send_control_locked(
					operations, &reply,
					now_ms);
				if (ret == 0) {
					operations->rekey_last_send_ms =
						now_ms;
					operations->rekey_retries++;
				}
				return ret;
			}
			if (operations->rekey->initiator ||
			    operations->rekey_phase !=
				    REKEY_WAIT_REQUEST ||
			    operations->rekey->pending_epoch !=
				    message->epoch ||
			    !secure_equal(
				    operations->rekey
					    ->expected_peer_confirmation,
				    message->payload,
				    PQCP_CHANNEL_FINISHED_BYTES)) {
				return -EKEYREJECTED;
			}
			memset(&reply, 0, sizeof(reply));
			reply.kind =
				PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
			reply.epoch = message->epoch;
			reply.value = REKEY_COMMIT_PHASE_ACK;
			memcpy(reply.payload,
			       operations->rekey->confirmation,
			       PQCP_CHANNEL_FINISHED_BYTES);
			reply.payload_length =
				REKEY_CONFIRM_PAYLOAD_BYTES;
			operations->state =
				PQCP_CHANNEL_POLICY_REKEY_COMMITTING;
			operations->rekey->pending_peer_receive =
				true;
			ret = send_control_locked(
				operations, &reply, now_ms);
			if (ret == 0) {
				operations->rekey_phase =
					REKEY_WAIT_ACTIVATE;
				operations->rekey_last_send_ms =
					now_ms;
				operations->rekey_retries = 0U;
			} else {
				(void)pqcp_channel_rekey_abort(
					operations->rekey);
				rekey_established_locked(
					operations, now_ms);
			}
			return ret;
		case REKEY_COMMIT_PHASE_ACK:
			if (operations->rekey->initiator &&
			    operations->rekey_phase ==
				    REKEY_WAIT_CONFIRM &&
			    operations->rekey->pending_epoch ==
				    message->epoch &&
			    secure_equal(
				    operations->rekey
					    ->expected_peer_confirmation,
				    message->payload,
				    PQCP_CHANNEL_FINISHED_BYTES)) {
				memset(&reply, 0, sizeof(reply));
				reply.kind =
					PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
				reply.epoch = message->epoch;
				reply.value =
					REKEY_COMMIT_PHASE_ACTIVATE;
				memcpy(reply.payload,
				       operations->rekey
					       ->confirmation,
				       PQCP_CHANNEL_FINISHED_BYTES);
				reply.payload_length =
					REKEY_CONFIRM_PAYLOAD_BYTES;
				ret = send_control_locked(
					operations, &reply,
					now_ms);
				if (ret == 0) {
					operations->rekey_last_send_ms =
						now_ms;
					operations->rekey_retries++;
				}
				return ret;
			}
			if (!operations->rekey->initiator ||
			    operations->rekey_phase !=
				    REKEY_WAIT_ACK ||
			    operations->rekey->pending_epoch !=
				    message->epoch ||
			    !secure_equal(
				    operations->rekey
					    ->expected_peer_confirmation,
				    message->payload,
				    PQCP_CHANNEL_FINISHED_BYTES)) {
				return -EKEYREJECTED;
			}
			ret = pqcp_channel_rekey_commit_local(
				operations->channel,
				operations->rekey, now_ms);
			if (ret != 0) {
				return ret;
			}
			operations->rekey->pending_peer_receive =
				true;
			memset(&reply, 0, sizeof(reply));
			reply.kind =
				PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
			reply.epoch = message->epoch;
			reply.value =
				REKEY_COMMIT_PHASE_ACTIVATE;
			memcpy(reply.payload,
			       operations->rekey->confirmation,
			       PQCP_CHANNEL_FINISHED_BYTES);
			reply.payload_length =
				REKEY_CONFIRM_PAYLOAD_BYTES;
			operations->state =
				PQCP_CHANNEL_POLICY_REKEY_COMMITTING;
			ret = send_control_locked(
				operations, &reply, now_ms);
			operations->rekey_phase =
				REKEY_WAIT_CONFIRM;
			operations->rekey_last_send_ms = now_ms;
			operations->rekey_retries = 0U;
			return ret;
		case REKEY_COMMIT_PHASE_ACTIVATE:
			if (!operations->rekey->initiator &&
			    operations->rekey->state ==
				    PQCP_CHANNEL_REKEY_COMMITTED &&
			    operations->rekey->current_epoch ==
				    message->epoch) {
				memset(&reply, 0, sizeof(reply));
				reply.kind =
					PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
				reply.epoch = message->epoch;
				reply.value =
					REKEY_COMMIT_PHASE_CONFIRM;
				memcpy(reply.payload,
				       operations->rekey
					       ->confirmation,
				       PQCP_CHANNEL_FINISHED_BYTES);
				reply.payload_length =
					REKEY_CONFIRM_PAYLOAD_BYTES;
				ret = send_control_locked(
					operations, &reply,
					now_ms);
				if (ret == 0) {
					rekey_established_locked(
						operations, now_ms);
				}
				return ret;
			}
			if (operations->rekey->initiator ||
			    operations->rekey_phase !=
				    REKEY_WAIT_ACTIVATE ||
			    operations->rekey->pending_epoch !=
				    message->epoch ||
			    !secure_equal(
				    operations->rekey
					    ->expected_peer_confirmation,
				    message->payload,
				    PQCP_CHANNEL_FINISHED_BYTES)) {
				return -EKEYREJECTED;
			}
			ret = pqcp_channel_rekey_commit_peer(
				operations->channel,
				operations->rekey, now_ms);
			if (ret == 0) {
				ret = pqcp_channel_rekey_commit_local(
					operations->channel,
					operations->rekey,
					now_ms);
			}
			if (ret != 0) {
				return ret;
			}
			memset(&reply, 0, sizeof(reply));
			reply.kind =
				PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
			reply.epoch = message->epoch;
			reply.value =
				REKEY_COMMIT_PHASE_CONFIRM;
			memcpy(reply.payload,
			       operations->rekey->confirmation,
			       PQCP_CHANNEL_FINISHED_BYTES);
			reply.payload_length =
				REKEY_CONFIRM_PAYLOAD_BYTES;
			ret = send_control_locked(
				operations, &reply, now_ms);
			if (ret == 0) {
				rekey_established_locked(
					operations, now_ms);
			}
			return ret;
		case REKEY_COMMIT_PHASE_CONFIRM:
			if (operations->rekey->state ==
				    PQCP_CHANNEL_REKEY_COMMITTED &&
			    operations->rekey->current_epoch ==
				    message->epoch) {
				return 0;
			}
			if (!operations->rekey->initiator ||
			    operations->rekey_phase !=
				    REKEY_WAIT_CONFIRM ||
			    operations->rekey->pending_epoch !=
				    message->epoch ||
			    !secure_equal(
				    operations->rekey
					    ->expected_peer_confirmation,
				    message->payload,
				    PQCP_CHANNEL_FINISHED_BYTES)) {
				return -EKEYREJECTED;
			}
			ret = pqcp_channel_rekey_commit_peer(
				operations->channel,
				operations->rekey, now_ms);
			if (ret == 0) {
				rekey_established_locked(
					operations, now_ms);
			}
			return ret;
		default:
			return -EBADMSG;
		}
	case PQCP_CHANNEL_CONTROL_REKEY_ABORT:
		if (operations->rekey
			    ->local_direction_committed) {
			operations->state =
				PQCP_CHANNEL_POLICY_FAILED;
			set_application_barrier(
				operations, true);
			ret = pqcp_channel_internal_fail(
				operations->channel,
				PQCP_CHANNEL_ALERT_TIMEOUT,
				-ECONNABORTED);
			break;
		}
		ret = pqcp_channel_rekey_abort(
			operations->rekey);
		rekey_established_locked(
			operations, now_ms);
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
	(void)pqcp_channel_rekey_policy_default(
		&operations->rekey_policy);
	operations->state = initial_policy_state(channel);
	operations->epoch_started_at_ms = now_ms;
	operations->epoch_started_bytes =
		channel->application_bytes_sent +
		channel->application_bytes_received;
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
		    operations->epoch_started_at_ms,
		    operations->epoch_started_bytes) ||
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
		if (ret != 0) {
			(void)pqcp_channel_rekey_abort(
				operations->rekey);
			operations->state =
				PQCP_CHANNEL_POLICY_ESTABLISHED;
		}
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
	operations->rekey_policy = *rekey_policy;
	if (operations->rekey->cleanup_pending ||
	    operations->rekey->pending_cleanup) {
		ret = pqcp_channel_rekey_cleanup(
			operations->rekey);
		if (ret != 0) {
			first_error = ret;
		}
	}
	if ((operations->rekey->state ==
		     PQCP_CHANNEL_REKEY_PREPARED ||
	     operations->rekey->state ==
		     PQCP_CHANNEL_REKEY_ACCEPTED) &&
	    now_ms > operations->rekey->expires_at_ms) {
		ret = pqcp_channel_rekey_abort(
			operations->rekey);
		operations->state =
			PQCP_CHANNEL_POLICY_ESTABLISHED;
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
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
