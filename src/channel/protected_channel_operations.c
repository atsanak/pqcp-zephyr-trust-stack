/*
 * SPDX-License-Identifier: MIT
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
#define REKEY_MAX_RETRIES 3U

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

static bool is_rekey_control(
	enum pqcp_channel_control_kind kind)
{
	return kind == PQCP_CHANNEL_CONTROL_REKEY_PREPARE ||
	       kind == PQCP_CHANNEL_CONTROL_REKEY_ACCEPT ||
	       kind == PQCP_CHANNEL_CONTROL_REKEY_COMMIT ||
	       kind == PQCP_CHANNEL_CONTROL_REKEY_ABORT;
}

static bool is_rekey_policy_state(
	enum pqcp_channel_policy_state state)
{
	return state == PQCP_CHANNEL_POLICY_ESTABLISHED ||
	       state == PQCP_CHANNEL_POLICY_REKEY_PREPARED ||
	       state == PQCP_CHANNEL_POLICY_REKEY_ACCEPTED ||
	       state == PQCP_CHANNEL_POLICY_REKEY_COMMITTING;
}

static int control_policy_lookup(
	const struct pqcp_channel_operations *operations,
	enum pqcp_channel_control_kind kind,
	struct pqcp_channel_policy_decision *decision)
{
	int ret;

	ret = pqcp_channel_policy_lookup(
		operations->state, kind, decision);
	if (ret != 0) {
		return ret;
	}
	/*
	 * Rekey is a multi-message exchange.  The static policy catalog models
	 * only the coarse state transitions, while this coordinator owns the
	 * protocol phases, duplicate recovery, and collision resolution.
	 */
	if (is_rekey_control(kind) &&
	    is_rekey_policy_state(operations->state)) {
		decision->action = PQCP_CHANNEL_POLICY_REQUIRE_REKEY;
		decision->next_state = operations->state;
		decision->error = 0;
	}
	return 0;
}

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

static void rekey_established_locked(
	struct pqcp_channel_operations *operations,
	uint64_t now_ms)
{
	if (!operations->channel->established ||
	    operations->channel->state !=
		    PQCP_CHANNEL_STATE_ESTABLISHED) {
		operations->state = PQCP_CHANNEL_POLICY_FAILED;
		set_application_barrier(operations, true);
		clear_rekey_progress(operations);
		return;
	}
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

static uint64_t rekey_retry_interval_ms(
	const struct pqcp_channel_rekey_policy *policy)
{
	uint64_t interval =
		(uint64_t)policy->handshake_timeout_ms /
		(REKEY_MAX_RETRIES + 1U);

	return interval == 0U ? 1U : interval;
}

static int build_rekey_phase_message(
	const struct pqcp_channel_operations *operations,
	struct pqcp_channel_control_message *message)
{
	if (operations == NULL || operations->rekey == NULL ||
	    message == NULL ||
	    operations->rekey->pending_epoch == 0U) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	message->epoch = operations->rekey->pending_epoch;
	switch (operations->rekey_phase) {
	case REKEY_WAIT_ACCEPT:
		message->kind =
			PQCP_CHANNEL_CONTROL_REKEY_PREPARE;
		memcpy(message->payload,
		       operations->rekey->salt,
		       PQCP_CHANNEL_REKEY_SALT_BYTES);
		memcpy(message->payload +
			       PQCP_CHANNEL_REKEY_SALT_BYTES,
		       operations->rekey->confirmation,
		       PQCP_CHANNEL_FINISHED_BYTES);
		message->payload_length =
			REKEY_PREPARE_PAYLOAD_BYTES;
		return 0;
	case REKEY_WAIT_REQUEST:
		message->kind =
			PQCP_CHANNEL_CONTROL_REKEY_ACCEPT;
		memcpy(message->payload,
		       operations->rekey->confirmation,
		       PQCP_CHANNEL_FINISHED_BYTES);
		message->payload_length =
			REKEY_CONFIRM_PAYLOAD_BYTES;
		return 0;
	case REKEY_WAIT_ACK:
		message->kind =
			PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
		message->value =
			REKEY_COMMIT_PHASE_REQUEST;
		break;
	case REKEY_WAIT_ACTIVATE:
		message->kind =
			PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
		message->value = REKEY_COMMIT_PHASE_ACK;
		break;
	case REKEY_WAIT_CONFIRM:
		message->kind =
			PQCP_CHANNEL_CONTROL_REKEY_COMMIT;
		message->value =
			REKEY_COMMIT_PHASE_ACTIVATE;
		break;
	default:
		return -EINVAL;
	}
	memcpy(message->payload,
	       operations->rekey->confirmation,
	       PQCP_CHANNEL_FINISHED_BYTES);
	message->payload_length =
		REKEY_CONFIRM_PAYLOAD_BYTES;
	return 0;
}

static int send_rekey_phase_locked(
	struct pqcp_channel_operations *operations,
	uint64_t now_ms,
	bool retry)
{
	struct pqcp_channel_control_message message;
	int ret;

	ret = build_rekey_phase_message(
		operations, &message);
	if (ret != 0) {
		return ret;
	}
	ret = send_control_locked(
		operations, &message, now_ms);
	if (ret == 0) {
		operations->rekey_last_send_ms = now_ms;
		if (retry &&
		    operations->rekey_retries < UINT32_MAX) {
			operations->rekey_retries++;
		}
	}
	return ret;
}

static int abort_rekey_before_cutover_locked(
	struct pqcp_channel_operations *operations,
	uint64_t epoch,
	uint32_t error,
	uint64_t now_ms,
	bool notify_peer)
{
	int notify_ret = 0;
	int abort_ret;

	if (operations->rekey->local_direction_committed ||
	    operations->rekey->peer_direction_committed) {
		return -EALREADY;
	}
	if (notify_peer && epoch != 0U &&
	    operations->channel->established &&
	    operations->channel->state ==
		    PQCP_CHANNEL_STATE_ESTABLISHED) {
		notify_ret = send_rekey_abort_locked(
			operations, epoch, error, now_ms);
	}
	abort_ret = pqcp_channel_rekey_abort(
		operations->rekey);
	rekey_established_locked(operations, now_ms);
	if (abort_ret != 0) {
		return abort_ret;
	}
	return notify_ret;
}

static int fail_rekey_after_cutover_locked(
	struct pqcp_channel_operations *operations,
	int error)
{
	operations->state = PQCP_CHANNEL_POLICY_FAILED;
	set_application_barrier(operations, true);
	clear_rekey_progress(operations);
	return pqcp_channel_internal_fail(
		operations->channel,
		PQCP_CHANNEL_ALERT_TIMEOUT, error);
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
	ret = control_policy_lookup(
		operations, message->kind, &decision);
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
	if (!is_rekey_control(message->kind)) {
		operations->state = decision.next_state;
	}
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

	ret = control_policy_lookup(
		operations, message->kind, &decision);
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
		    operations->rekey->current_epoch ==
			    UINT64_MAX ||
		    message->epoch !=
			    operations->rekey->current_epoch + 1U) {
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
			    message->epoch) {
			if (operations->channel->config.role ==
			    PQCP_CHANNEL_ROLE_CLIENT) {
				/*
				 * Simultaneous initiation is resolved by channel
				 * role: the client proposal wins.  Re-send it so
				 * the server can converge without an ambiguous
				 * abort for the shared epoch number.
				 */
				memset(&reply, 0, sizeof(reply));
				reply.kind =
					PQCP_CHANNEL_CONTROL_REKEY_PREPARE;
				reply.epoch = message->epoch;
				memcpy(reply.payload,
				       operations->rekey->salt,
				       PQCP_CHANNEL_REKEY_SALT_BYTES);
				memcpy(reply.payload +
					       PQCP_CHANNEL_REKEY_SALT_BYTES,
				       operations->rekey->confirmation,
				       PQCP_CHANNEL_FINISHED_BYTES);
				reply.payload_length =
					REKEY_PREPARE_PAYLOAD_BYTES;
				ret = send_control_locked(
					operations, &reply, now_ms);
				if (ret == 0) {
					operations->rekey_last_send_ms =
						now_ms;
				}
				return ret;
			}
			if (operations->rekey
				    ->local_direction_committed) {
				return -EBUSY;
			}
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
			const int abort_ret =
				abort_rekey_before_cutover_locked(
					operations, message->epoch,
					(uint32_t)(-ret), now_ms,
					true);

			return abort_ret != 0 ? abort_ret : ret;
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
			PQCP_CHANNEL_POLICY_REKEY_ACCEPTED;
		ret = send_control_locked(
			operations, &reply, now_ms);
		if (ret == 0) {
			operations->rekey_phase =
				REKEY_WAIT_REQUEST;
			operations->rekey_last_send_ms = now_ms;
			operations->rekey_retries = 0U;
		} else {
			(void)abort_rekey_before_cutover_locked(
				operations, message->epoch,
				(uint32_t)(-ret), now_ms, true);
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
			const int abort_ret =
				abort_rekey_before_cutover_locked(
					operations, message->epoch,
					(uint32_t)(-ret), now_ms,
					true);

			return abort_ret != 0 ? abort_ret : ret;
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
			(void)abort_rekey_before_cutover_locked(
				operations, message->epoch,
				(uint32_t)(-ret), now_ms, true);
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
				(void)abort_rekey_before_cutover_locked(
					operations, message->epoch,
					(uint32_t)(-ret), now_ms,
					true);
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
				const int abort_ret =
					abort_rekey_before_cutover_locked(
						operations,
						message->epoch,
						(uint32_t)(-ret),
						now_ms, true);

				return abort_ret != 0 ?
					abort_ret : ret;
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
				return fail_rekey_after_cutover_locked(
					operations, ret);
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
			rekey_established_locked(
				operations, now_ms);
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
			    ->local_direction_committed ||
		    operations->rekey
			    ->peer_direction_committed ||
		    (operations->rekey->state ==
			     PQCP_CHANNEL_REKEY_COMMITTED &&
		     operations->rekey->current_epoch ==
			     message->epoch)) {
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
	if (ret == 0 &&
	    !is_rekey_control(message->kind)) {
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
	rekey->key_store = channel->key_store;
	channel->rekey_context = rekey;
	channel->application_send_blocked = false;
	clear_rekey_progress(operations);
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
		     PQCP_CHANNEL_REKEY_ABORTED) ||
	    operations->rekey->cleanup_pending ||
	    operations->rekey->pending_cleanup) {
		return 0;
	}
	if (operations->rekey_phase != REKEY_WAIT_NONE ||
	    operations->rekey->current_epoch == UINT64_MAX) {
		return operations->rekey->current_epoch ==
			       UINT64_MAX ?
			       -EOVERFLOW : -EBUSY;
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
		set_application_barrier(operations, true);
		operations->state =
			PQCP_CHANNEL_POLICY_REKEY_PREPARED;
		operations->rekey_phase =
			REKEY_WAIT_ACCEPT;
		operations->rekey_retries = 0U;
		ret = send_rekey_phase_locked(
			operations, now_ms, false);
		if (ret != 0) {
			const uint64_t epoch =
				operations->rekey->pending_epoch;

			(void)abort_rekey_before_cutover_locked(
				operations, epoch,
				(uint32_t)(-ret), now_ms, false);
		}
	}
	pqcp_runtime_secure_zero(salt, sizeof(salt));
	return ret;
}

static int maintain_rekey_locked(
	struct pqcp_channel_operations *operations,
	uint64_t now_ms)
{
	const uint64_t expires_at_ms =
		operations->rekey->expires_at_ms;
	const uint64_t epoch =
		operations->rekey->pending_epoch;
	uint64_t retry_interval_ms;

	if (operations->rekey_phase == REKEY_WAIT_NONE) {
		return 0;
	}
	if (expires_at_ms == 0U ||
	    now_ms > expires_at_ms) {
		if (operations->rekey
			    ->local_direction_committed ||
		    operations->rekey
			    ->peer_direction_committed) {
			return fail_rekey_after_cutover_locked(
				operations, -ETIMEDOUT);
		}
		return abort_rekey_before_cutover_locked(
			operations, epoch,
			(uint32_t)ETIMEDOUT, now_ms, true);
	}
	if (now_ms < operations->rekey_last_send_ms) {
		if (operations->rekey
			    ->local_direction_committed) {
			return fail_rekey_after_cutover_locked(
				operations, -ERANGE);
		}
		if (operations->rekey
			    ->peer_direction_committed) {
			return fail_rekey_after_cutover_locked(
				operations, -ERANGE);
		}
		return abort_rekey_before_cutover_locked(
			operations, epoch,
			(uint32_t)ERANGE, now_ms, true);
	}
	if (operations->rekey_retries >=
		    REKEY_MAX_RETRIES) {
		return 0;
	}
	retry_interval_ms = rekey_retry_interval_ms(
		&operations->rekey_policy);
	if (now_ms - operations->rekey_last_send_ms <
	    retry_interval_ms) {
		return 0;
	}
	return send_rekey_phase_locked(
		operations, now_ms, true);
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
	ret = maintain_rekey_locked(
		operations, now_ms);
	if (ret != 0) {
		first_error = ret;
	}
	if (operations->rekey->pending_cleanup ||
	    (operations->rekey->cleanup_pending &&
	     (operations->rekey->state !=
		      PQCP_CHANNEL_REKEY_COMMITTED ||
	      operations->rekey->expires_at_ms == 0U ||
	      now_ms > operations->rekey->expires_at_ms))) {
		ret = pqcp_channel_rekey_cleanup(
			operations->rekey);
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
	}
	ret = pqcp_channel_peer_tick(
		operations->peer,
		&operations->peer_policy, now_ms);
	if (ret != 0 && first_error == 0) {
		first_error = ret;
	}
	if (operations->rekey_phase ==
	    REKEY_WAIT_NONE && operations->channel->established &&
	    operations->peer->status != PQCP_CHANNEL_PEER_UNREACHABLE) {
		ret = maybe_send_keepalive(
			operations, now_ms);
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
		ret = maybe_prepare_rekey(
			operations, rekey_policy, now_ms);
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
	}
	if (operations->peer->status ==
	    PQCP_CHANNEL_PEER_UNREACHABLE) {
		operations->state =
			PQCP_CHANNEL_POLICY_FAILED;
		(void)pqcp_channel_internal_fail(operations->channel,
			PQCP_CHANNEL_ALERT_TIMEOUT, -ETIMEDOUT);
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
	    operations->channel->rekey_context !=
		    operations->rekey ||
	    operations->resumption == NULL ||
	    operations->peer == NULL ||
	    operations->state < PQCP_CHANNEL_POLICY_NEW ||
	    operations->state >
		    PQCP_CHANNEL_POLICY_TERMINATED ||
	    operations->epoch_started_at_ms == 0U ||
	    operations->next_control_id == 0U ||
	    (operations->rekey_phase !=
		     REKEY_WAIT_NONE &&
	     !operations->channel
		      ->application_send_blocked)) {
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
