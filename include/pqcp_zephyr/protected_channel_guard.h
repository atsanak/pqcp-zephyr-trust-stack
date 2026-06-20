/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Exhaustive key-epoch and stream-lifecycle guards for channel controls.
 */

#ifndef PQCP_ZEPHYR_PROTECTED_CHANNEL_GUARD_H_
#define PQCP_ZEPHYR_PROTECTED_CHANNEL_GUARD_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/protected_channel_operations.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_CHANNEL_EPOCH_CONDITION_COUNT 16U
#define PQCP_CHANNEL_STREAM_CONDITION_COUNT 16U

enum pqcp_channel_epoch_condition {
	PQCP_CHANNEL_EPOCH_CURRENT = 0,
	PQCP_CHANNEL_EPOCH_ROTATION_DUE,
	PQCP_CHANNEL_EPOCH_ROTATION_OVERDUE,
	PQCP_CHANNEL_EPOCH_PREPARED_LOCAL,
	PQCP_CHANNEL_EPOCH_PREPARED_PEER,
	PQCP_CHANNEL_EPOCH_ACCEPTED,
	PQCP_CHANNEL_EPOCH_COMMITTING,
	PQCP_CHANNEL_EPOCH_PEER_AHEAD,
	PQCP_CHANNEL_EPOCH_PEER_BEHIND,
	PQCP_CHANNEL_EPOCH_CONFIRMATION_INVALID,
	PQCP_CHANNEL_EPOCH_SECRET_EXHAUSTED,
	PQCP_CHANNEL_EPOCH_EXPORTER_CHANGED,
	PQCP_CHANNEL_EPOCH_TICKET_STALE,
	PQCP_CHANNEL_EPOCH_REPLAY_SUSPECTED,
	PQCP_CHANNEL_EPOCH_LOCKED,
	PQCP_CHANNEL_EPOCH_TERMINATED,
};

enum pqcp_channel_epoch_directive {
	PQCP_CHANNEL_EPOCH_DENY = 0,
	PQCP_CHANNEL_EPOCH_ALLOW,
	PQCP_CHANNEL_EPOCH_REQUIRE_REKEY,
	PQCP_CHANNEL_EPOCH_ALLOW_REKEY_ONLY,
	PQCP_CHANNEL_EPOCH_RESYNC,
	PQCP_CHANNEL_EPOCH_REJECT,
	PQCP_CHANNEL_EPOCH_CLOSE,
	PQCP_CHANNEL_EPOCH_TERMINATE,
};

enum pqcp_channel_stream_condition {
	PQCP_CHANNEL_STREAM_CONDITION_IDLE = 0,
	PQCP_CHANNEL_STREAM_CONDITION_OPENING_LOCAL,
	PQCP_CHANNEL_STREAM_CONDITION_OPENING_PEER,
	PQCP_CHANNEL_STREAM_CONDITION_OPEN,
	PQCP_CHANNEL_STREAM_CONDITION_HALF_CLOSED_LOCAL,
	PQCP_CHANNEL_STREAM_CONDITION_HALF_CLOSED_PEER,
	PQCP_CHANNEL_STREAM_CONDITION_DRAINING,
	PQCP_CHANNEL_STREAM_CONDITION_RESET_LOCAL,
	PQCP_CHANNEL_STREAM_CONDITION_RESET_PEER,
	PQCP_CHANNEL_STREAM_CONDITION_FLOW_BLOCKED_LOCAL,
	PQCP_CHANNEL_STREAM_CONDITION_FLOW_BLOCKED_PEER,
	PQCP_CHANNEL_STREAM_CONDITION_SEQUENCE_GAP,
	PQCP_CHANNEL_STREAM_CONDITION_SEQUENCE_REPLAY,
	PQCP_CHANNEL_STREAM_CONDITION_CONNECTION_DRAINING,
	PQCP_CHANNEL_STREAM_CONDITION_CLOSED,
	PQCP_CHANNEL_STREAM_CONDITION_TERMINATED,
};

enum pqcp_channel_stream_directive {
	PQCP_CHANNEL_STREAM_DIRECTIVE_DENY = 0,
	PQCP_CHANNEL_STREAM_DIRECTIVE_ALLOW,
	PQCP_CHANNEL_STREAM_DIRECTIVE_ALLOW_CONTROL_ONLY,
	PQCP_CHANNEL_STREAM_DIRECTIVE_REQUIRE_OPEN,
	PQCP_CHANNEL_STREAM_DIRECTIVE_BACKPRESSURE,
	PQCP_CHANNEL_STREAM_DIRECTIVE_RESET_STREAM,
	PQCP_CHANNEL_STREAM_DIRECTIVE_DRAIN,
	PQCP_CHANNEL_STREAM_DIRECTIVE_CLOSE_CHANNEL,
	PQCP_CHANNEL_STREAM_DIRECTIVE_TERMINATE,
};

enum pqcp_channel_guard_verdict {
	PQCP_CHANNEL_GUARD_DENY = 0,
	PQCP_CHANNEL_GUARD_ALLOW,
	PQCP_CHANNEL_GUARD_DEFER,
	PQCP_CHANNEL_GUARD_RESET_STREAM,
	PQCP_CHANNEL_GUARD_DRAIN,
	PQCP_CHANNEL_GUARD_CLOSE,
	PQCP_CHANNEL_GUARD_TERMINATE,
};

struct pqcp_channel_epoch_policy_decision {
	enum pqcp_channel_epoch_condition condition;
	enum pqcp_channel_control_kind control;
	enum pqcp_channel_epoch_directive directive;
	enum pqcp_channel_policy_state next_state;
	uint32_t maximum_frames;
	uint32_t reason_mask;
	int error;
};

struct pqcp_channel_stream_policy_decision {
	enum pqcp_channel_stream_condition condition;
	enum pqcp_channel_control_kind control;
	enum pqcp_channel_stream_directive directive;
	enum pqcp_channel_policy_state next_state;
	uint32_t retry_after_ms;
	uint32_t reason_mask;
	int error;
};

struct pqcp_channel_guard_decision {
	struct pqcp_channel_policy_decision lifecycle;
	struct pqcp_channel_epoch_policy_decision epoch;
	struct pqcp_channel_stream_policy_decision stream;
	enum pqcp_channel_guard_verdict verdict;
	enum pqcp_channel_policy_state next_state;
	uint32_t retry_after_ms;
	uint32_t reason_mask;
	int error;
	bool allowed;
};

int pqcp_channel_epoch_policy_lookup(
	enum pqcp_channel_epoch_condition condition,
	enum pqcp_channel_control_kind control,
	struct pqcp_channel_epoch_policy_decision *decision);
int pqcp_channel_epoch_policy_catalog_audit(void);

int pqcp_channel_stream_policy_lookup(
	enum pqcp_channel_stream_condition condition,
	enum pqcp_channel_control_kind control,
	struct pqcp_channel_stream_policy_decision *decision);
int pqcp_channel_stream_policy_catalog_audit(void);

int pqcp_channel_guard_evaluate(
	enum pqcp_channel_policy_state state,
	enum pqcp_channel_epoch_condition epoch,
	enum pqcp_channel_stream_condition stream,
	enum pqcp_channel_control_kind control,
	struct pqcp_channel_guard_decision *decision);
int pqcp_channel_guard_audit(void);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROTECTED_CHANNEL_GUARD_H_ */
