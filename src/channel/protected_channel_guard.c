/*
 * SPDX-License-Identifier: MIT
 *
 * Composite protected-channel control guard.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel_guard.h>

static void deny_channel(
	struct pqcp_channel_guard_decision *decision,
	enum pqcp_channel_guard_verdict verdict,
	enum pqcp_channel_policy_state next_state,
	int error)
{
	decision->verdict = verdict;
	decision->next_state = next_state;
	decision->error = error != 0 ? error : -EACCES;
	decision->allowed = false;
}

int pqcp_channel_guard_evaluate(
	enum pqcp_channel_policy_state state,
	enum pqcp_channel_epoch_condition epoch,
	enum pqcp_channel_stream_condition stream,
	enum pqcp_channel_control_kind control,
	struct pqcp_channel_guard_decision *decision)
{
	int ret;

	if (decision == NULL) {
		return -EINVAL;
	}
	memset(decision, 0, sizeof(*decision));
	ret = pqcp_channel_policy_lookup(
		state, control, &decision->lifecycle);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_epoch_policy_lookup(
		epoch, control, &decision->epoch);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_stream_policy_lookup(
		stream, control, &decision->stream);
	if (ret != 0) {
		return ret;
	}

	decision->verdict = PQCP_CHANNEL_GUARD_ALLOW;
	decision->next_state = decision->lifecycle.next_state;
	decision->retry_after_ms =
		decision->stream.retry_after_ms;
	decision->reason_mask =
		decision->lifecycle.flags |
		decision->epoch.reason_mask |
		decision->stream.reason_mask;
	decision->allowed = true;

	if (decision->lifecycle.action ==
	    PQCP_CHANNEL_POLICY_DENY) {
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_DENY,
			decision->lifecycle.next_state,
			decision->lifecycle.error);
		return 0;
	}

	switch (decision->epoch.directive) {
	case PQCP_CHANNEL_EPOCH_ALLOW:
		break;
	case PQCP_CHANNEL_EPOCH_ALLOW_REKEY_ONLY:
		if (decision->epoch.error != 0) {
			deny_channel(
				decision, PQCP_CHANNEL_GUARD_DEFER,
				decision->epoch.next_state,
				decision->epoch.error);
			return 0;
		}
		decision->next_state = decision->epoch.next_state;
		break;
	case PQCP_CHANNEL_EPOCH_REQUIRE_REKEY:
	case PQCP_CHANNEL_EPOCH_RESYNC:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_DEFER,
			decision->epoch.next_state,
			decision->epoch.error != 0 ?
				decision->epoch.error : -EAGAIN);
		return 0;
	case PQCP_CHANNEL_EPOCH_CLOSE:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_CLOSE,
			PQCP_CHANNEL_POLICY_CLOSING,
			decision->epoch.error);
		return 0;
	case PQCP_CHANNEL_EPOCH_TERMINATE:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_TERMINATE,
			PQCP_CHANNEL_POLICY_TERMINATED,
			decision->epoch.error);
		return 0;
	case PQCP_CHANNEL_EPOCH_DENY:
	case PQCP_CHANNEL_EPOCH_REJECT:
	default:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_DENY,
			decision->epoch.next_state,
			decision->epoch.error);
		return 0;
	}

	switch (decision->stream.directive) {
	case PQCP_CHANNEL_STREAM_DIRECTIVE_ALLOW:
	case PQCP_CHANNEL_STREAM_DIRECTIVE_ALLOW_CONTROL_ONLY:
		break;
	case PQCP_CHANNEL_STREAM_DIRECTIVE_BACKPRESSURE:
	case PQCP_CHANNEL_STREAM_DIRECTIVE_REQUIRE_OPEN:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_DEFER,
			decision->stream.next_state,
			decision->stream.error != 0 ?
				decision->stream.error : -EAGAIN);
		break;
	case PQCP_CHANNEL_STREAM_DIRECTIVE_RESET_STREAM:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_RESET_STREAM,
			decision->stream.next_state,
			decision->stream.error);
		break;
	case PQCP_CHANNEL_STREAM_DIRECTIVE_DRAIN:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_DRAIN,
			decision->stream.next_state,
			decision->stream.error);
		break;
	case PQCP_CHANNEL_STREAM_DIRECTIVE_CLOSE_CHANNEL:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_CLOSE,
			PQCP_CHANNEL_POLICY_CLOSING,
			decision->stream.error);
		break;
	case PQCP_CHANNEL_STREAM_DIRECTIVE_TERMINATE:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_TERMINATE,
			PQCP_CHANNEL_POLICY_TERMINATED,
			decision->stream.error);
		break;
	case PQCP_CHANNEL_STREAM_DIRECTIVE_DENY:
	default:
		deny_channel(
			decision, PQCP_CHANNEL_GUARD_DENY,
			decision->stream.next_state,
			decision->stream.error);
		break;
	}
	return 0;
}

int pqcp_channel_guard_audit(void)
{
	struct pqcp_channel_guard_decision decision;
	int ret;

	ret = pqcp_channel_epoch_policy_catalog_audit();
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_stream_policy_catalog_audit();
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_guard_evaluate(
		PQCP_CHANNEL_POLICY_ESTABLISHED,
		PQCP_CHANNEL_EPOCH_CURRENT,
		PQCP_CHANNEL_STREAM_CONDITION_IDLE,
		PQCP_CHANNEL_CONTROL_STREAM_OPEN,
		&decision);
	if (ret != 0 || !decision.allowed ||
	    decision.verdict != PQCP_CHANNEL_GUARD_ALLOW) {
		return -EBADMSG;
	}
	ret = pqcp_channel_guard_evaluate(
		PQCP_CHANNEL_POLICY_ESTABLISHED,
		PQCP_CHANNEL_EPOCH_ROTATION_OVERDUE,
		PQCP_CHANNEL_STREAM_CONDITION_OPEN,
		PQCP_CHANNEL_CONTROL_STREAM_WINDOW,
		&decision);
	if (ret != 0 || decision.allowed ||
	    decision.verdict != PQCP_CHANNEL_GUARD_DEFER ||
	    decision.next_state !=
		    PQCP_CHANNEL_POLICY_REKEY_PREPARED) {
		return -EBADMSG;
	}
	ret = pqcp_channel_guard_evaluate(
		PQCP_CHANNEL_POLICY_ESTABLISHED,
		PQCP_CHANNEL_EPOCH_CURRENT,
		PQCP_CHANNEL_STREAM_CONDITION_SEQUENCE_REPLAY,
		PQCP_CHANNEL_CONTROL_STREAM_WINDOW,
		&decision);
	if (ret != 0 || decision.allowed ||
	    decision.verdict != PQCP_CHANNEL_GUARD_CLOSE ||
	    decision.next_state != PQCP_CHANNEL_POLICY_CLOSING) {
		return -EBADMSG;
	}
	return 0;
}
