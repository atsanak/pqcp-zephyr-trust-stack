/*
 * SPDX-License-Identifier: MIT
 *
 * Composite runtime command guard.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_guard.h>

static void deny_runtime(
	struct pqcp_runtime_guard_decision *decision,
	enum pqcp_runtime_guard_verdict verdict,
	enum pqcp_runtime_policy_state next_state,
	int error)
{
	decision->verdict = verdict;
	decision->next_state = next_state;
	decision->error = error != 0 ? error : -EACCES;
	decision->allowed = false;
}

int pqcp_runtime_guard_evaluate(
	enum pqcp_runtime_policy_state state,
	enum pqcp_runtime_authorization_condition authorization,
	enum pqcp_runtime_continuity_condition continuity,
	enum pqcp_runtime_command_kind command,
	struct pqcp_runtime_guard_decision *decision)
{
	int ret;

	if (decision == NULL) {
		return -EINVAL;
	}
	memset(decision, 0, sizeof(*decision));
	ret = pqcp_runtime_policy_lookup(
		state, command, &decision->lifecycle);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_authorization_policy_lookup(
		authorization, command, &decision->authorization);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_continuity_policy_lookup(
		continuity, command, &decision->continuity);
	if (ret != 0) {
		return ret;
	}

	decision->next_state = decision->lifecycle.next_state;
	decision->delay_ms = decision->continuity.delay_ms;
	decision->reason_mask =
		decision->lifecycle.flags |
		decision->authorization.reason_mask |
		decision->continuity.reason_mask;
	decision->verdict = PQCP_RUNTIME_GUARD_ALLOW;
	decision->allowed = true;

	if (decision->lifecycle.action ==
	    PQCP_RUNTIME_POLICY_DENY) {
		deny_runtime(
			decision, PQCP_RUNTIME_GUARD_DENY,
			decision->lifecycle.next_state,
			decision->lifecycle.error);
		return 0;
	}

	switch (decision->authorization.disposition) {
	case PQCP_RUNTIME_AUTHORIZATION_ALLOW:
		break;
	case PQCP_RUNTIME_AUTHORIZATION_ALLOW_READ_ONLY:
		decision->verdict =
			PQCP_RUNTIME_GUARD_ALLOW_READ_ONLY;
		break;
	case PQCP_RUNTIME_AUTHORIZATION_QUARANTINE:
		deny_runtime(
			decision, PQCP_RUNTIME_GUARD_LOCK_DOWN,
			PQCP_RUNTIME_POLICY_LOCKDOWN,
			decision->authorization.error);
		return 0;
	case PQCP_RUNTIME_AUTHORIZATION_DENY:
	case PQCP_RUNTIME_AUTHORIZATION_REQUIRE_OPERATOR:
	case PQCP_RUNTIME_AUTHORIZATION_REQUIRE_SECURITY_OFFICER:
	case PQCP_RUNTIME_AUTHORIZATION_REQUIRE_FRESH_TOKEN:
	case PQCP_RUNTIME_AUTHORIZATION_REQUIRE_BREAK_GLASS:
	default:
		deny_runtime(
			decision, PQCP_RUNTIME_GUARD_DENY,
			decision->lifecycle.state,
			decision->authorization.error);
		return 0;
	}

	switch (decision->continuity.directive) {
	case PQCP_RUNTIME_CONTINUITY_ALLOW:
		break;
	case PQCP_RUNTIME_CONTINUITY_ALLOW_READ_ONLY:
		decision->verdict =
			PQCP_RUNTIME_GUARD_ALLOW_READ_ONLY;
		decision->next_state =
			decision->continuity.next_state;
		break;
	case PQCP_RUNTIME_CONTINUITY_DEFER:
	case PQCP_RUNTIME_CONTINUITY_CHECKPOINT:
	case PQCP_RUNTIME_CONTINUITY_RECONCILE:
	case PQCP_RUNTIME_CONTINUITY_FAILOVER:
		deny_runtime(
			decision, PQCP_RUNTIME_GUARD_DEFER,
			decision->continuity.next_state,
			decision->continuity.error != 0 ?
				decision->continuity.error : -EAGAIN);
		break;
	case PQCP_RUNTIME_CONTINUITY_LOCK_DOWN:
		deny_runtime(
			decision, PQCP_RUNTIME_GUARD_LOCK_DOWN,
			PQCP_RUNTIME_POLICY_LOCKDOWN,
			decision->continuity.error);
		break;
	case PQCP_RUNTIME_CONTINUITY_TERMINATE:
		deny_runtime(
			decision, PQCP_RUNTIME_GUARD_TERMINATE,
			PQCP_RUNTIME_POLICY_TERMINATED,
			decision->continuity.error);
		break;
	case PQCP_RUNTIME_CONTINUITY_DENY:
	default:
		deny_runtime(
			decision, PQCP_RUNTIME_GUARD_DENY,
			decision->continuity.next_state,
			decision->continuity.error);
		break;
	}
	return 0;
}

int pqcp_runtime_guard_audit(void)
{
	struct pqcp_runtime_guard_decision decision;
	int ret;

	ret = pqcp_runtime_authorization_policy_catalog_audit();
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_continuity_policy_catalog_audit();
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_guard_evaluate(
		PQCP_RUNTIME_POLICY_RUNNING,
		PQCP_RUNTIME_AUTHORIZATION_OPERATOR,
		PQCP_RUNTIME_CONTINUITY_HEALTHY,
		PQCP_RUNTIME_COMMAND_SUBMIT_JOB,
		&decision);
	if (ret != 0 || !decision.allowed ||
	    decision.verdict != PQCP_RUNTIME_GUARD_ALLOW) {
		return -EBADMSG;
	}
	ret = pqcp_runtime_guard_evaluate(
		PQCP_RUNTIME_POLICY_RUNNING,
		PQCP_RUNTIME_AUTHORIZATION_REPLAY_SUSPECTED,
		PQCP_RUNTIME_CONTINUITY_HEALTHY,
		PQCP_RUNTIME_COMMAND_SUBMIT_JOB,
		&decision);
	if (ret != 0 || decision.allowed ||
	    decision.verdict != PQCP_RUNTIME_GUARD_LOCK_DOWN ||
	    decision.next_state != PQCP_RUNTIME_POLICY_LOCKDOWN) {
		return -EBADMSG;
	}
	ret = pqcp_runtime_guard_evaluate(
		PQCP_RUNTIME_POLICY_RUNNING,
		PQCP_RUNTIME_AUTHORIZATION_SECURITY_OFFICER,
		PQCP_RUNTIME_CONTINUITY_PARTITIONED,
		PQCP_RUNTIME_COMMAND_BEGIN_MIGRATION,
		&decision);
	if (ret != 0 || decision.allowed ||
	    decision.verdict != PQCP_RUNTIME_GUARD_DEFER ||
	    decision.next_state != PQCP_RUNTIME_POLICY_MIGRATING) {
		return -EBADMSG;
	}
	return 0;
}
