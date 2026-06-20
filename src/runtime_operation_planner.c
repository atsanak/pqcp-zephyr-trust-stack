/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Composite runtime planning across state, resource, and recovery policy.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/operation_planner.h>

static int error_or(int error, int fallback)
{
	return error != 0 ? error : fallback;
}

static void select_recovery(
	struct pqcp_runtime_operation_plan *plan)
{
	const struct pqcp_runtime_recovery_policy_decision *recovery =
		&plan->recovery_decision;

	switch (recovery->directive) {
	case PQCP_RUNTIME_RECOVERY_TERMINATE:
		plan->disposition = PQCP_RUNTIME_PLAN_TERMINATE;
		plan->next_state = PQCP_RUNTIME_POLICY_TERMINATED;
		plan->error = error_or(recovery->error, -ESHUTDOWN);
		break;
	case PQCP_RUNTIME_RECOVERY_LOCK_DOWN:
		plan->disposition = PQCP_RUNTIME_PLAN_LOCKDOWN;
		plan->next_state = PQCP_RUNTIME_POLICY_LOCKDOWN;
		plan->error = error_or(recovery->error, -EACCES);
		break;
	case PQCP_RUNTIME_RECOVERY_RESTART:
	case PQCP_RUNTIME_RECOVERY_ROLLBACK:
	case PQCP_RUNTIME_RECOVERY_ROTATE_KEYS:
		plan->disposition = PQCP_RUNTIME_PLAN_RECOVER;
		plan->next_state = recovery->next_state;
		plan->error = recovery->error;
		break;
	case PQCP_RUNTIME_RECOVERY_CHECKPOINT:
		plan->disposition = PQCP_RUNTIME_PLAN_CHECKPOINT;
		plan->next_state = recovery->next_state;
		plan->error = recovery->error;
		break;
	case PQCP_RUNTIME_RECOVERY_DRAIN:
		plan->disposition = PQCP_RUNTIME_PLAN_DRAIN;
		plan->next_state = recovery->next_state;
		plan->error = recovery->error;
		break;
	case PQCP_RUNTIME_RECOVERY_RETRY:
	case PQCP_RUNTIME_RECOVERY_BACKOFF:
		plan->disposition = PQCP_RUNTIME_PLAN_RETRY;
		plan->next_state = recovery->next_state;
		plan->error = recovery->error;
		break;
	case PQCP_RUNTIME_RECOVERY_IGNORE:
	case PQCP_RUNTIME_RECOVERY_OBSERVE:
	default:
		break;
	}
}

static bool recovery_selected(
	const struct pqcp_runtime_operation_plan *plan)
{
	return plan->disposition == PQCP_RUNTIME_PLAN_TERMINATE ||
	       plan->disposition == PQCP_RUNTIME_PLAN_LOCKDOWN ||
	       plan->disposition == PQCP_RUNTIME_PLAN_RECOVER ||
	       plan->disposition == PQCP_RUNTIME_PLAN_CHECKPOINT ||
	       plan->disposition == PQCP_RUNTIME_PLAN_DRAIN ||
	       plan->disposition == PQCP_RUNTIME_PLAN_RETRY;
}

static void select_resource(
	struct pqcp_runtime_operation_plan *plan)
{
	switch (plan->resource_decision.disposition) {
	case PQCP_RUNTIME_RESOURCE_REQUIRE_RECOVERY:
		plan->disposition = PQCP_RUNTIME_PLAN_RECOVER;
		plan->next_state = PQCP_RUNTIME_POLICY_RECOVERING;
		plan->error = plan->resource_decision.error;
		break;
	case PQCP_RUNTIME_RESOURCE_REQUIRE_CHECKPOINT:
		plan->disposition = PQCP_RUNTIME_PLAN_CHECKPOINT;
		plan->next_state = PQCP_RUNTIME_POLICY_CHECKPOINTING;
		plan->error = plan->resource_decision.error;
		break;
	case PQCP_RUNTIME_RESOURCE_ALLOW_RECLAIM:
		plan->disposition = PQCP_RUNTIME_PLAN_RECLAIM;
		plan->error = plan->resource_decision.error;
		break;
	case PQCP_RUNTIME_RESOURCE_ALLOW_THROTTLED:
		plan->disposition = PQCP_RUNTIME_PLAN_THROTTLE;
		plan->error = plan->resource_decision.error;
		break;
	case PQCP_RUNTIME_RESOURCE_ALLOW:
	case PQCP_RUNTIME_RESOURCE_DENY:
	default:
		break;
	}
}

static void select_state(
	struct pqcp_runtime_operation_plan *plan)
{
	const struct pqcp_runtime_policy_decision *state =
		&plan->state_decision;

	plan->next_state = state->next_state;
	plan->error = state->error;
	switch (state->action) {
	case PQCP_RUNTIME_POLICY_ALLOW:
		plan->disposition = PQCP_RUNTIME_PLAN_ALLOW;
		break;
	case PQCP_RUNTIME_POLICY_ALLOW_IDEMPOTENT:
		plan->disposition =
			PQCP_RUNTIME_PLAN_ALLOW_IDEMPOTENT;
		break;
	case PQCP_RUNTIME_POLICY_ALLOW_READ_ONLY:
		plan->disposition =
			PQCP_RUNTIME_PLAN_ALLOW_READ_ONLY;
		break;
	case PQCP_RUNTIME_POLICY_REQUIRE_DRAIN:
		plan->disposition = PQCP_RUNTIME_PLAN_DRAIN;
		break;
	case PQCP_RUNTIME_POLICY_REQUIRE_MAINTENANCE:
		plan->disposition = PQCP_RUNTIME_PLAN_MAINTENANCE;
		break;
	case PQCP_RUNTIME_POLICY_REQUIRE_RECOVERY:
		plan->disposition = PQCP_RUNTIME_PLAN_RECOVER;
		break;
	case PQCP_RUNTIME_POLICY_DENY:
	default:
		plan->disposition = PQCP_RUNTIME_PLAN_DENY;
		plan->error = error_or(state->error, -EACCES);
		break;
	}
}

int pqcp_runtime_operation_plan(
	const struct pqcp_runtime_operation_context *context,
	struct pqcp_runtime_operation_plan *plan)
{
	int ret;

	if (context == NULL || plan == NULL) {
		return -EINVAL;
	}
	memset(plan, 0, sizeof(*plan));
	plan->schema_version = PQCP_OPERATION_PLAN_SCHEMA_VERSION;
	plan->context = *context;
	ret = pqcp_runtime_policy_lookup(
		context->state, context->command,
		&plan->state_decision);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_resource_policy_lookup(
		context->resource_condition, context->command,
		&plan->resource_decision);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_recovery_policy_lookup(
		context->recovery_condition, context->command,
		&plan->recovery_decision);
	if (ret != 0) {
		return ret;
	}
	plan->maximum_concurrency =
		plan->resource_decision.maximum_concurrency;
	plan->reservation_ttl_ms =
		plan->resource_decision.reservation_ttl_ms;
	plan->priority_penalty =
		plan->resource_decision.priority_penalty;
	plan->retry_limit =
		plan->recovery_decision.maximum_attempts;
	plan->retry_delay_ms =
		plan->recovery_decision.delay_ms;
	plan->reason_mask =
		plan->state_decision.flags |
		plan->resource_decision.reason_mask |
		plan->recovery_decision.reason_mask;
	plan->disposition = PQCP_RUNTIME_PLAN_DENY;
	plan->next_state = context->state;

	if (plan->recovery_decision.directive ==
		    PQCP_RUNTIME_RECOVERY_TERMINATE ||
	    plan->recovery_decision.directive ==
		    PQCP_RUNTIME_RECOVERY_LOCK_DOWN) {
		select_recovery(plan);
		return pqcp_runtime_operation_plan_audit(plan);
	}
	if (plan->state_decision.action ==
	    PQCP_RUNTIME_POLICY_DENY) {
		select_state(plan);
		return pqcp_runtime_operation_plan_audit(plan);
	}
	if (plan->resource_decision.disposition ==
	    PQCP_RUNTIME_RESOURCE_DENY) {
		plan->disposition = PQCP_RUNTIME_PLAN_DENY;
		plan->next_state = context->state;
		plan->error = error_or(
			plan->resource_decision.error, -EDQUOT);
		return pqcp_runtime_operation_plan_audit(plan);
	}

	select_recovery(plan);
	if (recovery_selected(plan)) {
		return pqcp_runtime_operation_plan_audit(plan);
	}
	select_resource(plan);
	if (plan->disposition != PQCP_RUNTIME_PLAN_DENY) {
		return pqcp_runtime_operation_plan_audit(plan);
	}
	select_state(plan);
	return pqcp_runtime_operation_plan_audit(plan);
}

int pqcp_runtime_operation_plan_audit(
	const struct pqcp_runtime_operation_plan *plan)
{
	if (plan == NULL ||
	    plan->schema_version !=
		    PQCP_OPERATION_PLAN_SCHEMA_VERSION ||
	    plan->context.state < PQCP_RUNTIME_POLICY_UNINITIALIZED ||
	    plan->context.state > PQCP_RUNTIME_POLICY_TERMINATED ||
	    plan->context.resource_condition <
		    PQCP_RUNTIME_RESOURCE_AVAILABLE ||
	    plan->context.resource_condition >=
		    PQCP_RUNTIME_RESOURCE_CONDITION_COUNT ||
	    plan->context.recovery_condition <
		    PQCP_RUNTIME_RECOVERY_HEALTHY ||
	    plan->context.recovery_condition >=
		    PQCP_RUNTIME_RECOVERY_CONDITION_COUNT ||
	    plan->context.command < PQCP_RUNTIME_COMMAND_NONE ||
	    plan->context.command >=
		    PQCP_RUNTIME_COMMAND_KIND_COUNT ||
	    plan->disposition < PQCP_RUNTIME_PLAN_DENY ||
	    plan->disposition >=
		    PQCP_RUNTIME_PLAN_DISPOSITION_COUNT ||
	    plan->next_state < PQCP_RUNTIME_POLICY_UNINITIALIZED ||
	    plan->next_state > PQCP_RUNTIME_POLICY_TERMINATED ||
	    plan->state_decision.state != plan->context.state ||
	    plan->state_decision.command !=
		    plan->context.command ||
	    plan->resource_decision.condition !=
		    plan->context.resource_condition ||
	    plan->resource_decision.command !=
		    plan->context.command ||
	    plan->recovery_decision.condition !=
		    plan->context.recovery_condition ||
	    plan->recovery_decision.command !=
		    plan->context.command ||
	    plan->reason_mask == 0U) {
		return -EBADMSG;
	}
	if ((plan->disposition == PQCP_RUNTIME_PLAN_DENY ||
	     plan->disposition == PQCP_RUNTIME_PLAN_LOCKDOWN ||
	     plan->disposition == PQCP_RUNTIME_PLAN_TERMINATE) &&
	    plan->error == 0) {
		return -EBADMSG;
	}
	return 0;
}

const char *pqcp_runtime_plan_disposition_str(
	enum pqcp_runtime_plan_disposition disposition)
{
	static const char *const names[] = {
		[PQCP_RUNTIME_PLAN_DENY] = "deny",
		[PQCP_RUNTIME_PLAN_ALLOW] = "allow",
		[PQCP_RUNTIME_PLAN_ALLOW_IDEMPOTENT] =
			"allow-idempotent",
		[PQCP_RUNTIME_PLAN_ALLOW_READ_ONLY] =
			"allow-read-only",
		[PQCP_RUNTIME_PLAN_THROTTLE] = "throttle",
		[PQCP_RUNTIME_PLAN_RECLAIM] = "reclaim",
		[PQCP_RUNTIME_PLAN_DRAIN] = "drain",
		[PQCP_RUNTIME_PLAN_MAINTENANCE] =
			"maintenance",
		[PQCP_RUNTIME_PLAN_CHECKPOINT] = "checkpoint",
		[PQCP_RUNTIME_PLAN_RETRY] = "retry",
		[PQCP_RUNTIME_PLAN_RECOVER] = "recover",
		[PQCP_RUNTIME_PLAN_LOCKDOWN] = "lockdown",
		[PQCP_RUNTIME_PLAN_TERMINATE] = "terminate",
	};

	if (disposition < PQCP_RUNTIME_PLAN_DENY ||
	    disposition >=
		    PQCP_RUNTIME_PLAN_DISPOSITION_COUNT) {
		return "unknown";
	}
	return names[disposition];
}
