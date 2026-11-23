/*
 * SPDX-License-Identifier: MIT
 *
 * Composite channel planning across state, path, and fault policy.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/operation_planner.h>

static int error_or(int error, int fallback)
{
	return error != 0 ? error : fallback;
}

static void select_fault(
	struct pqcp_channel_operation_plan *plan)
{
	const struct pqcp_channel_fault_policy_decision *fault =
		&plan->fault_decision;

	plan->next_state = fault->next_state;
	plan->error = fault->error;
	switch (fault->directive) {
	case PQCP_CHANNEL_FAULT_TERMINATE_CHANNEL:
		plan->disposition = PQCP_CHANNEL_PLAN_TERMINATE;
		plan->next_state = PQCP_CHANNEL_POLICY_TERMINATED;
		plan->error = error_or(fault->error, -ESHUTDOWN);
		break;
	case PQCP_CHANNEL_FAULT_CLOSE_CHANNEL:
		plan->disposition = PQCP_CHANNEL_PLAN_CLOSE;
		plan->error = error_or(fault->error, -ECONNABORTED);
		break;
	case PQCP_CHANNEL_FAULT_DRAIN_CHANNEL:
		plan->disposition = PQCP_CHANNEL_PLAN_DRAIN;
		break;
	case PQCP_CHANNEL_FAULT_RESET_STREAM:
		plan->disposition = PQCP_CHANNEL_PLAN_RESET_STREAM;
		break;
	case PQCP_CHANNEL_FAULT_REKEY_CHANNEL:
		plan->disposition = PQCP_CHANNEL_PLAN_REKEY;
		break;
	case PQCP_CHANNEL_FAULT_MIGRATE_PATH:
		plan->disposition = PQCP_CHANNEL_PLAN_MIGRATE_PATH;
		break;
	case PQCP_CHANNEL_FAULT_RETRY:
	case PQCP_CHANNEL_FAULT_BACKOFF:
		plan->disposition = PQCP_CHANNEL_PLAN_RETRY;
		break;
	case PQCP_CHANNEL_FAULT_OBSERVE:
		if (fault->error != 0) {
			plan->disposition = PQCP_CHANNEL_PLAN_RETRY;
		}
		break;
	case PQCP_CHANNEL_FAULT_IGNORE:
	default:
		break;
	}
}

static bool fault_selected(
	const struct pqcp_channel_operation_plan *plan)
{
	return plan->disposition == PQCP_CHANNEL_PLAN_TERMINATE ||
	       plan->disposition == PQCP_CHANNEL_PLAN_CLOSE ||
	       plan->disposition == PQCP_CHANNEL_PLAN_DRAIN ||
	       plan->disposition == PQCP_CHANNEL_PLAN_RESET_STREAM ||
	       plan->disposition == PQCP_CHANNEL_PLAN_REKEY ||
	       plan->disposition == PQCP_CHANNEL_PLAN_MIGRATE_PATH ||
	       plan->disposition == PQCP_CHANNEL_PLAN_RETRY;
}

static void select_state(
	struct pqcp_channel_operation_plan *plan)
{
	const struct pqcp_channel_policy_decision *state =
		&plan->state_decision;

	plan->next_state = state->next_state;
	plan->error = state->error;
	switch (state->action) {
	case PQCP_CHANNEL_POLICY_ALLOW:
	case PQCP_CHANNEL_POLICY_CLOSE_ON_FAILURE:
		plan->disposition = PQCP_CHANNEL_PLAN_ALLOW;
		break;
	case PQCP_CHANNEL_POLICY_ALLOW_IDEMPOTENT:
		plan->disposition =
			PQCP_CHANNEL_PLAN_ALLOW_IDEMPOTENT;
		break;
	case PQCP_CHANNEL_POLICY_REQUIRE_ESTABLISHED:
		plan->disposition =
			PQCP_CHANNEL_PLAN_REQUIRE_ESTABLISHED;
		break;
	case PQCP_CHANNEL_POLICY_REQUIRE_REKEY:
		plan->disposition = PQCP_CHANNEL_PLAN_REKEY;
		break;
	case PQCP_CHANNEL_POLICY_REQUIRE_DRAIN:
		plan->disposition = PQCP_CHANNEL_PLAN_DRAIN;
		break;
	case PQCP_CHANNEL_POLICY_DENY:
	default:
		plan->disposition = PQCP_CHANNEL_PLAN_DENY;
		plan->error = error_or(state->error, -EACCES);
		break;
	}
}

static void select_path(
	struct pqcp_channel_operation_plan *plan)
{
	const struct pqcp_channel_path_policy_decision *path =
		&plan->path_decision;

	plan->next_state = path->next_state;
	plan->error = path->error;
	switch (path->disposition) {
	case PQCP_CHANNEL_PATH_ALLOW_PROBE:
		plan->disposition = PQCP_CHANNEL_PLAN_PROBE_PATH;
		break;
	case PQCP_CHANNEL_PATH_ALLOW_MIGRATE:
		plan->disposition = PQCP_CHANNEL_PLAN_MIGRATE_PATH;
		break;
	case PQCP_CHANNEL_PATH_ALLOW_DRAIN:
		plan->disposition = PQCP_CHANNEL_PLAN_DRAIN;
		break;
	case PQCP_CHANNEL_PATH_REQUIRE_REKEY:
		plan->disposition = PQCP_CHANNEL_PLAN_REKEY;
		break;
	case PQCP_CHANNEL_PATH_CLOSE:
		plan->disposition = PQCP_CHANNEL_PLAN_CLOSE;
		plan->error = error_or(path->error, -ESHUTDOWN);
		break;
	case PQCP_CHANNEL_PATH_ALLOW:
	case PQCP_CHANNEL_PATH_DENY:
	default:
		break;
	}
}

int pqcp_channel_operation_plan(
	const struct pqcp_channel_operation_context *context,
	struct pqcp_channel_operation_plan *plan)
{
	int ret;

	if (context == NULL || plan == NULL) {
		return -EINVAL;
	}
	memset(plan, 0, sizeof(*plan));
	plan->schema_version = PQCP_OPERATION_PLAN_SCHEMA_VERSION;
	plan->context = *context;
	ret = pqcp_channel_policy_lookup(
		context->state, context->control,
		&plan->state_decision);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_path_policy_lookup(
		context->path_condition, context->control,
		&plan->path_decision);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_fault_policy_lookup(
		context->fault_condition, context->control,
		&plan->fault_decision);
	if (ret != 0) {
		return ret;
	}
	plan->probe_timeout_ms =
		plan->path_decision.probe_timeout_ms;
	plan->migration_hysteresis_bps =
		plan->path_decision.migration_hysteresis_bps;
	plan->retry_limit =
		plan->fault_decision.maximum_attempts;
	plan->retry_delay_ms =
		plan->fault_decision.delay_ms;
	plan->reason_mask =
		plan->state_decision.flags |
		plan->path_decision.reason_mask |
		plan->fault_decision.reason_mask;
	plan->disposition = PQCP_CHANNEL_PLAN_DENY;
	plan->next_state = context->state;

	if (plan->fault_decision.directive ==
		    PQCP_CHANNEL_FAULT_TERMINATE_CHANNEL ||
	    plan->fault_decision.directive ==
		    PQCP_CHANNEL_FAULT_CLOSE_CHANNEL) {
		select_fault(plan);
		return pqcp_channel_operation_plan_audit(plan);
	}
	if (plan->path_decision.disposition ==
	    PQCP_CHANNEL_PATH_CLOSE) {
		select_path(plan);
		return pqcp_channel_operation_plan_audit(plan);
	}
	if (plan->state_decision.action ==
	    PQCP_CHANNEL_POLICY_DENY) {
		select_state(plan);
		return pqcp_channel_operation_plan_audit(plan);
	}
	if (plan->path_decision.disposition ==
	    PQCP_CHANNEL_PATH_DENY) {
		plan->disposition = PQCP_CHANNEL_PLAN_DENY;
		plan->next_state = context->state;
		plan->error = error_or(
			plan->path_decision.error, -EHOSTUNREACH);
		return pqcp_channel_operation_plan_audit(plan);
	}

	select_fault(plan);
	if (fault_selected(plan)) {
		return pqcp_channel_operation_plan_audit(plan);
	}
	select_state(plan);
	if (plan->disposition != PQCP_CHANNEL_PLAN_ALLOW &&
	    plan->disposition !=
		    PQCP_CHANNEL_PLAN_ALLOW_IDEMPOTENT) {
		return pqcp_channel_operation_plan_audit(plan);
	}
	select_path(plan);
	if (plan->disposition != PQCP_CHANNEL_PLAN_ALLOW &&
	    plan->disposition !=
		    PQCP_CHANNEL_PLAN_ALLOW_IDEMPOTENT) {
		return pqcp_channel_operation_plan_audit(plan);
	}
	select_state(plan);
	return pqcp_channel_operation_plan_audit(plan);
}

int pqcp_channel_operation_plan_audit(
	const struct pqcp_channel_operation_plan *plan)
{
	if (plan == NULL ||
	    plan->schema_version !=
		    PQCP_OPERATION_PLAN_SCHEMA_VERSION ||
	    plan->context.state < PQCP_CHANNEL_POLICY_NEW ||
	    plan->context.state > PQCP_CHANNEL_POLICY_TERMINATED ||
	    plan->context.path_condition <
		    PQCP_CHANNEL_PATH_CONDITION_PRIMARY_HEALTHY ||
	    plan->context.path_condition >=
		    PQCP_CHANNEL_PATH_CONDITION_COUNT ||
	    plan->context.fault_condition <
		    PQCP_CHANNEL_FAULT_NONE ||
	    plan->context.fault_condition >=
		    PQCP_CHANNEL_FAULT_CONDITION_COUNT ||
	    plan->context.control < PQCP_CHANNEL_CONTROL_NONE ||
	    plan->context.control >=
		    PQCP_CHANNEL_CONTROL_KIND_COUNT ||
	    plan->disposition < PQCP_CHANNEL_PLAN_DENY ||
	    plan->disposition >=
		    PQCP_CHANNEL_PLAN_DISPOSITION_COUNT ||
	    plan->next_state < PQCP_CHANNEL_POLICY_NEW ||
	    plan->next_state > PQCP_CHANNEL_POLICY_TERMINATED ||
	    plan->state_decision.state != plan->context.state ||
	    plan->state_decision.control !=
		    plan->context.control ||
	    plan->path_decision.condition !=
		    plan->context.path_condition ||
	    plan->path_decision.control !=
		    plan->context.control ||
	    plan->fault_decision.condition !=
		    plan->context.fault_condition ||
	    plan->fault_decision.control !=
		    plan->context.control ||
	    plan->reason_mask == 0U) {
		return -EBADMSG;
	}
	if ((plan->disposition == PQCP_CHANNEL_PLAN_DENY ||
	     plan->disposition == PQCP_CHANNEL_PLAN_CLOSE ||
	     plan->disposition == PQCP_CHANNEL_PLAN_TERMINATE) &&
	    plan->error == 0) {
		return -EBADMSG;
	}
	return 0;
}

const char *pqcp_channel_plan_disposition_str(
	enum pqcp_channel_plan_disposition disposition)
{
	static const char *const names[] = {
		[PQCP_CHANNEL_PLAN_DENY] = "deny",
		[PQCP_CHANNEL_PLAN_ALLOW] = "allow",
		[PQCP_CHANNEL_PLAN_ALLOW_IDEMPOTENT] =
			"allow-idempotent",
		[PQCP_CHANNEL_PLAN_REQUIRE_ESTABLISHED] =
			"require-established",
		[PQCP_CHANNEL_PLAN_PROBE_PATH] = "probe-path",
		[PQCP_CHANNEL_PLAN_MIGRATE_PATH] = "migrate-path",
		[PQCP_CHANNEL_PLAN_REKEY] = "rekey",
		[PQCP_CHANNEL_PLAN_DRAIN] = "drain",
		[PQCP_CHANNEL_PLAN_RESET_STREAM] = "reset-stream",
		[PQCP_CHANNEL_PLAN_RETRY] = "retry",
		[PQCP_CHANNEL_PLAN_CLOSE] = "close",
		[PQCP_CHANNEL_PLAN_TERMINATE] = "terminate",
	};

	if (disposition < PQCP_CHANNEL_PLAN_DENY ||
	    disposition >=
		    PQCP_CHANNEL_PLAN_DISPOSITION_COUNT) {
		return "unknown";
	}
	return names[disposition];
}
