/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Composition and replay for stateful operational policy transitions.
 */

#include <errno.h>
#include <string.h>

#include "operation_transition_internal.h"

#define FNV1A_OFFSET_BASIS UINT64_C(14695981039346656037)
#define FNV1A_PRIME UINT64_C(1099511628211)

static uint64_t fingerprint_u32(
	uint64_t fingerprint,
	uint32_t value)
{
	for (size_t index = 0U; index < sizeof(value); ++index) {
		fingerprint ^= (uint8_t)(value >> (index * 8U));
		fingerprint *= FNV1A_PRIME;
	}
	return fingerprint;
}

static uint64_t fingerprint_runtime_step(
	uint64_t fingerprint,
	const struct pqcp_runtime_transition_trace_step *step,
	const struct pqcp_runtime_transition_decision *decision)
{
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)step->resource_condition);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)step->recovery_condition);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)step->command);
	fingerprint = fingerprint_u32(
		fingerprint,
		(uint32_t)decision->plan.state_decision.action);
	fingerprint = fingerprint_u32(
		fingerprint,
		(uint32_t)decision->plan.resource_decision.disposition);
	fingerprint = fingerprint_u32(
		fingerprint,
		(uint32_t)decision->plan.recovery_decision.directive);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)decision->effective_state);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)decision->error);
	return fingerprint_u32(
		fingerprint, decision->permitted ? 1U : 0U);
}

static uint64_t fingerprint_channel_step(
	uint64_t fingerprint,
	const struct pqcp_channel_transition_trace_step *step,
	const struct pqcp_channel_transition_decision *decision)
{
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)step->path_condition);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)step->fault_condition);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)step->control);
	fingerprint = fingerprint_u32(
		fingerprint,
		(uint32_t)decision->plan.state_decision.action);
	fingerprint = fingerprint_u32(
		fingerprint,
		(uint32_t)decision->plan.path_decision.disposition);
	fingerprint = fingerprint_u32(
		fingerprint,
		(uint32_t)decision->plan.fault_decision.directive);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)decision->effective_state);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)decision->error);
	return fingerprint_u32(
		fingerprint, decision->permitted ? 1U : 0U);
}

int pqcp_runtime_transition_decide(
	const struct pqcp_runtime_transition_input *input,
	struct pqcp_runtime_transition_decision *decision)
{
	struct pqcp_runtime_operation_context context;
	int ret;

	if (input == NULL || decision == NULL ||
	    input->state < PQCP_RUNTIME_POLICY_UNINITIALIZED ||
	    input->state >= PQCP_RUNTIME_POLICY_STATE_COUNT ||
	    input->resource_condition <
		    PQCP_RUNTIME_RESOURCE_AVAILABLE ||
	    input->resource_condition >=
		    PQCP_RUNTIME_RESOURCE_CONDITION_COUNT ||
	    input->recovery_condition <
		    PQCP_RUNTIME_RECOVERY_HEALTHY ||
	    input->recovery_condition >=
		    PQCP_RUNTIME_RECOVERY_CONDITION_COUNT ||
	    input->command < PQCP_RUNTIME_COMMAND_NONE ||
	    input->command >= PQCP_RUNTIME_COMMAND_KIND_COUNT) {
		return -EINVAL;
	}
	memset(decision, 0, sizeof(*decision));
	context.state = input->state;
	context.resource_condition = input->resource_condition;
	context.recovery_condition = input->recovery_condition;
	context.command = input->command;
	ret = pqcp_runtime_operation_plan(
		&context, &decision->plan);
	if (ret != 0) {
		return ret;
	}
	decision->effective_state = decision->plan.next_state;
	decision->error = decision->plan.error;
	decision->permitted =
		decision->plan.disposition != PQCP_RUNTIME_PLAN_DENY &&
		decision->plan.disposition !=
			PQCP_RUNTIME_PLAN_LOCKDOWN &&
		decision->plan.disposition !=
			PQCP_RUNTIME_PLAN_TERMINATE &&
		decision->error == 0;
	return 0;
}

int pqcp_channel_transition_decide(
	const struct pqcp_channel_transition_input *input,
	struct pqcp_channel_transition_decision *decision)
{
	struct pqcp_channel_operation_context context;
	int ret;

	if (input == NULL || decision == NULL ||
	    input->state < PQCP_CHANNEL_POLICY_NEW ||
	    input->state >= PQCP_CHANNEL_POLICY_STATE_COUNT ||
	    input->path_condition <
		    PQCP_CHANNEL_PATH_CONDITION_PRIMARY_HEALTHY ||
	    input->path_condition >=
		    PQCP_CHANNEL_PATH_CONDITION_COUNT ||
	    input->fault_condition < PQCP_CHANNEL_FAULT_NONE ||
	    input->fault_condition >=
		    PQCP_CHANNEL_FAULT_CONDITION_COUNT ||
	    input->control < PQCP_CHANNEL_CONTROL_NONE ||
	    input->control >= PQCP_CHANNEL_CONTROL_KIND_COUNT) {
		return -EINVAL;
	}
	memset(decision, 0, sizeof(*decision));
	context.state = input->state;
	context.path_condition = input->path_condition;
	context.fault_condition = input->fault_condition;
	context.control = input->control;
	ret = pqcp_channel_operation_plan(
		&context, &decision->plan);
	if (ret != 0) {
		return ret;
	}
	decision->effective_state = decision->plan.next_state;
	decision->error = decision->plan.error;
	decision->permitted =
		decision->plan.disposition != PQCP_CHANNEL_PLAN_DENY &&
		decision->plan.disposition != PQCP_CHANNEL_PLAN_CLOSE &&
		decision->plan.disposition !=
			PQCP_CHANNEL_PLAN_TERMINATE &&
		decision->error == 0;
	return 0;
}

size_t pqcp_runtime_transition_trace_count(void)
{
	return pqcp_runtime_transition_catalog_count();
}

int pqcp_runtime_transition_trace_get(
	size_t index,
	struct pqcp_runtime_transition_trace *trace)
{
	return pqcp_runtime_transition_catalog_get(index, trace);
}

int pqcp_runtime_transition_trace_replay(
	const struct pqcp_runtime_transition_trace *trace,
	struct pqcp_runtime_transition_replay_result *result)
{
	struct pqcp_runtime_transition_input input;
	struct pqcp_runtime_transition_decision decision;
	uint64_t fingerprint = FNV1A_OFFSET_BASIS;

	if (trace == NULL || result == NULL ||
	    trace->schema_version !=
		    PQCP_OPERATION_TRANSITION_SCHEMA_VERSION ||
	    trace->step_count !=
		    PQCP_OPERATION_TRANSITION_STEPS_PER_TRACE ||
	    trace->initial_state < PQCP_RUNTIME_POLICY_UNINITIALIZED ||
	    trace->initial_state >= PQCP_RUNTIME_POLICY_STATE_COUNT) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->trace_id = trace->trace_id;
	input.state = trace->initial_state;
	fingerprint = fingerprint_u32(
		fingerprint, trace->schema_version);
	fingerprint = fingerprint_u32(
		fingerprint, trace->trace_id);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)trace->initial_state);
	for (size_t index = 0U; index < trace->step_count; ++index) {
		const struct pqcp_runtime_transition_trace_step *step =
			&trace->steps[index];
		int ret;

		input.resource_condition =
			step->resource_condition;
		input.recovery_condition =
			step->recovery_condition;
		input.command = step->command;
		ret = pqcp_runtime_transition_decide(
			&input, &decision);
		if (ret != 0) {
			return ret;
		}
		fingerprint = fingerprint_runtime_step(
			fingerprint, step, &decision);
		input.state = decision.effective_state;
		result->steps_replayed++;
	}
	result->final_state = input.state;
	result->fingerprint = fingerprint;
	return fingerprint == trace->expected_fingerprint ?
		       0 :
		       -EBADMSG;
}

size_t pqcp_channel_transition_trace_count(void)
{
	return pqcp_channel_transition_catalog_count();
}

int pqcp_channel_transition_trace_get(
	size_t index,
	struct pqcp_channel_transition_trace *trace)
{
	return pqcp_channel_transition_catalog_get(index, trace);
}

int pqcp_channel_transition_trace_replay(
	const struct pqcp_channel_transition_trace *trace,
	struct pqcp_channel_transition_replay_result *result)
{
	struct pqcp_channel_transition_input input;
	struct pqcp_channel_transition_decision decision;
	uint64_t fingerprint = FNV1A_OFFSET_BASIS;

	if (trace == NULL || result == NULL ||
	    trace->schema_version !=
		    PQCP_OPERATION_TRANSITION_SCHEMA_VERSION ||
	    trace->step_count !=
		    PQCP_OPERATION_TRANSITION_STEPS_PER_TRACE ||
	    trace->initial_state < PQCP_CHANNEL_POLICY_NEW ||
	    trace->initial_state >= PQCP_CHANNEL_POLICY_STATE_COUNT) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->trace_id = trace->trace_id;
	input.state = trace->initial_state;
	fingerprint = fingerprint_u32(
		fingerprint, trace->schema_version);
	fingerprint = fingerprint_u32(
		fingerprint, trace->trace_id);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)trace->initial_state);
	for (size_t index = 0U; index < trace->step_count; ++index) {
		const struct pqcp_channel_transition_trace_step *step =
			&trace->steps[index];
		int ret;

		input.path_condition = step->path_condition;
		input.fault_condition = step->fault_condition;
		input.control = step->control;
		ret = pqcp_channel_transition_decide(
			&input, &decision);
		if (ret != 0) {
			return ret;
		}
		fingerprint = fingerprint_channel_step(
			fingerprint, step, &decision);
		input.state = decision.effective_state;
		result->steps_replayed++;
	}
	result->final_state = input.state;
	result->fingerprint = fingerprint;
	return fingerprint == trace->expected_fingerprint ?
		       0 :
		       -EBADMSG;
}

int pqcp_runtime_transition_trace_fingerprint(
	uint64_t *fingerprint)
{
	struct pqcp_runtime_transition_trace trace;
	struct pqcp_runtime_transition_replay_result result;
	uint64_t value = FNV1A_OFFSET_BASIS;

	if (fingerprint == NULL) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < pqcp_runtime_transition_trace_count();
	     ++index) {
		int ret = pqcp_runtime_transition_trace_get(
			index, &trace);

		if (ret != 0) {
			return ret;
		}
		ret = pqcp_runtime_transition_trace_replay(
			&trace, &result);
		if (ret != 0) {
			return ret;
		}
		value = fingerprint_u32(
			value, (uint32_t)result.fingerprint);
		value = fingerprint_u32(
			value,
			(uint32_t)(result.fingerprint >> 32));
	}
	*fingerprint = value;
	return 0;
}

int pqcp_channel_transition_trace_fingerprint(
	uint64_t *fingerprint)
{
	struct pqcp_channel_transition_trace trace;
	struct pqcp_channel_transition_replay_result result;
	uint64_t value = FNV1A_OFFSET_BASIS;

	if (fingerprint == NULL) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < pqcp_channel_transition_trace_count();
	     ++index) {
		int ret = pqcp_channel_transition_trace_get(
			index, &trace);

		if (ret != 0) {
			return ret;
		}
		ret = pqcp_channel_transition_trace_replay(
			&trace, &result);
		if (ret != 0) {
			return ret;
		}
		value = fingerprint_u32(
			value, (uint32_t)result.fingerprint);
		value = fingerprint_u32(
			value,
			(uint32_t)(result.fingerprint >> 32));
	}
	*fingerprint = value;
	return 0;
}

int pqcp_runtime_transition_trace_audit(void)
{
	struct pqcp_runtime_transition_trace trace;
	struct pqcp_runtime_transition_replay_result result;

	if (pqcp_runtime_transition_trace_count() !=
	    PQCP_OPERATION_TRANSITION_TRACES_PER_DOMAIN) {
		return -EBADMSG;
	}
	for (size_t index = 0U;
	     index < pqcp_runtime_transition_trace_count();
	     ++index) {
		int ret = pqcp_runtime_transition_trace_get(
			index, &trace);

		if (ret != 0) {
			return ret;
		}
		ret = pqcp_runtime_transition_trace_replay(
			&trace, &result);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

int pqcp_channel_transition_trace_audit(void)
{
	struct pqcp_channel_transition_trace trace;
	struct pqcp_channel_transition_replay_result result;

	if (pqcp_channel_transition_trace_count() !=
	    PQCP_OPERATION_TRANSITION_TRACES_PER_DOMAIN) {
		return -EBADMSG;
	}
	for (size_t index = 0U;
	     index < pqcp_channel_transition_trace_count();
	     ++index) {
		int ret = pqcp_channel_transition_trace_get(
			index, &trace);

		if (ret != 0) {
			return ret;
		}
		ret = pqcp_channel_transition_trace_replay(
			&trace, &result);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

int pqcp_operation_transition_audit_all(void)
{
	int ret = pqcp_runtime_transition_trace_audit();

	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_transition_trace_audit();
	if (ret != 0) {
		return ret;
	}
	return pqcp_runtime_transition_trace_count() +
			       pqcp_channel_transition_trace_count() ==
		       PQCP_OPERATION_TRANSITION_TOTAL_TRACES ?
		       0 :
		       -EBADMSG;
}

const char *pqcp_operation_transition_domain_str(
	enum pqcp_operation_transition_domain domain)
{
	switch (domain) {
	case PQCP_OPERATION_TRANSITION_RUNTIME:
		return "runtime";
	case PQCP_OPERATION_TRANSITION_CHANNEL:
		return "channel";
	default:
		return "unknown";
	}
}
