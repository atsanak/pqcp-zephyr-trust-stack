/*
 * SPDX-License-Identifier: MIT
 *
 * Portable, allocation-free fleet policy bytecode interpreter.
 */

#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_policy_vm.h>

struct vm_state {
	const struct pqcp_fleet_policy_module *module;
	const struct pqcp_fleet_policy_execution_context *context;
	struct pqcp_fleet_policy_vm_workspace *workspace;
	struct pqcp_fleet_policy_execution_result *result;
	uint32_t pc;
	uint32_t function_index;
	uint32_t instruction_budget;
	size_t stack_size;
	size_t local_size;
	size_t frame_count;
	bool decision_emitted;
};

static bool value_type_valid(uint32_t type)
{
	return type >= PQCP_FLEET_POLICY_VALUE_I64 &&
	       type <= PQCP_FLEET_POLICY_VALUE_DIGEST;
}

int pqcp_fleet_policy_value_validate(
	const struct pqcp_fleet_policy_value *value)
{
	if (value == NULL || !value_type_valid(value->type) ||
	    value->reserved != 0U) {
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
	switch (value->type) {
	case PQCP_FLEET_POLICY_VALUE_I64:
	case PQCP_FLEET_POLICY_VALUE_U64:
	case PQCP_FLEET_POLICY_VALUE_BOOL:
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_VALUE_BYTES:
		if (value->as.bytes.data == NULL &&
		    value->as.bytes.length != 0U) {
			return PQCP_FLEET_POLICY_ERR_TYPE;
		}
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_VALUE_DIGEST:
		if (value->as.bytes.data == NULL ||
		    value->as.bytes.length !=
			    PQCP_FLEET_POLICY_DIGEST_BYTES) {
			return PQCP_FLEET_POLICY_ERR_TYPE;
		}
		return PQCP_FLEET_POLICY_OK;
	default:
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
}

static bool builtin_descriptor_valid(
	const struct pqcp_fleet_policy_builtin_descriptor *descriptor)
{
	if (descriptor == NULL || descriptor->builtin_id == 0U ||
	    descriptor->invoke == NULL ||
	    descriptor->argument_count >
		    PQCP_FLEET_POLICY_MAX_BUILTIN_ARGS ||
	    (descriptor->flags &
	     ~(PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC |
	       PQCP_FLEET_POLICY_BUILTIN_PURE)) != 0U ||
	    (descriptor->flags &
	     PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC) == 0U ||
	    (descriptor->result_type !=
		     PQCP_FLEET_POLICY_VALUE_INVALID &&
	     !value_type_valid(descriptor->result_type))) {
		return false;
	}
	for (uint32_t index = 0U;
	     index < descriptor->argument_count; ++index) {
		if (!value_type_valid(
			    descriptor->argument_types[index])) {
			return false;
		}
	}
	for (uint32_t index = descriptor->argument_count;
	     index < PQCP_FLEET_POLICY_MAX_BUILTIN_ARGS; ++index) {
		if (descriptor->argument_types[index] !=
		    PQCP_FLEET_POLICY_VALUE_INVALID) {
			return false;
		}
	}
	return descriptor->reserved == 0U;
}

static const struct pqcp_fleet_policy_builtin_descriptor *
builtin_find(
	const struct pqcp_fleet_policy_builtin_registry *registry,
	uint32_t builtin_id)
{
	if (registry == NULL || builtin_id == 0U ||
	    (registry->descriptors == NULL &&
	     registry->descriptor_count != 0U)) {
		return NULL;
	}
	for (size_t index = 0U;
	     index < registry->descriptor_count; ++index) {
		if (registry->descriptors[index].builtin_id ==
		    builtin_id) {
			return &registry->descriptors[index];
		}
	}
	return NULL;
}

static bool digest_nonzero(
	const uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_POLICY_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate != 0U;
}

static int module_validate(
	const struct pqcp_fleet_policy_module *module)
{
	uint32_t next_instruction = 0U;
	uint32_t entry_count = 0U;

	if (module == NULL ||
	    module->abi_version != PQCP_FLEET_POLICY_ABI_VERSION ||
	    module->bytecode_version !=
		    PQCP_FLEET_POLICY_BYTECODE_VERSION ||
	    module->instructions == NULL ||
	    module->instruction_count == 0U ||
	    module->functions == NULL ||
	    module->function_count == 0U ||
	    module->entry_function >= module->function_count ||
	    (module->constants == NULL &&
	     module->constant_count != 0U) ||
	    (module->flags &
	     ~(PQCP_FLEET_POLICY_MODULE_REQUIRE_DIGEST |
	       PQCP_FLEET_POLICY_MODULE_CANONICAL)) != 0U ||
	    ((module->flags &
	      PQCP_FLEET_POLICY_MODULE_REQUIRE_DIGEST) != 0U &&
	     !digest_nonzero(module->digest)) ||
	    module->bounds.instruction_budget == 0U ||
	    module->bounds.max_stack_values == 0U ||
	    module->bounds.max_call_frames == 0U ||
	    module->bounds.max_action_arguments >
		    PQCP_FLEET_POLICY_MAX_ACTION_ARGS ||
	    module->bounds.reserved != 0U) {
		return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
	}
	for (uint32_t index = 0U;
	     index < module->constant_count; ++index) {
		if (pqcp_fleet_policy_value_validate(
			    &module->constants[index]) !=
		    PQCP_FLEET_POLICY_OK) {
			return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
		}
	}
	for (uint32_t index = 0U;
	     index < module->function_count; ++index) {
		const struct pqcp_fleet_policy_function *function =
			&module->functions[index];

		if (function->first_instruction != next_instruction ||
		    function->instruction_count == 0U ||
		    function->first_instruction >
			    module->instruction_count ||
		    function->instruction_count >
			    module->instruction_count -
				    function->first_instruction ||
		    function->parameter_count > function->local_count ||
		    function->local_count >
			    module->bounds.max_local_values ||
		    function->result_count > 1U ||
		    function->reserved != 0U ||
		    (function->flags &
		     ~PQCP_FLEET_POLICY_FUNCTION_ENTRY) != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
		}
		if ((function->flags &
		     PQCP_FLEET_POLICY_FUNCTION_ENTRY) != 0U) {
			entry_count++;
			if (index != module->entry_function ||
			    function->parameter_count != 0U ||
			    function->result_count != 0U) {
				return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
			}
		}
		next_instruction += function->instruction_count;
	}
	if (entry_count != 1U ||
	    next_instruction != module->instruction_count) {
		return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
	}
	return PQCP_FLEET_POLICY_OK;
}

static void result_reset(
	struct pqcp_fleet_policy_execution_result *result)
{
	struct pqcp_fleet_policy_action *actions = result->actions;
	const size_t action_capacity = result->action_capacity;

	memset(result, 0, sizeof(*result));
	result->actions = actions;
	result->action_capacity = action_capacity;
	result->fault_instruction = UINT32_MAX;
	result->decision.outcome = PQCP_FLEET_POLICY_DECISION_DENY;
	result->decision.reason_code =
		PQCP_FLEET_POLICY_REASON_VM_FAULT;
}

static int fail_closed(
	struct vm_state *state,
	int status,
	uint32_t fault_instruction)
{
	state->result->status = status;
	state->result->fault_instruction = fault_instruction;
	state->result->action_count = 0U;
	state->result->decision.outcome =
		PQCP_FLEET_POLICY_DECISION_DENY;
	state->result->decision.reason_code =
		PQCP_FLEET_POLICY_REASON_VM_FAULT;
	state->result->decision.policy_code =
		status < 0 ? (uint32_t)(-status) : (uint32_t)status;
	state->result->decision.flags = 0U;
	return status;
}

static int state_validate(
	const struct pqcp_fleet_policy_module *module,
	const struct pqcp_fleet_policy_execution_context *context,
	struct pqcp_fleet_policy_vm_workspace *workspace,
	struct pqcp_fleet_policy_execution_result *result)
{
	int ret = module_validate(module);

	if (ret != PQCP_FLEET_POLICY_OK) {
		return ret;
	}
	if (context == NULL || workspace == NULL || result == NULL ||
	    context->flags != 0U ||
	    workspace->stack == NULL ||
	    workspace->stack_capacity <
		    module->bounds.max_stack_values ||
	    workspace->frames == NULL ||
	    workspace->frame_capacity <
		    module->bounds.max_call_frames ||
	    (module->bounds.max_local_values != 0U &&
	     workspace->locals == NULL) ||
	    workspace->local_capacity <
		    module->bounds.max_local_values ||
	    result->action_capacity <
		    module->bounds.max_actions ||
	    (result->action_capacity != 0U &&
	     result->actions == NULL) ||
	    (context->claims != NULL &&
	     context->claims->load == NULL) ||
	    (context->builtins != NULL &&
	     context->builtins->descriptors == NULL &&
	     context->builtins->descriptor_count != 0U)) {
		return PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT;
	}
	return PQCP_FLEET_POLICY_OK;
}

static int push(
	struct vm_state *state,
	const struct pqcp_fleet_policy_value *value)
{
	if (state->stack_size >=
		    state->module->bounds.max_stack_values ||
	    state->stack_size >=
		    state->workspace->stack_capacity) {
		return PQCP_FLEET_POLICY_ERR_STACK;
	}
	state->workspace->stack[state->stack_size++] = *value;
	if (state->stack_size >
	    state->result->maximum_stack_depth) {
		state->result->maximum_stack_depth =
			(uint32_t)state->stack_size;
	}
	return PQCP_FLEET_POLICY_OK;
}

static int pop(
	struct vm_state *state,
	struct pqcp_fleet_policy_value *value)
{
	const struct pqcp_fleet_policy_vm_frame *frame =
		&state->workspace->frames[state->frame_count - 1U];

	if (state->stack_size <= frame->stack_base) {
		return PQCP_FLEET_POLICY_ERR_STACK;
	}
	state->stack_size--;
	if (value != NULL) {
		*value = state->workspace->stack[state->stack_size];
	}
	return PQCP_FLEET_POLICY_OK;
}

static int require_stack(
	const struct vm_state *state,
	size_t count)
{
	const struct pqcp_fleet_policy_vm_frame *frame =
		&state->workspace->frames[state->frame_count - 1U];

	if (state->stack_size < frame->stack_base ||
	    state->stack_size - frame->stack_base < count) {
		return PQCP_FLEET_POLICY_ERR_STACK;
	}
	return PQCP_FLEET_POLICY_OK;
}

static int bytes_compare(
	const struct pqcp_fleet_policy_bytes *left,
	const struct pqcp_fleet_policy_bytes *right)
{
	const uint32_t common =
		left->length < right->length ?
			left->length : right->length;
	int compared = 0;

	if (common != 0U) {
		compared = memcmp(left->data, right->data, common);
	}
	if (compared < 0) {
		return -1;
	}
	if (compared > 0) {
		return 1;
	}
	if (left->length < right->length) {
		return -1;
	}
	if (left->length > right->length) {
		return 1;
	}
	return 0;
}

static int value_compare(
	const struct pqcp_fleet_policy_value *left,
	const struct pqcp_fleet_policy_value *right,
	int *comparison)
{
	if (left->type != right->type || comparison == NULL) {
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
	switch (left->type) {
	case PQCP_FLEET_POLICY_VALUE_I64:
		*comparison = left->as.i64 < right->as.i64 ? -1 :
			left->as.i64 > right->as.i64 ? 1 : 0;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_VALUE_U64:
		*comparison = left->as.u64 < right->as.u64 ? -1 :
			left->as.u64 > right->as.u64 ? 1 : 0;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_VALUE_BOOL:
		*comparison =
			left->as.boolean == right->as.boolean ? 0 :
			left->as.boolean ? 1 : -1;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_VALUE_BYTES:
	case PQCP_FLEET_POLICY_VALUE_DIGEST:
		*comparison = bytes_compare(
			&left->as.bytes, &right->as.bytes);
		return PQCP_FLEET_POLICY_OK;
	default:
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
}

static int signed_add(int64_t left, int64_t right, int64_t *result)
{
	if ((right > 0 && left > INT64_MAX - right) ||
	    (right < 0 && left < INT64_MIN - right)) {
		return PQCP_FLEET_POLICY_ERR_OVERFLOW;
	}
	*result = left + right;
	return PQCP_FLEET_POLICY_OK;
}

static int signed_subtract(
	int64_t left,
	int64_t right,
	int64_t *result)
{
	if ((right > 0 && left < INT64_MIN + right) ||
	    (right < 0 && left > INT64_MAX + right)) {
		return PQCP_FLEET_POLICY_ERR_OVERFLOW;
	}
	*result = left - right;
	return PQCP_FLEET_POLICY_OK;
}

static int signed_multiply(
	int64_t left,
	int64_t right,
	int64_t *result)
{
	if (left == 0 || right == 0) {
		*result = 0;
		return PQCP_FLEET_POLICY_OK;
	}
	if ((left == -1 && right == INT64_MIN) ||
	    (right == -1 && left == INT64_MIN)) {
		return PQCP_FLEET_POLICY_ERR_OVERFLOW;
	}
	if ((left > 0 && right > 0 &&
	     left > INT64_MAX / right) ||
	    (left > 0 && right < 0 &&
	     right < INT64_MIN / left) ||
	    (left < 0 && right > 0 &&
	     left < INT64_MIN / right) ||
	    (left < 0 && right < 0 &&
	     left < INT64_MAX / right)) {
		return PQCP_FLEET_POLICY_ERR_OVERFLOW;
	}
	*result = left * right;
	return PQCP_FLEET_POLICY_OK;
}

static int arithmetic(
	uint8_t opcode,
	const struct pqcp_fleet_policy_value *left,
	const struct pqcp_fleet_policy_value *right,
	struct pqcp_fleet_policy_value *result)
{
	int ret;

	if (left->type != right->type ||
	    (left->type != PQCP_FLEET_POLICY_VALUE_I64 &&
	     left->type != PQCP_FLEET_POLICY_VALUE_U64)) {
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
	memset(result, 0, sizeof(*result));
	result->type = left->type;
	if (left->type == PQCP_FLEET_POLICY_VALUE_I64) {
		switch (opcode) {
		case PQCP_FLEET_POLICY_OP_ADD:
			return signed_add(
				left->as.i64, right->as.i64,
				&result->as.i64);
		case PQCP_FLEET_POLICY_OP_SUB:
			return signed_subtract(
				left->as.i64, right->as.i64,
				&result->as.i64);
		case PQCP_FLEET_POLICY_OP_MUL:
			return signed_multiply(
				left->as.i64, right->as.i64,
				&result->as.i64);
		case PQCP_FLEET_POLICY_OP_DIV:
			if (right->as.i64 == 0) {
				return PQCP_FLEET_POLICY_ERR_DIVIDE_BY_ZERO;
			}
			if (left->as.i64 == INT64_MIN &&
			    right->as.i64 == -1) {
				return PQCP_FLEET_POLICY_ERR_OVERFLOW;
			}
			result->as.i64 =
				left->as.i64 / right->as.i64;
			return PQCP_FLEET_POLICY_OK;
		case PQCP_FLEET_POLICY_OP_MOD:
			if (right->as.i64 == 0) {
				return PQCP_FLEET_POLICY_ERR_DIVIDE_BY_ZERO;
			}
			if (left->as.i64 == INT64_MIN &&
			    right->as.i64 == -1) {
				result->as.i64 = 0;
			} else {
				result->as.i64 =
					left->as.i64 % right->as.i64;
			}
			return PQCP_FLEET_POLICY_OK;
		default:
			return PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
		}
	}
	switch (opcode) {
	case PQCP_FLEET_POLICY_OP_ADD:
		if (left->as.u64 > UINT64_MAX - right->as.u64) {
			return PQCP_FLEET_POLICY_ERR_OVERFLOW;
		}
		result->as.u64 = left->as.u64 + right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_OP_SUB:
		if (left->as.u64 < right->as.u64) {
			return PQCP_FLEET_POLICY_ERR_OVERFLOW;
		}
		result->as.u64 = left->as.u64 - right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_OP_MUL:
		if (right->as.u64 != 0U &&
		    left->as.u64 > UINT64_MAX / right->as.u64) {
			return PQCP_FLEET_POLICY_ERR_OVERFLOW;
		}
		result->as.u64 = left->as.u64 * right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_OP_DIV:
		if (right->as.u64 == 0U) {
			return PQCP_FLEET_POLICY_ERR_DIVIDE_BY_ZERO;
		}
		result->as.u64 = left->as.u64 / right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_OP_MOD:
		if (right->as.u64 == 0U) {
			return PQCP_FLEET_POLICY_ERR_DIVIDE_BY_ZERO;
		}
		result->as.u64 = left->as.u64 % right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	default:
		ret = PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
		break;
	}
	return ret;
}

static int bit_operation(
	uint8_t opcode,
	const struct pqcp_fleet_policy_value *left,
	const struct pqcp_fleet_policy_value *right,
	struct pqcp_fleet_policy_value *result)
{
	if (left->type != PQCP_FLEET_POLICY_VALUE_U64 ||
	    (right != NULL &&
	     right->type != PQCP_FLEET_POLICY_VALUE_U64)) {
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
	memset(result, 0, sizeof(*result));
	result->type = PQCP_FLEET_POLICY_VALUE_U64;
	switch (opcode) {
	case PQCP_FLEET_POLICY_OP_BIT_AND:
		result->as.u64 = left->as.u64 & right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_OP_BIT_OR:
		result->as.u64 = left->as.u64 | right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_OP_BIT_XOR:
		result->as.u64 = left->as.u64 ^ right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_OP_BIT_NOT:
		result->as.u64 = ~left->as.u64;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_OP_SHIFT_LEFT:
		if (right->as.u64 >= 64U ||
		    (right->as.u64 != 0U &&
		     left->as.u64 >
			     (UINT64_MAX >> right->as.u64))) {
			return PQCP_FLEET_POLICY_ERR_OVERFLOW;
		}
		result->as.u64 =
			left->as.u64 << right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_OP_SHIFT_RIGHT:
		if (right->as.u64 >= 64U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		result->as.u64 =
			left->as.u64 >> right->as.u64;
		return PQCP_FLEET_POLICY_OK;
	default:
		return PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
	}
}

static int execute_binary(
	struct vm_state *state,
	uint8_t opcode)
{
	struct pqcp_fleet_policy_value left;
	struct pqcp_fleet_policy_value right;
	struct pqcp_fleet_policy_value result;
	int comparison;
	int ret;

	ret = pop(state, &right);
	if (ret == PQCP_FLEET_POLICY_OK) {
		ret = pop(state, &left);
	}
	if (ret != PQCP_FLEET_POLICY_OK) {
		return ret;
	}
	switch (opcode) {
	case PQCP_FLEET_POLICY_OP_ADD:
	case PQCP_FLEET_POLICY_OP_SUB:
	case PQCP_FLEET_POLICY_OP_MUL:
	case PQCP_FLEET_POLICY_OP_DIV:
	case PQCP_FLEET_POLICY_OP_MOD:
		ret = arithmetic(opcode, &left, &right, &result);
		break;
	case PQCP_FLEET_POLICY_OP_BIT_AND:
	case PQCP_FLEET_POLICY_OP_BIT_OR:
	case PQCP_FLEET_POLICY_OP_BIT_XOR:
	case PQCP_FLEET_POLICY_OP_SHIFT_LEFT:
	case PQCP_FLEET_POLICY_OP_SHIFT_RIGHT:
		ret = bit_operation(
			opcode, &left, &right, &result);
		break;
	case PQCP_FLEET_POLICY_OP_EQUAL:
	case PQCP_FLEET_POLICY_OP_NOT_EQUAL:
	case PQCP_FLEET_POLICY_OP_LESS:
	case PQCP_FLEET_POLICY_OP_LESS_EQUAL:
	case PQCP_FLEET_POLICY_OP_GREATER:
	case PQCP_FLEET_POLICY_OP_GREATER_EQUAL:
		ret = value_compare(&left, &right, &comparison);
		if (ret == PQCP_FLEET_POLICY_OK) {
			memset(&result, 0, sizeof(result));
			result.type = PQCP_FLEET_POLICY_VALUE_BOOL;
			switch (opcode) {
			case PQCP_FLEET_POLICY_OP_EQUAL:
				result.as.boolean = comparison == 0;
				break;
			case PQCP_FLEET_POLICY_OP_NOT_EQUAL:
				result.as.boolean = comparison != 0;
				break;
			case PQCP_FLEET_POLICY_OP_LESS:
				result.as.boolean = comparison < 0;
				break;
			case PQCP_FLEET_POLICY_OP_LESS_EQUAL:
				result.as.boolean = comparison <= 0;
				break;
			case PQCP_FLEET_POLICY_OP_GREATER:
				result.as.boolean = comparison > 0;
				break;
			default:
				result.as.boolean = comparison >= 0;
				break;
			}
		}
		break;
	case PQCP_FLEET_POLICY_OP_BOOL_AND:
	case PQCP_FLEET_POLICY_OP_BOOL_OR:
		if (left.type != PQCP_FLEET_POLICY_VALUE_BOOL ||
		    right.type != PQCP_FLEET_POLICY_VALUE_BOOL) {
			ret = PQCP_FLEET_POLICY_ERR_TYPE;
			break;
		}
		memset(&result, 0, sizeof(result));
		result.type = PQCP_FLEET_POLICY_VALUE_BOOL;
		result.as.boolean =
			opcode == PQCP_FLEET_POLICY_OP_BOOL_AND ?
				left.as.boolean && right.as.boolean :
				left.as.boolean || right.as.boolean;
		ret = PQCP_FLEET_POLICY_OK;
		break;
	default:
		ret = PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
		break;
	}
	if (ret != PQCP_FLEET_POLICY_OK) {
		return ret;
	}
	return push(state, &result);
}

static int execute_unary(
	struct vm_state *state,
	uint8_t opcode)
{
	struct pqcp_fleet_policy_value input;
	struct pqcp_fleet_policy_value result;
	int ret = pop(state, &input);

	if (ret != PQCP_FLEET_POLICY_OK) {
		return ret;
	}
	memset(&result, 0, sizeof(result));
	switch (opcode) {
	case PQCP_FLEET_POLICY_OP_NEG:
		if (input.type != PQCP_FLEET_POLICY_VALUE_I64) {
			return PQCP_FLEET_POLICY_ERR_TYPE;
		}
		if (input.as.i64 == INT64_MIN) {
			return PQCP_FLEET_POLICY_ERR_OVERFLOW;
		}
		result.type = PQCP_FLEET_POLICY_VALUE_I64;
		result.as.i64 = -input.as.i64;
		break;
	case PQCP_FLEET_POLICY_OP_BIT_NOT:
		ret = bit_operation(opcode, &input, NULL, &result);
		if (ret != PQCP_FLEET_POLICY_OK) {
			return ret;
		}
		break;
	case PQCP_FLEET_POLICY_OP_BOOL_NOT:
		if (input.type != PQCP_FLEET_POLICY_VALUE_BOOL) {
			return PQCP_FLEET_POLICY_ERR_TYPE;
		}
		result.type = PQCP_FLEET_POLICY_VALUE_BOOL;
		result.as.boolean = !input.as.boolean;
		break;
	default:
		return PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
	}
	return push(state, &result);
}

static int execute_select(struct vm_state *state)
{
	struct pqcp_fleet_policy_value condition;
	struct pqcp_fleet_policy_value when_true;
	struct pqcp_fleet_policy_value when_false;
	int ret = pop(state, &condition);

	if (ret == PQCP_FLEET_POLICY_OK) {
		ret = pop(state, &when_true);
	}
	if (ret == PQCP_FLEET_POLICY_OK) {
		ret = pop(state, &when_false);
	}
	if (ret != PQCP_FLEET_POLICY_OK) {
		return ret;
	}
	if (condition.type != PQCP_FLEET_POLICY_VALUE_BOOL ||
	    when_true.type != when_false.type) {
		return PQCP_FLEET_POLICY_ERR_TYPE;
	}
	return push(state, condition.as.boolean ?
		    &when_true : &when_false);
}

static bool function_contains(
	const struct pqcp_fleet_policy_function *function,
	uint32_t instruction)
{
	return instruction >= function->first_instruction &&
	       instruction - function->first_instruction <
		       function->instruction_count;
}

static int execute_call(
	struct vm_state *state,
	uint32_t callee_index)
{
	const struct pqcp_fleet_policy_function *callee;
	struct pqcp_fleet_policy_vm_frame *frame;
	size_t argument_base;
	size_t local_base;

	if (callee_index >= state->module->function_count ||
	    callee_index == state->module->entry_function) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	callee = &state->module->functions[callee_index];
	if (require_stack(state, callee->parameter_count) !=
	    PQCP_FLEET_POLICY_OK) {
		return PQCP_FLEET_POLICY_ERR_STACK;
	}
	if (state->frame_count >=
		    state->module->bounds.max_call_frames ||
	    state->frame_count >=
		    state->workspace->frame_capacity) {
		return PQCP_FLEET_POLICY_ERR_CALL_DEPTH;
	}
	if (callee->local_count >
		    state->workspace->local_capacity -
			    state->local_size ||
	    callee->local_count >
		    state->module->bounds.max_local_values -
			    state->local_size) {
		return PQCP_FLEET_POLICY_ERR_CALL_DEPTH;
	}
	argument_base =
		state->stack_size - callee->parameter_count;
	local_base = state->local_size;
	for (uint32_t index = 0U;
	     index < callee->parameter_count; ++index) {
		state->workspace->locals[local_base + index] =
			state->workspace->stack[
				argument_base + index];
	}
	for (uint32_t index = callee->parameter_count;
	     index < callee->local_count; ++index) {
		memset(&state->workspace->locals[
			       local_base + index],
		       0,
		       sizeof(state->workspace->locals[0]));
	}
	state->stack_size = argument_base;
	state->local_size += callee->local_count;
	frame = &state->workspace->frames[state->frame_count++];
	frame->function_index = callee_index;
	frame->return_instruction = state->pc + 1U;
	frame->stack_base = (uint32_t)argument_base;
	frame->local_base = (uint32_t)local_base;
	state->function_index = callee_index;
	state->pc = callee->first_instruction;
	if (state->frame_count >
	    state->result->maximum_call_depth) {
		state->result->maximum_call_depth =
			(uint32_t)state->frame_count;
	}
	return PQCP_FLEET_POLICY_OK;
}

static int execute_return(struct vm_state *state)
{
	const struct pqcp_fleet_policy_function *function =
		&state->module->functions[state->function_index];
	const struct pqcp_fleet_policy_vm_frame frame =
		state->workspace->frames[state->frame_count - 1U];
	struct pqcp_fleet_policy_value returned;
	const bool has_result = function->result_count != 0U;

	if (state->frame_count <= 1U ||
	    state->stack_size !=
		    (size_t)frame.stack_base +
			    function->result_count) {
		return PQCP_FLEET_POLICY_ERR_STACK;
	}
	if (has_result) {
		returned =
			state->workspace->stack[state->stack_size - 1U];
	}
	state->stack_size = frame.stack_base;
	state->local_size = frame.local_base;
	state->frame_count--;
	state->function_index =
		state->workspace->frames[
			state->frame_count - 1U].function_index;
	state->pc = frame.return_instruction;
	if (has_result) {
		return push(state, &returned);
	}
	return PQCP_FLEET_POLICY_OK;
}

static int execute_builtin(
	struct vm_state *state,
	const struct pqcp_fleet_policy_instruction *instruction)
{
	const struct pqcp_fleet_policy_builtin_descriptor *descriptor;
	struct pqcp_fleet_policy_builtin_context builtin_context;
	struct pqcp_fleet_policy_value returned;
	const size_t argument_count = instruction->b;
	size_t argument_base;
	int ret;

	if (instruction->b >
		    PQCP_FLEET_POLICY_MAX_BUILTIN_ARGS ||
	    (instruction->a !=
		     PQCP_FLEET_POLICY_VALUE_INVALID &&
	     !value_type_valid(instruction->a)) ||
	    require_stack(state, argument_count) !=
		    PQCP_FLEET_POLICY_OK ||
	    state->context->builtins == NULL) {
		return PQCP_FLEET_POLICY_ERR_BUILTIN;
	}
	argument_base = state->stack_size - argument_count;
	descriptor = builtin_find(
		state->context->builtins,
		instruction->immediate);
	if (descriptor == NULL ||
	    !builtin_descriptor_valid(descriptor) ||
	    descriptor->argument_count != instruction->b ||
	    descriptor->result_type != instruction->a) {
		return PQCP_FLEET_POLICY_ERR_BUILTIN;
	}
	for (uint32_t index = 0U;
	     index < descriptor->argument_count; ++index) {
		if (state->workspace->stack[
			    argument_base + index].type !=
		    descriptor->argument_types[index]) {
			return PQCP_FLEET_POLICY_ERR_TYPE;
		}
	}
	memset(&returned, 0, sizeof(returned));
	memset(&builtin_context, 0, sizeof(builtin_context));
	builtin_context.module = state->module;
	builtin_context.claims = state->context->claims;
	builtin_context.registry_context =
		state->context->builtins->context;
	builtin_context.application_context =
		state->context->application_context;
	builtin_context.instruction_count =
		state->result->instructions_executed;
	builtin_context.call_depth =
		(uint32_t)state->frame_count;
	if (state->context->builtin_state != NULL) {
		state->context->builtin_state->invocation_count++;
		state->context->builtin_state->last_builtin_id =
			instruction->immediate;
	}
	ret = descriptor->invoke(
		&builtin_context,
		state->context->builtin_state,
		&state->workspace->stack[argument_base],
		instruction->b, &returned);
	if (state->context->builtin_state != NULL) {
		state->context->builtin_state->last_status = ret;
		if (ret != PQCP_FLEET_POLICY_OK) {
			state->context->builtin_state->failure_count++;
		}
	}
	if (ret != PQCP_FLEET_POLICY_OK) {
		return PQCP_FLEET_POLICY_ERR_BUILTIN;
	}
	if (instruction->a !=
	    PQCP_FLEET_POLICY_VALUE_INVALID) {
		if (pqcp_fleet_policy_value_validate(&returned) !=
			    PQCP_FLEET_POLICY_OK ||
		    returned.type != instruction->a) {
			return PQCP_FLEET_POLICY_ERR_TYPE;
		}
	}
	state->stack_size = argument_base;
	if (instruction->a !=
	    PQCP_FLEET_POLICY_VALUE_INVALID) {
		return push(state, &returned);
	}
	return PQCP_FLEET_POLICY_OK;
}

static int emit_action(
	struct vm_state *state,
	const struct pqcp_fleet_policy_instruction *instruction)
{
	struct pqcp_fleet_policy_action *action;
	const size_t argument_count = instruction->b;
	size_t argument_base;

	if (instruction->immediate == 0U ||
	    instruction->b >
		    PQCP_FLEET_POLICY_MAX_ACTION_ARGS ||
	    instruction->b >
		    state->module->bounds.max_action_arguments ||
	    require_stack(state, argument_count) !=
		    PQCP_FLEET_POLICY_OK) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	if (state->result->action_count >=
		    state->module->bounds.max_actions ||
	    state->result->action_count >=
		    state->result->action_capacity) {
		return PQCP_FLEET_POLICY_ERR_ACTION_LIMIT;
	}
	argument_base = state->stack_size - argument_count;
	action = &state->result->actions[
		state->result->action_count];
	memset(action, 0, sizeof(*action));
	action->action_id = instruction->immediate;
	action->flags = instruction->a;
	action->argument_count = instruction->b;
	for (uint32_t index = 0U;
	     index < instruction->b; ++index) {
		action->arguments[index] =
			state->workspace->stack[
				argument_base + index];
	}
	state->stack_size = argument_base;
	state->result->action_count++;
	return PQCP_FLEET_POLICY_OK;
}

static int load_local(
	struct vm_state *state,
	uint32_t local_index)
{
	const struct pqcp_fleet_policy_function *function =
		&state->module->functions[state->function_index];
	const struct pqcp_fleet_policy_vm_frame *frame =
		&state->workspace->frames[state->frame_count - 1U];
	const struct pqcp_fleet_policy_value *value;

	if (local_index >= function->local_count) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	value = &state->workspace->locals[
		frame->local_base + local_index];
	if (pqcp_fleet_policy_value_validate(value) !=
	    PQCP_FLEET_POLICY_OK) {
		return PQCP_FLEET_POLICY_ERR_STATE;
	}
	return push(state, value);
}

static int store_local(
	struct vm_state *state,
	uint32_t local_index)
{
	const struct pqcp_fleet_policy_function *function =
		&state->module->functions[state->function_index];
	const struct pqcp_fleet_policy_vm_frame *frame =
		&state->workspace->frames[state->frame_count - 1U];
	struct pqcp_fleet_policy_value value;
	int ret;

	if (local_index < function->parameter_count ||
	    local_index >= function->local_count) {
		return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
	}
	ret = pop(state, &value);
	if (ret == PQCP_FLEET_POLICY_OK) {
		state->workspace->locals[
			frame->local_base + local_index] = value;
	}
	return ret;
}

static int execute_instruction(
	struct vm_state *state,
	bool *halted)
{
	const struct pqcp_fleet_policy_instruction *instruction =
		&state->module->instructions[state->pc];
	const struct pqcp_fleet_policy_function *function =
		&state->module->functions[state->function_index];
	struct pqcp_fleet_policy_value value;
	int ret = PQCP_FLEET_POLICY_OK;
	bool advance = true;

	*halted = false;
	switch (instruction->opcode) {
	case PQCP_FLEET_POLICY_OP_NOP:
		break;
	case PQCP_FLEET_POLICY_OP_PUSH_CONST:
		if (instruction->immediate >=
		    state->module->constant_count) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		ret = push(state, &state->module->constants[
				   instruction->immediate]);
		break;
	case PQCP_FLEET_POLICY_OP_PUSH_I32:
		memset(&value, 0, sizeof(value));
		value.type = PQCP_FLEET_POLICY_VALUE_I64;
		value.as.i64 = (int32_t)instruction->immediate;
		ret = push(state, &value);
		break;
	case PQCP_FLEET_POLICY_OP_PUSH_U32:
		memset(&value, 0, sizeof(value));
		value.type = PQCP_FLEET_POLICY_VALUE_U64;
		value.as.u64 = instruction->immediate;
		ret = push(state, &value);
		break;
	case PQCP_FLEET_POLICY_OP_PUSH_FALSE:
	case PQCP_FLEET_POLICY_OP_PUSH_TRUE:
		memset(&value, 0, sizeof(value));
		value.type = PQCP_FLEET_POLICY_VALUE_BOOL;
		value.as.boolean =
			instruction->opcode ==
			PQCP_FLEET_POLICY_OP_PUSH_TRUE;
		ret = push(state, &value);
		break;
	case PQCP_FLEET_POLICY_OP_POP:
		ret = pop(state, NULL);
		break;
	case PQCP_FLEET_POLICY_OP_DUP:
		ret = require_stack(state, 1U);
		if (ret == PQCP_FLEET_POLICY_OK) {
			value = state->workspace->stack[
				state->stack_size - 1U];
			ret = push(state, &value);
		}
		break;
	case PQCP_FLEET_POLICY_OP_SWAP:
		ret = require_stack(state, 2U);
		if (ret == PQCP_FLEET_POLICY_OK) {
			value = state->workspace->stack[
				state->stack_size - 1U];
			state->workspace->stack[
				state->stack_size - 1U] =
				state->workspace->stack[
					state->stack_size - 2U];
			state->workspace->stack[
				state->stack_size - 2U] = value;
		}
		break;
	case PQCP_FLEET_POLICY_OP_LOAD_CLAIM:
		if (state->context->claims == NULL) {
			ret = PQCP_FLEET_POLICY_ERR_CLAIM;
			break;
		}
		memset(&value, 0, sizeof(value));
		ret = state->context->claims->load(
			state->context->claims->context,
			instruction->immediate, &value);
		if (ret != PQCP_FLEET_POLICY_OK ||
		    pqcp_fleet_policy_value_validate(&value) !=
			    PQCP_FLEET_POLICY_OK) {
			ret = PQCP_FLEET_POLICY_ERR_CLAIM;
		} else {
			ret = push(state, &value);
		}
		break;
	case PQCP_FLEET_POLICY_OP_LOAD_LOCAL:
		ret = load_local(state, instruction->immediate);
		break;
	case PQCP_FLEET_POLICY_OP_STORE_LOCAL:
		ret = store_local(state, instruction->immediate);
		break;
	case PQCP_FLEET_POLICY_OP_ADD:
	case PQCP_FLEET_POLICY_OP_SUB:
	case PQCP_FLEET_POLICY_OP_MUL:
	case PQCP_FLEET_POLICY_OP_DIV:
	case PQCP_FLEET_POLICY_OP_MOD:
	case PQCP_FLEET_POLICY_OP_BIT_AND:
	case PQCP_FLEET_POLICY_OP_BIT_OR:
	case PQCP_FLEET_POLICY_OP_BIT_XOR:
	case PQCP_FLEET_POLICY_OP_SHIFT_LEFT:
	case PQCP_FLEET_POLICY_OP_SHIFT_RIGHT:
	case PQCP_FLEET_POLICY_OP_EQUAL:
	case PQCP_FLEET_POLICY_OP_NOT_EQUAL:
	case PQCP_FLEET_POLICY_OP_LESS:
	case PQCP_FLEET_POLICY_OP_LESS_EQUAL:
	case PQCP_FLEET_POLICY_OP_GREATER:
	case PQCP_FLEET_POLICY_OP_GREATER_EQUAL:
	case PQCP_FLEET_POLICY_OP_BOOL_AND:
	case PQCP_FLEET_POLICY_OP_BOOL_OR:
		ret = execute_binary(state, instruction->opcode);
		break;
	case PQCP_FLEET_POLICY_OP_NEG:
	case PQCP_FLEET_POLICY_OP_BIT_NOT:
	case PQCP_FLEET_POLICY_OP_BOOL_NOT:
		ret = execute_unary(state, instruction->opcode);
		break;
	case PQCP_FLEET_POLICY_OP_SELECT:
		ret = execute_select(state);
		break;
	case PQCP_FLEET_POLICY_OP_JUMP:
		if (!function_contains(
			    function, instruction->immediate)) {
			ret = PQCP_FLEET_POLICY_ERR_CONTROL_FLOW;
		} else {
			state->pc = instruction->immediate;
			advance = false;
		}
		break;
	case PQCP_FLEET_POLICY_OP_JUMP_IF_TRUE:
	case PQCP_FLEET_POLICY_OP_JUMP_IF_FALSE:
		ret = pop(state, &value);
		if (ret != PQCP_FLEET_POLICY_OK) {
			break;
		}
		if (value.type != PQCP_FLEET_POLICY_VALUE_BOOL) {
			ret = PQCP_FLEET_POLICY_ERR_TYPE;
			break;
		}
		if (value.as.boolean ==
		    (instruction->opcode ==
		     PQCP_FLEET_POLICY_OP_JUMP_IF_TRUE)) {
			if (!function_contains(
				    function,
				    instruction->immediate)) {
				ret =
					PQCP_FLEET_POLICY_ERR_CONTROL_FLOW;
			} else {
				state->pc = instruction->immediate;
				advance = false;
			}
		}
		break;
	case PQCP_FLEET_POLICY_OP_CALL:
		ret = execute_call(state, instruction->immediate);
		advance = false;
		break;
	case PQCP_FLEET_POLICY_OP_RETURN:
		ret = execute_return(state);
		advance = false;
		break;
	case PQCP_FLEET_POLICY_OP_CALL_BUILTIN:
		ret = execute_builtin(state, instruction);
		break;
	case PQCP_FLEET_POLICY_OP_EMIT_DECISION:
		if (state->function_index !=
			    state->module->entry_function ||
		    state->decision_emitted ||
		    instruction->a >
			    PQCP_FLEET_POLICY_DECISION_DEFER) {
			ret =
				PQCP_FLEET_POLICY_ERR_CONTROL_FLOW;
			break;
		}
		state->result->decision.outcome = instruction->a;
		state->result->decision.reason_code =
			instruction->immediate;
		state->result->decision.policy_code =
			instruction->b;
		state->result->decision.flags = 0U;
		state->decision_emitted = true;
		break;
	case PQCP_FLEET_POLICY_OP_EMIT_ACTION:
		ret = emit_action(state, instruction);
		break;
	case PQCP_FLEET_POLICY_OP_HALT:
		if (state->frame_count != 1U ||
		    state->function_index !=
			    state->module->entry_function ||
		    state->stack_size != 0U ||
		    !state->decision_emitted) {
			ret = PQCP_FLEET_POLICY_ERR_NO_DECISION;
		} else {
			*halted = true;
			advance = false;
		}
		break;
	default:
		ret = PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
		break;
	}
	if (ret == PQCP_FLEET_POLICY_OK && advance) {
		state->pc++;
	}
	return ret;
}

int pqcp_fleet_policy_vm_execute(
	const struct pqcp_fleet_policy_module *module,
	const struct pqcp_fleet_policy_execution_context *context,
	struct pqcp_fleet_policy_vm_workspace *workspace,
	struct pqcp_fleet_policy_execution_result *result)
{
	struct vm_state state;
	const struct pqcp_fleet_policy_function *entry;
	int ret;

	if (result == NULL) {
		return PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT;
	}
	result_reset(result);
	memset(&state, 0, sizeof(state));
	state.module = module;
	state.context = context;
	state.workspace = workspace;
	state.result = result;
	ret = state_validate(module, context, workspace, result);
	if (ret != PQCP_FLEET_POLICY_OK) {
		return fail_closed(&state, ret, UINT32_MAX);
	}
	entry = &module->functions[module->entry_function];
	state.instruction_budget =
		context->instruction_limit == 0U ||
		context->instruction_limit >
			module->bounds.instruction_budget ?
			module->bounds.instruction_budget :
			context->instruction_limit;
	state.function_index = module->entry_function;
	state.pc = entry->first_instruction;
	state.local_size = entry->local_count;
	state.frame_count = 1U;
	for (uint32_t index = 0U;
	     index < entry->local_count; ++index) {
		memset(&workspace->locals[index], 0,
		       sizeof(workspace->locals[index]));
	}
	workspace->frames[0].function_index =
		module->entry_function;
	workspace->frames[0].return_instruction = UINT32_MAX;
	workspace->frames[0].stack_base = 0U;
	workspace->frames[0].local_base = 0U;
	result->maximum_call_depth = 1U;

	for (;;) {
		const struct pqcp_fleet_policy_function *function =
			&module->functions[state.function_index];
		const uint32_t instruction = state.pc;
		bool halted = false;

		if (!function_contains(function, state.pc)) {
			return fail_closed(
				&state,
				PQCP_FLEET_POLICY_ERR_CONTROL_FLOW,
				state.pc);
		}
		if (result->instructions_executed >=
		    state.instruction_budget) {
			return fail_closed(
				&state,
				PQCP_FLEET_POLICY_ERR_BUDGET,
				state.pc);
		}
		result->instructions_executed++;
		ret = execute_instruction(&state, &halted);
		if (ret != PQCP_FLEET_POLICY_OK) {
			return fail_closed(&state, ret, instruction);
		}
		if (halted) {
			result->status = PQCP_FLEET_POLICY_OK;
			result->fault_instruction = UINT32_MAX;
			return PQCP_FLEET_POLICY_OK;
		}
	}
}
