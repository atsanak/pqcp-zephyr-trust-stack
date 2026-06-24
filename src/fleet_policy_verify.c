/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Structural verifier for the portable fleet policy bytecode VM.
 */

#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_policy_vm.h>

#define PATH_WITHOUT_DECISION 0x01U
#define PATH_WITH_DECISION 0x02U
#define PATH_QUEUED 0x80U
#define FUNCTION_UNSEEN 0U
#define FUNCTION_VISITING 1U
#define FUNCTION_COMPLETE 2U

struct instruction_effect {
	uint32_t pops;
	uint32_t pushes;
	bool terminal;
	bool branch;
	bool conditional;
};

static int fail(
	struct pqcp_fleet_policy_verify_report *report,
	int status,
	uint32_t function_index,
	uint32_t instruction_index)
{
	report->status = status;
	report->fault_function = function_index;
	report->fault_instruction = instruction_index;
	return status;
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

static bool value_type_valid(uint32_t type)
{
	return type >= PQCP_FLEET_POLICY_VALUE_I64 &&
	       type <= PQCP_FLEET_POLICY_VALUE_DIGEST;
}

static bool result_type_valid(uint32_t type)
{
	return type == PQCP_FLEET_POLICY_VALUE_INVALID ||
	       value_type_valid(type);
}

static bool function_contains(
	const struct pqcp_fleet_policy_function *function,
	uint32_t instruction)
{
	return instruction >= function->first_instruction &&
	       instruction - function->first_instruction <
		       function->instruction_count;
}

static int validate_module_shape(
	const struct pqcp_fleet_policy_module *module,
	struct pqcp_fleet_policy_verify_workspace *workspace,
	struct pqcp_fleet_policy_verify_report *report)
{
	uint32_t next_instruction = 0U;
	uint32_t entry_flags = 0U;

	if (module == NULL || workspace == NULL || report == NULL) {
		return PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT;
	}
	if (module->abi_version != PQCP_FLEET_POLICY_ABI_VERSION ||
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
		return fail(report, PQCP_FLEET_POLICY_ERR_BAD_MODULE,
			    UINT32_MAX, UINT32_MAX);
	}
	if (workspace->stack_depths == NULL ||
	    workspace->path_flags == NULL ||
	    workspace->instruction_queue == NULL ||
	    workspace->instruction_capacity <
		    module->instruction_count ||
	    workspace->function_marks == NULL ||
	    workspace->function_depths == NULL ||
	    workspace->function_stack_peaks == NULL ||
	    workspace->function_local_peaks == NULL ||
	    workspace->function_stack == NULL ||
	    workspace->function_cursors == NULL ||
	    workspace->function_capacity < module->function_count) {
		return fail(report,
			    PQCP_FLEET_POLICY_ERR_VERIFY_WORKSPACE,
			    UINT32_MAX, UINT32_MAX);
	}
	for (uint32_t index = 0U;
	     index < module->constant_count; ++index) {
		if (pqcp_fleet_policy_value_validate(
			    &module->constants[index]) !=
		    PQCP_FLEET_POLICY_OK) {
			return fail(report,
				    PQCP_FLEET_POLICY_ERR_BAD_MODULE,
				    UINT32_MAX, index);
		}
	}
	for (uint32_t index = 0U;
	     index < module->function_count; ++index) {
		const struct pqcp_fleet_policy_function *function =
			&module->functions[index];

		if (function->instruction_count == 0U ||
		    function->first_instruction != next_instruction ||
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
			return fail(report,
				    PQCP_FLEET_POLICY_ERR_BAD_MODULE,
				    index, function->first_instruction);
		}
		if ((function->flags &
		     PQCP_FLEET_POLICY_FUNCTION_ENTRY) != 0U) {
			entry_flags++;
			if (index != module->entry_function ||
			    function->parameter_count != 0U ||
			    function->result_count != 0U) {
				return fail(
					report,
					PQCP_FLEET_POLICY_ERR_BAD_MODULE,
					index,
					function->first_instruction);
			}
		}
		next_instruction += function->instruction_count;
	}
	if (next_instruction != module->instruction_count ||
	    entry_flags != 1U) {
		return fail(report, PQCP_FLEET_POLICY_ERR_BAD_MODULE,
			    UINT32_MAX, next_instruction);
	}
	return PQCP_FLEET_POLICY_OK;
}

static int effect_for_instruction(
	const struct pqcp_fleet_policy_module *module,
	uint32_t function_index,
	uint32_t instruction_index,
	struct instruction_effect *effect)
{
	const struct pqcp_fleet_policy_function *function =
		&module->functions[function_index];
	const struct pqcp_fleet_policy_instruction *instruction =
		&module->instructions[instruction_index];

	memset(effect, 0, sizeof(*effect));
	switch (instruction->opcode) {
	case PQCP_FLEET_POLICY_OP_NOP:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		break;
	case PQCP_FLEET_POLICY_OP_PUSH_CONST:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate >= module->constant_count) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pushes = 1U;
		break;
	case PQCP_FLEET_POLICY_OP_PUSH_I32:
	case PQCP_FLEET_POLICY_OP_PUSH_U32:
		if (instruction->a != 0U || instruction->b != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pushes = 1U;
		break;
	case PQCP_FLEET_POLICY_OP_PUSH_FALSE:
	case PQCP_FLEET_POLICY_OP_PUSH_TRUE:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pushes = 1U;
		break;
	case PQCP_FLEET_POLICY_OP_LOAD_CLAIM:
		if (instruction->a != 0U || instruction->b != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pushes = 1U;
		break;
	case PQCP_FLEET_POLICY_OP_POP:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = 1U;
		break;
	case PQCP_FLEET_POLICY_OP_DUP:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = 1U;
		effect->pushes = 2U;
		break;
	case PQCP_FLEET_POLICY_OP_SWAP:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = 2U;
		effect->pushes = 2U;
		break;
	case PQCP_FLEET_POLICY_OP_LOAD_LOCAL:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate >= function->local_count) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pushes = 1U;
		break;
	case PQCP_FLEET_POLICY_OP_STORE_LOCAL:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate >= function->local_count ||
		    instruction->immediate <
			    function->parameter_count) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = 1U;
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
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = 2U;
		effect->pushes = 1U;
		break;
	case PQCP_FLEET_POLICY_OP_NEG:
	case PQCP_FLEET_POLICY_OP_BIT_NOT:
	case PQCP_FLEET_POLICY_OP_BOOL_NOT:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = 1U;
		effect->pushes = 1U;
		break;
	case PQCP_FLEET_POLICY_OP_SELECT:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = 3U;
		effect->pushes = 1U;
		break;
	case PQCP_FLEET_POLICY_OP_JUMP:
		if (instruction->a != 0U || instruction->b != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->branch = true;
		break;
	case PQCP_FLEET_POLICY_OP_JUMP_IF_TRUE:
	case PQCP_FLEET_POLICY_OP_JUMP_IF_FALSE:
		if (instruction->a != 0U || instruction->b != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = 1U;
		effect->branch = true;
		effect->conditional = true;
		break;
	case PQCP_FLEET_POLICY_OP_CALL:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate >= module->function_count ||
		    instruction->immediate ==
			    module->entry_function) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops =
			module->functions[instruction->immediate].
				parameter_count;
		effect->pushes =
			module->functions[instruction->immediate].
				result_count;
		break;
	case PQCP_FLEET_POLICY_OP_RETURN:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U ||
		    function_index == module->entry_function) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
		}
		effect->pops = function->result_count;
		effect->terminal = true;
		break;
	case PQCP_FLEET_POLICY_OP_CALL_BUILTIN:
		if (instruction->immediate == 0U ||
		    instruction->b >
			    PQCP_FLEET_POLICY_MAX_BUILTIN_ARGS ||
		    !result_type_valid(instruction->a)) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = instruction->b;
		effect->pushes =
			instruction->a ==
				PQCP_FLEET_POLICY_VALUE_INVALID ?
				0U : 1U;
		break;
	case PQCP_FLEET_POLICY_OP_EMIT_DECISION:
		if (function_index != module->entry_function ||
		    instruction->a >
			    PQCP_FLEET_POLICY_DECISION_DEFER) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		break;
	case PQCP_FLEET_POLICY_OP_EMIT_ACTION:
		if (instruction->immediate == 0U ||
		    instruction->b >
			    PQCP_FLEET_POLICY_MAX_ACTION_ARGS ||
		    instruction->b >
			    module->bounds.max_action_arguments) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPERAND;
		}
		effect->pops = instruction->b;
		break;
	case PQCP_FLEET_POLICY_OP_HALT:
		if (instruction->a != 0U || instruction->b != 0U ||
		    instruction->immediate != 0U ||
		    function_index != module->entry_function) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
		}
		effect->terminal = true;
		break;
	default:
		return PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
	}
	return PQCP_FLEET_POLICY_OK;
}

static int enqueue(
	struct pqcp_fleet_policy_verify_workspace *workspace,
	uint32_t instruction,
	size_t *queue_count)
{
	if ((workspace->path_flags[instruction] &
	     PATH_QUEUED) != 0U) {
		return PQCP_FLEET_POLICY_OK;
	}
	if (*queue_count >= workspace->instruction_capacity) {
		return PQCP_FLEET_POLICY_ERR_VERIFY_WORKSPACE;
	}
	workspace->path_flags[instruction] |= PATH_QUEUED;
	workspace->instruction_queue[(*queue_count)++] =
		instruction;
	return PQCP_FLEET_POLICY_OK;
}

static int merge_successor(
	const struct pqcp_fleet_policy_function *function,
	struct pqcp_fleet_policy_verify_workspace *workspace,
	uint32_t successor,
	int32_t depth,
	uint8_t path_state,
	size_t *queue_count)
{
	uint8_t merged;

	if (!function_contains(function, successor)) {
		return PQCP_FLEET_POLICY_ERR_CONTROL_FLOW;
	}
	if (workspace->stack_depths[successor] < 0) {
		workspace->stack_depths[successor] = depth;
		workspace->path_flags[successor] = path_state;
		return enqueue(workspace, successor, queue_count);
	}
	if (workspace->stack_depths[successor] != depth) {
		return PQCP_FLEET_POLICY_ERR_STACK;
	}
	merged = (workspace->path_flags[successor] &
		  (PATH_WITHOUT_DECISION | PATH_WITH_DECISION)) |
		 path_state;
	if (merged !=
	    (workspace->path_flags[successor] &
	     (PATH_WITHOUT_DECISION | PATH_WITH_DECISION))) {
		workspace->path_flags[successor] =
			(workspace->path_flags[successor] &
			 PATH_QUEUED) | merged;
		return enqueue(workspace, successor, queue_count);
	}
	return PQCP_FLEET_POLICY_OK;
}

static int verify_function_cfg(
	const struct pqcp_fleet_policy_module *module,
	uint32_t function_index,
	struct pqcp_fleet_policy_verify_workspace *workspace,
	struct pqcp_fleet_policy_verify_report *report)
{
	const struct pqcp_fleet_policy_function *function =
		&module->functions[function_index];
	const uint32_t first = function->first_instruction;
	const uint32_t end = first + function->instruction_count;
	size_t queue_count = 0U;
	uint32_t reached = 0U;
	uint32_t peak = 0U;
	int ret;

	for (uint32_t pc = first; pc < end; ++pc) {
		workspace->stack_depths[pc] = -1;
		workspace->path_flags[pc] = 0U;
	}
	workspace->stack_depths[first] = 0;
	workspace->path_flags[first] = PATH_WITHOUT_DECISION;
	ret = enqueue(workspace, first, &queue_count);
	if (ret != PQCP_FLEET_POLICY_OK) {
		return fail(report, ret, function_index, first);
	}
	while (queue_count != 0U) {
		struct instruction_effect effect;
		uint32_t pc =
			workspace->instruction_queue[--queue_count];
		const struct pqcp_fleet_policy_instruction *instruction =
			&module->instructions[pc];
		int32_t depth = workspace->stack_depths[pc];
		uint8_t path_state =
			workspace->path_flags[pc] &
			(PATH_WITHOUT_DECISION |
			 PATH_WITH_DECISION);
		int32_t next_depth;

		workspace->path_flags[pc] &= (uint8_t)~PATH_QUEUED;
		ret = effect_for_instruction(
			module, function_index, pc, &effect);
		if (ret != PQCP_FLEET_POLICY_OK) {
			return fail(report, ret, function_index, pc);
		}
		if (depth < 0 || (uint32_t)depth < effect.pops) {
			return fail(report,
				    PQCP_FLEET_POLICY_ERR_STACK,
				    function_index, pc);
		}
		next_depth = depth - (int32_t)effect.pops +
			(int32_t)effect.pushes;
		if ((uint32_t)depth > peak) {
			peak = (uint32_t)depth;
		}
		if ((uint32_t)next_depth > peak) {
			peak = (uint32_t)next_depth;
		}
		if (instruction->opcode ==
		    PQCP_FLEET_POLICY_OP_EMIT_DECISION) {
			if ((path_state &
			     PATH_WITH_DECISION) != 0U) {
				return fail(
					report,
					PQCP_FLEET_POLICY_ERR_CONTROL_FLOW,
					function_index, pc);
			}
			path_state = PATH_WITH_DECISION;
		}
		if (instruction->opcode ==
		    PQCP_FLEET_POLICY_OP_HALT) {
			if (depth != 0 ||
			    path_state != PATH_WITH_DECISION) {
				return fail(
					report,
					PQCP_FLEET_POLICY_ERR_NO_DECISION,
					function_index, pc);
			}
		}
		if (instruction->opcode ==
		    PQCP_FLEET_POLICY_OP_RETURN &&
		    depth != function->result_count) {
			return fail(report,
				    PQCP_FLEET_POLICY_ERR_STACK,
				    function_index, pc);
		}
		if (effect.terminal) {
			continue;
		}
		if (effect.branch) {
			ret = merge_successor(
				function, workspace,
				instruction->immediate,
				next_depth, path_state,
				&queue_count);
			if (ret != PQCP_FLEET_POLICY_OK) {
				return fail(report, ret,
					    function_index, pc);
			}
			if (!effect.conditional) {
				continue;
			}
		}
		if (pc + 1U >= end) {
			return fail(report,
				    PQCP_FLEET_POLICY_ERR_CONTROL_FLOW,
				    function_index, pc);
		}
		ret = merge_successor(
			function, workspace, pc + 1U,
			next_depth, path_state, &queue_count);
		if (ret != PQCP_FLEET_POLICY_OK) {
			return fail(report, ret, function_index, pc);
		}
	}
	for (uint32_t pc = first; pc < end; ++pc) {
		if (workspace->stack_depths[pc] < 0) {
			return fail(report,
				    PQCP_FLEET_POLICY_ERR_CONTROL_FLOW,
				    function_index, pc);
		}
		reached++;
	}
	workspace->function_stack_peaks[function_index] = peak;
	report->reachable_instructions += reached;
	return PQCP_FLEET_POLICY_OK;
}

static int verify_call_graph(
	const struct pqcp_fleet_policy_module *module,
	struct pqcp_fleet_policy_verify_workspace *workspace,
	struct pqcp_fleet_policy_verify_report *report)
{
	size_t stack_count = 0U;
	const uint32_t root = module->entry_function;

	memset(workspace->function_marks, 0,
	       module->function_count *
		       sizeof(workspace->function_marks[0]));
	workspace->function_stack[stack_count] = root;
	workspace->function_cursors[stack_count] =
		module->functions[root].first_instruction;
	workspace->function_marks[root] = FUNCTION_VISITING;
	stack_count++;

	while (stack_count != 0U) {
		const size_t top = stack_count - 1U;
		const uint32_t function_index =
			workspace->function_stack[top];
		const struct pqcp_fleet_policy_function *function =
			&module->functions[function_index];
		const uint32_t end = function->first_instruction +
			function->instruction_count;
		bool descended = false;

		while (workspace->function_cursors[top] < end) {
			const uint32_t pc =
				workspace->function_cursors[top]++;
			const struct pqcp_fleet_policy_instruction *instruction =
				&module->instructions[pc];
			uint32_t callee;

			if (instruction->opcode !=
			    PQCP_FLEET_POLICY_OP_CALL) {
				continue;
			}
			callee = instruction->immediate;
			if (workspace->function_marks[callee] ==
			    FUNCTION_VISITING) {
				return fail(
					report,
					PQCP_FLEET_POLICY_ERR_CONTROL_FLOW,
					function_index, pc);
			}
			if (workspace->function_marks[callee] ==
			    FUNCTION_UNSEEN) {
				if (stack_count >=
				    workspace->function_capacity) {
					return fail(
						report,
						PQCP_FLEET_POLICY_ERR_VERIFY_WORKSPACE,
						function_index, pc);
				}
				workspace->function_marks[callee] =
					FUNCTION_VISITING;
				workspace->function_stack[stack_count] =
					callee;
				workspace->function_cursors[stack_count] =
					module->functions[callee].
						first_instruction;
				stack_count++;
				descended = true;
				break;
			}
		}
		if (descended) {
			continue;
		}

		workspace->function_depths[function_index] = 1U;
		workspace->function_local_peaks[function_index] =
			function->local_count;
		for (uint32_t pc = function->first_instruction;
		     pc < end; ++pc) {
			const struct pqcp_fleet_policy_instruction *instruction =
				&module->instructions[pc];
			const struct pqcp_fleet_policy_function *callee_fn;
			uint32_t callee;
			uint32_t stack_peak;
			uint32_t local_peak;
			uint32_t call_depth;

			if (instruction->opcode !=
			    PQCP_FLEET_POLICY_OP_CALL) {
				continue;
			}
			callee = instruction->immediate;
			callee_fn = &module->functions[callee];
			call_depth =
				(uint32_t)workspace->
					function_depths[callee] + 1U;
			if (call_depth > UINT16_MAX) {
				return fail(
					report,
					PQCP_FLEET_POLICY_ERR_CALL_DEPTH,
					function_index, pc);
			}
			if (call_depth >
			    workspace->function_depths[function_index]) {
				workspace->function_depths[function_index] =
					(uint16_t)call_depth;
			}
			stack_peak =
				(uint32_t)workspace->stack_depths[pc] -
				callee_fn->parameter_count +
				workspace->function_stack_peaks[callee];
			if (stack_peak >
			    workspace->function_stack_peaks[
				    function_index]) {
				workspace->function_stack_peaks[
					function_index] = stack_peak;
			}
			local_peak = function->local_count +
				workspace->function_local_peaks[callee];
			if (local_peak <
			    function->local_count) {
				return fail(
					report,
					PQCP_FLEET_POLICY_ERR_OVERFLOW,
					function_index, pc);
			}
			if (local_peak >
			    workspace->function_local_peaks[
				    function_index]) {
				workspace->function_local_peaks[
					function_index] = local_peak;
			}
		}
		workspace->function_marks[function_index] =
			FUNCTION_COMPLETE;
		stack_count--;
	}

	for (uint32_t index = 0U;
	     index < module->function_count; ++index) {
		if (workspace->function_marks[index] !=
		    FUNCTION_COMPLETE) {
			return fail(report,
				    PQCP_FLEET_POLICY_ERR_CONTROL_FLOW,
				    index,
				    module->functions[index].
					    first_instruction);
		}
	}
	report->maximum_call_depth =
		workspace->function_depths[root];
	report->maximum_stack_depth =
		workspace->function_stack_peaks[root];
	report->maximum_local_values =
		workspace->function_local_peaks[root];
	if (report->maximum_stack_depth >
		    module->bounds.max_stack_values ||
	    report->maximum_call_depth >
		    module->bounds.max_call_frames ||
	    report->maximum_local_values >
		    module->bounds.max_local_values) {
		return fail(report,
			    PQCP_FLEET_POLICY_ERR_BAD_MODULE,
			    root,
			    module->functions[root].
				    first_instruction);
	}
	return PQCP_FLEET_POLICY_OK;
}

int pqcp_fleet_policy_module_verify(
	const struct pqcp_fleet_policy_module *module,
	struct pqcp_fleet_policy_verify_workspace *workspace,
	struct pqcp_fleet_policy_verify_report *report)
{
	int ret;

	if (report == NULL) {
		return PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT;
	}
	memset(report, 0, sizeof(*report));
	report->status = PQCP_FLEET_POLICY_ERR_BAD_MODULE;
	report->fault_function = UINT32_MAX;
	report->fault_instruction = UINT32_MAX;

	ret = validate_module_shape(module, workspace, report);
	if (ret != PQCP_FLEET_POLICY_OK) {
		return ret;
	}
	memset(workspace->function_stack_peaks, 0,
	       module->function_count *
		       sizeof(workspace->function_stack_peaks[0]));
	memset(workspace->function_local_peaks, 0,
	       module->function_count *
		       sizeof(workspace->function_local_peaks[0]));
	for (uint32_t function_index = 0U;
	     function_index < module->function_count;
	     ++function_index) {
		ret = verify_function_cfg(
			module, function_index, workspace, report);
		if (ret != PQCP_FLEET_POLICY_OK) {
			return ret;
		}
	}
	ret = verify_call_graph(module, workspace, report);
	if (ret != PQCP_FLEET_POLICY_OK) {
		return ret;
	}
	report->status = PQCP_FLEET_POLICY_OK;
	report->fault_function = UINT32_MAX;
	report->fault_instruction = UINT32_MAX;
	return PQCP_FLEET_POLICY_OK;
}
