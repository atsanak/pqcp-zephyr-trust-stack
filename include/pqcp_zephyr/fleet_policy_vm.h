/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Portable, allocation-free fleet policy bytecode runtime.
 *
 * The API deliberately depends only on ISO C types. Modules, VM workspaces,
 * verifier workspaces, codec storage, builtin state, and rollout state are
 * all owned by the caller.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_POLICY_VM_H_
#define PQCP_ZEPHYR_FLEET_POLICY_VM_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_POLICY_ABI_VERSION 1U
#define PQCP_FLEET_POLICY_BYTECODE_VERSION 1U
#define PQCP_FLEET_POLICY_WIRE_VERSION 1U
#define PQCP_FLEET_POLICY_DIGEST_BYTES 32U
#define PQCP_FLEET_POLICY_MAX_BUILTIN_ARGS 8U
#define PQCP_FLEET_POLICY_MAX_ACTION_ARGS 4U
#define PQCP_FLEET_POLICY_BASIS_POINTS 10000U

enum pqcp_fleet_policy_status {
	PQCP_FLEET_POLICY_OK = 0,
	PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT = -1,
	PQCP_FLEET_POLICY_ERR_BAD_MODULE = -2,
	PQCP_FLEET_POLICY_ERR_BAD_OPCODE = -3,
	PQCP_FLEET_POLICY_ERR_BAD_OPERAND = -4,
	PQCP_FLEET_POLICY_ERR_TYPE = -5,
	PQCP_FLEET_POLICY_ERR_STACK = -6,
	PQCP_FLEET_POLICY_ERR_CALL_DEPTH = -7,
	PQCP_FLEET_POLICY_ERR_BUDGET = -8,
	PQCP_FLEET_POLICY_ERR_OVERFLOW = -9,
	PQCP_FLEET_POLICY_ERR_DIVIDE_BY_ZERO = -10,
	PQCP_FLEET_POLICY_ERR_CLAIM = -11,
	PQCP_FLEET_POLICY_ERR_BUILTIN = -12,
	PQCP_FLEET_POLICY_ERR_NO_DECISION = -13,
	PQCP_FLEET_POLICY_ERR_ACTION_LIMIT = -14,
	PQCP_FLEET_POLICY_ERR_VERIFY_WORKSPACE = -15,
	PQCP_FLEET_POLICY_ERR_CONTROL_FLOW = -16,
	PQCP_FLEET_POLICY_ERR_DIGEST = -17,
	PQCP_FLEET_POLICY_ERR_CODEC = -18,
	PQCP_FLEET_POLICY_ERR_STATE = -19,
	PQCP_FLEET_POLICY_ERR_NOT_FOUND = -20,
	PQCP_FLEET_POLICY_ERR_CAPACITY = -21,
};

enum pqcp_fleet_policy_value_type {
	PQCP_FLEET_POLICY_VALUE_INVALID = 0,
	PQCP_FLEET_POLICY_VALUE_I64 = 1,
	PQCP_FLEET_POLICY_VALUE_U64 = 2,
	PQCP_FLEET_POLICY_VALUE_BOOL = 3,
	PQCP_FLEET_POLICY_VALUE_BYTES = 4,
	PQCP_FLEET_POLICY_VALUE_DIGEST = 5,
};

struct pqcp_fleet_policy_bytes {
	const uint8_t *data;
	uint32_t length;
};

struct pqcp_fleet_policy_value {
	uint32_t type;
	uint32_t reserved;
	union {
		int64_t i64;
		uint64_t u64;
		bool boolean;
		struct pqcp_fleet_policy_bytes bytes;
	} as;
};

enum pqcp_fleet_policy_opcode {
	PQCP_FLEET_POLICY_OP_NOP = 0,
	PQCP_FLEET_POLICY_OP_PUSH_CONST = 1,
	PQCP_FLEET_POLICY_OP_PUSH_I32 = 2,
	PQCP_FLEET_POLICY_OP_PUSH_U32 = 3,
	PQCP_FLEET_POLICY_OP_PUSH_FALSE = 4,
	PQCP_FLEET_POLICY_OP_PUSH_TRUE = 5,
	PQCP_FLEET_POLICY_OP_POP = 6,
	PQCP_FLEET_POLICY_OP_DUP = 7,
	PQCP_FLEET_POLICY_OP_SWAP = 8,
	PQCP_FLEET_POLICY_OP_LOAD_CLAIM = 9,
	PQCP_FLEET_POLICY_OP_LOAD_LOCAL = 10,
	PQCP_FLEET_POLICY_OP_STORE_LOCAL = 11,
	PQCP_FLEET_POLICY_OP_ADD = 12,
	PQCP_FLEET_POLICY_OP_SUB = 13,
	PQCP_FLEET_POLICY_OP_MUL = 14,
	PQCP_FLEET_POLICY_OP_DIV = 15,
	PQCP_FLEET_POLICY_OP_MOD = 16,
	PQCP_FLEET_POLICY_OP_NEG = 17,
	PQCP_FLEET_POLICY_OP_BIT_AND = 18,
	PQCP_FLEET_POLICY_OP_BIT_OR = 19,
	PQCP_FLEET_POLICY_OP_BIT_XOR = 20,
	PQCP_FLEET_POLICY_OP_BIT_NOT = 21,
	PQCP_FLEET_POLICY_OP_SHIFT_LEFT = 22,
	PQCP_FLEET_POLICY_OP_SHIFT_RIGHT = 23,
	PQCP_FLEET_POLICY_OP_EQUAL = 24,
	PQCP_FLEET_POLICY_OP_NOT_EQUAL = 25,
	PQCP_FLEET_POLICY_OP_LESS = 26,
	PQCP_FLEET_POLICY_OP_LESS_EQUAL = 27,
	PQCP_FLEET_POLICY_OP_GREATER = 28,
	PQCP_FLEET_POLICY_OP_GREATER_EQUAL = 29,
	PQCP_FLEET_POLICY_OP_BOOL_NOT = 30,
	PQCP_FLEET_POLICY_OP_BOOL_AND = 31,
	PQCP_FLEET_POLICY_OP_BOOL_OR = 32,
	PQCP_FLEET_POLICY_OP_SELECT = 33,
	PQCP_FLEET_POLICY_OP_JUMP = 34,
	PQCP_FLEET_POLICY_OP_JUMP_IF_TRUE = 35,
	PQCP_FLEET_POLICY_OP_JUMP_IF_FALSE = 36,
	PQCP_FLEET_POLICY_OP_CALL = 37,
	PQCP_FLEET_POLICY_OP_RETURN = 38,
	PQCP_FLEET_POLICY_OP_CALL_BUILTIN = 39,
	PQCP_FLEET_POLICY_OP_EMIT_DECISION = 40,
	PQCP_FLEET_POLICY_OP_EMIT_ACTION = 41,
	PQCP_FLEET_POLICY_OP_HALT = 42,
	PQCP_FLEET_POLICY_OP_COUNT,
};

/*
 * Instructions are host-side objects, not packed wire records. The codec
 * serializes each field explicitly, so execution is independent of host byte
 * order and alignment.
 */
struct pqcp_fleet_policy_instruction {
	uint8_t opcode;
	uint8_t a;
	uint16_t b;
	uint32_t immediate;
};

enum pqcp_fleet_policy_function_flag {
	PQCP_FLEET_POLICY_FUNCTION_ENTRY = (1U << 0),
};

struct pqcp_fleet_policy_function {
	uint32_t first_instruction;
	uint32_t instruction_count;
	uint16_t parameter_count;
	uint16_t local_count;
	uint8_t result_count;
	uint8_t flags;
	uint16_t reserved;
};

struct pqcp_fleet_policy_bounds {
	uint32_t instruction_budget;
	uint16_t max_stack_values;
	uint16_t max_call_frames;
	uint16_t max_local_values;
	uint16_t max_actions;
	uint16_t max_action_arguments;
	uint16_t reserved;
};

enum pqcp_fleet_policy_module_flag {
	PQCP_FLEET_POLICY_MODULE_REQUIRE_DIGEST = (1U << 0),
	PQCP_FLEET_POLICY_MODULE_CANONICAL = (1U << 1),
};

struct pqcp_fleet_policy_module {
	uint32_t abi_version;
	uint32_t bytecode_version;
	uint32_t flags;
	uint32_t entry_function;
	const struct pqcp_fleet_policy_instruction *instructions;
	uint32_t instruction_count;
	const struct pqcp_fleet_policy_value *constants;
	uint32_t constant_count;
	const struct pqcp_fleet_policy_function *functions;
	uint32_t function_count;
	struct pqcp_fleet_policy_bounds bounds;
	uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES];
};

typedef int (*pqcp_fleet_policy_claim_load_fn)(
	void *context,
	uint32_t claim_id,
	struct pqcp_fleet_policy_value *value);

struct pqcp_fleet_policy_claim_source {
	pqcp_fleet_policy_claim_load_fn load;
	void *context;
};

struct pqcp_fleet_policy_builtin_context {
	const struct pqcp_fleet_policy_module *module;
	const struct pqcp_fleet_policy_claim_source *claims;
	void *registry_context;
	void *application_context;
	uint32_t instruction_count;
	uint32_t call_depth;
};

struct pqcp_fleet_policy_builtin_state {
	void *scratch;
	size_t scratch_capacity;
	uint64_t invocation_count;
	uint64_t failure_count;
	uint32_t last_builtin_id;
	int32_t last_status;
};

typedef int (*pqcp_fleet_policy_builtin_fn)(
	const struct pqcp_fleet_policy_builtin_context *context,
	struct pqcp_fleet_policy_builtin_state *state,
	const struct pqcp_fleet_policy_value *arguments,
	uint32_t argument_count,
	struct pqcp_fleet_policy_value *result);

enum pqcp_fleet_policy_builtin_flag {
	PQCP_FLEET_POLICY_BUILTIN_DETERMINISTIC = (1U << 0),
	PQCP_FLEET_POLICY_BUILTIN_PURE = (1U << 1),
};

struct pqcp_fleet_policy_builtin_descriptor {
	uint32_t builtin_id;
	uint32_t flags;
	uint8_t argument_count;
	uint8_t result_type;
	uint16_t reserved;
	uint8_t argument_types[PQCP_FLEET_POLICY_MAX_BUILTIN_ARGS];
	pqcp_fleet_policy_builtin_fn invoke;
};

struct pqcp_fleet_policy_builtin_registry {
	const struct pqcp_fleet_policy_builtin_descriptor *descriptors;
	size_t descriptor_count;
	void *context;
};

int pqcp_fleet_policy_builtin_registry_init(
	struct pqcp_fleet_policy_builtin_registry *registry,
	const struct pqcp_fleet_policy_builtin_descriptor *descriptors,
	size_t descriptor_count,
	void *context);

const struct pqcp_fleet_policy_builtin_descriptor *
pqcp_fleet_policy_builtin_find(
	const struct pqcp_fleet_policy_builtin_registry *registry,
	uint32_t builtin_id);

void pqcp_fleet_policy_builtin_state_reset(
	struct pqcp_fleet_policy_builtin_state *state,
	void *scratch,
	size_t scratch_capacity);

enum pqcp_fleet_policy_decision_outcome {
	PQCP_FLEET_POLICY_DECISION_DENY = 0,
	PQCP_FLEET_POLICY_DECISION_ALLOW = 1,
	PQCP_FLEET_POLICY_DECISION_DEFER = 2,
};

#define PQCP_FLEET_POLICY_REASON_VM_FAULT UINT32_C(0xffffffff)

struct pqcp_fleet_policy_decision {
	uint32_t outcome;
	uint32_t reason_code;
	uint32_t policy_code;
	uint32_t flags;
};

struct pqcp_fleet_policy_action {
	uint32_t action_id;
	uint32_t flags;
	uint32_t argument_count;
	uint32_t reserved;
	struct pqcp_fleet_policy_value
		arguments[PQCP_FLEET_POLICY_MAX_ACTION_ARGS];
};

struct pqcp_fleet_policy_vm_frame {
	uint32_t function_index;
	uint32_t return_instruction;
	uint32_t stack_base;
	uint32_t local_base;
};

struct pqcp_fleet_policy_vm_workspace {
	struct pqcp_fleet_policy_value *stack;
	size_t stack_capacity;
	struct pqcp_fleet_policy_value *locals;
	size_t local_capacity;
	struct pqcp_fleet_policy_vm_frame *frames;
	size_t frame_capacity;
};

struct pqcp_fleet_policy_execution_context {
	const struct pqcp_fleet_policy_claim_source *claims;
	const struct pqcp_fleet_policy_builtin_registry *builtins;
	struct pqcp_fleet_policy_builtin_state *builtin_state;
	void *application_context;
	uint32_t instruction_limit;
	uint32_t flags;
};

struct pqcp_fleet_policy_execution_result {
	int32_t status;
	uint32_t fault_instruction;
	uint32_t instructions_executed;
	uint32_t maximum_stack_depth;
	uint32_t maximum_call_depth;
	struct pqcp_fleet_policy_decision decision;
	struct pqcp_fleet_policy_action *actions;
	size_t action_capacity;
	size_t action_count;
};

struct pqcp_fleet_policy_verify_workspace {
	int32_t *stack_depths;
	uint8_t *path_flags;
	uint32_t *instruction_queue;
	size_t instruction_capacity;
	uint8_t *function_marks;
	uint16_t *function_depths;
	uint32_t *function_stack_peaks;
	uint32_t *function_local_peaks;
	uint32_t *function_stack;
	uint32_t *function_cursors;
	size_t function_capacity;
};

struct pqcp_fleet_policy_verify_report {
	int32_t status;
	uint32_t fault_function;
	uint32_t fault_instruction;
	uint32_t reachable_instructions;
	uint32_t maximum_stack_depth;
	uint32_t maximum_call_depth;
	uint32_t maximum_local_values;
};

int pqcp_fleet_policy_value_validate(
	const struct pqcp_fleet_policy_value *value);

int pqcp_fleet_policy_module_verify(
	const struct pqcp_fleet_policy_module *module,
	struct pqcp_fleet_policy_verify_workspace *workspace,
	struct pqcp_fleet_policy_verify_report *report);

int pqcp_fleet_policy_vm_execute(
	const struct pqcp_fleet_policy_module *module,
	const struct pqcp_fleet_policy_execution_context *context,
	struct pqcp_fleet_policy_vm_workspace *workspace,
	struct pqcp_fleet_policy_execution_result *result);

/*
 * Canonical module codec. Decode borrows immutable byte and digest payloads
 * from input; the input must outlive the decoded module. Descriptor arrays are
 * supplied by the caller through storage.
 */
struct pqcp_fleet_policy_codec_storage {
	struct pqcp_fleet_policy_instruction *instructions;
	size_t instruction_capacity;
	struct pqcp_fleet_policy_value *constants;
	size_t constant_capacity;
	struct pqcp_fleet_policy_function *functions;
	size_t function_capacity;
};

struct pqcp_fleet_policy_codec_result {
	int32_t status;
	size_t bytes_consumed;
	size_t bytes_produced;
	uint32_t fault_offset;
};

int pqcp_fleet_policy_module_encoded_size(
	const struct pqcp_fleet_policy_module *module,
	size_t *encoded_size);

int pqcp_fleet_policy_module_encode(
	const struct pqcp_fleet_policy_module *module,
	uint8_t *output,
	size_t output_capacity,
	struct pqcp_fleet_policy_codec_result *result);

int pqcp_fleet_policy_module_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_fleet_policy_codec_storage *storage,
	struct pqcp_fleet_policy_module *module,
	struct pqcp_fleet_policy_codec_result *result);

int pqcp_fleet_policy_module_digest(
	const struct pqcp_fleet_policy_module *module,
	uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES]);

/*
 * Optional deterministic policy rollout controller. It contains no locking;
 * callers provide synchronization when a controller is shared.
 */
enum pqcp_fleet_policy_rollout_state {
	PQCP_FLEET_POLICY_ROLLOUT_EMPTY = 0,
	PQCP_FLEET_POLICY_ROLLOUT_PLANNED = 1,
	PQCP_FLEET_POLICY_ROLLOUT_ACTIVE = 2,
	PQCP_FLEET_POLICY_ROLLOUT_PAUSED = 3,
	PQCP_FLEET_POLICY_ROLLOUT_DRAINING = 4,
	PQCP_FLEET_POLICY_ROLLOUT_COMPLETED = 5,
	PQCP_FLEET_POLICY_ROLLOUT_ABORTED = 6,
};

enum pqcp_fleet_policy_rollout_health {
	PQCP_FLEET_POLICY_ROLLOUT_HEALTH_PENDING = 0,
	PQCP_FLEET_POLICY_ROLLOUT_HEALTH_HEALTHY = 1,
	PQCP_FLEET_POLICY_ROLLOUT_HEALTH_UNHEALTHY = 2,
	PQCP_FLEET_POLICY_ROLLOUT_HEALTH_ROLLED_BACK = 3,
};

struct pqcp_fleet_policy_rollout_campaign {
	uint32_t abi_version;
	uint32_t state;
	uint64_t campaign_id;
	uint64_t starts_at_ms;
	uint64_t promotion_not_before_ms;
	uint64_t deadline_ms;
	uint32_t cohort_basis_points;
	uint32_t minimum_success_basis_points;
	uint32_t maximum_failure_basis_points;
	uint32_t minimum_completed_devices;
	uint32_t assigned_devices;
	uint32_t pending_devices;
	uint32_t healthy_devices;
	uint32_t unhealthy_devices;
	uint32_t rolled_back_devices;
	uint8_t target_module_digest[PQCP_FLEET_POLICY_DIGEST_BYTES];
	uint8_t cohort_seed[PQCP_FLEET_POLICY_DIGEST_BYTES];
	bool occupied;
	uint8_t reserved[7];
};

struct pqcp_fleet_policy_rollout_health_report {
	uint64_t campaign_id;
	uint64_t observed_at_ms;
	uint32_t health;
	uint32_t reason_code;
	uint8_t device_digest[PQCP_FLEET_POLICY_DIGEST_BYTES];
	uint8_t module_digest[PQCP_FLEET_POLICY_DIGEST_BYTES];
};

struct pqcp_fleet_policy_rollout_assignment {
	bool assigned;
	uint8_t reserved[3];
	uint32_t cohort_value;
	uint64_t campaign_id;
	uint8_t target_module_digest[PQCP_FLEET_POLICY_DIGEST_BYTES];
};

struct pqcp_fleet_policy_rollout_controller {
	uint32_t abi_version;
	uint32_t flags;
	struct pqcp_fleet_policy_rollout_campaign *campaigns;
	size_t campaign_capacity;
	uint64_t assignment_count;
	uint64_t health_report_count;
	bool initialized;
	uint8_t reserved[7];
};

int pqcp_fleet_policy_rollout_init(
	struct pqcp_fleet_policy_rollout_controller *controller,
	struct pqcp_fleet_policy_rollout_campaign *campaigns,
	size_t campaign_capacity);

int pqcp_fleet_policy_rollout_create(
	struct pqcp_fleet_policy_rollout_controller *controller,
	const struct pqcp_fleet_policy_rollout_campaign *campaign);

int pqcp_fleet_policy_rollout_assign(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id,
	const uint8_t device_digest[PQCP_FLEET_POLICY_DIGEST_BYTES],
	struct pqcp_fleet_policy_rollout_assignment *assignment);

int pqcp_fleet_policy_rollout_record_health(
	struct pqcp_fleet_policy_rollout_controller *controller,
	const struct pqcp_fleet_policy_rollout_health_report *report);

int pqcp_fleet_policy_rollout_tick(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t now_ms,
	uint32_t *changed_campaigns);

int pqcp_fleet_policy_rollout_pause(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id);

int pqcp_fleet_policy_rollout_resume(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id,
	uint64_t now_ms);

int pqcp_fleet_policy_rollout_abort(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id,
	uint32_t reason_code);

int pqcp_fleet_policy_rollout_get(
	const struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id,
	struct pqcp_fleet_policy_rollout_campaign *campaign);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_POLICY_VM_H_ */
