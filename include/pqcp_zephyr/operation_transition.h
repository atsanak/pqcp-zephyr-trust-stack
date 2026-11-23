/*
 * SPDX-License-Identifier: MIT
 *
 * Composed runtime and protected-channel transition decisions.
 */

#ifndef PQCP_ZEPHYR_OPERATION_TRANSITION_H_
#define PQCP_ZEPHYR_OPERATION_TRANSITION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/operation_planner.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_OPERATION_TRANSITION_SCHEMA_VERSION 1U
#define PQCP_OPERATION_TRANSITION_STEPS_PER_TRACE 8U
#define PQCP_OPERATION_TRANSITION_TRACES_PER_DOMAIN 512U
#define PQCP_OPERATION_TRANSITION_DOMAIN_COUNT 2U
#define PQCP_OPERATION_TRANSITION_TOTAL_TRACES \
	(PQCP_OPERATION_TRANSITION_TRACES_PER_DOMAIN * \
	 PQCP_OPERATION_TRANSITION_DOMAIN_COUNT)

#define PQCP_OPERATION_TRANSITION_TRACE_ID(domain, initial_state, sequence) \
	((((uint32_t)(domain) & 0xffU) << 24) | \
	 (((uint32_t)(initial_state) & 0xffU) << 16) | \
	 ((uint32_t)(sequence) & 0xffffU))

enum pqcp_operation_transition_domain {
	PQCP_OPERATION_TRANSITION_RUNTIME = 0,
	PQCP_OPERATION_TRANSITION_CHANNEL,
};

struct pqcp_runtime_transition_input {
	enum pqcp_runtime_policy_state state;
	enum pqcp_runtime_resource_condition resource_condition;
	enum pqcp_runtime_recovery_condition recovery_condition;
	enum pqcp_runtime_command_kind command;
};

struct pqcp_runtime_transition_decision {
	struct pqcp_runtime_operation_plan plan;
	enum pqcp_runtime_policy_state effective_state;
	int error;
	bool permitted;
};

struct pqcp_channel_transition_input {
	enum pqcp_channel_policy_state state;
	enum pqcp_channel_path_condition path_condition;
	enum pqcp_channel_fault_condition fault_condition;
	enum pqcp_channel_control_kind control;
};

struct pqcp_channel_transition_decision {
	struct pqcp_channel_operation_plan plan;
	enum pqcp_channel_policy_state effective_state;
	int error;
	bool permitted;
};

struct pqcp_runtime_transition_trace_step {
	enum pqcp_runtime_resource_condition resource_condition;
	enum pqcp_runtime_recovery_condition recovery_condition;
	enum pqcp_runtime_command_kind command;
};

struct pqcp_runtime_transition_trace {
	uint32_t schema_version;
	uint32_t trace_id;
	enum pqcp_runtime_policy_state initial_state;
	uint32_t step_count;
	struct pqcp_runtime_transition_trace_step
		steps[PQCP_OPERATION_TRANSITION_STEPS_PER_TRACE];
	uint64_t expected_fingerprint;
};

struct pqcp_channel_transition_trace_step {
	enum pqcp_channel_path_condition path_condition;
	enum pqcp_channel_fault_condition fault_condition;
	enum pqcp_channel_control_kind control;
};

struct pqcp_channel_transition_trace {
	uint32_t schema_version;
	uint32_t trace_id;
	enum pqcp_channel_policy_state initial_state;
	uint32_t step_count;
	struct pqcp_channel_transition_trace_step
		steps[PQCP_OPERATION_TRANSITION_STEPS_PER_TRACE];
	uint64_t expected_fingerprint;
};

struct pqcp_runtime_transition_replay_result {
	uint32_t trace_id;
	uint32_t steps_replayed;
	enum pqcp_runtime_policy_state final_state;
	uint64_t fingerprint;
};

struct pqcp_channel_transition_replay_result {
	uint32_t trace_id;
	uint32_t steps_replayed;
	enum pqcp_channel_policy_state final_state;
	uint64_t fingerprint;
};

int pqcp_runtime_transition_decide(
	const struct pqcp_runtime_transition_input *input,
	struct pqcp_runtime_transition_decision *decision);
int pqcp_channel_transition_decide(
	const struct pqcp_channel_transition_input *input,
	struct pqcp_channel_transition_decision *decision);

size_t pqcp_runtime_transition_trace_count(void);
int pqcp_runtime_transition_trace_get(
	size_t index,
	struct pqcp_runtime_transition_trace *trace);
int pqcp_runtime_transition_trace_replay(
	const struct pqcp_runtime_transition_trace *trace,
	struct pqcp_runtime_transition_replay_result *result);
int pqcp_runtime_transition_trace_fingerprint(
	uint64_t *fingerprint);
int pqcp_runtime_transition_trace_audit(void);

size_t pqcp_channel_transition_trace_count(void);
int pqcp_channel_transition_trace_get(
	size_t index,
	struct pqcp_channel_transition_trace *trace);
int pqcp_channel_transition_trace_replay(
	const struct pqcp_channel_transition_trace *trace,
	struct pqcp_channel_transition_replay_result *result);
int pqcp_channel_transition_trace_fingerprint(
	uint64_t *fingerprint);
int pqcp_channel_transition_trace_audit(void);

int pqcp_operation_transition_audit_all(void);
const char *pqcp_operation_transition_domain_str(
	enum pqcp_operation_transition_domain domain);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_OPERATION_TRANSITION_H_ */
