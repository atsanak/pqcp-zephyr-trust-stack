/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Composite planning for runtime commands and protected-channel controls.
 */

#ifndef PQCP_ZEPHYR_OPERATION_PLANNER_H_
#define PQCP_ZEPHYR_OPERATION_PLANNER_H_

#include <stdint.h>

#include <pqcp_zephyr/protected_channel_operations.h>
#include <pqcp_zephyr/runtime_operations.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_OPERATION_PLAN_SCHEMA_VERSION 1U

enum pqcp_runtime_plan_disposition {
	PQCP_RUNTIME_PLAN_DENY = 0,
	PQCP_RUNTIME_PLAN_ALLOW,
	PQCP_RUNTIME_PLAN_ALLOW_IDEMPOTENT,
	PQCP_RUNTIME_PLAN_ALLOW_READ_ONLY,
	PQCP_RUNTIME_PLAN_THROTTLE,
	PQCP_RUNTIME_PLAN_RECLAIM,
	PQCP_RUNTIME_PLAN_DRAIN,
	PQCP_RUNTIME_PLAN_MAINTENANCE,
	PQCP_RUNTIME_PLAN_CHECKPOINT,
	PQCP_RUNTIME_PLAN_RETRY,
	PQCP_RUNTIME_PLAN_RECOVER,
	PQCP_RUNTIME_PLAN_LOCKDOWN,
	PQCP_RUNTIME_PLAN_TERMINATE,
	PQCP_RUNTIME_PLAN_DISPOSITION_COUNT,
};

enum pqcp_channel_plan_disposition {
	PQCP_CHANNEL_PLAN_DENY = 0,
	PQCP_CHANNEL_PLAN_ALLOW,
	PQCP_CHANNEL_PLAN_ALLOW_IDEMPOTENT,
	PQCP_CHANNEL_PLAN_REQUIRE_ESTABLISHED,
	PQCP_CHANNEL_PLAN_PROBE_PATH,
	PQCP_CHANNEL_PLAN_MIGRATE_PATH,
	PQCP_CHANNEL_PLAN_REKEY,
	PQCP_CHANNEL_PLAN_DRAIN,
	PQCP_CHANNEL_PLAN_RESET_STREAM,
	PQCP_CHANNEL_PLAN_RETRY,
	PQCP_CHANNEL_PLAN_CLOSE,
	PQCP_CHANNEL_PLAN_TERMINATE,
	PQCP_CHANNEL_PLAN_DISPOSITION_COUNT,
};

struct pqcp_runtime_operation_context {
	enum pqcp_runtime_policy_state state;
	enum pqcp_runtime_resource_condition resource_condition;
	enum pqcp_runtime_recovery_condition recovery_condition;
	enum pqcp_runtime_command_kind command;
};

struct pqcp_runtime_operation_plan {
	uint32_t schema_version;
	struct pqcp_runtime_operation_context context;
	struct pqcp_runtime_policy_decision state_decision;
	struct pqcp_runtime_resource_policy_decision resource_decision;
	struct pqcp_runtime_recovery_policy_decision recovery_decision;
	enum pqcp_runtime_plan_disposition disposition;
	enum pqcp_runtime_policy_state next_state;
	uint32_t maximum_concurrency;
	uint32_t reservation_ttl_ms;
	uint32_t priority_penalty;
	uint32_t retry_limit;
	uint32_t retry_delay_ms;
	uint32_t reason_mask;
	int error;
};

struct pqcp_channel_operation_context {
	enum pqcp_channel_policy_state state;
	enum pqcp_channel_path_condition path_condition;
	enum pqcp_channel_fault_condition fault_condition;
	enum pqcp_channel_control_kind control;
};

struct pqcp_channel_operation_plan {
	uint32_t schema_version;
	struct pqcp_channel_operation_context context;
	struct pqcp_channel_policy_decision state_decision;
	struct pqcp_channel_path_policy_decision path_decision;
	struct pqcp_channel_fault_policy_decision fault_decision;
	enum pqcp_channel_plan_disposition disposition;
	enum pqcp_channel_policy_state next_state;
	uint32_t probe_timeout_ms;
	uint32_t migration_hysteresis_bps;
	uint32_t retry_limit;
	uint32_t retry_delay_ms;
	uint32_t reason_mask;
	int error;
};

int pqcp_runtime_operation_plan(
	const struct pqcp_runtime_operation_context *context,
	struct pqcp_runtime_operation_plan *plan);
int pqcp_runtime_operation_plan_audit(
	const struct pqcp_runtime_operation_plan *plan);
const char *pqcp_runtime_plan_disposition_str(
	enum pqcp_runtime_plan_disposition disposition);

int pqcp_channel_operation_plan(
	const struct pqcp_channel_operation_context *context,
	struct pqcp_channel_operation_plan *plan);
int pqcp_channel_operation_plan_audit(
	const struct pqcp_channel_operation_plan *plan);
const char *pqcp_channel_plan_disposition_str(
	enum pqcp_channel_plan_disposition disposition);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_OPERATION_PLANNER_H_ */
