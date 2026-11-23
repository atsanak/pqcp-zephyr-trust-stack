/*
 * SPDX-License-Identifier: MIT
 *
 * Replayable witnesses for composite runtime and channel operation plans.
 */

#ifndef PQCP_ZEPHYR_OPERATION_PLAN_CONFORMANCE_H_
#define PQCP_ZEPHYR_OPERATION_PLAN_CONFORMANCE_H_

#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/operation_planner.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_OPERATION_PLAN_CONFORMANCE_SCHEMA_VERSION 1U
#define PQCP_OPERATION_PLAN_CONFORMANCE_SCENARIO_COUNT 2U
#define PQCP_RUNTIME_OPERATION_PLAN_CONFORMANCE_CASES 1024U
#define PQCP_CHANNEL_OPERATION_PLAN_CONFORMANCE_CASES 1024U
#define PQCP_OPERATION_PLAN_CONFORMANCE_TOTAL_CASES \
	(PQCP_RUNTIME_OPERATION_PLAN_CONFORMANCE_CASES + \
	 PQCP_CHANNEL_OPERATION_PLAN_CONFORMANCE_CASES)

#define PQCP_OPERATION_PLAN_CASE_ID(domain, scenario, primary, operation) \
	((((uint32_t)(domain) & 0x3U) << 30) | \
	 (((uint32_t)(scenario) & 0x3U) << 28) | \
	 (((uint32_t)(primary) & 0xffU) << 16) | \
	 (((uint32_t)(operation) & 0xffU) << 8))

enum pqcp_operation_plan_conformance_domain {
	PQCP_OPERATION_PLAN_CONFORMANCE_RUNTIME = 0,
	PQCP_OPERATION_PLAN_CONFORMANCE_CHANNEL,
	PQCP_OPERATION_PLAN_CONFORMANCE_DOMAIN_COUNT,
};

enum pqcp_operation_plan_scenario {
	PQCP_OPERATION_PLAN_SCENARIO_BASELINE = 0,
	PQCP_OPERATION_PLAN_SCENARIO_STRESS,
	PQCP_OPERATION_PLAN_SCENARIO_COUNT,
};

struct pqcp_runtime_operation_plan_case {
	uint32_t schema_version;
	uint32_t case_id;
	enum pqcp_operation_plan_scenario scenario;
	struct pqcp_runtime_operation_context context;
	enum pqcp_runtime_plan_disposition disposition;
	enum pqcp_runtime_policy_state next_state;
	uint32_t maximum_concurrency;
	uint32_t reservation_ttl_ms;
	uint32_t priority_penalty;
	uint32_t retry_limit;
	uint32_t retry_delay_ms;
	uint32_t reason_mask;
	int32_t expected_error;
};

struct pqcp_channel_operation_plan_case {
	uint32_t schema_version;
	uint32_t case_id;
	enum pqcp_operation_plan_scenario scenario;
	struct pqcp_channel_operation_context context;
	enum pqcp_channel_plan_disposition disposition;
	enum pqcp_channel_policy_state next_state;
	uint32_t probe_timeout_ms;
	uint32_t migration_hysteresis_bps;
	uint32_t retry_limit;
	uint32_t retry_delay_ms;
	uint32_t reason_mask;
	int32_t expected_error;
};

size_t pqcp_runtime_operation_plan_conformance_count(void);
int pqcp_runtime_operation_plan_conformance_get(
	size_t index,
	struct pqcp_runtime_operation_plan_case *test_case);
int pqcp_runtime_operation_plan_conformance_find(
	enum pqcp_operation_plan_scenario scenario,
	enum pqcp_runtime_policy_state state,
	enum pqcp_runtime_command_kind command,
	struct pqcp_runtime_operation_plan_case *test_case);
int pqcp_runtime_operation_plan_conformance_fingerprint(
	uint64_t *fingerprint);
int pqcp_runtime_operation_plan_conformance_audit(void);

size_t pqcp_channel_operation_plan_conformance_count(void);
int pqcp_channel_operation_plan_conformance_get(
	size_t index,
	struct pqcp_channel_operation_plan_case *test_case);
int pqcp_channel_operation_plan_conformance_find(
	enum pqcp_operation_plan_scenario scenario,
	enum pqcp_channel_policy_state state,
	enum pqcp_channel_control_kind control,
	struct pqcp_channel_operation_plan_case *test_case);
int pqcp_channel_operation_plan_conformance_fingerprint(
	uint64_t *fingerprint);
int pqcp_channel_operation_plan_conformance_audit(void);

int pqcp_operation_plan_conformance_audit_all(void);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_OPERATION_PLAN_CONFORMANCE_H_ */
