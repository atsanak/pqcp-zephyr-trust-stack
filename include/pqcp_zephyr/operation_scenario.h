/*
 * SPDX-License-Identifier: MIT
 *
 * Stateful scenario replay for runtime and protected-channel policy.
 */

#ifndef PQCP_ZEPHYR_OPERATION_SCENARIO_H_
#define PQCP_ZEPHYR_OPERATION_SCENARIO_H_

#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/protected_channel_operations.h>
#include <pqcp_zephyr/runtime_operations.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_OPERATION_SCENARIO_SCHEMA_VERSION 1U
#define PQCP_OPERATION_SCENARIO_CASES_PER_DOMAIN 512U
#define PQCP_OPERATION_SCENARIO_DOMAIN_COUNT 6U
#define PQCP_OPERATION_SCENARIO_TOTAL_CASES \
	(PQCP_OPERATION_SCENARIO_CASES_PER_DOMAIN * \
	 PQCP_OPERATION_SCENARIO_DOMAIN_COUNT)

#define PQCP_OPERATION_SCENARIO_CASE_ID( \
	domain, condition, first_operation, second_operation) \
	((((uint32_t)(domain) & 0xffU) << 24) | \
	 (((uint32_t)(condition) & 0xffU) << 16) | \
	 (((uint32_t)(first_operation) & 0xffU) << 8) | \
	 ((uint32_t)(second_operation) & 0xffU))

enum pqcp_operation_scenario_domain {
	PQCP_OPERATION_SCENARIO_RUNTIME_POLICY = 0,
	PQCP_OPERATION_SCENARIO_RUNTIME_RESOURCE,
	PQCP_OPERATION_SCENARIO_RUNTIME_RECOVERY,
	PQCP_OPERATION_SCENARIO_CHANNEL_POLICY,
	PQCP_OPERATION_SCENARIO_CHANNEL_PATH,
	PQCP_OPERATION_SCENARIO_CHANNEL_FAULT,
};

struct pqcp_operation_scenario_result {
	uint32_t second_condition;
	uint32_t first_decision;
	uint32_t first_next_state;
	uint32_t first_reason_mask;
	int32_t first_error;
	uint32_t second_decision;
	uint32_t second_next_state;
	uint32_t second_reason_mask;
	int32_t second_error;
	uint32_t aggregate_reason_mask;
	int32_t terminal_error;
};

struct pqcp_operation_scenario_case {
	uint32_t schema_version;
	uint32_t case_id;
	enum pqcp_operation_scenario_domain domain;
	uint32_t initial_condition;
	uint32_t first_operation;
	uint32_t second_operation;
	struct pqcp_operation_scenario_result expected;
};

size_t pqcp_operation_scenario_count(
	enum pqcp_operation_scenario_domain domain);
int pqcp_operation_scenario_get(
	enum pqcp_operation_scenario_domain domain,
	size_t index,
	struct pqcp_operation_scenario_case *test_case);
int pqcp_operation_scenario_find(
	enum pqcp_operation_scenario_domain domain,
	uint32_t initial_condition,
	uint32_t first_operation,
	uint32_t second_operation,
	struct pqcp_operation_scenario_case *test_case);
int pqcp_operation_scenario_replay(
	const struct pqcp_operation_scenario_case *test_case,
	struct pqcp_operation_scenario_result *result);
int pqcp_operation_scenario_verify(
	const struct pqcp_operation_scenario_case *test_case);
int pqcp_operation_scenario_fingerprint(
	enum pqcp_operation_scenario_domain domain,
	uint64_t *fingerprint);
int pqcp_operation_scenario_audit(
	enum pqcp_operation_scenario_domain domain);
int pqcp_operation_scenario_audit_all(void);
const char *pqcp_operation_scenario_domain_str(
	enum pqcp_operation_scenario_domain domain);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_OPERATION_SCENARIO_H_ */
