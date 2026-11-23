/*
 * SPDX-License-Identifier: MIT
 */

#ifndef PQCP_OPERATION_SCENARIO_INTERNAL_H_
#define PQCP_OPERATION_SCENARIO_INTERNAL_H_

#include <stddef.h>

#include <pqcp_zephyr/operation_scenario.h>

size_t pqcp_runtime_policy_scenario_catalog_count(void);
int pqcp_runtime_policy_scenario_catalog_get(
	size_t index,
	struct pqcp_operation_scenario_case *test_case);
int pqcp_runtime_policy_scenario_catalog_audit(void);

size_t pqcp_runtime_resource_scenario_catalog_count(void);
int pqcp_runtime_resource_scenario_catalog_get(
	size_t index,
	struct pqcp_operation_scenario_case *test_case);
int pqcp_runtime_resource_scenario_catalog_audit(void);

size_t pqcp_runtime_recovery_scenario_catalog_count(void);
int pqcp_runtime_recovery_scenario_catalog_get(
	size_t index,
	struct pqcp_operation_scenario_case *test_case);
int pqcp_runtime_recovery_scenario_catalog_audit(void);

size_t pqcp_channel_policy_scenario_catalog_count(void);
int pqcp_channel_policy_scenario_catalog_get(
	size_t index,
	struct pqcp_operation_scenario_case *test_case);
int pqcp_channel_policy_scenario_catalog_audit(void);

size_t pqcp_channel_path_scenario_catalog_count(void);
int pqcp_channel_path_scenario_catalog_get(
	size_t index,
	struct pqcp_operation_scenario_case *test_case);
int pqcp_channel_path_scenario_catalog_audit(void);

size_t pqcp_channel_fault_scenario_catalog_count(void);
int pqcp_channel_fault_scenario_catalog_get(
	size_t index,
	struct pqcp_operation_scenario_case *test_case);
int pqcp_channel_fault_scenario_catalog_audit(void);

#endif /* PQCP_OPERATION_SCENARIO_INTERNAL_H_ */
