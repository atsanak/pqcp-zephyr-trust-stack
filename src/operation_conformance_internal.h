/*
 * SPDX-License-Identifier: MIT
 */

#ifndef PQCP_OPERATION_CONFORMANCE_INTERNAL_H_
#define PQCP_OPERATION_CONFORMANCE_INTERNAL_H_

#include <stddef.h>

#include <pqcp_zephyr/operation_conformance.h>

size_t pqcp_runtime_policy_conformance_catalog_count(void);
int pqcp_runtime_policy_conformance_catalog_get(
	size_t index,
	struct pqcp_operation_conformance_case *test_case);
int pqcp_runtime_policy_conformance_catalog_audit(void);

size_t pqcp_runtime_resource_conformance_catalog_count(void);
int pqcp_runtime_resource_conformance_catalog_get(
	size_t index,
	struct pqcp_operation_conformance_case *test_case);
int pqcp_runtime_resource_conformance_catalog_audit(void);

size_t pqcp_runtime_recovery_conformance_catalog_count(void);
int pqcp_runtime_recovery_conformance_catalog_get(
	size_t index,
	struct pqcp_operation_conformance_case *test_case);
int pqcp_runtime_recovery_conformance_catalog_audit(void);

size_t pqcp_channel_policy_conformance_catalog_count(void);
int pqcp_channel_policy_conformance_catalog_get(
	size_t index,
	struct pqcp_operation_conformance_case *test_case);
int pqcp_channel_policy_conformance_catalog_audit(void);

size_t pqcp_channel_path_conformance_catalog_count(void);
int pqcp_channel_path_conformance_catalog_get(
	size_t index,
	struct pqcp_operation_conformance_case *test_case);
int pqcp_channel_path_conformance_catalog_audit(void);

size_t pqcp_channel_fault_conformance_catalog_count(void);
int pqcp_channel_fault_conformance_catalog_get(
	size_t index,
	struct pqcp_operation_conformance_case *test_case);
int pqcp_channel_fault_conformance_catalog_audit(void);

#endif /* PQCP_OPERATION_CONFORMANCE_INTERNAL_H_ */
