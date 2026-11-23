/*
 * SPDX-License-Identifier: MIT
 *
 * Replayable conformance witnesses for runtime and protected-channel policy.
 */

#ifndef PQCP_ZEPHYR_OPERATION_CONFORMANCE_H_
#define PQCP_ZEPHYR_OPERATION_CONFORMANCE_H_

#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/protected_channel_operations.h>
#include <pqcp_zephyr/runtime_operations.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_OPERATION_CONFORMANCE_SCHEMA_VERSION 1U
#define PQCP_OPERATION_CONFORMANCE_CASES_PER_DOMAIN 512U
#define PQCP_OPERATION_CONFORMANCE_DOMAIN_COUNT 6U
#define PQCP_OPERATION_CONFORMANCE_TOTAL_CASES \
	(PQCP_OPERATION_CONFORMANCE_CASES_PER_DOMAIN * \
	 PQCP_OPERATION_CONFORMANCE_DOMAIN_COUNT)

#define PQCP_OPERATION_CONFORMANCE_CASE_ID(domain, condition, operation) \
	((((uint32_t)(domain) & 0xffU) << 24) | \
	 (((uint32_t)(condition) & 0xffU) << 8) | \
	 ((uint32_t)(operation) & 0xffU))

enum pqcp_operation_conformance_domain {
	PQCP_OPERATION_CONFORMANCE_RUNTIME_POLICY = 0,
	PQCP_OPERATION_CONFORMANCE_RUNTIME_RESOURCE,
	PQCP_OPERATION_CONFORMANCE_RUNTIME_RECOVERY,
	PQCP_OPERATION_CONFORMANCE_CHANNEL_POLICY,
	PQCP_OPERATION_CONFORMANCE_CHANNEL_PATH,
	PQCP_OPERATION_CONFORMANCE_CHANNEL_FAULT,
};

struct pqcp_operation_conformance_case {
	uint32_t schema_version;
	uint32_t case_id;
	enum pqcp_operation_conformance_domain domain;
	uint32_t condition;
	uint32_t operation;
	uint32_t decision;
	uint32_t next_state;
	uint32_t parameter0;
	uint32_t parameter1;
	uint32_t parameter2;
	uint32_t reason_mask;
	int32_t expected_error;
};

size_t pqcp_operation_conformance_count(
	enum pqcp_operation_conformance_domain domain);
int pqcp_operation_conformance_get(
	enum pqcp_operation_conformance_domain domain,
	size_t index,
	struct pqcp_operation_conformance_case *test_case);
int pqcp_operation_conformance_find(
	enum pqcp_operation_conformance_domain domain,
	uint32_t condition,
	uint32_t operation,
	struct pqcp_operation_conformance_case *test_case);
int pqcp_operation_conformance_fingerprint(
	enum pqcp_operation_conformance_domain domain,
	uint64_t *fingerprint);
int pqcp_operation_conformance_audit(
	enum pqcp_operation_conformance_domain domain);
int pqcp_operation_conformance_audit_all(void);
const char *pqcp_operation_conformance_domain_str(
	enum pqcp_operation_conformance_domain domain);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_OPERATION_CONFORMANCE_H_ */
