/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Generic access to generated operational conformance catalogs.
 */

#include <errno.h>

#include "operation_conformance_internal.h"

#define FNV1A_OFFSET_BASIS UINT64_C(14695981039346656037)
#define FNV1A_PRIME UINT64_C(1099511628211)

typedef size_t (*catalog_count_fn)(void);
typedef int (*catalog_get_fn)(
	size_t index,
	struct pqcp_operation_conformance_case *test_case);
typedef int (*catalog_audit_fn)(void);

struct conformance_catalog {
	catalog_count_fn count;
	catalog_get_fn get;
	catalog_audit_fn audit;
	const char *name;
};

static const struct conformance_catalog catalogs[
	PQCP_OPERATION_CONFORMANCE_DOMAIN_COUNT] = {
	[PQCP_OPERATION_CONFORMANCE_RUNTIME_POLICY] = {
		.count =
			pqcp_runtime_policy_conformance_catalog_count,
		.get =
			pqcp_runtime_policy_conformance_catalog_get,
		.audit =
			pqcp_runtime_policy_conformance_catalog_audit,
		.name = "runtime-policy",
	},
	[PQCP_OPERATION_CONFORMANCE_RUNTIME_RESOURCE] = {
		.count =
			pqcp_runtime_resource_conformance_catalog_count,
		.get =
			pqcp_runtime_resource_conformance_catalog_get,
		.audit =
			pqcp_runtime_resource_conformance_catalog_audit,
		.name = "runtime-resource",
	},
	[PQCP_OPERATION_CONFORMANCE_RUNTIME_RECOVERY] = {
		.count =
			pqcp_runtime_recovery_conformance_catalog_count,
		.get =
			pqcp_runtime_recovery_conformance_catalog_get,
		.audit =
			pqcp_runtime_recovery_conformance_catalog_audit,
		.name = "runtime-recovery",
	},
	[PQCP_OPERATION_CONFORMANCE_CHANNEL_POLICY] = {
		.count =
			pqcp_channel_policy_conformance_catalog_count,
		.get =
			pqcp_channel_policy_conformance_catalog_get,
		.audit =
			pqcp_channel_policy_conformance_catalog_audit,
		.name = "channel-policy",
	},
	[PQCP_OPERATION_CONFORMANCE_CHANNEL_PATH] = {
		.count =
			pqcp_channel_path_conformance_catalog_count,
		.get =
			pqcp_channel_path_conformance_catalog_get,
		.audit =
			pqcp_channel_path_conformance_catalog_audit,
		.name = "channel-path",
	},
	[PQCP_OPERATION_CONFORMANCE_CHANNEL_FAULT] = {
		.count =
			pqcp_channel_fault_conformance_catalog_count,
		.get =
			pqcp_channel_fault_conformance_catalog_get,
		.audit =
			pqcp_channel_fault_conformance_catalog_audit,
		.name = "channel-fault",
	},
};

static const struct conformance_catalog *catalog_for(
	enum pqcp_operation_conformance_domain domain)
{
	if (domain < PQCP_OPERATION_CONFORMANCE_RUNTIME_POLICY ||
	    domain >= PQCP_OPERATION_CONFORMANCE_DOMAIN_COUNT) {
		return NULL;
	}
	if (catalogs[domain].count == NULL ||
	    catalogs[domain].get == NULL ||
	    catalogs[domain].audit == NULL ||
	    catalogs[domain].name == NULL) {
		return NULL;
	}
	return &catalogs[domain];
}

static uint64_t fingerprint_u32(
	uint64_t fingerprint,
	uint32_t value)
{
	for (size_t index = 0U; index < sizeof(value); ++index) {
		fingerprint ^=
			(uint8_t)(value >> (index * 8U));
		fingerprint *= FNV1A_PRIME;
	}
	return fingerprint;
}

static uint64_t fingerprint_case(
	uint64_t fingerprint,
	const struct pqcp_operation_conformance_case *test_case)
{
	fingerprint = fingerprint_u32(
		fingerprint, test_case->schema_version);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->case_id);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)test_case->domain);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->condition);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->operation);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->decision);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->next_state);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->parameter0);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->parameter1);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->parameter2);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->reason_mask);
	return fingerprint_u32(
		fingerprint,
		(uint32_t)test_case->expected_error);
}

size_t pqcp_operation_conformance_count(
	enum pqcp_operation_conformance_domain domain)
{
	const struct conformance_catalog *catalog =
		catalog_for(domain);

	return catalog == NULL ? 0U : catalog->count();
}

int pqcp_operation_conformance_get(
	enum pqcp_operation_conformance_domain domain,
	size_t index,
	struct pqcp_operation_conformance_case *test_case)
{
	const struct conformance_catalog *catalog =
		catalog_for(domain);

	if (catalog == NULL || test_case == NULL) {
		return -EINVAL;
	}
	return catalog->get(index, test_case);
}

int pqcp_operation_conformance_find(
	enum pqcp_operation_conformance_domain domain,
	uint32_t condition,
	uint32_t operation,
	struct pqcp_operation_conformance_case *test_case)
{
	const struct conformance_catalog *catalog =
		catalog_for(domain);
	struct pqcp_operation_conformance_case candidate;
	size_t count;
	int ret;

	if (catalog == NULL || test_case == NULL) {
		return -EINVAL;
	}
	count = catalog->count();
	for (size_t index = 0U; index < count; ++index) {
		ret = catalog->get(index, &candidate);
		if (ret != 0) {
			return ret;
		}
		if (candidate.condition == condition &&
		    candidate.operation == operation) {
			*test_case = candidate;
			return 0;
		}
	}
	return -ENOENT;
}

int pqcp_operation_conformance_fingerprint(
	enum pqcp_operation_conformance_domain domain,
	uint64_t *fingerprint)
{
	const struct conformance_catalog *catalog =
		catalog_for(domain);
	struct pqcp_operation_conformance_case test_case;
	uint64_t value = FNV1A_OFFSET_BASIS;
	size_t count;
	int ret;

	if (catalog == NULL || fingerprint == NULL) {
		return -EINVAL;
	}
	count = catalog->count();
	for (size_t index = 0U; index < count; ++index) {
		ret = catalog->get(index, &test_case);
		if (ret != 0) {
			return ret;
		}
		value = fingerprint_case(value, &test_case);
	}
	*fingerprint = value;
	return 0;
}

int pqcp_operation_conformance_audit(
	enum pqcp_operation_conformance_domain domain)
{
	const struct conformance_catalog *catalog =
		catalog_for(domain);

	if (catalog == NULL) {
		return -EINVAL;
	}
	return catalog->audit();
}

int pqcp_operation_conformance_audit_all(void)
{
	size_t total = 0U;
	int ret;

	for (size_t domain = 0U;
	     domain < ARRAY_SIZE(catalogs); ++domain) {
		ret = pqcp_operation_conformance_audit(
			(enum pqcp_operation_conformance_domain)
				domain);
		if (ret != 0) {
			return ret;
		}
		total += pqcp_operation_conformance_count(
			(enum pqcp_operation_conformance_domain)
				domain);
	}
	return total ==
			       PQCP_OPERATION_CONFORMANCE_TOTAL_CASES ?
		       0 :
		       -EBADMSG;
}

const char *pqcp_operation_conformance_domain_str(
	enum pqcp_operation_conformance_domain domain)
{
	const struct conformance_catalog *catalog =
		catalog_for(domain);

	return catalog == NULL ? "unknown" : catalog->name;
}
