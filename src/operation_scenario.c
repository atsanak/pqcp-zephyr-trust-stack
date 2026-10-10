/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Generic replay of two-operation runtime and protected-channel scenarios.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include "operation_scenario_internal.h"

#define FNV1A_OFFSET_BASIS UINT64_C(14695981039346656037)
#define FNV1A_PRIME UINT64_C(1099511628211)

typedef size_t (*scenario_count_fn)(void);
typedef int (*scenario_get_fn)(
	size_t index,
	struct pqcp_operation_scenario_case *test_case);
typedef int (*scenario_audit_fn)(void);

struct scenario_catalog {
	scenario_count_fn count;
	scenario_get_fn get;
	scenario_audit_fn audit;
	const char *name;
};

static const struct scenario_catalog catalogs[
	PQCP_OPERATION_SCENARIO_DOMAIN_COUNT] = {
	[PQCP_OPERATION_SCENARIO_RUNTIME_POLICY] = {
		.count = pqcp_runtime_policy_scenario_catalog_count,
		.get = pqcp_runtime_policy_scenario_catalog_get,
		.audit = pqcp_runtime_policy_scenario_catalog_audit,
		.name = "runtime-policy-sequence",
	},
	[PQCP_OPERATION_SCENARIO_RUNTIME_RESOURCE] = {
		.count = pqcp_runtime_resource_scenario_catalog_count,
		.get = pqcp_runtime_resource_scenario_catalog_get,
		.audit = pqcp_runtime_resource_scenario_catalog_audit,
		.name = "runtime-resource-sequence",
	},
	[PQCP_OPERATION_SCENARIO_RUNTIME_RECOVERY] = {
		.count = pqcp_runtime_recovery_scenario_catalog_count,
		.get = pqcp_runtime_recovery_scenario_catalog_get,
		.audit = pqcp_runtime_recovery_scenario_catalog_audit,
		.name = "runtime-recovery-sequence",
	},
	[PQCP_OPERATION_SCENARIO_CHANNEL_POLICY] = {
		.count = pqcp_channel_policy_scenario_catalog_count,
		.get = pqcp_channel_policy_scenario_catalog_get,
		.audit = pqcp_channel_policy_scenario_catalog_audit,
		.name = "channel-policy-sequence",
	},
	[PQCP_OPERATION_SCENARIO_CHANNEL_PATH] = {
		.count = pqcp_channel_path_scenario_catalog_count,
		.get = pqcp_channel_path_scenario_catalog_get,
		.audit = pqcp_channel_path_scenario_catalog_audit,
		.name = "channel-path-sequence",
	},
	[PQCP_OPERATION_SCENARIO_CHANNEL_FAULT] = {
		.count = pqcp_channel_fault_scenario_catalog_count,
		.get = pqcp_channel_fault_scenario_catalog_get,
		.audit = pqcp_channel_fault_scenario_catalog_audit,
		.name = "channel-fault-sequence",
	},
};

static const struct scenario_catalog *catalog_for(
	enum pqcp_operation_scenario_domain domain)
{
	if (domain < PQCP_OPERATION_SCENARIO_RUNTIME_POLICY ||
	    domain >= PQCP_OPERATION_SCENARIO_DOMAIN_COUNT) {
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

static void result_finish(
	struct pqcp_operation_scenario_result *result)
{
	result->aggregate_reason_mask =
		result->first_reason_mask |
		result->second_reason_mask;
	result->terminal_error =
		result->first_error != 0 ?
			result->first_error :
			result->second_error;
}

static int replay_runtime_policy(
	const struct pqcp_operation_scenario_case *test_case,
	struct pqcp_operation_scenario_result *result)
{
	struct pqcp_runtime_policy_decision first;
	struct pqcp_runtime_policy_decision second;
	enum pqcp_runtime_policy_state second_state;
	int ret;

	ret = pqcp_runtime_policy_lookup(
		(enum pqcp_runtime_policy_state)
			test_case->initial_condition,
		(enum pqcp_runtime_command_kind)
			test_case->first_operation,
		&first);
	if (ret != 0) {
		return ret;
	}
	second_state = first.error == 0 ?
		first.next_state :
		(enum pqcp_runtime_policy_state)
			test_case->initial_condition;
	ret = pqcp_runtime_policy_lookup(
		second_state,
		(enum pqcp_runtime_command_kind)
			test_case->second_operation,
		&second);
	if (ret != 0) {
		return ret;
	}
	result->second_condition = second_state;
	result->first_decision = first.action;
	result->first_next_state = first.next_state;
	result->first_reason_mask = first.flags;
	result->first_error = first.error;
	result->second_decision = second.action;
	result->second_next_state = second.next_state;
	result->second_reason_mask = second.flags;
	result->second_error = second.error;
	result_finish(result);
	return 0;
}

static int replay_runtime_resource(
	const struct pqcp_operation_scenario_case *test_case,
	struct pqcp_operation_scenario_result *result)
{
	struct pqcp_runtime_resource_policy_decision first;
	struct pqcp_runtime_resource_policy_decision second;
	enum pqcp_runtime_resource_condition condition =
		(enum pqcp_runtime_resource_condition)
			test_case->initial_condition;
	int ret;

	ret = pqcp_runtime_resource_policy_lookup(
		condition,
		(enum pqcp_runtime_command_kind)
			test_case->first_operation,
		&first);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_resource_policy_lookup(
		condition,
		(enum pqcp_runtime_command_kind)
			test_case->second_operation,
		&second);
	if (ret != 0) {
		return ret;
	}
	result->second_condition = condition;
	result->first_decision = first.disposition;
	result->first_next_state = 0U;
	result->first_reason_mask = first.reason_mask;
	result->first_error = first.error;
	result->second_decision = second.disposition;
	result->second_next_state = 0U;
	result->second_reason_mask = second.reason_mask;
	result->second_error = second.error;
	result_finish(result);
	return 0;
}

static int replay_runtime_recovery(
	const struct pqcp_operation_scenario_case *test_case,
	struct pqcp_operation_scenario_result *result)
{
	struct pqcp_runtime_recovery_policy_decision first;
	struct pqcp_runtime_recovery_policy_decision second;
	enum pqcp_runtime_recovery_condition condition =
		(enum pqcp_runtime_recovery_condition)
			test_case->initial_condition;
	int ret;

	ret = pqcp_runtime_recovery_policy_lookup(
		condition,
		(enum pqcp_runtime_command_kind)
			test_case->first_operation,
		&first);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_recovery_policy_lookup(
		condition,
		(enum pqcp_runtime_command_kind)
			test_case->second_operation,
		&second);
	if (ret != 0) {
		return ret;
	}
	result->second_condition = condition;
	result->first_decision = first.directive;
	result->first_next_state = first.next_state;
	result->first_reason_mask = first.reason_mask;
	result->first_error = first.error;
	result->second_decision = second.directive;
	result->second_next_state = second.next_state;
	result->second_reason_mask = second.reason_mask;
	result->second_error = second.error;
	result_finish(result);
	return 0;
}

static int replay_channel_policy(
	const struct pqcp_operation_scenario_case *test_case,
	struct pqcp_operation_scenario_result *result)
{
	struct pqcp_channel_policy_decision first;
	struct pqcp_channel_policy_decision second;
	enum pqcp_channel_policy_state second_state;
	int ret;

	ret = pqcp_channel_policy_lookup(
		(enum pqcp_channel_policy_state)
			test_case->initial_condition,
		(enum pqcp_channel_control_kind)
			test_case->first_operation,
		&first);
	if (ret != 0) {
		return ret;
	}
	second_state = first.error == 0 ?
		first.next_state :
		(enum pqcp_channel_policy_state)
			test_case->initial_condition;
	ret = pqcp_channel_policy_lookup(
		second_state,
		(enum pqcp_channel_control_kind)
			test_case->second_operation,
		&second);
	if (ret != 0) {
		return ret;
	}
	result->second_condition = second_state;
	result->first_decision = first.action;
	result->first_next_state = first.next_state;
	result->first_reason_mask = first.flags;
	result->first_error = first.error;
	result->second_decision = second.action;
	result->second_next_state = second.next_state;
	result->second_reason_mask = second.flags;
	result->second_error = second.error;
	result_finish(result);
	return 0;
}

static int replay_channel_path(
	const struct pqcp_operation_scenario_case *test_case,
	struct pqcp_operation_scenario_result *result)
{
	struct pqcp_channel_path_policy_decision first;
	struct pqcp_channel_path_policy_decision second;
	enum pqcp_channel_path_condition condition =
		(enum pqcp_channel_path_condition)
			test_case->initial_condition;
	int ret;

	ret = pqcp_channel_path_policy_lookup(
		condition,
		(enum pqcp_channel_control_kind)
			test_case->first_operation,
		&first);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_path_policy_lookup(
		condition,
		(enum pqcp_channel_control_kind)
			test_case->second_operation,
		&second);
	if (ret != 0) {
		return ret;
	}
	result->second_condition = condition;
	result->first_decision = first.disposition;
	result->first_next_state = first.next_state;
	result->first_reason_mask = first.reason_mask;
	result->first_error = first.error;
	result->second_decision = second.disposition;
	result->second_next_state = second.next_state;
	result->second_reason_mask = second.reason_mask;
	result->second_error = second.error;
	result_finish(result);
	return 0;
}

static int replay_channel_fault(
	const struct pqcp_operation_scenario_case *test_case,
	struct pqcp_operation_scenario_result *result)
{
	struct pqcp_channel_fault_policy_decision first;
	struct pqcp_channel_fault_policy_decision second;
	enum pqcp_channel_fault_condition condition =
		(enum pqcp_channel_fault_condition)
			test_case->initial_condition;
	int ret;

	ret = pqcp_channel_fault_policy_lookup(
		condition,
		(enum pqcp_channel_control_kind)
			test_case->first_operation,
		&first);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_fault_policy_lookup(
		condition,
		(enum pqcp_channel_control_kind)
			test_case->second_operation,
		&second);
	if (ret != 0) {
		return ret;
	}
	result->second_condition = condition;
	result->first_decision = first.directive;
	result->first_next_state = first.next_state;
	result->first_reason_mask = first.reason_mask;
	result->first_error = first.error;
	result->second_decision = second.directive;
	result->second_next_state = second.next_state;
	result->second_reason_mask = second.reason_mask;
	result->second_error = second.error;
	result_finish(result);
	return 0;
}

static bool results_equal(
	const struct pqcp_operation_scenario_result *left,
	const struct pqcp_operation_scenario_result *right)
{
	return left->second_condition ==
		       right->second_condition &&
	       left->first_decision ==
		       right->first_decision &&
	       left->first_next_state ==
		       right->first_next_state &&
	       left->first_reason_mask ==
		       right->first_reason_mask &&
	       left->first_error ==
		       right->first_error &&
	       left->second_decision ==
		       right->second_decision &&
	       left->second_next_state ==
		       right->second_next_state &&
	       left->second_reason_mask ==
		       right->second_reason_mask &&
	       left->second_error ==
		       right->second_error &&
	       left->aggregate_reason_mask ==
		       right->aggregate_reason_mask &&
	       left->terminal_error ==
		       right->terminal_error;
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
	const struct pqcp_operation_scenario_case *test_case)
{
	fingerprint = fingerprint_u32(
		fingerprint, test_case->schema_version);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->case_id);
	fingerprint = fingerprint_u32(
		fingerprint, (uint32_t)test_case->domain);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->initial_condition);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->first_operation);
	fingerprint = fingerprint_u32(
		fingerprint, test_case->second_operation);
	fingerprint = fingerprint_u32(
		fingerprint,
		test_case->expected.second_condition);
	fingerprint = fingerprint_u32(
		fingerprint,
		test_case->expected.first_decision);
	fingerprint = fingerprint_u32(
		fingerprint,
		test_case->expected.first_next_state);
	fingerprint = fingerprint_u32(
		fingerprint,
		test_case->expected.first_reason_mask);
	fingerprint = fingerprint_u32(
		fingerprint,
		(uint32_t)test_case->expected.first_error);
	fingerprint = fingerprint_u32(
		fingerprint,
		test_case->expected.second_decision);
	fingerprint = fingerprint_u32(
		fingerprint,
		test_case->expected.second_next_state);
	fingerprint = fingerprint_u32(
		fingerprint,
		test_case->expected.second_reason_mask);
	fingerprint = fingerprint_u32(
		fingerprint,
		(uint32_t)test_case->expected.second_error);
	fingerprint = fingerprint_u32(
		fingerprint,
		test_case->expected.aggregate_reason_mask);
	return fingerprint_u32(
		fingerprint,
		(uint32_t)test_case->expected.terminal_error);
}

size_t pqcp_operation_scenario_count(
	enum pqcp_operation_scenario_domain domain)
{
	const struct scenario_catalog *catalog =
		catalog_for(domain);

	return catalog == NULL ? 0U : catalog->count();
}

int pqcp_operation_scenario_get(
	enum pqcp_operation_scenario_domain domain,
	size_t index,
	struct pqcp_operation_scenario_case *test_case)
{
	const struct scenario_catalog *catalog =
		catalog_for(domain);

	if (catalog == NULL || test_case == NULL) {
		return -EINVAL;
	}
	return catalog->get(index, test_case);
}

int pqcp_operation_scenario_find(
	enum pqcp_operation_scenario_domain domain,
	uint32_t initial_condition,
	uint32_t first_operation,
	uint32_t second_operation,
	struct pqcp_operation_scenario_case *test_case)
{
	const struct scenario_catalog *catalog =
		catalog_for(domain);
	struct pqcp_operation_scenario_case candidate;
	size_t count;

	if (catalog == NULL || test_case == NULL) {
		return -EINVAL;
	}
	count = catalog->count();
	for (size_t index = 0U; index < count; ++index) {
		int ret = catalog->get(index, &candidate);

		if (ret != 0) {
			return ret;
		}
		if (candidate.initial_condition ==
			    initial_condition &&
		    candidate.first_operation ==
			    first_operation &&
		    candidate.second_operation ==
			    second_operation) {
			*test_case = candidate;
			return 0;
		}
	}
	return -ENOENT;
}

int pqcp_operation_scenario_replay(
	const struct pqcp_operation_scenario_case *test_case,
	struct pqcp_operation_scenario_result *result)
{
	if (test_case == NULL || result == NULL ||
	    catalog_for(test_case->domain) == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	switch (test_case->domain) {
	case PQCP_OPERATION_SCENARIO_RUNTIME_POLICY:
		return replay_runtime_policy(test_case, result);
	case PQCP_OPERATION_SCENARIO_RUNTIME_RESOURCE:
		return replay_runtime_resource(test_case, result);
	case PQCP_OPERATION_SCENARIO_RUNTIME_RECOVERY:
		return replay_runtime_recovery(test_case, result);
	case PQCP_OPERATION_SCENARIO_CHANNEL_POLICY:
		return replay_channel_policy(test_case, result);
	case PQCP_OPERATION_SCENARIO_CHANNEL_PATH:
		return replay_channel_path(test_case, result);
	case PQCP_OPERATION_SCENARIO_CHANNEL_FAULT:
		return replay_channel_fault(test_case, result);
	default:
		return -EINVAL;
	}
}

int pqcp_operation_scenario_verify(
	const struct pqcp_operation_scenario_case *test_case)
{
	struct pqcp_operation_scenario_result actual;
	int ret;

	if (test_case == NULL ||
	    test_case->schema_version !=
		    PQCP_OPERATION_SCENARIO_SCHEMA_VERSION ||
	    test_case->case_id !=
		    PQCP_OPERATION_SCENARIO_CASE_ID(
			    test_case->domain,
			    test_case->initial_condition,
			    test_case->first_operation,
			    test_case->second_operation)) {
		return -EINVAL;
	}
	ret = pqcp_operation_scenario_replay(
		test_case, &actual);
	if (ret != 0) {
		return ret;
	}
	return results_equal(
		       &actual, &test_case->expected) ?
		       0 :
		       -EBADMSG;
}

int pqcp_operation_scenario_fingerprint(
	enum pqcp_operation_scenario_domain domain,
	uint64_t *fingerprint)
{
	const struct scenario_catalog *catalog =
		catalog_for(domain);
	struct pqcp_operation_scenario_case test_case;
	uint64_t value = FNV1A_OFFSET_BASIS;
	size_t count;

	if (catalog == NULL || fingerprint == NULL) {
		return -EINVAL;
	}
	count = catalog->count();
	for (size_t index = 0U; index < count; ++index) {
		int ret = catalog->get(index, &test_case);

		if (ret != 0) {
			return ret;
		}
		value = fingerprint_case(value, &test_case);
	}
	*fingerprint = value;
	return 0;
}

int pqcp_operation_scenario_audit(
	enum pqcp_operation_scenario_domain domain)
{
	const struct scenario_catalog *catalog =
		catalog_for(domain);

	if (catalog == NULL) {
		return -EINVAL;
	}
	return catalog->audit();
}

int pqcp_operation_scenario_audit_all(void)
{
	size_t total = 0U;

	for (size_t domain = 0U;
	     domain < ARRAY_SIZE(catalogs); ++domain) {
		int ret = pqcp_operation_scenario_audit(
			(enum pqcp_operation_scenario_domain)
				domain);

		if (ret != 0) {
			return ret;
		}
		total += pqcp_operation_scenario_count(
			(enum pqcp_operation_scenario_domain)
				domain);
	}
	return total == PQCP_OPERATION_SCENARIO_TOTAL_CASES ?
		       0 :
		       -EBADMSG;
}

const char *pqcp_operation_scenario_domain_str(
	enum pqcp_operation_scenario_domain domain)
{
	const struct scenario_catalog *catalog =
		catalog_for(domain);

	return catalog == NULL ? "unknown" : catalog->name;
}
