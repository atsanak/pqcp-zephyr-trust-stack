/*
 * SPDX-License-Identifier: MIT
 *
 * Shared validation for composite operation-plan witness catalogs.
 */

#include <errno.h>

#include <pqcp_zephyr/operation_plan_conformance.h>

int pqcp_operation_plan_conformance_audit_all(void)
{
	int ret;

	ret = pqcp_runtime_operation_plan_conformance_audit();
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_channel_operation_plan_conformance_audit();
	if (ret != 0) {
		return ret;
	}
	if (pqcp_runtime_operation_plan_conformance_count() !=
		    PQCP_RUNTIME_OPERATION_PLAN_CONFORMANCE_CASES ||
	    pqcp_channel_operation_plan_conformance_count() !=
		    PQCP_CHANNEL_OPERATION_PLAN_CONFORMANCE_CASES ||
	    pqcp_runtime_operation_plan_conformance_count() +
			    pqcp_channel_operation_plan_conformance_count() !=
		    PQCP_OPERATION_PLAN_CONFORMANCE_TOTAL_CASES) {
		return -EBADMSG;
	}
	return 0;
}
