/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#ifndef PQCP_OPERATION_TRANSITION_INTERNAL_H_
#define PQCP_OPERATION_TRANSITION_INTERNAL_H_

#include <stddef.h>

#include <pqcp_zephyr/operation_transition.h>

size_t pqcp_runtime_transition_catalog_count(void);
int pqcp_runtime_transition_catalog_get(
	size_t index,
	struct pqcp_runtime_transition_trace *trace);

size_t pqcp_channel_transition_catalog_count(void);
int pqcp_channel_transition_catalog_get(
	size_t index,
	struct pqcp_channel_transition_trace *trace);

#endif /* PQCP_OPERATION_TRANSITION_INTERNAL_H_ */
