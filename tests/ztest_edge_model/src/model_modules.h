/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * The model vtables, one per checked module. Module names are part of the
 * marker contract: principal, session, credential, policy.
 */

#ifndef MODEL_MODULES_H_
#define MODEL_MODULES_H_

#include "model_harness.h"

#define MODEL_SEEDS 64U
#define MODEL_MODULE_COUNT 4U

/* Run one module for MODEL_SEEDS traces; fails the calling test on a violation. */
void model_run_module(const struct model_vtable *vt, uint32_t index);

#endif /* MODEL_MODULES_H_ */
