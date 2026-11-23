/*
 * SPDX-License-Identifier: MIT
 *
 * The model vtables, one per checked module. Module names are part of the
 * marker contract: principal, session, credential, policy.
 */

#ifndef MODEL_MODULES_H_
#define MODEL_MODULES_H_

#include "model_harness.h"

#define MODEL_SEEDS 64U
#define MODEL_MODULE_COUNT 4U

/* Stable module indices: they seed the per-module trace streams. */
enum {
	MODEL_INDEX_PRINCIPAL,
	MODEL_INDEX_SESSION,
	MODEL_INDEX_CREDENTIAL,
	MODEL_INDEX_POLICY,
};

extern const struct model_vtable model_principal_vt;
extern const struct model_vtable model_session_vt;
extern const struct model_vtable model_credential_vt;
extern const struct model_vtable model_policy_vt;

/* Run one module for MODEL_SEEDS traces; fails the calling test on a violation. */
void model_run_module(const struct model_vtable *vt, uint32_t index);

#endif /* MODEL_MODULES_H_ */
