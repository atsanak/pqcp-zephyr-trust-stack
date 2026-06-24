/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#ifndef PQCP_SOVEREIGN_CONTINUITY_INTERNAL_H_
#define PQCP_SOVEREIGN_CONTINUITY_INTERNAL_H_

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_continuity.h>

#include "edge_security_internal.h"

bool pqcp_sovereign_continuity_text_valid(
	const char *value);
bool pqcp_sovereign_continuity_digest_valid(
	const uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
bool pqcp_sovereign_continuity_digest_equal(
	const uint8_t left[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES],
	const uint8_t right[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
int pqcp_sovereign_continuity_copy_id(
	char destination[PQCP_SOVEREIGN_CONTINUITY_ID_MAX_CHARS],
	const char *source);
int pqcp_sovereign_continuity_digest_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t count,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
int pqcp_sovereign_continuity_digest_objective(
	const struct pqcp_sovereign_continuity_objective *objective,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
int pqcp_sovereign_continuity_digest_point(
	const struct pqcp_sovereign_recovery_point *point,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
int pqcp_sovereign_continuity_digest_lease(
	const struct pqcp_sovereign_authority_lease *lease,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
int pqcp_sovereign_continuity_digest_fence(
	const struct pqcp_sovereign_fence *fence,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
int pqcp_sovereign_continuity_digest_plan(
	const struct pqcp_sovereign_recovery_plan *plan,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
int pqcp_sovereign_continuity_digest_run(
	const struct pqcp_sovereign_recovery_run *run,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
int pqcp_sovereign_continuity_digest_event(
	const struct pqcp_sovereign_continuity_event *event,
	uint8_t digest[PQCP_SOVEREIGN_CONTINUITY_DIGEST_BYTES]);
uint64_t pqcp_sovereign_continuity_add_u64(
	uint64_t left,
	uint64_t right);
uint32_t pqcp_sovereign_continuity_step_mask(
	uint32_t step_count);
uint32_t pqcp_sovereign_continuity_operation_for_step(
	enum pqcp_sovereign_recovery_step_kind kind);
enum pqcp_sovereign_recovery_run_state
pqcp_sovereign_continuity_state_for_step(
	enum pqcp_sovereign_recovery_step_kind kind);
bool pqcp_sovereign_continuity_terminal_state(
	enum pqcp_sovereign_recovery_run_state state);
bool pqcp_sovereign_continuity_mode_valid(
	enum pqcp_sovereign_recovery_mode mode);
bool pqcp_sovereign_continuity_step_kind_valid(
	enum pqcp_sovereign_recovery_step_kind kind);
bool pqcp_sovereign_continuity_transition_valid(
	enum pqcp_sovereign_recovery_run_state current,
	enum pqcp_sovereign_recovery_run_state next);

#endif /* PQCP_SOVEREIGN_CONTINUITY_INTERNAL_H_ */
