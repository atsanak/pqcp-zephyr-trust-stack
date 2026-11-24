/*
 * SPDX-License-Identifier: MIT
 *
 * Sliding replay window for protected-channel records.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel.h>

int pqcp_channel_replay_reset(
	struct pqcp_channel_replay_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}
	memset(state, 0, sizeof(*state));
	return 0;
}

int pqcp_channel_replay_accept(
	struct pqcp_channel_replay_state *state,
	uint64_t sequence)
{
	uint64_t distance;
	uint64_t bit;

	if (state == NULL) {
		return -EINVAL;
	}
	if (!state->initialized) {
		state->highest_sequence = sequence;
		state->bitmap = 1U;
		state->initialized = true;
		return 0;
	}
	if (sequence > state->highest_sequence) {
		distance = sequence - state->highest_sequence;
		if (distance >= PQCP_CHANNEL_REPLAY_WINDOW) {
			state->bitmap = 1U;
		} else {
			state->bitmap =
				(state->bitmap << distance) | 1U;
		}
		state->highest_sequence = sequence;
		return 0;
	}
	distance = state->highest_sequence - sequence;
	if (distance >= PQCP_CHANNEL_REPLAY_WINDOW) {
		return -ERANGE;
	}
	bit = UINT64_C(1) << distance;
	if ((state->bitmap & bit) != 0U) {
		return -EALREADY;
	}
	state->bitmap |= bit;
	return 0;
}
