/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Correlated fleet risk scoring with decay and deterministic response actions.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>

static bool signal_valid(enum pqcp_fleet_risk_signal signal)
{
	return signal >= PQCP_FLEET_RISK_AUTH_FAILURE &&
	       signal < PQCP_FLEET_RISK_SIGNAL_COUNT;
}

static bool action_valid(enum pqcp_fleet_risk_action action)
{
	return action >= PQCP_FLEET_RISK_ACTION_NONE &&
	       action <= PQCP_FLEET_RISK_ACTION_QUARANTINE;
}

static int policy_validate(
	const struct pqcp_fleet_risk_policy *policy)
{
	if (policy == NULL || policy->maximum_score == 0U ||
	    policy->observe_threshold == 0U ||
	    policy->observe_threshold >
		    policy->throttle_threshold ||
	    policy->throttle_threshold >
		    policy->reauthenticate_threshold ||
	    policy->reauthenticate_threshold >
		    policy->recovery_threshold ||
	    policy->recovery_threshold >
		    policy->quarantine_threshold ||
	    policy->quarantine_threshold >
		    policy->maximum_score ||
	    policy->decay_points == 0U ||
	    policy->decay_interval_ms == 0U ||
	    policy->correlation_window_ms == 0U) {
		return -EINVAL;
	}
	for (size_t signal = 0U;
	     signal < PQCP_FLEET_RISK_SIGNAL_COUNT; ++signal) {
		if (policy->signal_weight[signal] == 0U ||
		    policy->signal_weight[signal] >
			    policy->maximum_score) {
			return -EINVAL;
		}
	}
	return 0;
}

static enum pqcp_fleet_risk_action action_for_score(
	const struct pqcp_fleet_risk_policy *policy,
	uint32_t score)
{
	if (score >= policy->quarantine_threshold) {
		return PQCP_FLEET_RISK_ACTION_QUARANTINE;
	}
	if (score >= policy->recovery_threshold) {
		return PQCP_FLEET_RISK_ACTION_RECOVERY;
	}
	if (score >= policy->reauthenticate_threshold) {
		return PQCP_FLEET_RISK_ACTION_REAUTHENTICATE;
	}
	if (score >= policy->throttle_threshold) {
		return PQCP_FLEET_RISK_ACTION_THROTTLE;
	}
	if (score >= policy->observe_threshold) {
		return PQCP_FLEET_RISK_ACTION_OBSERVE;
	}
	return PQCP_FLEET_RISK_ACTION_NONE;
}

static void apply_decay(
	struct pqcp_fleet_risk_engine *engine,
	uint64_t now_ms)
{
	uint64_t intervals;
	uint64_t decay;

	if (now_ms < engine->last_decay_ms) {
		engine->last_decay_ms = now_ms;
		return;
	}
	intervals =
		(now_ms - engine->last_decay_ms) /
		engine->policy.decay_interval_ms;
	if (intervals == 0U) {
		return;
	}
	if (intervals > UINT64_MAX /
	    engine->policy.decay_points) {
		decay = UINT64_MAX;
	} else {
		decay = intervals * engine->policy.decay_points;
	}
	if (decay >= engine->score) {
		engine->score = 0U;
	} else {
		engine->score -= (uint32_t)decay;
	}
	if (intervals > UINT64_MAX /
	    engine->policy.decay_interval_ms) {
		engine->last_decay_ms = now_ms;
	} else {
		engine->last_decay_ms +=
			intervals *
			engine->policy.decay_interval_ms;
	}
	engine->action =
		action_for_score(&engine->policy, engine->score);
}

int pqcp_fleet_risk_engine_init(
	struct pqcp_fleet_risk_engine *engine,
	const struct pqcp_fleet_risk_policy *policy,
	uint64_t now_ms)
{
	if (engine == NULL || policy_validate(policy) != 0 ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	memset(engine, 0, sizeof(*engine));
	engine->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	engine->policy = *policy;
	engine->last_decay_ms = now_ms;
	engine->action = PQCP_FLEET_RISK_ACTION_NONE;
	k_mutex_init(&engine->lock);
	engine->initialized = true;
	return 0;
}

static uint32_t correlation_multiplier(
	const struct pqcp_fleet_risk_signal_state *state)
{
	uint32_t multiplier = 1U + state->consecutive / 4U;

	return multiplier > 8U ? 8U : multiplier;
}

static uint32_t saturating_add(
	uint32_t current,
	uint64_t increment,
	uint32_t maximum)
{
	if (increment >= maximum ||
	    current >= maximum - (uint32_t)increment) {
		return maximum;
	}
	return current + (uint32_t)increment;
}

int pqcp_fleet_risk_report(
	struct pqcp_fleet_risk_engine *engine,
	enum pqcp_fleet_risk_signal signal,
	uint32_t magnitude,
	uint64_t now_ms,
	uint32_t *score,
	enum pqcp_fleet_risk_action *action)
{
	struct pqcp_fleet_risk_signal_state *state;
	uint64_t increment;
	int ret;

	if (engine == NULL || !engine->initialized ||
	    !signal_valid(signal) || magnitude == 0U ||
	    now_ms == 0U || score == NULL || action == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&engine->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	apply_decay(engine, now_ms);
	state = &engine->signals[signal];
	if (state->window_started_ms == 0U ||
	    now_ms < state->window_started_ms ||
	    now_ms - state->window_started_ms >
		    engine->policy.correlation_window_ms) {
		state->window_started_ms = now_ms;
		state->occurrences = 0U;
		state->consecutive = 0U;
	}
	state->last_seen_ms = now_ms;
	if (state->occurrences != UINT32_MAX) {
		state->occurrences++;
	}
	if (state->consecutive != UINT32_MAX) {
		state->consecutive++;
	}
	if (state->consecutive > state->peak_consecutive) {
		state->peak_consecutive = state->consecutive;
	}
	increment =
		(uint64_t)engine->policy.signal_weight[signal] *
		magnitude * correlation_multiplier(state);
	engine->score = saturating_add(
		engine->score, increment,
		engine->policy.maximum_score);
	if (engine->score > engine->peak_score) {
		engine->peak_score = engine->score;
	}
	if (engine->event_count != UINT64_MAX) {
		engine->event_count++;
	}
	engine->action =
		action_for_score(&engine->policy, engine->score);
	*score = engine->score;
	*action = engine->action;
	(void)k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_fleet_risk_success(
	struct pqcp_fleet_risk_engine *engine,
	enum pqcp_fleet_risk_signal signal,
	uint64_t now_ms)
{
	struct pqcp_fleet_risk_signal_state *state;
	uint32_t credit;
	int ret;

	if (engine == NULL || !engine->initialized ||
	    !signal_valid(signal) || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&engine->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	apply_decay(engine, now_ms);
	state = &engine->signals[signal];
	state->consecutive = 0U;
	credit = engine->policy.signal_weight[signal] / 2U;
	if (credit == 0U) {
		credit = 1U;
	}
	if (credit >= engine->score) {
		engine->score = 0U;
	} else {
		engine->score -= credit;
	}
	engine->action =
		action_for_score(&engine->policy, engine->score);
	(void)k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_fleet_risk_tick(
	struct pqcp_fleet_risk_engine *engine,
	uint64_t now_ms,
	uint32_t *score,
	enum pqcp_fleet_risk_action *action)
{
	int ret;

	if (engine == NULL || !engine->initialized ||
	    now_ms == 0U || score == NULL || action == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&engine->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	apply_decay(engine, now_ms);
	for (size_t signal = 0U;
	     signal < PQCP_FLEET_RISK_SIGNAL_COUNT; ++signal) {
		struct pqcp_fleet_risk_signal_state *state =
			&engine->signals[signal];

		if (state->window_started_ms != 0U &&
		    now_ms >= state->window_started_ms &&
		    now_ms - state->window_started_ms >
			    engine->policy.correlation_window_ms) {
			state->window_started_ms = now_ms;
			state->occurrences = 0U;
			state->consecutive = 0U;
		}
	}
	*score = engine->score;
	*action = engine->action;
	(void)k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_fleet_risk_reset(
	struct pqcp_fleet_risk_engine *engine,
	uint64_t now_ms)
{
	int ret;

	if (engine == NULL || !engine->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&engine->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	memset(engine->signals, 0, sizeof(engine->signals));
	engine->score = 0U;
	engine->last_decay_ms = now_ms;
	engine->action = PQCP_FLEET_RISK_ACTION_NONE;
	(void)k_mutex_unlock(&engine->lock);
	return 0;
}

int pqcp_fleet_risk_audit(
	struct pqcp_fleet_risk_engine *engine)
{
	int ret;

	if (engine == NULL || !engine->initialized ||
	    engine->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    policy_validate(&engine->policy) != 0 ||
	    engine->score > engine->policy.maximum_score ||
	    engine->peak_score < engine->score ||
	    !action_valid(engine->action) ||
	    engine->action != action_for_score(
		    &engine->policy, engine->score) ||
	    engine->last_decay_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&engine->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t signal = 0U;
	     signal < PQCP_FLEET_RISK_SIGNAL_COUNT; ++signal) {
		const struct pqcp_fleet_risk_signal_state *state =
			&engine->signals[signal];

		if (state->peak_consecutive <
			    state->consecutive ||
		    (state->occurrences == 0U &&
		     state->consecutive != 0U) ||
		    (state->last_seen_ms != 0U &&
		     state->window_started_ms == 0U)) {
			(void)k_mutex_unlock(&engine->lock);
			return -EBADMSG;
		}
	}
	(void)k_mutex_unlock(&engine->lock);
	return 0;
}
