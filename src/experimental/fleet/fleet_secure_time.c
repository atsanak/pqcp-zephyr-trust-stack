/*
 * SPDX-License-Identifier: MIT
 *
 * Monotonic secure-time fusion with bounded uncertainty and holdover.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_resilience.h>

static bool source_valid(enum pqcp_fleet_time_source source)
{
	return source > PQCP_FLEET_TIME_SOURCE_NONE &&
	       source <= PQCP_FLEET_TIME_SOURCE_SECURE_ELEMENT;
}

static bool quality_valid(enum pqcp_fleet_time_quality quality)
{
	return quality >= PQCP_FLEET_TIME_HOLDOVER &&
	       quality <= PQCP_FLEET_TIME_ATTESTED;
}

static bool digest_zero(
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static int anchor_validate(
	const struct pqcp_fleet_time_anchor *anchor)
{
	if (anchor == NULL ||
	    anchor->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    !source_valid(anchor->source) ||
	    !quality_valid(anchor->quality) ||
	    anchor->local_monotonic_ms == 0U ||
	    anchor->reference_time_ms == 0U ||
	    anchor->valid_until_monotonic_ms <=
		    anchor->local_monotonic_ms ||
	    anchor->maximum_drift_ppm > 100000U ||
	    anchor->priority == 0U ||
	    digest_zero(anchor->source_digest)) {
		return -EINVAL;
	}
	return 0;
}

static int source_index(
	const struct pqcp_fleet_secure_time *time,
	enum pqcp_fleet_time_source source)
{
	for (size_t index = 0U; index < time->capacity; ++index) {
		if (time->anchors[index].occupied &&
		    time->anchors[index].source == source) {
			return (int)index;
		}
	}
	return -1;
}

static int replacement_index(
	const struct pqcp_fleet_secure_time *time)
{
	int selected = -1;
	uint32_t lowest_priority = UINT32_MAX;
	enum pqcp_fleet_time_quality lowest_quality =
		PQCP_FLEET_TIME_ATTESTED;

	for (size_t index = 0U; index < time->capacity; ++index) {
		const struct pqcp_fleet_time_anchor *anchor =
			&time->anchors[index];

		if (!anchor->occupied) {
			return (int)index;
		}
		if (anchor->quality < lowest_quality ||
		    (anchor->quality == lowest_quality &&
		     anchor->priority < lowest_priority)) {
			lowest_quality = anchor->quality;
			lowest_priority = anchor->priority;
			selected = (int)index;
		}
	}
	return selected;
}

static int anchor_estimate(
	const struct pqcp_fleet_time_anchor *anchor,
	uint64_t local_monotonic_ms,
	uint64_t *estimate,
	uint64_t *uncertainty,
	bool *holdover)
{
	uint64_t elapsed;
	uint64_t drift;

	if (local_monotonic_ms < anchor->local_monotonic_ms) {
		return -ERANGE;
	}
	elapsed = local_monotonic_ms -
		  anchor->local_monotonic_ms;
	if (UINT64_MAX - anchor->reference_time_ms < elapsed) {
		return -EOVERFLOW;
	}
	*estimate = anchor->reference_time_ms + elapsed;
	if (anchor->maximum_drift_ppm != 0U &&
	    elapsed > UINT64_MAX /
		    anchor->maximum_drift_ppm) {
		drift = UINT64_MAX;
	} else {
		drift = elapsed * anchor->maximum_drift_ppm /
			1000000U;
	}
	if (drift == UINT64_MAX ||
	    UINT64_MAX - anchor->uncertainty_ms < drift) {
		*uncertainty = UINT64_MAX;
	} else {
		*uncertainty =
			anchor->uncertainty_ms + drift;
	}
	*holdover =
		local_monotonic_ms >
			anchor->valid_until_monotonic_ms ||
		anchor->quality == PQCP_FLEET_TIME_HOLDOVER;
	return 0;
}

int pqcp_fleet_secure_time_init(
	struct pqcp_fleet_secure_time *time,
	struct pqcp_fleet_time_anchor *anchors,
	size_t capacity,
	uint64_t rollback_tolerance_ms,
	uint64_t maximum_uncertainty_ms)
{
	if (time == NULL || anchors == NULL || capacity == 0U ||
	    rollback_tolerance_ms == 0U ||
	    maximum_uncertainty_ms == 0U) {
		return -EINVAL;
	}
	memset(time, 0, sizeof(*time));
	memset(anchors, 0, sizeof(*anchors) * capacity);
	time->schema_version =
		PQCP_FLEET_RESILIENCE_SCHEMA_VERSION;
	time->anchors = anchors;
	time->capacity = capacity;
	time->rollback_tolerance_ms =
		rollback_tolerance_ms;
	time->maximum_uncertainty_ms =
		maximum_uncertainty_ms;
	k_mutex_init(&time->lock);
	time->initialized = true;
	return 0;
}

int pqcp_fleet_secure_time_update(
	struct pqcp_fleet_secure_time *time,
	const struct pqcp_fleet_time_anchor *anchor)
{
	uint64_t estimated;
	uint64_t uncertainty;
	bool holdover;
	int index;
	int ret;

	if (time == NULL || !time->initialized ||
	    anchor_validate(anchor) != 0 ||
	    anchor->uncertainty_ms >
		    time->maximum_uncertainty_ms) {
		return -EINVAL;
	}
	ret = anchor_estimate(
		anchor, anchor->local_monotonic_ms,
		&estimated, &uncertainty, &holdover);
	if (ret != 0 || holdover) {
		return ret != 0 ? ret : -ESTALE;
	}
	ret = k_mutex_lock(&time->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (time->last_returned_ms != 0U &&
	    estimated + time->rollback_tolerance_ms <
		    time->last_returned_ms) {
		time->rejected_count++;
		(void)k_mutex_unlock(&time->lock);
		return -ESTALE;
	}
	index = source_index(time, anchor->source);
	if (index >= 0) {
		const struct pqcp_fleet_time_anchor *previous =
			&time->anchors[index];

		if (anchor->local_monotonic_ms <=
		    previous->local_monotonic_ms) {
			time->rejected_count++;
			(void)k_mutex_unlock(&time->lock);
			return -EALREADY;
		}
	} else {
		index = replacement_index(time);
	}
	if (index < 0) {
		time->rejected_count++;
		(void)k_mutex_unlock(&time->lock);
		return -ENOSPC;
	}
	time->anchors[index] = *anchor;
	time->anchors[index].occupied = true;
	time->update_count++;
	(void)k_mutex_unlock(&time->lock);
	return 0;
}

static bool better_anchor(
	const struct pqcp_fleet_time_anchor *candidate,
	uint64_t candidate_uncertainty,
	bool candidate_holdover,
	const struct pqcp_fleet_time_anchor *selected,
	uint64_t selected_uncertainty,
	bool selected_holdover)
{
	if (selected == NULL) {
		return true;
	}
	if (candidate_holdover != selected_holdover) {
		return !candidate_holdover;
	}
	if (candidate->quality != selected->quality) {
		return candidate->quality > selected->quality;
	}
	if (candidate_uncertainty != selected_uncertainty) {
		return candidate_uncertainty <
		       selected_uncertainty;
	}
	return candidate->priority > selected->priority;
}

int pqcp_fleet_secure_time_now(
	struct pqcp_fleet_secure_time *time,
	uint64_t local_monotonic_ms,
	struct pqcp_fleet_time_reading *reading)
{
	const struct pqcp_fleet_time_anchor *selected = NULL;
	uint64_t selected_time = 0U;
	uint64_t selected_uncertainty = UINT64_MAX;
	bool selected_holdover = true;
	int ret;

	if (time == NULL || !time->initialized ||
	    local_monotonic_ms == 0U || reading == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&time->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < time->capacity; ++index) {
		const struct pqcp_fleet_time_anchor *anchor =
			&time->anchors[index];
		uint64_t estimate;
		uint64_t uncertainty;
		bool holdover;

		if (!anchor->occupied ||
		    anchor_estimate(
			    anchor, local_monotonic_ms,
			    &estimate, &uncertainty,
			    &holdover) != 0 ||
		    uncertainty > time->maximum_uncertainty_ms) {
			continue;
		}
		if (better_anchor(
			    anchor, uncertainty, holdover,
			    selected, selected_uncertainty,
			    selected_holdover)) {
			selected = anchor;
			selected_time = estimate;
			selected_uncertainty = uncertainty;
			selected_holdover = holdover;
		}
	}
	if (selected == NULL) {
		(void)k_mutex_unlock(&time->lock);
		return -ENODATA;
	}
	if (selected_time < time->last_returned_ms) {
		if (time->last_returned_ms - selected_time >
		    time->rollback_tolerance_ms) {
			time->rejected_count++;
			(void)k_mutex_unlock(&time->lock);
			return -ESTALE;
		}
		selected_time = time->last_returned_ms;
	}
	time->last_returned_ms = selected_time;
	memset(reading, 0, sizeof(*reading));
	reading->time_ms = selected_time;
	reading->uncertainty_ms = selected_uncertainty;
	reading->source = selected->source;
	reading->quality = selected_holdover ?
		PQCP_FLEET_TIME_HOLDOVER : selected->quality;
	reading->holdover = selected_holdover;
	(void)k_mutex_unlock(&time->lock);
	return 0;
}

int pqcp_fleet_secure_time_expire(
	struct pqcp_fleet_secure_time *time,
	uint64_t local_monotonic_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret;

	if (time == NULL || !time->initialized ||
	    local_monotonic_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&time->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < time->capacity; ++index) {
		struct pqcp_fleet_time_anchor *anchor =
			&time->anchors[index];
		uint64_t elapsed;
		uint64_t drift;

		if (!anchor->occupied ||
		    local_monotonic_ms <=
			    anchor->valid_until_monotonic_ms) {
			continue;
		}
		elapsed = local_monotonic_ms -
			  anchor->valid_until_monotonic_ms;
		if (elapsed > UINT64_MAX /
		    (anchor->maximum_drift_ppm + 1U)) {
			drift = UINT64_MAX;
		} else {
			drift = elapsed *
				(anchor->maximum_drift_ppm + 1U) /
				1000000U;
		}
		if (drift == UINT64_MAX ||
		    anchor->uncertainty_ms + drift >
			    time->maximum_uncertainty_ms) {
			pqcp_runtime_secure_zero(
				anchor, sizeof(*anchor));
			expired++;
		}
	}
	(void)k_mutex_unlock(&time->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_fleet_secure_time_audit(
	struct pqcp_fleet_secure_time *time)
{
	int ret;

	if (time == NULL || !time->initialized ||
	    time->schema_version !=
		    PQCP_FLEET_RESILIENCE_SCHEMA_VERSION ||
	    time->anchors == NULL || time->capacity == 0U ||
	    time->rollback_tolerance_ms == 0U ||
	    time->maximum_uncertainty_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&time->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < time->capacity; ++index) {
		const struct pqcp_fleet_time_anchor *anchor =
			&time->anchors[index];

		if (!anchor->occupied) {
			continue;
		}
		if (anchor_validate(anchor) != 0 ||
		    anchor->uncertainty_ms >
			    time->maximum_uncertainty_ms) {
			(void)k_mutex_unlock(&time->lock);
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < time->capacity; ++other) {
			if (time->anchors[other].occupied &&
			    time->anchors[other].source ==
				    anchor->source) {
				(void)k_mutex_unlock(&time->lock);
				return -EEXIST;
			}
		}
	}
	(void)k_mutex_unlock(&time->lock);
	return 0;
}
