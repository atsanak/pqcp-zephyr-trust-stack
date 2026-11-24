/*
 * SPDX-License-Identifier: MIT
 *
 * Guarded deterministic rollout orchestration for fleet policy modules.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/fleet_policy_store.h>
#include <pqcp_zephyr/fleet_policy_vm.h>

#define ROLLOUT_BAD_WINDOWS_PAUSE 2U
#define ROLLOUT_BAD_WINDOWS_ROLLBACK 3U
#define ROLLOUT_GOOD_WINDOWS_RESUME 2U
#define ROLLOUT_MIN_HYSTERESIS_BPS 25U
#define ROLLOUT_MIN_ISOLATION_BPS 1000U

#define META_BAD_WINDOWS 0U
#define META_GOOD_WINDOWS 1U
#define META_PHASE 2U
#define META_TOKEN 3U
#define META_MANUAL_PAUSE UINT8_C(0x80)
#define META_PHASE_MASK UINT8_C(0x7f)

#define CONTROLLER_META_TOKEN 0U

_Static_assert(
	PQCP_FLEET_POLICY_DIGEST_BYTES ==
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES,
	"policy VM and store digests must remain compatible");

static bool digest_zero(
	const uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_POLICY_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static uint64_t hash_bytes(
	uint64_t hash,
	const uint8_t *bytes,
	size_t length)
{
	for (size_t index = 0U; index < length; ++index) {
		hash ^= bytes[index];
		hash *= UINT64_C(1099511628211);
	}
	return hash;
}

static uint64_t hash_u64(uint64_t hash, uint64_t value)
{
	uint8_t encoded[8];

	for (size_t index = 0U; index < sizeof(encoded); ++index) {
		encoded[index] =
			(uint8_t)(value >> (index * 8U));
	}
	return hash_bytes(hash, encoded, sizeof(encoded));
}

static uint32_t report_token(
	const struct pqcp_fleet_policy_rollout_health_report *report)
{
	uint64_t hash = UINT64_C(1469598103934665603);
	uint32_t token;

	hash = hash_u64(hash, report->campaign_id);
	hash = hash_u64(hash, report->observed_at_ms);
	hash = hash_u64(hash, report->health);
	hash = hash_u64(hash, report->reason_code);
	hash = hash_bytes(
		hash, report->device_digest,
		sizeof(report->device_digest));
	hash = hash_bytes(
		hash, report->module_digest,
		sizeof(report->module_digest));
	token = (uint32_t)(hash ^ (hash >> 32U));
	return token == 0U ? 1U : token;
}

static uint32_t assignment_token(
	uint64_t campaign_id,
	const uint8_t device_digest[PQCP_FLEET_POLICY_DIGEST_BYTES])
{
	uint64_t hash = UINT64_C(1469598103934665603);
	uint32_t token;

	hash = hash_u64(hash, campaign_id);
	hash = hash_bytes(
		hash, device_digest, PQCP_FLEET_POLICY_DIGEST_BYTES);
	token = (uint32_t)(hash ^ (hash >> 32U));
	return token == 0U ? 1U : token;
}

static uint32_t controller_token(
	const struct pqcp_fleet_policy_rollout_controller *controller)
{
	return ((uint32_t)controller->reserved[CONTROLLER_META_TOKEN] << 24U) |
	       ((uint32_t)controller->reserved[
			CONTROLLER_META_TOKEN + 1U] << 16U) |
	       ((uint32_t)controller->reserved[
			CONTROLLER_META_TOKEN + 2U] << 8U) |
	       (uint32_t)controller->reserved[
			CONTROLLER_META_TOKEN + 3U];
}

static void controller_set_token(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint32_t token)
{
	controller->reserved[CONTROLLER_META_TOKEN] =
		(uint8_t)(token >> 24U);
	controller->reserved[CONTROLLER_META_TOKEN + 1U] =
		(uint8_t)(token >> 16U);
	controller->reserved[CONTROLLER_META_TOKEN + 2U] =
		(uint8_t)(token >> 8U);
	controller->reserved[CONTROLLER_META_TOKEN + 3U] =
		(uint8_t)token;
}

static uint32_t metadata_token(
	const struct pqcp_fleet_policy_rollout_campaign *campaign)
{
	return ((uint32_t)campaign->reserved[META_TOKEN] << 24U) |
	       ((uint32_t)campaign->reserved[META_TOKEN + 1U] << 16U) |
	       ((uint32_t)campaign->reserved[META_TOKEN + 2U] << 8U) |
	       (uint32_t)campaign->reserved[META_TOKEN + 3U];
}

static void metadata_set_token(
	struct pqcp_fleet_policy_rollout_campaign *campaign,
	uint32_t token)
{
	campaign->reserved[META_TOKEN] = (uint8_t)(token >> 24U);
	campaign->reserved[META_TOKEN + 1U] =
		(uint8_t)(token >> 16U);
	campaign->reserved[META_TOKEN + 2U] =
		(uint8_t)(token >> 8U);
	campaign->reserved[META_TOKEN + 3U] = (uint8_t)token;
}

static bool state_valid(uint32_t state)
{
	return state >= PQCP_FLEET_POLICY_ROLLOUT_PLANNED &&
	       state <= PQCP_FLEET_POLICY_ROLLOUT_ABORTED;
}

static bool health_valid(uint32_t health)
{
	return health <= PQCP_FLEET_POLICY_ROLLOUT_HEALTH_ROLLED_BACK;
}

static bool terminal(uint32_t state)
{
	return state == PQCP_FLEET_POLICY_ROLLOUT_COMPLETED ||
	       state == PQCP_FLEET_POLICY_ROLLOUT_ABORTED;
}

static uint64_t phase_window_ms(
	const struct pqcp_fleet_policy_rollout_campaign *campaign)
{
	if (campaign->promotion_not_before_ms <=
	    campaign->starts_at_ms) {
		return 1U;
	}
	return campaign->promotion_not_before_ms -
	       campaign->starts_at_ms;
}

static uint64_t saturated_add(uint64_t left, uint64_t right)
{
	return UINT64_MAX - left < right ?
		       UINT64_MAX : left + right;
}

static uint32_t ratio_basis_points(
	uint32_t numerator,
	uint32_t denominator)
{
	if (denominator == 0U) {
		return 0U;
	}
	return (uint32_t)(
		((uint64_t)numerator * PQCP_FLEET_POLICY_BASIS_POINTS) /
		denominator);
}

static uint32_t hysteresis_basis_points(
	const struct pqcp_fleet_policy_rollout_campaign *campaign)
{
	uint32_t hysteresis =
		campaign->maximum_failure_basis_points / 4U;

	return hysteresis < ROLLOUT_MIN_HYSTERESIS_BPS ?
		       ROLLOUT_MIN_HYSTERESIS_BPS : hysteresis;
}

static uint32_t isolation_basis_points(
	const struct pqcp_fleet_policy_rollout_campaign *campaign)
{
	const uint32_t hysteresis = hysteresis_basis_points(campaign);
	uint32_t threshold;

	if (campaign->maximum_failure_basis_points >
	    PQCP_FLEET_POLICY_BASIS_POINTS - hysteresis * 2U) {
		threshold = PQCP_FLEET_POLICY_BASIS_POINTS;
	} else {
		threshold =
			campaign->maximum_failure_basis_points +
			hysteresis * 2U;
	}
	if (threshold < ROLLOUT_MIN_ISOLATION_BPS) {
		threshold = ROLLOUT_MIN_ISOLATION_BPS;
	}
	return threshold;
}

static uint32_t next_cohort(uint32_t cohort_basis_points)
{
	static const uint32_t phases[] = {
		100U, 500U, 1000U, 2500U, 5000U, 10000U,
	};

	for (size_t index = 0U;
	     index < sizeof(phases) / sizeof(phases[0]); ++index) {
		if (cohort_basis_points < phases[index]) {
			return phases[index];
		}
	}
	return PQCP_FLEET_POLICY_BASIS_POINTS;
}

static int campaign_validate(
	const struct pqcp_fleet_policy_rollout_campaign *campaign)
{
	uint64_t completed;

	if (campaign == NULL ||
	    campaign->abi_version != PQCP_FLEET_POLICY_ABI_VERSION ||
	    !state_valid(campaign->state) ||
	    campaign->campaign_id == 0U ||
	    campaign->starts_at_ms == 0U ||
	    campaign->promotion_not_before_ms <=
		    campaign->starts_at_ms ||
	    campaign->deadline_ms <=
		    campaign->promotion_not_before_ms ||
	    campaign->cohort_basis_points == 0U ||
	    campaign->cohort_basis_points >
		    PQCP_FLEET_POLICY_BASIS_POINTS ||
	    campaign->minimum_success_basis_points >
		    PQCP_FLEET_POLICY_BASIS_POINTS ||
	    campaign->maximum_failure_basis_points >
		    PQCP_FLEET_POLICY_BASIS_POINTS ||
	    campaign->minimum_success_basis_points +
		    campaign->maximum_failure_basis_points >
		    PQCP_FLEET_POLICY_BASIS_POINTS ||
	    campaign->minimum_completed_devices == 0U ||
	    digest_zero(campaign->target_module_digest) ||
	    digest_zero(campaign->cohort_seed)) {
		return -EINVAL;
	}
	completed =
		(uint64_t)campaign->healthy_devices +
		campaign->unhealthy_devices +
		campaign->rolled_back_devices;
	if (completed > campaign->assigned_devices ||
	    campaign->pending_devices >
		    campaign->assigned_devices ||
	    completed + campaign->pending_devices !=
		    campaign->assigned_devices) {
		return -EINVAL;
	}
	return 0;
}

static int campaign_index(
	const struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id)
{
	for (size_t index = 0U;
	     index < controller->campaign_capacity; ++index) {
		if (controller->campaigns[index].occupied &&
		    controller->campaigns[index].campaign_id ==
			    campaign_id) {
			return (int)index;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_policy_rollout_controller *controller)
{
	for (size_t index = 0U;
	     index < controller->campaign_capacity; ++index) {
		if (!controller->campaigns[index].occupied) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_fleet_policy_rollout_init(
	struct pqcp_fleet_policy_rollout_controller *controller,
	struct pqcp_fleet_policy_rollout_campaign *campaigns,
	size_t campaign_capacity)
{
	if (controller == NULL || campaigns == NULL ||
	    campaign_capacity == 0U) {
		return -EINVAL;
	}
	memset(controller, 0, sizeof(*controller));
	memset(campaigns, 0, sizeof(*campaigns) * campaign_capacity);
	controller->abi_version = PQCP_FLEET_POLICY_ABI_VERSION;
	controller->campaigns = campaigns;
	controller->campaign_capacity = campaign_capacity;
	controller->initialized = true;
	return 0;
}

static bool campaigns_equal(
	const struct pqcp_fleet_policy_rollout_campaign *left,
	const struct pqcp_fleet_policy_rollout_campaign *right)
{
	return left->campaign_id == right->campaign_id &&
	       left->starts_at_ms == right->starts_at_ms &&
	       left->promotion_not_before_ms ==
		       right->promotion_not_before_ms &&
	       left->deadline_ms == right->deadline_ms &&
	       left->cohort_basis_points ==
		       right->cohort_basis_points &&
	       left->minimum_success_basis_points ==
		       right->minimum_success_basis_points &&
	       left->maximum_failure_basis_points ==
		       right->maximum_failure_basis_points &&
	       left->minimum_completed_devices ==
		       right->minimum_completed_devices &&
	       memcmp(left->target_module_digest,
		      right->target_module_digest,
		      sizeof(left->target_module_digest)) == 0 &&
	       memcmp(left->cohort_seed, right->cohort_seed,
		      sizeof(left->cohort_seed)) == 0;
}

int pqcp_fleet_policy_rollout_create(
	struct pqcp_fleet_policy_rollout_controller *controller,
	const struct pqcp_fleet_policy_rollout_campaign *campaign)
{
	struct pqcp_fleet_policy_rollout_campaign *slot;
	int index;

	if (controller == NULL || !controller->initialized ||
	    controller->abi_version != PQCP_FLEET_POLICY_ABI_VERSION ||
	    campaign_validate(campaign) != 0 ||
	    campaign->state != PQCP_FLEET_POLICY_ROLLOUT_PLANNED ||
	    campaign->assigned_devices != 0U ||
	    campaign->pending_devices != 0U ||
	    campaign->healthy_devices != 0U ||
	    campaign->unhealthy_devices != 0U ||
	    campaign->rolled_back_devices != 0U) {
		return -EINVAL;
	}
	index = campaign_index(controller, campaign->campaign_id);
	if (index >= 0) {
		return campaigns_equal(
			       &controller->campaigns[index], campaign) ?
			       0 : -EEXIST;
	}
	index = free_index(controller);
	if (index < 0) {
		return -ENOSPC;
	}
	slot = &controller->campaigns[index];
	*slot = *campaign;
	memset(slot->reserved, 0, sizeof(slot->reserved));
	slot->occupied = true;
	return 0;
}

int pqcp_fleet_policy_rollout_assign(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id,
	const uint8_t device_digest[PQCP_FLEET_POLICY_DIGEST_BYTES],
	struct pqcp_fleet_policy_rollout_assignment *assignment)
{
	struct pqcp_fleet_policy_rollout_campaign *campaign;
	uint64_t hash = UINT64_C(1469598103934665603);
	uint32_t token;
	int index;

	if (controller == NULL || !controller->initialized ||
	    campaign_id == 0U || device_digest == NULL ||
	    assignment == NULL || digest_zero(device_digest)) {
		return -EINVAL;
	}
	index = campaign_index(controller, campaign_id);
	if (index < 0) {
		return -ENOENT;
	}
	campaign = &controller->campaigns[index];
	memset(assignment, 0, sizeof(*assignment));
	assignment->campaign_id = campaign_id;
	memcpy(
		assignment->target_module_digest,
		campaign->target_module_digest,
		sizeof(assignment->target_module_digest));
	hash = hash_bytes(
		hash, campaign->cohort_seed,
		sizeof(campaign->cohort_seed));
	hash = hash_u64(hash, campaign->campaign_id);
	hash = hash_bytes(
		hash, device_digest,
		PQCP_FLEET_POLICY_DIGEST_BYTES);
	assignment->cohort_value = (uint32_t)(
		hash % PQCP_FLEET_POLICY_BASIS_POINTS);
	assignment->assigned =
		(campaign->state == PQCP_FLEET_POLICY_ROLLOUT_PLANNED ||
		 campaign->state == PQCP_FLEET_POLICY_ROLLOUT_ACTIVE ||
		 (campaign->state ==
			  PQCP_FLEET_POLICY_ROLLOUT_PAUSED &&
		  (campaign->reserved[META_PHASE] &
		   META_MANUAL_PAUSE) == 0U)) &&
		assignment->cohort_value <
			campaign->cohort_basis_points;
	token = assignment_token(campaign_id, device_digest);
	if (controller_token(controller) == token) {
		return 0;
	}
	if (assignment->assigned &&
	    (campaign->assigned_devices == UINT32_MAX ||
	     campaign->pending_devices == UINT32_MAX)) {
		return -EOVERFLOW;
	}
	controller_set_token(controller, token);
	if (controller->assignment_count != UINT64_MAX) {
		controller->assignment_count++;
	}
	if (assignment->assigned) {
		campaign->assigned_devices++;
		campaign->pending_devices++;
	}
	return 0;
}

int pqcp_fleet_policy_rollout_record_health(
	struct pqcp_fleet_policy_rollout_controller *controller,
	const struct pqcp_fleet_policy_rollout_health_report *report)
{
	struct pqcp_fleet_policy_rollout_campaign *campaign;
	uint32_t token;
	int index;

	if (controller == NULL || !controller->initialized ||
	    report == NULL || report->campaign_id == 0U ||
	    report->observed_at_ms == 0U ||
	    !health_valid(report->health) ||
	    digest_zero(report->device_digest) ||
	    digest_zero(report->module_digest)) {
		return -EINVAL;
	}
	index = campaign_index(controller, report->campaign_id);
	if (index < 0) {
		return -ENOENT;
	}
	campaign = &controller->campaigns[index];
	if ((campaign->state !=
		     PQCP_FLEET_POLICY_ROLLOUT_ACTIVE &&
	     campaign->state !=
		     PQCP_FLEET_POLICY_ROLLOUT_PAUSED &&
	     campaign->state !=
		     PQCP_FLEET_POLICY_ROLLOUT_DRAINING) ||
	    report->observed_at_ms < campaign->starts_at_ms ||
	    (report->observed_at_ms > campaign->deadline_ms &&
	     campaign->state !=
		     PQCP_FLEET_POLICY_ROLLOUT_DRAINING) ||
	    memcmp(report->module_digest,
		   campaign->target_module_digest,
		   sizeof(report->module_digest)) != 0) {
		return -EACCES;
	}
	if (campaign->state ==
		    PQCP_FLEET_POLICY_ROLLOUT_DRAINING &&
	    report->health !=
		    PQCP_FLEET_POLICY_ROLLOUT_HEALTH_PENDING &&
	    report->health !=
		    PQCP_FLEET_POLICY_ROLLOUT_HEALTH_ROLLED_BACK) {
		return -EACCES;
	}
	token = report_token(report);
	if (metadata_token(campaign) == token) {
		return 0;
	}
	if (campaign->pending_devices == 0U) {
		return -EALREADY;
	}
	switch (report->health) {
	case PQCP_FLEET_POLICY_ROLLOUT_HEALTH_PENDING:
		return 0;
	case PQCP_FLEET_POLICY_ROLLOUT_HEALTH_HEALTHY:
		if (campaign->healthy_devices == UINT32_MAX) {
			return -EOVERFLOW;
		}
		campaign->healthy_devices++;
		break;
	case PQCP_FLEET_POLICY_ROLLOUT_HEALTH_UNHEALTHY:
		if (campaign->unhealthy_devices == UINT32_MAX) {
			return -EOVERFLOW;
		}
		campaign->unhealthy_devices++;
		break;
	case PQCP_FLEET_POLICY_ROLLOUT_HEALTH_ROLLED_BACK:
		if (campaign->rolled_back_devices == UINT32_MAX) {
			return -EOVERFLOW;
		}
		campaign->rolled_back_devices++;
		break;
	default:
		return -EINVAL;
	}
	campaign->pending_devices--;
	metadata_set_token(campaign, token);
	if (controller->health_report_count != UINT64_MAX) {
		controller->health_report_count++;
	}
	return 0;
}

static void reset_window(
	struct pqcp_fleet_policy_rollout_campaign *campaign,
	uint64_t now_ms,
	uint32_t cohort_basis_points,
	bool advance_phase)
{
	const uint64_t window = phase_window_ms(campaign);

	campaign->starts_at_ms = now_ms;
	campaign->promotion_not_before_ms =
		saturated_add(now_ms, window);
	if (campaign->promotion_not_before_ms >
	    campaign->deadline_ms) {
		campaign->promotion_not_before_ms =
			campaign->deadline_ms;
	}
	campaign->cohort_basis_points = cohort_basis_points;
	campaign->assigned_devices = 0U;
	campaign->pending_devices = 0U;
	campaign->healthy_devices = 0U;
	campaign->unhealthy_devices = 0U;
	campaign->rolled_back_devices = 0U;
	if (advance_phase) {
		const uint8_t phase =
			campaign->reserved[META_PHASE] &
			META_PHASE_MASK;

		campaign->reserved[META_BAD_WINDOWS] = 0U;
		campaign->reserved[META_GOOD_WINDOWS] = 0U;
		campaign->reserved[META_PHASE] =
			phase == META_PHASE_MASK ?
			META_PHASE_MASK : (uint8_t)(phase + 1U);
	}
	metadata_set_token(campaign, 0U);
}

static bool health_window_ready(
	const struct pqcp_fleet_policy_rollout_campaign *campaign)
{
	const uint64_t completed =
		(uint64_t)campaign->healthy_devices +
		campaign->unhealthy_devices +
		campaign->rolled_back_devices;

	return completed >= campaign->minimum_completed_devices &&
	       completed <= UINT32_MAX &&
	       campaign->pending_devices == 0U;
}

static int evaluate_health_window(
	struct pqcp_fleet_policy_rollout_campaign *campaign,
	uint64_t now_ms)
{
	const uint32_t completed =
		campaign->healthy_devices +
		campaign->unhealthy_devices +
		campaign->rolled_back_devices;
	const uint32_t successes = ratio_basis_points(
		campaign->healthy_devices, completed);
	const uint32_t failures = ratio_basis_points(
		campaign->unhealthy_devices +
			campaign->rolled_back_devices,
		completed);
	const uint32_t hysteresis =
		hysteresis_basis_points(campaign);
	const uint32_t healthy_limit =
		campaign->maximum_failure_basis_points > hysteresis ?
		campaign->maximum_failure_basis_points - hysteresis :
		0U;

	if (failures >= isolation_basis_points(campaign)) {
		campaign->state =
			PQCP_FLEET_POLICY_ROLLOUT_ABORTED;
		return 1;
	}
	if (failures > campaign->maximum_failure_basis_points ||
	    successes < campaign->minimum_success_basis_points) {
		campaign->reserved[META_GOOD_WINDOWS] = 0U;
		if (campaign->reserved[META_BAD_WINDOWS] != UINT8_MAX) {
			campaign->reserved[META_BAD_WINDOWS]++;
		}
		if (campaign->reserved[META_BAD_WINDOWS] >=
		    ROLLOUT_BAD_WINDOWS_ROLLBACK) {
			campaign->state =
				PQCP_FLEET_POLICY_ROLLOUT_DRAINING;
		} else if (campaign->reserved[META_BAD_WINDOWS] >=
			   ROLLOUT_BAD_WINDOWS_PAUSE) {
			campaign->state =
				PQCP_FLEET_POLICY_ROLLOUT_PAUSED;
			reset_window(
				campaign, now_ms,
				campaign->cohort_basis_points, false);
		} else {
			reset_window(
				campaign, now_ms,
				campaign->cohort_basis_points, false);
		}
		return 1;
	}
	if (failures > healthy_limit) {
		campaign->reserved[META_GOOD_WINDOWS] = 0U;
		reset_window(
			campaign, now_ms,
			campaign->cohort_basis_points, false);
		return 1;
	}
	if (campaign->reserved[META_GOOD_WINDOWS] != UINT8_MAX) {
		campaign->reserved[META_GOOD_WINDOWS]++;
	}
	if (campaign->reserved[META_BAD_WINDOWS] != 0U) {
		campaign->reserved[META_BAD_WINDOWS]--;
	}
	if (campaign->state == PQCP_FLEET_POLICY_ROLLOUT_PAUSED) {
		if ((campaign->reserved[META_PHASE] &
		     META_MANUAL_PAUSE) != 0U) {
			reset_window(
				campaign, now_ms,
				campaign->cohort_basis_points, false);
			return 1;
		}
		if (campaign->reserved[META_GOOD_WINDOWS] >=
		    ROLLOUT_GOOD_WINDOWS_RESUME) {
			campaign->state =
				PQCP_FLEET_POLICY_ROLLOUT_ACTIVE;
			campaign->reserved[META_BAD_WINDOWS] = 0U;
			campaign->reserved[META_GOOD_WINDOWS] = 0U;
			reset_window(
				campaign, now_ms,
				campaign->cohort_basis_points, false);
			return 1;
		}
		reset_window(
			campaign, now_ms,
			campaign->cohort_basis_points, false);
		return 1;
	}
	if (campaign->cohort_basis_points ==
	    PQCP_FLEET_POLICY_BASIS_POINTS) {
		campaign->state =
			PQCP_FLEET_POLICY_ROLLOUT_COMPLETED;
		return 1;
	}
	reset_window(
		campaign, now_ms,
		next_cohort(campaign->cohort_basis_points), true);
	return 1;
}

static int campaign_tick(
	struct pqcp_fleet_policy_rollout_campaign *campaign,
	uint64_t now_ms)
{
	if (terminal(campaign->state)) {
		return 0;
	}
	if (campaign->state ==
		    PQCP_FLEET_POLICY_ROLLOUT_DRAINING) {
		if (campaign->pending_devices == 0U) {
			campaign->state =
				PQCP_FLEET_POLICY_ROLLOUT_ABORTED;
			return 1;
		}
		return 0;
	}
	if (now_ms >= campaign->deadline_ms) {
		campaign->state =
			campaign->pending_devices == 0U ?
			PQCP_FLEET_POLICY_ROLLOUT_ABORTED :
			PQCP_FLEET_POLICY_ROLLOUT_DRAINING;
		return 1;
	}
	if (campaign->state ==
		    PQCP_FLEET_POLICY_ROLLOUT_PLANNED &&
	    now_ms >= campaign->starts_at_ms) {
		campaign->state =
			PQCP_FLEET_POLICY_ROLLOUT_ACTIVE;
		return 1;
	}
	if ((campaign->state !=
		     PQCP_FLEET_POLICY_ROLLOUT_ACTIVE &&
	     campaign->state !=
		     PQCP_FLEET_POLICY_ROLLOUT_PAUSED) ||
	    now_ms < campaign->promotion_not_before_ms) {
		return 0;
	}
	if (!health_window_ready(campaign)) {
		return 0;
	}
	return evaluate_health_window(campaign, now_ms);
}

int pqcp_fleet_policy_rollout_tick(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t now_ms,
	uint32_t *changed_campaigns)
{
	uint32_t changed = 0U;

	if (controller == NULL || !controller->initialized ||
	    controller->abi_version != PQCP_FLEET_POLICY_ABI_VERSION ||
	    now_ms == 0U || changed_campaigns == NULL) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < controller->campaign_capacity; ++index) {
		struct pqcp_fleet_policy_rollout_campaign *campaign =
			&controller->campaigns[index];
		int result;

		if (!campaign->occupied) {
			continue;
		}
		result = campaign_tick(campaign, now_ms);
		if (result < 0) {
			return result;
		}
		if (result > 0 && changed != UINT32_MAX) {
			changed++;
		}
	}
	*changed_campaigns = changed;
	return 0;
}

int pqcp_fleet_policy_rollout_pause(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id)
{
	struct pqcp_fleet_policy_rollout_campaign *campaign;
	int index;

	if (controller == NULL || !controller->initialized ||
	    campaign_id == 0U) {
		return -EINVAL;
	}
	index = campaign_index(controller, campaign_id);
	if (index < 0) {
		return -ENOENT;
	}
	campaign = &controller->campaigns[index];
	if (campaign->state == PQCP_FLEET_POLICY_ROLLOUT_PAUSED) {
		campaign->reserved[META_PHASE] |= META_MANUAL_PAUSE;
		return 0;
	}
	if (campaign->state != PQCP_FLEET_POLICY_ROLLOUT_ACTIVE) {
		return -EALREADY;
	}
	campaign->state = PQCP_FLEET_POLICY_ROLLOUT_PAUSED;
	campaign->reserved[META_PHASE] |= META_MANUAL_PAUSE;
	return 0;
}

int pqcp_fleet_policy_rollout_resume(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id,
	uint64_t now_ms)
{
	struct pqcp_fleet_policy_rollout_campaign *campaign;
	uint64_t window;
	int index;

	if (controller == NULL || !controller->initialized ||
	    campaign_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	index = campaign_index(controller, campaign_id);
	if (index < 0) {
		return -ENOENT;
	}
	campaign = &controller->campaigns[index];
	if (campaign->state == PQCP_FLEET_POLICY_ROLLOUT_ACTIVE) {
		return 0;
	}
	if (campaign->state != PQCP_FLEET_POLICY_ROLLOUT_PAUSED ||
	    now_ms >= campaign->deadline_ms) {
		return -EALREADY;
	}
	window = phase_window_ms(campaign);
	campaign->state = PQCP_FLEET_POLICY_ROLLOUT_ACTIVE;
	campaign->reserved[META_PHASE] &= META_PHASE_MASK;
	campaign->reserved[META_BAD_WINDOWS] = 0U;
	campaign->reserved[META_GOOD_WINDOWS] = 0U;
	campaign->starts_at_ms = now_ms;
	campaign->promotion_not_before_ms =
		saturated_add(now_ms, window);
	if (campaign->promotion_not_before_ms >
	    campaign->deadline_ms) {
		campaign->promotion_not_before_ms =
			campaign->deadline_ms;
	}
	return 0;
}

int pqcp_fleet_policy_rollout_abort(
	struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id,
	uint32_t reason_code)
{
	struct pqcp_fleet_policy_rollout_campaign *campaign;
	int index;

	if (controller == NULL || !controller->initialized ||
	    campaign_id == 0U || reason_code == 0U) {
		return -EINVAL;
	}
	index = campaign_index(controller, campaign_id);
	if (index < 0) {
		return -ENOENT;
	}
	campaign = &controller->campaigns[index];
	if (campaign->state == PQCP_FLEET_POLICY_ROLLOUT_ABORTED ||
	    campaign->state == PQCP_FLEET_POLICY_ROLLOUT_DRAINING) {
		return 0;
	}
	if (campaign->state == PQCP_FLEET_POLICY_ROLLOUT_COMPLETED) {
		return -EALREADY;
	}
	metadata_set_token(campaign, reason_code);
	campaign->state =
		campaign->pending_devices == 0U ?
		PQCP_FLEET_POLICY_ROLLOUT_ABORTED :
		PQCP_FLEET_POLICY_ROLLOUT_DRAINING;
	return 0;
}

int pqcp_fleet_policy_rollout_get(
	const struct pqcp_fleet_policy_rollout_controller *controller,
	uint64_t campaign_id,
	struct pqcp_fleet_policy_rollout_campaign *campaign)
{
	int index;

	if (controller == NULL || !controller->initialized ||
	    campaign_id == 0U || campaign == NULL) {
		return -EINVAL;
	}
	index = campaign_index(controller, campaign_id);
	if (index < 0) {
		return -ENOENT;
	}
	*campaign = controller->campaigns[index];
	return 0;
}
