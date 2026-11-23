/*
 * SPDX-License-Identifier: MIT
 *
 * Resource headroom and profile-fit model for adaptive PQC deployment.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_RESOURCE_DOMAIN UINT64_C(0x4144505245534f55)

static bool limits_valid(
	const struct pqcp_adaptive_resource_limits *limits)
{
	if (limits == NULL || limits->reserve_permille > 900U ||
	    limits->minimum_battery_permille > 1000U ||
	    limits->maximum_temperature_millic < -100000 ||
	    limits->maximum_temperature_millic > 200000) {
		return false;
	}
	if (limits->ram_capacity_bytes == 0U ||
	    limits->stack_capacity_bytes == 0U ||
	    limits->flash_capacity_bytes == 0U) {
		return false;
	}
	return true;
}

static uint64_t reserve_amount(
	uint64_t capacity, uint32_t reserve_permille)
{
	return pqcp_adaptive_internal_saturating_mul_u64(
		capacity, reserve_permille) / 1000U;
}

static uint64_t subtract_floor(uint64_t available, uint64_t reserved)
{
	return available > reserved ? available - reserved : 0U;
}

static uint32_t headroom_permille(
	uint64_t headroom, uint64_t capacity)
{
	if (capacity == 0U) {
		return 1000U;
	}
	return pqcp_adaptive_internal_permille(headroom, capacity);
}

static enum pqcp_adaptive_pressure pressure_from_headroom(
	uint32_t headroom_permille_value)
{
	if (headroom_permille_value <= 20U) {
		return PQCP_ADAPTIVE_PRESSURE_CRITICAL;
	}
	if (headroom_permille_value <= 100U) {
		return PQCP_ADAPTIVE_PRESSURE_HIGH;
	}
	if (headroom_permille_value <= 250U) {
		return PQCP_ADAPTIVE_PRESSURE_MODERATE;
	}
	if (headroom_permille_value <= 500U) {
		return PQCP_ADAPTIVE_PRESSURE_LOW;
	}
	return PQCP_ADAPTIVE_PRESSURE_NONE;
}

static enum pqcp_adaptive_pressure maximum_pressure(
	enum pqcp_adaptive_pressure left,
	enum pqcp_adaptive_pressure right)
{
	return left > right ? left : right;
}

static void update_minimum(
	uint32_t value, uint32_t *minimum, bool *seen)
{
	if (!*seen || value < *minimum) {
		*minimum = value;
		*seen = true;
	}
}

static void assess_latency(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment,
	uint32_t *minimum,
	bool *seen)
{
	uint64_t used;
	uint32_t headroom;

	if (limits->latency_budget_us == 0U) {
		return;
	}
	assessment->available_mask |= PQCP_ADAPTIVE_RESOURCE_LATENCY;
	used = telemetry != NULL ? telemetry->latency.p99 : 0U;
	if (forecast != NULL &&
	    forecast->predicted_latency_us > used) {
		used = forecast->predicted_latency_us;
	}
	assessment->latency_headroom_us =
		subtract_floor(limits->latency_budget_us, used);
	headroom = headroom_permille(
		assessment->latency_headroom_us,
		limits->latency_budget_us);
	update_minimum(headroom, minimum, seen);
	assessment->overall_pressure = maximum_pressure(
		assessment->overall_pressure,
		pressure_from_headroom(headroom));
	if (used >= limits->latency_budget_us) {
		assessment->exhausted_mask |=
			PQCP_ADAPTIVE_RESOURCE_LATENCY;
	}
}

static void assess_ram(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment,
	uint32_t *minimum,
	bool *seen)
{
	uint64_t free_bytes;
	uint64_t reserved;
	uint32_t headroom;

	assessment->available_mask |= PQCP_ADAPTIVE_RESOURCE_RAM;
	free_bytes = telemetry != NULL ?
		telemetry->minimum_free_ram_bytes :
		limits->ram_capacity_bytes;
	if (forecast != NULL &&
	    forecast->predicted_free_ram_bytes < free_bytes) {
		free_bytes = forecast->predicted_free_ram_bytes;
	}
	reserved = reserve_amount(
		limits->ram_capacity_bytes, limits->reserve_permille);
	assessment->ram_headroom_bytes =
		subtract_floor(free_bytes, reserved);
	headroom = headroom_permille(
		assessment->ram_headroom_bytes,
		limits->ram_capacity_bytes);
	update_minimum(headroom, minimum, seen);
	assessment->overall_pressure = maximum_pressure(
		assessment->overall_pressure,
		pressure_from_headroom(headroom));
	if (free_bytes <= reserved) {
		assessment->exhausted_mask |=
			PQCP_ADAPTIVE_RESOURCE_RAM;
	}
}

static void assess_stack(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment,
	uint32_t *minimum,
	bool *seen)
{
	uint64_t used;
	uint64_t reserved;
	uint64_t usable;
	uint32_t headroom;

	assessment->available_mask |= PQCP_ADAPTIVE_RESOURCE_STACK;
	used = telemetry != NULL ?
		telemetry->maximum_stack_used_bytes : 0U;
	if (forecast != NULL &&
	    forecast->predicted_stack_used_bytes > used) {
		used = forecast->predicted_stack_used_bytes;
	}
	reserved = reserve_amount(
		limits->stack_capacity_bytes, limits->reserve_permille);
	usable = subtract_floor(
		limits->stack_capacity_bytes, reserved);
	assessment->stack_headroom_bytes =
		subtract_floor(usable, used);
	headroom = headroom_permille(
		assessment->stack_headroom_bytes,
		limits->stack_capacity_bytes);
	update_minimum(headroom, minimum, seen);
	assessment->overall_pressure = maximum_pressure(
		assessment->overall_pressure,
		pressure_from_headroom(headroom));
	if (used >= usable) {
		assessment->exhausted_mask |=
			PQCP_ADAPTIVE_RESOURCE_STACK;
	}
}

static void assess_heap(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment,
	uint32_t *minimum,
	bool *seen)
{
	uint64_t free_bytes;
	uint64_t reserved;
	uint32_t headroom;

	if (limits->heap_capacity_bytes == 0U) {
		return;
	}
	assessment->available_mask |= PQCP_ADAPTIVE_RESOURCE_HEAP;
	free_bytes = telemetry != NULL ?
		telemetry->minimum_heap_free_bytes :
		limits->heap_capacity_bytes;
	if (forecast != NULL &&
	    forecast->predicted_heap_free_bytes < free_bytes) {
		free_bytes = forecast->predicted_heap_free_bytes;
	}
	reserved = reserve_amount(
		limits->heap_capacity_bytes, limits->reserve_permille);
	assessment->heap_headroom_bytes =
		subtract_floor(free_bytes, reserved);
	headroom = headroom_permille(
		assessment->heap_headroom_bytes,
		limits->heap_capacity_bytes);
	update_minimum(headroom, minimum, seen);
	assessment->overall_pressure = maximum_pressure(
		assessment->overall_pressure,
		pressure_from_headroom(headroom));
	if (free_bytes <= reserved) {
		assessment->exhausted_mask |=
			PQCP_ADAPTIVE_RESOURCE_HEAP;
	}
}

static void assess_flash(
	const struct pqcp_adaptive_resource_limits *limits,
	struct pqcp_adaptive_resource_assessment *assessment,
	uint32_t *minimum,
	bool *seen)
{
	uint64_t reserved;
	uint32_t headroom;

	assessment->available_mask |= PQCP_ADAPTIVE_RESOURCE_FLASH;
	reserved = reserve_amount(
		limits->flash_capacity_bytes, limits->reserve_permille);
	assessment->flash_headroom_bytes =
		subtract_floor(limits->flash_capacity_bytes, reserved);
	headroom = headroom_permille(
		assessment->flash_headroom_bytes,
		limits->flash_capacity_bytes);
	update_minimum(headroom, minimum, seen);
}

static void assess_energy(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment,
	uint32_t *minimum,
	bool *seen)
{
	uint64_t used;
	uint32_t headroom;

	if (limits->energy_budget_uj == 0U) {
		return;
	}
	assessment->available_mask |= PQCP_ADAPTIVE_RESOURCE_ENERGY;
	used = telemetry != NULL ? telemetry->energy.p99 : 0U;
	if (forecast != NULL &&
	    forecast->predicted_energy_uj > used) {
		used = forecast->predicted_energy_uj;
	}
	assessment->energy_headroom_uj =
		subtract_floor(limits->energy_budget_uj, used);
	headroom = headroom_permille(
		assessment->energy_headroom_uj,
		limits->energy_budget_uj);
	update_minimum(headroom, minimum, seen);
	assessment->overall_pressure = maximum_pressure(
		assessment->overall_pressure,
		pressure_from_headroom(headroom));
	if (used >= limits->energy_budget_uj) {
		assessment->exhausted_mask |=
			PQCP_ADAPTIVE_RESOURCE_ENERGY;
	}
}

static void assess_queue(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment,
	uint32_t *minimum,
	bool *seen)
{
	uint32_t used;
	uint32_t headroom;

	if (limits->queue_capacity == 0U) {
		return;
	}
	assessment->available_mask |= PQCP_ADAPTIVE_RESOURCE_QUEUE;
	used = telemetry != NULL ?
		telemetry->maximum_queue_depth : 0U;
	if (forecast != NULL &&
	    forecast->predicted_queue_depth > used) {
		used = forecast->predicted_queue_depth;
	}
	assessment->queue_headroom =
		used >= limits->queue_capacity ?
		0U : limits->queue_capacity - used;
	headroom = pqcp_adaptive_internal_permille(
		assessment->queue_headroom, limits->queue_capacity);
	update_minimum(headroom, minimum, seen);
	assessment->overall_pressure = maximum_pressure(
		assessment->overall_pressure,
		pressure_from_headroom(headroom));
	if (used >= limits->queue_capacity) {
		assessment->exhausted_mask |=
			PQCP_ADAPTIVE_RESOURCE_QUEUE;
	}
}

static void assess_thermal(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment,
	uint32_t *minimum,
	bool *seen)
{
	int32_t used;
	int64_t range;
	uint32_t headroom;

	if (limits->maximum_temperature_millic == 0) {
		return;
	}
	assessment->available_mask |= PQCP_ADAPTIVE_RESOURCE_THERMAL;
	used = telemetry != NULL ?
		telemetry->maximum_temperature_millic : 0;
	if (forecast != NULL &&
	    forecast->predicted_temperature_millic > used) {
		used = forecast->predicted_temperature_millic;
	}
	assessment->thermal_headroom_millic =
		used >= limits->maximum_temperature_millic ?
		0 : limits->maximum_temperature_millic - used;
	range = (int64_t)limits->maximum_temperature_millic + 100000;
	headroom = range <= 0 ?
		0U :
		pqcp_adaptive_internal_permille(
			(uint64_t)assessment->thermal_headroom_millic,
			(uint64_t)range);
	update_minimum(headroom, minimum, seen);
	assessment->overall_pressure = maximum_pressure(
		assessment->overall_pressure,
		pressure_from_headroom(headroom));
	if (used >= limits->maximum_temperature_millic) {
		assessment->exhausted_mask |=
			PQCP_ADAPTIVE_RESOURCE_THERMAL;
	}
}

static void assess_battery(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment,
	uint32_t *minimum,
	bool *seen)
{
	uint32_t battery;
	uint32_t headroom;

	if (limits->minimum_battery_permille == 0U) {
		return;
	}
	assessment->available_mask |= PQCP_ADAPTIVE_RESOURCE_BATTERY;
	battery = telemetry != NULL ?
		telemetry->average_battery_permille : 1000U;
	if (forecast != NULL &&
	    forecast->predicted_battery_permille < battery) {
		battery = forecast->predicted_battery_permille;
	}
	assessment->battery_headroom_permille =
		battery > limits->minimum_battery_permille ?
		battery - limits->minimum_battery_permille : 0U;
	headroom = assessment->battery_headroom_permille;
	update_minimum(headroom, minimum, seen);
	assessment->overall_pressure = maximum_pressure(
		assessment->overall_pressure,
		pressure_from_headroom(headroom));
	if (battery <= limits->minimum_battery_permille) {
		assessment->exhausted_mask |=
			PQCP_ADAPTIVE_RESOURCE_BATTERY;
	}
}

static int resource_digest(
	const struct pqcp_adaptive_resource_assessment *assessment,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_RESOURCE_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)assessment->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->available_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->exhausted_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)assessment->overall_pressure);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, assessment->latency_headroom_us);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, assessment->ram_headroom_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, assessment->stack_headroom_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, assessment->heap_headroom_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, assessment->flash_headroom_bytes);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, assessment->energy_headroom_uj);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->queue_headroom);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)assessment->thermal_headroom_millic);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->battery_headroom_permille);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->minimum_headroom_permille);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

int pqcp_adaptive_resource_assess(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_resource_assessment *assessment)
{
	uint32_t minimum = 1000U;
	bool seen = false;

	if (!limits_valid(limits) || assessment == NULL) {
		return -EINVAL;
	}
	if (telemetry != NULL &&
	    telemetry->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	if (forecast != NULL &&
	    forecast->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	memset(assessment, 0, sizeof(*assessment));
	assessment->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	assess_latency(
		limits, telemetry, forecast, assessment, &minimum, &seen);
	assess_ram(
		limits, telemetry, forecast, assessment, &minimum, &seen);
	assess_stack(
		limits, telemetry, forecast, assessment, &minimum, &seen);
	assess_heap(
		limits, telemetry, forecast, assessment, &minimum, &seen);
	assess_flash(limits, assessment, &minimum, &seen);
	assess_energy(
		limits, telemetry, forecast, assessment, &minimum, &seen);
	assess_queue(
		limits, telemetry, forecast, assessment, &minimum, &seen);
	assess_thermal(
		limits, telemetry, forecast, assessment, &minimum, &seen);
	assess_battery(
		limits, telemetry, forecast, assessment, &minimum, &seen);
	assessment->minimum_headroom_permille =
		seen ? minimum : 0U;
	if (assessment->exhausted_mask != 0U ||
	    assessment->overall_pressure ==
		    PQCP_ADAPTIVE_PRESSURE_CRITICAL) {
		assessment->status = PQCP_ADAPTIVE_STATUS_FAIL;
	} else if (assessment->overall_pressure >=
		   PQCP_ADAPTIVE_PRESSURE_MODERATE) {
		assessment->status = PQCP_ADAPTIVE_STATUS_WARN;
	} else {
		assessment->status = PQCP_ADAPTIVE_STATUS_PASS;
	}
	return resource_digest(
		assessment, assessment->resource_digest_hex);
}

static void fit_metric(
	uint64_t required,
	uint64_t available,
	uint32_t blocker,
	uint32_t *blocker_mask,
	uint32_t *minimum,
	bool *seen)
{
	uint32_t headroom;

	if (required == 0U || available == 0U) {
		return;
	}
	if (required > available) {
		*blocker_mask |= blocker;
		update_minimum(0U, minimum, seen);
		return;
	}
	headroom = pqcp_adaptive_internal_permille(
		available - required, available);
	update_minimum(headroom, minimum, seen);
}

int pqcp_adaptive_resource_profile_fits(
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_resource_assessment *assessment,
	const struct pqcp_adaptive_profile *profile,
	uint32_t *blocker_mask,
	uint32_t *minimum_headroom_permille)
{
	uint32_t blockers = 0U;
	uint32_t minimum = 1000U;
	bool seen = false;
	uint64_t usable_ram;
	uint64_t usable_stack;
	uint64_t usable_heap;
	uint64_t usable_flash;

	if (!limits_valid(limits) || assessment == NULL ||
	    assessment->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_profile_valid(profile) ||
	    blocker_mask == NULL || minimum_headroom_permille == NULL) {
		return -EINVAL;
	}
	usable_ram = assessment->ram_headroom_bytes;
	usable_stack = assessment->stack_headroom_bytes;
	usable_heap = assessment->heap_headroom_bytes;
	usable_flash = assessment->flash_headroom_bytes;
	fit_metric(profile->nominal_latency_us,
		   limits->latency_budget_us,
		   PQCP_ADAPTIVE_BLOCK_LATENCY,
		   &blockers, &minimum, &seen);
	fit_metric(profile->ram_bytes, usable_ram,
		   PQCP_ADAPTIVE_BLOCK_RAM,
		   &blockers, &minimum, &seen);
	fit_metric(profile->stack_bytes, usable_stack,
		   PQCP_ADAPTIVE_BLOCK_STACK,
		   &blockers, &minimum, &seen);
	if (limits->heap_capacity_bytes != 0U) {
		fit_metric(profile->heap_bytes, usable_heap,
			   PQCP_ADAPTIVE_BLOCK_HEAP,
			   &blockers, &minimum, &seen);
	}
	fit_metric(profile->flash_bytes, usable_flash,
		   PQCP_ADAPTIVE_BLOCK_FLASH,
		   &blockers, &minimum, &seen);
	if (limits->energy_budget_uj != 0U) {
		fit_metric(profile->energy_uj,
			   limits->energy_budget_uj,
			   PQCP_ADAPTIVE_BLOCK_ENERGY,
			   &blockers, &minimum, &seen);
	}
	*blocker_mask = blockers;
	*minimum_headroom_permille = seen ? minimum : 0U;
	return blockers == 0U ? 0 : -ENOSPC;
}

int pqcp_adaptive_resource_emit(
	const struct pqcp_adaptive_resource_assessment *assessment)
{
	if (assessment == NULL ||
	    assessment->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_status_valid(assessment->status) ||
	    !pqcp_adaptive_internal_pressure_valid(
		    assessment->overall_pressure)) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_RESOURCE schema=%u status=%s pressure=%s available=0x%08x exhausted=0x%08x warnings=0x%08x latency_headroom_us=%llu ram_headroom=%llu stack_headroom=%llu heap_headroom=%llu flash_headroom=%llu energy_headroom_uj=%llu queue_headroom=%u thermal_headroom_millic=%d battery_headroom=%u minimum_headroom_permille=%u digest=%s\n",
	       assessment->schema_version,
	       pqcp_adaptive_status_str(assessment->status),
	       pqcp_adaptive_pressure_str(
		       assessment->overall_pressure),
	       assessment->available_mask,
	       assessment->exhausted_mask,
	       assessment->warning_mask,
	       (unsigned long long)assessment->latency_headroom_us,
	       (unsigned long long)assessment->ram_headroom_bytes,
	       (unsigned long long)assessment->stack_headroom_bytes,
	       (unsigned long long)assessment->heap_headroom_bytes,
	       (unsigned long long)assessment->flash_headroom_bytes,
	       (unsigned long long)assessment->energy_headroom_uj,
	       assessment->queue_headroom,
	       assessment->thermal_headroom_millic,
	       assessment->battery_headroom_permille,
	       assessment->minimum_headroom_permille,
	       assessment->resource_digest_hex);
	return 0;
}
