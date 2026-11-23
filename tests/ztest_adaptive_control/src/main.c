/*
 * SPDX-License-Identifier: MIT
 */

#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/adaptive_control.h>

static struct pqcp_adaptive_control_plane control;
static struct pqcp_adaptive_control_plane decoded;
static struct pqcp_adaptive_control_result result;
static struct pqcp_adaptive_snapshot snapshot;
static struct pqcp_adaptive_snapshot decoded_snapshot;
static struct pqcp_adaptive_calibration_table calibration;
static uint8_t snapshot_buffer[PQCP_ADAPTIVE_SNAPSHOT_MAX_BYTES];

static const struct pqcp_adaptive_resource_limits limits = {
	.latency_budget_us = 30000U,
	.ram_capacity_bytes = 512U * 1024U,
	.stack_capacity_bytes = 64U * 1024U,
	.heap_capacity_bytes = 128U * 1024U,
	.flash_capacity_bytes = 1024U * 1024U,
	.energy_budget_uj = 20000U,
	.queue_capacity = 32U,
	.maximum_temperature_millic = 85000,
	.minimum_battery_permille = 100U,
	.reserve_permille = 100U,
};

static struct pqcp_adaptive_telemetry_sample sample(uint64_t timestamp)
{
	return (struct pqcp_adaptive_telemetry_sample) {
		.timestamp_ms = timestamp,
		.latency_us = 8200U,
		.cycles = 8200000U,
		.free_ram_bytes = 400000U,
		.stack_used_bytes = 24000U,
		.heap_free_bytes = 100000U,
		.energy_uj = 6200U,
		.queue_depth = 2U,
		.temperature_millic = 43000,
		.battery_permille = 900U,
		.network_loss_permille = 0U,
		.operation_succeeded = true,
	};
}

static void initialize_control(void)
{
	zassert_ok(pqcp_adaptive_control_init(
		&control, "test-device",
		PQCP_ADAPTIVE_POLICY_GATEWAY,
		"hybrid768-65-balanced", 1000U));
}

ZTEST(adaptive_control, test_default_registry_native_contract)
{
	struct pqcp_adaptive_profile_registry registry;

	zassert_ok(pqcp_adaptive_profile_registry_default(&registry));
	zassert_ok(pqcp_adaptive_profile_registry_validate(&registry));
	zassert_equal(registry.count, 9U);
	zassert_equal(registry.native_count, registry.count);
	zassert_equal(registry.production_count, registry.count);
	for (uint32_t index = 0U; index < registry.count; ++index) {
		zassert_true(registry.profiles[index].native_provider);
		zassert_true(registry.profiles[index].production_allowed);
		zassert_not_equal(
			registry.profiles[index].evidence_mask &
			PQCP_DEPLOYMENT_EVIDENCE_PROVIDER, 0U);
	}
}

ZTEST(adaptive_control, test_closed_loop_control_cycle)
{
	initialize_control();
	for (uint32_t index = 0U; index < 5U; ++index) {
		struct pqcp_adaptive_telemetry_sample telemetry =
			sample(2000U + index * 1000U);
		struct pqcp_adaptive_threat_signal threat = {
			.timestamp_ms = telemetry.timestamp_ms,
			.data_sensitivity = 2U,
		};
		struct pqcp_adaptive_health_signal health = {
			.timestamp_ms = telemetry.timestamp_ms,
		};
		struct pqcp_adaptive_control_input input = {
			.now_ms = telemetry.timestamp_ms,
			.telemetry = &telemetry,
			.threat_signal = &threat,
			.resource_limits = &limits,
			.health = &health,
			.required_operation_mask =
				PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS,
			.commit_transition = true,
		};

		zassert_ok(pqcp_adaptive_control_cycle(
			&control, &input, &result));
	}
	zassert_equal(result.status, PQCP_ADAPTIVE_STATUS_PASS);
	zassert_equal(control.cycle_count, 5U);
	zassert_equal(
		strcmp(result.active_profile_id,
		       "hybrid768-65-balanced"), 0);
	zassert_true(result.confidence >= 900U);
	zassert_true(control.events.count >= 6U);
	zassert_ok(pqcp_adaptive_event_log_verify(&control.events));
}

ZTEST(adaptive_control, test_snapshot_roundtrip_and_tamper)
{
	initialize_control();
	for (uint32_t index = 0U; index < 4U; ++index) {
		struct pqcp_adaptive_telemetry_sample telemetry =
			sample(2000U + index * 1000U);
		struct pqcp_adaptive_control_input input = {
			.now_ms = telemetry.timestamp_ms,
			.telemetry = &telemetry,
			.resource_limits = &limits,
			.required_operation_mask =
				PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS,
		};

		zassert_ok(pqcp_adaptive_control_cycle(
			&control, &input, &result));
	}
	zassert_ok(pqcp_adaptive_snapshot_encode(
		&control, snapshot_buffer,
		sizeof(snapshot_buffer), &snapshot));
	zassert_ok(pqcp_adaptive_snapshot_decode(
		snapshot_buffer, snapshot.byte_count,
		&decoded, &decoded_snapshot));
	zassert_equal(
		strcmp(snapshot.snapshot_digest_hex,
		       decoded_snapshot.snapshot_digest_hex), 0);
	zassert_equal(
		strcmp(control.transition.current_profile_id,
		       decoded.transition.current_profile_id), 0);
	snapshot_buffer[snapshot.byte_count / 2U] ^= 0x5aU;
	zassert_not_equal(pqcp_adaptive_snapshot_decode(
		snapshot_buffer, snapshot.byte_count,
		&decoded, &decoded_snapshot), 0);
}

ZTEST(adaptive_control, test_workload_admission)
{
	struct pqcp_adaptive_workload_plan plan;
	struct pqcp_adaptive_workload_item urgent = {
		.request_id = 1U,
		.kind = PQCP_ADAPTIVE_SESSION_ONBOARDING,
		.state = PQCP_ADAPTIVE_WORKLOAD_QUEUED,
		.submitted_at_ms = 2000U,
		.deadline_ms = 6000U,
		.estimated_latency_us = 8000U,
		.estimated_energy_uj = 5000U,
		.priority = 900U,
		.minimum_security_level = 3U,
		.required_evidence_mask =
			PQCP_DEPLOYMENT_EVIDENCE_KAT |
			PQCP_DEPLOYMENT_EVIDENCE_PROVIDER,
		.transition_allowed = true,
	};

	initialize_control();
	control.resources = (struct pqcp_adaptive_resource_assessment) {
		.schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION,
		.status = PQCP_ADAPTIVE_STATUS_PASS,
		.overall_pressure = PQCP_ADAPTIVE_PRESSURE_LOW,
	};
	control.recommendation =
		(struct pqcp_adaptive_recommendation) {
			.schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION,
			.status = PQCP_ADAPTIVE_STATUS_PASS,
		};
	(void)strncpy(
		control.recommendation.recommended_profile_id,
		"hybrid768-65-balanced",
		sizeof(control.recommendation
			       .recommended_profile_id) - 1U);
	zassert_ok(pqcp_adaptive_workload_submit(
		&control.workload, &urgent));
	zassert_ok(pqcp_adaptive_workload_plan(
		&control.workload, &control.registry,
		&control.recommendation, &limits,
		&control.resources, 2000U, &plan));
	zassert_equal(plan.admitted_count, 1U);
	zassert_equal(
		control.workload.items[0].state,
		PQCP_ADAPTIVE_WORKLOAD_ADMITTED);
	zassert_equal(
		strcmp(plan.preferred_profile_id,
		       "hybrid768-65-balanced"), 0);
}

ZTEST(adaptive_control, test_calibration_and_replay_validation)
{
	const struct pqcp_adaptive_profile *profile;
	struct pqcp_adaptive_profile calibrated;

	initialize_control();
	profile = pqcp_adaptive_profile_registry_find(
		&control.registry, "hybrid768-65-balanced");
	zassert_not_null(profile);
	zassert_ok(pqcp_adaptive_calibration_init(&calibration));
	for (uint32_t index = 0U; index < 16U; ++index) {
		struct pqcp_adaptive_calibration_observation observation = {
			.timestamp_ms = 2000U + index,
			.latency_us =
				profile->nominal_latency_us + index,
			.cycles = profile->nominal_cycles + index,
			.ram_bytes = profile->ram_bytes,
			.stack_bytes = profile->stack_bytes,
			.heap_bytes = profile->heap_bytes,
			.energy_uj = profile->energy_uj + index,
			.successful = true,
		};

		(void)strncpy(
			observation.profile_id, profile->profile_id,
			sizeof(observation.profile_id) - 1U);
		zassert_ok(pqcp_adaptive_calibration_observe(
			&calibration, &control.registry,
			&observation));
	}
	zassert_ok(pqcp_adaptive_calibration_validate(
		&calibration, &control.registry));
	zassert_ok(pqcp_adaptive_calibration_apply(
		&calibration, profile, 500U, &calibrated));
	zassert_true(calibrated.nominal_latency_us >=
		     profile->nominal_latency_us);
	calibration.profiles[0].latency_ewma_us++;
	zassert_not_equal(pqcp_adaptive_calibration_validate(
		&calibration, &control.registry), 0);
}

ZTEST(adaptive_control, test_resilience_isolates_profile)
{
	struct pqcp_adaptive_resilience_policy policy;
	struct pqcp_adaptive_health_signal health = {
		.timestamp_ms = 2000U,
		.consecutive_failures = 3U,
		.total_failures = 3U,
		.profile_fault_mask = 1U,
	};

	initialize_control();
	zassert_ok(pqcp_adaptive_resilience_default_policy(&policy));
	zassert_ok(pqcp_adaptive_resilience_evaluate(
		&control.resilience, &policy, &health,
		&control.transition, &control.registry));
	zassert_equal(
		control.resilience.action,
		PQCP_ADAPTIVE_RESILIENCE_ROLLBACK);
	zassert_false(pqcp_adaptive_resilience_profile_allowed(
		&control.resilience, &control.registry,
		control.registry.profiles[0].profile_id));
}

ZTEST_SUITE(adaptive_control, NULL, NULL, NULL, NULL, NULL);
