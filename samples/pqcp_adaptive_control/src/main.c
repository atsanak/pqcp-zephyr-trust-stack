/*
 * SPDX-License-Identifier: MIT
 *
 * End-to-end adaptive PQC deployment control-plane demonstration.
 */

#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

static struct pqcp_adaptive_control_plane control;
static struct pqcp_adaptive_control_plane replayed_control;
static struct pqcp_adaptive_control_result cycle_result;
static struct pqcp_adaptive_calibration_table calibration;
static struct pqcp_adaptive_workload_plan workload_plan;
static struct pqcp_adaptive_snapshot snapshot;
static struct pqcp_adaptive_snapshot replayed_snapshot;
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
	.minimum_battery_permille = 150U,
	.reserve_permille = 100U,
};

static struct pqcp_adaptive_telemetry_sample telemetry_sample(
	uint64_t timestamp_ms,
	uint32_t cycle)
{
	struct pqcp_adaptive_telemetry_sample sample = {
		.timestamp_ms = timestamp_ms,
		.latency_us = 7900U + cycle * 70U,
		.cycles = 7900000U + cycle * 70000U,
		.free_ram_bytes = 410000U - cycle * 512U,
		.stack_used_bytes = 24000U + cycle * 64U,
		.heap_free_bytes = 100000U - cycle * 256U,
		.energy_uj = 5800U + cycle * 35U,
		.queue_depth = 2U + cycle / 3U,
		.temperature_millic = 42000 + (int32_t)cycle * 120,
		.battery_permille = 900U - cycle,
		.network_loss_permille = cycle,
		.handshake_failures = 0U,
		.auth_failures = 0U,
		.operation_succeeded = true,
	};

	return sample;
}

static struct pqcp_adaptive_threat_signal threat_signal(
	uint64_t timestamp_ms,
	uint32_t cycle)
{
	struct pqcp_adaptive_threat_signal signal = {
		.timestamp_ms = timestamp_ms,
		.signal_mask = cycle >= 6U ?
			PQCP_ADAPTIVE_THREAT_PUBLIC_NETWORK |
			PQCP_ADAPTIVE_THREAT_SENSITIVE_DATA :
			0U,
		.auth_failures = cycle == 7U ? 1U : 0U,
		.replay_events = 0U,
		.signature_failures = 0U,
		.rollback_attempts = 0U,
		.remote_advisory_level = cycle >= 6U ? 1U : 0U,
		.fleet_divergence_percent = 0U,
		.data_sensitivity = cycle >= 6U ? 4U : 2U,
		.physical_tamper = false,
		.public_network = cycle >= 6U,
	};

	return signal;
}

static struct pqcp_adaptive_health_signal health_signal(
	uint64_t timestamp_ms)
{
	struct pqcp_adaptive_health_signal signal = {
		.timestamp_ms = timestamp_ms,
		.consecutive_failures = 0U,
		.total_failures = 0U,
		.digest_failures = 0U,
		.replay_failures = 0U,
		.transition_failures = 0U,
		.session_failures = 0U,
		.watchdog_resets = 0U,
		.profile_fault_mask = 0U,
		.state_corrupt = false,
		.backend_unavailable = false,
		.entropy_degraded = false,
	};

	return signal;
}

static int run_control_cycles(uint64_t start_ms)
{
	for (uint32_t cycle = 0U; cycle < 8U; ++cycle) {
		const uint64_t now_ms = start_ms + cycle * 1000U;
		struct pqcp_adaptive_telemetry_sample telemetry =
			telemetry_sample(now_ms, cycle);
		struct pqcp_adaptive_threat_signal threat =
			threat_signal(now_ms, cycle);
		struct pqcp_adaptive_health_signal health =
			health_signal(now_ms);
		struct pqcp_adaptive_control_input input = {
			.now_ms = now_ms,
			.telemetry = &telemetry,
			.threat_signal = &threat,
			.resource_limits = &limits,
			.authorization = NULL,
			.fleet = NULL,
			.health = &health,
			.required_operation_mask =
				PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
				PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING,
			.reason = PQCP_ADAPTIVE_REASON_NONE,
			.force_recommendation = false,
			.commit_transition = true,
		};
		int ret = pqcp_adaptive_control_cycle(
			&control, &input, &cycle_result);

		if (ret != 0 &&
		    cycle_result.status != PQCP_ADAPTIVE_STATUS_FAIL) {
			return ret;
		}
		ret = pqcp_adaptive_control_emit(
			&control, &cycle_result);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

static int submit_workload(uint64_t now_ms)
{
	const struct pqcp_adaptive_workload_item items[] = {
		{
			.request_id = 1001U,
			.kind = PQCP_ADAPTIVE_SESSION_ONBOARDING,
			.state = PQCP_ADAPTIVE_WORKLOAD_QUEUED,
			.submitted_at_ms = now_ms,
			.deadline_ms = now_ms + 5000U,
			.estimated_latency_us = 8500U,
			.estimated_energy_uj = 6200U,
			.payload_bytes = 4096U,
			.priority = 900U,
			.minimum_security_level = 3U,
			.required_evidence_mask =
				PQCP_DEPLOYMENT_EVIDENCE_KAT |
				PQCP_DEPLOYMENT_EVIDENCE_PROVIDER,
			.transition_allowed = true,
			.batchable = false,
		},
		{
			.request_id = 1002U,
			.kind = PQCP_ADAPTIVE_SESSION_TELEMETRY,
			.state = PQCP_ADAPTIVE_WORKLOAD_QUEUED,
			.submitted_at_ms = now_ms,
			.deadline_ms = now_ms + 15000U,
			.estimated_latency_us = 4000U,
			.estimated_energy_uj = 2200U,
			.payload_bytes = 768U,
			.priority = 500U,
			.minimum_security_level = 3U,
			.required_evidence_mask =
				PQCP_DEPLOYMENT_EVIDENCE_KAT |
				PQCP_DEPLOYMENT_EVIDENCE_PROVIDER,
			.transition_allowed = true,
			.batchable = true,
		},
	};

	for (size_t index = 0U;
	     index < sizeof(items) / sizeof(items[0]); ++index) {
		const int ret = pqcp_adaptive_workload_submit(
			&control.workload, &items[index]);

		if (ret != 0) {
			return ret;
		}
	}
	if (pqcp_adaptive_workload_plan(
		    &control.workload, &control.registry,
		    &control.recommendation, &limits,
		    &control.resources, now_ms,
		    &workload_plan) != 0) {
		return -1;
	}
	return pqcp_adaptive_workload_emit(
		&control.workload, &workload_plan);
}

static int calibrate_active_profile(uint64_t now_ms)
{
	const char *profile_id =
		control.transition.current_profile_id;
	const struct pqcp_adaptive_profile *profile =
		pqcp_adaptive_profile_registry_find(
			&control.registry, profile_id);

	if (profile == NULL ||
	    pqcp_adaptive_calibration_init(&calibration) != 0) {
		return -1;
	}
	for (uint32_t index = 0U; index < 8U; ++index) {
		struct pqcp_adaptive_calibration_observation observation = {
			.timestamp_ms = now_ms + index,
			.latency_us =
				profile->nominal_latency_us +
				index * 10U,
			.cycles =
				profile->nominal_cycles +
				index * 1000U,
			.ram_bytes = profile->ram_bytes,
			.stack_bytes = profile->stack_bytes,
			.heap_bytes = profile->heap_bytes,
			.energy_uj = profile->energy_uj + index * 5U,
			.successful = true,
		};

		(void)strncpy(
			observation.profile_id, profile_id,
			sizeof(observation.profile_id) - 1U);
		if (pqcp_adaptive_calibration_observe(
			    &calibration, &control.registry,
			    &observation) != 0) {
			return -1;
		}
	}
	if (pqcp_adaptive_calibration_validate(
		    &calibration, &control.registry) != 0) {
		return -1;
	}
	return pqcp_adaptive_calibration_emit(&calibration);
}

static int snapshot_roundtrip(void)
{
	int ret = pqcp_adaptive_snapshot_encode(
		&control, snapshot_buffer,
		sizeof(snapshot_buffer), &snapshot);

	if (ret != 0) {
		return ret;
	}
	if ((ret = pqcp_adaptive_snapshot_emit(&snapshot)) != 0) {
		return ret;
	}
	ret = pqcp_adaptive_snapshot_decode(
		snapshot_buffer, snapshot.byte_count,
		&replayed_control, &replayed_snapshot);
	if (ret != 0) {
		return ret;
	}
	if (strcmp(snapshot.snapshot_digest_hex,
		   replayed_snapshot.snapshot_digest_hex) != 0 ||
	    strcmp(control.device_id,
		   replayed_control.device_id) != 0 ||
	    strcmp(control.transition.current_profile_id,
		   replayed_control.transition.current_profile_id) != 0) {
		return -1;
	}
	printk("PQCP_ADAPTIVE_SNAPSHOT_REPLAY schema=%u status=PASS bytes=%u records=%u digest=%s\n",
	       replayed_snapshot.schema_version,
	       replayed_snapshot.byte_count,
	       replayed_snapshot.record_count,
	       replayed_snapshot.snapshot_digest_hex);
	return 0;
}

int main(void)
{
	const uint64_t start_ms = 1000U;
	int ret;

	ret = pqcp_adaptive_control_init(
		&control, "demo-gateway",
		PQCP_ADAPTIVE_POLICY_GATEWAY,
		"hybrid768-65-balanced", start_ms);
	if (ret == 0) {
		ret = run_control_cycles(start_ms + 1000U);
	}
	if (ret == 0) {
		ret = submit_workload(start_ms + 10000U);
	}
	if (ret == 0) {
		ret = calibrate_active_profile(start_ms + 11000U);
	}
	if (ret == 0) {
		ret = snapshot_roundtrip();
	}
	printk("PQCP_ADAPTIVE_DEMO status=%s active=%s recommended=%s cycles=%u events=%u sessions=%u workload=%u digest=%s\n",
	       ret == 0 ? "PASS" : "FAIL",
	       control.transition.current_profile_id,
	       control.recommendation.recommended_profile_id,
	       control.cycle_count,
	       control.events.count,
	       control.sessions.active_count,
	       control.workload.count,
	       control.state_digest_hex);
	return ret;
}
