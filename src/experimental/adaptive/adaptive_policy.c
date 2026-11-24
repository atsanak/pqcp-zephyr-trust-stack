/*
 * SPDX-License-Identifier: MIT
 *
 * Policy profiles for adaptive PQC deployment.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define POLICY_OVERRIDE_MIN_SECURITY       (1U << 0)
#define POLICY_OVERRIDE_EVIDENCE           (1U << 1)
#define POLICY_OVERRIDE_CONFIDENCE         (1U << 2)
#define POLICY_OVERRIDE_TRANSITION         (1U << 3)
#define POLICY_OVERRIDE_FLEET              (1U << 4)
#define POLICY_OVERRIDE_WEIGHTS            (1U << 5)
#define POLICY_OVERRIDE_PENALTIES          (1U << 6)
#define POLICY_OVERRIDE_PROVIDER           (1U << 7)
#define POLICY_OVERRIDE_PRODUCTION         (1U << 8)
#define POLICY_OVERRIDE_HARDWARE           (1U << 9)
#define POLICY_OVERRIDE_DOWNGRADE          (1U << 10)
#define POLICY_OVERRIDE_MANUAL             (1U << 11)
#define POLICY_OVERRIDE_FAIL_CLOSED        (1U << 12)
#define POLICY_OVERRIDE_MODE               (1U << 13)
#define POLICY_OVERRIDE_KNOWN ((1U << 14) - 1U)

static void policy_common(struct pqcp_adaptive_policy *policy)
{
	memset(policy, 0, sizeof(*policy));
	policy->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	policy->minimum_security_level = 2U;
	policy->required_evidence_mask =
		PQCP_DEPLOYMENT_EVIDENCE_KAT |
		PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
		PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	policy->minimum_confidence = 650U;
	policy->minimum_improvement_score = 40U;
	policy->transition_confirmations = 3U;
	policy->cooldown_cycles = 4U;
	policy->maximum_transitions_per_hour = 6U;
	policy->fleet_quorum_percent = 60U;
	policy->weight_security = 250U;
	policy->weight_latency = 180U;
	policy->weight_memory = 180U;
	policy->weight_energy = 120U;
	policy->weight_evidence = 170U;
	policy->weight_stability = 100U;
	policy->risk_penalty = 180U;
	policy->missing_evidence_penalty = 45U;
	policy->require_native_provider = true;
	policy->require_production_allowed = true;
	policy->require_hardware_evidence = false;
	policy->allow_security_downgrade = false;
	policy->allow_manual_override = false;
	policy->require_fleet_consensus = false;
	policy->fail_closed = true;
}

static void sensor_policy(struct pqcp_adaptive_policy *policy)
{
	policy_common(policy);
	policy->profile = PQCP_ADAPTIVE_POLICY_SENSOR;
	policy->default_mode = PQCP_ADAPTIVE_MODE_BALANCED;
	policy->minimum_security_level = 2U;
	policy->minimum_confidence = 600U;
	policy->minimum_improvement_score = 50U;
	policy->transition_confirmations = 4U;
	policy->cooldown_cycles = 8U;
	policy->maximum_transitions_per_hour = 4U;
	policy->weight_security = 220U;
	policy->weight_latency = 180U;
	policy->weight_memory = 240U;
	policy->weight_energy = 220U;
	policy->weight_evidence = 90U;
	policy->weight_stability = 150U;
	policy->risk_penalty = 150U;
	policy->missing_evidence_penalty = 35U;
}

static void gateway_policy(struct pqcp_adaptive_policy *policy)
{
	policy_common(policy);
	policy->profile = PQCP_ADAPTIVE_POLICY_GATEWAY;
	policy->default_mode = PQCP_ADAPTIVE_MODE_BALANCED;
	policy->minimum_security_level = 3U;
	policy->required_evidence_mask |=
		PQCP_DEPLOYMENT_EVIDENCE_ACVP |
		PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT;
	policy->minimum_confidence = 720U;
	policy->transition_confirmations = 3U;
	policy->cooldown_cycles = 5U;
	policy->maximum_transitions_per_hour = 8U;
	policy->weight_security = 280U;
	policy->weight_latency = 230U;
	policy->weight_memory = 120U;
	policy->weight_energy = 80U;
	policy->weight_evidence = 190U;
	policy->weight_stability = 100U;
	policy->risk_penalty = 210U;
	policy->missing_evidence_penalty = 55U;
}

static void firmware_update_policy(
	struct pqcp_adaptive_policy *policy)
{
	policy_common(policy);
	policy->profile = PQCP_ADAPTIVE_POLICY_FIRMWARE_UPDATE;
	policy->default_mode = PQCP_ADAPTIVE_MODE_CONSERVATIVE;
	policy->minimum_security_level = 3U;
	policy->required_evidence_mask |=
		PQCP_DEPLOYMENT_EVIDENCE_ACVP |
		PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
		PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT;
	policy->minimum_confidence = 780U;
	policy->minimum_improvement_score = 80U;
	policy->transition_confirmations = 5U;
	policy->cooldown_cycles = 10U;
	policy->maximum_transitions_per_hour = 2U;
	policy->weight_security = 360U;
	policy->weight_latency = 80U;
	policy->weight_memory = 120U;
	policy->weight_energy = 60U;
	policy->weight_evidence = 280U;
	policy->weight_stability = 100U;
	policy->risk_penalty = 300U;
	policy->missing_evidence_penalty = 80U;
}

static void critical_policy(struct pqcp_adaptive_policy *policy)
{
	policy_common(policy);
	policy->profile =
		PQCP_ADAPTIVE_POLICY_CRITICAL_INFRASTRUCTURE;
	policy->default_mode = PQCP_ADAPTIVE_MODE_LOCKDOWN;
	policy->minimum_security_level = 5U;
	policy->required_evidence_mask =
		PQCP_DEPLOYMENT_EVIDENCE_KAT |
		PQCP_DEPLOYMENT_EVIDENCE_ACVP |
		PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
		PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
		PQCP_DEPLOYMENT_EVIDENCE_BASELINE |
		PQCP_DEPLOYMENT_EVIDENCE_HARDWARE |
		PQCP_DEPLOYMENT_EVIDENCE_POLICY |
		PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
		PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
		PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	policy->minimum_confidence = 900U;
	policy->minimum_improvement_score = 100U;
	policy->transition_confirmations = 6U;
	policy->cooldown_cycles = 20U;
	policy->maximum_transitions_per_hour = 1U;
	policy->fleet_quorum_percent = 80U;
	policy->weight_security = 420U;
	policy->weight_latency = 60U;
	policy->weight_memory = 60U;
	policy->weight_energy = 40U;
	policy->weight_evidence = 360U;
	policy->weight_stability = 60U;
	policy->risk_penalty = 450U;
	policy->missing_evidence_penalty = 120U;
	policy->require_hardware_evidence = true;
	policy->require_fleet_consensus = true;
}

static void research_policy(struct pqcp_adaptive_policy *policy)
{
	policy_common(policy);
	policy->profile = PQCP_ADAPTIVE_POLICY_RESEARCH;
	policy->default_mode = PQCP_ADAPTIVE_MODE_PERFORMANCE;
	policy->minimum_security_level = 1U;
	policy->required_evidence_mask =
		PQCP_DEPLOYMENT_EVIDENCE_KAT |
		PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		PQCP_DEPLOYMENT_EVIDENCE_SIMULATION |
		PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
		PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
	policy->minimum_confidence = 450U;
	policy->minimum_improvement_score = 20U;
	policy->transition_confirmations = 2U;
	policy->cooldown_cycles = 2U;
	policy->maximum_transitions_per_hour = 20U;
	policy->fleet_quorum_percent = 0U;
	policy->weight_security = 160U;
	policy->weight_latency = 300U;
	policy->weight_memory = 170U;
	policy->weight_energy = 120U;
	policy->weight_evidence = 100U;
	policy->weight_stability = 50U;
	policy->risk_penalty = 80U;
	policy->missing_evidence_penalty = 20U;
	policy->require_production_allowed = false;
	policy->allow_security_downgrade = true;
	policy->allow_manual_override = true;
	policy->fail_closed = false;
}

int pqcp_adaptive_policy_default(
	enum pqcp_adaptive_policy_profile profile,
	struct pqcp_adaptive_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	switch (profile) {
	case PQCP_ADAPTIVE_POLICY_SENSOR:
		sensor_policy(policy);
		break;
	case PQCP_ADAPTIVE_POLICY_GATEWAY:
		gateway_policy(policy);
		break;
	case PQCP_ADAPTIVE_POLICY_FIRMWARE_UPDATE:
		firmware_update_policy(policy);
		break;
	case PQCP_ADAPTIVE_POLICY_CRITICAL_INFRASTRUCTURE:
		critical_policy(policy);
		break;
	case PQCP_ADAPTIVE_POLICY_RESEARCH:
		research_policy(policy);
		break;
	default:
		return -EINVAL;
	}
	return pqcp_adaptive_policy_validate(policy);
}

int pqcp_adaptive_policy_validate(
	const struct pqcp_adaptive_policy *policy)
{
	return pqcp_adaptive_internal_policy_valid(policy) ?
		0 : -EINVAL;
}

static void merge_minimums(
	struct pqcp_adaptive_policy *result,
	const struct pqcp_adaptive_policy *override_policy)
{
	result->minimum_security_level =
		override_policy->minimum_security_level;
}

static void merge_evidence(
	struct pqcp_adaptive_policy *result,
	const struct pqcp_adaptive_policy *override_policy)
{
	result->required_evidence_mask =
		override_policy->required_evidence_mask;
}

static void merge_confidence(
	struct pqcp_adaptive_policy *result,
	const struct pqcp_adaptive_policy *override_policy)
{
	result->minimum_confidence =
		override_policy->minimum_confidence;
	result->minimum_improvement_score =
		override_policy->minimum_improvement_score;
}

static void merge_transition(
	struct pqcp_adaptive_policy *result,
	const struct pqcp_adaptive_policy *override_policy)
{
	result->transition_confirmations =
		override_policy->transition_confirmations;
	result->cooldown_cycles =
		override_policy->cooldown_cycles;
	result->maximum_transitions_per_hour =
		override_policy->maximum_transitions_per_hour;
}

static void merge_fleet(
	struct pqcp_adaptive_policy *result,
	const struct pqcp_adaptive_policy *override_policy)
{
	result->fleet_quorum_percent =
		override_policy->fleet_quorum_percent;
	result->require_fleet_consensus =
		override_policy->require_fleet_consensus;
}

static void merge_weights(
	struct pqcp_adaptive_policy *result,
	const struct pqcp_adaptive_policy *override_policy)
{
	result->weight_security = override_policy->weight_security;
	result->weight_latency = override_policy->weight_latency;
	result->weight_memory = override_policy->weight_memory;
	result->weight_energy = override_policy->weight_energy;
	result->weight_evidence = override_policy->weight_evidence;
	result->weight_stability = override_policy->weight_stability;
}

static void merge_penalties(
	struct pqcp_adaptive_policy *result,
	const struct pqcp_adaptive_policy *override_policy)
{
	result->risk_penalty = override_policy->risk_penalty;
	result->missing_evidence_penalty =
		override_policy->missing_evidence_penalty;
}

int pqcp_adaptive_policy_merge(
	const struct pqcp_adaptive_policy *base,
	const struct pqcp_adaptive_policy *override_policy,
	uint32_t override_mask,
	struct pqcp_adaptive_policy *result)
{
	if (!pqcp_adaptive_internal_policy_valid(base) ||
	    override_policy == NULL || result == NULL ||
	    (override_mask & ~POLICY_OVERRIDE_KNOWN) != 0U) {
		return -EINVAL;
	}
	*result = *base;
	if ((override_mask & POLICY_OVERRIDE_MIN_SECURITY) != 0U) {
		merge_minimums(result, override_policy);
	}
	if ((override_mask & POLICY_OVERRIDE_EVIDENCE) != 0U) {
		merge_evidence(result, override_policy);
	}
	if ((override_mask & POLICY_OVERRIDE_CONFIDENCE) != 0U) {
		merge_confidence(result, override_policy);
	}
	if ((override_mask & POLICY_OVERRIDE_TRANSITION) != 0U) {
		merge_transition(result, override_policy);
	}
	if ((override_mask & POLICY_OVERRIDE_FLEET) != 0U) {
		merge_fleet(result, override_policy);
	}
	if ((override_mask & POLICY_OVERRIDE_WEIGHTS) != 0U) {
		merge_weights(result, override_policy);
	}
	if ((override_mask & POLICY_OVERRIDE_PENALTIES) != 0U) {
		merge_penalties(result, override_policy);
	}
	if ((override_mask & POLICY_OVERRIDE_PROVIDER) != 0U) {
		result->require_native_provider =
			override_policy->require_native_provider;
	}
	if ((override_mask & POLICY_OVERRIDE_PRODUCTION) != 0U) {
		result->require_production_allowed =
			override_policy->require_production_allowed;
	}
	if ((override_mask & POLICY_OVERRIDE_HARDWARE) != 0U) {
		result->require_hardware_evidence =
			override_policy->require_hardware_evidence;
	}
	if ((override_mask & POLICY_OVERRIDE_DOWNGRADE) != 0U) {
		result->allow_security_downgrade =
			override_policy->allow_security_downgrade;
	}
	if ((override_mask & POLICY_OVERRIDE_MANUAL) != 0U) {
		result->allow_manual_override =
			override_policy->allow_manual_override;
	}
	if ((override_mask & POLICY_OVERRIDE_FAIL_CLOSED) != 0U) {
		result->fail_closed = override_policy->fail_closed;
	}
	if ((override_mask & POLICY_OVERRIDE_MODE) != 0U) {
		result->default_mode = override_policy->default_mode;
	}
	return pqcp_adaptive_policy_validate(result);
}

static const char *policy_profile_str(
	enum pqcp_adaptive_policy_profile profile)
{
	switch (profile) {
	case PQCP_ADAPTIVE_POLICY_SENSOR:
		return "sensor";
	case PQCP_ADAPTIVE_POLICY_GATEWAY:
		return "gateway";
	case PQCP_ADAPTIVE_POLICY_FIRMWARE_UPDATE:
		return "firmware_update";
	case PQCP_ADAPTIVE_POLICY_CRITICAL_INFRASTRUCTURE:
		return "critical_infrastructure";
	case PQCP_ADAPTIVE_POLICY_RESEARCH:
		return "research";
	default:
		return "invalid";
	}
}

int pqcp_adaptive_policy_emit(const struct pqcp_adaptive_policy *policy)
{
	if (pqcp_adaptive_policy_validate(policy) != 0) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_POLICY schema=%u profile=%s mode=%s minimum_security=%u evidence=0x%08x confidence=%u improvement=%u confirmations=%u cooldown=%u transitions_per_hour=%u fleet_quorum=%u weight_security=%u weight_latency=%u weight_memory=%u weight_energy=%u weight_evidence=%u weight_stability=%u risk_penalty=%u missing_penalty=%u native=%u production=%u hardware=%u downgrade=%u manual=%u fleet=%u fail_closed=%u\n",
	       policy->schema_version,
	       policy_profile_str(policy->profile),
	       pqcp_adaptive_mode_str(policy->default_mode),
	       policy->minimum_security_level,
	       policy->required_evidence_mask,
	       policy->minimum_confidence,
	       policy->minimum_improvement_score,
	       policy->transition_confirmations,
	       policy->cooldown_cycles,
	       policy->maximum_transitions_per_hour,
	       policy->fleet_quorum_percent,
	       policy->weight_security,
	       policy->weight_latency,
	       policy->weight_memory,
	       policy->weight_energy,
	       policy->weight_evidence,
	       policy->weight_stability,
	       policy->risk_penalty,
	       policy->missing_evidence_penalty,
	       policy->require_native_provider ? 1U : 0U,
	       policy->require_production_allowed ? 1U : 0U,
	       policy->require_hardware_evidence ? 1U : 0U,
	       policy->allow_security_downgrade ? 1U : 0U,
	       policy->allow_manual_override ? 1U : 0U,
	       policy->require_fleet_consensus ? 1U : 0U,
	       policy->fail_closed ? 1U : 0U);
	return 0;
}
