/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Runtime threat-state assessment for adaptive PQC deployment.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_THREAT_DOMAIN UINT64_C(0x4144505448524541)

static bool threat_policy_valid(
	const struct pqcp_adaptive_threat_policy *policy)
{
	if (policy == NULL ||
	    policy->elevated_threshold == 0U ||
	    policy->elevated_threshold >= policy->high_threshold ||
	    policy->high_threshold >= policy->severe_threshold ||
	    policy->severe_threshold >= policy->critical_threshold ||
	    policy->critical_threshold > 1000U) {
		return false;
	}
	return true;
}

static bool threat_signal_valid(
	const struct pqcp_adaptive_threat_signal *signal)
{
	if (signal == NULL ||
	    (signal->signal_mask &
	     ~PQCP_ADAPTIVE_THREAT_KNOWN_MASK) != 0U ||
	    signal->remote_advisory_level > 5U ||
	    signal->fleet_divergence_percent > 100U ||
	    signal->data_sensitivity > 5U) {
		return false;
	}
	return true;
}

static uint32_t saturating_score_add(
	uint32_t score, uint64_t addition)
{
	uint64_t total = (uint64_t)score + addition;

	return total > 1000U ? 1000U : (uint32_t)total;
}

static uint32_t bounded_event_contribution(
	uint32_t count, uint32_t weight, uint32_t limit)
{
	uint64_t bounded = count > limit ? limit : count;
	uint64_t result = bounded * weight;

	return result > 1000U ? 1000U : (uint32_t)result;
}

static uint32_t reason_mask_from_signal(
	const struct pqcp_adaptive_threat_signal *signal,
	const struct pqcp_adaptive_telemetry_summary *telemetry)
{
	uint32_t reasons = signal->signal_mask;

	if (signal->auth_failures != 0U) {
		reasons |= PQCP_ADAPTIVE_THREAT_AUTH_FAILURE;
	}
	if (signal->replay_events != 0U) {
		reasons |= PQCP_ADAPTIVE_THREAT_REPLAY;
	}
	if (signal->signature_failures != 0U) {
		reasons |= PQCP_ADAPTIVE_THREAT_SIGNATURE_FAILURE;
	}
	if (signal->rollback_attempts != 0U) {
		reasons |= PQCP_ADAPTIVE_THREAT_ROLLBACK_ATTEMPT;
	}
	if (signal->physical_tamper) {
		reasons |= PQCP_ADAPTIVE_THREAT_PHYSICAL_TAMPER;
	}
	if (signal->remote_advisory_level != 0U) {
		reasons |= PQCP_ADAPTIVE_THREAT_REMOTE_ADVISORY;
	}
	if (signal->public_network) {
		reasons |= PQCP_ADAPTIVE_THREAT_PUBLIC_NETWORK;
	}
	if (signal->data_sensitivity >= 3U) {
		reasons |= PQCP_ADAPTIVE_THREAT_SENSITIVE_DATA;
	}
	if (signal->fleet_divergence_percent >= 20U) {
		reasons |= PQCP_ADAPTIVE_THREAT_FLEET_DIVERGENCE;
	}
	if (telemetry != NULL &&
	    (telemetry->anomaly_mask != 0U ||
	     telemetry->total_auth_failures != 0U ||
	     telemetry->total_handshake_failures >= 3U)) {
		reasons |= PQCP_ADAPTIVE_THREAT_BEHAVIORAL_ANOMALY;
	}
	return reasons & PQCP_ADAPTIVE_THREAT_KNOWN_MASK;
}

static uint32_t threat_score(
	const struct pqcp_adaptive_threat_signal *signal,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_threat_policy *policy)
{
	uint32_t score = 0U;

	score = saturating_score_add(
		score,
		bounded_event_contribution(
			signal->auth_failures,
			policy->auth_failure_weight, 10U));
	score = saturating_score_add(
		score,
		bounded_event_contribution(
			signal->replay_events,
			policy->replay_weight, 5U));
	score = saturating_score_add(
		score,
		bounded_event_contribution(
			signal->signature_failures,
			policy->signature_failure_weight, 5U));
	score = saturating_score_add(
		score,
		bounded_event_contribution(
			signal->rollback_attempts,
			policy->rollback_weight, 5U));
	if (signal->physical_tamper) {
		score = saturating_score_add(
			score, policy->tamper_weight);
	}
	score = saturating_score_add(
		score,
		(uint64_t)signal->remote_advisory_level *
		policy->advisory_weight);
	if (signal->public_network) {
		score = saturating_score_add(
			score, policy->public_network_weight);
	}
	score = saturating_score_add(
		score,
		(uint64_t)signal->data_sensitivity *
		policy->sensitive_data_weight);
	score = saturating_score_add(
		score,
		((uint64_t)signal->fleet_divergence_percent *
		 policy->fleet_divergence_weight) / 10U);
	if (telemetry != NULL) {
		const uint32_t anomaly_count =
			pqcp_adaptive_internal_bit_count(
				telemetry->anomaly_mask);

		score = saturating_score_add(
			score,
			(uint64_t)anomaly_count *
			policy->anomaly_weight);
		score = saturating_score_add(
			score,
			bounded_event_contribution(
				telemetry->total_auth_failures,
				policy->auth_failure_weight / 2U,
				10U));
		score = saturating_score_add(
			score,
			bounded_event_contribution(
				telemetry->total_handshake_failures,
				policy->anomaly_weight / 2U,
				10U));
	}
	return score;
}

static enum pqcp_adaptive_threat_level level_from_score(
	uint32_t score,
	const struct pqcp_adaptive_threat_policy *policy)
{
	if (score >= policy->critical_threshold) {
		return PQCP_ADAPTIVE_THREAT_CRITICAL;
	}
	if (score >= policy->severe_threshold) {
		return PQCP_ADAPTIVE_THREAT_SEVERE;
	}
	if (score >= policy->high_threshold) {
		return PQCP_ADAPTIVE_THREAT_HIGH;
	}
	if (score >= policy->elevated_threshold) {
		return PQCP_ADAPTIVE_THREAT_ELEVATED;
	}
	return PQCP_ADAPTIVE_THREAT_NOMINAL;
}

static uint32_t minimum_security_for_level(
	enum pqcp_adaptive_threat_level level)
{
	switch (level) {
	case PQCP_ADAPTIVE_THREAT_NOMINAL:
		return 1U;
	case PQCP_ADAPTIVE_THREAT_ELEVATED:
		return 2U;
	case PQCP_ADAPTIVE_THREAT_HIGH:
		return 3U;
	case PQCP_ADAPTIVE_THREAT_SEVERE:
		return 4U;
	case PQCP_ADAPTIVE_THREAT_CRITICAL:
		return 5U;
	default:
		return 5U;
	}
}

static void apply_reason_escalation(
	uint32_t reason_mask,
	struct pqcp_adaptive_threat_assessment *assessment)
{
	if ((reason_mask &
	     PQCP_ADAPTIVE_THREAT_ROLLBACK_ATTEMPT) != 0U) {
		assessment->prohibit_downgrade = true;
		if (assessment->level < PQCP_ADAPTIVE_THREAT_HIGH) {
			assessment->level = PQCP_ADAPTIVE_THREAT_HIGH;
		}
	}
	if ((reason_mask &
	     PQCP_ADAPTIVE_THREAT_PHYSICAL_TAMPER) != 0U) {
		assessment->prohibit_downgrade = true;
		assessment->require_hardware_evidence = true;
		if (assessment->level < PQCP_ADAPTIVE_THREAT_SEVERE) {
			assessment->level =
				PQCP_ADAPTIVE_THREAT_SEVERE;
		}
	}
	if ((reason_mask &
	     PQCP_ADAPTIVE_THREAT_SIGNATURE_FAILURE) != 0U) {
		assessment->require_signature = true;
	}
	if ((reason_mask &
	     (PQCP_ADAPTIVE_THREAT_PUBLIC_NETWORK |
	      PQCP_ADAPTIVE_THREAT_SENSITIVE_DATA)) ==
	    (PQCP_ADAPTIVE_THREAT_PUBLIC_NETWORK |
	     PQCP_ADAPTIVE_THREAT_SENSITIVE_DATA)) {
		assessment->require_hybrid = true;
	}
	if ((reason_mask &
	     PQCP_ADAPTIVE_THREAT_REPLAY) != 0U) {
		assessment->require_signature = true;
		assessment->prohibit_downgrade = true;
	}
	if ((reason_mask &
	     PQCP_ADAPTIVE_THREAT_REMOTE_ADVISORY) != 0U &&
	    assessment->level >= PQCP_ADAPTIVE_THREAT_HIGH) {
		assessment->require_hybrid = true;
	}
	assessment->minimum_security_level =
		minimum_security_for_level(assessment->level);
}

static int threat_digest(
	const struct pqcp_adaptive_threat_assessment *assessment,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (assessment == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_THREAT_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)assessment->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)assessment->level);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->score);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->reason_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, assessment->minimum_security_level);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, assessment->require_hybrid);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, assessment->require_signature);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, assessment->prohibit_downgrade);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, assessment->require_hardware_evidence);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, assessment->assessed_at_ms);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

int pqcp_adaptive_threat_default_policy(
	struct pqcp_adaptive_threat_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	memset(policy, 0, sizeof(*policy));
	policy->auth_failure_weight = 25U;
	policy->replay_weight = 90U;
	policy->signature_failure_weight = 80U;
	policy->rollback_weight = 140U;
	policy->tamper_weight = 280U;
	policy->advisory_weight = 45U;
	policy->public_network_weight = 70U;
	policy->sensitive_data_weight = 35U;
	policy->anomaly_weight = 30U;
	policy->fleet_divergence_weight = 8U;
	policy->elevated_threshold = 120U;
	policy->high_threshold = 300U;
	policy->severe_threshold = 550U;
	policy->critical_threshold = 800U;
	return 0;
}
int pqcp_adaptive_threat_assess(
	const struct pqcp_adaptive_threat_signal *signal,
	const struct pqcp_adaptive_telemetry_summary *telemetry,
	const struct pqcp_adaptive_threat_policy *policy,
	struct pqcp_adaptive_threat_assessment *assessment)
{
	if (!threat_signal_valid(signal) ||
	    !threat_policy_valid(policy) || assessment == NULL) {
		return -EINVAL;
	}
	if (telemetry != NULL &&
	    (telemetry->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	     !pqcp_adaptive_internal_status_valid(telemetry->status))) {
		return -EINVAL;
	}
	memset(assessment, 0, sizeof(*assessment));
	assessment->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	assessment->assessed_at_ms = signal->timestamp_ms;
	assessment->reason_mask =
		reason_mask_from_signal(signal, telemetry);
	assessment->score = threat_score(signal, telemetry, policy);
	assessment->level =
		level_from_score(assessment->score, policy);
	apply_reason_escalation(assessment->reason_mask, assessment);
	if (assessment->level >= PQCP_ADAPTIVE_THREAT_SEVERE) {
		assessment->status = PQCP_ADAPTIVE_STATUS_FAIL;
	} else if (assessment->level >=
		   PQCP_ADAPTIVE_THREAT_ELEVATED) {
		assessment->status = PQCP_ADAPTIVE_STATUS_WARN;
	} else {
		assessment->status = PQCP_ADAPTIVE_STATUS_PASS;
	}
	return threat_digest(
		assessment, assessment->threat_digest_hex);
}

int pqcp_adaptive_threat_emit(
	const struct pqcp_adaptive_threat_assessment *assessment)
{
	if (assessment == NULL ||
	    assessment->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_status_valid(assessment->status) ||
	    !pqcp_adaptive_internal_threat_valid(assessment->level)) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_THREAT schema=%u status=%s level=%s score=%u reasons=0x%08x minimum_security=%u hybrid=%u signature=%u prohibit_downgrade=%u hardware=%u assessed_at_ms=%llu digest=%s\n",
	       assessment->schema_version,
	       pqcp_adaptive_status_str(assessment->status),
	       pqcp_adaptive_threat_level_str(assessment->level),
	       assessment->score,
	       assessment->reason_mask,
	       assessment->minimum_security_level,
	       assessment->require_hybrid ? 1U : 0U,
	       assessment->require_signature ? 1U : 0U,
	       assessment->prohibit_downgrade ? 1U : 0U,
	       assessment->require_hardware_evidence ? 1U : 0U,
	       (unsigned long long)assessment->assessed_at_ms,
	       assessment->threat_digest_hex);
	return 0;
}
