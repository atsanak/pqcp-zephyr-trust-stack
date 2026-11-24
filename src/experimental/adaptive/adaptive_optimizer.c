/*
 * SPDX-License-Identifier: MIT
 *
 * Constrained multi-objective optimizer for compiled PQC profiles.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_OPTIMIZER_DOMAIN UINT64_C(0x4144504f5054494d)

static uint32_t normalized_inverse_score(
	uint64_t value, uint64_t limit)
{
	uint32_t used;

	if (limit == 0U) {
		return 500U;
	}
	if (value >= limit) {
		return value == limit ? 1U : 0U;
	}
	used = pqcp_adaptive_internal_permille(value, limit);
	return 1000U - used;
}

static uint32_t evidence_score(
	const struct pqcp_adaptive_profile *profile,
	const struct pqcp_adaptive_policy *policy,
	uint32_t *missing_mask)
{
	uint32_t required;
	uint32_t available_count;
	uint32_t required_count;
	uint32_t missing;
	uint32_t score;

	required = policy->required_evidence_mask;
	missing = required & ~profile->evidence_mask;
	*missing_mask = missing;
	required_count = pqcp_adaptive_internal_bit_count(required);
	if (required_count == 0U) {
		return 1000U;
	}
	available_count = pqcp_adaptive_internal_bit_count(
		required & profile->evidence_mask);
	score = (available_count * 1000U) / required_count;
	if ((profile->evidence_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_HARDWARE) != 0U) {
		score = pqcp_adaptive_internal_clamp_u32(
			score + 40U, 0U, 1000U);
	}
	if ((profile->evidence_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE) != 0U) {
		score = pqcp_adaptive_internal_clamp_u32(
			score + 30U, 0U, 1000U);
	}
	return score;
}

static uint32_t security_score(
	const struct pqcp_adaptive_profile *profile,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_threat_assessment *threat)
{
	uint32_t minimum = policy->minimum_security_level;
	uint32_t score;

	if (threat != NULL &&
	    threat->minimum_security_level > minimum) {
		minimum = threat->minimum_security_level;
	}
	if (profile->security_level < minimum) {
		return 0U;
	}
	score = 600U +
		(profile->security_level - minimum) * 80U;
	if (profile->kind ==
	    PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE) {
		score += 80U;
	}
	if (profile->hardware_validated) {
		score += 40U;
	}
	if (profile->production_allowed) {
		score += 20U;
	}
	return pqcp_adaptive_internal_clamp_u32(
		score, 0U, 1000U);
}

static uint32_t memory_score(
	const struct pqcp_adaptive_profile *profile,
	const struct pqcp_adaptive_resource_limits *limits)
{
	uint32_t count = 0U;
	uint32_t sum = 0U;

	if (limits->ram_capacity_bytes != 0U) {
		const uint32_t ram = normalized_inverse_score(
			profile->ram_bytes,
			limits->ram_capacity_bytes);
		sum += ram;
		count++;
	}
	if (limits->stack_capacity_bytes != 0U) {
		const uint32_t stack = normalized_inverse_score(
			profile->stack_bytes,
			limits->stack_capacity_bytes);
		sum += stack;
		count++;
	}
	if (limits->heap_capacity_bytes != 0U) {
		const uint32_t heap = normalized_inverse_score(
			profile->heap_bytes,
			limits->heap_capacity_bytes);
		sum += heap;
		count++;
	}
	if (limits->flash_capacity_bytes != 0U) {
		const uint32_t flash = normalized_inverse_score(
			profile->flash_bytes,
			limits->flash_capacity_bytes);
		sum += flash;
		count++;
	}
	return count == 0U ? 500U : sum / count;
}

static uint32_t stability_score(
	const struct pqcp_adaptive_profile *profile,
	const char *current_profile_id,
	const struct pqcp_adaptive_fleet_state *fleet)
{
	uint32_t score = 500U;

	if (current_profile_id != NULL &&
	    strcmp(profile->profile_id, current_profile_id) == 0) {
		score += 300U;
	}
	if (fleet != NULL && fleet->quorum_reached &&
	    strcmp(profile->profile_id,
		   fleet->consensus_profile_id) == 0) {
		score += 200U;
	}
	if (profile->priority > 500U) {
		score += (profile->priority - 500U) / 5U;
	}
	return pqcp_adaptive_internal_clamp_u32(
		score, 0U, 1000U);
}

static uint32_t weighted_total(
	const struct pqcp_adaptive_candidate_score *score,
	const struct pqcp_adaptive_policy *policy)
{
	uint64_t weighted = 0U;
	uint64_t weights = 0U;

	weighted += (uint64_t)score->security_score *
		    policy->weight_security;
	weighted += (uint64_t)score->latency_score *
		    policy->weight_latency;
	weighted += (uint64_t)score->memory_score *
		    policy->weight_memory;
	weighted += (uint64_t)score->energy_score *
		    policy->weight_energy;
	weighted += (uint64_t)score->evidence_score *
		    policy->weight_evidence;
	weighted += (uint64_t)score->stability_score *
		    policy->weight_stability;
	weights = (uint64_t)policy->weight_security +
		  policy->weight_latency +
		  policy->weight_memory +
		  policy->weight_energy +
		  policy->weight_evidence +
		  policy->weight_stability;
	return weights == 0U ? 0U : (uint32_t)(weighted / weights);
}

static void apply_policy_blockers(
	const struct pqcp_adaptive_profile *profile,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_threat_assessment *threat,
	const struct pqcp_adaptive_fleet_state *fleet,
	uint32_t required_operation_mask,
	uint32_t *blockers)
{
	uint32_t minimum_security = policy->minimum_security_level;

	if (!profile->enabled ||
	    (profile->operation_mask & required_operation_mask) !=
		    required_operation_mask) {
		*blockers |= PQCP_ADAPTIVE_BLOCK_OPERATION;
	}
	if (threat != NULL &&
	    threat->minimum_security_level > minimum_security) {
		minimum_security = threat->minimum_security_level;
	}
	if (profile->security_level < minimum_security) {
		*blockers |= PQCP_ADAPTIVE_BLOCK_SECURITY;
	}
	if (policy->require_native_provider &&
	    !profile->native_provider) {
		*blockers |= PQCP_ADAPTIVE_BLOCK_PROVIDER;
	}
	if (policy->require_production_allowed &&
	    !profile->production_allowed) {
		*blockers |= PQCP_ADAPTIVE_BLOCK_POLICY;
	}
	if ((policy->require_hardware_evidence ||
	     (threat != NULL &&
	      threat->require_hardware_evidence)) &&
	    !profile->hardware_validated) {
		*blockers |= PQCP_ADAPTIVE_BLOCK_HARDWARE;
	}
	if (threat != NULL && threat->require_hybrid &&
	    profile->kind !=
		    PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE) {
		*blockers |= PQCP_ADAPTIVE_BLOCK_SECURITY;
	}
	if (threat != NULL && threat->require_signature &&
	    profile->mldsa_level == 0U) {
		*blockers |= PQCP_ADAPTIVE_BLOCK_OPERATION;
	}
	if (policy->require_fleet_consensus &&
	    (fleet == NULL || !fleet->quorum_reached)) {
		*blockers |= PQCP_ADAPTIVE_BLOCK_FLEET_POLICY;
	}
	if (policy->require_fleet_consensus &&
	    fleet != NULL && fleet->quorum_reached &&
	    strcmp(profile->profile_id,
		   fleet->consensus_profile_id) != 0) {
		*blockers |= PQCP_ADAPTIVE_BLOCK_FLEET_POLICY;
	}
}

static void apply_evidence_policy(
	const struct pqcp_adaptive_profile *profile,
	const struct pqcp_adaptive_policy *policy,
	struct pqcp_adaptive_candidate_score *score)
{
	score->evidence_score = evidence_score(
		profile, policy, &score->missing_evidence_mask);
	if (score->missing_evidence_mask != 0U) {
		const uint32_t missing_count =
			pqcp_adaptive_internal_bit_count(
				score->missing_evidence_mask);
		const uint32_t penalty =
			missing_count *
			policy->missing_evidence_penalty;

		score->warning_mask |=
			PQCP_ADAPTIVE_WARNING_DEGRADED_EVIDENCE;
		if (policy->fail_closed) {
			score->blocker_mask |=
				PQCP_ADAPTIVE_BLOCK_EVIDENCE;
		}
		score->confidence = penalty >= 1000U ?
			0U : 1000U - penalty;
	} else {
		score->confidence = 1000U;
	}
}

static void project_profile(
	const struct pqcp_adaptive_profile *profile,
	const struct pqcp_adaptive_forecast *forecast,
	struct pqcp_adaptive_candidate_score *score)
{
	uint32_t latency_growth = 1000U;
	uint32_t energy_growth = 1000U;

	if (forecast != NULL &&
	    forecast->schema_version == PQCP_ADAPTIVE_SCHEMA_VERSION) {
		if (forecast->predicted_latency_us != 0U) {
			latency_growth +=
				forecast->predicted_latency_us > 1000000U ?
				200U :
				(uint32_t)(
					forecast->predicted_latency_us /
					5000U);
		}
		if (forecast->predicted_energy_uj != 0U) {
			energy_growth +=
				forecast->predicted_energy_uj > 100000U ?
				150U :
				(uint32_t)(
					forecast->predicted_energy_uj /
					1000U);
		}
	}
	latency_growth = pqcp_adaptive_internal_clamp_u32(
		latency_growth, 1000U, 1400U);
	energy_growth = pqcp_adaptive_internal_clamp_u32(
		energy_growth, 1000U, 1300U);
	score->projected_latency_us =
		pqcp_adaptive_internal_saturating_mul_u64(
			profile->nominal_latency_us,
			latency_growth) / 1000U;
	score->projected_energy_uj =
		pqcp_adaptive_internal_saturating_mul_u64(
			profile->energy_uj,
			energy_growth) / 1000U;
	score->projected_ram_bytes = profile->ram_bytes;
	score->projected_stack_bytes = profile->stack_bytes;
	score->projected_heap_bytes = profile->heap_bytes;
}

static int evaluate_candidate(
	const struct pqcp_adaptive_profile *profile,
	uint32_t profile_index,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_threat_assessment *threat,
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_resource_assessment *resources,
	const struct pqcp_adaptive_forecast *forecast,
	const struct pqcp_adaptive_fleet_state *fleet,
	uint32_t required_operation_mask,
	const char *current_profile_id,
	struct pqcp_adaptive_candidate_score *score)
{
	uint32_t resource_blockers = 0U;
	uint32_t headroom = 0U;

	memset(score, 0, sizeof(*score));
	score->profile_index = profile_index;
	pqcp_adaptive_internal_set_text(
		score->profile_id, sizeof(score->profile_id),
		profile->profile_id);
	project_profile(profile, forecast, score);
	apply_policy_blockers(
		profile, policy, threat, fleet,
		required_operation_mask, &score->blocker_mask);
	(void)pqcp_adaptive_resource_profile_fits(
		limits, resources, profile,
		&resource_blockers, &headroom);
	score->blocker_mask |= resource_blockers;
	score->security_score =
		security_score(profile, policy, threat);
	score->latency_score = normalized_inverse_score(
		score->projected_latency_us,
		limits->latency_budget_us);
	score->memory_score = memory_score(profile, limits);
	score->energy_score = normalized_inverse_score(
		score->projected_energy_uj,
		limits->energy_budget_uj);
	score->stability_score = stability_score(
		profile, current_profile_id, fleet);
	apply_evidence_policy(profile, policy, score);
	if (forecast != NULL &&
	    forecast->confidence < policy->minimum_confidence) {
		score->warning_mask |=
			PQCP_ADAPTIVE_WARNING_LOW_CONFIDENCE;
		score->confidence =
			score->confidence > 150U ?
			score->confidence - 150U : 0U;
	}
	if (resources->overall_pressure >=
	    PQCP_ADAPTIVE_PRESSURE_HIGH) {
		score->warning_mask |=
			PQCP_ADAPTIVE_WARNING_FORECAST_PRESSURE;
	}
	score->total_score = weighted_total(score, policy);
	if (score->missing_evidence_mask != 0U) {
		const uint32_t penalty =
			pqcp_adaptive_internal_bit_count(
				score->missing_evidence_mask) *
			policy->missing_evidence_penalty;

		score->total_score = score->total_score > penalty ?
			score->total_score - penalty : 0U;
	}
	if (score->blocker_mask != 0U) {
		score->status = PQCP_ADAPTIVE_STATUS_FAIL;
		score->total_score = 0U;
	} else if (score->warning_mask != 0U ||
		   score->confidence < policy->minimum_confidence) {
		score->status = PQCP_ADAPTIVE_STATUS_WARN;
	} else {
		score->status = PQCP_ADAPTIVE_STATUS_PASS;
	}
	return 0;
}
static bool candidate_better(
	const struct pqcp_adaptive_candidate_score *left,
	const struct pqcp_adaptive_candidate_score *right)
{
	if (left->status != right->status) {
		return left->status > right->status;
	}
	if (left->total_score != right->total_score) {
		return left->total_score > right->total_score;
	}
	if (left->confidence != right->confidence) {
		return left->confidence > right->confidence;
	}
	if (left->security_score != right->security_score) {
		return left->security_score > right->security_score;
	}
	if (left->projected_latency_us !=
	    right->projected_latency_us) {
		return left->projected_latency_us <
		       right->projected_latency_us;
	}
	return strcmp(left->profile_id, right->profile_id) < 0;
}

static void sort_candidates(
	struct pqcp_adaptive_candidate_score *scores,
	uint32_t count)
{
	for (uint32_t index = 1U; index < count; ++index) {
		struct pqcp_adaptive_candidate_score value =
			scores[index];
		uint32_t position = index;

		while (position > 0U &&
		       candidate_better(
			       &value, &scores[position - 1U])) {
			scores[position] = scores[position - 1U];
			position--;
		}
		scores[position] = value;
	}
}

static int recommendation_digest(
	const struct pqcp_adaptive_recommendation *recommendation,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_OPTIMIZER_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, recommendation->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)recommendation->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, recommendation->evaluated_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, recommendation->accepted_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, recommendation->rejected_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, recommendation->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, recommendation->top_index);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, recommendation->confidence);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, recommendation->transition_recommended);
	pqcp_deployment_evidence_digest_update_text(
		&digest, recommendation->current_profile_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, recommendation->recommended_profile_id);
	for (uint32_t index = 0U;
	     index < recommendation->evaluated_count; ++index) {
		const struct pqcp_adaptive_candidate_score *score =
			&recommendation->candidates[index];

		pqcp_deployment_evidence_digest_update_text(
			&digest, score->profile_id);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, score->total_score);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, score->blocker_mask);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, score->warning_mask);
		pqcp_deployment_evidence_digest_update_u32(
			&digest, score->confidence);
	}
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

int pqcp_adaptive_optimizer_run(
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_threat_assessment *threat,
	const struct pqcp_adaptive_resource_limits *limits,
	const struct pqcp_adaptive_resource_assessment *resources,
	const struct pqcp_adaptive_forecast *forecast,
	const struct pqcp_adaptive_fleet_state *fleet,
	uint32_t required_operation_mask,
	const char *current_profile_id,
	struct pqcp_adaptive_recommendation *recommendation)
{
	const struct pqcp_adaptive_candidate_score *top;

	if (pqcp_adaptive_profile_registry_validate(registry) != 0 ||
	    pqcp_adaptive_policy_validate(policy) != 0 ||
	    limits == NULL || resources == NULL ||
	    recommendation == NULL ||
	    required_operation_mask == 0U ||
	    (required_operation_mask &
	     ~PQCP_DEPLOYMENT_OPERATION_MASK_KNOWN) != 0U ||
	    !pqcp_adaptive_internal_id_valid(current_profile_id)) {
		return -EINVAL;
	}
	if (threat != NULL &&
	    threat->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	memset(recommendation, 0, sizeof(*recommendation));
	recommendation->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	recommendation->top_index = UINT32_MAX;
	pqcp_adaptive_internal_set_text(
		recommendation->current_profile_id,
		sizeof(recommendation->current_profile_id),
		current_profile_id);
	for (uint32_t index = 0U; index < registry->count; ++index) {
		struct pqcp_adaptive_candidate_score *score =
			&recommendation->candidates[
				recommendation->evaluated_count];

		evaluate_candidate(
			&registry->profiles[index], index, policy,
			threat, limits, resources, forecast, fleet,
			required_operation_mask, current_profile_id,
			score);
		recommendation->evaluated_count++;
		if (score->blocker_mask == 0U) {
			recommendation->accepted_count++;
		} else {
			recommendation->rejected_count++;
		}
	}
	sort_candidates(
		recommendation->candidates,
		recommendation->evaluated_count);
	if (recommendation->evaluated_count == 0U ||
	    recommendation->accepted_count == 0U ||
	    recommendation->candidates[0].blocker_mask != 0U) {
		recommendation->status = PQCP_ADAPTIVE_STATUS_FAIL;
		pqcp_adaptive_internal_set_text(
			recommendation->recommended_profile_id,
			sizeof(recommendation->recommended_profile_id),
			current_profile_id);
		recommendation->confidence = 0U;
	} else {
		top = &recommendation->candidates[0];
		recommendation->top_index = 0U;
		recommendation->confidence = top->confidence;
		recommendation->warning_mask = top->warning_mask;
		pqcp_adaptive_internal_set_text(
			recommendation->recommended_profile_id,
			sizeof(recommendation->recommended_profile_id),
			top->profile_id);
		recommendation->transition_recommended =
			strcmp(top->profile_id,
			       current_profile_id) != 0 &&
			top->total_score >=
				policy->minimum_improvement_score;
		recommendation->status =
			top->status == PQCP_ADAPTIVE_STATUS_PASS ?
			PQCP_ADAPTIVE_STATUS_PASS :
			PQCP_ADAPTIVE_STATUS_WARN;
	}
	return recommendation_digest(
		recommendation,
		recommendation->recommendation_digest_hex);
}

int pqcp_adaptive_optimizer_emit(
	const struct pqcp_adaptive_recommendation *recommendation)
{
	if (recommendation == NULL ||
	    recommendation->schema_version !=
		    PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    recommendation->evaluated_count >
		    PQCP_ADAPTIVE_MAX_RECOMMENDATIONS) {
		return -EINVAL;
	}
	for (uint32_t index = 0U;
	     index < recommendation->evaluated_count; ++index) {
		const struct pqcp_adaptive_candidate_score *score =
			&recommendation->candidates[index];

		printk("PQCP_ADAPTIVE_CANDIDATE schema=%u rank=%u id=%s status=%s score=%u confidence=%u blockers=0x%08x warnings=0x%08x missing=0x%08x security=%u latency=%u memory=%u energy=%u evidence=%u stability=%u projected_latency_us=%llu projected_ram=%llu projected_stack=%llu projected_heap=%llu projected_energy_uj=%llu\n",
		       recommendation->schema_version,
		       index,
		       score->profile_id,
		       pqcp_adaptive_status_str(score->status),
		       score->total_score,
		       score->confidence,
		       score->blocker_mask,
		       score->warning_mask,
		       score->missing_evidence_mask,
		       score->security_score,
		       score->latency_score,
		       score->memory_score,
		       score->energy_score,
		       score->evidence_score,
		       score->stability_score,
		       (unsigned long long)score->projected_latency_us,
		       (unsigned long long)score->projected_ram_bytes,
		       (unsigned long long)score->projected_stack_bytes,
		       (unsigned long long)score->projected_heap_bytes,
		       (unsigned long long)score->projected_energy_uj);
	}
	printk("PQCP_ADAPTIVE_RECOMMENDATION schema=%u status=%s evaluated=%u accepted=%u rejected=%u warnings=0x%08x confidence=%u transition=%u current=%s recommended=%s digest=%s\n",
	       recommendation->schema_version,
	       pqcp_adaptive_status_str(recommendation->status),
	       recommendation->evaluated_count,
	       recommendation->accepted_count,
	       recommendation->rejected_count,
	       recommendation->warning_mask,
	       recommendation->confidence,
	       recommendation->transition_recommended ? 1U : 0U,
	       recommendation->current_profile_id,
	       recommendation->recommended_profile_id,
	       recommendation->recommendation_digest_hex);
	return 0;
}
