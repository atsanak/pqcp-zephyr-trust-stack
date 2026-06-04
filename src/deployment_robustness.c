/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free deployment recommendation robustness analysis.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/deployment_robustness.h>

struct metric_pair {
	uint32_t metric;
	uint64_t value;
	uint64_t budget;
};

struct stress_level {
	uint32_t reduction_percent;
	uint32_t bit;
};

static const struct stress_level stress_levels[] = {
	{ 5U, PQCP_DEPLOYMENT_STRESS_PASS_5_PERCENT },
	{ 10U, PQCP_DEPLOYMENT_STRESS_PASS_10_PERCENT },
	{ 20U, PQCP_DEPLOYMENT_STRESS_PASS_20_PERCENT },
	{ 30U, PQCP_DEPLOYMENT_STRESS_PASS_30_PERCENT },
};

static bool robustness_status_valid(
	enum pqcp_deployment_robustness_status status)
{
	return status >= PQCP_DEPLOYMENT_ROBUSTNESS_REJECTED &&
	       status <= PQCP_DEPLOYMENT_ROBUSTNESS_ROBUST;
}

static bool stable_id_valid(const char *value)
{
	size_t length;

	if (value == NULL || value[0] == '\0') {
		return false;
	}
	length = strlen(value);
	if (length >= PQCP_DEPLOYMENT_ID_MAX_CHARS) {
		return false;
	}
	for (size_t i = 0U; i < length; ++i) {
		char c = value[i];

		if ((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') ||
		    c == '_' || c == '-' || c == '.') {
			continue;
		}
		return false;
	}

	return true;
}

static uint32_t count_bits(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += value & 1U;
		value >>= 1U;
	}

	return count;
}

const char *pqcp_deployment_robustness_status_str(
	enum pqcp_deployment_robustness_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_ROBUSTNESS_REJECTED:
		return "REJECTED";
	case PQCP_DEPLOYMENT_ROBUSTNESS_FRAGILE:
		return "FRAGILE";
	case PQCP_DEPLOYMENT_ROBUSTNESS_ADEQUATE:
		return "ADEQUATE";
	case PQCP_DEPLOYMENT_ROBUSTNESS_ROBUST:
		return "ROBUST";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_deployment_metric_str(uint32_t metric)
{
	switch (metric) {
	case PQCP_DEPLOYMENT_METRIC_LATENCY:
		return "latency";
	case PQCP_DEPLOYMENT_METRIC_RAM:
		return "ram";
	case PQCP_DEPLOYMENT_METRIC_STACK:
		return "stack";
	case PQCP_DEPLOYMENT_METRIC_HEAP:
		return "heap";
	case PQCP_DEPLOYMENT_METRIC_FLASH:
		return "flash";
	case PQCP_DEPLOYMENT_METRIC_ENERGY:
		return "energy";
	default:
		return "none";
	}
}

static void populate_metric_pairs(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	struct metric_pair pairs[6])
{
	pairs[0] = (struct metric_pair) {
		.metric = PQCP_DEPLOYMENT_METRIC_LATENCY,
		.value = candidate->latency_us,
		.budget = scenario->latency_budget_us,
	};
	pairs[1] = (struct metric_pair) {
		.metric = PQCP_DEPLOYMENT_METRIC_RAM,
		.value = candidate->ram_bytes,
		.budget = scenario->ram_budget_bytes,
	};
	pairs[2] = (struct metric_pair) {
		.metric = PQCP_DEPLOYMENT_METRIC_STACK,
		.value = candidate->stack_bytes,
		.budget = scenario->stack_budget_bytes,
	};
	pairs[3] = (struct metric_pair) {
		.metric = PQCP_DEPLOYMENT_METRIC_HEAP,
		.value = candidate->heap_bytes,
		.budget = scenario->heap_budget_bytes,
	};
	pairs[4] = (struct metric_pair) {
		.metric = PQCP_DEPLOYMENT_METRIC_FLASH,
		.value = candidate->flash_bytes,
		.budget = scenario->flash_budget_bytes,
	};
	pairs[5] = (struct metric_pair) {
		.metric = PQCP_DEPLOYMENT_METRIC_ENERGY,
		.value = candidate->energy_uj,
		.budget = scenario->energy_budget_uj,
	};
}

static uint32_t ratio_permille(uint64_t numerator, uint64_t denominator)
{
	uint64_t scaled;

	if (denominator == 0U || numerator == 0U) {
		return 0U;
	}
	if (numerator >= denominator) {
		return 1000U;
	}
	if (numerator <= UINT64_MAX / 1000U) {
		scaled = (numerator * 1000U) / denominator;
	} else {
		uint64_t divisor = denominator / 1000U;

		scaled = divisor == 0U ? 0U : numerator / divisor;
	}

	return scaled > 1000U ? 1000U : (uint32_t)scaled;
}

static int32_t metric_headroom_permille(uint64_t value, uint64_t budget)
{
	uint64_t difference;
	uint32_t ratio;

	if (value == 0U || budget == 0U) {
		return PQCP_DEPLOYMENT_HEADROOM_UNKNOWN;
	}
	if (value <= budget) {
		difference = budget - value;
		ratio = ratio_permille(difference, budget);
		return (int32_t)ratio;
	}

	difference = value - budget;
	ratio = ratio_permille(difference, budget);
	return -(int32_t)ratio;
}

static void set_metric_headroom(
	struct pqcp_deployment_candidate_robustness *result,
	uint32_t metric,
	int32_t headroom)
{
	switch (metric) {
	case PQCP_DEPLOYMENT_METRIC_LATENCY:
		result->latency_headroom_permille = headroom;
		break;
	case PQCP_DEPLOYMENT_METRIC_RAM:
		result->ram_headroom_permille = headroom;
		break;
	case PQCP_DEPLOYMENT_METRIC_STACK:
		result->stack_headroom_permille = headroom;
		break;
	case PQCP_DEPLOYMENT_METRIC_HEAP:
		result->heap_headroom_permille = headroom;
		break;
	case PQCP_DEPLOYMENT_METRIC_FLASH:
		result->flash_headroom_permille = headroom;
		break;
	case PQCP_DEPLOYMENT_METRIC_ENERGY:
		result->energy_headroom_permille = headroom;
		break;
	default:
		break;
	}
}

static void initialize_robustness(
	struct pqcp_deployment_candidate_robustness *result,
	uint32_t candidate_index,
	const char *candidate_id)
{
	*result = (struct pqcp_deployment_candidate_robustness) {
		.candidate_index = candidate_index,
		.candidate_id = candidate_id,
		.status = PQCP_DEPLOYMENT_ROBUSTNESS_REJECTED,
		.minimum_headroom_permille = PQCP_DEPLOYMENT_HEADROOM_UNKNOWN,
		.average_headroom_permille = PQCP_DEPLOYMENT_HEADROOM_UNKNOWN,
		.latency_headroom_permille = PQCP_DEPLOYMENT_HEADROOM_UNKNOWN,
		.ram_headroom_permille = PQCP_DEPLOYMENT_HEADROOM_UNKNOWN,
		.stack_headroom_permille = PQCP_DEPLOYMENT_HEADROOM_UNKNOWN,
		.heap_headroom_permille = PQCP_DEPLOYMENT_HEADROOM_UNKNOWN,
		.flash_headroom_permille = PQCP_DEPLOYMENT_HEADROOM_UNKNOWN,
		.energy_headroom_permille = PQCP_DEPLOYMENT_HEADROOM_UNKNOWN,
	};
}

static void calculate_headroom(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	struct pqcp_deployment_candidate_robustness *result)
{
	struct metric_pair pairs[6];
	int64_t total = 0;
	uint32_t known_count = 0U;

	populate_metric_pairs(scenario, candidate, pairs);
	for (size_t i = 0U; i < ARRAY_SIZE(pairs); ++i) {
		int32_t headroom;

		if (pairs[i].budget == 0U) {
			continue;
		}
		result->configured_metric_mask |= pairs[i].metric;
		headroom = metric_headroom_permille(
			pairs[i].value, pairs[i].budget);
		set_metric_headroom(result, pairs[i].metric, headroom);
		if (headroom == PQCP_DEPLOYMENT_HEADROOM_UNKNOWN) {
			result->missing_metric_mask |= pairs[i].metric;
			continue;
		}

		result->measured_metric_mask |= pairs[i].metric;
		total += headroom;
		known_count++;
		if (result->minimum_headroom_permille ==
			    PQCP_DEPLOYMENT_HEADROOM_UNKNOWN ||
		    headroom < result->minimum_headroom_permille) {
			result->minimum_headroom_permille = headroom;
			result->binding_metric = pairs[i].metric;
		}
	}

	if (known_count != 0U) {
		result->average_headroom_permille =
			(int32_t)(total / (int64_t)known_count);
	}
	result->measurements_complete =
		result->missing_metric_mask == 0U;
	if (result->minimum_headroom_permille > 0) {
		result->maximum_uniform_budget_reduction_percent =
			(uint32_t)result->minimum_headroom_permille / 10U;
		if (result->maximum_uniform_budget_reduction_percent > 100U) {
			result->maximum_uniform_budget_reduction_percent = 100U;
		}
	}
}

static bool passes_uniform_stress(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	uint32_t reduction_percent)
{
	struct metric_pair pairs[6];
	bool configured = false;

	populate_metric_pairs(scenario, candidate, pairs);
	for (size_t i = 0U; i < ARRAY_SIZE(pairs); ++i) {
		uint64_t reduced_budget;

		if (pairs[i].budget == 0U) {
			continue;
		}
		configured = true;
		if (pairs[i].value == 0U) {
			return false;
		}
		reduced_budget =
			(pairs[i].budget / 100U) * (100U - reduction_percent);
		reduced_budget +=
			((pairs[i].budget % 100U) *
			 (100U - reduction_percent)) / 100U;
		if (pairs[i].value > reduced_budget) {
			return false;
		}
	}

	return configured;
}

static void calculate_stress_mask(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	const struct pqcp_deployment_candidate_result *evaluation,
	struct pqcp_deployment_candidate_robustness *result)
{
	if (!evaluation->feasible) {
		return;
	}
	for (size_t i = 0U; i < ARRAY_SIZE(stress_levels); ++i) {
		if (passes_uniform_stress(
			    scenario, candidate,
			    stress_levels[i].reduction_percent)) {
			result->stress_pass_mask |= stress_levels[i].bit;
		}
	}
}

static bool metrics_dominate(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *left,
	const struct pqcp_deployment_candidate *right)
{
	struct metric_pair left_metrics[6];
	struct metric_pair right_metrics[6];
	bool strictly_better = false;
	bool compared = false;

	if (left->security_level < right->security_level) {
		return false;
	}
	if (left->security_level > right->security_level) {
		strictly_better = true;
	}
	if ((left->evidence_mask & right->evidence_mask) !=
	    right->evidence_mask ||
	    (right->independent_evidence && !left->independent_evidence)) {
		return false;
	}
	if (left->evidence_mask != right->evidence_mask ||
	    (left->independent_evidence && !right->independent_evidence)) {
		strictly_better = true;
	}

	populate_metric_pairs(scenario, left, left_metrics);
	populate_metric_pairs(scenario, right, right_metrics);
	for (size_t i = 0U; i < ARRAY_SIZE(left_metrics); ++i) {
		if (left_metrics[i].budget == 0U) {
			continue;
		}
		if (left_metrics[i].value == 0U ||
		    right_metrics[i].value == 0U) {
			return false;
		}
		compared = true;
		if (left_metrics[i].value > right_metrics[i].value) {
			return false;
		}
		if (left_metrics[i].value < right_metrics[i].value) {
			strictly_better = true;
		}
	}

	return compared && strictly_better;
}

static void calculate_pareto_frontier(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	const struct pqcp_deployment_candidate_result *evaluations,
	size_t candidate_count,
	struct pqcp_deployment_candidate_robustness *robustness)
{
	for (size_t left = 0U; left < candidate_count; ++left) {
		if (!evaluations[left].feasible) {
			continue;
		}
		for (size_t right = 0U; right < candidate_count; ++right) {
			if (left == right || !evaluations[right].feasible) {
				continue;
			}
			if (metrics_dominate(
			    scenario, &candidates[left], &candidates[right])) {
				robustness[left].dominates_count++;
				robustness[right].dominated_by_count++;
			}
		}
	}

	for (size_t i = 0U; i < candidate_count; ++i) {
		robustness[i].pareto_frontier =
			evaluations[i].feasible &&
			robustness[i].dominated_by_count == 0U;
	}
}

static uint32_t preference_bit(enum pqcp_deployment_preference preference)
{
	switch (preference) {
	case PQCP_DEPLOYMENT_PREFERENCE_BALANCED:
		return PQCP_DEPLOYMENT_PREFERENCE_WIN_BALANCED;
	case PQCP_DEPLOYMENT_PREFERENCE_CONSERVATIVE_SECURITY:
		return PQCP_DEPLOYMENT_PREFERENCE_WIN_SECURITY;
	case PQCP_DEPLOYMENT_PREFERENCE_COMPACT_ARTIFACTS:
		return PQCP_DEPLOYMENT_PREFERENCE_WIN_COMPACT;
	case PQCP_DEPLOYMENT_PREFERENCE_LOW_LATENCY:
		return PQCP_DEPLOYMENT_PREFERENCE_WIN_LOW_LATENCY;
	default:
		return 0U;
	}
}

static int calculate_preference_wins(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	size_t candidate_count,
	struct pqcp_deployment_candidate_robustness *robustness)
{
	struct pqcp_deployment_candidate_result
		evaluations[PQCP_DEPLOYMENT_MAX_CANDIDATES];
	struct pqcp_deployment_report report;

	for (enum pqcp_deployment_preference preference =
		     PQCP_DEPLOYMENT_PREFERENCE_BALANCED;
	     preference <= PQCP_DEPLOYMENT_PREFERENCE_LOW_LATENCY;
	     preference++) {
		struct pqcp_deployment_scenario variant = *scenario;
		uint32_t bit = preference_bit(preference);
		int ret;

		variant.preference = preference;
		ret = pqcp_deployment_advise(
			&variant, candidates, candidate_count, evaluations, &report);
		if (ret != 0) {
			return ret;
		}
		if (report.top_result_index == UINT32_MAX) {
			continue;
		}
		robustness[report.top_result_index].preference_win_mask |= bit;
		robustness[report.top_result_index].preference_win_count++;
	}

	return 0;
}

static uint32_t calculate_robustness_score(
	const struct pqcp_deployment_candidate_result *evaluation,
	const struct pqcp_deployment_candidate_robustness *robustness)
{
	uint32_t margin_score = 0U;
	uint32_t score;

	if (!evaluation->feasible) {
		return 0U;
	}
	if (robustness->minimum_headroom_permille > 0) {
		margin_score =
			(uint32_t)robustness->minimum_headroom_permille / 20U;
		if (margin_score > 50U) {
			margin_score = 50U;
		}
	}
	score = margin_score;
	score += (evaluation->confidence * 30U) / 100U;
	score += robustness->preference_win_count * 5U;
	if (robustness->pareto_frontier && score < 100U) {
		score += 1U;
	}

	return score > 100U ? 100U : score;
}

static enum pqcp_deployment_robustness_status classify_robustness(
	const struct pqcp_deployment_candidate_result *evaluation,
	const struct pqcp_deployment_candidate_robustness *robustness)
{
	if (!evaluation->feasible) {
		return PQCP_DEPLOYMENT_ROBUSTNESS_REJECTED;
	}
	if (robustness->measurements_complete &&
	    robustness->pareto_frontier &&
	    robustness->minimum_headroom_permille >= 200 &&
	    robustness->preference_win_count >= 2U &&
	    evaluation->confidence >= 80U) {
		return PQCP_DEPLOYMENT_ROBUSTNESS_ROBUST;
	}
	if (robustness->measurements_complete &&
	    robustness->minimum_headroom_permille >= 100 &&
	    evaluation->confidence >= 60U) {
		return PQCP_DEPLOYMENT_ROBUSTNESS_ADEQUATE;
	}

	return PQCP_DEPLOYMENT_ROBUSTNESS_FRAGILE;
}

int pqcp_deployment_robustness_analyze(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	size_t candidate_count,
	struct pqcp_deployment_candidate_result *evaluations,
	struct pqcp_deployment_candidate_robustness *robustness,
	struct pqcp_deployment_report *advisor_report,
	struct pqcp_deployment_robustness_report *robustness_report)
{
	uint32_t frontier_count = 0U;
	uint32_t top_index;
	int ret;

	if (scenario == NULL || candidates == NULL || evaluations == NULL ||
	    robustness == NULL || advisor_report == NULL ||
	    robustness_report == NULL || candidate_count == 0U) {
		return -EINVAL;
	}
	if (candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES) {
		return -E2BIG;
	}

	ret = pqcp_deployment_advise(
		scenario, candidates, candidate_count, evaluations, advisor_report);
	if (ret != 0) {
		return ret;
	}
	for (size_t i = 0U; i < candidate_count; ++i) {
		initialize_robustness(
			&robustness[i], (uint32_t)i, candidates[i].candidate_id);
		calculate_headroom(scenario, &candidates[i], &robustness[i]);
		calculate_stress_mask(
			scenario, &candidates[i], &evaluations[i], &robustness[i]);
	}

	calculate_pareto_frontier(
		scenario, candidates, evaluations, candidate_count, robustness);
	ret = calculate_preference_wins(
		scenario, candidates, candidate_count, robustness);
	if (ret != 0) {
		return ret;
	}

	for (size_t i = 0U; i < candidate_count; ++i) {
		robustness[i].robustness_score = calculate_robustness_score(
			&evaluations[i], &robustness[i]);
		robustness[i].status = classify_robustness(
			&evaluations[i], &robustness[i]);
		if (robustness[i].pareto_frontier) {
			frontier_count++;
		}
	}

	top_index = advisor_report->top_result_index;
	*robustness_report = (struct pqcp_deployment_robustness_report) {
		.schema_version = PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION,
		.scenario_id = scenario->scenario_id,
		.candidate_count = (uint32_t)candidate_count,
		.feasible_count = advisor_report->feasible_count,
		.pareto_frontier_count = frontier_count,
		.top_candidate_index = top_index,
		.top_robustness_score = top_index == UINT32_MAX ?
			0U : robustness[top_index].robustness_score,
		.top_preference_win_count = top_index == UINT32_MAX ?
			0U : robustness[top_index].preference_win_count,
		.recommendation_stable = top_index != UINT32_MAX &&
			robustness[top_index].preference_win_mask ==
				PQCP_DEPLOYMENT_PREFERENCE_WIN_KNOWN_MASK,
		.recommendation_robust = top_index != UINT32_MAX &&
			robustness[top_index].status ==
				PQCP_DEPLOYMENT_ROBUSTNESS_ROBUST,
	};

	return 0;
}

static bool headroom_valid(int32_t value)
{
	return value == PQCP_DEPLOYMENT_HEADROOM_UNKNOWN ||
	       (value >= -1000 && value <= 1000);
}

static int candidate_robustness_validate(
	const struct pqcp_deployment_candidate_robustness *result)
{
	if (result == NULL || !stable_id_valid(result->candidate_id) ||
	    !robustness_status_valid(result->status) ||
	    (result->configured_metric_mask &
	     ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) != 0U ||
	    (result->measured_metric_mask &
	     ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) != 0U ||
	    (result->missing_metric_mask &
	     ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) != 0U ||
	    (result->binding_metric &
	     ~PQCP_DEPLOYMENT_METRIC_KNOWN_MASK) != 0U ||
	    (result->preference_win_mask &
	     ~PQCP_DEPLOYMENT_PREFERENCE_WIN_KNOWN_MASK) != 0U ||
	    (result->stress_pass_mask &
	     ~PQCP_DEPLOYMENT_STRESS_PASS_KNOWN_MASK) != 0U ||
	    result->preference_win_count > 4U ||
	    result->maximum_uniform_budget_reduction_percent > 100U ||
	    result->robustness_score > 100U ||
	    !headroom_valid(result->minimum_headroom_permille) ||
	    !headroom_valid(result->average_headroom_permille) ||
	    !headroom_valid(result->latency_headroom_permille) ||
	    !headroom_valid(result->ram_headroom_permille) ||
	    !headroom_valid(result->stack_headroom_permille) ||
	    !headroom_valid(result->heap_headroom_permille) ||
	    !headroom_valid(result->flash_headroom_permille) ||
	    !headroom_valid(result->energy_headroom_permille)) {
		return -EINVAL;
	}
	if (result->preference_win_count !=
	    count_bits(result->preference_win_mask)) {
		return -EBADMSG;
	}
	if ((result->measured_metric_mask | result->missing_metric_mask) !=
	    result->configured_metric_mask ||
	    (result->measured_metric_mask & result->missing_metric_mask) != 0U ||
	    result->measurements_complete !=
		    (result->missing_metric_mask == 0U)) {
		return -EBADMSG;
	}

	return 0;
}

int pqcp_deployment_candidate_robustness_emit(
	const struct pqcp_deployment_candidate_robustness *result)
{
	if (candidate_robustness_validate(result) != 0) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_ROBUSTNESS_CANDIDATE schema=%u index=%u id=%s status=%s score=%u configured=0x%08x measured=0x%08x missing=0x%08x binding=%s min_headroom_permille=%d avg_headroom_permille=%d preference_wins=0x%08x stress_pass=0x%08x max_reduction_percent=%u dominates=%u dominated_by=%u pareto=%u complete=%u\n",
	       PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION,
	       result->candidate_index,
	       result->candidate_id,
	       pqcp_deployment_robustness_status_str(result->status),
	       result->robustness_score,
	       result->configured_metric_mask,
	       result->measured_metric_mask,
	       result->missing_metric_mask,
	       pqcp_deployment_metric_str(result->binding_metric),
	       result->minimum_headroom_permille,
	       result->average_headroom_permille,
	       result->preference_win_mask,
	       result->stress_pass_mask,
	       result->maximum_uniform_budget_reduction_percent,
	       result->dominates_count,
	       result->dominated_by_count,
	       result->pareto_frontier ? 1U : 0U,
	       result->measurements_complete ? 1U : 0U);

	return 0;
}

int pqcp_deployment_robustness_report_emit(
	const struct pqcp_deployment_robustness_report *report,
	const struct pqcp_deployment_candidate_robustness *results)
{
	const char *top_id = "none";
	const char *status = "NO_RECOMMENDATION";

	if (report == NULL || results == NULL ||
	    report->schema_version != PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION ||
	    !stable_id_valid(report->scenario_id) ||
	    report->candidate_count == 0U ||
	    report->candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES ||
	    report->feasible_count > report->candidate_count ||
	    report->pareto_frontier_count > report->feasible_count ||
	    report->top_robustness_score > 100U ||
	    report->top_preference_win_count > 4U) {
		return -EINVAL;
	}
	if (report->top_candidate_index != UINT32_MAX) {
		if (report->top_candidate_index >= report->candidate_count ||
		    candidate_robustness_validate(
			    &results[report->top_candidate_index]) != 0) {
			return -EINVAL;
		}
		top_id = results[report->top_candidate_index].candidate_id;
		status = report->recommendation_robust ? "ROBUST" :
			(report->recommendation_stable ? "STABLE" : "SENSITIVE");
	}

	printk("PQCP_DEPLOYMENT_ROBUSTNESS schema=%u id=%s status=%s candidates=%u feasible=%u frontier=%u top=%s top_score=%u top_preference_wins=%u stable=%u robust=%u\n",
	       report->schema_version,
	       report->scenario_id,
	       status,
	       report->candidate_count,
	       report->feasible_count,
	       report->pareto_frontier_count,
	       top_id,
	       report->top_robustness_score,
	       report->top_preference_win_count,
	       report->recommendation_stable ? 1U : 0U,
	       report->recommendation_robust ? 1U : 0U);

	return report->top_candidate_index == UINT32_MAX ? -ENODATA : 0;
}
