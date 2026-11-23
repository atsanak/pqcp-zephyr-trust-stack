/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment recommendation robustness analysis
 *
 * Stability: experimental decision-support API. The analyzer operates only on
 * caller-supplied measurements and does not make cryptographic security claims.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_ROBUSTNESS_H_
#define PQCP_ZEPHYR_DEPLOYMENT_ROBUSTNESS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_advisor.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for robustness result structures and transcript markers. */
#define PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION 1U

/** Sentinel used when a budget margin cannot be calculated. */
#define PQCP_DEPLOYMENT_HEADROOM_UNKNOWN INT32_MIN

/** Latency constraint participates in robustness analysis. */
#define PQCP_DEPLOYMENT_METRIC_LATENCY (1U << 0)
/** RAM constraint participates in robustness analysis. */
#define PQCP_DEPLOYMENT_METRIC_RAM     (1U << 1)
/** Stack constraint participates in robustness analysis. */
#define PQCP_DEPLOYMENT_METRIC_STACK   (1U << 2)
/** Heap constraint participates in robustness analysis. */
#define PQCP_DEPLOYMENT_METRIC_HEAP    (1U << 3)
/** Flash/code-size constraint participates in robustness analysis. */
#define PQCP_DEPLOYMENT_METRIC_FLASH   (1U << 4)
/** Energy constraint participates in robustness analysis. */
#define PQCP_DEPLOYMENT_METRIC_ENERGY  (1U << 5)

/** All metric bits known by this API version. */
#define PQCP_DEPLOYMENT_METRIC_KNOWN_MASK \
	(PQCP_DEPLOYMENT_METRIC_LATENCY | \
	 PQCP_DEPLOYMENT_METRIC_RAM | \
	 PQCP_DEPLOYMENT_METRIC_STACK | \
	 PQCP_DEPLOYMENT_METRIC_HEAP | \
	 PQCP_DEPLOYMENT_METRIC_FLASH | \
	 PQCP_DEPLOYMENT_METRIC_ENERGY)

/** Candidate wins when the balanced preference is applied. */
#define PQCP_DEPLOYMENT_PREFERENCE_WIN_BALANCED     (1U << 0)
/** Candidate wins when conservative-security preference is applied. */
#define PQCP_DEPLOYMENT_PREFERENCE_WIN_SECURITY     (1U << 1)
/** Candidate wins when compact-artifact preference is applied. */
#define PQCP_DEPLOYMENT_PREFERENCE_WIN_COMPACT      (1U << 2)
/** Candidate wins when low-latency preference is applied. */
#define PQCP_DEPLOYMENT_PREFERENCE_WIN_LOW_LATENCY  (1U << 3)

/** All preference-win bits known by this API version. */
#define PQCP_DEPLOYMENT_PREFERENCE_WIN_KNOWN_MASK \
	(PQCP_DEPLOYMENT_PREFERENCE_WIN_BALANCED | \
	 PQCP_DEPLOYMENT_PREFERENCE_WIN_SECURITY | \
	 PQCP_DEPLOYMENT_PREFERENCE_WIN_COMPACT | \
	 PQCP_DEPLOYMENT_PREFERENCE_WIN_LOW_LATENCY)

/** Candidate remains feasible after every configured budget is tightened 5%. */
#define PQCP_DEPLOYMENT_STRESS_PASS_5_PERCENT  (1U << 0)
/** Candidate remains feasible after every configured budget is tightened 10%. */
#define PQCP_DEPLOYMENT_STRESS_PASS_10_PERCENT (1U << 1)
/** Candidate remains feasible after every configured budget is tightened 20%. */
#define PQCP_DEPLOYMENT_STRESS_PASS_20_PERCENT (1U << 2)
/** Candidate remains feasible after every configured budget is tightened 30%. */
#define PQCP_DEPLOYMENT_STRESS_PASS_30_PERCENT (1U << 3)

/** All budget-stress bits known by this API version. */
#define PQCP_DEPLOYMENT_STRESS_PASS_KNOWN_MASK \
	(PQCP_DEPLOYMENT_STRESS_PASS_5_PERCENT | \
	 PQCP_DEPLOYMENT_STRESS_PASS_10_PERCENT | \
	 PQCP_DEPLOYMENT_STRESS_PASS_20_PERCENT | \
	 PQCP_DEPLOYMENT_STRESS_PASS_30_PERCENT)

/** Qualitative robustness class for one recommendation candidate. */
enum pqcp_deployment_robustness_status {
	PQCP_DEPLOYMENT_ROBUSTNESS_REJECTED = 0,
	PQCP_DEPLOYMENT_ROBUSTNESS_FRAGILE,
	PQCP_DEPLOYMENT_ROBUSTNESS_ADEQUATE,
	PQCP_DEPLOYMENT_ROBUSTNESS_ROBUST,
};

/**
 * @brief Robustness result for one deployment candidate.
 *
 * Headroom values are signed permille values. For example, 250 means the
 * measurement is 25% below its budget, zero means exactly at budget, and a
 * negative value means the measurement exceeds the budget. Unknown values use
 * PQCP_DEPLOYMENT_HEADROOM_UNKNOWN.
 */
struct pqcp_deployment_candidate_robustness {
	/** Index of the candidate in the caller-provided array. */
	uint32_t candidate_index;
	/** Stable candidate identifier. */
	const char *candidate_id;
	/** Qualitative robustness class. */
	enum pqcp_deployment_robustness_status status;
	/** Configured scenario metrics. */
	uint32_t configured_metric_mask;
	/** Configured metrics with concrete candidate measurements. */
	uint32_t measured_metric_mask;
	/** Configured metrics without concrete candidate measurements. */
	uint32_t missing_metric_mask;
	/** Metric with the smallest known headroom, or zero. */
	uint32_t binding_metric;
	/** Lowest known headroom across configured metrics. */
	int32_t minimum_headroom_permille;
	/** Mean known headroom across configured metrics. */
	int32_t average_headroom_permille;
	/** Per-metric latency headroom. */
	int32_t latency_headroom_permille;
	/** Per-metric RAM headroom. */
	int32_t ram_headroom_permille;
	/** Per-metric stack headroom. */
	int32_t stack_headroom_permille;
	/** Per-metric heap headroom. */
	int32_t heap_headroom_permille;
	/** Per-metric flash headroom. */
	int32_t flash_headroom_permille;
	/** Per-metric energy headroom. */
	int32_t energy_headroom_permille;
	/** Number of feasible candidates this candidate Pareto-dominates. */
	uint32_t dominates_count;
	/** Number of feasible candidates that Pareto-dominate this candidate. */
	uint32_t dominated_by_count;
	/** Preferences for which this candidate ranks first. */
	uint32_t preference_win_mask;
	/** Number of preferences for which this candidate ranks first. */
	uint32_t preference_win_count;
	/** Configured uniform budget-tightening stress levels passed. */
	uint32_t stress_pass_mask;
	/** Largest uniform budget reduction supported, from 0 to 100 percent. */
	uint32_t maximum_uniform_budget_reduction_percent;
	/** Composite deterministic robustness score from 0 to 100. */
	uint32_t robustness_score;
	/** True when no feasible candidate dominates this candidate. */
	bool pareto_frontier;
	/** True when every configured metric has a concrete measurement. */
	bool measurements_complete;
};

/** Summary of a complete robustness analysis. */
struct pqcp_deployment_robustness_report {
	/** Report schema version. */
	uint32_t schema_version;
	/** Stable scenario identifier. */
	const char *scenario_id;
	/** Number of analyzed candidates. */
	uint32_t candidate_count;
	/** Number of feasible candidates. */
	uint32_t feasible_count;
	/** Number of feasible candidates on the Pareto frontier. */
	uint32_t pareto_frontier_count;
	/** Index of the advisor's top candidate, or UINT32_MAX. */
	uint32_t top_candidate_index;
	/** Robustness score of the advisor's top candidate. */
	uint32_t top_robustness_score;
	/** Number of ranking preferences won by the top candidate. */
	uint32_t top_preference_win_count;
	/** True when the same candidate wins every ranking preference. */
	bool recommendation_stable;
	/** True when the top candidate is classified robust. */
	bool recommendation_robust;
};

/** Convert a robustness state to a stable transcript token. */
const char *pqcp_deployment_robustness_status_str(
	enum pqcp_deployment_robustness_status status);

/** Convert one metric bit to a stable transcript token. */
const char *pqcp_deployment_metric_str(uint32_t metric);

/**
 * @brief Analyze ranking robustness and constraint sensitivity.
 *
 * This call first invokes pqcp_deployment_advise(), then calculates budget
 * margins, uniform budget-tightening tolerance, preference sensitivity, and a
 * Pareto frontier across feasible candidates. No dynamic allocation is used.
 *
 * @param scenario Scenario constraints.
 * @param candidates Candidate facts.
 * @param candidate_count Number of candidates.
 * @param evaluations Caller-owned advisor results with candidate_count entries.
 * @param robustness Caller-owned robustness results with candidate_count entries.
 * @param advisor_report Caller-owned advisor report.
 * @param robustness_report Caller-owned robustness summary.
 *
 * @retval 0 Analysis completed.
 * @retval -EINVAL Invalid argument or malformed scenario.
 * @retval -E2BIG Candidate count exceeds PQCP_DEPLOYMENT_MAX_CANDIDATES.
 */
int pqcp_deployment_robustness_analyze(
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidates,
	size_t candidate_count,
	struct pqcp_deployment_candidate_result *evaluations,
	struct pqcp_deployment_candidate_robustness *robustness,
	struct pqcp_deployment_report *advisor_report,
	struct pqcp_deployment_robustness_report *robustness_report);

/** Emit one stable candidate robustness marker. */
int pqcp_deployment_candidate_robustness_emit(
	const struct pqcp_deployment_candidate_robustness *result);

/** Emit one stable robustness summary marker. */
int pqcp_deployment_robustness_report_emit(
	const struct pqcp_deployment_robustness_report *report,
	const struct pqcp_deployment_candidate_robustness *results);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_ROBUSTNESS_H_ */
