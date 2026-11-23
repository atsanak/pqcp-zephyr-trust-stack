/*
 * SPDX-License-Identifier: MIT
 *
 * Deployment measurement campaign tests.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_campaign.h>

static struct pqcp_deployment_candidate candidate_template(void)
{
	return (struct pqcp_deployment_candidate) {
		.candidate_id = "mlkem768_campaign",
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.target_class = PQCP_DEPLOYMENT_TARGET_CORTEX_M7,
		.operation_mask = PQCP_DEPLOYMENT_OPERATION_MASK_KEM,
		.security_level = 3U,
		.mlkem_level = 768U,
		.evidence_mask = PQCP_DEPLOYMENT_EVIDENCE_KAT |
				 PQCP_DEPLOYMENT_EVIDENCE_POLICY |
				 PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
				 PQCP_DEPLOYMENT_EVIDENCE_HARDWARE |
				 PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT,
		.independent_evidence = true,
		.policy_allowed = true,
		.native_provider = true,
	};
}

static struct pqcp_deployment_campaign_config config_base(void)
{
	return (struct pqcp_deployment_campaign_config) {
		.campaign_id = "campaign_a",
		.candidate_template = candidate_template(),
		.projection = PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90,
		.min_samples = 5U,
		.cv_warn_bps = 2000U,
		.static_drift_warn_permille = 100U,
	};
}

static struct pqcp_deployment_campaign_observation observation(
	uint64_t latency,
	uint64_t cycles,
	uint64_t ram,
	uint64_t stack,
	uint64_t heap,
	uint64_t flash,
	uint64_t energy)
{
	return (struct pqcp_deployment_campaign_observation) {
		.passed = true,
		.latency_us = latency,
		.cycles = cycles,
		.ram_bytes = ram,
		.stack_bytes = stack,
		.heap_bytes = heap,
		.flash_bytes = flash,
		.energy_uj = energy,
	};
}

static void add_stable_observations(
	struct pqcp_deployment_campaign_state *state)
{
	const uint64_t latency[] = { 100U, 110U, 120U, 130U, 140U };

	for (size_t i = 0U; i < ARRAY_SIZE(latency); ++i) {
		struct pqcp_deployment_campaign_observation obs = observation(
			latency[i], latency[i] * 10U, 1000U, 400U, 128U,
			12000U, 80U + i);

		zassert_equal(pqcp_deployment_campaign_add(state, &obs), 0);
	}
}

ZTEST(pqcp_deployment_campaign, test_tokens_are_stable)
{
	zassert_true(strcmp(pqcp_deployment_campaign_projection_str(
				    PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_P90),
			    "p90") == 0);
	zassert_true(strcmp(pqcp_deployment_campaign_projection_str(
				    (enum pqcp_deployment_campaign_projection)99),
			    "unknown") == 0);
	zassert_true(strcmp(pqcp_deployment_campaign_quality_str(
				    PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_HIGH_VARIANCE),
			    "high_variance") == 0);
	zassert_true(strcmp(pqcp_deployment_campaign_quality_str(0x80000000U),
			    "unknown") == 0);
}

ZTEST(pqcp_deployment_campaign, test_stable_campaign_projects_candidate)
{
	struct pqcp_deployment_campaign_observation storage[8];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_config config = config_base();

	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	add_stable_observations(&state);
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);

	zassert_equal(summary.quality_mask, 0U);
	zassert_equal(summary.observation_count, 5U);
	zassert_equal(summary.successful_count, 5U);
	zassert_equal(summary.failed_count, 0U);
	zassert_equal(summary.latency.count, 5U);
	zassert_equal(summary.latency.min, 100U);
	zassert_equal(summary.latency.median, 120U);
	zassert_equal(summary.latency.p90, 130U);
	zassert_equal(summary.latency.p99, 130U);
	zassert_equal(summary.latency.max, 140U);
	zassert_equal(summary.latency.mean, 120U);
	zassert_equal(summary.latency.mad, 10U);
	zassert_true(summary.latency.stable);
	zassert_true(summary.projected_candidate_valid);
	zassert_equal(summary.projected_candidate.latency_us, 130U);
	zassert_equal(summary.projected_candidate.cycles, 1300U);
	zassert_equal(summary.projected_candidate.ram_bytes, 1000U);
	zassert_equal(summary.projected_candidate.stack_bytes, 400U);
	zassert_equal(summary.projected_candidate.heap_bytes, 128U);
	zassert_equal(summary.projected_candidate.flash_bytes, 12000U);
	zassert_equal(summary.projected_candidate.energy_uj, 83U);
	zassert_true((summary.projected_candidate.evidence_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE) != 0U);
	zassert_true((summary.projected_candidate.evidence_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_RESOURCE) != 0U);
	zassert_true((summary.projected_candidate.evidence_mask &
		      PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE) != 0U);
	zassert_equal(pqcp_deployment_campaign_summary_emit(&summary), 0);
}

ZTEST(pqcp_deployment_campaign, test_projection_policy_changes_variable_metrics)
{
	struct pqcp_deployment_campaign_observation storage[8];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_config config = config_base();

	config.projection = PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MEDIAN;
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	add_stable_observations(&state);
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);
	zassert_equal(summary.projected_candidate.latency_us, 120U);

	config.projection = PQCP_DEPLOYMENT_CAMPAIGN_PROJECT_MAX;
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	add_stable_observations(&state);
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);
	zassert_equal(summary.projected_candidate.latency_us, 140U);
}

ZTEST(pqcp_deployment_campaign, test_empty_and_insufficient_campaigns_warn)
{
	struct pqcp_deployment_campaign_observation storage[8];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_config config = config_base();
	struct pqcp_deployment_campaign_observation obs =
		observation(100U, 1000U, 1000U, 400U, 128U, 12000U, 80U);

	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);
	zassert_true((summary.quality_mask &
		      PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_EMPTY) != 0U);
	zassert_true((summary.quality_mask &
		      PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_INSUFFICIENT) != 0U);
	zassert_equal(pqcp_deployment_campaign_summary_emit(&summary), -ENODATA);

	zassert_equal(pqcp_deployment_campaign_add(&state, &obs), 0);
	zassert_equal(pqcp_deployment_campaign_add(&state, &obs), 0);
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);
	zassert_false((summary.quality_mask &
		       PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_EMPTY) != 0U);
	zassert_true((summary.quality_mask &
		      PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_INSUFFICIENT) != 0U);
}

ZTEST(pqcp_deployment_campaign, test_failed_observations_are_reported)
{
	struct pqcp_deployment_campaign_observation storage[8];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_config config = config_base();
	struct pqcp_deployment_campaign_observation obs =
		observation(100U, 1000U, 1000U, 400U, 128U, 12000U, 80U);

	config.min_samples = 1U;
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	zassert_equal(pqcp_deployment_campaign_add(&state, &obs), 0);
	obs.passed = false;
	obs.latency_us = 1000000U;
	zassert_equal(pqcp_deployment_campaign_add(&state, &obs), 0);
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);
	zassert_equal(summary.failed_count, 1U);
	zassert_equal(summary.latency.count, 1U);
	zassert_true((summary.quality_mask &
		      PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_FAILED_OBSERVATION) != 0U);
}

ZTEST(pqcp_deployment_campaign, test_missing_performance_and_resource_warn)
{
	struct pqcp_deployment_campaign_observation storage[8];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_config config = config_base();
	struct pqcp_deployment_campaign_observation obs =
		observation(0U, 0U, 0U, 0U, 0U, 0U, 0U);

	config.min_samples = 1U;
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	zassert_equal(pqcp_deployment_campaign_add(&state, &obs), 0);
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);
	zassert_true((summary.quality_mask &
		      PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_PERFORMANCE) != 0U);
	zassert_true((summary.quality_mask &
		      PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_MISSING_RESOURCE) != 0U);
	zassert_false(summary.projected_candidate_valid);
}

ZTEST(pqcp_deployment_campaign, test_high_variance_and_outliers_warn)
{
	struct pqcp_deployment_campaign_observation storage[8];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_config config = config_base();
	const uint64_t latency[] = { 100U, 100U, 100U, 100U, 1000U };

	config.cv_warn_bps = 100U;
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	for (size_t i = 0U; i < ARRAY_SIZE(latency); ++i) {
		struct pqcp_deployment_campaign_observation obs = observation(
			latency[i], latency[i] * 10U, 1000U, 400U, 128U,
			12000U, 80U);

		zassert_equal(pqcp_deployment_campaign_add(&state, &obs), 0);
	}
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);
	zassert_true((summary.quality_mask &
		      PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_HIGH_VARIANCE) != 0U);
	zassert_true((summary.quality_mask &
		      PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_OUTLIERS) != 0U);
	zassert_not_equal(summary.latency.outlier_count, 0U);
	zassert_false((summary.projected_candidate.evidence_mask &
		       PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE) != 0U);
}

ZTEST(pqcp_deployment_campaign, test_static_resource_drift_warns)
{
	struct pqcp_deployment_campaign_observation storage[8];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_config config = config_base();
	const uint64_t ram[] = { 1000U, 2000U, 1000U, 2000U, 1000U };

	config.static_drift_warn_permille = 10U;
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	for (size_t i = 0U; i < ARRAY_SIZE(ram); ++i) {
		struct pqcp_deployment_campaign_observation obs = observation(
			100U + i, 1000U + i, ram[i], 400U, 128U, 12000U, 80U);

		zassert_equal(pqcp_deployment_campaign_add(&state, &obs), 0);
	}
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);
	zassert_true((summary.quality_mask &
		      PQCP_DEPLOYMENT_CAMPAIGN_QUALITY_STATIC_DRIFT) != 0U);
}

ZTEST(pqcp_deployment_campaign, test_capacity_and_value_limits)
{
	struct pqcp_deployment_campaign_observation storage[1];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_config config = config_base();
	struct pqcp_deployment_campaign_observation obs =
		observation(100U, 1000U, 1000U, 400U, 128U, 12000U, 80U);

	config.min_samples = 1U;
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	zassert_equal(pqcp_deployment_campaign_add(&state, &obs), 0);
	zassert_equal(pqcp_deployment_campaign_add(&state, &obs), -EINVAL);

	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	obs.latency_us = UINT64_MAX;
	zassert_equal(pqcp_deployment_campaign_add(&state, &obs), -EINVAL);
}

ZTEST(pqcp_deployment_campaign, test_invalid_config_rejected)
{
	struct pqcp_deployment_campaign_observation storage[8];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_config config = config_base();

	zassert_equal(pqcp_deployment_campaign_init(
			      NULL, &config, storage, ARRAY_SIZE(storage)),
		      -EINVAL);
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, NULL, storage, ARRAY_SIZE(storage)),
		      -EINVAL);
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, NULL, ARRAY_SIZE(storage)),
		      -EINVAL);
	config.campaign_id = "bad id";
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      -EINVAL);
	config = config_base();
	config.projection = (enum pqcp_deployment_campaign_projection)99;
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      -EINVAL);
	config = config_base();
	config.candidate_template.mlkem_level = 999U;
	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      -EINVAL);
}

ZTEST(pqcp_deployment_campaign, test_invalid_emit_rejected)
{
	struct pqcp_deployment_campaign_observation storage[8];
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_summary summary;
	struct pqcp_deployment_campaign_config config = config_base();

	zassert_equal(pqcp_deployment_campaign_init(
			      &state, &config, storage, ARRAY_SIZE(storage)),
		      0);
	add_stable_observations(&state);
	zassert_equal(pqcp_deployment_campaign_summarize(&state, &summary), 0);

	summary.quality_mask = 0x80000000U;
	zassert_equal(pqcp_deployment_campaign_summary_emit(&summary), -EINVAL);
	zassert_equal(pqcp_deployment_campaign_summary_emit(NULL), -EINVAL);
}

ZTEST_SUITE(pqcp_deployment_campaign, NULL, NULL, NULL, NULL, NULL);
